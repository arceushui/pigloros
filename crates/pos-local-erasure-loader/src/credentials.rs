//! Protected systemd credential directories (`$CREDENTIALS_DIRECTORY`) with
//! the custody checks of the ADR-107 Fork-authority credentials.
//!
//! The directory is opened once without following symlinks and validated by
//! descriptor: it must be a directory owned by the service UID with mode
//! `0700`. Its names and children are read relative to that descriptor, and
//! each child is opened non-blocking and without following a symlink, so a
//! FIFO fails the regular-file check instead of blocking; a child must be a
//! regular file owned by the service UID with mode `0400`, at most its
//! bound. Every read is zeroized on failure.

use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

use rustix::fs::{openat, Dir, Mode, OFlags};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const PRIVATE_CREDENTIAL_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_CREDENTIAL_FILE_MODE: u32 = 0o400;

/// Closed, payload-free credential failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialErrorV1 {
    /// The directory or a credential is missing or cannot be read.
    #[error("credential unavailable")]
    Unavailable,
    /// The directory or a credential fails a custody check, holds another
    /// set of names, or is over its bound.
    #[error("credential invalid")]
    Invalid,
}

/// A protected systemd credential directory, opened by descriptor.
pub struct CredentialDirectoryV1 {
    directory: File,
    service_uid: u32,
}

/// The flags a credential directory opens with: a path descriptor that
/// never follows a symlink and closes on exec. Built with `union`, so no
/// equivalent `|` to `^` mutant exists for disjoint flag bits.
const DIRECTORY_OPEN_FLAGS: i32 = OFlags::PATH
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .bits()
    .cast_signed();

impl CredentialDirectoryV1 {
    /// Open the credential directory `directory` (never a symlink) owned by
    /// `service_uid` and validate it by descriptor.
    ///
    /// # Errors
    /// Returns [`CredentialErrorV1::Unavailable`] for a relative or missing
    /// path and [`CredentialErrorV1::Invalid`] for anything but a private
    /// directory owned by `service_uid`.
    pub fn open(directory: &Path, service_uid: u32) -> Result<Self, CredentialErrorV1> {
        if !directory.is_absolute() {
            return Err(CredentialErrorV1::Unavailable);
        }
        OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY_OPEN_FLAGS)
            .open(directory)
            .and_then(|directory| directory.metadata().map(|metadata| (directory, metadata)))
            .map_err(|_| CredentialErrorV1::Unavailable)
            .and_then(|(directory, metadata)| {
                if !metadata.is_dir()
                    || metadata.uid() != service_uid
                    || metadata.mode() & 0o777 != PRIVATE_CREDENTIAL_DIRECTORY_MODE
                {
                    return Err(CredentialErrorV1::Invalid);
                }
                Ok(Self {
                    directory,
                    service_uid,
                })
            })
    }

    /// The directory's child names, sorted.
    ///
    /// # Errors
    /// Returns [`CredentialErrorV1::Unavailable`] when the directory cannot
    /// be listed and [`CredentialErrorV1::Invalid`] for a name that is not
    /// UTF-8.
    pub fn names(&self) -> Result<Vec<String>, CredentialErrorV1> {
        sorted_credential_names(&self.directory)
    }

    /// Read the credential `name`, at most `maximum` bytes.
    ///
    /// # Errors
    /// Returns [`CredentialErrorV1::Unavailable`] for a missing or
    /// unreadable credential and [`CredentialErrorV1::Invalid`] for one that
    /// fails a custody check, is over `maximum` or changes size while read.
    pub fn read(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialErrorV1> {
        read_bounded_credential(&self.directory, name, self.service_uid, maximum)
            .map(Zeroizing::new)
    }
}

/// A protected systemd credential directory that holds exactly the
/// credentials it was opened for.
pub struct ExactCredentialsV1 {
    directory: CredentialDirectoryV1,
}

impl ExactCredentialsV1 {
    /// Read the credential `name`, at most `maximum` bytes, with the
    /// custody checks of [`CredentialDirectoryV1::read`].
    ///
    /// # Errors
    /// Returns the [`CredentialDirectoryV1::read`] refusals.
    pub fn read(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialErrorV1> {
        self.directory.read(name, maximum)
    }
}

/// Open a protected systemd credential directory that must hold exactly
/// the credentials `names`, given in sorted order.
///
/// # Errors
/// Returns the [`CredentialDirectoryV1::open`] and
/// [`CredentialDirectoryV1::names`] refusals, and
/// [`CredentialErrorV1::Invalid`] when the directory holds other names.
pub fn open_exact_credentials(
    directory: &Path,
    names: &[&str],
    service_uid: u32,
) -> Result<ExactCredentialsV1, CredentialErrorV1> {
    CredentialDirectoryV1::open(directory, service_uid).and_then(|directory| {
        directory
            .names()
            .and_then(|found| {
                (found == names)
                    .then_some(())
                    .ok_or(CredentialErrorV1::Invalid)
            })
            .map(|()| ExactCredentialsV1 { directory })
    })
}

/// Read the one credential `name` of a protected systemd credential
/// directory that holds exactly it, at most `maximum` bytes.
///
/// # Errors
/// Returns the [`open_exact_credentials`] and [`ExactCredentialsV1::read`]
/// refusals.
pub fn read_single_credential(
    directory: &Path,
    name: &str,
    service_uid: u32,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, CredentialErrorV1> {
    open_exact_credentials(directory, &[name], service_uid)
        .and_then(|credentials| credentials.read(name, maximum))
}

/// List the credential directory's child names, sorted, by its descriptor.
fn sorted_credential_names(directory: &File) -> Result<Vec<String>, CredentialErrorV1> {
    openat(
        directory,
        ".",
        OFlags::RDONLY
            .union(OFlags::DIRECTORY)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
    )
    .and_then(Dir::new)
    .map_err(errno_unavailable)
    .and_then(|entries| {
        entries
            .map(|entry| {
                entry.map_err(errno_unavailable).and_then(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .map(str::to_owned)
                        .map_err(|_| CredentialErrorV1::Invalid)
                })
            })
            .filter(|name| !matches!(name.as_deref(), Ok("." | "..")))
            .collect::<Result<Vec<_>, _>>()
    })
    .map(|mut names| {
        names.sort_unstable();
        names
    })
}

/// Read one credential child, never following a symlink, within `maximum`.
fn read_bounded_credential(
    directory: &File,
    name: &str,
    service_uid: u32,
    maximum: usize,
) -> Result<Vec<u8>, CredentialErrorV1> {
    openat(
        directory,
        name,
        OFlags::RDONLY
            .union(OFlags::NOFOLLOW)
            .union(OFlags::NONBLOCK)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
    )
    .map(File::from)
    .map_err(errno_unavailable)
    .and_then(|mut file| {
        file.metadata()
            .map_err(|_| CredentialErrorV1::Unavailable)
            .and_then(|metadata| {
                if !metadata.is_file()
                    || metadata.uid() != service_uid
                    || metadata.mode() & 0o777 != PRIVATE_CREDENTIAL_FILE_MODE
                {
                    return Err(CredentialErrorV1::Invalid);
                }
                usize::try_from(metadata.len())
                    .map_err(|_| CredentialErrorV1::Invalid)
                    .and_then(|size| {
                        if size > maximum {
                            return Err(CredentialErrorV1::Invalid);
                        }
                        finish_credential_read(&mut file, size, maximum)
                    })
            })
    })
}

const fn errno_unavailable(_: rustix::io::Errno) -> CredentialErrorV1 {
    CredentialErrorV1::Unavailable
}

fn finish_credential_read(
    reader: &mut impl Read,
    size: usize,
    maximum: usize,
) -> Result<Vec<u8>, CredentialErrorV1> {
    let mut bytes = Vec::with_capacity(size);
    if reader
        .take(u64::try_from(maximum + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .is_err()
    {
        bytes.zeroize();
        return Err(CredentialErrorV1::Unavailable);
    }
    if bytes.len() != size {
        bytes.zeroize();
        return Err(CredentialErrorV1::Invalid);
    }
    Ok(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn chmod(path: &Path, mode: u32) -> TestResult {
        Ok(fs::set_permissions(path, fs::Permissions::from_mode(mode))?)
    }

    /// A private directory holding `credentials`, each private.
    fn directory(credentials: &[(&str, &[u8])]) -> TestResult<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        chmod(directory.path(), 0o700)?;
        for (name, bytes) in credentials {
            let path = directory.path().join(name);
            fs::write(&path, bytes)?;
            chmod(&path, 0o400)?;
        }
        Ok(directory)
    }

    #[test]
    fn the_directory_must_be_an_absolute_private_directory_of_the_service() -> TestResult {
        let directory = directory(&[("a", b"x")])?;
        let path = directory.path();
        assert!(CredentialDirectoryV1::open(path, uid()).is_ok());
        let missing = path.join("missing");
        for (unavailable, label) in [
            (Path::new("relative"), "relative"),
            (missing.as_path(), "missing"),
        ] {
            assert_eq!(
                CredentialDirectoryV1::open(unavailable, uid()).err(),
                Some(CredentialErrorV1::Unavailable),
                "{label}"
            );
        }
        assert_eq!(
            CredentialDirectoryV1::open(&path.join("a"), uid()).err(),
            Some(CredentialErrorV1::Invalid)
        );
        assert_eq!(
            CredentialDirectoryV1::open(path, uid() ^ 1).err(),
            Some(CredentialErrorV1::Invalid)
        );
        chmod(path, 0o750)?;
        assert_eq!(
            CredentialDirectoryV1::open(path, uid()).err(),
            Some(CredentialErrorV1::Invalid)
        );
        Ok(())
    }

    #[test]
    fn the_names_are_sorted_utf8_and_exclude_the_dot_entries() -> TestResult {
        let names = ["e", "c", "a", "d", "b"];
        let credentials = names.map(|name| (name, b"x".as_slice()));
        let directory = directory(&credentials)?;
        let opened = CredentialDirectoryV1::open(directory.path(), uid())?;
        assert_eq!(opened.names()?, ["a", "b", "c", "d", "e"]);
        fs::write(directory.path().join(OsString::from_vec(vec![0xff])), [])?;
        assert_eq!(opened.names().err(), Some(CredentialErrorV1::Invalid));
        Ok(())
    }

    #[test]
    fn a_credential_must_be_a_private_regular_file_within_its_bound() -> TestResult {
        let directory = directory(&[("bound", b"four"), ("loose", b"x")])?;
        chmod(&directory.path().join("loose"), 0o600)?;
        fs::create_dir(directory.path().join("child"))?;
        std::os::unix::fs::symlink(
            directory.path().join("bound"),
            directory.path().join("link"),
        )?;
        let opened = CredentialDirectoryV1::open(directory.path(), uid())?;
        assert_eq!(opened.read("bound", 4)?.as_slice(), b"four");
        for (name, maximum, error) in [
            ("bound", 3, CredentialErrorV1::Invalid),
            ("loose", 4, CredentialErrorV1::Invalid),
            ("child", 4, CredentialErrorV1::Invalid),
            ("link", 4, CredentialErrorV1::Unavailable),
            ("missing", 4, CredentialErrorV1::Unavailable),
        ] {
            assert_eq!(opened.read(name, maximum).err(), Some(error), "{name}");
        }
        assert_eq!(
            read_bounded_credential(&opened.directory, "bound", uid() ^ 1, 4).err(),
            Some(CredentialErrorV1::Invalid)
        );
        Ok(())
    }

    #[test]
    fn a_fifo_credential_fails_closed_without_blocking() -> TestResult {
        let directory = directory(&[])?;
        let fifo = directory.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            fifo.as_path(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o400),
            0,
        )?;
        let path = directory.path().to_path_buf();
        let service_uid = uid();
        let (sender, receiver) = std::sync::mpsc::channel();
        let _reader = std::thread::spawn(move || {
            sender.send(
                CredentialDirectoryV1::open(&path, service_uid)
                    .and_then(|opened| opened.read("fifo", 4))
                    .err(),
            )
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(Some(CredentialErrorV1::Invalid))
        );
        Ok(())
    }

    #[test]
    fn a_short_grown_or_failing_read_fails_closed() {
        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read fault"))
            }
        }

        let mut short = &b"short"[..];
        assert_eq!(
            finish_credential_read(&mut short, 6, 16),
            Err(CredentialErrorV1::Invalid)
        );
        let grown = vec![0; 116];
        let mut grown = grown.as_slice();
        assert_eq!(
            finish_credential_read(&mut grown, 1, 16),
            Err(CredentialErrorV1::Invalid)
        );
        // The read stops one byte past the bound.
        assert_eq!(grown.len(), 99);
        assert_eq!(
            finish_credential_read(&mut FailingReader, 1, 16),
            Err(CredentialErrorV1::Unavailable)
        );
    }

    #[test]
    fn an_exact_directory_holds_exactly_its_names() -> TestResult {
        let directory = directory(&[("a", b"one"), ("b", b"two")])?;
        let exact = open_exact_credentials(directory.path(), &["a", "b"], uid())?;
        assert_eq!(exact.read("b", 3)?.as_slice(), b"two");
        for names in [&["a"][..], &["a", "b", "c"], &["b", "a"]] {
            assert_eq!(
                open_exact_credentials(directory.path(), names, uid()).err(),
                Some(CredentialErrorV1::Invalid),
                "{names:?}"
            );
        }
        let single = directory_single()?;
        assert_eq!(
            read_single_credential(single.path(), "only", uid(), 4)?.as_slice(),
            b"only"
        );
        assert_eq!(
            read_single_credential(directory.path(), "a", uid(), 4).err(),
            Some(CredentialErrorV1::Invalid)
        );
        assert_eq!(CredentialErrorV1::Invalid.to_string(), "credential invalid");
        Ok(())
    }

    fn directory_single() -> TestResult<tempfile::TempDir> {
        directory(&[("only", b"only")])
    }
}
