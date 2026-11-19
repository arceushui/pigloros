#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-123 §3a quiescent installation of the coordination child.
//!
//! This is the one step that creates the coordination child and its §3b
//! reserved entries; participants such as
//! [`crate::owner_store_interlock::OwnerStoreFileInterlockV1`] only open them.
//! In Wave 9 it stays test-support gated (ADR-123 G13): no deployable build can
//! install a store that no ungated participant could open. It grants no store,
//! key or consent authority and never opens `SQLite`.

use std::io::Read;
use std::path::Path;

use pos_core::CoreError;
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags};
use rustix::io::{self, Errno};

use crate::owner_store_interlock::{
    enforce, open_coordination_directory, optional_file, reserved_names, same_file,
    verify_lock_entry, CheckedNamespace, RESOLVE,
};

const NAMESPACE: &str = crate::protected_sqlite_namespace::COORDINATION_DIRECTORY;

/// The first 16 bytes of every `SQLite` 3 database file.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// What one quiescent installation run did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerStoreInstallationV1 {
    /// The run created the coordination child or at least one reserved entry;
    /// a rerun after an interrupted installation reports this too.
    Installed,
    /// The child and every reserved entry already existed and passed the
    /// checks; nothing was created.
    AlreadyInstalled,
}

/// Install the coordination child of the main file `main_basename` in an
/// explicit private test database directory (ADR-123 §3a).
///
/// The caller is the operator's offline installation step. It asserts that no
/// participant or ordinary process has the store open, and it holds the
/// ADR-134 §8 sibling Gateway mode lock exclusively for the whole call.
///
/// The directory must be absolute, euid-owned, exactly 0700 and not on NFS.
/// The main file must be a singly linked regular/euid/0600 `SQLite` 3 database
/// in WAL mode, as the existing ordinary creation route leaves it; no
/// `-journal` entry may exist and existing WAL/SHM entries must pass the same
/// file policy. The run then:
///
/// 1. creates the child with mode 0700, or reuses an existing one, and checks
///    it is a private/euid/0700 directory, physically distinct from its
///    parent;
/// 2. syncs the database directory;
/// 3. creates each §3b reserved entry exclusively with mode 0600, or checks an
///    existing one; an entry that appears between the check and the creation
///    refuses, and nothing is replaced;
/// 4. syncs the child.
///
/// # Errors
/// Returns a fixed storage refusal for any failed precondition or step. No
/// path or OS diagnostic escapes. A refusal leaves every existing entry as it
/// was, so the operator can rerun the installation.
pub fn install_owner_store_namespace_v1(
    test_database_directory: &Path,
    main_basename: &str,
) -> Result<OwnerStoreInstallationV1, CoreError> {
    CheckedNamespace::open(test_database_directory, main_basename)
        .and_then(|namespace| {
            check_wal_database(&namespace, main_basename)
                .and_then(|()| install_child(&namespace))
                .and_then(|created| namespace.recheck().map(|()| created))
        })
        .map(|created| {
            if created {
                OwnerStoreInstallationV1::Installed
            } else {
                OwnerStoreInstallationV1::AlreadyInstalled
            }
        })
        .map_err(|_| CoreError::Storage("protected store installation unavailable".to_owned()))
}

/// Require a `SQLite` 3 header whose write and read versions select WAL.
fn check_wal_database(namespace: &CheckedNamespace, main_basename: &str) -> io::Result<()> {
    fs::openat2(
        &namespace.directory,
        main_basename,
        OFlags::RDONLY
            .union(OFlags::NOFOLLOW)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
        RESOLVE,
    )
    .and_then(|descriptor| {
        fs::fstat(&descriptor)
            .and_then(|stat| enforce(same_file(&stat, &namespace.main.stat)))
            .and_then(|()| {
                let mut header = [0; 20];
                std::fs::File::from(descriptor)
                    .read_exact(&mut header)
                    .map_err(|_| Errno::IO)
                    .map(|()| header)
            })
    })
    .and_then(|header| enforce(wal_header(&header)))
}

/// Whether the first 20 bytes of a database file are a `SQLite` 3 header in
/// WAL mode: file format write and read versions both 2.
fn wal_header(header: &[u8; 20]) -> bool {
    header[..16] == *SQLITE_MAGIC && header[18] == 2 && header[19] == 2
}

/// Create or reuse the child and every reserved entry, syncing the directory
/// after the child and the child after its entries. Returns whether anything
/// was created.
fn install_child(namespace: &CheckedNamespace) -> io::Result<bool> {
    let created_child = match fs::mkdirat(&namespace.directory, NAMESPACE, Mode::RWXU) {
        Ok(()) => Ok(true),
        Err(Errno::EXIST) => Ok(false),
        Err(error) => Err(error),
    }?;
    let child = open_coordination_directory(&namespace.directory)?;
    fs::fsync(readable_directory(&namespace.directory)?)?;
    let mut created_entry = false;
    for name in reserved_names(&namespace.main.stat) {
        created_entry |= ensure_entry(&child, &name)?;
    }
    fs::fsync(readable_directory(&child)?)?;
    Ok(created_child || created_entry)
}

/// A readable descriptor of the directory behind the `O_PATH` `directory`,
/// which `fsync` requires.
fn readable_directory(directory: &OwnedFd) -> io::Result<OwnedFd> {
    fs::openat2(
        directory,
        ".",
        OFlags::RDONLY
            .union(OFlags::DIRECTORY)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
        RESOLVE,
    )
    .and_then(|readable| {
        fs::fstat(directory)
            .and_then(|expected| fs::fstat(&readable).map(|stat| same_file(&expected, &stat)))
            .and_then(enforce)
            .map(|()| readable)
    })
}

/// Check an existing reserved entry, or create a missing one exclusively.
/// Returns whether it was created.
fn ensure_entry(child: &OwnedFd, name: &str) -> io::Result<bool> {
    optional_file(child, name).and_then(|observed| match observed {
        Some(_) => Ok(false),
        None => create_entry(child, name).map(|()| true),
    })
}

/// Create the reserved entry `name` with `O_EXCL` and mode 0600 and check it.
/// An entry that already exists refuses and is left as it is.
fn create_entry(child: &OwnedFd, name: &str) -> io::Result<()> {
    fs::openat2(
        child,
        name,
        OFlags::RDWR
            .union(OFlags::CREATE)
            .union(OFlags::EXCL)
            .union(OFlags::NOFOLLOW)
            .union(OFlags::CLOEXEC),
        Mode::RUSR.union(Mode::WUSR),
        RESOLVE,
    )
    .and_then(|descriptor| verify_lock_entry(child, name, &descriptor))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn header(magic: &[u8; 16], write: u8, read: u8) -> [u8; 20] {
        let mut header = [0; 20];
        header[..16].copy_from_slice(magic);
        header[16] = 0x10;
        header[18] = write;
        header[19] = read;
        header
    }

    #[test]
    fn only_a_sqlite_3_header_in_wal_mode_is_accepted() {
        assert!(wal_header(&header(SQLITE_MAGIC, 2, 2)));
        assert!(!wal_header(&header(SQLITE_MAGIC, 1, 1)));
        assert!(!wal_header(&header(SQLITE_MAGIC, 2, 1)));
        assert!(!wal_header(&header(SQLITE_MAGIC, 1, 2)));
        assert!(!wal_header(&header(b"SQLite format 2\0", 2, 2)));
    }

    #[test]
    fn creating_an_existing_entry_refuses_without_replacing_it() -> TestResult {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        std::fs::write(directory.path().join("entry"), b"kept")?;
        let child = fs::openat(
            fs::CWD,
            directory.path(),
            OFlags::PATH.union(OFlags::DIRECTORY),
            Mode::empty(),
        )?;
        assert_eq!(create_entry(&child, "entry"), Err(Errno::EXIST));
        assert_eq!(std::fs::read(directory.path().join("entry"))?, b"kept");
        Ok(())
    }
}
