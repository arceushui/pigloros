#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-123 §3b in-child Gateway mode lock.
//!
//! Opens the existing `gateway-mode.v1.<dev016x>.<ino016x>.lock` entry of the
//! coordination child and takes a nonblocking `flock` on it: shared for `serve`
//! and the offline writers, exclusive for `migrate-mode`. Only the quiescent
//! installation step creates the entry; this module never creates, renames or
//! unlinks anything, and it never falls back to another path. The lock is
//! mode-lifetime coordination state, not store, key or consent authority.

use std::path::Path;

use pos_core::CoreError;
use rustix::fd::OwnedFd;
use rustix::fs::{self, FlockOperation, Mode, OFlags, Stat};
use rustix::io::{self, Errno};

use crate::owner_store_interlock::{
    check_regular, enforce, open_coordination_directory, optional_file, reserved_names, same_file,
    verify_lock_entry, CheckedNamespace, RESOLVE,
};

const LOCK_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);

/// Which side of the Gateway mode lock a process takes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerStoreModeLockKindV1 {
    /// `serve` and every offline writer except `migrate-mode`.
    Shared,
    /// `migrate-mode`, which never runs beside `serve` or another writer.
    Exclusive,
}

impl OwnerStoreModeLockKindV1 {
    const fn operation(self) -> FlockOperation {
        match self {
            Self::Shared => FlockOperation::NonBlockingLockShared,
            Self::Exclusive => FlockOperation::NonBlockingLockExclusive,
        }
    }
}

/// A held in-child Gateway mode lock.
///
/// Retain it for the whole process lifetime of the holder. Drop closes the lock
/// descriptor, which releases the `flock`; it never unlinks the entry.
#[derive(Debug)]
#[must_use = "retain the mode lock for the whole process lifetime"]
pub struct OwnerStoreModeLockV1 {
    kind: OwnerStoreModeLockKindV1,
    _lock: OwnedFd,
}

impl OwnerStoreModeLockV1 {
    /// Take the mode lock of the installed store `main_basename` in an explicit
    /// private test database directory.
    ///
    /// The directory must be absolute, euid-owned and exactly 0700; the main
    /// file is screened as for the filesystem interlock. The fixed child and
    /// the lock entry named by the main file's device and inode must already
    /// exist, as regular euid 0600 singly linked files; nothing is created. The
    /// attempt never waits: a held conflicting lock refuses at once.
    ///
    /// # Errors
    /// Returns one fixed storage refusal for a missing child or entry, unsafe
    /// metadata, a changed object, contention or any filesystem failure. No
    /// path or OS diagnostic escapes, and no fallback lock is tried.
    pub fn try_acquire(
        test_database_directory: &Path,
        main_basename: &str,
        kind: OwnerStoreModeLockKindV1,
    ) -> Result<Self, CoreError> {
        CheckedNamespace::open(test_database_directory, main_basename)
            .and_then(|namespace| {
                open_coordination_directory(&namespace.directory).and_then(|coordination| {
                    let [_, _, name] = reserved_names(&namespace.main.stat);
                    open_mode_lock(&coordination, &name, kind)
                        .and_then(|lock| namespace.recheck().map(|()| Self { kind, _lock: lock }))
                })
            })
            .map_err(|_| CoreError::Storage("protected store mode lock unavailable".to_owned()))
    }

    /// The side of the lock this guard holds.
    #[must_use]
    pub const fn kind(&self) -> OwnerStoreModeLockKindV1 {
        self.kind
    }
}

/// Open the existing entry `name`, then lock it, checking the entry before and
/// after the lock. A missing entry refuses and is never created.
fn open_mode_lock(
    directory: &OwnedFd,
    name: &str,
    kind: OwnerStoreModeLockKindV1,
) -> io::Result<OwnedFd> {
    optional_file(directory, name)
        .and_then(|observed| observed.ok_or(Errno::NOENT))
        .and_then(|observed| open_observed(directory, name, &observed.stat))
        .and_then(|descriptor| {
            verify_lock_entry(directory, name, &descriptor)
                .and_then(|()| fs::flock(&descriptor, kind.operation()))
                .and_then(|()| verify_lock_entry(directory, name, &descriptor))
                .map(|()| descriptor)
        })
}

/// Open the entry for locking and require it to be the object just observed.
fn open_observed(directory: &OwnedFd, name: &str, observed: &Stat) -> io::Result<OwnedFd> {
    fs::openat2(directory, name, LOCK_FLAGS, Mode::empty(), RESOLVE).and_then(|descriptor| {
        check_regular(&descriptor)
            .and_then(|stat| enforce(same_file(observed, &stat)).map(|()| descriptor))
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::OwnerStoreModeLockKindV1::{Exclusive, Shared};
    use super::*;
    use crate::owner_store_installation::install_owner_store_namespace_v1;
    use crate::protected_sqlite_namespace::COORDINATION_DIRECTORY;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn write_main(directory: &Path) -> TestResult {
        let mut header = [0_u8; 100];
        header[..16].copy_from_slice(b"SQLite format 3\0");
        header[18] = 2;
        header[19] = 2;
        let path = directory.join("main");
        std::fs::write(&path, header)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn installed() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        write_main(directory.path())?;
        install_owner_store_namespace_v1(directory.path(), "main")?;
        Ok(directory)
    }

    fn entry(directory: &Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let child = directory.join(COORDINATION_DIRECTORY);
        std::fs::read_dir(&child)?
            .filter_map(Result::ok)
            .map(|file| file.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("gateway-mode.v1."))
            })
            .ok_or_else(|| "mode lock entry missing".into())
    }

    fn acquire(
        directory: &Path,
        kind: OwnerStoreModeLockKindV1,
    ) -> Result<OwnerStoreModeLockV1, CoreError> {
        OwnerStoreModeLockV1::try_acquire(directory, "main", kind)
    }

    #[test]
    fn shared_holders_coexist_and_exclude_the_exclusive_side() -> TestResult {
        let directory = installed()?;
        let first = acquire(directory.path(), Shared)?;
        let second = acquire(directory.path(), Shared)?;
        assert_eq!(first.kind(), Shared);
        assert_eq!(second.kind(), Shared);
        assert!(acquire(directory.path(), Exclusive).is_err());
        drop(first);
        assert!(acquire(directory.path(), Exclusive).is_err());
        drop(second);
        assert_eq!(acquire(directory.path(), Exclusive)?.kind(), Exclusive);
        Ok(())
    }

    #[test]
    fn exclusive_holder_refuses_both_sides_until_dropped() -> TestResult {
        let directory = installed()?;
        let held = acquire(directory.path(), Exclusive)?;
        assert!(acquire(directory.path(), Exclusive).is_err());
        assert!(acquire(directory.path(), Shared).is_err());
        drop(held);
        assert_eq!(acquire(directory.path(), Shared)?.kind(), Shared);
        Ok(())
    }

    #[test]
    fn refusal_is_one_fixed_storage_error() -> TestResult {
        let directory = installed()?;
        let _held = acquire(directory.path(), Exclusive)?;
        let Err(CoreError::Storage(message)) = acquire(directory.path(), Shared) else {
            return Err("expected a storage refusal".into());
        };
        assert_eq!(message, "protected store mode lock unavailable");
        assert!(!message.contains(directory.path().to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn a_missing_child_or_entry_refuses_and_creates_nothing() -> TestResult {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        write_main(directory.path())?;
        assert!(acquire(directory.path(), Shared).is_err());
        assert!(!directory.path().join(COORDINATION_DIRECTORY).exists());
        install_owner_store_namespace_v1(directory.path(), "main")?;
        let path = entry(directory.path())?;
        std::fs::remove_file(&path)?;
        assert!(acquire(directory.path(), Shared).is_err());
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn the_entry_name_must_encode_the_store_identity() -> TestResult {
        let directory = installed()?;
        std::fs::rename(
            directory.path().join("main"),
            directory.path().join("old-main"),
        )?;
        write_main(directory.path())?;
        assert!(acquire(directory.path(), Shared).is_err());
        Ok(())
    }

    #[test]
    fn unsafe_entry_metadata_and_types_refuse() -> TestResult {
        let directory = installed()?;
        let path = entry(directory.path())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(acquire(directory.path(), Shared).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let link = path.with_extension("link");
        std::fs::hard_link(&path, &link)?;
        assert!(acquire(directory.path(), Shared).is_err());
        std::fs::remove_file(&link)?;
        assert_eq!(acquire(directory.path(), Shared)?.kind(), Shared);
        std::fs::remove_file(&path)?;
        std::fs::create_dir(&path)?;
        assert!(acquire(directory.path(), Shared).is_err());
        std::fs::remove_dir(&path)?;
        symlink(directory.path().join("main"), &path)?;
        assert!(acquire(directory.path(), Shared).is_err());
        Ok(())
    }
}
