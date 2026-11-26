#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-123 filesystem coordination, without a native store constructor.
//!
//! This component grants no store, key or consent authority. It only opens the
//! coordination child and its lock entry: the quiescent installation step in
//! [`crate::owner_store_installation`] alone creates them (ADR-123 §3, §3a).
//! The protected profile still requires the complete constructor/alias/retirement
//! proof and managed native owner. Ordinary openers are not joined by this API.

use std::fmt;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

use pos_core::CoreError;
use rustix::fd::OwnedFd;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags, ResolveFlags, Stat, StatFs, CWD};
use rustix::io::{self, Errno};

use crate::owner_store_admission::OwnerStoreOperationV1;

const NAMESPACE: &str = crate::protected_sqlite_namespace::COORDINATION_DIRECTORY;
pub(crate) const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);
pub(crate) const OBSERVE: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const LOCK_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);

/// An exclusive nonblocking filesystem interlock inside an admitted operation.
///
/// Retain it across the entire eventual native operation and its cleanup. Drop
/// closes only the separate coordination file and metadata-only descriptors;
/// it never calls `SQLite`, unlinks an entry or releases admission.
#[must_use = "retain the interlock through all lower native work and cleanup"]
pub struct OwnerStoreFileInterlockV1<'operation> {
    _admission: PhantomData<&'operation ()>,
    namespace: CheckedNamespace,
    _coordination_directory: OwnedFd,
    _lock: OwnedFd,
}

impl fmt::Debug for OwnerStoreFileInterlockV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerStoreFileInterlockV1")
            .finish_non_exhaustive()
    }
}

impl<'operation> OwnerStoreFileInterlockV1<'operation> {
    /// Lock the screened main-file candidate in an explicit private test directory.
    ///
    /// The directory must be absolute, euid-owned and exactly 0700. Trusted
    /// directory aliases may resolve to that same actual directory. Relative
    /// entry resolution forbids symlinks and mount crossings; existing data
    /// files must be singly linked regular/euid/0600 objects. Missing WAL/SHM
    /// files remain missing. The fixed child and dev/ino-keyed lock are never
    /// selected from an independent path or removed on release. They must
    /// already exist: a missing child or lock entry refuses, and nothing is
    /// created (ADR-123 §3).
    ///
    /// The operation borrow prevents releasing admission while the lock lives:
    /// ```compile_fail
    /// use std::path::Path;
    /// use pos_store::owner_store_admission::OwnerStoreAdmissionV1;
    /// use pos_store::owner_store_interlock::OwnerStoreFileInterlockV1;
    /// let admission = OwnerStoreAdmissionV1::new();
    /// let Ok(operation) = admission.try_enter() else { return; };
    /// let Ok(interlock) = OwnerStoreFileInterlockV1::try_acquire(
    ///     &operation, Path::new("/explicit/test/database"), "store.db"
    /// ) else { return; };
    /// operation.complete_cleanly();
    /// drop(interlock);
    /// ```
    ///
    /// # Errors
    /// Returns a fixed storage refusal for unsafe metadata, unsupported lookup,
    /// a changed object, contention or any filesystem failure. No path or OS
    /// diagnostic escapes. A failure creates no native `SQLite` connection.
    pub fn try_acquire(
        _operation: &'operation OwnerStoreOperationV1<'_>,
        test_database_directory: &Path,
        main_basename: &str,
    ) -> Result<Self, CoreError> {
        CheckedNamespace::open(test_database_directory, main_basename)
            .and_then(|namespace| {
                open_coordination_directory(&namespace.directory).and_then(|coordination| {
                    let [name, ..] = reserved_names(&namespace.main.stat);
                    open_lock(&coordination, &name).and_then(|lock| {
                        namespace.recheck().map(|()| Self {
                            _admission: PhantomData,
                            namespace,
                            _coordination_directory: coordination,
                            _lock: lock,
                        })
                    })
                })
            })
            .map_err(|_| CoreError::Storage("protected store interlock unavailable".to_owned()))
    }

    /// The device and inode of the main file this interlock is keyed on, as
    /// read when it was taken.
    pub(crate) const fn main_key(&self) -> [u64; 2] {
        file_id(&self.namespace.main.stat)
    }

    /// A path naming the directory object this interlock holds through its own
    /// descriptor, valid while the interlock lives. It is transport for an
    /// identity proof, not identity.
    pub(crate) fn directory_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.namespace.directory.as_raw_fd()
        ))
    }
}

/// The ADR-123 §3b reserved entries of the coordination child for the screened
/// main file `main`: the filesystem interlock, the ADR-137 consent lease and
/// the in-child Gateway mode lock, each keyed on the main file's coordination
/// key.
pub(crate) fn reserved_names(main: &Stat) -> [String; 3] {
    ["store-namespace", "gateway-consent-lease", "gateway-mode"]
        .map(|entry| format!("{entry}.v1.{:016x}.{:016x}.lock", main.st_dev, main.st_ino))
}

pub(crate) struct FileWitness {
    descriptor: OwnedFd,
    pub(crate) stat: Stat,
}

pub(crate) struct CheckedNamespace {
    pub(crate) directory: OwnedFd,
    main_basename: String,
    pub(crate) main: FileWitness,
    pub(crate) companions: [Option<FileWitness>; 2],
}

impl CheckedNamespace {
    pub(crate) fn open(directory: &Path, main_basename: &str) -> io::Result<Self> {
        enforce(directory.is_absolute() && valid_basename(main_basename))
            .and_then(|()| {
                fs::openat(
                    CWD,
                    directory,
                    OBSERVE
                        .union(OFlags::DIRECTORY)
                        .difference(OFlags::NOFOLLOW),
                    Mode::empty(),
                )
            })
            .and_then(|directory| {
                validate_directory(&directory).and_then(|()| {
                    read_file(&directory, main_basename).and_then(|main| {
                        read_companions(&directory, main_basename).map(|companions| Self {
                            directory,
                            main_basename: main_basename.to_owned(),
                            main,
                            companions,
                        })
                    })
                })
            })
    }

    pub(crate) fn recheck(&self) -> io::Result<()> {
        validate_directory(&self.directory)
            .and_then(|()| check_regular(&self.main.descriptor))
            .and_then(|_| read_file(&self.directory, &self.main_basename))
            .and_then(|main| enforce(same_file(&main.stat, &self.main.stat)))
            .and_then(|()| read_companions(&self.directory, &self.main_basename))
            .and_then(|companions| {
                self.companions
                    .iter()
                    .flatten()
                    .try_for_each(|file| check_regular(&file.descriptor).map(|_| ()))
                    .and_then(|()| {
                        enforce(companions.iter().zip(&self.companions).all(
                            |(current, original)| {
                                current.as_ref().map(|file| file_id(&file.stat))
                                    == original.as_ref().map(|file| file_id(&file.stat))
                            },
                        ))
                    })
            })
    }
}

fn valid_basename(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !name.contains('/')
        && !name.starts_with("file:")
        && name != NAMESPACE
}

pub(crate) fn enforce(accepted: bool) -> io::Result<()> {
    accepted.then_some(()).ok_or(Errno::ACCESS)
}

fn private_metadata(stat: &Stat, kind: FileType, mode: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == kind
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o7777 == mode
}

fn validate_directory(directory: &OwnedFd) -> io::Result<()> {
    fs::fstat(directory)
        .and_then(|stat| enforce(private_metadata(&stat, FileType::Directory, 0o700)))
        .and_then(|()| fs::fstatfs(directory))
        .and_then(|stat| enforce(not_nfs(&stat)))
}

const fn not_nfs(stat: &StatFs) -> bool {
    stat.f_type != fs::NFS_SUPER_MAGIC
}

fn read_file(directory: &OwnedFd, name: &str) -> io::Result<FileWitness> {
    fs::openat2(directory, name, OBSERVE, Mode::empty(), RESOLVE).and_then(|descriptor| {
        check_regular(&descriptor).map(|stat| FileWitness { descriptor, stat })
    })
}

pub(crate) fn optional_file(directory: &OwnedFd, name: &str) -> io::Result<Option<FileWitness>> {
    read_file(directory, name).map(Some).or_else(|error| {
        if error == Errno::NOENT {
            Ok(None)
        } else {
            Err(error)
        }
    })
}

fn read_companions(directory: &OwnedFd, name: &str) -> io::Result<[Option<FileWitness>; 2]> {
    optional_file(directory, &format!("{name}-journal"))
        .and_then(|journal| enforce(journal.is_none()))
        .and_then(|()| optional_file(directory, &format!("{name}-wal")))
        .and_then(|wal| optional_file(directory, &format!("{name}-shm")).map(|shm| [wal, shm]))
}

/// Open the existing coordination child of `directory`, never creating it.
///
/// The child must be a private/euid/exact 0700 directory, not on NFS, and
/// physically distinct from its parent.
pub(crate) fn open_coordination_directory(directory: &OwnedFd) -> io::Result<OwnedFd> {
    fs::openat2(
        directory,
        NAMESPACE,
        OBSERVE.union(OFlags::DIRECTORY),
        Mode::empty(),
        RESOLVE,
    )
    .and_then(|child| {
        validate_directory(&child)
            .and_then(|()| fs::fstat(directory))
            .and_then(|parent| fs::fstat(&child).map(|stat| distinct_child(&parent, &stat)))
            .and_then(enforce)
            .map(|()| child)
    })
}

/// Whether a coordination child is a different physical directory from its
/// parent. Real filesystems with `RESOLVE_NO_XDEV` make the same object hard
/// to produce, so the check is a pure function the unit tests reach directly.
const fn distinct_child(parent: &Stat, child: &Stat) -> bool {
    !(parent.st_dev == child.st_dev && parent.st_ino == child.st_ino)
}

pub(crate) fn check_regular(descriptor: &OwnedFd) -> io::Result<Stat> {
    fs::fstat(descriptor).and_then(|stat| {
        enforce(private_metadata(&stat, FileType::RegularFile, 0o600) && stat.st_nlink == 1)
            .map(|()| stat)
    })
}

fn open_lock(directory: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    read_file(directory, name)
        .and_then(|observed| open_observed_lock(directory, name, &observed))
        .and_then(|descriptor| {
            verify_lock_entry(directory, name, &descriptor)
                .and_then(|()| fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive))
                .and_then(|()| verify_lock_entry(directory, name, &descriptor))
                .map(|()| descriptor)
        })
}

fn open_observed_lock(
    directory: &OwnedFd,
    name: &str,
    observed: &FileWitness,
) -> io::Result<OwnedFd> {
    fs::openat2(directory, name, LOCK_FLAGS, Mode::empty(), RESOLVE).and_then(|descriptor| {
        check_regular(&descriptor)
            .and_then(|stat| enforce(same_file(&observed.stat, &stat)).map(|()| descriptor))
    })
}

pub(crate) fn verify_lock_entry(
    directory: &OwnedFd,
    name: &str,
    descriptor: &OwnedFd,
) -> io::Result<()> {
    check_regular(descriptor).and_then(|stat| {
        read_file(directory, name).and_then(|current| enforce(same_file(&stat, &current.stat)))
    })
}

const fn file_id(stat: &Stat) -> [u64; 2] {
    [stat.st_dev, stat.st_ino]
}

pub(crate) fn same_file(first: &Stat, second: &Stat) -> bool {
    file_id(first) == file_id(second)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn private_directory() -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }

    fn create(directory: &Path, name: &str) -> TestResult {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))?;
        Ok(())
    }

    #[test]
    fn metadata_policy_distinguishes_owner_kind_mode_and_physical_identity() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main")?;
        let namespace = CheckedNamespace::open(directory.path(), "main")?;
        let original = &namespace.main.stat;
        assert!(private_metadata(original, FileType::RegularFile, 0o600));
        let mut changed = fs::fstat(&namespace.main.descriptor)?;
        changed.st_uid = changed.st_uid.wrapping_add(1);
        assert!(!private_metadata(&changed, FileType::RegularFile, 0o600));
        changed = fs::fstat(&namespace.main.descriptor)?;
        changed.st_dev = changed.st_dev.wrapping_add(1);
        assert!(!same_file(original, &changed));
        changed = fs::fstat(&namespace.main.descriptor)?;
        changed.st_ino = changed.st_ino.wrapping_add(1);
        assert!(!same_file(original, &changed));
        let mut filesystem = fs::fstatfs(&namespace.directory)?;
        assert!(not_nfs(&filesystem));
        filesystem.f_type = fs::NFS_SUPER_MAGIC;
        assert!(!not_nfs(&filesystem));
        Ok(())
    }

    #[test]
    fn retained_namespace_rejects_replaced_main_and_companion_objects() -> TestResult {
        let directory = private_directory()?;
        create(directory.path(), "main")?;
        create(directory.path(), "main-wal")?;
        let namespace = CheckedNamespace::open(directory.path(), "main")?;
        std::fs::rename(
            directory.path().join("main-wal"),
            directory.path().join("old-wal"),
        )?;
        create(directory.path(), "main-wal")?;
        assert!(namespace.recheck().is_err());
        let namespace = CheckedNamespace::open(directory.path(), "main")?;
        std::fs::rename(
            directory.path().join("main"),
            directory.path().join("old-main"),
        )?;
        create(directory.path(), "main")?;
        assert!(namespace.recheck().is_err());
        Ok(())
    }

    #[test]
    fn coordination_lookup_and_observation_failures_do_not_create_or_replace_entries() -> TestResult
    {
        let directory = private_directory()?;
        create(directory.path(), "main")?;
        let namespace = CheckedNamespace::open(directory.path(), "main")?;
        let child = directory.path().join(NAMESPACE);
        assert!(open_coordination_directory(&namespace.directory).is_err());
        assert!(!child.exists());
        std::fs::create_dir(&child)?;
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700))?;
        assert!(open_coordination_directory(&namespace.main.descriptor).is_err());
        let coordination = open_coordination_directory(&namespace.directory)?;
        assert!(open_lock(&coordination, "lock").is_err());
        assert!(!child.join("lock").exists());
        create(&child, "lock")?;
        let observed = read_file(&coordination, "lock")?;
        std::fs::rename(child.join("lock"), child.join("old-lock"))?;
        create(&child, "lock")?;
        assert!(open_observed_lock(&coordination, "lock", &observed).is_err());
        assert!(verify_lock_entry(&coordination, "lock", &observed.descriptor).is_err());
        assert!(child.join("old-lock").is_file());
        assert!(child.join("lock").is_file());
        Ok(())
    }

    #[test]
    fn a_child_must_be_physically_distinct_from_its_parent() -> TestResult {
        let directory = private_directory()?;
        let parent = fs::fstat(fs::openat(CWD, directory.path(), OBSERVE, Mode::empty())?)?;
        assert!(!distinct_child(&parent, &parent));
        let mut other = parent;
        other.st_ino = other.st_ino.wrapping_add(1);
        assert!(distinct_child(&parent, &other));
        other = parent;
        other.st_dev = other.st_dev.wrapping_add(1);
        assert!(distinct_child(&parent, &other));
        Ok(())
    }

    #[test]
    fn reserved_names_follow_the_coordination_key() -> TestResult {
        let directory = private_directory()?;
        let mut main = fs::fstat(fs::openat(CWD, directory.path(), OBSERVE, Mode::empty())?)?;
        main.st_dev = 0x0a;
        main.st_ino = u64::MAX;
        assert_eq!(
            reserved_names(&main),
            [
                "store-namespace.v1.000000000000000a.ffffffffffffffff.lock",
                "gateway-consent-lease.v1.000000000000000a.ffffffffffffffff.lock",
                "gateway-mode.v1.000000000000000a.ffffffffffffffff.lock",
            ]
        );
        Ok(())
    }
}
