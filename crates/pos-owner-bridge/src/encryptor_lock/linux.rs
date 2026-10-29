#![cfg(any(test, feature = "test-support"))]
//! Linux E16 primitives confined to explicit test directories until E15 activation.

use std::path::Path;

use rustix::fd::OwnedFd;
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat, StatFs, CWD};
use rustix::io::{self, Errno};

use super::{nonce_ledger_support, HOST_TARGET_OS};
use crate::{BridgeError, UnavailableCode};

const LOCK_NAME: &str = "pigloros.subject-encryptor.v1.lock";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

/// A non-cloneable descriptor holding a nonblocking lock in a test directory.
///
/// Retain this value for the owner-process lifetime, including quarantine and
/// recovery. Dropping it closes the descriptor. The lock file is never unlinked.
/// This is admission only: no owner adapter, store binding or nonce reservation
/// is created. The remaining ADR-097 activation gates still apply.
#[derive(Debug)]
#[must_use = "retain the encryptor lock for the owner-process lifetime"]
pub struct SubjectEncryptorLock {
    _file: OwnedFd,
}

impl SubjectEncryptorLock {
    /// Acquire the test-directory lock without waiting for another holder.
    ///
    /// E15 requires this explicit directory; no `XDG_STATE_HOME` or `HOME` is
    /// read and no production per-user location is selected. The absolute test
    /// directory must exist. Its symlinks may be followed, but the appended
    /// `pigloros` leaf and lock file are opened without following symlinks.
    /// The leaf must be owned by the effective UID with exactly mode 0700; the
    /// lock must be a singly linked regular file with the same owner and 0600.
    /// NFS is refused. Other filesystems receive no durability qualification.
    ///
    /// # Errors
    /// Returns the closed `Unavailable(InterfaceUnavailable)` on invalid paths,
    /// ownership, modes, links, filesystem, contention, changed path identity,
    /// or any filesystem failure. No supplied path or OS error escapes.
    pub fn acquire(test_directory: &Path) -> Result<Self, BridgeError> {
        nonce_ledger_support(HOST_TARGET_OS).and_then(|()| {
            open_directory(test_directory)
                .and_then(|directory| {
                    validate_directory(&directory).and_then(|()| acquire_file(&directory))
                })
                .map(|file| Self { _file: file })
                .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
        })
    }
}

fn open_directory(test_directory: &Path) -> io::Result<OwnedFd> {
    enforce(test_directory.is_absolute())
        .and_then(|()| fs::openat(CWD, test_directory, DIRECTORY_FLAGS, Mode::empty()))
        .and_then(|base| open_or_create_directory_component(&base, "pigloros"))
}

fn open_or_create_directory_component(parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    fs::mkdirat(parent, name, Mode::RWXU)
        .or_else(|error| {
            if error == Errno::EXIST {
                Ok(())
            } else {
                Err(error)
            }
        })
        .and_then(|()| {
            fs::openat(
                parent,
                name,
                DIRECTORY_FLAGS.union(OFlags::NOFOLLOW),
                Mode::empty(),
            )
        })
}

fn enforce(accepted: bool) -> io::Result<()> {
    accepted.then_some(()).ok_or(Errno::ACCESS)
}

fn private_metadata(stat: &Stat, kind: FileType, mode: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == kind
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o7777 == mode
}

const fn not_nfs(stat: &StatFs) -> bool {
    stat.f_type != fs::NFS_SUPER_MAGIC
}

const fn same_file(descriptor: &Stat, path: &Stat) -> bool {
    descriptor.st_dev == path.st_dev && descriptor.st_ino == path.st_ino
}

fn validate_directory(directory: &OwnedFd) -> io::Result<()> {
    fs::fstat(directory)
        .and_then(|stat| enforce(private_metadata(&stat, FileType::Directory, 0o700)))
        .and_then(|()| fs::fstatfs(directory))
        .and_then(|stat| enforce(not_nfs(&stat)))
}

fn acquire_file(directory: &OwnedFd) -> io::Result<OwnedFd> {
    let flags = OFlags::RDWR
        .union(OFlags::CREATE)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    fs::openat(directory, LOCK_NAME, flags, Mode::RUSR.union(Mode::WUSR)).and_then(|file| {
        fs::fstat(&file)
            .and_then(|stat| {
                enforce(private_metadata(&stat, FileType::RegularFile, 0o600) && stat.st_nlink == 1)
            })
            .and_then(|()| fs::flock(&file, FlockOperation::NonBlockingLockExclusive))
            .and_then(|()| {
                fs::fstat(&file).and_then(|locked| {
                    fs::statat(directory, LOCK_NAME, AtFlags::SYMLINK_NOFOLLOW)
                        .and_then(|path| enforce(same_file(&locked, &path)))
                })
            })
            .map(|()| file)
    })
}

#[cfg(test)]
mod tests;
