//! Named network namespaces, each pinned by a bind mount of its namespace
//! file under one directory, as iproute2 pins them under `/run/netns`
//! (#911, owner decision 2026-11-09).
//!
//! A namespace is created on a dedicated thread that unshares its network
//! namespace, so no other thread, and no process, ever enters it. Creation
//! is exclusive: an existing entry of the same name fails it.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{fstatfs, mkdir, open, unlink, Mode, OFlags};
use rustix::io::Errno;
use rustix::mount::{mount_bind, unmount, UnmountFlags};
use rustix::thread::UnshareFlags;

use super::netlink::NetlinkError;
use super::NamespaceName;

/// The calling thread's network namespace file.
const THREAD_NAMESPACE: &str = "/proc/thread-self/ns/net";
/// `NSFS_MAGIC`: the filesystem of a namespace file.
const NSFS_MAGIC: i128 = 0x6e73_6673;
/// Open read-only and close on exec.
pub(super) const READ_ONLY: OFlags = OFlags::RDONLY.union(OFlags::CLOEXEC);
/// Create a new entry, read-only and close on exec, and fail if it exists.
const CREATE_NEW: OFlags = READ_ONLY.union(OFlags::CREATE).union(OFlags::EXCL);

/// The directory where namespaces are pinned by name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkNamespaces {
    directory: PathBuf,
}

impl NetworkNamespaces {
    /// Namespaces pinned under `directory`.
    #[must_use]
    pub fn pinned_under(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Namespaces pinned under `/run/netns`, where iproute2 finds them.
    #[must_use]
    pub fn system() -> Self {
        Self::pinned_under("/run/netns")
    }

    /// The pin of namespace `name`.
    fn pin(&self, name: &NamespaceName) -> PathBuf {
        self.directory.join(name.as_str())
    }

    /// Create a new, empty network namespace pinned as `name`, and return a
    /// descriptor of it.
    ///
    /// # Errors
    /// Fails if an entry named `name` exists, or if the namespace cannot be
    /// created or pinned. A failure after the pin's file was created leaves
    /// it for [`NetworkNamespaces::delete`].
    pub fn create(&self, name: &NamespaceName) -> Result<OwnedFd, NetlinkError> {
        let pin = self.pin(name);
        mkdir(&self.directory, Mode::from_raw_mode(0o755))
            .or_else(|errno| (errno == Errno::EXIST).then_some(()).ok_or(errno))
            .and_then(|()| open(&pin, CREATE_NEW, Mode::empty()))
            .map_err(NetlinkError::from)
            .and_then(|_| {
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| pin_new_namespace(&pin))
                        .join()
                        .unwrap_or(Err(NetlinkError::Panicked))
                })
            })
    }

    /// A descriptor of namespace `name`, or `None` if nothing is pinned as
    /// `name`: no entry exists, or the entry is no namespace.
    ///
    /// # Errors
    /// Fails if the entry exists but cannot be opened or examined.
    pub fn open(&self, name: &NamespaceName) -> Result<Option<OwnedFd>, NetlinkError> {
        match open(self.pin(name), READ_ONLY, Mode::empty()) {
            Err(Errno::NOENT) => Ok(None),
            opened => opened
                .and_then(|file| {
                    fstatfs(&file).map(|filesystem| {
                        (i128::from(filesystem.f_type) == NSFS_MAGIC).then_some(file)
                    })
                })
                .map_err(NetlinkError::from),
        }
    }

    /// Every attempt namespace entry: each entry that is no directory and
    /// whose name [`NamespaceName::parse`] accepts. A missing directory holds
    /// none.
    ///
    /// # Errors
    /// Fails if the directory exists but cannot be read.
    pub fn attempt_names(&self) -> Result<Vec<NamespaceName>, NetlinkError> {
        match std::fs::read_dir(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            listed => listed
                .and_then(|entries| {
                    entries
                        .map(|entry| {
                            entry.and_then(|entry| {
                                entry.file_type().map(|kind| {
                                    entry
                                        .file_name()
                                        .to_str()
                                        .filter(|_| !kind.is_dir())
                                        .and_then(NamespaceName::parse)
                                })
                            })
                        })
                        .filter_map(Result::transpose)
                        .collect()
                })
                .map_err(|error| {
                    NetlinkError::Io(Errno::from_io_error(&error).unwrap_or(Errno::IO))
                }),
        }
    }

    /// Unpin namespace `name` and remove its entry, whichever of them
    /// exist. The namespace ends once nothing else holds it.
    ///
    /// # Errors
    /// Fails if an existing pin or entry cannot be removed.
    pub fn delete(&self, name: &NamespaceName) -> Result<(), NetlinkError> {
        let pin = self.pin(name);
        // `EINVAL`: the entry is not a mount point.
        unmount(&pin, UnmountFlags::DETACH)
            .or_else(|errno| absent(errno, &[Errno::INVAL, Errno::NOENT]))
            .and_then(|()| unlink(&pin).or_else(|errno| absent(errno, &[Errno::NOENT])))
            .map_err(NetlinkError::from)
    }
}

/// `Ok` if `errno` is one of `absent`, which report that nothing was there
/// to remove.
fn absent(errno: Errno, absent: &[Errno]) -> Result<(), Errno> {
    absent.contains(&errno).then_some(()).ok_or(errno)
}

/// Unshare the calling thread's network namespace, pin it at `pin`, and
/// return a descriptor of it.
fn pin_new_namespace(pin: &Path) -> Result<OwnedFd, NetlinkError> {
    unshare_network()
        .and_then(|()| mount_bind(THREAD_NAMESPACE, pin))
        .and_then(|()| open(THREAD_NAMESPACE, READ_ONLY, Mode::empty()))
        .map_err(NetlinkError::from)
}

/// Move the calling thread into a new network namespace.
#[expect(
    deprecated,
    reason = "rustix deprecates its safe `unshare` because `CLONE_FILES` can strand descriptors \
              that other threads hold; `CLONE_NEWNET` leaves the descriptor table shared, so this \
              call is sound (owner decision 2026-11-09, #911). Revisit at rustix 2.0, which \
              removes it."
)]
fn unshare_network() -> rustix::io::Result<()> {
    rustix::thread::unshare(UnshareFlags::NEWNET)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
