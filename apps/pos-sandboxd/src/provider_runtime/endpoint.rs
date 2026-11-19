//! The provider runtime's two SIC1 endpoints, bound under the ADR-069 §4.1
//! admin-socket rule (ADR-069 R11 §6, #1358).
//!
//! For each endpoint the runtime:
//! 1. opens every directory from `/` to the endpoint's parent beneath the
//!    one before it, and requires each to be a UID 0 directory with no group
//!    or other write bit and no symlink or magic link on the way;
//! 2. refuses an endpoint at or under `/run/pigloros/sandbox` (M4);
//! 3. requires that the leaf does not exist: the provider never unlinks a
//!    node it did not create;
//! 4. binds the listener, captures the new leaf's identity, re-validates the
//!    parent, `chmodat`s the leaf to `0600`, and requires a UID 0 socket of
//!    mode `0600` with the captured identity.
//!
//! Every accept is preceded and followed by the same parent and leaf check.
//! Dropping an endpoint removes its leaf only while the leaf still has its
//! own identity, so a replacement node is preserved.

use std::ffi::OsString;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use rustix::fs::{
    chmodat, openat2, statat, unlinkat, AtFlags, FileType, Mode, OFlags, ResolveFlags,
};

use super::{unavailable, unsafe_endpoint, ProviderRuntimeError};

/// The provider's own state directory, which no endpoint may enter (M4).
const SANDBOX_STATE: &str = "/run/pigloros/sandbox";
/// The mode of each bound leaf.
const LEAF_MODE: u32 = 0o600;
/// The group and other write bits.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

const DIRECTORY_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// One bound endpoint: its listener, its held parent and its leaf identity.
#[derive(Debug)]
pub(super) struct ProviderEndpoint {
    listener: UnixListener,
    parent: File,
    parent_path: PathBuf,
    leaf: OsString,
    identity: (u64, u64),
}

impl ProviderEndpoint {
    /// Bind `endpoint`, a SIC1 provider endpoint, under the §6 rules.
    ///
    /// # Errors
    /// `ReservedEndpoint` for an endpoint under `/run/pigloros/sandbox`,
    /// `UnsafeEndpoint` for an unsafe directory, an existing node or a leaf
    /// that fails its check, and `EndpointUnavailable` when the socket cannot
    /// be bound.
    pub(super) fn bind(endpoint: &Path) -> Result<Self, ProviderRuntimeError> {
        if endpoint.starts_with(SANDBOX_STATE) {
            return Err(ProviderRuntimeError::ReservedEndpoint);
        }
        endpoint
            .parent()
            .zip(endpoint.file_name())
            .ok_or(ProviderRuntimeError::UnsafeEndpoint)
            .and_then(|(parent_path, leaf)| {
                open_parent(parent_path).map(|parent| (parent, parent_path, leaf))
            })
            .and_then(|(parent, parent_path, leaf)| {
                if statat(&parent, leaf, AtFlags::SYMLINK_NOFOLLOW).err()
                    == Some(rustix::io::Errno::NOENT)
                {
                    UnixListener::bind(endpoint)
                        .map_err(unavailable)
                        .map(|listener| (listener, parent, parent_path, leaf))
                } else {
                    Err(ProviderRuntimeError::UnsafeEndpoint)
                }
            })
            .and_then(|(listener, parent, parent_path, leaf)| {
                // Without the new leaf's identity there is no safe basis for
                // removing it again: a node that cannot be identified stays.
                leaf_socket(&parent, leaf).map(|(identity, _)| Self {
                    listener,
                    parent,
                    parent_path: parent_path.to_path_buf(),
                    leaf: leaf.to_os_string(),
                    identity,
                })
            })
            .and_then(|bound| bound.verify_parent().map(|()| bound))
            .and_then(|bound| {
                chmodat(
                    &bound.parent,
                    &bound.leaf,
                    Mode::from_raw_mode(LEAF_MODE),
                    AtFlags::empty(),
                )
                .map_err(unsafe_endpoint)
                .map(|()| bound)
            })
            .and_then(|bound| bound.verify().map(|()| bound))
            .and_then(|bound| {
                bound
                    .listener
                    .set_nonblocking(true)
                    .map_err(unavailable)
                    .map(|()| bound)
            })
    }

    /// The listener, for readiness polling.
    pub(super) const fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Require the held parent to still be the directory at its path, and
    /// the leaf to be this endpoint's UID 0 socket of mode `0600`.
    ///
    /// # Errors
    /// `UnsafeEndpoint` when either has changed.
    pub(super) fn verify(&self) -> Result<(), ProviderRuntimeError> {
        self.verify_parent().and_then(|()| {
            leaf_socket(&self.parent, &self.leaf).and_then(|(identity, mode)| {
                if identity == self.identity && mode == LEAF_MODE {
                    Ok(())
                } else {
                    Err(ProviderRuntimeError::UnsafeEndpoint)
                }
            })
        })
    }

    fn verify_parent(&self) -> Result<(), ProviderRuntimeError> {
        self.parent
            .metadata()
            .map_err(unsafe_endpoint)
            .and_then(|held| {
                std::fs::symlink_metadata(&self.parent_path)
                    .map_err(unsafe_endpoint)
                    .map(|named| (held, named))
            })
            .and_then(|(held, named)| {
                if safe_directory(&held)
                    && named.is_dir()
                    && (held.dev(), held.ino()) == (named.dev(), named.ino())
                {
                    Ok(())
                } else {
                    Err(ProviderRuntimeError::UnsafeEndpoint)
                }
            })
    }

    /// Accept one pending connection, checking the endpoint before the
    /// accept and again after it, before any byte is read.
    ///
    /// # Errors
    /// `UnsafeEndpoint` when either check fails.
    pub(super) fn accept(&self) -> Result<Option<UnixStream>, ProviderRuntimeError> {
        self.verify().and_then(|()| {
            // A spurious wake-up or a connection that was reset before the
            // accept yields nothing; the next readiness tries again.
            let accepted = self.listener.accept().ok().map(|(stream, _)| stream);
            self.verify().map(|()| accepted)
        })
    }
}

impl Drop for ProviderEndpoint {
    fn drop(&mut self) {
        let own = leaf_socket(&self.parent, &self.leaf)
            .is_ok_and(|(identity, _)| identity == self.identity);
        if own {
            unlinkat(&self.parent, &self.leaf, AtFlags::empty()).ok();
        }
    }
}

/// Bind the execute endpoint, then the control endpoint. If the second bind
/// fails, the first leaf is removed again under its identity check.
///
/// # Errors
/// The first bind's failure.
pub(super) fn bind_endpoints(
    execute: &Path,
    control: &Path,
) -> Result<(ProviderEndpoint, ProviderEndpoint), ProviderRuntimeError> {
    ProviderEndpoint::bind(execute)
        .and_then(|execute| ProviderEndpoint::bind(control).map(|control| (execute, control)))
}

/// Open `parent` from `/` one component at a time, each beneath the last.
fn open_parent(parent: &Path) -> Result<File, ProviderRuntimeError> {
    parent
        .strip_prefix("/")
        .map_err(unsafe_endpoint)
        .and_then(|below_root| {
            rustix::fs::open("/", DIRECTORY_OPEN, Mode::empty())
                .map(File::from)
                .map_err(unsafe_endpoint)
                .and_then(require_safe_directory)
                .and_then(|root| {
                    below_root.iter().try_fold(root, |directory, name| {
                        openat2(&directory, name, DIRECTORY_OPEN, Mode::empty(), RESOLVE)
                            .map(File::from)
                            .map_err(unsafe_endpoint)
                            .and_then(require_safe_directory)
                    })
                })
        })
}

fn require_safe_directory(directory: File) -> Result<File, ProviderRuntimeError> {
    directory
        .metadata()
        .ok()
        .filter(safe_directory)
        .map(|_| directory)
        .ok_or(ProviderRuntimeError::UnsafeEndpoint)
}

fn safe_directory(metadata: &std::fs::Metadata) -> bool {
    metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & GROUP_OR_OTHER_WRITE == 0
}

/// The identity and permission bits of `leaf` beneath `parent`, which must
/// be a UID 0 socket.
fn leaf_socket(
    parent: &File,
    leaf: &std::ffi::OsStr,
) -> Result<((u64, u64), u32), ProviderRuntimeError> {
    statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(unsafe_endpoint)
        .and_then(|metadata| {
            if FileType::from_raw_mode(metadata.st_mode) == FileType::Socket && metadata.st_uid == 0
            {
                Ok((
                    (metadata.st_dev, metadata.st_ino),
                    metadata.st_mode & 0o7777,
                ))
            } else {
                Err(ProviderRuntimeError::UnsafeEndpoint)
            }
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
