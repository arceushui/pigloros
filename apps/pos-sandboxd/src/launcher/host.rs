//! The launcher's environmental port and its one production adapter.
//!
//! Everything the launch barrier reads from or does to the surrounding system
//! goes through [`LaunchHost`], so the barrier is exercised in-process by a
//! test host against real sockets and files. [`ProcessHost`] is the only
//! production implementation and has no tunable state.

use std::{ffi::CString, fs::File, io, os::fd::OwnedFd};

use pos_reference::sandbox_provider_protocol::FdIdentity;
use rustix::fs::{open, Mode, OFlags};

use super::process_identity::{own_process_identity, peer_process_identity};
use super::{adapter::open_beneath, descriptors::scan_proc_self_fd, exec::replace_process_image};

const ROOT_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);

/// What the launch barrier needs from its surroundings.
pub(super) trait LaunchHost {
    /// The process identity of the launcher itself (from a pidfd it opens on itself).
    fn own_identity(&self) -> Option<FdIdentity>;
    /// The process identity (pidfs mount ID and inode) of the `SO_PEERPIDFD` of the release
    /// channel `release`, or `None` when the kernel gives no pidfd.
    fn peer_identity(&self, release: &OwnedFd) -> Option<FdIdentity>;
    /// Open descriptors at or above 3, without the one used to list them.
    fn open_descriptors(&self) -> io::Result<Vec<u32>>;
    /// The launcher's own executable image.
    fn open_launcher(&self) -> io::Result<File>;
    /// The adapter beneath the activated root, without symlink traversal.
    fn open_adapter(&self, path: &str) -> io::Result<File>;
    /// `CLOCK_MONOTONIC` in nanoseconds.
    fn monotonic_ns(&self) -> io::Result<u64>;
    /// Replace the process image with the held adapter; returns only on failure.
    fn replace_process(&self, adapter: &File, argv: &[CString]) -> io::Error;
}

/// The real process: the peer's pidfd, `/proc/self`, `/` and the real clock.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProcessHost;

impl LaunchHost for ProcessHost {
    fn own_identity(&self) -> Option<FdIdentity> {
        own_process_identity()
    }

    fn peer_identity(&self, release: &OwnedFd) -> Option<FdIdentity> {
        peer_process_identity(release)
    }

    fn open_descriptors(&self) -> io::Result<Vec<u32>> {
        scan_proc_self_fd()
    }

    fn open_launcher(&self) -> io::Result<File> {
        File::open("/proc/self/exe")
    }

    fn open_adapter(&self, path: &str) -> io::Result<File> {
        open("/", ROOT_FLAGS, Mode::empty())
            .map_err(io::Error::from)
            .and_then(|root| open_beneath(&root, path))
    }

    fn monotonic_ns(&self) -> io::Result<u64> {
        super::clock::monotonic_ns()
    }

    fn replace_process(&self, adapter: &File, argv: &[CString]) -> io::Error {
        replace_process_image(adapter, argv)
    }
}
