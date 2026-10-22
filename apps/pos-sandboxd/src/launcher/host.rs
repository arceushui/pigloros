//! The launcher's environmental port and its one production adapter.
//!
//! Everything the launch barrier reads from or does to the surrounding system
//! goes through [`LaunchHost`], so the barrier is exercised in-process by a
//! test host against real sockets and files. [`ProcessHost`] is the only
//! production implementation and has no tunable state.

use std::{ffi::CString, fs::File, io};

use rustix::{
    fs::{open, Mode, OFlags},
    time::{clock_gettime, ClockId},
};

use super::{adapter::open_beneath, descriptors::scan_proc_self_fd, exec::replace_process_image};

const ROOT_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// What the launch barrier needs from its surroundings.
pub(super) trait LaunchHost {
    /// The uid `SO_PEERCRED` must report for the release channel peer.
    fn provider_uid(&self) -> u32;
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

/// The real process: a provider peer of the given uid, `/proc/self`, `/` and
/// the real clock.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProcessHost {
    pub(super) provider_uid: u32,
}

impl ProcessHost {
    /// The production host: the provider is root.
    pub(super) const fn root() -> Self {
        Self { provider_uid: 0 }
    }
}

impl LaunchHost for ProcessHost {
    fn provider_uid(&self) -> u32 {
        self.provider_uid
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
        let now = clock_gettime(ClockId::Monotonic);
        let seconds = u64::try_from(now.tv_sec).unwrap_or_default();
        let nanoseconds = u64::try_from(now.tv_nsec).unwrap_or_default();
        Ok(seconds
            .saturating_mul(NANOSECONDS_PER_SECOND)
            .saturating_add(nanoseconds))
    }

    fn replace_process(&self, adapter: &File, argv: &[CString]) -> io::Error {
        replace_process_image(adapter, argv)
    }
}
