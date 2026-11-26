//! The Linux hidraw `HidTransport` (ADR-110 E20 LS2, LS5): safe Rust, no ioctl.
//!
//! Discovery lists `/sys/class/hidraw/`, reads each `device/report_descriptor` and keeps the nodes
//! whose first application collection is usage page `0xF1D0`, usage `0x01`. Exactly one such
//! node must exist: none, or several, is `Lifecycle(ClientFailed)` before any CTAP command. A
//! descriptor that cannot be read refuses that device. The node is opened `O_RDWR | O_CLOEXEC |
//! O_NONBLOCK`; a 64-byte output report is written as 65 bytes (report ID 0 first), a 64-byte
//! input report is read, and `poll` bounds every wait. A removed device is a transport failure.

use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pos_owner_bridge::{BridgeError, LifecycleCode};
use rustix::fs::{openat, Mode, OFlags, CWD};
use rustix::io::{read, write};

use crate::fdwait::{wait_readable, Wait};
use crate::hid::{HidTransport, TransportError, REPORT_BYTES};

/// How a hidraw node is opened.
const OPEN_FLAGS: OFlags = OFlags::RDWR.union(OFlags::CLOEXEC).union(OFlags::NONBLOCK);

/// Where the kernel lists hidraw devices.
pub const SYSFS_HIDRAW: &str = "/sys/class/hidraw";

/// Where the hidraw nodes live.
pub const DEV_DIR: &str = "/dev";

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const FRAME_BYTES: usize = REPORT_BYTES + 1;
const FIDO_USAGE_PAGE: u32 = 0xf1d0;
const FIDO_USAGE: u32 = 0x01;
const COLLECTION_APPLICATION: u32 = 0x01;
const TAG_MASK: u8 = 0xfc;
const TAG_USAGE_PAGE: u8 = 0x04;
const TAG_USAGE: u8 = 0x08;
const TAG_COLLECTION: u8 = 0xa0;
const LONG_ITEM: u8 = 0xfe;
const DATA_BYTES: [usize; 4] = [0, 1, 2, 4];

/// Whether a HID report descriptor opens a FIDO application collection.
///
/// It reads the short items up to the first collection: the collection must be an application
/// collection, with the last usage page `0xF1D0` and the last usage `0x01` before it. A
/// truncated descriptor, a long item or no collection is not FIDO.
#[must_use]
pub fn is_fido_descriptor(descriptor: &[u8]) -> bool {
    let (mut page, mut usage) = (0, 0);
    let mut rest = descriptor;
    while let Some((&prefix, tail)) = rest.split_first() {
        let size = DATA_BYTES[usize::from(prefix & 0x03)];
        let Some((data, next)) = tail.split_at_checked(size) else {
            return false;
        };
        if prefix == LONG_ITEM {
            return false;
        }
        let mut word = [0; 4];
        word[..size].copy_from_slice(data);
        let value = u32::from_le_bytes(word);
        match prefix & TAG_MASK {
            TAG_USAGE_PAGE => page = value,
            TAG_USAGE => usage = value,
            TAG_COLLECTION => {
                return page == FIDO_USAGE_PAGE
                    && usage == FIDO_USAGE
                    && value == COLLECTION_APPLICATION;
            }
            _ => {}
        }
        rest = next;
    }
    false
}

/// Find the one FIDO hidraw node: `sysfs` lists the devices and `dev` holds their nodes.
///
/// # Errors
///
/// Returns `Lifecycle(ClientFailed)` when `sysfs` cannot be listed, when listing it fails on any
/// entry, and when it lists no FIDO device or more than one. A device whose descriptor cannot be
/// read is not a FIDO device, and only that device is skipped.
pub fn discover(sysfs: &Path, dev: &Path) -> Result<PathBuf, BridgeError> {
    let mut found = None;
    let entries = fs::read_dir(sysfs)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .or(Err(CLIENT_FAILED))?;
    for entry in entries {
        let descriptor = fs::read(entry.path().join("device").join("report_descriptor"));
        if descriptor.is_ok_and(|bytes| is_fido_descriptor(&bytes)) {
            if found.is_some() {
                return Err(CLIENT_FAILED);
            }
            found = Some(dev.join(entry.file_name()));
        }
    }
    found.ok_or(CLIENT_FAILED)
}

/// One FIDO HID device behind a hidraw node.
pub struct HidrawTransport {
    fd: OwnedFd,
}

impl HidrawTransport {
    /// Find the one FIDO device listed under `sysfs` and open its node under `dev`.
    ///
    /// The owner root passes [`SYSFS_HIDRAW`] and [`DEV_DIR`].
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` when there is not exactly one FIDO device, and when the
    /// node cannot be opened, as for a user without access to it (ADR-110 E20 LT2).
    pub fn open_in(sysfs: &Path, dev: &Path) -> Result<Self, BridgeError> {
        let node = discover(sysfs, dev)?;
        Self::open_node(&node).map_err(BridgeError::from)
    }

    /// Open the hidraw node `node`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when the node cannot be opened.
    pub fn open_node(node: &Path) -> Result<Self, TransportError> {
        openat(CWD, node, OPEN_FLAGS, Mode::empty())
            .map(Self::from_fd)
            .or(Err(TransportError))
    }

    /// Use `fd`, which moves 64-byte reports like a hidraw node: a write takes the report ID
    /// byte and the report, and a read returns one report.
    #[must_use]
    pub const fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }
}

impl HidTransport for HidrawTransport {
    fn write_report(&mut self, report: &[u8; REPORT_BYTES]) -> Result<(), TransportError> {
        let mut frame = [0; FRAME_BYTES];
        frame[1..].copy_from_slice(report);
        write(&self.fd, &frame)
            .ok()
            .filter(|written| *written == FRAME_BYTES)
            .map(|_| ())
            .ok_or(TransportError)
    }

    fn read_report(
        &mut self,
        report: &mut [u8; REPORT_BYTES],
        timeout: Duration,
    ) -> Result<bool, TransportError> {
        match wait_readable(&self.fd, timeout) {
            Wait::Idle => Ok(false),
            Wait::Gone => Err(TransportError),
            Wait::Readable => read(&self.fd, &mut report[..])
                .ok()
                .filter(|received| *received == REPORT_BYTES)
                .map(|_| true)
                .ok_or(TransportError),
        }
    }
}
