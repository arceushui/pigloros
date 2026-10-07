//! Host-side ports the bridge needs besides the surface: the listener view and cleanup storage.

use pos_owner_bridge_codec::{CeremonyId, ImagePathSha256};
use thiserror::Error;

use crate::BridgeError;

/// The listener's served count and integrity verdict for the current navigation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedSnapshot {
    /// Completed owner-document responses since the last navigation began.
    pub count: u32,
    /// Whether every completed response matched the pinned response digest.
    pub integrity_ok: bool,
}

/// What the ceremony driver needs from the loopback listener.
pub trait LoopbackPort {
    /// Reset the served count because a new navigation is about to begin.
    fn begin_navigation(&mut self);

    /// Return the served count and integrity verdict.
    fn served(&self) -> ServedSnapshot;

    /// Re-run the IPv6-absence probe.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable(LoopbackChanged)` when the IPv6 loopback is no longer absent.
    fn probe_ipv6(&mut self) -> Result<(), BridgeError>;
}

/// A cleanup-store failure. It carries no detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the cleanup store could not complete the operation")]
pub struct CleanupError;

/// Durable cleanup records and user-data folder removal, owned by the host application.
pub trait CleanupStore {
    /// Write one encoded cleanup record atomically and durably.
    ///
    /// # Errors
    ///
    /// Returns [`CleanupError`] when the record is not durable.
    fn write_record(&mut self, record: &[u8]) -> Result<(), CleanupError>;

    /// Delete the record previously written or listed with exactly these bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CleanupError`] when the record could not be deleted.
    fn delete_record(&mut self, record: &[u8]) -> Result<(), CleanupError>;

    /// List every encoded record that is still stored.
    ///
    /// # Errors
    ///
    /// Returns [`CleanupError`] when the store cannot be read.
    fn records(&mut self) -> Result<Vec<Vec<u8>>, CleanupError>;

    /// Remove one user-data folder by name; a sharing violation defers it to the next start.
    ///
    /// # Errors
    ///
    /// Returns [`CleanupError`] when the folder could not be removed.
    fn remove_folder(&mut self, folder_name: &str) -> Result<(), CleanupError>;
}

/// The verdict of one process-identity probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeResult {
    /// The process exists and its PID, creation time and image digest all match.
    Present,
    /// No such process, or its creation time or image differs.
    Absent,
}

/// Probes a recorded browser process by identity without enumerating, signalling or killing.
pub trait ProcessProbe {
    /// Probe `(pid, creation_filetime, image_path_sha256)`.
    fn probe(
        &mut self,
        browser_pid: u32,
        creation_filetime: u64,
        image_path_sha256: &ImagePathSha256,
    ) -> ProbeResult;
}

/// The collaborators the bridge owns besides its surface, randomness and clock.
pub struct HostPorts {
    /// The loopback listener view.
    pub loopback: Box<dyn LoopbackPort>,
    /// The cleanup-record store.
    pub store: Box<dyn CleanupStore>,
}

/// The lowercase hex folder name of `ceremony_id`.
#[must_use]
pub fn folder_name(ceremony_id: &CeremonyId) -> String {
    let mut name = String::with_capacity(32);
    for byte in ceremony_id.as_bytes() {
        name.push(hex_digit(byte >> 4));
        name.push(hex_digit(byte & 0x0f));
    }
    name
}

fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble), 16).unwrap_or('0')
}
