//! Host-side ports the bridge needs besides the surface: the listener view and cleanup storage.

use pos_owner_bridge_codec::{
    encode_cleanup_record, CeremonyId, CleanupRecordV1, ImagePathSha256, MAX_CLEANUP_RECORD_BYTES,
};
use thiserror::Error;

use crate::ceremony::driver::CeremonyDriver;
use crate::ceremony::plan::Verified;
use crate::{BridgeError, ProcessIdentity, UnavailableCode};

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

    /// List the ceremony user-data folders that exist on disk, whether or not a record names them.
    ///
    /// Only folders the bridge's own scheme created count: names that are not a lowercase hex
    /// ceremony ID (see [`folder_name`]) are ignored by the restart check.
    ///
    /// # Errors
    ///
    /// Returns [`CleanupError`] when the folders cannot be listed.
    fn folders(&mut self) -> Result<Vec<String>, CleanupError>;

    /// Remove one user-data folder by name; a sharing violation defers it to the next start.
    ///
    /// The name is always a lowercase hex ceremony ID that the bridge derived itself, but an
    /// implementation must still resolve it strictly under its own base folder and never follow
    /// a path out of it. Removing a folder that does not exist succeeds: a record whose folder
    /// is already gone must be able to clear, and an implementation that fails on a missing
    /// folder only defers that record to every later start.
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

/// What a host returns after running one ceremony.
///
/// The driver comes back with its slots (the bridge reads the PRF from them, then wipes them),
/// except when the ceremony ended in quarantine: the host keeps that driver and hands it back
/// from [`CeremonyHost::poll_quarantine`] once cleanup finished.
pub struct CeremonyReply {
    /// The ceremony's result.
    pub result: Result<Verified, BridgeError>,
    /// The finished driver, unless it is quarantined.
    pub driver: Option<CeremonyDriver>,
}

/// What polling the quarantined ceremonies returns.
#[derive(Default)]
pub struct QuarantinePoll {
    /// A driver whose browser exit and cleanup finished, if one did.
    pub driver: Option<CeremonyDriver>,
    /// Whether the host still holds another quarantined driver, whose browser may be alive.
    pub remaining: bool,
}

/// The surface thread's bookkeeping for quarantined ceremonies.
///
/// It keeps each driver until its cleanup finished, so every host applies the same policy: a
/// quarantined driver never returns to the owner thread before its browser exit and `finish()`
/// are done. The bridge starts no ceremony while one is quarantined, so more than one driver is
/// a host bug; the keeper still holds every one of them, because each may have a live browser.
#[derive(Default)]
pub struct QuarantineKeeper {
    held: Vec<CeremonyDriver>,
}

impl QuarantineKeeper {
    /// An empty keeper.
    #[must_use]
    pub const fn new() -> Self {
        Self { held: Vec::new() }
    }

    /// Turn a finished driver and its result into the reply for the owner thread; a driver that
    /// ended in quarantine stays here.
    pub fn finish(
        &mut self,
        driver: CeremonyDriver,
        result: Result<Verified, BridgeError>,
    ) -> CeremonyReply {
        let quarantined = matches!(result, Err(BridgeError::Quarantine(_)));
        let returned = if quarantined {
            self.held.push(driver);
            None
        } else {
            Some(driver)
        };
        CeremonyReply {
            result,
            driver: returned,
        }
    }

    /// Run `cleaned` (typically `CeremonyDriver::poll_cleanup` with the host's `StepEnv`) on each
    /// kept driver and hand back the first one that reports its cleanup finished, with whether
    /// any other driver is still kept.
    pub fn poll(&mut self, mut cleaned: impl FnMut(&mut CeremonyDriver) -> bool) -> QuarantinePoll {
        let driver = self
            .held
            .iter_mut()
            .position(&mut cleaned)
            .map(|index| self.held.remove(index));
        QuarantinePoll {
            driver,
            remaining: !self.held.is_empty(),
        }
    }
}

/// The host side of the ceremony hand-off (ADR-110 §1a, §6, §10).
///
/// The host owns the surface and the driver on its surface thread. The bridge, on the owner
/// thread, builds a driver and hands it over; the host moves it to the surface thread, calls
/// [`CeremonyDriver::step`] from its timer and surface-event callbacks until the driver finishes,
/// and replies. `OwnerBridge::enroll` and `unlock` block only inside [`CeremonyHost::run`]
/// (the owner thread blocks on a reply channel); the portable core itself never sleeps. The
/// crate's `ChannelHost` is the owner-side half of a bounded channel hand-off a host can use.
pub trait CeremonyHost {
    /// Run `driver` to the end and return its result.
    fn run(&mut self, driver: CeremonyDriver) -> CeremonyReply;

    /// Poll the quarantined ceremonies for their browser exit. The result carries a driver once
    /// its cleanup finished, and says whether another quarantined driver is still held: the
    /// bridge stays quarantined until none is.
    fn poll_quarantine(&mut self) -> QuarantinePoll;
}

/// Encode the cleanup record that precedes buffer creation (ADR-110 §16).
///
/// # Errors
///
/// Returns `Unavailable(InterfaceUnavailable)` when the record cannot be encoded: a ceremony
/// must not continue without its durable record.
pub fn cleanup_record_bytes(
    ceremony_id: CeremonyId,
    folder_name: &str,
    identity: &ProcessIdentity,
) -> Result<Vec<u8>, BridgeError> {
    let mut buffer = [0_u8; MAX_CLEANUP_RECORD_BYTES];
    let unavailable = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
    let length = CleanupRecordV1::new(
        ceremony_id,
        folder_name,
        identity.browser_pid,
        identity.creation_filetime,
        identity.image_path_sha256,
    )
    .and_then(|record| encode_cleanup_record(&record, &mut buffer))
    .or(Err(unavailable))?;
    Ok(buffer.split_at(length.min(buffer.len())).0.to_vec())
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
    let digit = if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' - 10 + nibble
    };
    char::from(digit)
}
