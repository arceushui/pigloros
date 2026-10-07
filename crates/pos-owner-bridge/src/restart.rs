//! Restart check of stale cleanup records (ADR-110 §16): probe by identity, never kill.

use std::time::Duration;

use pos_owner_bridge_codec::decode_cleanup_record;

use crate::{
    BridgeError, CleanupStore, MonotonicClock, ProbeResult, ProcessProbe, QuarantineCode,
    UnavailableCode,
};

/// The probe repeats at this interval while a recorded process is still present.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// The probe repeats this many times before the surface stays quarantined.
pub const PROBE_ATTEMPTS: u32 = 30;

fn clear(store: &mut dyn CleanupStore, folder_name: &str, record: &[u8]) -> bool {
    store.remove_folder(folder_name).is_ok() && store.delete_record(record).is_ok()
}

fn still_present(store: &mut dyn CleanupStore, probe: &mut dyn ProcessProbe, bytes: &[u8]) -> bool {
    let Ok(record) = decode_cleanup_record(bytes) else {
        return false;
    };
    let identity = (
        record.browser_pid(),
        record.creation_filetime(),
        record.image_path_sha256(),
    );
    match probe.probe(identity.0, identity.1, &identity.2) {
        ProbeResult::Present => true,
        ProbeResult::Absent => {
            clear(store, record.folder_name(), bytes);
            false
        }
    }
}

fn sweep(
    store: &mut dyn CleanupStore,
    probe: &mut dyn ProcessProbe,
    records: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    records
        .into_iter()
        .filter(|bytes| still_present(store, probe, bytes))
        .collect()
}

/// Probe every stored cleanup record by `(pid, creation time, image digest)`.
///
/// A record whose process is absent has its folder removed and itself deleted. While any
/// recorded process is present the probe repeats every second for 30 seconds.
///
/// # Errors
///
/// Returns `Quarantine(StaleProcessPresent)` when a recorded process is still present after
/// the repeats, and `Unavailable(InterfaceUnavailable)` when the store cannot be read.
pub fn restart_check(
    store: &mut dyn CleanupStore,
    probe: &mut dyn ProcessProbe,
    clock: &dyn MonotonicClock,
) -> Result<(), BridgeError> {
    let records = store.records().or(Err(BridgeError::Unavailable(
        UnavailableCode::InterfaceUnavailable,
    )))?;
    let mut present = sweep(store, probe, records);
    for _ in 0..PROBE_ATTEMPTS {
        if present.is_empty() {
            break;
        }
        clock.pause(PROBE_INTERVAL);
        present = sweep(store, probe, present);
    }
    if present.is_empty() {
        Ok(())
    } else {
        Err(BridgeError::Quarantine(QuarantineCode::StaleProcessPresent))
    }
}
