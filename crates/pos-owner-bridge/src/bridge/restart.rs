//! Restart check of stale cleanup records (ADR-110 §16): probe by identity, never kill.
//!
//! The check is a non-blocking state machine, because the portable core never sleeps. `begin`
//! makes the first pass over the stored records. While a recorded process is still present the
//! host calls `poll` once per [`PROBE_INTERVAL`], at the instant `wake` reports, for at most
//! [`PROBE_ATTEMPTS`] repeats. It must run before any ceremony starts: the orphan-folder sweep
//! of the first pass would otherwise remove the folder of a live ceremony.

use std::time::{Duration, Instant};

use pos_owner_bridge_codec::{decode_cleanup_record, ImagePathSha256};

use crate::{
    folder_name, BridgeError, CleanupStore, ProbeResult, ProcessProbe, QuarantineCode,
    UnavailableCode,
};

/// The probe repeats at this interval while a recorded process is still present.
pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// The probe repeats this many times before the surface stays quarantined.
pub(super) const PROBE_ATTEMPTS: u32 = 30;

const STALE: BridgeError = BridgeError::Quarantine(QuarantineCode::StaleProcessPresent);

/// One decoded, validated cleanup record: the identity to probe and the folder to remove.
#[derive(Debug)]
struct Entry {
    bytes: Vec<u8>,
    browser_pid: u32,
    creation_filetime: u64,
    image_path_sha256: ImagePathSha256,
    folder: String,
}

/// Decode `bytes` once. A record is valid only when its folder name is exactly the one the
/// bridge derives from its ceremony ID, so a stored record can never make the bridge remove a
/// path of its choosing; anything else counts as an unreadable record.
fn parse(bytes: Vec<u8>) -> Option<Entry> {
    let (browser_pid, creation_filetime, image_path_sha256, folder, id) = {
        let record = decode_cleanup_record(&bytes).ok()?;
        (
            record.browser_pid(),
            record.creation_filetime(),
            record.image_path_sha256(),
            record.folder_name().to_owned(),
            record.ceremony_id(),
        )
    };
    (folder == folder_name(&id)).then_some(Entry {
        bytes,
        browser_pid,
        creation_filetime,
        image_path_sha256,
        folder,
    })
}

/// What one pass over the entries found.
#[derive(Debug, Default)]
struct Sweep {
    /// Entries whose process is still present, kept for the next pass.
    present: Vec<Entry>,
    /// Entries whose process is absent but whose folder or record could not be removed yet.
    deferred: usize,
}

fn clear(store: &mut dyn CleanupStore, entry: &Entry) -> bool {
    store.remove_folder(&entry.folder).is_ok() && store.delete_record(&entry.bytes).is_ok()
}

fn sweep(store: &mut dyn CleanupStore, probe: &mut dyn ProcessProbe, entries: Vec<Entry>) -> Sweep {
    let mut found = Sweep::default();
    for entry in entries {
        let verdict = probe.probe(
            entry.browser_pid,
            entry.creation_filetime,
            &entry.image_path_sha256,
        );
        match verdict {
            ProbeResult::Present => found.present.push(entry),
            ProbeResult::Absent => found.deferred += usize::from(!clear(store, &entry)),
        }
    }
    found
}

/// A restart check that is waiting for a recorded process to exit.
#[derive(Debug)]
pub(super) struct Pending {
    present: Vec<Entry>,
    deferred: usize,
    repeats: u32,
    wake: Instant,
}

impl Pending {
    /// When the next probe is due.
    pub(super) const fn wake(&self) -> Instant {
        self.wake
    }
}

/// The result of one `begin` or `poll`.
#[derive(Debug)]
pub(super) enum Progress {
    /// Every recorded process is gone; this many cleanups are deferred to the next start.
    Done(usize),
    /// A recorded process is still present.
    Waiting(Pending),
}

fn settle(present: Vec<Entry>, deferred: usize, repeats: u32, now: Instant) -> Progress {
    if present.is_empty() {
        Progress::Done(deferred)
    } else {
        Progress::Waiting(Pending {
            present,
            deferred,
            repeats,
            wake: now + PROBE_INTERVAL,
        })
    }
}

/// Whether `name` is a ceremony user-data folder name: the lowercase hex of a 16-byte ID.
fn is_ceremony_folder(name: &str) -> bool {
    name.len() == 32
        && name
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Remove the ceremony folders that no record names and return how many could not be removed.
///
/// A folder without a record never held a shared buffer, because the record precedes buffer
/// creation (ADR-110 §16), so it holds no ceremony bytes. A sharing violation defers its removal
/// to the next start.
fn sweep_orphans(store: &mut dyn CleanupStore, folders: &[String], named: &[&str]) -> usize {
    folders
        .iter()
        .filter(|name| is_ceremony_folder(name) && !named.contains(&name.as_str()))
        .filter(|name| store.remove_folder(name).is_err())
        .count()
}

/// Probe every stored cleanup record by `(pid, creation time, image digest)` once.
///
/// A record whose process is absent has its folder removed and itself deleted. A ceremony folder
/// that no record names is removed too.
///
/// Policy for the cases the ADR leaves open, all fail-closed or visible:
///
/// - A record that cannot be decoded, or whose folder name is not the one derived from its
///   ceremony ID, names no process or path the bridge can trust. It is left in the store and the
///   check ends at once, before anything is removed, with `Quarantine(StaleProcessPresent)`; the
///   host application must inspect and delete it.
/// - When a folder or record of an absent process cannot be removed (a sharing violation is the
///   expected cause), the record stays in the store for the next start, which retries it. That
///   never blocks a fresh ceremony, because every ceremony uses a new folder name. The count of
///   those deferred records is reported so the host can log them.
/// - When the folders cannot be listed, the orphan sweep is skipped for this pass and counted as
///   one deferred removal; the surface stays usable, as §16 requires of the sweep. The sweep runs
///   only in this first pass.
///
/// # Errors
///
/// Returns `Quarantine(StaleProcessPresent)` when a record is unreadable, and
/// `Unavailable(InterfaceUnavailable)` when the store cannot list its records.
pub(super) fn begin(
    store: &mut dyn CleanupStore,
    probe: &mut dyn ProcessProbe,
    now: Instant,
) -> Result<Progress, BridgeError> {
    let records = store.records().or(Err(BridgeError::Unavailable(
        UnavailableCode::InterfaceUnavailable,
    )))?;
    let entries = records
        .into_iter()
        .map(parse)
        .collect::<Option<Vec<Entry>>>()
        .ok_or(STALE)?;
    let named: Vec<String> = entries.iter().map(|entry| entry.folder.clone()).collect();
    let named: Vec<&str> = named.iter().map(String::as_str).collect();
    let orphans = store
        .folders()
        .map_or(1, |folders| sweep_orphans(store, &folders, &named));
    let first = sweep(store, probe, entries);
    Ok(settle(first.present, first.deferred + orphans, 0, now))
}

/// Probe the records whose process was still present, if the next probe is due at `now`.
///
/// # Errors
///
/// Returns `Quarantine(StaleProcessPresent)` once a recorded process is still present after
/// [`PROBE_ATTEMPTS`] repeats.
pub(super) fn poll(
    pending: Pending,
    store: &mut dyn CleanupStore,
    probe: &mut dyn ProcessProbe,
    now: Instant,
) -> Result<Progress, BridgeError> {
    if now < pending.wake {
        return Ok(Progress::Waiting(pending));
    }
    let next = sweep(store, probe, pending.present);
    let (deferred, repeats) = (pending.deferred + next.deferred, pending.repeats + 1);
    if !next.present.is_empty() && repeats >= PROBE_ATTEMPTS {
        return Err(STALE);
    }
    Ok(settle(next.present, deferred, repeats, now))
}
