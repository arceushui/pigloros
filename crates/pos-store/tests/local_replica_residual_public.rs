//! Public-seam proof of the `local-replica` residual-bytes purge (ADR-136 F1,
//! Redmine #1406).
//!
//! Each scenario writes known markers, deletes them through
//! `EventStore::delete_timeline`, purges through
//! `LocalReplicaResidualPortV1`, and then scans the raw bytes of the database
//! file and its `-wal` and `-shm` files. Control scans show that every
//! marker really was on disk before the purge: first in the write-ahead log
//! only, then in the database file after a checkpoint, and still there after
//! the delete. Each marker fits inside one page, so a page or frame boundary
//! cannot split it.
#![cfg(feature = "sqlite")]

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pos_core::store::{EventStore, SeqRange};
use pos_core::{
    CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureErrorV1, EventDraft, Kind,
    LocalReplicaResidualPortV1, TimelineId,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::{SqliteStore, SqliteStoreOpenOptionsV1};
use tempfile::TempDir;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// Width of every payload marker.
const MARKER_BYTES: usize = 64;
/// The repeated unit of the overflow payload. Any surviving fragment of the
/// payload longer than twice its width contains a whole copy.
const OVERFLOW_UNIT: &[u8; 16] = b"F1-OVERFLOW-UNIT";
/// Copies of the unit: a 12,288-byte payload spread over a leaf cell and
/// three 4,096-byte overflow pages.
const OVERFLOW_UNITS: usize = 768;
/// Copies the controls may miss: one split at each of the 3 boundaries
/// between the leaf cell and the three overflow pages, plus 1 copy that a
/// freelist-trunk header can overwrite when the deletion frees those pages.
const OVERFLOW_SPLIT_SLACK: usize = 4;
/// Index scenario: rounds of one victim batch and one kept batch each.
const INDEX_ROUNDS: usize = 10;
/// Events per batch in the index scenario.
const INDEX_BATCH: usize = 100;
/// A blocked checkpoint fails fast instead of waiting four seconds.
const SHORT_BUSY: Duration = Duration::from_millis(50);
/// The database file, its write-ahead log and its shared-memory index.
const ALL_FILES: [&str; 3] = ["", "-wal", "-shm"];

const POSITIVE: Result<(), ErasureErrorV1> = Ok(());
const NEGATIVE: Result<(), ErasureErrorV1> = Err(ErasureErrorV1::ReplicaNegativeAcknowledgement);
const TIMEOUT: Result<(), ErasureErrorV1> = Err(ErasureErrorV1::ReplicaTimeout);

struct Replica {
    _dir: TempDir,
    path: PathBuf,
    store: SqliteStore,
}

impl Replica {
    fn open() -> Fallible<Self> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("replica.sqlite");
        let mut store = SqliteStore::open_with_options(
            path.to_str().ok_or("utf-8 path")?,
            SqliteStoreOpenOptionsV1 {
                busy_timeout: SHORT_BUSY,
            },
        )?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        Ok(Self {
            _dir: dir,
            path,
            store,
        })
    }

    /// Create the victim and kept Timelines, then purge once so that the
    /// write-ahead log is empty before any marker is written.
    fn timelines(&mut self) -> Fallible<(TimelineId, TimelineId)> {
        let victim = self.store.create_timeline("f1-victim")?.id();
        let keep = self.store.create_timeline("f1-keep")?.id();
        assert_eq!(self.store.purge_local_replica_residue(), POSITIVE);
        assert_eq!(self.wal_len()?, 0);
        Ok((victim, keep))
    }

    fn file(&self, suffix: &str) -> PathBuf {
        let mut name = OsString::from(self.path.as_os_str());
        name.push(suffix);
        PathBuf::from(name)
    }

    fn wal_len(&self) -> Fallible<u64> {
        Ok(std::fs::metadata(self.file("-wal"))?.len())
    }

    /// Occurrences of each marker in the named files. Every marker has the
    /// same width, and every named file must exist.
    fn occurrences(
        &self,
        suffixes: &[&str],
        markers: &[Vec<u8>],
    ) -> Fallible<HashMap<Vec<u8>, usize>> {
        let width = markers.first().map_or(1, Vec::len).max(1);
        assert!(markers.iter().all(|marker| marker.len() == width));
        let wanted: HashSet<&[u8]> = markers.iter().map(Vec::as_slice).collect();
        let mut counts = HashMap::new();
        for suffix in suffixes {
            let bytes = std::fs::read(self.file(suffix))?;
            for window in bytes.windows(width) {
                if wanted.contains(window) {
                    *counts.entry(window.to_vec()).or_insert(0) += 1;
                }
            }
        }
        Ok(counts)
    }

    /// Control: every marker occurs, at least `minimum` times in total.
    fn assert_on_disk(
        &self,
        suffixes: &[&str],
        markers: &[Vec<u8>],
        minimum: usize,
        control: &str,
    ) -> Fallible<()> {
        let counts = self.occurrences(suffixes, markers)?;
        assert_eq!(counts.len(), markers.len(), "{control}: every marker");
        assert!(
            counts.values().sum::<usize>() >= minimum,
            "{control}: copies"
        );
        Ok(())
    }

    /// The shared proof: controls before the purge, none of the markers after.
    fn prove_purged(
        &mut self,
        victim: TimelineId,
        keep: TimelineId,
        markers: &[Vec<u8>],
        minimum: usize,
    ) -> Fallible<()> {
        self.assert_on_disk(&["-wal"], markers, minimum, "write-ahead log only")?;
        assert_eq!(self.store.purge_local_replica_residue(), POSITIVE);
        assert_eq!(self.wal_len()?, 0);
        self.assert_on_disk(&[""], markers, minimum, "database file after checkpoint")?;
        let kept = self.store.read(keep, SeqRange::all())?.len();
        self.store.delete_timeline(victim)?;
        self.assert_on_disk(&ALL_FILES, markers, minimum, "after deletion")?;
        assert_eq!(self.store.purge_local_replica_residue(), POSITIVE);
        assert!(self.occurrences(&ALL_FILES, markers)?.is_empty());
        assert_eq!(self.wal_len()?, 0);
        assert_eq!(self.store.read(keep, SeqRange::all())?.len(), kept);
        Ok(())
    }
}

fn marker(tag: &str, index: usize) -> Vec<u8> {
    let mut bytes = format!("{tag}-{index:010}-").into_bytes();
    bytes.resize(MARKER_BYTES, b'~');
    bytes
}

fn draft(payload: Vec<u8>) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new("world.test"),
        CanonicalBytes::from_vec(payload),
    )
}

#[test]
fn a_deleted_small_payload_leaves_no_residual_bytes() -> Fallible<()> {
    let mut replica = Replica::open()?;
    let (victim, keep) = replica.timelines()?;
    let deleted = marker("F1-SMALL", 0);
    replica.store.append(victim, &[draft(deleted.clone())])?;
    replica.store.append(keep, &[draft(marker("F1-KEPT", 0))])?;
    let markers = [deleted];
    replica.prove_purged(victim, keep, &markers, markers.len())?;
    Ok(())
}

#[test]
fn a_deleted_overflow_payload_leaves_no_residual_bytes() -> Fallible<()> {
    let mut replica = Replica::open()?;
    let (victim, keep) = replica.timelines()?;
    replica
        .store
        .append(victim, &[draft(OVERFLOW_UNIT.repeat(OVERFLOW_UNITS))])?;
    replica
        .store
        .append(keep, &[draft(b"F1-KEPT-OVERFLOW".repeat(OVERFLOW_UNITS))])?;
    let markers = [OVERFLOW_UNIT.to_vec()];
    let minimum = OVERFLOW_UNITS - OVERFLOW_SPLIT_SLACK;
    replica.prove_purged(victim, keep, &markers, minimum)?;
    Ok(())
}

#[test]
fn deleted_index_keys_leave_no_residual_bytes() -> Fallible<()> {
    let mut replica = Replica::open()?;
    let (victim, keep) = replica.timelines()?;
    // Event ids are keys of the unique `event_id` index, and the Timeline id
    // is the leading key of the primary-key index. Interleaved batches make
    // the victim keys share index pages with live keys.
    let mut markers = vec![victim.to_string().into_bytes()];
    for round in 0..INDEX_ROUNDS {
        let batch = |tag: &str| -> Vec<EventDraft> {
            (0..INDEX_BATCH)
                .map(|index| draft(marker(tag, round * INDEX_BATCH + index)))
                .collect()
        };
        let appended = replica.store.append(victim, &batch("F1-INDEX"))?;
        markers.extend(
            appended
                .iter()
                .map(|event| event.id.to_string().into_bytes()),
        );
        replica.store.append(keep, &batch("F1-KEPT"))?;
    }
    assert_eq!(markers.len(), 1 + INDEX_ROUNDS * INDEX_BATCH);
    replica.prove_purged(victim, keep, &markers, markers.len())?;
    Ok(())
}

#[test]
fn a_writer_holding_the_store_is_a_transient_timeout() -> Fallible<()> {
    let mut replica = Replica::open()?;
    replica.timelines()?;
    let writer = rusqlite::Connection::open(&replica.path)?;
    writer.execute_batch("BEGIN IMMEDIATE")?;
    assert_eq!(replica.store.purge_local_replica_residue(), TIMEOUT);
    writer.execute_batch("COMMIT")?;
    drop(writer);
    assert_eq!(replica.store.purge_local_replica_residue(), POSITIVE);
    assert_eq!(replica.wal_len()?, 0);
    Ok(())
}

#[test]
fn a_reader_holding_the_store_is_a_transient_timeout() -> Fallible<()> {
    let mut replica = Replica::open()?;
    let (victim, _) = replica.timelines()?;
    replica
        .store
        .append(victim, &[draft(marker("F1-BUSY", 0))])?;
    let reader = rusqlite::Connection::open(&replica.path)?;
    reader.execute_batch("BEGIN")?;
    let events: i64 = reader.query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
    assert_eq!(events, 1);
    assert_eq!(replica.store.purge_local_replica_residue(), TIMEOUT);
    reader.execute_batch("COMMIT")?;
    drop(reader);
    assert_eq!(replica.store.purge_local_replica_residue(), POSITIVE);
    assert_eq!(replica.wal_len()?, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_non_empty_write_ahead_log_at_the_store_path_is_negative() -> Fallible<()> {
    let mut replica = Replica::open()?;
    let (victim, _) = replica.timelines()?;
    // The store keeps its open log descriptor, so its own checkpoint still
    // succeeds; the file now at the store's `-wal` path is not empty.
    std::fs::rename(replica.file("-wal"), replica.file("-wal.moved"))?;
    std::fs::write(replica.file("-wal"), b"x")?;
    replica
        .store
        .append(victim, &[draft(marker("F1-MOVED", 0))])?;
    assert_eq!(replica.store.purge_local_replica_residue(), NEGATIVE);
    Ok(())
}

#[test]
fn a_read_only_store_is_negative() -> Fallible<()> {
    let mut replica = Replica::open()?;
    replica.timelines()?;
    let mut read_only = SqliteStore::open_read_only(replica.path.to_str().ok_or("utf-8 path")?)?;
    assert_eq!(read_only.purge_local_replica_residue(), NEGATIVE);
    Ok(())
}

#[test]
fn an_in_memory_sqlite_store_is_negative() -> Fallible<()> {
    let mut store = SqliteStore::open_in_memory()?;
    assert_eq!(store.purge_local_replica_residue(), NEGATIVE);
    Ok(())
}

#[test]
fn a_memory_store_is_negative() {
    let mut store = MemoryStore::new();
    assert_eq!(store.purge_local_replica_residue(), NEGATIVE);
}
