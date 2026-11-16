//! `SQLite` adapter of the `local-replica` residual-bytes port (ADR-136 F1,
//! Redmine #1406).
//!
//! `PRAGMA secure_delete` alone is not enough. A b-tree balance
//! (`rebuildPage`) leaves stale copies of moved cells in a page's unallocated
//! gap, and later deletes do not reach them. A deleted index key can
//! therefore survive in the database file. The purge instead rebuilds the
//! whole database from its live content with `VACUUM`. It then moves every
//! frame into the database file and truncates the write-ahead log with
//! `wal_checkpoint(TRUNCATE)`.
//!
//! The proof is strict. The purge is positive only when the checkpoint
//! reports no busy reader and no remaining frames (`0, 0, 0`), and the
//! `-wal` file is empty afterwards. A checkpoint blocked by another
//! connection is the transient `ReplicaTimeout`. Every other outcome is a
//! negative acknowledgement, including a read-only store and an in-memory
//! database, which has no file to prove anything about.

use pos_core::{ErasureErrorV1, LocalReplicaResidualPortV1};

use super::SqliteStore;

/// The checkpoint row `(busy, log frames, checkpointed frames)`.
type CheckpointRow = (i64, i64, i64);

impl SqliteStore {
    fn vacuum_and_truncate_wal(&self) -> rusqlite::Result<CheckpointRow> {
        self.conn.execute_batch("VACUUM").and_then(|()| {
            self.conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    row.get::<_, i64>(0).and_then(|busy| {
                        row.get::<_, i64>(1)
                            .and_then(|log| row.get::<_, i64>(2).map(|done| (busy, log, done)))
                    })
                })
        })
    }

    /// Whether the store's `-wal` file exists and holds zero bytes.
    fn write_ahead_log_is_empty(&self) -> bool {
        self.conn
            .path()
            .filter(|path| !path.is_empty())
            .and_then(|path| std::fs::metadata(format!("{path}-wal")).ok())
            .is_some_and(|metadata| metadata.len() == 0)
    }
}

impl LocalReplicaResidualPortV1 for SqliteStore {
    fn purge_local_replica_residue(&mut self) -> Result<(), ErasureErrorV1> {
        match self.vacuum_and_truncate_wal() {
            Ok((1, _, _)) => Err(ErasureErrorV1::ReplicaTimeout),
            Ok((0, 0, 0)) if self.write_ahead_log_is_empty() => Ok(()),
            _ => Err(ErasureErrorV1::ReplicaNegativeAcknowledgement),
        }
    }
}
