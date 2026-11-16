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
//! `-wal` file is empty afterwards. A store that another connection holds is
//! the transient `ReplicaTimeout`. That covers a writer that makes `VACUUM`
//! fail busy or locked, and a reader that keeps the checkpoint busy. Every
//! other outcome is a negative acknowledgement. That includes a read-only
//! store and an in-memory database, which has no file to prove anything
//! about. A writer on another connection that commits between the
//! checkpoint and the `-wal` size check also makes the purge negative, which
//! fails closed.

use pos_core::{ErasureErrorV1, LocalReplicaResidualPortV1};
use rusqlite::ErrorCode;

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

    /// Whether the `-wal` file at the store's path holds zero bytes.
    fn write_ahead_log_is_empty(&self) -> bool {
        self.conn
            .path()
            .and_then(|path| std::fs::metadata(format!("{path}-wal")).ok())
            .is_some_and(|metadata| metadata.len() == 0)
    }
}

/// Whether another connection holding the store caused the failure.
fn held_by_another_connection(error: &rusqlite::Error) -> bool {
    error
        .sqlite_error_code()
        .is_some_and(|code| code == ErrorCode::DatabaseBusy || code == ErrorCode::DatabaseLocked)
}

impl LocalReplicaResidualPortV1 for SqliteStore {
    fn purge_local_replica_residue(&mut self) -> Result<(), ErasureErrorV1> {
        match self.vacuum_and_truncate_wal() {
            Ok((1, _, _)) => Err(ErasureErrorV1::ReplicaTimeout),
            Ok((0, 0, 0)) if self.write_ahead_log_is_empty() => Ok(()),
            Err(error) if held_by_another_connection(&error) => Err(ErasureErrorV1::ReplicaTimeout),
            _ => Err(ErasureErrorV1::ReplicaNegativeAcknowledgement),
        }
    }
}
