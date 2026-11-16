//! The `local-replica` residual-bytes port (ADR-136 F1, Redmine #1406).
//!
//! ADR-136 lets the `local-replica` acknowledgement class be positive only
//! when deleted pages cannot be recovered from the store file. The scope is
//! the store's own files: for `SQLite`, the database, its `-wal` and its
//! `-shm`. Filesystem, flash-translation and backup copies are out of scope;
//! backups belong to `local-backup-inventory`.

use super::ErasureErrorV1;

/// Removes residual bytes of deleted content from the single local store.
///
/// The erasure executor calls this in the `local-replica` step after every
/// other owner of the request has run. `Ok(())` is the only positive
/// acknowledgement. It means the adapter proved that no page freed before
/// the call is still readable in the store's files.
pub trait LocalReplicaResidualPortV1 {
    /// Purge residual bytes and prove that they are gone.
    ///
    /// # Errors
    /// - [`ErasureErrorV1::ReplicaTimeout`]: another connection still holds
    ///   the store, so the purge could not complete. That connection is
    ///   either a writer while the store is rebuilt or a reader while the
    ///   write-ahead log is truncated. This code is transient and the driver
    ///   retries it.
    /// - [`ErasureErrorV1::ReplicaNegativeAcknowledgement`]: any other
    ///   failure, or a store with no file the proof could cover. This code is
    ///   permanent.
    fn purge_local_replica_residue(&mut self) -> Result<(), ErasureErrorV1>;
}
