#![cfg(any(test, feature = "test-support"))]
//! ADR-137 P5 for one failed enrollment attempt.
//!
//! P3: a failure before step 6 commits, with a definite outcome, "runs the
//! same P5 deletion for this attempt at once and wipes owned secrets". The
//! attempt's staging record was committed by this adapter at P3 step 3,
//! so it names this store and P5's foreign-record branch cannot apply. The
//! steps follow the P3a crash table: the wrap and binding files (canonical
//! and `.tmp`) by #206 durable deletion, then the SNL1 row by a checked
//! ledger replacement, then the record. Each step is idempotent, and a
//! failure stops before the next one, so the record survives every
//! incomplete deletion for P5 recovery at the next owner start.

use pos_core::EntityId;
use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerV1, SubjectStoreFileIdV1};
use pos_owner_bridge::encryptor_lock::linux::{
    SubjectEncryptorLock, SubjectKeyArtifactName, SubjectOwnerExclusiveGuard,
};
use pos_owner_bridge::OwnerError;

use super::{read_ledger, write_ledger, EnrollmentStore, DURABLE_WRITE, REGISTRY};

/// One attempt that committed its P3a staging record.
pub(super) struct Attempt<'a> {
    /// The subject whose owner the guard holds.
    pub(super) subject: EntityId,
    /// The epoch of the staging record.
    pub(super) epoch: u64,
    /// The bound store's identity that the staging record carries.
    pub(super) store_file_id: SubjectStoreFileIdV1,
    /// The reserved wrap and binding names of `(owner, epoch)`.
    pub(super) names: &'a [SubjectKeyArtifactName; 2],
}

/// Delete what `attempt` staged, as P5 does for an orphan of this store.
///
/// Nothing is deleted unless P1 is readable and its ceiling is below the
/// epoch, which proves the identity absent from the registry, and unless the
/// SNL1 ledger decodes. When an SNL1 row for `(owner, epoch)` carries another
/// store's identity, the files may serve that store, so they and the row are
/// kept and only the record is deleted. Otherwise both files are deleted, the
/// row is removed when it is this store's, and the record is deleted last.
///
/// # Errors
/// Returns `Registry` when P1 or the ledger refuses, or P1 may hold the
/// identity; `DurableWrite` when a file or the ledger cannot be written; or
/// the store's own refusal to delete the record.
pub(super) fn discard_attempt(
    lock: &SubjectEncryptorLock,
    owner: &SubjectOwnerExclusiveGuard<'_>,
    store: &mut impl EnrollmentStore,
    attempt: &Attempt<'_>,
) -> Result<(), OwnerError> {
    let owner_id = owner.owner_id();
    // This read also refuses under a B6 fence, so a fence that appears during
    // the attempt keeps every artifact for P5 recovery at the next owner start.
    let ceiling = store.registry_epoch_ceiling(owner_id, attempt.subject)?;
    let ledger = read_ledger(lock)
        .filter(|_| ceiling < attempt.epoch)
        .ok_or(REGISTRY)?;
    let row = ledger
        .rows()
        .find(|row| row.owner_id == owner_id && row.epoch == attempt.epoch);
    if !row.is_some_and(|row| row.store_file_id != attempt.store_file_id) {
        for name in attempt.names {
            lock.delete_subject_key_artifact(owner, name)
                .or(Err(DURABLE_WRITE))?;
        }
    }
    if let Some(row) = row.filter(|row| row.store_file_id == attempt.store_file_id) {
        SubjectNonceLedgerV1::new(ledger.rows().filter(|other| *other != row).cloned())
            // Unreachable error: dropping one row of a valid SNL1 leaves a
            // smaller ledger with unique identities in the same order.
            .or(Err(DURABLE_WRITE))
            .and_then(|smaller| write_ledger(lock, &smaller))?;
    }
    store.delete_staging_record(owner_id, attempt.epoch)
}
