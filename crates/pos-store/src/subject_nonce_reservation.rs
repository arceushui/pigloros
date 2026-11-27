#![cfg(any(test, feature = "test-support"))]
//! ADR-137 N1/N2 durable SNL1 reservation over a checked ledger storage.
//!
//! [`DurableSubjectNonceReservationV1`] is the production shape of
//! [`SubjectNonceReservationPortV1`]. It owns the N1 steps and nothing else:
//! read the bounded ledger, strictly decode it, validate the exact
//! `(owner, role, epoch, root_material_digest, store_file_id)`, advance the
//! counter, durably replace the ledger with a readback, and return the counter
//! only after the readback matches the replacement.
//!
//! The storage behind [`SubjectNonceLedgerStorageV1`] is the held ADR-110 E16
//! lifetime lock's checked ledger file (ADR-132 rule 4 on Windows). It owns
//! the lock, the directory admission and the byte replacement; this module
//! never sees a path. The lock stays held on every failure, so a refusal here
//! never releases the ledger.
//!
//! Every failure refuses with the one fixed
//! [`SubjectDataConsumerErrorV1::NonceReservationRefused`] and keeps the lock.
//! After a write may have happened the port never restores the old counter
//! (N2): a later call re-reads the ledger and either finds the successor row
//! and returns the next counter, or finds the old row, whose counter was never
//! returned. Nothing here is activated before #1438.

use pos_core::{Hash, KeyIdentityV1, KeyRoleV1};
use pos_crypto::subject_key::SubjectKeyUseV1;
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, SubjectStoreFileIdV1,
};
use thiserror::Error;

use crate::subject_data_consumer::{SubjectDataConsumerErrorV1, SubjectNonceReservationPortV1};

/// The checked ledger storage was unavailable, unsafe or uncertain.
///
/// The error carries no path, no OS diagnostic and no counter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("subject nonce ledger storage was unavailable")]
pub struct SubjectNonceLedgerStorageErrorV1;

/// Bounded byte storage of the one SNL1 ledger, under the held E16 lock.
///
/// An implementation holds the lifetime lock for its whole life, including
/// after a failure. It must be the sole writer of the ledger for that time
/// (the E16 lock gives compare-and-swap exclusivity), so no other writer can
/// change the bytes between a read and the replacement. It neither parses,
/// validates nor reserves anything.
pub trait SubjectNonceLedgerStorageV1 {
    /// Read the existing ledger's bytes, at most 1 MiB.
    ///
    /// # Errors
    /// Returns [`SubjectNonceLedgerStorageErrorV1`] for a missing or unsafe
    /// ledger, contention, an oversized file or any I/O failure.
    fn read_ledger_bytes(&mut self) -> Result<Vec<u8>, SubjectNonceLedgerStorageErrorV1>;

    /// Durably replace the existing ledger's bytes.
    ///
    /// # Errors
    /// Returns [`SubjectNonceLedgerStorageErrorV1`] when the replacement failed
    /// or its outcome is unconfirmed; the caller then treats it as possibly
    /// committed.
    fn replace_ledger_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SubjectNonceLedgerStorageErrorV1>;
}

/// The checked-ledger owner of ADR-137 N1: the durable nonce reservation port.
#[derive(Debug)]
pub struct DurableSubjectNonceReservationV1<S> {
    storage: S,
    store_file_id: SubjectStoreFileIdV1,
}

impl<S: SubjectNonceLedgerStorageV1> DurableSubjectNonceReservationV1<S> {
    /// Bind the held ledger storage to the ADR-123 proven store identity (N3).
    ///
    /// Only a row naming exactly `store_file_id` can reserve; any other row is
    /// decryption-only and is never rewritten.
    #[must_use]
    pub const fn new(storage: S, store_file_id: SubjectStoreFileIdV1) -> Self {
        Self {
            storage,
            store_file_id,
        }
    }

    /// The exact row, if any, and the candidate ledger that advances it.
    fn candidate(
        &mut self,
        identity: &KeyIdentityV1,
        root_material_digest: Hash,
    ) -> Option<(SubjectNonceLedgerRowV1, SubjectNonceLedgerV1)> {
        let expected_store = self.store_file_id;
        self.storage
            .read_ledger_bytes()
            .ok()
            .and_then(|bytes| SubjectNonceLedgerV1::from_bytes(&bytes).ok())
            .and_then(|ledger| {
                ledger
                    .rows()
                    .find(|row| {
                        row.owner_id == identity.owner_id.as_str()
                            && row.epoch == identity.epoch
                            && row.root_material_digest == *root_material_digest.as_bytes()
                            && row.store_file_id == expected_store
                    })
                    .and_then(|row| {
                        ledger
                            .advance_counter(row, SubjectKeyUseV1::Data)
                            .ok()
                            .map(|next| (row.clone(), next))
                    })
            })
    }

    /// Replace the ledger and read it back; true only for an exact readback.
    fn commit(&mut self, next: &SubjectNonceLedgerV1) -> bool {
        self.storage.replace_ledger_bytes(next.as_bytes()).is_ok()
            && self
                .storage
                .read_ledger_bytes()
                .is_ok_and(|bytes| bytes == next.as_bytes())
    }
}

impl<S: SubjectNonceLedgerStorageV1> SubjectNonceReservationPortV1
    for DurableSubjectNonceReservationV1<S>
{
    fn reserve_data_counter(
        &mut self,
        identity: KeyIdentityV1,
        root_material_digest: Hash,
    ) -> Result<u64, SubjectDataConsumerErrorV1> {
        if identity.role != KeyRoleV1::SubjectDataEncryption {
            return Err(SubjectDataConsumerErrorV1::NonceReservationRefused);
        }
        let (row, next) = self
            .candidate(&identity, root_material_digest)
            .ok_or(SubjectDataConsumerErrorV1::NonceReservationRefused)?;
        if self.commit(&next) {
            Ok(row.data_next)
        } else {
            Err(SubjectDataConsumerErrorV1::NonceReservationRefused)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
