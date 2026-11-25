//! The Memory pass Abort (#560 A4e-2; ADR-129 R8.3, R13.1(4)–(5), R14 and
//! R15.1–R15.4).
//!
//! An Abort resolves one unresolved pass: it commits the pass's CAB1 and
//! its terminal status, replaces the pass's pending erasure entry by the
//! rows it registers and, for a failure Abort, binds the failure records.
//! It is never refused for the budget or a cap, and it never counts
//! (R13.1(5), RN.1(1)).
//!
//! This module holds what every Abort shares: the retry lookup by
//! `(T, reservation_operation_id)` in the A5.5 order (R15.3(2) steps 4 and
//! 5), the CAB1 and the terminal state a committed Abort leaves.
//! [`operator`] is the authenticated Abort of reasons 0 and 4. The failure
//! Abort of reasons 1 to 3 follows in A4e-2b.

mod operator;

use pos_core::community_lifecycle::{
    CommunityAbortInputV1, CommunityAbortReasonV1, CommunityAbortV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1,
};
use pos_core::{Hash, TimelineId};
use zeroize::Zeroizing;

pub use operator::{CommunityPassAbortCallV1, CommunityPassAbortReceiptV1};

use super::memory_domain::MemoryCommunityDomainV1;
use super::pass_record::{CommunityPassRecordV1, CommunityPassStatusV1};
use super::private_hash::private_digest;
use super::sealer::SealedMetadataV1;

/// The bound content of one Abort (R15.3(2) step 4): the reason, the CFO1
/// digest and the control identities, sorted. The key `(T,
/// reservation_operation_id)` fixes the rest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PassAbortBoundV1 {
    reason: u8,
    failure_evidence_digest: Option<Hash>,
    control_operation_ids: Vec<[u8; 16]>,
}

impl PassAbortBoundV1 {
    /// The bound of an Abort of `reason` with its CFO1 and the control
    /// identities of its in-Abort `SetReason`s, in any order.
    pub(super) fn new(
        reason: CommunityAbortReasonV1,
        failure_evidence_digest: Option<Hash>,
        mut control_operation_ids: Vec<[u8; 16]>,
    ) -> Self {
        control_operation_ids.sort_unstable();
        Self {
            reason: reason_code(reason),
            failure_evidence_digest,
            control_operation_ids,
        }
    }
}

/// The CAB1 `abort_reason` code.
const fn reason_code(reason: CommunityAbortReasonV1) -> u8 {
    match reason {
        CommunityAbortReasonV1::AuthenticatedCancellation => 0,
        CommunityAbortReasonV1::ValidatedInvocationFailure => 1,
        CommunityAbortReasonV1::AdmissionRefused => 2,
        CommunityAbortReasonV1::ProtectedUseRefused => 3,
        CommunityAbortReasonV1::RetiringGeneration => 4,
    }
}

/// One committed Abort, retained for its retry (A5.3(5)).
pub(super) struct CommittedPassAbortV1 {
    pub(super) bound: PassAbortBoundV1,
    /// The canonical CAB1.
    pub(super) abort: Zeroizing<Vec<u8>>,
    /// `H(CAB1)`.
    pub(super) abort_digest: Hash,
    /// The administrative decision's leaf grant, whose grantee is the
    /// original principal (A5.3(6)).
    pub(super) leaf_grant_id: Hash,
    /// The protection ID of the pass metadata key that sealed `records`.
    pub(super) metadata_key: [u8; 16],
    /// Every sealed metadata record; the first is the CAB1.
    pub(super) records: Vec<SealedMetadataV1>,
}

/// What the retry lookup found.
pub(super) enum PassAbortLookupV1<'a> {
    /// An identical retry: the original is in the retry index.
    Original,
    /// A first Abort of this unresolved pass.
    First(&'a CommunityPassRecordV1),
}

impl MemoryCommunityDomainV1 {
    /// The retry lookup and the first-Abort preconditions of R15.3(2)
    /// steps 4 and 5, for the pass reserved under `(T, operation)`.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a pass nobody reserved (12),
    /// `Conflict` for a Committed pass and for a retry with other bound
    /// content (4) and `OperationActive` for an Abort while the pass's call
    /// is live (15).
    pub(super) fn lookup_pass_abort(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
        bound: &PassAbortBoundV1,
    ) -> Result<PassAbortLookupV1<'_>, Error> {
        let record = self
            .pass_record(timeline, reservation_operation_id)
            .ok_or(Error::EvidenceUnavailable)?;
        match record.status {
            CommunityPassStatusV1::Committed => Err(Error::Conflict),
            CommunityPassStatusV1::Aborted => self
                .pass_aborts
                .get(&(timeline, reservation_operation_id))
                .filter(|original| original.bound == *bound)
                .map(|_| PassAbortLookupV1::Original)
                .ok_or(Error::Conflict),
            CommunityPassStatusV1::Reserved | CommunityPassStatusV1::Sealed => {
                first_abort(record).map(|()| PassAbortLookupV1::First(record))
            }
        }
    }
}

/// R15.3(2) step 5: a first Abort of an unresolved pass is refused while the
/// `run_pass` call that reserved it is live (R8.3(3)).
const fn first_abort(record: &CommunityPassRecordV1) -> Result<(), Error> {
    if record.live {
        Err(Error::OperationActive)
    } else {
        Ok(())
    }
}

/// The fields of a CAB1 the host derives (R8.3(2)).
#[derive(Clone, Copy)]
pub(super) struct AbortFieldsV1 {
    pub(super) pass_key: CommunityPassKeyV1,
    pub(super) reservation_digest: Hash,
    pub(super) sealed_result_digest: Option<Hash>,
    pub(super) reason: CommunityAbortReasonV1,
    pub(super) failure_evidence_digest: Option<Hash>,
    pub(super) quarantine_delta_digest: Option<Hash>,
    pub(super) evidence_not_after_micros: u64,
}

/// The canonical CAB1 and `H(CAB1)`.
pub(super) fn abort_record(fields: AbortFieldsV1) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    CommunityAbortV1::new(CommunityAbortInputV1 {
        pass_key: fields.pass_key,
        reservation_digest: fields.reservation_digest,
        sealed_result_digest: fields.sealed_result_digest,
        reason: fields.reason,
        failure_evidence_digest: fields.failure_evidence_digest,
        quarantine_delta_digest: fields.quarantine_delta_digest,
        evidence_not_after_micros: fields.evidence_not_after_micros,
    })
    .map(|record| {
        let bytes = record.to_canonical_cbor();
        let digest = private_digest(b"PiglorOS.Community.CAB1.v1", &[bytes.as_slice()]);
        (bytes, digest)
    })
}
