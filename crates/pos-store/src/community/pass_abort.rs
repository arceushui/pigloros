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

mod failure;
mod failure_abort;
mod operator;

use pos_core::community_lifecycle::{
    CommunityAbortInputV1, CommunityAbortReasonV1, CommunityAbortV1, CommunityArtifactAdmissionV1,
    CommunityLifecycleErrorV1 as Error, CommunityReservationInputV1, CommunityReservationV1,
};
use pos_core::{Hash, TimelineId};
use zeroize::Zeroizing;

pub use failure::{
    CommunityObservedFailureV1, CommunityPassAbortFailureInputV1, CommunityPassAbortFailureV1,
};
pub use failure_abort::{CommunityPassAbortFailureCallV1, CommunityPassAbortScopeV1};
pub use operator::{CommunityPassAbortCallV1, CommunityPassAbortReceiptV1};

use super::memory_domain::MemoryCommunityDomainV1;
use super::pass_record::{CommunityPassRecordV1, CommunityPassStatusV1};
use super::private_hash::private_digest;
use super::quarantine::{current_floor, CommunityQuarantineContextV1};
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
    /// The CAB1's `evidence_not_after_micros`, the pass's `H_r`: a retry at
    /// or after it is discovery of expired evidence (R13.2(4), 13).
    pub(super) evidence_not_after_micros: u64,
    /// The administrative decision's leaf grant, whose grantee is the
    /// original principal (A5.3(6)).
    pub(super) leaf_grant_id: Hash,
    /// The protection ID of the pass metadata key that sealed `records`.
    pub(super) metadata_key: [u8; 16],
    /// Every sealed metadata record; the first is the CAB1.
    pub(super) records: Vec<SealedMetadataV1>,
    /// One COA1 per ARD1 the Abort published: the CFO1's and each CFI1's.
    pub(super) admissions: Vec<CommunityArtifactAdmissionV1>,
    /// The generation whose catalogue owner owns those ARD1s.
    pub(super) generation: [u8; 16],
}

/// What the retry lookup found.
pub(super) enum PassAbortLookupV1<'a> {
    /// An identical retry: the original Abort.
    Original(&'a CommittedPassAbortV1),
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
        self.lookup_pass_abort_with(timeline, reservation_operation_id, bound, first_abort)
    }

    /// [`Self::lookup_pass_abort`] with the preconditions `first` puts on a
    /// first Abort of an unresolved pass.
    pub(super) fn lookup_pass_abort_with(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
        bound: &PassAbortBoundV1,
        first: fn(&CommunityPassRecordV1) -> Result<(), Error>,
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
                .map(PassAbortLookupV1::Original)
                .ok_or(Error::Conflict),
            CommunityPassStatusV1::Reserved | CommunityPassStatusV1::Sealed => {
                first(record).map(|()| PassAbortLookupV1::First(record))
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

/// R15.3(2) step 5 and R15.3(5): the installed failure producer aborts only a
/// Reserved pass whose reserving `run_pass` call is live. Another status, or a
/// call that already ended, is refused with 3 (N18).
pub(super) const fn first_failure_abort(record: &CommunityPassRecordV1) -> Result<(), Error> {
    match (record.status, record.live) {
        (CommunityPassStatusV1::Reserved, true) => Ok(()),
        _ => Err(Error::InvalidBinding),
    }
}

/// What the fences of a first Abort read.
pub(super) struct FencedV1 {
    /// The CMA1 anchor `(T, G)` every metadata record's CSM1 names.
    pub(super) anchor: (TimelineId, [u8; 16]),
    /// The CNE1 address of the CSI1 read.
    pub(super) selection_address: Hash,
    /// The NMP1 `metadata_not_after_micros`.
    pub(super) metadata_horizon: u64,
}

impl MemoryCommunityDomainV1 {
    /// The fences of a first Abort: the installed CDP1 must be the Reserve's
    /// (3), then the generation (5) and the head (6), then the metadata
    /// horizon (13), as A5.5 step 4 and A4e-1 order them.
    /// `decision_bound_micros` is the call's decision bound.
    ///
    /// A first Abort at or after the pass's `H_r` still commits its CAB1
    /// (R15.2(3a), N17).
    pub(super) fn fence_first_abort(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        record: &CommunityPassRecordV1,
        timeline: TimelineId,
        decision_bound_micros: u64,
    ) -> Result<FencedV1, Error> {
        let reservation = record.reserved.reservation;
        if context.profile.digest() != reservation.profile_digest {
            return Err(Error::InvalidBinding);
        }
        let (anchor, selection, selection_address) = self.read_selection(context)?;
        let (generation, head) = current_floor(&selection, timeline)?;
        if generation != reservation.pass_key.generation() {
            return Err(Error::StaleGeneration);
        }
        if head != reservation.predecessor_head_digest {
            return Err(Error::StaleFrontier);
        }
        let metadata_horizon = context
            .binding
            .metadata_policy
            .as_input()
            .metadata_not_after_micros;
        if decision_bound_micros > metadata_horizon {
            return Err(Error::EvidenceExpired);
        }
        Ok(FencedV1 {
            anchor,
            selection_address,
            metadata_horizon,
        })
    }
}

/// The fields of a CAB1 the host derives (R8.3(2)).
#[derive(Clone, Copy)]
pub(super) struct AbortFieldsV1 {
    /// The reservation, whose CPK1 and horizon the CAB1 copies and whose
    /// digest `H(CPR1)` it binds.
    pub(super) reservation: CommunityReservationInputV1,
    pub(super) sealed_result_digest: Option<Hash>,
    pub(super) reason: CommunityAbortReasonV1,
    pub(super) failure_evidence_digest: Option<Hash>,
    pub(super) quarantine_delta_digest: Option<Hash>,
}

/// The canonical CAB1 and `H(CAB1)`.
///
/// `H(CPR1)` is [`CommunityReservationV1::digest`], the one definition Seal
/// (CPS1 `reservation_digest`) and Commit share.
pub(super) fn abort_record(fields: &AbortFieldsV1) -> Result<(Zeroizing<Vec<u8>>, Hash), Error> {
    CommunityReservationV1::new(fields.reservation)
        .and_then(|reservation| {
            CommunityAbortV1::new(CommunityAbortInputV1 {
                pass_key: fields.reservation.pass_key,
                reservation_digest: reservation.digest(),
                sealed_result_digest: fields.sealed_result_digest,
                reason: fields.reason,
                failure_evidence_digest: fields.failure_evidence_digest,
                quarantine_delta_digest: fields.quarantine_delta_digest,
                evidence_not_after_micros: fields.reservation.evidence_not_after_micros,
            })
        })
        .map(|record| {
            let bytes = record.to_canonical_cbor();
            let digest = private_digest(b"PiglorOS.Community.CAB1.v1", &[bytes.as_slice()]);
            (bytes, digest)
        })
}
