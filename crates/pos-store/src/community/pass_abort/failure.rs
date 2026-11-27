//! The sealed failure input of a failure Abort and the records it derives
//! (ADR-129 revision 15, R15.3(1), (2) steps 1 and 6).
//!
//! The installed failure producer hands the store a
//! [`CommunityPassAbortFailureV1`]. It carries no record bytes and no digest
//! the store can derive: the store builds every CFI1, the CFO1 and the CAB1
//! itself. Nothing here reads a ledger, a clock or a domain.

use std::collections::BTreeSet;

use pos_core::community_lifecycle::{
    community_decision_provenance_digest_v1, community_quarantine_reason_v1,
    CommunityAbortReasonV1, CommunityDecisionProvenanceInputV1, CommunityDigestListV1,
    CommunityGuestErrorV1, CommunityInvocationFailureInputV1, CommunityInvocationFailureV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassFailureInputV1, CommunityPassFailureV1,
    CommunityPassKeyV1, CommunityPluginHostErrorV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};
use zeroize::Zeroizing;

use super::super::pass_record::CommunityPassMemberDigestsV1;

/// The host codes a reason-1 failure can carry (R15.3(2) step 1): the
/// invocation and guest-output failures of one prepared invocation. Code 9
/// and 17 cannot occur in V1 and code 18 closes the context instead.
const REASON_ONE_CODES: [u8; 11] = [6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 19];

/// The host codes of a reason-2 launch refusal after Reserve. Code 2 is a
/// trust write the interlock holds back; code 1 is confirmed at the
/// authority step.
const REASON_TWO_CODES: [u8; 6] = [0, 1, 3, 4, 5, 20];

/// The host code of `GuestDeclaredFailure`, the only one that carries a
/// guest error.
const GUEST_DECLARED_FAILURE: u8 = 10;

/// One observed failure of a due member (R15.3(1)).
#[derive(Clone, Copy)]
pub struct CommunityObservedFailureV1<'a> {
    /// The failing member's CMB1 digest.
    pub member_binding_digest: Hash,
    /// The failed prepared invocation: present for reason 1, null for a
    /// reason-2 launch refusal.
    pub invocation_id: Option<[u8; 16]>,
    /// The closed host failure.
    pub host_failure: CommunityPluginHostErrorV1,
    /// The guest error, present exactly for `GuestDeclaredFailure`.
    pub guest_error: Option<CommunityGuestErrorV1<'a>>,
    /// The nonzero control identity of the in-Abort `SetReason`, present
    /// exactly when the host failure maps to a quarantine reason (N7).
    pub control_operation_id: Option<[u8; 16]>,
}

/// The fields of one failure Abort's sealed input.
#[derive(Clone, Copy)]
pub struct CommunityPassAbortFailureInputV1<'a> {
    /// The execution Timeline T.
    pub timeline: TimelineId,
    /// The aborted pass's `reservation_operation_id`.
    pub reservation_operation_id: [u8; 16],
    /// The Abort reason: 1, 2 or 3.
    pub reason: CommunityAbortReasonV1,
    /// The observed failures, in ascending due-roster order.
    pub failures: &'a [CommunityObservedFailureV1<'a>],
}

/// A sealed failure from the installed failure producer (R15.3(1)).
///
/// The store accepts it as trusted code only after its own re-checks
/// (A5.9). Only the composition root, which holds the
/// [`AuthorityTrustRootSealV1`], hands it out:
///
/// ```compile_fail,E0061
/// use pos_store::community::{CommunityPassAbortFailureInputV1, CommunityPassAbortFailureV1};
/// fn forge(input: CommunityPassAbortFailureInputV1<'_>) {
///     let _ = CommunityPassAbortFailureV1::new(input);
/// }
/// ```
#[derive(Clone, Copy)]
pub struct CommunityPassAbortFailureV1<'a>(CommunityPassAbortFailureInputV1<'a>);

impl<'a> CommunityPassAbortFailureV1<'a> {
    /// Seal the producer's failure for one Abort call.
    #[must_use]
    pub const fn new(
        _seal: &'static AuthorityTrustRootSealV1,
        input: CommunityPassAbortFailureInputV1<'a>,
    ) -> Self {
        Self(input)
    }

    pub(super) const fn input(&self) -> &CommunityPassAbortFailureInputV1<'a> {
        &self.0
    }
}

/// Step 1, the part that needs no pass record (R15.3(2)): the reason, the
/// failure count, the host codes, the guest errors and the control
/// identities. Every refusal is `InvalidBinding` and echoes nothing.
pub(super) fn check_shape(input: &CommunityPassAbortFailureInputV1<'_>) -> Result<(), Error> {
    let codes: &[u8] = match input.reason {
        CommunityAbortReasonV1::ValidatedInvocationFailure => &REASON_ONE_CODES,
        CommunityAbortReasonV1::AdmissionRefused => &REASON_TWO_CODES,
        CommunityAbortReasonV1::ProtectedUseRefused => {
            return if input.failures.is_empty() {
                Ok(())
            } else {
                Err(Error::InvalidBinding)
            };
        }
        CommunityAbortReasonV1::AuthenticatedCancellation
        | CommunityAbortReasonV1::RetiringGeneration => return Err(Error::InvalidBinding),
    };
    let reason_two = input.reason == CommunityAbortReasonV1::AdmissionRefused;
    if input.failures.is_empty() || (reason_two && input.failures.len() != 1) {
        return Err(Error::InvalidBinding);
    }
    input
        .failures
        .iter()
        .try_for_each(|failure| check_failure(failure, codes, reason_two))?;
    check_control_identities(input.failures)
}

/// One failure's host code, invocation, guest error and control identity.
fn check_failure(
    failure: &CommunityObservedFailureV1<'_>,
    codes: &[u8],
    reason_two: bool,
) -> Result<(), Error> {
    let code = failure.host_failure.code();
    let mapped = community_quarantine_reason_v1(failure.host_failure).is_some();
    let valid = codes.contains(&code)
        && failure.invocation_id.is_none() == reason_two
        && failure.guest_error.is_some() == (code == GUEST_DECLARED_FAILURE)
        && failure.control_operation_id.is_some() == mapped
        && failure.control_operation_id != Some([0; 16]);
    if valid && failure.invocation_id != Some([0; 16]) {
        failure
            .guest_error
            .map_or(Ok(()), CommunityGuestErrorV1::check)
            .map_err(|_| Error::InvalidBinding)
    } else {
        Err(Error::InvalidBinding)
    }
}

/// No `control_operation_id` repeats (R15.3(2) step 1).
fn check_control_identities(failures: &[CommunityObservedFailureV1<'_>]) -> Result<(), Error> {
    let identities: Vec<[u8; 16]> = failures
        .iter()
        .filter_map(|failure| failure.control_operation_id)
        .collect();
    let distinct: BTreeSet<[u8; 16]> = identities.iter().copied().collect();
    if distinct.len() == identities.len() {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

/// Step 1's roster part: every failure names a due member, with no CMB1
/// twice and in ascending due-roster order. `due` is the pass's due members
/// in roster order.
pub(super) fn check_roster_order(
    failures: &[CommunityObservedFailureV1<'_>],
    due: &[CommunityPassMemberDigestsV1],
) -> Result<(), Error> {
    let mut previous: Option<usize> = None;
    for failure in failures {
        let position = due
            .iter()
            .position(|member| member.cmb1_digest == failure.member_binding_digest)
            .ok_or(Error::InvalidBinding)?;
        if previous.is_some_and(|last| position <= last) {
            return Err(Error::InvalidBinding);
        }
        previous = Some(position);
    }
    Ok(())
}

/// One derived CFI1 and what the CFO1 and the quarantine records take from it.
pub(super) struct InvocationRecordV1 {
    /// The canonical CFI1.
    pub(super) bytes: Zeroizing<Vec<u8>>,
    /// `H(CFI1)`.
    pub(super) digest: Hash,
    /// The failing member's CMB1 digest.
    pub(super) member: Hash,
    /// The CFI1's `decision_provenance_digest` (R8.5(1)).
    pub(super) provenance: Hash,
    /// The closed host failure.
    pub(super) host_failure: CommunityPluginHostErrorV1,
}

/// The CFI1s and CFO1 of a failure Abort (R15.3(2) step 6).
pub(super) struct DerivedFailureV1 {
    /// Each CFI1, in failure order.
    pub(super) invocations: Vec<InvocationRecordV1>,
    /// The CFO1's canonical bytes.
    pub(super) failure: Zeroizing<Vec<u8>>,
    /// `H(CFO1)`.
    pub(super) failure_digest: Hash,
}

/// Derive one CFI1 per failure and the CFO1 over them, under `horizon`
/// (R15.2). The CFO1 takes its host failure and provenance from the first
/// CFI1 (R8.5(3)).
pub(super) fn derive_failure(
    pass_key: CommunityPassKeyV1,
    due: &[CommunityPassMemberDigestsV1],
    failures: &[CommunityObservedFailureV1<'_>],
    horizon: u64,
) -> Result<DerivedFailureV1, Error> {
    let invocations = failures
        .iter()
        .map(|failure| {
            due.iter()
                .find(|member| member.cmb1_digest == failure.member_binding_digest)
                .ok_or(Error::InvalidBinding)
                .and_then(|member| invocation_record(pass_key, member, failure, horizon))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let first = invocations.first().ok_or(Error::InvalidBinding)?;
    let digests: Vec<Hash> = invocations.iter().map(|record| record.digest).collect();
    CommunityPassFailureV1::new(CommunityPassFailureInputV1 {
        pass_key: Some(pass_key),
        invocation_evidence_digests: CommunityDigestListV1::from_digests(&digests),
        host_failure: first.host_failure,
        host_decision_provenance_digest: first.provenance,
        evidence_not_after_micros: horizon,
    })
    .map(|record| DerivedFailureV1 {
        invocations,
        failure: record.to_canonical_cbor(),
        failure_digest: record.digest(),
    })
}

/// The CFI1 of `failure` by the due `member`, under `horizon`.
fn invocation_record(
    pass_key: CommunityPassKeyV1,
    member: &CommunityPassMemberDigestsV1,
    failure: &CommunityObservedFailureV1<'_>,
    horizon: u64,
) -> Result<InvocationRecordV1, Error> {
    let provenance = community_decision_provenance_digest_v1(CommunityDecisionProvenanceInputV1 {
        pass_key: Some(pass_key),
        member_binding_digest: member.cmb1_digest,
        prepared_invocation_digest: Some(member.cin1_digest),
        host_failure: Some(failure.host_failure),
        trust_snapshot_digest: member.trust_policy_snapshot_digest,
    });
    CommunityInvocationFailureV1::new(CommunityInvocationFailureInputV1 {
        pass_key: Some(pass_key),
        member_binding_digest: member.cmb1_digest,
        invocation_id: failure.invocation_id,
        prepared_invocation_digest: Some(member.cin1_digest),
        host_failure: failure.host_failure,
        guest_error: failure.guest_error,
        decision_provenance_digest: provenance,
        evidence_not_after_micros: horizon,
    })
    .map(|record| InvocationRecordV1 {
        bytes: record.to_canonical_cbor(),
        digest: record.digest(),
        member: member.cmb1_digest,
        provenance,
        host_failure: failure.host_failure,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
