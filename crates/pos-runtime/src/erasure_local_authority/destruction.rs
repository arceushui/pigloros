//! Attempt, acknowledgement and receipt admission of
//! `LocalErasureAuthorityV1` (ADR-136 §5 and §6).
//!
//! Every decision is a pure function of the verified bundle, the installed
//! TPS1 revocations and the host-built view. An attempt needs no signature:
//! it runs under the request's original authorization. Each owner result
//! and each receipt needs an ELS1 by the signer of the bundle its attempt
//! pins, which the installed TPS1 must not revoke.
//!
//! Automatic retry of transient owner results up to ELP1 `auto_retry_max`
//! is the C4 driver's scheduling (ADR-136 §6): the authority admits any
//! retry that recomputes, within the per-request attempt quota.

use pos_core::{
    local_erasure_receipt_body_reference_v1, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementProvenanceV1, ErasureAttemptQuotaReservationV1, ErasureErrorV1,
    ErasureLifecycleV1, ErasureReceiptInputV1, ErasureReceiptV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureRetryAdmissionV1, ErasureVerifiedStateV1, LocalErasureBundleV1,
    LocalErasureOwnerResultV1, LocalErasureSignaturePurposeV1, LocalErasureSignatureV1,
    LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};

use super::authority::LocalErasureAuthorityV1;
use super::freeze::{verified_signature, LOCAL_FREEZE_POSITION};
use super::LOCAL_ERASURE_QUOTA_ATTEMPTS_V1;
use crate::erasure_host::is_pre_terminal;
use crate::ErasureAuthorityReadViewV1;

/// The position attempt 0 is admitted at, one past the freeze (ADR-136 §6).
const FIRST_ATTEMPT_POSITION: u64 = LOCAL_FREEZE_POSITION + 1;

/// Whether attempt `ordinal`, counted from 0, is within the request's
/// lifetime attempt quota `quota_attempts` (ADR-136 §5): 64 attempts per
/// request. ERQ1 pins the compiled ELP1 (`authenticate` refuses any other),
/// so the pinned and the compiled quota are the same value.
const fn within_quota(ordinal: u64) -> bool {
    ordinal < LOCAL_ERASURE_QUOTA_ATTEMPTS_V1
}

/// The position the receipt of `attempt` issues at (ADR-136 §6): a
/// complete receipt at the position its executed obligations reach, each
/// advancing it by one, and a partial-failure receipt at the deadline.
fn issue_position(attempt: &ErasureRetryAdmissionV1, lifecycle: ErasureLifecycleV1) -> Option<u64> {
    if lifecycle == ErasureLifecycleV1::Complete {
        u64::try_from(attempt.unresolved_obligations().len())
            .ok()
            .and_then(|executed| attempt.admitted_position().checked_add(executed))
    } else {
        Some(attempt.deadline_position())
    }
}

/// The acknowledgement outcome an ELO1 stands for: a positive result
/// acknowledges, a negative one is negative. No ELO1 stands for `Stale`:
/// Local owners are synchronous, so a stale acknowledgement is refused.
const fn outcome_of(result: &LocalErasureOwnerResultV1) -> ErasureAcknowledgementOutcomeV1 {
    if result.error.is_none() {
        ErasureAcknowledgementOutcomeV1::Acknowledged
    } else {
        ErasureAcknowledgementOutcomeV1::Negative
    }
}

/// Whether ELO1 `result` is the owner result `acknowledgement` names: the
/// same request, attempt, obligation, command and owner, and the same
/// outcome (ADR-136 §5). An ELO1 of an earlier attempt is therefore never
/// admitted into a later one.
fn binds_acknowledgement(
    result: &LocalErasureOwnerResultV1,
    acknowledgement: &ErasureAcknowledgementProvenanceV1,
) -> bool {
    result.request == acknowledgement.request()
        && result.attempt == acknowledgement.attempt()
        && result.obligation == acknowledgement.obligation()
        && result.command == acknowledgement.command()
        && result.owner_ref == acknowledgement.owner()
        && outcome_of(result) == acknowledgement.outcome()
}

impl LocalErasureAuthorityV1 {
    /// Whether the installed TPS1 revokes `bundle`'s root or its signer
    /// (ADR-136 §5, *Compromise*).
    fn revoked(&self, bundle: &LocalErasureBundleV1) -> bool {
        self.revoked_key_ids
            .iter()
            .any(|key_id| *key_id == bundle.issued_by || *key_id == bundle.signer_key_id)
    }

    /// The bundle an attempt pins, while the installed TPS1 does not revoke
    /// it: an owner result or receipt needs an unrevoked signer (ADR-136
    /// §4), so a revocation blocks completion and expiry does not.
    fn live_bundle(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        trust: ErasureReferenceV1,
    ) -> Option<LocalErasureBundleV1> {
        self.pinned_bundle(view, trust)
            .filter(|bundle| !self.revoked(bundle))
    }

    /// Whether `state` holds its subject's one active erasure (ADR-136 §6).
    /// A complete or rejected request never does, and its attempt is not
    /// read. Otherwise, with an active attempt it does unless that attempt
    /// is pinned to a revoked bundle (§5); without one it does while
    /// pre-terminal. An attempt that cannot be read holds it.
    pub(super) fn subject_held_by(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        state: &ErasureVerifiedStateV1,
    ) -> bool {
        let lifecycle = state.lifecycle();
        !matches!(
            lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::Rejected
        ) && view
            .active_attempt(state.request().reference())
            .map_or(true, |active| {
                active.map_or(is_pre_terminal(lifecycle), |attempt| {
                    !self
                        .pinned_bundle(view, attempt.trust())
                        .is_some_and(|bundle| self.revoked(&bundle))
                })
            })
    }

    /// Whether another request of `erq1`'s subject holds it.
    fn subject_held_elsewhere(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        erq1: &ErasureRequestV1,
    ) -> bool {
        view.verified_requests()
            .into_iter()
            .filter(|state| {
                state.request().subject() == erq1.subject()
                    && state.request().reference() != erq1.reference()
            })
            .any(|state| self.subject_held_by(view, state))
    }

    /// The ADR-136 §6 positions of `admission`: attempt 0 is admitted at 2
    /// with the ERQ1 horizon as its deadline, and a retry one past its
    /// source receipt's issue position, with its deadline one attempt
    /// window later.
    fn attempt_positions(
        view: &dyn ErasureAuthorityReadViewV1,
        erq1: &ErasureRequestV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Option<(u64, u64)> {
        admission.source_receipt().map_or(
            Some((FIRST_ATTEMPT_POSITION, erq1.horizon_position())),
            |source| {
                view.retained_object(source)
                    .and_then(|bytes| ErasureReceiptV1::from_canonical_cbor(&bytes).ok())
                    .and_then(|receipt| receipt.issue_position().checked_add(1))
                    .and_then(|admitted| {
                        admitted
                            .checked_add(LOCAL_ERASURE_ATTEMPT_WINDOW_V1)
                            .map(|deadline| (admitted, deadline))
                    })
            },
        )
    }

    /// Whether ERRA1 is the attempt ADR-136 §5 derives for `erq1`: within
    /// the lifetime attempt quota, under the request's own ERAZ1 and the
    /// ELP1 ERQ1 pins, at the §6 positions, pinning the bundle current at
    /// admission. That bundle's ELB1 must already be retained under the
    /// pinned `CA(ELB1)`, so recovery can resolve it after a rotation.
    fn binds_attempt(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        erq1: &ErasureRequestV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> bool {
        within_quota(admission.attempt_ordinal())
            && admission.authorization_provenance() == erq1.authorization()
            && admission.policy() == erq1.policy()
            && view
                .retained_object(admission.trust())
                .and_then(|bytes| LocalErasureBundleV1::from_canonical_cbor(&bytes).ok())
                .is_some_and(|bundle| bundle == self.bundle)
            && Self::attempt_positions(view, erq1, admission)
                == Some((admission.admitted_position(), admission.deadline_position()))
    }

    /// Admit one attempt of a request the installed inventory holds, whose
    /// ERAZ1 still verifies at its bound position. The reservation is the
    /// admission itself: the authority is stateless, and the committed
    /// attempt is what counts against the quota.
    ///
    /// # Errors
    /// `PolicyConflict` for an unknown request, an attempt that differs
    /// from its derivation or exceeds the quota, or while another request
    /// of the subject holds it; `Unauthorized` when the ERAZ1 fails.
    pub(super) fn attempt_admitted(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        view.verified_request(admission.request())
            .map(|state| state.request().clone())
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|erq1| {
                self.verified_authorization(view, &erq1, false)
                    .map(|_| erq1)
            })
            .and_then(|erq1| {
                (self.binds_attempt(view, &erq1, admission)
                    && !self.subject_held_elsewhere(view, &erq1))
                .then_some(ErasureAttemptQuotaReservationV1::new(
                    admission.reference(),
                    admission.reference(),
                ))
                .ok_or(ErasureErrorV1::PolicyConflict)
            })
    }

    /// The ELO1 a purpose-1 ELS1 `evidence` signs, verified with `bundle`'s
    /// signer key. The ELO1 must recompute to the signed digest, in defence
    /// in depth over the content-addressed read.
    fn owner_result(
        view: &dyn ErasureAuthorityReadViewV1,
        bundle: &LocalErasureBundleV1,
        evidence: &[u8],
    ) -> Option<LocalErasureOwnerResultV1> {
        LocalErasureSignatureV1::from_canonical_cbor(evidence)
            .ok()
            .map(|signature| signature.signed_digest)
            .filter(|digest| {
                verified_signature(
                    bundle,
                    LocalErasureSignaturePurposeV1::OwnerResult,
                    *digest,
                    evidence,
                )
            })
            .and_then(|digest| {
                view.retained_object(digest)
                    .and_then(|bytes| LocalErasureOwnerResultV1::from_canonical_cbor(&bytes).ok())
                    .filter(|result| result.reference().ok() == Some(digest))
            })
    }

    /// Admit one owner acknowledgement (ADR-136 §5): its owner must be an
    /// owner of the bundle its attempt pins, whose `owner_ref` the bundle
    /// codec derives from the store, category and acknowledgement class;
    /// its evidence must be a purpose-1 ELS1 by that bundle's signer over
    /// an ELO1 that binds it. A `Stale` acknowledgement never binds one.
    ///
    /// # Errors
    /// `TrustSnapshotInvalid` when the pinned bundle is unknown or revoked;
    /// otherwise `Unauthorized`.
    pub(super) fn acknowledgement_admitted(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.live_bundle(view, acknowledgement.trust())
            .ok_or(ErasureErrorV1::TrustSnapshotInvalid)
            .and_then(|bundle| {
                view.retained_object(acknowledgement.evidence())
                    .filter(|_| {
                        bundle
                            .owners
                            .iter()
                            .any(|row| row.owner_ref == acknowledgement.owner())
                    })
                    .and_then(|evidence| Self::owner_result(view, &bundle, &evidence))
                    .filter(|result| binds_acknowledgement(result, acknowledgement))
                    .map(drop)
                    .ok_or(ErasureErrorV1::Unauthorized)
            })
    }

    /// Admit one receipt of the active attempt (ADR-136 §5): it must issue
    /// at its §6 position, and its signature must name a purpose-2 ELS1 over
    /// its ERCB1 by the signer of the bundle the attempt pins.
    ///
    /// # Errors
    /// `ProvenanceMissing` without a readable active attempt,
    /// `TrustSnapshotInvalid` when the pinned bundle is unknown or revoked,
    /// `PolicyConflict` for another issue position, otherwise
    /// `Unauthorized`.
    pub(super) fn receipt_admitted(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<(), ErasureErrorV1> {
        view.active_attempt(input.request)
            .ok()
            .flatten()
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|attempt| {
                self.live_bundle(view, attempt.trust())
                    .ok_or(ErasureErrorV1::TrustSnapshotInvalid)
                    .and_then(|bundle| {
                        (issue_position(&attempt, input.lifecycle) == Some(input.issue_position))
                            .then_some(bundle)
                            .ok_or(ErasureErrorV1::PolicyConflict)
                    })
            })
            .and_then(|bundle| {
                ErasureReceiptV1::new(input.clone())
                    .and_then(|receipt| local_erasure_receipt_body_reference_v1(&receipt))
                    .and_then(|body| {
                        view.retained_object(input.signature)
                            .filter(|evidence| {
                                verified_signature(
                                    &bundle,
                                    LocalErasureSignaturePurposeV1::ReceiptBody,
                                    body,
                                    evidence,
                                )
                            })
                            .map(drop)
                            .ok_or(ErasureErrorV1::Unauthorized)
                    })
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn the_attempt_quota_admits_exactly_its_64_ordinals() {
        assert!(within_quota(0));
        assert!(within_quota(LOCAL_ERASURE_QUOTA_ATTEMPTS_V1 - 1));
        assert!(!within_quota(LOCAL_ERASURE_QUOTA_ATTEMPTS_V1));
        assert_eq!(LOCAL_ERASURE_QUOTA_ATTEMPTS_V1, 64);
    }
}
