//! The core of the quarantine reset (#560 A4e-3; ADR-129 annex "Reset
//! authority and compare-and-swap", R8.5(4), R15.2(1) and R15.3(6)).
//!
//! [`MemoryCommunityDomainV1::reset_quarantine`] appends one CQR1 with an
//! empty active set to a member's ledger, or returns the original outcome
//! of a retry. It runs, in order:
//!
//! 1. the CQK1 (3);
//! 2. the retry lookup by `(T, control_operation_id)`: the original CQO1 for
//!    identical bound content, otherwise 4;
//! 3. the trust premises (12): the retained TPS1 is the call's and its
//!    digest the expected snapshot, and this domain's registry evaluates the
//!    member's current release (a revoked release stays denied);
//! 4. the generation (5) and head (6), the member of that generation (12),
//!    no unresolved pass of T (7), the quarantine index row (12 when there
//!    is none) and its ledger digest and complete reason set (4).
//!
//! The reset never reads the evidence of a reason it clears (R15.2(1)): the
//! expected ledger digest and reason set are compared with the domain-private
//! index alone, and the new ledger carries the reset's own metadata horizon.
//! It re-arms only the `F_q` shares a pre-execution `SetReason` spent
//! (R15.3(6)).
//!
//! The commit advances the inventory generation once, as every committed
//! control does. The principal and authorization refs and the authorization
//! deadline are caller-supplied and opaque here: their verification, the
//! reset's CAV1, CAU1, metadata key and registrations are slice R15-6's.

use std::collections::BTreeMap;

use pos_core::community_lifecycle::{
    community_decision_provenance_digest_v1, ArtifactRefV1, CommunityDecisionProvenanceInputV1,
    CommunityLifecycleErrorV1 as Error, CommunityQuarantineControlInputV1,
    CommunityQuarantineControlKindV1, CommunityQuarantineControlV1,
    CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1, CommunityQuarantineOutcomeInputV1,
    CommunityQuarantineOutcomeV1, CommunityQuarantineReasonEvidenceV1,
    CommunityQuarantineReasonsV1, CommunityQuarantineRevisionInputV1,
    CommunityQuarantineRevisionV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, ImplementationKeyV1, TimelineId};

use super::{
    CommittedQuarantineControlV1, CommunityPreExecutionTrustV1, CommunityQuarantineContextV1,
    CommunityQuarantineReceiptV1, ControlBoundV1, MemberRefV1, MemberV1, QuarantineLedgerV1,
    ResetBoundV1,
};
use crate::community::lifecycle_authority::CommunityLifecycleAuthorityV1;
use crate::community::memory_domain::MemoryCommunityDomainV1;
use crate::community::store_domain::CommunityStoreDomainV1;

/// One quarantine reset caller form: the CQC1 premises the caller expects.
///
/// The refs and the deadline are opaque inputs of the trusted composition
/// root (annex "Reset authority and compare-and-swap"). No API accepts CQC1,
/// CQR1 or CQO1 bytes.
#[derive(Clone, Copy)]
pub struct CommunityQuarantineResetCallV1<'a> {
    /// The quarantine Timeline T.
    pub timeline: TimelineId,
    /// The member's admitted stable World entry.
    pub stable_entry: &'a str,
    /// The member's implementation (IMK1).
    pub implementation: &'a ImplementationKeyV1,
    /// The host-selected nonzero control identity, scoped to T.
    pub control_operation_id: [u8; 16],
    /// The current CQR1 head.
    pub expected_ledger_digest: Hash,
    /// The complete expected active reason set, with each CFO1 digest.
    pub expected_reasons: &'a [CommunityQuarantineReasonEvidenceV1],
    /// T's active generation.
    pub expected_generation: [u8; 16],
    /// T's current complete selected head.
    pub expected_state_head_digest: Hash,
    /// The TPS1 digest the caller expects the trust scope to retain.
    pub trust_snapshot_digest: Hash,
    /// The trust evidence the store re-evaluates on its own registry.
    pub trust: CommunityPreExecutionTrustV1<'a>,
    /// The CQC1 principal ref.
    pub principal_ref: ArtifactRefV1,
    /// The CQC1 authorization ref.
    pub authorization_ref: ArtifactRefV1,
    /// The absolute authorization deadline of the CQC1.
    pub authorization_not_after_micros: u64,
}

/// The CQC1, CQR1 and CQO1 of one reset, and the ledger they select.
struct ResetRecordsV1 {
    request_digest: Hash,
    outcome: zeroize::Zeroizing<Vec<u8>>,
    ledger: QuarantineLedgerV1,
}

/// What the premises of a first reset found: the records and what the commit
/// retains.
struct ResetPremisesV1 {
    records: ResetRecordsV1,
    generation: [u8; 16],
    /// The reasons whose `F_q` share a pre-execution `SetReason` spent.
    spent: u64,
}

impl MemoryCommunityDomainV1 {
    /// Reset the quarantine of one member, or return the original outcome of
    /// a retry.
    ///
    /// Only the trusted composition root, which holds the
    /// [`AuthorityTrustRootSealV1`], resets:
    ///
    /// ```compile_fail,E0061
    /// use pos_store::community::{
    ///     CommunityLifecycleAuthorityV1, CommunityQuarantineContextV1,
    ///     CommunityQuarantineResetCallV1, MemoryCommunityDomainV1,
    /// };
    /// fn forge(
    ///     domain: &mut MemoryCommunityDomainV1,
    ///     context: CommunityQuarantineContextV1<'_>,
    ///     lifecycle: &CommunityLifecycleAuthorityV1,
    ///     call: &CommunityQuarantineResetCallV1<'_>,
    /// ) {
    ///     let _ = domain.reset_quarantine(context, lifecycle, call);
    /// }
    /// ```
    ///
    /// # Errors
    /// `InvalidBinding` for an invalid CQK1 and a CDP1 other than the
    /// generation's; `Conflict` for a retry with other bound content, another
    /// expected ledger and another reason set; `EvidenceUnavailable` for a
    /// TPS1 other than the call's, a release the registry does not currently
    /// admit (a revoked one stays denied), a CQK1 with no CMB1 in the
    /// generation and no index row; `StaleGeneration` and `StaleFrontier`
    /// for a moved generation or head; `PassUnresolved` while T has an
    /// unresolved pass; and the codec refusals.
    pub fn reset_quarantine(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        call: &CommunityQuarantineResetCallV1<'_>,
    ) -> Result<CommunityQuarantineReceiptV1, Error> {
        CommunityQuarantineKeyV1::new(call.timeline, call.stable_entry, call.implementation)
            .and_then(|cqk1| {
                let bound = reset_bound(call, cqk1.digest());
                match self
                    .quarantine_controls
                    .get(&(call.timeline, call.control_operation_id))
                {
                    Some(original)
                        if matches!(&original.bound, ControlBoundV1::Reset(held) if *held == bound) =>
                    {
                        Ok(original.receipt.clone())
                    }
                    Some(_) => Err(Error::Conflict),
                    None => self
                        .reset_premises(lifecycle, context, call, cqk1)
                        .map(|premises| self.retain_reset(call, (cqk1.digest(), bound), premises)),
                }
            })
    }

    /// The premises of a first reset, in order, and its records.
    fn reset_premises(
        &self,
        lifecycle: &CommunityLifecycleAuthorityV1,
        context: CommunityQuarantineContextV1<'_>,
        call: &CommunityQuarantineResetCallV1<'_>,
        cqk1: CommunityQuarantineKeyV1<'_>,
    ) -> Result<ResetPremisesV1, Error> {
        self.verify_reset_trust(lifecycle.trust_scope(), call)?;
        let member = self.member_at(
            context,
            &MemberRefV1 {
                timeline: call.timeline,
                stable_entry: call.stable_entry,
                implementation: call.implementation,
                pmf1_digest: call.trust.projection.pmf1_digest(),
            },
            (call.expected_generation, call.expected_state_head_digest),
        )?;
        if self.unresolved_pass(call.timeline).is_some() {
            return Err(Error::PassUnresolved);
        }
        let current = self
            .quarantine_index
            .get(&cqk1.digest())
            .ok_or(Error::EvidenceUnavailable)?;
        if current.head != call.expected_ledger_digest || !same_reasons(current, call) {
            return Err(Error::Conflict);
        }
        reset_records(context, call, (cqk1, &member), current).map(|records| ResetPremisesV1 {
            records,
            generation: member.generation,
            spent: current
                .states
                .values()
                .filter(|state| state.share_spent)
                .count() as u64,
        })
    }

    /// The re-verification under the guard: the retained TPS1 is the call's
    /// and its digest the expected snapshot, and this domain's own registry
    /// evaluates the member's current release. A revoked release fails the
    /// evaluation, so a reset cannot override Revoked.
    fn verify_reset_trust(
        &self,
        scope: &str,
        call: &CommunityQuarantineResetCallV1<'_>,
    ) -> Result<(), Error> {
        CommunityStoreDomainV1::plugin_trust_policy(self, scope).and_then(|policy| {
            if policy.tps1_bytes() == call.trust.tps1_bytes
                && Hash::from_bytes(policy.tps1_digest()) == call.trust_snapshot_digest
                && self.evaluate_release(call.trust).is_ok()
            {
                Ok(())
            } else {
                Err(Error::EvidenceUnavailable)
            }
        })
    }

    /// Retain the reset: the successor ledger, the retry index entry, the
    /// re-armed `F_q` shares and the advanced inventory generation. The records are CQC1, CQR1 and CQO1 only (the
    /// reset's registrations and metadata records are R15-6's).
    fn retain_reset(
        &mut self,
        call: &CommunityQuarantineResetCallV1<'_>,
        (key, bound): (Hash, ResetBoundV1),
        premises: ResetPremisesV1,
    ) -> CommunityQuarantineReceiptV1 {
        let ResetPremisesV1 {
            records,
            generation,
            spent,
        } = premises;
        let receipt = CommunityQuarantineReceiptV1 {
            timeline: call.timeline,
            control_operation_id: call.control_operation_id,
            request_digest: records.request_digest,
            selected_ledger_digest: records.ledger.head,
            already_quarantined: false,
            outcome: records.outcome,
        };
        self.count_quarantine_pairs(call.timeline, spent, 0);
        self.inventory_generation += 1;
        self.quarantine_index.insert(key, records.ledger);
        self.quarantine_controls.insert(
            (call.timeline, call.control_operation_id),
            CommittedQuarantineControlV1 {
                bound: ControlBoundV1::Reset(bound),
                generation,
                sealed: None,
                admission: None,
                receipt: receipt.clone(),
            },
        );
        receipt
    }
}

/// The bound content of the reset `call` of the quarantine key `key`.
fn reset_bound(call: &CommunityQuarantineResetCallV1<'_>, key: Hash) -> ResetBoundV1 {
    ResetBoundV1 {
        key,
        expected_ledger: call.expected_ledger_digest,
        reasons: call
            .expected_reasons
            .iter()
            .map(|row| (row.reason.code(), row.failure_evidence_digest))
            .collect(),
        expected_generation: call.expected_generation,
        expected_head: call.expected_state_head_digest,
        trust_snapshot_digest: call.trust_snapshot_digest,
        principal_ref: call.principal_ref,
        authorization_ref: call.authorization_ref,
        authorization_not_after_micros: call.authorization_not_after_micros,
    }
}

/// Whether the call's expected reasons are the ledger's active set exactly:
/// the same codes and CFO1 digests, in code order.
fn same_reasons(current: &QuarantineLedgerV1, call: &CommunityQuarantineResetCallV1<'_>) -> bool {
    current.reasons.len() == call.expected_reasons.len()
        && current
            .reasons
            .iter()
            .zip(call.expected_reasons)
            .all(|(held, expected)| {
                held.reason.code() == expected.reason.code()
                    && held.failure_evidence_digest == expected.failure_evidence_digest
            })
}

/// The CQC1 `AuthenticatedReset` with the R8.5(4) provenance of the current
/// admission, the CQR1 with an empty active set whose horizon is the
/// reset's own metadata horizon (R15.2(1)), and the CQO1.
fn reset_records(
    context: CommunityQuarantineContextV1<'_>,
    call: &CommunityQuarantineResetCallV1<'_>,
    (cqk1, member): (CommunityQuarantineKeyV1<'_>, &MemberV1),
    current: &QuarantineLedgerV1,
) -> Result<ResetRecordsV1, Error> {
    let provenance = community_decision_provenance_digest_v1(CommunityDecisionProvenanceInputV1 {
        pass_key: None,
        member_binding_digest: member.member_binding_digest,
        prepared_invocation_digest: None,
        host_failure: None,
        trust_snapshot_digest: call.trust_snapshot_digest,
    });
    let horizon = context
        .binding
        .metadata_policy
        .as_input()
        .metadata_not_after_micros;
    let ordinal = current.ordinal + 1;
    CommunityQuarantineControlV1::new(CommunityQuarantineControlInputV1 {
        control_operation_id: call.control_operation_id,
        key: cqk1,
        expected_ledger_digest: Some(current.head),
        operation: CommunityQuarantineControlKindV1::AuthenticatedReset,
        bound_reasons: CommunityQuarantineReasonsV1::from_reasons(call.expected_reasons),
        trust_snapshot_digest: call.trust_snapshot_digest,
        expected_generation: call.expected_generation,
        expected_state_head_digest: call.expected_state_head_digest,
        principal_ref: Some(call.principal_ref),
        authorization_ref: Some(call.authorization_ref),
        authorization_not_after_micros: call.authorization_not_after_micros,
        host_decision_provenance_digest: provenance,
    })
    .and_then(|request| {
        CommunityQuarantineRevisionV1::new(CommunityQuarantineRevisionInputV1 {
            key: cqk1,
            ledger_ordinal: ordinal,
            predecessor_ledger_digest: Some(current.head),
            active_reasons: CommunityQuarantineReasonsV1::from_reasons(&[]),
            control_request_digest: request.digest(),
            evidence_not_after_micros: horizon,
        })
        .and_then(|revision| {
            CommunityQuarantineOutcomeV1::new(CommunityQuarantineOutcomeInputV1 {
                control_operation_id: call.control_operation_id,
                control_request_digest: request.digest(),
                prior_ledger_digest: Some(current.head),
                selected_ledger_digest: revision.digest(),
                disposition: CommunityQuarantineDispositionV1::Applied,
                evidence_not_after_micros: horizon,
            })
            .map(|outcome| ResetRecordsV1 {
                request_digest: request.digest(),
                outcome: outcome.to_canonical_cbor(),
                ledger: QuarantineLedgerV1 {
                    head: revision.digest(),
                    ordinal,
                    reasons: Vec::new(),
                    evidence_not_after_micros: horizon,
                    states: BTreeMap::new(),
                },
            })
        })
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
