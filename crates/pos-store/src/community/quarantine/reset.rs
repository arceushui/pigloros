//! The core of the quarantine reset (#560 A4e-3 and R15-6a; ADR-129 annex
//! "Reset authority and compare-and-swap", R8.5(4), R15.2(1), R15.3(6),
//! R16.6 and R16.7).
//!
//! [`MemoryCommunityDomainV1::reset_quarantine`] appends one CQR1 with an
//! empty active set to a member's ledger, or returns the original outcome
//! of a retry. It runs, in the R16.7 order:
//!
//! 1. the shape (3): the CQK1 and the derived `community.quarantine.reset.v1`
//!    request, which refuses a zero Timeline or control identity;
//! 2. the authority (12): the FAE1 with its one trusted-clock reservation
//!    `t_r`, the administrative decision and a fresh metadata `write`
//!    decision. The bound is `B = min(t_r + 32 s, FAE1 expiry, metadata
//!    owner expiry)`;
//! 3. the retry lookup by `(T, control_operation_id)`: a committed
//!    materialization `M_id` of T (4), a retained `SetReason` (4), a retained
//!    reset with other bound content or another leaf grantee (4), otherwise
//!    the original receipt. The retry at the retained CQO1's horizon (13)
//!    and the sealed CQO1 read (12) belong to slice R15-6b with the reset's
//!    sealed records;
//! 4. the first-reset premises: this domain's registry evaluates the
//!    member's current release under its own retained anchor and TPS1 from
//!    the caller's PTR1/PRV1 histories (12, a revoked release stays denied),
//!    the generation (5) and head (6), the member of that generation whose
//!    PMF1 is the evidence's (12), no unresolved pass of T (7), the quarantine
//!    index row (12 when there is none), its ledger digest and complete
//!    reason set (4) and then the erasure budget for the re-armed `F_q`
//!    shares (14, never for a reset that re-arms none);
//! 5. the writer: the administrative and metadata decisions and the registry
//!    TPS1 digest still equal the evaluated ones, the writer is before `B`,
//!    and the inventory generation and CSI1 are unmoved (12), then one
//!    atomic commit.
//!
//! The reset never reads the evidence of a reason it clears (R15.2(1)): the
//! expected ledger digest and reason set are compared with the domain-private
//! index alone, and the new ledger carries the reset's own metadata horizon.
//! It re-arms only the `F_q` shares a pre-execution `SetReason` spent
//! (R15.3(6)).
//!
//! This domain has no context-wide operation guard (17, or 15): neither the
//! `SetReason` nor the authenticated Abort has one, and the pass's own live
//! call is judged by the pass planner. A reset's guard lands with A5.
//!
//! The commit advances the inventory generation once, as every committed
//! control does. The reset's CAV1, CAU1, metadata key and sealed records are
//! slice R15-6b's.

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
use pos_core::{
    AuthorityGranteeV1, AuthorityTrustRootSealV1, AuthorizationDecisionV1, Hash,
    ImplementationKeyV1, Seq, TimelineId,
};
use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;

use super::{
    CommittedQuarantineControlV1, CommunityQuarantineContextV1, CommunityQuarantineReceiptV1,
    MemberRefV1, MemberV1, QuarantineLedgerV1, ResetBoundV1, RetainedControlV1, RetainedResetV1,
};
use crate::community::lifecycle_authority::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1,
    CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1, CommunityLifecycleAuthorityV1,
};
use crate::community::memory_domain::MemoryCommunityDomainV1;
use crate::community::metadata_authority::{CommunityMetadataAuthorityV1, MetadataActionV1};
use crate::community::store_domain::CommunityStoreDomainV1;
#[cfg(target_os = "linux")]
use crate::plugin_trust_registry::{PluginTrustPolicyRegistryV1, TrustedUtcSecondV1};

/// The Tick of the reset's trust evaluation: T's committed host Tick from
/// the selected CST1, which is 0 while CST1 holds `[0]` (R16.6). No Commit
/// exists yet, so every CST1 holds `[0]`; A5 Commit supplies the real Tick.
const RESET_TRUST_TICK: u64 = 0;

/// One quarantine reset caller form (R16.6).
///
/// It carries the premises the caller expects, its one FAE1 and the
/// untrusted locators of its administrative decision and trust evidence. The
/// host derives the principal and authorization refs, the deadline `B`, the
/// TPS1 digest and the provenance. No API accepts CQC1, CQR1 or CQO1 bytes.
#[derive(Clone, Copy)]
pub struct CommunityQuarantineResetCallV1<'a> {
    /// The call's one canonical FAE1 (R6.2(1)).
    pub credential: &'a [u8],
    /// The leaf grant of the administrative decision.
    pub administrative_leaf: Hash,
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
    /// The member release's trust evidence, which the registry verifies.
    pub trust_evidence: CommunityResetTrustEvidenceV1<'a>,
}

/// The trust evidence of a reset's member release: untrusted locators.
///
/// The registry verifies the raw PTR1 and PRV1 histories at the host-derived
/// UTC second and Tick under its own retained anchor, so a caller never
/// builds verified evidence for coordinates only the host knows.
#[derive(Clone, Copy)]
pub struct CommunityResetTrustEvidenceV1<'a> {
    /// The complete PTR1 history, genesis first.
    pub ptr1_histories: &'a [&'a [u8]],
    /// The complete PRV1 history, genesis first.
    pub prv1_histories: &'a [&'a [u8]],
    /// The member release's manifest projection.
    pub projection: &'a ValidatedPluginManifestProjectionV1,
}

/// The CQC1, CQR1 and CQO1 of one reset, and the ledger they select.
struct ResetRecordsV1 {
    request_digest: Hash,
    outcome: zeroize::Zeroizing<Vec<u8>>,
    ledger: QuarantineLedgerV1,
}

/// A decision's leaf grant, authority head and chain bindings: what a later
/// re-evaluation must find unchanged.
type DecisionKeyV1 = (Option<Hash>, Seq, Vec<Hash>);

fn decision_key(decision: &AuthorizationDecisionV1) -> DecisionKeyV1 {
    (
        decision.grant_id(),
        decision.at_position(),
        decision.grant_chain_bindings().to_vec(),
    )
}

/// What the writer compares: the administrative decision's leaf and
/// authorization ref, the metadata decision's key and the registry's TPS1
/// digest.
type ResetDecisionsV1 = (Hash, ArtifactRefV1, DecisionKeyV1, Hash);

/// What the authority steps of a reset found: the host-derived CQC1 fields
/// and the decisions the writer re-checks.
struct ResetAuthorityV1 {
    leaf_grant_id: Hash,
    principal_ref: ArtifactRefV1,
    authorization_ref: ArtifactRefV1,
    /// The reservation sample `t_r`.
    sample_micros: u64,
    /// The deadline `B`.
    bound_micros: u64,
    metadata: DecisionKeyV1,
}

/// What the premises of a first reset found: the records and what the commit
/// retains.
struct ResetPremisesV1 {
    records: ResetRecordsV1,
    /// The reasons whose `F_q` share a pre-execution `SetReason` spent.
    spent: u64,
    /// The TPS1 digest the registry evaluated under.
    trust_snapshot_digest: Hash,
    /// The CSI1 address the premises read.
    selection_address: Hash,
}

/// Everything one reset commits, staged before the writer.
struct StagedResetV1 {
    key: Hash,
    control: (TimelineId, [u8; 16]),
    bound: ResetBoundV1,
    authority: ResetAuthorityV1,
    premises: ResetPremisesV1,
    /// The inventory generation the operation read.
    inventory_generation: u64,
}

/// The outcome of every step before the writer.
enum ResetPreparedV1 {
    /// A retry's original receipt.
    Original(CommunityQuarantineReceiptV1),
    /// A new reset and the call whose bound the writer checks.
    Staged(Box<StagedResetV1>, CommunityAuthorityCallV1),
}

/// What the records of one reset are built from.
struct ResetFactsV1<'a> {
    call: &'a CommunityQuarantineResetCallV1<'a>,
    authority: &'a ResetAuthorityV1,
    trust_snapshot_digest: Hash,
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
    ///     CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityV1,
    ///     CommunityQuarantineContextV1, CommunityQuarantineResetCallV1,
    ///     MemoryCommunityDomainV1,
    /// };
    /// fn forge(
    ///     domain: &mut MemoryCommunityDomainV1,
    ///     context: CommunityQuarantineContextV1<'_>,
    ///     lifecycle: &mut CommunityLifecycleAuthorityV1,
    ///     metadata: &mut CommunityMetadataAuthorityV1,
    ///     call: &CommunityQuarantineResetCallV1<'_>,
    /// ) {
    ///     let _ = domain.reset_quarantine(context, lifecycle, metadata, call);
    /// }
    /// ```
    ///
    /// # Errors
    /// In the R16.7 order: `InvalidBinding` for an invalid CQK1, a zero
    /// Timeline or control identity and a CDP1 other than the generation's;
    /// `EvidenceUnavailable` for every authority failure, a release the
    /// registry does not currently admit (a revoked one stays denied), a
    /// CQK1 with no CMB1 in the generation or whose PMF1 is not the
    /// evidence's, no index row, and a writer whose decisions, TPS1 digest,
    /// inventory generation or CSI1 moved or whose time is at or after `B`;
    /// `Conflict` for a control identity that is a committed `M_id`, a
    /// retained `SetReason`, a retry with other bound content or by another
    /// principal, and another expected ledger and reason set;
    /// `StaleGeneration` and `StaleFrontier` for a moved generation or head;
    /// `PassUnresolved` while T has an unresolved pass; `CapacityExhausted`
    /// (14) when re-arming the spent `F_q` shares does not fit the erasure
    /// budget of T's scope (the quarantine stays, R13.1(3)); and the codec
    /// refusals.
    pub fn reset_quarantine(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: &CommunityQuarantineResetCallV1<'_>,
    ) -> Result<CommunityQuarantineReceiptV1, Error> {
        match self.prepare_reset(context, lifecycle, metadata, call)? {
            ResetPreparedV1::Original(receipt) => Ok(receipt),
            ResetPreparedV1::Staged(staged, authenticated) => {
                self.commit_reset(context, lifecycle, metadata, (*staged, authenticated))
            }
        }
    }

    /// Every step before the writer.
    fn prepare_reset(
        &mut self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        call: &CommunityQuarantineResetCallV1<'_>,
    ) -> Result<ResetPreparedV1, Error> {
        let cqk1 =
            CommunityQuarantineKeyV1::new(call.timeline, call.stable_entry, call.implementation)?;
        let request = CommunityAdministrativeRequestV1::derive(
            &CommunityAdministrativeOperationV1::QuarantineReset {
                timeline: call.timeline,
                control_operation_id: call.control_operation_id,
            },
        )?;
        CommunityQuarantineReasonsV1::from_reasons(call.expected_reasons)
            .validate()
            .or(Err(Error::InvalidBinding))?;
        let authenticated = lifecycle.authenticate(call.credential, request, self)?;
        let administrative =
            lifecycle.authorize_administrative(&authenticated, self, call.administrative_leaf)?;
        let write = self.reset_metadata_write(context, metadata)?;
        let authenticated = authenticated.bounded_by(metadata.owner_expires_at());
        let bound = reset_bound(call, cqk1.digest());
        let control = (call.timeline, call.control_operation_id);
        if let Some(retry) = self.reset_retry(control, &bound, &administrative) {
            return retry.map(ResetPreparedV1::Original);
        }
        let authority = ResetAuthorityV1 {
            leaf_grant_id: administrative.leaf_grant_id(),
            principal_ref: administrative.principal_ref(),
            authorization_ref: administrative.authorization_ref(),
            sample_micros: authenticated.at_time().as_micros(),
            bound_micros: authenticated.decision_bound().as_micros(),
            metadata: write,
        };
        self.reset_premises(lifecycle, context, call, (cqk1, &authority))
            .map(|premises| {
                let staged = StagedResetV1 {
                    key: cqk1.digest(),
                    control,
                    bound,
                    authority,
                    premises,
                    inventory_generation: CommunityStoreDomainV1::inventory_generation(self),
                };
                ResetPreparedV1::Staged(Box::new(staged), authenticated)
            })
    }

    /// The metadata `write` decision of the reset, which alone admits every
    /// CNE1 read or write (A5.4, no latch).
    ///
    /// This copies `abort_metadata_write` of `pass_abort/operator.rs`, to be
    /// unified with it once #1599 lands.
    fn reset_metadata_write(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        metadata: &mut CommunityMetadataAuthorityV1,
    ) -> Result<DecisionKeyV1, Error> {
        let policy = context.binding.metadata_policy;
        CommunityStoreDomainV1::load_authority(
            self,
            policy.as_input().metadata_authority_leaf_grant,
        )
        .ok()
        .and_then(|persisted| {
            metadata
                .authorize_request(
                    policy,
                    &persisted,
                    self.store_incarnation,
                    MetadataActionV1::Write,
                )
                .ok()
        })
        .map(|(_request, decision)| decision_key(&decision))
        .ok_or(Error::EvidenceUnavailable)
    }

    /// The A5.5 step-4 lookup of a reset under `control`: 4 when the identity
    /// is a committed materialization's `M_id` (R16.9(2)), 4 for a retained
    /// `SetReason`, other bound content or another leaf grantee (A5.3(6)),
    /// otherwise the original receipt of a retry, if any.
    fn reset_retry(
        &self,
        control: (TimelineId, [u8; 16]),
        bound: &ResetBoundV1,
        administrative: &CommunityAuthorityAdmissionV1,
    ) -> Option<Result<CommunityQuarantineReceiptV1, Error>> {
        if self.materialization_ids.contains(&control) {
            return Some(Err(Error::Conflict));
        }
        self.quarantine_controls
            .get(&control)
            .map(|original| match &original.kind {
                RetainedControlV1::Reset(held)
                    if held.bound == *bound
                        && self.is_grantee(held.leaf_grant_id, administrative) =>
                {
                    Ok(original.receipt.clone())
                }
                _ => Err(Error::Conflict),
            })
    }

    /// Whether the decision's principal is the grantee of `leaf_grant_id`'s
    /// leaf grant. A leaf grant that no longer loads has no grantee, so it is
    /// not the decision's principal and the retry gives 4 (A5.3(6)).
    fn is_grantee(
        &self,
        leaf_grant_id: Hash,
        administrative: &CommunityAuthorityAdmissionV1,
    ) -> bool {
        CommunityStoreDomainV1::load_authority(self, leaf_grant_id)
            .ok()
            .and_then(|persisted| {
                persisted
                    .chain()
                    .grants()
                    .last()
                    .map(|grant| grant.grantee().clone())
            })
            == Some(AuthorityGranteeV1::Principal(
                administrative.decision().principal().clone(),
            ))
    }

    /// The premises of a first reset, in order, and its records.
    fn reset_premises(
        &self,
        lifecycle: &CommunityLifecycleAuthorityV1,
        context: CommunityQuarantineContextV1<'_>,
        call: &CommunityQuarantineResetCallV1<'_>,
        (cqk1, authority): (CommunityQuarantineKeyV1<'_>, &ResetAuthorityV1),
    ) -> Result<ResetPremisesV1, Error> {
        let trust_snapshot_digest =
            self.evaluate_reset_trust(lifecycle.trust_scope(), call, authority.sample_micros)?;
        let member = self.member_at(
            context,
            &MemberRefV1 {
                timeline: call.timeline,
                stable_entry: call.stable_entry,
                implementation: call.implementation,
                pmf1_digest: call.trust_evidence.projection.pmf1_digest(),
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
        if !is_current(current, call) {
            return Err(Error::Conflict);
        }
        let spent = current
            .states
            .values()
            .filter(|state| state.share_spent)
            .count() as u64;
        self.check_rearm_budget(call.timeline, spent)?;
        reset_records(
            context,
            (cqk1, &member),
            current,
            &ResetFactsV1 {
                call,
                authority,
                trust_snapshot_digest,
            },
        )
        .map(|records| ResetPremisesV1 {
            records,
            spent,
            trust_snapshot_digest,
            selection_address: member.selection_address,
        })
    }

    /// Evaluate the member's release on this domain's own registry under the
    /// scope's retained anchor and TPS1 (R16.6): the PTR1 and PRV1 histories
    /// are verified at the host's UTC second and Tick. A release the registry
    /// does not currently admit, a revoked one included, gives 12, and so
    /// does any registry error, a storage fault or a poisoned handle included
    /// (R6.5(4): the store's registry reads answer 12 for any registry error).
    /// Returns the TPS1 digest the evaluation read, the CQC1 trust snapshot.
    fn evaluate_reset_trust(
        &self,
        scope: &str,
        call: &CommunityQuarantineResetCallV1<'_>,
        sample_micros: u64,
    ) -> Result<Hash, Error> {
        let evidence = &call.trust_evidence;
        self.store
            .evaluate_retained_release(
                scope,
                evidence.ptr1_histories,
                evidence.prv1_histories,
                evidence.projection,
                TrustedUtcSecondV1::from_micros(sample_micros),
                RESET_TRUST_TICK,
            )
            .map(|evaluation| Hash::from_bytes(evaluation.tps1_digest()))
            .or(Err(Error::EvidenceUnavailable))
    }

    /// The writer (A5.4, R16.7 step 7), refusing in the spec's order: the
    /// writer is before `B`, then the decisions and the registry TPS1 digest
    /// still equal the evaluated ones, then the inventory generation and CSI1
    /// are unmoved (all 12); then the commit.
    ///
    /// The decisions are read before the call is consumed by the bound check
    /// and judged after it, so the bound is the first refusal.
    fn commit_reset(
        &mut self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &mut CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        (staged, authenticated): (StagedResetV1, CommunityAuthorityCallV1),
    ) -> Result<CommunityQuarantineReceiptV1, Error> {
        let authority = &staged.authority;
        let found = self.reset_decisions_now(
            context,
            lifecycle,
            metadata,
            (authority.leaf_grant_id, &authenticated),
        );
        lifecycle.check_writer_bound(authenticated, self)?;
        let evaluated = (
            authority.leaf_grant_id,
            authority.authorization_ref,
            authority.metadata.clone(),
            staged.premises.trust_snapshot_digest,
        );
        if found? != evaluated {
            return Err(Error::EvidenceUnavailable);
        }
        self.selection_unmoved(
            staged.inventory_generation,
            staged.premises.selection_address,
        )?;
        Ok(self.retain_reset(staged))
    }

    /// The administrative and metadata decisions of the call evaluated again,
    /// and the registry's TPS1 digest: what the writer compares with the
    /// premises' (12 when any cannot be read).
    fn reset_decisions_now(
        &self,
        context: CommunityQuarantineContextV1<'_>,
        lifecycle: &CommunityLifecycleAuthorityV1,
        metadata: &mut CommunityMetadataAuthorityV1,
        (leaf_grant_id, authenticated): (Hash, &CommunityAuthorityCallV1),
    ) -> Result<ResetDecisionsV1, Error> {
        let administrative =
            lifecycle.authorize_administrative(authenticated, self, leaf_grant_id)?;
        let write = self.reset_metadata_write(context, metadata)?;
        let policy = CommunityStoreDomainV1::plugin_trust_policy(self, lifecycle.trust_scope())?;
        Ok((
            administrative.leaf_grant_id(),
            administrative.authorization_ref(),
            write,
            Hash::from_bytes(policy.tps1_digest()),
        ))
    }

    /// Retain the reset: the successor ledger, the retry index entry, the
    /// re-armed `F_q` shares and the advanced inventory generation. The
    /// records are CQC1, CQR1 and CQO1 only (the reset's registrations and
    /// metadata records are R15-6b's).
    fn retain_reset(&mut self, staged: StagedResetV1) -> CommunityQuarantineReceiptV1 {
        let StagedResetV1 {
            key,
            control,
            bound,
            authority,
            premises,
            ..
        } = staged;
        let ResetPremisesV1 { records, spent, .. } = premises;
        let receipt = CommunityQuarantineReceiptV1 {
            timeline: control.0,
            control_operation_id: control.1,
            request_digest: records.request_digest,
            selected_ledger_digest: records.ledger.head,
            already_quarantined: false,
            outcome: records.outcome,
        };
        self.count_quarantine_pairs(control.0, spent, 0);
        self.inventory_generation += 1;
        self.quarantine_index.insert(key, records.ledger);
        self.quarantine_controls.insert(
            control,
            CommittedQuarantineControlV1 {
                kind: RetainedControlV1::Reset(RetainedResetV1 {
                    bound,
                    leaf_grant_id: authority.leaf_grant_id,
                }),
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
    }
}

/// Whether the call expects the ledger's head and its active set exactly.
fn is_current(current: &QuarantineLedgerV1, call: &CommunityQuarantineResetCallV1<'_>) -> bool {
    current.head == call.expected_ledger_digest && same_reasons(current, call)
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

/// The CQC1 `AuthenticatedReset` with the host-derived refs, deadline `B`,
/// TPS1 digest and the R8.5(4) provenance of the current admission, the CQR1
/// with an empty active set whose horizon is the reset's own metadata
/// horizon (R15.2(1)), and the CQO1.
fn reset_records(
    context: CommunityQuarantineContextV1<'_>,
    (cqk1, member): (CommunityQuarantineKeyV1<'_>, &MemberV1),
    current: &QuarantineLedgerV1,
    facts: &ResetFactsV1<'_>,
) -> Result<ResetRecordsV1, Error> {
    let call = facts.call;
    let provenance = community_decision_provenance_digest_v1(CommunityDecisionProvenanceInputV1 {
        pass_key: None,
        member_binding_digest: member.member_binding_digest,
        prepared_invocation_digest: None,
        host_failure: None,
        trust_snapshot_digest: facts.trust_snapshot_digest,
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
        trust_snapshot_digest: facts.trust_snapshot_digest,
        expected_generation: call.expected_generation,
        expected_state_head_digest: call.expected_state_head_digest,
        principal_ref: Some(facts.authority.principal_ref),
        authorization_ref: Some(facts.authority.authorization_ref),
        authorization_not_after_micros: facts.authority.bound_micros,
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
