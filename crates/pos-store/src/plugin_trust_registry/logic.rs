//! The adapter-independent decision logic of the Plugin trust policy registry.
//!
//! Each `plan_*` function reads the retained state through the abstract
//! `PluginTrustTransactionV1`, runs the ADR-103 revisions 4 and 5 steps in their
//! contract order, and returns a plan of writes. An adapter applies the plan
//! inside its own transaction. `plan_evaluate` (revision 5) runs the same
//! checks, with the differences that decision 2 lists, and returns the
//! read-only evaluation instead of a plan: it writes nothing. The Memory and
//! `SQLite` adapters therefore share every check, every error precedence, and
//! every record layout; they differ only in how they read, lock, and persist.

use pos_conformance::{
    authenticate_plugin_tps1_v1, check_plugin_tps1_artifact_denial_v1, check_plugin_tps1_genesis_v1,
    check_plugin_tps1_successor_v1, plan_plugin_floor_transition_v1, verify_plugin_tps1_policy_v1,
    AuthenticatedPluginTps1V1, PluginFloorPlanV1, PluginFloorStateV1, PluginFloorTransitionV1,
    PluginTrustPolicyAnchorV1,
};
use pos_crypto::plugin_trust::{
    ResolvedPluginTrustAuthorizationV1, ValidatedPluginManifestProjectionV1,
    VerifiedPluginTrustEvidenceV1,
};

use super::error::PluginTrustPolicyRegistryErrorV1;
use super::types::{
    ActivationEventIdentityV1, ActivationEventInputV1, ActiveReleaseV1, CurrentReleaseEvaluationV1,
    PluginTrustLedgerBodyV1, PluginTrustLedgerRowV1, PolicyAdvanceKindV1, PolicyAdvanceOutcomeV1,
    RetainedPolicyStateV1, RetainedReleaseDecisionV1, RollbackFactsV1,
};
use super::utc::TrustedUtcSecondV1;

type RegistryResult<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

/// The retained anchor and policy state of one scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedScopeV1 {
    pub(crate) anchor: PluginTrustPolicyAnchorV1,
    pub(crate) policy: RetainedPolicyStateV1,
}

/// The reads an adapter must provide inside one transaction.
///
/// Every method returns the committed state as the transaction sees it. A
/// missing row is `Ok(None)`; only a storage or corruption failure is `Err`.
pub(crate) trait PluginTrustTransactionV1 {
    /// The scope row, or `None` when the scope is not provisioned.
    fn scope(&self, scope: &str) -> RegistryResult<Option<RetainedScopeV1>>;

    /// The retained decision keyed `(scope, PMF1 digest)`.
    fn decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> RegistryResult<Option<RetainedReleaseDecisionV1>>;

    /// The active pointer of `(scope, Plugin ID)`.
    fn active(&self, scope: &str, plugin_id: &str) -> RegistryResult<Option<ActiveReleaseV1>>;

    /// The latest `Admission` or `Rollback` ledger row of `(scope, Plugin ID)`.
    fn latest_release_row(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> RegistryResult<Option<PluginTrustLedgerRowV1>>;

    /// The `row_seq` the next ledger row of `scope` takes.
    fn next_row_seq(&self, scope: &str) -> RegistryResult<u64>;
}

/// The trusted inputs every policy-bearing operation shares.
#[derive(Clone, Copy)]
pub(crate) struct PolicyInputV1<'a> {
    pub(crate) anchor: &'a PluginTrustPolicyAnchorV1,
    pub(crate) tps1_bytes: &'a [u8],
    pub(crate) evidence: &'a VerifiedPluginTrustEvidenceV1,
    pub(crate) utc: TrustedUtcSecondV1,
    pub(crate) tick: u64,
}

/// The state change every committed policy-bearing operation writes.
#[derive(Clone, Debug)]
pub(crate) struct PolicyWriteV1 {
    pub(crate) tps1: AuthenticatedPluginTps1V1,
    pub(crate) root: (u64, [u8; 32]),
    pub(crate) revocation: (u64, [u8; 32]),
    pub(crate) utc: i64,
}

impl PolicyWriteV1 {
    /// Install the successor TPS1, both floors, and the highest trusted UTC second.
    pub(crate) fn apply(&self, policy: &mut RetainedPolicyStateV1) {
        policy.tps1_epoch = self.tps1.epoch();
        policy.tps1_digest = self.tps1.digest();
        policy.tps1_effective_position = self.tps1.effective_timeline_position();
        policy.tps1_bytes = self.tps1.bytes().to_vec();
        policy.ptr1_floor = Some(self.root);
        policy.prv1_floor = Some(self.revocation);
        policy.highest_trusted_utc_second = Some(self.utc);
    }

    const fn row(&self, row_seq: u64, body: PluginTrustLedgerBodyV1) -> PluginTrustLedgerRowV1 {
        PluginTrustLedgerRowV1 {
            row_seq,
            tps1_digest: self.tps1.digest(),
            tps1_epoch: self.tps1.epoch(),
            tps1_effective_position: self.tps1.effective_timeline_position(),
            ptr1_floor: Some(self.root),
            prv1_floor: Some(self.revocation),
            body,
        }
    }
}

/// A scope row and its first ledger row.
#[derive(Clone, Debug)]
pub(crate) struct ProvisionWriteV1 {
    pub(crate) scope: RetainedScopeV1,
    pub(crate) row: PluginTrustLedgerRowV1,
}

/// Decide `provision`. `None` means the scope exists under the same anchor: write nothing.
///
/// Order: anchor comparison when the scope exists; TPS1 authentication;
/// genesis check; then create or leave unchanged.
pub(crate) fn plan_provision(
    tx: &impl PluginTrustTransactionV1,
    anchor: &PluginTrustPolicyAnchorV1,
    tps1_bytes: &[u8],
) -> RegistryResult<Option<ProvisionWriteV1>> {
    let existing = tx.scope(anchor.scope())?;
    if existing
        .as_ref()
        .is_some_and(|retained| retained.anchor != *anchor)
    {
        return Err(PluginTrustPolicyRegistryErrorV1::AnchorMismatch);
    }
    let tps1 = authenticate_plugin_tps1_v1(anchor, tps1_bytes)?;
    check_plugin_tps1_genesis_v1(anchor, &tps1)?;
    if existing.is_some() {
        return Ok(None);
    }
    let policy = RetainedPolicyStateV1 {
        scope: anchor.scope().to_owned(),
        tps1_epoch: tps1.epoch(),
        tps1_digest: tps1.digest(),
        tps1_effective_position: tps1.effective_timeline_position(),
        tps1_bytes: tps1.bytes().to_vec(),
        ptr1_floor: None,
        prv1_floor: None,
        highest_trusted_utc_second: None,
    };
    let row = PluginTrustLedgerRowV1 {
        row_seq: 1,
        tps1_digest: tps1.digest(),
        tps1_epoch: tps1.epoch(),
        tps1_effective_position: tps1.effective_timeline_position(),
        ptr1_floor: None,
        prv1_floor: None,
        body: PluginTrustLedgerBodyV1::Provision,
    };
    Ok(Some(ProvisionWriteV1 {
        scope: RetainedScopeV1 {
            anchor: anchor.clone(),
            policy,
        },
        row,
    }))
}

/// The state every release-independent check of one operation established.
struct CheckedPolicyV1 {
    scope: RetainedScopeV1,
    floors: PluginFloorStateV1,
    tps1: AuthenticatedPluginTps1V1,
}

/// How the supplied TPS1 relates to the retained one, once it is authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Continuity {
    /// The supplied bytes are the retained bytes.
    Retained,
    /// The supplied bytes are a valid successor of the retained TPS1.
    Successor,
}

/// The shared steps that follow the transaction prefix, up to and including TPS1 continuity.
///
/// Order: scope row (`MissingState`); anchor (`AnchorMismatch`); floor shape
/// (`CorruptState`); UTC regression; TPS1 authentication; TPS1 continuity. The continuity
/// result is returned so that `plan_evaluate` can refuse a valid successor before the bridge,
/// whereas the writes continue to the bridge.
fn check_policy_prefix(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
) -> RegistryResult<(CheckedPolicyV1, Continuity)> {
    let scope = tx
        .scope(input.anchor.scope())?
        .ok_or(PluginTrustPolicyRegistryErrorV1::MissingState)?;
    if scope.anchor != *input.anchor {
        return Err(PluginTrustPolicyRegistryErrorV1::AnchorMismatch);
    }
    let floors =
        PluginFloorStateV1::from_retained(scope.policy.ptr1_floor, scope.policy.prv1_floor)
            .or(Err(PluginTrustPolicyRegistryErrorV1::CorruptState))?;
    if scope
        .policy
        .highest_trusted_utc_second
        .is_some_and(|highest| input.utc.as_i64() < highest)
    {
        return Err(PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed);
    }
    let tps1 = authenticate_plugin_tps1_v1(input.anchor, input.tps1_bytes)?;
    let continuity = if tps1.bytes() == scope.policy.tps1_bytes.as_slice() {
        Continuity::Retained
    } else {
        check_plugin_tps1_successor_v1(scope.policy.tps1_epoch, scope.policy.tps1_digest, &tps1)?;
        Continuity::Successor
    };
    let checked = CheckedPolicyV1 {
        scope,
        floors,
        tps1,
    };
    Ok((checked, continuity))
}

/// The projection-free policy bridge, whose coordinate checks bind the evidence to the
/// transaction's UTC second and Tick.
fn check_bridge(checked: &CheckedPolicyV1, input: &PolicyInputV1<'_>) -> RegistryResult<()> {
    verify_plugin_tps1_policy_v1(
        &checked.tps1,
        input.evidence,
        input.utc.as_i64(),
        input.tick,
    )?;
    Ok(())
}

/// The shared steps that follow the transaction prefix.
///
/// Order: the prefix of `check_policy_prefix`, then the bridge of `check_bridge`.
fn check_policy(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
) -> RegistryResult<CheckedPolicyV1> {
    let (checked, _) = check_policy_prefix(tx, input)?;
    check_bridge(&checked, input)?;
    Ok(checked)
}

const fn policy_write(tps1: AuthenticatedPluginTps1V1, input: &PolicyInputV1<'_>) -> PolicyWriteV1 {
    PolicyWriteV1 {
        tps1,
        root: input.evidence.terminal_root(),
        revocation: input.evidence.terminal_revocation(),
        utc: input.utc.as_i64(),
    }
}

/// The writes of one `advance_policy`.
#[derive(Clone, Debug)]
pub(crate) struct AdvancePlanV1 {
    pub(crate) write: PolicyWriteV1,
    /// The `Advance` ledger row; `None` when only the UTC floor changes.
    pub(crate) row: Option<PluginTrustLedgerRowV1>,
    pub(crate) outcome: PolicyAdvanceOutcomeV1,
}

/// Decide `advance_policy`: the prefix, then the floor plan.
///
/// The policy changed unless the TPS1 is the retained one and both floors exist. An
/// identical TPS1 cannot move a floor, because it binds both the PTR1 version and the
/// PRV1 epoch; the floor plan accepts it only as an exact match.
pub(crate) fn plan_advance(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
) -> RegistryResult<AdvancePlanV1> {
    let checked = check_policy(tx, input)?;
    plan_plugin_floor_transition_v1(&checked.floors, input.evidence)?;
    let changed = matches!(checked.floors, PluginFloorStateV1::Absent)
        || checked.tps1.digest() != checked.scope.policy.tps1_digest;
    let write = policy_write(checked.tps1, input);
    let row = if changed {
        let row_seq = tx.next_row_seq(input.anchor.scope())?;
        Some(write.row(
            row_seq,
            PluginTrustLedgerBodyV1::Advance {
                utc: write.utc,
                tick: input.tick,
            },
        ))
    } else {
        None
    };
    let outcome = PolicyAdvanceOutcomeV1 {
        outcome: if changed {
            PolicyAdvanceKindV1::Advanced
        } else {
            PolicyAdvanceKindV1::Unchanged
        },
        tps1_digest: write.tps1.digest(),
        tps1_epoch: write.tps1.epoch(),
        ptr1_floor: Some(write.root),
        prv1_floor: Some(write.revocation),
    };
    Ok(AdvancePlanV1 {
        write,
        row,
        outcome,
    })
}

/// The release-dependent tail shared by `admit`, `rollback` and the evaluation.
///
/// Order: `authorize_release` (`Trust`); the TPS1 artifact-denial check; the floor plan.
fn check_release_tail(
    checked: &CheckedPolicyV1,
    input: &PolicyInputV1<'_>,
    projection: &ValidatedPluginManifestProjectionV1,
) -> RegistryResult<(ResolvedPluginTrustAuthorizationV1, PluginFloorPlanV1)> {
    let authorization = input.evidence.authorize_release(projection)?;
    check_plugin_tps1_artifact_denial_v1(&checked.tps1, &authorization)?;
    let plan = plan_plugin_floor_transition_v1(&checked.floors, input.evidence)?;
    Ok((authorization, plan))
}

/// The release-dependent prefix of `admit` and `rollback`.
///
/// Order: the shared prefix; the release tail. The floor plan only has to succeed.
fn check_release(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
    projection: &ValidatedPluginManifestProjectionV1,
) -> RegistryResult<(CheckedPolicyV1, ResolvedPluginTrustAuthorizationV1)> {
    let checked = check_policy(tx, input)?;
    let (authorization, _plan) = check_release_tail(&checked, input, projection)?;
    Ok((checked, authorization))
}

/// The retained floors when the plan leaves both exactly as they are, else `None`.
///
/// Absent floors (`Initialize`) and floors that the evidence would move (`Advance`) are policy
/// the registry has not adopted.
const fn unchanged_floors(
    floors: &PluginFloorStateV1,
    plan: &PluginFloorPlanV1,
) -> Option<((u64, [u8; 32]), (u64, [u8; 32]))> {
    match (floors, plan.root, plan.revocation) {
        (
            PluginFloorStateV1::Present { root, revocation },
            PluginFloorTransitionV1::Unchanged,
            PluginFloorTransitionV1::Unchanged,
        ) => Some((*root, *revocation)),
        _ => None,
    }
}

/// Whether the retained decision describes the release the pointer names and the authorization
/// authorized (a stored invariant: any difference is corrupt state).
fn decision_describes(
    decision: &RetainedReleaseDecisionV1,
    active: &ActiveReleaseV1,
    authorization: &ResolvedPluginTrustAuthorizationV1,
) -> bool {
    decision.plugin_id == active.plugin_id
        && decision.release_digest == active.release_digest
        && decision.release_digest == authorization.release_digest()
}

/// Decide `evaluate_current_release`: read-only, writes nothing.
///
/// Order: the shared prefix; a valid TPS1 successor is `PolicyNotAdvanced`; the bridge; the
/// release tail; floors that are not exactly unchanged are `PolicyNotAdvanced`; the pointer of
/// `(scope, Plugin ID)` must name the authorized complete-PMF1 digest (`ReleaseNotActive`); the
/// retained decision of the pointer must describe that release (`CorruptState`).
pub(crate) fn plan_evaluate(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
    projection: &ValidatedPluginManifestProjectionV1,
) -> RegistryResult<CurrentReleaseEvaluationV1> {
    let (checked, continuity) = check_policy_prefix(tx, input)?;
    if matches!(continuity, Continuity::Successor) {
        return Err(PluginTrustPolicyRegistryErrorV1::PolicyNotAdvanced);
    }
    check_bridge(&checked, input)?;
    let (authorization, plan) = check_release_tail(&checked, input, projection)?;
    let (root, revocation) = unchanged_floors(&checked.floors, &plan)
        .ok_or(PluginTrustPolicyRegistryErrorV1::PolicyNotAdvanced)?;
    let scope = input.anchor.scope();
    let active = tx
        .active(scope, authorization.plugin_id())?
        .filter(|active| active.pmf1_digest == authorization.pmf1_digest())
        .ok_or(PluginTrustPolicyRegistryErrorV1::ReleaseNotActive)?;
    let decision = tx
        .decision(scope, active.pmf1_digest)?
        .filter(|decision| decision_describes(decision, &active, &authorization))
        .ok_or(PluginTrustPolicyRegistryErrorV1::CorruptState)?;
    let policy = &checked.scope.policy;
    Ok(CurrentReleaseEvaluationV1 {
        scope: decision.scope,
        plugin_id: decision.plugin_id,
        pmf1_digest: decision.pmf1_digest,
        release_digest: decision.release_digest,
        previous_release_digest: decision.previous_release_digest,
        tps1_digest: policy.tps1_digest,
        tps1_epoch: policy.tps1_epoch,
        tps1_effective_position: policy.tps1_effective_position,
        ptr1_floor: root,
        prv1_floor: revocation,
        trusted_utc_second: input.utc.as_i64(),
        tick: input.tick,
        activation_event: active.activation_event,
    })
}

/// The outcome of `plan_admit`.
#[derive(Clone, Debug)]
pub(crate) enum AdmitPlanV1 {
    /// An identical decision exists: return it and raise only the UTC floor.
    Replay(Box<RetainedReleaseDecisionV1>),
    /// A new decision: append the Event, then write.
    Commit(Box<AdmitCommitV1>),
}

/// Everything an `admit` commit needs except the appended Event's identity.
#[derive(Clone, Debug)]
pub(crate) struct AdmitCommitV1 {
    write: PolicyWriteV1,
    scope: String,
    plugin_id: String,
    pmf1_digest: [u8; 32],
    release_digest: [u8; 32],
    previous_release_digest: Option<[u8; 32]>,
    previous_active_pmf1_digest: Option<[u8; 32]>,
    tick: u64,
    row_seq: u64,
}

/// The complete write set of a committed `admit`.
#[derive(Clone, Debug)]
pub(crate) struct AdmitWritesV1 {
    pub(crate) policy: PolicyWriteV1,
    pub(crate) decision: RetainedReleaseDecisionV1,
    pub(crate) active: ActiveReleaseV1,
    pub(crate) row: PluginTrustLedgerRowV1,
}

// The snapshot fields repeated by `AdmitCommitV1::finish` and `RollbackCommitV1::finish` belong
// to distinct public record types (decision, rollback facts, ledger columns) whose layouts the
// accepted port table fixes separately; a shared snapshot type would add an indirection to every
// accessor without removing a field, so the duplication is deliberate.
impl AdmitCommitV1 {
    /// Complete the write set with the identity of the Event the guarded append returned.
    pub(crate) fn finish(self, event: ActivationEventIdentityV1) -> AdmitWritesV1 {
        let decision = RetainedReleaseDecisionV1 {
            scope: self.scope.clone(),
            plugin_id: self.plugin_id.clone(),
            pmf1_digest: self.pmf1_digest,
            release_digest: self.release_digest,
            previous_release_digest: self.previous_release_digest,
            tps1_digest: self.write.tps1.digest(),
            tps1_epoch: self.write.tps1.epoch(),
            tps1_effective_position: self.write.tps1.effective_timeline_position(),
            terminal_root: self.write.root,
            terminal_revocation: self.write.revocation,
            trusted_utc_second: self.write.utc,
            tick: self.tick,
            activation_event: event.clone(),
        };
        let active = ActiveReleaseV1 {
            scope: self.scope,
            plugin_id: self.plugin_id,
            pmf1_digest: self.pmf1_digest,
            release_digest: self.release_digest,
            activation_event: event,
        };
        let row = self.write.row(
            self.row_seq,
            PluginTrustLedgerBodyV1::Admission {
                decision: Box::new(decision.clone()),
                previous_active_pmf1_digest: self.previous_active_pmf1_digest,
            },
        );
        AdmitWritesV1 {
            policy: self.write,
            decision,
            active,
            row,
        }
    }
}

/// Whether an existing decision has the identity of decision 12 for this call.
fn same_decision_identity(
    decision: &RetainedReleaseDecisionV1,
    tps1: &AuthenticatedPluginTps1V1,
    input: &PolicyInputV1<'_>,
    activation: &ActivationEventInputV1,
) -> bool {
    decision.tps1_digest == tps1.digest()
        && decision.terminal_root == input.evidence.terminal_root()
        && decision.terminal_revocation == input.evidence.terminal_revocation()
        && decision.activation_event.matches_input(activation)
}

/// Whether the release-chain rule of decision 2 permits activating `authorization`.
fn chain_permits(
    active: Option<&ActiveReleaseV1>,
    authorization: &ResolvedPluginTrustAuthorizationV1,
) -> bool {
    active.is_none_or(|active| {
        authorization.release_digest() == active.release_digest
            || authorization.previous_release_digest() == Some(active.release_digest)
    })
}

/// Decide `admit`.
///
/// Order: the release prefix; the idempotency lookup (`ReleaseConflict` or
/// replay); the release-chain rule (`ReleaseChainViolation`); the commit plan.
pub(crate) fn plan_admit(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
    projection: &ValidatedPluginManifestProjectionV1,
    activation: &ActivationEventInputV1,
) -> RegistryResult<AdmitPlanV1> {
    let (checked, authorization) = check_release(tx, input, projection)?;
    let scope = input.anchor.scope();
    if let Some(existing) = tx.decision(scope, authorization.pmf1_digest())? {
        return if same_decision_identity(&existing, &checked.tps1, input, activation) {
            Ok(AdmitPlanV1::Replay(Box::new(existing)))
        } else {
            Err(PluginTrustPolicyRegistryErrorV1::ReleaseConflict)
        };
    }
    let active = tx.active(scope, authorization.plugin_id())?;
    if !chain_permits(active.as_ref(), &authorization) {
        return Err(PluginTrustPolicyRegistryErrorV1::ReleaseChainViolation);
    }
    Ok(AdmitPlanV1::Commit(Box::new(AdmitCommitV1 {
        write: policy_write(checked.tps1, input),
        scope: scope.to_owned(),
        plugin_id: authorization.plugin_id().to_owned(),
        pmf1_digest: authorization.pmf1_digest(),
        release_digest: authorization.release_digest(),
        previous_release_digest: authorization.previous_release_digest(),
        previous_active_pmf1_digest: active.map(|active| active.pmf1_digest),
        tick: input.tick,
        row_seq: tx.next_row_seq(scope)?,
    })))
}

/// The outcome of `plan_rollback`.
#[derive(Clone, Debug)]
pub(crate) enum RollbackPlanV1 {
    /// An identical rollback is the latest of the Plugin ID: return its facts.
    Replay(Box<RollbackFactsV1>),
    /// A new rollback: append the Event, then write.
    Commit(Box<RollbackCommitV1>),
}

/// Everything a `rollback` commit needs except the appended Event's identity.
#[derive(Clone, Debug)]
pub(crate) struct RollbackCommitV1 {
    write: PolicyWriteV1,
    scope: String,
    plugin_id: String,
    target_pmf1_digest: [u8; 32],
    target_release_digest: [u8; 32],
    replaced_pmf1_digest: [u8; 32],
    tick: u64,
    row_seq: u64,
}

/// The complete write set of a committed `rollback`.
#[derive(Clone, Debug)]
pub(crate) struct RollbackWritesV1 {
    pub(crate) policy: PolicyWriteV1,
    pub(crate) facts: RollbackFactsV1,
    pub(crate) active: ActiveReleaseV1,
    pub(crate) row: PluginTrustLedgerRowV1,
}

impl RollbackCommitV1 {
    /// Complete the write set with the identity of the Event the guarded append returned.
    pub(crate) fn finish(self, event: ActivationEventIdentityV1) -> RollbackWritesV1 {
        let facts = RollbackFactsV1 {
            scope: self.scope.clone(),
            plugin_id: self.plugin_id.clone(),
            target_pmf1_digest: self.target_pmf1_digest,
            target_release_digest: self.target_release_digest,
            replaced_pmf1_digest: self.replaced_pmf1_digest,
            tps1_digest: self.write.tps1.digest(),
            tps1_epoch: self.write.tps1.epoch(),
            tps1_effective_position: self.write.tps1.effective_timeline_position(),
            terminal_root: self.write.root,
            terminal_revocation: self.write.revocation,
            trusted_utc_second: self.write.utc,
            tick: self.tick,
            activation_event: event.clone(),
        };
        let active = ActiveReleaseV1 {
            scope: self.scope,
            plugin_id: self.plugin_id,
            pmf1_digest: self.target_pmf1_digest,
            release_digest: self.target_release_digest,
            activation_event: event,
        };
        let row = self.write.row(
            self.row_seq,
            PluginTrustLedgerBodyV1::Rollback(Box::new(facts.clone())),
        );
        RollbackWritesV1 {
            policy: self.write,
            facts,
            active,
            row,
        }
    }
}

/// The facts of an identical earlier rollback, when `row` is one.
fn identical_rollback(
    row: Option<PluginTrustLedgerRowV1>,
    target_pmf1_digest: [u8; 32],
    tps1: &AuthenticatedPluginTps1V1,
    input: &PolicyInputV1<'_>,
    activation: &ActivationEventInputV1,
) -> Option<RollbackFactsV1> {
    match row?.body {
        PluginTrustLedgerBodyV1::Rollback(facts)
            if facts.target_pmf1_digest == target_pmf1_digest
                && facts.tps1_digest == tps1.digest()
                && facts.terminal_root == input.evidence.terminal_root()
                && facts.terminal_revocation == input.evidence.terminal_revocation()
                && facts.activation_event.matches_input(activation) =>
        {
            Some(*facts)
        }
        _ => None,
    }
}

/// Decide `rollback`.
///
/// Order: the release prefix for the target projection; the retained decision
/// (`UnknownRollbackTarget`); the active pointer (`NoActiveRelease`); the
/// pointer against the target (replay or `RollbackTargetActive`); the commit plan.
pub(crate) fn plan_rollback(
    tx: &impl PluginTrustTransactionV1,
    input: &PolicyInputV1<'_>,
    target: &ValidatedPluginManifestProjectionV1,
    activation: &ActivationEventInputV1,
) -> RegistryResult<RollbackPlanV1> {
    let (checked, authorization) = check_release(tx, input, target)?;
    let scope = input.anchor.scope();
    let target_pmf1_digest = authorization.pmf1_digest();
    if tx.decision(scope, target_pmf1_digest)?.is_none() {
        return Err(PluginTrustPolicyRegistryErrorV1::UnknownRollbackTarget);
    }
    let active = tx
        .active(scope, authorization.plugin_id())?
        .ok_or(PluginTrustPolicyRegistryErrorV1::NoActiveRelease)?;
    if active.pmf1_digest == target_pmf1_digest {
        let latest = tx.latest_release_row(scope, authorization.plugin_id())?;
        return identical_rollback(latest, target_pmf1_digest, &checked.tps1, input, activation)
            .map(|facts| RollbackPlanV1::Replay(Box::new(facts)))
            .ok_or(PluginTrustPolicyRegistryErrorV1::RollbackTargetActive);
    }
    Ok(RollbackPlanV1::Commit(Box::new(RollbackCommitV1 {
        write: policy_write(checked.tps1, input),
        scope: scope.to_owned(),
        plugin_id: authorization.plugin_id().to_owned(),
        target_pmf1_digest,
        target_release_digest: authorization.release_digest(),
        replaced_pmf1_digest: active.pmf1_digest,
        tick: input.tick,
        row_seq: tx.next_row_seq(scope)?,
    })))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{
        CanonicalBytes, EntityId, EventDraft, EventId, Kind, SchemaVersion, Seq, TimelineId,
    };

    use super::*;
    use crate::plugin_trust_registry_fixtures::{
        activation, release_one, release_two, spec, tps_after, Env, ManifestSpec, Material, Spec,
        TestResult, TpsSpec,
    };

    /// The identity of one committed activation Event for `input`.
    fn identity(input: &ActivationEventInputV1) -> ActivationEventIdentityV1 {
        ActivationEventIdentityV1 {
            timeline: input.timeline,
            event_id: EventId::new(),
            seq: Seq::from_u64(7),
            event_type: input.draft.event_type.as_str().to_owned(),
            schema_version: SchemaVersion::V1,
            payload_digest: input.payload_digest(),
            origin_logical_seq: Some(Seq::from_u64(7)),
        }
    }

    fn authenticated(env: &Env, material: &Material) -> TestResult<AuthenticatedPluginTps1V1> {
        Ok(authenticate_plugin_tps1_v1(&env.anchor, &material.tps1)?)
    }

    fn decision_of(
        tps1: &AuthenticatedPluginTps1V1,
        material: &Material,
        input: &ActivationEventInputV1,
    ) -> RetainedReleaseDecisionV1 {
        RetainedReleaseDecisionV1 {
            scope: "scope".to_owned(),
            plugin_id: "plugin-a".to_owned(),
            pmf1_digest: [1; 32],
            release_digest: [2; 32],
            previous_release_digest: None,
            tps1_digest: tps1.digest(),
            tps1_epoch: tps1.epoch(),
            tps1_effective_position: tps1.effective_timeline_position(),
            terminal_root: material.terminal_root(),
            terminal_revocation: material.terminal_revocation(),
            trusted_utc_second: 50,
            tick: 5,
            activation_event: identity(input),
        }
    }

    /// Evidence whose terminal PTR1 digest differs from the genesis one.
    fn other_root_material(env: &Env) -> TestResult<Material> {
        env.material(
            &Spec {
                root_variant: 1,
                ..spec(2, 2)
            },
            &TpsSpec::default(),
        )
    }

    /// Evidence whose terminal PRV1 digest differs from the genesis one.
    fn other_revocation_material(env: &Env) -> TestResult<Material> {
        env.material(
            &Spec {
                revocation_variant: 1,
                ..Spec::default()
            },
            &TpsSpec::default(),
        )
    }

    fn policy_input<'a>(env: &'a Env, material: &'a Material) -> TestResult<PolicyInputV1<'a>> {
        Ok(PolicyInputV1 {
            anchor: &env.anchor,
            tps1_bytes: &material.tps1,
            evidence: &material.evidence,
            utc: material.trusted()?,
            tick: material.tick,
        })
    }

    #[test]
    fn a_decision_identity_compares_every_component_it_names() -> TestResult {
        let env = Env::new("scope")?;
        let timeline = TimelineId::new();
        let genesis = env.genesis()?;
        let tps1 = authenticated(&env, &genesis)?;
        let input = activation(timeline, 1);
        let decision = decision_of(&tps1, &genesis, &input);
        let same = policy_input(&env, &genesis)?;
        assert!(same_decision_identity(&decision, &tps1, &same, &input));

        // Each component alone breaks the identity.
        let newer = env.material(&spec(2, 2), &tps_after(&genesis))?;
        let newer_tps1 = authenticated(&env, &newer)?;
        assert!(!same_decision_identity(
            &decision,
            &newer_tps1,
            &same,
            &input
        ));
        let other_root = other_root_material(&env)?;
        assert_ne!(other_root.terminal_root(), genesis.terminal_root());
        assert!(!same_decision_identity(
            &decision,
            &tps1,
            &policy_input(&env, &other_root)?,
            &input
        ));
        let other_revocation = other_revocation_material(&env)?;
        assert_ne!(
            other_revocation.terminal_revocation(),
            genesis.terminal_revocation()
        );
        assert!(!same_decision_identity(
            &decision,
            &tps1,
            &policy_input(&env, &other_revocation)?,
            &input
        ));
        for changed in [
            activation(TimelineId::new(), 1),
            activation(timeline, 2),
            ActivationEventInputV1 {
                timeline,
                draft: EventDraft::new(
                    EntityId::new(),
                    Kind::new("plugin.other.v1"),
                    CanonicalBytes::from_vec(vec![1]),
                ),
            },
        ] {
            assert!(!same_decision_identity(&decision, &tps1, &same, &changed));
        }
        Ok(())
    }

    #[test]
    fn an_identical_rollback_compares_the_target_the_snapshot_and_the_event() -> TestResult {
        let env = Env::new("scope")?;
        let timeline = TimelineId::new();
        let genesis = env.genesis()?;
        let tps1 = authenticated(&env, &genesis)?;
        let input = activation(timeline, 1);
        let same = policy_input(&env, &genesis)?;
        let facts = RollbackFactsV1 {
            scope: "scope".to_owned(),
            plugin_id: "plugin-a".to_owned(),
            target_pmf1_digest: [1; 32],
            target_release_digest: [2; 32],
            replaced_pmf1_digest: [3; 32],
            tps1_digest: tps1.digest(),
            tps1_epoch: tps1.epoch(),
            tps1_effective_position: tps1.effective_timeline_position(),
            terminal_root: genesis.terminal_root(),
            terminal_revocation: genesis.terminal_revocation(),
            trusted_utc_second: 50,
            tick: 5,
            activation_event: identity(&input),
        };
        let row = |facts: &RollbackFactsV1| PluginTrustLedgerRowV1 {
            row_seq: 4,
            tps1_digest: facts.tps1_digest,
            tps1_epoch: facts.tps1_epoch,
            tps1_effective_position: facts.tps1_effective_position,
            ptr1_floor: Some(facts.terminal_root),
            prv1_floor: Some(facts.terminal_revocation),
            body: PluginTrustLedgerBodyV1::Rollback(Box::new(facts.clone())),
        };
        let replay = identical_rollback(Some(row(&facts)), [1; 32], &tps1, &same, &input);
        assert_eq!(replay, Some(facts.clone()));

        // Anything but an identical earlier rollback row is not a replay.
        assert_eq!(
            identical_rollback(None, [1; 32], &tps1, &same, &input),
            None
        );
        assert_eq!(
            identical_rollback(Some(row(&facts)), [9; 32], &tps1, &same, &input),
            None
        );
        let newer = env.material(&spec(2, 2), &tps_after(&genesis))?;
        let newer_tps1 = authenticated(&env, &newer)?;
        assert_eq!(
            identical_rollback(Some(row(&facts)), [1; 32], &newer_tps1, &same, &input),
            None
        );
        let other_root = other_root_material(&env)?;
        assert_eq!(
            identical_rollback(
                Some(row(&facts)),
                [1; 32],
                &tps1,
                &policy_input(&env, &other_root)?,
                &input
            ),
            None
        );
        let other_revocation = other_revocation_material(&env)?;
        assert_eq!(
            identical_rollback(
                Some(row(&facts)),
                [1; 32],
                &tps1,
                &policy_input(&env, &other_revocation)?,
                &input
            ),
            None
        );
        for changed in [activation(TimelineId::new(), 1), activation(timeline, 2)] {
            assert_eq!(
                identical_rollback(Some(row(&facts)), [1; 32], &tps1, &same, &changed),
                None
            );
        }
        let admission = PluginTrustLedgerRowV1 {
            body: PluginTrustLedgerBodyV1::Admission {
                decision: Box::new(decision_of(&tps1, &genesis, &input)),
                previous_active_pmf1_digest: None,
            },
            ..row(&facts)
        };
        assert_eq!(
            identical_rollback(Some(admission), [1; 32], &tps1, &same, &input),
            None
        );
        Ok(())
    }

    #[test]
    fn the_chain_rule_admits_the_first_the_same_content_and_the_direct_successor() -> TestResult {
        let env = Env::new("scope")?;
        let genesis = env.genesis()?;
        let authorize = |manifest: &ManifestSpec| {
            Ok::<_, Box<dyn std::error::Error>>(
                genesis
                    .evidence
                    .authorize_release(&manifest.projection()?)?,
            )
        };
        let active = ActiveReleaseV1 {
            scope: "scope".to_owned(),
            plugin_id: "plugin-a".to_owned(),
            pmf1_digest: [0x01; 32],
            release_digest: [0x11; 32],
            activation_event: identity(&activation(TimelineId::new(), 1)),
        };
        // release_one: release 0x11, no previous; release_two: release 0x12, previous 0x11.
        let one = authorize(&release_one())?;
        let two = authorize(&release_two())?;
        let unrelated = authorize(&ManifestSpec::new("plugin-a", 0x05, 0x15, Some(0x99)))?;
        assert!(chain_permits(None, &unrelated));
        assert!(chain_permits(Some(&active), &one));
        assert!(chain_permits(Some(&active), &two));
        assert!(!chain_permits(Some(&active), &unrelated));
        Ok(())
    }

    #[test]
    fn only_floors_that_stay_exactly_as_retained_count_as_adopted() {
        use PluginFloorTransitionV1::{Advance, Initialize, Unchanged};

        let root = (1, [1; 32]);
        let revocation = (2, [2; 32]);
        let present = PluginFloorStateV1::Present { root, revocation };
        let plan = |root, revocation| PluginFloorPlanV1 { root, revocation };
        assert_eq!(
            unchanged_floors(&present, &plan(Unchanged, Unchanged)),
            Some((root, revocation))
        );
        for (root_plan, revocation_plan) in [
            (Advance, Unchanged),
            (Unchanged, Advance),
            (Initialize, Unchanged),
            (Unchanged, Initialize),
        ] {
            let moved = plan(root_plan, revocation_plan);
            assert_eq!(unchanged_floors(&present, &moved), None);
        }
        let absent = PluginFloorStateV1::Absent;
        assert_eq!(
            unchanged_floors(&absent, &plan(Initialize, Initialize)),
            None
        );
        assert_eq!(unchanged_floors(&absent, &plan(Unchanged, Unchanged)), None);
    }

    #[test]
    fn a_decision_describes_the_pointer_and_the_authorization_only_when_all_agree() -> TestResult {
        let env = Env::new("scope")?;
        let genesis = env.genesis()?;
        let tps1 = authenticated(&env, &genesis)?;
        let input = activation(TimelineId::new(), 1);
        // release_one authorizes release digest 0x11 of "plugin-a".
        let authorization = genesis
            .evidence
            .authorize_release(&release_one().projection()?)?;
        let active = |release: u8| ActiveReleaseV1 {
            scope: "scope".to_owned(),
            plugin_id: "plugin-a".to_owned(),
            pmf1_digest: [0x01; 32],
            release_digest: [release; 32],
            activation_event: identity(&input),
        };
        let decision = |plugin: &str, release: u8| RetainedReleaseDecisionV1 {
            plugin_id: plugin.to_owned(),
            release_digest: [release; 32],
            ..decision_of(&tps1, &genesis, &input)
        };
        assert!(decision_describes(
            &decision("plugin-a", 0x11),
            &active(0x11),
            &authorization
        ));
        // Each disagreement alone: the Plugin ID, the pointer's release, the authorization's.
        assert!(!decision_describes(
            &decision("plugin-b", 0x11),
            &active(0x11),
            &authorization
        ));
        assert!(!decision_describes(
            &decision("plugin-a", 0x11),
            &active(0x12),
            &authorization
        ));
        assert!(!decision_describes(
            &decision("plugin-a", 0x12),
            &active(0x12),
            &authorization
        ));
        Ok(())
    }

    /// The read that a `FailingTx` fails.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Read {
        Scope,
        Decision,
        Active,
        LatestRow,
        NextRowSeq,
    }

    /// A transaction whose one named read fails and whose others return fixed state.
    struct FailingTx {
        fail: Read,
        scope: Option<RetainedScopeV1>,
        decision: Option<RetainedReleaseDecisionV1>,
        active: Option<ActiveReleaseV1>,
    }

    impl FailingTx {
        fn gate<T>(&self, read: Read, value: T) -> RegistryResult<T> {
            if self.fail == read {
                Err(PluginTrustPolicyRegistryErrorV1::StorageFailed)
            } else {
                Ok(value)
            }
        }
    }

    impl PluginTrustTransactionV1 for FailingTx {
        fn scope(&self, _scope: &str) -> RegistryResult<Option<RetainedScopeV1>> {
            self.gate(Read::Scope, self.scope.clone())
        }

        fn decision(
            &self,
            _scope: &str,
            _pmf1_digest: [u8; 32],
        ) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
            self.gate(Read::Decision, self.decision.clone())
        }

        fn active(
            &self,
            _scope: &str,
            _plugin_id: &str,
        ) -> RegistryResult<Option<ActiveReleaseV1>> {
            self.gate(Read::Active, self.active.clone())
        }

        fn latest_release_row(
            &self,
            _scope: &str,
            _plugin_id: &str,
        ) -> RegistryResult<Option<PluginTrustLedgerRowV1>> {
            self.gate(Read::LatestRow, None)
        }

        fn next_row_seq(&self, _scope: &str) -> RegistryResult<u64> {
            self.gate(Read::NextRowSeq, 1)
        }
    }

    #[test]
    fn the_evaluation_propagates_each_failed_transaction_read() -> TestResult {
        let env = Env::new("scope")?;
        let genesis = env.genesis()?;
        let tps1 = authenticated(&env, &genesis)?;
        let input = activation(TimelineId::new(), 1);
        let policy = policy_input(&env, &genesis)?;
        let retained = RetainedScopeV1 {
            anchor: env.anchor.clone(),
            policy: RetainedPolicyStateV1 {
                scope: "scope".to_owned(),
                tps1_epoch: tps1.epoch(),
                tps1_digest: tps1.digest(),
                tps1_effective_position: tps1.effective_timeline_position(),
                tps1_bytes: tps1.bytes().to_vec(),
                ptr1_floor: Some(genesis.terminal_root()),
                prv1_floor: Some(genesis.terminal_revocation()),
                highest_trusted_utc_second: None,
            },
        };
        let active = ActiveReleaseV1 {
            scope: "scope".to_owned(),
            plugin_id: "plugin-a".to_owned(),
            pmf1_digest: [0x01; 32],
            release_digest: [0x11; 32],
            activation_event: identity(&input),
        };
        let decision = RetainedReleaseDecisionV1 {
            pmf1_digest: [0x01; 32],
            release_digest: [0x11; 32],
            ..decision_of(&tps1, &genesis, &input)
        };
        let tx = |fail: Read| FailingTx {
            fail,
            scope: Some(retained.clone()),
            decision: Some(decision.clone()),
            active: Some(active.clone()),
        };
        let projection = release_one().projection()?;
        let failed = Some(PluginTrustPolicyRegistryErrorV1::StorageFailed);
        for read in [Read::Scope, Read::Active, Read::Decision] {
            let plan = plan_evaluate(&tx(read), &policy, &projection);
            assert_eq!(plan.err(), failed);
        }
        // No evaluation read touches the ledger: the same transaction otherwise evaluates.
        let evaluation = plan_evaluate(&tx(Read::LatestRow), &policy, &projection)?;
        assert_eq!(evaluation.pmf1_digest(), [0x01; 32]);
        assert_eq!(evaluation.activation_event(), &active.activation_event);
        Ok(())
    }

    #[test]
    fn every_plan_propagates_each_failed_transaction_read() -> TestResult {
        let env = Env::new("scope")?;
        let genesis = env.genesis()?;
        let tps1 = authenticated(&env, &genesis)?;
        let input = activation(TimelineId::new(), 1);
        let policy = policy_input(&env, &genesis)?;
        let retained = RetainedScopeV1 {
            anchor: env.anchor.clone(),
            policy: RetainedPolicyStateV1 {
                scope: "scope".to_owned(),
                tps1_epoch: tps1.epoch(),
                tps1_digest: tps1.digest(),
                tps1_effective_position: tps1.effective_timeline_position(),
                tps1_bytes: tps1.bytes().to_vec(),
                ptr1_floor: None,
                prv1_floor: None,
                highest_trusted_utc_second: None,
            },
        };
        let decision = decision_of(&tps1, &genesis, &input);
        let active = |pmf1: u8| ActiveReleaseV1 {
            scope: "scope".to_owned(),
            plugin_id: "plugin-a".to_owned(),
            pmf1_digest: [pmf1; 32],
            release_digest: [0x11; 32],
            activation_event: identity(&input),
        };
        let tx = |fail: Read, decided: bool, pointer: Option<u8>| FailingTx {
            fail,
            scope: Some(retained.clone()),
            decision: decided.then(|| decision.clone()),
            active: pointer.map(active),
        };
        let failed = Some(PluginTrustPolicyRegistryErrorV1::StorageFailed);
        let projection = release_one().projection()?;

        let empty = FailingTx {
            fail: Read::Scope,
            scope: None,
            decision: None,
            active: None,
        };
        assert_eq!(
            plan_provision(&empty, &env.anchor, &genesis.tps1).err(),
            failed
        );
        for read in [Read::Scope, Read::NextRowSeq] {
            assert_eq!(plan_advance(&tx(read, false, None), &policy).err(), failed);
        }
        for read in [Read::Scope, Read::Decision, Read::Active, Read::NextRowSeq] {
            let plan = plan_admit(&tx(read, false, None), &policy, &projection, &input);
            assert_eq!(plan.err(), failed);
        }
        // Rollback reaches each read in turn: the target is retained, then the pointer names
        // either the target (latest-row lookup) or another release (next row sequence).
        for (read, pointer) in [
            (Read::Scope, Some(0x03)),
            (Read::Decision, Some(0x03)),
            (Read::Active, Some(0x03)),
            (Read::LatestRow, Some(0x01)),
            (Read::NextRowSeq, Some(0x03)),
        ] {
            let plan = plan_rollback(&tx(read, true, pointer), &policy, &projection, &input);
            assert_eq!(plan.err(), failed);
        }
        Ok(())
    }
}
