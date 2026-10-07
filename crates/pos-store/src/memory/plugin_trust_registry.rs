//! `MemoryStore` adapter for the ADR-103 revision 4 Plugin trust policy registry port.
//!
//! The registry state is one more `MemoryStore` field, so an activation Event
//! shares the store's single mutable owner with the decision that authorized
//! it. Every operation computes its complete plan from the committed state
//! first, appends the activation Event as the last fallible step, and only then
//! performs infallible assignments: a failed append leaves the state
//! byte-identical, and a failed state write leaves no Event.
//!
//! The Event append runs under the same guards, in the same order, as
//! `EventStore::append`: the erasure fence is the outermost scope, then the
//! non-geographic draft, fork, and visibility guards, then the append itself.
//! This adapter is test-only parity for the durable `SQLite` adapter.

use std::collections::BTreeMap;

use pos_conformance::{PluginFloorStateV1, PluginTrustPolicyAnchorV1};
use pos_core::{ErasureProtectedOperationV1, TimelineId};
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};

use super::MemoryStore;
use crate::plugin_trust_registry::logic::{
    plan_admit, plan_advance, plan_provision, plan_rollback, AdmitPlanV1, AdmitWritesV1,
    AdvancePlanV1, PluginTrustTransactionV1, PolicyInputV1, ProvisionWriteV1, RetainedScopeV1,
    RollbackPlanV1, RollbackWritesV1,
};
use crate::plugin_trust_registry::{
    ActivationEventIdentityV1, ActivationEventInputV1, ActiveReleaseV1,
    AdmittedPluginReleaseReceiptV1, PluginRollbackReceiptV1, PluginTrustCommitOutcomeV1,
    PluginTrustLedgerRowV1, PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1,
    PolicyAdvanceOutcomeV1, ProvisionOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1,
    TrustedUtcSecondV1,
};

type RegistryResult<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

/// Faults a unit test can inject around the commit of an Event-bearing operation.
///
/// The faults are threaded as an adapter-internal parameter, not a `cfg(test)` field, so no
/// test-only code sits in a production path. The public methods pass `NONE`; the failure
/// branches are exercised by the E4 and F3 unit tests.
#[derive(Clone, Copy, Debug)]
struct MemoryFaultsV1 {
    /// Fails after the plan validated, before the Event append.
    before_append: Option<PluginTrustPolicyRegistryErrorV1>,
    /// Fails after the commit, as a lost acknowledgement.
    after_commit: Option<PluginTrustPolicyRegistryErrorV1>,
}

impl MemoryFaultsV1 {
    const NONE: Self = Self {
        before_append: None,
        after_commit: None,
    };
}

/// The committed state of one provisioned scope.
#[derive(Debug)]
struct MemoryScopeV1 {
    retained: RetainedScopeV1,
    decisions: BTreeMap<[u8; 32], RetainedReleaseDecisionV1>,
    active: BTreeMap<String, ActiveReleaseV1>,
    ledger: Vec<PluginTrustLedgerRowV1>,
}

impl MemoryScopeV1 {
    fn commit_admit(&mut self, writes: AdmitWritesV1) {
        writes.policy.apply(&mut self.retained.policy);
        let key = writes.decision.pmf1_digest;
        self.decisions.insert(key, writes.decision);
        self.active
            .insert(writes.active.plugin_id.clone(), writes.active);
        self.ledger.push(writes.row);
    }

    fn commit_rollback(&mut self, writes: RollbackWritesV1) {
        writes.policy.apply(&mut self.retained.policy);
        self.active
            .insert(writes.active.plugin_id.clone(), writes.active);
        self.ledger.push(writes.row);
    }

    const fn raise_utc(&mut self, utc: i64) {
        self.retained.policy.highest_trusted_utc_second = Some(utc);
    }

    fn next_row_seq(&self) -> u64 {
        self.ledger.last().map_or(1, |row| row.row_seq + 1)
    }

    fn latest_release_row(&self, plugin_id: &str) -> Option<&PluginTrustLedgerRowV1> {
        self.ledger
            .iter()
            .rev()
            .find(|row| row.plugin_id() == Some(plugin_id))
    }

    fn commit_advance(&mut self, plan: AdvancePlanV1) {
        plan.write.apply(&mut self.retained.policy);
        self.ledger.extend(plan.row);
    }
}

/// The registry state of one `MemoryStore`, keyed by exact scope text.
#[derive(Debug, Default)]
pub(super) struct MemoryPluginTrustStateV1 {
    scopes: BTreeMap<String, MemoryScopeV1>,
}

impl MemoryPluginTrustStateV1 {
    fn scope_state(&self, scope: &str) -> RegistryResult<&MemoryScopeV1> {
        self.scopes
            .get(scope)
            .ok_or(PluginTrustPolicyRegistryErrorV1::MissingState)
    }

    /// Apply `apply` to the committed state of `scope`.
    ///
    /// Every caller planned from this scope's state a moment earlier under the store's single
    /// mutable owner, so the scope exists; a missing scope is still reported, never skipped.
    fn with_scope(
        &mut self,
        scope: &str,
        apply: impl FnOnce(&mut MemoryScopeV1),
    ) -> RegistryResult<()> {
        self.scopes
            .get_mut(scope)
            .ok_or(PluginTrustPolicyRegistryErrorV1::MissingState)
            .map(apply)
    }

    fn insert_scope(&mut self, write: ProvisionWriteV1) {
        let scope = write.scope.policy.scope.clone();
        self.scopes.insert(
            scope,
            MemoryScopeV1 {
                retained: write.scope,
                decisions: BTreeMap::new(),
                active: BTreeMap::new(),
                ledger: vec![write.row],
            },
        );
    }
}

impl PluginTrustTransactionV1 for MemoryPluginTrustStateV1 {
    fn scope(&self, scope: &str) -> RegistryResult<Option<RetainedScopeV1>> {
        let state = self.scopes.get(scope);
        Ok(state.map(|state| state.retained.clone()))
    }

    fn decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
        let state = self.scopes.get(scope);
        let decision = state.and_then(|state| state.decisions.get(&pmf1_digest));
        Ok(decision.cloned())
    }

    fn active(&self, scope: &str, plugin_id: &str) -> RegistryResult<Option<ActiveReleaseV1>> {
        let state = self.scopes.get(scope);
        let active = state.and_then(|state| state.active.get(plugin_id));
        Ok(active.cloned())
    }

    fn latest_release_row(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> RegistryResult<Option<PluginTrustLedgerRowV1>> {
        let state = self.scopes.get(scope);
        let latest = state.and_then(|state| state.latest_release_row(plugin_id));
        Ok(latest.cloned())
    }

    fn next_row_seq(&self, scope: &str) -> RegistryResult<u64> {
        let state = self.scopes.get(scope);
        Ok(state.map_or(1, MemoryScopeV1::next_row_seq))
    }
}

impl MemoryStore {
    /// Append the activation Event under the guards of `EventStore::append`.
    ///
    /// The caller already holds the erasure fence. The adapter computes
    /// `BLAKE3-256(payload)` itself and requires the store's own payload hash
    /// to equal it, so a store with another hasher can never activate.
    fn append_activation_event(
        &mut self,
        activation: &ActivationEventInputV1,
    ) -> RegistryResult<ActivationEventIdentityV1> {
        let timeline = activation.timeline;
        let payload_digest = activation.payload_digest();
        if *self
            .hasher
            .hash_payload(&activation.draft.payload)
            .as_bytes()
            != payload_digest
        {
            return Err(PluginTrustPolicyRegistryErrorV1::ActivationEventRejected);
        }
        // Appending exactly one draft yields exactly one Event, so a single `ok_or` covers both
        // a refused append and the (impossible) empty result.
        let appended = self
            .guarded_generic_append(timeline, std::slice::from_ref(&activation.draft))
            .ok()
            .and_then(|events| events.into_iter().next());
        appended
            .map(|event| ActivationEventIdentityV1::from_event(timeline, &event, payload_digest))
            .ok_or(PluginTrustPolicyRegistryErrorV1::ActivationEventRejected)
    }

    /// Run `operation` inside the erasure fence of the activation Timeline.
    ///
    /// A missing gate or a refused fence is `ActivationEventRejected`.
    fn in_activation_fence<T>(
        &mut self,
        timeline: TimelineId,
        mut operation: impl FnMut(&mut Self) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        let append = ErasureProtectedOperationV1::Append;
        let fenced = self.with_erasure_fence(timeline, append, |store| Ok(operation(store)));
        fenced
            .or(Err(
                PluginTrustPolicyRegistryErrorV1::ActivationEventRejected,
            ))
            .and_then(std::convert::identity)
    }

    fn admit_with_faults(
        &mut self,
        input: &PolicyInputV1<'_>,
        projection: &ValidatedPluginManifestProjectionV1,
        activation: &ActivationEventInputV1,
        faults: MemoryFaultsV1,
    ) -> RegistryResult<AdmittedPluginReleaseReceiptV1> {
        self.in_activation_fence(activation.timeline, |store| {
            store.admit_fenced(input, projection, activation, faults)
        })
    }

    fn admit_fenced(
        &mut self,
        input: &PolicyInputV1<'_>,
        projection: &ValidatedPluginManifestProjectionV1,
        activation: &ActivationEventInputV1,
        faults: MemoryFaultsV1,
    ) -> RegistryResult<AdmittedPluginReleaseReceiptV1> {
        let scope = input.anchor.scope();
        let utc = input.utc.as_i64();
        match plan_admit(&self.plugin_trust, input, projection, activation)? {
            AdmitPlanV1::Replay(decision) => {
                self.plugin_trust
                    .with_scope(scope, |state| state.raise_utc(utc))
                    .map(|()| AdmittedPluginReleaseReceiptV1 {
                        decision: *decision,
                        outcome: PluginTrustCommitOutcomeV1::IdempotentReplay,
                    })
            }
            AdmitPlanV1::Commit(commit) => {
                faults.before_append.map_or(Ok(()), Err)?;
                let event = self.append_activation_event(activation)?;
                let writes = commit.finish(event);
                let receipt = AdmittedPluginReleaseReceiptV1 {
                    decision: writes.decision.clone(),
                    outcome: PluginTrustCommitOutcomeV1::Committed,
                };
                self.plugin_trust
                    .with_scope(scope, |state| state.commit_admit(writes))
                    .and_then(|()| faults.after_commit.map_or(Ok(receipt), Err))
            }
        }
    }

    fn rollback_with_faults(
        &mut self,
        input: &PolicyInputV1<'_>,
        target: &ValidatedPluginManifestProjectionV1,
        activation: &ActivationEventInputV1,
        faults: MemoryFaultsV1,
    ) -> RegistryResult<PluginRollbackReceiptV1> {
        self.in_activation_fence(activation.timeline, |store| {
            store.rollback_fenced(input, target, activation, faults)
        })
    }

    fn rollback_fenced(
        &mut self,
        input: &PolicyInputV1<'_>,
        target: &ValidatedPluginManifestProjectionV1,
        activation: &ActivationEventInputV1,
        faults: MemoryFaultsV1,
    ) -> RegistryResult<PluginRollbackReceiptV1> {
        let scope = input.anchor.scope();
        let utc = input.utc.as_i64();
        match plan_rollback(&self.plugin_trust, input, target, activation)? {
            RollbackPlanV1::Replay(facts) => {
                self.plugin_trust
                    .with_scope(scope, |state| state.raise_utc(utc))
                    .map(|()| PluginRollbackReceiptV1 {
                        facts: *facts,
                        outcome: PluginTrustCommitOutcomeV1::IdempotentReplay,
                    })
            }
            RollbackPlanV1::Commit(commit) => {
                faults.before_append.map_or(Ok(()), Err)?;
                let event = self.append_activation_event(activation)?;
                let writes = commit.finish(event);
                let receipt = PluginRollbackReceiptV1 {
                    facts: writes.facts.clone(),
                    outcome: PluginTrustCommitOutcomeV1::Committed,
                };
                self.plugin_trust
                    .with_scope(scope, |state| state.commit_rollback(writes))
                    .and_then(|()| faults.after_commit.map_or(Ok(receipt), Err))
            }
        }
    }
}

impl PluginTrustPolicyRegistryV1 for MemoryStore {
    fn provision(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
    ) -> RegistryResult<ProvisionOutcomeV1> {
        let write = plan_provision(&self.plugin_trust, anchor, tps1_bytes)?;
        Ok(write.map_or(ProvisionOutcomeV1::Unchanged, |write| {
            self.plugin_trust.insert_scope(write);
            ProvisionOutcomeV1::Created
        }))
    }

    fn admit(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> RegistryResult<AdmittedPluginReleaseReceiptV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        self.admit_with_faults(&input, projection, &activation, MemoryFaultsV1::NONE)
    }

    fn advance_policy(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> RegistryResult<PolicyAdvanceOutcomeV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        let plan = plan_advance(&self.plugin_trust, &input)?;
        let outcome = plan.outcome;
        self.plugin_trust
            .with_scope(anchor.scope(), |state| state.commit_advance(plan))
            .map(|()| outcome)
    }

    fn rollback(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        target: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> RegistryResult<PluginRollbackReceiptV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        self.rollback_with_faults(&input, target, &activation, MemoryFaultsV1::NONE)
    }

    fn retained_release_decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
        self.plugin_trust
            .scope_state(scope)
            .map(|state| state.decisions.get(&pmf1_digest).cloned())
    }

    fn active_release(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> RegistryResult<Option<ActiveReleaseV1>> {
        self.plugin_trust
            .scope_state(scope)
            .map(|state| state.active.get(plugin_id).cloned())
    }

    fn retained_policy_state(&self, scope: &str) -> RegistryResult<RetainedPolicyStateV1> {
        let policy = &self.plugin_trust.scope_state(scope)?.retained.policy;
        PluginFloorStateV1::from_retained(policy.ptr1_floor, policy.prv1_floor)
            .or(Err(PluginTrustPolicyRegistryErrorV1::CorruptState))
            .map(|_| policy.clone())
    }

    fn ledger(&self, scope: &str) -> RegistryResult<Vec<PluginTrustLedgerRowV1>> {
        self.plugin_trust
            .scope_state(scope)
            .map(|state| state.ledger.clone())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{
        store::{EventStore, SeqRange},
        ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionOriginV1, Hash,
        OwnerIdV1,
    };

    use super::*;
    use crate::plugin_trust_registry_fixtures::{
        activation, release_one, release_two, Harness, Material, TestResult,
    };

    fn policy_input<'a>(
        anchor: &'a PluginTrustPolicyAnchorV1,
        material: &'a Material,
        utc: TrustedUtcSecondV1,
    ) -> PolicyInputV1<'a> {
        PolicyInputV1 {
            anchor,
            tps1_bytes: &material.tps1,
            evidence: &material.evidence,
            utc,
            tick: material.tick,
        }
    }

    const fn faults(
        before_append: Option<PluginTrustPolicyRegistryErrorV1>,
        after_commit: Option<PluginTrustPolicyRegistryErrorV1>,
    ) -> MemoryFaultsV1 {
        MemoryFaultsV1 {
            before_append,
            after_commit,
        }
    }

    #[test]
    fn a_state_write_failure_after_validation_appends_no_event() -> TestResult {
        let Harness {
            mut store,
            env,
            timeline,
        } = Harness::new()?;
        let genesis = env.genesis()?;
        let utc = genesis.trusted()?;
        let input = policy_input(&env.anchor, &genesis, utc);
        let before = store.retained_policy_state("scope")?;
        let failing = faults(Some(PluginTrustPolicyRegistryErrorV1::StorageFailed), None);
        assert_eq!(
            store.admit_with_faults(
                &input,
                &release_one().projection()?,
                &activation(timeline, 1),
                failing
            ),
            Err(PluginTrustPolicyRegistryErrorV1::StorageFailed)
        );
        assert_eq!(store.retained_policy_state("scope")?, before);
        assert_eq!(store.ledger("scope")?.len(), 1);
        assert_eq!(store.active_release("scope", "plugin-a")?, None);
        assert!(store.read(timeline, SeqRange::all())?.is_empty());

        // The same failure on a rollback leaves the pointer, ledger, and Timeline alone.
        for (manifest, tag) in [(release_one(), 1), (release_two(), 2)] {
            store.admit(
                &env.anchor,
                &genesis.tps1,
                &genesis.evidence,
                &manifest.projection()?,
                utc,
                genesis.tick,
                activation(timeline, tag),
            )?;
        }
        let ledger = store.ledger("scope")?;
        let events = store.read(timeline, SeqRange::all())?;
        assert_eq!(
            store.rollback_with_faults(
                &input,
                &release_one().projection()?,
                &activation(timeline, 3),
                failing
            ),
            Err(PluginTrustPolicyRegistryErrorV1::StorageFailed)
        );
        assert_eq!(store.ledger("scope")?, ledger);
        assert_eq!(store.read(timeline, SeqRange::all())?, events);
        let active = store
            .active_release("scope", "plugin-a")?
            .ok_or("no pointer")?;
        assert_eq!(active.pmf1_digest(), [0x03; 32]);
        Ok(())
    }

    #[test]
    fn a_lost_acknowledgement_commits_and_the_retry_replays_the_original() -> TestResult {
        let Harness {
            mut store,
            env,
            timeline,
        } = Harness::new()?;
        let genesis = env.genesis()?;
        let utc = genesis.trusted()?;
        let input = policy_input(&env.anchor, &genesis, utc);
        let lost = faults(
            None,
            Some(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate),
        );
        let one = release_one().projection()?;
        assert_eq!(
            store.admit_with_faults(&input, &one, &activation(timeline, 1), lost),
            Err(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate)
        );
        let committed = store
            .retained_release_decision("scope", [0x01; 32])?
            .ok_or("the commit was lost")?;
        assert_eq!(store.read(timeline, SeqRange::all())?.len(), 1);
        let retry = store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &one,
            utc,
            genesis.tick,
            activation(timeline, 1),
        )?;
        assert_eq!(
            retry.outcome(),
            PluginTrustCommitOutcomeV1::IdempotentReplay
        );
        assert_eq!(retry.decision(), &committed);
        assert_eq!(store.read(timeline, SeqRange::all())?.len(), 1);

        // The same on a rollback.
        store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &release_two().projection()?,
            utc,
            genesis.tick,
            activation(timeline, 2),
        )?;
        assert_eq!(
            store.rollback_with_faults(&input, &one, &activation(timeline, 3), lost),
            Err(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate)
        );
        let active = store
            .active_release("scope", "plugin-a")?
            .ok_or("no pointer")?;
        assert_eq!(active.pmf1_digest(), [0x01; 32]);
        let events = store.read(timeline, SeqRange::all())?.len();
        let replay = store.rollback(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &one,
            utc,
            genesis.tick,
            activation(timeline, 3),
        )?;
        assert_eq!(
            replay.outcome(),
            PluginTrustCommitOutcomeV1::IdempotentReplay
        );
        assert_eq!(replay.activation_event(), active.activation_event());
        assert_eq!(store.read(timeline, SeqRange::all())?.len(), events);
        Ok(())
    }

    #[test]
    fn a_partial_floor_pair_is_corrupt_state_in_every_operation_and_read() -> TestResult {
        for partial_root in [true, false] {
            let Harness {
                mut store,
                env,
                timeline,
            } = Harness::new()?;
            let genesis = env.genesis()?;
            let utc = genesis.trusted()?;
            store.advance_policy(
                &env.anchor,
                &genesis.tps1,
                &genesis.evidence,
                utc,
                genesis.tick,
            )?;
            let state = store
                .plugin_trust
                .scopes
                .get_mut("scope")
                .ok_or("no scope")?;
            if partial_root {
                state.retained.policy.prv1_floor = None;
            } else {
                state.retained.policy.ptr1_floor = None;
            }
            assert_eq!(
                store.retained_policy_state("scope"),
                Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
            );
            assert_eq!(
                store.advance_policy(
                    &env.anchor,
                    &genesis.tps1,
                    &genesis.evidence,
                    utc,
                    genesis.tick
                ),
                Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
            );
            let one = release_one().projection()?;
            assert_eq!(
                store.admit(
                    &env.anchor,
                    &genesis.tps1,
                    &genesis.evidence,
                    &one,
                    utc,
                    genesis.tick,
                    activation(timeline, 1)
                ),
                Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
            );
            assert_eq!(
                store.rollback(
                    &env.anchor,
                    &genesis.tps1,
                    &genesis.evidence,
                    &one,
                    utc,
                    genesis.tick,
                    activation(timeline, 1)
                ),
                Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
            );
        }
        Ok(())
    }

    /// Admit on `timeline` and assert the activation Event was refused with nothing changed.
    fn assert_activation_refused(h: Harness) -> TestResult {
        let Harness {
            mut store,
            env,
            timeline,
        } = h;
        let genesis = env.genesis()?;
        let before = store.retained_policy_state("scope")?;
        let events = store.event_ids.len();
        assert_eq!(
            store.admit(
                &env.anchor,
                &genesis.tps1,
                &genesis.evidence,
                &release_one().projection()?,
                genesis.trusted()?,
                genesis.tick,
                activation(timeline, 1)
            ),
            Err(PluginTrustPolicyRegistryErrorV1::ActivationEventRejected)
        );
        assert_eq!(store.retained_policy_state("scope")?, before);
        assert_eq!(store.ledger("scope")?.len(), 1);
        assert_eq!(store.active_release("scope", "plugin-a")?, None);
        assert_eq!(store.event_ids.len(), events);
        Ok(())
    }

    #[test]
    fn the_visibility_guard_rejects_a_hidden_activation_timeline() -> TestResult {
        let mut h = Harness::new()?;
        h.store.geographic_timelines.insert(h.timeline);
        assert_activation_refused(h)
    }

    #[test]
    fn the_fork_guard_rejects_an_admitted_fork_activation_timeline() -> TestResult {
        let mut h = Harness::new()?;
        let fork = h.timeline;
        let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
            operation_id: Hash::from_bytes([1; 32]),
            principal_owner_binding_digest: Hash::from_bytes([2; 32]),
            creator: OwnerIdV1::from_static("test-owner"),
            parent_timeline_id: TimelineId::new(),
            child_timeline_id: fork,
            room_revision_descriptor_hash: Hash::from_bytes([3; 32]),
            parent_logical_head: 0,
            parent_chain_head_hash: Hash::from_bytes([4; 32]),
            completed_fold_cursor: 0,
            post_fold_tick_boundary: 0,
            plugin_composition_hash: Hash::from_bytes([5; 32]),
            attribution_required: false,
            origin: ForkAttributionOriginV1::Local,
        })
        .map_err(|error| format!("{error:?}"))?;
        h.store.fork_admissions.insert(fork, admission);
        assert_activation_refused(h)
    }
}
