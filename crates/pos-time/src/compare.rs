//! Fork-comparison: install both arms of two timelines that share a common
//! ancestor and report the entities whose State differs.

use pos_core::staged_install::PreparedInstallPairV1;
use pos_core::store::{EventReadBounds, SeqRange};
use pos_core::trusted_clock::{ApplicableExpiriesV1, ReleaseGuardV1, StagedProtectedOutputV1};
use pos_core::{
    CoreError, EntityId, ErasureProtectedOperationV1, Event, Seq, TimelineId, WorldReplayClosureV1,
};
use pos_runtime::{ErasureReadSenderV1, WorldReplayUseV1};
use pos_state::{ProjectionRegistry, RevokedSubjectsV1};

use crate::{ProtectedFoldV1, ProtectedReleaseV1, ReleaseHealthV1};

/// The State-only result of comparing two diverged timelines.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ForkDiff {
    /// Seq of the common ancestor (the fork point).
    pub fork_seq: Seq,
    /// `EntityId`s whose installed State differs between A and B, over the
    /// union of entity IDs in both, sorted by raw `EntityId` bytes.
    pub diverged_entities: Vec<EntityId>,
}

/// Compare two timelines that share a common ancestor at `fork_seq`.
///
/// `fork_seq` is the last sequence number the two timelines share.
///
/// `registry_a` and `registry_b` are separate [`ProjectionRegistry`] instances —
/// one per fork arm — so that each arm's reducers accumulate state in isolation
/// and plugins on different forks never clobber each other's keys.
///
/// Steps, inside `release`'s guard and both Timelines' fences:
/// 1. Verify and read both complete histories, and check the shared prefix.
/// 2. Fold each history on the staged executor for its arm's consumers.
/// 3. Re-verify both, then prepare both installs as one pair and hand them
///    over under one ADR-112 handoff token: both arms install or neither.
/// 4. Report the entities whose installed State differs. No Event is
///    returned.
///
/// # Errors
/// Fails closed when protected-use authorization, native evidence, read
/// bounds, the staged folds, the install checks, the handoff or final
/// rechecks are unavailable. Host errors are mapped to
/// [`CoreError::ArtifactUnavailable`], [`CoreError::ErasureAccessFrozen`], or
/// [`CoreError::ErasureContainmentUnavailable`]. Neither registry changes,
/// except that each arm forgets the revoked subjects of its own range when
/// that range was read and verified.
pub fn compare(
    sender: &mut ErasureReadSenderV1<'_>,
    timelines: [TimelineId; 2],
    fork_seq: Seq,
    registries: [&mut ProjectionRegistry; 2],
    closures: [&WorldReplayClosureV1; 2],
    release: ProtectedReleaseV1<'_>,
    folds: [&ProtectedFoldV1<'_>; 2],
) -> Result<ForkDiff, CoreError> {
    let [a, b] = timelines;
    let [registry_a, registry_b] = registries;
    let consumer_ids = comparison_consumers(fork_seq, [&*registry_a, &*registry_b])?;
    let request = CompareRequestV1 {
        timelines,
        fork_seq,
        closures,
        folds,
        consumer_ids: &consumer_ids,
    };
    let ProtectedReleaseV1 {
        guard,
        expiries,
        health,
    } = release;
    let mut guard = Some(guard);
    let mut revoked: [Option<RevokedSubjectsV1>; 2] = [None, None];
    let mut comparison_outcome = Err(CoreError::ArtifactUnavailable);
    let mut second_timeline_fence_result = Err(CoreError::ArtifactUnavailable);
    let mut first_timeline_effect = |sender: &mut ErasureReadSenderV1<'_>| {
        let mut second_timeline_effect = |sender: &mut ErasureReadSenderV1<'_>| {
            if let Some(held) = guard.take() {
                let target = CompareTargetV1 {
                    registries: [&mut *registry_a, &mut *registry_b],
                    guard: held,
                    expiries: &expiries,
                    health,
                    revoked: &mut revoked,
                };
                comparison_outcome = compare_in_fences(sender, &request, target);
            }
        };
        second_timeline_fence_result = sender
            .with_protected_effect_fence(
                b,
                ErasureProtectedOperationV1::Export,
                &mut second_timeline_effect,
            )
            .map_err(crate::host_error_to_core);
    };
    let fenced = sender
        .with_protected_effect_fence(
            a,
            ErasureProtectedOperationV1::Export,
            &mut first_timeline_effect,
        )
        .map_err(crate::host_error_to_core)
        .and(second_timeline_fence_result)
        .and(comparison_outcome);
    // P2 and teardown of a guard the effect never took, before the
    // failure-path forget of each arm.
    crate::teardown(guard, health);
    let [revoked_a, revoked_b] = revoked;
    let fenced = crate::forget_on_failure(fenced, registry_a, revoked_a.as_ref());
    crate::forget_on_failure(fenced, registry_b, revoked_b.as_ref())
}

/// Refuse a Fork point with no successor and a quarantined staged executor,
/// then select each arm's consumers.
fn comparison_consumers(
    fork_seq: Seq,
    registries: [&ProjectionRegistry; 2],
) -> Result<[Vec<String>; 2], CoreError> {
    if fork_seq.as_u64() == u64::MAX {
        return Err(CoreError::ArtifactUnavailable);
    }
    let [registry_a, registry_b] = registries;
    pos_runtime::require_staged_release()
        .map_err(crate::unavailable)
        .and_then(|()| crate::consumer_selection(registry_a))
        .and_then(|ids_a| crate::consumer_selection(registry_b).map(|ids_b| [ids_a, ids_b]))
}

/// One protected Compare request.
struct CompareRequestV1<'r> {
    timelines: [TimelineId; 2],
    fork_seq: Seq,
    closures: [&'r WorldReplayClosureV1; 2],
    folds: [&'r ProtectedFoldV1<'r>; 2],
    consumer_ids: &'r [Vec<String>; 2],
}

/// Both visible registries, the held guard and each arm's failure-path record.
struct CompareTargetV1<'t, 'g> {
    registries: [&'t mut ProjectionRegistry; 2],
    guard: ReleaseGuardV1<'g>,
    expiries: &'t ApplicableExpiriesV1,
    health: &'t ReleaseHealthV1,
    revoked: &'t mut [Option<RevokedSubjectsV1>; 2],
}

/// Stage both arms inside their fences, then hand them over under one token
/// and release the diverged entities; on any failure before the handoff,
/// run P2 and tear the guard down.
fn compare_in_fences(
    sender: &mut ErasureReadSenderV1<'_>,
    request: &CompareRequestV1<'_>,
    target: CompareTargetV1<'_, '_>,
) -> Result<ForkDiff, CoreError> {
    let CompareTargetV1 {
        registries,
        guard,
        expiries,
        health,
        revoked,
    } = target;
    let prepared = prepare_comparison(sender, request, &guard, revoked, registries);
    keep_guard_or_teardown(guard, health, prepared).and_then(
        |(guard, (prepared, diverged_entities))| {
            // One token commits both arms. ADR-112's overrun signal is
            // recorded and the displaced maps are dropped after the handoff
            // returns, and only then is the diff released.
            pos_runtime::handoff(guard, expiries, prepared)
                .map(|used| health.record_overrun(used.overrun_signal()))
                .map_err(crate::unavailable)
                .map(|()| ForkDiff {
                    fork_seq: request.fork_seq,
                    diverged_entities,
                })
        },
    )
}

/// Keep the held guard for the handoff when both arms were prepared;
/// otherwise run P2 and tear the guard down before reporting the failure.
fn keep_guard_or_teardown<'g, T>(
    guard: ReleaseGuardV1<'g>,
    health: &ReleaseHealthV1,
    prepared: Result<T, CoreError>,
) -> Result<(ReleaseGuardV1<'g>, T), CoreError> {
    match prepared {
        Ok(prepared) => Ok((guard, prepared)),
        Err(error) => {
            crate::teardown(Some(guard), health);
            Err(error)
        }
    }
}

/// Both arms' prepared install and their diverged entities.
type PreparedComparisonV1<'t> = (
    StagedProtectedOutputV1<PreparedInstallPairV1<'t, 't>>,
    Vec<EntityId>,
);

/// Bind, verify, read, fold and re-verify both arms inside their fences,
/// check the handoff reserve, compute the diverged entities, and prepare
/// both installs as one pair.
fn prepare_comparison<'t>(
    sender: &mut ErasureReadSenderV1<'_>,
    request: &CompareRequestV1<'_>,
    guard: &ReleaseGuardV1<'_>,
    revoked: &mut [Option<RevokedSubjectsV1>; 2],
    registries: [&'t mut ProjectionRegistry; 2],
) -> Result<PreparedComparisonV1<'t>, CoreError> {
    let [a, b] = request.timelines;
    let [closure_a, closure_b] = request.closures;
    let requested_a = comparison_use(sender, a, &request.consumer_ids[0])?;
    let requested_b = comparison_use(sender, b, &request.consumer_ids[1])?;
    let requested_uses = [&requested_a, &requested_b];
    let read_bounds = require_comparison_artifacts(sender, request.closures, requested_uses)?;
    let events_a = crate::read_complete_world_replay(sender, &requested_a, read_bounds[0])?;
    revoked[0] = Some(RevokedSubjectsV1::from_verified_events(&events_a));
    let events_b = crate::read_complete_world_replay(sender, &requested_b, read_bounds[1])?;
    revoked[1] = Some(RevokedSubjectsV1::from_verified_events(&events_b));
    require_shared_fork(request.fork_seq, &events_a, &events_b)?;
    let [fold_a, fold_b] = request.folds;
    let staged_a = crate::fold_staged(
        fold_a,
        guard,
        events_a,
        crate::verified_source(a, closure_a),
    )?;
    let staged_b = crate::fold_staged(
        fold_b,
        guard,
        events_b,
        crate::verified_source(b, closure_b),
    )?;
    let final_bounds = require_comparison_artifacts(sender, request.closures, requested_uses)?;
    if final_bounds != read_bounds {
        return Err(CoreError::ArtifactUnavailable);
    }
    crate::handoff_reserve(guard)?;
    let diverged_entities = staged_a
        .diverged_entities(&staged_b)
        .map_err(crate::unavailable)?;
    let [registry_a, registry_b] = registries;
    ProjectionRegistry::prepare_install_pair(registry_a, staged_a, registry_b, staged_b)
        .map(|prepared| (prepared, diverged_entities))
        .map_err(crate::unavailable)
}

fn require_comparison_artifacts(
    sender: &mut ErasureReadSenderV1<'_>,
    closures: [&WorldReplayClosureV1; 2],
    requested_uses: [&WorldReplayUseV1; 2],
) -> Result<[EventReadBounds; 2], CoreError> {
    let [closure_a, closure_b] = closures;
    let [requested_a, requested_b] = requested_uses;
    crate::require_world_replay(sender, closure_a, requested_a).and_then(|bounds_a| {
        crate::require_world_replay(sender, closure_b, requested_b)
            .map(|bounds_b| [bounds_a, bounds_b])
    })
}

fn comparison_use(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    consumer_ids: &[String],
) -> Result<WorldReplayUseV1, CoreError> {
    crate::observed_world_replay_use(
        sender,
        timeline,
        ErasureProtectedOperationV1::Export,
        SeqRange::all(),
        consumer_ids,
    )
}

/// Require both complete histories to share exactly the prefix through
/// `fork_seq` and to diverge after it.
fn require_shared_fork(
    fork_seq: Seq,
    events_a: &[Event],
    events_b: &[Event],
) -> Result<(), CoreError> {
    let prefix_a = &events_a[..events_a.partition_point(|event| event.seq <= fork_seq)];
    let prefix_b = &events_b[..events_b.partition_point(|event| event.seq <= fork_seq)];
    // A zero Fork point has no shared Event with which to establish lineage;
    // its native owner proof is not available through this provisional seam.
    if fork_seq == Seq::ZERO
        || prefix_a != prefix_b
        || prefix_a.last().is_none_or(|event| event.seq != fork_seq)
        || (events_a.get(prefix_a.len()).is_some()
            && events_a.get(prefix_a.len()) == events_b.get(prefix_b.len()))
    {
        return Err(CoreError::ArtifactUnavailable);
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected compare fixture error: {error:?}"
                )))
            })
        }
    }

    use super::*;
    use crate::test_support::{with_release, ProtectedFixture};
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
        EventId, Hash, PluginId, Reducer, SchemaVersion, State, WallTime,
    };
    use pos_runtime::ErasureExecutionHostV1;
    use pos_state::ProjectionRegistry;
    use pos_store::StoreConfig;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    // ── helpers ──────────────────────────────────────────────────────────────

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            let mut s = State::new();
            s.set("n", serde_json::json!(0u64));
            s
        }

        fn apply(&self, state: &mut State, _event: &Event) {
            let n = state
                .get("n")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn count_reducer() -> Box<dyn Reducer> {
        Box::new(CountReducer)
    }

    fn count_fixture() -> ProtectedFixture {
        ProtectedFixture::new("count", count_reducer)
    }

    struct RecordGenerationVerifier {
        observations: Mutex<Vec<(TimelineId, pos_core::ErasureReferenceV1)>>,
    }

    impl pos_runtime::WorldReplayVerifierV1 for RecordGenerationVerifier {
        fn verify(
            &self,
            closure: &pos_core::WorldReplayClosureV1,
            requested_use: &pos_runtime::WorldReplayUseV1,
            inventory_generation: pos_core::ErasureReferenceV1,
        ) -> Result<pos_runtime::VerifiedWorldReplayV1, pos_runtime::WorldReplayVerificationErrorV1>
        {
            self.observations
                .lock()
                .map_err(|_| pos_runtime::WorldReplayVerificationErrorV1::EvidenceUnavailable)?
                .push((requested_use.timeline_id(), inventory_generation));
            Ok(pos_runtime::world_replay::test_verified_world_replay(
                closure,
                requested_use,
                inventory_generation,
                pos_core::ErasureReplayClaimV1::Exact,
            ))
        }
    }

    struct RejectThirdVerification {
        calls: AtomicUsize,
    }

    impl pos_runtime::WorldReplayVerifierV1 for RejectThirdVerification {
        fn verify(
            &self,
            closure: &pos_core::WorldReplayClosureV1,
            requested_use: &pos_runtime::WorldReplayUseV1,
            inventory_generation: pos_core::ErasureReferenceV1,
        ) -> Result<pos_runtime::VerifiedWorldReplayV1, pos_runtime::WorldReplayVerificationErrorV1>
        {
            if self.calls.fetch_add(1, Ordering::SeqCst) < 2 {
                Ok(pos_runtime::world_replay::test_verified_world_replay(
                    closure,
                    requested_use,
                    inventory_generation,
                    pos_core::ErasureReplayClaimV1::Exact,
                ))
            } else {
                Err(pos_runtime::WorldReplayVerificationErrorV1::EvidenceUnavailable)
            }
        }
    }

    struct ChangeBoundsOnThirdVerification {
        calls: AtomicUsize,
    }

    impl pos_runtime::WorldReplayVerifierV1 for ChangeBoundsOnThirdVerification {
        fn verify(
            &self,
            closure: &pos_core::WorldReplayClosureV1,
            requested_use: &pos_runtime::WorldReplayUseV1,
            inventory_generation: pos_core::ErasureReferenceV1,
        ) -> Result<pos_runtime::VerifiedWorldReplayV1, pos_runtime::WorldReplayVerificationErrorV1>
        {
            let max_events = if self.calls.fetch_add(1, Ordering::SeqCst) < 2 {
                65_536
            } else {
                65_535
            };
            Ok(
                pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
                    closure.digest(),
                    closure.timeline_id(),
                    closure.source_head(),
                    requested_use.clone(),
                    inventory_generation,
                    pos_core::ErasureReplayClaimV1::Exact,
                    EventReadBounds::new_with_total_bytes_and_elapsed(
                        65_536, 128, 8, max_events, 67_108_864, 30_000_000,
                    ),
                ),
            )
        }
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.tick"),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    fn count_for(reg: &ProjectionRegistry, timeline: TimelineId, entity: EntityId) -> u64 {
        reg.state_for(timeline, &entity)
            .test_ok()
            .and_then(|s| s.get("n").and_then(serde_json::Value::as_u64))
            .unwrap_or(0)
    }

    fn compare_with(
        fixture: &ProtectedFixture,
        reads: &mut ErasureReadSenderV1<'_>,
        timelines: [TimelineId; 2],
        fork_seq: Seq,
        registries: [&mut ProjectionRegistry; 2],
        closures: [&WorldReplayClosureV1; 2],
    ) -> Result<ForkDiff, CoreError> {
        let (fold_a, fold_b) = (fixture.fold(), fixture.fold());
        with_release(|release| {
            super::compare(
                reads,
                timelines,
                fork_seq,
                registries,
                closures,
                release,
                [&fold_a, &fold_b],
            )
        })
    }

    /// Forks of one parent: `shared` Events, then `extra_a` and `extra_b`
    /// Events on each fork, all for `entities` in turn.
    fn forked(
        host: &mut ErasureExecutionHostV1,
        entities: &[EntityId],
        shared: usize,
        extra: [usize; 2],
    ) -> (TimelineId, TimelineId, Seq) {
        let drafts = |count: usize| -> Vec<EventDraft> {
            (0..count)
                .map(|index| draft(entities[index % entities.len()]))
                .collect()
        };
        let mut commands = host.command_sender().test_ok();
        let parent = commands.create_timeline("compare-parent").test_ok();
        let committed = commands.append(parent.id(), &drafts(shared)).test_ok();
        let fork_seq = committed[shared - 1].seq;
        let fork_a = commands
            .fork_timeline(parent.id(), fork_seq, "compare-a")
            .test_ok();
        let fork_b = commands
            .fork_timeline(parent.id(), fork_seq, "compare-b")
            .test_ok();
        for (fork, count) in [(fork_a.id(), extra[0]), (fork_b.id(), extra[1])] {
            if count > 0 {
                commands.append(fork, &drafts(count)).test_ok();
            }
        }
        (fork_a.id(), fork_b.id(), fork_seq)
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn public_compare_rejects_either_empty_consumer_selection() {
        let fixture = count_fixture();
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let mut reads = host.read_sender().test_ok();
        let closure = pos_core::WorldReplayClosureV1::test_fixture().test_ok();
        let timelines = [TimelineId::new(), TimelineId::new()];
        let mut empty_a = ProjectionRegistry::new();
        let mut valid_b = fixture.registry(Arc::clone(&gate));
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                timelines,
                Seq::ZERO,
                [&mut empty_a, &mut valid_b],
                [&closure, &closure],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        let mut valid_a = fixture.registry(gate);
        let mut empty_b = ProjectionRegistry::new();
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                timelines,
                Seq::ZERO,
                [&mut valid_a, &mut empty_b],
                [&closure, &closure],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    #[test]
    fn compare_rejects_histories_without_a_shared_fork_point() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (a, b) = {
            let mut commands = host.command_sender().test_ok();
            let a = commands.create_timeline("unrelated-a").test_ok().id();
            let b = commands.create_timeline("unrelated-b").test_ok().id();
            commands.append(a, &[draft(entity)]).test_ok();
            commands.append(b, &[draft(entity)]).test_ok();
            (a, b)
        };
        let closure_a = crate::test_support::closure_for_host(&mut host, a);
        let closure_b = crate::test_support::closure_for_host(&mut host, b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                [a, b],
                Seq::from_u64(1),
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(count_for(&registry_a, a, entity), 0);
        assert_eq!(count_for(&registry_b, b, entity), 0);
    }

    #[test]
    fn compare_identical_timelines_no_diff() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &[entity], 3, [0, 0]);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        let diff = compare_with(
            &fixture,
            &mut reads,
            [fork_a, fork_b],
            fork_seq,
            [&mut registry_a, &mut registry_b],
            [&closure_a, &closure_b],
        )
        .test_ok();

        assert!(diff.diverged_entities.is_empty());
        assert_eq!(diff.fork_seq, fork_seq);
        assert_eq!(count_for(&registry_a, fork_a, entity), 3);
        assert_eq!(count_for(&registry_b, fork_b, entity), 3);
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                [fork_a, fork_b],
                Seq::from_u64(fork_seq.as_u64() + 1),
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    #[test]
    fn public_compare_holds_one_host_generation_across_both_forks() {
        let fixture = count_fixture();
        let verifier = Arc::new(RecordGenerationVerifier {
            observations: Mutex::new(Vec::new()),
        });
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(verifier.clone());
        let mut host = pos_runtime::ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &[entity], 1, [1, 0]);
        let (_, generation) = host
            .read_sender()
            .test_ok()
            .read_bounded_at_generation(
                fork_a,
                SeqRange::all(),
                EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
                None,
            )
            .test_ok();
        let mut registry_a = fixture.registry(gate.clone());
        let mut registry_b = fixture.registry(gate);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut reads = host.read_sender().test_ok();
        let diff = compare_with(
            &fixture,
            &mut reads,
            [fork_a, fork_b],
            fork_seq,
            [&mut registry_a, &mut registry_b],
            [&closure_a, &closure_b],
        )
        .test_ok();
        assert_eq!(diff.diverged_entities, vec![entity]);
        assert_eq!(
            verifier.observations.lock().test_ok().as_slice(),
            &[
                (fork_a, generation),
                (fork_b, generation),
                (fork_a, generation),
                (fork_b, generation),
            ]
        );
    }

    /// Case 15 (success): both arms install under one handoff and the diff
    /// has only `fork_seq` and the diverged entities, sorted by raw bytes.
    #[test]
    fn public_compare_uses_an_installed_world_verifier() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let mut entities = [EntityId::new(), EntityId::new(), EntityId::new()];
        entities.reverse();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &entities, 3, [5, 0]);
        let earlier_seq = Seq::from_u64(fork_seq.as_u64() - 1);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        let diff = compare_with(
            &fixture,
            &mut reads,
            [fork_a, fork_b],
            fork_seq,
            [&mut registry_a, &mut registry_b],
            [&closure_a, &closure_b],
        )
        .test_ok();
        let mut expected = entities.to_vec();
        expected.sort_unstable_by_key(|entity| entity.inner().to_bytes());
        assert_eq!(diff.diverged_entities, expected);
        assert_eq!(diff.fork_seq, fork_seq);
        assert_eq!(count_for(&registry_a, fork_a, entities[0]), 3);
        assert_eq!(count_for(&registry_b, fork_b, entities[0]), 1);
        for invalid_fork_seq in [earlier_seq, Seq::ZERO, Seq::from_u64(7)] {
            assert!(matches!(
                compare_with(
                    &fixture,
                    &mut reads,
                    [fork_a, fork_b],
                    invalid_fork_seq,
                    [&mut registry_a, &mut registry_b],
                    [&closure_a, &closure_b],
                ),
                Err(CoreError::ArtifactUnavailable)
            ));
        }
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                [fork_a, fork_b],
                Seq::from_u64(u64::MAX),
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(count_for(&registry_a, fork_a, entities[0]), 3);
    }

    /// Case 15 (failure): when one arm cannot be prepared, neither arm is
    /// installed.
    #[test]
    fn public_compare_installs_neither_arm_when_one_cannot_be_prepared() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &[entity], 1, [1, 2]);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = ProjectionRegistry::new().with_erasure_gate(gate);
        registry_b
            .register_installed_reducer(PluginId::new(), "count", count_reducer())
            .test_ok();
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                [fork_a, fork_b],
                fork_seq,
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(count_for(&registry_a, fork_a, entity), 0);
        assert_eq!(count_for(&registry_b, fork_b, entity), 0);
    }

    /// Arms folded for different consumer sets cannot be compared slot by
    /// slot: the diff fails closed and neither arm is installed, even though
    /// each arm alone would install.
    #[test]
    fn public_compare_refuses_arms_with_different_consumer_sets() {
        let fixture = count_fixture();
        let rival = fixture.rival();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &[entity], 1, [1, 2]);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = rival.registry(gate);
        let mut reads = host.read_sender().test_ok();
        let (fold_a, fold_b) = (fixture.fold(), rival.fold());
        let compared = with_release(|release| {
            super::compare(
                &mut reads,
                [fork_a, fork_b],
                fork_seq,
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
                release,
                [&fold_a, &fold_b],
            )
        });
        assert!(matches!(compared, Err(CoreError::ArtifactUnavailable)));
        assert_eq!(count_for(&registry_a, fork_a, entity), 0);
        assert_eq!(count_for(&registry_b, fork_b, entity), 0);
    }

    #[test]
    fn public_compare_rolls_back_when_final_verification_fails() {
        let fixture = count_fixture();
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(RejectThirdVerification {
                calls: AtomicUsize::new(0),
            }));
        let mut host = pos_runtime::ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &[entity], 1, [1, 1]);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                [fork_a, fork_b],
                fork_seq,
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(count_for(&registry_a, fork_a, entity), 0);
        assert_eq!(count_for(&registry_b, fork_b, entity), 0);
    }

    #[test]
    fn public_compare_rolls_back_when_final_read_bounds_change() {
        let fixture = count_fixture();
        let verifier = Arc::new(ChangeBoundsOnThirdVerification {
            calls: AtomicUsize::new(0),
        });
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(verifier.clone());
        let mut host = pos_runtime::ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let entity = EntityId::new();
        let (fork_a, fork_b, fork_seq) = forked(&mut host, &[entity], 1, [1, 1]);
        let closure_a = crate::test_support::closure_for_host(&mut host, fork_a);
        let closure_b = crate::test_support::closure_for_host(&mut host, fork_b);
        let mut registry_a = fixture.registry(Arc::clone(&gate));
        let mut registry_b = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            compare_with(
                &fixture,
                &mut reads,
                [fork_a, fork_b],
                fork_seq,
                [&mut registry_a, &mut registry_b],
                [&closure_a, &closure_b],
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(count_for(&registry_a, fork_a, entity), 0);
        assert_eq!(count_for(&registry_b, fork_b, entity), 0);
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn shared_fork_requires_one_common_prefix_and_divergence_after_it() {
        let event = |seq: u64| Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("test.tick"),
            payload: CanonicalBytes::from_vec(Vec::new()),
            wall_time: WallTime::from_micros(seq),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let (first, second) = (event(1), event(2));
        let a = [first.clone(), event(2)];
        let b = [first.clone(), event(2)];
        let one = Seq::from_u64(1);
        assert!(require_shared_fork(one, &a, &b).is_ok());
        assert!(require_shared_fork(Seq::ZERO, &a, &b).is_err());
        assert!(require_shared_fork(one, &a, &[event(1)]).is_err());
        assert!(require_shared_fork(
            Seq::from_u64(3),
            std::slice::from_ref(&first),
            std::slice::from_ref(&first),
        )
        .is_err());
        let same_after = [first.clone(), second.clone()];
        assert!(require_shared_fork(one, &same_after, &[first, second]).is_err());
    }
}
