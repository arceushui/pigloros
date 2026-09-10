//! Fork-comparison: diff two timelines that share a common ancestor.

use std::collections::HashSet;

use pos_core::store::{EventReadBounds, SeqRange};
use pos_core::{CoreError, EntityId, ErasureProtectedOperationV1, Event, Seq, TimelineId};
use pos_runtime::ErasureReadSenderV1;
use pos_state::ProjectionRegistry;

/// The result of comparing two diverged timelines.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ForkDiff {
    /// Seq of the common ancestor (the fork point).
    pub fork_seq: Seq,
    /// Events in timeline A after the fork point (not in B).
    pub only_in_a: Vec<Event>,
    /// Events in timeline B after the fork point (not in A).
    pub only_in_b: Vec<Event>,
    /// `EntityId`s whose state differs between A and B at their respective heads.
    pub diverged_entities: Vec<EntityId>,
}

/// Compare two timelines that share a common ancestor at `fork_seq`.
///
/// `fork_seq` is the last sequence number the two timelines share.
/// Events from `fork_seq + 1` onwards are read from each timeline and compared.
///
/// `registry_a` and `registry_b` are separate [`ProjectionRegistry`] instances —
/// one per fork arm — so that each arm's reducers accumulate state in isolation
/// and plugins on different forks never clobber each other's keys.
///
/// Steps:
/// 1. Read post-fork events from `a` and `b`.
/// 2. Collect `only_in_a` and `only_in_b`.
/// 3. Fold post-fork events through `registry_a` and `registry_b` respectively.
/// 4. Collect entity IDs that appear in either side and compare final state.
///
/// # Errors
/// Propagates [`CoreError`] from the underlying store.
pub fn compare(
    sender: &mut ErasureReadSenderV1<'_>,
    timelines: [TimelineId; 2],
    fork_seq: Seq,
    registries: [&mut ProjectionRegistry; 2],
    artifact_digests: [pos_core::ErasureReferenceV1; 2],
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<ForkDiff, CoreError> {
    let [a, b] = timelines;
    let [registry_a, registry_b] = registries;
    let mut outcome = Err(CoreError::ArtifactUnavailable);
    let mut second_fence = Err(CoreError::ArtifactUnavailable);
    let mut first_effect = |sender: &mut ErasureReadSenderV1<'_>| {
        let mut second_effect = |sender: &mut ErasureReadSenderV1<'_>| {
            outcome = require_comparison_artifacts(artifact_digests, evaluation)
                .and_then(|()| compare_with_sender(sender, a, b, fork_seq, registry_a, registry_b));
        };
        second_fence = sender
            .with_protected_effect_fence(b, ErasureProtectedOperationV1::Export, &mut second_effect)
            .map_err(crate::host_error_to_core);
    };
    sender
        .with_protected_effect_fence(a, ErasureProtectedOperationV1::Export, &mut first_effect)
        .map_err(crate::host_error_to_core)?;
    second_fence?;
    outcome
}

fn require_comparison_artifacts(
    artifact_digests: [pos_core::ErasureReferenceV1; 2],
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<(), CoreError> {
    artifact_digests.into_iter().try_for_each(|digest| {
        evaluation
            .require_authoritative_use(pos_core::ErasureArtifactClassV1::ForkOrSnapshot, digest)
            .map_err(|_| CoreError::ArtifactUnavailable)
    })
}

fn compare_with_sender(
    sender: &mut ErasureReadSenderV1<'_>,
    a: TimelineId,
    b: TimelineId,
    fork_seq: Seq,
    registry_a: &mut ProjectionRegistry,
    registry_b: &mut ProjectionRegistry,
) -> Result<ForkDiff, CoreError> {
    let post_fork_range = SeqRange::from_seq(fork_seq.next());
    let bounds = EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let events_a = sender
        .read_bounded(a, post_fork_range, bounds)
        .map_err(crate::host_error_to_core)?;
    let events_b = sender
        .read_bounded(b, post_fork_range, bounds)
        .map_err(crate::host_error_to_core)?;
    compare_events(a, b, fork_seq, registry_a, registry_b, events_a, events_b)
}

fn compare_events(
    a: TimelineId,
    b: TimelineId,
    fork_seq: Seq,
    registry_a: &mut ProjectionRegistry,
    registry_b: &mut ProjectionRegistry,
    events_a: Vec<Event>,
    events_b: Vec<Event>,
) -> Result<ForkDiff, CoreError> {
    registry_a.fold_events(&events_a);
    registry_b.fold_events(&events_b);
    let all_entities: HashSet<EntityId> = events_a
        .iter()
        .chain(events_b.iter())
        .map(|event| event.entity)
        .collect();
    registry_a
        .state_snapshot(a)
        .map_err(|_| CoreError::ArtifactUnavailable)
        .and_then(|snap_a| {
            registry_b
                .state_snapshot(b)
                .map_err(|_| CoreError::ArtifactUnavailable)
                .map(|snap_b| {
                    // Entities whose state differs across any registered reducer.
                    let diverged_entities: Vec<EntityId> = all_entities
                        .into_iter()
                        .filter(|eid| {
                            // Check all reducer names present in either snapshot.
                            let names: HashSet<&String> =
                                snap_a.keys().chain(snap_b.keys()).collect();
                            names.iter().any(|name| {
                                let reg_a = snap_a.get(*name).cloned().unwrap_or_default();
                                let reg_b = snap_b.get(*name).cloned().unwrap_or_default();
                                reg_a.get_or_default(eid) != reg_b.get_or_default(eid)
                            })
                        })
                        .collect();

                    ForkDiff {
                        fork_seq,
                        only_in_a: events_a,
                        only_in_b: events_b,
                        diverged_entities,
                    }
                })
        })
}

#[cfg(test)]
fn compare_from_store(
    store: &dyn pos_core::store::EventStore,
    a: TimelineId,
    b: TimelineId,
    fork_seq: Seq,
    registry_a: &mut ProjectionRegistry,
    registry_b: &mut ProjectionRegistry,
) -> Result<ForkDiff, CoreError> {
    let post_fork_range = SeqRange::from_seq(fork_seq.next());
    let events_a = store.read(a, post_fork_range)?;
    let events_b = store.read(b, post_fork_range)?;
    compare_events(a, b, fork_seq, registry_a, registry_b, events_a, events_b)
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

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful compare fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
        store::EventStore,
        ErasureContainmentGateV1, Event, Reducer, State,
    };
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};
    use std::sync::Arc;

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

    fn make_registry() -> ProjectionRegistry {
        let mut reg =
            ProjectionRegistry::new().with_erasure_gate(Arc::new(ErasureContainmentGateV1::new()));
        reg.register("count", Box::new(CountReducer));
        reg
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.tick"),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    fn count_for(reg: &ProjectionRegistry, timeline: TimelineId, entity: EntityId) -> u64 {
        reg.state_snapshot(timeline)
            .test_ok()
            .get("count")
            .and_then(|r| r.get(&entity))
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    fn open_test_store() -> Box<dyn EventStore> {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()))
            .test_ok();
        store
    }

    fn compare(
        store: &dyn EventStore,
        a: TimelineId,
        b: TimelineId,
        fork_seq: Seq,
        registry_a: &mut ProjectionRegistry,
        registry_b: &mut ProjectionRegistry,
    ) -> Result<ForkDiff, CoreError> {
        compare_from_store(store, a, b, fork_seq, registry_a, registry_b)
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_identical_timelines_no_diff() {
        // Fork a timeline, append nothing to either fork. Diff should be empty.
        let mut store = open_test_store();
        let parent = store.create_timeline("parent").test_ok();
        let entity = EntityId::new();

        // Append some shared events to the parent.
        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        let committed = store.append(parent.id(), &drafts).test_ok();
        let fork_seq = committed.last().test_ok().seq;

        // Fork twice at the same point.
        let fork_a = store.fork(parent.id(), fork_seq, "a").test_ok();
        let fork_b = store.fork(parent.id(), fork_seq, "b").test_ok();

        // No additional events on either fork.
        let diff = compare(
            store.as_ref(),
            fork_a.id(),
            fork_b.id(),
            fork_seq,
            &mut make_registry(),
            &mut make_registry(),
        )
        .test_ok();

        assert!(diff.only_in_a.is_empty());
        assert!(diff.only_in_b.is_empty());
        assert!(diff.diverged_entities.is_empty());
        assert_eq!(diff.fork_seq, fork_seq);
    }

    #[test]
    fn public_compare_holds_one_host_generation_across_both_forks() {
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
        )
        .test_ok();
        let gate = host.containment_gate();
        let (fork_a, fork_b, fork_seq, entity) = {
            let mut commands = host.command_sender().test_ok();
            let parent = commands.create_timeline("hosted-compare").test_ok();
            let entity = EntityId::new();
            let shared = commands.append(parent.id(), &[draft(entity)]).test_ok();
            let fork_seq = shared[0].seq;
            let fork_a = commands
                .fork_timeline(parent.id(), fork_seq, "hosted-a")
                .test_ok();
            let fork_b = commands
                .fork_timeline(parent.id(), fork_seq, "hosted-b")
                .test_ok();
            commands.append(fork_a.id(), &[draft(entity)]).test_ok();
            (fork_a.id(), fork_b.id(), fork_seq, entity)
        };
        let digests = [
            pos_core::ErasureReferenceV1::from_digest([40; 32]),
            pos_core::ErasureReferenceV1::from_digest([41; 32]),
        ];
        let claims = digests.map(|digest| pos_core::ArtifactClaimInputV1 {
            registration: pos_core::RegisteredArtifactV1::new(
                pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
                digest,
                pos_core::ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                pos_core::ErasureReferenceV1::from_digest([42; 32]),
                pos_core::ArtifactOptionalityV1::Required,
                pos_core::ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: pos_core::ErasureReplayClaimV1::Exact,
            state: pos_core::ArtifactStateV1::Retained,
        });
        let evaluation = pos_core::ReplayClaimEvaluatorV1::evaluate(
            pos_core::ErasureReplayClaimV1::Exact,
            &claims,
        )
        .test_ok();
        let mut registry_a = ProjectionRegistry::new().with_erasure_gate(Arc::clone(&gate));
        registry_a.register("count", Box::new(CountReducer));
        let mut registry_b = ProjectionRegistry::new().with_erasure_gate(gate);
        registry_b.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();
        let diff = super::compare(
            &mut reads,
            [fork_a, fork_b],
            fork_seq,
            [&mut registry_a, &mut registry_b],
            digests,
            &evaluation,
        )
        .test_ok();
        assert_eq!(diff.only_in_a.len(), 1);
        assert!(diff.only_in_b.is_empty());
        assert!(diff.diverged_entities.contains(&entity));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_diverged_timelines_detects_differences() {
        let mut store = open_test_store();
        let parent = store.create_timeline("parent").test_ok();
        let shared_entity = EntityId::new();

        // Append 2 shared events.
        let shared_drafts: Vec<EventDraft> = (0..2).map(|_| draft(shared_entity)).collect();
        let committed = store.append(parent.id(), &shared_drafts).test_ok();
        let fork_seq = committed.last().test_ok().seq;

        // Fork into A and B.
        let fork_a = store.fork(parent.id(), fork_seq, "branch-a").test_ok();
        let fork_b = store.fork(parent.id(), fork_seq, "branch-b").test_ok();

        // Append different counts to each fork for the same entity.
        let drafts_a: Vec<EventDraft> = (0..2).map(|_| draft(shared_entity)).collect();
        let drafts_b: Vec<EventDraft> = (0..3).map(|_| draft(shared_entity)).collect();

        store.append(fork_a.id(), &drafts_a).test_ok();
        store.append(fork_b.id(), &drafts_b).test_ok();

        let diff = compare(
            store.as_ref(),
            fork_a.id(),
            fork_b.id(),
            fork_seq,
            &mut make_registry(),
            &mut make_registry(),
        )
        .test_ok();

        // Each side should have its own post-fork events.
        assert_eq!(diff.only_in_a.len(), 2);
        assert_eq!(diff.only_in_b.len(), 3);

        // shared_entity has different counts on A (2) vs B (3) -> diverged.
        assert!(diff.diverged_entities.contains(&shared_entity));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_isolated_registries_no_clobber() {
        // Two registries must not share state even when both see events for the
        // same entity. This exercises the isolation guarantee that motivated the
        // fix from a single shared reducers slice.
        let mut store = open_test_store();
        let parent = store.create_timeline("parent").test_ok();
        let entity = EntityId::new();

        let shared: Vec<EventDraft> = (0..2).map(|_| draft(entity)).collect();
        let committed = store.append(parent.id(), &shared).test_ok();
        let fork_seq = committed.last().test_ok().seq;

        let fork_a = store.fork(parent.id(), fork_seq, "iso-a").test_ok();
        let fork_b = store.fork(parent.id(), fork_seq, "iso-b").test_ok();

        // Only A gets new events; B stays at the fork point.
        let new_a: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(fork_a.id(), &new_a).test_ok();

        let mut reg_a = make_registry();
        let mut reg_b = make_registry();

        let diff = compare(
            store.as_ref(),
            fork_a.id(),
            fork_b.id(),
            fork_seq,
            &mut reg_a,
            &mut reg_b,
        )
        .test_ok();

        // B has no post-fork events.
        assert_eq!(diff.only_in_b.len(), 0);
        // A saw 3 events, B saw 0 → the entity state must diverge.
        assert!(diff.diverged_entities.contains(&entity));

        // Verify registry isolation: reg_a accumulated 3 events, reg_b accumulated 0.
        let count_a = count_for(&reg_a, fork_a.id(), entity);
        let count_b = count_for(&reg_b, fork_b.id(), entity);
        let _ = count_for(&reg_b, fork_b.id(), EntityId::new());

        assert_eq!(count_a, 3, "reg_a should have folded 3 post-fork events");
        assert_eq!(count_b, 0, "reg_b should have seen no post-fork events");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_unknown_timeline_returns_store_error() {
        let store = open_test_store();
        let mut reg_a = make_registry();
        let mut reg_b = make_registry();
        let err = compare(
            store.as_ref(),
            TimelineId::new(),
            TimelineId::new(),
            Seq::ZERO,
            &mut reg_a,
            &mut reg_b,
        )
        .test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_second_timeline_missing_returns_error() {
        // Covers the `events_b` read error path (first timeline exists).
        let mut store = open_test_store();
        let a = store.create_timeline("a").test_ok();
        let mut reg_a = make_registry();
        let mut reg_b = make_registry();
        let err = compare(
            store.as_ref(),
            a.id(),
            TimelineId::new(),
            Seq::ZERO,
            &mut reg_a,
            &mut reg_b,
        )
        .test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }
}
