//! Timeline snapshots: capture state at the current head and verify consistency.

use std::collections::{HashMap, HashSet};

use pos_core::store::{EventReadBounds, SeqRange};
use pos_core::{CoreError, EntityId, ErasureProtectedOperationV1, Seq, StateRegistry, TimelineId};
use pos_runtime::ErasureReadSenderV1;
use pos_state::ProjectionRegistry;

/// A snapshot of all per-reducer entity states at a specific sequence number
/// on a timeline.
///
/// The `registry` field is a map from reducer name → [`StateRegistry`] that
/// mirrors the full [`ProjectionRegistry`] state at capture time. It is kept
/// serialisable so snapshots can be persisted and loaded without re-running
/// every registered reducer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    /// The timeline this snapshot was taken from.
    pub timeline: TimelineId,
    /// The sequence number at which the snapshot was taken (inclusive).
    pub at_seq: Seq,
    /// Per-reducer, per-entity state at `at_seq`.
    pub registry: HashMap<String, StateRegistry>,
}

/// Take a snapshot of the current head of `timeline`.
///
/// All events on the timeline are folded through every reducer registered in
/// `registry`. The resulting per-reducer state is captured inside the returned
/// [`Snapshot`].
///
/// # Errors
/// Returns [`CoreError::ArtifactUnavailable`] when snapshot creation is not
/// authoritative; otherwise propagates [`CoreError`] from the store.
pub fn snapshot(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<Snapshot, CoreError> {
    let mut outcome = Err(CoreError::ArtifactUnavailable);
    let mut effect = |sender: &mut ErasureReadSenderV1<'_>| {
        outcome = snapshot_effect(sender, timeline, registry, artifact_digest, evaluation);
    };
    sender
        .with_protected_effect_fence(timeline, ErasureProtectedOperationV1::Snapshot, &mut effect)
        .map_err(crate::host_error_to_core)?;
    outcome
}

fn snapshot_effect(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<Snapshot, CoreError> {
    evaluation
        .require_authoritative_use(
            pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
            artifact_digest,
        )
        .map_err(|_| CoreError::ArtifactUnavailable)?;
    let events = sender
        .read_bounded(timeline, SeqRange::all(), unbounded_snapshot_read())
        .map_err(crate::host_error_to_core)?;
    snapshot_from_events(timeline, registry, &events)
}

/// Error type for snapshot consistency checks.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// ADR-060 no longer permits the snapshot as authoritative state.
    #[error("snapshot artifact is unavailable for authoritative use")]
    ArtifactUnavailable,
    /// A store I/O error occurred.
    #[error("store error: {0}")]
    Store(#[from] CoreError),
    /// The snapshot and full-replay state disagree for an entity.
    #[error("snapshot inconsistent: entity {entity:?} differs")]
    Inconsistent { entity: EntityId },
}

/// Verify that `snapshot` + tail events produces the same state as a full replay.
///
/// Steps:
/// 1. Read events after `snapshot.at_seq` (the "tail") and all events.
/// 2. Restore `registry` to `snap.registry` state, then fold the tail to build
///    the incremental projection.
/// 3. Reset `registry` to empty and fold all events to build the full-replay
///    reference projection.
/// 4. Compare both state maps; return `Err(Inconsistent)` on any mismatch.
///
/// `registry` must be pre-populated with the same reducers used when the
/// snapshot was originally taken. Its accumulated state is managed internally
/// and will be in the full-replay state when this function returns.
///
/// # Errors
/// Returns [`SnapshotError::ArtifactUnavailable`] when the registered snapshot
/// may no longer be used authoritatively, [`SnapshotError::Store`] on I/O
/// failure, or [`SnapshotError::Inconsistent`] if the states differ.
pub fn verify_snapshot_consistency(
    sender: &mut ErasureReadSenderV1<'_>,
    snap: &Snapshot,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<(), SnapshotError> {
    let mut outcome = Err(SnapshotError::ArtifactUnavailable);
    let mut effect = |sender: &mut ErasureReadSenderV1<'_>| {
        outcome = verify_snapshot_effect(sender, snap, registry, artifact_digest, evaluation);
    };
    sender
        .with_protected_effect_fence(
            snap.timeline,
            ErasureProtectedOperationV1::Snapshot,
            &mut effect,
        )
        .map_err(crate::host_error_to_core)
        .map_err(SnapshotError::from)?;
    outcome
}

fn verify_snapshot_effect(
    sender: &mut ErasureReadSenderV1<'_>,
    snap: &Snapshot,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<(), SnapshotError> {
    evaluation
        .require_authoritative_use(
            pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
            artifact_digest,
        )
        .map_err(|_| SnapshotError::ArtifactUnavailable)?;
    let tail_events = sender
        .read_bounded(
            snap.timeline,
            SeqRange::from_seq(snap.at_seq.next()),
            unbounded_snapshot_read(),
        )
        .map_err(crate::host_error_to_core)?;
    let all_events = sender
        .read_bounded(snap.timeline, SeqRange::all(), unbounded_snapshot_read())
        .map_err(crate::host_error_to_core)?;
    verify_snapshot_event_sets(snap, registry, &tail_events, &all_events)
}

const fn unbounded_snapshot_read() -> EventReadBounds {
    EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX)
}

fn snapshot_from_events(
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    events: &[pos_core::Event],
) -> Result<Snapshot, CoreError> {
    let at_seq = events.last().map_or(Seq::ZERO, |event| event.seq);
    registry.fold_events(events);
    registry
        .state_snapshot(timeline)
        .map(|snapshot| Snapshot {
            timeline,
            at_seq,
            registry: snapshot,
        })
        .map_err(|_| CoreError::ArtifactUnavailable)
}

fn verify_snapshot_event_sets(
    snap: &Snapshot,
    registry: &mut ProjectionRegistry,
    tail_events: &[pos_core::Event],
    all_events: &[pos_core::Event],
) -> Result<(), SnapshotError> {
    let all_entities: Vec<EntityId> = all_events
        .iter()
        .map(|event| event.entity)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    registry.restore_from_snapshot(&snap.registry);
    registry.fold_events(tail_events);
    let incremental_state = registry
        .state_snapshot(snap.timeline)
        .map_err(|_| SnapshotError::ArtifactUnavailable)?;
    registry.clear_state();
    registry.fold_events(all_events);
    let full_state = registry
        .state_snapshot(snap.timeline)
        .map_err(|_| SnapshotError::ArtifactUnavailable)?;
    for entity in &all_entities {
        for name in full_state.keys() {
            let incremental_registry = incremental_state.get(name).cloned().unwrap_or_default();
            let full_registry = full_state.get(name).cloned().unwrap_or_default();
            if incremental_registry.get_or_default(entity) != full_registry.get_or_default(entity) {
                return Err(SnapshotError::Inconsistent { entity: *entity });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn snapshot_from_store(
    store: &dyn pos_core::store::EventStore,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<Snapshot, CoreError> {
    evaluation
        .require_authoritative_use(
            pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
            artifact_digest,
        )
        .map_err(|_| CoreError::ArtifactUnavailable)
        .and_then(|()| store.read(timeline, SeqRange::all()))
        .and_then(|events| snapshot_from_events(timeline, registry, &events))
}

#[cfg(test)]
fn verify_snapshot_consistency_from_store(
    store: &dyn pos_core::store::EventStore,
    snap: &Snapshot,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<(), SnapshotError> {
    evaluation
        .require_authoritative_use(
            pos_core::ErasureArtifactClassV1::ForkOrSnapshot,
            artifact_digest,
        )
        .map_err(|_| SnapshotError::ArtifactUnavailable)
        .and_then(|()| {
            let tail_range = SeqRange::from_seq(snap.at_seq.next());
            store
                .read(snap.timeline, tail_range)
                .and_then(|tail_events| {
                    store
                        .read(snap.timeline, SeqRange::all())
                        .map(|all_events| (tail_events, all_events))
                })
                .map_err(SnapshotError::from)
        })
        .and_then(|(tail_events, all_events)| {
            verify_snapshot_event_sets(snap, registry, &tail_events, &all_events)
        })
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
                    "unexpected snapshot fixture error: {error:?}"
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
                    "unexpected successful snapshot fixture value: {value:?}"
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
        ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
        ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureContainmentGateV1,
        ErasureKeyRoleV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, Reducer,
        RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, State,
    };
    use pos_state::{EntityStateProjection, ProjectionRegistry};
    use pos_store::{open_store, StoreConfig};
    use std::sync::Arc;

    struct ReadFailStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl pos_core::store::EventStore for ReadFailStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("read failed".to_owned()))
        }

        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    const SNAPSHOT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([42; 32]);

    fn snapshot_evaluation(state: ArtifactStateV1) -> ReplayClaimEvaluationV1 {
        ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[ArtifactClaimInputV1 {
                registration: RegisteredArtifactV1::new(
                    ErasureArtifactClassV1::ForkOrSnapshot,
                    SNAPSHOT_DIGEST,
                    ArtifactDataClassV1::PrivateSubjectData,
                    Some(ErasureKeyRoleV1::DataEncryption),
                    ErasureReferenceV1::from_digest([43; 32]),
                    ArtifactOptionalityV1::Required,
                    ArtifactTransitionRuleV1::Remove,
                ),
                current_claim: ErasureReplayClaimV1::Exact,
                state,
            }],
        )
        .test_ok()
    }

    fn snapshot(
        store: &dyn EventStore,
        timeline: TimelineId,
        registry: &mut ProjectionRegistry,
    ) -> Result<Snapshot, CoreError> {
        snapshot_from_store(
            store,
            timeline,
            registry,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        )
    }

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

    fn count_in_snapshot(snap: &Snapshot, entity: &EntityId) -> u64 {
        snap.registry
            .get("count")
            .and_then(|r| r.get(entity))
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

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_captures_state_at_head() {
        let mut store = open_test_store();
        let tl = store.create_timeline("snap").test_ok();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..4).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).test_ok();

        let mut reg = make_registry();
        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).test_ok();

        // State should show 4 events applied.
        assert_eq!(count_in_snapshot(&snap, &entity), 4);
        // at_seq should be the seq of the 4th event (non-zero).
        assert!(snap.at_seq > Seq::ZERO);
        assert_eq!(snap.timeline, tl.id());
    }

    #[test]
    fn public_snapshot_commands_hold_the_host_generation_fence() {
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
        )
        .test_ok();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("hosted-snapshot").test_ok();
            let entity = EntityId::new();
            commands
                .append(timeline.id(), &[draft(entity), draft(entity)])
                .test_ok();
            (timeline.id(), entity)
        };
        let evaluation = snapshot_evaluation(ArtifactStateV1::Retained);
        let mut projected = ProjectionRegistry::new().with_erasure_gate(Arc::clone(&gate));
        projected.register("count", Box::new(CountReducer));
        let mut verified = ProjectionRegistry::new().with_erasure_gate(gate);
        verified.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();
        let snapshot = super::snapshot(
            &mut reads,
            timeline,
            &mut projected,
            SNAPSHOT_DIGEST,
            &evaluation,
        )
        .test_ok();
        assert_eq!(count_in_snapshot(&snapshot, &entity), 2);
        super::verify_snapshot_consistency(
            &mut reads,
            &snapshot,
            &mut verified,
            SNAPSHOT_DIGEST,
            &evaluation,
        )
        .test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_passes_on_fresh_store() {
        // No tail events: snapshot IS the full replay.
        let mut store = open_test_store();
        let tl = store.create_timeline("consistent").test_ok();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).test_ok();

        let mut reg = make_registry();
        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).test_ok();

        let mut verify_reg = make_registry();
        verify_snapshot_consistency_from_store(
            store.as_ref(),
            &snap,
            &mut verify_reg,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        )
        .test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_with_tail_events() {
        // Take a snapshot, then append more events. Verification should still pass.
        let mut store = open_test_store();
        let tl = store.create_timeline("with-tail").test_ok();
        let entity = EntityId::new();

        // Initial 3 events -> snapshot
        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).test_ok();
        let mut reg = make_registry();
        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).test_ok();

        // Append 2 more events after the snapshot.
        let tail: Vec<EventDraft> = (0..2).map(|_| draft(entity)).collect();
        store.append(tl.id(), &tail).test_ok();

        // Consistency should hold: snapshot(3) + tail(2) == full replay(5).
        let mut verify_reg = make_registry();
        verify_snapshot_consistency_from_store(
            store.as_ref(),
            &snap,
            &mut verify_reg,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        )
        .test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_isolates_multiple_reducers() {
        // Register two reducers — their states should be tracked independently.
        let mut store = open_test_store();
        let tl = store.create_timeline("multi-reducer").test_ok();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..5).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).test_ok();

        let mut reg = make_registry();
        reg.register("count", Box::new(CountReducer));
        reg.register("entity_state", Box::new(EntityStateProjection));

        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).test_ok();

        // "count" reducer sees n=5.
        assert_eq!(count_in_snapshot(&snap, &entity), 5);
        // "entity_state" reducer also tracks independently.
        let ec = snap
            .registry
            .get("entity_state")
            .and_then(|r| r.get(&entity))
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(ec, 5, "entity_state should count 5 events independently");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_read_err_propagates() {
        let store = ReadFailStore;
        let mut reg = make_registry();
        let err = snapshot(&store, TimelineId::new(), &mut reg).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod extra_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected snapshot fixture error: {error:?}"
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
                    "unexpected successful snapshot fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    use super::*;
    use pos_core::{
        clock::WallTime,
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId},
        store::EventStore,
        ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
        ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureContainmentGateV1,
        ErasureKeyRoleV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, Reducer,
        RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, State,
    };
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};
    use std::sync::Arc;

    const SNAPSHOT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([41; 32]);

    fn snapshot_evaluation(state: ArtifactStateV1) -> ReplayClaimEvaluationV1 {
        ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[ArtifactClaimInputV1 {
                registration: RegisteredArtifactV1::new(
                    ErasureArtifactClassV1::ForkOrSnapshot,
                    SNAPSHOT_DIGEST,
                    ArtifactDataClassV1::PrivateSubjectData,
                    Some(ErasureKeyRoleV1::DataEncryption),
                    ErasureReferenceV1::from_digest([42; 32]),
                    ArtifactOptionalityV1::Required,
                    ArtifactTransitionRuleV1::Remove,
                ),
                current_claim: ErasureReplayClaimV1::Exact,
                state,
            }],
        )
        .test_ok()
    }

    fn snapshot(
        store: &dyn EventStore,
        timeline: TimelineId,
        registry: &mut ProjectionRegistry,
    ) -> Result<Snapshot, CoreError> {
        snapshot_from_store(
            store,
            timeline,
            registry,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        )
    }

    struct ReadFailStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl pos_core::store::EventStore for ReadFailStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("read failed".to_owned()))
        }

        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }

    /// Fails only on `SeqRange::all()` reads (second read in verify).
    struct ReadFailOnAllEventsStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl pos_core::store::EventStore for ReadFailOnAllEventsStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn read(&self, _: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if range.from == Seq::ZERO && range.to.is_none() {
                return Err(CoreError::Storage("all-events read failed".to_owned()));
            }
            Ok(vec![])
        }

        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            State::new()
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
        EventDraft::new(entity, Kind::new("t"), CanonicalBytes::from_vec(vec![]))
    }

    fn open_test_store() -> Box<dyn EventStore> {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()))
            .test_ok();
        store
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_detects_corrupted_snapshot() {
        // Covers the case where snapshot.registry has been tampered with.
        // Build a valid snapshot via normal snapshot(), then manually corrupt
        // the registry map before verifying.
        let mut store = open_test_store();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();

        store.append(tl.id(), &[draft(entity)]).test_ok();
        let mut reg = make_registry();
        let mut snap = snapshot(store.as_ref(), tl.id(), &mut reg).test_ok();

        // Corrupt the snapshot by injecting a bogus extra count for the entity.
        if let Some(count_reg) = snap.registry.get_mut("count") {
            count_reg.apply(
                &CountReducer,
                &Event {
                    id: EventId::new(),
                    entity,
                    event_type: Kind::new("corrupt"),
                    payload: CanonicalBytes::from_vec(vec![]),
                    wall_time: WallTime::from_micros(0),
                    seq: pos_core::clock::Seq::from_u64(999),
                    causation_id: None,
                    correlation_id: None,
                    schema_version: SchemaVersion::V1,
                    signature: None,
                    signature_identity: None,
                    payload_hash: Hash::from_bytes([0u8; 32]),
                },
            );
        }

        // Now the snapshot registry state (2 events) differs from a full replay (1 event).
        // verify_snapshot_consistency must detect the inconsistency.
        let mut verify_reg = make_registry();
        let result = verify_snapshot_consistency_from_store(
            store.as_ref(),
            &snap,
            &mut verify_reg,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        );
        assert!(
            result.is_err(),
            "corrupted snapshot should fail consistency check"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_read_err_propagates() {
        let store = ReadFailStore;
        let snap = Snapshot {
            timeline: TimelineId::new(),
            at_seq: Seq::ZERO,
            registry: HashMap::new(),
        };
        let mut reg = make_registry();
        let err = verify_snapshot_consistency_from_store(
            &store,
            &snap,
            &mut reg,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        )
        .test_err();
        assert!(matches!(err, SnapshotError::Store(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_all_events_read_err_propagates() {
        let store = ReadFailOnAllEventsStore;
        let snap = Snapshot {
            timeline: TimelineId::new(),
            at_seq: Seq::ZERO,
            registry: HashMap::new(),
        };
        let mut reg = make_registry();
        let err = verify_snapshot_consistency_from_store(
            &store,
            &snap,
            &mut reg,
            SNAPSHOT_DIGEST,
            &snapshot_evaluation(ArtifactStateV1::Retained),
        )
        .test_err();
        assert!(matches!(err, SnapshotError::Store(_)));
    }
}
