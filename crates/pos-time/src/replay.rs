//! Replay events from an `EventStore` through a `ProjectionRegistry`.
//!
//! Replay is projection-only. It has no `PluginRegistry` or action-approval
//! authority, so replay cannot submit new human actions.

use pos_core::store::{EventStore, SeqRange};
use pos_core::{CoreError, Seq, TimelineId};
use pos_state::ProjectionRegistry;

/// Replay **all** events on `timeline` through every reducer in `registry`.
///
/// Events are read with [`SeqRange::all`] and then folded via
/// [`ProjectionRegistry::fold_events`]. An empty timeline is a no-op.
///
/// Returns the events that were replayed so callers do not need a second read.
///
/// # Errors
/// Returns [`CoreError::ArtifactUnavailable`] when the Timeline Replay is no
/// longer authoritative; otherwise propagates [`CoreError`] from the store.
pub fn replay(
    store: &dyn EventStore,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<Vec<pos_core::Event>, CoreError> {
    evaluation
        .require_authoritative_use(
            pos_core::ErasureArtifactClassV1::TimelineReplay,
            artifact_digest,
        )
        .map_err(|_| CoreError::ArtifactUnavailable)
        .and_then(|()| store.read(timeline, SeqRange::all()))
        .inspect(|events| {
            registry.fold_events(events);
        })
}

/// Replay events up to and **including** `at_seq` on `timeline`.
///
/// Reads [`SeqRange::bounded`](`Seq::ZERO`, `at_seq`) and folds through `registry`.
///
/// # Errors
/// Returns [`CoreError::ArtifactUnavailable`] when the Timeline Replay is no
/// longer authoritative; otherwise propagates [`CoreError`] from the store.
pub fn replay_at(
    store: &dyn EventStore,
    timeline: TimelineId,
    at_seq: Seq,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<(), CoreError> {
    evaluation
        .require_authoritative_use(
            pos_core::ErasureArtifactClassV1::TimelineReplay,
            artifact_digest,
        )
        .map_err(|_| CoreError::ArtifactUnavailable)
        .and_then(|()| store.read(timeline, SeqRange::bounded(Seq::ZERO, at_seq)))
        .map(|events| registry.fold_events(&events))
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
                    "unexpected replay fixture error: {error:?}"
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
                    "unexpected successful replay fixture value: {value:?}"
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
        ids::{EntityId, EventId, TimelineId},
        store::{EventStore, SeqRange},
        CoreError, Event, Reducer, State,
    };
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};
    use proptest::prelude::*;

    const REPLAY_DIGEST: pos_core::ErasureReferenceV1 =
        pos_core::ErasureReferenceV1::from_digest([43; 32]);

    fn replay_evaluation(state: pos_core::ArtifactStateV1) -> pos_core::ReplayClaimEvaluationV1 {
        pos_core::ReplayClaimEvaluatorV1::evaluate(
            pos_core::ErasureReplayClaimV1::Exact,
            &[pos_core::ArtifactClaimInputV1 {
                registration: pos_core::RegisteredArtifactV1::new(
                    pos_core::ErasureArtifactClassV1::TimelineReplay,
                    REPLAY_DIGEST,
                    pos_core::ArtifactDataClassV1::PrivateSubjectData,
                    None,
                    pos_core::ErasureReferenceV1::from_digest([44; 32]),
                    pos_core::ArtifactOptionalityV1::Required,
                    pos_core::ArtifactTransitionRuleV1::Remove,
                ),
                current_claim: pos_core::ErasureReplayClaimV1::Exact,
                state,
            }],
        )
        .test_ok()
    }

    fn replay(
        store: &dyn EventStore,
        timeline: TimelineId,
        registry: &mut ProjectionRegistry,
    ) -> Result<Vec<Event>, CoreError> {
        super::replay(
            store,
            timeline,
            registry,
            REPLAY_DIGEST,
            &replay_evaluation(pos_core::ArtifactStateV1::Retained),
        )
    }

    fn replay_at(
        store: &dyn EventStore,
        timeline: TimelineId,
        at_seq: Seq,
        registry: &mut ProjectionRegistry,
    ) -> Result<(), CoreError> {
        super::replay_at(
            store,
            timeline,
            at_seq,
            registry,
            REPLAY_DIGEST,
            &replay_evaluation(pos_core::ArtifactStateV1::Retained),
        )
    }

    #[test]
    fn erased_timeline_cannot_be_replayed_as_authoritative_input() {
        let mut registry = ProjectionRegistry::new();
        assert!(matches!(
            super::replay(
                &ReadFailStore,
                TimelineId::new(),
                &mut registry,
                REPLAY_DIGEST,
                &replay_evaluation(pos_core::ArtifactStateV1::Erased),
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    struct ReadFailStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl EventStore for ReadFailStore {
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

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.tick"),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    fn make_event(entity: EntityId, seq: u64) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn count_for(reg: &ProjectionRegistry, entity: &EntityId) -> u64 {
        reg.state_for(entity)
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_empty_timeline_is_noop() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("empty").test_ok();
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));

        replay(store.as_ref(), tl.id(), &mut reg).test_ok();

        // No entities seen — state_for returns None (count is zero).
        let entity = EntityId::new();
        assert_eq!(count_for(&reg, &entity), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_full_timeline_folds_all_events() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("full").test_ok();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..5).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).test_ok();

        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        replay(store.as_ref(), tl.id(), &mut reg).test_ok();

        assert_eq!(count_for(&reg, &entity), 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_at_seq_stops_at_boundary() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("partial").test_ok();
        let entity = EntityId::new();

        // Append 6 events; we only want to replay the first 3.
        let drafts: Vec<EventDraft> = (0..6).map(|_| draft(entity)).collect();
        let committed = store.append(tl.id(), &drafts).test_ok();
        // seq of the 3rd event (0-indexed = 2, but seqs are 1-based in MemoryStore)
        let third_seq = committed[2].seq;

        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        replay_at(store.as_ref(), tl.id(), third_seq, &mut reg).test_ok();

        assert_eq!(count_for(&reg, &entity), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_read_err_propagates() {
        let store = ReadFailStore;
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        let err = replay(&store, TimelineId::new(), &mut reg).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_at_read_err_propagates() {
        let store = ReadFailStore;
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        let err = replay_at(&store, TimelineId::new(), Seq::from_u64(1), &mut reg).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    proptest! {
        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn replay_is_deterministic(event_count in 0usize..20) {
            let mut store = open_store(StoreConfig::Memory).test_ok();
            let tl = store.create_timeline("det").test_ok();
            let entity = EntityId::new();

            // Pre-populate with events built directly so we don't need mut store later.
            let events: Vec<Event> = (0..event_count)
                .map(|i| make_event(entity, (i + 1) as u64))
                .collect();

            // We build a registry using the raw events directly (avoids store borrow issues).
            let mut reg1 = ProjectionRegistry::new();
            reg1.register("count", Box::new(CountReducer));
            reg1.fold_events(&events);

            let mut reg2 = ProjectionRegistry::new();
            reg2.register("count", Box::new(CountReducer));
            reg2.fold_events(&events);

            let c1 = count_for(&reg1, &entity);
            let c2 = count_for(&reg2, &entity);
            prop_assert_eq!(c1, c2);
            prop_assert_eq!(c1, event_count as u64);

            // Also exercise the store-based replay path.
            let drafts: Vec<EventDraft> = (0..event_count).map(|_| draft(entity)).collect();
            if !drafts.is_empty() {
                store.append(tl.id(), &drafts).test_ok();
            }
            let mut reg3 = ProjectionRegistry::new();
            reg3.register("count", Box::new(CountReducer));
            replay(store.as_ref(), tl.id(), &mut reg3).test_ok();
            prop_assert_eq!(count_for(&reg3, &entity), event_count as u64);
        }
    }
}
