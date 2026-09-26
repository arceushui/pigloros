//! Replay events from an `EventStore` through a `ProjectionRegistry`.
//!
//! Replay is projection-only. It has no `PluginRegistry` or action-approval
//! authority, so replay cannot submit new human actions.

use pos_core::store::{EventReadBounds, SeqRange};
use pos_core::{CoreError, ErasureProtectedOperationV1, Seq, TimelineId};
use pos_runtime::ErasureReadSenderV1;
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
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<Vec<pos_core::Event>, CoreError> {
    replay_range(
        sender,
        timeline,
        SeqRange::all(),
        registry,
        artifact_digest,
        evaluation,
    )
}

/// Replay events up to and **including** `at_seq` on `timeline`.
///
/// Reads [`SeqRange::bounded`](`Seq::ZERO`, `at_seq`) and folds through `registry`.
///
/// # Errors
/// Returns [`CoreError::ArtifactUnavailable`] when the Timeline Replay is no
/// longer authoritative; otherwise propagates [`CoreError`] from the store.
pub fn replay_at(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    at_seq: Seq,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<(), CoreError> {
    replay_range(
        sender,
        timeline,
        SeqRange::bounded(Seq::ZERO, at_seq),
        registry,
        artifact_digest,
        evaluation,
    )
    .map(|_| ())
}

fn replay_range(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    range: SeqRange,
    registry: &mut ProjectionRegistry,
    artifact_digest: pos_core::ErasureReferenceV1,
    evaluation: &pos_core::ReplayClaimEvaluationV1,
) -> Result<Vec<pos_core::Event>, CoreError> {
    let mut outcome = Err(CoreError::ArtifactUnavailable);
    let mut effect = |sender: &mut ErasureReadSenderV1<'_>| {
        outcome = evaluation
            .require_authoritative_use(
                pos_core::ErasureArtifactClassV1::TimelineReplay,
                artifact_digest,
            )
            .map_err(|_| CoreError::ArtifactUnavailable)
            .and_then(|()| {
                sender
                    .read_bounded(
                        timeline,
                        range,
                        EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
                    )
                    .map_err(crate::host_error_to_core)
            })
            .inspect(|events| registry.fold_events(events));
    };
    sender
        .with_protected_effect_fence(timeline, ErasureProtectedOperationV1::Read, &mut effect)
        .map_err(crate::host_error_to_core)?;
    outcome
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
        CoreError, ErasureContainmentGateV1, Event, Reducer, State,
    };
    use pos_plugin_world::{
        encode_actuator_pair_v1, ActionKindV1, Body, SimpleKinematicBackend, WorldActionV1,
        WorldConfigV1, WorldDriver, WorldObservationV1, WorldReducer, ACTION_SCOPE_SINGLE_BODY,
        COORD_CONVENTION_RIGHT_HANDED_Y_UP, EVENT_TYPE_ACTION_V1, EVENT_TYPE_OBSERVATION_V1,
        SENSOR_MIN_RESOLUTION_MM,
    };
    use pos_runtime::{Driver, ObservationView};
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};
    use proptest::prelude::*;
    use std::sync::Arc;

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
        replay_from_store(
            store,
            timeline,
            registry,
            REPLAY_DIGEST,
            &replay_evaluation(pos_core::ArtifactStateV1::Retained),
        )
    }

    fn replay_from_store(
        store: &dyn EventStore,
        timeline: TimelineId,
        registry: &mut ProjectionRegistry,
        artifact_digest: pos_core::ErasureReferenceV1,
        evaluation: &pos_core::ReplayClaimEvaluationV1,
    ) -> Result<Vec<Event>, CoreError> {
        evaluation
            .require_authoritative_use(
                pos_core::ErasureArtifactClassV1::TimelineReplay,
                artifact_digest,
            )
            .map_err(|_| CoreError::ArtifactUnavailable)
            .and_then(|()| store.read(timeline, SeqRange::all()))
            .inspect(|events| registry.fold_events(events))
    }

    fn open_test_store() -> Box<dyn EventStore> {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
            .test_ok();
        store
    }

    fn replay_at(
        store: &dyn EventStore,
        timeline: TimelineId,
        at_seq: Seq,
        registry: &mut ProjectionRegistry,
    ) -> Result<(), CoreError> {
        replay_evaluation(pos_core::ArtifactStateV1::Retained)
            .require_authoritative_use(
                pos_core::ErasureArtifactClassV1::TimelineReplay,
                REPLAY_DIGEST,
            )
            .map_err(|_| CoreError::ArtifactUnavailable)
            .and_then(|()| store.read(timeline, SeqRange::bounded(Seq::ZERO, at_seq)))
            .map(|events| registry.fold_events(&events))
    }

    #[test]
    fn erased_timeline_cannot_be_replayed_as_authoritative_input() {
        let mut registry = ProjectionRegistry::new();
        let result = replay_from_store(
            &ReadFailStore,
            TimelineId::new(),
            &mut registry,
            REPLAY_DIGEST,
            &replay_evaluation(pos_core::ArtifactStateV1::Erased),
        );
        match result {
            Err(CoreError::ArtifactUnavailable) => {}
            other => std::panic::resume_unwind(Box::new(format!(
                "expected unavailable replay, got {other:?}"
            ))),
        }
    }

    #[test]
    fn public_replay_commands_hold_the_host_generation_fence() {
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let (timeline, entity, third_seq) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("hosted-replay").test_ok();
            let entity = EntityId::new();
            let events = commands
                .append(
                    timeline.id(),
                    &[draft(entity), draft(entity), draft(entity)],
                )
                .test_ok();
            (timeline.id(), entity, events[2].seq)
        };

        let mut complete = ProjectionRegistry::new().with_erasure_gate(gate.clone());
        complete.register("count", Box::new(CountReducer));
        let mut partial = ProjectionRegistry::new().with_erasure_gate(gate);
        partial.register("count", Box::new(CountReducer));
        let evaluation = replay_evaluation(pos_core::ArtifactStateV1::Retained);
        let mut reads = host.read_sender().test_ok();
        assert_eq!(
            super::replay(
                &mut reads,
                timeline,
                &mut complete,
                REPLAY_DIGEST,
                &evaluation,
            )
            .test_ok()
            .len(),
            3
        );
        super::replay_at(
            &mut reads,
            timeline,
            third_seq,
            &mut partial,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        assert_eq!(count_for(&complete, &entity), 3);
        assert_eq!(count_for(&partial, &entity), 3);
    }

    fn committed_world_step() -> (
        pos_runtime::ErasureExecutionHostV1,
        TimelineId,
        [EntityId; 2],
        Event,
        Vec<Event>,
    ) {
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let mut bodies = [EntityId::new(), EntityId::new()];
        bodies.sort_unstable();
        let config = WorldConfigV1 {
            timestep_micros: 1_000_000,
            coord_convention: COORD_CONVENTION_RIGHT_HANDED_Y_UP,
            gravity_x: 0.0,
            gravity_y: -9.81,
            gravity_z: 0.0,
            backend_id: "simple-kinematic".to_owned(),
            backend_version: "1.0.0".to_owned(),
            backend_content_hash: [3; 32],
            action_schema_version: 1,
            observation_schema_version: 1,
            sensor_min_resolution_mm: SENSOR_MIN_RESOLUTION_MM,
            actuator_catalogue_version: 1,
        };
        let mut driver = WorldDriver::new(
            vec![
                Body {
                    entity_id: bodies[1],
                    x: 10.0,
                    y: 0.0,
                    z: 0.0,
                    vx: 0.0,
                    vy: 0.0,
                    vz: 0.0,
                },
                Body {
                    entity_id: bodies[0],
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    vx: 0.0,
                    vy: 0.0,
                    vz: 0.0,
                },
            ],
            Box::new(SimpleKinematicBackend::new()),
            config,
        );
        let action = WorldActionV1 {
            actor_entity_id: bodies[0],
            body_entity_id: bodies[0],
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: encode_actuator_pair_v1(1.0, 2.0).test_ok(),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let (timeline, action, committed) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("world-live-replay").test_ok().id();
            let action = commands
                .append(
                    timeline,
                    &[EventDraft::new(
                        bodies[0],
                        Kind::new(EVENT_TYPE_ACTION_V1),
                        action.encode().test_ok(),
                    )],
                )
                .test_ok()
                .remove(0);
            let output = driver
                .step(
                    timeline,
                    ObservationView::from_events(std::slice::from_ref(&action)),
                )
                .test_ok();
            let committed = commands.append(timeline, &output.drafts).test_ok();
            (timeline, action, committed)
        };
        drop(driver);
        (host, timeline, bodies, action, committed)
    }

    fn world_registry(gate: Arc<ErasureContainmentGateV1>) -> ProjectionRegistry {
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("world", Box::new(WorldReducer));
        registry
    }

    #[test]
    fn world_live_observations_replay_without_backend_at_exact_seq_boundaries() {
        let (mut host, timeline, bodies, action, committed) = committed_world_step();
        let gate = host.containment_gate();

        let observations: Vec<_> = committed
            .iter()
            .filter(|event| event.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .collect();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].entity, bodies[0]);
        assert_eq!(observations[1].entity, bodies[1]);
        assert!(observations[0].seq < observations[1].seq);
        assert_eq!(observations[0].causation_id, Some(action.id));
        let observed = WorldObservationV1::decode(&observations[0].payload).test_ok();
        assert_eq!(
            (observed.pos_x, observed.pos_y, observed.pos_z),
            (1.0, 0.0, 2.0)
        );
        assert_eq!(
            (observed.vel_lin_x, observed.vel_lin_y, observed.vel_lin_z),
            (1.0, 0.0, 2.0)
        );

        let mut live = world_registry(gate.clone());
        live.apply_event(&action);
        live.fold_events(&committed);
        let expected: Vec<_> = bodies
            .iter()
            .map(|body| live.state_for_reducer("world", body).test_ok().clone())
            .collect();

        let evaluation = replay_evaluation(pos_core::ArtifactStateV1::Retained);
        let mut before = world_registry(gate.clone());
        let mut first = world_registry(gate.clone());
        let mut complete = world_registry(gate.clone());
        let mut reads = host.read_sender().test_ok();
        super::replay_at(
            &mut reads,
            timeline,
            action.seq,
            &mut before,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        assert!(before.state_for_reducer("world", &bodies[0]).is_none());
        assert!(before.state_for_reducer("world", &bodies[1]).is_none());
        super::replay_at(
            &mut reads,
            timeline,
            observations[0].seq,
            &mut first,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        assert_eq!(
            first.state_for_reducer("world", &bodies[0]),
            Some(&expected[0])
        );
        assert!(first.state_for_reducer("world", &bodies[1]).is_none());
        super::replay(
            &mut reads,
            timeline,
            &mut complete,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        for (body, state) in bodies.iter().zip(&expected) {
            assert_eq!(complete.state_for_reducer("world", body), Some(state));
        }

        let telemetry = EventDraft::new(
            bodies[0],
            Kind::new("world.telemetry.ephemeral"),
            CanonicalBytes::from_static(b"discardable"),
        );
        host.command_sender()
            .test_ok()
            .append(timeline, &[telemetry])
            .test_ok();
        let mut with_telemetry = world_registry(gate);
        super::replay(
            &mut host.read_sender().test_ok(),
            timeline,
            &mut with_telemetry,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        for (body, state) in bodies.iter().zip(&expected) {
            assert_eq!(with_telemetry.state_for_reducer("world", body), Some(state));
        }
    }

    #[test]
    fn world_replay_does_not_materialize_invalid_or_disposable_entities() {
        let (mut host, timeline, bodies, action, committed) = committed_world_step();
        let gate = host.containment_gate();
        let canonical = committed
            .iter()
            .find(|event| event.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .test_ok();
        let last_observation_seq = committed.last().test_ok().seq;
        let mut noncanonical_bytes = canonical.payload.as_slice().to_vec();
        noncanonical_bytes.push(0);
        let invalid = [
            EventDraft::new(
                EntityId::new(),
                Kind::new(EVENT_TYPE_ACTION_V1),
                action.payload,
            ),
            EventDraft::new(
                EntityId::new(),
                Kind::new(EVENT_TYPE_OBSERVATION_V1),
                CanonicalBytes::from_static(b"malformed"),
            ),
            EventDraft::new(
                EntityId::new(),
                Kind::new(EVENT_TYPE_OBSERVATION_V1),
                CanonicalBytes::from_vec(noncanonical_bytes),
            ),
            EventDraft::new(
                EntityId::new(),
                Kind::new("world.observation"),
                canonical.payload.clone(),
            ),
            EventDraft::new(
                EntityId::new(),
                Kind::new(EVENT_TYPE_OBSERVATION_V1),
                canonical.payload.clone(),
            ),
            EventDraft::new(
                EntityId::new(),
                Kind::new("world.telemetry.ephemeral"),
                CanonicalBytes::from_static(b"discardable"),
            ),
        ];
        let invalid_entities: Vec<_> = invalid.iter().map(|draft| draft.entity).collect();
        host.command_sender()
            .test_ok()
            .append(timeline, &invalid)
            .test_ok();

        let evaluation = replay_evaluation(pos_core::ArtifactStateV1::Retained);
        let mut accepted = world_registry(gate.clone());
        let mut after_invalid = world_registry(gate);
        let mut reads = host.read_sender().test_ok();
        super::replay_at(
            &mut reads,
            timeline,
            last_observation_seq,
            &mut accepted,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        super::replay(
            &mut reads,
            timeline,
            &mut after_invalid,
            REPLAY_DIGEST,
            &evaluation,
        )
        .test_ok();
        for body in bodies {
            assert_eq!(
                after_invalid.state_for_reducer("world", &body),
                accepted.state_for_reducer("world", &body)
            );
        }
        for entity in invalid_entities {
            assert!(after_invalid.state_for_reducer("world", &entity).is_none());
        }
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
        let mut store = open_test_store();
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
        let mut store = open_test_store();
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
        let mut store = open_test_store();
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
        let entity = EntityId::new();
        reg.apply_event(&make_event(entity, 1));
        let err = replay(&store, TimelineId::new(), &mut reg).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert_eq!(count_for(&reg, &entity), 1);
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
            let mut store = open_test_store();
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
