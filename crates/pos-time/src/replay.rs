//! Replay events from an `EventStore` through a `ProjectionRegistry`.
//!
//! Replay is projection-only. It has no `PluginRegistry` or action-approval
//! authority, so replay cannot submit new human actions.

use pos_core::store::SeqRange;
use pos_core::{CoreError, ErasureProtectedOperationV1, Seq, TimelineId, WorldReplayClosureV1};
use pos_runtime::{ErasureReadSenderV1, WorldReplayUseV1};
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
    closure: &WorldReplayClosureV1,
) -> Result<Vec<pos_core::Event>, CoreError> {
    replay_range(sender, timeline, SeqRange::all(), registry, closure)
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
    closure: &WorldReplayClosureV1,
) -> Result<(), CoreError> {
    replay_range(
        sender,
        timeline,
        SeqRange::bounded(Seq::ZERO, at_seq),
        registry,
        closure,
    )
    .map(|_| ())
}

fn replay_range(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    range: SeqRange,
    registry: &mut ProjectionRegistry,
    closure: &WorldReplayClosureV1,
) -> Result<Vec<pos_core::Event>, CoreError> {
    let requested_use = WorldReplayUseV1::new(
        timeline,
        ErasureProtectedOperationV1::Read,
        range,
        registry
            .reducer_names()
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
    .map_err(|_| CoreError::ArtifactUnavailable)?;
    let mut outcome = Err(CoreError::ArtifactUnavailable);
    let mut effect = |sender: &mut ErasureReadSenderV1<'_>| {
        outcome = registry.try_with_state_transaction(|candidate| {
            let read_bounds = crate::require_world_replay(sender, closure, &requested_use)?;
            let events = crate::read_complete_world_replay(sender, timeline, range, read_bounds)?;
            candidate.fold_events(&events);
            let final_bounds = crate::require_world_replay(sender, closure, &requested_use)?;
            if final_bounds != read_bounds {
                return Err(CoreError::ArtifactUnavailable);
            }
            Ok(events)
        });
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
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};
    use proptest::prelude::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const REPLAY_DIGEST: pos_core::ErasureReferenceV1 =
        pos_core::ErasureReferenceV1::from_digest([43; 32]);
    const ONE_EVENT_READ_BOUNDS: pos_core::store::EventReadBounds =
        pos_core::store::EventReadBounds::new_with_total_bytes_and_elapsed(
            65_536, 128, 8, 1, 65_536, 30_000_000,
        );

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
    fn public_replay_commands_fail_closed_without_installed_world_verifier() {
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let timeline = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("hosted-replay").test_ok();
            let entity = EntityId::new();
            commands
                .append(
                    timeline.id(),
                    &[draft(entity), draft(entity), draft(entity)],
                )
                .test_ok();
            timeline.id()
        };

        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();
        let closure = pos_core::WorldReplayClosureV1::test_fixture().test_ok();
        assert!(matches!(
            super::replay(&mut reads, timeline, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_replay_commands_use_an_installed_world_verifier() {
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("verified-replay").test_ok();
            let entity = EntityId::new();
            commands
                .append(
                    timeline.id(),
                    &[draft(entity), draft(entity), draft(entity)],
                )
                .test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&host, timeline);
        let mut registry = ProjectionRegistry::new().with_erasure_gate(Arc::clone(&gate));
        registry.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();
        let events = super::replay(&mut reads, timeline, &mut registry, &closure).test_ok();
        assert_eq!(events.len(), 3);
        assert_eq!(count_for(&registry, &entity), 3);

        let mut bounded_registry = ProjectionRegistry::new().with_erasure_gate(gate);
        bounded_registry.register("count", Box::new(CountReducer));
        super::replay_at(
            &mut reads,
            timeline,
            events[1].seq,
            &mut bounded_registry,
            &closure,
        )
        .test_ok();
        assert_eq!(count_for(&bounded_registry, &entity), 2);
    }

    #[test]
    fn public_replay_rejects_cross_timeline_closures() {
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let (authorized, requested) = {
            let mut commands = host.command_sender().test_ok();
            let authorized = commands.create_timeline("authorized-replay").test_ok();
            let requested = commands.create_timeline("requested-replay").test_ok();
            commands
                .append(requested.id(), &[draft(EntityId::new())])
                .test_ok();
            (authorized.id(), requested.id())
        };
        let closure = crate::test_support::closure_for_host(&host, authorized);
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            super::replay(&mut reads, requested, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    #[test]
    fn public_replay_rolls_back_when_final_verification_fails() {
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(ChangeBoundsOnSecondVerification {
                calls: AtomicUsize::new(0),
            }));
        let mut host = pos_runtime::ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("rollback-replay").test_ok();
            let entity = EntityId::new();
            commands.append(timeline.id(), &[draft(entity)]).test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&host, timeline);
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            super::replay(&mut reads, timeline, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(registry.state_for_reducer("count", &entity), None);
    }

    #[test]
    fn public_replay_enforces_verified_read_bounds() {
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(OneEventWorldReplayVerifier));
        let mut host = pos_runtime::ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("bounded-replay").test_ok();
            let entity = EntityId::new();
            commands
                .append(timeline.id(), &[draft(entity), draft(entity)])
                .test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&host, timeline);
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("count", Box::new(CountReducer));
        let mut reads = host.read_sender().test_ok();

        let replay_result = super::replay(&mut reads, timeline, &mut registry, &closure);
        assert!(
            matches!(&replay_result, Err(CoreError::ArtifactUnavailable)),
            "expected an over-bound Replay to fail closed, got {replay_result:?}"
        );
        assert_eq!(registry.state_for_reducer("count", &entity), None);
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

    struct ChangeBoundsOnSecondVerification {
        calls: AtomicUsize,
    }

    struct OneEventWorldReplayVerifier;

    impl pos_runtime::WorldReplayVerifierV1 for OneEventWorldReplayVerifier {
        fn verify(
            &self,
            closure: &pos_core::WorldReplayClosureV1,
            requested_use: &pos_runtime::WorldReplayUseV1,
            inventory_generation: pos_core::ErasureReferenceV1,
        ) -> Result<pos_runtime::VerifiedWorldReplayV1, pos_runtime::WorldReplayVerificationErrorV1>
        {
            Ok(
                pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
                    closure.digest(),
                    closure.timeline_id(),
                    closure.source_head(),
                    requested_use.clone(),
                    inventory_generation,
                    pos_core::ErasureReplayClaimV1::Exact,
                    ONE_EVENT_READ_BOUNDS,
                ),
            )
        }
    }

    impl pos_runtime::WorldReplayVerifierV1 for ChangeBoundsOnSecondVerification {
        fn verify(
            &self,
            closure: &pos_core::WorldReplayClosureV1,
            requested_use: &pos_runtime::WorldReplayUseV1,
            inventory_generation: pos_core::ErasureReferenceV1,
        ) -> Result<pos_runtime::VerifiedWorldReplayV1, pos_runtime::WorldReplayVerificationErrorV1>
        {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(pos_runtime::world_replay::test_verified_world_replay(
                    closure,
                    requested_use,
                    inventory_generation,
                    pos_core::ErasureReplayClaimV1::Exact,
                ))
            } else {
                Ok(
                    pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
                        closure.digest(),
                        closure.timeline_id(),
                        closure.source_head(),
                        requested_use.clone(),
                        inventory_generation,
                        pos_core::ErasureReplayClaimV1::Exact,
                        ONE_EVENT_READ_BOUNDS,
                    ),
                )
            }
        }
    }

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
