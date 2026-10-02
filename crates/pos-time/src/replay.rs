//! Protected Replay: install Projection State folded on the staged executor.
//!
//! Replay is projection-only. It has no `PluginRegistry` or action-approval
//! authority, so replay cannot submit new human actions. It returns no
//! Events (ADR-113 §8).

use pos_core::store::SeqRange;
use pos_core::trusted_clock::{ApplicableExpiriesV1, ReleaseGuardV1};
use pos_core::{CoreError, ErasureProtectedOperationV1, Seq, TimelineId, WorldReplayClosureV1};
use pos_runtime::ErasureReadSenderV1;
use pos_state::{ProjectionRegistry, RevokedSubjectsV1};

use crate::{ProtectedFoldV1, ProtectedReleaseV1};

/// Replay **all** events on `timeline` and install the resulting State in
/// `registry`.
///
/// Inside `release`'s guard the complete range is verified and read, folded
/// on the staged executor for `fold`'s recorded consumers, re-verified, and
/// installed through ADR-112's checked handoff. An empty timeline installs
/// empty State. No Event is returned.
///
/// # Errors
/// Fails closed with [`CoreError::ArtifactUnavailable`],
/// [`CoreError::ErasureAccessFrozen`], or
/// [`CoreError::ErasureContainmentUnavailable`] when protected Replay
/// authority, complete reads, the staged fold, the install checks or the
/// handoff are unavailable. The registry is then unchanged, except that it
/// forgets the revoked subjects of a range that was read and verified.
pub fn replay(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
    closure: &WorldReplayClosureV1,
    release: ProtectedReleaseV1<'_>,
    fold: &ProtectedFoldV1<'_>,
) -> Result<(), CoreError> {
    let request = ReplayRequestV1 {
        timeline,
        range: SeqRange::all(),
        closure,
        fold,
    };
    replay_range(sender, &request, registry, release)
}

/// Replay events up to and **including** `at_seq` on `timeline` and install
/// the resulting State in `registry`, as [`replay`] does.
///
/// # Errors
/// Fails closed as [`replay`] does.
pub fn replay_at(
    sender: &mut ErasureReadSenderV1<'_>,
    timeline: TimelineId,
    at_seq: Seq,
    registry: &mut ProjectionRegistry,
    closure: &WorldReplayClosureV1,
    release: ProtectedReleaseV1<'_>,
    fold: &ProtectedFoldV1<'_>,
) -> Result<(), CoreError> {
    let request = ReplayRequestV1 {
        timeline,
        range: SeqRange::bounded(Seq::ZERO, at_seq),
        closure,
        fold,
    };
    replay_range(sender, &request, registry, release)
}

/// One protected Replay request.
struct ReplayRequestV1<'r> {
    timeline: TimelineId,
    range: SeqRange,
    closure: &'r WorldReplayClosureV1,
    fold: &'r ProtectedFoldV1<'r>,
}

fn replay_range(
    sender: &mut ErasureReadSenderV1<'_>,
    request: &ReplayRequestV1<'_>,
    registry: &mut ProjectionRegistry,
    release: ProtectedReleaseV1<'_>,
) -> Result<(), CoreError> {
    pos_runtime::require_staged_release().map_err(crate::unavailable)?;
    let consumer_ids = crate::consumer_selection(registry)?;
    let ProtectedReleaseV1 { guard, expiries } = release;
    let mut guard = Some(guard);
    let mut revoked = None;
    let mut outcome = Err(CoreError::ArtifactUnavailable);
    let mut effect = |sender: &mut ErasureReadSenderV1<'_>| {
        if let Some(guard) = guard.take() {
            let target = ReplayTargetV1 {
                registry: &mut *registry,
                guard,
                expiries: &expiries,
                revoked: &mut revoked,
            };
            outcome = replay_in_fence(sender, request, &consumer_ids, target);
        }
    };
    let fenced = sender
        .with_protected_effect_fence(
            request.timeline,
            ErasureProtectedOperationV1::Read,
            &mut effect,
        )
        .map_err(crate::host_error_to_core);
    // Teardown: a guard the effect never took is rolled back and released
    // before the failure-path forget.
    drop(guard);
    crate::forget_on_failure(fenced.and(outcome), registry, revoked.as_ref())
}

/// The visible registry, the held guard and the failure-path record of one
/// Replay inside its fence.
struct ReplayTargetV1<'t, 'g> {
    registry: &'t mut ProjectionRegistry,
    guard: ReleaseGuardV1<'g>,
    expiries: &'t ApplicableExpiriesV1,
    revoked: &'t mut Option<RevokedSubjectsV1>,
}

/// Verify, read, fold, re-verify and hand one Replay over inside its fence.
fn replay_in_fence(
    sender: &mut ErasureReadSenderV1<'_>,
    request: &ReplayRequestV1<'_>,
    consumer_ids: &[String],
    target: ReplayTargetV1<'_, '_>,
) -> Result<(), CoreError> {
    let ReplayTargetV1 {
        registry,
        guard,
        expiries,
        revoked,
    } = target;
    let requested_use = crate::observed_world_replay_use(
        sender,
        request.timeline,
        ErasureProtectedOperationV1::Read,
        request.range,
        consumer_ids,
    )?;
    let read_bounds = crate::require_world_replay(sender, request.closure, &requested_use)?;
    let events = crate::read_complete_world_replay(sender, &requested_use, read_bounds)?;
    *revoked = Some(RevokedSubjectsV1::from_verified_events(&events));
    let source = crate::verified_source(request.timeline, request.closure);
    let staged = crate::fold_staged(request.fold, &guard, &events, source)?;
    let final_bounds = crate::require_world_replay(sender, request.closure, &requested_use)?;
    if final_bounds != read_bounds {
        return Err(CoreError::ArtifactUnavailable);
    }
    crate::handoff_reserve(&guard)?;
    let prepared = registry
        .prepare_install(staged)
        .map_err(crate::unavailable)?;
    // The displaced maps are dropped after the handoff returns.
    pos_runtime::handoff(guard, expiries, prepared)
        .map(drop)
        .map_err(crate::unavailable)
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

    use crate::test_support::{with_release, ProtectedFixture};
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, TimelineId},
        store::{EventReadBounds, SeqRange},
        CoreError, ErasureGate, Event, PluginId, Reducer, Seq, State, WorldReplayClosureV1,
    };
    use pos_plugin_world::{
        encode_actuator_pair_v1, ActionKindV1, Body, BodyRotationV1, WorldActionV1, WorldDriver,
        WorldObservationV1, WorldPlugin, WorldReducer, ACTION_SCOPE_SINGLE_BODY,
        EVENT_TYPE_ACTION_V1, EVENT_TYPE_CONFIG_V1, EVENT_TYPE_OBSERVATION_V1,
    };
    use pos_runtime::{
        ErasureExecutionHostV1, ErasureReadSenderV1, PluginRegistry, TimelineHistorySegment,
    };
    use pos_state::ProjectionRegistry;
    use pos_store::StoreConfig;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const ONE_EVENT_READ_BOUNDS: EventReadBounds =
        EventReadBounds::new_with_total_bytes_and_elapsed(65_536, 128, 8, 1, 65_536, 30_000_000);

    fn count_reducer() -> Box<dyn Reducer> {
        Box::new(CountReducer)
    }

    fn world_reducer() -> Box<dyn Reducer> {
        Box::new(WorldReducer)
    }

    fn count_fixture() -> ProtectedFixture {
        ProtectedFixture::new("count", count_reducer)
    }

    fn replay_with(
        fixture: &ProtectedFixture,
        reads: &mut ErasureReadSenderV1<'_>,
        timeline: TimelineId,
        registry: &mut ProjectionRegistry,
        closure: &WorldReplayClosureV1,
    ) -> Result<(), CoreError> {
        with_release(|release| {
            super::replay(reads, timeline, registry, closure, release, &fixture.fold())
        })
    }

    fn replay_at_with(
        fixture: &ProtectedFixture,
        reads: &mut ErasureReadSenderV1<'_>,
        timeline: TimelineId,
        at_seq: Seq,
        registry: &mut ProjectionRegistry,
        closure: &WorldReplayClosureV1,
    ) -> Result<(), CoreError> {
        with_release(|release| {
            super::replay_at(
                reads,
                timeline,
                at_seq,
                registry,
                closure,
                release,
                &fixture.fold(),
            )
        })
    }

    fn timeline_events(host: &mut ErasureExecutionHostV1, timeline: TimelineId) -> Vec<Event> {
        let bounds = EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX);
        let (events, _) = host
            .read_sender()
            .test_ok()
            .read_bounded_at_generation(timeline, SeqRange::all(), bounds, None)
            .test_ok();
        events
    }

    #[test]
    fn public_replay_commands_fail_closed_without_installed_world_verifier() {
        let fixture = count_fixture();
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

        let mut registry = fixture.registry(gate);
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            replay_with(&fixture, &mut reads, timeline, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    fn committed_world_step() -> (
        pos_runtime::ErasureExecutionHostV1,
        TimelineId,
        [EntityId; 2],
        Event,
        Vec<Event>,
    ) {
        let mut host = crate::test_support::open_exact_host();
        let mut bodies = [EntityId::new(), EntityId::new()];
        bodies.sort_unstable();
        let driver = WorldDriver::new_live(
            vec![
                Body {
                    entity_id: bodies[1],
                    rotation: BodyRotationV1::default(),
                    x: 10.0,
                    y: 0.0,
                    z: 0.0,
                    vx: 0.0,
                    vy: 0.0,
                    vz: 0.0,
                },
                Body {
                    entity_id: bodies[0],
                    rotation: BodyRotationV1::default(),
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    vx: 0.0,
                    vy: 0.0,
                    vz: 0.0,
                },
            ],
            pos_runtime::HostWorldProfileV1::moat_proof(),
        )
        .test_ok();
        let action = WorldActionV1 {
            actor_entity_id: bodies[0],
            body_entity_id: bodies[0],
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: encode_actuator_pair_v1(1.0, 2.0).test_ok(),
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick: 0,
        };
        let gate = host.containment_gate();
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
            let mut registry = PluginRegistry::new().with_erasure_gate(gate);
            registry
                .register_generated(
                    &WorldPlugin::new().with_bodies(bodies),
                    Some(Box::new(WorldReducer)),
                    Some(Box::new(driver)),
                )
                .test_ok();
            registry.compose_non_participant_drivers().test_ok();
            registry
                .restore_driver_state(
                    &[TimelineHistorySegment::new(timeline, action.seq)],
                    std::slice::from_ref(&action),
                )
                .test_ok();
            let drafts = registry
                .step_all_anchored_with_events(timeline, action.seq, std::slice::from_ref(&action))
                .test_ok();
            let committed = commands.append(timeline, &drafts).test_ok();
            (timeline, action, committed)
        };
        (host, timeline, bodies, action, committed)
    }

    fn world_registry(gate: Arc<dyn ErasureGate>) -> ProjectionRegistry {
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry.register("world", Box::new(WorldReducer));
        registry
    }

    fn assert_committed_world_step_shape(committed: &[Event]) {
        assert_eq!(committed.len(), 3);
        assert_eq!(
            committed
                .iter()
                .filter(|event| event.event_type.as_str() == EVENT_TYPE_CONFIG_V1)
                .count(),
            1
        );
    }

    fn assert_world_states(
        registry: &ProjectionRegistry,
        timeline: TimelineId,
        bodies: &[EntityId],
        expected: &[State],
    ) {
        for (body, state) in bodies.iter().zip(expected) {
            assert_eq!(
                registry
                    .state_for_reducer(timeline, "world", body)
                    .test_ok(),
                Some(state.clone())
            );
        }
    }

    #[test]
    fn world_live_observations_replay_without_backend_at_exact_seq_boundaries() {
        let fixture = ProtectedFixture::new("world", world_reducer);
        let (mut host, timeline, bodies, action, committed) = committed_world_step();
        let gate = host.containment_gate();

        let observations: Vec<_> = committed
            .iter()
            .filter(|event| event.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .collect();
        assert_committed_world_step_shape(&committed);
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
        live.apply_event(timeline, &action);
        live.fold_events(timeline, &committed);
        let expected: Vec<_> = bodies
            .iter()
            .map(|body| {
                live.state_for_reducer(timeline, "world", body)
                    .test_ok()
                    .test_ok()
            })
            .collect();

        let closure = crate::test_support::closure_for_host_consumer(&mut host, timeline, "world");
        let mut before = fixture.registry(gate.clone());
        let mut first = fixture.registry(gate.clone());
        let mut complete = fixture.registry(gate.clone());
        let count_only = crate::test_support::closure_for_host(&mut host, timeline);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            replay_at_with(
                &fixture,
                &mut reads,
                timeline,
                action.seq,
                &mut before,
                &count_only
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        replay_at_with(
            &fixture,
            &mut reads,
            timeline,
            action.seq,
            &mut before,
            &closure,
        )
        .test_ok();
        for body in &bodies {
            assert!(before
                .state_for_reducer(timeline, "world", body)
                .test_ok()
                .is_none());
        }
        replay_at_with(
            &fixture,
            &mut reads,
            timeline,
            observations[0].seq,
            &mut first,
            &closure,
        )
        .test_ok();
        assert_eq!(
            first
                .state_for_reducer(timeline, "world", &bodies[0])
                .test_ok(),
            Some(expected[0].clone())
        );
        assert!(first
            .state_for_reducer(timeline, "world", &bodies[1])
            .test_ok()
            .is_none());
        replay_with(&fixture, &mut reads, timeline, &mut complete, &closure).test_ok();
        assert_world_states(&complete, timeline, &bodies, &expected);

        let telemetry = EventDraft::new(
            bodies[0],
            Kind::new("world.telemetry.ephemeral"),
            CanonicalBytes::from_static(b"discardable"),
        );
        host.command_sender()
            .test_ok()
            .append(timeline, &[telemetry])
            .test_ok();
        let closure = crate::test_support::closure_for_host_consumer(&mut host, timeline, "world");
        let mut with_telemetry = fixture.registry(gate);
        replay_with(
            &fixture,
            &mut host.read_sender().test_ok(),
            timeline,
            &mut with_telemetry,
            &closure,
        )
        .test_ok();
        assert_world_states(&with_telemetry, timeline, &bodies, &expected);
    }

    #[test]
    fn world_replay_does_not_materialize_invalid_or_disposable_entities() {
        let fixture = ProtectedFixture::new("world", world_reducer);
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

        let closure = crate::test_support::closure_for_host_consumer(&mut host, timeline, "world");
        let mut accepted = fixture.registry(gate.clone());
        let mut after_invalid = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        replay_at_with(
            &fixture,
            &mut reads,
            timeline,
            last_observation_seq,
            &mut accepted,
            &closure,
        )
        .test_ok();
        replay_with(&fixture, &mut reads, timeline, &mut after_invalid, &closure).test_ok();
        for body in bodies {
            assert_eq!(
                after_invalid
                    .state_for_reducer(timeline, "world", &body)
                    .test_ok(),
                accepted
                    .state_for_reducer(timeline, "world", &body)
                    .test_ok()
            );
        }
        for entity in invalid_entities {
            assert!(after_invalid
                .state_for_reducer(timeline, "world", &entity)
                .test_ok()
                .is_none());
        }
    }

    #[test]
    fn world_replay_matches_the_timeline_without_its_disposable_telemetry() {
        const TELEMETRY: &str = "world.telemetry.ephemeral";
        fn telemetry(entity: EntityId) -> EventDraft {
            EventDraft::new(
                entity,
                Kind::new(TELEMETRY),
                CanonicalBytes::from_static(b"discardable"),
            )
        }
        let fixture = ProtectedFixture::new("world", world_reducer);
        let (mut host, _, bodies, action, committed) = committed_world_step();
        let gate = host.containment_gate();
        let timeline = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands
                .create_timeline("world-telemetry-replay")
                .test_ok()
                .id();
            let mut copied_action = None;
            for event in std::iter::once(&action).chain(&committed) {
                let mut draft = EventDraft::new(
                    event.entity,
                    event.event_type.clone(),
                    event.payload.clone(),
                );
                draft.causation_id = event.causation_id.and(copied_action);
                let appended = commands
                    .append(timeline, &[telemetry(event.entity), draft])
                    .test_ok();
                copied_action = copied_action.or(Some(appended[1].id));
            }
            let trailing = [telemetry(bodies[1])];
            commands.append(timeline, &trailing).test_ok();
            timeline
        };

        let closure = crate::test_support::closure_for_host_consumer(&mut host, timeline, "world");
        let events = timeline_events(&mut host, timeline);
        let mut reads = host.read_sender().test_ok();
        let mut with_telemetry = fixture.registry(gate.clone());
        replay_with(
            &fixture,
            &mut reads,
            timeline,
            &mut with_telemetry,
            &closure,
        )
        .test_ok();
        let authoritative: Vec<_> = events
            .iter()
            .filter(|event| event.event_type.as_str() != TELEMETRY)
            .cloned()
            .collect();
        assert_eq!(authoritative.len(), committed.len() + 1);
        assert_eq!(events.len(), 2 * authoritative.len() + 1);

        let states = |registry: &ProjectionRegistry| -> Vec<Option<State>> {
            bodies
                .iter()
                .map(|body| {
                    registry
                        .state_for_reducer(timeline, "world", body)
                        .test_ok()
                })
                .collect()
        };
        for (index, boundary) in authoritative.iter().enumerate() {
            let mut replayed = fixture.registry(gate.clone());
            replay_at_with(
                &fixture,
                &mut reads,
                timeline,
                boundary.seq,
                &mut replayed,
                &closure,
            )
            .test_ok();
            let mut without_telemetry = world_registry(gate.clone());
            without_telemetry.fold_events(timeline, &authoritative[..=index]);
            assert_eq!(states(&replayed), states(&without_telemetry));
        }
        let mut without_telemetry = world_registry(gate);
        without_telemetry.fold_events(timeline, &authoritative);
        let expected = states(&without_telemetry);
        assert!(expected.iter().all(Option::is_some));
        assert_eq!(states(&with_telemetry), expected);
    }

    /// Case 11: protected Replay installs State equal to an independent live
    /// fold, returns no Events, and replaces rather than accumulates State.
    #[test]
    fn public_replay_commands_use_an_installed_world_verifier() {
        let fixture = count_fixture();
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
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let events = timeline_events(&mut host, timeline);
        let mut registry = fixture.registry(Arc::clone(&gate));
        let mut reads = host.read_sender().test_ok();
        replay_with(&fixture, &mut reads, timeline, &mut registry, &closure).test_ok();
        assert_eq!(count_for(&registry, timeline, &entity), 3);
        let mut live = ProjectionRegistry::new().with_erasure_gate(Arc::clone(&gate));
        live.register("count", count_reducer());
        live.fold_events(timeline, &events);
        assert_eq!(
            registry.state_for(timeline, &entity).test_ok(),
            live.state_for(timeline, &entity).test_ok()
        );
        replay_with(&fixture, &mut reads, timeline, &mut registry, &closure).test_ok();
        assert_eq!(count_for(&registry, timeline, &entity), 3);

        let mut bounded_registry = fixture.registry(gate);
        replay_at_with(
            &fixture,
            &mut reads,
            timeline,
            events[1].seq,
            &mut bounded_registry,
            &closure,
        )
        .test_ok();
        assert_eq!(count_for(&bounded_registry, timeline, &entity), 2);
    }

    /// Case 11: a visible slot whose Plugin identity differs from the
    /// recorded consumer fails at `prepare_install` and changes nothing.
    #[test]
    fn public_replay_rejects_a_live_slot_of_another_plugin() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("stale-slot").test_ok();
            let entity = EntityId::new();
            commands.append(timeline.id(), &[draft(entity)]).test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
        registry
            .register_installed_reducer(PluginId::new(), "count", count_reducer())
            .test_ok();
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            replay_with(&fixture, &mut reads, timeline, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(
            registry
                .state_for_reducer(timeline, "count", &entity)
                .test_ok(),
            None
        );
    }

    /// A consumer the host provider never admitted fails the staged fold
    /// after the verified read; nothing is installed.
    #[test]
    fn public_replay_rejects_an_unadmitted_consumer() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("unadmitted").test_ok();
            let entity = EntityId::new();
            commands.append(timeline.id(), &[draft(entity)]).test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut registry = fixture.registry(gate);
        let unknown = [pos_state::RecordedConsumerV1::new(
            PluginId::new(),
            pos_core::Hash::from_bytes([1; 32]),
        )];
        let fold = crate::ProtectedFoldV1 {
            consumers: &unknown,
            ..fixture.fold()
        };
        let mut reads = host.read_sender().test_ok();
        let result = with_release(|release| {
            super::replay(
                &mut reads,
                timeline,
                &mut registry,
                &closure,
                release,
                &fold,
            )
        });
        assert!(matches!(result, Err(CoreError::ArtifactUnavailable)));
        assert_eq!(count_for(&registry, timeline, &entity), 0);
    }

    #[test]
    fn public_replay_rejects_cross_timeline_closures() {
        let fixture = count_fixture();
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
        let closure = crate::test_support::closure_for_host(&mut host, authorized);
        let mut registry = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            replay_with(&fixture, &mut reads, requested, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    #[test]
    fn public_replay_reads_a_complete_fork_in_timeline_order() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let (fork, entity) = {
            let mut commands = host.command_sender().test_ok();
            let parent = commands.create_timeline("replay-parent").test_ok();
            let entity = EntityId::new();
            let shared = commands
                .append(parent.id(), &[draft(entity), draft(entity)])
                .test_ok();
            let fork = commands
                .fork_timeline(parent.id(), shared[1].seq, "replay-fork")
                .test_ok();
            commands.append(fork.id(), &[draft(entity)]).test_ok();
            (fork.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&mut host, fork);
        let events = timeline_events(&mut host, fork);
        let mut registry = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();

        replay_with(&fixture, &mut reads, fork, &mut registry, &closure).test_ok();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].seq, Seq::from_u64(3));
        assert_eq!(count_for(&registry, fork, &entity), 3);
    }

    #[test]
    fn public_replay_rolls_back_when_final_verification_fails() {
        let fixture = count_fixture();
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
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut registry = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            replay_with(&fixture, &mut reads, timeline, &mut registry, &closure),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(
            registry
                .state_for_reducer(timeline, "count", &entity)
                .test_ok(),
            None
        );
    }

    #[test]
    fn public_replay_rejects_empty_consumer_selection() {
        let fixture = count_fixture();
        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let mut reads = host.read_sender().test_ok();
        let closure = pos_core::WorldReplayClosureV1::test_fixture().test_ok();
        let mut registry = ProjectionRegistry::new();
        assert!(matches!(
            replay_with(
                &fixture,
                &mut reads,
                TimelineId::new(),
                &mut registry,
                &closure
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
    }

    #[test]
    fn public_replay_enforces_verified_read_bounds() {
        let fixture = count_fixture();
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
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut registry = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();

        let replay_result = replay_with(&fixture, &mut reads, timeline, &mut registry, &closure);
        assert!(
            matches!(&replay_result, Err(CoreError::ArtifactUnavailable)),
            "expected an over-bound Replay to fail closed, got {replay_result:?}"
        );
        assert_eq!(
            registry
                .state_for_reducer(timeline, "count", &entity)
                .test_ok(),
            None
        );
    }

    #[test]
    fn public_replay_rejects_requested_range_past_logical_head() {
        let fixture = count_fixture();
        let mut host = crate::test_support::open_exact_host();
        let gate = host.containment_gate();
        let (timeline, entity) = {
            let mut commands = host.command_sender().test_ok();
            let timeline = commands.create_timeline("range-past-head").test_ok();
            let entity = EntityId::new();
            commands.append(timeline.id(), &[draft(entity)]).test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut registry = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        let result = replay_at_with(
            &fixture,
            &mut reads,
            timeline,
            Seq::from_u64(2),
            &mut registry,
            &closure,
        );
        assert!(matches!(result, Err(CoreError::ArtifactUnavailable)));
        assert_eq!(
            registry
                .state_for_reducer(timeline, "count", &entity)
                .test_ok(),
            None
        );
    }

    /// Mirrors the installed-verifier contract: a closure's source head is
    /// accepted only for the logical head at which the closure was recorded.
    struct RecordedHeadVerifier {
        recorded_head: Seq,
    }

    impl pos_runtime::WorldReplayVerifierV1 for RecordedHeadVerifier {
        fn verify(
            &self,
            closure: &pos_core::WorldReplayClosureV1,
            requested_use: &pos_runtime::WorldReplayUseV1,
            inventory_generation: pos_core::ErasureReferenceV1,
        ) -> Result<pos_runtime::VerifiedWorldReplayV1, pos_runtime::WorldReplayVerificationErrorV1>
        {
            if requested_use.source_logical_head() == self.recorded_head {
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

    #[test]
    fn public_replay_rejects_events_appended_after_the_closure_head() {
        let fixture = count_fixture();
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(RecordedHeadVerifier {
                recorded_head: Seq::from_u64(2),
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
            let timeline = commands.create_timeline("closure-head").test_ok();
            let entity = EntityId::new();
            commands
                .append(timeline.id(), &[draft(entity), draft(entity)])
                .test_ok();
            (timeline.id(), entity)
        };
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut exact_registry = fixture.registry(Arc::clone(&gate));
        {
            let mut reads = host.read_sender().test_ok();
            replay_with(
                &fixture,
                &mut reads,
                timeline,
                &mut exact_registry,
                &closure,
            )
            .test_ok();
        }
        assert_eq!(count_for(&exact_registry, timeline, &entity), 2);

        host.command_sender()
            .test_ok()
            .append(timeline, &[draft(entity)])
            .test_ok();
        let closure = crate::test_support::closure_for_host(&mut host, timeline);
        let mut appended_registry = fixture.registry(gate);
        let mut reads = host.read_sender().test_ok();
        assert!(matches!(
            replay_with(
                &fixture,
                &mut reads,
                timeline,
                &mut appended_registry,
                &closure
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert_eq!(
            appended_registry
                .state_for_reducer(timeline, "count", &entity)
                .test_ok(),
            None
        );
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

    fn count_for(reg: &ProjectionRegistry, timeline: TimelineId, entity: &EntityId) -> u64 {
        reg.state_for(timeline, entity)
            .test_ok()
            .and_then(|s| s.get("n").and_then(serde_json::Value::as_u64))
            .unwrap_or(0)
    }
}
