//! Staged protected installs commit only through ADR-112's checked handoff
//! (ADR-113 §2 and §9; acceptance cases 9, 11, 15 and 23).

use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::staged_install::ProjectionSourceV1;
use pos_core::trusted_clock::{
    handoff_checked, open_release_guard, reserve_trusted_clock, ApplicableExpiriesV1,
    AuthorizedArtifactUseV1, ExpiryPremisesV1, ProtectedHandoffTargetV1, ReleaseGuardV1,
    ScriptedGuardMonotonicSourceV1, ScriptedTrustedWallSourceV1, StagedProtectedOutputV1,
    TrustedClockErrorV1, WaitBudgetV1,
};
use pos_core::trusted_clock_fixture::TrustedClockFixtureV1;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureReferenceV1, Event, EventId, Hash,
    Kind, PluginId, PrincipalRefV1, Reducer, SchemaVersion, Seq, State, TimelineId, WallTime,
};
use pos_state::{
    CandidateBoundsV1, CandidateReducerV1, DetachedProjectionCandidateV1, InitialStateV1,
    InstallErrorV1, ProjectionObservationPolicyV1, ProjectionRegistry, RecordedConsumerV1,
    StagedProjectionV1,
};
use std::{fmt::Debug, sync::Arc, time::Duration};

const SECOND: u64 = 1_000_000;
const DAY: u64 = 86_400 * SECOND;
const T0: u64 = 1_800_000_000 * SECOND;
const FAR: u64 = T0 + 1_000 * DAY;
const NAME: &str = "counting";

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

fn test_some<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
}

struct CountingReducer;

impl Reducer for CountingReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        let count = state
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

fn counted(entity: EntityId, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new("fixture.counted"),
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
    }
}

fn count_of(registry: &ProjectionRegistry, timeline: TimelineId, entity: &EntityId) -> Option<u64> {
    test_ok(registry.state_for_reducer(timeline, NAME, entity))
        .and_then(|state| state.get("count").and_then(serde_json::Value::as_u64))
}

fn policy() -> ProjectionObservationPolicyV1 {
    test_ok(ProjectionObservationPolicyV1::try_new(
        vec!["count".to_owned()],
        "fixture.schema.v1".to_owned(),
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        Hash::from_bytes([3; 32]),
    ))
}

/// A staged fold of `events` for one consumer, bound to `source`.
fn staged_with(
    consumer: RecordedConsumerV1,
    name: &'static str,
    observation_policy: Option<ProjectionObservationPolicyV1>,
    source: ProjectionSourceV1,
    events: &[Event],
) -> StagedProjectionV1 {
    let reducer = CandidateReducerV1 {
        consumer,
        name,
        reducer: Box::new(CountingReducer),
        bounds: CandidateBoundsV1 {
            callback_bound: Duration::from_millis(250),
            growth_per_payload_byte: 0,
            growth_constant_bytes: 64,
        },
        observation_policy,
    };
    let mut candidate = test_ok(DetachedProjectionCandidateV1::from_reducers(
        vec![reducer],
        InitialStateV1::Empty,
        source,
    ));
    for event in events {
        test_ok(candidate.fold_event_with(event, |mut turn| {
            turn.apply();
            turn.account()
        }));
    }
    test_ok(candidate.exact_pass());
    test_some(candidate.take_staged())
}

fn staged(
    consumer: RecordedConsumerV1,
    timeline: TimelineId,
    events: &[Event],
) -> StagedProjectionV1 {
    staged_with(
        consumer,
        NAME,
        None,
        ProjectionSourceV1::bound(timeline, None),
        events,
    )
}

/// A visible registry with one installed slot for `consumer`, already
/// holding one counted Event for `entity` on `timeline`.
fn live(
    consumer: RecordedConsumerV1,
    timeline: TimelineId,
    entity: EntityId,
) -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    test_ok(registry.register_installed_reducer(
        consumer.plugin_id(),
        NAME,
        Box::new(CountingReducer),
    ));
    registry.apply_event(timeline, &counted(entity, 1));
    registry
}

fn consumer() -> RecordedConsumerV1 {
    RecordedConsumerV1::new(PluginId::new(), Hash::from_bytes([9; 32]))
}

fn lease(deadline: u64) -> WorldRetentionLeaseV1 {
    let policy = test_ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world".to_owned(),
        audience_policy_hash: Hash::from_bytes([7; 32]),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    }));
    let input = WorldRetentionLeaseInputV1 {
        timeline_id: TimelineId::new(),
        policy_hash: policy.digest(),
        started_at_micros: deadline - 120 * DAY,
        admission_closes_at_micros: deadline - 90 * DAY,
        retention_deadline_micros: deadline,
    };
    test_ok(WorldRetentionLeaseV1::new(&policy, input))
}

fn authenticated(expires_at: u64) -> AuthenticatedPrincipalResultV1 {
    let draft = AuthenticatedPrincipalDraftV1 {
        principal: test_ok(PrincipalRefV1::try_new([1; 16], "operators")),
        adapter_id: "test-passkey".to_owned(),
        assurance: test_ok(AssuranceLevelV1::try_new(2)),
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(expires_at),
        binding_digest: Hash::from_bytes([7; 32]),
    };
    test_ok(AuthenticatedPrincipalResultV1::try_from_draft(draft))
}

fn still() -> ScriptedGuardMonotonicSourceV1 {
    ScriptedGuardMonotonicSourceV1::new([Duration::ZERO])
}

fn guarded(port: &mut TrustedClockFixtureV1) -> (ReleaseGuardV1<'_>, ApplicableExpiriesV1) {
    let mut store = port.clone();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([T0]);
    let mut wait = WaitBudgetV1::new();
    let reservation = test_ok(reserve_trusted_clock(
        &mut store,
        &mut wall,
        &mut still(),
        &mut wait,
        None,
    ));
    let guard = test_ok(open_release_guard(
        port,
        reservation,
        &mut wait,
        &mut still(),
    ));
    let leases = [lease(FAR)];
    let access = authenticated(FAR);
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let expiries = test_ok(guard.applicable_expiries(&premises));
    (guard, expiries)
}

/// Hand a staged target over with a final trusted sample `at`.
fn release<T: ProtectedHandoffTargetV1>(
    staged: StagedProtectedOutputV1<T>,
    at: u64,
) -> Result<AuthorizedArtifactUseV1<T::Committed>, TrustedClockErrorV1> {
    let mut port = TrustedClockFixtureV1::new();
    let (guard, expiries) = guarded(&mut port);
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([at, at]);
    handoff_checked(guard, &expiries, staged, &mut wall, &mut still())
}

#[test]
fn a_checked_handoff_swaps_the_staged_maps_in() {
    let (timeline, entity) = (TimelineId::new(), EntityId::new());
    let recorded = consumer();
    let mut registry = live(recorded, timeline, entity);
    let events = [counted(entity, 1), counted(entity, 2), counted(entity, 3)];
    let staged = staged(recorded, timeline, &events);

    let prepared = test_ok(registry.prepare_install(staged));
    let released = test_ok(release(prepared, T0));
    let displaced = released.value();

    assert_eq!(displaced.maps().len(), 1);
    assert_eq!(displaced.maps()[0].len(), 1);
    assert_eq!(displaced.source().timeline(), Some(timeline));
    assert_eq!(count_of(&registry, timeline, &entity), Some(3));
}

#[test]
fn a_refused_handoff_leaves_the_registry_unchanged() {
    let (timeline, entity) = (TimelineId::new(), EntityId::new());
    let recorded = consumer();
    let mut registry = live(recorded, timeline, entity);
    let staged = staged(
        recorded,
        timeline,
        &[counted(entity, 1), counted(entity, 2)],
    );

    let prepared = test_ok(registry.prepare_install(staged));
    let late = T0 + 33 * SECOND;
    assert_eq!(
        release(prepared, late).err(),
        Some(TrustedClockErrorV1::WindowExceeded)
    );
    assert_eq!(count_of(&registry, timeline, &entity), Some(1));
}

#[test]
fn stale_sources_and_slots_fail_before_any_change() {
    let (timeline, entity) = (TimelineId::new(), EntityId::new());
    let recorded = consumer();
    let events = [counted(entity, 1), counted(entity, 2)];
    let refused =
        |registry: &mut ProjectionRegistry, staged| registry.prepare_install(staged).err();
    let source = Some(InstallErrorV1::SourceMismatch);
    let slot = Some(InstallErrorV1::SlotMismatch);

    let mut registry = live(recorded, timeline, entity);
    let other_generation =
        ProjectionSourceV1::bound(timeline, Some(ErasureReferenceV1::from_digest([4; 32])));
    let stale = staged_with(recorded, NAME, None, other_generation, &events);
    assert_eq!(refused(&mut registry, stale), source);

    let mut ungated = ProjectionRegistry::new();
    test_ok(ungated.register_installed_reducer(
        recorded.plugin_id(),
        NAME,
        Box::new(CountingReducer),
    ));
    assert_eq!(
        refused(&mut ungated, staged(recorded, timeline, &events)),
        source
    );

    // The recorded consumer's Plugin identity differs from the live slot's.
    let other = RecordedConsumerV1::new(PluginId::new(), recorded.reducer_identity());
    assert_eq!(
        refused(&mut registry, staged(other, timeline, &events)),
        slot
    );
    let renamed = staged_with(
        recorded,
        "renamed",
        None,
        ProjectionSourceV1::bound(timeline, None),
        &events,
    );
    assert_eq!(refused(&mut registry, renamed), slot);
    let observed = staged_with(
        recorded,
        NAME,
        Some(policy()),
        ProjectionSourceV1::bound(timeline, None),
        &events,
    );
    assert_eq!(refused(&mut registry, observed), slot);
    let mut empty = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    assert_eq!(
        refused(&mut empty, staged(recorded, timeline, &events)),
        slot
    );

    assert_eq!(count_of(&registry, timeline, &entity), Some(1));
}

#[test]
fn compare_arms_commit_together_or_not_at_all() {
    let (timeline_a, timeline_b, entity) = (TimelineId::new(), TimelineId::new(), EntityId::new());
    let (recorded_a, recorded_b) = (consumer(), consumer());
    let mut arm_a = live(recorded_a, timeline_a, entity);
    let mut arm_b = live(recorded_b, timeline_b, entity);
    let two = [counted(entity, 1), counted(entity, 2)];
    let three = [counted(entity, 1), counted(entity, 2), counted(entity, 3)];

    let refused = ProjectionRegistry::prepare_install_pair(
        &mut arm_a,
        staged(recorded_a, timeline_a, &two),
        &mut arm_b,
        staged(recorded_a, timeline_b, &three),
    );
    assert_eq!(refused.err(), Some(InstallErrorV1::SlotMismatch));
    let refused = ProjectionRegistry::prepare_install_pair(
        &mut arm_a,
        staged(recorded_b, timeline_a, &two),
        &mut arm_b,
        staged(recorded_b, timeline_b, &three),
    );
    assert_eq!(refused.err(), Some(InstallErrorV1::SlotMismatch));

    let prepared = test_ok(ProjectionRegistry::prepare_install_pair(
        &mut arm_a,
        staged(recorded_a, timeline_a, &two),
        &mut arm_b,
        staged(recorded_b, timeline_b, &three),
    ));
    let late = T0 + 33 * SECOND;
    assert!(release(prepared, late).is_err());
    assert_eq!(count_of(&arm_a, timeline_a, &entity), Some(1));
    assert_eq!(count_of(&arm_b, timeline_b, &entity), Some(1));

    let prepared = test_ok(ProjectionRegistry::prepare_install_pair(
        &mut arm_a,
        staged(recorded_a, timeline_a, &two),
        &mut arm_b,
        staged(recorded_b, timeline_b, &three),
    ));
    let released = test_ok(release(prepared, T0));
    let (displaced_a, displaced_b) = released.value();
    assert_eq!(displaced_a.source().timeline(), Some(timeline_a));
    assert_eq!(displaced_b.source().timeline(), Some(timeline_b));
    assert_eq!(count_of(&arm_a, timeline_a, &entity), Some(2));
    assert_eq!(count_of(&arm_b, timeline_b, &entity), Some(3));
}
