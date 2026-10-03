//! Detached protected candidates fold exactly like the visible registry
//! (ADR-113 §3, acceptance case 14 for the shared fold step) and account
//! their staged size incrementally (§4 E5, acceptance cases 10 and 20).

use pos_core::{
    staged_install::ProjectionSourceV1, CanonicalBytes, ConsentRevokedV1, EntityId,
    ErasureContainmentGateV1, Event, EventId, Hash, Kind, PluginId, Reducer, SchemaVersion, Seq,
    State, TimelineId, WallTime, EVENT_TYPE_CONSENT_REVOKED_V1, GEOGRAPHIC_EVENT_TYPE,
};
use pos_state::{
    CandidateBoundsV1, CandidateBuildV1, CandidateReducerV1, DetachedProjectionCandidateV1,
    InitialStateV1, ProjectionCandidateErrorV1, ProjectionRegistry, ProtectedProjectionProviderV1,
    RecordedConsumerV1, StagedLimitErrorV1, MAX_STAGED_ENTITIES_PER_CONSUMER_V1,
    MAX_STAGED_OUTPUT_BYTES_V1,
};
use std::{fmt::Debug, sync::Arc, time::Duration};

const COUNTED: &str = "fixture.counted";
const REJECTED: &str = "fixture.rejected";
const BLOB: &str = "fixture.blob";

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
}

fn test_some<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
}

/// Counts every projected Event and rejects one Event type (ADR-090).
struct CountingReducer;

impl Reducer for CountingReducer {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("count", serde_json::json!(0));
        state
    }

    fn projects_event(&self, event: &Event) -> bool {
        event.event_type.as_str() != REJECTED
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        let count = state
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("count", serde_json::json!(count + 1));
    }
}

/// Records the last Event type it was offered.
struct LastTypeReducer;

impl Reducer for LastTypeReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        state.set("last", serde_json::json!(event.event_type.as_str()));
    }
}

/// Stores a string as long as the payload's little-endian `u64` length.
struct BlobReducer;

impl Reducer for BlobReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        let mut length = [0_u8; 8];
        length.copy_from_slice(&event.payload.as_slice()[..8]);
        let length = usize::try_from(u64::from_le_bytes(length)).unwrap_or(0);
        state.set("b", serde_json::json!("a".repeat(length)));
    }
}

fn event(entity: EntityId, kind: &str, payload: CanonicalBytes, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(kind),
        payload,
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

fn counted(entity: EntityId, seq: u64) -> Event {
    event(entity, COUNTED, CanonicalBytes::from_vec(Vec::new()), seq)
}

/// A blob Event whose staged entity size is exactly `staged_bytes`: 16 for
/// the identifier, 1 for the field name and 2 for the JSON quotes.
fn blob(entity: EntityId, staged_bytes: u64) -> Event {
    let length = staged_bytes - 19;
    let payload = CanonicalBytes::from_vec(length.to_le_bytes().to_vec());
    event(entity, BLOB, payload, 1)
}

fn revocation(subject: EntityId, seq: u64) -> Event {
    let payload = test_ok(
        ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: seq,
        }
        .encode(),
    );
    event(subject, EVENT_TYPE_CONSENT_REVOKED_V1, payload, seq)
}

/// Every filtering branch of the live fold step, in one Event range.
fn mixed_events(kept: EntityId, revoked: EntityId) -> Vec<Event> {
    let empty = || CanonicalBytes::from_vec(Vec::new());
    vec![
        event(kept, COUNTED, empty(), 1),
        event(revoked, COUNTED, empty(), 2),
        event(kept, REJECTED, empty(), 3),
        event(kept, "consent.granted.v1", empty(), 4),
        event(kept, GEOGRAPHIC_EVENT_TYPE, empty(), 5),
        revocation(revoked, 6),
        event(kept, EVENT_TYPE_CONSENT_REVOKED_V1, empty(), 7),
        event(kept, COUNTED, empty(), 8),
    ]
}

fn consumer(byte: u8) -> RecordedConsumerV1 {
    RecordedConsumerV1::new(PluginId::new(), Hash::from_bytes([byte; 32]))
}

const fn bounds(constant: u64) -> CandidateBoundsV1 {
    CandidateBoundsV1 {
        callback_bound: Duration::from_millis(250),
        growth_per_payload_byte: 0,
        growth_constant_bytes: constant,
    }
}

fn source() -> ProjectionSourceV1 {
    ProjectionSourceV1::bound(TimelineId::new(), None)
}

fn built(consumer: RecordedConsumerV1, reducer: impl Reducer + 'static) -> CandidateReducerV1 {
    built_with(consumer, reducer, bounds(4096))
}

fn built_with(
    consumer: RecordedConsumerV1,
    reducer: impl Reducer + 'static,
    bounds: CandidateBoundsV1,
) -> CandidateReducerV1 {
    CandidateReducerV1 {
        consumer,
        name: "fixture",
        reducer: Box::new(reducer),
        bounds,
        observation_policy: None,
    }
}

fn assemble(reducers: Vec<CandidateReducerV1>) -> DetachedProjectionCandidateV1 {
    test_ok(DetachedProjectionCandidateV1::from_reducers(
        reducers,
        InitialStateV1::Empty,
        source(),
    ))
}

fn candidate_for(
    counting: RecordedConsumerV1,
    typed: RecordedConsumerV1,
) -> DetachedProjectionCandidateV1 {
    assemble(vec![
        built(counting, CountingReducer),
        built(typed, LastTypeReducer),
    ])
}

/// Fold with accounting, as the staged executor does without its clock.
fn fold_accounted(
    candidate: &mut DetachedProjectionCandidateV1,
    events: &[Event],
) -> Result<(), StagedLimitErrorV1> {
    for event in events {
        candidate.fold_event_with(event, |mut turn| {
            turn.apply();
            turn.account()
        })?;
        if candidate.exact_pass_due() {
            candidate.exact_pass()?;
        }
    }
    candidate.exact_pass()
}

#[test]
fn candidate_fold_equals_the_live_registry_fold() {
    let timeline = TimelineId::new();
    let (kept, revoked, absent) = (EntityId::new(), EntityId::new(), EntityId::new());
    let (counting, typed) = (consumer(1), consumer(2));
    let events = mixed_events(kept, revoked);

    let mut live = ProjectionRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    test_ok(live.register_installed_reducer(
        counting.plugin_id(),
        "counting",
        Box::new(CountingReducer),
    ));
    test_ok(live.register_installed_reducer(typed.plugin_id(), "typed", Box::new(LastTypeReducer)));
    live.fold_events(timeline, &events);

    let mut candidate = candidate_for(counting, typed);
    candidate.fold_events(&events);

    for recorded in [counting, typed] {
        for entity in [kept, revoked, absent] {
            let expected = test_ok(live.state_for_plugin(timeline, recorded.plugin_id(), &entity));
            assert_eq!(
                candidate.state_for(recorded.plugin_id(), &entity),
                expected.as_ref()
            );
        }
    }
    let kept_count = candidate
        .state_for(counting.plugin_id(), &kept)
        .and_then(|state| state.get("count"))
        .and_then(serde_json::Value::as_u64);
    assert_eq!(kept_count, Some(2));
    assert!(candidate.state_for(typed.plugin_id(), &revoked).is_none());
    assert!(candidate.state_for(PluginId::new(), &kept).is_none());
    assert_eq!(candidate.revocations(), &[revoked]);
}

#[test]
fn candidates_own_independent_ordered_reducer_state() {
    let (counting, typed) = (consumer(3), consumer(4));
    let entity = EntityId::new();
    let mut folded = candidate_for(counting, typed);
    let fresh = candidate_for(counting, typed);
    folded.fold_events(&[counted(entity, 1)]);

    assert!(folded.state_for(counting.plugin_id(), &entity).is_some());
    assert!(fresh.state_for(counting.plugin_id(), &entity).is_none());
    assert_eq!(folded.consumers(), vec![counting, typed]);
    assert_eq!(counting.reducer_identity(), Hash::from_bytes([3; 32]));
}

#[test]
fn a_consumer_cannot_be_assembled_twice() {
    let (counting, typed) = (consumer(5), consumer(8));
    let duplicate = RecordedConsumerV1::new(counting.plugin_id(), Hash::from_bytes([6; 32]));
    let open = |reducers| {
        DetachedProjectionCandidateV1::from_reducers(reducers, InitialStateV1::Empty, source())
    };
    let repeated_later = open(vec![
        built(counting, CountingReducer),
        built(typed, LastTypeReducer),
        built(duplicate, LastTypeReducer),
    ]);
    let repeated_adjacent = open(vec![
        built(typed, LastTypeReducer),
        built(counting, CountingReducer),
        built(duplicate, LastTypeReducer),
    ]);
    let mismatch = Some(ProjectionCandidateErrorV1::ConsumerSetMismatch);
    assert_eq!(repeated_later.err(), mismatch);
    assert_eq!(repeated_adjacent.err(), mismatch);

    let distinct = assemble(vec![
        built(typed, LastTypeReducer),
        built(counting, CountingReducer),
    ]);
    assert_eq!(distinct.consumers(), vec![typed, counting]);
    let empty = assemble(Vec::new());
    assert!(empty.consumers().is_empty());
}

#[test]
fn a_candidate_is_bound_to_one_timeline_source() {
    let bound = source();
    let candidate = test_ok(DetachedProjectionCandidateV1::from_reducers(
        vec![built(consumer(9), CountingReducer)],
        InitialStateV1::Empty,
        bound,
    ));
    assert_eq!(candidate.source(), bound);
    for unbound in [ProjectionSourceV1::default(), ProjectionSourceV1::mixed()] {
        let refused = DetachedProjectionCandidateV1::from_reducers(
            vec![built(consumer(9), CountingReducer)],
            InitialStateV1::Empty,
            unbound,
        );
        assert_eq!(
            refused.err(),
            Some(ProjectionCandidateErrorV1::SourceMismatch)
        );
    }
}

#[test]
fn staged_results_exist_only_after_a_current_exact_pass() {
    let (counting, typed) = (consumer(10), consumer(11));
    let (kept, revoked) = (EntityId::new(), EntityId::new());
    let mut candidate = candidate_for(counting, typed);
    assert!(candidate.take_staged().is_none());

    test_ok(fold_accounted(&mut candidate, &mixed_events(kept, revoked)));
    let accounting = candidate.accounting();
    assert_eq!(accounting.exact_passes(), 1);
    assert_eq!(accounting.upper_bound(), accounting.last_exact());
    let staged = test_some(candidate.take_staged());
    assert_eq!(staged.consumers(), &[counting, typed]);
    assert_eq!(staged.source(), candidate.source());
    assert_eq!(staged.revoked_subjects(), &[revoked]);
    assert!(candidate.take_staged().is_none());

    candidate.fold_events(&[counted(kept, 9)]);
    assert!(candidate.take_staged().is_none());
}

#[test]
fn growth_beyond_the_declared_bound_fails_the_exact_pass() {
    let entity = EntityId::new();
    let mut within = assemble(vec![built_with(consumer(12), CountingReducer, bounds(64))]);
    test_ok(fold_accounted(
        &mut within,
        &[counted(entity, 1), counted(entity, 2)],
    ));

    let mut over = assemble(vec![built_with(consumer(13), CountingReducer, bounds(0))]);
    let growing: Vec<Event> = (1..=10).map(|seq| counted(entity, seq)).collect();
    assert_eq!(
        fold_accounted(&mut over, &growing),
        Err(StagedLimitErrorV1::GrowthBoundExceeded)
    );

    let mut unaccounted = assemble(vec![built(consumer(14), CountingReducer)]);
    unaccounted.fold_events(&[counted(entity, 1)]);
    assert_eq!(
        unaccounted.exact_pass(),
        Err(StagedLimitErrorV1::GrowthBoundExceeded)
    );
}

#[test]
fn the_first_apply_of_an_entity_is_bounded_too() {
    // BlobReducer's `initial()` State is the 16-byte identifier alone.
    let mut within = assemble(vec![built_with(consumer(19), BlobReducer, bounds(64))]);
    test_ok(fold_accounted(
        &mut within,
        &[blob(EntityId::new(), 16 + 64)],
    ));
    assert_eq!(within.accounting().last_exact(), 16 + 64);

    let mut over = assemble(vec![built_with(consumer(20), BlobReducer, bounds(64))]);
    assert_eq!(
        fold_accounted(&mut over, &[blob(EntityId::new(), 16 + 65)]),
        Err(StagedLimitErrorV1::GrowthBoundExceeded)
    );
}

#[test]
fn the_staged_output_limit_is_exact() {
    let generous = bounds(MAX_STAGED_OUTPUT_BYTES_V1);
    let mut at_limit = assemble(vec![built_with(consumer(15), BlobReducer, generous)]);
    test_ok(fold_accounted(
        &mut at_limit,
        &[blob(EntityId::new(), MAX_STAGED_OUTPUT_BYTES_V1)],
    ));
    assert_eq!(
        at_limit.accounting().last_exact(),
        MAX_STAGED_OUTPUT_BYTES_V1
    );

    let mut over = assemble(vec![built_with(consumer(16), BlobReducer, generous)]);
    let event = blob(EntityId::new(), MAX_STAGED_OUTPUT_BYTES_V1 + 1);
    test_ok(over.fold_event_with(&event, |mut turn| {
        turn.apply();
        turn.account()
    }));
    assert!(over.exact_pass_due());
    assert_eq!(
        over.exact_pass(),
        Err(StagedLimitErrorV1::StagedOutputExceeded)
    );
    assert!(over.take_staged().is_none());
}

#[test]
fn the_entity_limit_is_exact() {
    let at_limit: Vec<Event> = (0..MAX_STAGED_ENTITIES_PER_CONSUMER_V1)
        .map(|_| counted(EntityId::new(), 1))
        .collect();
    let mut candidate = assemble(vec![built(consumer(17), CountingReducer)]);
    test_ok(fold_accounted(&mut candidate, &at_limit));
    assert_eq!(
        fold_accounted(&mut candidate, &[counted(EntityId::new(), 2)]),
        Err(StagedLimitErrorV1::EntityLimitExceeded)
    );
}

#[test]
fn exact_passes_stay_within_their_bound_for_one_growing_entity() {
    let entity = EntityId::new();
    let events: Vec<Event> = (1..=10_000).map(|seq| counted(entity, seq)).collect();
    let mut candidate = assemble(vec![built(consumer(18), CountingReducer)]);
    test_ok(fold_accounted(&mut candidate, &events));
    // Σ declared growth is 4096 × 10,000 bytes, far below the 64 MiB limit,
    // so the final pass is the only one.
    assert_eq!(candidate.accounting().exact_passes(), 1);
}

/// A build's admitted bounds are the only bounds its reducer folds under,
/// whatever bounds the builder itself returned.
#[test]
fn a_build_stamps_its_own_bounds_on_the_reducer() {
    let admitted = bounds(64);
    let build = CandidateBuildV1::new(admitted, || {
        Ok(built_with(consumer(9), CountingReducer, bounds(4096)))
    });
    assert_eq!(build.bounds(), admitted);
    assert_eq!(test_ok(build.build()).bounds, admitted);
}

/// A provider is object-safe and is held as a shared trait object.
struct EmptyProvider;

impl ProtectedProjectionProviderV1 for EmptyProvider {
    fn candidate_builds(
        &self,
        recorded_consumers: &[RecordedConsumerV1],
    ) -> Result<Vec<CandidateBuildV1<'_>>, ProjectionCandidateErrorV1> {
        if recorded_consumers.is_empty() {
            Ok(Vec::new())
        } else {
            Err(ProjectionCandidateErrorV1::NotAdmitted)
        }
    }
}

#[test]
fn providers_are_object_safe() {
    let provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync> = Arc::new(EmptyProvider);
    let empty = test_ok(provider.open_candidate(&[], InitialStateV1::Empty, source()));
    assert!(empty.consumers().is_empty());
    assert_eq!(
        provider
            .open_candidate(&[consumer(7)], InitialStateV1::Empty, source())
            .err(),
        Some(ProjectionCandidateErrorV1::NotAdmitted)
    );
}
