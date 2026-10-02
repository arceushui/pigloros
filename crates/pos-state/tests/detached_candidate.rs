//! Detached protected candidates fold exactly like the visible registry
//! (ADR-113 §3, acceptance case 14 for the shared fold step).

use pos_core::{
    CanonicalBytes, ConsentRevokedV1, EntityId, ErasureContainmentGateV1, Event, EventId, Hash,
    Kind, PluginId, Reducer, SchemaVersion, Seq, State, TimelineId, WallTime,
    EVENT_TYPE_CONSENT_REVOKED_V1, GEOGRAPHIC_EVENT_TYPE,
};
use pos_state::{
    DetachedProjectionCandidateV1, ProjectionCandidateErrorV1, ProjectionRegistry,
    ProtectedProjectionProviderV1, RecordedConsumerV1,
};
use std::{fmt::Debug, sync::Arc};

const COUNTED: &str = "fixture.counted";
const REJECTED: &str = "fixture.rejected";

fn test_ok<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
    })
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

fn candidate_for(
    counting: RecordedConsumerV1,
    typed: RecordedConsumerV1,
) -> DetachedProjectionCandidateV1 {
    let mut candidate = DetachedProjectionCandidateV1::default();
    test_ok(candidate.push_reducer(counting, Box::new(CountingReducer)));
    test_ok(candidate.push_reducer(typed, Box::new(LastTypeReducer)));
    candidate
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
    test_ok(live.register_installed_reducer(
        typed.plugin_id(),
        "typed",
        Box::new(LastTypeReducer),
    ));
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
}

#[test]
fn candidates_own_independent_ordered_reducer_state() {
    let (counting, typed) = (consumer(3), consumer(4));
    let entity = EntityId::new();
    let mut folded = candidate_for(counting, typed);
    let fresh = candidate_for(counting, typed);
    let counted = event(entity, COUNTED, CanonicalBytes::from_vec(Vec::new()), 1);
    folded.fold_events(&[counted]);

    assert!(folded.state_for(counting.plugin_id(), &entity).is_some());
    assert!(fresh.state_for(counting.plugin_id(), &entity).is_none());
    assert_eq!(folded.consumers(), vec![counting, typed]);
    assert_eq!(counting.reducer_identity(), Hash::from_bytes([3; 32]));
}

#[test]
fn a_consumer_cannot_be_pushed_twice() {
    let counting = consumer(5);
    let mut candidate = DetachedProjectionCandidateV1::default();
    test_ok(candidate.push_reducer(counting, Box::new(CountingReducer)));
    let duplicate = RecordedConsumerV1::new(counting.plugin_id(), Hash::from_bytes([6; 32]));

    assert_eq!(
        candidate.push_reducer(duplicate, Box::new(LastTypeReducer)),
        Err(ProjectionCandidateErrorV1::ConsumerSetMismatch)
    );
    assert_eq!(candidate.consumers(), vec![counting]);
}

/// A provider is object-safe and is held as a shared trait object.
struct EmptyProvider;

impl ProtectedProjectionProviderV1 for EmptyProvider {
    fn open_candidate(
        &self,
        recorded_consumers: &[RecordedConsumerV1],
    ) -> Result<DetachedProjectionCandidateV1, ProjectionCandidateErrorV1> {
        recorded_consumers
            .is_empty()
            .then(DetachedProjectionCandidateV1::default)
            .ok_or(ProjectionCandidateErrorV1::NotAdmitted)
    }
}

#[test]
fn providers_are_object_safe() {
    let provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync> = Arc::new(EmptyProvider);
    let empty = test_ok(provider.open_candidate(&[]));
    assert!(empty.consumers().is_empty());
    assert_eq!(
        provider.open_candidate(&[consumer(7)]).err(),
        Some(ProjectionCandidateErrorV1::NotAdmitted)
    );
}
