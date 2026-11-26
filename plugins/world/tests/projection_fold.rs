//! ADR-141 §9 (D3, D16): the on-demand Projection fold through a fresh
//! `WorldReducer` projects World body observations and never World actions.

use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, Hash, Kind, SchemaVersion, Seq, WallTime,
};
use pos_plugin_world::{
    WorldObservationV1, WorldReducer, EVENT_TYPE_ACTION_V1, EVENT_TYPE_OBSERVATION_V1,
};
use pos_state::{fold_projection_page_v1, ProjectionPageLimitV1, ProjectionPageV1};

fn world_event(entity: EntityId, event_type: &str, payload: CanonicalBytes, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload,
        wall_time: WallTime::from_micros(0),
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

/// A WOB1 observation of `body` at `tick`, as the body's own Event.
fn body_observation(body: EntityId, tick: u64, seq: u64) -> Event {
    let payload = WorldObservationV1 {
        body_entity_id: body,
        tick,
        step_index: 0,
        pos_x: 1.0,
        pos_y: 2.0,
        pos_z: 3.0,
        orient_w: 1.0,
        orient_x: 0.0,
        orient_y: 0.0,
        orient_z: 0.0,
        vel_lin_x: 0.0,
        vel_lin_y: 0.0,
        vel_lin_z: 0.0,
        vel_ang_x: 0.0,
        vel_ang_y: 0.0,
        vel_ang_z: 0.0,
        sensor_kind: 0,
        sensor_value: vec![],
    }
    .encode()
    .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
    world_event(body, EVENT_TYPE_OBSERVATION_V1, payload, seq)
}

fn world_action(actor: EntityId, seq: u64) -> Event {
    let payload = CanonicalBytes::from_static(b"action");
    world_event(actor, EVENT_TYPE_ACTION_V1, payload, seq)
}

fn world_page(events: &[Event], at_seq: u64) -> ProjectionPageV1 {
    let limit = ProjectionPageLimitV1::from_entry_count_v1(100)
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("page limit")));
    let cut = Seq::from_u64(at_seq);
    fold_projection_page_v1(Box::new(WorldReducer), events, cut, None, limit)
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

#[test]
fn world_actions_alone_fold_to_an_empty_projection() {
    let actor = EntityId::new();
    let events = [world_action(actor, 1), world_action(actor, 2)];
    let page = world_page(&events, 2);
    assert_eq!((page.entries, page.more_remain), (Vec::new(), false));
}

#[test]
fn each_body_projects_its_last_observation() {
    let first_body = EntityId::new();
    let second_body = EntityId::new();
    let events = [
        body_observation(first_body, 1, 1),
        body_observation(second_body, 2, 2),
        body_observation(first_body, 3, 3),
    ];
    let page = world_page(&events, 3);
    let mut bodies = vec![first_body, second_body];
    bodies.sort();
    let projected: Vec<EntityId> = page.entries.iter().map(|entry| entry.entity_id).collect();
    assert_eq!(projected, bodies);
    let first = page
        .entries
        .iter()
        .find(|entry| entry.entity_id == first_body)
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("first body missing")));
    assert_eq!(first.last_projected.event_id, events[2].id);
    assert_eq!(first.last_projected.payload, events[2].payload);
    assert_eq!(first.state.get("tick"), Some(&serde_json::json!(3)));
}
