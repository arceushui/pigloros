use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
};
use pos_plugin_world::{
    SimpleKinematicBackend, WorldConfigV1, WorldDriver, COORD_CONVENTION_RIGHT_HANDED_Y_UP,
    EVENT_TYPE_CONFIG_V1,
};
use pos_runtime::{PluginRegistry, TimelineHistorySegment};

fn config() -> WorldConfigV1 {
    WorldConfigV1 {
        timestep_micros: 16_667,
        coord_convention: COORD_CONVENTION_RIGHT_HANDED_Y_UP,
        gravity_x: 0.0,
        gravity_y: -9.81,
        gravity_z: 0.0,
        backend_id: "simple-kinematic".to_owned(),
        backend_version: "1.0.0".to_owned(),
        backend_content_hash: [0; 32],
        action_schema_version: 1,
        observation_schema_version: 1,
        sensor_min_resolution_mm: 100,
        actuator_catalogue_version: 1,
    }
}

#[test]
fn public_world_recovery_accepts_and_commits_the_pinned_configuration(
) -> Result<(), Box<dyn std::error::Error>> {
    let timeline = TimelineId::new();
    let payload = config().encode()?;
    let event = Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new(EVENT_TYPE_CONFIG_V1),
        payload: CanonicalBytes::from_vec(payload.as_slice().to_vec()),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(1),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        payload_hash: Hash::from_bytes([0; 32]),
    };

    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(WorldDriver::new(
        Vec::new(),
        Box::new(SimpleKinematicBackend::new()),
        config(),
    )));
    registry.restore_driver_state(
        &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
        &[event],
    )?;
    let drafts = registry.step_all(timeline)?;
    assert!(drafts
        .iter()
        .all(|draft| draft.event_type.as_str() != EVENT_TYPE_CONFIG_V1));
    Ok(())
}
