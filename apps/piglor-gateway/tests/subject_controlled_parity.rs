//! The Gateway Event-read filter hides exactly the subject-controlled types
//! of the shared `pos-core` predicate (ADR-021 Revision 4 Decision 2, #494).

use piglor_gateway::EventView;
use pos_core::{
    is_subject_controlled_event_type, CanonicalBytes, EntityId, Event, EventId, Hash, Kind,
    SchemaVersion, Seq, WallTime, HOST_CONSENT_CLOSED_EVENT_TYPE,
};

/// One Event type and whether the Gateway Event read hides it.
const TABLE: [(&str, bool); 16] = [
    ("persona.prediction", true),
    ("geo.location", true),
    ("geo.cell", true),
    ("location.coordinate.v1", true),
    ("model.fit.v1", true),
    ("export.bundle.v1", true),
    ("timeline.fork.requested", true),
    ("retention.extended", true),
    ("consent.granted.v1", true),
    ("consent.revoked.v1", true),
    (HOST_CONSENT_CLOSED_EVENT_TYPE, false),
    ("eval.prediction", false),
    ("timeline.forked", false),
    ("retention", false),
    ("world.observation.v1", false),
    ("ordinary.event", false),
];

fn event(event_type: &str) -> Event {
    Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(&[0xf6]),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(1),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

#[test]
fn the_event_read_filter_hides_exactly_the_subject_controlled_types() {
    for (event_type, hidden) in TABLE {
        let view = EventView::try_from(&event(event_type));
        assert_eq!(view.is_err(), hidden, "{event_type}");
        assert_eq!(
            is_subject_controlled_event_type(&Kind::new(event_type)),
            hidden,
            "{event_type}"
        );
    }
}
