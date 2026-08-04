use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
    timeline::{Timeline, TimelineMeta, TimelineMode},
    TimelineExport,
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

const TIMELINE_ID: u128 = 1;
const ENTITY_ID: u128 = 2;
const FIRST_EVENT_ID: u128 = 2;
const SECOND_EVENT_ID: u128 = 3;

#[derive(Serialize, Deserialize)]
struct Signal {
    dimension: String,
    value: f64,
    subject: Option<String>,
    object: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("fixture decode failed: {0}")]
    Decode(String),
    #[error("fixture validation failed: {0}")]
    Invalid(String),
}

/// Encode the stable, complete `TimelineExport` used by the world client.
///
/// # Panics
///
/// Panics only if the in-memory CBOR writer fails.
#[must_use]
pub fn fixture_bytes() -> Vec<u8> {
    let events = [
        fixture_event(fixed_ulid(FIRST_EVENT_ID), 1, 0.5),
        fixture_event(fixed_ulid(SECOND_EVENT_ID), 2, 1.0),
    ];
    let export = TimelineExport {
        timeline: Timeline {
            meta: TimelineMeta {
                id: TimelineId::from_ulid(fixed_ulid(TIMELINE_ID)),
                mode: TimelineMode::Live,
                name: Some("world-client-fixture".to_owned()),
                fork_point: None,
            },
            head: Seq::from_u64(2),
        },
        events: events.to_vec(),
        parent_fork_hash: None,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&export, &mut bytes).expect("CBOR write to Vec is infallible");
    bytes
}

/// Decode and validate the stable world-client fixture boundary.
///
/// # Errors
///
/// Returns [`ClientError::Decode`] for malformed CBOR and
/// [`ClientError::Invalid`] for a decoded export outside the fixture contract.
pub fn decode_fixture(bytes: &[u8]) -> Result<TimelineExport, ClientError> {
    let export: TimelineExport =
        ciborium::from_reader(bytes).map_err(|error| ClientError::Decode(error.to_string()))?;
    validate_export(&export)?;
    Ok(export)
}

fn fixture_event(id: Ulid, seq: u64, value: f64) -> Event {
    let payload = signal_payload(value);
    Event {
        id: EventId::from_ulid(id),
        entity: EntityId::from_ulid(fixed_ulid(ENTITY_ID)),
        event_type: Kind::new("society.signal"),
        payload: CanonicalBytes::from_vec(payload.clone()),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: payload_hash(&payload),
    }
}

fn signal_payload(value: f64) -> Vec<u8> {
    let signal = Signal {
        dimension: "trust".to_owned(),
        value,
        subject: None,
        object: None,
    };
    let mut payload = Vec::new();
    ciborium::into_writer(&signal, &mut payload).expect("CBOR write to Vec is infallible");
    payload
}

fn payload_hash(payload: &[u8]) -> Hash {
    Hash::from_bytes(*blake3::hash(payload).as_bytes())
}

fn fixed_ulid(value: u128) -> Ulid {
    Ulid::from(value)
}

fn validate_export(export: &TimelineExport) -> Result<(), ClientError> {
    let timeline = &export.timeline;
    if timeline.meta.id != TimelineId::from_ulid(fixed_ulid(TIMELINE_ID))
        || timeline.meta.mode != TimelineMode::Live
        || timeline.meta.fork_point.is_some()
        || timeline.head != Seq::from_u64(2)
        || export.parent_fork_hash.is_some()
    {
        return Err(ClientError::Invalid(
            "timeline identity or root metadata".to_owned(),
        ));
    }
    if export.events.len() != 2 {
        return Err(ClientError::Invalid("expected two events".to_owned()));
    }
    for (index, event) in export.events.iter().enumerate() {
        let expected_seq = Seq::from_u64((index + 1) as u64);
        let expected_id = match index {
            0 => EventId::from_ulid(fixed_ulid(FIRST_EVENT_ID)),
            _ => EventId::from_ulid(fixed_ulid(SECOND_EVENT_ID)),
        };
        if event.id != expected_id
            || event.entity != EntityId::from_ulid(fixed_ulid(ENTITY_ID))
            || event.event_type != Kind::new("society.signal")
            || event.seq != expected_seq
            || event.wall_time != WallTime::from_micros((index + 1) as u64)
            || event.causation_id.is_some()
            || event.correlation_id.is_some()
            || event.schema_version != SchemaVersion::V1
            || event.signature.is_some()
            || event.payload_hash != payload_hash(event.payload.as_slice())
        {
            return Err(ClientError::Invalid("event fields".to_owned()));
        }
        let signal: Signal = ciborium::from_reader(event.payload.as_slice())
            .map_err(|error| ClientError::Invalid(format!("signal payload: {error}")))?;
        let expected_value = if index == 0 { 0.5 } else { 1.0 };
        if signal.dimension != "trust"
            || !signal.value.is_finite()
            || (signal.value - expected_value).abs() > f64::EPSILON
            || signal.subject.is_some()
            || signal.object.is_some()
        {
            return Err(ClientError::Invalid("signal payload fields".to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{decode_fixture, fixture_bytes};
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{Kind, SchemaVersion},
        ids::{EntityId, EventId, TimelineId},
        timeline::TimelineMode,
    };
    use ulid::Ulid;

    fn encode(export: &TimelineExport) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(export, &mut bytes).unwrap();
        bytes
    }

    fn decoded_fixture() -> TimelineExport {
        decode_fixture(&fixture_bytes()).unwrap()
    }

    #[test]
    fn fixture_bytes_are_deterministic() {
        assert_eq!(fixture_bytes(), fixture_bytes());
    }

    #[test]
    fn fixture_preserves_complete_event_fields() {
        let export = decoded_fixture();
        assert_eq!(export.events.len(), 2);
        assert_eq!(
            export.events[0].entity,
            EntityId::from_ulid(Ulid::from(2u128))
        );
        assert_eq!(export.events[1].entity, export.events[0].entity);
        for (index, event) in export.events.iter().enumerate() {
            assert_eq!(
                event.id,
                EventId::from_ulid(Ulid::from((index + 2) as u128))
            );
            assert_eq!(event.event_type, Kind::new("society.signal"));
            assert_eq!(event.schema_version, SchemaVersion::V1);
            assert_eq!(event.signature, None);
            assert_eq!(event.causation_id, None);
            assert_eq!(event.correlation_id, None);
            assert_eq!(event.wall_time, WallTime::from_micros((index + 1) as u64));
            assert_eq!(event.seq, Seq::from_u64((index + 1) as u64));
            assert_eq!(
                event.payload_hash,
                Hash::from_bytes(*blake3::hash(event.payload.as_slice()).as_bytes())
            );
            let signal: Signal = ciborium::from_reader(event.payload.as_slice()).unwrap();
            assert_eq!(signal.dimension, "trust");
            assert!((signal.value - [0.5, 1.0][index]).abs() <= f64::EPSILON);
            assert_eq!(signal.subject, None);
            assert_eq!(signal.object, None);
        }
    }

    #[test]
    fn fixture_round_trips_with_identity() {
        let export = decoded_fixture();
        let round_trip = decode_fixture(&encode(&export)).unwrap();
        assert_eq!(round_trip.timeline, export.timeline);
        assert_eq!(round_trip.events, export.events);
        assert_eq!(round_trip.parent_fork_hash, export.parent_fork_hash);
        assert_eq!(
            export.timeline.meta.id,
            TimelineId::from_ulid(Ulid::from(1u128))
        );
        assert_eq!(export.timeline.head, Seq::from_u64(2));
    }

    #[test]
    fn malformed_cbor_is_rejected() {
        assert!(decode_fixture(&[0xff, 0x00]).is_err());
    }

    #[test]
    fn wrong_timeline_identity_is_rejected() {
        let mut export = decoded_fixture();
        export.timeline.meta.id = TimelineId::from_ulid(Ulid::from(99u128));
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn wrong_root_mode_is_rejected() {
        let mut export = decoded_fixture();
        export.timeline.meta.mode = TimelineMode::Historical;
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn fork_metadata_on_root_is_rejected() {
        let mut export = decoded_fixture();
        export.timeline.meta.fork_point = Some((export.timeline.meta.id, Seq::from_u64(1)));
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn parent_fork_hash_on_root_is_rejected() {
        let mut export = decoded_fixture();
        export.parent_fork_hash = Some(Hash::from_bytes([1u8; 32]));
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn wrong_event_id_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].id = EventId::from_ulid(Ulid::from(99u128));
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn wrong_event_entity_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].entity = EntityId::from_ulid(Ulid::from(99u128));
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn wrong_event_wall_time_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].wall_time = WallTime::from_micros(99);
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn wrong_payload_hash_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].payload_hash = Hash::from_bytes([99u8; 32]);
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn malformed_signal_payload_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].payload = CanonicalBytes::from_vec(vec![0xff, 0x00]);
        export.events[0].payload_hash = payload_hash(export.events[0].payload.as_slice());
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn invalid_signal_dimension_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].payload = signal_payload_for_test("opinion", 0.5, None, None);
        export.events[0].payload_hash = payload_hash(export.events[0].payload.as_slice());
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn invalid_signal_value_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].payload = signal_payload_for_test("trust", 2.0, None, None);
        export.events[0].payload_hash = payload_hash(export.events[0].payload.as_slice());
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn invalid_signal_subject_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].payload = signal_payload_for_test("trust", 0.5, Some("subject"), None);
        export.events[0].payload_hash = payload_hash(export.events[0].payload.as_slice());
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn invalid_signal_object_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].payload = signal_payload_for_test("trust", 0.5, None, Some("object"));
        export.events[0].payload_hash = payload_hash(export.events[0].payload.as_slice());
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    fn signal_payload_for_test(
        dimension: &str,
        value: f64,
        subject: Option<&str>,
        object: Option<&str>,
    ) -> CanonicalBytes {
        let signal = Signal {
            dimension: dimension.to_owned(),
            value,
            subject: subject.map(str::to_owned),
            object: object.map(str::to_owned),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&signal, &mut payload).unwrap();
        CanonicalBytes::from_vec(payload)
    }

    #[test]
    fn wrong_event_type_is_rejected() {
        let mut export = decoded_fixture();
        export.events[0].event_type = Kind::new("world.action");
        assert!(decode_fixture(&encode(&export)).is_err());
    }

    #[test]
    fn non_contiguous_sequences_are_rejected() {
        let mut export = decoded_fixture();
        export.events[1].seq = Seq::from_u64(3);
        assert!(decode_fixture(&encode(&export)).is_err());
    }
}
