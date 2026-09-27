use std::fmt::Write;

use ciborium::Value;
use pos_core::{
    CanonicalBytes, CorrelationId, EntityId, EventId, KeyIdentityV1, KeyRoleV1, Kind, OwnerIdV1,
    Seq, TimelineEventEnvelopeErrorV1 as EnvelopeError, TimelineEventEnvelopeInputV1,
    TimelineEventEnvelopeV1, TimelineId, WallTime, MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1,
    MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1,
};
use ulid::Ulid;

fn input() -> TimelineEventEnvelopeInputV1 {
    TimelineEventEnvelopeInputV1 {
        identity: KeyIdentityV1::new("alice", KeyRoleV1::TimelineIntegritySigning, 1),
        origin_timeline_id: TimelineId::from_ulid(Ulid::from_bytes([1; 16])),
        event_id: EventId::from_ulid(Ulid::from_bytes([2; 16])),
        origin_logical_seq: Seq::from_u64(24),
        entity_id: EntityId::from_ulid(Ulid::from_bytes([3; 16])),
        event_type: Kind::new("demo.event"),
        schema_version: 1,
        wall_time: WallTime::from_micros(0),
        causation_id: None,
        correlation_id: None,
    }
}

const fn payload() -> CanonicalBytes {
    CanonicalBytes::from_static(b"abc")
}

fn replace_field(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(bytes)?;
    let Value::Array(ref mut fields) = value else {
        return Err("expected array fixture".into());
    };
    fields[index] = replacement;
    let mut changed = Vec::new();
    ciborium::into_writer(&value, &mut changed)?;
    Ok(changed)
}

#[test]
fn exact_public_bytes_and_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let input = input();
    let envelope = TimelineEventEnvelopeV1::new(input.clone(), &payload())?;
    assert_eq!(envelope.input(), &input);
    assert_eq!(envelope.identity(), input.identity);
    assert_eq!(
        envelope.payload_hash(),
        pos_core::Hash::from_bytes([
            0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a,
            0x8d, 0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c,
            0xd5, 0xbd, 0x9d, 0x85,
        ])
    );
    let mut actual = String::new();
    for byte in envelope.canonical_bytes() {
        write!(&mut actual, "{byte:02x}")?;
    }
    assert_eq!(
        actual,
        concat!(
            "8e58237069676c6f726f732f74696d656c696e652d6576656e742d656e76656c6f70652f7631",
            "65616c69636550010101010101010101010101010101015002020202020202020202020202020202",
            "181850030303030303030303030303030303036a64656d6f2e6576656e740100f6f65820",
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d850201"
        )
    );
    let decoded = TimelineEventEnvelopeV1::from_canonical_bytes(envelope.canonical_bytes())?;
    assert_eq!(decoded, envelope);
    decoded.validate_payload(&payload())?;
    Ok(())
}

#[test]
fn public_encoder_covers_integer_widths_optional_ids_and_maximum_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    for value in [1, 24, 256, 65_536, 4_294_967_296, u64::MAX] {
        let mut fields = input();
        fields.origin_logical_seq = Seq::from_u64(value);
        fields.identity = KeyIdentityV1::new("alice", KeyRoleV1::TimelineIntegritySigning, value);
        fields.wall_time = WallTime::from_micros(value);
        let encoded = TimelineEventEnvelopeV1::new(fields, &payload())?;
        assert_eq!(
            TimelineEventEnvelopeV1::from_canonical_bytes(encoded.canonical_bytes())?,
            encoded
        );
    }
    let mut fields = input();
    fields.causation_id = Some(EventId::from_ulid(Ulid::from_bytes([4; 16])));
    fields.correlation_id = Some(CorrelationId::from_ulid(Ulid::from_bytes([5; 16])));
    fields.schema_version = u32::MAX;
    let encoded = TimelineEventEnvelopeV1::new(fields, &payload())?;
    assert_eq!(
        TimelineEventEnvelopeV1::from_canonical_bytes(encoded.canonical_bytes())?,
        encoded
    );
    let mut largest = input();
    largest.identity = KeyIdentityV1::from_parts(
        OwnerIdV1::new("a".repeat(128))?,
        KeyRoleV1::TimelineIntegritySigning,
        1,
    );
    largest.event_type = Kind::new("e".repeat(256));
    largest.causation_id = Some(EventId::from_ulid(Ulid::from_bytes([4; 16])));
    largest.correlation_id = Some(CorrelationId::from_ulid(Ulid::from_bytes([5; 16])));
    assert_eq!(
        TimelineEventEnvelopeV1::new(largest, &payload()),
        Err(EnvelopeError::FieldOutOfBounds)
    );
    assert!(encoded.canonical_bytes().len() <= MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1);
    Ok(())
}

#[test]
fn constructor_rejects_invalid_finalized_fields_and_payload() {
    let mut fields = input();
    fields.identity = KeyIdentityV1::new("alice", KeyRoleV1::SubjectAttributionSigning, 1);
    assert_eq!(
        TimelineEventEnvelopeV1::new(fields, &payload()),
        Err(EnvelopeError::InvalidIdentity)
    );
    let mut fields = input();
    fields.identity = KeyIdentityV1::new("alice", KeyRoleV1::TimelineIntegritySigning, 0);
    assert_eq!(
        TimelineEventEnvelopeV1::new(fields, &payload()),
        Err(EnvelopeError::InvalidIdentity)
    );
    for fields in [
        TimelineEventEnvelopeInputV1 {
            origin_logical_seq: Seq::ZERO,
            ..input()
        },
        TimelineEventEnvelopeInputV1 {
            schema_version: 0,
            ..input()
        },
        TimelineEventEnvelopeInputV1 {
            event_type: Kind::new(""),
            ..input()
        },
        TimelineEventEnvelopeInputV1 {
            event_type: Kind::new("e".repeat(257)),
            ..input()
        },
    ] {
        assert_eq!(
            TimelineEventEnvelopeV1::new(fields, &payload()),
            Err(EnvelopeError::FieldOutOfBounds)
        );
    }
    let oversized = CanonicalBytes::from_vec(vec![0; MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1 + 1]);
    assert_eq!(
        TimelineEventEnvelopeV1::new(input(), &oversized),
        Err(EnvelopeError::FieldOutOfBounds)
    );
}

#[test]
fn decoder_rejects_wrong_shape_types_and_identity() -> Result<(), Box<dyn std::error::Error>> {
    let original = TimelineEventEnvelopeV1::new(input(), &payload())?;
    let bytes = original.canonical_bytes();
    assert_eq!(
        TimelineEventEnvelopeV1::from_canonical_bytes(&[]),
        Err(EnvelopeError::InvalidEncoding)
    );
    assert_eq!(
        TimelineEventEnvelopeV1::from_canonical_bytes(&[0xf6]),
        Err(EnvelopeError::InvalidEncoding)
    );
    assert_eq!(
        TimelineEventEnvelopeV1::from_canonical_bytes(&[0x80]),
        Err(EnvelopeError::InvalidEncoding)
    );
    let wrong = [
        (0, Value::Bytes(b"wrong-domain".to_vec())),
        (1, Value::Integer(1.into())),
        (2, Value::Bytes(vec![0; 15])),
        (3, Value::Null),
        (4, Value::Integer((-1).into())),
        (5, Value::Text("entity".into())),
        (6, Value::Bytes(b"kind".to_vec())),
        (7, Value::Null),
        (8, Value::Null),
        (9, Value::Bytes(vec![0; 15])),
        (10, Value::Text("correlation".into())),
        (11, Value::Bytes(vec![0; 31])),
        (12, Value::Text("role".into())),
        (13, Value::Null),
    ];
    for (index, replacement) in wrong {
        let changed = replace_field(bytes, index, replacement)?;
        assert!(TimelineEventEnvelopeV1::from_canonical_bytes(&changed).is_err());
    }
    for role in [1_u64, 256] {
        let changed = replace_field(bytes, 12, Value::Integer(role.into()))?;
        assert_eq!(
            TimelineEventEnvelopeV1::from_canonical_bytes(&changed),
            Err(EnvelopeError::InvalidIdentity)
        );
    }
    Ok(())
}

#[test]
fn decoder_rejects_noncanonical_and_out_of_bounds_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let original = TimelineEventEnvelopeV1::new(input(), &payload())?;
    let bytes = original.canonical_bytes();
    let mut overlong_epoch = bytes.to_vec();
    assert_eq!(overlong_epoch.pop(), Some(1));
    overlong_epoch.extend_from_slice(&[0x18, 1]);
    assert_eq!(
        TimelineEventEnvelopeV1::from_canonical_bytes(&overlong_epoch),
        Err(EnvelopeError::NonCanonical)
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(TimelineEventEnvelopeV1::from_canonical_bytes(&trailing).is_err());
    assert_eq!(
        TimelineEventEnvelopeV1::from_canonical_bytes(&vec![
            0;
            MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1
                + 1
        ]),
        Err(EnvelopeError::FieldOutOfBounds)
    );
    for (index, replacement) in [
        (1, Value::Text(String::new())),
        (1, Value::Text("a".repeat(129))),
        (4, Value::Integer(0.into())),
        (6, Value::Text("e".repeat(257))),
        (7, Value::Integer(0.into())),
        (7, Value::Integer((u64::from(u32::MAX) + 1).into())),
        (13, Value::Integer(0.into())),
    ] {
        let changed = replace_field(bytes, index, replacement)?;
        assert!(
            TimelineEventEnvelopeV1::from_canonical_bytes(&changed).is_err(),
            "field {index} should fail"
        );
    }
    let changed = replace_field(bytes, 11, Value::Bytes(vec![99; 32]))?;
    let decoded = TimelineEventEnvelopeV1::from_canonical_bytes(&changed)?;
    assert_eq!(
        decoded.validate_payload(&payload()),
        Err(EnvelopeError::PayloadHashMismatch)
    );
    assert_eq!(
        original.validate_payload(&CanonicalBytes::from_static(b"different")),
        Err(EnvelopeError::PayloadHashMismatch)
    );
    let oversized = CanonicalBytes::from_vec(vec![0; MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1 + 1]);
    assert_eq!(
        original.validate_payload(&oversized),
        Err(EnvelopeError::FieldOutOfBounds)
    );
    Ok(())
}
