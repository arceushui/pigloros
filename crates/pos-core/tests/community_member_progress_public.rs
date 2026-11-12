//! Independent CMS1/IDP1 wire checks; no registry/owner authority is fabricated.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityCarriedEventV1 as Event, CommunityCarriedEventsV1 as Events,
    CommunityFactualNodeReferenceV1 as Node, CommunityLifecycleErrorV1 as Error,
    CommunityMemberProgressInputV1 as Input, CommunityMemberProgressV1 as Progress,
    CommunityProgressReferenceV1 as Reference, MAX_COMMUNITY_CARRIED_EVENTS_V1,
};
use pos_core::{DependencyNodeCoordinateV1, Hash, Seq, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
const fn event(t: u8, seq: u64, h: u8) -> Event {
    Event {
        timeline: timeline(t),
        seq: Seq::from_u64(seq),
        payload_hash: hash(h),
    }
}
const fn input(rows: &[Event]) -> Input<'_> {
    Input {
        member_binding_digest: hash(1),
        state_revision_digest: hash(2),
        last_step_simulation_time: None,
        forwarded_cursor: Seq::from_u64(7),
        carried_events: Events::from_events(rows),
        step_chain: Reference::None,
        history_input: Reference::Pending(hash(9)),
    }
}
const fn node(owner_id: &str) -> Node<'_> {
    Node {
        tick: 0,
        scheduler_position: 2,
        owner_id,
        output_ordinal: 3,
        schema_id: 1,
        artifact_digest: hash(10),
    }
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| "test array absent".into())
}
fn node_value(node: Node<'_>) -> Value {
    Value::Array(vec![
        uint(node.tick),
        uint(u64::from(node.scheduler_position)),
        Value::Text(node.owner_id.into()),
        uint(u64::from(node.output_ordinal)),
        uint(u64::from(node.schema_id)),
        bytes(node.artifact_digest.as_bytes()),
    ])
}
fn reference_value(reference: Reference<'_>) -> Fallible<Value> {
    Ok(match reference {
        Reference::None => Value::Array(vec![uint(0)]),
        Reference::Pending(hash) => Value::Array(vec![uint(1), bytes(hash.as_bytes())]),
        Reference::Factual(node) => Value::Array(vec![uint(2), bytes(&encode(&node_value(node))?)]),
    })
}
fn expected() -> Value {
    Value::Array(vec![
        bytes(b"CMS1"),
        uint(1),
        bytes(&[1; 32]),
        bytes(&[2; 32]),
        Value::Null,
        uint(7),
        Value::Array(vec![
            Value::Array(vec![bytes(&[3; 16]), uint(4), bytes(&[5; 32])]),
            Value::Array(vec![bytes(&[6; 16]), uint(7), bytes(&[8; 32])]),
        ]),
        Value::Array(vec![uint(0)]),
        Value::Array(vec![uint(1), bytes(&[9; 32])]),
    ])
}

fn assert_exact_encoding(record: &Progress<'_>, expected: &[u8]) {
    let encoded = record.to_canonical_cbor();
    assert_eq!(encoded.as_slice(), expected);
    // Verify the workspace's actual allocator profile has no unused capacity;
    // the portable owner must still account for an allocator that returns more.
    assert_eq!(encoded.capacity(), expected.len());
}

#[test]
fn exact_nine_field_record_and_borrowed_rows_have_an_independent_oracle() -> TestResult {
    let rows = [event(3, 4, 5), event(6, 7, 8)];
    let record = Progress::new(input(&rows))?;
    let wire = encode(&expected())?;
    assert_eq!(&wire[..7], &[0x89, 0x44, b'C', b'M', b'S', b'1', 1]);
    assert_exact_encoding(&record, &wire);
    let decoded = Progress::from_canonical_cbor(&wire)?;
    assert!(decoded.as_input() == record.as_input());
    assert_exact_encoding(&decoded, &wire);
    assert!(record
        .as_input()
        .carried_events
        .as_canonical_rows()
        .is_none());
    let encoded_rows = decoded
        .as_input()
        .carried_events
        .as_canonical_rows()
        .ok_or("rows copied")?;
    assert_eq!(encoded_rows.len(), 106);
    assert!(std::ptr::eq(encoded_rows.as_ptr(), wire[78..].as_ptr()));
    for events in [
        record.as_input().carried_events,
        decoded.as_input().carried_events,
    ] {
        assert!(!events.is_empty());
        assert_eq!(events.len(), 2);
        let mut iter = events.iter();
        assert_eq!(iter.size_hint(), (2, Some(2)));
        assert_eq!(iter.len(), 2);
        assert!(iter.next() == Some(Ok(rows[0])));
        assert!(iter.next() == Some(Ok(rows[1])));
        assert!(iter.next().is_none());
        assert_eq!(iter.size_hint(), (0, Some(0)));
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
        assert!(events.into_iter().next() == Some(Ok(rows[0])));
    }
    Ok(())
}

#[test]
fn all_reference_forms_and_absent_zero_or_maximum_step_time_remain_distinct() -> TestResult {
    let rows = [event(3, 4, 5), event(6, 7, 8)];
    let variants = [
        Reference::None,
        Reference::Pending(hash(11)),
        Reference::Factual(node("driver:test")),
    ];
    for step_chain in variants {
        for history_input in variants {
            for time in [None, Some(0), Some(u64::MAX)] {
                let data = Input {
                    last_step_simulation_time: time,
                    step_chain,
                    history_input,
                    ..input(&rows)
                };
                let record = Progress::new(data)?;
                let mut value = expected();
                fields(&mut value)?[4] = time.map_or(Value::Null, uint);
                fields(&mut value)?[7] = reference_value(step_chain)?;
                fields(&mut value)?[8] = reference_value(history_input)?;
                let wire = encode(&value)?;
                assert_exact_encoding(&record, &wire);
                let decoded = Progress::from_canonical_cbor(&wire)?;
                assert!(decoded.as_input() == &data);
                assert_exact_encoding(&decoded, &wire);
            }
        }
    }
    Ok(())
}

#[test]
fn progress_equality_distinguishes_original_event_identity_and_count() -> TestResult {
    let rows = [event(3, 4, 5), event(6, 7, 8)];
    let original = Progress::new(input(&rows))?;
    let wire = original.to_canonical_cbor();
    let decoded = Progress::from_canonical_cbor(&wire)?;
    for changed in [
        vec![event(3, 4, 5)],
        vec![event(3, 4, 5), event(6, 7, 9)],
        vec![event(3, 4, 5), event(6, 8, 8)],
        vec![event(3, 4, 5), event(7, 7, 8)],
    ] {
        let different = Progress::new(input(&changed))?;
        let different_wire = different.to_canonical_cbor();
        let different_decoded = Progress::from_canonical_cbor(&different_wire)?;
        for left in [original.as_input(), decoded.as_input()] {
            for right in [different.as_input(), different_decoded.as_input()] {
                assert!(left != right);
                assert!(right != left);
            }
        }
    }
    Ok(())
}

#[test]
fn recorded_reference_borrows_existing_idp1_coordinate_and_decoded_owner() -> TestResult {
    let coordinate =
        DependencyNodeCoordinateV1::try_new(0, 2, "driver:test".into(), 3, 1, hash(10))?;
    let reference = Node::from_coordinate(&coordinate);
    assert!(reference == node("driver:test"));
    assert!(std::ptr::eq(
        reference.owner_id.as_ptr(),
        coordinate.owner_id().as_ptr()
    ));
    let record = Progress::new(Input {
        step_chain: Reference::Factual(reference),
        ..input(&[])
    })?;
    let wire = record.to_canonical_cbor();
    let decoded = Progress::from_canonical_cbor(&wire)?;
    let Reference::Factual(actual) = decoded.as_input().step_chain else {
        return Err("node absent".into());
    };
    assert!(actual == reference);
    let position = wire
        .windows(11)
        .position(|bytes| bytes == b"driver:test")
        .ok_or("owner absent")?;
    assert!(std::ptr::eq(
        actual.owner_id.as_ptr(),
        wire[position..].as_ptr()
    ));
    Ok(())
}

#[test]
fn every_integer_width_and_utf8_owner_byte_bound_fits_nested_framing() -> TestResult {
    let owner = "é".repeat(64);
    for tick in [
        0,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let factual = Node {
            tick,
            scheduler_position: u32::MAX,
            owner_id: &owner,
            output_ordinal: u32::MAX,
            schema_id: u32::MAX,
            artifact_digest: hash(10),
        };
        let data = Input {
            last_step_simulation_time: Some(tick),
            forwarded_cursor: Seq::from_u64(tick),
            step_chain: Reference::Factual(factual),
            history_input: Reference::Factual(factual),
            ..input(&[])
        };
        let record = Progress::new(data)?;
        let mut value = expected();
        fields(&mut value)?[4] = uint(tick);
        fields(&mut value)?[5] = uint(tick);
        fields(&mut value)?[6] = Value::Array(vec![]);
        fields(&mut value)?[7] = reference_value(data.step_chain)?;
        fields(&mut value)?[8] = reference_value(data.history_input)?;
        let wire = encode(&value)?;
        assert_exact_encoding(&record, &wire);
        let decoded = Progress::from_canonical_cbor(&wire)?;
        assert!(decoded.as_input() == &data);
        assert_exact_encoding(&decoded, &wire);
        assert!(decoded.as_input().carried_events.is_empty());
        assert_eq!(
            decoded.as_input().carried_events.iter().size_hint(),
            (0, Some(0))
        );
    }
    Ok(())
}

#[test]
fn maximum_carried_set_and_maximum_coordinates_fit_the_enclosing_record() -> TestResult {
    assert_eq!(MAX_COMMUNITY_CARRIED_EVENTS_V1, 3836);
    let rows: Vec<_> = (0..3836)
        .map(|index| event(3, u64::MAX - 3835 + index, 5))
        .collect();
    let owner = "é".repeat(64);
    let factual = Node {
        tick: u64::MAX,
        scheduler_position: u32::MAX,
        owner_id: &owner,
        output_ordinal: u32::MAX,
        schema_id: u32::MAX,
        artifact_digest: hash(10),
    };
    assert_eq!(encode(&node_value(factual))?.len(), 189);
    let data = Input {
        last_step_simulation_time: Some(u64::MAX),
        forwarded_cursor: Seq::from_u64(u64::MAX),
        step_chain: Reference::Factual(factual),
        history_input: Reference::Factual(factual),
        ..input(&rows)
    };
    let record = Progress::new(data)?;
    let wire = record.to_canonical_cbor();
    // Literal preferred field/header widths: 96 fixed bytes, 3836*61, two193-byte refs.
    assert_eq!(wire.len(), 234_478);
    assert_eq!(wire.capacity(), wire.len());
    assert!(wire.len() < 1_048_576);
    assert!(Progress::from_canonical_cbor(&wire)?.as_input() == &data);
    let too_many = vec![event(3, 1, 5); 3837];
    assert_eq!(
        Progress::new(input(&too_many)).err(),
        Some(Error::BoundsExceeded)
    );
    let mut value = expected();
    fields(&mut value)?[6] = Value::Array(vec![
        Value::Array(vec![
            bytes(&[3; 16]),
            uint(1),
            bytes(&[5; 32])
        ]);
        3837
    ]);
    assert_eq!(
        Progress::from_canonical_cbor(&encode(&value)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn smallest_factual_coordinate_preserves_the_two_byte_nested_header() -> TestResult {
    let factual = Node {
        tick: 0,
        scheduler_position: 0,
        owner_id: "x",
        output_ordinal: 0,
        schema_id: 1,
        artifact_digest: hash(10),
    };
    assert_eq!(encode(&node_value(factual))?.len(), 41);
    let data = Input {
        step_chain: Reference::Factual(factual),
        history_input: Reference::Factual(factual),
        ..input(&[])
    };
    let record = Progress::new(data)?;
    let mut value = expected();
    fields(&mut value)?[6] = Value::Array(vec![]);
    fields(&mut value)?[7] = reference_value(data.step_chain)?;
    fields(&mut value)?[8] = reference_value(data.history_input)?;
    let wire = encode(&value)?;
    assert_eq!(wire.len(), 168);
    assert_exact_encoding(&record, &wire);
    let decoded = Progress::from_canonical_cbor(&wire)?;
    assert!(decoded.as_input() == &data);
    assert_exact_encoding(&decoded, &wire);
    Ok(())
}

#[test]
fn zero_links_invalid_events_and_conflicting_or_descending_event_keys_refuse() {
    assert_eq!(
        Progress::new(Input {
            member_binding_digest: Hash::zero(),
            ..input(&[])
        })
        .err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Progress::new(Input {
            state_revision_digest: Hash::zero(),
            ..input(&[])
        })
        .err(),
        Some(Error::InvalidBinding)
    );
    for rows in [
        vec![event(0, 1, 5)],
        vec![event(3, 0, 5)],
        vec![event(3, 1, 0)],
        vec![event(3, 1, 5), event(3, 1, 5)],
        vec![event(3, 1, 5), event(3, 1, 6)],
        vec![event(3, 2, 5), event(3, 1, 5)],
        vec![event(6, 1, 5), event(3, 2, 5)],
    ] {
        assert_eq!(
            Progress::new(input(&rows)).err(),
            Some(Error::InvalidBinding)
        );
    }
}

#[test]
fn pending_and_recorded_references_validate_each_slot_without_inventing_authority() {
    let long_owner = "x".repeat(129);
    for reference in [
        Reference::Pending(Hash::zero()),
        Reference::Factual(Node {
            owner_id: "",
            ..node("driver:test")
        }),
        Reference::Factual(Node {
            owner_id: &long_owner,
            ..node("driver:test")
        }),
        Reference::Factual(Node {
            schema_id: 0,
            ..node("driver:test")
        }),
        Reference::Factual(Node {
            artifact_digest: Hash::zero(),
            ..node("driver:test")
        }),
    ] {
        assert_eq!(
            Progress::new(Input {
                step_chain: reference,
                ..input(&[])
            })
            .err(),
            Some(Error::InvalidBinding)
        );
        assert_eq!(
            Progress::new(Input {
                history_input: reference,
                ..input(&[])
            })
            .err(),
            Some(Error::InvalidBinding)
        );
    }
}

#[test]
fn decoder_rejects_small_record_truncation_each_field_and_nonpreferred_framing() -> TestResult {
    let wire = encode(&expected())?;
    for length in 0..wire.len() {
        assert!(
            Progress::from_canonical_cbor(&wire[..length]).is_err(),
            "prefix {length}"
        );
    }
    for index in 0..9 {
        let mut value = expected();
        fields(&mut value)?[index] = Value::Bool(true);
        assert!(
            Progress::from_canonical_cbor(&encode(&value)?).is_err(),
            "field {index}"
        );
    }
    let mut value = expected();
    fields(&mut value)?[1] = uint(2);
    assert_eq!(
        Progress::from_canonical_cbor(&encode(&value)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut extra = wire.clone();
    extra.push(0);
    assert_eq!(
        Progress::from_canonical_cbor(&extra).err(),
        Some(Error::InvalidEncoding)
    );
    extra.resize(1_048_576, 0);
    assert_eq!(
        Progress::from_canonical_cbor(&extra).err(),
        Some(Error::InvalidEncoding)
    );
    extra.push(0);
    assert_eq!(
        Progress::from_canonical_cbor(&extra).err(),
        Some(Error::BoundsExceeded)
    );
    for (range, replacement) in [
        (0..1, vec![0x98, 9]),
        (1..2, vec![0x58, 4]),
        (6..7, vec![0x18, 1]),
    ] {
        let mut changed = wire.clone();
        changed.splice(range, replacement);
        assert_eq!(
            Progress::from_canonical_cbor(&changed).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn decoder_validates_nested_coordinate_and_reference_governance() -> TestResult {
    for reference in [
        Value::Array(vec![uint(0), uint(0)]),
        Value::Array(vec![uint(1)]),
        Value::Array(vec![uint(3), bytes(&[1; 32])]),
        Value::Array(vec![uint(1), bytes(&[0; 32])]),
        Value::Array(vec![uint(2), bytes(&[0; 190])]),
        Value::Array(vec![uint(2), bytes(&[])]),
    ] {
        let mut value = expected();
        fields(&mut value)?[7] = reference;
        assert!(Progress::from_canonical_cbor(&encode(&value)?).is_err());
    }
    for index in 0..6 {
        let mut coordinate = node_value(node("driver:test"));
        fields(&mut coordinate)?[index] = Value::Bool(true);
        let mut value = expected();
        fields(&mut value)?[8] = Value::Array(vec![uint(2), bytes(&encode(&coordinate)?)]);
        assert!(
            Progress::from_canonical_cbor(&encode(&value)?).is_err(),
            "node field {index}"
        );
    }
    for index in [1, 3, 4] {
        let mut coordinate = node_value(node("driver:test"));
        fields(&mut coordinate)?[index] = uint(u64::from(u32::MAX) + 1);
        let mut value = expected();
        fields(&mut value)?[8] = Value::Array(vec![uint(2), bytes(&encode(&coordinate)?)]);
        assert_eq!(
            Progress::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    let mut coordinate = encode(&node_value(node("driver:test")))?;
    coordinate.push(0);
    let mut value = expected();
    fields(&mut value)?[7] = Value::Array(vec![uint(2), bytes(&coordinate)]);
    assert_eq!(
        Progress::from_canonical_cbor(&encode(&value)?).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn factual_reference_byte_limit_refuses_before_parsing_either_nested_payload() -> TestResult {
    for slot in [7, 8] {
        let mut value = expected();
        // One over the existing IDP1 maximum, with intentionally malformed
        // content: the encoded-byte bound must win over nested parsing.
        fields(&mut value)?[slot] = Value::Array(vec![uint(2), bytes(&[0; 190])]);
        assert_eq!(
            Progress::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn event_sequence_widths_use_one_exact_allocation_for_typed_and_decoded_rows() -> TestResult {
    for sequence in [
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let rows = [event(3, sequence, 5)];
        let record = Progress::new(input(&rows))?;
        let mut value = expected();
        fields(&mut value)?[6] = Value::Array(vec![Value::Array(vec![
            bytes(&[3; 16]),
            uint(sequence),
            bytes(&[5; 32]),
        ])]);
        let wire = encode(&value)?;
        assert_exact_encoding(&record, &wire);
        let decoded = Progress::from_canonical_cbor(&wire)?;
        assert_exact_encoding(&decoded, &wire);
    }
    Ok(())
}

#[test]
fn nested_idp1_requires_preferred_framing_and_valid_bounded_utf8() -> TestResult {
    let original = encode(&node_value(node("driver:test")))?;
    // Six fields, Tick zero, schedule two, then an eleven-byte owner text.
    assert_eq!(&original[..4], &[0x86, 0, 2, 0x6b]);
    for (range, replacement) in [
        (0..1, vec![0x98, 6]),
        (1..2, vec![0x18, 0]),
        (3..4, vec![0x78, 11]),
        (4..5, vec![0xff]),
    ] {
        let mut coordinate = original.clone();
        coordinate.splice(range, replacement);
        let mut value = expected();
        fields(&mut value)?[7] = Value::Array(vec![uint(2), bytes(&coordinate)]);
        assert_eq!(
            Progress::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    for owner in [String::new(), "x".repeat(129)] {
        let coordinate = encode(&node_value(node(&owner)))?;
        let mut value = expected();
        fields(&mut value)?[8] = Value::Array(vec![uint(2), bytes(&coordinate)]);
        assert!(Progress::from_canonical_cbor(&encode(&value)?).is_err());
    }
    Ok(())
}
