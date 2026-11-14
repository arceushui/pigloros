//! Independent CGI1/CIS1 wire oracles through public data boundaries.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDigestListV1 as Digests, CommunityInitializationProducerInputV1,
    CommunityInitializationProducerV1 as Producer, CommunityInitializationRequestInputV1,
    CommunityInitializationRequestV1 as Request, CommunityInitializationSourceV1 as Source,
    CommunityLifecycleErrorV1 as Error,
};
use pos_core::{Hash, Seq, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}
const fn timeline(value: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([value; 16]))
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
const fn reference(value: u8) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: 7,
        byte_length: 0,
        digest: [value; 32],
    }
}
fn reference_value(value: u8) -> Value {
    Value::Array(vec![uint(7), uint(0), bytes(&[value; 32])])
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| "expected test array".into())
}
fn independent_digest(domain: &[u8], wire: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(wire);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
const fn request_input(members: &[Hash]) -> CommunityInitializationRequestInputV1<'_> {
    CommunityInitializationRequestInputV1 {
        operation_id: [1; 16],
        timeline: timeline(2),
        generation: [3; 16],
        expected_prior_generation: None,
        expected_prior_head_digest: None,
        profile_digest: hash(4),
        member_binding_digests: Digests::from_digests(members),
        initial_source: Source::Initializer(reference(5)),
        principal_ref: reference(6),
        authorization_ref: reference(7),
        evidence_not_after_micros: 1000,
    }
}
fn request_value() -> Value {
    Value::Array(vec![
        bytes(b"CGI1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        bytes(&[3; 16]),
        Value::Null,
        Value::Null,
        bytes(&[4; 32]),
        Value::Array(vec![bytes(&[9; 32]), bytes(&[8; 32])]),
        Value::Array(vec![uint(0), reference_value(5)]),
        reference_value(6),
        reference_value(7),
        uint(1000),
    ])
}
const fn producer_input() -> CommunityInitializationProducerInputV1 {
    CommunityInitializationProducerInputV1 {
        generation_request_digest: hash(1),
        member_binding_digest: hash(2),
        initializer_ref: reference(3),
        state_content_digest: hash(4),
        scope_binding_digest: hash(5),
        evidence_not_after_micros: 1000,
    }
}
fn producer_value() -> Value {
    Value::Array(vec![
        bytes(b"CIS1"),
        uint(1),
        bytes(&[1; 32]),
        bytes(&[2; 32]),
        reference_value(3),
        bytes(&[4; 32]),
        bytes(&[5; 32]),
        uint(1000),
    ])
}

#[test]
fn request_preserves_exact_thirteen_fields_roster_order_and_borrowed_wire() -> TestResult {
    let members = [hash(9), hash(8)];
    let record = Request::new(request_input(&members))?;
    let expected = encode(&request_value())?;
    assert_eq!(&expected[..7], &[0x8d, 0x44, b'C', b'G', b'I', b'1', 1]);
    assert_eq!(record.to_canonical_cbor().as_slice(), expected);
    assert_eq!(
        record.digest(),
        independent_digest(b"PiglorOS.Community.CGI1.v1\0", &expected)
    );
    let decoded = Request::from_canonical_cbor(&expected)?;
    assert!(decoded.as_input() == record.as_input());
    assert_eq!(decoded.to_canonical_cbor().as_slice(), expected);
    let rows = decoded
        .as_input()
        .member_binding_digests
        .as_canonical_rows()
        .ok_or("not borrowed")?;
    assert_eq!(rows.len(), 68);
    assert!(std::ptr::eq(rows.as_ptr(), expected[95..].as_ptr()));
    assert!(record
        .as_input()
        .member_binding_digests
        .as_canonical_rows()
        .is_none());
    Ok(())
}

#[test]
fn all_initial_sources_and_predecessor_coordinates_have_independent_wire_shapes() -> TestResult {
    let members = [hash(9), hash(8)];
    for (source, source_wire) in [
        (
            Source::Initializer(reference(5)),
            Value::Array(vec![uint(0), reference_value(5)]),
        ),
        (
            Source::PriorState(hash(10)),
            Value::Array(vec![uint(1), bytes(&[10; 32])]),
        ),
        (
            Source::Fork {
                timeline: timeline(11),
                cut: Seq::from_u64(0),
                selected_head_digest: hash(12),
                operation_id: [13; 16],
            },
            Value::Array(vec![
                uint(2),
                bytes(&[11; 16]),
                uint(0),
                bytes(&[12; 32]),
                bytes(&[13; 16]),
            ]),
        ),
        (
            Source::Fork {
                timeline: timeline(11),
                cut: Seq::from_u64(u64::MAX),
                selected_head_digest: hash(12),
                operation_id: [13; 16],
            },
            Value::Array(vec![
                uint(2),
                bytes(&[11; 16]),
                uint(u64::MAX),
                bytes(&[12; 32]),
                bytes(&[13; 16]),
            ]),
        ),
    ] {
        let input = CommunityInitializationRequestInputV1 {
            expected_prior_generation: Some([14; 16]),
            expected_prior_head_digest: Some(hash(15)),
            initial_source: source,
            ..request_input(&members)
        };
        let record = Request::new(input)?;
        let mut expected = request_value();
        fields(&mut expected)?[5] = bytes(&[14; 16]);
        fields(&mut expected)?[6] = bytes(&[15; 32]);
        fields(&mut expected)?[9] = source_wire;
        let wire = encode(&expected)?;
        assert_eq!(record.to_canonical_cbor().as_slice(), wire);
        assert!(Request::from_canonical_cbor(&wire)?.as_input() == &input);
    }
    Ok(())
}

#[test]
fn request_rejects_missing_coordinates_links_predecessor_pair_and_source_bindings() {
    let members = [hash(9), hash(8)];
    let good = request_input(&members);
    for bad in [
        CommunityInitializationRequestInputV1 {
            operation_id: [0; 16],
            ..good
        },
        CommunityInitializationRequestInputV1 {
            timeline: timeline(0),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            generation: [0; 16],
            ..good
        },
        CommunityInitializationRequestInputV1 {
            profile_digest: Hash::zero(),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            expected_prior_generation: Some([0; 16]),
            expected_prior_head_digest: Some(hash(1)),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            expected_prior_generation: Some([1; 16]),
            expected_prior_head_digest: Some(Hash::zero()),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            expected_prior_generation: Some([1; 16]),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            expected_prior_head_digest: Some(hash(1)),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            principal_ref: reference(0),
            ..good
        },
        CommunityInitializationRequestInputV1 {
            authorization_ref: reference(0),
            ..good
        },
    ] {
        assert_eq!(Request::new(bad).err(), Some(Error::InvalidBinding));
    }
    for source in [
        Source::Initializer(reference(0)),
        Source::PriorState(Hash::zero()),
        Source::Fork {
            timeline: timeline(0),
            cut: Seq::from_u64(1),
            selected_head_digest: hash(1),
            operation_id: [1; 16],
        },
        Source::Fork {
            timeline: timeline(1),
            cut: Seq::from_u64(1),
            selected_head_digest: Hash::zero(),
            operation_id: [1; 16],
        },
        Source::Fork {
            timeline: timeline(1),
            cut: Seq::from_u64(1),
            selected_head_digest: hash(1),
            operation_id: [0; 16],
        },
    ] {
        assert_eq!(
            Request::new(CommunityInitializationRequestInputV1 {
                initial_source: source,
                ..good
            })
            .err(),
            Some(Error::InvalidBinding)
        );
    }
}

#[test]
fn roster_and_fixed_horizon_boundaries_do_not_sort_or_renew_records() -> TestResult {
    let maximum: Vec<_> = (1..=64).rev().map(hash).collect();
    let record = Request::new(request_input(&maximum))?;
    let wire = record.to_canonical_cbor();
    assert_eq!(
        Request::from_canonical_cbor(&wire)?
            .as_input()
            .member_binding_digests
            .len(),
        64
    );
    for (members, error) in [
        (Vec::new(), Error::BoundsExceeded),
        (vec![hash(1); 65], Error::BoundsExceeded),
        (vec![Hash::zero()], Error::InvalidBinding),
        (vec![hash(1), hash(1)], Error::InvalidBinding),
    ] {
        assert_eq!(Request::new(request_input(&members)).err(), Some(error));
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Request::new(CommunityInitializationRequestInputV1 {
                evidence_not_after_micros: horizon,
                ..request_input(&maximum)
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
        assert_eq!(
            Producer::new(CommunityInitializationProducerInputV1 {
                evidence_not_after_micros: horizon,
                ..producer_input()
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    for horizon in [1, u64::MAX / 2] {
        let request = Request::new(CommunityInitializationRequestInputV1 {
            evidence_not_after_micros: horizon,
            ..request_input(&maximum)
        })?;
        assert_eq!(
            Request::from_canonical_cbor(&request.to_canonical_cbor())?
                .as_input()
                .evidence_not_after_micros,
            horizon
        );
        let producer = Producer::new(CommunityInitializationProducerInputV1 {
            evidence_not_after_micros: horizon,
            ..producer_input()
        })?;
        assert_eq!(
            Producer::from_canonical_cbor(&producer.to_canonical_cbor())?
                .as_input()
                .evidence_not_after_micros,
            horizon
        );
    }
    Ok(())
}

#[test]
fn producer_preserves_exact_eight_fields_and_independent_digest_domain() -> TestResult {
    let record = Producer::new(producer_input())?;
    let expected = encode(&producer_value())?;
    assert_eq!(&expected[..7], &[0x88, 0x44, b'C', b'I', b'S', b'1', 1]);
    assert_eq!(record.to_canonical_cbor().as_slice(), expected);
    assert_eq!(
        record.digest(),
        independent_digest(b"PiglorOS.Community.CIS1.v1\0", &expected)
    );
    let decoded = Producer::from_canonical_cbor(&expected)?;
    assert!(decoded.as_input() == record.as_input());
    assert_eq!(decoded.to_canonical_cbor().as_slice(), expected);
    for bad in [
        CommunityInitializationProducerInputV1 {
            generation_request_digest: Hash::zero(),
            ..producer_input()
        },
        CommunityInitializationProducerInputV1 {
            member_binding_digest: Hash::zero(),
            ..producer_input()
        },
        CommunityInitializationProducerInputV1 {
            initializer_ref: reference(0),
            ..producer_input()
        },
        CommunityInitializationProducerInputV1 {
            state_content_digest: Hash::zero(),
            ..producer_input()
        },
        CommunityInitializationProducerInputV1 {
            scope_binding_digest: Hash::zero(),
            ..producer_input()
        },
    ] {
        assert_eq!(Producer::new(bad).err(), Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn decoders_refuse_every_truncation_changed_field_and_nonpreferred_header() -> TestResult {
    for (value, is_request, maximum) in [
        (request_value(), true, 65_536),
        (producer_value(), false, 1024),
    ] {
        let wire = encode(&value)?;
        let decode = |wire: &[u8]| {
            if is_request {
                Request::from_canonical_cbor(wire).map(|_| ())
            } else {
                Producer::from_canonical_cbor(wire).map(|_| ())
            }
        };
        for end in 0..wire.len() {
            assert!(decode(&wire[..end]).is_err(), "truncation {end}");
        }
        let mut changed = wire.clone();
        changed.push(0);
        assert_eq!(decode(&changed), Err(Error::InvalidEncoding));
        changed.resize(maximum, 0);
        assert_eq!(decode(&changed), Err(Error::InvalidEncoding));
        changed.push(0);
        assert_eq!(decode(&changed), Err(Error::BoundsExceeded));
        for index in 0..value.as_array().ok_or("array absent")?.len() {
            let mut changed = value.clone();
            fields(&mut changed)?[index] = Value::Bool(true);
            assert!(decode(&encode(&changed)?).is_err(), "field {index}");
        }
        let mut changed = value.clone();
        fields(&mut changed)?[1] = uint(2);
        assert_eq!(decode(&encode(&changed)?), Err(Error::UnsupportedVersion));
        let mut changed = wire.clone();
        changed.splice(6..7, [0x18, 1]);
        assert_eq!(decode(&changed), Err(Error::InvalidEncoding));
        let mut changed = wire.clone();
        changed.splice(1..2, [0x58, 4]);
        assert_eq!(decode(&changed), Err(Error::InvalidEncoding));
    }
    Ok(())
}

#[test]
fn decoder_checks_nested_source_list_and_reference_bounds_before_acceptance() -> TestResult {
    for source in [
        Value::Array(vec![uint(3), bytes(&[1; 32])]),
        Value::Array(vec![uint(0)]),
        Value::Array(vec![uint(1), bytes(&[0; 32])]),
        Value::Array(vec![uint(2), bytes(&[1; 16]), uint(0), bytes(&[1; 32])]),
    ] {
        let mut changed = request_value();
        fields(&mut changed)?[9] = source;
        assert!(Request::from_canonical_cbor(&encode(&changed)?).is_err());
    }
    for members in [
        Value::Array(vec![]),
        Value::Array(vec![bytes(&[1; 32]); 65]),
        Value::Array(vec![bytes(&[0; 32])]),
        Value::Array(vec![bytes(&[1; 31])]),
        Value::Array(vec![bytes(&[1; 32]); 2]),
    ] {
        let mut changed = request_value();
        fields(&mut changed)?[8] = members;
        assert!(Request::from_canonical_cbor(&encode(&changed)?).is_err());
    }
    let mut changed = request_value();
    fields(&mut changed)?[10] = Value::Array(vec![
        uint(u64::from(u32::MAX) + 1),
        uint(0),
        bytes(&[1; 32]),
    ]);
    assert_eq!(
        Request::from_canonical_cbor(&encode(&changed)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn producer_decoder_checks_semantic_links_and_full_reference_integer_range() -> TestResult {
    for index in [2, 3, 5, 6] {
        let mut changed = producer_value();
        fields(&mut changed)?[index] = bytes(&[0; 32]);
        assert_eq!(
            Producer::from_canonical_cbor(&encode(&changed)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut changed = producer_value();
    fields(&mut changed)?[4] = reference_value(0);
    assert_eq!(
        Producer::from_canonical_cbor(&encode(&changed)?).err(),
        Some(Error::InvalidBinding)
    );
    fields(&mut changed)?[4] = Value::Array(vec![
        uint(u64::from(u32::MAX) + 1),
        uint(0),
        bytes(&[3; 32]),
    ]);
    assert_eq!(
        Producer::from_canonical_cbor(&encode(&changed)?).err(),
        Some(Error::BoundsExceeded)
    );
    for horizon in [0, u64::MAX] {
        fields(&mut changed)?[4] = reference_value(3);
        fields(&mut changed)?[7] = uint(horizon);
        assert_eq!(
            Producer::from_canonical_cbor(&encode(&changed)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    let input = CommunityInitializationProducerInputV1 {
        initializer_ref: ArtifactRefV1 {
            schema_id: u32::MAX,
            byte_length: u64::MAX,
            digest: [3; 32],
        },
        ..producer_input()
    };
    let wire = Producer::new(input)?.to_canonical_cbor();
    assert!(Producer::from_canonical_cbor(&wire)?.as_input() == &input);
    Ok(())
}
