//! Independent CIV1 byte oracles. Data fields never certify actual execution.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityInvocationEvidenceInputV1 as Input, CommunityInvocationEvidenceV1 as Evidence,
    CommunityLifecycleErrorV1 as Error, CommunityOutputUsageV1 as Usage,
    CommunityPassKeyV1 as Pass, MeteringV1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
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
fn pass_value() -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ])
}
fn input() -> Fallible<Input> {
    Ok(Input {
        pass_key: Pass::new(
            TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
            [2; 16],
            3,
        )?,
        member_binding_digest: hash(4),
        invocation_id: [5; 16],
        negotiated_tuple_digest: hash(6),
        prepared_invocation_digest: hash(7),
        validated_output_digest: hash(8),
        metering: MeteringV1 {
            startup_fuel: 9,
            call_fuel: 10,
            memory_bytes: 11,
            host_calls: 12,
        },
        output_usage: Usage {
            event_count: 13,
            event_payload_bytes: 14,
            state_bytes: 15,
        },
        validated_annotation_count: 16,
        next_state_content_digest: hash(17),
        event_draft_vector_digest: hash(18),
    })
}
fn fixture() -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CIV1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        bytes(&[4; 32]),
        bytes(&[5; 16]),
        bytes(&[6; 32]),
        bytes(&[7; 32]),
        bytes(&[8; 32]),
        Value::Array((9..=12).map(uint).collect()),
        Value::Array((13..=15).map(uint).collect()),
        Value::Null,
        Value::Null,
        uint(16),
        bytes(&[17; 32]),
        bytes(&[18; 32]),
    ]))
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}

#[test]
fn invocation_has_exact_fifteen_fields_and_all_seven_measurements() -> TestResult {
    let input = input()?;
    let evidence = Evidence::new(input)?;
    let expected = encode(&fixture()?)?;
    assert_eq!(&*evidence.to_canonical_cbor(), &expected);
    assert!(*Evidence::from_canonical_cbor(&expected)?.as_input() == input);
    let mut preimage = b"PiglorOS.Community.CIV1.v1\0".to_vec();
    preimage.extend_from_slice(&expected);
    assert_eq!(
        evidence.digest(),
        Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
    );
    Ok(())
}

#[test]
fn zero_event_state_only_success_keeps_complete_measurement_arrays() -> TestResult {
    let input = Input {
        metering: MeteringV1 {
            startup_fuel: 0,
            call_fuel: 0,
            memory_bytes: 0,
            host_calls: 0,
        },
        output_usage: Usage {
            event_count: 0,
            event_payload_bytes: 0,
            state_bytes: 0,
        },
        validated_annotation_count: 0,
        ..input()?
    };
    let mut expected = fixture()?;
    let fields = fields(&mut expected)?;
    fields[8] = Value::Array(vec![uint(0); 4]);
    fields[9] = Value::Array(vec![uint(0); 3]);
    fields[12] = uint(0);
    let evidence = Evidence::new(input)?;
    assert_eq!(&*evidence.to_canonical_cbor(), &encode(&expected)?);
    assert!(*Evidence::from_canonical_cbor(&evidence.to_canonical_cbor())?.as_input() == input);
    Ok(())
}

#[test]
fn measurements_preserve_every_u64_width_without_narrowing_or_summing() -> TestResult {
    for value in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX,
    ] {
        let input = Input {
            metering: MeteringV1 {
                startup_fuel: value,
                call_fuel: value,
                memory_bytes: value,
                host_calls: value,
            },
            output_usage: Usage {
                event_count: value,
                event_payload_bytes: value,
                state_bytes: value,
            },
            validated_annotation_count: value,
            ..input()?
        };
        let evidence = Evidence::new(input)?;
        let bytes = evidence.to_canonical_cbor();
        assert!(*Evidence::from_canonical_cbor(&bytes)?.as_input() == input);
        let mut expected = fixture()?;
        let fields = fields(&mut expected)?;
        fields[8] = Value::Array(vec![uint(value); 4]);
        fields[9] = Value::Array(vec![uint(value); 3]);
        fields[12] = uint(value);
        assert_eq!(&*bytes, &encode(&expected)?);
    }
    // Wire round trips do not validate effective CNT1 limits or actual usage.
    Ok(())
}

#[test]
fn invocation_rejects_every_zero_identity() -> TestResult {
    for index in 0..7 {
        let mut input = input()?;
        match index {
            0 => input.member_binding_digest = Hash::zero(),
            1 => input.invocation_id = [0; 16],
            2 => input.negotiated_tuple_digest = Hash::zero(),
            3 => input.prepared_invocation_digest = Hash::zero(),
            4 => input.validated_output_digest = Hash::zero(),
            5 => input.next_state_content_digest = Hash::zero(),
            _ => input.event_draft_vector_digest = Hash::zero(),
        }
        assert_eq!(Evidence::new(input).err(), Some(Error::InvalidBinding));
    }
    for (index, value) in [
        (3, bytes(&[0; 32])),
        (4, bytes(&[0; 16])),
        (5, bytes(&[0; 32])),
        (6, bytes(&[0; 32])),
        (7, bytes(&[0; 32])),
        (13, bytes(&[0; 32])),
        (14, bytes(&[0; 32])),
    ] {
        let mut fixture = fixture()?;
        fields(&mut fixture)?[index] = value;
        assert_eq!(
            Evidence::from_canonical_cbor(&encode(&fixture)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn invocation_rejects_null_incomplete_and_noninteger_measurements() -> TestResult {
    for (index, count) in [(8, 4), (9, 3)] {
        for replacement in [
            Value::Null,
            Value::Array(vec![]),
            Value::Array(vec![uint(0); count - 1]),
            Value::Array(vec![uint(0); count + 1]),
        ] {
            let mut fixture = fixture()?;
            fields(&mut fixture)?[index] = replacement;
            assert_eq!(
                Evidence::from_canonical_cbor(&encode(&fixture)?).err(),
                Some(Error::InvalidEncoding)
            );
        }
        for member in 0..count {
            let mut values = vec![uint(0); count];
            values[member] = Value::Null;
            let mut fixture = fixture()?;
            fields(&mut fixture)?[index] = Value::Array(values);
            assert_eq!(
                Evidence::from_canonical_cbor(&encode(&fixture)?).err(),
                Some(Error::InvalidEncoding)
            );
        }
    }
    Ok(())
}

#[test]
fn invocation_requires_both_failure_fields_null() -> TestResult {
    for index in [10, 11] {
        for value in [
            uint(0),
            bytes(&[]),
            Value::Array(vec![uint(0)]),
            Value::Bool(false),
        ] {
            let mut fixture = fixture()?;
            fields(&mut fixture)?[index] = value;
            assert_eq!(
                Evidence::from_canonical_cbor(&encode(&fixture)?).err(),
                Some(Error::InvalidEncoding)
            );
        }
    }
    Ok(())
}

#[test]
fn invocation_rejects_malformed_pass_and_identity_shapes() -> TestResult {
    for (index, value) in [
        (2, bytes(&[])),
        (3, bytes(&[4; 31])),
        (4, bytes(&[5; 17])),
        (12, Value::Null),
        (13, bytes(&[17; 33])),
    ] {
        let mut fixture = fixture()?;
        fields(&mut fixture)?[index] = value;
        assert_eq!(
            Evidence::from_canonical_cbor(&encode(&fixture)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut pass = pass_value();
    fields(&mut pass)?[4] = uint(0);
    let mut fixture = fixture()?;
    fields(&mut fixture)?[2] = bytes(&encode(&pass)?);
    assert_eq!(
        Evidence::from_canonical_cbor(&encode(&fixture)?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn invocation_rejects_truncations_trailing_versions_and_nonpreferred() -> TestResult {
    let encoded = encode(&fixture()?)?;
    for end in 0..encoded.len() {
        assert!(Evidence::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Evidence::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = fixture()?;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Evidence::from_canonical_cbor(&encode(&unsupported)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Evidence::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Evidence::from_canonical_cbor(&vec![0; 4097]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
