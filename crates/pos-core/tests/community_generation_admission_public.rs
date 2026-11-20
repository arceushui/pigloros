//! Independent CGA1 wire and local-binding checks, without owner authority.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityGenerationAdmissionInputV1 as Input, CommunityGenerationAdmissionV1 as Admission,
    CommunityLifecycleErrorV1 as Error,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
const fn input() -> Input {
    Input {
        generation_request_digest: hash(1),
        timeline: timeline(2),
        generation: [3; 16],
        initial_selected_head_digest: hash(4),
        graph_root_ref: hash(5),
        evidence_not_after_micros: 1000,
    }
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn fields() -> Vec<Value> {
    vec![
        bytes(b"CGA1"),
        uint(1),
        bytes(&[1; 32]),
        bytes(&[2; 16]),
        bytes(&[3; 16]),
        bytes(&[4; 32]),
        bytes(&[5; 32]),
        uint(1000),
    ]
}
fn encode(fields: Vec<Value>) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Array(fields), &mut out)?;
    Ok(out)
}

#[test]
fn complete_original_result_has_the_exact_independent_eight_field_encoding() -> TestResult {
    let record = Admission::new(input())?;
    let expected = encode(fields())?;
    assert_eq!(&expected[..7], &[0x88, 0x44, b'C', b'G', b'A', b'1', 1]);
    assert_eq!(expected.len(), 146);
    let actual = record.to_canonical_cbor();
    assert_eq!(actual.as_slice(), expected);
    assert!(record.as_input() == &input());
    let decoded = Admission::from_canonical_cbor(&expected)?;
    assert!(decoded.as_input() == record.as_input());
    assert_eq!(decoded.to_canonical_cbor().as_slice(), expected);
    Ok(())
}

#[test]
fn every_supported_evidence_width_and_maximum_horizon_preserve_original_bytes() -> TestResult {
    for horizon in [
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX / 2,
    ] {
        let data = Input {
            evidence_not_after_micros: horizon,
            ..input()
        };
        let record = Admission::new(data)?;
        let mut value = fields();
        value[7] = uint(horizon);
        let expected = encode(value)?;
        let actual = record.to_canonical_cbor();
        assert_eq!(actual.as_slice(), expected);
        assert!(actual.len() <= 152);
        assert!(Admission::from_canonical_cbor(&expected)?.as_input() == &data);
    }
    let largest = Admission::new(Input {
        evidence_not_after_micros: u64::MAX / 2,
        ..input()
    })?;
    assert_eq!(largest.to_canonical_cbor().len(), 152);
    Ok(())
}

#[test]
fn constructor_rejects_each_zero_link_and_invalid_horizon_without_authority_claims() {
    for data in [
        Input {
            generation_request_digest: Hash::zero(),
            ..input()
        },
        Input {
            timeline: timeline(0),
            ..input()
        },
        Input {
            generation: [0; 16],
            ..input()
        },
        Input {
            initial_selected_head_digest: Hash::zero(),
            ..input()
        },
        Input {
            graph_root_ref: Hash::zero(),
            ..input()
        },
    ] {
        assert_eq!(Admission::new(data).err(), Some(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Admission::new(Input {
                evidence_not_after_micros: horizon,
                ..input()
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
}

#[test]
fn decoder_rejects_all_zero_wire_links_and_invalid_finite_horizons() -> TestResult {
    for slot in 2..=6 {
        let mut value = fields();
        value[slot] = bytes(&vec![0; if slot == 3 || slot == 4 { 16 } else { 32 }]);
        assert_eq!(
            Admission::from_canonical_cbor(&encode(value)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        let mut value = fields();
        value[7] = uint(horizon);
        assert_eq!(
            Admission::from_canonical_cbor(&encode(value)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn every_field_type_width_and_truncation_is_checked_through_the_public_decoder() -> TestResult {
    let wire = encode(fields())?;
    for length in 0..wire.len() {
        assert!(
            Admission::from_canonical_cbor(&wire[..length]).is_err(),
            "prefix {length}"
        );
    }
    for slot in 0..8 {
        let mut value = fields();
        value[slot] = Value::Bool(true);
        assert!(
            Admission::from_canonical_cbor(&encode(value)?).is_err(),
            "field {slot}"
        );
    }
    for slot in 2..=6 {
        for length in [0, 15, 17, 31, 33] {
            let mut value = fields();
            value[slot] = bytes(&vec![1; length]);
            assert!(
                Admission::from_canonical_cbor(&encode(value)?).is_err(),
                "field {slot} size {length}"
            );
        }
    }
    Ok(())
}

#[test]
fn framing_magic_version_preferred_widths_and_exact_whole_record_bound_refuse() -> TestResult {
    let mut value = fields();
    value[0] = bytes(b"CGA2");
    assert_eq!(
        Admission::from_canonical_cbor(&encode(value)?).err(),
        Some(Error::InvalidEncoding)
    );
    let mut value = fields();
    value[1] = uint(2);
    assert_eq!(
        Admission::from_canonical_cbor(&encode(value)?).err(),
        Some(Error::UnsupportedVersion)
    );
    for count in [7, 9] {
        let mut value = fields();
        value.resize(count, Value::Null);
        assert_eq!(
            Admission::from_canonical_cbor(&encode(value)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let wire = encode(fields())?;
    for (range, replacement) in [
        (0..1, vec![0x98, 8]),
        (1..2, vec![0x58, 4]),
        (6..7, vec![0x18, 1]),
        (7..9, vec![0x59, 0, 32]),
        (143..146, vec![0x1a, 0, 0, 3, 0xe8]),
    ] {
        let mut changed = wire.clone();
        changed.splice(range, replacement);
        assert_eq!(
            Admission::from_canonical_cbor(&changed).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut trailing = wire;
    trailing.push(0);
    assert_eq!(
        Admission::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    trailing.resize(1024, 0);
    assert_eq!(
        Admission::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    trailing.push(0);
    assert_eq!(
        Admission::from_canonical_cbor(&trailing).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
