//! Independent wire oracles for the ADR-129 portable data boundary.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityHostProgressV1, CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1,
    CommunityStateContentV1, MAX_COMMUNITY_PASS_KEY_BYTES_V1, MAX_COMMUNITY_STATE_BYTES_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const TIMELINE: [u8; 16] = [1; 16];
const GENERATION: [u8; 16] = [2; 16];
const SCHEMA: [u8; 32] = [3; 32];
const WIDTHS: [u64; 10] = [
    1,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    4_294_967_295,
    4_294_967_296,
    u64::MAX,
];

const fn timeline(bytes: [u8; 16]) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes(bytes))
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

fn pass_value(ordinal: u64) -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&TIMELINE),
        bytes(&GENERATION),
        uint(ordinal),
    ])
}

fn state_value(state: &[u8]) -> Value {
    Value::Array(vec![bytes(b"CSC1"), uint(1), bytes(&SCHEMA), bytes(state)])
}

fn expected_digest(domain: &[u8], encoded: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(encoded);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

#[test]
fn pass_key_matches_independent_wire_and_domain_at_every_integer_width() -> TestResult {
    for ordinal in WIDTHS {
        let expected = encode(&pass_value(ordinal))?;
        let key = CommunityPassKeyV1::new(timeline(TIMELINE), GENERATION, ordinal)?;
        assert_eq!(key.to_canonical_cbor(), expected);
        assert!(expected.len() <= MAX_COMMUNITY_PASS_KEY_BYTES_V1);
        assert_eq!(key.timeline(), timeline(TIMELINE));
        assert_eq!(key.generation(), GENERATION);
        assert_eq!(key.ordinal(), ordinal);
        assert_eq!(
            key.digest(),
            expected_digest(b"PiglorOS.Community.CPK1.v1\0", &expected)
        );
        assert!(CommunityPassKeyV1::from_canonical_cbor(&expected)? == key);
    }
    Ok(())
}

#[test]
fn pass_zero_is_not_an_initialization_or_an_event_cut() -> TestResult {
    for (id, generation, ordinal) in [
        ([0; 16], GENERATION, 1),
        (TIMELINE, [0; 16], 1),
        (TIMELINE, GENERATION, 0),
    ] {
        assert_eq!(
            CommunityPassKeyV1::new(timeline(id), generation, ordinal).err(),
            Some(Error::InvalidBinding)
        );
    }
    let zero_ordinal = encode(&pass_value(0))?;
    assert_eq!(
        CommunityPassKeyV1::from_canonical_cbor(&zero_ordinal).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn pass_decoder_rejects_truncation_unknown_version_and_nonpreferred_input() -> TestResult {
    let valid = encode(&pass_value(1))?;
    for end in 0..valid.len() {
        assert_eq!(
            CommunityPassKeyV1::from_canonical_cbor(&valid[..end]).err(),
            Some(Error::InvalidEncoding)
        );
    }
    for index in [0, 1, 2, 7, 24] {
        let mut wrong = valid.clone();
        wrong[index] = 0;
        assert_eq!(
            CommunityPassKeyV1::from_canonical_cbor(&wrong).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut version = valid.clone();
    version[6] = 2;
    assert_eq!(
        CommunityPassKeyV1::from_canonical_cbor(&version).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut long_version = valid.clone();
    long_version.splice(6..7, [0x18, 1]);
    let mut long_ordinal = valid.clone();
    long_ordinal.splice(valid.len() - 1.., [0x18, 1]);
    let mut trailing = valid;
    trailing.push(0);
    for wrong in [long_version, long_ordinal, trailing] {
        assert_eq!(
            CommunityPassKeyV1::from_canonical_cbor(&wrong).err(),
            Some(Error::InvalidEncoding)
        );
    }
    assert_eq!(
        CommunityPassKeyV1::from_canonical_cbor(&[0; MAX_COMMUNITY_PASS_KEY_BYTES_V1 + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        CommunityPassKeyV1::from_canonical_cbor(&[0; MAX_COMMUNITY_PASS_KEY_BYTES_V1]).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn state_content_preserves_opaque_bytes_and_borrows_the_encoded_range() -> TestResult {
    for length in [
        0,
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        MAX_COMMUNITY_STATE_BYTES_V1,
    ] {
        let state = vec![0x9f; length]; // Opaque bytes need not themselves be CBOR.
        let expected = encode(&state_value(&state))?;
        let record = CommunityStateContentV1::new(Hash::from_bytes(SCHEMA), &state)?;
        let encoded = record.to_canonical_cbor();
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(record.schema_digest(), Hash::from_bytes(SCHEMA));
        assert_eq!(record.state_bytes(), state.as_slice());
        let decoded = CommunityStateContentV1::from_canonical_cbor(&encoded)?;
        assert_eq!(decoded.state_bytes(), state.as_slice());
        assert_eq!(decoded.schema_digest(), Hash::from_bytes(SCHEMA));
        let offset = encoded.len() - length;
        assert!(std::ptr::eq(
            decoded.state_bytes().as_ptr(),
            encoded[offset..].as_ptr()
        ));
    }
    Ok(())
}

#[test]
fn nonpreferred_heads_are_invalid_before_version_binding_or_length_semantics() -> TestResult {
    let valid = encode(&pass_value(1))?;
    let mut long_unknown_version = valid.clone();
    long_unknown_version.splice(6..7, [0x18, 2]);
    let mut long_zero_ordinal = valid;
    long_zero_ordinal.splice(41..42, [0x18, 0]);
    for wire in [long_unknown_version, long_zero_ordinal] {
        assert_eq!(
            CommunityPassKeyV1::from_canonical_cbor(&wire).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut long_oversized_state = encode(&state_value(&[]))?;
    long_oversized_state.splice(41..42, [0x5b, 0, 0, 0, 0, 0, 0x10, 0, 1]);
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&long_oversized_state).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn state_content_checks_owning_schema_and_both_payload_and_record_bounds() -> TestResult {
    assert_eq!(
        CommunityStateContentV1::new(Hash::zero(), &[]).err(),
        Some(Error::InvalidBinding)
    );
    let oversized = vec![0; MAX_COMMUNITY_STATE_BYTES_V1 + 1];
    assert_eq!(
        CommunityStateContentV1::new(Hash::from_bytes(SCHEMA), &oversized).err(),
        Some(Error::BoundsExceeded)
    );
    let record = encode(&state_value(&oversized))?;
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&record).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&vec![0; 1_048_625]).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&vec![0; 1_048_624]).err(),
        Some(Error::InvalidEncoding)
    );
    let mut zero_schema = encode(&state_value(&[]))?;
    zero_schema[9..41].fill(0);
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&zero_schema).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn state_decoder_rejects_nonpreferred_lengths_and_trailing_or_truncated_bytes() -> TestResult {
    let valid = encode(&state_value(b"sensitive input"))?;
    for end in 0..valid.len() {
        assert_eq!(
            CommunityStateContentV1::from_canonical_cbor(&valid[..end]).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut wrong_version = valid.clone();
    wrong_version[6] = 2;
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&wrong_version).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = valid.clone();
    nonpreferred.splice(41..42, [0x58, 15]);
    let mut wrong_type = valid.clone();
    wrong_type[41] = 0x6f;
    let mut trailing = valid;
    trailing.push(0);
    for wrong in [nonpreferred, wrong_type, trailing] {
        assert_eq!(
            CommunityStateContentV1::from_canonical_cbor(&wrong).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut huge = encode(&state_value(&[]))?;
    huge.splice(
        41..42,
        [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert_eq!(
        CommunityStateContentV1::from_canonical_cbor(&huge).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

fn boundary(value: Option<u64>) -> Value {
    Value::Array(value.map_or_else(|| vec![uint(0)], |v| vec![uint(1), uint(v)]))
}

fn progress_value(tick: Value, time: Value) -> Value {
    Value::Array(vec![
        bytes(b"CST1"),
        uint(1),
        bytes(&TIMELINE),
        bytes(&GENERATION),
        tick,
        time,
    ])
}

#[test]
fn host_progress_preserves_initial_and_zero_boundaries_and_independent_coordinates() -> TestResult {
    for tick in [None, Some(0), Some(24), Some(u64::MAX)] {
        for time in [None, Some(0), Some(65_536), Some(u64::MAX)] {
            let expected = encode(&progress_value(boundary(tick), boundary(time)))?;
            let progress =
                CommunityHostProgressV1::new(timeline(TIMELINE), GENERATION, tick, time)?;
            assert_eq!(progress.to_canonical_cbor(), expected);
            assert_eq!(progress.timeline(), timeline(TIMELINE));
            assert_eq!(progress.generation(), GENERATION);
            assert_eq!(progress.host_tick(), tick);
            assert_eq!(progress.simulation_time(), time);
            assert!(CommunityHostProgressV1::from_canonical_cbor(&expected)? == progress);
            assert_eq!(
                progress.digest(),
                expected_digest(b"PiglorOS.Community.CST1.v1\0", &expected)
            );
        }
    }
    assert_eq!(
        CommunityHostProgressV1::new(timeline(TIMELINE), [0; 16], None, None).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn host_progress_rejects_unknown_tags_nonpreferred_scalars_and_partial_records() -> TestResult {
    let valid = encode(&progress_value(boundary(None), boundary(None)))?;
    for end in 0..valid.len() {
        assert_eq!(
            CommunityHostProgressV1::from_canonical_cbor(&valid[..end]).err(),
            Some(Error::InvalidEncoding)
        );
    }
    for bad in [
        Value::Array(vec![uint(2)]),
        Value::Array(vec![uint(0), uint(0)]),
        Value::Array(vec![uint(1)]),
        Value::Null,
        Value::Array(vec![uint(1), Value::Null]),
    ] {
        let value = progress_value(bad, boundary(None));
        assert_eq!(
            CommunityHostProgressV1::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut nonpreferred = encode(&progress_value(boundary(Some(0)), boundary(None)))?;
    nonpreferred.splice(43..44, [0x18, 0]);
    assert_eq!(
        CommunityHostProgressV1::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        CommunityHostProgressV1::from_canonical_cbor(&[0; 129]).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        CommunityHostProgressV1::from_canonical_cbor(&[0; 128]).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn lifecycle_error_codes_are_closed_and_do_not_persist_rust_discriminants() {
    use Error as E;
    let codes = [
        E::InvalidEncoding,
        E::UnsupportedVersion,
        E::BoundsExceeded,
        E::InvalidBinding,
        E::Conflict,
        E::StaleGeneration,
        E::StaleFrontier,
        E::PassUnresolved,
        E::PermitConsumed,
        E::Quarantined,
        E::AdmissionDenied,
        E::ProtectedUseDenied,
        E::EvidenceUnavailable,
        E::EvidenceExpired,
        E::CapacityExhausted,
        E::OperationActive,
        E::OutcomeUnknown,
        E::ContextClosed,
        E::StorageUnavailable,
        E::RecordingUnavailable,
    ];
    for (code, error) in (0_u8..).zip(codes) {
        assert_eq!(error.to_canonical_cbor(), [0x81, code]);
        assert_eq!(Error::from_canonical_cbor(&[0x81, code]), Ok(error));
        assert!(!error.to_string().is_empty());
    }
    for invalid in [
        vec![],
        vec![0x81],
        vec![0x81, 20],
        vec![0x81, 0x18, 0],
        vec![0x81, 0, 0],
        vec![0x9f, 0, 0xff],
    ] {
        assert_eq!(
            Error::from_canonical_cbor(&invalid),
            Err(E::InvalidEncoding)
        );
    }
}
