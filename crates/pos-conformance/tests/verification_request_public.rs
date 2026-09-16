#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-058 RVR1 verification-request contract.

use ciborium::value::Value;
use pos_conformance::{
    ReproVerificationRequestContractErrorV1, ReproVerificationRequestV1, ReproducibilityClassV1,
    MAX_REPORT_BYTES_V1, MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const fn valid_request() -> ReproVerificationRequestV1 {
    ReproVerificationRequestV1 {
        request_digest: [1; 32],
        manifest_digest: [2; 32],
        reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
        execution_profile_digest: [3; 32],
        trust_policy_snapshot_digest: [4; 32],
        artifact_closure_digest: [5; 32],
        evaluator_digest: [6; 32],
        report_bytes_limit: MAX_REPORT_BYTES_V1,
    }
}

fn decode_value(bytes: &[u8]) -> TestResult<Value> {
    ciborium::from_reader(bytes).map_err(Into::into)
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn replace_field(bytes: &[u8], index: usize, replacement: Value) -> TestResult<Vec<u8>> {
    let mut document = decode_value(bytes)?;
    let Value::Array(fields) = &mut document else {
        return Err("RVR1 must be represented by a CBOR array".into());
    };
    let Some(field) = fields.get_mut(index) else {
        return Err(format!("RVR1 field {index} is absent").into());
    };
    *field = replacement;
    encode_value(&document)
}

fn assert_decode_error(bytes: &[u8], expected: ReproVerificationRequestContractErrorV1) {
    assert_eq!(
        ReproVerificationRequestV1::from_canonical_cbor(bytes).map(|_| ()),
        Err(expected),
        "input was {bytes:?}"
    );
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

#[test]
fn public_codec_roundtrips_and_hashes_the_closed_request() -> TestResult {
    let request = valid_request();
    let encoded = request.to_canonical_cbor()?;

    assert_eq!(
        ReproVerificationRequestV1::from_canonical_cbor(&encoded)?,
        request
    );
    assert_ne!(request.digest()?, [0; 32]);
    assert!(encoded.len() <= MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1);

    for class in [
        ReproducibilityClassV1::RecordedReplay,
        ReproducibilityClassV1::ProfileRecomputation,
        ReproducibilityClassV1::CrossProfileConformance,
        ReproducibilityClassV1::LiveUnverified,
    ] {
        let mut candidate = request.clone();
        candidate.reproducibility_class = class;
        let encoded = candidate.to_canonical_cbor()?;
        assert_eq!(
            ReproVerificationRequestV1::from_canonical_cbor(&encoded)?,
            candidate
        );
    }
    Ok(())
}

#[test]
fn digest_changes_when_any_bound_reference_or_budget_changes() -> TestResult {
    let request = valid_request();
    let original_digest = request.digest()?;

    let mutations: [fn(&mut ReproVerificationRequestV1); 7] = [
        |candidate: &mut ReproVerificationRequestV1| candidate.request_digest[0] ^= 1,
        |candidate: &mut ReproVerificationRequestV1| candidate.manifest_digest[0] ^= 1,
        |candidate: &mut ReproVerificationRequestV1| candidate.execution_profile_digest[0] ^= 1,
        |candidate: &mut ReproVerificationRequestV1| candidate.trust_policy_snapshot_digest[0] ^= 1,
        |candidate: &mut ReproVerificationRequestV1| candidate.artifact_closure_digest[0] ^= 1,
        |candidate: &mut ReproVerificationRequestV1| candidate.evaluator_digest[0] ^= 1,
        |candidate: &mut ReproVerificationRequestV1| candidate.report_bytes_limit -= 1,
    ];
    for mutate in mutations {
        let mut candidate = request.clone();
        mutate(&mut candidate);
        assert_ne!(candidate.digest()?, original_digest);
    }
    Ok(())
}

#[test]
fn validation_rejects_zero_references_and_unbounded_budgets() {
    for index in 0..6 {
        let mut candidate = valid_request();
        match index {
            0 => candidate.request_digest = [0; 32],
            1 => candidate.manifest_digest = [0; 32],
            2 => candidate.execution_profile_digest = [0; 32],
            3 => candidate.trust_policy_snapshot_digest = [0; 32],
            4 => candidate.artifact_closure_digest = [0; 32],
            _ => candidate.evaluator_digest = [0; 32],
        }
        assert_eq!(
            candidate.validate(),
            Err(ReproVerificationRequestContractErrorV1::FieldOutOfBounds)
        );
    }

    for budget in [0, MAX_REPORT_BYTES_V1 + 1, u64::MAX] {
        let mut candidate = valid_request();
        candidate.report_bytes_limit = budget;
        assert_eq!(
            candidate.validate(),
            Err(ReproVerificationRequestContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            candidate.to_canonical_cbor(),
            Err(ReproVerificationRequestContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            candidate.digest(),
            Err(ReproVerificationRequestContractErrorV1::FieldOutOfBounds)
        );
    }
}

#[test]
fn decoder_rejects_unknown_missing_trailing_and_oversized_input() -> TestResult {
    let valid = valid_request().to_canonical_cbor()?;
    let document = decode_value(&valid)?;
    let Value::Array(fields) = document else {
        return Err("RVR1 must be an array".into());
    };

    let mut missing = fields.clone();
    missing.pop();
    assert_decode_error(
        &encode_value(&Value::Array(missing))?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );

    let mut unknown = fields;
    unknown.push(Value::Null);
    assert_decode_error(
        &encode_value(&Value::Array(unknown))?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );

    let mut trailing = valid;
    trailing.push(0);
    assert_decode_error(
        &trailing,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );

    assert_decode_error(
        &vec![0; MAX_REPRO_VERIFICATION_REQUEST_BYTES_V1 + 1],
        ReproVerificationRequestContractErrorV1::FieldOutOfBounds,
    );
    Ok(())
}

#[test]
fn decoder_rejects_closed_header_enum_and_reference_shapes() -> TestResult {
    let valid = valid_request().to_canonical_cbor()?;
    assert_decode_error(
        &replace_field(&valid, 0, Value::Text("RVR2".to_owned()))?,
        ReproVerificationRequestContractErrorV1::UnsupportedVersion,
    );
    assert_decode_error(
        &replace_field(&valid, 0, Value::Null)?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(&valid, 0, Value::Bytes(Vec::new()))?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(&valid, 1, Value::Bytes(Vec::new()))?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(&valid, 1, uint(2))?,
        ReproVerificationRequestContractErrorV1::UnsupportedVersion,
    );
    assert_decode_error(
        &replace_field(&valid, 4, uint(9))?,
        ReproVerificationRequestContractErrorV1::UnsupportedVersion,
    );
    assert_decode_error(
        &replace_field(&valid, 4, Value::Bytes(Vec::new()))?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    for index in [2, 3, 5, 6, 7, 8] {
        for replacement in [
            Value::Bytes(vec![1; 31]),
            Value::Text("digest".to_owned()),
        ] {
            assert_decode_error(
                &replace_field(&valid, index, replacement)?,
                ReproVerificationRequestContractErrorV1::InvalidEncoding,
            );
        }
    }
    assert_decode_error(
        &replace_field(&valid, 3, Value::Null)?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(&valid, 9, Value::Text("budget".to_owned()))?,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    Ok(())
}

#[test]
fn decoder_rejects_noncanonical_and_forbidden_cbor_forms() -> TestResult {
    let valid = valid_request().to_canonical_cbor()?;
    for raw in [
        vec![0xff],                         // malformed CBOR
        vec![0xa0],                         // map
        vec![0xc0, 0x00],                   // tag
        vec![0xf9, 0x00, 0x00],             // float
        vec![0x9f, 0xff],                   // indefinite array
        vec![0x61, 0xff],                   // invalid UTF-8
        vec![0x81, 0x81, 0x81, 0x00],       // excessive nesting
        vec![0x9a, 0x00, 0x00, 0x00, 0x0c], // excessive array count
    ] {
        let expected = if raw == [0x81, 0x81, 0x81, 0x00] || raw == [0x9a, 0x00, 0x00, 0x00, 0x0c] {
            ReproVerificationRequestContractErrorV1::FieldOutOfBounds
        } else {
            ReproVerificationRequestContractErrorV1::InvalidEncoding
        };
        assert_decode_error(&raw, expected);
    }

    let marker = [0x64, b'R', b'V', b'R', b'1', 0x01];
    let marker_index = valid
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("canonical RVR1 header bytes are absent")?;
    let mut noncanonical_integer = valid;
    noncanonical_integer.splice(
        marker_index + marker.len() - 1..marker_index + marker.len(),
        [0x18, 0x01],
    );
    assert_decode_error(
        &noncanonical_integer,
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
    );
    Ok(())
}

#[test]
fn every_closed_error_has_a_safe_display() {
    for error in [
        ReproVerificationRequestContractErrorV1::InvalidEncoding,
        ReproVerificationRequestContractErrorV1::UnsupportedVersion,
        ReproVerificationRequestContractErrorV1::FieldOutOfBounds,
    ] {
        assert!(!error.to_string().is_empty());
    }
}
