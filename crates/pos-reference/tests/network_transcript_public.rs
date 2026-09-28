//! Independent wire oracle for ADR-069 section 7's public capture/Replay seam.

use std::error::Error;

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    NetworkExchangePlan, NetworkExchangeTranscript, NetworkRetentionPolicy,
};

type TestResult = Result<(), Box<dyn Error>>;

const REQUEST: &[u8] = b"request";
const RESPONSE: &[u8] = b"response";
const ATTEMPT: [u8; 16] = [9; 16];

#[test]
fn indefinite_retention_has_the_exact_public_preimage() -> TestResult {
    let policy = NetworkRetentionPolicy::RetainIndefinitely;
    let unsigned = vec![0x83, 0x64, b'N', b'R', b'P', b'1', 0x01, 0x00];
    let digest = hash(b"PiglorOS.NRP1.v1\0", &unsigned);
    assert_eq!(policy.digest()?, digest);
    let mut expected = vec![0x82];
    expected.extend(unsigned);
    expected.extend([0x58, 0x20]);
    expected.extend(digest);
    assert_eq!(policy.to_canonical_cbor()?, expected);
    assert_eq!(
        NetworkRetentionPolicy::from_canonical_cbor(&expected)?,
        policy
    );
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] ^= 1;
        assert!(NetworkRetentionPolicy::from_canonical_cbor(&changed).is_err());
    }
    assert!(NetworkRetentionPolicy::from_canonical_cbor(&[]).is_err());
    expected.push(0);
    assert!(NetworkRetentionPolicy::from_canonical_cbor(&expected).is_err());
    Ok(())
}

#[test]
fn capture_matches_an_independent_nxt1_wire_oracle() -> TestResult {
    let plan = plan(0, REQUEST, RESPONSE)?;
    let transcript = NetworkExchangeTranscript::capture(ATTEMPT, &plan, REQUEST, RESPONSE)?;
    let unsigned = transcript_prefix(&plan, RESPONSE);
    let digest = hash(
        b"PiglorOS.NetworkExchangeTranscript.v1\0",
        &encode(&unsigned)?,
    );
    let expected = encode(&Value::Array(vec![unsigned, bytes(&digest)]))?;
    assert_eq!(transcript.digest(), digest);
    assert_eq!(transcript.to_canonical_cbor()?, expected);
    assert_eq!(
        NetworkExchangeTranscript::verify_replay(&expected, ATTEMPT, &plan, RESPONSE)?,
        transcript
    );
    assert_ne!(digest, hash(b"PiglorOS.NXT1.v1\0", &expected));
    Ok(())
}

#[test]
fn empty_capture_is_distinct_from_missing_or_changed_capture() -> TestResult {
    let plan = plan(0, b"", b"")?;
    let transcript = NetworkExchangeTranscript::capture(ATTEMPT, &plan, b"", b"")?;
    let encoded = transcript.to_canonical_cbor()?;
    assert_eq!(
        NetworkExchangeTranscript::verify_replay(&encoded, ATTEMPT, &plan, b"")?,
        transcript
    );
    assert!(NetworkExchangeTranscript::verify_replay(&encoded, ATTEMPT, &plan, b"x").is_err());
    assert!(NetworkExchangeTranscript::verify_replay(&[], ATTEMPT, &plan, b"").is_err());
    Ok(())
}

#[test]
fn capture_rejects_wrong_request_response_attempt_and_retention() -> TestResult {
    let plan = plan(0, REQUEST, RESPONSE)?;
    for request in [b"reques".as_slice(), b"requesX".as_slice()] {
        assert!(NetworkExchangeTranscript::capture(ATTEMPT, &plan, request, RESPONSE).is_err());
    }
    for response in [
        b"respons".as_slice(),
        b"responsX".as_slice(),
        b"responses".as_slice(),
    ] {
        assert!(NetworkExchangeTranscript::capture(ATTEMPT, &plan, REQUEST, response).is_err());
    }
    assert!(NetworkExchangeTranscript::capture([0; 16], &plan, REQUEST, RESPONSE).is_err());
    let mut wrong_policy = plan;
    wrong_policy.retention_policy_digest = [7; 32];
    seal(&mut wrong_policy)?;
    assert!(NetworkExchangeTranscript::capture(ATTEMPT, &wrong_policy, REQUEST, RESPONSE).is_err());
    Ok(())
}

#[test]
fn capture_and_replay_reject_invalid_plan_digests_and_bounds() -> TestResult {
    let plan = plan(0, REQUEST, RESPONSE)?;
    let encoded = NetworkExchangeTranscript::capture(ATTEMPT, &plan, REQUEST, RESPONSE)?
        .to_canonical_cbor()?;
    let mut changed = plan.clone();
    changed.plan_digest[0] ^= 1;
    let mut oversized = plan.clone();
    oversized.request_length = 128 * 1024 * 1024 + 1;
    seal(&mut oversized)?;
    let mut invalid_identifier = plan;
    invalid_identifier.capability_id = "invalid identifier".to_owned();
    seal(&mut invalid_identifier)?;
    for invalid in [changed, oversized, invalid_identifier] {
        assert!(NetworkExchangeTranscript::capture(ATTEMPT, &invalid, REQUEST, RESPONSE).is_err());
        assert!(
            NetworkExchangeTranscript::verify_replay(&encoded, ATTEMPT, &invalid, RESPONSE)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn replay_binds_every_field_even_after_an_attacker_rehashes_the_record() -> TestResult {
    let plan = plan(0, REQUEST, RESPONSE)?;
    let Value::Array(prefix) = transcript_prefix(&plan, RESPONSE) else {
        return Err("oracle must produce an array".into());
    };
    for index in 0..prefix.len() {
        let mut fields = prefix.clone();
        fields[index] = Value::Null;
        let changed = Value::Array(fields);
        let digest = hash(
            b"PiglorOS.NetworkExchangeTranscript.v1\0",
            &encode(&changed)?,
        );
        let encoded = encode(&Value::Array(vec![changed, bytes(&digest)]))?;
        assert!(
            NetworkExchangeTranscript::verify_replay(&encoded, ATTEMPT, &plan, RESPONSE).is_err()
        );
    }
    let encoded = NetworkExchangeTranscript::capture(ATTEMPT, &plan, REQUEST, RESPONSE)?
        .to_canonical_cbor()?;
    for index in encoded.len() - 32..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(
            NetworkExchangeTranscript::verify_replay(&changed, ATTEMPT, &plan, RESPONSE).is_err()
        );
    }
    assert!(NetworkExchangeTranscript::verify_replay(&encoded, [8; 16], &plan, RESPONSE).is_err());
    Ok(())
}

#[test]
fn repeated_identical_payloads_retain_distinct_occurrence_identity() -> TestResult {
    let first_plan = plan(0, REQUEST, RESPONSE)?;
    let second_plan = plan(1, REQUEST, RESPONSE)?;
    let first = NetworkExchangeTranscript::capture(ATTEMPT, &first_plan, REQUEST, RESPONSE)?;
    let second = NetworkExchangeTranscript::capture(ATTEMPT, &second_plan, REQUEST, RESPONSE)?;
    assert_ne!(first.digest(), second.digest());
    assert!(NetworkExchangeTranscript::verify_replay(
        &first.to_canonical_cbor()?,
        ATTEMPT,
        &second_plan,
        RESPONSE
    )
    .is_err());
    let mut other_exchange = first_plan;
    other_exchange.exchange_id = [8; 16];
    seal(&mut other_exchange)?;
    assert!(NetworkExchangeTranscript::verify_replay(
        &first.to_canonical_cbor()?,
        ATTEMPT,
        &other_exchange,
        RESPONSE
    )
    .is_err());
    Ok(())
}

#[test]
fn replay_rejects_trailing_truncated_and_noncanonical_records() -> TestResult {
    let plan = plan(0, REQUEST, RESPONSE)?;
    let encoded = NetworkExchangeTranscript::capture(ATTEMPT, &plan, REQUEST, RESPONSE)?
        .to_canonical_cbor()?;
    for length in 0..encoded.len() {
        assert!(NetworkExchangeTranscript::verify_replay(
            &encoded[..length],
            ATTEMPT,
            &plan,
            RESPONSE
        )
        .is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NetworkExchangeTranscript::verify_replay(&trailing, ATTEMPT, &plan, RESPONSE).is_err());
    let mut noncanonical = vec![0x98, 2];
    noncanonical.extend_from_slice(&encoded[1..]);
    assert!(
        NetworkExchangeTranscript::verify_replay(&noncanonical, ATTEMPT, &plan, RESPONSE).is_err()
    );
    Ok(())
}

fn plan(
    occurrence: u64,
    request: &[u8],
    response: &[u8],
) -> Result<NetworkExchangePlan, Box<dyn Error>> {
    let mut value = NetworkExchangePlan {
        exchange_id: [4; 16],
        occurrence,
        capability_id: "exact-endpoint".to_owned(),
        request_length: request.len() as u64,
        request_digest: hash(b"PiglorOS.NetworkRequestBytes.v1\0", request),
        response_maximum: (response.len() as u64).max(1),
        expected_response_digest: hash(b"PiglorOS.NetworkResponseBytes.v1\0", response),
        retention_policy_digest: NetworkRetentionPolicy::RetainIndefinitely.digest()?,
        plan_digest: [0; 32],
    };
    seal(&mut value)?;
    Ok(value)
}

fn seal(plan: &mut NetworkExchangePlan) -> TestResult {
    let fields = Value::Array(vec![
        text("NXP1"),
        uint(1),
        bytes(&plan.exchange_id),
        uint(plan.occurrence),
        text(&plan.capability_id),
        uint(plan.request_length),
        bytes(&plan.request_digest),
        uint(plan.response_maximum),
        bytes(&plan.expected_response_digest),
        bytes(&plan.retention_policy_digest),
    ]);
    plan.plan_digest = hash(b"PiglorOS.NetworkExchangePlan.v1\0", &encode(&fields)?);
    Ok(())
}

fn transcript_prefix(plan: &NetworkExchangePlan, response: &[u8]) -> Value {
    let digest = hash(b"PiglorOS.NetworkResponseBytes.v1\0", response);
    Value::Array(vec![
        text("NXT1"),
        uint(1),
        bytes(&ATTEMPT),
        bytes(&plan.exchange_id),
        uint(plan.occurrence),
        bytes(&plan.plan_digest),
        uint(plan.request_length),
        bytes(&plan.request_digest),
        uint(response.len() as u64),
        bytes(&digest),
        bytes(&digest),
        bytes(&plan.retention_policy_digest),
    ])
}

fn hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let preimage: Vec<_> = domain.iter().chain(payload).copied().collect();
    *blake3::hash(&preimage).as_bytes()
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
