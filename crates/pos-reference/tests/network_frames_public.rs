//! Public FD3 wire checks; no socket or provider execution authority is minted.

use std::{
    error::Error,
    io::{self, Write},
};

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    NetworkExchangeFailure, NetworkExchangePlan, NetworkExchangeReply, NetworkExchangeRequest,
    NetworkRetentionPolicy,
};

type TestResult = Result<(), Box<dyn Error>>;
const ATTEMPT: [u8; 16] = [9; 16];
const LIMIT: usize = 16 * 1024 * 1024;

#[test]
fn successful_frames_round_trip_with_exact_field_order_and_integer_widths() -> TestResult {
    for occurrence in [0, 24, 256, 65_536, u64::from(u32::MAX) + 1] {
        let plan = plan(occurrence, b"query", b"answer")?;
        let query = NetworkExchangeRequest::new(&plan, b"query")?;
        let mut frame = Vec::new();
        query.write_to(&mut frame)?;
        assert_eq!(
            frame,
            framed(&Value::Array(vec![
                text("NXQ1"),
                uint(1),
                bytes(&plan.exchange_id),
                uint(occurrence),
                bytes(b"query"),
                bytes(&plan.request_digest),
            ]))?
        );
        assert_eq!(
            NetworkExchangeRequest::read_from(&mut frame.as_slice(), &plan)?,
            query
        );
        assert_eq!(query.request_bytes(), b"query");
        let reply = query.capture(ATTEMPT, b"answer")?;
        assert_eq!(reply.response_bytes(), Some(b"answer".as_slice()));
        assert_eq!(reply.failure(), None);
        let transcript = reply.transcript().ok_or("missing capture transcript")?;
        let expected = Value::Array(vec![
            text("NXY1"),
            uint(1),
            bytes(&plan.exchange_id),
            uint(occurrence),
            uint(0),
            uint(6),
            bytes(&plan.expected_response_digest),
            bytes(b"answer"),
            bytes(&transcript.digest()),
        ]);
        let mut encoded = Vec::new();
        reply.write_to(&mut encoded)?;
        assert_eq!(encoded, framed(&expected)?);
        assert_eq!(
            NetworkExchangeReply::read_from(&mut encoded.as_slice(), ATTEMPT, &plan)?,
            reply
        );
    }
    Ok(())
}

#[test]
fn failure_frames_never_carry_capture_evidence() -> TestResult {
    let plan = plan(0, b"query", b"answer")?;
    let query = NetworkExchangeRequest::new(&plan, b"query")?;
    for (failure, status) in [
        (NetworkExchangeFailure::RemoteUnavailable, 1),
        (NetworkExchangeFailure::DigestMismatch, 2),
    ] {
        let reply = query.failed(failure);
        assert_eq!(reply.failure(), Some(failure));
        assert_eq!(reply.response_bytes(), None);
        assert_eq!(reply.transcript(), None);
        let mut frame = Vec::new();
        reply.write_to(&mut frame)?;
        let fields = vec![
            text("NXY1"),
            uint(1),
            bytes(&plan.exchange_id),
            uint(0),
            uint(status),
            uint(0),
            Value::Null,
            Value::Null,
            Value::Null,
        ];
        assert_eq!(frame, framed(&Value::Array(fields.clone()))?);
        assert_eq!(
            NetworkExchangeReply::read_from(&mut frame.as_slice(), ATTEMPT, &plan)?,
            reply
        );
        for index in 5..9 {
            let mut changed = fields.clone();
            changed[index] = bytes(&[1; 32]);
            assert!(NetworkExchangeReply::read_from(
                &mut framed(&Value::Array(changed))?.as_slice(),
                ATTEMPT,
                &plan
            )
            .is_err());
        }
    }
    Ok(())
}

#[test]
fn empty_success_is_not_a_failure_or_eof() -> TestResult {
    let plan = plan(0, b"", b"")?;
    let query = NetworkExchangeRequest::new(&plan, b"")?;
    let reply = query.capture(ATTEMPT, b"")?;
    let mut frame = Vec::new();
    reply.write_to(&mut frame)?;
    let decoded = NetworkExchangeReply::read_from(&mut frame.as_slice(), ATTEMPT, &plan)?;
    assert_eq!(decoded.response_bytes(), Some(b"".as_slice()));
    assert!(decoded.transcript().is_some());
    assert!(NetworkExchangeRequest::read_from(&mut b"".as_slice(), &plan).is_err());
    assert!(NetworkExchangeReply::read_from(&mut b"".as_slice(), ATTEMPT, &plan).is_err());
    Ok(())
}

#[test]
fn every_query_and_reply_field_is_bound_to_the_expected_occurrence() -> TestResult {
    let plan = plan(0, b"query", b"answer")?;
    let query = NetworkExchangeRequest::new(&plan, b"query")?;
    let reply = query.capture(ATTEMPT, b"answer")?;
    let mut query_frame = Vec::new();
    let mut reply_frame = Vec::new();
    query.write_to(&mut query_frame)?;
    reply.write_to(&mut reply_frame)?;
    for (frame, is_reply) in [(&query_frame, false), (&reply_frame, true)] {
        let Value::Array(fields) = ciborium::from_reader(&frame[4..])? else {
            return Err("expected array".into());
        };
        for index in 0..fields.len() {
            let mut changed = fields.clone();
            changed[index] = Value::Null;
            let frame = framed(&Value::Array(changed))?;
            if is_reply {
                assert!(
                    NetworkExchangeReply::read_from(&mut frame.as_slice(), ATTEMPT, &plan).is_err()
                );
            } else {
                assert!(NetworkExchangeRequest::read_from(&mut frame.as_slice(), &plan).is_err());
            }
        }
    }
    let Value::Array(mut fields) = ciborium::from_reader(&reply_frame[4..])? else {
        return Err("expected array".into());
    };
    fields[4] = uint(3);
    assert!(NetworkExchangeReply::read_from(
        &mut framed(&Value::Array(fields))?.as_slice(),
        ATTEMPT,
        &plan
    )
    .is_err());
    assert!(NetworkExchangeRequest::read_from(&mut reply_frame.as_slice(), &plan).is_err());
    assert!(NetworkExchangeReply::read_from(&mut query_frame.as_slice(), ATTEMPT, &plan).is_err());
    assert!(NetworkExchangeReply::read_from(&mut reply_frame.as_slice(), [8; 16], &plan).is_err());
    assert!(NetworkExchangeReply::read_from(&mut reply_frame.as_slice(), [0; 16], &plan).is_err());
    Ok(())
}

#[test]
fn malformed_framing_and_document_encodings_are_rejected() -> TestResult {
    let plan = plan(0, b"q", b"r")?;
    let query = NetworkExchangeRequest::new(&plan, b"q")?;
    let mut frame = Vec::new();
    query.write_to(&mut frame)?;
    for length in 0..frame.len() {
        assert!(NetworkExchangeRequest::read_from(&mut &frame[..length], &plan).is_err());
    }
    for data in [
        vec![0; 4],
        vec![255; 4],
        vec![0, 0, 0, 1, 255],
        vec![0, 0, 0, 2, 0, 0],
    ] {
        assert!(NetworkExchangeRequest::read_from(&mut data.as_slice(), &plan).is_err());
        assert!(NetworkExchangeReply::read_from(&mut data.as_slice(), ATTEMPT, &plan).is_err());
    }
    let mut noncanonical = frame.clone();
    let body_length = u32::try_from(frame.len() - 3)?;
    noncanonical[..4].copy_from_slice(&body_length.to_be_bytes());
    noncanonical.splice(4..5, [0x98, 6]);
    assert!(NetworkExchangeRequest::read_from(&mut noncanonical.as_slice(), &plan).is_err());
    // The stream is a sequence; each call consumes exactly its own frame.
    let mut sequence = frame.clone();
    sequence.extend(frame);
    let mut remaining = sequence.as_slice();
    assert_eq!(
        NetworkExchangeRequest::read_from(&mut remaining, &plan)?,
        query
    );
    assert_eq!(
        NetworkExchangeRequest::read_from(&mut remaining, &plan)?,
        query
    );
    assert!(remaining.is_empty());
    Ok(())
}

#[test]
fn request_and_response_validation_precedes_evidence_release() -> TestResult {
    let plan = plan(0, b"q", b"r")?;
    let query = NetworkExchangeRequest::new(&plan, b"q")?;
    assert!(NetworkExchangeRequest::new(&plan, b"qq").is_err());
    assert!(NetworkExchangeRequest::new(&plan, b"x").is_err());
    assert!(query.capture(ATTEMPT, b"x").is_err());
    assert!(query.capture([0; 16], b"r").is_err());
    let mut reply = Vec::new();
    query
        .failed(NetworkExchangeFailure::RemoteUnavailable)
        .write_to(&mut reply)?;
    let mut bad_digest = plan.clone();
    bad_digest.plan_digest[0] ^= 1;
    let mut unsupported_retention = plan;
    unsupported_retention.retention_policy_digest = [7; 32];
    seal(&mut unsupported_retention)?;
    for invalid in [bad_digest, unsupported_retention] {
        assert!(NetworkExchangeRequest::new(&invalid, b"q").is_err());
        assert!(NetworkExchangeReply::read_from(&mut reply.as_slice(), ATTEMPT, &invalid).is_err());
    }
    for remaining in [0, 2, 4, 9] {
        assert!(query.write_to(&mut FailingWriter { remaining }).is_err());
        assert!(query
            .failed(NetworkExchangeFailure::DigestMismatch)
            .write_to(&mut FailingWriter { remaining })
            .is_err());
    }
    Ok(())
}

#[test]
fn encoded_frame_limits_include_cbor_overhead() -> TestResult {
    let request = vec![1; LIMIT - 64];
    let query = NetworkExchangeRequest::new(&plan(0, &request, b"r")?, &request)?;
    let mut frame = Vec::new();
    query.write_to(&mut frame)?;
    assert_eq!(frame.len(), LIMIT + 4);
    drop(frame);
    drop(query);
    let mut oversized_request = request;
    oversized_request.push(1);
    assert!(
        NetworkExchangeRequest::new(&plan(0, &oversized_request, b"r")?, &oversized_request)
            .is_err()
    );
    drop(oversized_request);
    let response = vec![2; LIMIT - 104];
    let query = NetworkExchangeRequest::new(&plan(0, b"q", &response)?, b"q")?;
    let reply = query.capture(ATTEMPT, &response)?;
    let mut frame = Vec::new();
    reply.write_to(&mut frame)?;
    assert_eq!(frame.len(), LIMIT + 4);
    drop(frame);
    drop(reply);
    let mut oversized_response = response;
    oversized_response.push(2);
    assert!(query.capture(ATTEMPT, &oversized_response).is_err());
    Ok(())
}

struct FailingWriter {
    remaining: usize,
}
impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let written = bytes.len().min(self.remaining);
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Independent NXP1 fixture builder; no production encoder supplies the oracle.
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
fn hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(payload);
    *blake3::hash(&preimage).as_bytes()
}
fn framed(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let body = encode(value)?;
    let mut bytes = u32::try_from(body.len())?.to_be_bytes().to_vec();
    bytes.extend(body);
    Ok(bytes)
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
