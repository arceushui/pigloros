//! The provider runtime's SDY1, SPE1 and output SBC1 producers (ADR-069
//! §4, R9 §5, R11 §7).
//!
//! Each record is self-digested by its encoder, signed over the message the
//! sealed record derives, verified under the admitted key, and encoded. An
//! oracle that builds the same CDDL with `ciborium`, digests it with
//! `blake3` and signs it with `ed25519-dalek` directly must produce the
//! identical bytes, and the independent decoder must accept them.

use std::error::Error;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pos_reference::sandbox_provider_protocol::{
    PayloadDescriptor, PayloadDirection, PayloadStreamValidator, RuntimeSigned,
    SandboxDescribeResponse, SandboxDescribeResponseFields, SandboxPayloadChunk,
    SandboxProviderError, SandboxProviderErrorCode, SandboxProviderErrorFields,
    SandboxProviderProtocolError, Sdy1, SelfDigested, Spe1,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const KEY_ID: &str = "runtime";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[4; 32])
}

fn bytes(slice: &[u8]) -> Value {
    Value::Bytes(slice.to_vec())
}

fn int(number: u64) -> Value {
    Value::Integer(number.into())
}

fn optional(value: Option<&[u8]>) -> Value {
    value.map_or(Value::Null, bytes)
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// The oracle: `[unsigned, digest, signature]` under the R9 §5 domains.
fn oracle(magic: &str, unsigned: Vec<Value>) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(unsigned);
    let mut preimage = format!("PiglorOS.{magic}.v1\0").into_bytes();
    preimage.extend(encode(&unsigned)?);
    let digest = *blake3::hash(&preimage).as_bytes();
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend(digest);
    let signature = signing_key().sign(&message).to_bytes();
    encode(&Value::Array(vec![
        unsigned,
        bytes(&digest),
        bytes(&signature),
    ]))
}

/// Sign `record` as the runtime does, and verify it under the admitted key.
fn sign<M: RuntimeSigned>(
    record: SelfDigested<M>,
) -> Result<pos_reference::sandbox_provider_protocol::Verified<M>, SandboxProviderProtocolError> {
    let signature = signing_key().sign(&record.signature_message()).to_bytes();
    record.verify(signature, &signing_key().verifying_key())
}

fn describe_fields() -> SandboxDescribeResponseFields {
    SandboxDescribeResponseFields {
        request_id: [1; 16],
        spm1_digest: [2; 32],
        provider_binary_digest: [3; 32],
        hcp1_digest: [4; 32],
        active_apt1_digest: [5; 32],
        runtime_attestation_key_id: KEY_ID.to_owned(),
    }
}

/// The SPE1 `11` refusal of `operation`; a describe refusal names no attempt.
fn refusal(operation: u8) -> SandboxProviderErrorFields {
    SandboxProviderErrorFields {
        operation: Some(operation),
        request_id: Some([6; 16]),
        request_digest: Some([7; 32]),
        attempt_id: (operation != 0).then_some([8; 16]),
        code: SandboxProviderErrorCode::SandboxUnavailable,
        safe_detail: None,
        runtime_attestation_key_id: KEY_ID.to_owned(),
    }
}

fn error_oracle(fields: &SandboxProviderErrorFields, code: u64) -> TestResult<Vec<u8>> {
    oracle(
        "SPE1",
        vec![
            Value::Text("SPE1".to_owned()),
            int(1),
            fields
                .operation
                .map_or(Value::Null, |operation| int(u64::from(operation))),
            optional(fields.request_id.as_ref().map(<[u8; 16]>::as_slice)),
            optional(fields.request_digest.as_ref().map(<[u8; 32]>::as_slice)),
            optional(fields.attempt_id.as_ref().map(<[u8; 16]>::as_slice)),
            int(code),
            fields.safe_detail.clone().map_or(Value::Null, Value::Text),
            Value::Text(KEY_ID.to_owned()),
        ],
    )
}

fn signed_error(fields: SandboxProviderErrorFields) -> TestResult<SandboxProviderError> {
    let verified = sign(SandboxProviderError::self_digested(fields)?)?;
    Ok(SandboxProviderError::new(
        verified,
        &signing_key().verifying_key(),
    )?)
}

#[test]
fn sdy1_matches_the_oracle_and_the_decoder() -> TestResult {
    let record = SandboxDescribeResponse::self_digested(describe_fields())?;
    assert_eq!(record.key_id(), KEY_ID);
    assert_eq!(record.body(), &describe_fields());
    let mut message = b"PiglorOS.SDY1.Signature.v1\0".to_vec();
    message.extend(record.digest());
    assert_eq!(record.signature_message(), message);
    let response = SandboxDescribeResponse::new(sign(record)?, &signing_key().verifying_key())?;
    let encoded = response.to_canonical_cbor()?;
    let expected = oracle(
        "SDY1",
        vec![
            Value::Text("SDY1".to_owned()),
            int(1),
            bytes(&[1; 16]),
            bytes(&[2; 32]),
            bytes(&[3; 32]),
            bytes(&[4; 32]),
            bytes(&[5; 32]),
            Value::Text(KEY_ID.to_owned()),
        ],
    )?;
    assert_eq!(encoded, expected);
    let decoded = SandboxDescribeResponse::from_canonical_cbor(&encoded)?;
    assert_eq!(decoded, response);
    decoded.verify_signature(&signing_key().verifying_key())?;
    assert_eq!(decoded.request_id, [1; 16]);
    assert_eq!(decoded.response_digest(), response.response_digest());
    assert_ne!(decoded.response_digest(), [0; 32]);
    assert_eq!(decoded.signature(), response.signature());
    signing_key().verifying_key().verify_strict(
        &[
            b"PiglorOS.SDY1.Signature.v1\0".as_slice(),
            &decoded.response_digest(),
        ]
        .concat(),
        &ed25519_dalek::Signature::from_bytes(&decoded.signature()),
    )?;
    assert_eq!(decoded.active_apt1_digest, [5; 32]);
    Ok(())
}

#[test]
fn spe1_refusals_of_every_operation_match_the_oracle_and_the_decoder() -> TestResult {
    for operation in 0..=3 {
        let fields = refusal(operation);
        let error = signed_error(fields.clone())?;
        let encoded = error.to_canonical_cbor()?;
        assert_eq!(encoded, error_oracle(&fields, 11)?);
        let decoded = SandboxProviderError::from_canonical_cbor(&encoded)?;
        assert_eq!(decoded, error);
        decoded.verify_signature(&signing_key().verifying_key())?;
        assert_eq!(decoded.code, SandboxProviderErrorCode::SandboxUnavailable);
        assert_eq!(decoded.operation, Some(operation));
        assert_eq!(decoded.attempt_id, fields.attempt_id);
        assert_eq!(decoded.safe_detail, None);
        assert_eq!(decoded.error_digest(), error.error_digest());
        assert_eq!(decoded.signature(), error.signature());
        signing_key().verifying_key().verify_strict(
            &[
                b"PiglorOS.SPE1.Signature.v1\0".as_slice(),
                &decoded.error_digest(),
            ]
            .concat(),
            &ed25519_dalek::Signature::from_bytes(&decoded.signature()),
        )?;
    }
    // An unidentified encoding failure and a detailed unknown attempt.
    let unidentified = SandboxProviderErrorFields {
        operation: None,
        request_id: None,
        request_digest: None,
        attempt_id: None,
        code: SandboxProviderErrorCode::InvalidEncoding,
        safe_detail: None,
        runtime_attestation_key_id: KEY_ID.to_owned(),
    };
    let detailed = SandboxProviderErrorFields {
        code: SandboxProviderErrorCode::UnknownAttempt,
        safe_detail: Some("unknown attempt".to_owned()),
        ..refusal(2)
    };
    for (fields, code) in [(unidentified, 0), (detailed, 15)] {
        let encoded = signed_error(fields.clone())?.to_canonical_cbor()?;
        assert_eq!(encoded, error_oracle(&fields, code)?);
        SandboxProviderError::from_canonical_cbor(&encoded)?
            .verify_signature(&signing_key().verifying_key())?;
    }
    Ok(())
}

#[test]
fn the_producers_refuse_what_the_decoders_refuse() {
    let out_of_bounds = [
        SandboxDescribeResponseFields {
            request_id: [0; 16],
            ..describe_fields()
        },
        SandboxDescribeResponseFields {
            spm1_digest: [0; 32],
            ..describe_fields()
        },
        SandboxDescribeResponseFields {
            active_apt1_digest: [0; 32],
            ..describe_fields()
        },
        SandboxDescribeResponseFields {
            runtime_attestation_key_id: String::new(),
            ..describe_fields()
        },
    ];
    for fields in out_of_bounds {
        assert_eq!(
            SandboxDescribeResponse::self_digested(fields).err(),
            Some(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    let bounds = [
        SandboxProviderErrorFields {
            operation: Some(4),
            ..refusal(1)
        },
        SandboxProviderErrorFields {
            request_id: Some([0; 16]),
            ..refusal(1)
        },
        SandboxProviderErrorFields {
            safe_detail: Some(String::new()),
            ..refusal(1)
        },
        SandboxProviderErrorFields {
            safe_detail: Some("a\0b".to_owned()),
            ..refusal(1)
        },
        SandboxProviderErrorFields {
            safe_detail: Some("d".repeat(257)),
            ..refusal(1)
        },
        SandboxProviderErrorFields {
            runtime_attestation_key_id: String::new(),
            ..refusal(1)
        },
    ];
    for fields in bounds {
        assert_eq!(
            SandboxProviderError::self_digested(fields).err(),
            Some(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    let inconsistent = [
        // A refusal must bind the operation, request and digest.
        SandboxProviderErrorFields {
            operation: None,
            attempt_id: None,
            ..refusal(0)
        },
        SandboxProviderErrorFields {
            request_digest: None,
            ..refusal(1)
        },
        // Describe names no attempt; the other operations do.
        SandboxProviderErrorFields {
            attempt_id: Some([8; 16]),
            ..refusal(0)
        },
        SandboxProviderErrorFields {
            attempt_id: None,
            ..refusal(2)
        },
        // A payload timeout is an execute failure.
        SandboxProviderErrorFields {
            code: SandboxProviderErrorCode::PayloadTransferTimeout,
            ..refusal(2)
        },
    ];
    for fields in inconsistent {
        assert_eq!(
            SandboxProviderError::self_digested(fields).err(),
            Some(SandboxProviderProtocolError::InconsistentFields)
        );
    }
}

#[test]
fn only_a_signature_under_the_admitted_key_becomes_a_record() -> TestResult {
    let other = SigningKey::from_bytes(&[9; 32]);
    let admitted: VerifyingKey = signing_key().verifying_key();
    // A signature that verified, but under another key than the admitted one.
    let record = SandboxDescribeResponse::self_digested(describe_fields())?;
    let foreign = other.sign(&record.signature_message()).to_bytes();
    let verified = record.verify(foreign, &other.verifying_key())?;
    assert_eq!(
        SandboxDescribeResponse::new(verified, &admitted).err(),
        Some(SandboxProviderProtocolError::SignatureInvalid)
    );
    let record = SandboxProviderError::self_digested(refusal(1))?;
    let foreign = other.sign(&record.signature_message()).to_bytes();
    let verified = record.verify(foreign, &other.verifying_key())?;
    assert_eq!(
        SandboxProviderError::new(verified, &admitted).err(),
        Some(SandboxProviderProtocolError::SignatureInvalid)
    );
    // A signature that does not verify under the admitted key at all.
    let record = SandboxProviderError::self_digested(refusal(1))?;
    let foreign = other.sign(&record.signature_message()).to_bytes();
    assert_eq!(
        record.verify(foreign, &admitted).err(),
        Some(SandboxProviderProtocolError::SignatureInvalid)
    );
    // The two kinds' messages are domain-separated.
    let describe: SelfDigested<Sdy1> = SandboxDescribeResponse::self_digested(describe_fields())?;
    let error: SelfDigested<Spe1> = SandboxProviderError::self_digested(refusal(0))?;
    assert!(describe
        .signature_message()
        .starts_with(b"PiglorOS.SDY1.Signature.v1\0"));
    assert!(error
        .signature_message()
        .starts_with(b"PiglorOS.SPE1.Signature.v1\0"));
    assert_eq!(describe.key_id(), KEY_ID);
    assert_eq!(error.key_id(), KEY_ID);
    Ok(())
}

#[test]
fn every_field_bound_holds_at_its_edge() -> TestResult {
    // The longest detail and an execute payload timeout are accepted.
    for fields in [
        SandboxProviderErrorFields {
            safe_detail: Some("d".repeat(256)),
            ..refusal(1)
        },
        SandboxProviderErrorFields {
            code: SandboxProviderErrorCode::PayloadTransferTimeout,
            ..refusal(1)
        },
    ] {
        let encoded = signed_error(fields)?.to_canonical_cbor()?;
        SandboxProviderError::from_canonical_cbor(&encoded)?
            .verify_signature(&signing_key().verifying_key())?;
    }
    for (fields, expected) in [
        (
            SandboxProviderErrorFields {
                attempt_id: Some([0; 16]),
                ..refusal(1)
            },
            SandboxProviderProtocolError::FieldOutOfBounds,
        ),
        (
            SandboxProviderErrorFields {
                request_digest: Some([0; 32]),
                ..refusal(1)
            },
            SandboxProviderProtocolError::FieldOutOfBounds,
        ),
        (
            SandboxProviderErrorFields {
                request_id: None,
                attempt_id: None,
                ..refusal(0)
            },
            SandboxProviderProtocolError::InconsistentFields,
        ),
    ] {
        assert_eq!(
            SandboxProviderError::self_digested(fields).err(),
            Some(expected)
        );
    }
    for fields in [
        SandboxDescribeResponseFields {
            provider_binary_digest: [0; 32],
            ..describe_fields()
        },
        SandboxDescribeResponseFields {
            hcp1_digest: [0; 32],
            ..describe_fields()
        },
    ] {
        assert_eq!(
            SandboxDescribeResponse::self_digested(fields).err(),
            Some(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn the_decoders_refuse_correctly_digested_records_with_bad_fields() -> TestResult {
    // An SDY1 with a zero request ID, digested and signed by the oracle.
    let zero_request = oracle(
        "SDY1",
        vec![
            Value::Text("SDY1".to_owned()),
            int(1),
            bytes(&[0; 16]),
            bytes(&[2; 32]),
            bytes(&[3; 32]),
            bytes(&[4; 32]),
            bytes(&[5; 32]),
            Value::Text(KEY_ID.to_owned()),
        ],
    )?;
    assert_eq!(
        SandboxDescribeResponse::from_canonical_cbor(&zero_request).err(),
        Some(SandboxProviderProtocolError::FieldOutOfBounds)
    );
    // SPE1 identities that only the field rules refuse: a refusal with no
    // operation, a digest with no request, and an attempt with no operation
    // or no request, under a code that requires no identity.
    let unidentified = SandboxProviderErrorFields {
        operation: None,
        request_id: None,
        request_digest: None,
        attempt_id: None,
        code: SandboxProviderErrorCode::InvalidEncoding,
        safe_detail: None,
        runtime_attestation_key_id: KEY_ID.to_owned(),
    };
    let cases = [
        (
            SandboxProviderErrorFields {
                operation: None,
                attempt_id: None,
                ..refusal(0)
            },
            11,
        ),
        (
            SandboxProviderErrorFields {
                request_digest: Some([7; 32]),
                ..unidentified.clone()
            },
            0,
        ),
        (
            SandboxProviderErrorFields {
                attempt_id: Some([8; 16]),
                ..unidentified.clone()
            },
            0,
        ),
        (
            SandboxProviderErrorFields {
                operation: Some(1),
                attempt_id: Some([8; 16]),
                ..unidentified
            },
            0,
        ),
    ];
    for (fields, code) in cases {
        assert_eq!(
            SandboxProviderError::self_digested(fields.clone()).err(),
            Some(SandboxProviderProtocolError::InconsistentFields)
        );
        assert_eq!(
            SandboxProviderError::from_canonical_cbor(&error_oracle(&fields, code)?).err(),
            Some(SandboxProviderProtocolError::InconsistentFields)
        );
    }
    Ok(())
}

#[test]
fn the_sdy1_decoder_refuses_an_unbound_digest_and_a_zero_signature() -> TestResult {
    // Fields the decoder accepts, but a digest that does not bind them, and
    // then a zero signature: only the record validation refuses either.
    let response = SandboxDescribeResponse::new(
        sign(SandboxDescribeResponse::self_digested(describe_fields())?)?,
        &signing_key().verifying_key(),
    )?;
    let Value::Array(mut wrapper) =
        ciborium::from_reader(response.to_canonical_cbor()?.as_slice())?
    else {
        return Err("an SDY1 is an array".into());
    };
    wrapper[1] = bytes(&[9; 32]);
    assert_eq!(
        SandboxDescribeResponse::from_canonical_cbor(&encode(&Value::Array(wrapper.clone()))?)
            .err(),
        Some(SandboxProviderProtocolError::DigestMismatch)
    );
    wrapper[1] = bytes(&response.response_digest());
    wrapper[2] = bytes(&[0; 64]);
    assert_eq!(
        SandboxDescribeResponse::from_canonical_cbor(&encode(&Value::Array(wrapper))?).err(),
        Some(SandboxProviderProtocolError::SignatureInvalid)
    );
    Ok(())
}

const CHUNK: usize = 1024 * 1024;

/// The oracle of one SBC1: `[unsigned, digest]` under its §4 domain.
fn chunk_oracle(parent: [u8; 32], index: u64, chunk: &[u8]) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(vec![
        Value::Text("SBC1".to_owned()),
        int(1),
        bytes(&parent),
        bytes(&[3; 16]),
        bytes(&[4; 16]),
        int(1),
        int(index),
        int(index * CHUNK as u64),
        bytes(chunk),
    ]);
    let mut preimage = b"PiglorOS.SBC1.v1\0".to_vec();
    preimage.extend(encode(&unsigned)?);
    let digest = *blake3::hash(&preimage).as_bytes();
    encode(&Value::Array(vec![unsigned, bytes(&digest)]))
}

#[test]
fn output_records_are_the_contiguous_sbc1_chunks_a_selector_accepts() -> TestResult {
    let parent = [2; 32];
    assert_eq!(SandboxPayloadChunk::CHUNK_BYTES, CHUNK);
    let payload: Vec<u8> = (0..=CHUNK).map(|byte| byte.to_le_bytes()[0]).collect();
    let record = |index: u64, bytes: &[u8]| {
        SandboxPayloadChunk::output_record(parent, [3; 16], [4; 16], index, bytes.to_vec())
    };
    let records = [record(0, &payload[..CHUNK])?, record(1, &payload[CHUNK..])?];
    assert_eq!(
        records,
        [
            chunk_oracle(parent, 0, &payload[..CHUNK])?,
            chunk_oracle(parent, 1, &payload[CHUNK..])?,
        ]
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SandboxOutputBytes.v1\0");
    hasher.update(&payload);
    let mut validator = PayloadStreamValidator::new(
        parent,
        [3; 16],
        [4; 16],
        PayloadDirection::Output,
        PayloadDescriptor {
            byte_length: payload.len() as u64,
            digest: *hasher.finalize().as_bytes(),
        },
    )?;
    for record in &records {
        validator.accept(&SandboxPayloadChunk::from_canonical_cbor(record)?)?;
    }
    validator.finish()?;
    // A chunk names its parent SPY1, carries bytes, and fits the 128-chunk
    // payload, even at an index whose offset overflows.
    for (parent, index, bytes) in [
        ([0; 32], 0, vec![1]),
        (parent, 0, Vec::new()),
        (parent, 0, vec![1; CHUNK + 1]),
        (parent, 128, vec![1]),
        (parent, u64::MAX, vec![1]),
    ] {
        assert_eq!(
            SandboxPayloadChunk::output_record(parent, [3; 16], [4; 16], index, bytes).err(),
            Some(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    Ok(())
}
