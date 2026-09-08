//! Canonical SLX1/SLY1 codec for the root selector boundary.

use ciborium::value::Value;

use crate::adapter_transport::{read_observation, write_attempt};
use crate::evaluator::{AdapterError, CaseAttempt, SubjectObservation, SubjectResult};
use crate::evaluator_protocol::{
    array, array_values, decode_canonical_with_limit, encode_with_limit, fixed_bytes, text, uint,
    EvaluationRequest,
};
use crate::sandbox_provider_protocol::{
    AdmissionGrant, SandboxAuditRecord, SandboxExecuteRequest, SandboxProviderError,
    SandboxProviderReceipt, SandboxProviderResult, SandboxTerminalOutcome,
};

const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const INPUT_DOMAIN: &[u8] = b"PiglorOS.SandboxInputBytes.v1\0";
const OUTPUT_DOMAIN: &[u8] = b"PiglorOS.SandboxOutputBytes.v1\0";
const SLX1_DOMAIN: &[u8] = b"PiglorOS.SLX1.v1\0";
const SLY1_DOMAIN: &[u8] = b"PiglorOS.SLY1.v1\0";

pub(crate) struct EncodedSelectorRequest {
    pub control: Vec<u8>,
    pub attempt_stream: Vec<u8>,
    pub provider_request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub digest: [u8; 32],
}

pub(crate) struct DecodedSelectorReply {
    pub observation: Result<SubjectObservation, AdapterError>,
    pub provenance: Option<[u8; 32]>,
}

pub(crate) fn encode_request(
    request: &EvaluationRequest,
    request_bytes: &[u8],
    attempt: &CaseAttempt,
    ordinal: u16,
) -> Result<EncodedSelectorRequest, AdapterError> {
    let mut attempt_stream = Vec::new();
    write_attempt(&mut attempt_stream, attempt).map_err(|_| AdapterError::ProtocolFailure)?;
    let provider_request_id = derived_id(request.request_id, ordinal);
    let attempt_id = derived_id(request.request_id, ordinal ^ 0x8000);
    let input_digest = domain_digest(INPUT_DOMAIN, &attempt_stream);
    let unsigned = Value::Array(vec![
        Value::Text("SLX1".to_owned()),
        integer(1),
        Value::Bytes(provider_request_id.to_vec()),
        Value::Bytes(attempt_id.to_vec()),
        Value::Bytes(request_bytes.to_vec()),
        descriptor(&attempt_stream, input_digest)?,
    ]);
    let unsigned_bytes =
        encode_with_limit(&unsigned, CONTROL_LIMIT).map_err(|_| AdapterError::ProtocolFailure)?;
    let digest = domain_digest(SLX1_DOMAIN, &unsigned_bytes);
    let control = encode_with_limit(
        &Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]),
        CONTROL_LIMIT,
    )
    .map_err(|_| AdapterError::ProtocolFailure)?;
    Ok(EncodedSelectorRequest {
        control,
        attempt_stream,
        provider_request_id,
        attempt_id,
        digest,
    })
}

pub(crate) fn decode_reply(
    control: &[u8],
    trailing: &[u8],
    request: &EncodedSelectorRequest,
    evr1_digest: [u8; 32],
    output_limit: u64,
) -> Result<DecodedSelectorReply, AdapterError> {
    let value = decode_canonical_with_limit(control, CONTROL_LIMIT)
        .map_err(|_| AdapterError::ProtocolFailure)?;
    if is_magic(&value, "SLE1") {
        let fields = array(&value, 9).map_err(|_| AdapterError::ProtocolFailure)?;
        if !trailing.is_empty() {
            return Err(AdapterError::ProtocolFailure);
        }
        let error = if uint(&fields[2]).map_err(|_| AdapterError::ProtocolFailure)? == 2 {
            AdapterError::AuthenticatedEvidenceFailure
        } else {
            AdapterError::Unavailable
        };
        return Ok(DecodedSelectorReply {
            observation: Err(error),
            provenance: None,
        });
    }
    let wrapper = array(&value, 2).map_err(|_| AdapterError::ProtocolFailure)?;
    let fields = array(&wrapper[0], 12).map_err(|_| AdapterError::ProtocolFailure)?;
    if text(&fields[0]).map_err(|_| AdapterError::ProtocolFailure)? != "SLY1"
        || uint(&fields[1]).map_err(|_| AdapterError::ProtocolFailure)? != 1
        || fixed_bytes::<16>(&fields[2]).map_err(|_| AdapterError::ProtocolFailure)?
            != request.provider_request_id
        || fixed_bytes::<16>(&fields[3]).map_err(|_| AdapterError::ProtocolFailure)?
            != request.attempt_id
        || fixed_bytes::<32>(&fields[4]).map_err(|_| AdapterError::ProtocolFailure)?
            != request.digest
    {
        return Err(AdapterError::ProtocolFailure);
    }
    let unsigned =
        encode_with_limit(&wrapper[0], CONTROL_LIMIT).map_err(|_| AdapterError::ProtocolFailure)?;
    if fixed_bytes::<32>(&wrapper[1]).map_err(|_| AdapterError::ProtocolFailure)?
        != domain_digest(SLY1_DOMAIN, &unsigned)
    {
        return Err(AdapterError::ProtocolFailure);
    }
    let spx = SandboxExecuteRequest::from_canonical_cbor(bytes(&fields[5])?)
        .map_err(|_| AdapterError::ProtocolFailure)?;
    if spx.request.request_id != request.provider_request_id
        || spx.attempt_id != request.attempt_id
        || spx.authority.evr1_digest != evr1_digest
        || spx.adapter_input.digest != domain_digest(INPUT_DOMAIN, &request.attempt_stream)
    {
        return Err(AdapterError::ProtocolFailure);
    }
    match uint(&fields[6]).map_err(|_| AdapterError::ProtocolFailure)? {
        0 => decode_provider_result(fields, trailing, request, output_limit),
        1 => {
            SandboxProviderError::from_canonical_cbor(bytes(&fields[7])?)
                .map_err(|_| AdapterError::ProtocolFailure)?;
            require_absent_evidence(fields, trailing)?;
            Ok(DecodedSelectorReply {
                observation: Err(AdapterError::ProtocolFailure),
                provenance: None,
            })
        }
        _ => Err(AdapterError::ProtocolFailure),
    }
}

fn decode_provider_result(
    fields: &[Value],
    trailing: &[u8],
    request: &EncodedSelectorRequest,
    output_limit: u64,
) -> Result<DecodedSelectorReply, AdapterError> {
    let result = SandboxProviderResult::from_canonical_cbor(bytes(&fields[7])?)
        .map_err(|_| AdapterError::ProtocolFailure)?;
    if result.request_id != request.provider_request_id || result.attempt_id != request.attempt_id {
        return Err(AdapterError::ProtocolFailure);
    }
    match result.outcome {
        SandboxTerminalOutcome::Completed
        | SandboxTerminalOutcome::Cancelled
        | SandboxTerminalOutcome::UnavailableAfterAdmission => {
            let grant = AdmissionGrant::from_canonical_cbor(required_bytes(&fields[8])?)
                .map_err(|_| AdapterError::ProtocolFailure)?;
            let receipt = SandboxProviderReceipt::from_canonical_cbor(required_bytes(&fields[9])?)
                .map_err(|_| AdapterError::ProtocolFailure)?;
            validate_evidence(fields, &result, &grant, &receipt)?;
            let observation = if result.outcome == SandboxTerminalOutcome::Completed {
                validate_output_descriptor(&fields[11], trailing)?;
                read_observation(trailing, output_limit).map_err(|_| AdapterError::ProtocolFailure)
            } else {
                if fields[11] != Value::Null || !trailing.is_empty() {
                    return Err(AdapterError::ProtocolFailure);
                }
                Ok(SubjectObservation {
                    result: SubjectResult::Unavailable,
                    usage: Default::default(),
                })
            };
            Ok(DecodedSelectorReply {
                observation,
                provenance: Some(receipt.receipt_digest),
            })
        }
        SandboxTerminalOutcome::UnavailableBeforeAdmission | SandboxTerminalOutcome::Rejected => {
            require_absent_evidence(fields, trailing)?;
            Ok(DecodedSelectorReply {
                observation: Ok(SubjectObservation {
                    result: SubjectResult::Unavailable,
                    usage: Default::default(),
                }),
                provenance: None,
            })
        }
    }
}

fn validate_evidence(
    fields: &[Value],
    result: &SandboxProviderResult,
    grant: &AdmissionGrant,
    receipt: &SandboxProviderReceipt,
) -> Result<(), AdapterError> {
    if grant.request_id != result.request_id
        || grant.attempt_id != result.attempt_id
        || receipt.attempt_id != result.attempt_id
        || result.agr1_digest != Some(grant.grant_digest)
        || result.spr1_digest != Some(receipt.receipt_digest)
        || receipt.authority.agr1_digest != grant.grant_digest
        || grant.runtime_attestation_key_id != receipt.runtime_attestation_key_id
        || receipt.runtime_attestation_key_id != result.runtime_attestation_key_id
    {
        return Err(AdapterError::ProtocolFailure);
    }
    result
        .validate_receipt_lifecycle(receipt)
        .map_err(|_| AdapterError::ProtocolFailure)?;
    let records = array_values(&fields[10]).map_err(|_| AdapterError::ProtocolFailure)?;
    if records.is_empty() || records.len() > 256 {
        return Err(AdapterError::ProtocolFailure);
    }
    let mut previous = None;
    for (index, value) in records.iter().enumerate() {
        let record = SandboxAuditRecord::from_canonical_cbor(bytes(value)?)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        if record.attempt_id != result.attempt_id
            || record.sequence != u64::try_from(index).map_err(|_| AdapterError::ProtocolFailure)?
            || record.previous_digest != previous
            || record.runtime_attestation_key_id != result.runtime_attestation_key_id
            || result.operational_events.get(index) != Some(&record.event_code)
        {
            return Err(AdapterError::ProtocolFailure);
        }
        previous = Some(record.record_digest);
    }
    if previous != Some(receipt.sau1_digest) || records.len() != result.operational_events.len() {
        return Err(AdapterError::ProtocolFailure);
    }
    Ok(())
}

fn validate_output_descriptor(value: &Value, trailing: &[u8]) -> Result<(), AdapterError> {
    let fields = array(value, 2).map_err(|_| AdapterError::ProtocolFailure)?;
    let length = uint(&fields[0]).map_err(|_| AdapterError::ProtocolFailure)?;
    let digest = fixed_bytes::<32>(&fields[1]).map_err(|_| AdapterError::ProtocolFailure)?;
    if length != u64::try_from(trailing.len()).map_err(|_| AdapterError::ProtocolFailure)?
        || digest != domain_digest(OUTPUT_DOMAIN, trailing)
    {
        return Err(AdapterError::ProtocolFailure);
    }
    Ok(())
}

fn require_absent_evidence(fields: &[Value], trailing: &[u8]) -> Result<(), AdapterError> {
    if fields[8] != Value::Null
        || fields[9] != Value::Null
        || !array_values(&fields[10])
            .map_err(|_| AdapterError::ProtocolFailure)?
            .is_empty()
        || fields[11] != Value::Null
        || !trailing.is_empty()
    {
        Err(AdapterError::ProtocolFailure)
    } else {
        Ok(())
    }
}

fn derived_id(mut namespace: [u8; 16], ordinal: u16) -> [u8; 16] {
    namespace[14..].copy_from_slice(&ordinal.to_be_bytes());
    namespace
}

fn descriptor(payload: &[u8], digest: [u8; 32]) -> Result<Value, AdapterError> {
    Ok(Value::Array(vec![
        integer(u64::try_from(payload.len()).map_err(|_| AdapterError::ProtocolFailure)?),
        Value::Bytes(digest.to_vec()),
    ]))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &Value) -> Result<&[u8], AdapterError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(AdapterError::ProtocolFailure),
    }
}

fn required_bytes(value: &Value) -> Result<&[u8], AdapterError> {
    let bytes = bytes(value)?;
    (!bytes.is_empty())
        .then_some(bytes)
        .ok_or(AdapterError::ProtocolFailure)
}

fn is_magic(value: &Value, magic: &str) -> bool {
    array_values(value)
        .ok()
        .and_then(|fields| fields.first())
        .and_then(|field| text(field).ok())
        == Some(magic)
}
