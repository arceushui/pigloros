//! Canonical SLX1/SLY1 codec for the root selector boundary.

use ciborium::value::Value;

use crate::adapter_transport::{read_observation, write_attempt};
use crate::evaluator::{
    AdapterError, CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult,
};
use crate::evaluator_protocol::{
    array, array_values, decode_canonical_with_limit, encode_with_limit, fixed_bytes, text, uint,
    EvaluationRequest,
};
use crate::sandbox_provider_protocol::{
    AdmissionGrant, SandboxAuditRecord, SandboxExecuteRequest, SandboxLocalError,
    SandboxLocalErrorPhase, SandboxProviderError, SandboxProviderReceipt, SandboxProviderResult,
    SandboxTerminalOutcome,
};

const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const INPUT_DOMAIN: &[u8] = b"PiglorOS.SandboxInputBytes.v1\0";
const OUTPUT_DOMAIN: &[u8] = b"PiglorOS.SandboxOutputBytes.v1\0";
const SLX1_DOMAIN: &[u8] = b"PiglorOS.SLX1.v1\0";
const SLY1_DOMAIN: &[u8] = b"PiglorOS.SLY1.v1\0";

pub(crate) struct EncodedSelectorRequest {
    pub(crate) control: Vec<u8>,
    pub(crate) attempt_stream: Vec<u8>,
    pub(crate) provider_request_id: [u8; 16],
    pub(crate) attempt_id: [u8; 16],
    pub(crate) digest: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DecodedSelectorReply {
    pub(crate) observation: Result<SubjectObservation, AdapterError>,
    pub(crate) provenance: Option<[u8; 32]>,
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
        if !trailing.is_empty() {
            return Err(AdapterError::ProtocolFailure);
        }
        let local = SandboxLocalError::from_canonical_cbor(control)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let error = if local.phase == SandboxLocalErrorPhase::AfterAdmission {
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
    let request_id_matches = result.request_id == request.provider_request_id;
    let attempt_id_matches = result.attempt_id == request.attempt_id;
    if !request_id_matches || !attempt_id_matches {
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
                    usage: ResourceUsage::default(),
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
                    usage: ResourceUsage::default(),
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashSet;

    use crate::adapter_transport::write_observation;
    use crate::evaluator::{AttemptArtifact, AttemptTransportCaps};
    use crate::evaluator_protocol::{ImplementationIdentity, OutputCapability, SubjectAdapterKind};
    use crate::profile::DeterministicBudget;

    use super::*;

    fn request() -> EvaluationRequest {
        EvaluationRequest {
            request_id: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            profile_digest: [2; 32],
            fixture_bundle_digest: [3; 32],
            subject_adapter: SubjectAdapterKind::PublicPluginProtocol,
            subject_artifact_digest: [4; 32],
            implementation: ImplementationIdentity {
                implementation_id: "subject".to_owned(),
                source_digest: [5; 32],
                build_digest: [6; 32],
                binary_digest: [7; 32],
                public_contract_digest: [8; 32],
                organization_id: None,
            },
            execution_profile_digest: [9; 32],
            trust_policy_snapshot_digest: [10; 32],
            output_capability: OutputCapability {
                capability_digest: [11; 32],
                report_bytes_limit: 1,
                diagnostic_bytes_limit: 0,
            },
            evaluator_protocol_digest: [12; 32],
            evaluator_hard_caps_digest: [13; 32],
            sandbox_requirement: None,
            request_digest: [14; 32],
        }
    }

    fn attempt() -> CaseAttempt {
        let artifact = |bytes: Vec<u8>| AttemptArtifact {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        };
        CaseAttempt {
            case_id: "case".to_owned(),
            claim_layer: 1,
            family: 1,
            mode: 1,
            fixture_digest: [15; 32],
            schema: artifact(vec![1]),
            payload: artifact(vec![2]),
            auxiliary: Vec::new(),
            budget: DeterministicBudget {
                memory_bytes: 1,
                cpu_fuel: 1,
                host_calls: 1,
                event_count: 1,
                output_bytes: 1024,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
            },
            watchdog_ms: 100,
            network_allowed: false,
            capability_ids: vec!["execute".to_owned()],
            transport_caps: AttemptTransportCaps {
                max_member_bytes: 1024,
                max_attempt_bytes: 4096,
            },
        }
    }

    #[test]
    fn case_ordinal_ids_are_injective_across_the_complete_namespace() {
        let namespace = request().request_id;
        let mut provider = HashSet::new();
        let mut attempts = HashSet::new();
        for ordinal in 0..=u16::MAX {
            assert!(provider.insert(derived_id(namespace, ordinal)));
            assert!(attempts.insert(derived_id(namespace, ordinal ^ 0x8000)));
        }
        assert_eq!(provider.len(), usize::from(u16::MAX) + 1);
        assert_eq!(attempts.len(), usize::from(u16::MAX) + 1);
    }

    #[test]
    fn slx1_binds_exact_request_attempt_and_stream() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 7)?;
        assert_eq!(&encoded.provider_request_id[14..], &7_u16.to_be_bytes());
        assert_eq!(&encoded.attempt_id[14..], &(7_u16 ^ 0x8000).to_be_bytes());
        let value = decode_canonical_with_limit(&encoded.control, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array(&value, 2).map_err(|_| AdapterError::ProtocolFailure)?;
        let fields = array(&wrapper[0], 6).map_err(|_| AdapterError::ProtocolFailure)?;
        assert_eq!(bytes(&fields[4])?, b"evr1");
        assert!(!encoded.attempt_stream.is_empty());
        assert_eq!(
            fixed_bytes::<32>(&wrapper[1]).map_err(|_| AdapterError::ProtocolFailure)?,
            encoded.digest
        );
        Ok(())
    }

    fn local_error(phase: u64) -> Result<Vec<u8>, AdapterError> {
        local_error_with_fields(vec![
            Value::Text("SLE1".to_owned()),
            integer(1),
            integer(phase),
            integer(1),
            Value::Bytes(vec![1; 16]),
            Value::Bytes(vec![2; 16]),
            if phase == 2 {
                Value::Bytes(vec![3; 32])
            } else {
                Value::Null
            },
            integer(if phase == 2 { 7 } else { 4 }),
            Value::Null,
        ])
    }

    fn local_error_with_fields(fields: Vec<Value>) -> Result<Vec<u8>, AdapterError> {
        encode_with_limit(&Value::Array(fields), CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)
    }

    fn optional_digest(value: Option<[u8; 32]>) -> Value {
        value.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec()))
    }

    fn protocol_record(
        magic: &str,
        fields: Vec<Value>,
        signed: bool,
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        let unsigned = Value::Array(fields);
        let unsigned_bytes = encode_with_limit(&unsigned, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let mut domain = format!("PiglorOS.{magic}.v1").into_bytes();
        domain.push(0);
        let digest = domain_digest(&domain, &unsigned_bytes);
        let mut wrapper = vec![unsigned, Value::Bytes(digest.to_vec())];
        if signed {
            wrapper.push(Value::Bytes(vec![1; 64]));
        }
        let bytes = encode_with_limit(&Value::Array(wrapper), CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        Ok((bytes, digest))
    }

    fn execute_request(
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
    ) -> Result<Vec<u8>, AdapterError> {
        let mut fields = vec![
            Value::Text("SPX1".to_owned()),
            integer(1),
            Value::Array(vec![
                Value::Bytes(request.provider_request_id.to_vec()),
                Value::Bytes(vec![12; 32]),
                integer(1),
                Value::Bytes(vec![13; 16]),
            ]),
            Value::Bytes(request.attempt_id.to_vec()),
        ];
        for digest in 20_u8..35 {
            fields.push(Value::Bytes(vec![digest; 32]));
        }
        fields[12] = Value::Bytes(vec![12; 32]);
        fields.extend([
            Value::Array(vec![Value::Text("execute".to_owned())]),
            descriptor(
                &request.attempt_stream,
                domain_digest(INPUT_DOMAIN, &request.attempt_stream),
            )?,
            Value::Array(Vec::new()),
        ]);
        fields[4] = Value::Bytes(evr1_digest.to_vec());
        protocol_record("SPX1", fields, false).map(|(bytes, _)| bytes)
    }

    fn audit_record(
        request: &EncodedSelectorRequest,
        sequence: u64,
        event: u8,
        authority: Vec<[u8; 32]>,
        previous: Option<[u8; 32]>,
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        protocol_record(
            "SAU1",
            vec![
                Value::Text("SAU1".to_owned()),
                integer(1),
                Value::Bytes(request.attempt_id.to_vec()),
                integer(sequence),
                integer(u64::from(event)),
                Value::Array(
                    authority
                        .into_iter()
                        .map(|digest| Value::Bytes(digest.to_vec()))
                        .collect(),
                ),
                optional_digest(previous),
                Value::Text("runtime-key".to_owned()),
            ],
            true,
        )
    }

    type AdmittedReply = (Vec<u8>, Vec<u8>, [u8; 32]);

    fn admission_grant(
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        let mut fields = vec![
            Value::Text("AGR1".to_owned()),
            integer(1),
            Value::Bytes(request.provider_request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
        ];
        for digest in 40_u8..53 {
            fields.push(Value::Bytes(vec![digest; 32]));
        }
        fields.extend([
            integer(1),
            integer(2),
            integer(3),
            Value::Bytes(vec![53; 32]),
            Value::Bytes(vec![54; 32]),
            Value::Array(Vec::new()),
            Value::Bytes(vec![55; 32]),
            Value::Bytes(vec![56; 32]),
            Value::Text("runtime-key".to_owned()),
        ]);
        fields[4] = Value::Bytes(evr1_digest.to_vec());
        protocol_record("AGR1", fields, true)
    }

    fn audit_chain(
        request: &EncodedSelectorRequest,
        grant_digest: [u8; 32],
        events: &[u8],
        ready: Option<[u8; 32]>,
        release: Option<[u8; 32]>,
    ) -> Result<(Vec<Vec<u8>>, [u8; 32]), AdapterError> {
        let mut records = Vec::new();
        let mut previous = None;
        for (sequence, event) in events.iter().copied().enumerate() {
            let authority = match event {
                11 => vec![
                    grant_digest,
                    ready.ok_or(AdapterError::ProtocolFailure)?,
                    [63; 32],
                ],
                12 => vec![
                    grant_digest,
                    ready.ok_or(AdapterError::ProtocolFailure)?,
                    release.ok_or(AdapterError::ProtocolFailure)?,
                    [63; 32],
                ],
                _ => vec![grant_digest, [64; 32], [65; 32]],
            };
            let (bytes, digest) = audit_record(
                request,
                u64::try_from(sequence).map_err(|_| AdapterError::ProtocolFailure)?,
                event,
                authority,
                previous,
            )?;
            records.push(bytes);
            previous = Some(digest);
        }
        Ok((records, previous.ok_or(AdapterError::ProtocolFailure)?))
    }

    fn provider_receipt(
        request: &EncodedSelectorRequest,
        grant_digest: [u8; 32],
        sau1_digest: [u8; 32],
        ready: Option<[u8; 32]>,
        release: Option<[u8; 32]>,
    ) -> Result<(Vec<u8>, [u8; 32]), AdapterError> {
        protocol_record(
            "SPR1",
            vec![
                Value::Text("SPR1".to_owned()),
                integer(1),
                Value::Bytes(request.attempt_id.to_vec()),
                Value::Bytes(grant_digest.to_vec()),
                Value::Bytes(vec![66; 32]),
                Value::Bytes(vec![67; 32]),
                Value::Bytes(vec![68; 32]),
                Value::Bytes(vec![69; 32]),
                Value::Bytes(vec![70; 32]),
                Value::Bytes(vec![71; 32]),
                Value::Bytes(vec![72; 32]),
                integer(1),
                integer(2),
                integer(3),
                Value::Bytes(vec![73; 32]),
                Value::Bytes(vec![64; 32]),
                Value::Array(Vec::new()),
                optional_digest(ready),
                optional_digest(release),
                Value::Bytes(vec![74; 32]),
                Value::Bytes(vec![63; 32]),
                Value::Bytes(vec![75; 32]),
                Value::Bytes(vec![65; 32]),
                Value::Bytes(sau1_digest.to_vec()),
                Value::Text("runtime-key".to_owned()),
            ],
            true,
        )
    }

    fn provider_result(
        request: &EncodedSelectorRequest,
        outcome: u64,
        grant_digest: [u8; 32],
        receipt_digest: [u8; 32],
        events: &[u8],
        output: Option<(u64, [u8; 32])>,
    ) -> Result<Vec<u8>, AdapterError> {
        protocol_record(
            "SPY1",
            vec![
                Value::Text("SPY1".to_owned()),
                integer(1),
                Value::Bytes(request.provider_request_id.to_vec()),
                Value::Bytes(request.attempt_id.to_vec()),
                integer(outcome),
                output.as_ref().map_or(Value::Null, |(length, digest)| {
                    Value::Array(vec![integer(*length), Value::Bytes(digest.to_vec())])
                }),
                Value::Bytes(grant_digest.to_vec()),
                Value::Bytes(receipt_digest.to_vec()),
                Value::Array(
                    events
                        .iter()
                        .copied()
                        .map(|event| integer(u64::from(event)))
                        .collect(),
                ),
                Value::Text("runtime-key".to_owned()),
            ],
            true,
        )
        .map(|(bytes, _)| bytes)
    }

    fn admitted_reply(
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
        outcome: u64,
    ) -> Result<AdmittedReply, AdapterError> {
        let (grant, grant_digest) = admission_grant(request, evr1_digest)?;
        let (events, ready, release) = match outcome {
            0 => (vec![11, 12], Some([61; 32]), Some([62; 32])),
            1 => (vec![1], None, None),
            4 => (vec![0], None, None),
            _ => return Err(AdapterError::ProtocolFailure),
        };
        let (audit_bytes, sau1_digest) =
            audit_chain(request, grant_digest, &events, ready, release)?;
        let (receipt, receipt_digest) =
            provider_receipt(request, grant_digest, sau1_digest, ready, release)?;
        let mut trailing = Vec::new();
        let output = if outcome == 0 {
            let observation = SubjectObservation {
                result: SubjectResult::Output(vec![77]),
                usage: ResourceUsage::default(),
            };
            write_observation(&mut trailing, &observation)
                .map_err(|_| AdapterError::ProtocolFailure)?;
            Some((
                u64::try_from(trailing.len()).map_err(|_| AdapterError::ProtocolFailure)?,
                domain_digest(OUTPUT_DOMAIN, &trailing),
            ))
        } else {
            None
        };
        let result = provider_result(
            request,
            outcome,
            grant_digest,
            receipt_digest,
            &events,
            output,
        )?;
        let fields = vec![
            Value::Text("SLY1".to_owned()),
            integer(1),
            Value::Bytes(request.provider_request_id.to_vec()),
            Value::Bytes(request.attempt_id.to_vec()),
            Value::Bytes(request.digest.to_vec()),
            Value::Bytes(execute_request(request, evr1_digest)?),
            integer(0),
            Value::Bytes(result),
            Value::Bytes(grant),
            Value::Bytes(receipt),
            Value::Array(audit_bytes.into_iter().map(Value::Bytes).collect()),
            output.map_or(Value::Null, |(length, digest)| {
                Value::Array(vec![integer(length), Value::Bytes(digest.to_vec())])
            }),
        ];
        let (control, _) = protocol_record("SLY1", fields, false)?;
        Ok((control, trailing, receipt_digest))
    }

    fn unavailable_reply(
        request: &EncodedSelectorRequest,
        evr1_digest: [u8; 32],
        outcome: u64,
    ) -> Result<Vec<u8>, AdapterError> {
        let (result, _) = protocol_record(
            "SPY1",
            vec![
                Value::Text("SPY1".to_owned()),
                integer(1),
                Value::Bytes(request.provider_request_id.to_vec()),
                Value::Bytes(request.attempt_id.to_vec()),
                integer(outcome),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Array(Vec::new()),
                Value::Text("runtime-key".to_owned()),
            ],
            true,
        )?;
        protocol_record(
            "SLY1",
            vec![
                Value::Text("SLY1".to_owned()),
                integer(1),
                Value::Bytes(request.provider_request_id.to_vec()),
                Value::Bytes(request.attempt_id.to_vec()),
                Value::Bytes(request.digest.to_vec()),
                Value::Bytes(execute_request(request, evr1_digest)?),
                integer(0),
                Value::Bytes(result),
                Value::Null,
                Value::Null,
                Value::Array(Vec::new()),
                Value::Null,
            ],
            false,
        )
        .map(|(bytes, _)| bytes)
    }

    struct AdmittedEvidence {
        fields: Vec<Value>,
        result: SandboxProviderResult,
        grant: AdmissionGrant,
        receipt: SandboxProviderReceipt,
    }

    fn admitted_evidence(control: &[u8]) -> Result<AdmittedEvidence, AdapterError> {
        let document = decode_canonical_with_limit(control, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&document).map_err(|_| AdapterError::ProtocolFailure)?;
        let fields = array_values(&wrapper[0])
            .map_err(|_| AdapterError::ProtocolFailure)?
            .to_vec();
        Ok(AdmittedEvidence {
            result: SandboxProviderResult::from_canonical_cbor(bytes(&fields[7])?)
                .map_err(|_| AdapterError::ProtocolFailure)?,
            grant: AdmissionGrant::from_canonical_cbor(required_bytes(&fields[8])?)
                .map_err(|_| AdapterError::ProtocolFailure)?,
            receipt: SandboxProviderReceipt::from_canonical_cbor(required_bytes(&fields[9])?)
                .map_err(|_| AdapterError::ProtocolFailure)?,
            fields,
        })
    }

    fn rewrite_spx(
        fields: &[Value],
        mutate: impl FnOnce(&mut Vec<Value>) -> Result<(), AdapterError>,
    ) -> Result<Vec<u8>, AdapterError> {
        let spx = decode_canonical_with_limit(bytes(&fields[5])?, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&spx).map_err(|_| AdapterError::ProtocolFailure)?;
        let mut unsigned = array_values(&wrapper[0])
            .map_err(|_| AdapterError::ProtocolFailure)?
            .to_vec();
        mutate(&mut unsigned)?;
        let (spx, _) = protocol_record("SPX1", unsigned, false)?;
        let mut changed = fields.to_vec();
        changed[5] = Value::Bytes(spx);
        protocol_record("SLY1", changed, false).map(|(control, _)| control)
    }

    fn rewrite_provider_result(
        fields: &[Value],
        mutate: impl FnOnce(&mut Vec<Value>),
    ) -> Result<Vec<Value>, AdapterError> {
        let result = decode_canonical_with_limit(bytes(&fields[7])?, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&result).map_err(|_| AdapterError::ProtocolFailure)?;
        let mut unsigned = array_values(&wrapper[0])
            .map_err(|_| AdapterError::ProtocolFailure)?
            .to_vec();
        mutate(&mut unsigned);
        let (result, _) = protocol_record("SPY1", unsigned, true)?;
        let mut changed = fields.to_vec();
        changed[7] = Value::Bytes(result);
        Ok(changed)
    }

    fn rewrite_audit(
        fields: &[Value],
        index: usize,
        mutate: impl FnOnce(&mut Vec<Value>),
    ) -> Result<Vec<Value>, AdapterError> {
        let mut changed = fields.to_vec();
        let Value::Array(records) = &mut changed[10] else {
            return Err(AdapterError::ProtocolFailure);
        };
        let record = decode_canonical_with_limit(bytes(&records[index])?, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&record).map_err(|_| AdapterError::ProtocolFailure)?;
        let mut unsigned = array_values(&wrapper[0])
            .map_err(|_| AdapterError::ProtocolFailure)?
            .to_vec();
        mutate(&mut unsigned);
        let (record, _) = protocol_record("SAU1", unsigned, true)?;
        records[index] = Value::Bytes(record);
        Ok(changed)
    }

    #[test]
    fn sle1_preserves_pre_and_post_admission_failure_classes() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let pre = decode_reply(&local_error(0)?, &[], &encoded, [14; 32], 1024)?;
        assert_eq!(pre.observation, Err(AdapterError::Unavailable));
        let post = decode_reply(&local_error(2)?, &[], &encoded, [14; 32], 1024)?;
        assert_eq!(
            post.observation,
            Err(AdapterError::AuthenticatedEvidenceFailure)
        );
        assert_eq!(
            decode_reply(&local_error(0)?, &[1], &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            decode_reply(b"not-cbor", &[], &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn sle1_accepts_every_phase_operation_and_failure_code() -> Result<(), AdapterError> {
        use crate::sandbox_provider_protocol::{
            SandboxLocalErrorCode, SandboxLocalErrorPhase, SandboxProviderOperation,
        };

        let valid_cases = [
            (0, None, None, None, None, 2),
            (0, Some(0), None, None, None, 4),
            (0, Some(1), Some([1; 16]), Some([2; 16]), None, 5),
            (0, Some(1), Some([1; 16]), Some([2; 16]), None, 6),
            (1, Some(1), Some([1; 16]), Some([2; 16]), None, 0),
            (1, Some(1), Some([1; 16]), Some([2; 16]), None, 1),
            (1, Some(1), Some([1; 16]), Some([2; 16]), None, 3),
            (1, Some(1), Some([1; 16]), Some([2; 16]), None, 8),
            (2, Some(1), Some([1; 16]), Some([2; 16]), Some([3; 32]), 3),
            (2, Some(1), Some([1; 16]), Some([2; 16]), Some([3; 32]), 7),
            (2, Some(1), Some([1; 16]), Some([2; 16]), Some([3; 32]), 8),
        ];
        for (phase, operation, request_id, attempt_id, grant, code) in valid_cases {
            let bytes = local_error_with_fields(vec![
                Value::Text("SLE1".to_owned()),
                integer(1),
                integer(phase),
                operation.map_or(Value::Null, integer),
                request_id.map_or(Value::Null, |id| Value::Bytes(id.to_vec())),
                attempt_id.map_or(Value::Null, |id| Value::Bytes(id.to_vec())),
                grant.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
                integer(code),
                Value::Null,
            ])?;
            SandboxLocalError::from_canonical_cbor(&bytes)
                .map_err(|_| AdapterError::ProtocolFailure)?;
        }

        for (code, expected) in [
            (0, SandboxProviderOperation::Describe),
            (1, SandboxProviderOperation::Execute),
            (2, SandboxProviderOperation::Cancel),
            (3, SandboxProviderOperation::Reconcile),
        ] {
            let bytes = local_error_with_fields(vec![
                Value::Text("SLE1".to_owned()),
                integer(1),
                integer(0),
                integer(code),
                Value::Null,
                Value::Null,
                Value::Null,
                integer(2),
                Value::Null,
            ])?;
            let decoded = SandboxLocalError::from_canonical_cbor(&bytes)
                .map_err(|_| AdapterError::ProtocolFailure)?;
            assert_eq!(decoded.operation, Some(expected));
            assert_eq!(decoded.phase, SandboxLocalErrorPhase::BeforeSpx1);
            assert_eq!(decoded.code, SandboxLocalErrorCode::PolicyUnavailable);
        }
        Ok(())
    }

    #[test]
    fn sle1_rejects_zero_and_inconsistent_phase_bindings() -> Result<(), AdapterError> {
        let invalid_cases = [
            (0, Some(1), Some([0; 16]), Some([2; 16]), None, 5),
            (0, Some(1), Some([1; 16]), Some([0; 16]), None, 5),
            (0, Some(1), Some([1; 16]), Some([2; 16]), Some([0; 32]), 5),
            (0, Some(0), Some([1; 16]), Some([2; 16]), None, 5),
            (0, Some(1), Some([1; 16]), None, None, 5),
            (0, Some(1), Some([1; 16]), Some([2; 16]), Some([3; 32]), 5),
            (1, None, Some([1; 16]), Some([2; 16]), None, 0),
            (1, Some(1), None, Some([2; 16]), None, 0),
            (1, Some(1), Some([1; 16]), None, None, 0),
            (1, Some(1), Some([1; 16]), Some([2; 16]), Some([3; 32]), 0),
            (1, Some(1), Some([1; 16]), Some([2; 16]), None, 7),
            (2, None, Some([1; 16]), Some([2; 16]), Some([3; 32]), 7),
            (2, Some(1), None, Some([2; 16]), Some([3; 32]), 7),
            (2, Some(1), Some([1; 16]), None, Some([3; 32]), 7),
            (2, Some(1), Some([1; 16]), Some([2; 16]), None, 7),
            (2, Some(1), Some([1; 16]), Some([2; 16]), Some([3; 32]), 0),
        ];
        for (phase, operation, request_id, attempt_id, grant, code) in invalid_cases {
            let bytes = local_error_with_fields(vec![
                Value::Text("SLE1".to_owned()),
                integer(1),
                integer(phase),
                operation.map_or(Value::Null, integer),
                request_id.map_or(Value::Null, |id| Value::Bytes(id.to_vec())),
                attempt_id.map_or(Value::Null, |id| Value::Bytes(id.to_vec())),
                grant.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
                integer(code),
                Value::Null,
            ])?;
            assert!(SandboxLocalError::from_canonical_cbor(&bytes).is_err());
        }
        Ok(())
    }

    #[test]
    fn sly1_maps_every_terminal_class_and_preserves_completed_output() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        for outcome in [0, 1, 4] {
            let (control, trailing, receipt_digest) = admitted_reply(&encoded, [14; 32], outcome)?;
            let reply = decode_reply(&control, &trailing, &encoded, [14; 32], 1024)?;
            assert_eq!(reply.provenance, Some(receipt_digest));
            if outcome == 0 {
                assert_eq!(
                    reply.observation?,
                    SubjectObservation {
                        result: SubjectResult::Output(vec![77]),
                        usage: ResourceUsage::default(),
                    }
                );
            } else {
                assert_eq!(
                    reply.observation?,
                    SubjectObservation {
                        result: SubjectResult::Unavailable,
                        usage: ResourceUsage::default(),
                    }
                );
            }
        }
        for outcome in [2, 3] {
            let control = unavailable_reply(&encoded, [14; 32], outcome)?;
            let reply = decode_reply(&control, &[], &encoded, [14; 32], 1024)?;
            assert_eq!(
                reply,
                DecodedSelectorReply {
                    observation: Ok(SubjectObservation {
                        result: SubjectResult::Unavailable,
                        usage: ResourceUsage::default(),
                    }),
                    provenance: None,
                }
            );
        }
        Ok(())
    }

    #[test]
    fn admitted_reply_rejects_each_result_identity_and_noncompleted_output(
    ) -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (control, _, _) = admitted_reply(&encoded, [14; 32], 1)?;
        let evidence = admitted_evidence(&control)?;

        assert_eq!(
            decode_provider_result(&evidence.fields, &[], &encoded, 1024),
            Ok(DecodedSelectorReply {
                observation: Ok(SubjectObservation {
                    result: SubjectResult::Unavailable,
                    usage: ResourceUsage::default(),
                }),
                provenance: Some(evidence.receipt.receipt_digest),
            })
        );
        for index in [2_usize, 3] {
            let fields = rewrite_provider_result(&evidence.fields, |result| {
                result[index] = Value::Bytes(vec![99; 16]);
            })?;
            assert_eq!(
                decode_provider_result(&fields, &[], &encoded, 1024),
                Err(AdapterError::ProtocolFailure)
            );
        }

        let mut descriptor = evidence.fields.clone();
        descriptor[11] = Value::Array(vec![integer(0), Value::Bytes(vec![0; 32])]);
        assert_eq!(
            decode_provider_result(&descriptor, &[], &encoded, 1024),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            decode_provider_result(&evidence.fields, &[1], &encoded, 1024),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn sly1_rejects_outer_identity_digest_and_evidence_shape_mismatches() -> Result<(), AdapterError>
    {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (control, trailing, _) = admitted_reply(&encoded, [14; 32], 0)?;
        let decoded = decode_canonical_with_limit(&control, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&decoded).map_err(|_| AdapterError::ProtocolFailure)?;
        let unsigned = array_values(&wrapper[0]).map_err(|_| AdapterError::ProtocolFailure)?;
        for index in [1_usize, 2, 3, 4, 6] {
            let mut changed = unsigned.to_vec();
            changed[index] = integer(99);
            let (changed, _) = protocol_record("SLY1", changed, false)?;
            assert_eq!(
                decode_reply(&changed, &trailing, &encoded, [14; 32], 1024),
                Err(AdapterError::ProtocolFailure)
            );
        }
        let mut changed = unsigned.to_vec();
        changed[8] = Value::Null;
        let (changed, _) = protocol_record("SLY1", changed, false)?;
        assert_eq!(
            decode_reply(&changed, &trailing, &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        let unavailable = unavailable_reply(&encoded, [14; 32], 2)?;
        assert_eq!(
            decode_reply(&unavailable, &[1], &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn sly1_rejects_wrong_execute_authority_and_output_descriptor() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (control, trailing, receipt_digest) = admitted_reply(&encoded, [14; 32], 0)?;
        assert_eq!(
            decode_reply(&control, &trailing, &encoded, [99; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        assert_eq!(
            decode_reply(&control, &trailing, &encoded, [14; 32], 0),
            Ok(DecodedSelectorReply {
                observation: Err(AdapterError::ProtocolFailure),
                provenance: Some(receipt_digest),
            })
        );
        let decoded = decode_canonical_with_limit(&control, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&decoded).map_err(|_| AdapterError::ProtocolFailure)?;
        let mut fields = array_values(&wrapper[0])
            .map_err(|_| AdapterError::ProtocolFailure)?
            .to_vec();
        fields[11] = Value::Array(vec![integer(0), Value::Bytes(vec![0; 32])]);
        let (changed, _) = protocol_record("SLY1", fields, false)?;
        assert_eq!(
            decode_reply(&changed, &trailing, &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn sly1_provider_error_is_closed_and_requires_absent_evidence() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (provider_error, _) = protocol_record(
            "SPE1",
            vec![
                Value::Text("SPE1".to_owned()),
                integer(1),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                integer(0),
                Value::Null,
                Value::Text("runtime-key".to_owned()),
            ],
            true,
        )?;
        let fields = vec![
            Value::Text("SLY1".to_owned()),
            integer(1),
            Value::Bytes(encoded.provider_request_id.to_vec()),
            Value::Bytes(encoded.attempt_id.to_vec()),
            Value::Bytes(encoded.digest.to_vec()),
            Value::Bytes(execute_request(&encoded, [14; 32])?),
            integer(1),
            Value::Bytes(provider_error),
            Value::Null,
            Value::Null,
            Value::Array(Vec::new()),
            Value::Null,
        ];
        let (control, _) = protocol_record("SLY1", fields.clone(), false)?;
        assert_eq!(
            decode_reply(&control, &[], &encoded, [14; 32], 1024),
            Ok(DecodedSelectorReply {
                observation: Err(AdapterError::ProtocolFailure),
                provenance: None,
            })
        );
        let mut with_evidence = fields;
        with_evidence[8] = Value::Bytes(vec![1]);
        let (control, _) = protocol_record("SLY1", with_evidence, false)?;
        assert_eq!(
            decode_reply(&control, &[], &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn sly1_rejects_each_spx_identity_and_authority_mismatch() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (control, trailing, _) = admitted_reply(&encoded, [14; 32], 0)?;
        let evidence = admitted_evidence(&control)?;
        for index in [2_usize, 3, 4, 20] {
            let changed = rewrite_spx(&evidence.fields, |spx| {
                match index {
                    2 => {
                        let Value::Array(authority) = &mut spx[2] else {
                            return Err(AdapterError::ProtocolFailure);
                        };
                        authority[0] = Value::Bytes(vec![99; 16]);
                    }
                    3 => spx[3] = Value::Bytes(vec![99; 16]),
                    4 => spx[4] = Value::Bytes(vec![99; 32]),
                    20 => {
                        let Value::Array(descriptor) = &mut spx[20] else {
                            return Err(AdapterError::ProtocolFailure);
                        };
                        descriptor[1] = Value::Bytes(vec![99; 32]);
                    }
                    _ => return Err(AdapterError::ProtocolFailure),
                }
                Ok(())
            })?;
            assert_eq!(
                decode_reply(&changed, &trailing, &encoded, [14; 32], 1024),
                Err(AdapterError::ProtocolFailure)
            );
        }
        let document = decode_canonical_with_limit(&control, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let mut wrapper = array_values(&document)
            .map_err(|_| AdapterError::ProtocolFailure)?
            .to_vec();
        wrapper[1] = Value::Bytes(vec![99; 32]);
        let malformed = encode_with_limit(&Value::Array(wrapper), CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        assert_eq!(
            decode_reply(&malformed, &trailing, &encoded, [14; 32], 1024),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn evidence_relationships_reject_each_cross_record_mismatch() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (control, _, _) = admitted_reply(&encoded, [14; 32], 0)?;
        let evidence = admitted_evidence(&control)?;
        assert_eq!(
            validate_evidence(
                &evidence.fields,
                &evidence.result,
                &evidence.grant,
                &evidence.receipt,
            ),
            Ok(())
        );

        for field in 0..3 {
            let mut grant = evidence.grant.clone();
            match field {
                0 => grant.request_id = [99; 16],
                1 => grant.attempt_id = [99; 16],
                2 => grant.runtime_attestation_key_id = "other-key".to_owned(),
                _ => return Err(AdapterError::ProtocolFailure),
            }
            assert_eq!(
                validate_evidence(
                    &evidence.fields,
                    &evidence.result,
                    &grant,
                    &evidence.receipt,
                ),
                Err(AdapterError::ProtocolFailure)
            );
        }

        for field in 0..3 {
            let mut receipt = evidence.receipt.clone();
            match field {
                0 => receipt.attempt_id = [99; 16],
                1 => receipt.authority.agr1_digest = [99; 32],
                2 => receipt.runtime_attestation_key_id = "other-key".to_owned(),
                _ => return Err(AdapterError::ProtocolFailure),
            }
            assert_eq!(
                validate_evidence(
                    &evidence.fields,
                    &evidence.result,
                    &evidence.grant,
                    &receipt,
                ),
                Err(AdapterError::ProtocolFailure)
            );
        }

        for field in 0..4 {
            let mut result = evidence.result.clone();
            match field {
                0 => result.agr1_digest = Some([99; 32]),
                1 => result.spr1_digest = Some([99; 32]),
                2 => result.runtime_attestation_key_id = "other-key".to_owned(),
                3 => result.operational_events = vec![11],
                _ => return Err(AdapterError::ProtocolFailure),
            }
            assert_eq!(
                validate_evidence(
                    &evidence.fields,
                    &result,
                    &evidence.grant,
                    &evidence.receipt,
                ),
                Err(AdapterError::ProtocolFailure)
            );
        }
        Ok(())
    }

    #[test]
    fn audit_chain_rejects_each_identity_order_link_and_event_mismatch() -> Result<(), AdapterError>
    {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let (control, _, _) = admitted_reply(&encoded, [14; 32], 0)?;
        let evidence = admitted_evidence(&control)?;
        for variant in 0_usize..5 {
            let index = usize::from(variant == 2);
            let changed = rewrite_audit(&evidence.fields, index, |record| match variant {
                0 => record[2] = Value::Bytes(vec![99; 16]),
                1 => {
                    record[3] = integer(1);
                    record[6] = Value::Bytes(vec![99; 32]);
                }
                2 => record[6] = Value::Bytes(vec![99; 32]),
                3 => record[7] = Value::Text("other-key".to_owned()),
                4 => record[4] = integer(10),
                _ => {}
            })?;
            assert_eq!(
                validate_evidence(
                    &changed,
                    &evidence.result,
                    &evidence.grant,
                    &evidence.receipt,
                ),
                Err(AdapterError::ProtocolFailure)
            );
        }
        for records in [Vec::new(), vec![Value::Null; 257]] {
            let mut changed = evidence.fields.clone();
            changed[10] = Value::Array(records);
            assert_eq!(
                validate_evidence(
                    &changed,
                    &evidence.result,
                    &evidence.grant,
                    &evidence.receipt,
                ),
                Err(AdapterError::ProtocolFailure)
            );
        }
        let mut truncated = evidence.fields.clone();
        let Value::Array(records) = &mut truncated[10] else {
            return Err(AdapterError::ProtocolFailure);
        };
        records.pop();
        assert_eq!(
            validate_evidence(
                &truncated,
                &evidence.result,
                &evidence.grant,
                &evidence.receipt,
            ),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }

    #[test]
    fn audit_record_rejects_every_closed_shape_boundary() -> Result<(), AdapterError> {
        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        for event in 0_u8..=13 {
            let authority_count = if event == 12 { 4 } else { 3 };
            let authority = (1..=authority_count)
                .map(|value| [value; 32])
                .collect::<Vec<_>>();
            let (record, _) = audit_record(&encoded, 0, event, authority, None)?;
            SandboxAuditRecord::from_canonical_cbor(&record)
                .map_err(|_| AdapterError::ProtocolFailure)?;
        }

        let invalid = [
            (0, 14, vec![[1; 32]; 3], None),
            (0, 1, vec![[1; 32]; 2], None),
            (0, 1, vec![[0; 32], [1; 32], [2; 32]], None),
            (0, 1, vec![[1; 32]; 3], Some([1; 32])),
            (1, 1, vec![[1; 32]; 3], None),
            (1, 1, vec![[1; 32]; 3], Some([0; 32])),
        ];
        for (sequence, event, authority, previous) in invalid {
            let (record, _) = audit_record(&encoded, sequence, event, authority, previous)?;
            assert!(SandboxAuditRecord::from_canonical_cbor(&record).is_err());
        }
        Ok(())
    }

    #[test]
    fn output_and_absent_evidence_validators_close_every_field() -> Result<(), AdapterError> {
        let trailing = [1_u8, 2, 3];
        let valid = Value::Array(vec![
            integer(3),
            Value::Bytes(domain_digest(OUTPUT_DOMAIN, &trailing).to_vec()),
        ]);
        assert_eq!(validate_output_descriptor(&valid, &trailing), Ok(()));
        for invalid in [
            Value::Null,
            Value::Array(vec![
                integer(2),
                Value::Bytes(domain_digest(OUTPUT_DOMAIN, &trailing).to_vec()),
            ]),
            Value::Array(vec![integer(3), Value::Bytes(vec![0; 32])]),
        ] {
            assert_eq!(
                validate_output_descriptor(&invalid, &trailing),
                Err(AdapterError::ProtocolFailure)
            );
        }

        let encoded = encode_request(&request(), b"evr1", &attempt(), 0)?;
        let control = unavailable_reply(&encoded, [14; 32], 2)?;
        let document = decode_canonical_with_limit(&control, CONTROL_LIMIT)
            .map_err(|_| AdapterError::ProtocolFailure)?;
        let wrapper = array_values(&document).map_err(|_| AdapterError::ProtocolFailure)?;
        let fields = array_values(&wrapper[0]).map_err(|_| AdapterError::ProtocolFailure)?;
        assert_eq!(require_absent_evidence(fields, &[]), Ok(()));
        for index in 8..=11 {
            let mut changed = fields.to_vec();
            changed[index] = if index == 10 {
                Value::Array(vec![Value::Null])
            } else {
                Value::Bytes(vec![1])
            };
            assert_eq!(
                require_absent_evidence(&changed, &[]),
                Err(AdapterError::ProtocolFailure)
            );
        }
        assert_eq!(
            require_absent_evidence(fields, &[1]),
            Err(AdapterError::ProtocolFailure)
        );
        Ok(())
    }
}
