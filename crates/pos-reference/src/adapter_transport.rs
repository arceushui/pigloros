//! Exact local transport between the evaluator and a public subject adapter.
//!
//! EAI1/EAO1 carry provider-owned payload and result bytes without interpreting
//! their schema. They are local process framing only: no transport field enters
//! CPF1 or changes provider semantics.

use ciborium::value::Value;

use crate::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};
use crate::evaluator_protocol::{
    array, array_values, bool_value, decode_canonical_with_limit, encode_with_limit, fixed_bytes,
    text, uint, ProtocolError,
};
use crate::profile::{DeterministicBudget, NamespacedFailure};

const MAX_TRANSPORT_BYTES: usize = 128 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;

/// Closed EAI1/EAO1 framing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportError {
    #[error("adapter transport encoding is invalid")]
    InvalidEncoding,
    #[error("adapter transport version is unsupported")]
    UnsupportedVersion,
    #[error("adapter transport field exceeds its bound")]
    FieldOutOfBounds,
}

impl From<ProtocolError> for TransportError {
    fn from(value: ProtocolError) -> Self {
        match value {
            ProtocolError::UnsupportedVersion => Self::UnsupportedVersion,
            ProtocolError::FieldOutOfBounds => Self::FieldOutOfBounds,
            ProtocolError::InvalidEncoding
            | ProtocolError::NonCanonicalOrder
            | ProtocolError::DigestMismatch => Self::InvalidEncoding,
        }
    }
}

/// Encode one exact EAI1 attempt for an out-of-process public adapter.
///
/// # Errors
/// Returns a closed failure if any transport field is unbounded.
pub fn encode_attempt(value: &CaseAttempt) -> Result<Vec<u8>, TransportError> {
    validate_attempt(value)?;
    encode_with_limit(
        &Value::Array(vec![
            Value::Text("EAI1".to_owned()),
            unsigned(1),
            Value::Text(value.case_id.clone()),
            unsigned(u64::from(value.claim_layer)),
            unsigned(u64::from(value.family)),
            unsigned(u64::from(value.mode)),
            bytes(&value.fixture_digest),
            Value::Bytes(value.schema.clone()),
            Value::Bytes(value.payload.clone()),
            Value::Array(value.auxiliary.iter().cloned().map(Value::Bytes).collect()),
            budget_value(value.budget),
            unsigned(value.watchdog_ms),
            Value::Bool(value.network_allowed),
            Value::Array(
                value
                    .capability_ids
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
        ]),
        MAX_TRANSPORT_BYTES,
    )
    .map_err(Into::into)
}

/// Decode one exact EAI1 attempt in an independently built adapter process.
///
/// # Errors
/// Returns a closed failure for malformed, noncanonical, or unbounded input.
pub fn decode_attempt(bytes: &[u8]) -> Result<CaseAttempt, TransportError> {
    let value = decode_canonical_with_limit(bytes, MAX_TRANSPORT_BYTES)?;
    let fields = array(&value, 14)?;
    if text(&fields[0])? != "EAI1" || uint(&fields[1])? != 1 {
        return Err(TransportError::UnsupportedVersion);
    }
    let attempt = CaseAttempt {
        case_id: identifier(&fields[2])?,
        claim_layer: bounded_u8(&fields[3], 6)?,
        family: bounded_u8(&fields[4], 6)?,
        mode: bounded_u8(&fields[5], 3)?,
        fixture_digest: fixed_bytes(&fields[6])?,
        schema: byte_string(&fields[7])?,
        payload: byte_string(&fields[8])?,
        auxiliary: array_values(&fields[9])?
            .iter()
            .map(byte_string)
            .collect::<Result<Vec<_>, _>>()?,
        budget: decode_budget(&fields[10])?,
        watchdog_ms: uint(&fields[11])?,
        network_allowed: bool_value(&fields[12])?,
        capability_ids: array_values(&fields[13])?
            .iter()
            .map(identifier)
            .collect::<Result<Vec<_>, _>>()?,
    };
    validate_attempt(&attempt).map(|()| attempt)
}

/// Encode one exact EAO1 observation.
///
/// # Errors
/// Returns a closed failure for an invalid result union or unbounded value.
pub fn encode_observation(value: &SubjectObservation) -> Result<Vec<u8>, TransportError> {
    validate_observation(value)?;
    let (kind, output, failure, divergence) = match &value.result {
        SubjectResult::Output(bytes) => (0, Value::Bytes(bytes.clone()), Value::Null, Value::Null),
        SubjectResult::Failure(failure) => (1, Value::Null, failure_value(failure), Value::Null),
        SubjectResult::Divergence {
            classification,
            first_coordinate,
        } => (
            2,
            Value::Null,
            Value::Null,
            Value::Array(vec![
                unsigned(u64::from(*classification)),
                Value::Bytes(first_coordinate.clone()),
            ]),
        ),
        SubjectResult::Unavailable => (3, Value::Null, Value::Null, Value::Null),
    };
    encode_with_limit(
        &Value::Array(vec![
            Value::Text("EAO1".to_owned()),
            unsigned(1),
            unsigned(kind),
            output,
            failure,
            divergence,
            usage_value(value.usage),
        ]),
        MAX_TRANSPORT_BYTES,
    )
    .map_err(Into::into)
}

/// Decode one exact EAO1 observation from an out-of-process adapter.
///
/// # Errors
/// Returns a closed failure for malformed, noncanonical, unbounded, or
/// non-exclusive result fields.
pub fn decode_observation(bytes: &[u8]) -> Result<SubjectObservation, TransportError> {
    let value = decode_canonical_with_limit(bytes, MAX_TRANSPORT_BYTES)?;
    let fields = array(&value, 7)?;
    if text(&fields[0])? != "EAO1" || uint(&fields[1])? != 1 {
        return Err(TransportError::UnsupportedVersion);
    }
    let result = match uint(&fields[2])? {
        0 if fields[4] == Value::Null && fields[5] == Value::Null => {
            SubjectResult::Output(byte_string(&fields[3])?)
        }
        1 if fields[3] == Value::Null && fields[5] == Value::Null => {
            SubjectResult::Failure(decode_failure(&fields[4])?)
        }
        2 if fields[3] == Value::Null && fields[4] == Value::Null => {
            let divergence = array(&fields[5], 2)?;
            SubjectResult::Divergence {
                classification: bounded_u8(&divergence[0], 8)?,
                first_coordinate: byte_string(&divergence[1])?,
            }
        }
        3 if fields[3] == Value::Null && fields[4] == Value::Null && fields[5] == Value::Null => {
            SubjectResult::Unavailable
        }
        _ => return Err(TransportError::InvalidEncoding),
    };
    let observation = SubjectObservation {
        result,
        usage: decode_usage(&fields[6])?,
    };
    validate_observation(&observation).map(|()| observation)
}

fn validate_attempt(value: &CaseAttempt) -> Result<(), TransportError> {
    if value.case_id.is_empty()
        || value.case_id.len() > MAX_IDENTIFIER_BYTES
        || value.claim_layer > 6
        || value.family > 6
        || value.mode > 3
        || value.fixture_digest == [0; 32]
        || value.schema.len() > 64 * 1024 * 1024
        || value.payload.len() > 64 * 1024 * 1024
        || value.auxiliary.len() > 65_536
        || value
            .auxiliary
            .iter()
            .any(|member| member.len() > 64 * 1024 * 1024)
        || value.watchdog_ms == 0
        || value.capability_ids.len() > 65_536
        || !strict_strings(&value.capability_ids)
    {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_observation(value: &SubjectObservation) -> Result<(), TransportError> {
    match &value.result {
        SubjectResult::Output(bytes) if bytes.len() > 64 * 1024 * 1024 => {
            Err(TransportError::FieldOutOfBounds)
        }
        SubjectResult::Failure(value) => validate_failure(value),
        SubjectResult::Divergence {
            classification,
            first_coordinate,
        } if *classification > 8 || first_coordinate.is_empty() || first_coordinate.len() > 128 => {
            Err(TransportError::FieldOutOfBounds)
        }
        _ => Ok(()),
    }
}

fn validate_failure(value: &NamespacedFailure) -> Result<(), TransportError> {
    if [&value.owner_id, &value.contract_version, &value.code_id]
        .iter()
        .any(|field| field.is_empty() || field.len() > MAX_IDENTIFIER_BYTES)
    {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn budget_value(value: DeterministicBudget) -> Value {
    Value::Array(
        [
            value.memory_bytes,
            value.cpu_fuel,
            value.host_calls,
            value.event_count,
            value.output_bytes,
            value.storage_bytes,
            value.execution_steps,
            value.simulation_time_ns,
        ]
        .map(unsigned)
        .to_vec(),
    )
}

fn decode_budget(value: &Value) -> Result<DeterministicBudget, TransportError> {
    let fields = array(value, 8)?;
    let values = fields.iter().map(uint).collect::<Result<Vec<_>, _>>()?;
    if values.contains(&0) {
        return Err(TransportError::FieldOutOfBounds);
    }
    Ok(DeterministicBudget {
        memory_bytes: values[0],
        cpu_fuel: values[1],
        host_calls: values[2],
        event_count: values[3],
        output_bytes: values[4],
        storage_bytes: values[5],
        execution_steps: values[6],
        simulation_time_ns: values[7],
    })
}

fn usage_value(value: ResourceUsage) -> Value {
    Value::Array(
        [
            value.memory_bytes,
            value.cpu_fuel,
            value.host_calls,
            value.event_count,
            value.output_bytes,
            value.storage_bytes,
            value.execution_steps,
            value.simulation_time_ns,
        ]
        .map(unsigned)
        .to_vec(),
    )
}

fn decode_usage(value: &Value) -> Result<ResourceUsage, TransportError> {
    let fields = array(value, 8)?;
    let values = fields.iter().map(uint).collect::<Result<Vec<_>, _>>()?;
    Ok(ResourceUsage {
        memory_bytes: values[0],
        cpu_fuel: values[1],
        host_calls: values[2],
        event_count: values[3],
        output_bytes: values[4],
        storage_bytes: values[5],
        execution_steps: values[6],
        simulation_time_ns: values[7],
    })
}

fn failure_value(value: &NamespacedFailure) -> Value {
    Value::Array(vec![
        Value::Text(value.owner_id.clone()),
        Value::Text(value.contract_version.clone()),
        Value::Text(value.code_id.clone()),
    ])
}

fn decode_failure(value: &Value) -> Result<NamespacedFailure, TransportError> {
    let fields = array(value, 3)?;
    let failure = NamespacedFailure {
        owner_id: identifier(&fields[0])?,
        contract_version: identifier(&fields[1])?,
        code_id: identifier(&fields[2])?,
    };
    validate_failure(&failure).map(|()| failure)
}

fn identifier(value: &Value) -> Result<String, TransportError> {
    let value = text(value)?;
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(value.to_owned())
    }
}

fn bounded_u8(value: &Value, maximum: u8) -> Result<u8, TransportError> {
    let value = u8::try_from(uint(value)?).map_err(|_| TransportError::InvalidEncoding)?;
    if value <= maximum {
        Ok(value)
    } else {
        Err(TransportError::InvalidEncoding)
    }
}

fn byte_string(value: &Value) -> Result<Vec<u8>, TransportError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(TransportError::InvalidEncoding),
    }
}

fn strict_strings(values: &[String]) -> bool {
    values
        .iter()
        .all(|value| !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES)
        && values
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
