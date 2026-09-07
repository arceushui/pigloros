//! Bounded local transport between the evaluator and a public subject Adapter.
//!
//! EAI1/EAO1 frame streams carry provider-owned bytes without interpreting
//! their schema. A length prefix bounds every allocation before CBOR decoding.

use std::io::{Read, Write};

use ciborium::value::Value;

use crate::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectObservation,
    SubjectResult,
};
use crate::evaluator_protocol::{
    array, bool_value, decode_canonical_with_limit, encode_with_limit, fixed_bytes, text, uint,
    ProtocolError,
};
use crate::profile::{DeterministicBudget, NamespacedFailure};

const MAX_FRAME_BYTES: usize = 128 * 1024;
const MAX_CHUNK_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CAPABILITIES: usize = 65_536;
const MAX_AUXILIARY: usize = 65_536;
const MAX_MEMBERS: usize = MAX_AUXILIARY + 2;
const MAX_ATTEMPT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FRAME_NESTING: usize = 4;
const ATTEMPT_DOMAIN: &[u8] = b"PiglorOS.EvaluatorAttemptStream.v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"PiglorOS.EvaluatorObservationStream.v1\0";

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

struct Frame {
    prefix: [u8; 4],
    encoded: Vec<u8>,
    value: Value,
}

struct AttemptHeader {
    case_id: String,
    claim_layer: u8,
    family: u8,
    mode: u8,
    fixture_digest: [u8; 32],
    budget: DeterministicBudget,
    watchdog_ms: u64,
    network_allowed: bool,
    capability_count: usize,
    member_count: usize,
    transport_caps: AttemptTransportCaps,
}

struct AttemptMembers {
    schema: AttemptArtifact,
    payload: AttemptArtifact,
    auxiliary: Vec<AttemptArtifact>,
}

impl Frame {
    fn absorb(&self, transcript: &mut blake3::Hasher) {
        transcript.update(&self.prefix);
        transcript.update(&self.encoded);
    }
}

/// Stream one exact EAI1 attempt.
///
/// # Errors
/// Returns a closed failure when the attempt violates its authenticated limits
/// or the destination cannot accept the complete stream.
pub fn write_attempt(mut writer: impl Write, attempt: &CaseAttempt) -> Result<(), TransportError> {
    validate_attempt(attempt)?;
    let mut transcript = new_transcript(ATTEMPT_DOMAIN);
    let members = attempt.auxiliary.len() + 2;
    write_transcript_frame(
        &mut writer,
        Value::Array(vec![
            text_value("EAI1"),
            unsigned(1),
            text_value(&attempt.case_id),
            unsigned(u64::from(attempt.claim_layer)),
            unsigned(u64::from(attempt.family)),
            unsigned(u64::from(attempt.mode)),
            bytes_value(&attempt.fixture_digest),
            budget_value(attempt.budget),
            unsigned(attempt.watchdog_ms),
            Value::Bool(attempt.network_allowed),
            unsigned(as_u64(attempt.capability_ids.len())?),
            unsigned(as_u64(members)?),
            unsigned(attempt.transport_caps.max_member_bytes),
            unsigned(attempt.transport_caps.max_attempt_bytes),
        ]),
        &mut transcript,
    )?;
    for (index, capability) in attempt.capability_ids.iter().enumerate() {
        write_transcript_frame(
            &mut writer,
            Value::Array(vec![
                text_value("EIC1"),
                unsigned(1),
                unsigned(as_u64(index)?),
                text_value(capability),
            ]),
            &mut transcript,
        )?;
    }
    write_artifact(&mut writer, &mut transcript, 0, 0, &attempt.schema)?;
    write_artifact(&mut writer, &mut transcript, 1, 0, &attempt.payload)?;
    for (index, artifact) in attempt.auxiliary.iter().enumerate() {
        write_artifact(&mut writer, &mut transcript, 2, as_u64(index)?, artifact)?;
    }
    write_frame(
        &mut writer,
        Value::Array(vec![
            text_value("EIE1"),
            unsigned(1),
            bytes_value(transcript.finalize().as_bytes()),
        ]),
    )?;
    writer.flush().map_err(io_error)
}

/// Decode one complete EAI1 attempt stream.
///
/// # Errors
/// Returns a closed failure for malformed, noncanonical, truncated, reordered,
/// digest-mismatched, trailing, or out-of-bounds input.
pub fn read_attempt(mut reader: impl Read) -> Result<CaseAttempt, TransportError> {
    let mut transcript = new_transcript(ATTEMPT_DOMAIN);
    let start = read_transcript_frame(&mut reader, &mut transcript)?;
    let header = decode_attempt_header(&start.value)?;
    let capability_ids = read_capabilities(&mut reader, &mut transcript, header.capability_count)?;
    let members = read_attempt_members(
        &mut reader,
        &mut transcript,
        header.member_count,
        header.transport_caps,
    )?;
    read_attempt_end(&mut reader, &transcript)?;
    require_eof(&mut reader)?;
    Ok(CaseAttempt {
        case_id: header.case_id,
        claim_layer: header.claim_layer,
        family: header.family,
        mode: header.mode,
        fixture_digest: header.fixture_digest,
        schema: members.schema,
        payload: members.payload,
        auxiliary: members.auxiliary,
        budget: header.budget,
        watchdog_ms: header.watchdog_ms,
        network_allowed: header.network_allowed,
        capability_ids,
        transport_caps: header.transport_caps,
    })
}

fn decode_attempt_header(value: &Value) -> Result<AttemptHeader, TransportError> {
    let fields = array(value, 14)?;
    require_magic(fields, "EAI1")?;
    let header = AttemptHeader {
        case_id: identifier(&fields[2])?,
        claim_layer: bounded_u8(&fields[3], 6)?,
        family: bounded_u8(&fields[4], 6)?,
        mode: bounded_u8(&fields[5], 3)?,
        fixture_digest: nonzero_digest(&fields[6])?,
        budget: decode_budget(&fields[7])?,
        watchdog_ms: uint(&fields[8])?,
        network_allowed: bool_value(&fields[9])?,
        capability_count: bounded_usize(&fields[10], MAX_CAPABILITIES)?,
        member_count: bounded_usize(&fields[11], MAX_MEMBERS)?,
        transport_caps: AttemptTransportCaps {
            max_member_bytes: uint(&fields[12])?,
            max_attempt_bytes: uint(&fields[13])?,
        },
    };
    validate_header(
        header.watchdog_ms,
        header.member_count,
        header.transport_caps,
    )?;
    Ok(header)
}

fn read_capabilities(
    reader: &mut impl Read,
    transcript: &mut blake3::Hasher,
    count: usize,
) -> Result<Vec<String>, TransportError> {
    let mut capabilities = Vec::new();
    for index in 0..count {
        let frame = read_transcript_frame(reader, transcript)?;
        let fields = array(&frame.value, 4)?;
        require_magic(fields, "EIC1")?;
        require_index(&fields[2], index)?;
        let capability = identifier(&fields[3])?;
        if capabilities
            .last()
            .is_some_and(|prior: &String| prior.as_bytes() >= capability.as_bytes())
        {
            return Err(TransportError::InvalidEncoding);
        }
        capabilities.push(capability);
    }
    Ok(capabilities)
}

fn read_attempt_members(
    reader: &mut impl Read,
    transcript: &mut blake3::Hasher,
    member_count: usize,
    caps: AttemptTransportCaps,
) -> Result<AttemptMembers, TransportError> {
    let mut aggregate = 0_u64;
    let schema = read_artifact(reader, transcript, 0, 0, caps, &mut aggregate)?;
    let payload = read_artifact(reader, transcript, 1, 0, caps, &mut aggregate)?;
    let mut auxiliary = Vec::new();
    for index in 0..member_count - 2 {
        auxiliary.push(read_artifact(
            reader,
            transcript,
            2,
            as_u64(index)?,
            caps,
            &mut aggregate,
        )?);
    }
    Ok(AttemptMembers {
        schema,
        payload,
        auxiliary,
    })
}

fn read_attempt_end(
    reader: &mut impl Read,
    transcript: &blake3::Hasher,
) -> Result<(), TransportError> {
    let end = read_frame(reader)?;
    let fields = array(&end.value, 3)?;
    require_magic(fields, "EIE1")?;
    if fixed_bytes::<32>(&fields[2])? != *transcript.finalize().as_bytes() {
        return Err(TransportError::InvalidEncoding);
    }
    Ok(())
}

/// Stream one exact EAO1 observation.
///
/// # Errors
/// Returns a closed failure for an invalid result or an output above the
/// compiled ceiling.
pub fn write_observation(
    mut writer: impl Write,
    observation: &SubjectObservation,
) -> Result<(), TransportError> {
    validate_observation(observation, MAX_OUTPUT_BYTES)?;
    let mut transcript = new_transcript(OBSERVATION_DOMAIN);
    write_transcript_frame(
        &mut writer,
        Value::Array(vec![text_value("EAO1"), unsigned(1)]),
        &mut transcript,
    )?;
    let (kind, length, digest, failure, divergence) = match &observation.result {
        SubjectResult::Output(output) => {
            for (index, chunk) in output.chunks(MAX_CHUNK_BYTES).enumerate() {
                write_transcript_frame(
                    &mut writer,
                    Value::Array(vec![
                        text_value("EOB1"),
                        unsigned(1),
                        unsigned(as_u64(index * MAX_CHUNK_BYTES)?),
                        Value::Bytes(chunk.to_vec()),
                    ]),
                    &mut transcript,
                )?;
            }
            (
                0,
                unsigned(as_u64(output.len())?),
                bytes_value(blake3::hash(output).as_bytes()),
                Value::Null,
                Value::Null,
            )
        }
        SubjectResult::Failure(value) => (
            1,
            Value::Null,
            Value::Null,
            failure_value(value),
            Value::Null,
        ),
        SubjectResult::Divergence {
            classification,
            first_coordinate,
        } => (
            2,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Array(vec![
                unsigned(u64::from(*classification)),
                Value::Bytes(first_coordinate.clone()),
            ]),
        ),
        SubjectResult::Unavailable => (3, Value::Null, Value::Null, Value::Null, Value::Null),
    };
    write_frame(
        &mut writer,
        Value::Array(vec![
            text_value("EOE1"),
            unsigned(1),
            unsigned(kind),
            length,
            digest,
            failure,
            divergence,
            usage_value(observation.usage),
            bytes_value(transcript.finalize().as_bytes()),
        ]),
    )?;
    writer.flush().map_err(io_error)
}

/// Decode one complete EAO1 observation under the selected output limit.
///
/// # Errors
/// Returns a closed failure for malformed, noncanonical, truncated, reordered,
/// digest-mismatched, trailing, or out-of-bounds input.
pub fn read_observation(
    mut reader: impl Read,
    selected_output_bytes: u64,
) -> Result<SubjectObservation, TransportError> {
    if selected_output_bytes == 0 || selected_output_bytes > MAX_OUTPUT_BYTES {
        return Err(TransportError::FieldOutOfBounds);
    }
    let maximum = selected_output_bytes;
    let mut transcript = new_transcript(OBSERVATION_DOMAIN);
    let start = read_transcript_frame(&mut reader, &mut transcript)?;
    let fields = array(&start.value, 2)?;
    require_magic(fields, "EAO1")?;
    let mut provisional = Vec::new();
    let end = loop {
        let frame = read_frame(&mut reader)?;
        let fields = array_values(&frame.value)?;
        match fields.first().and_then(|value| text(value).ok()) {
            Some("EOB1") => {
                frame.absorb(&mut transcript);
                read_output_chunk(fields, &mut provisional, maximum)?;
            }
            Some("EOE1") => break frame,
            _ => return Err(TransportError::InvalidEncoding),
        }
    };
    let fields = array(&end.value, 9)?;
    require_magic(fields, "EOE1")?;
    if fixed_bytes::<32>(&fields[8])? != *transcript.finalize().as_bytes() {
        return Err(TransportError::InvalidEncoding);
    }
    let result = decode_result(fields, provisional)?;
    let observation = SubjectObservation {
        result,
        usage: decode_usage(&fields[7])?,
    };
    validate_observation(&observation, maximum)?;
    require_eof(&mut reader)?;
    Ok(observation)
}

fn write_artifact(
    writer: &mut impl Write,
    transcript: &mut blake3::Hasher,
    role: u64,
    index: u64,
    artifact: &AttemptArtifact,
) -> Result<(), TransportError> {
    write_transcript_frame(
        writer,
        Value::Array(vec![
            text_value("EIM1"),
            unsigned(1),
            unsigned(role),
            unsigned(index),
            unsigned(as_u64(artifact.bytes.len())?),
            bytes_value(&artifact.digest),
            unsigned(as_u64(artifact.bytes.len().div_ceil(MAX_CHUNK_BYTES))?),
        ]),
        transcript,
    )?;
    for (chunk_index, chunk) in artifact.bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        write_transcript_frame(
            writer,
            Value::Array(vec![
                text_value("EIB1"),
                unsigned(1),
                unsigned(role),
                unsigned(index),
                unsigned(as_u64(chunk_index * MAX_CHUNK_BYTES)?),
                Value::Bytes(chunk.to_vec()),
            ]),
            transcript,
        )?;
    }
    Ok(())
}

fn read_artifact(
    reader: &mut impl Read,
    transcript: &mut blake3::Hasher,
    expected_role: u64,
    expected_index: u64,
    caps: AttemptTransportCaps,
    aggregate: &mut u64,
) -> Result<AttemptArtifact, TransportError> {
    let start = read_transcript_frame(reader, transcript)?;
    let (expected_length, digest, chunks) =
        read_artifact_header(&start.value, expected_role, expected_index, caps, aggregate)?;
    let bytes = read_artifact_chunks(
        reader,
        transcript,
        expected_role,
        expected_index,
        chunks,
        expected_length,
    )?;
    if bytes.len() != expected_length || blake3::hash(&bytes).as_bytes() != &digest {
        return Err(TransportError::InvalidEncoding);
    }
    Ok(AttemptArtifact { digest, bytes })
}

fn read_artifact_header(
    value: &Value,
    expected_role: u64,
    expected_index: u64,
    caps: AttemptTransportCaps,
    aggregate: &mut u64,
) -> Result<(usize, [u8; 32], usize), TransportError> {
    let fields = array(value, 7)?;
    require_magic(fields, "EIM1")?;
    if uint(&fields[2])? != expected_role || uint(&fields[3])? != expected_index {
        return Err(TransportError::InvalidEncoding);
    }
    let length = uint(&fields[4])?;
    if length > caps.max_member_bytes {
        return Err(TransportError::FieldOutOfBounds);
    }
    *aggregate = aggregate
        .checked_add(length)
        .ok_or(TransportError::FieldOutOfBounds)?;
    if *aggregate > caps.max_attempt_bytes {
        return Err(TransportError::FieldOutOfBounds);
    }
    let digest = nonzero_digest(&fields[5])?;
    let chunk_limit = usize::try_from(MAX_ATTEMPT_BYTES / MAX_CHUNK_BYTES as u64)
        .map_err(|_| TransportError::FieldOutOfBounds)?;
    let chunks = bounded_usize(&fields[6], chunk_limit)?;
    let expected_length = usize::try_from(length).map_err(|_| TransportError::FieldOutOfBounds)?;
    if chunks != expected_length.div_ceil(MAX_CHUNK_BYTES) {
        return Err(TransportError::InvalidEncoding);
    }
    Ok((expected_length, digest, chunks))
}

fn read_artifact_chunks(
    reader: &mut impl Read,
    transcript: &mut blake3::Hasher,
    expected_role: u64,
    expected_index: u64,
    chunks: usize,
    expected_length: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut bytes = Vec::new();
    for chunk_index in 0..chunks {
        let frame = read_transcript_frame(reader, transcript)?;
        let fields = array(&frame.value, 6)?;
        require_magic(fields, "EIB1")?;
        if uint(&fields[2])? != expected_role || uint(&fields[3])? != expected_index {
            return Err(TransportError::InvalidEncoding);
        }
        require_index(&fields[4], chunk_index * MAX_CHUNK_BYTES)?;
        let chunk = byte_string(&fields[5])?;
        validate_chunk(chunk, chunk_index + 1 == chunks)?;
        if bytes.len().saturating_add(chunk.len()) > expected_length {
            return Err(TransportError::FieldOutOfBounds);
        }
        bytes.extend_from_slice(chunk);
    }
    Ok(bytes)
}

fn read_output_chunk(
    fields: &[Value],
    provisional: &mut Vec<u8>,
    maximum: u64,
) -> Result<(), TransportError> {
    if fields.len() != 4 || uint(&fields[1])? != 1 {
        return Err(TransportError::InvalidEncoding);
    }
    require_index(&fields[2], provisional.len())?;
    let chunk = byte_string(&fields[3])?;
    if chunk.is_empty()
        || chunk.len() > MAX_CHUNK_BYTES
        || !provisional.len().is_multiple_of(MAX_CHUNK_BYTES)
    {
        return Err(TransportError::FieldOutOfBounds);
    }
    let next = provisional
        .len()
        .checked_add(chunk.len())
        .ok_or(TransportError::FieldOutOfBounds)?;
    if as_u64(next)? > maximum {
        return Err(TransportError::FieldOutOfBounds);
    }
    provisional.extend_from_slice(chunk);
    Ok(())
}

fn decode_result(fields: &[Value], provisional: Vec<u8>) -> Result<SubjectResult, TransportError> {
    match uint(&fields[2])? {
        0 if fields[5] == Value::Null && fields[6] == Value::Null => {
            let length = uint(&fields[3])?;
            let digest = fixed_bytes::<32>(&fields[4])?;
            if as_u64(provisional.len())? != length
                || blake3::hash(&provisional).as_bytes() != &digest
            {
                return Err(TransportError::InvalidEncoding);
            }
            Ok(SubjectResult::Output(provisional))
        }
        1 if fields[3] == Value::Null && fields[4] == Value::Null && fields[6] == Value::Null => {
            Ok(SubjectResult::Failure(decode_failure(&fields[5])?))
        }
        2 if fields[3] == Value::Null && fields[4] == Value::Null && fields[5] == Value::Null => {
            let divergence = array(&fields[6], 2)?;
            Ok(SubjectResult::Divergence {
                classification: bounded_u8(&divergence[0], 8)?,
                first_coordinate: byte_string(&divergence[1])?.to_vec(),
            })
        }
        3 if fields[3..=6].iter().all(|field| *field == Value::Null) => {
            Ok(SubjectResult::Unavailable)
        }
        _ => Err(TransportError::InvalidEncoding),
    }
}

fn validate_attempt(attempt: &CaseAttempt) -> Result<(), TransportError> {
    validate_header(
        attempt.watchdog_ms,
        attempt.auxiliary.len() + 2,
        attempt.transport_caps,
    )?;
    validate_attempt_fields(attempt)?;
    validate_attempt_artifacts(attempt)
}

fn validate_attempt_fields(attempt: &CaseAttempt) -> Result<(), TransportError> {
    if attempt.case_id.is_empty()
        || attempt.case_id.len() > MAX_IDENTIFIER_BYTES
        || attempt.claim_layer > 6
        || attempt.family > 6
        || attempt.mode > 3
        || attempt.fixture_digest == [0; 32]
        || attempt.capability_ids.len() > MAX_CAPABILITIES
        || !strict_strings(&attempt.capability_ids)
        || budget_values(attempt.budget).contains(&0)
        || attempt.budget.output_bytes > MAX_OUTPUT_BYTES
    {
        return Err(TransportError::FieldOutOfBounds);
    }
    Ok(())
}

fn validate_attempt_artifacts(attempt: &CaseAttempt) -> Result<(), TransportError> {
    let mut aggregate = 0_u64;
    for artifact in std::iter::once(&attempt.schema)
        .chain(std::iter::once(&attempt.payload))
        .chain(&attempt.auxiliary)
    {
        let length = as_u64(artifact.bytes.len())?;
        aggregate = aggregate
            .checked_add(length)
            .ok_or(TransportError::FieldOutOfBounds)?;
        if length > attempt.transport_caps.max_member_bytes
            || aggregate > attempt.transport_caps.max_attempt_bytes
        {
            return Err(TransportError::FieldOutOfBounds);
        }
        if artifact.digest == [0; 32]
            || blake3::hash(&artifact.bytes).as_bytes() != &artifact.digest
        {
            return Err(TransportError::InvalidEncoding);
        }
    }
    Ok(())
}

const fn validate_header(
    watchdog_ms: u64,
    members: usize,
    caps: AttemptTransportCaps,
) -> Result<(), TransportError> {
    if watchdog_ms == 0
        || members < 2
        || members > MAX_MEMBERS
        || caps.max_member_bytes == 0
        || caps.max_member_bytes > MAX_MEMBER_BYTES
        || caps.max_attempt_bytes == 0
        || caps.max_attempt_bytes > MAX_ATTEMPT_BYTES
        || caps.max_member_bytes > caps.max_attempt_bytes
    {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_observation(
    observation: &SubjectObservation,
    maximum: u64,
) -> Result<(), TransportError> {
    match &observation.result {
        SubjectResult::Output(bytes) if as_u64(bytes.len())? > maximum => {
            Err(TransportError::FieldOutOfBounds)
        }
        SubjectResult::Failure(value) => validate_failure(value),
        SubjectResult::Divergence {
            classification,
            first_coordinate,
        } => validate_divergence(*classification, first_coordinate),
        _ => Ok(()),
    }
}

const fn validate_divergence(
    classification: u8,
    first_coordinate: &[u8],
) -> Result<(), TransportError> {
    if classification > 8 || first_coordinate.is_empty() || first_coordinate.len() > 128 {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(())
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

fn write_transcript_frame(
    writer: &mut impl Write,
    value: Value,
    transcript: &mut blake3::Hasher,
) -> Result<(), TransportError> {
    let frame = encode_frame(value)?;
    frame.absorb(transcript);
    write_encoded(writer, &frame)
}

fn write_frame(writer: &mut impl Write, value: Value) -> Result<(), TransportError> {
    write_encoded(writer, &encode_frame(value)?)
}

fn write_encoded(writer: &mut impl Write, frame: &Frame) -> Result<(), TransportError> {
    writer.write_all(&frame.prefix).map_err(io_error)?;
    writer.write_all(&frame.encoded).map_err(io_error)
}

fn encode_frame(value: Value) -> Result<Frame, TransportError> {
    let encoded = encode_with_limit(&value, MAX_FRAME_BYTES)?;
    if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
        return Err(TransportError::FieldOutOfBounds);
    }
    let length = u32::try_from(encoded.len()).map_err(|_| TransportError::FieldOutOfBounds)?;
    Ok(Frame {
        prefix: length.to_be_bytes(),
        encoded,
        value,
    })
}

fn read_transcript_frame(
    reader: &mut impl Read,
    transcript: &mut blake3::Hasher,
) -> Result<Frame, TransportError> {
    let frame = read_frame(reader)?;
    frame.absorb(transcript);
    Ok(frame)
}

fn read_frame(reader: &mut impl Read) -> Result<Frame, TransportError> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).map_err(io_error)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| TransportError::FieldOutOfBounds)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(TransportError::FieldOutOfBounds);
    }
    let mut encoded = vec![0; length];
    reader.read_exact(&mut encoded).map_err(io_error)?;
    let value = decode_canonical_with_limit(&encoded, MAX_FRAME_BYTES)?;
    if nesting_depth(&value) > MAX_FRAME_NESTING {
        return Err(TransportError::FieldOutOfBounds);
    }
    Ok(Frame {
        prefix,
        encoded,
        value,
    })
}

fn require_eof(reader: &mut impl Read) -> Result<(), TransportError> {
    let mut trailing = [0];
    match reader.read(&mut trailing).map_err(io_error)? {
        0 => Ok(()),
        _ => Err(TransportError::InvalidEncoding),
    }
}

fn require_magic(fields: &[Value], magic: &str) -> Result<(), TransportError> {
    if text(&fields[0])? == magic && uint(&fields[1])? == 1 {
        Ok(())
    } else {
        Err(TransportError::UnsupportedVersion)
    }
}

fn require_index(value: &Value, index: usize) -> Result<(), TransportError> {
    if uint(value)? == as_u64(index)? {
        Ok(())
    } else {
        Err(TransportError::InvalidEncoding)
    }
}

const fn validate_chunk(chunk: &[u8], final_chunk: bool) -> Result<(), TransportError> {
    if chunk.is_empty()
        || chunk.len() > MAX_CHUNK_BYTES
        || (!final_chunk && chunk.len() != MAX_CHUNK_BYTES)
    {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn budget_value(value: DeterministicBudget) -> Value {
    Value::Array(budget_values(value).map(unsigned).to_vec())
}

const fn budget_values(value: DeterministicBudget) -> [u64; 8] {
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
}

fn decode_budget(value: &Value) -> Result<DeterministicBudget, TransportError> {
    let values = eight_uints(value)?;
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
    let values = eight_uints(value)?;
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

fn eight_uints(value: &Value) -> Result<[u64; 8], TransportError> {
    let fields = array(value, 8)?;
    fields
        .iter()
        .map(uint)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| TransportError::InvalidEncoding)
}

fn failure_value(value: &NamespacedFailure) -> Value {
    Value::Array(vec![
        text_value(&value.owner_id),
        text_value(&value.contract_version),
        text_value(&value.code_id),
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

fn nonzero_digest(value: &Value) -> Result<[u8; 32], TransportError> {
    let digest = fixed_bytes(value)?;
    if digest == [0; 32] {
        Err(TransportError::FieldOutOfBounds)
    } else {
        Ok(digest)
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

fn bounded_usize(value: &Value, maximum: usize) -> Result<usize, TransportError> {
    let value = usize::try_from(uint(value)?).map_err(|_| TransportError::FieldOutOfBounds)?;
    if value <= maximum {
        Ok(value)
    } else {
        Err(TransportError::FieldOutOfBounds)
    }
}

fn byte_string(value: &Value) -> Result<&[u8], TransportError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
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

fn array_values(value: &Value) -> Result<&[Value], TransportError> {
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err(TransportError::InvalidEncoding),
    }
}

fn nesting_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => values
            .iter()
            .map(nesting_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        _ => 0,
    }
}

fn as_u64(value: usize) -> Result<u64, TransportError> {
    u64::try_from(value).map_err(|_| TransportError::FieldOutOfBounds)
}

fn new_transcript(domain: &[u8]) -> blake3::Hasher {
    let mut transcript = blake3::Hasher::new();
    transcript.update(domain);
    transcript
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn text_value(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes_value(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn io_error(_: std::io::Error) -> TransportError {
    TransportError::InvalidEncoding
}
