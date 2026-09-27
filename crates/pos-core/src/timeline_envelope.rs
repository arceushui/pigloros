//! The exact ADR-065 Timeline integrity message. This module does not authorize
//! signing, resolve trust anchors, or make a `ReplayClaim`.

use ciborium::Value;
use thiserror::Error;
use ulid::Ulid;

use crate::{
    CanonicalBytes, CorrelationId, EntityId, Event, EventId, Hash, KeyIdentityV1, KeyRoleV1, Kind,
    Seq, TimelineId, WallTime,
};

/// Whole-input bound for the deterministic CBOR envelope.
pub const MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1: usize = 512;
/// Maximum exact payload length admitted by the V1 signature contract.
pub const MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1: usize = 16 * 1024 * 1024;
const DOMAIN: &[u8; 35] = b"pigloros/timeline-event-envelope/v1";

/// Closed structural and payload failures for an exact Timeline envelope.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TimelineEventEnvelopeErrorV1 {
    #[error("invalid Timeline envelope encoding")]
    InvalidEncoding,
    #[error("noncanonical Timeline envelope encoding")]
    NonCanonical,
    #[error("Timeline envelope field is out of bounds")]
    FieldOutOfBounds,
    #[error("Timeline envelope signing identity is invalid")]
    InvalidIdentity,
    #[error("Timeline envelope payload hash does not match")]
    PayloadHashMismatch,
    #[error("Timeline envelope signature is invalid")]
    InvalidSignature,
}

/// Finalized first-commit context, without a private key or signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineEventEnvelopeInputV1 {
    pub identity: KeyIdentityV1,
    pub origin_timeline_id: TimelineId,
    pub event_id: EventId,
    pub origin_logical_seq: Seq,
    pub entity_id: EntityId,
    pub event_type: Kind,
    pub schema_version: u32,
    pub wall_time: WallTime,
    pub causation_id: Option<EventId>,
    pub correlation_id: Option<CorrelationId>,
}

/// Immutable 14-field signed representation for `TimelineIntegritySigning`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineEventEnvelopeV1 {
    input: TimelineEventEnvelopeInputV1,
    payload_hash: Hash,
    canonical_bytes: Vec<u8>,
}

impl TimelineEventEnvelopeV1 {
    /// Reconstruct the exact signed envelope from a committed Event's
    /// retained first-commit context and signing identity.
    ///
    /// # Errors
    /// Rejects missing or invalid origin/identity context and a payload hash
    /// that differs from the exact payload bytes.
    pub fn from_committed_event(event: &Event) -> Result<Self, TimelineEventEnvelopeErrorV1> {
        let identity = event
            .signature_identity
            .ok_or(TimelineEventEnvelopeErrorV1::InvalidIdentity)?;
        let origin = event
            .origin
            .ok_or(TimelineEventEnvelopeErrorV1::FieldOutOfBounds)?;
        let envelope = Self::new(
            TimelineEventEnvelopeInputV1 {
                identity,
                origin_timeline_id: origin.origin_timeline_id,
                event_id: event.id,
                origin_logical_seq: origin.origin_logical_seq,
                entity_id: event.entity,
                event_type: event.event_type.clone(),
                schema_version: event.schema_version.as_u32(),
                wall_time: event.wall_time,
                causation_id: event.causation_id,
                correlation_id: event.correlation_id,
            },
            &event.payload,
        )?;
        if envelope.payload_hash != event.payload_hash {
            return Err(TimelineEventEnvelopeErrorV1::PayloadHashMismatch);
        }
        Ok(envelope)
    }

    /// Bind finalized context to the exact payload before signing.
    ///
    /// # Errors
    /// Rejects an invalid role, epoch, sequence, schema, event type, payload
    /// length, or an envelope exceeding the 512-byte bound.
    pub fn new(
        input: TimelineEventEnvelopeInputV1,
        payload: &CanonicalBytes,
    ) -> Result<Self, TimelineEventEnvelopeErrorV1> {
        validate_fields(&input)?;
        validate_payload_length(payload.len())?;
        let payload_hash = Hash::from_bytes(*blake3::hash(payload.as_slice()).as_bytes());
        let canonical_bytes = encode(&input, payload_hash);
        if canonical_bytes.len() > MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1 {
            return Err(TimelineEventEnvelopeErrorV1::FieldOutOfBounds);
        }
        Ok(Self {
            input,
            payload_hash,
            canonical_bytes,
        })
    }

    /// Decode only exact deterministic CBOR for the fixed 14-field array.
    /// Payload bytes must still be checked before signing or verification.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unbounded, or unsupported fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TimelineEventEnvelopeErrorV1> {
        if bytes.len() > MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1 {
            return Err(TimelineEventEnvelopeErrorV1::FieldOutOfBounds);
        }
        let value: Value = ciborium::from_reader(bytes)
            .map_err(|_| TimelineEventEnvelopeErrorV1::InvalidEncoding)?;
        let Value::Array(fields) = value else {
            return Err(TimelineEventEnvelopeErrorV1::InvalidEncoding);
        };
        if fields.len() != 14 || exact_bytes::<35>(&fields[0])? != *DOMAIN {
            return Err(TimelineEventEnvelopeErrorV1::InvalidEncoding);
        }
        let owner_id = crate::OwnerIdV1::new(text(&fields[1])?.to_owned())
            .map_err(|_| TimelineEventEnvelopeErrorV1::FieldOutOfBounds)?;
        let role = u8::try_from(unsigned(&fields[12])?)
            .map_err(|_| TimelineEventEnvelopeErrorV1::InvalidIdentity)?;
        if role != KeyRoleV1::TimelineIntegritySigning.code() {
            return Err(TimelineEventEnvelopeErrorV1::InvalidIdentity);
        }
        let identity = KeyIdentityV1::from_parts(
            owner_id,
            KeyRoleV1::TimelineIntegritySigning,
            unsigned(&fields[13])?,
        );
        let input = TimelineEventEnvelopeInputV1 {
            identity,
            origin_timeline_id: TimelineId::from_ulid(Ulid::from_bytes(exact_bytes(&fields[2])?)),
            event_id: EventId::from_ulid(Ulid::from_bytes(exact_bytes(&fields[3])?)),
            origin_logical_seq: Seq::from_u64(unsigned(&fields[4])?),
            entity_id: EntityId::from_ulid(Ulid::from_bytes(exact_bytes(&fields[5])?)),
            event_type: Kind::new(text(&fields[6])?),
            schema_version: u32::try_from(unsigned(&fields[7])?)
                .map_err(|_| TimelineEventEnvelopeErrorV1::FieldOutOfBounds)?,
            wall_time: WallTime::from_micros(unsigned(&fields[8])?),
            causation_id: optional_id(&fields[9])?
                .map(|id| EventId::from_ulid(Ulid::from_bytes(id))),
            correlation_id: optional_id(&fields[10])?
                .map(|id| CorrelationId::from_ulid(Ulid::from_bytes(id))),
        };
        let payload_hash = Hash::from_bytes(exact_bytes(&fields[11])?);
        validate_fields(&input)?;
        if encode(&input, payload_hash) != bytes {
            return Err(TimelineEventEnvelopeErrorV1::NonCanonical);
        }
        Ok(Self {
            input,
            payload_hash,
            canonical_bytes: bytes.to_vec(),
        })
    }

    /// Return the immutable finalized context.
    #[must_use]
    pub const fn input(&self) -> &TimelineEventEnvelopeInputV1 {
        &self.input
    }

    /// Return the exact owner-scoped signing identity.
    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.input.identity
    }

    /// Return the signed digest of the exact payload bytes.
    #[must_use]
    pub const fn payload_hash(&self) -> Hash {
        self.payload_hash
    }

    /// Return exactly the CBOR bytes that Ed25519 signs.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes.as_slice()
    }

    /// Recompute the payload digest before signing or verifying.
    ///
    /// # Errors
    /// Rejects an oversized or mismatched payload.
    pub fn validate_payload(
        &self,
        payload: &CanonicalBytes,
    ) -> Result<(), TimelineEventEnvelopeErrorV1> {
        validate_payload_length(payload.len())?;
        if blake3::hash(payload.as_slice()).as_bytes() != self.payload_hash.as_bytes() {
            return Err(TimelineEventEnvelopeErrorV1::PayloadHashMismatch);
        }
        Ok(())
    }
}

fn validate_fields(
    input: &TimelineEventEnvelopeInputV1,
) -> Result<(), TimelineEventEnvelopeErrorV1> {
    if input.identity.role != KeyRoleV1::TimelineIntegritySigning || input.identity.epoch == 0 {
        return Err(TimelineEventEnvelopeErrorV1::InvalidIdentity);
    }
    let event_type_length = input.event_type.as_str().len();
    if input.origin_logical_seq.as_u64() == 0
        || input.schema_version == 0
        || !(1..=256).contains(&event_type_length)
    {
        return Err(TimelineEventEnvelopeErrorV1::FieldOutOfBounds);
    }
    Ok(())
}

const fn validate_payload_length(length: usize) -> Result<(), TimelineEventEnvelopeErrorV1> {
    if length > MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1 {
        Err(TimelineEventEnvelopeErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn encode(input: &TimelineEventEnvelopeInputV1, payload_hash: Hash) -> Vec<u8> {
    let mut output = Vec::with_capacity(MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1);
    output.push(0x8e);
    encode_bytes(&mut output, DOMAIN);
    encode_text(&mut output, input.identity.owner_id.as_str());
    encode_bytes(&mut output, &input.origin_timeline_id.inner().to_bytes());
    encode_bytes(&mut output, &input.event_id.inner().to_bytes());
    encode_head(&mut output, 0, input.origin_logical_seq.as_u64());
    encode_bytes(&mut output, &input.entity_id.inner().to_bytes());
    encode_text(&mut output, input.event_type.as_str());
    encode_head(&mut output, 0, u64::from(input.schema_version));
    encode_head(&mut output, 0, input.wall_time.as_micros());
    encode_optional_id(
        &mut output,
        input.causation_id.map(|id| id.inner().to_bytes()),
    );
    encode_optional_id(
        &mut output,
        input.correlation_id.map(|id| id.inner().to_bytes()),
    );
    encode_bytes(&mut output, payload_hash.as_bytes());
    encode_head(&mut output, 0, u64::from(input.identity.role.code()));
    encode_head(&mut output, 0, input.identity.epoch);
    output
}

fn encode_optional_id(output: &mut Vec<u8>, id: Option<[u8; 16]>) {
    if let Some(id) = id {
        encode_bytes(output, &id);
    } else {
        output.push(0xf6);
    }
}

fn encode_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(output, 2, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

fn encode_text(output: &mut Vec<u8>, value: &str) {
    encode_head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn encode_head(output: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let tag = major << 5;
    match value {
        0..=23 => output.push(tag | bytes[7]),
        24..=255 => output.extend_from_slice(&[tag | 0x18, bytes[7]]),
        256..=65_535 => {
            output.push(tag | 0x19);
            output.extend_from_slice(&bytes[6..]);
        }
        65_536..=4_294_967_295 => {
            output.push(tag | 0x1a);
            output.extend_from_slice(&bytes[4..]);
        }
        _ => {
            output.push(tag | 0x1b);
            output.extend_from_slice(&bytes);
        }
    }
}

fn text(value: &Value) -> Result<&str, TimelineEventEnvelopeErrorV1> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(TimelineEventEnvelopeErrorV1::InvalidEncoding),
    }
}

fn unsigned(value: &Value) -> Result<u64, TimelineEventEnvelopeErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| TimelineEventEnvelopeErrorV1::InvalidEncoding)
        }
        _ => Err(TimelineEventEnvelopeErrorV1::InvalidEncoding),
    }
}

fn exact_bytes<const N: usize>(value: &Value) -> Result<[u8; N], TimelineEventEnvelopeErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| TimelineEventEnvelopeErrorV1::InvalidEncoding),
        _ => Err(TimelineEventEnvelopeErrorV1::InvalidEncoding),
    }
}

fn optional_id(value: &Value) -> Result<Option<[u8; 16]>, TimelineEventEnvelopeErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        exact_bytes(value).map(Some)
    }
}
