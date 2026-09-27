use super::super::codec::{
    array, bytes, decode, digest, encode, fixed, uint, validate_magic, value_bytes, value_text,
    value_uint,
};
use super::super::{
    SandboxContractErrorV1, MAX_SANDBOX_PAYLOAD_BYTES_V1, MAX_SANDBOX_PAYLOAD_CHUNKS_V1,
    SANDBOX_PAYLOAD_CHUNK_BYTES_V1,
};
use ciborium::value::Value;

const SBC1: &str = "SBC1";

/// Direction of one provider payload transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadDirectionV1 {
    /// Evaluator-to-provider adapter input.
    Input,
    /// Provider-to-evaluator adapter output.
    Output,
}

impl PayloadDirectionV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Input => 0,
            Self::Output => 1,
        }
    }

    const fn from_code(code: u64) -> Result<Self, SandboxContractErrorV1> {
        match code {
            0 => Ok(Self::Input),
            1 => Ok(Self::Output),
            _ => Err(SandboxContractErrorV1::FieldOutOfBounds),
        }
    }

    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::Input => b"PiglorOS.SandboxInputBytes.v1\0",
            Self::Output => b"PiglorOS.SandboxOutputBytes.v1\0",
        }
    }
}

/// Bounded content-addressed payload descriptor carried by SPX1 or SPY1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadDescriptorV1 {
    /// Exact payload byte length.
    pub byte_length: u64,
    /// Direction-separated BLAKE3 digest of the complete payload.
    pub digest: [u8; 32],
}

impl PayloadDescriptorV1 {
    /// Construct a descriptor from exact payload bytes.
    ///
    /// # Errors
    /// Returns a closed error when the payload exceeds 128 MiB.
    pub fn from_bytes(
        direction: PayloadDirectionV1,
        bytes: &[u8],
    ) -> Result<Self, SandboxContractErrorV1> {
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| SandboxContractErrorV1::FieldOutOfBounds)?;
        if byte_length > MAX_SANDBOX_PAYLOAD_BYTES_V1 {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(direction.digest_domain());
        hasher.update(bytes);
        Ok(Self {
            byte_length,
            digest: *hasher.finalize().as_bytes(),
        })
    }

    pub(super) fn validate_for_direction(
        &self,
        direction: PayloadDirectionV1,
    ) -> Result<(), SandboxContractErrorV1> {
        if self.byte_length > MAX_SANDBOX_PAYLOAD_BYTES_V1 {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        if self.byte_length == 0 && self.digest != Self::from_bytes(direction, &[])?.digest {
            return Err(SandboxContractErrorV1::DigestMismatch);
        }
        Ok(())
    }
}

/// One self-digested, parent-bound SBC1 payload chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPayloadChunkV1 {
    pub parent_digest: [u8; 32],
    pub request_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub direction: PayloadDirectionV1,
    pub index: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub chunk_digest: [u8; 32],
}

impl SandboxPayloadChunkV1 {
    /// Compute and install the SBC1 self-digest.
    ///
    /// # Errors
    /// Returns a closed error when an unsigned field is invalid.
    pub fn seal(mut self) -> Result<Self, SandboxContractErrorV1> {
        self.validate_unsigned()?;
        digest(SBC1, &self.unsigned_value()).map(|digest| {
            self.chunk_digest = digest;
            self
        })
    }

    /// Validate the chunk shape and self-digest.
    ///
    /// # Errors
    /// Returns a closed error for malformed chunk metadata or bytes.
    pub fn validate(&self) -> Result<(), SandboxContractErrorV1> {
        self.validate_unsigned()?;
        digest(SBC1, &self.unsigned_value()).and_then(|digest| {
            (self.chunk_digest == digest)
                .then_some(())
                .ok_or(SandboxContractErrorV1::DigestMismatch)
        })
    }

    /// Encode exact deterministic-CBOR SBC1 bytes.
    ///
    /// # Errors
    /// Returns a closed error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SandboxContractErrorV1> {
        self.validate()?;
        encode(&Value::Array(vec![
            self.unsigned_value(),
            value_bytes(&self.chunk_digest),
        ]))
    }

    /// Decode exact deterministic-CBOR SBC1 bytes.
    ///
    /// # Errors
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(document_bytes: &[u8]) -> Result<Self, SandboxContractErrorV1> {
        let value = decode(document_bytes)?;
        let wrapper = array::<2>(&value)?;
        let fields = array::<9>(&wrapper[0])?;
        validate_magic(fields, SBC1)?;
        let chunk = Self {
            parent_digest: fixed(&fields[2])?,
            request_id: fixed(&fields[3])?,
            attempt_id: fixed(&fields[4])?,
            direction: PayloadDirectionV1::from_code(uint(&fields[5])?)?,
            index: uint(&fields[6])?,
            offset: uint(&fields[7])?,
            bytes: bytes(&fields[8])?.to_vec(),
            chunk_digest: fixed(&wrapper[1])?,
        };
        chunk.validate().map(|()| chunk)
    }

    fn validate_unsigned(&self) -> Result<(), SandboxContractErrorV1> {
        let expected_offset = self
            .index
            .checked_mul(SANDBOX_PAYLOAD_CHUNK_BYTES_V1 as u64)
            .ok_or(SandboxContractErrorV1::FieldOutOfBounds)?;
        if self.parent_digest == [0; 32]
            || self.request_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.index >= MAX_SANDBOX_PAYLOAD_CHUNKS_V1
            || self.offset != expected_offset
            || self.bytes.is_empty()
            || self.bytes.len() > SANDBOX_PAYLOAD_CHUNK_BYTES_V1
        {
            Err(SandboxContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    fn unsigned_value(&self) -> Value {
        Value::Array(vec![
            value_text(SBC1),
            value_uint(1),
            value_bytes(&self.parent_digest),
            value_bytes(&self.request_id),
            value_bytes(&self.attempt_id),
            value_uint(self.direction.code()),
            value_uint(self.index),
            value_uint(self.offset),
            value_bytes(&self.bytes),
        ])
    }
}

/// Incremental validator for one non-interleaved SBC1 payload sequence.
pub struct PayloadStreamValidatorV1 {
    parent_digest: [u8; 32],
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    direction: PayloadDirectionV1,
    descriptor: PayloadDescriptorV1,
    next_index: u64,
    accepted_bytes: u64,
    hasher: blake3::Hasher,
}

impl PayloadStreamValidatorV1 {
    /// Begin validating one descriptor-bound transfer.
    ///
    /// # Errors
    /// Returns a closed error for zero identities or an oversized descriptor.
    pub fn new(
        parent_digest: [u8; 32],
        request_id: [u8; 16],
        attempt_id: [u8; 16],
        direction: PayloadDirectionV1,
        descriptor: PayloadDescriptorV1,
    ) -> Result<Self, SandboxContractErrorV1> {
        descriptor.validate_for_direction(direction)?;
        if parent_digest == [0; 32] || request_id == [0; 16] || attempt_id == [0; 16] {
            return Err(SandboxContractErrorV1::FieldOutOfBounds);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(direction.digest_domain());
        Ok(Self {
            parent_digest,
            request_id,
            attempt_id,
            direction,
            descriptor,
            next_index: 0,
            accepted_bytes: 0,
            hasher,
        })
    }

    /// Accept the next exact contiguous chunk.
    ///
    /// # Errors
    /// Rejects a foreign, duplicate, reordered, gapped, or wrongly sized chunk.
    pub fn accept(&mut self, chunk: &SandboxPayloadChunkV1) -> Result<(), SandboxContractErrorV1> {
        chunk.validate()?;
        let remaining = self
            .descriptor
            .byte_length
            .saturating_sub(self.accepted_bytes);
        let expected_size = remaining.min(SANDBOX_PAYLOAD_CHUNK_BYTES_V1 as u64);
        let identity_mismatch = chunk.parent_digest != self.parent_digest
            || chunk.request_id != self.request_id
            || chunk.attempt_id != self.attempt_id
            || chunk.direction != self.direction;
        let position_mismatch = chunk.index != self.next_index
            || chunk.offset != self.accepted_bytes
            || chunk.bytes.len() as u64 != expected_size
            || expected_size == 0;
        if identity_mismatch || position_mismatch {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        self.hasher.update(&chunk.bytes);
        self.accepted_bytes += expected_size;
        self.next_index += 1;
        Ok(())
    }

    /// Finish after the exact descriptor length and digest have been observed.
    ///
    /// # Errors
    /// Rejects missing chunks or an aggregate payload-digest mismatch.
    pub fn finish(self) -> Result<(), SandboxContractErrorV1> {
        if self.accepted_bytes != self.descriptor.byte_length {
            return Err(SandboxContractErrorV1::InconsistentFields);
        }
        (self.hasher.finalize().as_bytes() == &self.descriptor.digest)
            .then_some(())
            .ok_or(SandboxContractErrorV1::DigestMismatch)
    }
}

// Implementations are kept below the data model so the public field order is
// readable beside ADR-069's wire order.

pub(super) fn payload_descriptor_value(value: &PayloadDescriptorV1) -> Value {
    Value::Array(vec![
        value_uint(value.byte_length),
        value_bytes(&value.digest),
    ])
}

pub(super) fn decode_payload_descriptor(
    value: &Value,
) -> Result<PayloadDescriptorV1, SandboxContractErrorV1> {
    let fields = array::<2>(value)?;
    Ok(PayloadDescriptorV1 {
        byte_length: uint(&fields[0])?,
        digest: fixed(&fields[1])?,
    })
}
