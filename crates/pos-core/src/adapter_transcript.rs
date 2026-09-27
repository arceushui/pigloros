//! ADR-101 AIR1 and MAT1 structural bytes for one selected `World` run.
//!
//! A decoded transcript does not prove a closed host recorder, an admitted
//! MAA1 policy, actual `PublicRecord` provenance, or protected-use authority.

use crate::{public_adapter_schema_digest_v1, Hash, PluginId, WorldReplayHandleV1};
use std::collections::BTreeMap;
use ulid::Ulid;

/// Maximum exact AIR1 input or output byte string in one MAT1 call.
pub const MAX_ADAPTER_CALL_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of captured calls in one MAT1 transcript.
pub const MAX_ADAPTER_TRANSCRIPT_CALLS_V1: usize = 1_048_576;
/// ADR-093 maximum retained artifact bytes for the first guarded profile.
pub const MAX_ADAPTER_TRANSCRIPT_BYTES_V1: usize = 256 * 1024 * 1024;

/// A closed structural AIR1/MAT1 failure; it grants no owner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterTranscriptErrorV1 {
    /// Wrong CBOR shape, type, magic, version, or truncated input.
    #[error("invalid AIR1 or MAT1 encoding")]
    InvalidEncoding,
    /// Input has a nonpreferred CBOR width or trailing bytes.
    #[error("noncanonical AIR1 or MAT1 encoding")]
    NonCanonical,
    /// A count, byte string, or whole record exceeds its accepted bound.
    #[error("AIR1 or MAT1 field exceeds its byte bound")]
    FieldOutOfBounds,
    /// Owner, handle, operation, or admission identity is invalid.
    #[error("invalid MAT1 identity")]
    InvalidIdentity,
    /// A call violates the fixed public adapter schema or digest contract.
    #[error("invalid MAT1 call")]
    InvalidCall,
    /// Global or per-`Plugin` call sequence is not contiguous.
    #[error("invalid MAT1 call order")]
    InvalidOrder,
}

/// Exact AIR1 fields; the owner must still compare them with its MAA1 row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterInvocationInputV1 {
    pub adapter_id: String,
    pub provider_id: String,
    pub operation_id: String,
    pub protocol_version: u64,
    pub request_schema_digest: Hash,
    pub response_schema_digest: Hash,
    pub configuration_digest: Hash,
    pub global_call_index: u64,
    pub exact_request_payload: Vec<u8>,
}

/// Canonical AIR1 request envelope without an admitted invocation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterInvocationV1(AdapterInvocationInputV1);

impl AdapterInvocationV1 {
    /// Validate the fixed public-byte schema and bounded request envelope.
    ///
    /// # Errors
    /// Rejects invalid identities, schema, configuration digest, or size.
    pub fn new(input: AdapterInvocationInputV1) -> Result<Self, AdapterTranscriptErrorV1> {
        if [&input.adapter_id, &input.provider_id, &input.operation_id]
            .iter()
            .any(|id| !valid_identity(id))
            || input.protocol_version == 0
            || input.request_schema_digest != public_adapter_schema_digest_v1()
            || input.response_schema_digest != public_adapter_schema_digest_v1()
            || input.configuration_digest == Hash::zero()
        {
            return Err(AdapterTranscriptErrorV1::InvalidCall);
        }
        if input.exact_request_payload.len() > MAX_ADAPTER_CALL_BYTES_V1 {
            return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
        }
        if invocation_size(&input) > MAX_ADAPTER_CALL_BYTES_V1 {
            return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    /// Borrow structurally checked fields without owner-admission authority.
    #[must_use]
    pub const fn as_input(&self) -> &AdapterInvocationInputV1 {
        &self.0
    }

    /// Encode the exact eleven-field preferred definite AIR1 array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(invocation_size(&self.0));
        bytes.extend_from_slice(&[0x8b, 0x44]);
        bytes.extend_from_slice(b"AIR1");
        bytes.push(1);
        for id in [
            &self.0.adapter_id,
            &self.0.provider_id,
            &self.0.operation_id,
        ] {
            encode_bytes(&mut bytes, id.as_bytes(), 3);
        }
        encode_head(&mut bytes, 0, self.0.protocol_version);
        for digest in [
            self.0.request_schema_digest,
            self.0.response_schema_digest,
            self.0.configuration_digest,
        ] {
            encode_hash(&mut bytes, digest);
        }
        encode_head(&mut bytes, 0, self.0.global_call_index);
        encode_bytes(&mut bytes, &self.0.exact_request_payload, 2);
        bytes
    }

    /// ADR-101 input digest, including operation identity and global order.
    #[must_use]
    pub fn digest(&self) -> Hash {
        length_hash(
            b"pigloros.repro.adapter-input.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode bounded preferred AIR1 bytes and recheck exact encoding.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, excessive, or invalid envelopes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, AdapterTranscriptErrorV1> {
        if bytes.len() > MAX_ADAPTER_CALL_BYTES_V1 {
            return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.fixed(&[0x8b, 0x44, b'A', b'I', b'R', b'1', 1])?;
        let input = AdapterInvocationInputV1 {
            adapter_id: reader.identity()?,
            provider_id: reader.identity()?,
            operation_id: reader.identity()?,
            protocol_version: reader.head(0)?,
            request_schema_digest: reader.hash()?,
            response_schema_digest: reader.hash()?,
            configuration_digest: reader.hash()?,
            global_call_index: reader.head(0)?,
            exact_request_payload: reader.bounded_bytes(2, MAX_ADAPTER_CALL_BYTES_V1)?.to_vec(),
        };
        if reader.offset != bytes.len() {
            return Err(AdapterTranscriptErrorV1::NonCanonical);
        }
        let invocation = Self::new(input)?;
        if invocation.to_canonical_cbor() != bytes {
            return Err(AdapterTranscriptErrorV1::NonCanonical);
        }
        Ok(invocation)
    }
}

/// One captured call's exact public bytes and ordering metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterTranscriptCallV1 {
    pub plugin_id: PluginId,
    pub per_plugin_call_index: u64,
    pub input: AdapterInvocationV1,
    pub exact_output_bytes: Vec<u8>,
    pub recorded_wall_time_micros: u64,
}

/// Untrusted MAT1 fields; an owner must derive these from a closed recorder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterTranscriptInputV1 {
    pub owner_reference: Hash,
    pub world_handle: WorldReplayHandleV1,
    pub run_operation_id: Hash,
    pub adapter_admission_digest: Hash,
    pub calls: Vec<AdapterTranscriptCallV1>,
}

/// Canonical MAT1 call transcript without owner or recorder authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterTranscriptV1(AdapterTranscriptInputV1);

impl AdapterTranscriptV1 {
    /// Check structural identities, byte bounds, and contiguous call order.
    ///
    /// # Errors
    /// Rejects wrong owner, excessive bytes/count, or gaps and duplicates.
    pub fn new(input: AdapterTranscriptInputV1) -> Result<Self, AdapterTranscriptErrorV1> {
        if input.owner_reference == Hash::zero()
            || input.owner_reference != input.world_handle.as_input().owner_reference
            || input.run_operation_id == Hash::zero()
            || input.adapter_admission_digest == Hash::zero()
        {
            return Err(AdapterTranscriptErrorV1::InvalidIdentity);
        }
        if input.calls.len() > MAX_ADAPTER_TRANSCRIPT_CALLS_V1
            || input
                .calls
                .iter()
                .any(|call| call.exact_output_bytes.len() > MAX_ADAPTER_CALL_BYTES_V1)
        {
            return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
        }
        let mut next_per_plugin = BTreeMap::<PluginId, u64>::new();
        for (global_index, call) in input.calls.iter().enumerate() {
            // The checked call-count ceiling bounds this index below 2^20.
            if call.input.as_input().global_call_index != global_index as u64 {
                return Err(AdapterTranscriptErrorV1::InvalidOrder);
            }
            let next = next_per_plugin.entry(call.plugin_id).or_insert(0);
            if call.per_plugin_call_index != *next {
                return Err(AdapterTranscriptErrorV1::InvalidOrder);
            }
            *next += 1;
        }
        let handle_len = input.world_handle.to_canonical_cbor().len();
        let mut size =
            7 + 34 + framed_size(handle_len) + 34 + 34 + head_size(input.calls.len() as u64);
        for call in &input.calls {
            size += 1
                + framed_size(16)
                + head_size(call.per_plugin_call_index)
                + framed_size(invocation_size(call.input.as_input()))
                + 34
                + framed_size(call.exact_output_bytes.len())
                + 34
                + head_size(call.recorded_wall_time_micros);
            if size > MAX_ADAPTER_TRANSCRIPT_BYTES_V1 {
                return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
            }
        }
        Ok(Self(input))
    }

    /// Borrow structurally checked fields without granting release authority.
    #[must_use]
    pub const fn as_input(&self) -> &AdapterTranscriptInputV1 {
        &self.0
    }

    /// Encode the exact seven-field preferred definite MAT1 array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x87, 0x44]);
        bytes.extend_from_slice(b"MAT1");
        bytes.push(1);
        encode_hash(&mut bytes, self.0.owner_reference);
        encode_bytes(&mut bytes, &self.0.world_handle.to_canonical_cbor(), 2);
        encode_hash(&mut bytes, self.0.run_operation_id);
        encode_hash(&mut bytes, self.0.adapter_admission_digest);
        encode_head(&mut bytes, 4, self.0.calls.len() as u64);
        for call in &self.0.calls {
            bytes.push(0x87);
            encode_bytes(
                &mut bytes,
                &u128::from(call.plugin_id.inner()).to_be_bytes(),
                2,
            );
            encode_head(&mut bytes, 0, call.per_plugin_call_index);
            encode_bytes(&mut bytes, &call.input.to_canonical_cbor(), 2);
            encode_hash(&mut bytes, call.input.digest());
            encode_bytes(&mut bytes, &call.exact_output_bytes, 2);
            encode_hash(
                &mut bytes,
                adapter_output_digest_v1(&call.exact_output_bytes),
            );
            encode_head(&mut bytes, 0, call.recorded_wall_time_micros);
        }
        bytes
    }

    /// Native BLAKE3 identity of exact canonical MAT1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        hash_bytes(
            b"pigloros.repro.adapter-transcript.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode bounded MAT1 bytes, call digests, and preferred encoding.
    ///
    /// # Errors
    /// Rejects malformed, excessive, reordered, modified, or invalid calls.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, AdapterTranscriptErrorV1> {
        if bytes.len() > MAX_ADAPTER_TRANSCRIPT_BYTES_V1 {
            return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.fixed(&[0x87, 0x44, b'M', b'A', b'T', b'1', 1])?;
        let owner_reference = reader.hash()?;
        let handle_bytes = reader.bounded_bytes(2, 256)?;
        let world_handle = WorldReplayHandleV1::from_canonical_cbor(handle_bytes)
            .map_err(|_| AdapterTranscriptErrorV1::InvalidEncoding)?;
        let run_operation_id = reader.hash()?;
        let adapter_admission_digest = reader.hash()?;
        let count = reader.head(4)?;
        if count > MAX_ADAPTER_TRANSCRIPT_CALLS_V1 as u64 {
            return Err(AdapterTranscriptErrorV1::FieldOutOfBounds);
        }
        let mut calls = Vec::new();
        for _ in 0..count {
            reader.fixed(&[0x87])?;
            let plugin_id =
                PluginId::from_ulid(Ulid::from(u128::from_be_bytes(reader.blob::<16>()?)));
            let per_plugin_call_index = reader.head(0)?;
            let input_bytes = reader.bounded_bytes(2, MAX_ADAPTER_CALL_BYTES_V1)?;
            let input = AdapterInvocationV1::from_canonical_cbor(input_bytes)?;
            let input_digest = reader.hash()?;
            if input_digest != input.digest() {
                return Err(AdapterTranscriptErrorV1::InvalidCall);
            }
            let exact_output_bytes = reader.bounded_bytes(2, MAX_ADAPTER_CALL_BYTES_V1)?.to_vec();
            let output_digest = reader.hash()?;
            if output_digest != adapter_output_digest_v1(&exact_output_bytes) {
                return Err(AdapterTranscriptErrorV1::InvalidCall);
            }
            let recorded_wall_time_micros = reader.head(0)?;
            calls.push(AdapterTranscriptCallV1 {
                plugin_id,
                per_plugin_call_index,
                input,
                exact_output_bytes,
                recorded_wall_time_micros,
            });
        }
        if reader.offset != bytes.len() {
            return Err(AdapterTranscriptErrorV1::NonCanonical);
        }
        let transcript = Self::new(AdapterTranscriptInputV1 {
            owner_reference,
            world_handle,
            run_operation_id,
            adapter_admission_digest,
            calls,
        })?;
        if transcript.to_canonical_cbor() != bytes {
            return Err(AdapterTranscriptErrorV1::NonCanonical);
        }
        Ok(transcript)
    }
}

/// ADR-101 output digest with exact byte-length framing.
#[must_use]
pub fn adapter_output_digest_v1(bytes: &[u8]) -> Hash {
    length_hash(b"pigloros.repro.adapter-output.v1\0", bytes)
}

fn length_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn hash_bytes(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn valid_identity(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn invocation_size(input: &AdapterInvocationInputV1) -> usize {
    7 + [
        input.adapter_id.len(),
        input.provider_id.len(),
        input.operation_id.len(),
    ]
    .into_iter()
    .map(framed_size)
    .sum::<usize>()
        + head_size(input.protocol_version)
        + 3 * 34
        + head_size(input.global_call_index)
        + framed_size(input.exact_request_payload.len())
}

const fn framed_size(length: usize) -> usize {
    head_size(length as u64) + length
}

const fn head_size(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn encode_hash(out: &mut Vec<u8>, hash: Hash) {
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(hash.as_bytes());
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8], major: u8) {
    encode_head(out, major, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    let full = value.to_be_bytes();
    match value {
        0..=23 => out.push(prefix | full[7]),
        24..=0xff => out.extend_from_slice(&[prefix | 0x18, full[7]]),
        0x100..=0xffff => {
            out.push(prefix | 0x19);
            out.extend_from_slice(&full[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 0x1a);
            out.extend_from_slice(&full[4..]);
        }
        _ => {
            out.push(prefix | 0x1b);
            out.extend_from_slice(&full);
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn fixed(&mut self, expected: &[u8]) -> Result<(), AdapterTranscriptErrorV1> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(AdapterTranscriptErrorV1::InvalidEncoding)
        }
    }

    fn hash(&mut self) -> Result<Hash, AdapterTranscriptErrorV1> {
        Ok(Hash::from_bytes(self.blob::<32>()?))
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], AdapterTranscriptErrorV1> {
        if self.head(2)? != N as u64 {
            return Err(AdapterTranscriptErrorV1::InvalidEncoding);
        }
        let mut result = [0; N];
        result.copy_from_slice(self.take(N)?);
        Ok(result)
    }

    fn identity(&mut self) -> Result<String, AdapterTranscriptErrorV1> {
        let bytes = self.bounded_bytes(3, 128)?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| AdapterTranscriptErrorV1::InvalidEncoding)?;
        Ok(text.to_owned())
    }

    fn bounded_bytes(
        &mut self,
        major: u8,
        maximum: usize,
    ) -> Result<&[u8], AdapterTranscriptErrorV1> {
        match usize::try_from(self.head(major)?) {
            Ok(length) if length <= maximum => self.take(length),
            _ => Err(AdapterTranscriptErrorV1::FieldOutOfBounds),
        }
    }

    fn head(&mut self, major: u8) -> Result<u64, AdapterTranscriptErrorV1> {
        let tag = self.take(1)?[0];
        if tag >> 5 != major {
            return Err(AdapterTranscriptErrorV1::InvalidEncoding);
        }
        match tag & 0x1f {
            small @ 0..=23 => Ok(u64::from(small)),
            24 => self.number::<1>(),
            25 => self.number::<2>(),
            26 => self.number::<4>(),
            27 => self.number::<8>(),
            _ => Err(AdapterTranscriptErrorV1::InvalidEncoding),
        }
    }

    fn number<const N: usize>(&mut self) -> Result<u64, AdapterTranscriptErrorV1> {
        Ok(self
            .take(N)?
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    fn take(&mut self, length: usize) -> Result<&[u8], AdapterTranscriptErrorV1> {
        let end = self.offset.saturating_add(length);
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AdapterTranscriptErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
}
