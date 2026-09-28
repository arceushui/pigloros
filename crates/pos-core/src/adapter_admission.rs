//! ADR-101 MAA1 adapter admission bytes.
//!
//! These structural bytes do not prove owner admission, `PublicRecord`
//! provenance, a complete Plugin roster, or authority to invoke an adapter.

use crate::{encode_head, Hash, PluginId};
use ulid::Ulid;

/// One admitted Plugin operation, before any owner-authority claim.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AdapterContractKey<'a> {
    pub plugin_id: PluginId,
    pub adapter_id: &'a str,
    pub provider_id: &'a str,
    pub operation_id: &'a str,
    pub protocol_version: u64,
}

pub(crate) fn valid_adapter_identity(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Largest accepted MAA1 record, including all adapter entries.
pub const MAX_ADAPTER_ADMISSION_BYTES_V1: usize = 16 * 1024 * 1024;
/// Largest number of adapter entries in one owner admission.
pub const MAX_ADAPTER_ADMISSION_ENTRIES_V1: usize = 1_024;
/// Largest exact public configuration byte string in one entry.
pub const MAX_ADAPTER_CONFIGURATION_BYTES_V1: usize = 4_096;

const SCHEMA: &[u8] = b"pigloros.repro.public-bytes-v1";

// All accepted fields together fit well below the whole-record ceiling.
const _: () = assert!(
    7 + 34
        + 9
        + 34
        + 3
        + MAX_ADAPTER_ADMISSION_ENTRIES_V1
            * (1 + 17 + 3 * 130 + 9 + 2 * 34 + 3 + MAX_ADAPTER_CONFIGURATION_BYTES_V1 + 34 + 3)
        <= MAX_ADAPTER_ADMISSION_BYTES_V1
);

/// Structural MAA1 validation failure; no variant grants owner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterAdmissionErrorV1 {
    /// Wrong CBOR shape, type, magic, version, or truncated input.
    #[error("invalid MAA1 encoding")]
    InvalidEncoding,
    /// Input has a nonpreferred CBOR width or trailing bytes.
    #[error("noncanonical MAA1 encoding")]
    NonCanonical,
    /// A count, string, or byte string exceeds its accepted bound.
    #[error("MAA1 field exceeds its byte bound")]
    FieldOutOfBounds,
    /// Owner, scope, or configuration generation is invalid.
    #[error("invalid MAA1 identity")]
    InvalidIdentity,
    /// An entry violates the fixed public adapter profile.
    #[error("invalid MAA1 adapter entry")]
    InvalidEntry,
    /// Adapter entries are not strictly sorted and unique.
    #[error("invalid MAA1 adapter order")]
    InvalidOrder,
}

/// Data classification admitted by the first public adapter profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdapterDataClassV1 {
    /// Exact public input or output bytes.
    PublicRecord = 2,
}

impl TryFrom<u8> for AdapterDataClassV1 {
    type Error = AdapterAdmissionErrorV1;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::PublicRecord),
            _ => Err(AdapterAdmissionErrorV1::InvalidEntry),
        }
    }
}

/// Effect behavior admitted by the first public adapter profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdapterEffectModeV1 {
    /// Provider call does not mutate external state.
    ReadOnly = 0,
    /// Provider enforces the owner-supplied idempotency key.
    ExternallyIdempotent = 1,
}

impl TryFrom<u8> for AdapterEffectModeV1 {
    type Error = AdapterAdmissionErrorV1;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ReadOnly),
            1 => Ok(Self::ExternallyIdempotent),
            _ => Err(AdapterAdmissionErrorV1::InvalidEntry),
        }
    }
}

/// Untrusted adapter contract fields, subject to actual owner admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterAdmissionEntryV1 {
    pub plugin_id: PluginId,
    pub adapter_id: String,
    pub provider_id: String,
    pub operation_id: String,
    pub protocol_version: u64,
    pub request_schema_digest: Hash,
    pub response_schema_digest: Hash,
    pub exact_configuration_bytes: Vec<u8>,
    pub configuration_digest: Hash,
    pub input_data_class: AdapterDataClassV1,
    pub output_data_class: AdapterDataClassV1,
    pub effect_mode: AdapterEffectModeV1,
}

impl AdapterAdmissionEntryV1 {
    pub(crate) fn contract_key(&self) -> AdapterContractKey<'_> {
        AdapterContractKey {
            plugin_id: self.plugin_id,
            adapter_id: &self.adapter_id,
            provider_id: &self.provider_id,
            operation_id: &self.operation_id,
            protocol_version: self.protocol_version,
        }
    }
}

/// Untrusted snapshot fields. An owner must derive and compare them at commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterAdmissionInputV1 {
    pub owner_reference: Hash,
    pub configuration_generation: u64,
    pub scope_digest: Hash,
    pub entries: Vec<AdapterAdmissionEntryV1>,
}

/// Canonical MAA1 bytes without a catalog or authenticated admission claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterAdmissionV1(AdapterAdmissionInputV1);

impl AdapterAdmissionV1 {
    /// Validate the fixed `PublicRecord` profile and exact entry order.
    ///
    /// # Errors
    /// Rejects invalid identities, entries, counts, order, or record length.
    pub fn new(input: AdapterAdmissionInputV1) -> Result<Self, AdapterAdmissionErrorV1> {
        if input.owner_reference == Hash::zero()
            || input.configuration_generation == 0
            || input.scope_digest == Hash::zero()
        {
            return Err(AdapterAdmissionErrorV1::InvalidIdentity);
        }
        if input.entries.len() > MAX_ADAPTER_ADMISSION_ENTRIES_V1 {
            return Err(AdapterAdmissionErrorV1::FieldOutOfBounds);
        }
        for entry in &input.entries {
            validate_entry(entry)?;
        }
        if input
            .entries
            .windows(2)
            .any(|pair| pair[0].contract_key() >= pair[1].contract_key())
        {
            return Err(AdapterAdmissionErrorV1::InvalidOrder);
        }
        Ok(Self(input))
    }

    /// Borrow structurally checked fields without granting owner authority.
    #[must_use]
    pub const fn as_input(&self) -> &AdapterAdmissionInputV1 {
        &self.0
    }

    /// Encode the exact six-field preferred definite MAA1 record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x86, 0x44]);
        bytes.extend_from_slice(b"MAA1");
        bytes.push(1);
        encode_hash(&mut bytes, self.0.owner_reference);
        encode_head(&mut bytes, 0, self.0.configuration_generation);
        encode_hash(&mut bytes, self.0.scope_digest);
        encode_head(&mut bytes, 4, self.0.entries.len() as u64);
        for entry in &self.0.entries {
            bytes.push(0x8c);
            encode_bytes(
                &mut bytes,
                &u128::from(entry.plugin_id.inner()).to_be_bytes(),
                2,
            );
            for id in [&entry.adapter_id, &entry.provider_id, &entry.operation_id] {
                encode_bytes(&mut bytes, id.as_bytes(), 3);
            }
            encode_head(&mut bytes, 0, entry.protocol_version);
            encode_hash(&mut bytes, entry.request_schema_digest);
            encode_hash(&mut bytes, entry.response_schema_digest);
            encode_bytes(&mut bytes, &entry.exact_configuration_bytes, 2);
            encode_hash(&mut bytes, entry.configuration_digest);
            for code in [
                entry.input_data_class as u8,
                entry.output_data_class as u8,
                entry.effect_mode as u8,
            ] {
                encode_head(&mut bytes, 0, u64::from(code));
            }
        }
        bytes
    }

    /// Native BLAKE3 identity of exact canonical MAA1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        hash_bytes(
            b"pigloros.repro.adapter-admission.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode a bounded MAA1 record and require exact preferred re-encoding.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, AdapterAdmissionErrorV1> {
        if bytes.len() > MAX_ADAPTER_ADMISSION_BYTES_V1 {
            return Err(AdapterAdmissionErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.fixed(&[0x86, 0x44, b'M', b'A', b'A', b'1', 1])?;
        let owner_reference = reader.hash()?;
        let configuration_generation = reader.head(0)?;
        let scope_digest = reader.hash()?;
        let count = reader.head(4)?;
        if count > MAX_ADAPTER_ADMISSION_ENTRIES_V1 as u64 {
            return Err(AdapterAdmissionErrorV1::FieldOutOfBounds);
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            reader.fixed(&[0x8c])?;
            let plugin_id =
                PluginId::from_ulid(Ulid::from(u128::from_be_bytes(reader.blob::<16>()?)));
            let adapter_id = reader.identity()?;
            let provider_id = reader.identity()?;
            let operation_id = reader.identity()?;
            let protocol_version = reader.head(0)?;
            let request_schema_digest = reader.hash()?;
            let response_schema_digest = reader.hash()?;
            let exact_configuration_bytes = reader
                .bounded_bytes(2, MAX_ADAPTER_CONFIGURATION_BYTES_V1)?
                .to_vec();
            let configuration_digest = reader.hash()?;
            let input_data_class = AdapterDataClassV1::try_from(reader.byte()?)?;
            let output_data_class = AdapterDataClassV1::try_from(reader.byte()?)?;
            let effect_mode = AdapterEffectModeV1::try_from(reader.byte()?)?;
            entries.push(AdapterAdmissionEntryV1 {
                plugin_id,
                adapter_id,
                provider_id,
                operation_id,
                protocol_version,
                request_schema_digest,
                response_schema_digest,
                exact_configuration_bytes,
                configuration_digest,
                input_data_class,
                output_data_class,
                effect_mode,
            });
        }
        if reader.offset != bytes.len() {
            return Err(AdapterAdmissionErrorV1::NonCanonical);
        }
        let record = Self::new(AdapterAdmissionInputV1 {
            owner_reference,
            configuration_generation,
            scope_digest,
            entries,
        })?;
        if record.to_canonical_cbor() != bytes {
            return Err(AdapterAdmissionErrorV1::NonCanonical);
        }
        Ok(record)
    }
}

/// Fixed opaque public-byte-string schema digest for both adapter directions.
#[must_use]
pub fn public_adapter_schema_digest_v1() -> Hash {
    length_hash(b"pigloros.repro.adapter-schema.v1\0", SCHEMA)
}

/// Digest of exact public configuration bytes retained in MAA1.
#[must_use]
pub fn adapter_configuration_digest_v1(bytes: &[u8]) -> Hash {
    length_hash(b"pigloros.repro.adapter-configuration.v1\0", bytes)
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

fn validate_entry(entry: &AdapterAdmissionEntryV1) -> Result<(), AdapterAdmissionErrorV1> {
    if entry.exact_configuration_bytes.len() > MAX_ADAPTER_CONFIGURATION_BYTES_V1 {
        return Err(AdapterAdmissionErrorV1::FieldOutOfBounds);
    }
    let schema = public_adapter_schema_digest_v1();
    if [&entry.adapter_id, &entry.provider_id, &entry.operation_id]
        .iter()
        .any(|id| !valid_adapter_identity(id))
        || entry.protocol_version == 0
        || entry.request_schema_digest != schema
        || entry.response_schema_digest != schema
        || entry.configuration_digest
            != adapter_configuration_digest_v1(&entry.exact_configuration_bytes)
    {
        return Err(AdapterAdmissionErrorV1::InvalidEntry);
    }
    Ok(())
}

fn encode_hash(out: &mut Vec<u8>, hash: Hash) {
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(hash.as_bytes());
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8], major: u8) {
    encode_head(out, major, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn fixed(&mut self, expected: &[u8]) -> Result<(), AdapterAdmissionErrorV1> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(AdapterAdmissionErrorV1::InvalidEncoding)
        }
    }

    fn hash(&mut self) -> Result<Hash, AdapterAdmissionErrorV1> {
        Ok(Hash::from_bytes(self.blob::<32>()?))
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], AdapterAdmissionErrorV1> {
        if self.head(2)? != N as u64 {
            return Err(AdapterAdmissionErrorV1::InvalidEncoding);
        }
        let mut result = [0; N];
        result.copy_from_slice(self.take(N)?);
        Ok(result)
    }

    fn identity(&mut self) -> Result<String, AdapterAdmissionErrorV1> {
        let bytes = self.bounded_bytes(3, 128)?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| AdapterAdmissionErrorV1::InvalidEncoding)?;
        Ok(text.to_owned())
    }

    fn bounded_bytes(
        &mut self,
        major: u8,
        maximum: usize,
    ) -> Result<&[u8], AdapterAdmissionErrorV1> {
        let length = u16::try_from(self.head(major)?)
            .map_err(|_| AdapterAdmissionErrorV1::FieldOutOfBounds)?;
        if usize::from(length) > maximum {
            return Err(AdapterAdmissionErrorV1::FieldOutOfBounds);
        }
        self.take(usize::from(length))
    }

    fn byte(&mut self) -> Result<u8, AdapterAdmissionErrorV1> {
        u8::try_from(self.head(0)?).map_err(|_| AdapterAdmissionErrorV1::InvalidEntry)
    }

    fn head(&mut self, major: u8) -> Result<u64, AdapterAdmissionErrorV1> {
        let tag = self.take(1)?[0];
        if tag >> 5 != major {
            return Err(AdapterAdmissionErrorV1::InvalidEncoding);
        }
        match tag & 0x1f {
            small @ 0..=23 => Ok(u64::from(small)),
            24 => self.number::<1>(),
            25 => self.number::<2>(),
            26 => self.number::<4>(),
            27 => self.number::<8>(),
            _ => Err(AdapterAdmissionErrorV1::InvalidEncoding),
        }
    }

    fn number<const N: usize>(&mut self) -> Result<u64, AdapterAdmissionErrorV1> {
        Ok(self
            .take(N)?
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    fn take(&mut self, length: usize) -> Result<&[u8], AdapterAdmissionErrorV1> {
        let end = self.offset.saturating_add(length);
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AdapterAdmissionErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
}
