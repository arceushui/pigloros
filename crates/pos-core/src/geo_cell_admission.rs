//! Core-owned V1 `geo.cell` Event admission contract.
//!
//! This module deliberately has no dependency on `pos-plugin-geo`. The plugin's
//! ADR-031 value crosses this boundary as already-canonical bytes; this module
//! validates the complete neutral wire shape before it can become Event data.

use std::{fmt, io::Cursor};

use ciborium::value::Value;
use thiserror::Error;

use crate::CanonicalBytes;

/// The only supported outer `geo.cell` payload schema.
pub const GEO_CELL_PAYLOAD_SCHEMA_V1: u8 = 1;
/// Maximum V1 payload size, including a signed 64-bit source bucket.
pub const GEO_CELL_PAYLOAD_MAX_BYTES: usize = 266;
const GEO_CELL_SYSTEM_H3_V4: &str = "h3-v4";

/// Strict failures at the neutral cell/Event wire boundary.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum GeoCellAdmissionError {
    #[error("geo.cell payload is too large: {size} bytes")]
    PayloadTooLarge { size: usize },
    #[error("geo.cell payload is malformed CBOR")]
    MalformedCbor,
    #[error("geo.cell payload is non-canonical CBOR")]
    NonCanonicalCbor,
    #[error("geo.cell payload has an unexpected field: {0}")]
    UnexpectedField(&'static str),
    #[error("geo.cell payload is missing field: {0}")]
    MissingField(&'static str),
    #[error("geo.cell payload has a duplicate field: {0}")]
    DuplicateField(&'static str),
    #[error("geo.cell payload has the wrong type for field: {0}")]
    WrongFieldType(&'static str),
    #[error("geo.cell payload has an invalid value for field: {0}")]
    InvalidField(&'static str),
    #[error("geo.cell H3 value is not a canonical ADR-031 value")]
    InvalidCell,
    #[error("geo.cell snapshot identity is not canonical")]
    InvalidSnapshotIdentity,
    #[error("geo.cell snapshot hash is not canonical")]
    InvalidSnapshotHash,
}

/// A neutral, validated copy of the exact 61-byte ADR-031 `GeoCellV1` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedGeoCellV1 {
    bytes: CanonicalBytes,
    resolution: u8,
}

impl ValidatedGeoCellV1 {
    /// Validate one exact ADR-031 V1 value without depending on H3 library code.
    pub fn from_adr031_bytes(bytes: &CanonicalBytes) -> Result<Self, GeoCellAdmissionError> {
        if bytes.len() != 61 {
            return Err(GeoCellAdmissionError::InvalidCell);
        }
        let mut cursor = Cursor::new(bytes.as_slice());
        let value: Value =
            ciborium::from_reader(&mut cursor).map_err(|_| GeoCellAdmissionError::MalformedCbor)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(GeoCellAdmissionError::MalformedCbor);
        }
        let Value::Map(entries) = value else {
            return Err(GeoCellAdmissionError::InvalidCell);
        };
        let mut index = None;
        let mut system = None;
        let mut resolution = None;
        let mut cell_format = None;
        for (key, value) in entries {
            let Value::Text(key) = key else {
                return Err(GeoCellAdmissionError::InvalidCell);
            };
            let slot = match key.as_str() {
                "index" => &mut index,
                "system" => &mut system,
                "resolution" => &mut resolution,
                "cell_format" => &mut cell_format,
                _ => return Err(GeoCellAdmissionError::InvalidCell),
            };
            if slot.replace(value).is_some() {
                return Err(GeoCellAdmissionError::InvalidCell);
            }
        }
        let index = text_value(index, "index")?;
        if index.len() != 15
            || !index.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
            })
            || !is_h3_index_for_resolution(
                &index,
                unsigned_value(resolution.clone(), "resolution")?,
            )
        {
            return Err(GeoCellAdmissionError::InvalidCell);
        }
        if text_value(system, "system")? != GEO_CELL_SYSTEM_H3_V4
            || unsigned_value(cell_format, "cell_format")? != 1
        {
            return Err(GeoCellAdmissionError::InvalidCell);
        }
        let resolution = unsigned_value(resolution, "resolution")?;
        if resolution > 15 {
            return Err(GeoCellAdmissionError::InvalidCell);
        }
        let canonical = encode_cell_value(&index, resolution);
        if canonical.as_slice() != bytes.as_slice() {
            return Err(GeoCellAdmissionError::NonCanonicalCbor);
        }
        Ok(Self {
            bytes: bytes.clone(),
            resolution: resolution as u8,
        })
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &CanonicalBytes {
        &self.bytes
    }

    #[must_use]
    pub const fn resolution(&self) -> u8 {
        self.resolution
    }
}

fn is_h3_index_for_resolution(index: &str, resolution: u64) -> bool {
    let Ok(value) = u64::from_str_radix(index, 16) else {
        return false;
    };
    ((value >> 52) & 0x0f) == resolution && (value >> 59) == 1
}

fn text_value(value: Option<Value>, field: &'static str) -> Result<String, GeoCellAdmissionError> {
    match value {
        Some(Value::Text(value)) => Ok(value),
        Some(_) => Err(GeoCellAdmissionError::WrongFieldType(field)),
        None => Err(GeoCellAdmissionError::MissingField(field)),
    }
}

fn unsigned_value(value: Option<Value>, field: &'static str) -> Result<u64, GeoCellAdmissionError> {
    match value {
        Some(Value::Integer(value)) => {
            u64::try_from(value).map_err(|_| GeoCellAdmissionError::WrongFieldType(field))
        }
        Some(_) => Err(GeoCellAdmissionError::WrongFieldType(field)),
        None => Err(GeoCellAdmissionError::MissingField(field)),
    }
}

fn signed_value(value: Option<Value>, field: &'static str) -> Result<i64, GeoCellAdmissionError> {
    match value {
        Some(Value::Integer(value)) => {
            i64::try_from(value).map_err(|_| GeoCellAdmissionError::WrongFieldType(field))
        }
        Some(_) => Err(GeoCellAdmissionError::WrongFieldType(field)),
        None => Err(GeoCellAdmissionError::MissingField(field)),
    }
}

fn encode_cell_value(index: &str, resolution: u64) -> CanonicalBytes {
    let value = Value::Map(vec![
        (
            Value::Text("index".to_owned()),
            Value::Text(index.to_owned()),
        ),
        (
            Value::Text("system".to_owned()),
            Value::Text(GEO_CELL_SYSTEM_H3_V4.to_owned()),
        ),
        (
            Value::Text("resolution".to_owned()),
            Value::Integer(resolution.into()),
        ),
        (
            Value::Text("cell_format".to_owned()),
            Value::Integer(1.into()),
        ),
    ]);
    let mut bytes = Vec::with_capacity(61);
    ciborium::into_writer(&value, &mut bytes)
        .expect("writing validated geo.cell CBOR to Vec cannot fail");
    CanonicalBytes::from_vec(bytes)
}

/// Validated 15-minute bucket of source occurrence time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceTimeBucket(i64);

impl SourceTimeBucket {
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }
}

/// The `geo.cell` observation-policy namespace, distinct from ADR-026/ADR-034.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GeoCellObservationPolicyVersion(u8);

impl GeoCellObservationPolicyVersion {
    pub const V1: Self = Self(1);

    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// Canonical upper-case Crockford Base32 ULID used for immutable snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdmissionSnapshotId(String);

impl AdmissionSnapshotId {
    pub fn from_canonical(value: &str) -> Result<Self, GeoCellAdmissionError> {
        let parsed = ulid::Ulid::from_string(value)
            .map_err(|_| GeoCellAdmissionError::InvalidSnapshotIdentity)?;
        if parsed.to_string() != value {
            return Err(GeoCellAdmissionError::InvalidSnapshotIdentity);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The fixed BLAKE3 hash domain for immutable admission snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdmissionSnapshotHash([u8; 32]);

impl AdmissionSnapshotHash {
    pub fn from_hex(value: &str) -> Result<Self, GeoCellAdmissionError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GeoCellAdmissionError::InvalidSnapshotHash);
        }
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *slot = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        let canonical = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if canonical != value {
            return Err(GeoCellAdmissionError::InvalidSnapshotHash);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn as_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

/// The exact six-field deterministic-CBOR outer V1 payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeographicObservationV1 {
    cell: ValidatedGeoCellV1,
    source_time_bucket: SourceTimeBucket,
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
}

impl GeographicObservationV1 {
    #[must_use]
    pub fn new(
        cell: ValidatedGeoCellV1,
        source_time_bucket: SourceTimeBucket,
        snapshot_id: AdmissionSnapshotId,
        snapshot_hash: AdmissionSnapshotHash,
    ) -> Self {
        Self {
            cell,
            source_time_bucket,
            snapshot_id,
            snapshot_hash,
        }
    }

    /// Encode the exact ADR-037 V1 payload.
    pub fn encode(&self) -> Result<CanonicalBytes, GeoCellAdmissionError> {
        let cell: Value = ciborium::from_reader(self.cell.as_bytes().as_slice())
            .map_err(|_| GeoCellAdmissionError::InvalidCell)?;
        let value = Value::Map(vec![
            (Value::Text("cell".to_owned()), cell),
            (
                Value::Text("quality_flags".to_owned()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("policy_version".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("source_time_bucket".to_owned()),
                Value::Integer(self.source_time_bucket.0.into()),
            ),
            (
                Value::Text("admission_snapshot_id".to_owned()),
                Value::Text(self.snapshot_id.0.clone()),
            ),
            (
                Value::Text("admission_snapshot_hash".to_owned()),
                Value::Text(self.snapshot_hash.as_hex()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes)
            .map_err(|_| GeoCellAdmissionError::MalformedCbor)?;
        if bytes.len() > GEO_CELL_PAYLOAD_MAX_BYTES {
            return Err(GeoCellAdmissionError::PayloadTooLarge { size: bytes.len() });
        }
        Ok(CanonicalBytes::from_vec(bytes))
    }

    /// Decode one exact canonical V1 payload.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, GeoCellAdmissionError> {
        if bytes.len() > GEO_CELL_PAYLOAD_MAX_BYTES {
            return Err(GeoCellAdmissionError::PayloadTooLarge { size: bytes.len() });
        }
        let mut cursor = Cursor::new(bytes.as_slice());
        let value: Value =
            ciborium::from_reader(&mut cursor).map_err(|_| GeoCellAdmissionError::MalformedCbor)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(GeoCellAdmissionError::MalformedCbor);
        }
        let Value::Map(entries) = value else {
            return Err(GeoCellAdmissionError::MalformedCbor);
        };
        if entries.len() != 6 {
            return Err(GeoCellAdmissionError::MalformedCbor);
        }
        let mut cell = None;
        let mut quality_flags = None;
        let mut policy_version = None;
        let mut source_time_bucket = None;
        let mut snapshot_id = None;
        let mut snapshot_hash = None;
        for (key, value) in entries {
            let Value::Text(key) = key else {
                return Err(GeoCellAdmissionError::MalformedCbor);
            };
            let slot = match key.as_str() {
                "cell" => &mut cell,
                "quality_flags" => &mut quality_flags,
                "policy_version" => &mut policy_version,
                "source_time_bucket" => &mut source_time_bucket,
                "admission_snapshot_id" => &mut snapshot_id,
                "admission_snapshot_hash" => &mut snapshot_hash,
                _ => return Err(GeoCellAdmissionError::UnexpectedField("outer")),
            };
            if slot.replace(value).is_some() {
                return Err(GeoCellAdmissionError::DuplicateField("outer"));
            }
        }
        if unsigned_value(quality_flags, "quality_flags")? != 0
            || unsigned_value(policy_version, "policy_version")? != 1
        {
            return Err(GeoCellAdmissionError::InvalidField("policy"));
        }
        let Value::Map(cell_map) = cell.ok_or(GeoCellAdmissionError::MissingField("cell"))? else {
            return Err(GeoCellAdmissionError::WrongFieldType("cell"));
        };
        let mut cell_bytes = Vec::new();
        ciborium::into_writer(&Value::Map(cell_map), &mut cell_bytes)
            .map_err(|_| GeoCellAdmissionError::InvalidCell)?;
        let cell = ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_vec(cell_bytes))?;
        let decoded = Self::new(
            cell,
            SourceTimeBucket::new(signed_value(source_time_bucket, "source_time_bucket")?),
            AdmissionSnapshotId::from_canonical(&text_value(
                snapshot_id,
                "admission_snapshot_id",
            )?)?,
            AdmissionSnapshotHash::from_hex(&text_value(
                snapshot_hash,
                "admission_snapshot_hash",
            )?)?,
        );
        if decoded.encode()?.as_slice() != bytes.as_slice() {
            return Err(GeoCellAdmissionError::NonCanonicalCbor);
        }
        Ok(decoded)
    }

    #[must_use]
    pub const fn cell(&self) -> &ValidatedGeoCellV1 {
        &self.cell
    }

    #[must_use]
    pub const fn source_time_bucket(&self) -> SourceTimeBucket {
        self.source_time_bucket
    }

    #[must_use]
    pub fn snapshot_id(&self) -> &AdmissionSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn snapshot_hash(&self) -> AdmissionSnapshotHash {
        self.snapshot_hash
    }
}

impl fmt::Display for AdmissionSnapshotHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CELL_BYTES: &[u8] =
        b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01";
    const PAYLOAD_BYTES: &[u8] = b"\xa6dcell\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01mquality_flags\x00npolicy_version\x01rsource_time_bucket\x1a\x00\x1e\x84\x80uadmission_snapshot_id\x78\x1a01ARZ3NDEKTSV4RRFFQ69G5FAVwadmission_snapshot_hash\x78\x400123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn decodes_and_reencodes_the_adr_037_fixture() {
        let cell = ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(CELL_BYTES))
            .unwrap();
        let snapshot_id =
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let snapshot_hash = AdmissionSnapshotHash::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let payload = GeographicObservationV1::new(
            cell,
            SourceTimeBucket::new(2_000_000),
            snapshot_id,
            snapshot_hash,
        )
        .encode()
        .unwrap();

        assert_eq!(payload.as_slice(), PAYLOAD_BYTES);
        assert_eq!(payload.len(), 262);
        assert_eq!(
            GeographicObservationV1::decode(&payload)
                .unwrap()
                .encode()
                .unwrap(),
            payload
        );
    }

    #[test]
    fn rejects_payloads_over_the_v1_bound() {
        let bytes = CanonicalBytes::from_vec(vec![0; 267]);
        assert!(matches!(
            GeographicObservationV1::decode(&bytes),
            Err(GeoCellAdmissionError::PayloadTooLarge { size: 267 })
        ));
    }
}
