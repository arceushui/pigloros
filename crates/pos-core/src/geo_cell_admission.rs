//! Core-owned V1 `geo.cell` Event admission contract.
//!
//! This module deliberately has no dependency on `pos-plugin-geo`. The plugin's
//! ADR-031 value crosses this boundary as already-canonical bytes; this module
//! validates the complete neutral wire shape before it can become Event data.
#![allow(clippy::missing_errors_doc)]

use std::{cmp::Ordering, fmt, fmt::Write as _, io::Cursor};

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CanonicalBytes, CoreError, EntityId, Event, EventId, Hash, Seq, TimelineId};

/// The only supported outer `geo.cell` payload schema.
pub const GEO_CELL_PAYLOAD_SCHEMA_V1: u8 = 1;
/// Maximum V1 payload size, including a signed 64-bit source bucket.
pub const GEO_CELL_PAYLOAD_MAX_BYTES: usize = 266;
const GEO_CELL_SYSTEM_H3_V4: &str = "h3-v4";
const H3_BASE_PENTAGONS: u128 = 0x0020_0802_0008_0100_8402_0040_0100_4010;

fn sort_snapshot_entries(entries: &mut [(Value, Value)]) {
    entries.sort_by(|(left, _), (right, _)| {
        let (Value::Text(left), Value::Text(right)) = (left, right) else {
            return Ordering::Equal;
        };
        left.len()
            .cmp(&right.len())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()))
    });
}

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
        let resolution = unsigned_value(resolution.as_ref(), "resolution")?;
        let index = text_value(index, "index")?;
        if index.len() != 15
            || !index.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
            })
            || !is_h3_index_for_resolution(&index, resolution)
        {
            return Err(GeoCellAdmissionError::InvalidCell);
        }
        if text_value(system, "system")? != GEO_CELL_SYSTEM_H3_V4
            || unsigned_value(cell_format.as_ref(), "cell_format")? != 1
        {
            return Err(GeoCellAdmissionError::InvalidCell);
        }
        let canonical = encode_cell_value(&index, resolution);
        if canonical.as_slice() != bytes.as_slice() {
            return Err(GeoCellAdmissionError::NonCanonicalCbor);
        }
        Ok(Self {
            bytes: bytes.clone(),
            resolution: u8::try_from(resolution).unwrap_or(0),
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
    let value = u64::from_str_radix(index, 16).unwrap_or(0);
    let base_cell = (value >> 45) & 0x7f;
    if resolution > 15
        || ((value >> 59) & 0x0f) != 1
        || ((value >> 56) & 0x07) != 0
        || ((value >> 52) & 0x0f) != resolution
        || base_cell > 121
    {
        return false;
    }
    if !(resolution..15).all(|digit| ((value >> (3 * (14 - digit))) & 0x07) == 7)
        || (0..resolution).any(|digit| ((value >> (3 * (14 - digit))) & 0x07) == 7)
    {
        return false;
    }
    if resolution > 0 && H3_BASE_PENTAGONS & (1_u128 << base_cell) != 0 {
        let first_non_center = (0..resolution)
            .map(|digit| (value >> (3 * (14 - digit))) & 0x07)
            .find(|digit| *digit != 0);
        if first_non_center == Some(1) {
            return false;
        }
    }
    true
}

fn text_value(value: Option<Value>, field: &'static str) -> Result<String, GeoCellAdmissionError> {
    match value {
        Some(Value::Text(value)) => Ok(value),
        Some(_) => Err(GeoCellAdmissionError::WrongFieldType(field)),
        None => Err(GeoCellAdmissionError::MissingField(field)),
    }
}

fn unsigned_value(
    value: Option<&Value>,
    field: &'static str,
) -> Result<u64, GeoCellAdmissionError> {
    match value {
        Some(Value::Integer(value)) => {
            u64::try_from(*value).map_err(|_| GeoCellAdmissionError::WrongFieldType(field))
        }
        Some(_) => Err(GeoCellAdmissionError::WrongFieldType(field)),
        None => Err(GeoCellAdmissionError::MissingField(field)),
    }
}

fn signed_value(value: Option<&Value>, field: &'static str) -> Result<i64, GeoCellAdmissionError> {
    match value {
        Some(Value::Integer(value)) => {
            i64::try_from(*value).map_err(|_| GeoCellAdmissionError::WrongFieldType(field))
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
    let _ = ciborium::into_writer(&value, &mut bytes);
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// The fixed BLAKE3 hash for immutable admission snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdmissionSnapshotHash([u8; 32]);

/// The distinct fixed BLAKE3 hash for immutable consent-record bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsentRecordHash([u8; 32]);

impl ConsentRecordHash {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for ConsentRecordHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AdmissionSnapshotHash {
    pub fn from_hex(value: &str) -> Result<Self, GeoCellAdmissionError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GeoCellAdmissionError::InvalidSnapshotHash);
        }
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *slot = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        let mut canonical = String::with_capacity(64);
        for byte in bytes {
            let _ = write!(&mut canonical, "{byte:02x}");
        }
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
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(&mut hex, "{byte:02x}");
        }
        hex
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
    #[must_use]
    pub fn encode(&self) -> CanonicalBytes {
        let cell: Value =
            ciborium::from_reader(self.cell.as_bytes().as_slice()).unwrap_or(Value::Null);
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
        let _ = ciborium::into_writer(&value, &mut bytes);
        CanonicalBytes::from_vec(bytes)
    }

    /// Decode one exact canonical V1 payload.
    ///
    /// # Panics
    ///
    /// This method panics only if a `Vec` writer reports an impossible I/O
    /// failure while rebuilding the validated cell value.
    #[allow(clippy::missing_panics_doc)]
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
        let entry_count = entries.len();
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
        if unsigned_value(quality_flags.as_ref(), "quality_flags")? != 0
            || unsigned_value(policy_version.as_ref(), "policy_version")? != 1
        {
            return Err(GeoCellAdmissionError::InvalidField("policy"));
        }
        let cell = cell.ok_or(GeoCellAdmissionError::MissingField("cell"))?;
        if entry_count != 6 {
            return Err(GeoCellAdmissionError::MalformedCbor);
        }
        let Value::Map(cell_map) = cell else {
            return Err(GeoCellAdmissionError::WrongFieldType("cell"));
        };
        let mut cell_bytes = Vec::new();
        let _ = ciborium::into_writer(&Value::Map(cell_map), &mut cell_bytes);
        let cell = ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_vec(cell_bytes))?;
        let decoded = Self::new(
            cell,
            SourceTimeBucket::new(signed_value(
                source_time_bucket.as_ref(),
                "source_time_bucket",
            )?),
            AdmissionSnapshotId::from_canonical(&text_value(
                snapshot_id,
                "admission_snapshot_id",
            )?)?,
            AdmissionSnapshotHash::from_hex(&text_value(
                snapshot_hash,
                "admission_snapshot_hash",
            )?)?,
        );
        if decoded.encode().as_slice() != bytes.as_slice() {
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

/// The immutable entitlement fields that are known before store allocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionEntitlementDraftV1 {
    timeline: TimelineId,
    entity: EntityId,
    consent_record_id: AdmissionSnapshotId,
    consent_revision: u64,
    consent_record_hash: ConsentRecordHash,
    purpose: String,
    entitled_principals: Vec<EntityId>,
    visibility_scope: String,
    maximum_h3_resolution: u8,
    admission_policy_version: u32,
    admission_epoch: u64,
}

impl AdmissionEntitlementDraftV1 {
    /// Construct one canonical, pre-allocation entitlement draft.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timeline: TimelineId,
        entity: EntityId,
        consent_record_id: AdmissionSnapshotId,
        consent_revision: u64,
        consent_record_hash: impl Into<ConsentRecordHash>,
        purpose: impl Into<String>,
        mut entitled_principals: Vec<EntityId>,
        visibility_scope: impl Into<String>,
        maximum_h3_resolution: u8,
        admission_policy_version: u32,
        admission_epoch: u64,
    ) -> Result<Self, CoreError> {
        let purpose = purpose.into();
        let visibility_scope = visibility_scope.into();
        if purpose.is_empty()
            || visibility_scope.is_empty()
            || maximum_h3_resolution > 15
            || consent_revision == 0
            || entitled_principals.is_empty()
            || admission_policy_version == 0
            || admission_epoch == 0
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        entitled_principals.sort_unstable();
        if entitled_principals
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(Self {
            timeline,
            entity,
            consent_record_id,
            consent_revision,
            consent_record_hash: consent_record_hash.into(),
            purpose,
            entitled_principals,
            visibility_scope,
            maximum_h3_resolution,
            admission_policy_version,
            admission_epoch,
        })
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.entity
    }

    #[must_use]
    pub const fn consent_record_id(&self) -> &AdmissionSnapshotId {
        &self.consent_record_id
    }

    #[must_use]
    pub const fn consent_revision(&self) -> u64 {
        self.consent_revision
    }

    #[must_use]
    pub const fn consent_record_hash(&self) -> &ConsentRecordHash {
        &self.consent_record_hash
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn entitled_principals(&self) -> &[EntityId] {
        &self.entitled_principals
    }

    #[must_use]
    pub fn visibility_scope(&self) -> &str {
        &self.visibility_scope
    }

    #[must_use]
    pub const fn maximum_h3_resolution(&self) -> u8 {
        self.maximum_h3_resolution
    }

    #[must_use]
    pub const fn admission_policy_version(&self) -> u32 {
        self.admission_policy_version
    }

    #[must_use]
    pub const fn admission_epoch(&self) -> u64 {
        self.admission_epoch
    }
}

/// Immutable consent bytes resolved by the authoritative ADR-034 consent port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionConsentRecordV1 {
    id: AdmissionSnapshotId,
    revision: u64,
    canonical_bytes: CanonicalBytes,
}

impl AdmissionConsentRecordV1 {
    /// Rehydrate one record returned by the typed persistence resolver port.
    #[must_use]
    pub const fn from_persistence_parts(
        id: AdmissionSnapshotId,
        revision: u64,
        canonical_bytes: CanonicalBytes,
    ) -> Self {
        Self {
            id,
            revision,
            canonical_bytes,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &AdmissionSnapshotId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn canonical_bytes(&self) -> &CanonicalBytes {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn hash(&self) -> ConsentRecordHash {
        ConsentRecordHash::from_bytes(*blake3::hash(self.canonical_bytes.as_slice()).as_bytes())
    }

    #[must_use]
    pub fn matches_draft(&self, draft: &AdmissionEntitlementDraftV1) -> bool {
        self.id == *draft.consent_record_id()
            && self.revision == draft.consent_revision()
            && self.hash() == *draft.consent_record_hash()
    }

    #[must_use]
    pub fn matches_linkage(&self, linkage: &AdmissionSnapshotLinkageV1) -> bool {
        self.id == *linkage.consent_record_id()
            && self.revision == linkage.consent_revision()
            && self.hash() == *linkage.consent_record_hash()
    }
}

/// Hash canonical immutable consent-record bytes in the ADR-034 domain.
#[must_use]
pub fn hash_admission_consent_record_bytes(bytes: &CanonicalBytes) -> ConsentRecordHash {
    ConsentRecordHash::from_bytes(*blake3::hash(bytes.as_slice()).as_bytes())
}

/// Current binding, consent, and policy state used by the atomic admission fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoCellAdmissionFenceV1 {
    draft: AdmissionEntitlementDraftV1,
    binding_identity: [u8; 32],
    binding_revision: u64,
    withdrawn: bool,
}

impl GeoCellAdmissionFenceV1 {
    #[must_use]
    pub fn new(
        draft: AdmissionEntitlementDraftV1,
        binding_identity: [u8; 32],
        binding_revision: u64,
        withdrawn: bool,
    ) -> Self {
        Self {
            draft,
            binding_identity,
            binding_revision,
            withdrawn,
        }
    }

    #[must_use]
    pub const fn draft(&self) -> &AdmissionEntitlementDraftV1 {
        &self.draft
    }

    #[must_use]
    pub const fn withdrawn(&self) -> bool {
        self.withdrawn
    }

    #[must_use]
    pub const fn binding_identity(&self) -> &[u8; 32] {
        &self.binding_identity
    }

    #[must_use]
    pub const fn binding_revision(&self) -> u64 {
        self.binding_revision
    }

    #[must_use]
    pub fn permits(&self, request: &GeoCellAdmissionRequestV1) -> bool {
        !self.withdrawn && self == request.fence()
    }

    /// Serialize the trusted fence for a backend-local persistence row.
    #[must_use]
    pub fn persistence_bytes(&self) -> CanonicalBytes {
        let mut bytes = Vec::new();
        let _ = ciborium::into_writer(self, &mut bytes);
        CanonicalBytes::from_vec(bytes)
    }

    /// Restore and validate one backend-local fence row.
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut cursor = Cursor::new(bytes);
        let fence: Self = ciborium::from_reader(&mut cursor)
            .map_err(|error| CoreError::Serialization(error.to_string()))?;
        if cursor.position() != bytes.len() as u64 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let mut canonical = Vec::new();
        let _ = ciborium::into_writer(&fence, &mut canonical);
        if canonical != bytes {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let draft = fence.draft();
        if AdmissionSnapshotId::from_canonical(draft.consent_record_id.as_str()).is_err()
            || draft.purpose.is_empty()
            || draft.visibility_scope.is_empty()
            || draft.maximum_h3_resolution > 15
            || draft.consent_revision == 0
            || draft.entitled_principals.is_empty()
            || draft.admission_policy_version == 0
            || draft.admission_epoch == 0
            || draft
                .entitled_principals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(fence)
    }
}

/// Already-minimized, source-validated input for one V1 `geo.cell` admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoCellAdmissionInputV1 {
    cell: ValidatedGeoCellV1,
    source_time_bucket: SourceTimeBucket,
    fence: GeoCellAdmissionFenceV1,
    fingerprint: GeographicAdmissionFingerprintV1,
}

impl GeoCellAdmissionInputV1 {
    #[must_use]
    pub fn new(
        cell: ValidatedGeoCellV1,
        source_time_bucket: SourceTimeBucket,
        fence: GeoCellAdmissionFenceV1,
        fingerprint: GeographicAdmissionFingerprintV1,
    ) -> Self {
        Self::with_fingerprint(cell, source_time_bucket, fence, fingerprint)
    }

    /// Construct input with a fingerprint produced by a trusted source ingress.
    #[must_use]
    pub fn with_fingerprint(
        cell: ValidatedGeoCellV1,
        source_time_bucket: SourceTimeBucket,
        fence: GeoCellAdmissionFenceV1,
        fingerprint: GeographicAdmissionFingerprintV1,
    ) -> Self {
        Self {
            cell,
            source_time_bucket,
            fence,
            fingerprint,
        }
    }
}

/// Opaque, core-encoded exact admission intent retained only by the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeographicAdmissionIntentV1(CanonicalBytes);

impl GeographicAdmissionIntentV1 {
    /// Return the bytes required by a persistence adapter for exact comparison.
    #[must_use]
    pub const fn as_persistence_bytes(&self) -> &CanonicalBytes {
        &self.0
    }
}

/// Opaque deduplication key supplied by the authenticated source ingress.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct GeographicAdmissionFingerprintV1([u8; 32]);

impl GeographicAdmissionFingerprintV1 {
    /// Wrap a fingerprint produced by a separately authenticated source ingress.
    #[must_use]
    pub const fn from_ingress(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the source-owned key bytes required by a persistence adapter.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Core-issued, immutable admission request. IDs and sequence are store-owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoCellAdmissionRequestV1 {
    cell: ValidatedGeoCellV1,
    source_time_bucket: SourceTimeBucket,
    fence: GeoCellAdmissionFenceV1,
    fingerprint: GeographicAdmissionFingerprintV1,
    intent: GeographicAdmissionIntentV1,
}

impl GeoCellAdmissionRequestV1 {
    pub fn from_input(input: GeoCellAdmissionInputV1) -> Result<Self, CoreError> {
        let intent = encode_intent(&input);
        let fingerprint = input.fingerprint;
        if input.fence.draft.maximum_h3_resolution < input.cell.resolution() {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(Self {
            cell: input.cell,
            source_time_bucket: input.source_time_bucket,
            fence: input.fence,
            fingerprint,
            intent,
        })
    }

    #[must_use]
    pub const fn fence(&self) -> &GeoCellAdmissionFenceV1 {
        &self.fence
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.fence.draft.timeline
    }

    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.fence.draft.entity
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
    pub const fn fingerprint(&self) -> GeographicAdmissionFingerprintV1 {
        self.fingerprint
    }

    #[must_use]
    pub const fn intent(&self) -> &GeographicAdmissionIntentV1 {
        &self.intent
    }

    /// Construct the Event payload after the store allocates the snapshot link.
    #[must_use]
    pub fn payload(
        &self,
        snapshot_id: AdmissionSnapshotId,
        snapshot_hash: AdmissionSnapshotHash,
    ) -> GeographicObservationV1 {
        GeographicObservationV1::new(
            self.cell.clone(),
            self.source_time_bucket,
            snapshot_id,
            snapshot_hash,
        )
    }
}

fn encode_intent(request: &GeoCellAdmissionInputV1) -> GeographicAdmissionIntentV1 {
    let principals: Vec<Value> = request
        .fence
        .draft
        .entitled_principals
        .iter()
        .map(|principal| Value::Text(principal.to_string()))
        .collect();
    let value = Value::Array(vec![
        Value::Text("geo.cell".to_owned()),
        Value::Integer(GEO_CELL_PAYLOAD_SCHEMA_V1.into()),
        Value::Integer(0_u8.into()),
        Value::Integer(GeoCellObservationPolicyVersion::V1.value().into()),
        Value::Text(request.fence.draft.timeline.to_string()),
        Value::Text(request.fence.draft.entity.to_string()),
        Value::Bytes(request.fence.binding_identity.to_vec()),
        Value::Integer(request.fence.binding_revision.into()),
        Value::Text(request.fence.draft.consent_record_id.as_str().to_owned()),
        Value::Integer(request.fence.draft.consent_revision.into()),
        Value::Bytes(request.fence.draft.consent_record_hash.as_bytes().to_vec()),
        Value::Text(request.fence.draft.purpose.clone()),
        Value::Array(principals),
        Value::Text(request.fence.draft.visibility_scope.clone()),
        Value::Integer(request.fence.draft.maximum_h3_resolution.into()),
        Value::Integer(request.fence.draft.admission_policy_version.into()),
        Value::Integer(request.fence.draft.admission_epoch.into()),
        Value::Integer(request.source_time_bucket.0.into()),
        Value::Bytes(request.cell.bytes.as_slice().to_vec()),
    ]);
    let mut bytes = Vec::new();
    let _ = ciborium::into_writer(&value, &mut bytes);
    GeographicAdmissionIntentV1(CanonicalBytes::from_vec(bytes))
}

/// Immutable snapshot bytes retained for the full Timeline lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEntitlementSnapshotV1 {
    id: AdmissionSnapshotId,
    fields: AdmissionSnapshotFieldsV1,
    event_id: EventId,
    event_seq: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdmissionSnapshotFieldsV1 {
    timeline: TimelineId,
    entity: EntityId,
    consent_record_id: AdmissionSnapshotId,
    consent_revision: u64,
    consent_record_hash: ConsentRecordHash,
    purpose: String,
    entitled_principals: Vec<EntityId>,
    visibility_scope: String,
    maximum_h3_resolution: u8,
    admission_policy_version: u32,
    admission_epoch: u64,
}

impl From<&AdmissionEntitlementDraftV1> for AdmissionSnapshotFieldsV1 {
    fn from(draft: &AdmissionEntitlementDraftV1) -> Self {
        Self {
            timeline: draft.timeline,
            entity: draft.entity,
            consent_record_id: draft.consent_record_id.clone(),
            consent_revision: draft.consent_revision,
            consent_record_hash: draft.consent_record_hash,
            purpose: draft.purpose.clone(),
            entitled_principals: draft.entitled_principals.clone(),
            visibility_scope: draft.visibility_scope.clone(),
            maximum_h3_resolution: draft.maximum_h3_resolution,
            admission_policy_version: draft.admission_policy_version,
            admission_epoch: draft.admission_epoch,
        }
    }
}

/// Immutable linkage fields decoded from a persisted admission snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionSnapshotLinkageV1 {
    snapshot_id: AdmissionSnapshotId,
    timeline: TimelineId,
    event_id: EventId,
    event_seq: Seq,
    entity: EntityId,
    consent_record_id: AdmissionSnapshotId,
    consent_revision: u64,
    consent_record_hash: ConsentRecordHash,
}

impl AdmissionSnapshotLinkageV1 {
    #[must_use]
    pub const fn snapshot_id(&self) -> &AdmissionSnapshotId {
        &self.snapshot_id
    }
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }
    #[must_use]
    pub const fn event_seq(&self) -> Seq {
        self.event_seq
    }
    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.entity
    }
    #[must_use]
    pub const fn consent_record_id(&self) -> &AdmissionSnapshotId {
        &self.consent_record_id
    }
    #[must_use]
    pub const fn consent_revision(&self) -> u64 {
        self.consent_revision
    }
    #[must_use]
    pub const fn consent_record_hash(&self) -> &ConsentRecordHash {
        &self.consent_record_hash
    }
}

impl AdmissionEntitlementSnapshotV1 {
    #[must_use]
    pub fn new(
        id: AdmissionSnapshotId,
        request: &GeoCellAdmissionRequestV1,
        event_id: EventId,
        event_seq: Seq,
    ) -> Self {
        Self {
            id,
            fields: AdmissionSnapshotFieldsV1::from(&request.fence.draft),
            event_id,
            event_seq,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> CanonicalBytes {
        let fields = &self.fields;
        let principals: Vec<Value> = fields
            .entitled_principals
            .iter()
            .map(|id| Value::Text(id.to_string()))
            .collect();
        let mut entries = vec![
            (
                Value::Text("snapshot_schema_version".to_owned()),
                Value::Integer(1_u8.into()),
            ),
            (
                Value::Text("snapshot_id".to_owned()),
                Value::Text(self.id.0.clone()),
            ),
            (
                Value::Text("timeline_id".to_owned()),
                Value::Text(fields.timeline.to_string()),
            ),
            (
                Value::Text("source_event_id".to_owned()),
                Value::Text(self.event_id.to_string()),
            ),
            (
                Value::Text("source_seq".to_owned()),
                Value::Integer(self.event_seq.as_u64().into()),
            ),
            (
                Value::Text("participant_entity_id".to_owned()),
                Value::Text(fields.entity.to_string()),
            ),
            (
                Value::Text("consent_record_id".to_owned()),
                Value::Text(fields.consent_record_id.as_str().to_owned()),
            ),
            (
                Value::Text("consent_revision".to_owned()),
                Value::Integer(fields.consent_revision.into()),
            ),
            (
                Value::Text("consent_record_hash".to_owned()),
                Value::Bytes(fields.consent_record_hash.as_bytes().to_vec()),
            ),
            (
                Value::Text("purpose".to_owned()),
                Value::Text(fields.purpose.clone()),
            ),
            (
                Value::Text("entitled_principals".to_owned()),
                Value::Array(principals),
            ),
            (
                Value::Text("visibility_scope".to_owned()),
                Value::Text(fields.visibility_scope.clone()),
            ),
            (
                Value::Text("maximum_h3_resolution".to_owned()),
                Value::Integer(fields.maximum_h3_resolution.into()),
            ),
            (
                Value::Text("admission_policy_version".to_owned()),
                Value::Integer(fields.admission_policy_version.into()),
            ),
            (
                Value::Text("admission_epoch".to_owned()),
                Value::Integer(fields.admission_epoch.into()),
            ),
        ];
        sort_snapshot_entries(&mut entries);
        let value = Value::Map(entries);
        let mut bytes = Vec::new();
        let _ = ciborium::into_writer(&value, &mut bytes);
        CanonicalBytes::from_vec(bytes)
    }

    #[must_use]
    pub fn hash(&self) -> AdmissionSnapshotHash {
        let bytes = self.canonical_bytes();
        hash_admission_snapshot_bytes(&bytes)
    }

    #[must_use]
    pub fn id(&self) -> &AdmissionSnapshotId {
        &self.id
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn event_seq(&self) -> Seq {
        self.event_seq
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.fields.timeline
    }

    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.fields.entity
    }

    #[must_use]
    pub const fn consent_record_id(&self) -> &AdmissionSnapshotId {
        &self.fields.consent_record_id
    }

    #[must_use]
    pub const fn consent_revision(&self) -> u64 {
        self.fields.consent_revision
    }

    #[must_use]
    pub const fn consent_record_hash(&self) -> &ConsentRecordHash {
        &self.fields.consent_record_hash
    }

    /// Expose the linkage already held by this typed immutable snapshot.
    #[must_use]
    pub fn linkage(&self) -> AdmissionSnapshotLinkageV1 {
        AdmissionSnapshotLinkageV1 {
            snapshot_id: self.id.clone(),
            timeline: self.fields.timeline,
            event_id: self.event_id,
            event_seq: self.event_seq,
            entity: self.fields.entity,
            consent_record_id: self.fields.consent_record_id.clone(),
            consent_revision: self.fields.consent_revision,
            consent_record_hash: self.fields.consent_record_hash,
        }
    }

    /// Validate one persisted snapshot's canonical structure without requiring
    /// source-side cell or fingerprint material during Replay.
    ///
    /// # Panics
    ///
    /// This method panics only if a `Vec` writer reports an impossible I/O
    /// failure while checking canonical bytes.
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::too_many_lines)]
    pub fn validate_canonical_bytes(bytes: &CanonicalBytes) -> Result<(), CoreError> {
        Self::canonical_linkage(bytes).map(|_| ())
    }

    /// Decode and validate the immutable linkage fields in one snapshot.
    #[allow(clippy::too_many_lines)]
    pub fn canonical_linkage(
        bytes: &CanonicalBytes,
    ) -> Result<AdmissionSnapshotLinkageV1, CoreError> {
        let mut cursor = Cursor::new(bytes.as_slice());
        let value: Value = ciborium::from_reader(&mut cursor)
            .map_err(|error| CoreError::Serialization(error.to_string()))?;
        if cursor.position() != bytes.len() as u64 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let Value::Map(entries) = value else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        if entries.len() != 15 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let mut snapshot_schema_version = None;
        let mut snapshot_id = None;
        let mut timeline_id = None;
        let mut source_event_id = None;
        let mut source_seq = None;
        let mut participant_entity_id = None;
        let mut consent_record_id = None;
        let mut consent_revision = None;
        let mut consent_record_hash = None;
        let mut purpose = None;
        let mut entitled_principals = None;
        let mut visibility_scope = None;
        let mut maximum_h3_resolution = None;
        let mut admission_policy_version = None;
        let mut admission_epoch = None;
        for (key, field) in entries {
            let Value::Text(key) = key else {
                return Err(CoreError::GeographicAdmissionValidationFailed);
            };
            let target = match key.as_str() {
                "snapshot_schema_version" => &mut snapshot_schema_version,
                "snapshot_id" => &mut snapshot_id,
                "timeline_id" => &mut timeline_id,
                "source_event_id" => &mut source_event_id,
                "source_seq" => &mut source_seq,
                "participant_entity_id" => &mut participant_entity_id,
                "consent_record_id" => &mut consent_record_id,
                "consent_revision" => &mut consent_revision,
                "consent_record_hash" => &mut consent_record_hash,
                "purpose" => &mut purpose,
                "entitled_principals" => &mut entitled_principals,
                "visibility_scope" => &mut visibility_scope,
                "maximum_h3_resolution" => &mut maximum_h3_resolution,
                "admission_policy_version" => &mut admission_policy_version,
                "admission_epoch" => &mut admission_epoch,
                _ => return Err(CoreError::GeographicAdmissionValidationFailed),
            };
            if target.replace(field).is_some() {
                return Err(CoreError::GeographicAdmissionValidationFailed);
            }
        }
        let text = |value: Option<Value>| match value {
            Some(Value::Text(value)) => Ok(value),
            _ => Err(CoreError::GeographicAdmissionValidationFailed),
        };
        let bytes32 = |value: Option<Value>| -> Result<[u8; 32], CoreError> {
            match value {
                Some(Value::Bytes(value)) => value
                    .try_into()
                    .map_err(|_| CoreError::GeographicAdmissionValidationFailed),
                _ => Err(CoreError::GeographicAdmissionValidationFailed),
            }
        };
        let unsigned = |value: Option<Value>| match value {
            Some(Value::Integer(value)) => {
                u64::try_from(value).map_err(|_| CoreError::GeographicAdmissionValidationFailed)
            }
            _ => Err(CoreError::GeographicAdmissionValidationFailed),
        };
        let parse_id = |value: Option<Value>| -> Result<ulid::Ulid, CoreError> {
            text(value)?
                .parse()
                .map_err(|_| CoreError::GeographicAdmissionValidationFailed)
        };
        if unsigned(snapshot_schema_version)? != 1 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let snapshot_id = AdmissionSnapshotId::from_canonical(&text(snapshot_id)?)
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        let timeline = TimelineId::from_ulid(parse_id(timeline_id)?);
        let event_id = EventId::from_ulid(parse_id(source_event_id)?);
        let entity = EntityId::from_ulid(parse_id(participant_entity_id)?);
        let event_seq = Seq::from_u64(unsigned(source_seq)?);
        let consent_record_id = AdmissionSnapshotId::from_canonical(&text(consent_record_id)?)
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        let consent_revision = unsigned(consent_revision)?;
        if consent_revision == 0 {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let consent_record_hash = ConsentRecordHash::from_bytes(bytes32(consent_record_hash)?);
        let purpose = text(purpose)?;
        let visibility_scope = text(visibility_scope)?;
        let maximum_h3_resolution = u8::try_from(unsigned(maximum_h3_resolution)?)
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        if maximum_h3_resolution > 15 || purpose.is_empty() || visibility_scope.is_empty() {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let admission_policy_version = u32::try_from(unsigned(admission_policy_version)?)
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        let admission_epoch = unsigned(admission_epoch)?;
        let Some(Value::Array(principals)) = entitled_principals else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        let entitled_principals = principals
            .into_iter()
            .map(|value| {
                let Value::Text(value) = value else {
                    return Err(CoreError::GeographicAdmissionValidationFailed);
                };
                value
                    .parse::<ulid::Ulid>()
                    .map(EntityId::from_ulid)
                    .map_err(|_| CoreError::GeographicAdmissionValidationFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if entitled_principals.is_empty()
            || entitled_principals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || admission_policy_version == 0
            || admission_epoch == 0
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let principals: Vec<Value> = entitled_principals
            .iter()
            .map(|id| Value::Text(id.to_string()))
            .collect();
        let mut canonical_entries = vec![
            (
                Value::Text("snapshot_schema_version".to_owned()),
                Value::Integer(1_u8.into()),
            ),
            (
                Value::Text("snapshot_id".to_owned()),
                Value::Text(snapshot_id.as_str().to_owned()),
            ),
            (
                Value::Text("timeline_id".to_owned()),
                Value::Text(timeline.to_string()),
            ),
            (
                Value::Text("source_event_id".to_owned()),
                Value::Text(event_id.to_string()),
            ),
            (
                Value::Text("source_seq".to_owned()),
                Value::Integer(event_seq.as_u64().into()),
            ),
            (
                Value::Text("participant_entity_id".to_owned()),
                Value::Text(entity.to_string()),
            ),
            (
                Value::Text("consent_record_id".to_owned()),
                Value::Text(consent_record_id.as_str().to_owned()),
            ),
            (
                Value::Text("consent_revision".to_owned()),
                Value::Integer(consent_revision.into()),
            ),
            (
                Value::Text("consent_record_hash".to_owned()),
                Value::Bytes(consent_record_hash.as_bytes().to_vec()),
            ),
            (Value::Text("purpose".to_owned()), Value::Text(purpose)),
            (
                Value::Text("entitled_principals".to_owned()),
                Value::Array(principals),
            ),
            (
                Value::Text("visibility_scope".to_owned()),
                Value::Text(visibility_scope),
            ),
            (
                Value::Text("maximum_h3_resolution".to_owned()),
                Value::Integer(maximum_h3_resolution.into()),
            ),
            (
                Value::Text("admission_policy_version".to_owned()),
                Value::Integer(admission_policy_version.into()),
            ),
            (
                Value::Text("admission_epoch".to_owned()),
                Value::Integer(admission_epoch.into()),
            ),
        ];
        sort_snapshot_entries(&mut canonical_entries);
        let canonical_value = Value::Map(canonical_entries);
        let mut canonical = Vec::new();
        let _ = ciborium::into_writer(&canonical_value, &mut canonical);
        if canonical != bytes.as_slice() {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(AdmissionSnapshotLinkageV1 {
            snapshot_id,
            timeline,
            event_id,
            event_seq,
            entity,
            consent_record_id,
            consent_revision,
            consent_record_hash,
        })
    }
}

impl AdmissionSnapshotId {
    /// Allocate a store-owned canonical snapshot identity.
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let value = ulid::Ulid::gen().to_string();
        Self(value)
    }
}

impl AdmissionSnapshotHash {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Hash canonical snapshot bytes as required by ADR-034/ADR-037.
#[must_use]
pub fn hash_admission_snapshot_bytes(bytes: &CanonicalBytes) -> AdmissionSnapshotHash {
    AdmissionSnapshotHash::from_bytes(*blake3::hash(bytes.as_slice()).as_bytes())
}

/// Result of one privileged V1 `geo.cell` admission attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeographicAdmissionOutcome {
    Accepted {
        persisted_event: Box<Event>,
        event_id: EventId,
        event_seq: Seq,
        snapshot_id: AdmissionSnapshotId,
        snapshot_hash: AdmissionSnapshotHash,
    },
    Duplicate {
        event_id: EventId,
        event_seq: Seq,
        snapshot_id: AdmissionSnapshotId,
        snapshot_hash: AdmissionSnapshotHash,
    },
    Conflict,
    Unavailable,
    OutcomeUnknown,
}

impl GeographicAdmissionOutcome {
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate { .. })
    }

    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict)
    }

    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
    }

    #[must_use]
    pub const fn is_outcome_unknown(&self) -> bool {
        matches!(self, Self::OutcomeUnknown)
    }

    #[must_use]
    pub const fn event_id(&self) -> Option<EventId> {
        match self {
            Self::Accepted { event_id, .. } | Self::Duplicate { event_id, .. } => Some(*event_id),
            Self::Conflict | Self::Unavailable | Self::OutcomeUnknown => None,
        }
    }

    #[must_use]
    pub const fn event_seq(&self) -> Option<Seq> {
        match self {
            Self::Accepted { event_seq, .. } | Self::Duplicate { event_seq, .. } => {
                Some(*event_seq)
            }
            Self::Conflict | Self::Unavailable | Self::OutcomeUnknown => None,
        }
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> Option<&AdmissionSnapshotId> {
        match self {
            Self::Accepted { snapshot_id, .. } | Self::Duplicate { snapshot_id, .. } => {
                Some(snapshot_id)
            }
            Self::Conflict | Self::Unavailable | Self::OutcomeUnknown => None,
        }
    }

    #[must_use]
    pub const fn snapshot_hash(&self) -> Option<AdmissionSnapshotHash> {
        match self {
            Self::Accepted { snapshot_hash, .. } | Self::Duplicate { snapshot_hash, .. } => {
                Some(*snapshot_hash)
            }
            Self::Conflict | Self::Unavailable | Self::OutcomeUnknown => None,
        }
    }

    #[must_use]
    pub fn persisted_event(&self) -> Option<&Event> {
        match self {
            Self::Accepted {
                persisted_event, ..
            } => Some(persisted_event.as_ref()),
            Self::Duplicate { .. } | Self::Conflict | Self::Unavailable | Self::OutcomeUnknown => {
                None
            }
        }
    }
}

/// Typed port to the authoritative immutable ADR-034 consent records.
pub trait GeographicAdmissionConsentResolver {
    fn resolve_admission_consent(
        &self,
        consent_record_id: &AdmissionSnapshotId,
        consent_revision: u64,
    ) -> Result<AdmissionConsentRecordV1, CoreError>;
}

/// Dedicated capability for the core-owned `geo.cell` admission transaction.
pub trait GeographicAdmissionStore: GeographicAdmissionConsentResolver {
    fn admit(
        &mut self,
        request: ValidatedGeographicAdmissionV1,
    ) -> Result<GeographicAdmissionOutcome, CoreError>;
}

/// Validated, core-owned input accepted by [`GeographicAdmissionStore`].
pub type ValidatedGeographicAdmissionV1 = GeoCellAdmissionRequestV1;

/// Trusted administrative capability for current geo.cell admission state.
pub trait GeographicAdmissionAdmin {
    /// Store one authoritative immutable consent record before installing a
    /// fence that references it. Existing `(id, revision)` bytes are immutable.
    fn set_geo_cell_admission_consent_record(
        &mut self,
        record: AdmissionConsentRecordV1,
    ) -> Result<(), CoreError>;

    fn set_geo_cell_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoCellAdmissionFenceV1,
    ) -> Result<(), CoreError>;
}

/// Verification-only replay evidence; no raw payload or snapshot bytes are exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeographicReplayEvidenceV1 {
    timeline: TimelineId,
    event_id: EventId,
    event_seq: Seq,
    event_payload_hash: Hash,
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
}

impl GeographicReplayEvidenceV1 {
    #[must_use]
    pub const fn new(
        timeline: TimelineId,
        event_id: EventId,
        event_seq: Seq,
        event_payload_hash: Hash,
        snapshot_id: AdmissionSnapshotId,
        snapshot_hash: AdmissionSnapshotHash,
    ) -> Self {
        Self {
            timeline,
            event_id,
            event_seq,
            event_payload_hash,
            snapshot_id,
            snapshot_hash,
        }
    }

    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }
    #[must_use]
    pub const fn event_seq(&self) -> Seq {
        self.event_seq
    }
    #[must_use]
    pub const fn event_payload_hash(&self) -> Hash {
        self.event_payload_hash
    }
    #[must_use]
    pub const fn snapshot_id(&self) -> &AdmissionSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn snapshot_hash(&self) -> AdmissionSnapshotHash {
        self.snapshot_hash
    }
}

/// Dedicated replay verifier for the protected Event/snapshot relationship.
pub trait GeographicReplayVerifier: Send {
    fn verify_geo_cell_event(&self, evidence: GeographicReplayEvidenceV1) -> Result<(), CoreError>;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::event::Kind;
    use crate::GEOGRAPHIC_CELL_EVENT_TYPE;

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
        .encode();

        assert_eq!(payload.as_slice(), PAYLOAD_BYTES);
        assert_eq!(payload.len(), 262);
        assert_eq!(
            GeographicObservationV1::decode(&payload).unwrap().encode(),
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

    fn cbor(value: &Value) -> CanonicalBytes {
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).unwrap();
        CanonicalBytes::from_vec(bytes)
    }

    fn cell_value(index: &str, system: &str, resolution: u64, cell_format: u64) -> Value {
        Value::Map(vec![
            (
                Value::Text("index".to_owned()),
                Value::Text(index.to_owned()),
            ),
            (
                Value::Text("system".to_owned()),
                Value::Text(system.to_owned()),
            ),
            (
                Value::Text("resolution".to_owned()),
                Value::Integer(resolution.into()),
            ),
            (
                Value::Text("cell_format".to_owned()),
                Value::Integer(cell_format.into()),
            ),
        ])
    }

    fn consent_id() -> AdmissionSnapshotId {
        AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").unwrap()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn neutral_cell_validation_rejects_wire_shape_and_value_errors() {
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_vec(vec![0; 60])),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_vec(vec![1; 61])),
            Err(GeoCellAdmissionError::MalformedCbor)
        ));
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&cbor(&Value::Bytes(vec![0; 59]))),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_vec(vec![0xff; 61])),
            Err(GeoCellAdmissionError::MalformedCbor)
        ));
        let valid = cbor(&cell_value("8928308280fffff", "h3-v4", 9, 1));
        assert_eq!(valid.len(), 61);
        let mut trailing = valid.as_slice().to_vec();
        trailing.push(0);
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_vec(trailing)),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        let Value::Map(mut reordered) = cell_value("8928308280fffff", "h3-v4", 9, 1) else {
            unreachable!();
        };
        reordered.reverse();
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&cbor(&Value::Map(reordered))),
            Err(GeoCellAdmissionError::NonCanonicalCbor)
        ));
        for value in [
            cell_value("8928308280ffffg", "h3-v4", 9, 1),
            cell_value("8928308280FFFFF", "h3-v4", 9, 1),
            cell_value("000000000000000", "h3-v4", 9, 1),
            cell_value("8928308280fffff", "h3-v5", 9, 1),
            cell_value("8928308280fffff", "h3-v4", 8, 1),
            cell_value("8928308280fffff", "h3-v4", 9, 2),
            cell_value("8928308280ffffe", "h3-v4", 9, 1),
            cell_value("810847fffffffff", "h3-v4", 1, 1),
        ] {
            let bytes = cbor(&value);
            assert_eq!(bytes.len(), 61);
            assert!(ValidatedGeoCellV1::from_adr031_bytes(&bytes).is_err());
        }
        for (field, value) in [
            ("system", Value::Bytes(b"h3-v4".to_vec())),
            ("resolution", Value::Integer((-1).into())),
            ("cell_format", Value::Integer((-1).into())),
        ] {
            let mut altered = cell_value("8928308280fffff", "h3-v4", 9, 1);
            if let Value::Map(entries) = &mut altered {
                entries
                    .iter_mut()
                    .find(|(key, _)| key == &Value::Text(field.to_owned()))
                    .unwrap()
                    .1 = value;
            }
            assert!(matches!(
                ValidatedGeoCellV1::from_adr031_bytes(&cbor(&altered)),
                Err(GeoCellAdmissionError::WrongFieldType(_))
            ));
        }
        let mut wrong_index_type = cell_value("8928308280fffff", "h3-v4", 9, 1);
        if let Value::Map(entries) = &mut wrong_index_type {
            entries[0].1 = Value::Bytes(vec![0; 15]);
        }
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&cbor(&wrong_index_type)),
            Err(GeoCellAdmissionError::WrongFieldType("index"))
        ));
        for missing_field in ["index", "system", "resolution", "cell_format"] {
            let mut missing = cell_value("8928308280fffff", "h3-v4", 9, 1);
            if let Value::Map(entries) = &mut missing {
                entries.retain(|(key, _)| key != &Value::Text(missing_field.to_owned()));
            }
            assert!(ValidatedGeoCellV1::from_adr031_bytes(&cbor(&missing)).is_err());
        }
        let mut non_text_key = cell_value("8928308280fffff", "h3-v4", 9, 1);
        if let Value::Map(entries) = &mut non_text_key {
            entries[0].0 = Value::Bytes(vec![0; 5]);
        }
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&cbor(&non_text_key)),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        let duplicate_cell_format = Value::Map(vec![
            (
                Value::Text("index".to_owned()),
                Value::Text("8928308280fffff".to_owned()),
            ),
            (
                Value::Text("resolution".to_owned()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("cell_format".to_owned()),
                Value::Integer(1.into()),
            ),
            (Value::Text("cell_format".to_owned()), Value::Null),
        ]);
        assert_eq!(cbor(&duplicate_cell_format).len(), 61);
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&cbor(&duplicate_cell_format)),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        let unknown = cbor(&Value::Map(vec![
            (
                Value::Text("xxxxx".to_owned()),
                Value::Text("8928308280fffff".to_owned()),
            ),
            (
                Value::Text("system".to_owned()),
                Value::Text("h3-v4".to_owned()),
            ),
            (
                Value::Text("resolution".to_owned()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("cell_format".to_owned()),
                Value::Integer(1.into()),
            ),
        ]));
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&unknown),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        assert_eq!(GeoCellObservationPolicyVersion::V1.value(), 1);
    }

    #[test]
    fn covers_geo_cell_contract_accessors_and_edge_guards() {
        let mut non_text_entries = vec![
            (Value::Integer(1.into()), Value::Null),
            (Value::Integer(2.into()), Value::Null),
        ];
        sort_snapshot_entries(&mut non_text_entries);
        assert_eq!(non_text_entries[0].0, Value::Integer(1.into()));
        assert!(matches!(
            text_value(None, "text"),
            Err(GeoCellAdmissionError::MissingField("text"))
        ));
        assert!(matches!(
            unsigned_value(None, "unsigned"),
            Err(GeoCellAdmissionError::MissingField("unsigned"))
        ));
        assert!(matches!(
            signed_value(None, "signed"),
            Err(GeoCellAdmissionError::MissingField("signed"))
        ));

        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let consent_record_id = consent_id();
        let draft = AdmissionEntitlementDraftV1::new(
            timeline,
            entity,
            consent_record_id.clone(),
            1,
            ConsentRecordHash::from_bytes([7; 32]),
            "purpose",
            vec![entity],
            "private",
            9,
            1,
            1,
        )
        .unwrap();
        assert_eq!(draft.timeline(), timeline);
        assert_eq!(draft.entity(), entity);
        assert_eq!(draft.consent_record_id(), &consent_record_id);
        assert_eq!(draft.consent_revision(), 1);
        assert_eq!(draft.consent_record_hash().as_bytes(), [7; 32]);
        assert_eq!(draft.purpose(), "purpose");
        assert_eq!(draft.entitled_principals(), &[entity]);
        assert_eq!(draft.visibility_scope(), "private");
        assert_eq!(draft.maximum_h3_resolution(), 9);
        assert_eq!(draft.admission_policy_version(), 1);
        assert_eq!(draft.admission_epoch(), 1);
        assert!(AdmissionEntitlementDraftV1::new(
            timeline,
            entity,
            consent_record_id.clone(),
            1,
            ConsentRecordHash::from_bytes([7; 32]),
            "purpose",
            vec![entity, entity],
            "private",
            9,
            1,
            1,
        )
        .is_err());

        let fence = GeoCellAdmissionFenceV1::new(draft, [8; 32], 2, false);
        assert_eq!(fence.binding_identity(), &[8; 32]);
        assert_eq!(fence.binding_revision(), 2);
        let mut persisted = fence.persistence_bytes().as_slice().to_vec();
        persisted.push(0);
        assert!(matches!(
            GeoCellAdmissionFenceV1::from_persistence_bytes(&persisted),
            Err(CoreError::GeographicAdmissionValidationFailed)
        ));
        let canonical = fence.persistence_bytes().as_slice().to_vec();
        let key = b"binding_revision";
        let marker = [0x70_u8]
            .into_iter()
            .chain(key.iter().copied())
            .chain([2_u8])
            .collect::<Vec<_>>();
        let position = canonical
            .windows(marker.len())
            .position(|window| window == marker.as_slice())
            .expect("binding revision is present in fence bytes");
        let mut noncanonical = canonical[..position + marker.len() - 1].to_vec();
        noncanonical.extend_from_slice(&[0x18, 2]);
        noncanonical.extend_from_slice(&canonical[position + marker.len()..]);
        assert!(matches!(
            GeoCellAdmissionFenceV1::from_persistence_bytes(&noncanonical),
            Err(CoreError::GeographicAdmissionValidationFailed)
        ));
    }

    #[test]
    fn validates_pentagon_center_and_deleted_subsequence() {
        let center = cbor(&cell_value("81083ffffffffff", "h3-v4", 1, 1));
        assert!(ValidatedGeoCellV1::from_adr031_bytes(&center).is_ok());
        let deleted = cbor(&cell_value("810847fffffffff", "h3-v4", 1, 1));
        assert!(matches!(
            ValidatedGeoCellV1::from_adr031_bytes(&deleted),
            Err(GeoCellAdmissionError::InvalidCell)
        ));
        let pentagon_base = 4_u64;
        let center_value =
            (1_u64 << 59) | (1_u64 << 52) | (pentagon_base << 45) | ((1_u64 << 42) - 1);
        let deleted_value = center_value | (1_u64 << 42);
        assert!(!is_h3_index_for_resolution(
            &format!("{deleted_value:015x}"),
            1
        ));
    }

    #[test]
    fn outer_geo_cell_decoder_rejects_shape_and_metadata_errors() {
        let cell = cbor(&cell_value("8928308280fffff", "h3-v4", 9, 1));
        let id = Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned());
        let hash = Value::Text(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        );
        let base = vec![
            (Value::Text("cell".to_owned()), cbor_to_value(&cell)),
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
                Value::Integer(2_000_000.into()),
            ),
            (Value::Text("admission_snapshot_id".to_owned()), id),
            (Value::Text("admission_snapshot_hash".to_owned()), hash),
        ];
        let valid = cbor(&Value::Map(base.clone()));
        assert!(GeographicObservationV1::decode(&valid).is_ok());
        assert!(GeographicObservationV1::decode(&CanonicalBytes::from_vec(vec![0xff])).is_err());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Bytes(vec![0]))).is_err());
        let mut missing_field = base.clone();
        missing_field.pop();
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(missing_field))).is_err());
        let mut missing_cell = base.clone();
        missing_cell.retain(|(key, _)| key != &Value::Text("cell".to_owned()));
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(missing_cell))).is_err());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Bytes(vec![0; 300]))).is_err());
        let mut trailing = valid.as_slice().to_vec();
        trailing.push(0);
        assert!(GeographicObservationV1::decode(&CanonicalBytes::from_vec(trailing)).is_err());
        for (field, value) in [
            ("quality_flags", Value::Integer(1.into())),
            ("policy_version", Value::Integer(2.into())),
            ("quality_flags", Value::Text("0".to_owned())),
            ("policy_version", Value::Text("1".to_owned())),
            ("source_time_bucket", Value::Text("2000000".to_owned())),
            ("admission_snapshot_id", Value::Text("lowercase".to_owned())),
            ("admission_snapshot_hash", Value::Text("ABCDEF".to_owned())),
        ] {
            let mut altered = base.clone();
            altered
                .iter_mut()
                .find(|(key, _)| key == &Value::Text(field.to_owned()))
                .unwrap()
                .1 = value;
            assert!(GeographicObservationV1::decode(&cbor(&Value::Map(altered))).is_err());
        }
        let mut unknown = base.clone();
        unknown[0].0 = Value::Text("unknown".to_owned());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(unknown))).is_err());
        let mut duplicate = base.clone();
        duplicate.pop();
        duplicate.push((Value::Text("cell".to_owned()), duplicate[0].1.clone()));
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(duplicate))).is_err());
        let mut missing_source_bucket = base.clone();
        missing_source_bucket
            .retain(|(key, _)| key != &Value::Text("source_time_bucket".to_owned()));
        assert!(
            GeographicObservationV1::decode(&cbor(&Value::Map(missing_source_bucket))).is_err()
        );
        let mut missing_snapshot_id = base.clone();
        missing_snapshot_id
            .retain(|(key, _)| key != &Value::Text("admission_snapshot_id".to_owned()));
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(missing_snapshot_id))).is_err());
        let mut missing_snapshot_hash = base.clone();
        missing_snapshot_hash
            .retain(|(key, _)| key != &Value::Text("admission_snapshot_hash".to_owned()));
        assert!(
            GeographicObservationV1::decode(&cbor(&Value::Map(missing_snapshot_hash))).is_err()
        );
        let mut wrong_cell = base.clone();
        wrong_cell[0].1 = Value::Text("not-a-cell".to_owned());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(wrong_cell))).is_err());
        let mut non_text_key = base.clone();
        non_text_key[0].0 = Value::Integer(1.into());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(non_text_key))).is_err());
        let mut reordered = base.clone();
        reordered.reverse();
        assert!(matches!(
            GeographicObservationV1::decode(&cbor(&Value::Map(reordered))),
            Err(GeoCellAdmissionError::NonCanonicalCbor)
        ));
        let mut negative_quality = base.clone();
        negative_quality[1].1 = Value::Integer((-1).into());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(negative_quality))).is_err());
        let mut oversized_bucket = base.clone();
        oversized_bucket[3].1 = Value::Integer(u64::MAX.into());
        assert!(GeographicObservationV1::decode(&cbor(&Value::Map(oversized_bucket))).is_err());
    }

    fn cbor_to_value(bytes: &CanonicalBytes) -> Value {
        ciborium::from_reader(bytes.as_slice()).unwrap()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn snapshot_validator_rejects_noncanonical_and_wrong_field_values() {
        let mut valid_entries = vec![
            (
                Value::Text("snapshot_schema_version".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("snapshot_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
            ),
            (
                Value::Text("timeline_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAW".to_owned()),
            ),
            (
                Value::Text("source_event_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAX".to_owned()),
            ),
            (
                Value::Text("source_seq".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("participant_entity_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned()),
            ),
            (
                Value::Text("consent_record_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAZ".to_owned()),
            ),
            (
                Value::Text("consent_revision".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("consent_record_hash".to_owned()),
                Value::Bytes(vec![3; 32]),
            ),
            (
                Value::Text("purpose".to_owned()),
                Value::Text("p".to_owned()),
            ),
            (
                Value::Text("entitled_principals".to_owned()),
                Value::Array(vec![Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned())]),
            ),
            (
                Value::Text("visibility_scope".to_owned()),
                Value::Text("private".to_owned()),
            ),
            (
                Value::Text("maximum_h3_resolution".to_owned()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("admission_policy_version".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("admission_epoch".to_owned()),
                Value::Integer(1.into()),
            ),
        ];
        sort_snapshot_entries(&mut valid_entries);
        let valid = Value::Map(valid_entries);
        let bytes = cbor(&valid);
        assert!(AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&bytes).is_ok());
        let mut wrong_schema_version = snapshot_entries();
        wrong_schema_version
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("snapshot_schema_version".to_owned()))
            .unwrap()
            .1 = Value::Integer(2.into());
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                wrong_schema_version
            )))
            .is_err()
        );
        let mut zero_consent_revision = snapshot_entries();
        zero_consent_revision
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("consent_revision".to_owned()))
            .unwrap()
            .1 = Value::Integer(0.into());
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                zero_consent_revision
            )))
            .is_err()
        );
        let mut trailing = bytes.as_slice().to_vec();
        trailing.push(0);
        assert!(AdmissionEntitlementSnapshotV1::validate_canonical_bytes(
            &CanonicalBytes::from_vec(trailing)
        )
        .is_err());
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(
                &Value::Bytes(vec![0],)
            ))
            .is_err()
        );
        assert!(AdmissionEntitlementSnapshotV1::validate_canonical_bytes(
            &CanonicalBytes::from_vec(vec![0xff])
        )
        .is_err());
        let Value::Map(mut duplicate) = valid else {
            unreachable!();
        };
        duplicate.push((
            Value::Text("snapshot_id".to_owned()),
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        ));
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(duplicate)))
                .is_err()
        );
        let mut exact_duplicate = snapshot_entries();
        exact_duplicate.pop();
        exact_duplicate.push((
            Value::Text("snapshot_id".to_owned()),
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        ));
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                exact_duplicate,
            )))
            .is_err()
        );
        let mut non_text_key = snapshot_entries();
        non_text_key[0].0 = Value::Integer(1.into());
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                non_text_key,
            )))
            .is_err()
        );
        let mut noncanonical = bytes.as_slice().to_vec();
        assert_eq!(noncanonical.pop(), Some(1));
        noncanonical.extend_from_slice(&[0x18, 1]);
        assert!(AdmissionEntitlementSnapshotV1::validate_canonical_bytes(
            &CanonicalBytes::from_vec(noncanonical),
        )
        .is_err());
        let mut reordered = snapshot_entries();
        reordered.reverse();
        assert!(AdmissionEntitlementSnapshotV1::validate_canonical_bytes(
            &cbor(&Value::Map(reordered)),
        )
        .is_err());
    }

    fn snapshot_entries() -> Vec<(Value, Value)> {
        match snapshot_value() {
            Value::Map(entries) => entries,
            _ => unreachable!(),
        }
    }

    fn snapshot_value() -> Value {
        let mut entries = vec![
            (
                Value::Text("snapshot_schema_version".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("snapshot_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
            ),
            (
                Value::Text("timeline_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAW".to_owned()),
            ),
            (
                Value::Text("source_event_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAX".to_owned()),
            ),
            (
                Value::Text("source_seq".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("participant_entity_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned()),
            ),
            (
                Value::Text("consent_record_id".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAZ".to_owned()),
            ),
            (
                Value::Text("consent_revision".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("consent_record_hash".to_owned()),
                Value::Bytes(vec![3; 32]),
            ),
            (
                Value::Text("purpose".to_owned()),
                Value::Text("p".to_owned()),
            ),
            (
                Value::Text("entitled_principals".to_owned()),
                Value::Array(vec![Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned())]),
            ),
            (
                Value::Text("visibility_scope".to_owned()),
                Value::Text("private".to_owned()),
            ),
            (
                Value::Text("maximum_h3_resolution".to_owned()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("admission_policy_version".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("admission_epoch".to_owned()),
                Value::Integer(1.into()),
            ),
        ];
        sort_snapshot_entries(&mut entries);
        Value::Map(entries)
    }

    fn replace_snapshot_field(entries: &mut [(Value, Value)], name: &str, value: Value) {
        entries
            .iter_mut()
            .find(|(key, _)| key == &Value::Text(name.to_owned()))
            .unwrap()
            .1 = value;
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn snapshot_validator_rejects_missing_types_and_semantic_errors() {
        for field in [
            "snapshot_schema_version",
            "snapshot_id",
            "timeline_id",
            "source_event_id",
            "source_seq",
            "participant_entity_id",
            "consent_record_id",
            "consent_revision",
            "consent_record_hash",
            "purpose",
            "entitled_principals",
            "visibility_scope",
            "maximum_h3_resolution",
            "admission_policy_version",
            "admission_epoch",
        ] {
            let mut entries = snapshot_entries();
            entries.retain(|(key, _)| key != &Value::Text(field.to_owned()));
            assert!(
                AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                    entries
                )))
                .is_err()
            );
        }
        for field in [
            "snapshot_schema_version",
            "snapshot_id",
            "timeline_id",
            "source_event_id",
            "source_seq",
            "participant_entity_id",
            "consent_record_id",
            "consent_revision",
            "consent_record_hash",
            "purpose",
            "entitled_principals",
            "visibility_scope",
            "maximum_h3_resolution",
            "admission_policy_version",
            "admission_epoch",
        ] {
            let mut entries = snapshot_entries();
            replace_snapshot_field(&mut entries, field, Value::Null);
            assert!(
                AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                    entries
                )))
                .is_err()
            );
        }

        for (field, value) in [
            ("snapshot_id", Value::Text("lowercase".to_owned())),
            ("source_seq", Value::Integer((-1).into())),
            ("consent_record_id", Value::Text("lowercase".to_owned())),
            ("consent_record_hash", Value::Bytes(vec![0; 31])),
            ("maximum_h3_resolution", Value::Integer(16.into())),
            ("admission_policy_version", Value::Integer(0.into())),
            ("admission_epoch", Value::Integer(0.into())),
            ("entitled_principals", Value::Array(vec![Value::Null])),
        ] {
            let mut entries = snapshot_entries();
            replace_snapshot_field(&mut entries, field, value);
            assert!(
                AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                    entries
                )))
                .is_err()
            );
        }
        let mut entries = snapshot_entries();
        replace_snapshot_field(&mut entries, "purpose", Value::Text(String::new()));
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        replace_snapshot_field(&mut entries, "visibility_scope", Value::Text(String::new()));
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        replace_snapshot_field(
            &mut entries,
            "entitled_principals",
            Value::Array(vec![
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned()),
                Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned()),
            ]),
        );
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        for field in ["timeline_id", "source_event_id", "participant_entity_id"] {
            let mut entries = snapshot_entries();
            replace_snapshot_field(&mut entries, field, Value::Text("not-an-id".to_owned()));
            assert!(
                AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                    entries
                )))
                .is_err()
            );
        }
        for field in ["consent_record_id", "consent_record_hash"] {
            let mut entries = snapshot_entries();
            replace_snapshot_field(
                &mut entries,
                field,
                if field == "consent_record_id" {
                    Value::Text("not-an-id".to_owned())
                } else {
                    Value::Bytes(vec![0; 31])
                },
            );
            assert!(
                AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(
                    entries
                )))
                .is_err()
            );
        }
        let mut entries = snapshot_entries();
        replace_snapshot_field(
            &mut entries,
            "entitled_principals",
            Value::Array(vec![Value::Text("not-an-id".to_owned())]),
        );
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        replace_snapshot_field(&mut entries, "source_seq", Value::Integer((-1).into()));
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        replace_snapshot_field(
            &mut entries,
            "maximum_h3_resolution",
            Value::Integer(u64::MAX.into()),
        );
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        replace_snapshot_field(
            &mut entries,
            "admission_policy_version",
            Value::Integer(u64::MAX.into()),
        );
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        entries[0].0 = Value::Integer(1.into());
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
        let mut entries = snapshot_entries();
        entries[0].0 = Value::Text("unknown".to_owned());
        assert!(
            AdmissionEntitlementSnapshotV1::validate_canonical_bytes(&cbor(&Value::Map(entries)))
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn core_geo_cell_types_validate_round_trip_and_expose_contract() {
        let cell = ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(CELL_BYTES))
            .unwrap();
        let snapshot_id =
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let snapshot_hash = AdmissionSnapshotHash::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(cell.resolution(), 9);
        assert_eq!(cell.as_bytes().as_slice(), CELL_BYTES);
        assert_eq!(snapshot_id.as_str(), "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(
            snapshot_hash.as_bytes(),
            [
                1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69,
                103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239
            ]
        );
        assert_eq!(
            snapshot_hash.as_hex(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(snapshot_hash.to_string(), snapshot_hash.as_hex());
        assert!(AdmissionSnapshotId::from_canonical("01arz3ndektsv4rrffq69g5fav").is_err());
        assert!(AdmissionSnapshotId::from_canonical("not-a-ulid").is_err());
        assert!(AdmissionSnapshotHash::from_hex("ABCDEF").is_err());
        assert!(AdmissionSnapshotHash::from_hex(&"A".repeat(64)).is_err());
        assert!(AdmissionSnapshotHash::from_hex(&"0".repeat(64)).is_ok());
        assert!(AdmissionSnapshotHash::from_hex(&"g".repeat(64)).is_err());
        assert_eq!(hex_nibble(b'Z'), 0);

        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let principal = EntityId::new();
        let draft = AdmissionEntitlementDraftV1::new(
            timeline,
            entity,
            consent_id(),
            4,
            [5; 32],
            "purpose",
            vec![principal, entity],
            "private",
            9,
            1,
            7,
        )
        .unwrap();
        assert_eq!(draft.timeline(), timeline);
        assert_eq!(draft.entity(), entity);
        assert_eq!(draft.consent_record_id(), &consent_id());
        assert_eq!(draft.consent_revision(), 4);
        assert_eq!(
            draft.consent_record_hash(),
            &ConsentRecordHash::from_bytes([5; 32])
        );
        assert_eq!(draft.purpose(), "purpose");
        assert_eq!(draft.visibility_scope(), "private");
        assert_eq!(draft.maximum_h3_resolution(), 9);
        assert_eq!(draft.admission_policy_version(), 1);
        assert_eq!(draft.admission_epoch(), 7);
        assert!(draft
            .entitled_principals()
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        for invalid in [
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                0,
                [0; 32],
                "",
                vec![],
                "private",
                9,
                1,
                1,
            ),
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                0,
                [0; 32],
                "purpose",
                vec![],
                "",
                9,
                1,
                1,
            ),
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                0,
                [0; 32],
                "purpose",
                vec![],
                "private",
                16,
                1,
                1,
            ),
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                0,
                [0; 32],
                "purpose",
                vec![],
                "private",
                9,
                0,
                1,
            ),
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                0,
                [0; 32],
                "purpose",
                vec![],
                "private",
                9,
                1,
                0,
            ),
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                0,
                [0; 32],
                "purpose",
                vec![entity, entity],
                "private",
                9,
                1,
                1,
            ),
        ] {
            assert!(invalid.is_err());
        }

        let fence = GeoCellAdmissionFenceV1::new(draft, [1; 32], 2, false);
        let input = GeoCellAdmissionInputV1::new(
            cell.clone(),
            SourceTimeBucket::new(-10),
            fence.clone(),
            GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        );
        let request = GeoCellAdmissionRequestV1::from_input(input).unwrap();
        let too_low_fence = GeoCellAdmissionFenceV1::new(
            AdmissionEntitlementDraftV1::new(
                timeline,
                entity,
                consent_id(),
                4,
                [5; 32],
                "purpose",
                vec![principal, entity],
                "private",
                8,
                1,
                7,
            )
            .unwrap(),
            [1; 32],
            2,
            false,
        );
        assert!(
            GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
                cell.clone(),
                SourceTimeBucket::new(-10),
                too_low_fence,
                GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
            ))
            .is_err()
        );
        assert_eq!(request.timeline(), timeline);
        assert_eq!(request.entity(), entity);
        assert_eq!(request.cell(), &cell);
        assert_eq!(request.source_time_bucket().value(), -10);
        assert_eq!(
            request.fingerprint(),
            GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
                cell.clone(),
                SourceTimeBucket::new(-10),
                fence.clone(),
                GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
            ))
            .unwrap()
            .fingerprint()
        );
        assert!(!request.intent().as_persistence_bytes().is_empty());
        assert!(fence.permits(&request));
        assert!(!fence.withdrawn());
        assert!(!GeoCellAdmissionFenceV1::new(
            fence.draft().clone(),
            *fence.binding_identity(),
            fence.binding_revision(),
            true,
        )
        .permits(&request));
        let persisted = fence.persistence_bytes();
        assert_eq!(
            GeoCellAdmissionFenceV1::from_persistence_bytes(persisted.as_slice()).unwrap(),
            fence
        );
        assert!(GeoCellAdmissionFenceV1::from_persistence_bytes(&[0xff]).is_err());
        let mut invalid_fence = fence.clone();
        invalid_fence.draft.purpose.clear();
        let mut invalid_fence_bytes = Vec::new();
        ciborium::into_writer(&invalid_fence, &mut invalid_fence_bytes).unwrap();
        assert!(GeoCellAdmissionFenceV1::from_persistence_bytes(&invalid_fence_bytes).is_err());
        let mut trailing_fence = fence.persistence_bytes().as_slice().to_vec();
        trailing_fence.push(0);
        assert!(GeoCellAdmissionFenceV1::from_persistence_bytes(&trailing_fence).is_err());
        let mut noncanonical_id = fence.clone();
        noncanonical_id.draft.consent_record_id = AdmissionSnapshotId("lowercase".to_owned());
        let mut noncanonical_id_bytes = Vec::new();
        ciborium::into_writer(&noncanonical_id, &mut noncanonical_id_bytes).unwrap();
        assert!(GeoCellAdmissionFenceV1::from_persistence_bytes(&noncanonical_id_bytes).is_err());
        let mut empty_principals = fence.clone();
        empty_principals.draft.entitled_principals.clear();
        let mut empty_principals_bytes = Vec::new();
        ciborium::into_writer(&empty_principals, &mut empty_principals_bytes).unwrap();
        assert!(GeoCellAdmissionFenceV1::from_persistence_bytes(&empty_principals_bytes).is_err());

        let observation = request.payload(snapshot_id.clone(), snapshot_hash);
        assert_eq!(observation.cell(), &cell);
        assert_eq!(observation.source_time_bucket().value(), -10);
        assert_eq!(observation.snapshot_id(), &snapshot_id);
        assert_eq!(observation.snapshot_hash(), snapshot_hash);
        let event_id = EventId::new();
        let snapshot = AdmissionEntitlementSnapshotV1::new(
            snapshot_id.clone(),
            &request,
            event_id,
            Seq::from_u64(1),
        );
        assert_eq!(snapshot.id(), &snapshot_id);
        assert_eq!(snapshot.timeline(), request.timeline());
        assert_eq!(snapshot.entity(), request.entity());
        assert_eq!(snapshot.event_id(), event_id);
        assert_eq!(snapshot.event_seq(), Seq::from_u64(1));
        assert_eq!(
            snapshot.consent_record_id(),
            request.fence().draft().consent_record_id()
        );
        assert_eq!(
            snapshot.consent_revision(),
            request.fence().draft().consent_revision()
        );
        assert_eq!(
            snapshot.consent_record_hash(),
            request.fence().draft().consent_record_hash()
        );
        let linkage = snapshot.linkage();
        assert_eq!(linkage.snapshot_id(), snapshot.id());
        assert_eq!(linkage.timeline(), snapshot.timeline());
        assert_eq!(linkage.event_id(), snapshot.event_id());
        assert_eq!(linkage.event_seq(), snapshot.event_seq());
        assert_eq!(linkage.entity(), snapshot.entity());
        assert_eq!(linkage.consent_record_id(), snapshot.consent_record_id());
        assert_eq!(linkage.consent_revision(), snapshot.consent_revision());
        assert_eq!(
            linkage.consent_record_hash(),
            snapshot.consent_record_hash()
        );
        assert!(AdmissionEntitlementSnapshotV1::validate_canonical_bytes(
            &snapshot.canonical_bytes()
        )
        .is_ok());
        assert_eq!(
            snapshot.hash(),
            hash_admission_snapshot_bytes(&snapshot.canonical_bytes())
        );
        let _ = AdmissionSnapshotId::new();

        let evidence = GeographicReplayEvidenceV1::new(
            timeline,
            event_id,
            Seq::from_u64(1),
            Hash::zero(),
            snapshot_id.clone(),
            snapshot_hash,
        );
        assert_eq!(evidence.timeline(), timeline);
        assert_eq!(evidence.event_id(), event_id);
        assert_eq!(evidence.event_seq(), Seq::from_u64(1));
        assert_eq!(evidence.event_payload_hash(), Hash::zero());
        assert_eq!(evidence.snapshot_id(), &snapshot_id);
        assert_eq!(evidence.snapshot_hash(), snapshot_hash);

        let event = Event {
            id: event_id,
            entity,
            event_type: Kind::new(GEOGRAPHIC_CELL_EVENT_TYPE),
            payload: CanonicalBytes::from_static(b"payload"),
            wall_time: crate::WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: crate::SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::zero(),
        };
        let accepted = GeographicAdmissionOutcome::Accepted {
            persisted_event: Box::new(event),
            event_id,
            event_seq: Seq::from_u64(1),
            snapshot_id: snapshot_id.clone(),
            snapshot_hash,
        };
        assert!(accepted.is_accepted());
        assert!(!accepted.is_duplicate());
        assert!(accepted.persisted_event().is_some());
        assert_eq!(accepted.event_id(), Some(event_id));
        assert_eq!(accepted.event_seq(), Some(Seq::from_u64(1)));
        assert_eq!(accepted.snapshot_id(), Some(&snapshot_id));
        assert_eq!(accepted.snapshot_hash(), Some(snapshot_hash));
        for outcome in [
            GeographicAdmissionOutcome::Duplicate {
                event_id,
                event_seq: Seq::from_u64(1),
                snapshot_id: snapshot_id.clone(),
                snapshot_hash,
            },
            GeographicAdmissionOutcome::Conflict,
            GeographicAdmissionOutcome::Unavailable,
            GeographicAdmissionOutcome::OutcomeUnknown,
        ] {
            assert!(!outcome.is_accepted());
            assert!(outcome.persisted_event().is_none());
            assert_eq!(
                outcome.is_duplicate(),
                matches!(&outcome, GeographicAdmissionOutcome::Duplicate { .. })
            );
            assert_eq!(
                outcome.is_conflict(),
                matches!(&outcome, GeographicAdmissionOutcome::Conflict)
            );
            assert_eq!(
                outcome.is_unavailable(),
                matches!(&outcome, GeographicAdmissionOutcome::Unavailable)
            );
            assert_eq!(
                outcome.is_outcome_unknown(),
                matches!(&outcome, GeographicAdmissionOutcome::OutcomeUnknown)
            );
            if outcome.is_duplicate() {
                assert_eq!(outcome.event_id(), Some(event_id));
                assert_eq!(outcome.event_seq(), Some(Seq::from_u64(1)));
                assert_eq!(outcome.snapshot_id(), Some(&snapshot_id));
                assert_eq!(outcome.snapshot_hash(), Some(snapshot_hash));
            } else {
                assert!(outcome.event_id().is_none());
                assert!(outcome.event_seq().is_none());
                assert!(outcome.snapshot_id().is_none());
                assert!(outcome.snapshot_hash().is_none());
            }
        }
    }

    #[test]
    fn geo_cell_admission_helper_functions_cover_overflow_and_wrong_type_arms() {
        // signed_value: too-large positive integer cannot be represented as i64.
        let too_large = Value::Integer(u64::MAX.into());
        assert!(matches!(
            signed_value(Some(&too_large), "source_time_bucket"),
            Err(GeoCellAdmissionError::WrongFieldType("source_time_bucket"))
        ));

        // unsigned_value: negative integer cannot be represented as u64.
        let negative = Value::Integer((-1i64).into());
        assert!(matches!(
            unsigned_value(Some(&negative), "quality_flags"),
            Err(GeoCellAdmissionError::WrongFieldType("quality_flags"))
        ));

        // text_value: non-text value present → WrongFieldType.
        let not_text = Value::Integer(1.into());
        assert!(matches!(
            text_value(Some(not_text), "admission_snapshot_id"),
            Err(GeoCellAdmissionError::WrongFieldType(
                "admission_snapshot_id"
            ))
        ));

        // unsigned_value: non-integer value present → WrongFieldType.
        let not_int = Value::Text("x".to_owned());
        assert!(matches!(
            unsigned_value(Some(&not_int), "policy_version"),
            Err(GeoCellAdmissionError::WrongFieldType("policy_version"))
        ));
    }
}
