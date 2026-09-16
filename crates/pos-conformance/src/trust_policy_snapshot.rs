//! Immutable TPS1 trust-policy snapshots defined by ADR-058.

use ciborium::value::Value;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Magic for the immutable trust-policy snapshot record.
pub const TRUST_POLICY_SNAPSHOT_MAGIC_V1: &str = "TPS1";
/// Maximum encoded size of a TPS1 trust-policy snapshot.
pub const MAX_TRUST_POLICY_SNAPSHOT_BYTES_V1: usize = 1024 * 1024;

const FIELD_COUNT: usize = 12;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_EXPIRY_BYTES: usize = 64;
const MAX_SEMANTIC_VERSION_BYTES: usize = 64;
const MAX_TRUST_ROOTS: usize = 64;
const MAX_REVOKED_KEYS: usize = 4_096;
const MAX_REVOKED_ARTIFACTS: usize = 4_096;
const MAX_MINIMUM_VERSIONS: usize = 256;
const MAX_NESTED_ARRAY_ITEMS: u64 = 4_097;
const MAX_NESTING_DEPTH: u8 = 3;

/// Closed safe errors exposed by the TPS1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustPolicySnapshotContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic, schema version, or trust-root signature algorithm is unsupported.
    UnsupportedSchemaVersion,
    /// A required value or encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// A set-like record list is not strictly ordered or contains a duplicate.
    NonCanonicalOrder,
}

impl std::fmt::Display for TrustPolicySnapshotContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid TPS1 trust-policy snapshot encoding",
            Self::UnsupportedSchemaVersion => {
                "unsupported TPS1 trust-policy snapshot schema version"
            }
            Self::FieldOutOfBounds => "TPS1 trust-policy snapshot field is out of bounds",
            Self::NonCanonicalOrder => "TPS1 trust-policy snapshot lists are not canonical",
        })
    }
}

impl std::error::Error for TrustPolicySnapshotContractErrorV1 {}

/// One operator-trusted signing root in a TPS1 snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPolicyRootV1 {
    pub key_id: String,
    pub root_version: u64,
    pub algorithm: String,
    pub public_key: [u8; 32],
}

/// Minimum accepted semantic version for one artifact kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimumArtifactVersionV1 {
    pub artifact_kind: String,
    pub semantic_version: String,
}

/// Complete immutable trust-policy snapshot represented by a TPS1 record.
///
/// This type validates the record shape and canonical encoding. Admission
/// policy and cryptographic signature authentication require an external
/// deployment trust authority and are intentionally outside this contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPolicySnapshotV1 {
    pub policy_id: String,
    pub epoch: u64,
    pub effective_timeline_position: u64,
    pub trust_roots: Vec<TrustPolicyRootV1>,
    pub revoked_key_ids: Vec<String>,
    pub revoked_artifact_digests: Vec<[u8; 32]>,
    pub minimum_versions: Vec<MinimumArtifactVersionV1>,
    pub offline_valid_through: String,
    pub previous_snapshot_digest: Option<[u8; 32]>,
    pub operator_signature: [u8; 64],
}

impl TrustPolicySnapshotV1 {
    /// Validate TPS1 field bounds, list ordering, and structural constraints.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field or ordered list is invalid.
    pub fn validate(&self) -> Result<(), TrustPolicySnapshotContractErrorV1> {
        validate_fields(self)
    }

    /// Encode this snapshot as an exact deterministic-CBOR TPS1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TrustPolicySnapshotContractErrorV1> {
        validate_fields(self).and_then(|()| encode_value(&encode_snapshot(self)))
    }

    /// Decode and validate exact canonical TPS1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// structurally invalid TPS1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TrustPolicySnapshotContractErrorV1> {
        if bytes.len() > MAX_TRUST_POLICY_SNAPSHOT_BYTES_V1 {
            Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
        } else {
            decode_value(bytes)
                .and_then(|value| decode_snapshot(&value))
                .and_then(|snapshot| snapshot.validate().map(|()| snapshot))
        }
    }

    /// Compute the BLAKE3 content digest of the complete canonical TPS1 bytes,
    /// including the operator signature.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error if the snapshot is structurally invalid.
    pub fn digest(&self) -> Result<[u8; 32], TrustPolicySnapshotContractErrorV1> {
        self.to_canonical_cbor()
            .map(|bytes| *blake3::hash(&bytes).as_bytes())
    }
}

fn validate_fields(
    snapshot: &TrustPolicySnapshotV1,
) -> Result<(), TrustPolicySnapshotContractErrorV1> {
    if !crate::identifier(&snapshot.policy_id, MAX_IDENTIFIER_BYTES)
        || snapshot.epoch == 0
        || !valid_expiry(&snapshot.offline_valid_through)
        || snapshot.trust_roots.is_empty()
        || snapshot.trust_roots.len() > MAX_TRUST_ROOTS
        || snapshot.revoked_key_ids.len() > MAX_REVOKED_KEYS
        || snapshot.revoked_artifact_digests.len() > MAX_REVOKED_ARTIFACTS
        || snapshot.minimum_versions.len() > MAX_MINIMUM_VERSIONS
    {
        return Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds);
    }
    validate_trust_roots(&snapshot.trust_roots)
        .and_then(|()| validate_revoked_keys(&snapshot.revoked_key_ids))
        .and_then(|()| validate_revoked_artifacts(&snapshot.revoked_artifact_digests))
        .and_then(|()| validate_minimum_versions(&snapshot.minimum_versions))
}

fn validate_trust_roots(
    roots: &[TrustPolicyRootV1],
) -> Result<(), TrustPolicySnapshotContractErrorV1> {
    let mut public_keys = BTreeSet::new();
    let mut previous_key_id: Option<&str> = None;
    for root in roots {
        if !crate::identifier(&root.key_id, MAX_IDENTIFIER_BYTES) || root.root_version == 0 {
            return Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds);
        }
        if root.algorithm != "Ed25519" {
            return Err(TrustPolicySnapshotContractErrorV1::UnsupportedSchemaVersion);
        }
        if previous_key_id.is_some_and(|previous| previous.as_bytes() >= root.key_id.as_bytes())
            || !public_keys.insert(root.public_key)
        {
            return Err(TrustPolicySnapshotContractErrorV1::NonCanonicalOrder);
        }
        previous_key_id = Some(&root.key_id);
    }
    Ok(())
}

fn validate_revoked_keys(keys: &[String]) -> Result<(), TrustPolicySnapshotContractErrorV1> {
    if keys
        .iter()
        .any(|key_id| !crate::identifier(key_id, MAX_IDENTIFIER_BYTES))
    {
        return Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds);
    }
    if strictly_ordered_by(keys, |previous, next| previous.as_bytes() < next.as_bytes()) {
        Ok(())
    } else {
        Err(TrustPolicySnapshotContractErrorV1::NonCanonicalOrder)
    }
}

fn validate_revoked_artifacts(
    digests: &[[u8; 32]],
) -> Result<(), TrustPolicySnapshotContractErrorV1> {
    if strictly_ordered_by(digests, |previous, next| {
        previous.as_slice() < next.as_slice()
    }) {
        Ok(())
    } else {
        Err(TrustPolicySnapshotContractErrorV1::NonCanonicalOrder)
    }
}

fn validate_minimum_versions(
    versions: &[MinimumArtifactVersionV1],
) -> Result<(), TrustPolicySnapshotContractErrorV1> {
    if versions.iter().any(|version| {
        !crate::identifier(&version.artifact_kind, MAX_IDENTIFIER_BYTES)
            || !crate::semantic_version(&version.semantic_version, MAX_SEMANTIC_VERSION_BYTES, None)
    }) {
        return Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds);
    }
    if strictly_ordered_by(versions, |previous, next| {
        previous.artifact_kind.as_bytes() < next.artifact_kind.as_bytes()
    }) {
        Ok(())
    } else {
        Err(TrustPolicySnapshotContractErrorV1::NonCanonicalOrder)
    }
}

fn valid_expiry(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_EXPIRY_BYTES
}

fn strictly_ordered_by<T>(values: &[T], less_than: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less_than(&pair[0], &pair[1]))
}

fn encode_snapshot(snapshot: &TrustPolicySnapshotV1) -> Value {
    Value::Array(vec![
        Value::Text(TRUST_POLICY_SNAPSHOT_MAGIC_V1.to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(snapshot.policy_id.clone()),
        Value::Integer(snapshot.epoch.into()),
        Value::Integer(snapshot.effective_timeline_position.into()),
        Value::Array(snapshot.trust_roots.iter().map(encode_trust_root).collect()),
        Value::Array(
            snapshot
                .revoked_key_ids
                .iter()
                .cloned()
                .map(Value::Text)
                .collect(),
        ),
        Value::Array(
            snapshot
                .revoked_artifact_digests
                .iter()
                .map(|digest| Value::Bytes(digest.to_vec()))
                .collect(),
        ),
        Value::Array(
            snapshot
                .minimum_versions
                .iter()
                .map(encode_minimum_version)
                .collect(),
        ),
        Value::Text(snapshot.offline_valid_through.clone()),
        optional_digest(snapshot.previous_snapshot_digest.as_ref()),
        Value::Bytes(snapshot.operator_signature.to_vec()),
    ])
}

fn encode_trust_root(root: &TrustPolicyRootV1) -> Value {
    Value::Array(vec![
        Value::Text(root.key_id.clone()),
        Value::Integer(root.root_version.into()),
        Value::Text(root.algorithm.clone()),
        Value::Bytes(root.public_key.to_vec()),
    ])
}

fn encode_minimum_version(version: &MinimumArtifactVersionV1) -> Value {
    Value::Array(vec![
        Value::Text(version.artifact_kind.clone()),
        Value::Text(version.semantic_version.clone()),
    ])
}

fn optional_digest(value: Option<&[u8; 32]>) -> Value {
    value.map_or(Value::Null, |digest| Value::Bytes(digest.to_vec()))
}

fn decode_snapshot(
    value: &Value,
) -> Result<TrustPolicySnapshotV1, TrustPolicySnapshotContractErrorV1> {
    let fields = array(value, FIELD_COUNT)?;
    if text_value(&fields[0])? != TRUST_POLICY_SNAPSHOT_MAGIC_V1 || uint_value(&fields[1])? != 1 {
        return Err(TrustPolicySnapshotContractErrorV1::UnsupportedSchemaVersion);
    }
    Ok(TrustPolicySnapshotV1 {
        policy_id: text_value(&fields[2])?,
        epoch: uint_value(&fields[3])?,
        effective_timeline_position: uint_value(&fields[4])?,
        trust_roots: decode_trust_roots(&fields[5])?,
        revoked_key_ids: decode_revoked_keys(&fields[6])?,
        revoked_artifact_digests: decode_revoked_artifacts(&fields[7])?,
        minimum_versions: decode_minimum_versions(&fields[8])?,
        offline_valid_through: text_value(&fields[9])?,
        previous_snapshot_digest: optional_digest_value(&fields[10])?,
        operator_signature: fixed_bytes::<64>(&fields[11])?,
    })
}

fn decode_trust_roots(
    value: &Value,
) -> Result<Vec<TrustPolicyRootV1>, TrustPolicySnapshotContractErrorV1> {
    array_values(value).and_then(|values| {
        if values.is_empty() || values.len() > MAX_TRUST_ROOTS {
            Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
        } else {
            values.iter().map(decode_trust_root).collect()
        }
    })
}

fn decode_trust_root(
    value: &Value,
) -> Result<TrustPolicyRootV1, TrustPolicySnapshotContractErrorV1> {
    let fields = array(value, 4)?;
    Ok(TrustPolicyRootV1 {
        key_id: text_value(&fields[0])?,
        root_version: uint_value(&fields[1])?,
        algorithm: text_value(&fields[2])?,
        public_key: fixed_bytes::<32>(&fields[3])?,
    })
}

fn decode_revoked_keys(value: &Value) -> Result<Vec<String>, TrustPolicySnapshotContractErrorV1> {
    array_values(value).and_then(|values| {
        if values.len() > MAX_REVOKED_KEYS {
            Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
        } else {
            values.iter().map(text_value).collect()
        }
    })
}

fn decode_revoked_artifacts(
    value: &Value,
) -> Result<Vec<[u8; 32]>, TrustPolicySnapshotContractErrorV1> {
    array_values(value).and_then(|values| {
        if values.len() > MAX_REVOKED_ARTIFACTS {
            Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
        } else {
            values.iter().map(fixed_bytes::<32>).collect()
        }
    })
}

fn decode_minimum_versions(
    value: &Value,
) -> Result<Vec<MinimumArtifactVersionV1>, TrustPolicySnapshotContractErrorV1> {
    array_values(value).and_then(|values| {
        if values.len() > MAX_MINIMUM_VERSIONS {
            Err(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
        } else {
            values.iter().map(decode_minimum_version).collect()
        }
    })
}

fn decode_minimum_version(
    value: &Value,
) -> Result<MinimumArtifactVersionV1, TrustPolicySnapshotContractErrorV1> {
    let fields = array(value, 2)?;
    Ok(MinimumArtifactVersionV1 {
        artifact_kind: text_value(&fields[0])?,
        semantic_version: text_value(&fields[1])?,
    })
}

fn decode_value(bytes: &[u8]) -> Result<Value, TrustPolicySnapshotContractErrorV1> {
    preflight_cbor(bytes).and_then(|()| {
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| TrustPolicySnapshotContractErrorV1::InvalidEncoding)
            .and_then(|value| {
                encode_value(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(TrustPolicySnapshotContractErrorV1::InvalidEncoding)
                    }
                })
            })
    })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), TrustPolicySnapshotContractErrorV1> {
    crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, MAX_NESTED_ARRAY_ITEMS, true).map_err(
        |error| match error {
            crate::CborPreflightError::InvalidEncoding => {
                TrustPolicySnapshotContractErrorV1::InvalidEncoding
            }
            crate::CborPreflightError::FieldOutOfBounds => {
                TrustPolicySnapshotContractErrorV1::FieldOutOfBounds
            }
        },
    )
}

fn encode_value(value: &Value) -> Result<Vec<u8>, TrustPolicySnapshotContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| TrustPolicySnapshotContractErrorV1::InvalidEncoding)
}

fn array(value: &Value, length: usize) -> Result<&[Value], TrustPolicySnapshotContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(TrustPolicySnapshotContractErrorV1::InvalidEncoding),
    }
}

fn array_values(value: &Value) -> Result<&[Value], TrustPolicySnapshotContractErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(TrustPolicySnapshotContractErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, TrustPolicySnapshotContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(TrustPolicySnapshotContractErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, TrustPolicySnapshotContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| TrustPolicySnapshotContractErrorV1::InvalidEncoding)
        }
        _ => Err(TrustPolicySnapshotContractErrorV1::InvalidEncoding),
    }
}

fn fixed_bytes<const LENGTH: usize>(
    value: &Value,
) -> Result<[u8; LENGTH], TrustPolicySnapshotContractErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| TrustPolicySnapshotContractErrorV1::InvalidEncoding),
        _ => Err(TrustPolicySnapshotContractErrorV1::InvalidEncoding),
    }
}

fn optional_digest_value(
    value: &Value,
) -> Result<Option<[u8; 32]>, TrustPolicySnapshotContractErrorV1> {
    match value {
        Value::Null => Ok(None),
        _ => fixed_bytes::<32>(value).map(Some),
    }
}
