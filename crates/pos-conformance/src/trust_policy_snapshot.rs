//! Immutable TPS1 trust-policy snapshots defined by ADR-058.

use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
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
const OPERATOR_SIGNATURE_DOMAIN_V1: &[u8] = b"PiglorOS.TPS1.operator-signature.v1\0";

/// Authentication failures are separate from the structural TPS1 codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustPolicySnapshotAuthenticationErrorV1 {
    /// The snapshot is not canonical or structurally valid.
    InvalidSnapshot,
    /// The pinned release role is not the deployment-operator role.
    InvalidOperatorRole,
    /// The pinned operator public key is invalid.
    InvalidOperatorKey,
    /// The exact domain-separated signature does not verify.
    InvalidOperatorSignature,
}

impl std::fmt::Display for TrustPolicySnapshotAuthenticationErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSnapshot => "invalid canonical TPS1 snapshot",
            Self::InvalidOperatorRole => "invalid TPS1 operator role",
            Self::InvalidOperatorKey => "invalid TPS1 operator verification key",
            Self::InvalidOperatorSignature => "invalid TPS1 operator signature",
        })
    }
}

impl std::error::Error for TrustPolicySnapshotAuthenticationErrorV1 {}

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
/// This type validates the record shape and canonical encoding. Its signature
/// verifier requires an independently pinned operator key; deployment
/// admission and durable continuity belong to the host trust registry.
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
    /// Build the exact Ed25519 message over TPS1 fields 0 through 10.
    ///
    /// # Errors
    /// Returns a structural error if the snapshot is invalid.
    pub fn operator_signature_message_v1(
        &self,
    ) -> Result<Vec<u8>, TrustPolicySnapshotContractErrorV1> {
        self.validate()?;
        let mut fields = encode_snapshot_fields(self);
        fields.truncate(FIELD_COUNT - 1);
        encode_value(&Value::Array(fields)).map(|unsigned| {
            let mut message =
                Vec::with_capacity(OPERATOR_SIGNATURE_DOMAIN_V1.len() + unsigned.len());
            message.extend_from_slice(OPERATOR_SIGNATURE_DOMAIN_V1);
            message.extend_from_slice(&unsigned);
            message
        })
    }

    /// Authenticate the operator signature using a release-pinned key and role.
    /// TPS1 artifact roots cannot authorize their own operator signature.
    ///
    /// # Errors
    /// Returns a closed error for invalid shape, role, key, or signature.
    pub fn verify_operator_signature_v1(
        &self,
        operator_public_key: &[u8; 32],
        operator_role: &str,
    ) -> Result<(), TrustPolicySnapshotAuthenticationErrorV1> {
        if operator_role != "deployment-operator" {
            return Err(TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorRole);
        }
        let message = self
            .operator_signature_message_v1()
            .map_err(|_| TrustPolicySnapshotAuthenticationErrorV1::InvalidSnapshot)?;
        let key = VerifyingKey::from_bytes(operator_public_key)
            .map_err(|_| TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorKey)?;
        key.verify_strict(&message, &Signature::from_bytes(&self.operator_signature))
            .map_err(|_| TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorSignature)
    }

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

const fn valid_expiry(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_EXPIRY_BYTES
}

fn strictly_ordered_by<T>(values: &[T], less_than: impl Fn(&T, &T) -> bool) -> bool {
    values.windows(2).all(|pair| less_than(&pair[0], &pair[1]))
}

fn encode_snapshot(snapshot: &TrustPolicySnapshotV1) -> Value {
    Value::Array(encode_snapshot_fields(snapshot))
}

fn encode_snapshot_fields(snapshot: &TrustPolicySnapshotV1) -> Vec<Value> {
    vec![
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
    ]
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod operator_authentication_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_snapshot() -> Result<(TrustPolicySnapshotV1, SigningKey), Box<dyn std::error::Error>>
    {
        let bytes = crate::draft_trust_policy_snapshot_bytes_v1()?;
        let mut snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&bytes)?;
        let signer = SigningKey::from_bytes(&[17; 32]);
        let message = snapshot.operator_signature_message_v1()?;
        snapshot.operator_signature = signer.sign(&message).to_bytes();
        Ok((snapshot, signer))
    }

    #[test]
    fn authentication_errors_keep_distinct_public_messages() {
        for (error, message) in [
            (
                TrustPolicySnapshotAuthenticationErrorV1::InvalidSnapshot,
                "invalid canonical TPS1 snapshot",
            ),
            (
                TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorRole,
                "invalid TPS1 operator role",
            ),
            (
                TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorKey,
                "invalid TPS1 operator verification key",
            ),
            (
                TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorSignature,
                "invalid TPS1 operator signature",
            ),
        ] {
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn exact_operator_preimage_has_domain_and_eleven_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (snapshot, _) = signed_snapshot()?;
        let message = snapshot.operator_signature_message_v1()?;
        assert!(message.starts_with(OPERATOR_SIGNATURE_DOMAIN_V1));
        let unsigned = &message[OPERATOR_SIGNATURE_DOMAIN_V1.len()..];
        let value = decode_value(unsigned)?;
        assert_eq!(array(&value, 11)?.len(), 11);
        assert_ne!(unsigned, snapshot.to_canonical_cbor()?);
        Ok(())
    }

    #[test]
    fn signed_snapshot_requires_pinned_operator_role_key_and_exact_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut snapshot, signer) = signed_snapshot()?;
        let operator_key = signer.verifying_key().to_bytes();
        assert_eq!(
            snapshot.verify_operator_signature_v1(&operator_key, "deployment-operator"),
            Ok(())
        );
        assert_eq!(
            snapshot.verify_operator_signature_v1(&operator_key, "artifact-root"),
            Err(TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorRole)
        );
        let foreign_key = SigningKey::from_bytes(&[18; 32]).verifying_key().to_bytes();
        assert_eq!(
            snapshot.verify_operator_signature_v1(&foreign_key, "deployment-operator"),
            Err(TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorSignature)
        );
        let mut off_curve_key = [0; 32];
        off_curve_key[0] = 2;
        assert_eq!(
            snapshot.verify_operator_signature_v1(&off_curve_key, "deployment-operator"),
            Err(TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorKey)
        );
        snapshot.epoch += 1;
        assert_eq!(
            snapshot.verify_operator_signature_v1(&operator_key, "deployment-operator"),
            Err(TrustPolicySnapshotAuthenticationErrorV1::InvalidOperatorSignature)
        );
        snapshot.epoch = 0;
        assert_eq!(
            snapshot.verify_operator_signature_v1(&operator_key, "deployment-operator"),
            Err(TrustPolicySnapshotAuthenticationErrorV1::InvalidSnapshot)
        );
        Ok(())
    }
}
