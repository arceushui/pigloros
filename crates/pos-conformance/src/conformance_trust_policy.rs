//! The CTP1 conformance trust policy of ADR-062 Revision 8 section 5.2 (K-B, slice G2, #1237).
//!
//! TPS1 trust roots carry no role, so the evaluator-release and report-signing roots of the
//! conformance trust seam live in a separate record bound to the TPS1 snapshot it extends. TPS1
//! and the ADR-058 preflight are unchanged. A CTP1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CTP1", 1, policy_id, epoch, previous_policy_digest / null, trust_policy_snapshot_digest,
//!   [evaluator-release public key, ...], [report-signing public key, ...],
//!   [revoked key id, ...], [revoked evaluator binary digest, ...], [revoked report digest, ...],
//!   minimum_evaluator_protocol_version, offline_valid_through, operator_signature ]
//! ```
//!
//! Each root list holds 32-byte Ed25519 verifying keys in strictly ascending byte order, and no
//! key is a root of both roles. A root's key id is the DSSE key id, the BLAKE3 digest of the key.
//! Revoked key ids and digests are 32-byte values in strictly ascending order.
//! `offline_valid_through` is exact `YYYY-MM-DDTHH:MM:SSZ` UTC text. The operator signs the
//! domain `PiglorOS.CTP1.operator-signature.v1\0` followed by the canonical array of the first
//! thirteen fields.

use crate::ConformanceTrustRoleV1;
use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use std::io::Cursor;

/// Magic of the CTP1 conformance trust policy record.
pub const CONFORMANCE_TRUST_POLICY_MAGIC_V1: &str = "CTP1";
/// Largest encoded CTP1 record (1 MiB, inclusive).
pub const MAX_CONFORMANCE_TRUST_POLICY_BYTES_V1: usize = 1024 * 1024;
/// Most roots in each role's list.
pub const MAX_CONFORMANCE_TRUST_ROOTS_V1: usize = crate::TPS1_MAX_TRUST_ROOTS;
/// Most entries in each revocation list.
pub const MAX_CONFORMANCE_TRUST_REVOCATIONS_V1: usize = crate::TPS1_MAX_REVOKED_KEYS;

const FIELD_COUNT: u8 = 14;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_SEMANTIC_VERSION_BYTES: usize = 64;
const MAX_NESTING_DEPTH: u8 = 2;
const MAX_ARRAY_ITEMS: u64 = MAX_CONFORMANCE_TRUST_REVOCATIONS_V1 as u64 + 1;
const OPERATOR_SIGNATURE_DOMAIN_V1: &[u8] = b"PiglorOS.CTP1.operator-signature.v1\0";

/// Closed errors of the CTP1 codec and validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConformanceTrustPolicyContractErrorV1 {
    /// The bytes are malformed, not canonical, trailing, or use a forbidden CBOR item.
    #[error("invalid CTP1 conformance trust policy encoding")]
    InvalidEncoding,
    /// The magic or record version is not CTP1 version 1.
    #[error("unsupported CTP1 conformance trust policy version")]
    UnsupportedSchemaVersion,
    /// A value or the encoded record is outside its bound.
    #[error("CTP1 conformance trust policy field is out of bounds")]
    FieldOutOfBounds,
    /// A root or revocation list is not strictly ascending.
    #[error("CTP1 conformance trust policy lists are not canonical")]
    NonCanonicalOrder,
    /// One key is a root of both roles.
    #[error("CTP1 conformance trust policy key is a root of both roles")]
    RootRoleConflict,
}

/// One CTP1 conformance trust policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceTrustPolicyV1 {
    pub policy_id: String,
    pub epoch: u64,
    pub previous_policy_digest: Option<[u8; 32]>,
    pub trust_policy_snapshot_digest: [u8; 32],
    pub evaluator_release_roots: Vec<[u8; 32]>,
    pub report_signing_roots: Vec<[u8; 32]>,
    pub revoked_key_ids: Vec<[u8; 32]>,
    pub revoked_evaluator_binary_digests: Vec<[u8; 32]>,
    pub revoked_report_digests: Vec<[u8; 32]>,
    pub minimum_evaluator_protocol_version: String,
    pub offline_valid_through: String,
    pub operator_signature: [u8; 64],
}

impl ConformanceTrustPolicyV1 {
    /// The roots of `role`.
    #[must_use]
    pub fn roots(&self, role: ConformanceTrustRoleV1) -> &[[u8; 32]] {
        match role {
            ConformanceTrustRoleV1::EvaluatorRelease => &self.evaluator_release_roots,
            ConformanceTrustRoleV1::ReportSigning => &self.report_signing_roots,
        }
    }

    /// Validate every bound, list order and the role separation of the roots.
    ///
    /// # Errors
    /// Returns the closed error of the first violation.
    pub fn validate(&self) -> Result<(), ConformanceTrustPolicyContractErrorV1> {
        let roots = [&self.evaluator_release_roots, &self.report_signing_roots];
        let revocations = [
            &self.revoked_key_ids,
            &self.revoked_evaluator_binary_digests,
            &self.revoked_report_digests,
        ];
        if !crate::identifier(&self.policy_id, MAX_IDENTIFIER_BYTES)
            || self.epoch == 0
            || roots
                .iter()
                .any(|list| list.len() > MAX_CONFORMANCE_TRUST_ROOTS_V1)
            || revocations
                .iter()
                .any(|list| list.len() > MAX_CONFORMANCE_TRUST_REVOCATIONS_V1)
            || roots.iter().any(|list| {
                list.iter()
                    .any(|key| VerifyingKey::from_bytes(key).is_err())
            })
            || !crate::semantic_version(
                &self.minimum_evaluator_protocol_version,
                MAX_SEMANTIC_VERSION_BYTES,
                None,
            )
            || crate::parse_offline_valid_through_v1(&self.offline_valid_through).is_err()
        {
            return Err(ConformanceTrustPolicyContractErrorV1::FieldOutOfBounds);
        }
        if !roots
            .iter()
            .chain(&revocations)
            .all(|list| crate::strictly_ordered(list.as_slice()))
        {
            return Err(ConformanceTrustPolicyContractErrorV1::NonCanonicalOrder);
        }
        if self
            .evaluator_release_roots
            .iter()
            .any(|key| self.report_signing_roots.binary_search(key).is_ok())
        {
            return Err(ConformanceTrustPolicyContractErrorV1::RootRoleConflict);
        }
        Ok(())
    }

    /// The exact Ed25519 message the operator signs: the domain, then the canonical array of
    /// fields 0 through 12.
    ///
    /// # Errors
    /// Returns the validation error when the policy is invalid.
    pub fn operator_signature_message_v1(
        &self,
    ) -> Result<Vec<u8>, ConformanceTrustPolicyContractErrorV1> {
        self.validate().map(|()| {
            let mut message = OPERATOR_SIGNATURE_DOMAIN_V1.to_vec();
            self.encode_into(&mut message, FIELD_COUNT - 1);
            message
        })
    }

    /// Whether the operator signature verifies under `operator_key`.
    #[must_use]
    pub fn has_operator_signature(&self, operator_key: &VerifyingKey) -> bool {
        self.operator_signature_message_v1().is_ok_and(|message| {
            operator_key
                .verify_strict(&message, &Signature::from_bytes(&self.operator_signature))
                .is_ok()
        })
    }

    /// Encode the policy as its canonical CTP1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the policy is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ConformanceTrustPolicyContractErrorV1> {
        self.validate().map(|()| {
            let mut bytes = Vec::new();
            self.encode_into(&mut bytes, FIELD_COUNT);
            bytes
        })
    }

    /// Decode and validate exact canonical CTP1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(
        bytes: &[u8],
    ) -> Result<Self, ConformanceTrustPolicyContractErrorV1> {
        if bytes.len() > MAX_CONFORMANCE_TRUST_POLICY_BYTES_V1 {
            return Err(ConformanceTrustPolicyContractErrorV1::FieldOutOfBounds);
        }
        crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, MAX_ARRAY_ITEMS, true).map_err(
            |error| match error {
                crate::CborPreflightError::InvalidEncoding => {
                    ConformanceTrustPolicyContractErrorV1::InvalidEncoding
                }
                crate::CborPreflightError::FieldOutOfBounds => {
                    ConformanceTrustPolicyContractErrorV1::FieldOutOfBounds
                }
            },
        )?;
        let value: Value = ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| ConformanceTrustPolicyContractErrorV1::InvalidEncoding)?;
        let policy = decode_policy(value)?;
        if policy.to_canonical_cbor()? == bytes {
            Ok(policy)
        } else {
            Err(ConformanceTrustPolicyContractErrorV1::InvalidEncoding)
        }
    }

    /// Write the first `fields` fields as one canonical array.
    fn encode_into(&self, out: &mut Vec<u8>, fields: u8) {
        head(out, 4, u64::from(fields));
        text(out, CONFORMANCE_TRUST_POLICY_MAGIC_V1);
        head(out, 0, 1);
        text(out, &self.policy_id);
        head(out, 0, self.epoch);
        out.extend(self.previous_policy_digest.map_or_else(
            || vec![0xf6],
            |digest| {
                let mut item = Vec::new();
                byte_string(&mut item, &digest);
                item
            },
        ));
        byte_string(out, &self.trust_policy_snapshot_digest);
        for list in [
            &self.evaluator_release_roots,
            &self.report_signing_roots,
            &self.revoked_key_ids,
            &self.revoked_evaluator_binary_digests,
            &self.revoked_report_digests,
        ] {
            head(out, 4, list.len() as u64);
            for value in list {
                byte_string(out, value);
            }
        }
        text(out, &self.minimum_evaluator_protocol_version);
        text(out, &self.offline_valid_through);
        if fields == FIELD_COUNT {
            byte_string(out, &self.operator_signature);
        }
    }
}

/// Write one shortest-form CBOR head.
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let be = value.to_be_bytes();
    let (additional, width) = match value {
        0..=23 => (be[7], 0),
        24..=0xff => (24, 1),
        0x100..=0xffff => (25, 2),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    out.push((major << 5) | additional);
    out.extend_from_slice(&be[8 - width..]);
}

fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn byte_string(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

fn decode_policy(
    value: Value,
) -> Result<ConformanceTrustPolicyV1, ConformanceTrustPolicyContractErrorV1> {
    let fields: [Value; FIELD_COUNT as usize] = into_array(value)?
        .try_into()
        .map_err(|_| ConformanceTrustPolicyContractErrorV1::InvalidEncoding)?;
    let [magic, version, policy_id, epoch, previous, rest @ ..] = fields;
    let [snapshot, evaluator_roots, report_roots, revoked_keys, rest @ ..] = rest;
    let [revoked_binaries, revoked_reports, minimum_version, valid_through, signature] = rest;
    if into_text(magic)? != CONFORMANCE_TRUST_POLICY_MAGIC_V1 || into_uint(version)? != 1 {
        return Err(ConformanceTrustPolicyContractErrorV1::UnsupportedSchemaVersion);
    }
    Ok(ConformanceTrustPolicyV1 {
        policy_id: into_text(policy_id)?,
        epoch: into_uint(epoch)?,
        previous_policy_digest: match previous {
            Value::Null => None,
            digest => Some(into_fixed(digest)?),
        },
        trust_policy_snapshot_digest: into_fixed(snapshot)?,
        evaluator_release_roots: into_digests(evaluator_roots)?,
        report_signing_roots: into_digests(report_roots)?,
        revoked_key_ids: into_digests(revoked_keys)?,
        revoked_evaluator_binary_digests: into_digests(revoked_binaries)?,
        revoked_report_digests: into_digests(revoked_reports)?,
        minimum_evaluator_protocol_version: into_text(minimum_version)?,
        offline_valid_through: into_text(valid_through)?,
        operator_signature: into_fixed(signature)?,
    })
}

fn into_array(value: Value) -> Result<Vec<Value>, ConformanceTrustPolicyContractErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(ConformanceTrustPolicyContractErrorV1::InvalidEncoding),
    }
}

fn into_text(value: Value) -> Result<String, ConformanceTrustPolicyContractErrorV1> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(ConformanceTrustPolicyContractErrorV1::InvalidEncoding),
    }
}

fn into_uint(value: Value) -> Result<u64, ConformanceTrustPolicyContractErrorV1> {
    match value {
        Value::Integer(integer) => u64::try_from(integer)
            .map_err(|_| ConformanceTrustPolicyContractErrorV1::InvalidEncoding),
        _ => Err(ConformanceTrustPolicyContractErrorV1::InvalidEncoding),
    }
}

fn into_fixed<const N: usize>(
    value: Value,
) -> Result<[u8; N], ConformanceTrustPolicyContractErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .try_into()
            .map_err(|_| ConformanceTrustPolicyContractErrorV1::InvalidEncoding),
        _ => Err(ConformanceTrustPolicyContractErrorV1::InvalidEncoding),
    }
}

fn into_digests(value: Value) -> Result<Vec<[u8; 32]>, ConformanceTrustPolicyContractErrorV1> {
    into_array(value)?.into_iter().map(into_fixed).collect()
}
