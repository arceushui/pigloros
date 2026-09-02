//! Independent CFB1 closure and signature validation.

use std::collections::BTreeMap;

use ciborium::value::Value;
use ed25519_dalek::Verifier;

use crate::evaluator_protocol::{
    array, array_values, decode_canonical, decode_canonical_with_limit, encode, fixed_bytes, text,
    uint, EvaluationRequest, ProtocolError,
};

const MAX_ARCHIVE_BYTES: usize = 1024 * 1024 * 1024;
const MAX_MEMBER_BYTES: usize = 64 * 1024 * 1024;
const MAX_MEMBERS: usize = 65_536;
const MAX_PATH_BYTES: usize = 256;
const PROFILE_PATH: &str = "profile/CPF1.cbor";
const TRUST_POLICY_PATH: &str = "authority/trust-policy-snapshot.tps1";

/// CFB1 verification failures that remain safe to expose to an operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BundleError {
    #[error("archive encoding is invalid")]
    InvalidEncoding,
    #[error("archive or member exceeds its bound")]
    FieldOutOfBounds,
    #[error("archive records are not in canonical order")]
    NonCanonicalOrder,
    #[error("archive closure is incomplete")]
    ClosureIncomplete,
    #[error("archive member digest is invalid")]
    DigestMismatch,
    #[error("archive signature is invalid")]
    SignatureInvalid,
    #[error("trusted policy does not match the request")]
    TrustPolicyMismatch,
}

impl From<ProtocolError> for BundleError {
    fn from(value: ProtocolError) -> Self {
        match value {
            ProtocolError::FieldOutOfBounds => Self::FieldOutOfBounds,
            ProtocolError::NonCanonicalOrder => Self::NonCanonicalOrder,
            ProtocolError::DigestMismatch => Self::DigestMismatch,
            ProtocolError::InvalidEncoding | ProtocolError::UnsupportedVersion => {
                Self::InvalidEncoding
            }
        }
    }
}

/// A verified immutable member. Bytes are exposed read-only after closure and
/// signature validation have completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMember {
    pub role: u8,
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
}

/// An expected result selected by case, claim layer, execution profile, and
/// execution mode.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedResultKey {
    pub case_id: String,
    pub claim_layer: u8,
    pub execution_profile_digest: [u8; 32],
    pub mode: u8,
}

/// Validated CFB1 content available to the evaluator implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBundle {
    pub mode: u8,
    pub profile_digest: [u8; 32],
    pub archive_digest: [u8; 32],
    pub members: BTreeMap<String, VerifiedMember>,
    pub expected_results: BTreeMap<ExpectedResultKey, String>,
}

impl VerifiedBundle {
    /// Obtain the canonical CPF1 bytes only after complete CFB1 verification.
    #[must_use]
    pub fn profile_bytes(&self) -> &[u8] {
        self.members
            .get(PROFILE_PATH)
            .map_or(&[], |member| member.bytes.as_slice())
    }

    /// Obtain one verified archive member by its canonical path.
    #[must_use]
    pub fn member(&self, path: &str) -> Option<&VerifiedMember> {
        self.members.get(path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Descriptor {
    path: String,
    size: u64,
    digest: [u8; 32],
    role: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedResult {
    key: ExpectedResultKey,
    path: String,
    digest: [u8; 32],
}

/// Verify exact CFB1 bytes against an externally selected, immutable TPS1
/// snapshot and the authority identities carried by EVR1.
///
/// # Errors
/// Returns a closed failure before exposing any member when encoding,
/// signature, trust, closure, ordering, digest, or size validation fails.
pub fn verify_signed_bundle(
    archive_bytes: &[u8],
    trust_policy_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<VerifiedBundle, BundleError> {
    if archive_bytes.is_empty() || archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(BundleError::FieldOutOfBounds);
    }
    let trust_digest = *blake3::hash(trust_policy_bytes).as_bytes();
    if trust_digest != request.trust_policy_snapshot_digest {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let trusted_key = decode_trusted_key(trust_policy_bytes)?;
    let archive_digest = *blake3::hash(archive_bytes).as_bytes();
    if archive_digest != request.fixture_bundle_digest {
        return Err(BundleError::DigestMismatch);
    }

    let root = decode_canonical_with_limit(archive_bytes, MAX_ARCHIVE_BYTES)?;
    let archive = array(&root, 4)?;
    let manifest = array(&archive[0], 6)?;
    if text(&manifest[0])? != "CFB1" || uint(&manifest[1])? != 0 {
        return Err(BundleError::InvalidEncoding);
    }
    let mode = u8::try_from(uint(&manifest[2])?).map_err(|_| BundleError::InvalidEncoding)?;
    if mode > 1 {
        return Err(BundleError::InvalidEncoding);
    }
    let profile_digest = fixed_bytes(&manifest[3])?;
    if profile_digest != request.profile_digest {
        return Err(BundleError::DigestMismatch);
    }

    let descriptors = decode_descriptors(&manifest[4])?;
    let expected = decode_expected_results(&manifest[5])?;
    let members = decode_members(&archive[1])?;
    validate_closure(&descriptors, &members, &expected)?;

    let signer_key: [u8; 32] = fixed_bytes(&archive[2])?;
    let signature: [u8; 64] = fixed_bytes(&archive[3])?;
    if signer_key != trusted_key {
        return Err(BundleError::SignatureInvalid);
    }
    let manifest_bytes = encode(&archive[0])?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&signer_key)
        .map_err(|_| BundleError::SignatureInvalid)?;
    key.verify(
        &manifest_bytes,
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| BundleError::SignatureInvalid)?;

    let expected_results = expected
        .into_iter()
        .map(|result| (result.key, result.path))
        .collect();
    Ok(VerifiedBundle {
        mode,
        profile_digest,
        archive_digest,
        members,
        expected_results,
    })
}

fn decode_trusted_key(bytes: &[u8]) -> Result<[u8; 32], BundleError> {
    let value = decode_canonical(bytes)?;
    let fields = array(&value, 12)?;
    if text(&fields[0])? != "TPS1" || uint(&fields[1])? != 1 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    if !valid_identifier(text(&fields[2])?) || uint(&fields[3])? == 0 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    uint(&fields[4])?;
    let roots = array_values(&fields[5])?;
    if roots.len() != 1
        || !array_values(&fields[6])?.is_empty()
        || !array_values(&fields[7])?.is_empty()
    {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let root = array(&roots[0], 4)?;
    if !valid_identifier(text(&root[0])?)
        || uint(&root[1])? == 0
        || text(&root[2])? != "Ed25519"
        || !valid_minimum_versions(&fields[8])?
        || !valid_expiry(text(&fields[9])?)
        || fields[10] != Value::Null
    {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let key: [u8; 32] = fixed_bytes(&root[3])?;
    let signature: [u8; 64] = fixed_bytes(&fields[11])?;
    let unsigned = encode(&Value::Array(fields[..11].to_vec()))?;
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| BundleError::TrustPolicyMismatch)?;
    verifier
        .verify(&unsigned, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| BundleError::TrustPolicyMismatch)?;
    Ok(key)
}

fn valid_minimum_versions(value: &Value) -> Result<bool, BundleError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > 64 {
        return Ok(false);
    }
    let mut previous: Option<&str> = None;
    for value in values {
        let fields = array(value, 2)?;
        let kind = text(&fields[0])?;
        let version = text(&fields[1])?;
        if !valid_identifier(kind)
            || !valid_semantic_version(version)
            || previous.is_some_and(|old| old.as_bytes() >= kind.as_bytes())
        {
            return Ok(false);
        }
        previous = Some(kind);
    }
    Ok(true)
}

fn valid_expiry(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'.' | b'Z'))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

fn valid_semantic_version(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let (core_pre, build) = match value.split_once('+') {
        Some((left, right)) if !right.is_empty() && !right.contains('+') => (left, right),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, pre) = match core_pre.split_once('-') {
        Some((left, right)) if !right.is_empty() => (left, right),
        Some(_) => return false,
        None => (core_pre, ""),
    };
    let mut parts = core.split('.');
    parts.next().is_some_and(valid_numeric_version)
        && parts.next().is_some_and(valid_numeric_version)
        && parts.next().is_some_and(valid_numeric_version)
        && parts.next().is_none()
        && valid_version_identifiers(pre, true)
        && valid_version_identifiers(build, false)
}

fn valid_numeric_version(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_version_identifiers(value: &str, no_leading_zero: bool) -> bool {
    value.is_empty()
        || value.split('.').all(|item| {
            !item.is_empty()
                && item
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!no_leading_zero
                    || !item.bytes().all(|byte| byte.is_ascii_digit())
                    || valid_numeric_version(item))
        })
}

fn decode_descriptors(value: &Value) -> Result<Vec<Descriptor>, BundleError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > MAX_MEMBERS {
        return Err(BundleError::FieldOutOfBounds);
    }
    let descriptors = values
        .iter()
        .map(|value| {
            let fields = array(value, 4)?;
            let path = validated_path(text(&fields[0])?)?;
            let size = uint(&fields[1])?;
            let digest = fixed_bytes(&fields[2])?;
            let role = u8::try_from(uint(&fields[3])?).map_err(|_| BundleError::InvalidEncoding)?;
            if size > 64 * 1024 * 1024 || role > 19 {
                return Err(BundleError::FieldOutOfBounds);
            }
            Ok(Descriptor {
                path,
                size,
                digest,
                role,
            })
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    if !strictly_ordered(descriptors.iter().map(|value| value.path.as_bytes())) {
        return Err(BundleError::NonCanonicalOrder);
    }
    Ok(descriptors)
}

fn decode_members(value: &Value) -> Result<BTreeMap<String, VerifiedMember>, BundleError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > MAX_MEMBERS {
        return Err(BundleError::FieldOutOfBounds);
    }
    let mut members = BTreeMap::new();
    let mut total = 0_usize;
    for value in values {
        let fields = array(value, 3)?;
        let path = validated_path(text(&fields[0])?)?;
        let raw = match &fields[1] {
            Value::Bytes(bytes) => bytes.clone(),
            _ => return Err(BundleError::InvalidEncoding),
        };
        let role = u8::try_from(uint(&fields[2])?).map_err(|_| BundleError::InvalidEncoding)?;
        total = total
            .checked_add(raw.len())
            .ok_or(BundleError::FieldOutOfBounds)?;
        if raw.len() > MAX_MEMBER_BYTES || total > MAX_ARCHIVE_BYTES || role > 19 {
            return Err(BundleError::FieldOutOfBounds);
        }
        let member = VerifiedMember {
            role,
            digest: *blake3::hash(&raw).as_bytes(),
            bytes: raw,
        };
        if members.insert(path, member).is_some() {
            return Err(BundleError::NonCanonicalOrder);
        }
    }
    if !strictly_ordered(values.iter().map(|value| {
        array(value, 3)
            .and_then(|fields| text(&fields[0]))
            .unwrap_or("")
            .as_bytes()
    })) {
        return Err(BundleError::NonCanonicalOrder);
    }
    Ok(members)
}

fn decode_expected_results(value: &Value) -> Result<Vec<ExpectedResult>, BundleError> {
    let values = array_values(value)?;
    if values.len() > MAX_MEMBERS {
        return Err(BundleError::FieldOutOfBounds);
    }
    let results = values
        .iter()
        .map(|value| {
            let fields = array(value, 6)?;
            let case_id = text(&fields[0])?.to_owned();
            if case_id.is_empty() || case_id.len() > 128 {
                return Err(BundleError::FieldOutOfBounds);
            }
            let claim_layer =
                u8::try_from(uint(&fields[1])?).map_err(|_| BundleError::InvalidEncoding)?;
            let mode = u8::try_from(uint(&fields[3])?).map_err(|_| BundleError::InvalidEncoding)?;
            if claim_layer > 6 || mode > 1 {
                return Err(BundleError::InvalidEncoding);
            }
            Ok(ExpectedResult {
                key: ExpectedResultKey {
                    case_id,
                    claim_layer,
                    execution_profile_digest: fixed_bytes(&fields[2])?,
                    mode,
                },
                path: validated_path(text(&fields[4])?)?,
                digest: fixed_bytes(&fields[5])?,
            })
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    if !results.windows(2).all(|pair| pair[0].key < pair[1].key) {
        return Err(BundleError::NonCanonicalOrder);
    }
    Ok(results)
}

fn validate_closure(
    descriptors: &[Descriptor],
    members: &BTreeMap<String, VerifiedMember>,
    expected: &[ExpectedResult],
) -> Result<(), BundleError> {
    if descriptors.len() != members.len()
        || !members.contains_key(PROFILE_PATH)
        || !members.contains_key(TRUST_POLICY_PATH)
    {
        return Err(BundleError::ClosureIncomplete);
    }
    for descriptor in descriptors {
        let member = members
            .get(&descriptor.path)
            .ok_or(BundleError::ClosureIncomplete)?;
        if descriptor.size
            != u64::try_from(member.bytes.len()).map_err(|_| BundleError::FieldOutOfBounds)?
            || descriptor.digest != member.digest
            || descriptor.role != member.role
        {
            return Err(BundleError::DigestMismatch);
        }
    }
    for result in expected {
        let member = members
            .get(&result.path)
            .ok_or(BundleError::ClosureIncomplete)?;
        if member.digest != result.digest {
            return Err(BundleError::DigestMismatch);
        }
    }
    Ok(())
}

fn validated_path(path: &str) -> Result<String, BundleError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.is_ascii()
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        Err(BundleError::FieldOutOfBounds)
    } else {
        Ok(path.to_owned())
    }
}

fn strictly_ordered<'a>(mut values: impl Iterator<Item = &'a [u8]>) -> bool {
    let Some(mut prior) = values.next() else {
        return true;
    };
    for value in values {
        if prior >= value {
            return false;
        }
        prior = value;
    }
    true
}
