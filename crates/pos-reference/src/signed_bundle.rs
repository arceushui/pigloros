//! Independent CFB1 closure and signature validation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;

use ciborium::value::Value;
use ciborium_ll::{Decoder, Header};
use ed25519_dalek::Verifier;

use crate::evaluator_protocol::{
    array, array_values, decode_canonical, decode_canonical_with_limit, encode, fixed_bytes,
    preflight_cbor, text, uint, EvaluationRequest, ProtocolError,
};

const MAX_ARCHIVE_BYTES: usize = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_MEMBER_BYTES: usize = 64 * 1024 * 1024;
const MAX_MEMBERS: usize = 65_536;
const MAX_PATH_BYTES: usize = 256;
const PROFILE_PATH: &str = "profile/CPF1.cbor";
const TRUST_POLICY_PATH: &str = "authority/trust-policy-snapshot.tps1";

trait ArchiveReader: Read + Seek {}

impl<T: Read + Seek> ArchiveReader for T {}

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
    #[error("archive contains prohibited secret material")]
    ProhibitedMaterial,
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
    pub(crate) authority_key_id: String,
    pub(crate) authority_verifying_key: ed25519_dalek::VerifyingKey,
}

/// Selected archive limits authenticated by the requested CPF1 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedBundleCaps {
    pub max_profile_bytes: u64,
    pub max_bundle_members: u64,
    pub max_member_path_bytes: u64,
    pub max_member_bytes: u64,
    pub max_total_bundle_bytes: u64,
}

/// Authenticated CFB1 metadata inspected without retaining member bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedBundlePreflight {
    profile_bytes: Vec<u8>,
    member_count: u64,
    maximum_path_bytes: u64,
    maximum_member_bytes: u64,
    total_member_bytes: u64,
}

impl AuthenticatedBundlePreflight {
    /// Return the digest-checked CPF1 member selected by the signed manifest.
    #[must_use]
    pub fn profile_bytes(&self) -> &[u8] {
        &self.profile_bytes
    }

    /// Apply authenticated CPF1 archive limits before any archive-wide allocation.
    ///
    /// # Errors
    /// Returns a bound failure when the indexed closure exceeds a selected cap.
    pub const fn enforce_selected_caps(&self, caps: SelectedBundleCaps) -> Result<(), BundleError> {
        if self.profile_bytes.len() as u64 > caps.max_profile_bytes
            || self.member_count > caps.max_bundle_members
            || self.maximum_path_bytes > caps.max_member_path_bytes
            || self.maximum_member_bytes > caps.max_member_bytes
            || self.total_member_bytes > caps.max_total_bundle_bytes
        {
            Err(BundleError::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }
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

#[derive(Clone)]
struct TrustRoot {
    key_id: String,
    public_key: [u8; 32],
}

struct TrustPolicy {
    roots: Vec<TrustRoot>,
    revoked_key_ids: BTreeSet<String>,
    revoked_artifact_digests: BTreeSet<[u8; 32]>,
}

struct DecodedArchive {
    mode: u8,
    profile_digest: [u8; 32],
    descriptors: Vec<Descriptor>,
    expected: Vec<ExpectedResult>,
    members: BTreeMap<String, VerifiedMember>,
    signer_key: [u8; 32],
    signature: [u8; 64],
    manifest_bytes: Vec<u8>,
}

struct DecodedManifest {
    mode: u8,
    profile_digest: [u8; 32],
    descriptors: Vec<Descriptor>,
    expected: Vec<ExpectedResult>,
    manifest_bytes: Vec<u8>,
}

struct ScannedMember {
    path: String,
    size: u64,
    role: u8,
}

struct ScannedArchive {
    manifest_range: Range<usize>,
    members: Vec<ScannedMember>,
    profile_bytes: Vec<u8>,
    signer_key: [u8; 32],
    signature: [u8; 64],
}

impl TrustPolicy {
    fn authority_for(&self, public_key: [u8; 32]) -> Option<&TrustRoot> {
        self.roots.iter().find(|root| {
            root.public_key == public_key && !self.revoked_key_ids.contains(&root.key_id)
        })
    }

    fn artifact_is_revoked(&self, digest: &[u8; 32]) -> bool {
        self.revoked_artifact_digests.contains(digest)
    }
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
    let (trust_policy, archive_digest) =
        validate_requested_artifacts(archive_bytes, trust_policy_bytes, request)?;
    let decoded = decode_archive(archive_bytes, request)?;
    validate_archive_closure(&decoded, &trust_policy)?;
    let (authority, authority_verifying_key) = verify_archive_signature(&decoded, &trust_policy)?;
    if decoded
        .members
        .values()
        .any(|member| prohibited_secret_material(&member.bytes))
    {
        return Err(BundleError::ProhibitedMaterial);
    }
    let expected_results = decoded
        .expected
        .into_iter()
        .map(|result| (result.key, result.path))
        .collect();
    Ok(VerifiedBundle {
        mode: decoded.mode,
        profile_digest: decoded.profile_digest,
        archive_digest,
        members: decoded.members,
        expected_results,
        authority_key_id: authority.key_id,
        authority_verifying_key,
    })
}

/// Authenticate and measure a seekable CFB1 archive without retaining its member bodies.
///
/// # Errors
/// Returns a closed failure when the archive identity, canonical structure, signed manifest,
/// trust policy, closure metadata, or authenticated CPF1 member is invalid.
pub fn preflight_signed_bundle<R: Read + Seek>(
    archive: &mut R,
    trust_policy_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<AuthenticatedBundlePreflight, BundleError> {
    preflight_archive(archive, trust_policy_bytes, request)
}

fn preflight_archive(
    archive: &mut dyn ArchiveReader,
    trust_policy_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<AuthenticatedBundlePreflight, BundleError> {
    let archive_length = bounded_archive_digest(archive, request.fixture_bundle_digest)?;
    let scanned = scan_archive(archive, archive_length)?;
    let manifest_bytes = read_range(archive, scanned.manifest_range.clone())?;
    let manifest = decode_manifest_bytes(manifest_bytes, request)?;
    let trust_policy = verified_trust_policy(trust_policy_bytes, request)?;
    verify_signature(
        &manifest.manifest_bytes,
        scanned.signer_key,
        scanned.signature,
        &trust_policy,
    )?;
    validate_scanned_closure(
        &manifest,
        &scanned.members,
        &scanned.profile_bytes,
        &trust_policy,
    )?;
    let member_count = scanned.members.len() as u64;
    let maximum_path_bytes = scanned
        .members
        .iter()
        .map(|member| member.path.len() as u64)
        .fold(0_u64, u64::max);
    let maximum_member_bytes = scanned
        .members
        .iter()
        .map(|member| member.size)
        .fold(0_u64, u64::max);
    let total_member_bytes = scanned.members.iter().map(|member| member.size).sum();
    Ok(AuthenticatedBundlePreflight {
        profile_bytes: scanned.profile_bytes,
        member_count,
        maximum_path_bytes,
        maximum_member_bytes,
        total_member_bytes,
    })
}

fn bounded_archive_digest<R: Read + Seek + ?Sized>(
    archive: &mut R,
    expected: [u8; 32],
) -> Result<u64, BundleError> {
    let length = archive
        .seek(SeekFrom::End(0))
        .map_err(|_| BundleError::InvalidEncoding)?;
    if length == 0 || length > MAX_ARCHIVE_BYTES as u64 {
        return Err(BundleError::FieldOutOfBounds);
    }
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| BundleError::InvalidEncoding)?;
    let mut hasher = blake3::Hasher::new();
    let copied = std::io::copy(&mut (&mut *archive).take(length), &mut hasher)
        .map_err(|_| BundleError::InvalidEncoding)?;
    if copied != length || *hasher.finalize().as_bytes() != expected {
        return Err(BundleError::DigestMismatch);
    }
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| BundleError::InvalidEncoding)?;
    Ok(length)
}

fn scan_archive<R: Read + Seek + ?Sized>(
    archive: &mut R,
    archive_length: u64,
) -> Result<ScannedArchive, BundleError> {
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| BundleError::InvalidEncoding)?;
    let mut decoder = Decoder::from(&mut *archive);
    expect_array(&mut decoder, 4)?;
    let manifest_start = decoder.offset();
    skip_cbor_value(&mut decoder, 0)?;
    let manifest_end = decoder.offset();
    if manifest_end.saturating_sub(manifest_start) > MAX_MANIFEST_BYTES {
        return Err(BundleError::FieldOutOfBounds);
    }
    let (members, profile_bytes) = scan_members(&mut decoder)?;
    let signer_key = read_fixed_bytes(&mut decoder)?;
    let signature = read_fixed_bytes(&mut decoder)?;
    if decoder.offset() as u64 != archive_length {
        return Err(BundleError::InvalidEncoding);
    }
    Ok(ScannedArchive {
        manifest_range: manifest_start..manifest_end,
        members,
        profile_bytes: profile_bytes.ok_or(BundleError::ClosureIncomplete)?,
        signer_key,
        signature,
    })
}

fn scan_members<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
) -> Result<(Vec<ScannedMember>, Option<Vec<u8>>), BundleError> {
    let count = array_length(decoder)?;
    if count == 0 || count > MAX_MEMBERS {
        return Err(BundleError::FieldOutOfBounds);
    }
    let mut members = Vec::with_capacity(count);
    let mut profile_bytes = None;
    for _ in 0..count {
        expect_array(decoder, 3)?;
        let path = validated_path(&read_text(decoder, MAX_PATH_BYTES)?)?;
        if members
            .last()
            .is_some_and(|member: &ScannedMember| member.path.as_bytes() >= path.as_bytes())
        {
            return Err(BundleError::NonCanonicalOrder);
        }
        let size = bytes_length(decoder)?;
        if size > MAX_MEMBER_BYTES {
            return Err(BundleError::FieldOutOfBounds);
        }
        let bytes = if path == PROFILE_PATH {
            Some(read_bytes(decoder, size, MAX_MEMBER_BYTES)?)
        } else {
            drain_bytes(decoder, size)?;
            None
        };
        let role = positive(decoder)?;
        let role = u8::try_from(role).map_err(|_| BundleError::InvalidEncoding)?;
        if role > 19 {
            return Err(BundleError::FieldOutOfBounds);
        }
        if let Some(bytes) = bytes {
            profile_bytes = Some(bytes);
        }
        members.push(ScannedMember {
            path,
            size: size as u64,
            role,
        });
    }
    Ok((members, profile_bytes))
}

fn skip_cbor_value<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
    depth: usize,
) -> Result<(), BundleError> {
    if depth > 32 {
        return Err(BundleError::FieldOutOfBounds);
    }
    match decoder.pull().map_err(|_| BundleError::InvalidEncoding)? {
        Header::Positive(_) | Header::Simple(20..=22) => Ok(()),
        Header::Bytes(Some(length)) => drain_bytes(decoder, length),
        Header::Text(Some(length)) => drain_text(decoder, length),
        Header::Array(Some(length)) if length <= MAX_MEMBERS => {
            (0..length).try_for_each(|_| skip_cbor_value(decoder, depth + 1))
        }
        Header::Array(Some(_)) => Err(BundleError::FieldOutOfBounds),
        _ => Err(BundleError::InvalidEncoding),
    }
}

fn expect_array<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
    expected: usize,
) -> Result<(), BundleError> {
    if decoder.pull().map_err(|_| BundleError::InvalidEncoding)? == Header::Array(Some(expected)) {
        Ok(())
    } else {
        Err(BundleError::InvalidEncoding)
    }
}

fn array_length<R: Read + ?Sized>(decoder: &mut Decoder<&mut R>) -> Result<usize, BundleError> {
    match decoder.pull().map_err(|_| BundleError::InvalidEncoding)? {
        Header::Array(Some(length)) => Ok(length),
        _ => Err(BundleError::InvalidEncoding),
    }
}

fn bytes_length<R: Read + ?Sized>(decoder: &mut Decoder<&mut R>) -> Result<usize, BundleError> {
    match decoder.pull().map_err(|_| BundleError::InvalidEncoding)? {
        Header::Bytes(Some(length)) => Ok(length),
        _ => Err(BundleError::InvalidEncoding),
    }
}

fn positive<R: Read + ?Sized>(decoder: &mut Decoder<&mut R>) -> Result<u64, BundleError> {
    match decoder.pull().map_err(|_| BundleError::InvalidEncoding)? {
        Header::Positive(value) => Ok(value),
        _ => Err(BundleError::InvalidEncoding),
    }
}

fn read_fixed_bytes<const N: usize, R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
) -> Result<[u8; N], BundleError> {
    let length = bytes_length(decoder)?;
    let bytes = read_bytes(decoder, length, N)?;
    bytes.try_into().map_err(|_| BundleError::InvalidEncoding)
}

fn read_text<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
    maximum: usize,
) -> Result<String, BundleError> {
    let length = match decoder.pull().map_err(|_| BundleError::InvalidEncoding)? {
        Header::Text(Some(length)) if length <= maximum => length,
        Header::Text(Some(_)) => return Err(BundleError::FieldOutOfBounds),
        _ => return Err(BundleError::InvalidEncoding),
    };
    let mut output = String::with_capacity(length);
    let mut segments = decoder.text(Some(length));
    while let Some(mut segment) = segments.pull().map_err(|_| BundleError::InvalidEncoding)? {
        let mut buffer = [0_u8; 256];
        while let Some(chunk) = segment
            .pull(&mut buffer)
            .map_err(|_| BundleError::InvalidEncoding)?
        {
            output.push_str(chunk);
        }
    }
    Ok(output)
}

fn read_bytes<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, BundleError> {
    if length > maximum {
        return Err(BundleError::FieldOutOfBounds);
    }
    let mut output = Vec::with_capacity(length);
    let mut segments = decoder.bytes(Some(length));
    while let Some(mut segment) = segments.pull().map_err(|_| BundleError::InvalidEncoding)? {
        let mut buffer = [0_u8; 8192];
        while let Some(chunk) = segment
            .pull(&mut buffer)
            .map_err(|_| BundleError::InvalidEncoding)?
        {
            output.extend_from_slice(chunk);
        }
    }
    Ok(output)
}

fn drain_bytes<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
    length: usize,
) -> Result<(), BundleError> {
    let mut segments = decoder.bytes(Some(length));
    while let Some(mut segment) = segments.pull().map_err(|_| BundleError::InvalidEncoding)? {
        let mut buffer = [0_u8; 8192];
        while segment
            .pull(&mut buffer)
            .map_err(|_| BundleError::InvalidEncoding)?
            .is_some()
        {}
    }
    Ok(())
}

fn drain_text<R: Read + ?Sized>(
    decoder: &mut Decoder<&mut R>,
    length: usize,
) -> Result<(), BundleError> {
    let mut segments = decoder.text(Some(length));
    while let Some(mut segment) = segments.pull().map_err(|_| BundleError::InvalidEncoding)? {
        let mut buffer = [0_u8; 8192];
        while segment
            .pull(&mut buffer)
            .map_err(|_| BundleError::InvalidEncoding)?
            .is_some()
        {}
    }
    Ok(())
}

fn read_range<R: Read + Seek + ?Sized>(
    archive: &mut R,
    range: Range<usize>,
) -> Result<Vec<u8>, BundleError> {
    let length = range.end - range.start;
    archive
        .seek(SeekFrom::Start(range.start as u64))
        .map_err(|_| BundleError::InvalidEncoding)?;
    let mut bytes = vec![0_u8; length];
    archive
        .read_exact(&mut bytes)
        .map_err(|_| BundleError::InvalidEncoding)?;
    Ok(bytes)
}

fn verified_trust_policy(
    trust_policy_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<TrustPolicy, BundleError> {
    if *blake3::hash(trust_policy_bytes).as_bytes() != request.trust_policy_snapshot_digest {
        return Err(BundleError::TrustPolicyMismatch);
    }
    decode_trust_policy(trust_policy_bytes)
}

fn validate_scanned_closure(
    manifest: &DecodedManifest,
    members: &[ScannedMember],
    profile_bytes: &[u8],
    trust_policy: &TrustPolicy,
) -> Result<(), BundleError> {
    if manifest.descriptors.len() != members.len() {
        return Err(BundleError::ClosureIncomplete);
    }
    for (descriptor, member) in manifest.descriptors.iter().zip(members) {
        if descriptor.path != member.path
            || descriptor.size != member.size
            || descriptor.role != member.role
        {
            return Err(BundleError::DigestMismatch);
        }
        if descriptor.path == PROFILE_PATH
            && (profile_bytes.len() as u64 != descriptor.size
                || *blake3::hash(profile_bytes).as_bytes() != descriptor.digest)
        {
            return Err(BundleError::DigestMismatch);
        }
        if trust_policy.artifact_is_revoked(&descriptor.digest) {
            return Err(BundleError::TrustPolicyMismatch);
        }
    }
    for expected in &manifest.expected {
        let descriptor = manifest
            .descriptors
            .iter()
            .find(|descriptor| descriptor.path == expected.path)
            .ok_or(BundleError::ClosureIncomplete)?;
        if descriptor.digest != expected.digest {
            return Err(BundleError::DigestMismatch);
        }
    }
    Ok(())
}

fn validate_requested_artifacts(
    archive_bytes: &[u8],
    trust_policy_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<(TrustPolicy, [u8; 32]), BundleError> {
    if archive_bytes.is_empty() || archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(BundleError::FieldOutOfBounds);
    }
    let trust_digest = *blake3::hash(trust_policy_bytes).as_bytes();
    if trust_digest != request.trust_policy_snapshot_digest {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let trust_policy = decode_trust_policy(trust_policy_bytes)?;
    let archive_digest = *blake3::hash(archive_bytes).as_bytes();
    if archive_digest != request.fixture_bundle_digest {
        return Err(BundleError::DigestMismatch);
    }
    Ok((trust_policy, archive_digest))
}

fn decode_archive(
    archive_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<DecodedArchive, BundleError> {
    let root = decode_canonical_with_limit(archive_bytes, MAX_ARCHIVE_BYTES)?;
    let [manifest_value, members_value, signer_key_value, signature_value] = into_array::<4>(root)?;
    let manifest_bytes = encode(&manifest_value)?;
    let manifest = decode_manifest_value(manifest_value, manifest_bytes, request)?;
    Ok(DecodedArchive {
        mode: manifest.mode,
        profile_digest: manifest.profile_digest,
        descriptors: manifest.descriptors,
        expected: manifest.expected,
        members: decode_members(members_value)?,
        signer_key: fixed_bytes(&signer_key_value)?,
        signature: fixed_bytes(&signature_value)?,
        manifest_bytes: manifest.manifest_bytes,
    })
}

fn decode_manifest_bytes(
    manifest_bytes: Vec<u8>,
    request: &EvaluationRequest,
) -> Result<DecodedManifest, BundleError> {
    let value = decode_canonical_with_limit(&manifest_bytes, MAX_MANIFEST_BYTES)?;
    decode_manifest_value(value, manifest_bytes, request)
}

fn decode_manifest_value(
    manifest_value: Value,
    manifest_bytes: Vec<u8>,
    request: &EvaluationRequest,
) -> Result<DecodedManifest, BundleError> {
    let [magic, version, mode, profile, descriptors, expected] = into_array::<6>(manifest_value)?;
    if text(&magic)? != "CFB1" || uint(&version)? != 0 {
        return Err(BundleError::InvalidEncoding);
    }
    let mode = u8::try_from(uint(&mode)?).map_err(|_| BundleError::InvalidEncoding)?;
    if mode > 1 {
        return Err(BundleError::InvalidEncoding);
    }
    let profile_digest = fixed_bytes(&profile)?;
    if profile_digest != request.profile_digest {
        return Err(BundleError::DigestMismatch);
    }
    Ok(DecodedManifest {
        mode,
        profile_digest,
        descriptors: decode_descriptors(descriptors)?,
        expected: decode_expected_results(expected)?,
        manifest_bytes,
    })
}

fn into_array<const WIDTH: usize>(value: Value) -> Result<[Value; WIDTH], BundleError> {
    match value {
        Value::Array(values) => values.try_into().map_err(|_| BundleError::InvalidEncoding),
        _ => Err(BundleError::InvalidEncoding),
    }
}

fn validate_archive_closure(
    archive: &DecodedArchive,
    trust_policy: &TrustPolicy,
) -> Result<(), BundleError> {
    validate_closure(&archive.descriptors, &archive.members, &archive.expected)?;
    if trust_policy.artifact_is_revoked(&archive.profile_digest)
        || archive
            .members
            .values()
            .any(|member| trust_policy.artifact_is_revoked(&member.digest))
    {
        Err(BundleError::TrustPolicyMismatch)
    } else {
        Ok(())
    }
}

fn verify_archive_signature(
    archive: &DecodedArchive,
    trust_policy: &TrustPolicy,
) -> Result<(TrustRoot, ed25519_dalek::VerifyingKey), BundleError> {
    verify_signature(
        &archive.manifest_bytes,
        archive.signer_key,
        archive.signature,
        trust_policy,
    )
}

fn verify_signature(
    manifest_bytes: &[u8],
    signer_key: [u8; 32],
    signature: [u8; 64],
    trust_policy: &TrustPolicy,
) -> Result<(TrustRoot, ed25519_dalek::VerifyingKey), BundleError> {
    let trusted_authority = trust_policy
        .authority_for(signer_key)
        .ok_or(BundleError::SignatureInvalid)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&signer_key)
        .map_err(|_| BundleError::SignatureInvalid)?;
    key.verify(
        manifest_bytes,
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| BundleError::SignatureInvalid)?;
    Ok((trusted_authority.clone(), key))
}

fn sensitive_name(value: &str) -> bool {
    matches!(
        value,
        "api_key"
            | "apikey"
            | "password"
            | "credential"
            | "credentials"
            | "access_token"
            | "refresh_token"
            | "authorization"
            | "bearer_token"
            | "client_secret"
            | "subject_secret"
            | "private_key"
            | "privatekey"
            | "secret"
            | "token"
    )
}

fn sensitive_key(value: &str) -> (bool, bool) {
    let normalized = value.to_ascii_lowercase().replace('-', "_");
    normalized.strip_suffix("_digest").map_or_else(
        || (sensitive_name(&normalized), false),
        |name| (sensitive_name(name), true),
    )
}

fn json_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            let (sensitive, digest) = sensitive_key(key);
            (sensitive && (digest || !value.is_null() && value.as_str() != Some("")))
                || json_secret(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(json_secret),
        _ => false,
    }
}

const fn cbor_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Text(text) => text.is_empty(),
        Value::Bytes(bytes) => bytes.is_empty(),
        _ => false,
    }
}

fn cbor_secret(value: &Value) -> bool {
    match value {
        Value::Map(fields) => fields.iter().any(|(key, value)| {
            let sensitive = key.as_text().map(sensitive_key);
            sensitive.is_some_and(|(sensitive, digest)| sensitive && (digest || !cbor_empty(value)))
                || cbor_secret(value)
        }),
        Value::Array(values) => values.iter().any(cbor_secret),
        Value::Tag(_, value) => cbor_secret(value),
        _ => false,
    }
}

fn prohibited_secret_material(bytes: &[u8]) -> bool {
    const TOKEN_PREFIXES: &[(&str, usize)] = &[
        ("bearer ", 16),
        ("basic ", 16),
        ("akia", 16),
        ("asia", 16),
        ("ghp_", 16),
        ("gho_", 16),
        ("ghu_", 16),
        ("ghs_", 16),
        ("ghr_", 16),
        ("github_pat_", 16),
        ("glpat-", 16),
        ("xoxb-", 16),
        ("xoxa-", 16),
        ("xoxp-", 16),
        ("xoxr-", 16),
        ("xoxs-", 16),
        ("sk_live_", 16),
        ("sk_test_", 16),
        ("aiza", 16),
        ("eyj", 20),
    ];
    if serde_json::from_slice(bytes).is_ok_and(|value| json_secret(&value)) {
        return true;
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let cbor = preflight_cbor(bytes, bytes.len(), true)
        .and_then(|()| {
            ciborium::from_reader::<Value, _>(&mut cursor)
                .map_err(|_| ProtocolError::InvalidEncoding)
        })
        .ok();
    if cursor.position() == bytes.len() as u64 && cbor.is_some_and(|value| cbor_secret(&value)) {
        return true;
    }
    let lowercase = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let text = String::from_utf8_lossy(&lowercase);
    if text.contains("-----begin") && text.contains("private key-----") {
        return true;
    }
    TOKEN_PREFIXES.iter().any(|(prefix, minimum)| {
        text.match_indices(prefix).any(|(offset, _)| {
            text[offset + prefix.len()..]
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || b"._~+/=-".contains(byte))
                .take(*minimum)
                .count()
                == *minimum
        })
    })
}

fn decode_trust_policy(bytes: &[u8]) -> Result<TrustPolicy, BundleError> {
    let value = decode_canonical(bytes)?;
    let fields = array(&value, 12)?;
    if text(&fields[0])? != "TPS1" || uint(&fields[1])? != 1 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    if !valid_identifier(text(&fields[2])?) || uint(&fields[3])? == 0 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    uint(&fields[4])?;
    let roots = decode_trust_roots(&fields[5])?;
    let revoked_key_ids = decode_revoked_key_ids(&fields[6])?;
    let revoked_artifact_digests = decode_revoked_artifact_digests(&fields[7])?;
    validate_nullable_digest(&fields[10])?;
    if !valid_minimum_versions(&fields[8])? || !valid_expiry(text(&fields[9])?) {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let signature: [u8; 64] = fixed_bytes(&fields[11])?;
    let unsigned = encode(&Value::Array(fields[..11].to_vec()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    let signed_by_active_root = roots.iter().any(|root| {
        !revoked_key_ids.contains(&root.key_id)
            && ed25519_dalek::VerifyingKey::from_bytes(&root.public_key)
                .is_ok_and(|key| key.verify(&unsigned, &signature).is_ok())
    });
    if !signed_by_active_root {
        return Err(BundleError::TrustPolicyMismatch);
    }
    Ok(TrustPolicy {
        roots,
        revoked_key_ids,
        revoked_artifact_digests,
    })
}

fn decode_trust_roots(value: &Value) -> Result<Vec<TrustRoot>, BundleError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > 64 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let mut roots = Vec::with_capacity(values.len());
    let mut public_keys = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for value in values {
        let fields = array(value, 4)?;
        let key_id = text(&fields[0])?;
        let public_key = fixed_bytes(&fields[3])?;
        if !valid_identifier(key_id)
            || previous.is_some_and(|old| old.as_bytes() >= key_id.as_bytes())
            || uint(&fields[1])? == 0
            || text(&fields[2])? != "Ed25519"
            || !public_keys.insert(public_key)
        {
            return Err(BundleError::TrustPolicyMismatch);
        }
        roots.push(TrustRoot {
            key_id: key_id.to_owned(),
            public_key,
        });
        previous = Some(key_id);
    }
    Ok(roots)
}

fn decode_revoked_key_ids(value: &Value) -> Result<BTreeSet<String>, BundleError> {
    let values = array_values(value)?;
    if values.len() > 4_096 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let mut ids = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for value in values {
        let key_id = text(value)?;
        if !valid_identifier(key_id)
            || previous.is_some_and(|old| old.as_bytes() >= key_id.as_bytes())
        {
            return Err(BundleError::TrustPolicyMismatch);
        }
        ids.insert(key_id.to_owned());
        previous = Some(key_id);
    }
    Ok(ids)
}

fn decode_revoked_artifact_digests(value: &Value) -> Result<BTreeSet<[u8; 32]>, BundleError> {
    let values = array_values(value)?;
    if values.len() > 4_096 {
        return Err(BundleError::TrustPolicyMismatch);
    }
    let mut digests = BTreeSet::new();
    let mut previous: Option<[u8; 32]> = None;
    for value in values {
        let digest = fixed_bytes(value)?;
        if previous.is_some_and(|old| old >= digest) {
            return Err(BundleError::TrustPolicyMismatch);
        }
        digests.insert(digest);
        previous = Some(digest);
    }
    Ok(digests)
}

fn validate_nullable_digest(value: &Value) -> Result<(), BundleError> {
    match value {
        Value::Null => Ok(()),
        _ => fixed_bytes::<32>(value).map(|_| ()).map_err(Into::into),
    }
}

fn valid_minimum_versions(value: &Value) -> Result<bool, BundleError> {
    let values = array_values(value)?;
    if values.len() > 256 {
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
        && value.len() <= 64
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

fn decode_descriptors(value: Value) -> Result<Vec<Descriptor>, BundleError> {
    let Value::Array(values) = value else {
        return Err(BundleError::InvalidEncoding);
    };
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
    if descriptors
        .windows(2)
        .any(|pair| pair[0].path.as_bytes() >= pair[1].path.as_bytes())
    {
        return Err(BundleError::NonCanonicalOrder);
    }
    Ok(descriptors)
}

fn decode_members(value: Value) -> Result<BTreeMap<String, VerifiedMember>, BundleError> {
    let Value::Array(values) = value else {
        return Err(BundleError::InvalidEncoding);
    };
    if values.is_empty() || values.len() > MAX_MEMBERS {
        return Err(BundleError::FieldOutOfBounds);
    }
    let mut members = BTreeMap::new();
    let mut total = 0_usize;
    let mut previous_path: Option<String> = None;
    for value in values {
        let [path_value, raw_value, role_value] = into_array::<3>(value)?;
        let Value::Text(path_value) = path_value else {
            return Err(BundleError::InvalidEncoding);
        };
        let path = validated_path(&path_value)?;
        if previous_path
            .as_ref()
            .is_some_and(|previous| previous.as_bytes() >= path.as_bytes())
        {
            return Err(BundleError::NonCanonicalOrder);
        }
        let Value::Bytes(raw) = raw_value else {
            return Err(BundleError::InvalidEncoding);
        };
        let role = u8::try_from(uint(&role_value)?).map_err(|_| BundleError::InvalidEncoding)?;
        total += raw.len();
        if raw.len() > MAX_MEMBER_BYTES || total > MAX_ARCHIVE_BYTES || role > 19 {
            return Err(BundleError::FieldOutOfBounds);
        }
        let member = VerifiedMember {
            role,
            digest: *blake3::hash(&raw).as_bytes(),
            bytes: raw,
        };
        previous_path = Some(path.clone());
        members.insert(path, member);
    }
    Ok(members)
}

fn decode_expected_results(value: Value) -> Result<Vec<ExpectedResult>, BundleError> {
    let Value::Array(values) = value else {
        return Err(BundleError::InvalidEncoding);
    };
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
        if descriptor.size != member.bytes.len() as u64
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
