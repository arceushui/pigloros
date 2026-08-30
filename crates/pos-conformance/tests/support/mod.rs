//! Shared public-boundary archive mutation harness for conformance tests.
//!
//! These helpers operate only on canonical bytes emitted by the public
//! materializer and fed back through public decoders/verifiers.  The named
//! fields intentionally document the wire-contract positions exercised by the
//! regression tests without importing a private codec implementation.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{verify_archive_independently, BundleMemberRoleV1, ConformanceBundleV1};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub const PROFILE_MEMBER_PATH: &str = "profile/CPF1.cbor";
pub const ARCHIVE_SIGNING_KEY: [u8; 32] = [7; 32];

#[derive(Clone, Copy)]
pub enum ArchiveField {
    Manifest,
    Members,
    SigningPublicKey,
    Signature,
}

impl ArchiveField {
    /// Returns this field's position in an archive record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Manifest => 0,
            Self::Members => 1,
            Self::SigningPublicKey => 2,
            Self::Signature => 3,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ManifestField {
    ProfileDigest,
    MemberDescriptors,
}

impl ManifestField {
    /// Returns this field's position in a manifest record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::ProfileDigest => 3,
            Self::MemberDescriptors => 4,
        }
    }
}

#[derive(Clone, Copy)]
pub enum MemberField {
    Path,
    Bytes,
    Role,
}

impl MemberField {
    /// Returns this field's position in an archive-member record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Path => 0,
            Self::Bytes => 1,
            Self::Role => 2,
        }
    }
}

#[derive(Clone, Copy)]
pub enum DescriptorField {
    Path,
    Length,
    Digest,
    Role,
}

#[derive(Clone, Copy)]
pub enum ArtifactDescriptorField {
    Path,
    MediaType,
    Length,
    Digest,
}

impl ArtifactDescriptorField {
    /// Returns this field's position in an artifact-descriptor record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Path => 0,
            Self::MediaType => 1,
            Self::Length => 2,
            Self::Digest => 3,
        }
    }
}

impl DescriptorField {
    /// Returns this field's position in a member-descriptor record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Path => 0,
            Self::Length => 1,
            Self::Digest => 2,
            Self::Role => 3,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ProfileField {
    Lifecycle,
    ExecutionMatrixDigest,
    ExecutionProfileDigests,
    ProviderRegistryBinding,
    Fixtures,
    IndependenceRequirements,
    Digest,
}

impl ProfileField {
    /// Returns this field's position in a conformance-profile record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Lifecycle => 4,
            Self::ExecutionMatrixDigest => 6,
            Self::ExecutionProfileDigests => 7,
            Self::ProviderRegistryBinding => 8,
            Self::Fixtures => 9,
            Self::IndependenceRequirements => 12,
            Self::Digest => 17,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ProviderBindingField {
    RegistryDescriptor,
    RequiredProviders,
}

impl ProviderBindingField {
    /// Returns this field's position in a provider-binding record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::RegistryDescriptor => 0,
            Self::RequiredProviders => 1,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ProviderKeyField {
    ProviderId,
}

impl ProviderKeyField {
    /// Returns this field's position in a provider-key record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::ProviderId => 0,
        }
    }
}

#[derive(Clone, Copy)]
pub enum IndependenceRequirementField {
    TrustPolicySnapshotDigest,
}

impl IndependenceRequirementField {
    /// Returns this field's position in an independence-requirement record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::TrustPolicySnapshotDigest => 3,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ReleaseAdmissionField {
    Magic,
    Signature,
}

#[derive(Clone, Copy)]
pub enum RecordField {
    Magic,
}

impl RecordField {
    /// Returns this field's position in a canonical record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Magic => 0,
        }
    }
}

impl ReleaseAdmissionField {
    /// Returns this field's position in a release-admission record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Magic => 0,
            Self::Signature => 10,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FixtureField {
    ProviderKey,
    ExecutionProfileDigest,
    Modes,
    Auxiliary,
    ReleaseAdmissionDigest,
    Digest,
}

impl FixtureField {
    /// Returns this field's position in a fixture record.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::ProviderKey => 4,
            Self::ExecutionProfileDigest => 6,
            Self::Modes => 7,
            Self::Auxiliary => 10,
            Self::ReleaseAdmissionDigest => 20,
            Self::Digest => 23,
        }
    }
}

#[test]
fn shared_named_wire_fields_cover_cross_suite_variants() {
    assert_eq!(ArtifactDescriptorField::MediaType.index(), 1);
    assert_eq!(ProviderBindingField::RegistryDescriptor.index(), 0);
}

pub struct TemporaryOutput(pub PathBuf);

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

/// Returns a unique temporary-root path for a test label.
///
/// # Errors
///
/// Returns an error when the system clock precedes the Unix epoch.
pub fn temporary_root(label: &str) -> TestResult<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("pigloros-{label}-{}-{nonce}", std::process::id())))
}

/// Returns the content address of the checked-in fixture inventory.
#[must_use]
pub fn source_inventory_address() -> String {
    let digest: [u8; 32] = Sha256::digest(include_bytes!(
        "../../../../fixtures/conformance/SHA256SUMS"
    ))
    .into();
    pos_conformance::hex_digest(&digest)
}

/// Lists all files below a published release directory.
///
/// # Errors
///
/// Returns an error when a directory cannot be read.
pub fn release_files(root: &Path) -> TestResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Materializes and returns the current public conformance archive.
///
/// # Errors
///
/// Returns an error when setup, materialization, publication discovery, or archive reading fails.
pub fn current_archive(label: &str) -> TestResult<Vec<u8>> {
    let root = temporary_root(label)?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let publication = root.join(source_inventory_address());
    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let status = Command::new(materializer)
        .current_dir(&root)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg(&publication)
        .status()?;
    if !status.success() {
        return Err("materializer did not publish a public archive".into());
    }
    let archive = release_files(&publication)?
        .into_iter()
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "cfb1")
        })
        .ok_or("materializer did not publish a CFB1 archive")?;
    Ok(fs::read(archive)?)
}

/// Encodes a CBOR value for a public-boundary mutation.
///
/// # Errors
///
/// Returns an error when CBOR serialization fails.
pub fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// Computes the domain-separated digest for canonical contract fields.
///
/// # Errors
///
/// Returns an error when field encoding or length conversion fails.
pub fn contract_digest(domain: &[u8], fields: &[Value]) -> TestResult<[u8; 32]> {
    let bytes = encode_value(&Value::Array(fields.to_vec()))?;
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len() + 9);
    preimage.extend_from_slice(domain);
    preimage.push(0);
    preimage.extend_from_slice(&u64::try_from(bytes.len())?.to_be_bytes());
    preimage.extend_from_slice(&bytes);
    Ok(*blake3::hash(&preimage).as_bytes())
}

/// Returns a mutable CBOR array, identifying it by name in any error.
///
/// # Errors
///
/// Returns an error when the value is not a CBOR array.
pub fn array_mut<'a>(value: &'a mut Value, name: &str) -> TestResult<&'a mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(format!("{name} is not an array").into()),
    }
}

/// Returns a mutable array field, identifying it by name in any error.
///
/// # Errors
///
/// Returns an error when the indexed field is absent or not a CBOR array.
pub fn array_field<'a>(
    fields: &'a mut [Value],
    index: usize,
    name: &str,
) -> TestResult<&'a mut Vec<Value>> {
    match fields.get_mut(index) {
        Some(Value::Array(values)) => Ok(values),
        _ => Err(format!("{name} is not an array").into()),
    }
}

/// Replaces a named field with a CBOR value.
///
/// # Errors
///
/// Returns an error when the indexed field is absent.
pub fn replace_value(fields: &mut [Value], index: usize, value: Value, name: &str) -> TestResult {
    let slot = fields
        .get_mut(index)
        .ok_or_else(|| format!("{name} is absent"))?;
    *slot = value;
    Ok(())
}

/// Returns the bytes of an archive member at a path.
///
/// # Errors
///
/// Returns an error when the archive structure or member bytes are invalid or absent.
pub fn member_bytes(archive: &Value, path: &str) -> TestResult<Vec<u8>> {
    let Value::Array(archive_fields) = archive else {
        return Err("archive is not an array".into());
    };
    let Some(Value::Array(members)) = archive_fields.get(ArchiveField::Members.index()) else {
        return Err("archive members are not an array".into());
    };
    let member = members
        .iter()
        .find(|member| {
            matches!(member, Value::Array(fields) if matches!(fields.get(MemberField::Path.index()), Some(Value::Text(member_path)) if member_path == path))
        })
        .ok_or_else(|| format!("archive member {path} is absent"))?;
    match member {
        Value::Array(fields) => match fields.get(MemberField::Bytes.index()) {
            Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
            _ => Err("archive member bytes are absent".into()),
        },
        _ => Err("archive member is not an array".into()),
    }
}

/// Returns the path of an archive member with a wire role.
///
/// # Errors
///
/// Returns an error when the archive structure, member role, or member path is invalid or absent.
pub fn member_path_by_role(archive: &Value, role: u64) -> TestResult<String> {
    let Value::Array(archive_fields) = archive else {
        return Err("archive is not an array".into());
    };
    let Some(Value::Array(members)) = archive_fields.get(ArchiveField::Members.index()) else {
        return Err("archive members are not an array".into());
    };
    let member = members
        .iter()
        .find(|member| {
            matches!(member, Value::Array(fields) if fields.get(MemberField::Role.index()) == Some(&Value::Integer(role.into())))
        })
        .ok_or_else(|| format!("archive member role {role} is absent"))?;
    match member {
        Value::Array(fields) => match fields.get(MemberField::Path.index()) {
            Some(Value::Text(path)) => Ok(path.clone()),
            _ => Err("archive member path is absent".into()),
        },
        _ => Err("archive member is not an array".into()),
    }
}

/// Returns the mutable fields of an archive member at a path.
///
/// # Errors
///
/// Returns an error when the archive structure or member is invalid or absent.
pub fn archive_member_fields<'a>(
    archive: &'a mut [Value],
    path: &str,
) -> TestResult<&'a mut Vec<Value>> {
    let members = array_field(archive, ArchiveField::Members.index(), "archive members")?;
    let member = members
        .iter_mut()
        .find(|member| {
            matches!(member, Value::Array(fields) if matches!(fields.get(MemberField::Path.index()), Some(Value::Text(member_path)) if member_path == path))
        })
        .ok_or_else(|| format!("archive member {path} is absent"))?;
    array_mut(member, "archive member")
}

/// Returns the mutable descriptor fields for an archive member path.
///
/// # Errors
///
/// Returns an error when the archive structure or descriptor is invalid or absent.
pub fn archive_descriptor_fields<'a>(
    archive: &'a mut [Value],
    path: &str,
) -> TestResult<&'a mut Vec<Value>> {
    let manifest = array_field(archive, ArchiveField::Manifest.index(), "manifest")?;
    let descriptors = array_field(
        manifest,
        ManifestField::MemberDescriptors.index(),
        "member descriptors",
    )?;
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| {
            matches!(descriptor, Value::Array(fields) if matches!(fields.get(DescriptorField::Path.index()), Some(Value::Text(descriptor_path)) if descriptor_path == path))
        })
        .ok_or_else(|| format!("archive descriptor {path} is absent"))?;
    array_mut(descriptor, "archive descriptor")
}

/// Replaces an archive member and refreshes its descriptor metadata.
///
/// # Errors
///
/// Returns an error when the member or descriptor is absent, malformed, or cannot encode the length.
pub fn replace_archive_member_bytes(archive: &mut [Value], path: &str, bytes: &[u8]) -> TestResult {
    replace_value(
        archive_member_fields(archive, path)?,
        MemberField::Bytes.index(),
        Value::Bytes(bytes.to_owned()),
        "archive member bytes",
    )?;
    let descriptor = archive_descriptor_fields(archive, path)?;
    replace_value(
        descriptor,
        DescriptorField::Length.index(),
        Value::Integer(u64::try_from(bytes.len())?.into()),
        "archive member length",
    )?;
    replace_value(
        descriptor,
        DescriptorField::Digest.index(),
        Value::Bytes(blake3::hash(bytes).as_bytes().to_vec()),
        "archive member digest",
    )
}

fn rebuild_archive_descriptors(archive: &mut [Value]) -> TestResult {
    let descriptors = array_field(archive, ArchiveField::Members.index(), "archive members")?
        .iter()
        .map(|member| {
            let Value::Array(fields) = member else {
                return Err("archive member is not an array".into());
            };
            let path = fields
                .get(MemberField::Path.index())
                .ok_or("archive member path is absent")?
                .clone();
            let Some(Value::Bytes(bytes)) = fields.get(MemberField::Bytes.index()) else {
                return Err("archive member bytes are absent".into());
            };
            let role = fields
                .get(MemberField::Role.index())
                .ok_or("archive member role is absent")?
                .clone();
            Ok(Value::Array(vec![
                path,
                Value::Integer(u64::try_from(bytes.len())?.into()),
                Value::Bytes(blake3::hash(bytes).as_bytes().to_vec()),
                role,
            ]))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let manifest = array_field(archive, ArchiveField::Manifest.index(), "manifest")?;
    manifest[ManifestField::MemberDescriptors.index()] = Value::Array(descriptors);
    Ok(())
}

/// Re-signs an archive after a public-boundary mutation.
///
/// # Errors
///
/// Returns an error when the archive structure or manifest encoding is invalid.
pub fn resign_archive(archive: &mut Value) -> TestResult {
    let manifest = {
        let fields = array_mut(archive, "archive")?;
        encode_value(&fields[ArchiveField::Manifest.index()])?
    };
    let key = SigningKey::from_bytes(&ARCHIVE_SIGNING_KEY);
    let fields = array_mut(archive, "archive")?;
    fields[ArchiveField::SigningPublicKey.index()] =
        Value::Bytes(key.verifying_key().to_bytes().to_vec());
    fields[ArchiveField::Signature.index()] = Value::Bytes(key.sign(&manifest).to_bytes().to_vec());
    Ok(())
}

/// Recomputes digest fields for every fixture in a profile.
///
/// # Errors
///
/// Returns an error when the profile or fixture structure is invalid or a digest cannot be encoded.
pub fn refresh_fixture_digests(profile: &mut [Value]) -> TestResult {
    let fixtures = array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?;
    for fixture in fixtures {
        let fields = array_mut(fixture, "fixture")?;
        if fields.len() != 24 {
            return Err("fixture does not have the CPF1 field count".into());
        }
        fields[FixtureField::Digest.index()] = Value::Bytes(
            contract_digest(
                b"PiglorOS.Conformance.Fixture.v1",
                &fields[..FixtureField::Digest.index()],
            )?
            .to_vec(),
        );
    }
    Ok(())
}

/// Mutates, re-signs, and encodes an archive through its public representation.
///
/// # Errors
///
/// Returns an error when archive decoding, mutation, signing, or encoding fails.
pub fn mutate_archive(
    original: &[u8],
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    mutate(array_mut(&mut archive, "archive")?)?;
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

/// Mutates, re-hashes, and re-signs one decoded archive member.
///
/// # Errors
///
/// Returns an error when archive or member decoding, mutation, metadata refresh, signing, or encoding fails.
pub fn mutate_member(
    original: &[u8],
    path: &str,
    mutate: impl FnOnce(&mut Vec<Value>) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    let original_bytes = member_bytes(&archive, path)?;
    let mut value: Value = ciborium::from_reader(original_bytes.as_slice())?;
    mutate(array_mut(&mut value, "authority member")?)?;
    let updated = encode_value(&value)?;
    replace_archive_member_bytes(array_mut(&mut archive, "archive")?, path, &updated)?;
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

/// Mutates a release-admission member and refreshes every bound profile digest.
///
/// # Errors
///
/// Returns an error when the archive or profile is malformed, the admission is unbound, or re-signing fails.
pub fn mutate_release_admission(
    original: &[u8],
    path: &str,
    mutate: impl FnOnce(&mut Vec<Value>) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    let original_bytes = member_bytes(&archive, path)?;
    let original_digest = blake3::hash(&original_bytes).as_bytes().to_vec();
    let mut admission: Value = ciborium::from_reader(original_bytes.as_slice())?;
    mutate(array_mut(&mut admission, "release admission")?)?;
    let updated_bytes = encode_value(&admission)?;
    let updated_digest = blake3::hash(&updated_bytes).as_bytes().to_vec();
    replace_archive_member_bytes(array_mut(&mut archive, "archive")?, path, &updated_bytes)?;

    let profile_bytes = member_bytes(&archive, PROFILE_MEMBER_PATH)?;
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let profile_digest = {
        let fields = array_mut(&mut profile, "profile")?;
        let fixtures = array_field(fields, ProfileField::Fixtures.index(), "profile fixtures")?;
        let mut replaced = false;
        for fixture in fixtures {
            let fixture_fields = array_mut(fixture, "fixture")?;
            if fixture_fields[FixtureField::ReleaseAdmissionDigest.index()]
                == Value::Bytes(original_digest.clone())
            {
                fixture_fields[FixtureField::ReleaseAdmissionDigest.index()] =
                    Value::Bytes(updated_digest.clone());
                replaced = true;
            }
        }
        if !replaced {
            return Err("release admission is not referenced by a fixture".into());
        }
        refresh_fixture_digests(fields)?;
        fields[ProfileField::Digest.index()] = Value::Bytes(
            contract_digest(
                b"PiglorOS.ConformanceProfile.v1",
                &fields[..ProfileField::Digest.index()],
            )?
            .to_vec(),
        );
        match &fields[ProfileField::Digest.index()] {
            Value::Bytes(digest) => digest.clone(),
            _ => return Err("profile digest is not bytes".into()),
        }
    };
    let updated_profile = encode_value(&profile)?;
    replace_archive_member_bytes(
        array_mut(&mut archive, "archive")?,
        PROFILE_MEMBER_PATH,
        &updated_profile,
    )?;
    let manifest = array_field(
        array_mut(&mut archive, "archive")?,
        ArchiveField::Manifest.index(),
        "manifest",
    )?;
    manifest[ManifestField::ProfileDigest.index()] = Value::Bytes(profile_digest);
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

/// Mutates draft evidence and refreshes the bound archive and profile digests.
///
/// # Errors
///
/// Returns an error when evidence, archive, or profile data is malformed or cannot be re-signed.
pub fn mutate_draft_evidence(
    original: &[u8],
    mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    let profile_bytes = member_bytes(&archive, PROFILE_MEMBER_PATH)?;
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let evidence_path = {
        let profile_fields = array_mut(&mut profile, "profile")?;
        let fixtures = array_field(
            profile_fields,
            ProfileField::Fixtures.index(),
            "profile fixtures",
        )?;
        let fixture = fixtures.first_mut().ok_or("profile fixture is absent")?;
        let fixture_fields = array_mut(fixture, "fixture")?;
        let auxiliary = array_field(
            fixture_fields,
            FixtureField::Auxiliary.index(),
            "fixture auxiliary artifacts",
        )?;
        let descriptor = auxiliary
            .iter_mut()
            .find(|descriptor| {
                matches!(descriptor, Value::Array(fields) if matches!(fields.get(ArtifactDescriptorField::Path.index()), Some(Value::Text(path)) if path.starts_with("evidence/")))
            })
            .ok_or("fixture evidence descriptor is absent")?;
        let descriptor_fields = array_mut(descriptor, "evidence descriptor")?;
        match &descriptor_fields[ArtifactDescriptorField::Path.index()] {
            Value::Text(path) => path.clone(),
            _ => return Err("evidence path is not text".into()),
        }
    };
    let evidence_bytes = member_bytes(&archive, &evidence_path)?;
    let mut evidence: serde_json::Value = serde_json::from_slice(&evidence_bytes)?;
    mutate(
        evidence
            .as_object_mut()
            .ok_or("evidence status is not a JSON object")?,
    )?;
    let updated_evidence = serde_json::to_vec(&evidence)?;
    let profile_digest = {
        let profile_fields = array_mut(&mut profile, "profile")?;
        let fixtures = array_field(
            profile_fields,
            ProfileField::Fixtures.index(),
            "profile fixtures",
        )?;
        let fixture = fixtures.first_mut().ok_or("profile fixture is absent")?;
        let fixture_fields = array_mut(fixture, "fixture")?;
        let auxiliary = array_field(
            fixture_fields,
            FixtureField::Auxiliary.index(),
            "fixture auxiliary artifacts",
        )?;
        let descriptor = auxiliary
            .iter_mut()
            .find(|descriptor| {
                matches!(descriptor, Value::Array(fields) if fields.get(ArtifactDescriptorField::Path.index()) == Some(&Value::Text(evidence_path.clone())))
            })
            .ok_or("fixture evidence descriptor is absent")?;
        let descriptor_fields = array_mut(descriptor, "evidence descriptor")?;
        descriptor_fields[ArtifactDescriptorField::Length.index()] =
            Value::Integer(u64::try_from(updated_evidence.len())?.into());
        descriptor_fields[ArtifactDescriptorField::Digest.index()] =
            Value::Bytes(blake3::hash(&updated_evidence).as_bytes().to_vec());
        refresh_fixture_digests(profile_fields)?;
        profile_fields[ProfileField::Digest.index()] = Value::Bytes(
            contract_digest(
                b"PiglorOS.ConformanceProfile.v1",
                &profile_fields[..ProfileField::Digest.index()],
            )?
            .to_vec(),
        );
        match &profile_fields[ProfileField::Digest.index()] {
            Value::Bytes(digest) => digest.clone(),
            _ => return Err("profile digest is not bytes".into()),
        }
    };
    replace_archive_member_bytes(
        array_mut(&mut archive, "archive")?,
        &evidence_path,
        &updated_evidence,
    )?;
    replace_archive_member_bytes(
        array_mut(&mut archive, "archive")?,
        PROFILE_MEMBER_PATH,
        &encode_value(&profile)?,
    )?;
    rebuild_archive_descriptors(array_mut(&mut archive, "archive")?)?;
    let manifest = array_field(
        array_mut(&mut archive, "archive")?,
        ArchiveField::Manifest.index(),
        "manifest",
    )?;
    manifest[ManifestField::ProfileDigest.index()] = Value::Bytes(profile_digest);
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

/// Mutates a profile and refreshes its bound archive metadata.
///
/// # Errors
///
/// Returns an error when the archive or profile is malformed or cannot be re-signed.
pub fn mutate_profile(
    original: &[u8],
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    let profile_bytes = member_bytes(&archive, PROFILE_MEMBER_PATH)?;
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let profile_digest = {
        let fields = array_mut(&mut profile, "profile")?;
        mutate(fields)?;
        refresh_fixture_digests(fields)?;
        fields[ProfileField::Digest.index()] = Value::Bytes(
            contract_digest(
                b"PiglorOS.ConformanceProfile.v1",
                &fields[..ProfileField::Digest.index()],
            )?
            .to_vec(),
        );
        match &fields[ProfileField::Digest.index()] {
            Value::Bytes(digest) => digest.clone(),
            _ => return Err("profile digest is not bytes".into()),
        }
    };
    let updated_profile = encode_value(&profile)?;
    replace_archive_member_bytes(
        array_mut(&mut archive, "archive")?,
        PROFILE_MEMBER_PATH,
        &updated_profile,
    )?;
    let manifest = array_field(
        array_mut(&mut archive, "archive")?,
        ArchiveField::Manifest.index(),
        "manifest",
    )?;
    manifest[ManifestField::ProfileDigest.index()] = Value::Bytes(profile_digest);
    resign_archive(&mut archive)?;
    encode_value(&archive)
}

/// Asserts that the independent verifier rejects an archive scenario.
///
/// # Errors
///
/// Returns an error when the independent verifier accepts the archive.
pub fn assert_independent_rejects(archive: &[u8], scenario: &str) -> TestResult {
    if verify_archive_independently(archive).is_ok() {
        return Err(format!("independent verifier accepted {scenario}").into());
    }
    Ok(())
}

/// Replaces typed bundle-member bytes and refreshes their manifest descriptor.
///
/// # Errors
///
/// Returns an error when the member or descriptor is absent or its length cannot be represented.
pub fn update_typed_member(
    bundle: &mut ConformanceBundleV1,
    role: BundleMemberRoleV1,
    bytes: Vec<u8>,
) -> TestResult {
    let member = bundle
        .members
        .iter_mut()
        .find(|member| member.role == role)
        .ok_or("bundle member is absent")?;
    member.bytes = bytes;
    member.digest = *blake3::hash(&member.bytes).as_bytes();
    let member_path = member.path.clone();
    let descriptor = bundle
        .manifest
        .members
        .iter_mut()
        .find(|descriptor| descriptor.path == member_path)
        .ok_or("bundle member descriptor is absent")?;
    descriptor.size_bytes = u64::try_from(member.bytes.len())?;
    descriptor.digest = member.digest;
    Ok(())
}
