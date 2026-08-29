//! Signed, current-only CPF1 conformance bundles.
//!
//! The typed boundary binds public archive members to current fixture and
//! provider descriptors.  The independent entry point parses raw CBOR and
//! never invokes typed profile, registry, or package codecs.

use ciborium::value::Value;
use ed25519_dalek::{Signer, Verifier};
use pos_core::{CanonicalBytes, PublicKey, Signature};
use pos_crypto::signing;
use std::collections::BTreeSet;
use std::io::Cursor;
use thiserror::Error;

use crate::{
    ArtifactDescriptorV1, ConformanceProfileV1, ExecutionModeV1, FixtureProviderPackageV1,
    FixtureProviderRegistryV1, ProfileLifecycleV1, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
};

pub const CONFORMANCE_BUNDLE_MAGIC_V1: &str = "CFB1";
pub const MAX_CONFORMANCE_BUNDLE_BYTES_V1: u64 = 1024 * 1024 * 1024;
const PROFILE_PATH: &str = "profile/CPF1.cbor";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BundleContractErrorV1 {
    #[error("bundle member is invalid")]
    MemberOutOfBounds,
    #[error("bundle member digest is invalid")]
    MemberDigestMismatch,
    #[error("bundle member is missing")]
    MemberMissing,
    #[error("bundle member is undeclared")]
    UndeclaredMember,
    #[error("bundle lifecycle is invalid")]
    LifecycleInvalid,
    #[error("bundle order is invalid")]
    NonCanonicalOrder,
    #[error("bundle oracle binding is invalid")]
    ExpectedResultMismatch,
    #[error("bundle profile is invalid")]
    ProfileInvalid,
    #[error("bundle signature is invalid")]
    SignatureInvalid,
    #[error("bundle modes differ")]
    ModeParityMismatch,
    #[error("bundle encoding failed")]
    EncodingFailed,
    #[error("bundle archive encoding is invalid")]
    ArchiveEncodingInvalid,
    #[error("bundle filename is invalid")]
    ReleaseFilenameInvalid,
    #[error("bundle archive digest is invalid")]
    ArchiveDigestMismatch,
    #[error("bundle contains prohibited secret material")]
    SecretMaterialDetected,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BundleModeV1 {
    Local,
    AirGapped,
}
impl BundleModeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Local => 0,
            Self::AirGapped => 1,
        }
    }
    const fn execution(self) -> ExecutionModeV1 {
        match self {
            Self::Local => ExecutionModeV1::Local,
            Self::AirGapped => ExecutionModeV1::AirGapped,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BundleMemberRoleV1 {
    FixtureInput,
    ExpectedResult,
    Profile,
    NormativeSpecification,
    Schema,
    Licence,
    Notice,
    Sbom,
    Provenance,
    Limitations,
    AuthorityInventory,
    ExecutionMatrix,
    FixtureProviderRegistry,
    FixtureProviderPackage,
}
impl BundleMemberRoleV1 {
    const fn code(self) -> u64 {
        match self {
            Self::FixtureInput => 0,
            Self::ExpectedResult => 1,
            Self::Profile => 2,
            Self::NormativeSpecification => 3,
            Self::Schema => 4,
            Self::Licence => 5,
            Self::Notice => 6,
            Self::Sbom => 7,
            Self::Provenance => 8,
            Self::Limitations => 9,
            Self::AuthorityInventory => 10,
            Self::ExecutionMatrix => 11,
            Self::FixtureProviderRegistry => 12,
            Self::FixtureProviderPackage => 13,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleMemberV1 {
    pub path: String,
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub role: BundleMemberRoleV1,
}
impl BundleMemberV1 {
    fn new(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        let digest = *blake3::hash(&bytes).as_bytes();
        Self {
            path: path.into(),
            bytes,
            digest,
            role,
        }
    }
    #[must_use]
    pub fn fixture_input(p: impl Into<String>, b: Vec<u8>) -> Self {
        Self::new(p, b, BundleMemberRoleV1::FixtureInput)
    }
    #[must_use]
    pub fn expected_result(p: impl Into<String>, b: Vec<u8>) -> Self {
        Self::new(p, b, BundleMemberRoleV1::ExpectedResult)
    }
    #[must_use]
    pub fn profile(b: Vec<u8>) -> Self {
        Self::new(PROFILE_PATH, b, BundleMemberRoleV1::Profile)
    }
    #[must_use]
    pub fn supporting(p: impl Into<String>, b: Vec<u8>, r: BundleMemberRoleV1) -> Self {
        Self::new(p, b, r)
    }
    #[must_use]
    pub fn authority_inventory(b: Vec<u8>) -> Self {
        Self::new(
            "authority/expected-authority-inventory.json",
            b,
            BundleMemberRoleV1::AuthorityInventory,
        )
    }
    #[must_use]
    pub fn execution_matrix(b: Vec<u8>) -> Self {
        Self::new(
            "authority/execution-matrix.json",
            b,
            BundleMemberRoleV1::ExecutionMatrix,
        )
    }
    #[must_use]
    pub fn fixture_provider_registry(b: Vec<u8>) -> Self {
        Self::new(
            FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
            b,
            BundleMemberRoleV1::FixtureProviderRegistry,
        )
    }
    #[must_use]
    pub fn fixture_provider_package(p: impl Into<String>, b: Vec<u8>) -> Self {
        Self::new(p, b, BundleMemberRoleV1::FixtureProviderPackage)
    }
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BundleExpectedResultV1 {
    pub case_id: String,
    pub claim_layer: crate::ClaimLayerV1,
    pub execution_profile_digest: [u8; 32],
    pub mode: BundleModeV1,
    pub member_path: String,
    pub digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BundleMemberDescriptorV1 {
    pub path: String,
    pub size_bytes: u64,
    pub digest: [u8; 32],
    pub role: BundleMemberRoleV1,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleManifestV1 {
    pub magic: String,
    pub lifecycle: ProfileLifecycleV1,
    pub mode: BundleModeV1,
    pub profile_digest: [u8; 32],
    pub members: Vec<BundleMemberDescriptorV1>,
    pub expected_results: Vec<BundleExpectedResultV1>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceBundleV1 {
    pub manifest: BundleManifestV1,
    pub members: Vec<BundleMemberV1>,
    pub signer_public_key: PublicKey,
    pub signature: Signature,
}

impl ConformanceBundleV1 {
    /// Assemble an unsigned Draft bundle from a validated CPF1 profile and its declared members.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when the profile, member closure, or expected-result binding
    /// is invalid.
    pub fn materialize(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
        mut members: Vec<BundleMemberV1>,
        expected_results: Vec<BundleExpectedResultV1>,
    ) -> Result<Self, BundleContractErrorV1> {
        if profile.lifecycle != ProfileLifecycleV1::Draft {
            return Err(BundleContractErrorV1::LifecycleInvalid);
        }
        members.push(BundleMemberV1::profile(
            profile
                .to_canonical_cbor()
                .map_err(|_| BundleContractErrorV1::ProfileInvalid)?,
        ));
        members.sort_by(|a, b| a.path.cmp(&b.path));
        let descriptors = members
            .iter()
            .map(|m| BundleMemberDescriptorV1 {
                path: m.path.clone(),
                size_bytes: u64::try_from(m.bytes.len()).unwrap_or(u64::MAX),
                digest: m.digest,
                role: m.role,
            })
            .collect();
        let result = Self {
            manifest: BundleManifestV1 {
                magic: CONFORMANCE_BUNDLE_MAGIC_V1.to_owned(),
                lifecycle: ProfileLifecycleV1::Draft,
                mode,
                profile_digest: profile.profile_digest,
                members: descriptors,
                expected_results,
            },
            members,
            signer_public_key: PublicKey::from_bytes([0; 32]),
            signature: Signature::from_bytes([0; 64]),
        };
        result.validate_unsigned().map(|()| result)
    }
    /// Sign the canonical manifest after revalidating the complete unsigned bundle.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when validation, encoding, or signature verification fails.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, BundleContractErrorV1> {
        self.validate_unsigned()?;
        self.signer_public_key = PublicKey::from_bytes(key.verifying_key().to_bytes());
        self.signature = Signature::from_bytes(key.sign(&self.manifest_bytes()?).to_bytes());
        self.validate().map(|()| self)
    }
    /// Decode and validate exact canonical CFB1 archive bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error for malformed, noncanonical, oversized, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleContractErrorV1> {
        if u64::try_from(bytes.len()).map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?
            > MAX_CONFORMANCE_BUNDLE_BYTES_V1
        {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        let value = decode(bytes)?;
        let fields = array(&value, 4)?;
        let manifest = decode_manifest(&fields[0])?;
        let members = array_values(&fields[1])?
            .iter()
            .map(decode_member)
            .collect::<Result<Vec<_>, _>>()?;
        let signer_public_key = PublicKey::from_bytes(digest::<32>(&fields[2])?);
        let signature = Signature::from_bytes(digest::<64>(&fields[3])?);
        let bundle = Self {
            manifest,
            members,
            signer_public_key,
            signature,
        };
        bundle.validate()?;
        Ok(bundle)
    }
    /// Validate member closure, descriptor bindings, profile/provider contracts, and signature.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error for the first rejected invariant.
    pub fn validate(&self) -> Result<(), BundleContractErrorV1> {
        self.validate_unsigned()?;
        let key = signing::verifying_key_from_public_key(&self.signer_public_key)
            .map_err(|_| BundleContractErrorV1::SignatureInvalid)?;
        signing::verify(
            &key,
            &CanonicalBytes::from_vec(self.manifest_bytes()?),
            &self.signature,
        )
        .map_err(|_| BundleContractErrorV1::SignatureInvalid)
    }
    /// Encode the canonical six-field CFB1 manifest.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the manifest cannot be represented canonically.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>, BundleContractErrorV1> {
        encode(&manifest_value(&self.manifest))
    }
    /// Compute the domain-separated digest of the canonical manifest.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if canonical manifest bytes cannot be produced.
    pub fn manifest_digest(&self) -> Result<[u8; 32], BundleContractErrorV1> {
        self.manifest_bytes()
            .map(|b| digest_domain(b"PiglorOS.ConformanceBundle.v1\0", &b))
    }
    /// Validate and encode the complete canonical signed CFB1 archive.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, BundleContractErrorV1> {
        self.validate()?;
        encode(&archive_value(self))
    }
    /// Compute the BLAKE3 digest of the complete canonical archive bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when the archive cannot be validated or encoded.
    pub fn archive_digest(&self) -> Result<[u8; 32], BundleContractErrorV1> {
        self.to_canonical_cbor()
            .map(|b| *blake3::hash(&b).as_bytes())
    }
    /// Derive the content-addressed `.cfb1` release filename from the complete archive.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when the archive cannot be validated or encoded.
    pub fn release_filename(&self) -> Result<String, BundleContractErrorV1> {
        self.archive_digest().map(|digest| {
            let hexadecimal = crate::hex_digest(&digest);
            format!("{hexadecimal}.cfb1")
        })
    }
    fn validate_unsigned(&self) -> Result<(), BundleContractErrorV1> {
        if self.members.len() != self.manifest.members.len()
            || self
                .members
                .iter()
                .try_fold(0_u64, |total, member| {
                    total.checked_add(u64::try_from(member.bytes.len()).ok()?)
                })
                .is_none_or(|total| total > MAX_CONFORMANCE_BUNDLE_BYTES_V1)
        {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        if self.manifest.magic != CONFORMANCE_BUNDLE_MAGIC_V1
            || self.manifest.lifecycle != ProfileLifecycleV1::Draft
            || !ordered_members(&self.members)
            || !ordered_descriptors(&self.manifest.members)
        {
            return Err(BundleContractErrorV1::NonCanonicalOrder);
        }
        let profile_member = one(&self.members, BundleMemberRoleV1::Profile, PROFILE_PATH)?;
        let profile = ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        if profile.profile_digest != self.manifest.profile_digest {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        for (m, d) in self.members.iter().zip(&self.manifest.members) {
            if m.path != d.path
                || m.role != d.role
                || m.digest != d.digest
                || d.size_bytes != u64::try_from(m.bytes.len()).unwrap_or(u64::MAX)
                || m.digest != *blake3::hash(&m.bytes).as_bytes()
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
        }
        validate_provider_members(&profile, &self.members)?;
        validate_fixture_members(
            &profile,
            self.manifest.mode,
            &self.members,
            &self.manifest.expected_results,
        )
    }
}

fn validate_provider_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let binding = &profile.fixture_provider_registry;
    let registry_member = descriptor_member(
        members,
        &binding.registry_artifact,
        BundleMemberRoleV1::FixtureProviderRegistry,
    )?;
    if registry_member.path != FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1 {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    let registry = FixtureProviderRegistryV1::from_canonical_cbor(&registry_member.bytes)
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let used = profile
        .fixtures
        .iter()
        .map(|f| f.provider_key.clone())
        .collect::<BTreeSet<_>>();
    if used.iter().collect::<Vec<_>>() != binding.required_provider_keys.iter().collect::<Vec<_>>()
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let registry_package_paths = registry
        .providers
        .iter()
        .map(|entry| entry.provider_package_descriptor.member_path.as_str())
        .collect::<BTreeSet<_>>();
    if members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::FixtureProviderPackage)
        .any(|member| !registry_package_paths.contains(member.path.as_str()))
    {
        return Err(BundleContractErrorV1::UndeclaredMember);
    }
    let registry_keys = registry
        .providers
        .iter()
        .map(|entry| &entry.provider_key)
        .collect::<BTreeSet<_>>();
    if binding
        .required_provider_keys
        .iter()
        .any(|key| !registry_keys.contains(key))
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for entry in &registry.providers {
        let p = descriptor_member(
            members,
            &entry.provider_package_descriptor,
            BundleMemberRoleV1::FixtureProviderPackage,
        )?;
        let package = FixtureProviderPackageV1::from_canonical_cbor(&p.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        package
            .validate_registry_binding(entry, &p.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        validate_provider_support_members(members, &package)?;
        if !binding.required_provider_keys.contains(&entry.provider_key) {
            continue;
        }
        let fixtures = profile
            .fixtures
            .iter()
            .filter(|f| f.provider_key == entry.provider_key);
        for fixture in fixtures {
            let family = usize::try_from(fixture.family.wire_code())
                .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
            if fixture.claim_layer != entry.claim_layer
                || fixture.subject_adapter != entry.subject_adapter
                || package
                    .family_schemas
                    .get(family)
                    .is_none_or(|s| s.schema_descriptor != fixture.schema)
            {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
        }
    }
    Ok(())
}

fn validate_provider_support_members(
    members: &[BundleMemberV1],
    package: &FixtureProviderPackageV1,
) -> Result<(), BundleContractErrorV1> {
    for schema in &package.family_schemas {
        descriptor_member(
            members,
            &schema.schema_descriptor,
            BundleMemberRoleV1::Schema,
        )?;
    }
    descriptor_member(
        members,
        &package.licence_descriptor,
        BundleMemberRoleV1::Licence,
    )?;
    descriptor_member(
        members,
        &package.notices_descriptor,
        BundleMemberRoleV1::Notice,
    )?;
    descriptor_member(members, &package.sbom_descriptor, BundleMemberRoleV1::Sbom)?;
    descriptor_member(
        members,
        &package.source_provenance_descriptor,
        BundleMemberRoleV1::Provenance,
    )?;
    descriptor_member(
        members,
        &package.limitations_descriptor,
        BundleMemberRoleV1::Limitations,
    )?;
    Ok(())
}

fn validate_fixture_members(
    profile: &ConformanceProfileV1,
    mode: BundleModeV1,
    members: &[BundleMemberV1],
    expected: &[BundleExpectedResultV1],
) -> Result<(), BundleContractErrorV1> {
    if expected.windows(2).any(|p| p[0] >= p[1]) {
        return Err(BundleContractErrorV1::NonCanonicalOrder);
    }
    for fixture in profile
        .fixtures
        .iter()
        .filter(|f| f.modes.contains(&mode.execution()))
    {
        descriptor_member(members, &fixture.payload, BundleMemberRoleV1::FixtureInput)?;
        descriptor_member(members, &fixture.schema, BundleMemberRoleV1::Schema)?;
        for a in &fixture.auxiliary {
            descriptor_member(members, a, BundleMemberRoleV1::FixtureInput)
                .or_else(|_| descriptor_member(members, a, BundleMemberRoleV1::ExpectedResult))?;
        }
        let e = expected
            .iter()
            .find(|e| {
                e.case_id == fixture.case_id
                    && e.claim_layer == fixture.claim_layer
                    && e.execution_profile_digest == fixture.execution_profile_digest
                    && e.mode == mode
            })
            .ok_or(BundleContractErrorV1::ExpectedResultMismatch)?;
        let expected_member = one(members, BundleMemberRoleV1::ExpectedResult, &e.member_path)?;
        let expected_size = u64::try_from(expected_member.bytes.len())
            .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?;
        let expected_digest = e.digest;
        let a = fixture
            .auxiliary
            .iter()
            .find(|a| {
                a.member_path == e.member_path
                    && a.blake3_digest == expected_digest
                    && a.byte_length == expected_size
            })
            .ok_or(BundleContractErrorV1::ExpectedResultMismatch)?;
        let m = descriptor_member(members, a, BundleMemberRoleV1::ExpectedResult)?;
        if m.digest != expected_digest {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
    }
    let selected = profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.modes.contains(&mode.execution()))
        .count();
    if expected.len() != selected {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    Ok(())
}
fn one<'a>(
    members: &'a [BundleMemberV1],
    role: BundleMemberRoleV1,
    path: &str,
) -> Result<&'a BundleMemberV1, BundleContractErrorV1> {
    let values = members
        .iter()
        .filter(|m| m.role == role && m.path == path)
        .collect::<Vec<_>>();
    if values.len() == 1 {
        Ok(values[0])
    } else {
        Err(BundleContractErrorV1::MemberMissing)
    }
}
fn descriptor_member<'a>(
    members: &'a [BundleMemberV1],
    d: &ArtifactDescriptorV1,
    r: BundleMemberRoleV1,
) -> Result<&'a BundleMemberV1, BundleContractErrorV1> {
    let m = one(members, r, &d.member_path)?;
    if m.digest == d.blake3_digest
        && u64::try_from(m.bytes.len()).unwrap_or(u64::MAX) == d.byte_length
    {
        Ok(m)
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}
fn decode_manifest(value: &Value) -> Result<BundleManifestV1, BundleContractErrorV1> {
    let f = array(value, 6)?;
    let lifecycle = match uint(&f[1])? {
        0 => ProfileLifecycleV1::Draft,
        1 => ProfileLifecycleV1::Candidate,
        2 => ProfileLifecycleV1::Stable,
        3 => ProfileLifecycleV1::Retired,
        _ => return Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    };
    let mode = decode_mode(&f[2])?;
    let members = array_values(&f[4])?
        .iter()
        .map(|v| {
            let x = array(v, 4)?;
            Ok(BundleMemberDescriptorV1 {
                path: text(&x[0])?.to_owned(),
                size_bytes: uint(&x[1])?,
                digest: digest(&x[2])?,
                role: decode_role(&x[3])?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_results = array_values(&f[5])?
        .iter()
        .map(|v| {
            let x = array(v, 6)?;
            Ok(BundleExpectedResultV1 {
                case_id: text(&x[0])?.to_owned(),
                claim_layer: crate::ClaimLayerV1::from_wire_code(
                    u8::try_from(uint(&x[1])?)
                        .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?,
                )
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?,
                execution_profile_digest: digest(&x[2])?,
                mode: decode_mode(&x[3])?,
                member_path: text(&x[4])?.to_owned(),
                digest: digest(&x[5])?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BundleManifestV1 {
        magic: text(&f[0])?.to_owned(),
        lifecycle,
        mode,
        profile_digest: digest(&f[3])?,
        members,
        expected_results,
    })
}
fn decode_member(value: &Value) -> Result<BundleMemberV1, BundleContractErrorV1> {
    let f = array(value, 3)?;
    let bytes = bytes(&f[1])?.to_vec();
    Ok(BundleMemberV1::new(
        text(&f[0])?.to_owned(),
        bytes,
        decode_role(&f[2])?,
    ))
}
fn decode_mode(value: &Value) -> Result<BundleModeV1, BundleContractErrorV1> {
    match uint(value)? {
        0 => Ok(BundleModeV1::Local),
        1 => Ok(BundleModeV1::AirGapped),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn decode_role(value: &Value) -> Result<BundleMemberRoleV1, BundleContractErrorV1> {
    match uint(value)? {
        0 => Ok(BundleMemberRoleV1::FixtureInput),
        1 => Ok(BundleMemberRoleV1::ExpectedResult),
        2 => Ok(BundleMemberRoleV1::Profile),
        3 => Ok(BundleMemberRoleV1::NormativeSpecification),
        4 => Ok(BundleMemberRoleV1::Schema),
        5 => Ok(BundleMemberRoleV1::Licence),
        6 => Ok(BundleMemberRoleV1::Notice),
        7 => Ok(BundleMemberRoleV1::Sbom),
        8 => Ok(BundleMemberRoleV1::Provenance),
        9 => Ok(BundleMemberRoleV1::Limitations),
        10 => Ok(BundleMemberRoleV1::AuthorityInventory),
        11 => Ok(BundleMemberRoleV1::ExecutionMatrix),
        12 => Ok(BundleMemberRoleV1::FixtureProviderRegistry),
        13 => Ok(BundleMemberRoleV1::FixtureProviderPackage),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
/// Independently validate canonical CFB1, CPF1, FPR1, and FPP1 bytes without typed codecs.
///
/// # Errors
///
/// Returns a closed bundle error for malformed bytes or any failed archive-contract invariant.
pub fn verify_archive_independently(archive_bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    if u64::try_from(archive_bytes.len()).map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?
        > MAX_CONFORMANCE_BUNDLE_BYTES_V1
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    let value = decode(archive_bytes)?;
    let fields = array(&value, 4)?;
    let manifest = array(&fields[0], 6)?;
    if text(&manifest[0])? != CONFORMANCE_BUNDLE_MAGIC_V1
        || uint(&manifest[1])? != 0
        || uint(&manifest[2])? > 1
    {
        return Err(BundleContractErrorV1::LifecycleInvalid);
    }
    let members = array_values(&fields[1])?;
    let descriptors = array_values(&manifest[4])?;
    if members.len() != descriptors.len()
        || !raw_member_paths_ordered(members)?
        || !raw_descriptor_paths_ordered(descriptors)?
    {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    for (member, descriptor) in members.iter().zip(descriptors) {
        let member_fields = array(member, 3)?;
        let descriptor_fields = array(descriptor, 4)?;
        let raw = bytes(&member_fields[1])?;
        if text(&member_fields[0])? != text(&descriptor_fields[0])?
            || uint(&member_fields[2])? != uint(&descriptor_fields[3])?
            || u64::try_from(raw.len()).map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?
                != uint(&descriptor_fields[1])?
            || *blake3::hash(raw).as_bytes() != digest::<32>(&descriptor_fields[2])?
        {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    let profile_member = raw_member(members, PROFILE_PATH, 2)?;
    let profile = decode(bytes(&profile_member[1])?)?;
    let profile_fields = array(&profile, 18)?;
    raw_cpf1_value(profile_fields)?;
    if profile_fields[4] != manifest[1] {
        return Err(BundleContractErrorV1::LifecycleInvalid);
    }
    let profile_digest = digest::<32>(&profile_fields[17])?;
    if profile_digest
        != digest_domain(
            b"PiglorOS.ConformanceProfile.v1\0",
            &length_bound(&Value::Array(profile_fields[..17].to_vec()))?,
        )
        || profile_digest != digest::<32>(&manifest[3])?
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    raw_registry_and_packages(profile_fields, members)?;
    raw_expected_results(&manifest[5], profile_fields, members, uint(&manifest[2])?)?;
    let key = digest::<32>(&fields[2])?;
    let sig = digest::<64>(&fields[3])?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| BundleContractErrorV1::SignatureInvalid)?
        .verify(
            &encode(&fields[0])?,
            &ed25519_dalek::Signature::from_bytes(&sig),
        )
        .map_err(|_| BundleContractErrorV1::SignatureInvalid)
}
fn raw_cpf1_value(f: &[Value]) -> Result<(), BundleContractErrorV1> {
    if text(&f[0])? != "CPF1"
        || uint(&f[1])? != 1
        || !raw_identifier(text(&f[2])?, 128)
        || !raw_semver(text(&f[3])?)
        || uint(&f[4])? > 3
        || digest::<32>(&f[5])? == [0; 32]
        || digest::<32>(&f[6])? == [0; 32]
        || digest::<32>(&f[13])? == [0; 32]
        || digest::<32>(&f[14])? == [0; 32]
        || digest::<32>(&f[15])? == [0; 32]
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let executions = array_values(&f[7])?;
    if executions.is_empty()
        || !raw_digests_ordered(executions)?
        || executions.iter().any(|value| digest::<32>(value).is_err())
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let binding = array(&f[8], 2)?;
    raw_artifact(&binding[0])?;
    let provider_keys = array_values(&binding[1])?;
    if provider_keys.is_empty() || !raw_provider_keys_ordered(provider_keys)? {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for key in provider_keys {
        raw_provider_key(key)?;
    }
    let fixtures = array_values(&f[9])?;
    if fixtures.is_empty() || !raw_fixture_ordered(fixtures)? {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for fixture in fixtures {
        let x = array(fixture, 24)?;
        if !raw_identifier(text(&x[0])?, 128)
            || uint(&x[2])? > 6
            || uint(&x[3])? > 6
            || uint(&x[5])? > 2
            || !matches!(&x[1], Value::Bool(_))
            || !matches!(&x[2], Value::Integer(_))
            || !matches!(&x[5], Value::Integer(_))
            || digest::<32>(&x[6]).is_err()
            || array_values(&x[7]).is_err()
            || raw_artifact(&x[8]).is_err()
            || raw_artifact(&x[9]).is_err()
            || raw_oracle(&x[11]).is_err()
            || raw_budget(&x[16]).is_err()
            || raw_watchdog(&x[17]).is_err()
            || raw_capabilities(&x[18]).is_err()
            || digest::<32>(&x[23]).is_err()
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        raw_provider_key(&x[4])?;
        let modes = array_values(&x[7])?;
        if modes.is_empty()
            || !raw_uints_ordered(modes)?
            || modes
                .iter()
                .any(|mode| uint(mode).map_or(true, |code| code > 1))
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        for auxiliary in array_values(&x[10])? {
            raw_artifact(auxiliary)?;
        }
        if uint(&x[12])? > 5 || uint(&x[14])? > 4 || uint(&x[15])? > 3 {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        raw_nullable_failure(&x[13])?;
        raw_provenance(&x[21])?;
        raw_nullable_digest(&x[19])?;
        raw_nullable_digest(&x[20])?;
        raw_transition(&x[22])?;
        let fixture_digest = digest_domain(
            b"PiglorOS.Conformance.Fixture.v1\0",
            &length_bound(&Value::Array(x[..23].to_vec()))?,
        );
        if fixture_digest != digest::<32>(&x[23])? {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    for divergence in array_values(&f[10])? {
        let fields = array(divergence, 2)?;
        if uint(&fields[0])? > 6 || bytes(&fields[1])?.is_empty() {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    raw_protocol(&f[11])?;
    raw_independence(&f[12])?;
    raw_nullable_digest(&f[16])?;
    Ok(())
}

fn raw_nullable_digest(value: &Value) -> Result<(), BundleContractErrorV1> {
    if !matches!(value, Value::Null) {
        let _ = digest::<32>(value)?;
    }
    Ok(())
}
fn raw_nullable_failure(value: &Value) -> Result<(), BundleContractErrorV1> {
    if !matches!(value, Value::Null) {
        let f = array(value, 3)?;
        if text(&f[0])?.is_empty() || text(&f[1])?.is_empty() || text(&f[2])?.is_empty() {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    Ok(())
}
fn raw_provenance(value: &Value) -> Result<(), BundleContractErrorV1> {
    let f = array(value, 7)?;
    if text(&f[0])?.is_empty() {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for digest_value in &f[1..] {
        if digest::<32>(digest_value)? == [0; 32] {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    Ok(())
}
fn raw_transition(value: &Value) -> Result<(), BundleContractErrorV1> {
    if !matches!(value, Value::Null) {
        let f = array(value, 2)?;
        raw_provider_key(&f[0])?;
        raw_provider_key(&f[1])?;
    }
    Ok(())
}
fn raw_protocol(value: &Value) -> Result<(), BundleContractErrorV1> {
    let f = array(value, 5)?;
    if text(&f[0])?.is_empty() {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for digest_value in &f[1..4] {
        if digest::<32>(digest_value)? == [0; 32] {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    let caps = array(&f[4], 10)?;
    if caps.iter().any(|v| uint(v).map_or(true, |n| n == 0)) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}
fn raw_independence(value: &Value) -> Result<(), BundleContractErrorV1> {
    let f = array(value, 5)?;
    if f[..3].iter().any(|v| !matches!(v, Value::Bool(_)))
        || digest::<32>(&f[3])? == [0; 32]
        || digest::<32>(&f[4])? == [0; 32]
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn raw_member<'a>(
    members: &'a [Value],
    path: &str,
    role: u64,
) -> Result<&'a [Value], BundleContractErrorV1> {
    let mut result = None;
    for member in members {
        let fields = array(member, 3)?;
        if text(&fields[0])? == path
            && uint(&fields[2])? == role
            && result.replace(fields).is_some()
        {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
    }
    result.ok_or(BundleContractErrorV1::MemberMissing)
}

fn raw_registry_and_packages(
    profile: &[Value],
    members: &[Value],
) -> Result<(), BundleContractErrorV1> {
    let binding = array(&profile[8], 2)?;
    let descriptor = array(&binding[0], 4)?;
    if text(&descriptor[0])? != FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let registry_member = raw_member(members, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, 12)?;
    raw_descriptor_matches_member(descriptor, registry_member)?;
    let registry = decode(bytes(&registry_member[1])?)?;
    let fields = array(&registry, 4)?;
    if text(&fields[0])? != "FPR1" || uint(&fields[1])? != 1 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let providers = array_values(&fields[2])?;
    if providers.is_empty() || !raw_provider_entries_ordered(providers)? {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let expected_digest = digest_domain(
        b"PiglorOS.Conformance.ProviderRegistry.v1\0",
        &length_bound(&Value::Array(fields[..3].to_vec()))?,
    );
    if expected_digest != digest::<32>(&fields[3])? {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for required in array_values(&binding[1])? {
        let required_fields = array(required, 4)?;
        if !providers.iter().any(|provider| {
            array(provider, 7).is_ok_and(|entry| {
                entry[..4]
                    .iter()
                    .zip(required_fields.iter())
                    .all(|(left, right)| left == right)
            })
        }) {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    for member in members {
        let member_fields = array(member, 3)?;
        if uint(&member_fields[2])? == 13
            && !providers.iter().any(|provider| {
                array(provider, 7).is_ok_and(|entry| {
                    array(&entry[6], 4)
                        .is_ok_and(|package| text(&package[0]).ok() == text(&member_fields[0]).ok())
                })
            })
        {
            return Err(BundleContractErrorV1::UndeclaredMember);
        }
    }
    for provider in providers {
        let entry = array(provider, 7)?;
        raw_provider_key(&Value::Array(entry[..4].to_vec()))?;
        if uint(&entry[4])? > 6 || uint(&entry[5])? > 2 {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        let package_descriptor = array(&entry[6], 4)?;
        raw_artifact(&entry[6])?;
        let package_member = raw_member(members, text(&package_descriptor[0])?, 13)?;
        raw_descriptor_matches_member(package_descriptor, package_member)?;
        raw_fpp1(bytes(&package_member[1])?, entry, members)?;
    }
    Ok(())
}

fn raw_fpp1(
    bytes_value: &[u8],
    entry: &[Value],
    members: &[Value],
) -> Result<(), BundleContractErrorV1> {
    let value = decode(bytes_value)?;
    let fields = array(&value, 12)?;
    if text(&fields[0])? != "FPP1"
        || uint(&fields[1])? != 1
        || fields[2] != Value::Array(entry[..4].to_vec())
        || fields[3] != entry[4]
        || fields[4] != entry[5]
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let schemas = array_values(&fields[5])?;
    if schemas.len() != 7 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    for (index, schema) in schemas.iter().enumerate() {
        let record = array(schema, 2)?;
        if uint(&record[0])?
            != u64::try_from(index).map_err(|_| BundleContractErrorV1::ProfileInvalid)?
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        raw_artifact(&record[1])?;
        let descriptor = array(&record[1], 4)?;
        raw_descriptor_matches_member(descriptor, raw_member(members, text(&descriptor[0])?, 4)?)?;
    }
    for (offset, descriptor) in fields[6..11].iter().enumerate() {
        raw_artifact(descriptor)?;
        let descriptor = array(descriptor, 4)?;
        raw_descriptor_matches_member(
            descriptor,
            raw_member(
                members,
                text(&descriptor[0])?,
                5 + u64::try_from(offset).map_err(|_| BundleContractErrorV1::ProfileInvalid)?,
            )?,
        )?;
    }
    let expected = digest_domain(
        b"PiglorOS.Conformance.ProviderPackage.v1\0",
        &length_bound(&Value::Array(fields[..11].to_vec()))?,
    );
    if expected != digest::<32>(&fields[11])? {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn raw_descriptor_matches_member(
    descriptor: &[Value],
    member: &[Value],
) -> Result<(), BundleContractErrorV1> {
    let raw = bytes(&member[1])?;
    if u64::try_from(raw.len()).map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?
        != uint(&descriptor[2])?
        || *blake3::hash(raw).as_bytes() != digest::<32>(&descriptor[3])?
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    Ok(())
}

fn raw_expected_results(
    value: &Value,
    profile: &[Value],
    members: &[Value],
    mode: u64,
) -> Result<(), BundleContractErrorV1> {
    let expected = array_values(value)?;
    if !raw_expected_ordered(expected)? {
        return Err(BundleContractErrorV1::NonCanonicalOrder);
    }
    for record in expected {
        let fields = array(record, 6)?;
        if uint(&fields[3])? != mode {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let member = raw_member(members, text(&fields[4])?, 1)?;
        if *blake3::hash(bytes(&member[1])?).as_bytes() != digest::<32>(&fields[5])? {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let mut bound = false;
        for fixture in array_values(&profile[9])? {
            let fixture_fields = array(fixture, 24)?;
            if text(&fixture_fields[0])? != text(&fields[0])?
                || uint(&fixture_fields[2])? != uint(&fields[1])?
                || digest::<32>(&fixture_fields[6])? != digest::<32>(&fields[2])?
            {
                continue;
            }
            for auxiliary in array_values(&fixture_fields[10])? {
                let descriptor = array(auxiliary, 4)?;
                if text(&descriptor[0])? == text(&fields[4])?
                    && digest::<32>(&descriptor[3])? == digest::<32>(&fields[5])?
                    && uint(&descriptor[2])?
                        == u64::try_from(bytes(&member[1])?.len())
                            .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?
                {
                    bound = true;
                }
            }
        }
        if !bound {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
    }
    let selected = array_values(&profile[9])?
        .iter()
        .filter(|fixture| {
            array(fixture, 24).is_ok_and(|fields| {
                array_values(&fields[7]).is_ok_and(|modes| {
                    modes
                        .iter()
                        .any(|candidate| uint(candidate).ok() == Some(mode))
                })
            })
        })
        .count();
    if expected.len() != selected {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    Ok(())
}

fn raw_member_paths_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    raw_paths_ordered(values, 3)
}
fn raw_descriptor_paths_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    raw_paths_ordered(values, 4)
}
fn raw_paths_ordered(values: &[Value], width: usize) -> Result<bool, BundleContractErrorV1> {
    let mut previous = "";
    for value in values {
        let current = text(&array(value, width)?[0])?;
        if !previous.is_empty() && previous >= current {
            return Ok(false);
        }
        previous = current;
    }
    Ok(true)
}
fn raw_digests_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    let mut previous = None;
    for value in values {
        let current = digest::<32>(value)?;
        if previous.is_some_and(|old| old >= current) {
            return Ok(false);
        }
        previous = Some(current);
    }
    Ok(true)
}
fn raw_uints_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    let mut previous = None;
    for value in values {
        let current = uint(value)?;
        if current > 1 || previous.is_some_and(|old| old >= current) {
            return Ok(false);
        }
        previous = Some(current);
    }
    Ok(true)
}
fn raw_provider_keys_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    let mut previous = None;
    for value in values {
        let fields = array(value, 4)?;
        let current = (
            text(&fields[0])?.to_owned(),
            text(&fields[1])?.to_owned(),
            uint(&fields[2])?,
            uint(&fields[3])?,
        );
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Ok(false);
        }
        previous = Some(current);
    }
    Ok(true)
}
fn raw_provider_entries_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    let mut previous = None;
    for value in values {
        let f = array(value, 7)?;
        let current = (
            text(&f[0])?.to_owned(),
            text(&f[1])?.to_owned(),
            uint(&f[2])?,
            uint(&f[3])?,
        );
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Ok(false);
        }
        previous = Some(current);
    }
    Ok(true)
}
fn raw_fixture_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    let mut previous = None;
    for value in values {
        let f = array(value, 24)?;
        let provider = array(&f[4], 4)?;
        let modes = array_values(&f[7])?
            .iter()
            .map(uint)
            .collect::<Result<Vec<_>, _>>()?;
        let current = (
            text(&provider[0])?.to_owned(),
            text(&provider[1])?.to_owned(),
            uint(&provider[2])?,
            uint(&provider[3])?,
            uint(&f[3])?,
            text(&f[0])?.to_owned(),
            digest::<32>(&f[6])?,
            modes,
        );
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Ok(false);
        }
        previous = Some(current);
    }
    Ok(true)
}
fn raw_expected_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    let mut previous = None;
    for value in values {
        let f = array(value, 6)?;
        let current = (
            text(&f[0])?.to_owned(),
            uint(&f[1])?,
            digest::<32>(&f[2])?,
            uint(&f[3])?,
            text(&f[4])?.to_owned(),
            digest::<32>(&f[5])?,
        );
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Ok(false);
        }
        previous = Some(current);
    }
    Ok(true)
}
fn length_bound(value: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    let encoded = encode(value)?;
    let mut bound = u64::try_from(encoded.len())
        .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?
        .to_be_bytes()
        .to_vec();
    bound.extend(encoded);
    Ok(bound)
}

fn raw_provider_key(value: &Value) -> Result<(), BundleContractErrorV1> {
    let fields = array(value, 4)?;
    if !raw_identifier(text(&fields[0])?, 128)
        || !raw_semver(text(&fields[1])?)
        || uint(&fields[2])? > u64::from(u16::MAX)
        || uint(&fields[3])? > u64::from(u16::MAX)
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn raw_artifact(value: &Value) -> Result<(), BundleContractErrorV1> {
    let fields = array(value, 4)?;
    if !raw_member_path(text(&fields[0])?)
        || !raw_media_type(text(&fields[1])?)
        || uint(&fields[2])? == 0
        || uint(&fields[2])? > 64 * 1024 * 1024
        || digest::<32>(&fields[3])? == [0; 32]
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn raw_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
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
fn raw_member_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value.split('/').count() <= 16
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 128)
}
fn raw_media_type(value: &str) -> bool {
    (3..=127).contains(&value.len())
        && value.is_ascii()
        && value.bytes().filter(|byte| *byte == b'/').count() == 1
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        })
}
fn raw_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let (core_pre, build) = match value.split_once('+') {
        Some((left, right)) if !right.is_empty() && !right.contains('+') => (left, right),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, pre) = match core_pre.split_once('-') {
        Some((left, right)) if !right.is_empty() && !right.contains('-') => (left, right),
        Some(_) => return false,
        None => (core_pre, ""),
    };
    let mut parts = core.split('.');
    parts.next().is_some_and(raw_numeric_semver)
        && parts.next().is_some_and(raw_numeric_semver)
        && parts.next().is_some_and(raw_numeric_semver)
        && parts.next().is_none()
        && raw_semver_identifiers(pre, true)
        && raw_semver_identifiers(build, false)
}
fn raw_numeric_semver(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn raw_semver_identifiers(value: &str, no_leading_zero: bool) -> bool {
    value.is_empty()
        || value.split('.').all(|item| {
            !item.is_empty()
                && item
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!no_leading_zero
                    || !item.bytes().all(|byte| byte.is_ascii_digit())
                    || raw_numeric_semver(item))
        })
}

fn raw_oracle(value: &Value) -> Result<(), BundleContractErrorV1> {
    let fields = array(value, 4)?;
    let active = match uint(&fields[0])? {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(BundleContractErrorV1::ProfileInvalid),
    };
    for (index, field) in fields.iter().enumerate().skip(1) {
        if (index == active) != !matches!(field, Value::Null) {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    Ok(())
}

fn raw_budget(value: &Value) -> Result<(), BundleContractErrorV1> {
    let fields = array(value, 8)?;
    if fields.iter().any(|field| uint(field).unwrap_or(0) == 0) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn raw_watchdog(value: &Value) -> Result<(), BundleContractErrorV1> {
    if uint(&array(value, 1)?[0])? == 0 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn raw_capabilities(value: &Value) -> Result<(), BundleContractErrorV1> {
    let fields = array(value, 2)?;
    if !matches!(fields[0], Value::Bool(_)) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let ids = array_values(&fields[1])?;
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) || ids.iter().any(|id| text(id).is_err()) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}
/// Independently validate an archive and its full-archive content-addressed filename.
///
/// # Errors
///
/// Returns a closed bundle error when either archive validation or filename binding fails.
pub fn verify_archive_release_filename(
    bytes: &[u8],
    filename: &str,
) -> Result<(), BundleContractErrorV1> {
    verify_archive_independently(bytes)?;
    if filename == format!("{}.cfb1", crate::hex_digest(blake3::hash(bytes).as_bytes())) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ReleaseFilenameInvalid)
    }
}
fn ordered_members(v: &[BundleMemberV1]) -> bool {
    v.windows(2).all(|p| p[0].path < p[1].path)
}
fn ordered_descriptors(v: &[BundleMemberDescriptorV1]) -> bool {
    v.windows(2).all(|p| p[0] < p[1])
}
fn encode(v: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b)
        .map_err(|_| BundleContractErrorV1::EncodingFailed)
        .map(|()| b)
}
fn decode(b: &[u8]) -> Result<Value, BundleContractErrorV1> {
    let v = ciborium::from_reader(Cursor::new(b))
        .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
    if encode(&v)? == b {
        Ok(v)
    } else {
        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
    }
}
fn array(v: &Value, n: usize) -> Result<&[Value], BundleContractErrorV1> {
    match v {
        Value::Array(a) if a.len() == n => Ok(a),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn array_values(v: &Value) -> Result<&[Value], BundleContractErrorV1> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn text(v: &Value) -> Result<&str, BundleContractErrorV1> {
    match v {
        Value::Text(x) => Ok(x),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn bytes(v: &Value) -> Result<&[u8], BundleContractErrorV1> {
    match v {
        Value::Bytes(x) => Ok(x),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn uint(v: &Value) -> Result<u64, BundleContractErrorV1> {
    match v {
        Value::Integer(x) => {
            u64::try_from(*x).map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
        }
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn digest<const N: usize>(v: &Value) -> Result<[u8; N], BundleContractErrorV1> {
    bytes(v)?
        .try_into()
        .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
}
fn digest_domain(d: &[u8], b: &[u8]) -> [u8; 32] {
    let mut x = d.to_vec();
    x.extend_from_slice(b);
    *blake3::hash(&x).as_bytes()
}
fn manifest_value(m: &BundleManifestV1) -> Value {
    Value::Array(vec![
        Value::Text(m.magic.clone()),
        Value::Integer(m.lifecycle.wire_code().into()),
        Value::Integer(m.mode.code().into()),
        Value::Bytes(m.profile_digest.to_vec()),
        Value::Array(
            m.members
                .iter()
                .map(|x| {
                    Value::Array(vec![
                        Value::Text(x.path.clone()),
                        Value::Integer(x.size_bytes.into()),
                        Value::Bytes(x.digest.to_vec()),
                        Value::Integer(x.role.code().into()),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            m.expected_results
                .iter()
                .map(|x| {
                    Value::Array(vec![
                        Value::Text(x.case_id.clone()),
                        Value::Integer(x.claim_layer.wire_code().into()),
                        Value::Bytes(x.execution_profile_digest.to_vec()),
                        Value::Integer(x.mode.code().into()),
                        Value::Text(x.member_path.clone()),
                        Value::Bytes(x.digest.to_vec()),
                    ])
                })
                .collect(),
        ),
    ])
}
fn archive_value(b: &ConformanceBundleV1) -> Value {
    Value::Array(vec![
        manifest_value(&b.manifest),
        Value::Array(
            b.members
                .iter()
                .map(|m| {
                    Value::Array(vec![
                        Value::Text(m.path.clone()),
                        Value::Bytes(m.bytes.clone()),
                        Value::Integer(m.role.code().into()),
                    ])
                })
                .collect(),
        ),
        Value::Bytes(b.signer_public_key.as_bytes().to_vec()),
        Value::Bytes(b.signature.as_bytes().to_vec()),
    ])
}
/// Derive a deterministic archive path for one fixture-owned member.
#[must_use]
pub fn fixture_input_member_path(
    case: &str,
    layer: crate::ClaimLayerV1,
    execution: &[u8; 32],
    member: &str,
) -> String {
    let mut x = b"PiglorOS.CPF1InputPath.v1\0".to_vec();
    x.extend_from_slice(case.as_bytes());
    x.push(layer.wire_code());
    x.extend_from_slice(execution);
    x.extend_from_slice(member.as_bytes());
    let digest = blake3::hash(&x).to_hex();
    format!("inputs/{digest}.bin")
}
/// Derive the deterministic expected-result member path for one fixture execution.
#[must_use]
pub fn expected_result_member_path(
    case: &str,
    layer: crate::ClaimLayerV1,
    execution: &[u8; 32],
) -> String {
    fixture_input_member_path(case, layer, execution, "strict-oracle")
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceBundlePairV1 {
    pub local: ConformanceBundleV1,
    pub air_gapped: ConformanceBundleV1,
}

impl ConformanceBundlePairV1 {
    /// Validate local and air-gapped bundles and require a shared CPF1 profile digest.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when either bundle is invalid or parity is absent.
    pub fn validate(&self) -> Result<(), BundleContractErrorV1> {
        self.local.validate()?;
        self.air_gapped.validate()?;
        if self.local.manifest.profile_digest == self.air_gapped.manifest.profile_digest {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ModeParityMismatch)
        }
    }
}
