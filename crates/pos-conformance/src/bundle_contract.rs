//! Signed, current-only CPF1 conformance bundles.
//!
//! The typed boundary binds public archive members to current fixture and
//! provider descriptors.  The independent entry point parses raw CBOR and
//! never invokes typed profile, registry, or package codecs.

use ciborium::value::Value;
use ed25519_dalek::{Signer, Verifier};
use pos_core::{CanonicalBytes, PublicKey, Signature};
use pos_crypto::signing;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use thiserror::Error;

use crate::{
    ArtifactDescriptorV1, ConformanceProfileV1, ExecutionModeV1, FixtureFamilyV1,
    FixtureProviderPackageV1, FixtureProviderRegistryV1, ProfileLifecycleV1,
    FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
};

pub const CONFORMANCE_BUNDLE_MAGIC_V1: &str = "CFB1";
pub const MAX_CONFORMANCE_BUNDLE_BYTES_V1: u64 = 1024 * 1024 * 1024;
const MAX_CONFORMANCE_MEMBER_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_CONFORMANCE_TEXT_BYTES_V1: u64 = 512;
const MAX_CONFORMANCE_ITEMS_V1: u64 = 65_536;
const MAX_CONFORMANCE_NESTING_V1: u8 = 32;
const PROFILE_PATH: &str = "profile/CPF1.cbor";
const NORMATIVE_SPEC_PATH: &str = "support/normative-requirements.md";
const EXECUTION_MATRIX_PATH: &str = "authority/execution-matrix.json";
const AUTHORITY_INVENTORY_PATH: &str = "authority/expected-authority-inventory.json";
const PROFILE_SCHEMA_PATH: &str = "support/schema-cpf1-v1.cddl";
const LIMITATIONS_PATH: &str = "support/limitations.md";
const SOURCE_PROVENANCE_PATH: &str = "support/source-provenance.json";
const BUILD_PROVENANCE_PATH: &str = "support/build-provenance.json";
const PUBLICATION_REVIEW_PATH: &str = "support/publication-review.json";
const NOTICE_PATH: &str = "support/NOTICE";
const SBOM_PATH: &str = "support/sbom.json";

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
    pub fn fixture_input(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::new(path, bytes, BundleMemberRoleV1::FixtureInput)
    }
    #[must_use]
    pub fn expected_result(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::new(path, bytes, BundleMemberRoleV1::ExpectedResult)
    }
    #[must_use]
    pub fn profile(bytes: Vec<u8>) -> Self {
        Self::new(PROFILE_PATH, bytes, BundleMemberRoleV1::Profile)
    }
    #[must_use]
    pub fn supporting(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        Self::new(path, bytes, role)
    }
    #[must_use]
    pub fn authority_inventory(bytes: Vec<u8>) -> Self {
        Self::new(
            "authority/expected-authority-inventory.json",
            bytes,
            BundleMemberRoleV1::AuthorityInventory,
        )
    }
    #[must_use]
    pub fn execution_matrix(bytes: Vec<u8>) -> Self {
        Self::new(
            "authority/execution-matrix.json",
            bytes,
            BundleMemberRoleV1::ExecutionMatrix,
        )
    }
    #[must_use]
    pub fn fixture_provider_registry(bytes: Vec<u8>) -> Self {
        Self::new(
            FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
            bytes,
            BundleMemberRoleV1::FixtureProviderRegistry,
        )
    }
    #[must_use]
    pub fn fixture_provider_package(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::new(path, bytes, BundleMemberRoleV1::FixtureProviderPackage)
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
        profile
            .to_canonical_cbor()
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)
            .and_then(|profile_bytes| {
                members.push(BundleMemberV1::profile(profile_bytes));
                members.sort_by(|a, b| a.path.cmp(&b.path));
                let descriptors = members
                    .iter()
                    .map(|member| BundleMemberDescriptorV1 {
                        path: member.path.clone(),
                        size_bytes: u64::try_from(member.bytes.len()).unwrap_or(u64::MAX),
                        digest: member.digest,
                        role: member.role,
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
            })
    }
    /// Sign the canonical manifest after revalidating the complete unsigned bundle.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error when validation, encoding, or signature verification fails.
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, BundleContractErrorV1> {
        self.validate_unsigned().and_then(|()| {
            self.signer_public_key = PublicKey::from_bytes(key.verifying_key().to_bytes());
            self.manifest_bytes()
                .map(|manifest| {
                    self.signature = Signature::from_bytes(key.sign(&manifest).to_bytes());
                })
                .and_then(|()| self.validate())
                .map(|()| self)
        })
    }
    /// Decode and validate exact canonical CFB1 archive bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error for malformed, noncanonical, oversized, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleContractErrorV1> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFORMANCE_BUNDLE_BYTES_V1 {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        decode(bytes).and_then(|value| {
            array(&value, 4).and_then(|fields| {
                decode_manifest(&fields[0]).and_then(|manifest| {
                    array_values(&fields[1]).and_then(|member_values| {
                        member_values
                            .iter()
                            .map(decode_member)
                            .collect::<Result<Vec<_>, _>>()
                            .and_then(|members| {
                                digest::<32>(&fields[2]).and_then(|public_key| {
                                    digest::<64>(&fields[3]).and_then(|signature| {
                                        let bundle = Self {
                                            manifest,
                                            members,
                                            signer_public_key: PublicKey::from_bytes(public_key),
                                            signature: Signature::from_bytes(signature),
                                        };
                                        bundle.validate().map(|()| bundle)
                                    })
                                })
                            })
                    })
                })
            })
        })
    }
    /// Validate member closure, descriptor bindings, profile/provider contracts, and signature.
    ///
    /// # Errors
    ///
    /// Returns a closed bundle error for the first rejected invariant.
    pub fn validate(&self) -> Result<(), BundleContractErrorV1> {
        self.validate_unsigned().and_then(|()| {
            signing::verifying_key_from_public_key(&self.signer_public_key)
                .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                .and_then(|key| {
                    self.manifest_bytes().and_then(|manifest| {
                        signing::verify(&key, &CanonicalBytes::from_vec(manifest), &self.signature)
                            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                    })
                })
        })
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
        self.validate().and_then(|()| encode(&archive_value(self)))
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
        let maximum_items = usize::try_from(MAX_CONFORMANCE_ITEMS_V1).unwrap_or(usize::MAX);
        if self.members.len() != self.manifest.members.len()
            || self.members.len() > maximum_items
            || self.manifest.expected_results.len() > maximum_items
            || self
                .members
                .iter()
                .try_fold(0_u64, |total, member| {
                    total.checked_add(u64::try_from(member.bytes.len()).unwrap_or(u64::MAX))
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
        member_by_role_and_path(&self.members, BundleMemberRoleV1::Profile, PROFILE_PATH).and_then(
            |profile_member| {
                ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)
                    .map_err(|_| BundleContractErrorV1::ProfileInvalid)
                    .and_then(|profile| {
                        if profile.profile_digest != self.manifest.profile_digest {
                            return Err(BundleContractErrorV1::ProfileInvalid);
                        }
                        validate_member_descriptors(&self.members, &self.manifest.members)
                            .and_then(|()| {
                                validate_profile_support_members(&profile, &self.members)
                            })
                            .and_then(|()| validate_provider_members(&profile, &self.members))
                            .and_then(|()| {
                                validate_fixture_members(
                                    &profile,
                                    self.manifest.mode,
                                    &self.members,
                                    &self.manifest.expected_results,
                                )
                            })
                            .and_then(|()| {
                                validate_member_closure(
                                    &profile,
                                    &self.members,
                                    &self.manifest.expected_results,
                                )
                            })
                    })
            },
        )
    }
}

fn validate_profile_support_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let bindings = [
        (
            NORMATIVE_SPEC_PATH,
            BundleMemberRoleV1::NormativeSpecification,
            profile.normative_spec_digest,
        ),
        (
            EXECUTION_MATRIX_PATH,
            BundleMemberRoleV1::ExecutionMatrix,
            profile.execution_matrix_digest,
        ),
        (
            LIMITATIONS_PATH,
            BundleMemberRoleV1::Limitations,
            profile.limitations_digest,
        ),
        (
            PUBLICATION_REVIEW_PATH,
            BundleMemberRoleV1::Provenance,
            profile.provenance_digest,
        ),
        (
            PROFILE_SCHEMA_PATH,
            BundleMemberRoleV1::Schema,
            profile.fixture_contract_policy_digest,
        ),
    ];
    bindings
        .into_iter()
        .try_for_each(|(path, role, digest)| {
            member_by_role_and_path(members, role, path).and_then(|member| {
                if member.digest == digest {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
        .and_then(|()| validate_fixture_provenance_members(profile, members))
        .and_then(|()| {
            member_by_role_and_path(
                members,
                BundleMemberRoleV1::AuthorityInventory,
                AUTHORITY_INVENTORY_PATH,
            )
            .map(|_| ())
        })
}

fn validate_fixture_provenance_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    profile.fixtures.iter().try_for_each(|fixture| {
        let provenance = &fixture.provenance;
        [
            (
                NOTICE_PATH,
                BundleMemberRoleV1::Notice,
                provenance.notices_digest,
            ),
            (SBOM_PATH, BundleMemberRoleV1::Sbom, provenance.sbom_digest),
            (
                SOURCE_PROVENANCE_PATH,
                BundleMemberRoleV1::Provenance,
                provenance.source_digest,
            ),
            (
                BUILD_PROVENANCE_PATH,
                BundleMemberRoleV1::Provenance,
                provenance.build_digest,
            ),
            (
                PUBLICATION_REVIEW_PATH,
                BundleMemberRoleV1::Provenance,
                provenance.publication_review_digest,
            ),
            (
                LIMITATIONS_PATH,
                BundleMemberRoleV1::Limitations,
                provenance.limitations_digest,
            ),
        ]
        .into_iter()
        .try_for_each(|(path, role, digest)| {
            member_by_role_and_path(members, role, path).and_then(|member| {
                if member.digest == digest {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
    })
}

fn validate_member_closure(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
    expected: &[BundleExpectedResultV1],
) -> Result<(), BundleContractErrorV1> {
    let mut declared = [
        PROFILE_PATH,
        NORMATIVE_SPEC_PATH,
        EXECUTION_MATRIX_PATH,
        AUTHORITY_INVENTORY_PATH,
        PROFILE_SCHEMA_PATH,
        LIMITATIONS_PATH,
        SOURCE_PROVENANCE_PATH,
        BUILD_PROVENANCE_PATH,
        PUBLICATION_REVIEW_PATH,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    declared.insert(
        profile
            .fixture_provider_registry
            .registry_artifact
            .member_path
            .clone(),
    );
    for fixture in &profile.fixtures {
        declared.insert(fixture.schema.member_path.clone());
        declared.insert(fixture.payload.member_path.clone());
        declared.extend(
            fixture
                .auxiliary
                .iter()
                .map(|artifact| artifact.member_path.clone()),
        );
        if let Some(output) = &fixture.strict_oracle.output {
            declared.insert(output.member_path.clone());
        }
    }
    declared.extend(expected.iter().map(|result| result.member_path.clone()));
    declare_provider_members(members, &mut declared)?;
    if members.iter().all(|member| declared.contains(&member.path)) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::UndeclaredMember)
    }
}

fn declare_provider_members(
    members: &[BundleMemberV1],
    declared: &mut BTreeSet<String>,
) -> Result<(), BundleContractErrorV1> {
    let registry_member = member_by_role_and_path(
        members,
        BundleMemberRoleV1::FixtureProviderRegistry,
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
    )?;
    let registry = FixtureProviderRegistryV1::from_canonical_cbor(&registry_member.bytes)
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    for entry in registry.providers {
        declared.insert(entry.provider_package_descriptor.member_path.clone());
        let package_member = descriptor_member(
            members,
            &entry.provider_package_descriptor,
            BundleMemberRoleV1::FixtureProviderPackage,
        )?;
        let package = FixtureProviderPackageV1::from_canonical_cbor(&package_member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        declared.extend(
            package
                .family_schemas
                .iter()
                .map(|schema| schema.schema_descriptor.member_path.clone()),
        );
        declared.extend(
            [
                &package.licence_descriptor,
                &package.notices_descriptor,
                &package.sbom_descriptor,
                &package.source_provenance_descriptor,
                &package.limitations_descriptor,
            ]
            .into_iter()
            .map(|descriptor| descriptor.member_path.clone()),
        );
    }
    Ok(())
}

fn validate_member_descriptors(
    members: &[BundleMemberV1],
    descriptors: &[BundleMemberDescriptorV1],
) -> Result<(), BundleContractErrorV1> {
    if members.iter().zip(descriptors).any(|(member, descriptor)| {
        member.path != descriptor.path
            || member.role != descriptor.role
            || member.digest != descriptor.digest
            || descriptor.size_bytes != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
            || member.digest != *blake3::hash(&member.bytes).as_bytes()
    }) {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    } else {
        Ok(())
    }
}

fn validate_provider_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let binding = &profile.fixture_provider_registry;
    descriptor_member(
        members,
        &binding.registry_artifact,
        BundleMemberRoleV1::FixtureProviderRegistry,
    )
    .and_then(|registry_member| {
        FixtureProviderRegistryV1::from_canonical_cbor(&registry_member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)
    })
    .and_then(|registry| validate_provider_registry(profile, members, &registry))
}

fn validate_provider_registry(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
    registry: &FixtureProviderRegistryV1,
) -> Result<(), BundleContractErrorV1> {
    let binding = &profile.fixture_provider_registry;
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
    registry
        .providers
        .iter()
        .try_for_each(|entry| validate_provider_entry(profile, members, entry))
}

fn validate_provider_entry(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
    entry: &crate::FixtureProviderEntryV1,
) -> Result<(), BundleContractErrorV1> {
    descriptor_member(
        members,
        &entry.provider_package_descriptor,
        BundleMemberRoleV1::FixtureProviderPackage,
    )
    .and_then(|member| {
        FixtureProviderPackageV1::from_canonical_cbor(&member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)
            .and_then(|package| {
                package
                    .validate_registry_binding(entry, &member.bytes)
                    .map_err(|_| BundleContractErrorV1::ProfileInvalid)
                    .and_then(|()| validate_provider_support_members(members, &package))
                    .and_then(|()| validate_provider_fixtures(profile, entry, &package))
            })
    })
}

fn validate_provider_fixtures(
    profile: &ConformanceProfileV1,
    entry: &crate::FixtureProviderEntryV1,
    package: &FixtureProviderPackageV1,
) -> Result<(), BundleContractErrorV1> {
    if !profile
        .fixture_provider_registry
        .required_provider_keys
        .contains(&entry.provider_key)
    {
        return Ok(());
    }
    profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.provider_key == entry.provider_key)
        .try_for_each(|fixture| {
            let family = match fixture.family {
                FixtureFamilyV1::Positive => 0,
                FixtureFamilyV1::Denied => 1,
                FixtureFamilyV1::Malformed => 2,
                FixtureFamilyV1::ResourceExhaustion => 3,
                FixtureFamilyV1::DeletionRedaction => 4,
                FixtureFamilyV1::Downgrade => 5,
                FixtureFamilyV1::IndependentEvaluation => 6,
            };
            if fixture.claim_layer == entry.claim_layer
                && fixture.subject_adapter == entry.subject_adapter
                && package
                    .family_schemas
                    .get(family)
                    .is_some_and(|schema| schema.schema_descriptor == fixture.schema)
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
}

fn validate_provider_support_members(
    members: &[BundleMemberV1],
    package: &FixtureProviderPackageV1,
) -> Result<(), BundleContractErrorV1> {
    package
        .family_schemas
        .iter()
        .try_for_each(|schema| {
            descriptor_member(
                members,
                &schema.schema_descriptor,
                BundleMemberRoleV1::Schema,
            )
            .map(|_| ())
        })
        .and_then(|()| {
            descriptor_member(
                members,
                &package.licence_descriptor,
                BundleMemberRoleV1::Licence,
            )
            .map(|_| ())
        })
        .and_then(|()| {
            descriptor_member(
                members,
                &package.notices_descriptor,
                BundleMemberRoleV1::Notice,
            )
            .map(|_| ())
        })
        .and_then(|()| {
            descriptor_member(members, &package.sbom_descriptor, BundleMemberRoleV1::Sbom)
                .map(|_| ())
        })
        .and_then(|()| {
            descriptor_member(
                members,
                &package.source_provenance_descriptor,
                BundleMemberRoleV1::Provenance,
            )
            .map(|_| ())
        })
        .and_then(|()| {
            descriptor_member(
                members,
                &package.limitations_descriptor,
                BundleMemberRoleV1::Limitations,
            )
            .map(|_| ())
        })
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
    let members_valid = profile
        .fixtures
        .iter()
        .filter(|f| f.modes.contains(&mode.execution()))
        .try_for_each(|fixture| {
            descriptor_member(members, &fixture.payload, BundleMemberRoleV1::FixtureInput)
                .and_then(|_| {
                    fixture.auxiliary.iter().try_for_each(|artifact| {
                        descriptor_member(members, artifact, BundleMemberRoleV1::FixtureInput)
                            .or_else(|_| {
                                descriptor_member(
                                    members,
                                    artifact,
                                    BundleMemberRoleV1::ExpectedResult,
                                )
                            })
                            .map(|_| ())
                    })
                })
                .and_then(|()| {
                    expected
                        .iter()
                        .find(|result| {
                            result.case_id == fixture.case_id
                                && result.claim_layer == fixture.claim_layer
                                && result.execution_profile_digest
                                    == fixture.execution_profile_digest
                                && result.mode == mode
                        })
                        .ok_or(BundleContractErrorV1::ExpectedResultMismatch)
                })
                .and_then(|result| {
                    member_by_role_and_path(
                        members,
                        BundleMemberRoleV1::ExpectedResult,
                        &result.member_path,
                    )
                    .map(|member| (result, member))
                })
                .and_then(|(result, member)| {
                    let expected_size = u64::try_from(member.bytes.len()).unwrap_or(u64::MAX);
                    fixture
                        .auxiliary
                        .iter()
                        .chain(fixture.strict_oracle.output.iter())
                        .find(|artifact| {
                            (
                                artifact.member_path.as_str(),
                                artifact.blake3_digest,
                                artifact.byte_length,
                            ) == (result.member_path.as_str(), result.digest, expected_size)
                        })
                        .ok_or(BundleContractErrorV1::ExpectedResultMismatch)
                })
                .and_then(|artifact| {
                    descriptor_member(members, artifact, BundleMemberRoleV1::ExpectedResult)
                        .map(|_| ())
                })
        });
    members_valid.and_then(|()| {
        let selected = profile
            .fixtures
            .iter()
            .filter(|fixture| fixture.modes.contains(&mode.execution()))
            .count();
        if expected.len() == selected {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        }
    })
}
fn member_by_role_and_path<'a>(
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
    member_by_role_and_path(members, r, &d.member_path).and_then(|member| {
        if member.digest == d.blake3_digest
            && u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) == d.byte_length
        {
            Ok(member)
        } else {
            Err(BundleContractErrorV1::MemberDigestMismatch)
        }
    })
}
fn decode_manifest(value: &Value) -> Result<BundleManifestV1, BundleContractErrorV1> {
    let Ok(fields) = array(value, 6) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (
        Ok(magic),
        Ok(lifecycle),
        Ok(mode),
        Ok(profile_digest),
        Ok(member_values),
        Ok(expected_values),
    ) = (
        text(&fields[0]),
        decode_lifecycle(&fields[1]),
        decode_mode(&fields[2]),
        digest(&fields[3]),
        array_values(&fields[4]),
        array_values(&fields[5]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(members), Ok(expected_results)) = (
        member_values
            .iter()
            .map(decode_member_descriptor)
            .collect::<Result<Vec<_>, _>>(),
        expected_values
            .iter()
            .map(decode_expected_result)
            .collect::<Result<Vec<_>, _>>(),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    Ok(BundleManifestV1 {
        magic: magic.to_owned(),
        lifecycle,
        mode,
        profile_digest,
        members,
        expected_results,
    })
}

fn decode_lifecycle(value: &Value) -> Result<ProfileLifecycleV1, BundleContractErrorV1> {
    uint(value).and_then(|code| match code {
        0 => Ok(ProfileLifecycleV1::Draft),
        1 => Ok(ProfileLifecycleV1::Candidate),
        2 => Ok(ProfileLifecycleV1::Stable),
        3 => Ok(ProfileLifecycleV1::Retired),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    })
}

fn decode_member_descriptor(
    value: &Value,
) -> Result<BundleMemberDescriptorV1, BundleContractErrorV1> {
    let Ok(fields) = array(value, 4) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(path), Ok(size_bytes), Ok(digest), Ok(role)) = (
        text(&fields[0]),
        uint(&fields[1]),
        digest(&fields[2]),
        decode_role(&fields[3]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    Ok(BundleMemberDescriptorV1 {
        path: path.to_owned(),
        size_bytes,
        digest,
        role,
    })
}

fn decode_expected_result(value: &Value) -> Result<BundleExpectedResultV1, BundleContractErrorV1> {
    let Ok(fields) = array(value, 6) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (
        Ok(case_id),
        Ok(claim_layer),
        Ok(execution_profile_digest),
        Ok(mode),
        Ok(member_path),
        Ok(digest),
    ) = (
        text(&fields[0]),
        uint(&fields[1]).and_then(|code| {
            u8::try_from(code)
                .ok()
                .and_then(crate::ClaimLayerV1::from_wire_code)
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)
        }),
        digest(&fields[2]),
        decode_mode(&fields[3]),
        text(&fields[4]),
        digest(&fields[5]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    Ok(BundleExpectedResultV1 {
        case_id: case_id.to_owned(),
        claim_layer,
        execution_profile_digest,
        mode,
        member_path: member_path.to_owned(),
        digest,
    })
}
fn decode_member(value: &Value) -> Result<BundleMemberV1, BundleContractErrorV1> {
    array(value, 3).and_then(|fields| {
        text(&fields[0]).and_then(|path| {
            bytes(&fields[1]).and_then(|raw| {
                decode_role(&fields[2])
                    .map(|role| BundleMemberV1::new(path.to_owned(), raw.to_vec(), role))
            })
        })
    })
}
fn decode_mode(value: &Value) -> Result<BundleModeV1, BundleContractErrorV1> {
    uint(value).and_then(|code| match code {
        0 => Ok(BundleModeV1::Local),
        1 => Ok(BundleModeV1::AirGapped),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    })
}
fn decode_role(value: &Value) -> Result<BundleMemberRoleV1, BundleContractErrorV1> {
    uint(value).and_then(|code| match code {
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
    })
}
/// Independently validate canonical CFB1, CPF1, FPR1, and FPP1 bytes without typed codecs.
///
/// # Errors
///
/// Returns a closed bundle error for malformed bytes or any failed archive-contract invariant.
pub fn verify_archive_independently(archive_bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    verify_archive_summary_independently(archive_bytes).map(|_| ())
}

fn verify_archive_summary_independently(
    archive_bytes: &[u8],
) -> Result<RawReleaseArchiveSummary, BundleContractErrorV1> {
    if u64::try_from(archive_bytes.len()).unwrap_or(u64::MAX) > MAX_CONFORMANCE_BUNDLE_BYTES_V1 {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    let value = decode(archive_bytes)?;
    let fields = array(&value, 4)?;
    let manifest = array(&fields[0], 6)?;
    let mode = raw_manifest_header(manifest)?;
    let summary = raw_archive_body(fields, manifest, mode)?;
    raw_archive_signature(fields)?;
    Ok(summary)
}

/// Independently validate the complete seven-profile, dual-mode release tree.
///
/// # Errors
///
/// Returns a closed bundle error if any archive is invalid, a profile mode pair
/// is incomplete, registries differ, or any registry provider is unreferenced.
pub fn verify_release_tree_independently(archives: &[&[u8]]) -> Result<(), BundleContractErrorV1> {
    let mut registry_bytes: Option<Vec<u8>> = None;
    let mut registry_providers: Option<BTreeSet<RawProviderKey>> = None;
    let mut profile_modes =
        BTreeMap::<[u8; 32], BTreeMap<u64, BTreeMap<(String, u64), Vec<u8>>>>::new();
    let mut claim_layers = BTreeSet::new();
    let mut referenced_providers = BTreeSet::new();

    for archive in archives {
        let summary = verify_archive_summary_independently(archive)?;
        if registry_bytes
            .as_ref()
            .is_some_and(|expected| expected != &summary.registry_bytes)
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        registry_bytes.get_or_insert(summary.registry_bytes);
        registry_providers.get_or_insert(summary.registry_providers);
        if profile_modes
            .entry(summary.profile_digest)
            .or_default()
            .insert(summary.mode, summary.expected_results)
            .is_some()
        {
            return Err(BundleContractErrorV1::ModeParityMismatch);
        }
        claim_layers.insert(summary.claim_layer);
        referenced_providers.extend(summary.required_providers);
    }

    if profile_modes.len() == 7
        && claim_layers == BTreeSet::from([0, 1, 2, 3, 4, 5, 6])
        && profile_modes.values().all(raw_mode_pair_has_parity)
        && registry_providers.as_ref() == Some(&referenced_providers)
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_mode_pair_has_parity(modes: &BTreeMap<u64, BTreeMap<(String, u64), Vec<u8>>>) -> bool {
    modes.len() == 2
        && modes
            .get(&0)
            .zip(modes.get(&1))
            .is_some_and(|(local, air_gapped)| local == air_gapped)
}

type RawProviderKey = (String, String, u64, u64);

struct RawReleaseArchiveSummary {
    profile_digest: [u8; 32],
    claim_layer: u64,
    mode: u64,
    registry_bytes: Vec<u8>,
    registry_providers: BTreeSet<RawProviderKey>,
    required_providers: BTreeSet<RawProviderKey>,
    expected_results: BTreeMap<(String, u64), Vec<u8>>,
}

fn raw_manifest_header(manifest: &[Value]) -> Result<u64, BundleContractErrorV1> {
    let magic = text(&manifest[0])?;
    let lifecycle = uint(&manifest[1])?;
    let mode = uint(&manifest[2])?;
    if magic == CONFORMANCE_BUNDLE_MAGIC_V1 && lifecycle == 0 && mode <= 1 {
        Ok(mode)
    } else {
        Err(BundleContractErrorV1::LifecycleInvalid)
    }
}

fn raw_archive_body(
    fields: &[Value],
    manifest: &[Value],
    mode: u64,
) -> Result<RawReleaseArchiveSummary, BundleContractErrorV1> {
    let member_values = array_values(&fields[1])?;
    let descriptors = array_values(&manifest[4])?;
    if member_values.len() != descriptors.len() {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    let members = member_values
        .iter()
        .zip(descriptors)
        .map(|(member, descriptor)| raw_member_descriptor_pair(member, descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    if members.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    raw_archive_profile(manifest, &members, mode)
}

struct RawArchiveMember<'a> {
    path: &'a str,
    bytes: &'a [u8],
    role: u64,
}

fn raw_member_descriptor_pair<'a>(
    member: &'a Value,
    descriptor: &Value,
) -> Result<RawArchiveMember<'a>, BundleContractErrorV1> {
    let (Ok(member_fields), Ok(descriptor_fields)) = (array(member, 3), array(descriptor, 4))
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (
        Ok(raw),
        Ok(member_path),
        Ok(descriptor_path),
        Ok(member_role),
        Ok(descriptor_role),
        Ok(descriptor_size),
        Ok(descriptor_digest),
    ) = (
        bytes(&member_fields[1]),
        text(&member_fields[0]),
        text(&descriptor_fields[0]),
        uint(&member_fields[2]),
        uint(&descriptor_fields[3]),
        uint(&descriptor_fields[1]),
        digest::<32>(&descriptor_fields[2]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let raw_size = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    if member_path == descriptor_path
        && member_role == descriptor_role
        && raw_size == descriptor_size
        && *blake3::hash(raw).as_bytes() == descriptor_digest
    {
        Ok(RawArchiveMember {
            path: member_path,
            bytes: raw,
            role: member_role,
        })
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn raw_archive_profile(
    manifest: &[Value],
    members: &[RawArchiveMember<'_>],
    mode: u64,
) -> Result<RawReleaseArchiveSummary, BundleContractErrorV1> {
    let profile_member = raw_member(members, PROFILE_PATH, 2)?;
    let profile = decode(profile_member.bytes)?;
    let profile_fields = array(&profile, 18)?;
    let raw_profile = raw_cpf1_value(profile_fields)?;
    if profile_fields[4] != manifest[1] {
        return Err(BundleContractErrorV1::LifecycleInvalid);
    }
    let profile_digest = raw_profile_digest(manifest, profile_fields)?;
    raw_profile_support_members(&raw_profile, members)?;
    let registry = raw_registry_and_packages(&raw_profile, members, mode)?;
    let expected_results = raw_expected_results(&manifest[5], &raw_profile, members, mode)?;
    raw_member_closure(
        &raw_profile.declared_paths,
        &expected_results.member_paths,
        &registry.declared_paths,
        members,
    )?;
    Ok(RawReleaseArchiveSummary {
        profile_digest,
        claim_layer: raw_profile.claim_layer,
        mode,
        registry_bytes: registry.bytes,
        registry_providers: registry.providers,
        required_providers: registry.required_providers,
        expected_results: expected_results.results,
    })
}

fn raw_profile_support_members(
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let bindings = [
        (NORMATIVE_SPEC_PATH, 3),
        (EXECUTION_MATRIX_PATH, 11),
        (PROFILE_SCHEMA_PATH, 4),
        (LIMITATIONS_PATH, 9),
        (PUBLICATION_REVIEW_PATH, 8),
    ];
    for ((path, role), expected_digest) in bindings.into_iter().zip(profile.support_digests) {
        let member = raw_member(members, path, role)?;
        let member_digest = *blake3::hash(member.bytes).as_bytes();
        if member_digest != expected_digest {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    raw_fixture_provenance_members(&profile.fixtures, members)
        .and_then(|()| raw_member(members, AUTHORITY_INVENTORY_PATH, 10).map(|_| ()))
}

fn raw_fixture_provenance_members(
    fixtures: &[RawFixtureSummary],
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    for fixture in fixtures {
        let bindings = [
            (NOTICE_PATH, 6),
            (SBOM_PATH, 7),
            (SOURCE_PROVENANCE_PATH, 8),
            (BUILD_PROVENANCE_PATH, 8),
            (PUBLICATION_REVIEW_PATH, 8),
            (LIMITATIONS_PATH, 9),
        ];
        for ((path, role), expected_digest) in bindings.into_iter().zip(fixture.provenance) {
            let member = raw_member(members, path, role)?;
            if *blake3::hash(member.bytes).as_bytes() != expected_digest {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
        }
    }
    Ok(())
}

fn raw_member_closure(
    profile_paths: &BTreeSet<String>,
    expected_paths: &BTreeSet<String>,
    provider_paths: &BTreeSet<String>,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let mut declared = [
        PROFILE_PATH,
        NORMATIVE_SPEC_PATH,
        EXECUTION_MATRIX_PATH,
        AUTHORITY_INVENTORY_PATH,
        PROFILE_SCHEMA_PATH,
        LIMITATIONS_PATH,
        SOURCE_PROVENANCE_PATH,
        BUILD_PROVENANCE_PATH,
        PUBLICATION_REVIEW_PATH,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    declared.extend(profile_paths.iter().cloned());
    declared.extend(expected_paths.iter().cloned());
    declared.extend(provider_paths.iter().cloned());
    let member_paths = members
        .iter()
        .map(|member| member.path.to_owned())
        .collect::<BTreeSet<_>>();
    if member_paths.len() == members.len() && member_paths.is_subset(&declared) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::UndeclaredMember)
    }
}

fn raw_profile_digest(
    manifest: &[Value],
    profile: &[Value],
) -> Result<[u8; 32], BundleContractErrorV1> {
    let profile_digest = digest::<32>(&profile[17])?;
    let bound = length_bound(&Value::Array(profile[..17].to_vec()))?;
    let manifest_digest = digest::<32>(&manifest[3])?;
    if profile_digest == digest_domain(b"PiglorOS.ConformanceProfile.v1\0", &bound)
        && profile_digest == manifest_digest
    {
        Ok(profile_digest)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_archive_signature(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    digest::<32>(&fields[2]).and_then(|key| {
        digest::<64>(&fields[3]).and_then(|signature| {
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                .and_then(|verifying_key| {
                    encode(&fields[0]).and_then(|manifest| {
                        verifying_key
                            .verify(&manifest, &ed25519_dalek::Signature::from_bytes(&signature))
                            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                    })
                })
        })
    })
}
struct RawCpf1Summary {
    claim_layer: u64,
    declared_paths: BTreeSet<String>,
    required_providers: BTreeSet<RawProviderKey>,
    fixtures: Vec<RawFixtureSummary>,
    support_digests: [[u8; 32]; 5],
    registry: RawArtifact,
}

fn raw_cpf1_value(profile_fields: &[Value]) -> Result<RawCpf1Summary, BundleContractErrorV1> {
    let support_digests = raw_cpf1_header(profile_fields)?;
    let executions = raw_execution_digests(&profile_fields[7])?;
    let (registry, required_providers) = raw_provider_binding(&profile_fields[8])?;
    let deterministic_caps = raw_protocol(&profile_fields[11])?;
    let mut fixture_collection = raw_fixtures(&profile_fields[9], &deterministic_caps)?;
    let claim_layer = fixture_collection.fixtures[0].claim_layer;
    fixture_collection
        .declared_paths
        .insert(registry.path.clone());
    let allowed = raw_allowed_divergences(&profile_fields[10])?;
    raw_profile_fixture_relationships(
        &required_providers,
        &executions,
        &fixture_collection.fixtures,
        &allowed,
        claim_layer,
    )?;
    raw_independence(&profile_fields[12])?;
    raw_nullable_digest(&profile_fields[16])?;
    Ok(RawCpf1Summary {
        claim_layer,
        declared_paths: fixture_collection.declared_paths,
        required_providers,
        fixtures: fixture_collection.fixtures,
        support_digests,
        registry,
    })
}

fn raw_allowed_divergences(
    value: &Value,
) -> Result<BTreeSet<RawDivergence>, BundleContractErrorV1> {
    array_values(value).and_then(|divergences| {
        let mut allowed = BTreeSet::new();
        let mut previous = None;
        for divergence in divergences {
            let current = raw_divergence(divergence)?;
            if previous.as_ref().is_some_and(|old| old >= &current) {
                return Err(BundleContractErrorV1::NonCanonicalOrder);
            }
            previous = Some(current.clone());
            allowed.insert(current);
        }
        Ok(allowed)
    })
}

fn raw_profile_fixture_relationships(
    required: &BTreeSet<RawProviderKey>,
    executions: &BTreeSet<[u8; 32]>,
    fixtures: &[RawFixtureSummary],
    allowed: &BTreeSet<RawDivergence>,
    claim_layer: u64,
) -> Result<(), BundleContractErrorV1> {
    raw_fixture_inventory(required, executions, fixtures)?;
    fixtures.iter().try_for_each(|fixture| {
        if !required.contains(&fixture.provider) || !executions.contains(&fixture.execution) {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        raw_fixture_oracle_relationships(fixture, allowed)
            .and_then(|()| raw_fixture_claim_relationship(fixture))
            .and_then(|()| raw_fixture_downgrade_relationship(fixture))
    })?;
    if fixtures
        .iter()
        .all(|fixture| fixture.claim_layer == claim_layer)
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_fixture_inventory(
    required: &BTreeSet<RawProviderKey>,
    executions: &BTreeSet<[u8; 32]>,
    fixtures: &[RawFixtureSummary],
) -> Result<(), BundleContractErrorV1> {
    let mut inventory = BTreeMap::<(RawProviderKey, [u8; 32], u64), BTreeSet<usize>>::new();
    let mut required_modes = BTreeMap::<[u8; 32], BTreeSet<u64>>::new();
    for fixture in fixtures {
        for mode in &fixture.modes {
            required_modes
                .entry(fixture.execution)
                .or_default()
                .insert(*mode);
            let coordinate = (fixture.provider.clone(), fixture.execution, *mode);
            if !inventory
                .entry(coordinate)
                .or_default()
                .insert(fixture.family)
            {
                return Err(BundleContractErrorV1::NonCanonicalOrder);
            }
        }
    }
    let required_families = (0_usize..=6).collect::<BTreeSet<_>>();
    for provider in required {
        for execution in executions {
            let Some(modes) = required_modes.get(execution) else {
                return Err(BundleContractErrorV1::ProfileInvalid);
            };
            for mode in modes {
                if inventory
                    .get(&(provider.clone(), *execution, *mode))
                    .is_none_or(|families| families != &required_families)
                {
                    return Err(BundleContractErrorV1::ProfileInvalid);
                }
            }
        }
    }
    Ok(())
}

fn raw_fixture_oracle_relationships(
    fixture: &RawFixtureSummary,
    allowed: &BTreeSet<RawDivergence>,
) -> Result<(), BundleContractErrorV1> {
    let result_is_valid = match &fixture.oracle {
        RawOracle::Output(_) => fixture.verification == 0 && fixture.failure.is_none(),
        RawOracle::Failure(failure) => {
            fixture.verification != 0
                && fixture.verification != 1
                && fixture.failure.as_ref() == Some(failure)
        }
        RawOracle::Divergence(divergence) => {
            fixture.verification == 1 && fixture.failure.is_none() && allowed.contains(divergence)
        }
    };
    if !result_is_valid {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    if let RawOracle::Failure((owner, version, _)) = &fixture.oracle {
        if owner != "pigloros.core"
            && (owner != &fixture.provider.0 || version != &fixture.provider.1)
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    Ok(())
}

const fn raw_fixture_claim_relationship(
    fixture: &RawFixtureSummary,
) -> Result<(), BundleContractErrorV1> {
    if fixture.replay == 4
        || matches!(
            (fixture.redaction, fixture.replay),
            (0, _) | (1, 1) | (2, 2) | (3, 3)
        )
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_fixture_downgrade_relationship(
    fixture: &RawFixtureSummary,
) -> Result<(), BundleContractErrorV1> {
    if fixture.family != 5 {
        return if fixture.trust_snapshot.is_none()
            && fixture.release_admission.is_none()
            && fixture.transition.is_none()
        {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ProfileInvalid)
        };
    }
    if fixture.trust_snapshot.is_some_and(|value| value != [0; 32])
        && fixture
            .release_admission
            .is_some_and(|value| value != [0; 32])
        && fixture
            .transition
            .as_ref()
            .is_some_and(|(from, to)| from != to)
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_cpf1_header(fields: &[Value]) -> Result<[[u8; 32]; 5], BundleContractErrorV1> {
    let (
        Ok(magic),
        Ok(version),
        Ok(profile_id),
        Ok(semantic_version),
        Ok(lifecycle),
        Ok(normative_spec),
        Ok(execution_matrix),
        Ok(limitations),
        Ok(provenance),
        Ok(provider_registry),
    ) = (
        text(&fields[0]),
        uint(&fields[1]),
        text(&fields[2]),
        text(&fields[3]),
        uint(&fields[4]),
        digest::<32>(&fields[5]),
        digest::<32>(&fields[6]),
        digest::<32>(&fields[13]),
        digest::<32>(&fields[14]),
        digest::<32>(&fields[15]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if magic == "CPF1"
        && version == 1
        && raw_identifier(profile_id, 128)
        && raw_semver(semantic_version)
        && lifecycle <= 3
        && normative_spec != [0; 32]
        && execution_matrix != [0; 32]
        && limitations != [0; 32]
        && provenance != [0; 32]
        && provider_registry != [0; 32]
    {
        Ok([
            normative_spec,
            execution_matrix,
            limitations,
            provenance,
            provider_registry,
        ])
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_execution_digests(value: &Value) -> Result<BTreeSet<[u8; 32]>, BundleContractErrorV1> {
    array_values(value).and_then(|executions| {
        raw_digests_ordered(executions).and_then(|ordered| {
            if !executions.is_empty() && executions.len() <= 64 && ordered {
                executions.iter().map(digest::<32>).collect()
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_provider_binding(
    value: &Value,
) -> Result<(RawArtifact, BTreeSet<RawProviderKey>), BundleContractErrorV1> {
    array(value, 2).and_then(|binding| {
        raw_artifact(&binding[0]).and_then(|registry| {
            array_values(&binding[1]).and_then(|provider_keys| {
                raw_provider_keys_ordered(provider_keys).and_then(|ordered| {
                    if provider_keys.is_empty() || !ordered {
                        return Err(BundleContractErrorV1::ProfileInvalid);
                    }
                    provider_keys
                        .iter()
                        .map(raw_provider_key)
                        .collect::<Result<BTreeSet<_>, _>>()
                        .map(|keys| (registry, keys))
                })
            })
        })
    })
}

fn raw_fixtures(
    value: &Value,
    deterministic_caps: &[u64; 8],
) -> Result<RawFixtureCollection, BundleContractErrorV1> {
    array_values(value).and_then(|fixtures| {
        raw_fixture_ordered(fixtures).and_then(|ordered| {
            if fixtures.is_empty() || fixtures.len() > 65_536 || !ordered {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            fixtures.iter().try_fold(
                RawFixtureCollection::default(),
                |mut collection, fixture| {
                    let summary = raw_fixture(fixture, deterministic_caps)?;
                    collection
                        .declared_paths
                        .extend(summary.artifact_paths.iter().cloned());
                    collection.fixtures.push(summary);
                    Ok(collection)
                },
            )
        })
    })
}

#[derive(Default)]
struct RawFixtureCollection {
    fixtures: Vec<RawFixtureSummary>,
    declared_paths: BTreeSet<String>,
}

struct RawFixtureSummary {
    case_id: String,
    claim_layer: u64,
    family: usize,
    provider: RawProviderKey,
    adapter: u64,
    execution: [u8; 32],
    modes: Vec<u64>,
    schema: RawArtifact,
    payload: RawArtifact,
    auxiliary: Vec<RawArtifact>,
    oracle: RawOracle,
    verification: u64,
    failure: Option<RawFailure>,
    replay: u64,
    redaction: u64,
    trust_snapshot: Option<[u8; 32]>,
    release_admission: Option<[u8; 32]>,
    transition: Option<(RawProviderKey, RawProviderKey)>,
    provenance: [[u8; 32]; 6],
    artifact_paths: BTreeSet<String>,
}

fn raw_fixture(
    value: &Value,
    deterministic_caps: &[u64; 8],
) -> Result<RawFixtureSummary, BundleContractErrorV1> {
    let Ok(fields) = array(value, 24) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(case_id), Ok(claim_layer), Ok(family), Ok(adapter), Ok(execution)) = (
        text(&fields[0]),
        uint(&fields[2]),
        uint(&fields[3]),
        uint(&fields[5]),
        digest::<32>(&fields[6]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let provider = raw_provider_key(&fields[4])?;
    let mode_values = array_values(&fields[7])?;
    let modes = raw_ordered_modes(mode_values)?;
    let network_allowed = raw_capabilities(&fields[18])?;
    let family = match family {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        6 => 6,
        _ => return Err(BundleContractErrorV1::ProfileInvalid),
    };
    if !raw_identifier(case_id, 128)
        || claim_layer > 6
        || adapter > 2
        || !matches!(&fields[1], Value::Bool(_))
        || network_allowed && (adapter == 2 || modes.contains(&1))
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    raw_budget(&fields[16], deterministic_caps)?;
    raw_watchdog(&fields[17])?;
    let schema = raw_artifact(&fields[8])?;
    let payload = raw_artifact(&fields[9])?;
    let auxiliary = raw_ordered_artifacts(array_values(&fields[10])?)?;
    if auxiliary.len() > 64 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let oracle = raw_oracle(&fields[11])?;
    let mut artifact_paths = [&schema, &payload]
        .into_iter()
        .chain(&auxiliary)
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    if let RawOracle::Output(output) = &oracle {
        artifact_paths.insert(output.path.clone());
    }
    let expected_artifact_count =
        auxiliary.len() + 2 + usize::from(matches!(&oracle, RawOracle::Output(_)));
    if artifact_paths.len() != expected_artifact_count {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let verification = uint(&fields[12])?;
    let failure = raw_optional_failure(&fields[13])?;
    let replay = uint(&fields[14])?;
    let redaction = uint(&fields[15])?;
    if verification > 5 || replay > 4 || redaction > 3 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let trust_snapshot = raw_optional_digest(&fields[19])?;
    let release_admission = raw_optional_digest(&fields[20])?;
    let provenance = raw_provenance(&fields[21])?;
    let transition = raw_optional_transition(&fields[22])?;
    let bound = length_bound(&Value::Array(fields[..23].to_vec()))?;
    if digest::<32>(&fields[23])? != digest_domain(b"PiglorOS.Conformance.Fixture.v1\0", &bound) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(RawFixtureSummary {
        case_id: case_id.to_owned(),
        claim_layer,
        family,
        provider,
        adapter,
        execution,
        modes,
        schema,
        payload,
        auxiliary,
        oracle,
        verification,
        failure,
        replay,
        redaction,
        trust_snapshot,
        release_admission,
        transition,
        provenance,
        artifact_paths,
    })
}

fn raw_nullable_digest(value: &Value) -> Result<(), BundleContractErrorV1> {
    raw_optional_digest(value).map(|_| ())
}

fn raw_optional_digest(value: &Value) -> Result<Option<[u8; 32]>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        digest::<32>(value).map(Some)
    }
}

fn raw_optional_failure(value: &Value) -> Result<Option<RawFailure>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        raw_failure(value).map(Some)
    }
}

type RawFailure = (String, String, String);

fn raw_failure(value: &Value) -> Result<RawFailure, BundleContractErrorV1> {
    array(value, 3).and_then(|fields| {
        text(&fields[0]).and_then(|owner| {
            text(&fields[1]).and_then(|version| {
                text(&fields[2]).and_then(|code| {
                    if owner.is_empty() || version.is_empty() || code.is_empty() {
                        Err(BundleContractErrorV1::ProfileInvalid)
                    } else {
                        Ok((owner.to_owned(), version.to_owned(), code.to_owned()))
                    }
                })
            })
        })
    })
}
fn raw_provenance(value: &Value) -> Result<[[u8; 32]; 6], BundleContractErrorV1> {
    array(value, 7).and_then(|fields| {
        text(&fields[0]).and_then(|licence| {
            if licence.is_empty() {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            let mut digests = [[0; 32]; 6];
            for (slot, value) in digests.iter_mut().zip(&fields[1..]) {
                *slot = digest::<32>(value)?;
                if *slot == [0; 32] {
                    return Err(BundleContractErrorV1::ProfileInvalid);
                }
            }
            Ok(digests)
        })
    })
}

fn raw_optional_transition(
    value: &Value,
) -> Result<Option<(RawProviderKey, RawProviderKey)>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        return Ok(None);
    }
    array(value, 2).and_then(|fields| {
        raw_provider_key(&fields[0])
            .and_then(|from| raw_provider_key(&fields[1]).map(|to| Some((from, to))))
    })
}
fn raw_protocol(value: &Value) -> Result<[u64; 8], BundleContractErrorV1> {
    array(value, 5).and_then(|fields| {
        text(&fields[0]).and_then(|version| {
            if version.is_empty() {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            fields[1..4]
                .iter()
                .try_for_each(|value| {
                    digest::<32>(value).and_then(|digest| {
                        if digest == [0; 32] {
                            Err(BundleContractErrorV1::ProfileInvalid)
                        } else {
                            Ok(())
                        }
                    })
                })
                .and_then(|()| {
                    array(&fields[4], 18).and_then(|caps| {
                        let maxima = [
                            16 * 1024 * 1024,
                            65_536,
                            65_536,
                            256,
                            64 * 1024 * 1024,
                            1024 * 1024 * 1024,
                            100,
                            32,
                            128,
                            1024 * 1024,
                            1024 * 1024 * 1024,
                            1_000_000_000,
                            1_000_000,
                            1_000_000,
                            64 * 1024 * 1024,
                            1024 * 1024 * 1024,
                            1_000_000_000,
                            86_400_000_000_000,
                        ];
                        let values = caps.iter().map(uint).collect::<Result<Vec<_>, _>>()?;
                        let valid =
                            values
                                .iter()
                                .zip(maxima)
                                .enumerate()
                                .all(|(index, (cap, maximum))| {
                                    *cap <= maximum && (index == 9 || *cap > 0)
                                });
                        if !valid {
                            return Err(BundleContractErrorV1::ProfileInvalid);
                        }
                        Ok([
                            values[10], values[11], values[12], values[13], values[14], values[15],
                            values[16], values[17],
                        ])
                    })
                })
        })
    })
}
fn raw_independence(value: &Value) -> Result<(), BundleContractErrorV1> {
    array(value, 5).and_then(|fields| {
        digest::<32>(&fields[3]).and_then(|shared_code_audit| {
            digest::<32>(&fields[4]).and_then(|declaration| {
                if fields[..3]
                    .iter()
                    .all(|value| matches!(value, Value::Bool(_)))
                    && shared_code_audit != [0; 32]
                    && declaration != [0; 32]
                {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        })
    })
}

fn raw_member<'a, 'member>(
    members: &'a [RawArchiveMember<'member>],
    path: &str,
    role: u64,
) -> Result<&'a RawArchiveMember<'member>, BundleContractErrorV1> {
    members
        .iter()
        .find(|member| member.path == path && member.role == role)
        .ok_or(BundleContractErrorV1::MemberMissing)
}

struct RawRegistrySummary {
    bytes: Vec<u8>,
    providers: BTreeSet<RawProviderKey>,
    required_providers: BTreeSet<RawProviderKey>,
    declared_paths: BTreeSet<String>,
}

struct RawProviderSummary {
    key: RawProviderKey,
    claim_layer: u64,
    adapter: u64,
    package: RawArtifact,
    schemas: Vec<RawArtifact>,
    declared_paths: BTreeSet<String>,
}

struct RawPackageSummary {
    schemas: Vec<RawArtifact>,
    declared_paths: BTreeSet<String>,
}

fn raw_registry_and_packages(
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: u64,
) -> Result<RawRegistrySummary, BundleContractErrorV1> {
    if profile.registry.path != FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let registry_member = raw_member(members, FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, 12)?;
    raw_artifact_matches_member(&profile.registry, registry_member)?;
    let registry = decode(registry_member.bytes)?;
    let fields = array(&registry, 4)?;
    raw_registry_fields(fields, registry_member.bytes, profile, members, mode)
}

fn raw_registry_fields(
    fields: &[Value],
    registry_bytes: &[u8],
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: u64,
) -> Result<RawRegistrySummary, BundleContractErrorV1> {
    if text(&fields[0])? != "FPR1" || uint(&fields[1])? != 1 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let providers = array_values(&fields[2])?;
    if providers.is_empty() || !raw_provider_entries_ordered(providers)? {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    raw_registry_digest(fields)?;
    let provider_summaries = providers
        .iter()
        .map(|provider| raw_provider_package(provider, members))
        .collect::<Result<Vec<_>, _>>()?;
    let provider_keys = provider_summaries
        .iter()
        .map(|provider| provider.key.clone())
        .collect::<BTreeSet<_>>();
    if !profile.required_providers.is_subset(&provider_keys) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    raw_declared_packages(members, &provider_summaries)?;
    raw_fixture_provider_bindings(&profile.fixtures, &provider_summaries, members, mode)?;
    let declared_paths = provider_summaries
        .iter()
        .flat_map(|provider| provider.declared_paths.iter().cloned())
        .collect();
    Ok(RawRegistrySummary {
        bytes: registry_bytes.to_vec(),
        providers: provider_keys,
        required_providers: profile.required_providers.clone(),
        declared_paths,
    })
}

fn raw_fixture_provider_bindings(
    fixtures: &[RawFixtureSummary],
    providers: &[RawProviderSummary],
    members: &[RawArchiveMember<'_>],
    mode: u64,
) -> Result<(), BundleContractErrorV1> {
    fixtures
        .iter()
        .filter(|fixture| fixture.modes.contains(&mode))
        .try_for_each(|fixture| {
            let provider = providers
                .iter()
                .find(|candidate| {
                    (&candidate.key, candidate.claim_layer, candidate.adapter)
                        == (&fixture.provider, fixture.claim_layer, fixture.adapter)
                })
                .ok_or(BundleContractErrorV1::ProfileInvalid)?;
            raw_fixture_schema_binding(fixture, provider)
                .and_then(|()| raw_bound_raw_artifact(&fixture.payload, members, 0))
                .and_then(|()| {
                    fixture
                        .auxiliary
                        .iter()
                        .try_for_each(|artifact| raw_bound_raw_artifact_any(artifact, members))
                })
                .and_then(|()| match &fixture.oracle {
                    RawOracle::Output(output) => raw_bound_raw_artifact_any(output, members),
                    RawOracle::Failure(_) | RawOracle::Divergence(_) => Ok(()),
                })
        })
}

fn raw_fixture_schema_binding(
    fixture: &RawFixtureSummary,
    provider: &RawProviderSummary,
) -> Result<(), BundleContractErrorV1> {
    let schema = &provider.schemas[fixture.family];
    if schema.path == fixture.schema.path
        && schema.size == fixture.schema.size
        && schema.digest == fixture.schema.digest
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_bound_raw_artifact_any(
    artifact: &RawArtifact,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let member = members
        .iter()
        .find(|member| member.path == artifact.path)
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    raw_artifact_matches_member(artifact, member)
}

fn raw_bound_raw_artifact(
    artifact: &RawArtifact,
    members: &[RawArchiveMember<'_>],
    role: u64,
) -> Result<(), BundleContractErrorV1> {
    raw_member(members, &artifact.path, role)
        .and_then(|member| raw_artifact_matches_member(artifact, member))
}

fn raw_artifact_matches_member(
    artifact: &RawArtifact,
    member: &RawArchiveMember<'_>,
) -> Result<(), BundleContractErrorV1> {
    if u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) == artifact.size
        && *blake3::hash(member.bytes).as_bytes() == artifact.digest
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn raw_registry_digest(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    length_bound(&Value::Array(fields[..3].to_vec())).and_then(|bound| {
        digest::<32>(&fields[3]).and_then(|recorded| {
            let computed = digest_domain(b"PiglorOS.Conformance.ProviderRegistry.v1\0", &bound);
            if computed == recorded {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_declared_packages(
    members: &[RawArchiveMember<'_>],
    providers: &[RawProviderSummary],
) -> Result<(), BundleContractErrorV1> {
    if members.iter().all(|member| {
        member.role != 13
            || providers
                .iter()
                .any(|provider| member.path == provider.package.path)
    }) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::UndeclaredMember)
    }
}

fn raw_provider_package(
    provider: &Value,
    members: &[RawArchiveMember<'_>],
) -> Result<RawProviderSummary, BundleContractErrorV1> {
    array(provider, 7).and_then(|entry| {
        raw_provider_key(&Value::Array(entry[..4].to_vec())).and_then(|key| {
            uint(&entry[4]).and_then(|claim_layer| {
                uint(&entry[5]).and_then(|adapter| {
                    if claim_layer > 6 || adapter > 2 {
                        return Err(BundleContractErrorV1::ProfileInvalid);
                    }
                    raw_artifact(&entry[6]).and_then(|package| {
                        raw_member(members, &package.path, 13).and_then(|package_member| {
                            raw_artifact_matches_member(&package, package_member).and_then(|()| {
                                raw_fpp1(package_member.bytes, entry, members).map(
                                    |package_summary| {
                                        let mut declared_paths = package_summary.declared_paths;
                                        declared_paths.insert(package.path.clone());
                                        RawProviderSummary {
                                            key,
                                            claim_layer,
                                            adapter,
                                            package,
                                            schemas: package_summary.schemas,
                                            declared_paths,
                                        }
                                    },
                                )
                            })
                        })
                    })
                })
            })
        })
    })
}

fn raw_fpp1(
    bytes_value: &[u8],
    entry: &[Value],
    members: &[RawArchiveMember<'_>],
) -> Result<RawPackageSummary, BundleContractErrorV1> {
    decode(bytes_value).and_then(|value| {
        array(&value, 12).and_then(|fields| {
            raw_fpp1_header(fields, entry)?;
            let declared_paths = raw_fpp1_paths(fields)?;
            let schemas = raw_fpp1_schemas(&fields[5], members)?;
            raw_fpp1_support(&fields[6..11], members)?;
            raw_fpp1_digest(fields)?;
            Ok(RawPackageSummary {
                schemas,
                declared_paths,
            })
        })
    })
}

fn raw_fpp1_paths(fields: &[Value]) -> Result<BTreeSet<String>, BundleContractErrorV1> {
    let schemas = array_values(&fields[5])?;
    let schema_paths = schemas.iter().map(|schema| {
        let record = array(schema, 2)?;
        let descriptor = array(&record[1], 4)?;
        text(&descriptor[0])
    });
    let support_paths = fields[6..11]
        .iter()
        .map(|descriptor| array(descriptor, 4).and_then(|record| text(&record[0])));
    let mut paths = BTreeSet::new();
    for path in schema_paths.chain(support_paths) {
        if !paths.insert(path?.to_owned()) {
            return Err(BundleContractErrorV1::NonCanonicalOrder);
        }
    }
    Ok(paths)
}

fn raw_fpp1_header(fields: &[Value], entry: &[Value]) -> Result<(), BundleContractErrorV1> {
    text(&fields[0]).and_then(|magic| {
        uint(&fields[1]).and_then(|version| {
            if magic == "FPP1"
                && version == 1
                && fields[2] == Value::Array(entry[..4].to_vec())
                && fields[3] == entry[4]
                && fields[4] == entry[5]
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_fpp1_schemas(
    value: &Value,
    members: &[RawArchiveMember<'_>],
) -> Result<Vec<RawArtifact>, BundleContractErrorV1> {
    array_values(value).and_then(|schemas| {
        if schemas.len() != 7 {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        schemas
            .iter()
            .enumerate()
            .map(|(index, schema)| {
                array(schema, 2).and_then(|record| {
                    uint(&record[0]).and_then(|family| {
                        if family != u64::try_from(index).unwrap_or(u64::MAX) {
                            return Err(BundleContractErrorV1::ProfileInvalid);
                        }
                        raw_artifact(&record[1]).and_then(|artifact| {
                            raw_bound_raw_artifact(&artifact, members, 4).map(|()| artifact)
                        })
                    })
                })
            })
            .collect()
    })
}

fn raw_fpp1_support(
    values: &[Value],
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    values
        .iter()
        .enumerate()
        .try_for_each(|(offset, descriptor)| {
            let role = 5 + u64::try_from(offset).unwrap_or(u64::MAX);
            raw_bound_artifact(descriptor, members, role)
        })
}

fn raw_bound_artifact(
    value: &Value,
    members: &[RawArchiveMember<'_>],
    role: u64,
) -> Result<(), BundleContractErrorV1> {
    raw_artifact(value).and_then(|artifact| raw_bound_raw_artifact(&artifact, members, role))
}

fn raw_fpp1_digest(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    length_bound(&Value::Array(fields[..11].to_vec())).and_then(|bound| {
        digest::<32>(&fields[11]).and_then(|recorded| {
            let computed = digest_domain(b"PiglorOS.Conformance.ProviderPackage.v1\0", &bound);
            if computed == recorded {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

struct RawExpectedResults {
    results: BTreeMap<(String, u64), Vec<u8>>,
    member_paths: BTreeSet<String>,
}

struct RawExpectedResult {
    key: (String, u64),
    bytes: Vec<u8>,
    path: String,
    order_key: RawExpectedOrderKey,
}

fn raw_expected_results(
    value: &Value,
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: u64,
) -> Result<RawExpectedResults, BundleContractErrorV1> {
    array_values(value).and_then(|expected| {
        let mut results = BTreeMap::new();
        let mut member_paths = BTreeSet::new();
        let mut previous = None;
        for record in expected {
            let result = raw_expected_result(record, profile, members, mode)?;
            if previous
                .as_ref()
                .is_some_and(|old| old >= &result.order_key)
            {
                return Err(BundleContractErrorV1::NonCanonicalOrder);
            }
            previous = Some(result.order_key);
            results.insert(result.key, result.bytes);
            member_paths.insert(result.path);
        }
        let selected = profile
            .fixtures
            .iter()
            .filter(|fixture| fixture.modes.contains(&mode))
            .count();
        if expected.len() == selected && results.len() == expected.len() {
            Ok(RawExpectedResults {
                results,
                member_paths,
            })
        } else {
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        }
    })
}

fn raw_expected_result(
    value: &Value,
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: u64,
) -> Result<RawExpectedResult, BundleContractErrorV1> {
    let Ok(fields) = array(value, 6) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (
        Ok(case_id),
        Ok(claim_layer),
        Ok(execution),
        Ok(record_mode),
        Ok(path),
        Ok(recorded_digest),
    ) = (
        text(&fields[0]),
        uint(&fields[1]),
        digest::<32>(&fields[2]),
        uint(&fields[3]),
        text(&fields[4]),
        digest::<32>(&fields[5]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if record_mode != mode {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    let member = raw_member(members, path, 1)?;
    let member_bytes = member.bytes;
    if *blake3::hash(member_bytes).as_bytes() != recorded_digest
        || !raw_expected_fixture_bound(
            &profile.fixtures,
            case_id,
            claim_layer,
            execution,
            path,
            recorded_digest,
            member_bytes.len(),
        )
    {
        Err(BundleContractErrorV1::ExpectedResultMismatch)
    } else {
        let case_id = case_id.to_owned();
        let path = path.to_owned();
        Ok(RawExpectedResult {
            key: (case_id.clone(), claim_layer),
            bytes: member_bytes.to_vec(),
            path: path.clone(),
            order_key: (
                case_id,
                claim_layer,
                execution,
                record_mode,
                path,
                recorded_digest,
            ),
        })
    }
}

fn raw_expected_fixture_bound(
    fixtures: &[RawFixtureSummary],
    case_id: &str,
    claim_layer: u64,
    execution: [u8; 32],
    path: &str,
    digest: [u8; 32],
    member_size: usize,
) -> bool {
    let size = u64::try_from(member_size).unwrap_or(u64::MAX);
    fixtures.iter().any(|fixture| {
        fixture.case_id == case_id
            && fixture.claim_layer == claim_layer
            && fixture.execution == execution
            && (fixture
                .auxiliary
                .iter()
                .any(|artifact| raw_expected_artifact_bound(artifact, path, digest, size))
                || matches!(
                    &fixture.oracle,
                    RawOracle::Output(output)
                        if raw_expected_artifact_bound(output, path, digest, size)
                ))
    })
}

fn raw_expected_artifact_bound(
    artifact: &RawArtifact,
    path: &str,
    digest: [u8; 32],
    size: u64,
) -> bool {
    artifact.path == path && artifact.digest == digest && artifact.size == size
}

fn raw_ordered_artifacts(values: &[Value]) -> Result<Vec<RawArtifact>, BundleContractErrorV1> {
    let mut artifacts = Vec::with_capacity(values.len());
    for value in values {
        let artifact = raw_artifact(value)?;
        if artifacts
            .last()
            .is_some_and(|previous: &RawArtifact| previous.path.as_str() >= artifact.path.as_str())
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        artifacts.push(artifact);
    }
    Ok(artifacts)
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
fn raw_ordered_modes(values: &[Value]) -> Result<Vec<u64>, BundleContractErrorV1> {
    let mut modes = Vec::with_capacity(values.len());
    for value in values {
        let mode = uint(value)?;
        if mode > 3 || modes.last().is_some_and(|previous| previous >= &mode) {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        modes.push(mode);
    }
    if modes.is_empty() {
        Err(BundleContractErrorV1::ProfileInvalid)
    } else {
        Ok(modes)
    }
}
fn raw_provider_keys_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    values
        .iter()
        .try_fold((None, true), |(previous, ordered), value| {
            raw_provider_order_key(value).map(|current| {
                let next_ordered = ordered && previous.as_ref().is_none_or(|old| old < &current);
                (Some(current), next_ordered)
            })
        })
        .map(|(_, ordered)| ordered)
}

fn raw_provider_order_key(
    value: &Value,
) -> Result<(String, String, u64, u64), BundleContractErrorV1> {
    raw_provider_key(value)
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
type RawExpectedOrderKey = (String, u64, [u8; 32], u64, String, [u8; 32]);
fn length_bound(value: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    encode(value).map(|encoded| {
        let mut bound = u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes()
            .to_vec();
        bound.extend(encoded);
        bound
    })
}

fn raw_provider_key(value: &Value) -> Result<RawProviderKey, BundleContractErrorV1> {
    let Ok(fields) = array(value, 4) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(provider_id), Ok(contract_version), Ok(abi_major), Ok(abi_minor)) = (
        text(&fields[0]),
        text(&fields[1]),
        uint(&fields[2]),
        uint(&fields[3]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if raw_identifier(provider_id, 128)
        && raw_semver(contract_version)
        && u16::try_from(abi_major).is_ok()
        && u16::try_from(abi_minor).is_ok()
    {
        Ok((
            provider_id.to_owned(),
            contract_version.to_owned(),
            abi_major,
            abi_minor,
        ))
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_artifact(value: &Value) -> Result<RawArtifact, BundleContractErrorV1> {
    let Ok(fields) = array(value, 4) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(member_path), Ok(media_type), Ok(byte_length), Ok(digest)) = (
        text(&fields[0]),
        text(&fields[1]),
        uint(&fields[2]),
        digest::<32>(&fields[3]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if raw_member_path(member_path)
        && raw_media_type(media_type)
        && (1..=64 * 1024 * 1024).contains(&byte_length)
        && digest != [0; 32]
    {
        Ok(RawArtifact {
            path: member_path.to_owned(),
            size: byte_length,
            digest,
        })
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
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

#[derive(Clone)]
struct RawArtifact {
    path: String,
    size: u64,
    digest: [u8; 32],
}

enum RawOracle {
    Output(RawArtifact),
    Failure(RawFailure),
    Divergence(RawDivergence),
}

#[derive(Clone, Copy)]
enum RawOracleKind {
    Output,
    Failure,
    Divergence,
}

fn raw_oracle(value: &Value) -> Result<RawOracle, BundleContractErrorV1> {
    array(value, 4).and_then(|fields| {
        uint(&fields[0]).and_then(|kind| {
            let kind = match kind {
                0 => RawOracleKind::Output,
                1 => RawOracleKind::Failure,
                2 => RawOracleKind::Divergence,
                _ => return Err(BundleContractErrorV1::ProfileInvalid),
            };
            let active = match kind {
                RawOracleKind::Output => 1,
                RawOracleKind::Failure => 2,
                RawOracleKind::Divergence => 3,
            };
            if fields
                .iter()
                .enumerate()
                .skip(1)
                .any(|(index, field)| (index == active) != !matches!(field, Value::Null))
            {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            match kind {
                RawOracleKind::Output => raw_artifact(&fields[active]).map(RawOracle::Output),
                RawOracleKind::Failure => raw_failure(&fields[active]).map(RawOracle::Failure),
                RawOracleKind::Divergence => {
                    raw_divergence(&fields[active]).map(RawOracle::Divergence)
                }
            }
        })
    })
}

type RawDivergence = (u64, Vec<u8>);

fn raw_divergence(value: &Value) -> Result<RawDivergence, BundleContractErrorV1> {
    array(value, 2).and_then(|fields| {
        uint(&fields[0]).and_then(|classification| {
            bytes(&fields[1]).and_then(|coordinate| {
                if classification <= 6 && !coordinate.is_empty() && coordinate.len() <= 128 {
                    Ok((classification, coordinate.to_vec()))
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        })
    })
}

fn raw_budget(value: &Value, deterministic_caps: &[u64; 8]) -> Result<(), BundleContractErrorV1> {
    array(value, 8).and_then(|fields| {
        if fields
            .iter()
            .zip(deterministic_caps)
            .all(|(field, ceiling)| uint(field).is_ok_and(|limit| limit > 0 && limit <= *ceiling))
        {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ProfileInvalid)
        }
    })
}

fn raw_watchdog(value: &Value) -> Result<(), BundleContractErrorV1> {
    array(value, 1).and_then(|fields| {
        uint(&fields[0]).and_then(|watchdog| {
            if watchdog == 0 {
                Err(BundleContractErrorV1::ProfileInvalid)
            } else {
                Ok(())
            }
        })
    })
}

fn raw_capabilities(value: &Value) -> Result<bool, BundleContractErrorV1> {
    array(value, 2).and_then(|fields| {
        let Value::Bool(network_allowed) = &fields[0] else {
            return Err(BundleContractErrorV1::ProfileInvalid);
        };
        array_values(&fields[1]).and_then(|ids| {
            if ids.len() <= 256
                && ids.windows(2).all(|pair| pair[0] < pair[1])
                && ids
                    .iter()
                    .all(|id| text(id).is_ok_and(|id| raw_identifier(id, 128)))
            {
                Ok(*network_allowed)
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
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
    verify_archive_independently(bytes).and_then(|()| {
        if filename == format!("{}.cfb1", crate::hex_digest(blake3::hash(bytes).as_bytes())) {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ReleaseFilenameInvalid)
        }
    })
}
fn ordered_members(members: &[BundleMemberV1]) -> bool {
    members.windows(2).all(|pair| pair[0].path < pair[1].path)
}
fn ordered_descriptors(descriptors: &[BundleMemberDescriptorV1]) -> bool {
    descriptors.windows(2).all(|pair| pair[0] < pair[1])
}
fn encode(value: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| BundleContractErrorV1::EncodingFailed)
        .map(|()| bytes)
}
fn decode(bytes: &[u8]) -> Result<Value, BundleContractErrorV1> {
    preflight_archive_cbor(bytes).and_then(|()| {
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
            .and_then(|value| {
                encode(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
                    }
                })
            })
    })
}

fn preflight_archive_cbor(bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    fn read_length(
        bytes: &[u8],
        index: &mut usize,
        additional: u8,
    ) -> Result<u64, BundleContractErrorV1> {
        let width = match additional {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(BundleContractErrorV1::ArchiveEncodingInvalid),
        };
        let end = index.saturating_add(width);
        let encoded = bytes
            .get(*index..end)
            .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
        *index = end;
        let mut value = [0_u8; 8];
        value[8 - width..].copy_from_slice(encoded);
        Ok(u64::from_be_bytes(value))
    }

    fn item(bytes: &[u8], index: &mut usize, depth: u8) -> Result<(), BundleContractErrorV1> {
        if depth > MAX_CONFORMANCE_NESTING_V1 {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        let initial = *bytes
            .get(*index)
            .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
        *index += 1;
        let major = initial >> 5;
        let length = read_length(bytes, index, initial & 0x1f)?;
        match major {
            0 | 1 => Ok(()),
            7 if matches!(initial & 0x1f, 20..=22) => Ok(()),
            2 | 3 => {
                if (major == 2 && length > MAX_CONFORMANCE_MEMBER_BYTES_V1)
                    || (major == 3 && length > MAX_CONFORMANCE_TEXT_BYTES_V1)
                {
                    return Err(BundleContractErrorV1::MemberOutOfBounds);
                }
                let count = usize::try_from(length).unwrap_or(usize::MAX);
                let end = index.saturating_add(count);
                bytes
                    .get(*index..end)
                    .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
                *index = end;
                Ok(())
            }
            4 => {
                if length > MAX_CONFORMANCE_ITEMS_V1 {
                    return Err(BundleContractErrorV1::MemberOutOfBounds);
                }
                for _ in 0..length {
                    item(bytes, index, depth.saturating_add(1))?;
                }
                Ok(())
            }
            _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
        }
    }

    let mut index = 0;
    item(bytes, &mut index, 0)?;
    if index == bytes.len() {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
    }
}
fn array(value: &Value, width: usize) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(fields) if fields.len() == width => Ok(fields),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn array_values(value: &Value) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn text(value: &Value) -> Result<&str, BundleContractErrorV1> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn bytes(value: &Value) -> Result<&[u8], BundleContractErrorV1> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn uint(value: &Value) -> Result<u64, BundleContractErrorV1> {
    match value {
        Value::Integer(integer) => {
            u64::try_from(*integer).map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
        }
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}
fn digest<const N: usize>(value: &Value) -> Result<[u8; N], BundleContractErrorV1> {
    bytes(value).and_then(|value| {
        value
            .try_into()
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
    })
}
fn digest_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut source = domain.to_vec();
    source.extend_from_slice(bytes);
    *blake3::hash(&source).as_bytes()
}
fn manifest_value(manifest: &BundleManifestV1) -> Value {
    Value::Array(vec![
        Value::Text(manifest.magic.clone()),
        Value::Integer(manifest.lifecycle.wire_code().into()),
        Value::Integer(manifest.mode.code().into()),
        Value::Bytes(manifest.profile_digest.to_vec()),
        Value::Array(
            manifest
                .members
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
            manifest
                .expected_results
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
    fixture_member_path(
        b"PiglorOS.CPF1InputPath.v1\0",
        "inputs",
        case,
        layer,
        execution,
        member,
    )
}
/// Derive the deterministic expected-result member path for one fixture execution.
#[must_use]
pub fn expected_result_member_path(
    case: &str,
    layer: crate::ClaimLayerV1,
    execution: &[u8; 32],
) -> String {
    fixture_member_path(
        b"PiglorOS.CPF1ExpectedResultPath.v1\0",
        "expected",
        case,
        layer,
        execution,
        "strict-oracle",
    )
}

fn fixture_member_path(
    domain: &[u8],
    namespace: &str,
    case: &str,
    layer: crate::ClaimLayerV1,
    execution: &[u8; 32],
    purpose: &str,
) -> String {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(case.as_bytes());
    preimage.push(layer.wire_code());
    preimage.extend_from_slice(execution);
    preimage.extend_from_slice(purpose.as_bytes());
    let digest = blake3::hash(&preimage).to_hex();
    format!("{namespace}/{digest}.bin")
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
        self.local.validate().and_then(|()| {
            self.air_gapped.validate().and_then(|()| {
                if self.local.manifest.mode == BundleModeV1::Local
                    && self.air_gapped.manifest.mode == BundleModeV1::AirGapped
                    && self.local.manifest.profile_digest == self.air_gapped.manifest.profile_digest
                    && authoritative_expected_results(&self.local)?
                        == authoritative_expected_results(&self.air_gapped)?
                {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::ModeParityMismatch)
                }
            })
        })
    }
}

fn authoritative_expected_results(
    bundle: &ConformanceBundleV1,
) -> Result<BTreeMap<(String, crate::ClaimLayerV1), Vec<u8>>, BundleContractErrorV1> {
    bundle
        .manifest
        .expected_results
        .iter()
        .map(|expected| {
            member_by_role_and_path(
                &bundle.members,
                BundleMemberRoleV1::ExpectedResult,
                &expected.member_path,
            )
            .map(|member| {
                (
                    (expected.case_id.clone(), expected.claim_layer),
                    member.bytes.clone(),
                )
            })
        })
        .collect()
}
