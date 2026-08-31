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
    FixtureProviderKeyV1, FixtureProviderPackageV1, FixtureProviderRegistryV1, ProfileLifecycleV1,
    DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION, DRAFT_AUTHORITY_KEY_ID,
    DRAFT_AUTHORITY_MINIMUM_VERSIONS, DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH,
    DRAFT_AUTHORITY_ROOT_ALGORITHM, DRAFT_AUTHORITY_ROOT_VERSION,
    DRAFT_AUTHORITY_TRUST_POLICY_EPOCH, DRAFT_AUTHORITY_TRUST_POLICY_ID, DRAFT_EXECUTION_PROFILES,
    FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
};

pub const CONFORMANCE_BUNDLE_MAGIC_V1: &str = "CFB1";
pub const MAX_CONFORMANCE_BUNDLE_BYTES_V1: u64 = 1024 * 1024 * 1024;
const MAX_CONFORMANCE_BUNDLE_LEN_V1: usize = 1024 * 1024 * 1024;
const MAX_CONFORMANCE_MEMBER_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_CONFORMANCE_TEXT_BYTES_V1: u64 = 512;
const MAX_CONFORMANCE_ITEMS_V1: u64 = 65_536;
const MAX_CONFORMANCE_NESTING_V1: u8 = 32;
const PROFILE_PATH: &str = "profile/CPF1.cbor";
const NORMATIVE_SPEC_PATH: &str = "support/normative-requirements.md";
const EXECUTION_MATRIX_PATH: &str = "authority/execution-matrix.json";
const AUTHORITY_INVENTORY_PATH: &str = "authority/expected-authority-inventory.json";
const TRUST_POLICY_SNAPSHOT_PATH: &str = "authority/trust-policy-snapshot.tps1";
const PROFILE_SCHEMA_PATH: &str = "support/schema-cpf1-v1.cddl";
const EVALUATOR_PROTOCOL_PATH: &str = "support/evaluator-protocol-v1.json";
const EVALUATOR_REQUEST_SCHEMA_PATH: &str = "support/evaluator-request-v1.cddl";
const EVALUATOR_REPORT_SCHEMA_PATH: &str = "support/evaluator-report-v1.cddl";
const EVALUATOR_PROTOCOL_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/evaluator-protocol-v1.json");
const EVALUATOR_REQUEST_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/evaluator-request-v1.cddl");
const EVALUATOR_REPORT_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../fixtures/conformance/support/evaluator-report-v1.cddl");
const FIXTURE_CONTRACT_POLICY_PATH: &str = "support/fixture-family-contract.json";
const LIMITATIONS_PATH: &str = "support/limitations.md";
const SOURCE_PROVENANCE_PATH: &str = "support/source-provenance.json";
const BUILD_PROVENANCE_PATH: &str = "support/build-provenance.json";
const PUBLICATION_REVIEW_PATH: &str = "support/publication-review.json";
const SUPPORT_PACKAGE_MANIFEST_PATH: &str = "support/package-manifest.json";
const NOTICE_PATH: &str = "support/NOTICE";
const SBOM_PATH: &str = "support/sbom.json";
include!(concat!(env!("OUT_DIR"), "/bundle_contract_assets.rs"));

const DRAFT_FIXTURE_AUTHORITY_SIGNING_BYTES: [u8; 32] = [7; 32];

fn draft_fixture_authority_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&DRAFT_FIXTURE_AUTHORITY_SIGNING_BYTES)
}

/// Build the canonical current EPF1 artifact declared by the repository Draft authority.
///
/// # Errors
///
/// Returns [`BundleContractErrorV1::ProfileInvalid`] for an undeclared profile, or
/// [`BundleContractErrorV1::EncodingFailed`] if canonical CBOR encoding fails.
pub fn draft_execution_profile_bytes_v1(
    profile_id: &str,
) -> Result<Vec<u8>, BundleContractErrorV1> {
    let declaration = DRAFT_EXECUTION_PROFILES
        .iter()
        .find(|candidate| candidate.profile_id == profile_id)
        .ok_or(BundleContractErrorV1::ProfileInvalid)?;
    let fields = vec![
        Value::Text("EPF1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(declaration.profile_id.to_owned()),
        Value::Text(declaration.semantic_version.to_owned()),
        Value::Array(
            declaration
                .reproducibility_classes
                .iter()
                .copied()
                .map(|code| Value::Integer(code.into()))
                .collect(),
        ),
        text_array(declaration.architecture_rules),
        text_array(declaration.numeric_rules),
        text_array(declaration.scheduler_driver_order),
        Value::Text(declaration.tick_policy.to_owned()),
        text_array(declaration.schemas_and_upcasters),
        text_array(declaration.artifact_rules),
        Value::Array(vec![
            Value::Bool(declaration.network_allowed),
            text_array(declaration.capability_ids),
        ]),
        Value::Array(
            declaration
                .deterministic_budgets
                .into_iter()
                .map(|limit| Value::Integer(limit.into()))
                .collect(),
        ),
        text_array(declaration.allowed_operational_differences),
        Value::Array(vec![
            Value::Text(declaration.minimum_evaluator_version.to_owned()),
            Value::Text(declaration.maximum_evaluator_version.to_owned()),
        ]),
        Value::Null,
    ];
    encode(&Value::Array(fields.clone())).and_then(|unsigned| {
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(
            digest_domain(b"PiglorOS.ExecutionProfile.v1\0", &unsigned).to_vec(),
        ));
        encode(&Value::Array(signed_fields))
    })
}

fn text_array(values: &[&str]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::Text((*value).to_owned()))
            .collect(),
    )
}

/// Build the canonical current TPS1 artifact for the repository Draft authority.
///
/// # Errors
///
/// Returns [`BundleContractErrorV1::EncodingFailed`] if canonical CBOR encoding fails.
pub fn draft_trust_policy_snapshot_bytes_v1() -> Result<Vec<u8>, BundleContractErrorV1> {
    let fields = vec![
        Value::Text("TPS1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Text(DRAFT_AUTHORITY_TRUST_POLICY_ID.to_owned()),
        Value::Integer(DRAFT_AUTHORITY_TRUST_POLICY_EPOCH.into()),
        Value::Integer(DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION.into()),
        Value::Array(vec![Value::Array(vec![
            Value::Text(DRAFT_AUTHORITY_KEY_ID.to_owned()),
            Value::Integer(DRAFT_AUTHORITY_ROOT_VERSION.into()),
            Value::Text(DRAFT_AUTHORITY_ROOT_ALGORITHM.to_owned()),
            Value::Bytes(crate::DRAFT_AUTHORITY_PUBLIC_KEY_BYTES.to_vec()),
        ])]),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
        Value::Array(
            DRAFT_AUTHORITY_MINIMUM_VERSIONS
                .iter()
                .map(|(kind, version)| {
                    Value::Array(vec![
                        Value::Text((*kind).to_owned()),
                        Value::Text((*version).to_owned()),
                    ])
                })
                .collect(),
        ),
        Value::Text(DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH.to_owned()),
        Value::Null,
    ];
    encode(&Value::Array(fields.clone())).and_then(|unsigned| {
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(
            draft_fixture_authority_signing_key()
                .sign(&unsigned)
                .to_bytes()
                .to_vec(),
        ));
        encode(&Value::Array(signed_fields))
    })
}

fn fixture_provider_key_value(key: &FixtureProviderKeyV1) -> Value {
    Value::Array(vec![
        Value::Text(key.provider_id.clone()),
        Value::Text(key.contract_version.clone()),
        Value::Integer(u64::from(key.abi_major).into()),
        Value::Integer(u64::from(key.abi_minor).into()),
    ])
}

/// Build a canonical current RAD1 artifact signed by the repository Draft authority.
///
/// # Errors
///
/// Returns [`BundleContractErrorV1::EncodingFailed`] if canonical CBOR encoding fails.
pub fn draft_release_admission_bytes_v1(
    case_id: &str,
    execution_profile_digest: [u8; 32],
    trust_policy_snapshot_digest: [u8; 32],
    from: &FixtureProviderKeyV1,
    to: &FixtureProviderKeyV1,
) -> Result<Vec<u8>, BundleContractErrorV1> {
    let fields = vec![
        Value::Text("RAD1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Text(case_id.to_owned()),
        Value::Bytes(execution_profile_digest.to_vec()),
        Value::Bytes(trust_policy_snapshot_digest.to_vec()),
        fixture_provider_key_value(from),
        fixture_provider_key_value(to),
        Value::Bool(false),
        Value::Text(DRAFT_AUTHORITY_KEY_ID.to_owned()),
    ];
    encode(&Value::Array(fields.clone())).and_then(|unsigned| {
        let mut signed_fields = fields;
        signed_fields.push(Value::Bytes(
            draft_fixture_authority_signing_key()
                .sign(&unsigned)
                .to_bytes()
                .to_vec(),
        ));
        encode(&Value::Array(signed_fields))
    })
}

fn draft_authority_verifying_key() -> Result<ed25519_dalek::VerifyingKey, BundleContractErrorV1> {
    ed25519_dalek::VerifyingKey::from_bytes(&crate::DRAFT_AUTHORITY_PUBLIC_KEY_BYTES)
        .map_err(|_| BundleContractErrorV1::SignatureInvalid)
}

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
    ExecutionProfile,
    TrustPolicySnapshot,
    ReleaseAdmission,
    EvidenceStatus,
    FixtureContractPolicy,
    AuthorityDeclaration,
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
            Self::ExecutionProfile => 14,
            Self::TrustPolicySnapshot => 15,
            Self::ReleaseAdmission => 16,
            Self::EvidenceStatus => 17,
            Self::FixtureContractPolicy => 18,
            Self::AuthorityDeclaration => 19,
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
    pub fn evidence_status(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::new(path, bytes, BundleMemberRoleV1::EvidenceStatus)
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
        if bytes.len() > MAX_CONFORMANCE_BUNDLE_LEN_V1 {
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
            if self.signer_public_key.as_bytes() != &crate::DRAFT_AUTHORITY_PUBLIC_KEY_BYTES {
                return Err(BundleContractErrorV1::SignatureInvalid);
            }
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
        self.validate()
            .and_then(|()| encode(&archive_value(self)))
            .and_then(|bytes| {
                if bytes.len() <= MAX_CONFORMANCE_BUNDLE_LEN_V1 {
                    Ok(bytes)
                } else {
                    Err(BundleContractErrorV1::MemberOutOfBounds)
                }
            })
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
                        if profile.lifecycle != self.manifest.lifecycle {
                            return Err(BundleContractErrorV1::LifecycleInvalid);
                        }
                        if profile.profile_digest != self.manifest.profile_digest {
                            return Err(BundleContractErrorV1::ProfileInvalid);
                        }
                        validate_selected_archive_caps(&profile, &self.members)
                            .and_then(|()| {
                                validate_member_descriptors(&self.members, &self.manifest.members)
                            })
                            .and_then(|()| {
                                validate_profile_support_members(&profile, &self.members).and_then(
                                    |()| {
                                        validate_execution_authority_members(
                                            &profile,
                                            &self.members,
                                            self.manifest.mode,
                                        )
                                    },
                                )
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

fn validate_selected_archive_caps(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let caps = &profile.evaluator_protocol.hard_caps;
    if members.len() > usize::try_from(caps.max_bundle_members).unwrap_or(usize::MAX)
        || members.iter().any(|member| {
            member.path.len() > usize::from(caps.max_member_path_bytes)
                || u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) > caps.max_member_bytes
        })
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    let total_bytes = members.iter().try_fold(0_u64, |total, member| {
        total.checked_add(u64::try_from(member.bytes.len()).unwrap_or(u64::MAX))
    });
    if total_bytes.is_none_or(|total| total > caps.max_total_bundle_bytes) {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
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
            FIXTURE_CONTRACT_POLICY_PATH,
            BundleMemberRoleV1::FixtureContractPolicy,
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
        .and_then(|()| validate_evaluator_support_members(profile, members))
        .and_then(|()| validate_fixture_provenance_members(profile, members))
        .and_then(|()| {
            member_by_role_and_path(
                members,
                BundleMemberRoleV1::AuthorityInventory,
                AUTHORITY_INVENTORY_PATH,
            )
            .and_then(|member| {
                if member.bytes == AUTHORITY_INVENTORY_BYTES_V1 {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
        .and_then(|()| {
            member_by_role_and_path(
                members,
                BundleMemberRoleV1::Schema,
                SUPPORT_PACKAGE_MANIFEST_PATH,
            )
            .and_then(|member| {
                if member.bytes == SUPPORT_PACKAGE_MANIFEST_BYTES_V1 {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
        .and_then(|()| {
            member_by_role_and_path(
                members,
                BundleMemberRoleV1::ExecutionMatrix,
                EXECUTION_MATRIX_PATH,
            )
            .and_then(|member| {
                if member.bytes == EXECUTION_MATRIX_BYTES_V1 {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
        .and_then(|()| {
            member_by_role_and_path(
                members,
                BundleMemberRoleV1::AuthorityDeclaration,
                "support/draft-execution-authority.json",
            )
            .and_then(|member| {
                if member.bytes == DRAFT_AUTHORITY_DECLARATION_BYTES_V1 {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
}

fn validate_evaluator_support_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    [
        (
            EVALUATOR_PROTOCOL_PATH,
            profile.evaluator_protocol.protocol_digest,
            EVALUATOR_PROTOCOL_BYTES,
        ),
        (
            EVALUATOR_REQUEST_SCHEMA_PATH,
            profile.evaluator_protocol.request_schema_digest,
            EVALUATOR_REQUEST_SCHEMA_BYTES,
        ),
        (
            EVALUATOR_REPORT_SCHEMA_PATH,
            profile.evaluator_protocol.report_schema_digest,
            EVALUATOR_REPORT_SCHEMA_BYTES,
        ),
    ]
    .into_iter()
    .try_for_each(|(path, declared_digest, approved_bytes)| {
        member_by_role_and_path(members, BundleMemberRoleV1::Schema, path).and_then(|member| {
            let approved_digest = *blake3::hash(approved_bytes).as_bytes();
            if member.bytes == approved_bytes
                && member.digest == declared_digest
                && declared_digest == approved_digest
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::MemberDigestMismatch)
            }
        })
    })
}

fn validate_execution_authority_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
    mode: BundleModeV1,
) -> Result<(), BundleContractErrorV1> {
    let execution_members = members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::ExecutionProfile)
        .collect::<Vec<_>>();
    let execution_profiles = execution_members
        .iter()
        .map(|member| {
            validate_execution_profile_member(member).map(|profile_id| (profile_id, member.digest))
        })
        .collect::<Result<BTreeMap<_, _>, _>>();
    let snapshot_members = members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::TrustPolicySnapshot)
        .count();
    if snapshot_members != 1 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let downgrades = profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.family == FixtureFamilyV1::Downgrade)
        .filter(|fixture| fixture.modes.contains(&mode.execution()))
        .collect::<Vec<_>>();
    if members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::ReleaseAdmission)
        .count()
        != downgrades.len()
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    execution_profiles.and_then(|execution_profiles| {
        let declared_profiles = DRAFT_EXECUTION_PROFILES
            .iter()
            .map(|profile| profile.profile_id.to_owned())
            .collect::<BTreeSet<_>>();
        let execution_digests = execution_profiles
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let execution_profile_ids = execution_profiles.keys().cloned().collect::<BTreeSet<_>>();
        if execution_members.len() != profile.execution_profile_digests.len()
            || execution_profiles.len() != profile.execution_profile_digests.len()
            || execution_digests != profile.execution_profile_digests.iter().copied().collect()
            || execution_profile_ids != declared_profiles
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        member_by_role_and_path(
            members,
            BundleMemberRoleV1::TrustPolicySnapshot,
            TRUST_POLICY_SNAPSHOT_PATH,
        )
        .and_then(|snapshot| {
            validate_trust_policy_snapshot(snapshot).and_then(|()| {
                if snapshot.digest
                    == profile
                        .independence_requirements
                        .trust_policy_snapshot_digest
                {
                    downgrades
                        .into_iter()
                        .try_for_each(|fixture| validate_release_admission_member(fixture, members))
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
    })
}

fn validate_execution_profile_member(
    member: &BundleMemberV1,
) -> Result<String, BundleContractErrorV1> {
    decode(&member.bytes).and_then(|value| {
        array(&value, 17)
            .and_then(|fields| validate_execution_profile_fields(member.path.as_str(), fields))
    })
}

fn validate_execution_profile_fields(
    path: &str,
    fields: &[Value],
) -> Result<String, BundleContractErrorV1> {
    match (text(&fields[0]), uint(&fields[1]), text(&fields[2])) {
        (Ok("EPF1"), Ok(1), Ok(profile_id)) => draft_execution_profile_bytes_v1(profile_id)
            .and_then(|expected| {
                if path == format!("authority/execution-profiles/{profile_id}.epf1")
                    && encode(&Value::Array(fields.to_vec())).is_ok_and(|bytes| bytes == expected)
                {
                    Ok(profile_id.to_owned())
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            }),
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn validate_trust_policy_snapshot(member: &BundleMemberV1) -> Result<(), BundleContractErrorV1> {
    decode(&member.bytes)
        .and_then(|value| array(&value, 12).and_then(validate_trust_policy_snapshot_fields))
}

fn validate_trust_policy_snapshot_fields(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    match (
        text(&fields[0]),
        uint(&fields[1]),
        text(&fields[2]),
        uint(&fields[3]),
        uint(&fields[4]),
        text(&fields[9]),
        digest::<64>(&fields[11]),
    ) {
        (
            Ok(magic),
            Ok(version),
            Ok(policy_id),
            Ok(epoch),
            Ok(position),
            Ok(expiry),
            Ok(signature),
        ) => encode(&Value::Array(fields[..11].to_vec())).and_then(|unsigned| {
            draft_authority_verifying_key()
                .and_then(|verifying_key| {
                    verifying_key
                        .verify(&unsigned, &ed25519_dalek::Signature::from_bytes(&signature))
                        .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                })
                .and_then(|()| {
                    if magic == "TPS1"
                        && version == 1
                        && policy_id == DRAFT_AUTHORITY_TRUST_POLICY_ID
                        && epoch == DRAFT_AUTHORITY_TRUST_POLICY_EPOCH
                        && position == DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION
                        && fields[5]
                            == Value::Array(vec![Value::Array(vec![
                                Value::Text(DRAFT_AUTHORITY_KEY_ID.to_owned()),
                                Value::Integer(DRAFT_AUTHORITY_ROOT_VERSION.into()),
                                Value::Text(DRAFT_AUTHORITY_ROOT_ALGORITHM.to_owned()),
                                Value::Bytes(crate::DRAFT_AUTHORITY_PUBLIC_KEY_BYTES.to_vec()),
                            ])])
                        && fields[6] == Value::Array(Vec::new())
                        && fields[7] == Value::Array(Vec::new())
                        && fields[8]
                            == Value::Array(
                                DRAFT_AUTHORITY_MINIMUM_VERSIONS
                                    .iter()
                                    .map(|(kind, version)| {
                                        Value::Array(vec![
                                            Value::Text((*kind).to_owned()),
                                            Value::Text((*version).to_owned()),
                                        ])
                                    })
                                    .collect(),
                            )
                        && expiry == DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH
                        && fields[10] == Value::Null
                    {
                        Ok(())
                    } else {
                        Err(BundleContractErrorV1::ProfileInvalid)
                    }
                })
        }),
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn validate_release_admission_member(
    fixture: &crate::FixtureDescriptorV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    fixture
        .release_admission_digest
        .ok_or(BundleContractErrorV1::ProfileInvalid)
        .and_then(|digest| {
            members
                .iter()
                .find(|member| {
                    member.role == BundleMemberRoleV1::ReleaseAdmission && member.digest == digest
                })
                .ok_or(BundleContractErrorV1::MemberMissing)
        })
        .and_then(|member| {
            fixture
                .trust_policy_snapshot_digest
                .ok_or(BundleContractErrorV1::ProfileInvalid)
                .and_then(|snapshot| {
                    fixture
                        .transition
                        .as_ref()
                        .ok_or(BundleContractErrorV1::ProfileInvalid)
                        .and_then(|transition| {
                            decode(&member.bytes).and_then(|value| {
                                array(&value, 11).and_then(|fields| {
                                    validate_release_admission_fields(
                                        fields, fixture, snapshot, transition,
                                    )
                                })
                            })
                        })
                })
        })
}

fn validate_release_admission_fields(
    fields: &[Value],
    fixture: &crate::FixtureDescriptorV1,
    snapshot: [u8; 32],
    transition: &crate::FixtureContractTransitionV1,
) -> Result<(), BundleContractErrorV1> {
    match (
        text(&fields[0]),
        uint(&fields[1]),
        uint(&fields[2]),
        text(&fields[3]),
        digest::<32>(&fields[4]),
        digest::<32>(&fields[5]),
        text(&fields[9]),
        digest::<64>(&fields[10]),
    ) {
        (
            Ok(magic),
            Ok(version),
            Ok(lifecycle),
            Ok(case_id),
            Ok(execution),
            Ok(policy),
            Ok(key_id),
            Ok(signature),
        ) => encode(&Value::Array(fields[..10].to_vec())).and_then(|unsigned| {
            draft_authority_verifying_key()
                .and_then(|key| {
                    key.verify(&unsigned, &ed25519_dalek::Signature::from_bytes(&signature))
                        .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                })
                .and_then(|()| {
                    if magic == "RAD1"
                        && version == 1
                        && lifecycle == 0
                        && case_id == fixture.case_id
                        && execution == fixture.execution_profile_digest
                        && policy == snapshot
                        && fields[6] == provider_key_value(&transition.from)
                        && fields[7] == provider_key_value(&transition.to)
                        && fields[8] == Value::Bool(false)
                        && key_id == DRAFT_AUTHORITY_KEY_ID
                    {
                        Ok(())
                    } else {
                        Err(BundleContractErrorV1::ProfileInvalid)
                    }
                })
        }),
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn provider_key_value(key: &crate::FixtureProviderKeyV1) -> Value {
    Value::Array(vec![
        Value::Text(key.provider_id.clone()),
        Value::Text(key.contract_version.clone()),
        Value::Integer(u64::from(key.abi_major).into()),
        Value::Integer(u64::from(key.abi_minor).into()),
    ])
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
        EVALUATOR_PROTOCOL_PATH,
        EVALUATOR_REQUEST_SCHEMA_PATH,
        EVALUATOR_REPORT_SCHEMA_PATH,
        SUPPORT_PACKAGE_MANIFEST_PATH,
        FIXTURE_CONTRACT_POLICY_PATH,
        "support/draft-execution-authority.json",
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
    declared.extend(
        members
            .iter()
            .filter(|member| {
                matches!(
                    member.role,
                    BundleMemberRoleV1::ExecutionProfile
                        | BundleMemberRoleV1::TrustPolicySnapshot
                        | BundleMemberRoleV1::ReleaseAdmission
                        | BundleMemberRoleV1::AuthorityDeclaration
                )
            })
            .map(|member| member.path.clone()),
    );
    declare_provider_members(members, &mut declared).and_then(|()| {
        if members.iter().all(|member| declared.contains(&member.path)) {
            Ok(())
        } else {
            Err(BundleContractErrorV1::UndeclaredMember)
        }
    })
}

fn declare_provider_members(
    members: &[BundleMemberV1],
    declared: &mut BTreeSet<String>,
) -> Result<(), BundleContractErrorV1> {
    member_by_role_and_path(
        members,
        BundleMemberRoleV1::FixtureProviderRegistry,
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
    )
    .and_then(|registry_member| {
        FixtureProviderRegistryV1::from_canonical_cbor(&registry_member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)
    })
    .and_then(|registry| {
        registry.providers.into_iter().try_for_each(|entry| {
            declared.insert(entry.provider_package_descriptor.member_path.clone());
            descriptor_member(
                members,
                &entry.provider_package_descriptor,
                BundleMemberRoleV1::FixtureProviderPackage,
            )
            .and_then(|package_member| {
                FixtureProviderPackageV1::from_canonical_cbor(&package_member.bytes)
                    .map_err(|_| BundleContractErrorV1::ProfileInvalid)
            })
            .map(|package| {
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
            })
        })
    })
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
    let claim_layer = profile
        .fixtures
        .first()
        .map(|fixture| fixture.claim_layer)
        .ok_or(BundleContractErrorV1::ProfileInvalid)?;
    let layer_keys = registry
        .providers
        .iter()
        .filter(|entry| entry.claim_layer == claim_layer)
        .map(|entry| &entry.provider_key)
        .collect::<BTreeSet<_>>();
    let required_keys = binding
        .required_provider_keys
        .iter()
        .collect::<BTreeSet<_>>();
    if required_keys != layer_keys {
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
            if fixture.claim_layer == entry.claim_layer
                && fixture.subject_adapter == entry.subject_adapter
                && package
                    .family_schemas
                    .iter()
                    .find(|schema| schema.family == fixture.family)
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
            [
                (&package.licence_descriptor, BundleMemberRoleV1::Licence),
                (&package.notices_descriptor, BundleMemberRoleV1::Notice),
                (&package.sbom_descriptor, BundleMemberRoleV1::Sbom),
                (
                    &package.source_provenance_descriptor,
                    BundleMemberRoleV1::Provenance,
                ),
                (
                    &package.limitations_descriptor,
                    BundleMemberRoleV1::Limitations,
                ),
            ]
            .into_iter()
            .try_for_each(|(descriptor, role)| {
                descriptor_member(members, descriptor, role).map(|_| ())
            })
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
                .and_then(|_| validate_draft_evidence(fixture, members))
                .and_then(|()| {
                    fixture.auxiliary.iter().try_for_each(|artifact| {
                        descriptor_member_with_roles(
                            members,
                            artifact,
                            &[
                                BundleMemberRoleV1::FixtureInput,
                                BundleMemberRoleV1::ExpectedResult,
                                BundleMemberRoleV1::EvidenceStatus,
                            ],
                        )
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

fn validate_draft_evidence(
    fixture: &crate::FixtureDescriptorV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let evidence = fixture.auxiliary.iter().filter(|artifact| {
        members.iter().any(|member| {
            member.path == artifact.member_path && member.role == BundleMemberRoleV1::EvidenceStatus
        })
    });
    let mut evidence = evidence.take(2);
    let Some(descriptor) = evidence.next() else {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    };
    if evidence.next().is_some() {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    descriptor_member(members, descriptor, BundleMemberRoleV1::EvidenceStatus).map(|_| ())
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

fn descriptor_member_with_roles<'a>(
    members: &'a [BundleMemberV1],
    descriptor: &ArtifactDescriptorV1,
    roles: &[BundleMemberRoleV1],
) -> Result<&'a BundleMemberV1, BundleContractErrorV1> {
    members
        .iter()
        .find(|member| member.path == descriptor.member_path && roles.contains(&member.role))
        .ok_or(BundleContractErrorV1::MemberMissing)
        .and_then(|member| {
            if member.digest == descriptor.blake3_digest
                && u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) == descriptor.byte_length
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
        14 => Ok(BundleMemberRoleV1::ExecutionProfile),
        15 => Ok(BundleMemberRoleV1::TrustPolicySnapshot),
        16 => Ok(BundleMemberRoleV1::ReleaseAdmission),
        17 => Ok(BundleMemberRoleV1::EvidenceStatus),
        18 => Ok(BundleMemberRoleV1::FixtureContractPolicy),
        19 => Ok(BundleMemberRoleV1::AuthorityDeclaration),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    })
}
#[path = "independent_bundle_verifier.rs"]
mod independent_bundle_verifier;
pub use independent_bundle_verifier::{
    verify_archive_independently, verify_release_tree_independently,
};

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
        bytes
            .get(*index..end)
            .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)
            .map(|encoded| {
                *index = end;
                let mut value = [0_u8; 8];
                value[8 - width..].copy_from_slice(encoded);
                u64::from_be_bytes(value)
            })
    }

    fn item(bytes: &[u8], index: &mut usize, depth: u8) -> Result<(), BundleContractErrorV1> {
        if depth > MAX_CONFORMANCE_NESTING_V1 {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        let Some(initial) = bytes.get(*index).copied() else {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        };
        *index += 1;
        let major = initial >> 5;
        read_length(bytes, index, initial & 0x1f).and_then(|length| match major {
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
                    .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)
                    .map(|_| *index = end)
            }
            4 => {
                if length > MAX_CONFORMANCE_ITEMS_V1 {
                    Err(BundleContractErrorV1::MemberOutOfBounds)
                } else {
                    (0..length).try_for_each(|_| item(bytes, index, depth.saturating_add(1)))
                }
            }
            _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
        })
    }

    let mut index = 0;
    let parsed = item(bytes, &mut index, 0);
    if parsed.is_err() {
        parsed
    } else if index == bytes.len() {
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
                authoritative_expected_results(&self.local).and_then(|local_expected| {
                    authoritative_expected_results(&self.air_gapped).and_then(|air_expected| {
                        if self.local.manifest.mode == BundleModeV1::Local
                            && self.air_gapped.manifest.mode == BundleModeV1::AirGapped
                            && self.local.manifest.profile_digest
                                == self.air_gapped.manifest.profile_digest
                            && local_expected == air_expected
                        {
                            Ok(())
                        } else {
                            Err(BundleContractErrorV1::ModeParityMismatch)
                        }
                    })
                })
            })
        })
    }
}

type ExpectedResultIdentity = (String, crate::ClaimLayerV1, [u8; 32]);

fn authoritative_expected_results(
    bundle: &ConformanceBundleV1,
) -> Result<BTreeMap<ExpectedResultIdentity, Vec<u8>>, BundleContractErrorV1> {
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
                    (
                        expected.case_id.clone(),
                        expected.claim_layer,
                        expected.execution_profile_digest,
                    ),
                    member.bytes.clone(),
                )
            })
        })
        .collect()
}
