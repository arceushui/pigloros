//! Signed, content-addressed Draft conformance bundles.
//!
//! This boundary materializes public bytes and expected results. It never
//! invokes the implementation under test: callers provide fixture and
//! expected-result members, while this module recomputes their digests,
//! validates them against CPF1, and verifies the bundle signature.

use ciborium::value::Value;
use ed25519_dalek::{Signer, Verifier};
use pos_core::{CanonicalBytes, PublicKey, Signature};
use pos_crypto::signing;
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Cursor;
use thiserror::Error;

use crate::{
    ClaimLayerV1, ConformanceProfileV1, ExecutionModeV1, ExpectedResultV1, ProfileLifecycleV1,
};

/// Magic for a materialized conformance bundle manifest.
pub const CONFORMANCE_BUNDLE_MAGIC_V1: &str = "CFB1";
/// Maximum encoded CFB1 archive size accepted by public verifiers.
pub const MAX_CONFORMANCE_BUNDLE_BYTES_V1: u64 = 1024 * 1024 * 1024;
const MAX_MEMBER_PATH_BYTES: usize = 256;
const MAX_MEMBERS: usize = 65_536;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BUNDLE_BYTES: u64 = MAX_CONFORMANCE_BUNDLE_BYTES_V1;
const MAX_PROFILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STRUCTURAL_NESTING: u8 = 32;
const PROFILE_MEMBER_PATH: &str = "profile/CPF1.cbor";
const INPUT_MEMBER_PREFIX: &str = "inputs/";
const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/execution-matrix.json";
const AUTHORITY_FIXTURE_IDS: [&str; 11] = [
    "RPL-001", "PRF-001", "PRF-002", "DIV-001", "INV-001", "INV-002", "INV-003", "RES-001",
    "LIVE-001", "ERA-001", "SEC-001",
];
const NON_INTERFERENCE_ROW_IDS: [&str; 12] = [
    "NI-TOOL-001",
    "NI-CACHE-002",
    "NI-STATE-003",
    "NI-OBS-004",
    "NI-TIME-005",
    "NI-PUBLIC-006",
    "NI-EVAL-007",
    "NI-FORK-008",
    "NI-ARCHIVE-009",
    "NI-NET-010",
    "NI-SERVICE-011",
    "NI-CRASH-012",
];
const NON_INTERFERENCE_VARIANTS: [&str; 4] = ["S", "D", "W", "C"];
const NON_INTERFERENCE_MODES: [&str; 4] = ["L", "A", "R", "F"];
const NON_INTERFERENCE_AUTH_EQ: &str = "control and canary runs have byte-identical authoritative Events, Timeline Order, permitted Projections, Plugin-visible snapshots/state, typed outcome, and visible authorization/causal records in all four modes";
const NON_INTERFERENCE_PUBLIC_EQ: [&str; 12] = [
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical including category, status order, cursor count, page count, and padded length; operational diagnostics omitted",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
    "byte-identical public status/error/cursor/export/evaluator input after the row's declared normalization",
];
const NON_INTERFERENCE_OP_EQ: [&str; 12] = [
    "count/category/digest, with provider text absent",
    "bounded hit-class counters after all key/value/latency fields are removed",
    "migration phase/category; no canary bytes or canary-derived digest",
    "schema/category/count/padded length; text, stack, path, raw IDs absent",
    "after deleting wall timestamps/durations; watchdog cannot create an authoritative Event or change public error category",
    "operational diagnostics omitted",
    "evaluator input member names/order/bytes/digests and ordered case outcomes are identical in all four modes",
    "all listed artifact bytes/digests/order and ADR-060 ReplayClaim are identical",
    "member names/order/modes/lengths/decompressed bytes are identical; canonical archive mode also requires archive bytes identical",
    "identical category/count with endpoint/body/timing absent; zero live calls in deterministic Local, Air-Gapped, Replay, and Fork",
    "request digests, call ordinals, projected response bytes, dependency edges, and outputs are identical",
    "safe category/count/padded length, with strings/stacks/dumps/paths absent",
];

/// Closed bundle failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BundleContractErrorV1 {
    /// A member path, size, or archive bound is invalid.
    #[error("conformance bundle member is invalid or out of bounds")]
    MemberOutOfBounds,
    /// A declared digest does not match the supplied bytes.
    #[error("conformance bundle member digest does not match its bytes")]
    MemberDigestMismatch,
    /// A required profile or expected-result member is absent.
    #[error("conformance bundle member is missing")]
    MemberMissing,
    /// The bundle contains a member that is not declared by its manifest.
    #[error("conformance bundle contains an undeclared member")]
    UndeclaredMember,
    /// A public fixture contains a private-key or secret marker.
    #[error("conformance bundle contains forbidden subject secret material")]
    SecretMaterialDetected,
    /// Only Draft bundles are valid for this contract. Candidate publication
    /// is governed by the separate #198 evidence workflow.
    #[error("conformance bundle lifecycle is not Draft")]
    LifecycleInvalid,
    /// The member manifest is not canonical.
    #[error("conformance bundle manifest is not in canonical order")]
    NonCanonicalOrder,
    /// A fixture expected result is empty or not bound to the CPF1 fixture.
    #[error("conformance bundle expected result is missing or mismatched")]
    ExpectedResultMismatch,
    /// Air-Gapped materialization attempted to use network-enabled input.
    #[error("Air-Gapped conformance bundle permits network access")]
    AirGappedNetwork,
    /// CPF1 bytes or the profile identity are invalid.
    #[error("conformance bundle profile is invalid")]
    ProfileInvalid,
    /// The signature over the immutable manifest is invalid or absent.
    #[error("conformance bundle signature is invalid")]
    SignatureInvalid,
    /// The Local and Air-Gapped bundles do not carry identical expected data.
    #[error("Local and Air-Gapped expected-result records differ")]
    ModeParityMismatch,
    /// Canonical manifest encoding failed.
    #[error("conformance bundle manifest encoding failed")]
    EncodingFailed,
    /// The public archive encoding is malformed or not canonical.
    #[error("conformance bundle archive encoding is invalid")]
    ArchiveEncodingInvalid,
}

/// The two execution modes materialized by #190.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BundleModeV1 {
    /// Local execution with the public adapter.
    Local,
    /// Air-Gapped execution with no online service.
    AirGapped,
}

impl BundleModeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Local => 0,
            Self::AirGapped => 1,
        }
    }
}

/// The authority-bearing role of one bundle member.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BundleMemberRoleV1 {
    /// A public fixture input declared by CPF1.
    FixtureInput,
    /// A public expected-result record declared by CPF1.
    ExpectedResult,
    /// The canonical CPF1 profile bytes.
    Profile,
    /// The normative requirements and specification artifact.
    NormativeSpecification,
    /// A public schema artifact.
    Schema,
    /// The governing licence artifact.
    Licence,
    /// The public notices artifact.
    Notice,
    /// The software bill of materials artifact.
    Sbom,
    /// The source/build/publication provenance artifact.
    Provenance,
    /// The limitations and exclusions artifact.
    Limitations,
    /// The checked-in #172 expected-authority inventory.
    AuthorityInventory,
    /// The accepted ADR-059 execution inventory.
    ExecutionMatrix,
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
        }
    }

    const fn is_supporting(self) -> bool {
        matches!(
            self,
            Self::NormativeSpecification
                | Self::Schema
                | Self::Licence
                | Self::Notice
                | Self::Sbom
                | Self::Provenance
                | Self::Limitations
        )
    }
}

/// One byte-bearing member in a materialized bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleMemberV1 {
    /// Canonical relative archive path.
    pub path: String,
    /// Raw public bytes.
    pub bytes: Vec<u8>,
    /// Recomputed BLAKE3 content address.
    pub digest: [u8; 32],
    /// Authority-bearing role committed by the manifest.
    pub role: BundleMemberRoleV1,
    /// Whether this member is an expected-result payload.
    ///
    /// This field remains as an explicit invariant seam for callers that
    /// classify expected-result members. Validation rejects disagreement with
    /// [`Self::role`].
    pub expected_result: bool,
}

impl BundleMemberV1 {
    /// Construct a member and derive its content address from the bytes.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: Vec<u8>, expected_result: bool) -> Self {
        let digest = *blake3::hash(&bytes).as_bytes();
        Self {
            path: path.into(),
            bytes,
            digest,
            role: if expected_result {
                BundleMemberRoleV1::ExpectedResult
            } else {
                BundleMemberRoleV1::FixtureInput
            },
            expected_result,
        }
    }

    /// Construct a typed public support artifact member.
    #[must_use]
    pub fn supporting(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        debug_assert!(role.is_supporting());
        let digest = *blake3::hash(&bytes).as_bytes();
        Self {
            path: path.into(),
            bytes,
            digest,
            role,
            expected_result: false,
        }
    }

    /// Construct an authority-bearing member.
    ///
    /// Authority inventory and execution-matrix members are public bundle
    /// inputs. Their bytes remain content-addressed and the complete role/path
    /// relationship is validated when the bundle is materialized or decoded.
    #[must_use]
    pub fn authority(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        let digest = *blake3::hash(&bytes).as_bytes();
        Self {
            path: path.into(),
            bytes,
            digest,
            role,
            expected_result: false,
        }
    }
}

/// One expected-result pointer in the immutable manifest.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BundleExpectedResultV1 {
    /// CPF1 fixture identity.
    pub case_id: String,
    /// CPF1 claim layer.
    pub claim_layer: ClaimLayerV1,
    /// CPF1 execution-profile identity.
    pub execution_profile_digest: [u8; 32],
    /// Execution mode represented by this bundle.
    pub mode: BundleModeV1,
    /// Relative path of the public expected-result member.
    pub member_path: String,
    /// Digest of the expected-result bytes.
    pub digest: [u8; 32],
}

/// Canonical manifest fields committed by the bundle signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleManifestV1 {
    /// Bundle magic.
    pub magic: String,
    /// Draft lifecycle.
    pub lifecycle: ProfileLifecycleV1,
    /// Local or Air-Gapped execution mode.
    pub mode: BundleModeV1,
    /// Logical CPF1 profile identity; the member descriptor commits its raw
    /// canonical bytes separately.
    pub profile_digest: [u8; 32],
    /// Canonically ordered member descriptors.
    pub members: Vec<BundleMemberDescriptorV1>,
    /// Canonically ordered expected-result pointers.
    pub expected_results: Vec<BundleExpectedResultV1>,
}

/// Digest/size descriptor committed for one member.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BundleMemberDescriptorV1 {
    /// Canonical relative archive path.
    pub path: String,
    /// Exact raw byte length.
    pub size_bytes: u64,
    /// BLAKE3 digest of the raw bytes.
    pub digest: [u8; 32],
    /// Authority-bearing member role.
    pub role: BundleMemberRoleV1,
}

/// One signed, immutable Draft bundle.
///
/// Candidate publication is intentionally outside this contract. The #198
/// governance workflow must provide the protected review, trusted-key
/// admission, and publication evidence before a Candidate bundle exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceBundleV1 {
    /// Signed manifest.
    pub manifest: BundleManifestV1,
    /// Raw members addressed by the manifest.
    pub members: Vec<BundleMemberV1>,
    /// Public key used to sign the manifest digest.
    pub signer_public_key: PublicKey,
    /// Signature over the canonical manifest bytes.
    pub signature: Signature,
}

impl ConformanceBundleV1 {
    /// Materialize an unsigned bundle from a validated CPF1 profile and public
    /// member bytes. The profile member is added from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the profile, members, or expected-result
    /// pointers cannot form a valid Draft bundle.
    pub fn materialize(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
        mut members: Vec<BundleMemberV1>,
        expected_results: Vec<BundleExpectedResultV1>,
    ) -> Result<Self, BundleContractErrorV1> {
        if profile.lifecycle != ProfileLifecycleV1::Draft {
            return Err(BundleContractErrorV1::LifecycleInvalid);
        }
        let profile_bytes = profile
            .to_canonical_cbor()
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        let mut profile_member = BundleMemberV1::new(PROFILE_MEMBER_PATH, profile_bytes, false);
        profile_member.role = BundleMemberRoleV1::Profile;
        members.push(profile_member);
        let mut bundle = Self {
            manifest: BundleManifestV1 {
                magic: CONFORMANCE_BUNDLE_MAGIC_V1.to_owned(),
                lifecycle: profile.lifecycle,
                mode,
                profile_digest: profile.profile_digest,
                members: Vec::new(),
                expected_results,
            },
            members,
            signer_public_key: PublicKey::from_bytes([0; 32]),
            signature: Signature::from_bytes([0; 64]),
        };
        bundle.rebuild_member_descriptors();
        bundle.validate_unsigned().map(|()| bundle)
    }

    /// Sign the canonical manifest with a caller-owned signing key.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the unsigned bundle is invalid.
    pub fn sign(
        mut self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, BundleContractErrorV1> {
        self.validate_unsigned().and_then(|()| {
            self.manifest_bytes().and_then(|bytes| {
                self.signer_public_key =
                    PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
                self.signature = Signature::from_bytes(signing_key.sign(&bytes).to_bytes());
                self.validate()
                    .map(|()| self)
                    .map_err(|_| BundleContractErrorV1::SignatureInvalid)
            })
        })
    }

    /// Validate bytes, manifest declarations, profile binding, expected
    /// results, and the cryptographic signature.
    ///
    /// # Errors
    ///
    /// Returns a closed error for any content, archive, profile, or signature
    /// violation.
    pub fn validate(&self) -> Result<(), BundleContractErrorV1> {
        self.validate_unsigned().and_then(|()| {
            signing::verifying_key_from_public_key(&self.signer_public_key)
                .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                .and_then(|key| {
                    self.manifest_bytes().and_then(|bytes| {
                        signing::verify(&key, &CanonicalBytes::from_vec(bytes), &self.signature)
                            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                    })
                })
        })
    }

    /// Return the content address of the canonical manifest.
    ///
    /// # Errors
    ///
    /// Returns [`BundleContractErrorV1::EncodingFailed`] if canonical encoding
    /// fails.
    pub fn bundle_digest(&self) -> Result<[u8; 32], BundleContractErrorV1> {
        self.manifest_bytes().map(|bytes| {
            let mut input = Vec::with_capacity(32 + bytes.len());
            input.extend_from_slice(b"PiglorOS.ConformanceBundle.v1\0");
            input.extend_from_slice(&bytes);
            *blake3::hash(&input).as_bytes()
        })
    }

    fn validate_unsigned(&self) -> Result<(), BundleContractErrorV1> {
        if self.manifest.magic != CONFORMANCE_BUNDLE_MAGIC_V1
            || !matches!(self.manifest.lifecycle, ProfileLifecycleV1::Draft)
            || self.members.is_empty()
        {
            return Err(BundleContractErrorV1::LifecycleInvalid);
        }
        validate_member_count(self.members.len())?;
        let profile_member = self
            .members
            .iter()
            .find(|member| {
                member.path == PROFILE_MEMBER_PATH
                    && member.role == BundleMemberRoleV1::Profile
                    && !member.expected_result
            })
            .ok_or(BundleContractErrorV1::MemberMissing)?;
        let profile = ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        let execution_mode = execution_mode_for_bundle(self.manifest.mode);
        if profile.lifecycle != self.manifest.lifecycle
            || profile.profile_digest != self.manifest.profile_digest
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        validate_fixture_inputs_for_mode(&profile, Some(self.manifest.mode), &self.members)?;
        if self.manifest.members.len() != self.members.len()
            || !strictly_ordered(&self.manifest.members)
            || !members_strictly_ordered(&self.members)
        {
            return Err(BundleContractErrorV1::NonCanonicalOrder);
        }
        let mut total_bytes = 0_u64;
        for (member, descriptor) in self.members.iter().zip(&self.manifest.members) {
            validate_member_path(&member.path)?;
            if descriptor.path != member.path {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if descriptor.role != member.role
                || member.expected_result != (member.role == BundleMemberRoleV1::ExpectedResult)
            {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            let expected_reference_count = self
                .manifest
                .expected_results
                .iter()
                .filter(|expected| expected.member_path == member.path)
                .count();
            if member.role == BundleMemberRoleV1::ExpectedResult && expected_reference_count != 1 {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if member.role == BundleMemberRoleV1::FixtureInput
                && !profile.fixtures.iter().any(|fixture| {
                    fixture.modes.contains(&execution_mode)
                        && fixture.inputs.iter().any(|input| {
                            member.path
                                == fixture_input_member_path(
                                    &fixture.case_id,
                                    fixture.claim_layer,
                                    &fixture.execution_profile_digest,
                                    &input.member_id,
                                )
                        })
                })
            {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if member.role == BundleMemberRoleV1::Profile && member.path != PROFILE_MEMBER_PATH {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if descriptor.size_bytes != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
                || descriptor.digest != member.digest
                || member.digest != *blake3::hash(&member.bytes).as_bytes()
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            total_bytes = accumulate_member_bytes(total_bytes, member.bytes.len() as u64)?;
            if contains_secret_marker(&member.bytes) {
                return Err(BundleContractErrorV1::SecretMaterialDetected);
            }
        }
        validate_total_bytes(total_bytes)?;
        validate_supporting_members(&profile, &self.members)?;
        validate_authority_members(&profile, &self.members)?;
        validate_selected_bundle_caps(&profile, self)?;
        validate_expected_results(&profile, &self.manifest, &self.members)
    }

    fn rebuild_member_descriptors(&mut self) {
        self.members
            .sort_by(|left, right| left.path.cmp(&right.path));
        self.manifest.members = self
            .members
            .iter()
            .map(|member| BundleMemberDescriptorV1 {
                path: member.path.clone(),
                size_bytes: member.bytes.len() as u64,
                digest: member.digest,
                role: member.role,
            })
            .collect();
        self.manifest.expected_results.sort_unstable();
    }

    /// Return the exact canonical bytes signed by this bundle.
    ///
    /// # Errors
    ///
    /// Returns [`BundleContractErrorV1::EncodingFailed`] when the manifest
    /// cannot be canonically encoded.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>, BundleContractErrorV1> {
        encode_archive_value(&manifest_value(&self.manifest))
    }

    /// Encode the complete immutable bundle as canonical public archive bytes.
    ///
    /// The archive carries the manifest, every raw member, the signer key, and
    /// the manifest signature. It is deterministic and contains no compression
    /// layer, so an independent evaluator can materialize and verify it without
    /// importing the implementation under test.
    ///
    /// # Errors
    ///
    /// Returns a closed error when validation, selected hard caps, or canonical
    /// encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, BundleContractErrorV1> {
        self.validate().and_then(|()| {
            let value = bundle_value(self);
            encode_archive_value(&value)
                .and_then(|bytes| validate_archive_caps(self, &value, bytes.len()).map(|()| bytes))
        })
    }

    /// Decode and validate complete canonical public archive bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed/noncanonical bytes, invalid bundle
    /// declarations, a profile-cap violation, or an invalid signature.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleContractErrorV1> {
        validate_archive_length(bytes.len())?;
        let preflight = preflight_archive_caps(bytes)?;
        let preflight_profile = ConformanceProfileV1::from_canonical_cbor(
            preflight
                .profile_bytes
                .ok_or(BundleContractErrorV1::MemberMissing)?,
        )
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        validate_preflight_archive_caps(&preflight_profile, &preflight, bytes.len())?;
        let archive: (Value, Value, Value, Vec<Value>, Value, Value) =
            ciborium::from_reader(Cursor::new(bytes))
                .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        let canonical_bytes = encode_archive_value(&archive)
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        if canonical_bytes.as_slice() != bytes {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let (magic, version, manifest_value, members, signer_value, signature_value) = archive;
        if archive_text(&magic)? != CONFORMANCE_BUNDLE_MAGIC_V1 || archive_u64(&version)? != 1 {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let manifest = decode_manifest(&manifest_value)?;
        let members = members
            .iter()
            .map(decode_member)
            .collect::<Result<Vec<_>, _>>()?;
        let signer_public_key = archive_digest::<32>(&signer_value)
            .map(PublicKey::from_bytes)
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        let signature = archive_digest::<64>(&signature_value)
            .map(Signature::from_bytes)
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        let bundle = Self {
            manifest,
            members,
            signer_public_key,
            signature,
        };
        bundle.validate().map(|()| bundle)
    }
}

/// Independently verify the public CFB1 archive envelope and every embedded
/// member, expected-result, profile, and signature digest.
///
/// This verifier intentionally operates on generic CBOR values rather than
/// decoding through [`ConformanceBundleV1`]. It is suitable for a publication
/// check performed by a separate consumer of the generated archive.
///
/// # Errors
///
/// Returns a closed bundle error when the archive is malformed, noncanonical,
/// internally inconsistent, or signed by a key that does not authenticate its
/// manifest.
pub fn verify_archive_independently(bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    validate_archive_length(bytes.len())?;
    let preflight = preflight_archive_caps(bytes)?;
    let profile_bytes = preflight
        .profile_bytes
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    let profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let caps = independent_archive_caps(profile_bytes)?;
    validate_independent_preflight_caps(&caps, &preflight, bytes.len())?;
    let archive: (Value, Value, Value, Vec<Value>, Value, Value) =
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
    if encode_archive_value(&archive)?.as_slice() != bytes {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    let (magic, version, manifest_value, members, public_key, signature) = archive;
    if archive_text(&magic)? != CONFORMANCE_BUNDLE_MAGIC_V1 || archive_u64(&version)? != 1 {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    let manifest = independent_array(&manifest_value, 6)?;
    let lifecycle = archive_u64(&manifest[1])?;
    let bundle_mode = archive_u64(&manifest[2])?;
    decode_bundle_mode(bundle_mode)?;
    if lifecycle != 0 {
        return Err(BundleContractErrorV1::LifecycleInvalid);
    }
    independent_verify_signature(&manifest_value, &public_key, &signature)?;
    let descriptors = independent_array_bounded(&manifest[4])?;
    if members.len() != descriptors.len() {
        return Err(BundleContractErrorV1::UndeclaredMember);
    }
    let (member_records, _) = independent_member_records(&members, descriptors)?;
    let expected_results = independent_array_bounded(&manifest[5])?;
    independent_verify_expected_results(expected_results, &member_records, &profile, bundle_mode)?;
    independent_verify_fixture_inputs(&member_records, &profile, bundle_mode)?;
    independent_verify_supporting_members(&member_records, &profile)?;
    independent_verify_authority_members(&member_records, &profile)?;
    independent_verify_profile(profile_bytes, lifecycle, &manifest[3])
}

fn independent_verify_signature(
    manifest: &Value,
    public_key: &Value,
    signature: &Value,
) -> Result<(), BundleContractErrorV1> {
    encode_archive_value(manifest).and_then(|manifest_bytes| {
        independent_digest::<32>(public_key).and_then(|public_key| {
            independent_digest::<64>(signature).and_then(|signature| {
                ed25519_dalek::VerifyingKey::from_bytes(&public_key)
                    .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                    .and_then(|verifying_key| {
                        verifying_key
                            .verify(
                                &manifest_bytes,
                                &ed25519_dalek::Signature::from_bytes(&signature),
                            )
                            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                    })
            })
        })
    })
}

struct IndependentMember<'a> {
    path: &'a str,
    bytes: &'a [u8],
    digest: [u8; 32],
    role: BundleMemberRoleV1,
}

fn independent_member_records<'a>(
    members: &'a [Value],
    descriptors: &[Value],
) -> Result<(Vec<IndependentMember<'a>>, Option<&'a [u8]>), BundleContractErrorV1> {
    let mut normalized_member_paths = BTreeSet::new();
    let mut records = Vec::with_capacity(members.len());
    let mut profile_bytes = None;
    let mut previous_member_path = None;
    for (member_value, descriptor_value) in members.iter().zip(descriptors) {
        let member = independent_array(member_value, 3)?;
        let descriptor = independent_array(descriptor_value, 4)?;
        let member_path = archive_text(&member[0])?;
        let member_bytes = archive_bytes(&member[1])?;
        let member_role = decode_member_role(archive_u64(&member[2])?)?;
        let descriptor_role = decode_member_role(archive_u64(&descriptor[3])?)?;
        let descriptor_digest = independent_digest::<32>(&descriptor[2])?;
        validate_member_path(member_path)?;
        if previous_member_path.is_some_and(|previous| previous >= member_path)
            || !normalized_member_paths.insert(member_path.to_ascii_lowercase())
        {
            return Err(BundleContractErrorV1::NonCanonicalOrder);
        }
        previous_member_path = Some(member_path);
        if archive_text(&descriptor[0])? != member_path || descriptor_role != member_role {
            return Err(BundleContractErrorV1::UndeclaredMember);
        }
        if archive_u64(&descriptor[1])? != u64::try_from(member_bytes.len()).unwrap_or(u64::MAX)
            || descriptor_digest != *blake3::hash(member_bytes).as_bytes()
        {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
        if contains_secret_marker(member_bytes) {
            return Err(BundleContractErrorV1::SecretMaterialDetected);
        }
        if member_role == BundleMemberRoleV1::Profile
            && (member_path != PROFILE_MEMBER_PATH || profile_bytes.replace(member_bytes).is_some())
        {
            return Err(BundleContractErrorV1::MemberMissing);
        }
        records.push(IndependentMember {
            path: member_path,
            bytes: member_bytes,
            digest: descriptor_digest,
            role: member_role,
        });
    }
    Ok((records, profile_bytes))
}

fn independent_verify_expected_results(
    expected_results: &[Value],
    members: &[IndependentMember<'_>],
    profile: &Value,
    bundle_mode: u64,
) -> Result<(), BundleContractErrorV1> {
    let profile_fields = independent_array(profile, 17)?;
    let fixtures = independent_array_bounded(&profile_fields[8])?;
    let mut referenced_expected_results = BTreeSet::new();
    let mut referenced_fixture_identities = BTreeSet::new();
    for expected_value in expected_results {
        let expected = independent_array(expected_value, 6)?;
        let path = archive_text(&expected[4])?;
        if !referenced_expected_results.insert(path.to_owned()) {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let Some(member) = members.iter().find(|member| member.path == path) else {
            return Err(BundleContractErrorV1::MemberMissing);
        };
        if member.role != BundleMemberRoleV1::ExpectedResult
            || independent_digest::<32>(&expected[5])? != member.digest
        {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let case_id = archive_text(&expected[0])?;
        let claim_layer_code = archive_u64(&expected[1])?;
        let claim_layer = decode_claim_layer(claim_layer_code)?;
        let execution_profile_digest = independent_digest::<32>(&expected[2])?;
        referenced_fixture_identities.insert((
            case_id.to_owned(),
            claim_layer_code,
            execution_profile_digest,
        ));
        let expected_mode = archive_u64(&expected[3])?;
        decode_bundle_mode(expected_mode)?;
        let Some(fixture) = fixtures.iter().find_map(|fixture_value| {
            let Ok(fixture) = independent_array(fixture_value, 17) else {
                return None;
            };
            let Ok(modes) = independent_array_bounded(&fixture[5]) else {
                return None;
            };
            if expected_mode == bundle_mode
                && archive_text(&fixture[0]).ok() == Some(case_id)
                && archive_u64(&fixture[2]).ok() == Some(claim_layer_code)
                && independent_digest::<32>(&fixture[3]).ok() == Some(execution_profile_digest)
                && modes
                    .iter()
                    .any(|mode| archive_u64(mode).ok() == Some(bundle_mode))
            {
                Some(fixture)
            } else {
                None
            }
        }) else {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        };
        let expected_bytes = independent_expected_result_bytes(&fixture[8])?;
        if path != independent_expected_member_path(case_id, claim_layer, &execution_profile_digest)
            || member.bytes != expected_bytes.as_slice()
        {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
    }
    let member_expected_paths = members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::ExpectedResult)
        .map(|member| member.path.to_owned())
        .collect::<BTreeSet<_>>();
    if member_expected_paths != referenced_expected_results {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    for fixture_value in fixtures {
        let fixture = independent_array(fixture_value, 17)?;
        let mandatory = match &fixture[1] {
            Value::Bool(value) => *value,
            _ => return Err(BundleContractErrorV1::ExpectedResultMismatch),
        };
        let selected = independent_array_bounded(&fixture[5])?
            .iter()
            .any(|mode| archive_u64(mode).ok() == Some(bundle_mode));
        let fixture_identity = (
            archive_text(&fixture[0])?.to_owned(),
            archive_u64(&fixture[2])?,
            independent_digest::<32>(&fixture[3])?,
        );
        if mandatory && selected && !referenced_fixture_identities.contains(&fixture_identity) {
            return Err(BundleContractErrorV1::MemberMissing);
        }
    }
    Ok(())
}

fn independent_expected_result_bytes(value: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    let fields = independent_array(value, 5)?;
    match archive_u64(&fields[0])? {
        0 => {
            let bytes = archive_bytes(&fields[1])?;
            if independent_digest::<32>(&fields[2])? != *blake3::hash(bytes).as_bytes() {
                return Err(BundleContractErrorV1::ExpectedResultMismatch);
            }
            Ok(bytes.to_vec())
        }
        1 | 2 => encode_archive_value(value),
        _ => Err(BundleContractErrorV1::ExpectedResultMismatch),
    }
}

fn independent_verify_fixture_inputs(
    members: &[IndependentMember<'_>],
    profile: &Value,
    bundle_mode: u64,
) -> Result<(), BundleContractErrorV1> {
    let profile_fields = independent_array(profile, 17)?;
    let fixtures = independent_array_bounded(&profile_fields[8])?;
    let mut declared_paths = BTreeSet::new();
    for fixture_value in fixtures {
        let fixture = independent_array(fixture_value, 17)?;
        if !independent_array_bounded(&fixture[5])?
            .iter()
            .any(|mode| archive_u64(mode).ok() == Some(bundle_mode))
        {
            continue;
        }
        let case_id = archive_text(&fixture[0])?;
        let claim_layer_code = archive_u64(&fixture[2])?;
        let execution_profile_digest = independent_digest::<32>(&fixture[3])?;
        for input_value in independent_array_bounded(&fixture[7])? {
            let input = independent_array(input_value, 4)?;
            let member_id = archive_text(&input[0])?;
            let path = independent_input_member_path(
                case_id,
                claim_layer_code,
                &execution_profile_digest,
                member_id,
            );
            if !declared_paths.insert(path.clone()) {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            let Some(member) = members.iter().find(|member| member.path == path) else {
                return Err(BundleContractErrorV1::MemberMissing);
            };
            if member.role != BundleMemberRoleV1::FixtureInput
                || member.bytes.is_empty()
                || archive_u64(&input[1])? != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
                || independent_digest::<32>(&input[2])? != member.digest
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
        }
    }
    if members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::FixtureInput)
        .any(|member| !declared_paths.contains(member.path))
    {
        return Err(BundleContractErrorV1::UndeclaredMember);
    }
    Ok(())
}

fn independent_input_member_path(
    case_id: &str,
    claim_layer_code: u64,
    execution_profile_digest: &[u8; 32],
    member_id: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"PiglorOS.CPF1InputPath.v1\0");
    append_path_component(&mut input, case_id);
    input.push(u8::try_from(claim_layer_code).unwrap_or(u8::MAX));
    input.extend_from_slice(execution_profile_digest);
    append_path_component(&mut input, member_id);
    format!("inputs/{}.bin", blake3::hash(&input).to_hex())
}

const INDEPENDENT_SUPPORT_MEMBERS: [(BundleMemberRoleV1, &str); 7] = [
    (
        BundleMemberRoleV1::NormativeSpecification,
        "support/normative-requirements.md",
    ),
    (BundleMemberRoleV1::Schema, "support/schema-cpf1-v1.cddl"),
    (BundleMemberRoleV1::Licence, "support/LICENSE"),
    (BundleMemberRoleV1::Notice, "support/NOTICE"),
    (BundleMemberRoleV1::Sbom, "support/sbom.json"),
    (BundleMemberRoleV1::Provenance, "support/provenance.json"),
    (BundleMemberRoleV1::Limitations, "support/limitations.md"),
];

fn independent_verify_supporting_members(
    members: &[IndependentMember<'_>],
    profile: &Value,
) -> Result<(), BundleContractErrorV1> {
    let profile_fields = independent_array(profile, 17)?;
    let fixtures = independent_array_bounded(&profile_fields[8])?;
    for (role, path) in INDEPENDENT_SUPPORT_MEMBERS {
        let matching = members
            .iter()
            .filter(|member| member.role == role)
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].path != path || matching[0].bytes.is_empty() {
            return Err(BundleContractErrorV1::MemberMissing);
        }
        let expected_digests = independent_support_digests(profile_fields, fixtures, role)?;
        if !expected_digests.contains(&matching[0].digest) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
}

fn independent_support_digests(
    profile_fields: &[Value],
    fixtures: &[Value],
    role: BundleMemberRoleV1,
) -> Result<BTreeSet<[u8; 32]>, BundleContractErrorV1> {
    let mut digests = BTreeSet::new();
    match role {
        BundleMemberRoleV1::NormativeSpecification => {
            digests.insert(independent_digest::<32>(&profile_fields[5])?);
        }
        BundleMemberRoleV1::Schema => {
            for digest in independent_array_bounded(&profile_fields[7])? {
                digests.insert(independent_digest::<32>(digest)?);
            }
            for fixture_value in fixtures {
                let fixture = independent_array(fixture_value, 17)?;
                digests.insert(independent_digest::<32>(&fixture[4])?);
            }
        }
        BundleMemberRoleV1::Licence => {
            for fixture_value in fixtures {
                let provenance = independent_array(&independent_array(fixture_value, 17)?[15], 7)?;
                let licence_id = archive_text(&provenance[0])?;
                let mut bytes = licence_id.as_bytes().to_vec();
                bytes.push(b'\n');
                digests.insert(*blake3::hash(&bytes).as_bytes());
            }
        }
        BundleMemberRoleV1::Notice => {
            for fixture_value in fixtures {
                let provenance = independent_array(&independent_array(fixture_value, 17)?[15], 7)?;
                digests.insert(independent_digest::<32>(&provenance[1])?);
            }
        }
        BundleMemberRoleV1::Sbom => {
            for fixture_value in fixtures {
                let provenance = independent_array(&independent_array(fixture_value, 17)?[15], 7)?;
                digests.insert(independent_digest::<32>(&provenance[2])?);
            }
        }
        BundleMemberRoleV1::Provenance => {
            digests.insert(independent_digest::<32>(&profile_fields[14])?);
            for fixture_value in fixtures {
                let provenance = independent_array(&independent_array(fixture_value, 17)?[15], 7)?;
                for index in [3, 4, 5] {
                    digests.insert(independent_digest::<32>(&provenance[index])?);
                }
            }
        }
        BundleMemberRoleV1::Limitations => {
            digests.insert(independent_digest::<32>(&profile_fields[13])?);
            for fixture_value in fixtures {
                let provenance = independent_array(&independent_array(fixture_value, 17)?[15], 7)?;
                digests.insert(independent_digest::<32>(&provenance[6])?);
            }
        }
        _ => {}
    }
    Ok(digests)
}

fn independent_verify_authority_members(
    members: &[IndependentMember<'_>],
    profile: &Value,
) -> Result<(), BundleContractErrorV1> {
    let inventory = independent_unique_member(
        members,
        BundleMemberRoleV1::AuthorityInventory,
        AUTHORITY_INVENTORY_MEMBER_PATH,
    )?;
    let matrix = independent_unique_member(
        members,
        BundleMemberRoleV1::ExecutionMatrix,
        EXECUTION_MATRIX_MEMBER_PATH,
    )?;
    independent_unique_member(
        members,
        BundleMemberRoleV1::Provenance,
        "support/provenance.json",
    )?;
    let inventory_json = parse_authority_json(inventory.bytes)?;
    let matrix_json = parse_authority_json(matrix.bytes)?;
    let profile_fields = independent_array(profile, 17)?;
    let profile_id = archive_text(&profile_fields[2])?;
    if crate::requires_execution_matrix_binding(profile_id) || profile_id.contains("#matrix=") {
        let bound_matrix_digest = independent_matrix_digest(profile_id)?;
        if bound_matrix_digest != *blake3::hash(matrix.bytes).as_bytes() {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    let inventory_lifecycle = json_text(&inventory_json, "lifecycle")?;
    let matrix_lifecycle = json_text(&matrix_json, "lifecycle")?;
    if json_text(&inventory_json, "magic")? != "W8H1"
        || json_u64(&inventory_json, "version")? != 1
        || json_text(&inventory_json, "digest_algorithm")? != "BLAKE3-256"
        || json_text(&matrix_json, "magic")? != "NIM1"
        || json_u64(&matrix_json, "version")? != 1
        || inventory_lifecycle != matrix_lifecycle
        || inventory_lifecycle != "Draft"
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let entries = inventory_json
        .get("entries")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    if entries.len() != AUTHORITY_FIXTURE_IDS.len()
        || entries
            .iter()
            .zip(AUTHORITY_FIXTURE_IDS)
            .any(|(entry, id)| json_text(entry, "fixture_id") != Ok(id))
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    independent_validate_draft_authority_entries(entries)
}

fn independent_validate_draft_authority_entries(
    entries: &[JsonValue],
) -> Result<(), BundleContractErrorV1> {
    if entries.iter().any(|entry| {
        json_text(entry, "materialization_status") != Ok("pending")
            || !entry
                .get("fixture_bytes_path")
                .is_some_and(JsonValue::is_null)
            || !entry
                .get("fixture_bytes_digest")
                .is_some_and(JsonValue::is_null)
            || !entry
                .get("expected_result_path")
                .is_some_and(JsonValue::is_null)
            || !entry
                .get("expected_result_digest")
                .is_some_and(JsonValue::is_null)
    }) {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    Ok(())
}

fn independent_unique_member<'a>(
    members: &'a [IndependentMember<'a>],
    role: BundleMemberRoleV1,
    path: &str,
) -> Result<&'a IndependentMember<'a>, BundleContractErrorV1> {
    let mut matching = members
        .iter()
        .filter(|member| member.role == role && member.path == path);
    let member = matching
        .next()
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    if matching.next().is_some() {
        Err(BundleContractErrorV1::MemberMissing)
    } else {
        Ok(member)
    }
}

fn independent_matrix_digest(profile_id: &str) -> Result<[u8; 32], BundleContractErrorV1> {
    let Some((base, encoded_digest)) = profile_id.split_once("#matrix=") else {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    };
    if !crate::requires_execution_matrix_binding(profile_id)
        || base.is_empty()
        || encoded_digest.contains("#matrix=")
        || encoded_digest.len() != 64
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let digest = crate::decode_hex_digest(encoded_digest)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    if digest == [0; 32] {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    } else {
        Ok(digest)
    }
}

fn independent_expected_member_path(
    case_id: &str,
    claim_layer: ClaimLayerV1,
    execution_profile_digest: &[u8; 32],
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"PiglorOS.CPF1ExpectedPath.v1\0");
    append_path_component(&mut input, case_id);
    input.push(claim_layer_code(claim_layer));
    input.extend_from_slice(execution_profile_digest);
    format!("expected/{}.bin", blake3::hash(&input).to_hex())
}

fn independent_verify_profile(
    profile_bytes: &[u8],
    lifecycle: u64,
    manifest_profile_digest: &Value,
) -> Result<(), BundleContractErrorV1> {
    let profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let profile_fields = independent_array(&profile, 17)?;
    if archive_text(&profile_fields[0])? != "CPF1"
        || archive_u64(&profile_fields[1])? != 1
        || archive_u64(&profile_fields[4])? != lifecycle
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let embedded_profile_digest = independent_digest::<32>(&profile_fields[16])?;
    if embedded_profile_digest != independent_digest::<32>(manifest_profile_digest)? {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let mut profile_identity = profile_fields.to_vec();
    profile_identity[16] = Value::Null;
    let stable_evidence_digest = independent_domain_digest(
        b"PiglorOS.ConformanceProfileStableEvidence.v1",
        &Value::Array(Vec::new()),
    );
    let recomputed_profile_digest = independent_domain_digest(
        b"PiglorOS.ConformanceProfile.v1",
        &Value::Array(vec![
            Value::Array(profile_identity),
            Value::Bytes(stable_evidence_digest.to_vec()),
        ]),
    );
    if embedded_profile_digest != recomputed_profile_digest {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    Ok(())
}

fn independent_array(value: &Value, length: usize) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn independent_array_bounded(value: &Value) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(values) if values.len() <= MAX_MEMBERS => Ok(values),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn independent_digest<const N: usize>(value: &Value) -> Result<[u8; N], BundleContractErrorV1> {
    archive_bytes(value)?
        .try_into()
        .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
}

fn independent_domain_digest(domain: &[u8], value: &Value) -> [u8; 32] {
    let mut encoded = Vec::new();
    // `Vec<u8>` has an infallible `Write` implementation. The serializer's
    // result therefore has no reachable error state at this boundary.
    drop(ciborium::into_writer(value, &mut encoded));
    let mut input = Vec::with_capacity(domain.len() + encoded.len() + 1);
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(&encoded);
    *blake3::hash(&input).as_bytes()
}

fn bundle_value(bundle: &ConformanceBundleV1) -> Value {
    Value::Array(vec![
        Value::Text(CONFORMANCE_BUNDLE_MAGIC_V1.to_owned()),
        Value::Integer(1_u64.into()),
        manifest_value(&bundle.manifest),
        Value::Array(
            bundle
                .members
                .iter()
                .map(|member| {
                    Value::Array(vec![
                        Value::Text(member.path.clone()),
                        Value::Bytes(member.bytes.clone()),
                        Value::Integer(member.role.code().into()),
                    ])
                })
                .collect(),
        ),
        Value::Bytes(bundle.signer_public_key.as_bytes().to_vec()),
        Value::Bytes(bundle.signature.as_bytes().to_vec()),
    ])
}

fn encode_archive_value<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, BundleContractErrorV1> {
    let mut bytes = Vec::new();
    encode_archive_value_to_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn encode_archive_value_to_writer<T: serde::Serialize, W: std::io::Write>(
    value: &T,
    writer: W,
) -> Result<(), BundleContractErrorV1> {
    ciborium::into_writer(value, writer).map_err(|_| BundleContractErrorV1::EncodingFailed)
}

fn validate_archive_length(length: usize) -> Result<(), BundleContractErrorV1> {
    if u64::try_from(length).unwrap_or(u64::MAX) > MAX_TOTAL_BUNDLE_BYTES {
        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn preflight_archive(bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    fn length(
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
        if depth > MAX_STRUCTURAL_NESTING {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let initial = *bytes
            .get(*index)
            .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
        *index += 1;
        let major = initial >> 5;
        let item_length = length(bytes, index, initial & 0x1f)?;
        match major {
            0 | 1 => Ok(()),
            2 => {
                validate_member_size(item_length)
                    .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
                let end = index.saturating_add(usize::try_from(item_length).unwrap_or(usize::MAX));
                *index = end;
                if end <= bytes.len() {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::ArchiveEncodingInvalid)
                }
            }
            3 => {
                if item_length > u64::try_from(MAX_MEMBER_PATH_BYTES).unwrap_or(u64::MAX) {
                    return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
                }
                let end = index.saturating_add(usize::try_from(item_length).unwrap_or(usize::MAX));
                *index = end;
                if end <= bytes.len() {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::ArchiveEncodingInvalid)
                }
            }
            4 => {
                if item_length > u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX) {
                    return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
                }
                for _ in 0..item_length {
                    item(bytes, index, depth + 1)?;
                }
                Ok(())
            }
            7 => match initial & 0x1f {
                20..=22 => Ok(()),
                _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
            },
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

struct ArchivePreflight<'a> {
    profile_bytes: Option<&'a [u8]>,
    member_count: usize,
    total_member_bytes: u64,
    largest_member_bytes: u64,
    largest_member_path_bytes: usize,
    maximum_depth: usize,
}

struct ScannedArchiveItem<'a> {
    bytes: Option<&'a [u8]>,
    text_bytes: Option<usize>,
    unsigned: Option<u64>,
    maximum_depth: usize,
}

struct IndependentArchiveCaps {
    profile_bytes: u64,
    bundle_members: u64,
    member_path_bytes: u64,
    member_bytes: u64,
    total_bundle_bytes: u64,
    structural_nesting: u64,
}

mod archive_preflight {
    use super::{
        ArchivePreflight, BundleContractErrorV1, BundleMemberRoleV1, ScannedArchiveItem,
        MAX_MEMBERS, MAX_MEMBER_BYTES, MAX_MEMBER_PATH_BYTES, MAX_STRUCTURAL_NESTING,
    };

    fn length(
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

    fn array_length(bytes: &[u8], index: &mut usize) -> Result<u64, BundleContractErrorV1> {
        let initial = *bytes
            .get(*index)
            .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
        *index += 1;
        if initial >> 5 != 4 {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let length = length(bytes, index, initial & 0x1f)?;
        if length > u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX) {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        Ok(length)
    }

    fn item<'a>(
        bytes: &'a [u8],
        index: &mut usize,
        depth: usize,
    ) -> Result<ScannedArchiveItem<'a>, BundleContractErrorV1> {
        if depth > usize::from(MAX_STRUCTURAL_NESTING) {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let initial = *bytes
            .get(*index)
            .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
        *index += 1;
        let major = initial >> 5;
        let item_length = length(bytes, index, initial & 0x1f)?;
        let mut scanned = ScannedArchiveItem {
            bytes: None,
            text_bytes: None,
            unsigned: None,
            maximum_depth: depth,
        };
        match major {
            0 => scanned.unsigned = Some(item_length),
            1 => {}
            2 => {
                if item_length > MAX_MEMBER_BYTES {
                    return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
                }
                let end = index.saturating_add(usize::try_from(item_length).unwrap_or(usize::MAX));
                scanned.bytes = Some(
                    bytes
                        .get(*index..end)
                        .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?,
                );
                *index = end;
            }
            3 => {
                if item_length > u64::try_from(MAX_MEMBER_PATH_BYTES).unwrap_or(u64::MAX) {
                    return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
                }
                let end = index.saturating_add(usize::try_from(item_length).unwrap_or(usize::MAX));
                bytes
                    .get(*index..end)
                    .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
                scanned.text_bytes = Some(usize::try_from(item_length).unwrap_or(usize::MAX));
                *index = end;
            }
            4 => {
                if item_length > u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX) {
                    return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
                }
                for _ in 0..item_length {
                    let child = item(bytes, index, depth + 1)?;
                    scanned.maximum_depth = scanned.maximum_depth.max(child.maximum_depth);
                }
            }
            7 => match initial & 0x1f {
                20..=22 => {}
                _ => return Err(BundleContractErrorV1::ArchiveEncodingInvalid),
            },
            _ => return Err(BundleContractErrorV1::ArchiveEncodingInvalid),
        }
        Ok(scanned)
    }

    fn members<'a>(
        bytes: &'a [u8],
        index: &mut usize,
        depth: usize,
    ) -> Result<ArchivePreflight<'a>, BundleContractErrorV1> {
        let member_count = array_length(bytes, index)?;
        let mut result = ArchivePreflight {
            profile_bytes: None,
            member_count: usize::try_from(member_count).unwrap_or(usize::MAX),
            total_member_bytes: 0,
            largest_member_bytes: 0,
            largest_member_path_bytes: 0,
            maximum_depth: depth,
        };
        for _ in 0..member_count {
            if array_length(bytes, index)? != 3 {
                return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
            }
            let member_depth = depth + 1;
            let path = item(bytes, index, member_depth + 1)?;
            let member = item(bytes, index, member_depth + 1)?;
            let role = item(bytes, index, member_depth + 1)?;
            let role_depth = role.maximum_depth;
            let path_bytes = path
                .text_bytes
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
            let member_bytes = member
                .bytes
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
            let role = role
                .unsigned
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
            result.maximum_depth = result
                .maximum_depth
                .max(path.maximum_depth)
                .max(member.maximum_depth)
                .max(role_depth);
            result.largest_member_path_bytes = result.largest_member_path_bytes.max(path_bytes);
            result.largest_member_bytes = result
                .largest_member_bytes
                .max(u64::try_from(member_bytes.len()).unwrap_or(u64::MAX));
            result.total_member_bytes = result
                .total_member_bytes
                .saturating_add(u64::try_from(member_bytes.len()).unwrap_or(u64::MAX));
            if role == BundleMemberRoleV1::Profile.code()
                && result.profile_bytes.replace(member_bytes).is_some()
            {
                return Err(BundleContractErrorV1::MemberMissing);
            }
            result.maximum_depth = result.maximum_depth.max(member_depth);
        }
        Ok(result)
    }

    pub(super) fn scan(bytes: &[u8]) -> Result<ArchivePreflight<'_>, BundleContractErrorV1> {
        let mut index = 0;
        if array_length(bytes, &mut index)? != 6 {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let mut maximum_depth = 1;
        for _ in 0..3 {
            let field = item(bytes, &mut index, 2)?;
            maximum_depth = maximum_depth.max(field.maximum_depth);
        }
        let mut result = members(bytes, &mut index, 2)?;
        for _ in 0..2 {
            let field = item(bytes, &mut index, 2)?;
            maximum_depth = maximum_depth.max(field.maximum_depth);
        }
        maximum_depth = maximum_depth.max(result.maximum_depth);
        if index != bytes.len() {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        result.maximum_depth = maximum_depth;
        Ok(result)
    }
}

fn preflight_archive_caps(bytes: &[u8]) -> Result<ArchivePreflight<'_>, BundleContractErrorV1> {
    archive_preflight::scan(bytes)
}

fn validate_preflight_archive_caps(
    profile: &ConformanceProfileV1,
    preflight: &ArchivePreflight<'_>,
    encoded_len: usize,
) -> Result<(), BundleContractErrorV1> {
    let caps = &profile.evaluator_protocol.hard_caps;
    if u64::try_from(encoded_len).unwrap_or(u64::MAX) > caps.max_total_bundle_bytes
        || u64::try_from(preflight.profile_bytes.map_or(0, <[u8]>::len)).unwrap_or(u64::MAX)
            > caps.max_profile_bytes
        || preflight.maximum_depth > usize::from(caps.max_structural_nesting)
        || preflight.member_count > usize::try_from(caps.max_bundle_members).unwrap_or(usize::MAX)
        || preflight.largest_member_path_bytes > usize::from(caps.max_member_path_bytes)
        || preflight.largest_member_bytes > caps.max_member_bytes
        || preflight.total_member_bytes > caps.max_total_bundle_bytes
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    caps.validate_compression_expansion(
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
    )
    .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)
}

fn independent_archive_caps(
    profile_bytes: &[u8],
) -> Result<IndependentArchiveCaps, BundleContractErrorV1> {
    let profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    if encode_archive_value(&profile)?.as_slice() != profile_bytes {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let fields =
        independent_array(&profile, 17).map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let protocol =
        independent_array(&fields[10], 5).map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let caps =
        independent_array(&protocol[4], 10).map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let values = caps
        .iter()
        .map(|value| archive_u64(value).map_err(|_| BundleContractErrorV1::ProfileInvalid))
        .collect::<Result<Vec<_>, _>>()?;
    let max_profile_bytes = &values[0];
    let max_cases = &values[1];
    let max_bundle_members = &values[2];
    let max_member_path_bytes = &values[3];
    let max_member_bytes = &values[4];
    let max_total_bundle_bytes = &values[5];
    let max_compression_expansion = &values[6];
    let max_structural_nesting = &values[7];
    if *max_profile_bytes == 0
        || *max_profile_bytes > MAX_PROFILE_BYTES
        || *max_cases == 0
        || *max_cases > u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX)
        || *max_bundle_members == 0
        || *max_bundle_members > u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX)
        || *max_member_path_bytes == 0
        || *max_member_path_bytes > u64::try_from(MAX_MEMBER_PATH_BYTES).unwrap_or(u64::MAX)
        || *max_member_bytes == 0
        || *max_member_bytes > MAX_MEMBER_BYTES
        || *max_total_bundle_bytes == 0
        || *max_total_bundle_bytes > MAX_TOTAL_BUNDLE_BYTES
        || *max_compression_expansion == 0
        || *max_compression_expansion > u64::from(u32::MAX)
        || *max_structural_nesting == 0
        || *max_structural_nesting > u64::from(MAX_STRUCTURAL_NESTING)
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    Ok(IndependentArchiveCaps {
        profile_bytes: *max_profile_bytes,
        bundle_members: *max_bundle_members,
        member_path_bytes: *max_member_path_bytes,
        member_bytes: *max_member_bytes,
        total_bundle_bytes: *max_total_bundle_bytes,
        structural_nesting: *max_structural_nesting,
    })
}

fn validate_independent_preflight_caps(
    caps: &IndependentArchiveCaps,
    preflight: &ArchivePreflight<'_>,
    encoded_len: usize,
) -> Result<(), BundleContractErrorV1> {
    let encoded_len = u64::try_from(encoded_len).unwrap_or(u64::MAX);
    if encoded_len > caps.total_bundle_bytes
        || u64::try_from(preflight.profile_bytes.map_or(0, <[u8]>::len)).unwrap_or(u64::MAX)
            > caps.profile_bytes
        || u64::try_from(preflight.maximum_depth).unwrap_or(u64::MAX) > caps.structural_nesting
        || u64::try_from(preflight.member_count).unwrap_or(u64::MAX) > caps.bundle_members
        || u64::try_from(preflight.largest_member_path_bytes).unwrap_or(u64::MAX)
            > caps.member_path_bytes
        || preflight.largest_member_bytes > caps.member_bytes
        || preflight.total_member_bytes > caps.total_bundle_bytes
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    Ok(())
}

fn validate_archive_caps(
    bundle: &ConformanceBundleV1,
    value: &Value,
    encoded_len: usize,
) -> Result<(), BundleContractErrorV1> {
    let profile_member = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    let profile = ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let caps = &profile.evaluator_protocol.hard_caps;
    if u64::try_from(encoded_len).unwrap_or(u64::MAX) > caps.max_total_bundle_bytes
        || value_depth(value) > usize::from(caps.max_structural_nesting)
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    caps.validate_compression_expansion(
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
    )
    .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)
}

fn decode_manifest(value: &Value) -> Result<BundleManifestV1, BundleContractErrorV1> {
    let fields = archive_array_exact(value, 6)?;
    let members = archive_array_bounded(&fields[4], MAX_MEMBERS)?
        .iter()
        .map(|value| {
            let fields = archive_array_exact(value, 4)?;
            Ok(BundleMemberDescriptorV1 {
                path: archive_text(&fields[0])?.to_owned(),
                size_bytes: archive_u64(&fields[1])?,
                digest: archive_digest(&fields[2])?,
                role: decode_member_role(archive_u64(&fields[3])?)?,
            })
        })
        .collect::<Result<Vec<_>, BundleContractErrorV1>>()?;
    let expected_results = archive_array_bounded(&fields[5], MAX_MEMBERS)?
        .iter()
        .map(|value| {
            let fields = archive_array_exact(value, 6)?;
            Ok(BundleExpectedResultV1 {
                case_id: archive_text(&fields[0])?.to_owned(),
                claim_layer: decode_claim_layer(archive_u64(&fields[1])?)?,
                execution_profile_digest: archive_digest(&fields[2])?,
                mode: decode_bundle_mode(archive_u64(&fields[3])?)?,
                member_path: archive_text(&fields[4])?.to_owned(),
                digest: archive_digest(&fields[5])?,
            })
        })
        .collect::<Result<Vec<_>, BundleContractErrorV1>>()?;
    Ok(BundleManifestV1 {
        magic: archive_text(&fields[0])?.to_owned(),
        lifecycle: decode_lifecycle(archive_u64(&fields[1])?)?,
        mode: decode_bundle_mode(archive_u64(&fields[2])?)?,
        profile_digest: archive_digest(&fields[3])?,
        members,
        expected_results,
    })
}

fn decode_member(value: &Value) -> Result<BundleMemberV1, BundleContractErrorV1> {
    archive_array_exact(value, 3).and_then(|fields| {
        archive_text(&fields[0]).and_then(|path| {
            archive_bytes(&fields[1]).and_then(|bytes| {
                archive_u64(&fields[2])
                    .and_then(decode_member_role)
                    .map(|role| BundleMemberV1 {
                        path: path.to_owned(),
                        digest: *blake3::hash(bytes).as_bytes(),
                        bytes: bytes.to_vec(),
                        role,
                        expected_result: role == BundleMemberRoleV1::ExpectedResult,
                    })
            })
        })
    })
}

fn archive_array_exact(
    value: &Value,
    expected_len: usize,
) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == expected_len => Ok(values),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn archive_array_bounded(
    value: &Value,
    maximum_len: usize,
) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(values) if values.len() <= maximum_len => Ok(values),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn archive_text(value: &Value) -> Result<&str, BundleContractErrorV1> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn archive_bytes(value: &Value) -> Result<&[u8], BundleContractErrorV1> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn archive_u64(value: &Value) -> Result<u64, BundleContractErrorV1> {
    match value {
        Value::Integer(integer) => (*integer)
            .try_into()
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn archive_digest<const N: usize>(value: &Value) -> Result<[u8; N], BundleContractErrorV1> {
    let bytes = archive_bytes(value)?;
    bytes
        .try_into()
        .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
}

const fn decode_member_role(code: u64) -> Result<BundleMemberRoleV1, BundleContractErrorV1> {
    match code {
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
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

const fn decode_bundle_mode(code: u64) -> Result<BundleModeV1, BundleContractErrorV1> {
    match code {
        0 => Ok(BundleModeV1::Local),
        1 => Ok(BundleModeV1::AirGapped),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

const fn decode_lifecycle(code: u64) -> Result<ProfileLifecycleV1, BundleContractErrorV1> {
    match code {
        0 => Ok(ProfileLifecycleV1::Draft),
        1 => Ok(ProfileLifecycleV1::Candidate),
        2 => Ok(ProfileLifecycleV1::Stable),
        3 => Ok(ProfileLifecycleV1::Retired),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

const fn decode_claim_layer(code: u64) -> Result<ClaimLayerV1, BundleContractErrorV1> {
    match code {
        0 => Ok(ClaimLayerV1::ArtifactIntegrity),
        1 => Ok(ClaimLayerV1::ReplayConformance),
        2 => Ok(ClaimLayerV1::KnowledgeNonInterference),
        3 => Ok(ClaimLayerV1::GatewayClientConformance),
        4 => Ok(ClaimLayerV1::PluginConformance),
        5 => Ok(ClaimLayerV1::MetricConformance),
        6 => Ok(ClaimLayerV1::EmpiricalEvaluation),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

const fn validate_total_bytes(total_bytes: u64) -> Result<(), BundleContractErrorV1> {
    if total_bytes > MAX_TOTAL_BUNDLE_BYTES {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

const fn validate_member_count(member_count: usize) -> Result<(), BundleContractErrorV1> {
    if member_count > MAX_MEMBERS {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

const fn validate_member_size(member_size: u64) -> Result<(), BundleContractErrorV1> {
    if member_size > MAX_MEMBER_BYTES {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

fn accumulate_member_bytes(
    total_bytes: u64,
    member_size: u64,
) -> Result<u64, BundleContractErrorV1> {
    validate_member_size(member_size)?;
    Ok(total_bytes.saturating_add(member_size))
}

/// Derive the deterministic archive path for one CPF1 fixture-input member.
#[must_use]
pub fn fixture_input_member_path(
    case_id: &str,
    claim_layer: ClaimLayerV1,
    execution_profile_digest: &[u8; 32],
    member_id: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"PiglorOS.CPF1InputPath.v1\0");
    append_path_component(&mut input, case_id);
    input.push(claim_layer_code(claim_layer));
    input.extend_from_slice(execution_profile_digest);
    append_path_component(&mut input, member_id);
    format!("{INPUT_MEMBER_PREFIX}{}.bin", blake3::hash(&input).to_hex())
}

/// Derive the deterministic archive path for one CPF1 expected-result member.
#[must_use]
pub fn expected_result_member_path(
    case_id: &str,
    claim_layer: ClaimLayerV1,
    execution_profile_digest: &[u8; 32],
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"PiglorOS.CPF1ExpectedPath.v1\0");
    append_path_component(&mut input, case_id);
    input.push(claim_layer_code(claim_layer));
    input.extend_from_slice(execution_profile_digest);
    format!("expected/{}.bin", blake3::hash(&input).to_hex())
}

fn append_path_component(input: &mut Vec<u8>, value: &str) {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
}

const fn execution_mode_for_bundle(mode: BundleModeV1) -> ExecutionModeV1 {
    match mode {
        BundleModeV1::Local => ExecutionModeV1::Local,
        BundleModeV1::AirGapped => ExecutionModeV1::AirGapped,
    }
}

fn validate_fixture_inputs_for_mode(
    profile: &ConformanceProfileV1,
    mode: Option<BundleModeV1>,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let execution_mode = mode.map(execution_mode_for_bundle);
    for fixture in &profile.fixtures {
        if execution_mode.is_some_and(|execution_mode| !fixture.modes.contains(&execution_mode)) {
            continue;
        }
        for input in &fixture.inputs {
            let path = fixture_input_member_path(
                &fixture.case_id,
                fixture.claim_layer,
                &fixture.execution_profile_digest,
                &input.member_id,
            );
            let Some(member) = members.iter().find(|member| member.path == path) else {
                return Err(BundleContractErrorV1::MemberMissing);
            };
            if member.role != BundleMemberRoleV1::FixtureInput || member.expected_result {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if member.bytes.is_empty()
                || member.bytes.len() as u64 != input.size_bytes
                || member.digest != input.digest
                || member.digest != *blake3::hash(&member.bytes).as_bytes()
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
        }
    }
    Ok(())
}

/// A Local/Air-Gapped pair that must share exact expected-result records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceBundlePairV1 {
    /// Local bundle.
    pub local: ConformanceBundleV1,
    /// Air-Gapped bundle.
    pub air_gapped: ConformanceBundleV1,
}

impl ConformanceBundlePairV1 {
    /// Validate both signatures and their byte-for-byte authority-data parity.
    ///
    /// # Errors
    ///
    /// Returns a closed error when either bundle is invalid or the expected
    /// result records differ.
    pub fn validate(&self) -> Result<(), BundleContractErrorV1> {
        self.local.validate()?;
        self.air_gapped.validate()?;
        if self.local.manifest.profile_digest != self.air_gapped.manifest.profile_digest
            || self.local.manifest.mode != BundleModeV1::Local
            || self.air_gapped.manifest.mode != BundleModeV1::AirGapped
            || expected_identity(&self.local.manifest.expected_results)
                != expected_identity(&self.air_gapped.manifest.expected_results)
            || bundle_pair_payloads(&self.local) != bundle_pair_payloads(&self.air_gapped)
        {
            return Err(BundleContractErrorV1::ModeParityMismatch);
        }
        Ok(())
    }
}

fn bundle_pair_payloads(
    bundle: &ConformanceBundleV1,
) -> Vec<(String, BundleMemberRoleV1, Vec<u8>)> {
    let mut payloads = bundle
        .members
        .iter()
        .filter(|member| {
            matches!(
                member.role,
                BundleMemberRoleV1::ExpectedResult
                    | BundleMemberRoleV1::AuthorityInventory
                    | BundleMemberRoleV1::ExecutionMatrix
            )
        })
        .map(|member| {
            let identity = if member.role == BundleMemberRoleV1::ExpectedResult {
                bundle
                    .manifest
                    .expected_results
                    .iter()
                    .find(|expected| expected.member_path == member.path)
                    .map_or_else(
                        || member.path.clone(),
                        |expected| {
                            format!(
                                "expected-result/{}/{}",
                                expected.case_id,
                                claim_layer_code(expected.claim_layer)
                            )
                        },
                    )
            } else {
                member.path.clone()
            };
            (identity, member.role, member.bytes.clone())
        })
        .collect::<Vec<_>>();
    payloads.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    payloads
}

fn validate_expected_results(
    profile: &ConformanceProfileV1,
    manifest: &BundleManifestV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    if !strictly_ordered(&manifest.expected_results) {
        return Err(BundleContractErrorV1::NonCanonicalOrder);
    }
    for expected in &manifest.expected_results {
        if expected.mode != manifest.mode || expected.digest == [0; 32] {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let Some(member) = members
            .iter()
            .find(|member| member.path == expected.member_path)
        else {
            return Err(BundleContractErrorV1::MemberMissing);
        };
        if member.role != BundleMemberRoleV1::ExpectedResult
            || !member.expected_result
            || member.bytes.is_empty()
            || member.digest != expected.digest
        {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let Some(fixture) = profile.fixtures.iter().find(|fixture| {
            fixture.case_id == expected.case_id
                && fixture.claim_layer == expected.claim_layer
                && fixture.execution_profile_digest == expected.execution_profile_digest
        }) else {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        };
        if expected.member_path
            != expected_result_member_path(
                &fixture.case_id,
                fixture.claim_layer,
                &fixture.execution_profile_digest,
            )
        {
            return Err(BundleContractErrorV1::UndeclaredMember);
        }
        if !fixture.modes.contains(&match expected.mode {
            BundleModeV1::Local => ExecutionModeV1::Local,
            BundleModeV1::AirGapped => ExecutionModeV1::AirGapped,
        }) {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let expected_bytes = match &fixture.expected {
            ExpectedResultV1::CanonicalBytes { bytes, digest } => {
                if *digest != expected.digest || *digest != *blake3::hash(bytes).as_bytes() {
                    return Err(BundleContractErrorV1::ExpectedResultMismatch);
                }
                bytes.clone()
            }
            typed_or_divergent => typed_or_divergent
                .to_canonical_bytes()
                .map_err(|_| BundleContractErrorV1::EncodingFailed)?,
        };
        if expected.digest != *blake3::hash(&expected_bytes).as_bytes() {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        if member.bytes != expected_bytes {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        if expected.mode == BundleModeV1::AirGapped && fixture.capability_policy.network_allowed {
            return Err(BundleContractErrorV1::AirGappedNetwork);
        }
    }
    if profile.fixtures.iter().any(|fixture| {
        fixture.mandatory
            && fixture.modes.iter().any(|mode| {
                matches!(
                    (manifest.mode, mode),
                    (BundleModeV1::Local, ExecutionModeV1::Local)
                        | (BundleModeV1::AirGapped, ExecutionModeV1::AirGapped)
                )
            })
            && !manifest.expected_results.iter().any(|expected| {
                expected.case_id == fixture.case_id
                    && expected.claim_layer == fixture.claim_layer
                    && expected.execution_profile_digest == fixture.execution_profile_digest
            })
    }) {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    Ok(())
}

fn expected_identity(values: &[BundleExpectedResultV1]) -> ExpectedIdentity<'_> {
    let mut identity = values
        .iter()
        .map(|value| (value.case_id.as_str(), value.claim_layer, value.digest))
        .collect::<ExpectedIdentity<'_>>();
    identity.sort_unstable();
    identity
}

type ExpectedIdentity<'a> = Vec<(&'a str, ClaimLayerV1, [u8; 32])>;

fn validate_supporting_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    const REQUIRED_MEMBERS: [(BundleMemberRoleV1, &str); 7] = [
        (
            BundleMemberRoleV1::NormativeSpecification,
            "support/normative-requirements.md",
        ),
        (BundleMemberRoleV1::Schema, "support/schema-cpf1-v1.cddl"),
        (BundleMemberRoleV1::Licence, "support/LICENSE"),
        (BundleMemberRoleV1::Notice, "support/NOTICE"),
        (BundleMemberRoleV1::Sbom, "support/sbom.json"),
        (BundleMemberRoleV1::Provenance, "support/provenance.json"),
        (BundleMemberRoleV1::Limitations, "support/limitations.md"),
    ];
    for (role, path) in REQUIRED_MEMBERS {
        let matching = members
            .iter()
            .filter(|member| member.role == role && member.path == path)
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].bytes.is_empty() {
            return Err(BundleContractErrorV1::MemberMissing);
        }
        if !support_digest_is_bound(profile, role, &matching[0].digest) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    if members
        .iter()
        .filter(|member| member.role.is_supporting())
        .count()
        != REQUIRED_MEMBERS.len()
    {
        return Err(BundleContractErrorV1::UndeclaredMember);
    }
    Ok(())
}

fn validate_authority_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let provenance = members
        .iter()
        .find(|member| {
            member.role == BundleMemberRoleV1::Provenance
                && member.digest == profile.provenance_digest
        })
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    let inventory = required_authority_member(
        members,
        BundleMemberRoleV1::AuthorityInventory,
        AUTHORITY_INVENTORY_MEMBER_PATH,
    )?;
    let matrix = required_authority_member(
        members,
        BundleMemberRoleV1::ExecutionMatrix,
        EXECUTION_MATRIX_MEMBER_PATH,
    )?;
    let provenance = parse_authority_json(&provenance.bytes)?;
    let inventory_json = parse_authority_json(&inventory.bytes)?;
    let matrix_json = parse_authority_json(&matrix.bytes)?;
    if let Ok(bound_matrix_digest) = profile.execution_matrix_digest() {
        if bound_matrix_digest != *blake3::hash(&matrix.bytes).as_bytes() {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    validate_matrix_provenance_digest(&provenance, &matrix.bytes)?;
    let inventory_lifecycle = json_text(&inventory_json, "lifecycle")?;
    let matrix_lifecycle = json_text(&matrix_json, "lifecycle")?;
    if inventory_lifecycle != matrix_lifecycle {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    if inventory_lifecycle != "Draft" {
        return Err(BundleContractErrorV1::LifecycleInvalid);
    }
    validate_provenance_authority_binding(&provenance)?;
    validate_execution_matrix(&matrix_json)?;
    validate_authority_inventory_digest(&provenance, &inventory.bytes)?;
    validate_authority_inventory(&inventory_json)?;
    Ok(())
}

fn required_authority_member<'a>(
    members: &'a [BundleMemberV1],
    role: BundleMemberRoleV1,
    path: &str,
) -> Result<&'a BundleMemberV1, BundleContractErrorV1> {
    let matched = members
        .iter()
        .filter(|member| member.role == role)
        .collect::<Vec<_>>();
    if matched.len() != 1 || matched[0].path != path || matched[0].bytes.is_empty() {
        Err(BundleContractErrorV1::MemberMissing)
    } else {
        Ok(matched[0])
    }
}

fn parse_authority_json(bytes: &[u8]) -> Result<JsonValue, BundleContractErrorV1> {
    serde_json::from_slice(bytes).map_err(|_| BundleContractErrorV1::MemberDigestMismatch)
}

fn json_text<'a>(value: &'a JsonValue, field: &str) -> Result<&'a str, BundleContractErrorV1> {
    value
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)
}

fn json_u64(value: &JsonValue, field: &str) -> Result<u64, BundleContractErrorV1> {
    value
        .get(field)
        .and_then(JsonValue::as_u64)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)
}

fn json_object<'a>(
    value: &'a JsonValue,
    field: &str,
) -> Result<&'a JsonValue, BundleContractErrorV1> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)
}

fn validate_provenance_authority_binding(
    provenance: &JsonValue,
) -> Result<(), BundleContractErrorV1> {
    let inventory = json_object(provenance, "authority_inventory")?;
    let matrix = json_object(provenance, "adr_059_execution_matrix")?;
    if json_text(inventory, "path")? != "expected-authority/inventory.json"
        || json_text(inventory, "digest_algorithm")? != "SHA-256"
        || json_text(inventory, "status")? != "Draft"
        || json_text(matrix, "path")? != "matrix/execution-matrix.json"
        || json_text(matrix, "digest_algorithm")? != "BLAKE3-256"
        || json_text(matrix, "status")? != "Draft"
        || json_u64(matrix, "executed_case_count")? != 0
    {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    } else {
        Ok(())
    }
}

fn validate_authority_inventory_digest(
    provenance: &JsonValue,
    inventory_bytes: &[u8],
) -> Result<(), BundleContractErrorV1> {
    let inventory = json_object(provenance, "authority_inventory")?;
    let declared = crate::decode_hex_digest(json_text(inventory, "sha256_digest")?)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    let actual: [u8; 32] = Sha256::digest(inventory_bytes).into();
    if declared == actual {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn validate_matrix_provenance_digest(
    provenance: &JsonValue,
    matrix_bytes: &[u8],
) -> Result<(), BundleContractErrorV1> {
    let matrix = json_object(provenance, "adr_059_execution_matrix")?;
    let declared = crate::decode_hex_digest(json_text(matrix, "blake3_digest")?)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    if declared == *blake3::hash(matrix_bytes).as_bytes() {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn validate_authority_inventory(inventory: &JsonValue) -> Result<(), BundleContractErrorV1> {
    if json_text(inventory, "magic")? != "W8H1"
        || json_u64(inventory, "version")? != 1
        || json_text(inventory, "lifecycle")? != "Draft"
        || json_text(inventory, "digest_algorithm")? != "BLAKE3-256"
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let entries = inventory
        .get("entries")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    if entries.len() != 11 {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    if entries
        .iter()
        .zip(AUTHORITY_FIXTURE_IDS)
        .any(|(entry, id)| json_text(entry, "fixture_id") != Ok(id))
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let mut fixture_ids = BTreeSet::new();
    for (entry, fixture_id) in entries.iter().zip(AUTHORITY_FIXTURE_IDS) {
        if !fixture_ids.insert(fixture_id)
            || json_text(entry, "materialization_status")? != "pending"
            || !entry
                .get("fixture_bytes_path")
                .is_some_and(JsonValue::is_null)
            || !entry
                .get("fixture_bytes_digest")
                .is_some_and(JsonValue::is_null)
            || !entry
                .get("expected_result_path")
                .is_some_and(JsonValue::is_null)
            || !entry
                .get("expected_result_digest")
                .is_some_and(JsonValue::is_null)
        {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
}

fn validate_execution_matrix(matrix: &JsonValue) -> Result<(), BundleContractErrorV1> {
    let rows = matrix
        .get("rows")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    let cases = matrix
        .get("cases")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    if json_text(matrix, "magic")? != "NIM1"
        || json_u64(matrix, "version")? != 1
        || json_text(matrix, "lifecycle")? != "Draft"
        || json_u64(matrix, "row_count")? != 12
        || json_u64(matrix, "variant_count")? != 4
        || json_u64(matrix, "mode_count")? != 4
        || json_u64(matrix, "case_count")? != 192
        || json_u64(matrix, "executed_case_count")? != 0
        || rows.len() != 12
        || cases.len() != 192
        || rows.iter().enumerate().any(|(index, row)| {
            json_text(row, "fixture_id") != Ok(NON_INTERFERENCE_ROW_IDS[index])
                || json_string_array(row, "variants") != Ok(NON_INTERFERENCE_VARIANTS.to_vec())
                || json_string_array(row, "modes") != Ok(NON_INTERFERENCE_MODES.to_vec())
        })
        || cases.iter().enumerate().any(|(index, case)| {
            let row_index = index / 16;
            let variant_index = (index % 16) / 4;
            let mode_index = index % 4;
            let expected_case_id = format!(
                "{}-{}-{}",
                NON_INTERFERENCE_ROW_IDS[row_index],
                NON_INTERFERENCE_VARIANTS[variant_index],
                NON_INTERFERENCE_MODES[mode_index]
            );
            json_text(case, "fixture_id") != Ok(NON_INTERFERENCE_ROW_IDS[row_index])
                || json_text(case, "variant") != Ok(NON_INTERFERENCE_VARIANTS[variant_index])
                || json_text(case, "mode") != Ok(NON_INTERFERENCE_MODES[mode_index])
                || json_text(case, "case_id") != Ok(expected_case_id.as_str())
        })
        || rows.iter().any(|row| {
            json_u64(row, "case_count").ok() != Some(16)
                || json_u64(row, "executed_case_count").ok() != Some(0)
        })
        || !matrix_cases_are_open(cases)
    {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    } else {
        let predicates = matrix
            .get("equality_predicates")
            .and_then(JsonValue::as_array)
            .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
        if predicates.len() != NON_INTERFERENCE_ROW_IDS.len()
            || predicates.iter().enumerate().any(|(index, predicate)| {
                json_text(predicate, "fixture_id") != Ok(NON_INTERFERENCE_ROW_IDS[index])
                    || json_text(predicate, "AuthEq") != Ok(NON_INTERFERENCE_AUTH_EQ)
                    || json_text(predicate, "PublicEq") != Ok(NON_INTERFERENCE_PUBLIC_EQ[index])
                    || json_text(predicate, "OpEq") != Ok(NON_INTERFERENCE_OP_EQ[index])
            })
        {
            Err(BundleContractErrorV1::MemberDigestMismatch)
        } else {
            Ok(())
        }
    }
}

fn matrix_cases_are_open(cases: &[JsonValue]) -> bool {
    cases.iter().all(|case| {
        case.get("executed").and_then(JsonValue::as_bool) == Some(false)
            && case
                .get("expected_result_digest")
                .is_some_and(JsonValue::is_null)
            && [
                "authority_fixture_id",
                "authority_result_digest",
                "expected_result",
            ]
            .iter()
            .all(|field| case.get(*field).is_none_or(JsonValue::is_null))
    })
}

fn json_string_array<'a>(
    value: &'a JsonValue,
    field: &str,
) -> Result<Vec<&'a str>, BundleContractErrorV1> {
    value
        .get(field)
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or(BundleContractErrorV1::MemberDigestMismatch)
        })
        .collect()
}

fn required_support_digests(
    profile: &ConformanceProfileV1,
    role: BundleMemberRoleV1,
) -> BTreeSet<[u8; 32]> {
    let mut digests = BTreeSet::new();
    match role {
        BundleMemberRoleV1::NormativeSpecification => {
            digests.insert(profile.normative_spec_digest);
        }
        BundleMemberRoleV1::Schema => {
            digests.extend(profile.public_schema_digests.iter().copied());
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.public_schema_digest),
            );
        }
        BundleMemberRoleV1::Licence => {
            digests.extend(profile.fixtures.iter().map(|fixture| {
                let identity = format!("{}\n", fixture.provenance.licence_id);
                *blake3::hash(identity.as_bytes()).as_bytes()
            }));
        }
        BundleMemberRoleV1::Notice => {
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.provenance.notices_digest),
            );
        }
        BundleMemberRoleV1::Sbom => {
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.provenance.sbom_digest),
            );
        }
        BundleMemberRoleV1::Provenance => {
            digests.insert(profile.provenance_digest);
            digests.extend(profile.fixtures.iter().flat_map(|fixture| {
                [
                    fixture.provenance.source_digest,
                    fixture.provenance.build_digest,
                    fixture.provenance.publication_review_digest,
                ]
            }));
        }
        BundleMemberRoleV1::Limitations => {
            digests.insert(profile.limitations_digest);
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.provenance.limitations_digest),
            );
        }
        BundleMemberRoleV1::FixtureInput
        | BundleMemberRoleV1::ExpectedResult
        | BundleMemberRoleV1::Profile
        | BundleMemberRoleV1::AuthorityInventory
        | BundleMemberRoleV1::ExecutionMatrix => {}
    }
    digests
}

fn support_digest_is_bound(
    profile: &ConformanceProfileV1,
    role: BundleMemberRoleV1,
    digest: &[u8; 32],
) -> bool {
    role.is_supporting() && required_support_digests(profile, role).contains(digest)
}

fn validate_selected_bundle_caps(
    profile: &ConformanceProfileV1,
    bundle: &ConformanceBundleV1,
) -> Result<(), BundleContractErrorV1> {
    let caps = &profile.evaluator_protocol.hard_caps;
    let profile_member = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    if u64::try_from(profile_member.bytes.len()).unwrap_or(u64::MAX) > caps.max_profile_bytes
        || value_depth(&manifest_value(&bundle.manifest)) > usize::from(caps.max_structural_nesting)
    {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    caps.validate_case_count(u32::try_from(profile.fixtures.len()).unwrap_or(u32::MAX))
        .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?;
    if bundle.members.len() > usize::try_from(caps.max_bundle_members).unwrap_or(usize::MAX) {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    let mut total_bytes = 0_u64;
    for member in &bundle.members {
        if member.path.len() > usize::from(caps.max_member_path_bytes)
            || u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) > caps.max_member_bytes
        {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        total_bytes =
            total_bytes.saturating_add(u64::try_from(member.bytes.len()).unwrap_or(u64::MAX));
    }
    if total_bytes > caps.max_total_bundle_bytes {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    Ok(())
}

fn validate_member_path(path: &str) -> Result<(), BundleContractErrorV1> {
    if path.is_empty()
        || path.len() > MAX_MEMBER_PATH_BYTES
        || path.starts_with('/')
        || !path.is_ascii()
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

fn contains_secret_marker(bytes: &[u8]) -> bool {
    let lowercase = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    [
        b"private key".as_slice(),
        b"private_key".as_slice(),
        b"begin secret".as_slice(),
    ]
    .iter()
    .any(|marker| {
        lowercase
            .windows(marker.len())
            .any(|window| window == *marker)
    }) || json_contains_secret_value(bytes)
        || standalone_secret_string(bytes)
        || contains_prefixed_secret(&lowercase, b"bearer ", 16)
        || contains_prefixed_secret(&lowercase, b"basic ", 16)
        || contains_prefixed_secret(&lowercase, b"ghp_", 20)
        || contains_prefixed_secret(&lowercase, b"github_pat_", 20)
        || contains_prefixed_secret(&lowercase, b"glpat-", 20)
        || contains_prefixed_secret(&lowercase, b"xoxb-", 20)
        || contains_prefixed_secret(&lowercase, b"xoxp-", 20)
        || contains_prefixed_secret(&lowercase, b"sk_live_", 16)
        || contains_prefixed_secret(&lowercase, b"sk_test_", 16)
        || contains_prefixed_secret(&lowercase, b"aiza", 30)
        || contains_aws_access_key(&lowercase)
        || contains_jwt(&lowercase)
}

fn json_contains_secret_value(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<JsonValue>(bytes) else {
        return false;
    };
    json_value_contains_secret(&value)
}

fn standalone_secret_string(bytes: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<JsonValue>(bytes),
        Ok(JsonValue::String(value)) if is_sensitive_json_key(&value)
    )
}

fn json_value_contains_secret(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(fields) => fields.iter().any(|(key, value)| {
            (is_sensitive_json_key(key) && !is_empty_sensitive_value(value))
                || is_sensitive_digest_key(key)
                || json_value_contains_secret(value)
        }),
        JsonValue::Array(values) => values.iter().any(json_value_contains_secret),
        _ => false,
    }
}

fn is_sensitive_json_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
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

fn is_sensitive_digest_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    normalized
        .strip_suffix("_digest")
        .is_some_and(is_sensitive_json_key)
}

const fn is_empty_sensitive_value(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => true,
        JsonValue::String(text) => text.is_empty(),
        _ => false,
    }
}

fn contains_prefixed_secret(bytes: &[u8], prefix: &[u8], minimum_length: usize) -> bool {
    bytes
        .windows(prefix.len())
        .enumerate()
        .any(|(index, window)| {
            window == prefix && token_length(bytes, index + prefix.len()) >= minimum_length
        })
}

fn token_length(bytes: &[u8], start: usize) -> usize {
    bytes
        .get(start..)
        .unwrap_or_default()
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || b"_~+/=-".contains(byte))
        .count()
}

fn contains_aws_access_key(bytes: &[u8]) -> bool {
    bytes.windows(4).enumerate().any(|(index, window)| {
        (window == b"akia" || window == b"asia") && token_length(bytes, index + 4) >= 16
    })
}

fn contains_jwt(bytes: &[u8]) -> bool {
    bytes.windows(3).enumerate().any(|(index, window)| {
        if window != b"eyj" {
            return false;
        }
        let first = token_length(bytes, index);
        let Some(dot_one) = bytes.get(index + first) else {
            return false;
        };
        if *dot_one != b'.' || first < 10 {
            return false;
        }
        let second_start = index + first + 1;
        let second = token_length(bytes, second_start);
        let third_start = second_start + second + 1;
        second >= 10
            && bytes.get(second_start + second) == Some(&b'.')
            && token_length(bytes, third_start) >= 10
    })
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn members_strictly_ordered(values: &[BundleMemberV1]) -> bool {
    let mut normalized = BTreeSet::new();
    normalized.extend(values.iter().map(|value| value.path.to_ascii_lowercase()));
    normalized.len() == values.len()
        && values
            .windows(2)
            .all(|pair| pair[0].path.as_str().cmp(pair[1].path.as_str()).is_lt())
}

fn value_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(value_depth).max().unwrap_or_default(),
        Value::Map(values) => {
            1 + values
                .iter()
                .map(|(key, value)| value_depth(key).max(value_depth(value)))
                .max()
                .unwrap_or_default()
        }
        Value::Tag(_, value) => 1 + value_depth(value),
        _ => 1,
    }
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
                .map(|member| {
                    Value::Array(vec![
                        Value::Text(member.path.clone()),
                        Value::Integer(member.size_bytes.into()),
                        Value::Bytes(member.digest.to_vec()),
                        Value::Integer(member.role.code().into()),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            manifest
                .expected_results
                .iter()
                .map(|expected| {
                    Value::Array(vec![
                        Value::Text(expected.case_id.clone()),
                        Value::Integer(claim_layer_code(expected.claim_layer).into()),
                        Value::Bytes(expected.execution_profile_digest.to_vec()),
                        Value::Integer(expected.mode.code().into()),
                        Value::Text(expected.member_path.clone()),
                        Value::Bytes(expected.digest.to_vec()),
                    ])
                })
                .collect(),
        ),
    ])
}

const fn claim_layer_code(layer: ClaimLayerV1) -> u8 {
    match layer {
        ClaimLayerV1::ArtifactIntegrity => 0,
        ClaimLayerV1::ReplayConformance => 1,
        ClaimLayerV1::KnowledgeNonInterference => 2,
        ClaimLayerV1::GatewayClientConformance => 3,
        ClaimLayerV1::PluginConformance => 4,
        ClaimLayerV1::MetricConformance => 5,
        ClaimLayerV1::EmpiricalEvaluation => 6,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        CapabilityPolicyV1, EvaluatorHardCapsV1, EvaluatorProtocolV1, FixtureBoundsV1,
        FixtureDescriptorV1, FixtureInputMemberV1, FixtureProvenanceV1, IndependenceRequirementsV1,
        RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, SubjectAdapterKindV1,
        VerificationOutcomeV1,
    };
    use pos_crypto::canonical;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn fixture_input_bytes(index: usize) -> Vec<u8> {
        [
            include_bytes!(
                "../../../fixtures/conformance/inputs/artifact-integrity/positive.json"
            )
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/inputs/replay-conformance/negative.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/inputs/knowledge-non-interference/malformed.json"
            )
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/inputs/gateway-client-conformance/resource.json"
            )
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/plugin-conformance/deletion.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/metric-conformance/downgrade.json")
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/inputs/empirical-evaluation/independent-evaluation.json"
            )
                .as_slice(),
        ][index]
            .to_vec()
    }

    fn fixture_expected_bytes(index: usize) -> Vec<u8> {
        [
            include_bytes!(
                "../../../fixtures/conformance/expected/artifact-integrity/positive.json"
            )
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/expected/replay-conformance/negative.json"
            )
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/expected/knowledge-non-interference/malformed.json"
            )
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/expected/gateway-client-conformance/resource.json"
            )
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/plugin-conformance/deletion.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/metric-conformance/downgrade.json")
                .as_slice(),
            include_bytes!(
                "../../../fixtures/conformance/expected/empirical-evaluation/independent-evaluation.json"
            )
                .as_slice(),
        ][index]
            .to_vec()
    }

    fn profile_fixture(index: usize, claim_layer: ClaimLayerV1) -> FixtureDescriptorV1 {
        let expected_bytes = fixture_expected_bytes(index);
        let input_bytes = fixture_input_bytes(index);
        FixtureDescriptorV1 {
            case_id: format!("case-{index:02}"),
            mandatory: true,
            claim_layer,
            execution_profile_digest: digest(1),
            public_schema_digest: digest(2),
            modes: vec![ExecutionModeV1::Local],
            subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
            inputs: vec![FixtureInputMemberV1 {
                member_id: format!("input-{index:02}.json"),
                size_bytes: input_bytes.len() as u64,
                digest: *blake3::hash(&input_bytes).as_bytes(),
                provenance_digest: digest(4),
            }],
            expected: ExpectedResultV1::CanonicalBytes {
                digest: *blake3::hash(&expected_bytes).as_bytes(),
                bytes: expected_bytes,
            },
            expected_verification_outcome: VerificationOutcomeV1::VerifiedExact,
            expected_verification_error: None,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            bounds: FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 1024,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            capability_policy: CapabilityPolicyV1 {
                network_allowed: false,
                capability_ids: vec!["read-public-bundle".to_owned()],
            },
            provenance: FixtureProvenanceV1 {
                licence_id: "MIT".to_owned(),
                notices_digest: digest(5),
                sbom_digest: digest(6),
                source_digest: digest(7),
                build_digest: digest(8),
                publication_review_digest: digest(9),
                limitations_digest: digest(10),
            },
            compatibility_digest: digest(11),
        }
    }

    fn evaluator_protocol() -> EvaluatorProtocolV1 {
        EvaluatorProtocolV1 {
            protocol_id: "pigloros.evaluator.v1".to_owned(),
            protocol_digest: digest(13),
            request_schema_digest: digest(14),
            report_schema_digest: digest(15),
            hard_caps: EvaluatorHardCapsV1 {
                max_profile_bytes: 16 * 1024 * 1024,
                max_cases: 65_536,
                max_bundle_members: 65_536,
                max_member_path_bytes: 256,
                max_member_bytes: 64 * 1024 * 1024,
                max_total_bundle_bytes: 1024 * 1024 * 1024,
                max_compression_expansion: 100,
                max_structural_nesting: 32,
                max_coordinate_bytes: 128,
                max_diagnostic_bytes: 1024 * 1024,
            },
        }
    }

    fn independence_requirements() -> IndependenceRequirementsV1 {
        IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: digest(16),
            requirements_digest: digest(17),
        }
    }

    pub(super) fn profile() -> ConformanceProfileV1 {
        let claim_layers = [
            ClaimLayerV1::ArtifactIntegrity,
            ClaimLayerV1::ReplayConformance,
            ClaimLayerV1::KnowledgeNonInterference,
            ClaimLayerV1::GatewayClientConformance,
            ClaimLayerV1::PluginConformance,
            ClaimLayerV1::MetricConformance,
            ClaimLayerV1::EmpiricalEvaluation,
        ];
        let mut fixtures = claim_layers
            .into_iter()
            .enumerate()
            .map(|(index, claim_layer)| profile_fixture(index, claim_layer))
            .collect::<Vec<_>>();
        let mut air_gapped = fixtures
            .iter()
            .cloned()
            .map(|mut fixture| {
                fixture.execution_profile_digest = digest(2);
                fixture.modes = vec![ExecutionModeV1::AirGapped];
                fixture
            })
            .collect::<Vec<_>>();
        fixtures.append(&mut air_gapped);
        fixtures.sort_by_key(|fixture| {
            (
                fixture.case_id.clone(),
                fixture.claim_layer,
                fixture.execution_profile_digest,
            )
        });
        let mut profile = ConformanceProfileV1 {
            profile_id: "pigloros.w8.knowledge-non-interference.1.0.0".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            normative_spec_digest: digest(12),
            execution_profile_digests: vec![digest(1), digest(2)],
            public_schema_digests: vec![digest(2)],
            fixtures,
            allowed_divergences: Vec::new(),
            evaluator_protocol: evaluator_protocol(),
            independence_requirements: independence_requirements(),
            compatibility_digest: digest(18),
            limitations_digest: digest(19),
            provenance_digest: digest(20),
            previous_profile_digest: None,
            stable_evidence: Vec::new(),
            profile_digest: [0; 32],
        };
        let normative_digest = *blake3::hash(include_bytes!(
            "../../../fixtures/conformance/support/normative-requirements.md"
        ))
        .as_bytes();
        let schema_digest = *blake3::hash(include_bytes!(
            "../../../fixtures/conformance/support/schema-cpf1-v1.cddl"
        ))
        .as_bytes();
        let notice_digest = *blake3::hash(include_bytes!(
            "../../../fixtures/conformance/support/NOTICE"
        ))
        .as_bytes();
        let sbom_digest = *blake3::hash(include_bytes!(
            "../../../fixtures/conformance/support/sbom.json"
        ))
        .as_bytes();
        let provenance_digest = *blake3::hash(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))
        .as_bytes();
        let limitations_digest = *blake3::hash(include_bytes!(
            "../../../fixtures/conformance/support/limitations.md"
        ))
        .as_bytes();
        profile.normative_spec_digest = normative_digest;
        profile.public_schema_digests = vec![schema_digest];
        profile.limitations_digest = limitations_digest;
        profile.provenance_digest = provenance_digest;
        for fixture in &mut profile.fixtures {
            fixture.public_schema_digest = schema_digest;
            fixture.provenance.notices_digest = notice_digest;
            fixture.provenance.sbom_digest = sbom_digest;
            fixture.provenance.source_digest = provenance_digest;
            fixture.provenance.build_digest = provenance_digest;
            fixture.provenance.publication_review_digest = provenance_digest;
            fixture.provenance.limitations_digest = limitations_digest;
        }
        assert!(
            profile
                .bind_execution_matrix_digest(
                    *blake3::hash(include_bytes!(
                        "../../../fixtures/conformance/matrix/execution-matrix.json"
                    ))
                    .as_bytes(),
                )
                .is_ok(),
            "knowledge test profile matrix binding must succeed"
        );
        profile
    }

    fn wide_profile() -> ConformanceProfileV1 {
        let mut profile = profile();
        let caps = &mut profile.evaluator_protocol.hard_caps;
        caps.max_profile_bytes = 16 * 1024 * 1024;
        caps.max_cases = 65_536;
        caps.max_bundle_members = 65_536;
        caps.max_member_path_bytes = 256;
        caps.max_member_bytes = 64 * 1024 * 1024;
        caps.max_total_bundle_bytes = 1024 * 1024 * 1024;
        caps.max_structural_nesting = 32;
        profile
    }

    fn claim_layer_profile_id(claim_layer: ClaimLayerV1) -> &'static str {
        match claim_layer {
            ClaimLayerV1::ArtifactIntegrity => "pigloros.w8.artifact-integrity.1.0.0",
            ClaimLayerV1::ReplayConformance => "pigloros.w8.replay-conformance.1.0.0",
            ClaimLayerV1::KnowledgeNonInterference => {
                "pigloros.w8.knowledge-non-interference.1.0.0"
            }
            ClaimLayerV1::GatewayClientConformance => {
                "pigloros.w8.gateway-client-conformance.1.0.0"
            }
            ClaimLayerV1::PluginConformance => "pigloros.w8.plugin-conformance.1.0.0",
            ClaimLayerV1::MetricConformance => "pigloros.w8.metric-conformance.1.0.0",
            ClaimLayerV1::EmpiricalEvaluation => "pigloros.w8.empirical-evaluation.1.0.0",
        }
    }

    fn profile_for_claim_layer(claim_layer: ClaimLayerV1) -> ConformanceProfileV1 {
        let mut profile = profile();
        profile.profile_id = claim_layer_profile_id(claim_layer).to_owned();
        profile.fixtures.retain(|fixture| {
            fixture.claim_layer == claim_layer && fixture.modes == [ExecutionModeV1::Local]
        });
        if claim_layer == ClaimLayerV1::KnowledgeNonInterference {
            assert!(
                profile
                    .bind_execution_matrix_digest(
                        *blake3::hash(include_bytes!(
                            "../../../fixtures/conformance/matrix/execution-matrix.json"
                        ))
                        .as_bytes(),
                    )
                    .is_ok(),
                "knowledge test profile matrix binding must succeed"
            );
        } else {
            profile.profile_digest = profile.digest();
        }
        profile
    }

    fn profile_for_claim_layer_families(claim_layer: ClaimLayerV1) -> ConformanceProfileV1 {
        let mut profile = profile();
        profile.profile_id = claim_layer_profile_id(claim_layer).to_owned();
        for fixture in &mut profile.fixtures {
            fixture.claim_layer = claim_layer;
        }
        if claim_layer == ClaimLayerV1::KnowledgeNonInterference {
            assert!(
                profile
                    .bind_execution_matrix_digest(
                        *blake3::hash(include_bytes!(
                            "../../../fixtures/conformance/matrix/execution-matrix.json"
                        ))
                        .as_bytes(),
                    )
                    .is_ok(),
                "knowledge test profile matrix binding must succeed"
            );
        } else {
            profile.profile_digest = profile.digest();
        }
        profile
    }

    pub(super) fn bundle_inputs(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
    ) -> Result<(Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>), Box<dyn std::error::Error>>
    {
        let execution_mode = match mode {
            BundleModeV1::Local => ExecutionModeV1::Local,
            BundleModeV1::AirGapped => ExecutionModeV1::AirGapped,
        };
        let mut members = Vec::new();
        let mut expected_results = Vec::new();
        for (index, fixture) in profile.fixtures.iter().enumerate() {
            if !fixture.modes.contains(&execution_mode) {
                continue;
            }
            let fixture_index = fixture
                .case_id
                .strip_prefix("case-")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(index);
            for input in &fixture.inputs {
                let input_bytes = fixture_input_bytes(fixture_index);
                members.push(BundleMemberV1::new(
                    fixture_input_member_path(
                        &fixture.case_id,
                        fixture.claim_layer,
                        &fixture.execution_profile_digest,
                        &input.member_id,
                    ),
                    input_bytes,
                    false,
                ));
            }
            let bytes = match &fixture.expected {
                ExpectedResultV1::CanonicalBytes { bytes, .. } => bytes.clone(),
                typed_or_divergent => typed_or_divergent.to_canonical_bytes()?,
            };
            let path = expected_result_member_path(
                &fixture.case_id,
                fixture.claim_layer,
                &fixture.execution_profile_digest,
            );
            let member = BundleMemberV1::new(path.clone(), bytes, true);
            expected_results.push(BundleExpectedResultV1 {
                case_id: fixture.case_id.clone(),
                claim_layer: fixture.claim_layer,
                execution_profile_digest: fixture.execution_profile_digest,
                mode,
                member_path: path,
                digest: member.digest,
            });
            members.push(member);
        }
        members.extend(supporting_bundle_members());
        Ok((members, expected_results))
    }

    fn supporting_bundle_members() -> [BundleMemberV1; 9] {
        [
            BundleMemberV1::supporting(
                "support/normative-requirements.md",
                include_bytes!("../../../fixtures/conformance/support/normative-requirements.md")
                    .to_vec(),
                BundleMemberRoleV1::NormativeSpecification,
            ),
            BundleMemberV1::supporting(
                "support/schema-cpf1-v1.cddl",
                include_bytes!("../../../fixtures/conformance/support/schema-cpf1-v1.cddl")
                    .to_vec(),
                BundleMemberRoleV1::Schema,
            ),
            BundleMemberV1::supporting(
                "support/LICENSE",
                include_bytes!("../../../fixtures/conformance/support/LICENSE").to_vec(),
                BundleMemberRoleV1::Licence,
            ),
            BundleMemberV1::supporting(
                "support/NOTICE",
                include_bytes!("../../../fixtures/conformance/support/NOTICE").to_vec(),
                BundleMemberRoleV1::Notice,
            ),
            BundleMemberV1::supporting(
                "support/sbom.json",
                include_bytes!("../../../fixtures/conformance/support/sbom.json").to_vec(),
                BundleMemberRoleV1::Sbom,
            ),
            BundleMemberV1::supporting(
                "support/provenance.json",
                include_bytes!("../../../fixtures/conformance/support/provenance.json").to_vec(),
                BundleMemberRoleV1::Provenance,
            ),
            BundleMemberV1::supporting(
                "support/limitations.md",
                include_bytes!("../../../fixtures/conformance/support/limitations.md").to_vec(),
                BundleMemberRoleV1::Limitations,
            ),
            BundleMemberV1::authority(
                AUTHORITY_INVENTORY_MEMBER_PATH,
                include_bytes!("../../../fixtures/conformance/expected-authority/inventory.json")
                    .to_vec(),
                BundleMemberRoleV1::AuthorityInventory,
            ),
            BundleMemberV1::authority(
                EXECUTION_MATRIX_MEMBER_PATH,
                include_bytes!("../../../fixtures/conformance/matrix/execution-matrix.json")
                    .to_vec(),
                BundleMemberRoleV1::ExecutionMatrix,
            ),
        ]
    }

    fn signed_bundle(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
    ) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        let (members, expected_results) = bundle_inputs(profile, mode)?;
        let bundle = ConformanceBundleV1::materialize(profile, mode, members, expected_results)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        Ok(bundle.sign(&signing_key)?)
    }

    fn resign_archive(value: &mut Value) -> Result<(), Box<dyn std::error::Error>> {
        use ed25519_dalek::Signer;

        let Value::Array(fields) = value else {
            return Err("archive must be an array".into());
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let manifest_bytes = encode_archive_value(&fields[2])?;
        fields[4] = Value::Bytes(signing_key.verifying_key().to_bytes().to_vec());
        fields[5] = Value::Bytes(signing_key.sign(&manifest_bytes).to_bytes().to_vec());
        Ok(())
    }

    fn replace_profile_bytes(
        value: &mut Value,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Value::Array(fields) = value else {
            return Err("archive must be an array".into());
        };
        let Value::Array(members) = &mut fields[3] else {
            return Err("members must be an array".into());
        };
        let index = members
            .iter()
            .position(|member| {
                matches!(
                    member,
                    Value::Array(fields)
                        if fields.first() == Some(&Value::Text(PROFILE_MEMBER_PATH.to_owned()))
                )
            })
            .ok_or("missing profile member")?;
        let Value::Array(member) = &mut members[index] else {
            return Err("member must be an array".into());
        };
        member[1] = Value::Bytes(bytes.to_owned());
        let Value::Array(manifest) = &mut fields[2] else {
            return Err("manifest must be an array".into());
        };
        let Value::Array(descriptors) = manifest
            .get_mut(4)
            .ok_or("manifest descriptors are missing")?
        else {
            return Err("descriptors must be an array".into());
        };
        let Value::Array(descriptor) = descriptors
            .get_mut(index)
            .ok_or("manifest descriptors must contain the profile")?
        else {
            return Err("descriptor must be an array".into());
        };
        descriptor[1] = Value::Integer(u64::try_from(bytes.len())?.into());
        descriptor[2] = Value::Bytes(blake3::hash(bytes).as_bytes().to_vec());
        Ok(())
    }

    fn rename_profile_member(value: &mut Value) -> Result<(), Box<dyn std::error::Error>> {
        let Value::Array(fields) = value else {
            return Err("archive must be an array".into());
        };
        let Value::Array(members) = &mut fields[3] else {
            return Err("members must be an array".into());
        };
        let index = members
            .iter()
            .position(|member| {
                matches!(
                    member,
                    Value::Array(fields)
                        if fields.first() == Some(&Value::Text(PROFILE_MEMBER_PATH.to_owned()))
                )
            })
            .ok_or("missing profile member")?;
        let replacement = "profile/not-cpf1.cbor".to_owned();
        let Value::Array(member) = &mut members[index] else {
            return Err("member must be an array".into());
        };
        member[0] = Value::Text(replacement.clone());
        let Value::Array(manifest) = &mut fields[2] else {
            return Err("manifest must be an array".into());
        };
        let Value::Array(descriptors) = manifest
            .get_mut(4)
            .ok_or("manifest descriptors are missing")?
        else {
            return Err("descriptors must be an array".into());
        };
        let Value::Array(descriptor) = descriptors
            .get_mut(index)
            .ok_or("manifest descriptors must contain the profile")?
        else {
            return Err("descriptor must be an array".into());
        };
        descriptor[0] = Value::Text(replacement);
        Ok(())
    }

    fn assert_independent_error(
        value: &Value,
        expected: BundleContractErrorV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            verify_archive_independently(&encode_archive_value(value)?),
            Err(expected)
        );
        Ok(())
    }

    fn independent_envelope_rejections(valid: &Value) -> Result<(), Box<dyn std::error::Error>> {
        for (field, replacement) in [
            (0, Value::Text("wrong-magic".to_owned())),
            (1, Value::Integer(2_u64.into())),
        ] {
            let mut invalid = valid.clone();
            if let Value::Array(fields) = &mut invalid {
                fields[field] = replacement;
            }
            assert_independent_error(&invalid, BundleContractErrorV1::ArchiveEncodingInvalid)?;
        }
        for (field, expected_error) in [
            (1, BundleContractErrorV1::LifecycleInvalid),
            (2, BundleContractErrorV1::ArchiveEncodingInvalid),
        ] {
            let mut invalid = valid.clone();
            if let Value::Array(fields) = &mut invalid {
                fields[2] = match &fields[2] {
                    Value::Array(manifest) => {
                        let mut manifest = manifest.clone();
                        manifest[field] = Value::Integer(2_u64.into());
                        Value::Array(manifest)
                    }
                    _ => return Err("manifest must be an array".into()),
                };
            }
            assert_independent_error(&invalid, expected_error)?;
        }
        let mut mismatched_count = valid.clone();
        if let Value::Array(fields) = &mut mismatched_count {
            if let Value::Array(members) = &mut fields[3] {
                members.pop();
            }
        }
        assert_independent_error(&mismatched_count, BundleContractErrorV1::UndeclaredMember)?;
        let mut mismatched_member = valid.clone();
        if let Value::Array(fields) = &mut mismatched_member {
            if let Value::Array(members) = &mut fields[3] {
                if let Value::Array(member) = &mut members[0] {
                    if let Value::Bytes(bytes) = &mut member[1] {
                        bytes.push(0);
                    }
                }
            }
        }
        assert_independent_error(
            &mismatched_member,
            BundleContractErrorV1::MemberDigestMismatch,
        )?;
        let mut invalid_members_shape = valid.clone();
        if let Value::Array(fields) = &mut invalid_members_shape {
            fields[3] = Value::Null;
        }
        assert_independent_error(
            &invalid_members_shape,
            BundleContractErrorV1::ArchiveEncodingInvalid,
        )?;
        let mut invalid_signer_key = valid.clone();
        if let Value::Array(fields) = &mut invalid_signer_key {
            fields[4] = Value::Bytes(vec![0]);
        }
        assert_independent_error(
            &invalid_signer_key,
            BundleContractErrorV1::ArchiveEncodingInvalid,
        )?;
        let mut wrong_profile_path = valid.clone();
        rename_profile_member(&mut wrong_profile_path)?;
        resign_archive(&mut wrong_profile_path)?;
        assert_independent_error(&wrong_profile_path, BundleContractErrorV1::MemberMissing)
    }

    fn independent_expected_result_rejections(
        valid: &Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut duplicate_expected = valid.clone();
        if let Value::Array(fields) = &mut duplicate_expected {
            let Value::Array(manifest) = &mut fields[2] else {
                return Err("manifest must be an array".into());
            };
            let Value::Array(expected) = &mut manifest[5] else {
                return Err("expected results must be an array".into());
            };
            expected[1] = expected[0].clone();
        }
        resign_archive(&mut duplicate_expected)?;
        assert_independent_error(
            &duplicate_expected,
            BundleContractErrorV1::ExpectedResultMismatch,
        )?;
        let mut missing_expected_member = valid.clone();
        if let Value::Array(fields) = &mut missing_expected_member {
            let Value::Array(manifest) = &mut fields[2] else {
                return Err("manifest must be an array".into());
            };
            let Value::Array(expected) = &mut manifest[5] else {
                return Err("expected results must be an array".into());
            };
            if let Value::Array(first) = &mut expected[0] {
                first[4] = Value::Text("expected/missing".to_owned());
            }
        }
        resign_archive(&mut missing_expected_member)?;
        assert_independent_error(
            &missing_expected_member,
            BundleContractErrorV1::MemberMissing,
        )?;
        let mut wrong_expected_digest = valid.clone();
        if let Value::Array(fields) = &mut wrong_expected_digest {
            let Value::Array(manifest) = &mut fields[2] else {
                return Err("manifest must be an array".into());
            };
            let Value::Array(expected) = &mut manifest[5] else {
                return Err("expected results must be an array".into());
            };
            if let Value::Array(first) = &mut expected[0] {
                first[5] = Value::Bytes(vec![9; 32]);
            }
        }
        resign_archive(&mut wrong_expected_digest)?;
        assert_independent_error(
            &wrong_expected_digest,
            BundleContractErrorV1::ExpectedResultMismatch,
        )?;
        let mut missing_expected_reference = valid.clone();
        if let Value::Array(fields) = &mut missing_expected_reference {
            let Value::Array(manifest) = &mut fields[2] else {
                return Err("manifest must be an array".into());
            };
            manifest[5] = Value::Array(Vec::new());
        }
        resign_archive(&mut missing_expected_reference)?;
        assert_independent_error(
            &missing_expected_reference,
            BundleContractErrorV1::ExpectedResultMismatch,
        )
    }

    fn independent_expected_fixture_shape_rejections(
        bundle: &ConformanceBundleV1,
        valid: &Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile_bytes = bundle
            .members
            .iter()
            .find(|member| member.path == PROFILE_MEMBER_PATH)
            .ok_or("missing profile member")?
            .bytes
            .clone();
        let profile_value: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;

        let mut invalid_fixture = profile_value.clone();
        if let Value::Array(fields) = &mut invalid_fixture {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            fixtures[0] = Value::Null;
            fixtures.truncate(1);
        }
        let mut invalid_fixture_archive = valid.clone();
        replace_profile_bytes(
            &mut invalid_fixture_archive,
            &encode_archive_value(&invalid_fixture)?,
        )?;
        resign_archive(&mut invalid_fixture_archive)?;
        assert_independent_error(
            &invalid_fixture_archive,
            BundleContractErrorV1::ExpectedResultMismatch,
        )?;

        let mut invalid_modes = profile_value;
        if let Value::Array(fields) = &mut invalid_modes {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            let Value::Array(mut fixture) = fixtures[0].clone() else {
                return Err("fixture must be an array".into());
            };
            fixture[5] = Value::Null;
            fixtures[0] = Value::Array(fixture);
            fixtures.truncate(1);
        }
        let mut invalid_modes_archive = valid.clone();
        replace_profile_bytes(
            &mut invalid_modes_archive,
            &encode_archive_value(&invalid_modes)?,
        )?;
        resign_archive(&mut invalid_modes_archive)?;
        assert_independent_error(
            &invalid_modes_archive,
            BundleContractErrorV1::ExpectedResultMismatch,
        )?;

        let mut mismatched_path = valid.clone();
        if let Value::Array(fields) = &mut mismatched_path {
            let Value::Array(manifest) = &mut fields[2] else {
                return Err("manifest must be an array".into());
            };
            let Value::Array(expected_results) = &mut manifest[5] else {
                return Err("expected results must be an array".into());
            };
            let Value::Array(expected) = &mut expected_results[0] else {
                return Err("expected result must be an array".into());
            };
            expected[0] = Value::Text("case-rebound".to_owned());
        }

        let profile_bytes = bundle
            .members
            .iter()
            .find(|member| member.path == PROFILE_MEMBER_PATH)
            .ok_or("missing profile member")?
            .bytes
            .clone();
        let mut profile_value: Value = ciborium::from_reader(Cursor::new(&profile_bytes))?;
        let Value::Array(profile_fields) = &mut profile_value else {
            return Err("profile must be an array".into());
        };
        let Value::Array(fixtures) = &mut profile_fields[8] else {
            return Err("fixtures must be an array".into());
        };
        let Value::Array(fixture) = &mut fixtures[0] else {
            return Err("fixture must be an array".into());
        };
        fixture[0] = Value::Text("case-rebound".to_owned());
        replace_profile_bytes(&mut mismatched_path, &encode_archive_value(&profile_value)?)?;
        resign_archive(&mut mismatched_path)?;
        assert_independent_error(
            &mismatched_path,
            BundleContractErrorV1::ExpectedResultMismatch,
        )?;

        Ok(())
    }

    fn independent_profile_rejections(
        bundle: &ConformanceBundleV1,
        valid: &Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut noncanonical_profile = valid.clone();
        replace_profile_bytes(&mut noncanonical_profile, &[0x9f, 0xff])?;
        resign_archive(&mut noncanonical_profile)?;
        assert_independent_error(&noncanonical_profile, BundleContractErrorV1::ProfileInvalid)?;
        let profile_bytes = bundle
            .members
            .iter()
            .find(|member| member.path == PROFILE_MEMBER_PATH)
            .ok_or("missing profile member")?
            .bytes
            .clone();
        let profile_value: Value = ciborium::from_reader(Cursor::new(profile_bytes))?;
        let mut invalid_profile = profile_value.clone();
        if let Value::Array(fields) = &mut invalid_profile {
            fields[0] = Value::Text("CPF0".to_owned());
        }
        let mut invalid_profile_archive = valid.clone();
        replace_profile_bytes(
            &mut invalid_profile_archive,
            &encode_archive_value(&invalid_profile)?,
        )?;
        resign_archive(&mut invalid_profile_archive)?;
        assert_independent_error(
            &invalid_profile_archive,
            BundleContractErrorV1::ProfileInvalid,
        )?;
        let mut embedded_digest_mismatch = profile_value;
        if let Value::Array(fields) = &mut embedded_digest_mismatch {
            fields[16] = Value::Bytes(vec![9; 32]);
        }
        let mut embedded_digest_archive = valid.clone();
        replace_profile_bytes(
            &mut embedded_digest_archive,
            &encode_archive_value(&embedded_digest_mismatch)?,
        )?;
        resign_archive(&mut embedded_digest_archive)?;
        assert_independent_error(
            &embedded_digest_archive,
            BundleContractErrorV1::MemberDigestMismatch,
        )?;
        let mut recomputed_digest_mismatch = embedded_digest_archive;
        if let Value::Array(fields) = &mut recomputed_digest_mismatch {
            let Value::Array(manifest) = &mut fields[2] else {
                return Err("manifest must be an array".into());
            };
            manifest[3] = Value::Bytes(vec![9; 32]);
        }
        resign_archive(&mut recomputed_digest_mismatch)?;
        assert_independent_error(
            &recomputed_digest_mismatch,
            BundleContractErrorV1::MemberDigestMismatch,
        )
    }

    #[test]
    fn independent_archive_verifier_rejects_each_binding_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let valid = bundle_value(&bundle);
        assert_eq!(
            independent_array(&Value::Null, 6),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            verify_archive_independently(&encode_archive_value(&valid)?),
            Ok(())
        );
        assert_eq!(
            verify_archive_independently(&[0x9f, 0xff]),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        independent_envelope_rejections(&valid)?;
        independent_expected_result_rejections(&valid)?;
        independent_expected_fixture_shape_rejections(&bundle, &valid)?;
        independent_profile_rejections(&bundle, &valid)?;

        let mut candidate = valid;
        if let Value::Array(fields) = &mut candidate {
            if let Value::Array(manifest) = &mut fields[2] {
                manifest[1] = Value::Integer(1_u64.into());
            }
        }
        resign_archive(&mut candidate)?;
        assert_independent_error(&candidate, BundleContractErrorV1::LifecycleInvalid)
    }

    fn expected_member_index(bundle: &ConformanceBundleV1) -> Option<usize> {
        bundle
            .members
            .iter()
            .position(|member| member.expected_result)
    }

    #[test]
    fn member_constructor_is_content_addressed() {
        let member = BundleMemberV1::new("expected/outcome", b"expected".to_vec(), true);
        assert_eq!(member.digest, *blake3::hash(b"expected").as_bytes());
        assert!(member.expected_result);
    }

    #[test]
    fn path_and_secret_guards_are_closed() {
        assert_eq!(
            validate_member_path(""),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path(&"a".repeat(MAX_MEMBER_PATH_BYTES + 1)),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("/absolute"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("../secret"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("nested//empty"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("nested/./result"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("nested/../result"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("nested\\result"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("résultat"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("drive:C/result"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_member_path("control\nresult"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert!(validate_member_path(&"a".repeat(MAX_MEMBER_PATH_BYTES)).is_ok());
        assert!(validate_member_path("nested/result").is_ok());
        assert!(validate_member_path("space result").is_ok());
        assert!(contains_secret_marker(b"PUBLIC PRIVATE_KEY material"));
        assert!(contains_secret_marker(br#"{"password":"not-public"}"#));
        assert!(contains_secret_marker(br"Bearer abcdefghijklmnop"));
        assert!(contains_secret_marker(
            br#"{"secret_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
        ));
        assert!(!contains_secret_marker(
            br#"{"sha256_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
        ));
        assert!(!contains_secret_marker(
            br#"{"subject_secret":null,"public":"expected result"}"#
        ));
        assert!(contains_secret_marker(
            b"eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc"
        ));
        assert!(!contains_secret_marker(b"public expected result"));
    }

    #[test]
    fn derived_member_paths_bind_complete_fixture_identity() {
        let first = digest(1);
        let second = digest(2);
        assert_ne!(
            fixture_input_member_path(
                "case/a",
                ClaimLayerV1::ArtifactIntegrity,
                &first,
                "member/b",
            ),
            fixture_input_member_path(
                "case",
                ClaimLayerV1::ArtifactIntegrity,
                &first,
                "a/member/b",
            )
        );
        assert_ne!(
            fixture_input_member_path("case", ClaimLayerV1::ArtifactIntegrity, &first, "member"),
            fixture_input_member_path("case", ClaimLayerV1::ArtifactIntegrity, &second, "member")
        );
        assert_ne!(
            fixture_input_member_path("case", ClaimLayerV1::ArtifactIntegrity, &first, "member"),
            fixture_input_member_path("case", ClaimLayerV1::ReplayConformance, &first, "member")
        );
        assert_ne!(
            expected_result_member_path("case", ClaimLayerV1::ArtifactIntegrity, &first),
            expected_result_member_path("case", ClaimLayerV1::ArtifactIntegrity, &second)
        );
    }

    #[test]
    fn total_bundle_size_limit_is_closed() {
        assert_eq!(MAX_MEMBER_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_TOTAL_BUNDLE_BYTES, 1024 * 1024 * 1024);
        assert_eq!(validate_member_count(MAX_MEMBERS), Ok(()));
        assert_eq!(
            validate_member_count(MAX_MEMBERS + 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(validate_member_size(MAX_MEMBER_BYTES), Ok(()));
        assert_eq!(
            validate_member_size(MAX_MEMBER_BYTES + 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(validate_total_bytes(MAX_TOTAL_BUNDLE_BYTES), Ok(()));
        assert_eq!(
            validate_total_bytes(MAX_TOTAL_BUNDLE_BYTES + 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(validate_archive_length(0), Ok(()));
        assert_eq!(
            validate_archive_length(usize::try_from(MAX_TOTAL_BUNDLE_BYTES).unwrap_or(usize::MAX)),
            Ok(())
        );
        assert_eq!(
            validate_archive_length(
                usize::try_from(MAX_TOTAL_BUNDLE_BYTES + 1).unwrap_or(usize::MAX)
            ),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            accumulate_member_bytes(0, MAX_MEMBER_BYTES + 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            accumulate_member_bytes(MAX_TOTAL_BUNDLE_BYTES, 1),
            Ok(MAX_TOTAL_BUNDLE_BYTES + 1)
        );
    }

    #[test]
    fn canonical_archive_encoding_maps_write_failures() {
        struct FailingWriter;

        impl std::io::Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("write failure"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        assert_eq!(
            encode_archive_value_to_writer(&Value::Null, FailingWriter),
            Err(BundleContractErrorV1::EncodingFailed)
        );
    }

    #[test]
    fn manifest_encoding_is_deterministic() -> Result<(), BundleContractErrorV1> {
        let manifest = BundleManifestV1 {
            magic: CONFORMANCE_BUNDLE_MAGIC_V1.to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            mode: BundleModeV1::Local,
            profile_digest: [1; 32],
            members: vec![BundleMemberDescriptorV1 {
                path: PROFILE_MEMBER_PATH.to_owned(),
                size_bytes: 1,
                digest: [2; 32],
                role: BundleMemberRoleV1::Profile,
            }],
            expected_results: vec![BundleExpectedResultV1 {
                case_id: "case".to_owned(),
                claim_layer: ClaimLayerV1::ArtifactIntegrity,
                execution_profile_digest: [4; 32],
                mode: BundleModeV1::Local,
                member_path: "expected/result".to_owned(),
                digest: [3; 32],
            }],
        };
        let first = canonical::encode(&manifest_value(&manifest))
            .map_err(|_| BundleContractErrorV1::EncodingFailed)?;
        let second = canonical::encode(&manifest_value(&manifest))
            .map_err(|_| BundleContractErrorV1::EncodingFailed)?;
        assert_eq!(first, second);
        assert_eq!(BundleModeV1::Local.code(), 0);
        assert_eq!(BundleModeV1::AirGapped.code(), 1);
        for (layer, expected_code) in [
            (ClaimLayerV1::ArtifactIntegrity, 0),
            (ClaimLayerV1::ReplayConformance, 1),
            (ClaimLayerV1::KnowledgeNonInterference, 2),
            (ClaimLayerV1::GatewayClientConformance, 3),
            (ClaimLayerV1::PluginConformance, 4),
            (ClaimLayerV1::MetricConformance, 5),
            (ClaimLayerV1::EmpiricalEvaluation, 6),
        ] {
            assert_eq!(claim_layer_code(layer), expected_code);
        }
        for (lifecycle, expected_code) in [
            (ProfileLifecycleV1::Draft, 0),
            (ProfileLifecycleV1::Candidate, 1),
            (ProfileLifecycleV1::Stable, 2),
            (ProfileLifecycleV1::Retired, 3),
        ] {
            assert_eq!(lifecycle.wire_code(), expected_code);
        }
        for lifecycle in [ProfileLifecycleV1::Stable, ProfileLifecycleV1::Retired] {
            let mut lifecycle_manifest = manifest.clone();
            lifecycle_manifest.lifecycle = lifecycle;
            assert!(canonical::encode(&manifest_value(&lifecycle_manifest)).is_ok());
        }
        Ok(())
    }

    #[test]
    fn materialized_bundle_is_signed_content_addressed_and_bound_to_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        bundle.validate()?;
        let manifest_bytes = bundle.manifest_bytes()?;
        assert_eq!(
            manifest_bytes,
            encode_archive_value(&manifest_value(&bundle.manifest))?
        );
        let mut digest_input = b"PiglorOS.ConformanceBundle.v1\0".to_vec();
        digest_input.extend_from_slice(&manifest_bytes);
        assert_eq!(
            bundle.bundle_digest()?,
            *blake3::hash(&digest_input).as_bytes()
        );
        assert_eq!(bundle.manifest.profile_digest, profile.profile_digest);
        Ok(())
    }

    #[test]
    fn public_archive_codec_round_trips_both_execution_modes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        for mode in [BundleModeV1::Local, BundleModeV1::AirGapped] {
            let bundle = signed_bundle(&profile, mode)?;
            let encoded = bundle.to_canonical_cbor()?;
            let preflight = preflight_archive_caps(&encoded)?;
            assert_eq!(preflight.maximum_depth, value_depth(&bundle_value(&bundle)));
            let decoded = ConformanceBundleV1::from_canonical_cbor(&encoded)?;
            assert_eq!(decoded, bundle);
            assert_eq!(decoded.to_canonical_cbor()?, encoded);
        }
        Ok(())
    }

    #[test]
    fn each_public_claim_layer_materializes_as_its_own_profile_and_bundle(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let claim_layers = [
            ClaimLayerV1::ArtifactIntegrity,
            ClaimLayerV1::ReplayConformance,
            ClaimLayerV1::KnowledgeNonInterference,
            ClaimLayerV1::GatewayClientConformance,
            ClaimLayerV1::PluginConformance,
            ClaimLayerV1::MetricConformance,
            ClaimLayerV1::EmpiricalEvaluation,
        ];
        for claim_layer in claim_layers {
            let profile = profile_for_claim_layer_families(claim_layer);
            assert_eq!(profile.fixtures.len(), 14);
            for mode in [BundleModeV1::Local, BundleModeV1::AirGapped] {
                let bundle = signed_bundle(&profile, mode)?;
                assert_eq!(bundle.manifest.expected_results.len(), 7);
                assert_eq!(bundle.manifest.mode, mode);
                bundle.validate()?;
            }
        }
        Ok(())
    }

    #[test]
    fn draft_bundle_validates_authority_slots() -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = profile();
        profile.lifecycle = ProfileLifecycleV1::Draft;
        profile.profile_digest = profile.digest();
        let (members, expected_results) = bundle_inputs(&profile, BundleModeV1::Local)?;
        let bundle = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?
        .sign(&ed25519_dalek::SigningKey::from_bytes(&[42; 32]))?;
        assert!(bundle.validate().is_ok());
        Ok(())
    }

    #[test]
    fn public_archive_decoder_rejects_noncanonical_and_unknown_roles(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let mut trailing = bundle.to_canonical_cbor()?;
        trailing.push(0);
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&trailing),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        for role in [12_u64, 13, 99] {
            let mut invalid_role = bundle_value(&bundle);
            if let Value::Array(fields) = &mut invalid_role {
                if let Value::Array(members) = &mut fields[3] {
                    if let Value::Array(member) = &mut members[0] {
                        member[2] = Value::Integer(role.into());
                    }
                }
            }
            let invalid_role_bytes = encode_archive_value(&invalid_role)?;
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&invalid_role_bytes),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }
        Ok(())
    }

    #[test]
    fn archive_preflight_rejects_unsafe_shapes_before_decode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for bytes in [
            vec![0x18],
            vec![0x1f],
            vec![0x19, 0, 0x17],
            vec![0x1a, 0, 0, 0, 0x17],
            vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 0x17],
            vec![0x58, 1, 0],
            vec![0x78, 1, b'a'],
            vec![0xa0],
            vec![0xc0],
            vec![0xfa, 0, 0, 0, 0],
            vec![0x9a, 0, 1, 0, 1],
            vec![0x7a, 0, 0, 1, 1],
            vec![0x5b, 0, 0, 0, 0, 4, 0, 0, 1],
        ] {
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&bytes),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }
        let mut deeply_nested = Value::Null;
        for _ in 0..=usize::from(MAX_STRUCTURAL_NESTING) {
            deeply_nested = Value::Array(vec![deeply_nested]);
        }
        let deeply_nested_bytes = encode_archive_value(&deeply_nested)?;
        assert_eq!(
            preflight_archive(&deeply_nested_bytes),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&deeply_nested_bytes),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        Ok(())
    }

    #[test]
    fn archive_preflight_supported_items_and_boundaries_are_explicit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for value in [
            Value::Integer(0_u64.into()),
            Value::Integer((-1_i8).into()),
            Value::Bytes(vec![1]),
            Value::Text("path".to_owned()),
            Value::Array(vec![Value::Null]),
            Value::Bool(false),
            Value::Bool(true),
            Value::Null,
        ] {
            assert_eq!(preflight_archive(&encode_archive_value(&value)?), Ok(()));
        }

        let exact_path = Value::Text("a".repeat(MAX_MEMBER_PATH_BYTES));
        assert_eq!(
            preflight_archive(&encode_archive_value(&exact_path)?),
            Ok(())
        );
        let oversized_path = Value::Text("a".repeat(MAX_MEMBER_PATH_BYTES + 1));
        assert_eq!(
            preflight_archive(&encode_archive_value(&oversized_path)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let exact_array = Value::Array(vec![Value::Null; MAX_MEMBERS]);
        assert_eq!(
            preflight_archive(&encode_archive_value(&exact_array)?),
            Ok(())
        );
        let oversized_array = Value::Array(vec![Value::Null; MAX_MEMBERS + 1]);
        assert_eq!(
            preflight_archive(&encode_archive_value(&oversized_array)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(preflight_archive(&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]), Ok(()));

        let mut exact_depth = Value::Null;
        for _ in 0..usize::from(MAX_STRUCTURAL_NESTING) {
            exact_depth = Value::Array(vec![exact_depth]);
        }
        assert_eq!(
            preflight_archive(&encode_archive_value(&exact_depth)?),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn archive_preflight_caps_report_member_statistics() -> Result<(), Box<dyn std::error::Error>> {
        let value = Value::Array(vec![
            Value::Text(CONFORMANCE_BUNDLE_MAGIC_V1.to_owned()),
            Value::Integer((-1_i8).into()),
            Value::Array(vec![Value::Null]),
            Value::Array(vec![Value::Array(vec![
                Value::Text("profile".to_owned()),
                Value::Bytes(vec![1, 2, 3]),
                Value::Integer(BundleMemberRoleV1::Profile.code().into()),
            ])]),
            Value::Bool(true),
            Value::Null,
        ]);
        let bytes = encode_archive_value(&value)?;
        assert_eq!(preflight_archive(&bytes), Ok(()));
        let preflight = preflight_archive_caps(&bytes)?;
        assert_eq!(preflight.profile_bytes, Some(&[1, 2, 3][..]));
        assert_eq!(preflight.member_count, 1);
        assert_eq!(preflight.total_member_bytes, 3);
        assert_eq!(preflight.largest_member_bytes, 3);
        assert_eq!(preflight.largest_member_path_bytes, 7);
        assert_eq!(preflight.maximum_depth, 4);
        Ok(())
    }

    #[test]
    fn preflight_archive_caps_check_each_limit_independently() {
        let profile_bytes = [1_u8, 2];
        for limit in 0..7 {
            let mut profile = wide_profile();
            let mut preflight = ArchivePreflight {
                profile_bytes: Some(&profile_bytes),
                member_count: 2,
                total_member_bytes: 2,
                largest_member_bytes: 2,
                largest_member_path_bytes: 2,
                maximum_depth: 2,
            };
            let mut encoded_len = 1;
            match limit {
                0 => {
                    profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = 1;
                    preflight.total_member_bytes = 1;
                    encoded_len = 2;
                }
                1 => profile.evaluator_protocol.hard_caps.max_profile_bytes = 1,
                2 => profile.evaluator_protocol.hard_caps.max_structural_nesting = 1,
                3 => profile.evaluator_protocol.hard_caps.max_bundle_members = 1,
                4 => profile.evaluator_protocol.hard_caps.max_member_path_bytes = 1,
                5 => profile.evaluator_protocol.hard_caps.max_member_bytes = 1,
                _ => {
                    profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = 1;
                    preflight.total_member_bytes = 2;
                }
            }
            assert_eq!(
                validate_preflight_archive_caps(&profile, &preflight, encoded_len),
                Err(BundleContractErrorV1::MemberOutOfBounds)
            );
        }

        for limit in 0..7 {
            let mut profile = wide_profile();
            let mut preflight = ArchivePreflight {
                profile_bytes: Some(&profile_bytes[..1]),
                member_count: 1,
                total_member_bytes: 1,
                largest_member_bytes: 1,
                largest_member_path_bytes: 1,
                maximum_depth: 1,
            };
            let mut encoded_len = 1;
            match limit {
                0 => profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = 1,
                1 => profile.evaluator_protocol.hard_caps.max_profile_bytes = 1,
                2 => profile.evaluator_protocol.hard_caps.max_structural_nesting = 1,
                3 => profile.evaluator_protocol.hard_caps.max_bundle_members = 1,
                4 => profile.evaluator_protocol.hard_caps.max_member_path_bytes = 1,
                5 => profile.evaluator_protocol.hard_caps.max_member_bytes = 1,
                _ => {
                    profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = 2;
                    preflight.total_member_bytes = 2;
                    encoded_len = 1;
                }
            }
            assert_eq!(
                validate_preflight_archive_caps(&profile, &preflight, encoded_len),
                Ok(())
            );
        }
    }

    #[test]
    fn archive_decoder_rejects_invalid_fields_and_cap_overflows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&[]),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        for bytes in [vec![0x42, 0], vec![0x62, b'a']] {
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&bytes),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }

        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let mut invalid_magic = bundle_value(&bundle);
        if let Value::Array(fields) = &mut invalid_magic {
            fields[0] = Value::Text("wrong-magic".to_owned());
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&invalid_magic)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut invalid_version = bundle_value(&bundle);
        if let Value::Array(fields) = &mut invalid_version {
            fields[1] = Value::Integer(2_u64.into());
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&invalid_version)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut missing_version = bundle_value(&bundle);
        if let Value::Array(fields) = &mut missing_version {
            fields[1] = Value::Null;
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&missing_version)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        assert_eq!(
            archive_array_exact(&Value::Null, 1),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            archive_array_bounded(&Value::Null, 1),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            archive_text(&Value::Null),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            archive_bytes(&Value::Null),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            archive_u64(&Value::Null),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            archive_u64(&Value::Integer((-1_i8).into())),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            decode_bundle_mode(2),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(decode_lifecycle(0), Ok(ProfileLifecycleV1::Draft));
        assert_eq!(decode_lifecycle(2), Ok(ProfileLifecycleV1::Stable));
        assert_eq!(decode_lifecycle(3), Ok(ProfileLifecycleV1::Retired));
        assert_eq!(
            decode_lifecycle(4),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            decode_claim_layer(7),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let value = bundle_value(&bundle);
        assert_eq!(
            validate_archive_caps(&bundle, &value, usize::MAX),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn archive_array_decoder_boundaries_are_inclusive() {
        let one = Value::Array(vec![Value::Null]);
        assert_eq!(archive_array_exact(&one, 1), Ok(&[Value::Null][..]));
        assert_eq!(
            archive_array_exact(&one, 0),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(archive_array_bounded(&one, 1), Ok(&[Value::Null][..]));
        assert_eq!(
            archive_array_bounded(&one, 0),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }

    #[test]
    fn decoded_archive_caps_accept_exact_depth_and_reject_overflow(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let exact_depth = (0..usize::from(MAX_STRUCTURAL_NESTING - 1))
            .fold(Value::Null, |value, _| Value::Array(vec![value]));
        assert_eq!(validate_archive_caps(&bundle, &exact_depth, 1), Ok(()));
        let over_depth = Value::Array(vec![exact_depth]);
        assert_eq!(
            validate_archive_caps(&bundle, &over_depth, 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        Ok(())
    }

    #[test]
    fn support_digest_fallbacks_and_selected_caps_are_checked(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut support_profile = profile();
        support_profile.provenance_digest = digest(100);
        support_profile.fixtures[0].provenance.source_digest = digest(101);
        support_profile.fixtures[0].provenance.build_digest = digest(102);
        support_profile.fixtures[0]
            .provenance
            .publication_review_digest = digest(103);
        assert!(support_digest_is_bound(
            &support_profile,
            BundleMemberRoleV1::Provenance,
            &digest(101)
        ));
        assert!(support_digest_is_bound(
            &support_profile,
            BundleMemberRoleV1::Provenance,
            &digest(102)
        ));
        assert!(support_digest_is_bound(
            &support_profile,
            BundleMemberRoleV1::Provenance,
            &digest(103)
        ));
        support_profile.limitations_digest = digest(104);
        support_profile.fixtures[0].provenance.limitations_digest = digest(105);
        assert!(support_digest_is_bound(
            &support_profile,
            BundleMemberRoleV1::Limitations,
            &digest(105)
        ));
        assert!(!support_digest_is_bound(
            &support_profile,
            BundleMemberRoleV1::FixtureInput,
            &digest(101)
        ));

        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let mut profile_cap = profile();
        profile_cap.evaluator_protocol.hard_caps.max_profile_bytes = 0;
        assert_eq!(
            validate_selected_bundle_caps(&profile_cap, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        let mut member_cap = profile();
        member_cap.evaluator_protocol.hard_caps.max_profile_bytes = u64::MAX;
        member_cap
            .evaluator_protocol
            .hard_caps
            .max_structural_nesting = u8::MAX;
        member_cap
            .evaluator_protocol
            .hard_caps
            .max_member_path_bytes = u16::MAX;
        member_cap.evaluator_protocol.hard_caps.max_bundle_members = u32::MAX;
        member_cap.evaluator_protocol.hard_caps.max_member_bytes = 0;
        assert_eq!(
            validate_selected_bundle_caps(&member_cap, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        let mut total_cap = profile();
        total_cap.evaluator_protocol.hard_caps.max_profile_bytes = u64::MAX;
        total_cap
            .evaluator_protocol
            .hard_caps
            .max_structural_nesting = u8::MAX;
        total_cap.evaluator_protocol.hard_caps.max_member_path_bytes = u16::MAX;
        total_cap.evaluator_protocol.hard_caps.max_member_bytes = u64::MAX;
        total_cap.evaluator_protocol.hard_caps.max_bundle_members = u32::MAX;
        total_cap
            .evaluator_protocol
            .hard_caps
            .max_total_bundle_bytes = 0;
        assert_eq!(
            validate_selected_bundle_caps(&total_cap, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );

        let nested = Value::Map(vec![(
            Value::Text("key".to_owned()),
            Value::Tag(1, Box::new(Value::Array(vec![Value::Null]))),
        )]);
        let mut nesting_cap = profile();
        nesting_cap.evaluator_protocol.hard_caps.max_profile_bytes = u64::MAX;
        nesting_cap
            .evaluator_protocol
            .hard_caps
            .max_structural_nesting = 0;
        assert_eq!(
            validate_selected_bundle_caps(&nesting_cap, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(value_depth(&nested), 4);
        Ok(())
    }

    #[test]
    fn selected_bundle_caps_check_each_limit_independently(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let profile_member_bytes = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::Profile)
            .map(|member| member.bytes.len() as u64)
            .ok_or("missing profile member")?;
        let manifest_depth = value_depth(&manifest_value(&bundle.manifest));
        let member_count = u32::try_from(bundle.members.len())?;
        let largest_path = bundle
            .members
            .iter()
            .map(|member| member.path.len())
            .max()
            .ok_or("missing bundle members")?;
        let largest_path = u16::try_from(largest_path)?;
        let largest_member = bundle
            .members
            .iter()
            .map(|member| member.bytes.len() as u64)
            .max()
            .ok_or("missing member bytes")?;
        let total_bytes = bundle
            .members
            .iter()
            .map(|member| member.bytes.len() as u64)
            .sum::<u64>();

        for limit in 0..7 {
            let mut profile = wide_profile();
            match limit {
                0 => profile.evaluator_protocol.hard_caps.max_profile_bytes = 0,
                1 => profile.evaluator_protocol.hard_caps.max_structural_nesting = 0,
                2 => profile.evaluator_protocol.hard_caps.max_bundle_members = 0,
                3 => profile.evaluator_protocol.hard_caps.max_member_path_bytes = 0,
                4 => profile.evaluator_protocol.hard_caps.max_member_bytes = 0,
                5 => profile.evaluator_protocol.hard_caps.max_total_bundle_bytes = 0,
                _ => profile.evaluator_protocol.hard_caps.max_cases = 0,
            }
            assert_eq!(
                validate_selected_bundle_caps(&profile, &bundle),
                Err(BundleContractErrorV1::MemberOutOfBounds)
            );
        }

        let mut exact_profile = wide_profile();
        exact_profile.evaluator_protocol.hard_caps.max_profile_bytes = profile_member_bytes;
        assert_eq!(
            validate_selected_bundle_caps(&exact_profile, &bundle),
            Ok(())
        );
        exact_profile
            .evaluator_protocol
            .hard_caps
            .max_structural_nesting = u8::try_from(manifest_depth)?;
        assert_eq!(
            validate_selected_bundle_caps(&exact_profile, &bundle),
            Ok(())
        );
        exact_profile
            .evaluator_protocol
            .hard_caps
            .max_bundle_members = member_count;
        assert_eq!(
            validate_selected_bundle_caps(&exact_profile, &bundle),
            Ok(())
        );
        exact_profile
            .evaluator_protocol
            .hard_caps
            .max_member_path_bytes = largest_path;
        assert_eq!(
            validate_selected_bundle_caps(&exact_profile, &bundle),
            Ok(())
        );
        exact_profile.evaluator_protocol.hard_caps.max_member_bytes = largest_member;
        assert_eq!(
            validate_selected_bundle_caps(&exact_profile, &bundle),
            Ok(())
        );
        exact_profile
            .evaluator_protocol
            .hard_caps
            .max_total_bundle_bytes = total_bytes;
        assert_eq!(
            validate_selected_bundle_caps(&exact_profile, &bundle),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_descriptor_role_and_profile_path_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let support_index = bundle
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Schema)
            .ok_or("missing schema support member")?;

        let mut mismatched_descriptor = bundle.clone();
        mismatched_descriptor.manifest.members[support_index].role = BundleMemberRoleV1::Profile;
        assert_eq!(
            mismatched_descriptor.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let mut mismatched_profile_path = bundle;
        mismatched_profile_path.members[support_index].role = BundleMemberRoleV1::Profile;
        mismatched_profile_path.manifest.members[support_index].role = BundleMemberRoleV1::Profile;
        assert_eq!(
            mismatched_profile_path.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_missing_profile_and_descriptor_digest_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let profile_index = bundle
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Profile)
            .ok_or("missing profile member")?;
        let support_index = bundle
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Schema)
            .ok_or("missing schema support member")?;

        let mut missing_profile = bundle.clone();
        missing_profile.members[support_index].role = BundleMemberRoleV1::Profile;
        missing_profile.members.remove(profile_index);
        assert_eq!(
            missing_profile.validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let input_index = bundle
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::FixtureInput)
            .ok_or("missing fixture input")?;
        let mut mismatched_digest = bundle;
        mismatched_digest.manifest.members[input_index].digest = digest(99);
        assert_eq!(
            mismatched_digest.validate(),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn required_support_artifacts_and_selected_caps_are_enforced(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let mut missing_support = signed_bundle(&profile, BundleModeV1::Local)?;
        missing_support
            .members
            .retain(|member| member.role != BundleMemberRoleV1::Schema);
        missing_support.rebuild_member_descriptors();
        assert_eq!(
            missing_support.validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut unbound_support = signed_bundle(&profile, BundleModeV1::Local)?;
        unbound_support.members.push(BundleMemberV1::supporting(
            "support/unbound-schema.cddl",
            b"unbound schema".to_vec(),
            BundleMemberRoleV1::Schema,
        ));
        unbound_support.rebuild_member_descriptors();
        assert_eq!(
            unbound_support.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let mut limited_profile = profile.clone();
        limited_profile
            .evaluator_protocol
            .hard_caps
            .max_bundle_members = 1;
        assert_eq!(
            validate_selected_bundle_caps(&limited_profile, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );

        let mut incomplete_profile = profile;
        incomplete_profile.public_schema_digests.push(digest(99));
        assert_eq!(
            validate_supporting_members(&incomplete_profile, &bundle.members),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn ordering_predicates_reject_descending_and_duplicate_values() {
        assert!(strictly_ordered(&[1_u8, 2, 3]));
        assert!(!strictly_ordered(&[2_u8, 1]));
        assert!(!strictly_ordered(&[1_u8, 1]));
        assert!(strictly_ordered::<u8>(&[]));
        assert!(strictly_ordered(&[1_u8]));

        let ordered = vec![
            BundleMemberV1::new("a", vec![1], false),
            BundleMemberV1::new("b", vec![2], false),
        ];
        assert!(members_strictly_ordered(&ordered));
        let mut descending = ordered;
        descending.swap(0, 1);
        assert!(!members_strictly_ordered(&descending));
        let duplicate = vec![
            BundleMemberV1::new("a", vec![1], false),
            BundleMemberV1::new("a", vec![2], false),
        ];
        assert!(!members_strictly_ordered(&duplicate));
        let case_collision = vec![
            BundleMemberV1::new("a", vec![1], false),
            BundleMemberV1::new("A", vec![2], false),
        ];
        assert!(!members_strictly_ordered(&case_collision));
        let non_adjacent_case_collision = vec![
            BundleMemberV1::new("A", vec![1], false),
            BundleMemberV1::new("B", vec![2], false),
            BundleMemberV1::new("a", vec![3], false),
        ];
        assert!(!members_strictly_ordered(&non_adjacent_case_collision));
    }

    #[test]
    fn local_and_air_gapped_bundles_require_expected_result_parity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let pair = ConformanceBundlePairV1 {
            local: signed_bundle(&profile, BundleModeV1::Local)?,
            air_gapped: signed_bundle(&profile, BundleModeV1::AirGapped)?,
        };
        pair.validate()?;

        let mut changed_authority_data = pair.air_gapped.clone();
        let matrix_index = changed_authority_data
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("signed test bundle has no execution matrix")?;
        changed_authority_data.members[matrix_index]
            .bytes
            .push(b'!');
        assert_ne!(
            bundle_pair_payloads(&pair.air_gapped),
            bundle_pair_payloads(&changed_authority_data)
        );

        let mut changed_profile = profile;
        if let ExpectedResultV1::CanonicalBytes { bytes, digest } =
            &mut changed_profile.fixtures[0].expected
        {
            bytes.push(b'!');
            *digest = *blake3::hash(bytes).as_bytes();
        }
        changed_profile.profile_digest = changed_profile.digest();
        let invalid_pair = ConformanceBundlePairV1 {
            local: pair.local,
            air_gapped: signed_bundle(&changed_profile, BundleModeV1::AirGapped)?,
        };
        assert_eq!(
            invalid_pair.validate(),
            Err(BundleContractErrorV1::ModeParityMismatch)
        );
        Ok(())
    }

    #[test]
    fn expected_identity_preserves_case_layer_and_digest() -> Result<(), Box<dyn std::error::Error>>
    {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let identity = expected_identity(&bundle.manifest.expected_results);
        assert_eq!(identity.len(), bundle.manifest.expected_results.len());
        assert!(!identity.is_empty());
        assert_eq!(identity[0].0, bundle.manifest.expected_results[0].case_id);
        assert_eq!(identity[0].2, bundle.manifest.expected_results[0].digest);
        Ok(())
    }

    #[test]
    fn pair_validation_checks_modes_and_member_paths() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let air_gapped = signed_bundle(&profile, BundleModeV1::AirGapped)?;

        let mut local_with_air_mode = signed_bundle(&profile, BundleModeV1::Local)?;
        local_with_air_mode.manifest.mode = BundleModeV1::AirGapped;
        for expected in &mut local_with_air_mode.manifest.expected_results {
            expected.mode = BundleModeV1::AirGapped;
        }
        assert_eq!(
            (ConformanceBundlePairV1 {
                local: local_with_air_mode,
                air_gapped: air_gapped.clone(),
            })
            .validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut local_with_opposite_mode_input = signed_bundle(&profile, BundleModeV1::Local)?;
        let opposite_mode_input = air_gapped
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::FixtureInput)
            .cloned()
            .ok_or("test bundle has an opposite-mode fixture input")?;
        local_with_opposite_mode_input
            .members
            .push(opposite_mode_input);
        local_with_opposite_mode_input.rebuild_member_descriptors();
        assert_eq!(
            local_with_opposite_mode_input.sign(&signing_key),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let mut air_with_local_mode = air_gapped.clone();
        air_with_local_mode.manifest.mode = BundleModeV1::Local;
        for expected in &mut air_with_local_mode.manifest.expected_results {
            expected.mode = BundleModeV1::Local;
        }
        assert_eq!(
            (ConformanceBundlePairV1 {
                local: signed_bundle(&profile, BundleModeV1::Local)?,
                air_gapped: air_with_local_mode,
            })
            .validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut air_with_other_path = air_gapped;
        let alternate_path = "expected/alternate.bin".to_owned();
        let expected_index = expected_member_index(&air_with_other_path)
            .ok_or("test bundle has an expected-result member")?;
        air_with_other_path.members[expected_index].path = alternate_path.clone();
        air_with_other_path.manifest.members[expected_index].path = alternate_path.clone();
        air_with_other_path.manifest.expected_results[0].member_path = alternate_path;
        air_with_other_path.rebuild_member_descriptors();
        assert_eq!(
            (ConformanceBundlePairV1 {
                local: signed_bundle(&profile, BundleModeV1::Local)?,
                air_gapped: air_with_other_path,
            })
            .validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_profile_and_manifest_contract_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut stable_profile = profile;
        stable_profile.lifecycle = ProfileLifecycleV1::Stable;
        assert_eq!(
            ConformanceBundleV1::materialize(
                &stable_profile,
                BundleModeV1::Local,
                Vec::new(),
                Vec::new(),
            ),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_magic = bundle.clone();
        invalid_magic.manifest.magic = "invalid".to_owned();
        assert_eq!(
            invalid_magic.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_lifecycle = bundle.clone();
        invalid_lifecycle.manifest.lifecycle = ProfileLifecycleV1::Stable;
        assert_eq!(
            invalid_lifecycle.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_profile_digest = bundle.clone();
        invalid_profile_digest.manifest.profile_digest = digest(99);
        assert_eq!(
            invalid_profile_digest.validate(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );

        let mut unsorted_expected = bundle.clone();
        unsorted_expected.manifest.expected_results.swap(0, 1);
        assert_eq!(
            unsorted_expected.validate(),
            Err(BundleContractErrorV1::NonCanonicalOrder)
        );

        let mut missing_member = bundle;
        missing_member.manifest.expected_results[0].member_path = "expected/missing".to_owned();
        assert_eq!(
            missing_member.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );
        Ok(())
    }

    #[test]
    fn expected_result_validation_rejects_each_binding_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut wrong_mode = bundle.manifest.clone();
        wrong_mode.expected_results[0].mode = BundleModeV1::AirGapped;
        assert_eq!(
            validate_expected_results(&profile, &wrong_mode, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut zero_digest = bundle.manifest.clone();
        zero_digest.expected_results[0].digest = [0; 32];
        assert_eq!(
            validate_expected_results(&profile, &zero_digest, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut not_an_expected_result = bundle.members.clone();
        let expected_result_index = not_an_expected_result
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::ExpectedResult)
            .ok_or("missing expected-result member")?;
        not_an_expected_result[expected_result_index].expected_result = false;
        assert_eq!(
            validate_expected_results(&profile, &bundle.manifest, &not_an_expected_result),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut unknown_fixture = bundle.manifest.clone();
        unknown_fixture.expected_results[0].case_id = "case-00-unknown".to_owned();
        assert_eq!(
            validate_expected_results(&profile, &unknown_fixture, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut missing_layer = profile.clone();
        missing_layer.fixtures.remove(0);
        assert_eq!(
            validate_expected_results(&missing_layer, &bundle.manifest, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut unsupported_mode = profile.clone();
        unsupported_mode.fixtures[0].modes = vec![ExecutionModeV1::AirGapped];
        let mut supporting_artifact = unsupported_mode.fixtures[0].clone();
        supporting_artifact.case_id = "case-support".to_owned();
        supporting_artifact.mandatory = false;
        supporting_artifact.modes = vec![ExecutionModeV1::Local];
        unsupported_mode.fixtures.push(supporting_artifact);
        assert_eq!(
            validate_expected_results(&unsupported_mode, &bundle.manifest, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut wrong_fixture_digest = profile.clone();
        match &mut wrong_fixture_digest.fixtures[0].expected {
            ExpectedResultV1::CanonicalBytes {
                digest: fixture_digest,
                ..
            } => *fixture_digest = digest(99),
            ExpectedResultV1::TypedFailure(_) | ExpectedResultV1::AllowedDivergence { .. } => {}
        }
        assert_eq!(
            validate_expected_results(&wrong_fixture_digest, &bundle.manifest, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut missing_expected = bundle.manifest.clone();
        missing_expected.expected_results.remove(0);
        assert_eq!(
            validate_expected_results(&profile, &missing_expected, &bundle.members),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut noncanonical_expected = profile.clone();
        noncanonical_expected.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding);
        assert_eq!(
            validate_expected_results(&noncanonical_expected, &bundle.manifest, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut typed_profile = profile;
        typed_profile.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding);
        let typed_bytes = typed_profile.fixtures[0].expected.to_canonical_bytes()?;
        let typed_digest = *blake3::hash(&typed_bytes).as_bytes();
        let mut typed_members = bundle.members;
        let typed_path = expected_result_member_path(
            &typed_profile.fixtures[0].case_id,
            typed_profile.fixtures[0].claim_layer,
            &typed_profile.fixtures[0].execution_profile_digest,
        );
        let typed_member_index = typed_members
            .iter()
            .position(|member| member.path == typed_path)
            .ok_or("case-00 expected member")?;
        typed_members[typed_member_index] = BundleMemberV1::new(typed_path, typed_bytes, true);
        let mut typed_manifest = bundle.manifest;
        typed_manifest.expected_results[0].digest = typed_digest;
        assert_eq!(
            validate_expected_results(&typed_profile, &typed_manifest, &typed_members),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn canonical_expected_result_digest_binds_fixture_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let ExpectedResultV1::CanonicalBytes { bytes, .. } = &mut profile.fixtures[0].expected
        else {
            return Err("profile fixture must use canonical bytes".into());
        };
        bytes.push(b'!');
        assert_eq!(
            validate_expected_results(&profile, &bundle.manifest, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
        let typed = ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding)
            .to_canonical_bytes()?;
        assert!(!typed.is_empty());
        assert_ne!(typed, vec![0]);
        assert_ne!(typed, vec![1]);
        Ok(())
    }

    #[test]
    fn expected_result_member_guards_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut wrong_digest_members = bundle.members.clone();
        let expected_index =
            expected_member_index(&bundle).ok_or("test bundle has an expected-result member")?;
        wrong_digest_members[expected_index].digest = digest(99);
        assert_eq!(
            validate_expected_results(&profile, &bundle.manifest, &wrong_digest_members,),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut empty_profile = profile.clone();
        if let ExpectedResultV1::CanonicalBytes { digest, bytes } =
            &mut empty_profile.fixtures[0].expected
        {
            bytes.clear();
            *digest = *blake3::hash(bytes).as_bytes();
        }
        let mut empty_members = bundle.members.clone();
        let expected_index =
            expected_member_index(&bundle).ok_or("test bundle has an expected-result member")?;
        empty_members[expected_index].bytes.clear();
        empty_members[expected_index].digest =
            *blake3::hash(&empty_members[expected_index].bytes).as_bytes();
        let mut empty_manifest = bundle.manifest.clone();
        empty_manifest.expected_results[0].digest = empty_members[expected_index].digest;
        assert_eq!(
            validate_expected_results(&empty_profile, &empty_manifest, &empty_members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut missing_path_manifest = bundle.manifest.clone();
        missing_path_manifest.expected_results[0].member_path = "expected/missing".to_owned();
        assert_eq!(
            validate_expected_results(&profile, &missing_path_manifest, &bundle.members),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut undeclared_path_manifest = bundle.manifest.clone();
        let mut undeclared_path_members = bundle.members.clone();
        let expected_index = bundle
            .members
            .iter()
            .position(|member| member.path == bundle.manifest.expected_results[0].member_path)
            .ok_or("test bundle has the first expected-result member")?;
        let alternate_path = "expected/alternate".to_owned();
        undeclared_path_members[expected_index].path = alternate_path.clone();
        undeclared_path_manifest.expected_results[0].member_path = alternate_path;
        assert_eq!(
            validate_expected_results(
                &profile,
                &undeclared_path_manifest,
                &undeclared_path_members,
            ),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let mut mismatched_bytes = bundle.members.clone();
        mismatched_bytes[expected_index].bytes = b"different expected bytes".to_vec();
        mismatched_bytes[expected_index].digest = bundle.manifest.expected_results[0].digest;
        assert_eq!(
            validate_expected_results(&profile, &bundle.manifest, &mismatched_bytes),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
        Ok(())
    }

    #[test]
    fn mandatory_fixture_matching_requires_case_and_layer_and_execution_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut missing_case = bundle.manifest.clone();
        missing_case.expected_results[0].case_id = "case-00-unknown".to_owned();
        assert_eq!(
            validate_expected_results(&profile, &missing_case, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut missing_layer = bundle.manifest.clone();
        missing_layer.expected_results[0].claim_layer = ClaimLayerV1::ReplayConformance;
        assert_eq!(
            validate_expected_results(&profile, &missing_layer, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut missing_execution_profile = bundle.manifest.clone();
        missing_execution_profile.expected_results[0].execution_profile_digest = digest(99);
        assert_eq!(
            validate_expected_results(&profile, &missing_execution_profile, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut missing_mandatory_case = bundle.manifest.clone();
        missing_mandatory_case
            .expected_results
            .retain(|expected| expected.case_id != "case-00");
        assert_eq!(
            validate_expected_results(&profile, &missing_mandatory_case, &bundle.members),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut duplicate_case_profile = profile;
        let mut duplicate_case_fixture = duplicate_case_profile.fixtures[0].clone();
        duplicate_case_fixture.claim_layer = ClaimLayerV1::ReplayConformance;
        duplicate_case_profile
            .fixtures
            .insert(1, duplicate_case_fixture);
        duplicate_case_profile.fixtures.sort_by_key(|fixture| {
            (
                fixture.case_id.clone(),
                fixture.claim_layer,
                fixture.execution_profile_digest,
            )
        });
        duplicate_case_profile.profile_digest = duplicate_case_profile.digest();
        let duplicate_case_bundle = signed_bundle(&duplicate_case_profile, BundleModeV1::Local)?;
        let mut missing_one_of_duplicate_cases = duplicate_case_bundle.manifest.clone();
        missing_one_of_duplicate_cases
            .expected_results
            .retain(|expected| expected.claim_layer != ClaimLayerV1::ArtifactIntegrity);
        assert_eq!(
            validate_expected_results(
                &duplicate_case_profile,
                &missing_one_of_duplicate_cases,
                &duplicate_case_bundle.members,
            ),
            Err(BundleContractErrorV1::MemberMissing)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_tampered_bytes_and_unsorted_members(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut tampered = bundle.clone();
        let expected_index =
            expected_member_index(&tampered).ok_or("test bundle has an expected-result member")?;
        tampered.members[expected_index].bytes[0] ^= 1;
        assert_eq!(
            tampered.validate(),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut unsorted = bundle;
        unsorted.members.swap(0, 1);
        assert_eq!(
            unsorted.validate(),
            Err(BundleContractErrorV1::NonCanonicalOrder)
        );

        let mut unsorted_manifest = signed_bundle(&profile, BundleModeV1::Local)?;
        unsorted_manifest.manifest.members.swap(0, 1);
        assert_eq!(
            unsorted_manifest.validate(),
            Err(BundleContractErrorV1::NonCanonicalOrder)
        );

        let mut undeclared = signed_bundle(&profile, BundleModeV1::Local)?;
        let last_descriptor = undeclared.manifest.members.len() - 1;
        undeclared.manifest.members[last_descriptor].path = "zz-undeclared".to_owned();
        assert_eq!(
            undeclared.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let mut invalid_signature = signed_bundle(&profile, BundleModeV1::Local)?;
        invalid_signature.signature = Signature::from_bytes([1; 64]);
        assert_eq!(
            invalid_signature.validate(),
            Err(BundleContractErrorV1::SignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn fixture_input_guards_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile_for_claim_layer(ClaimLayerV1::ArtifactIntegrity);
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let input_index = bundle
            .members
            .iter()
            .position(|member| member.path.starts_with(INPUT_MEMBER_PREFIX))
            .ok_or("missing fixture input member")?;

        let mut wrong_size = profile.clone();
        wrong_size.fixtures[0].inputs[0].size_bytes += 1;
        assert_eq!(
            validate_fixture_inputs_for_mode(&wrong_size, None, &bundle.members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut wrong_declared_digest = profile.clone();
        wrong_declared_digest.fixtures[0].inputs[0].digest = digest(99);
        assert_eq!(
            validate_fixture_inputs_for_mode(&wrong_declared_digest, None, &bundle.members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut wrong_content_digest = profile.clone();
        wrong_content_digest.fixtures[0].inputs[0].digest = digest(99);
        let mut wrong_content_member = bundle.members.clone();
        wrong_content_member[input_index].digest = digest(99);
        assert_eq!(
            validate_fixture_inputs_for_mode(&wrong_content_digest, None, &wrong_content_member),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut empty_profile = profile.clone();
        empty_profile.fixtures[0].inputs[0].size_bytes = 0;
        empty_profile.fixtures[0].inputs[0].digest = *blake3::hash(b"").as_bytes();
        let mut empty_member = bundle.members.clone();
        empty_member[input_index].bytes.clear();
        empty_member[input_index].digest = *blake3::hash(b"").as_bytes();
        assert_eq!(
            validate_fixture_inputs_for_mode(&empty_profile, None, &empty_member),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut marked_expected = bundle.members;
        marked_expected[input_index].expected_result = true;
        assert_eq!(
            validate_fixture_inputs_for_mode(&profile, None, &marked_expected),
            Err(BundleContractErrorV1::UndeclaredMember)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_secret_payloads_and_air_gapped_network_access(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let mut secret = signed_bundle(&profile, BundleModeV1::Local)?;
        let expected_index =
            expected_member_index(&secret).ok_or("test bundle has an expected-result member")?;
        secret.members[expected_index].bytes = b"PRIVATE KEY material".to_vec();
        secret.members[expected_index].digest =
            *blake3::hash(&secret.members[expected_index].bytes).as_bytes();
        secret.manifest.members[expected_index].digest = secret.members[expected_index].digest;
        secret.manifest.members[expected_index].size_bytes =
            secret.members[expected_index].bytes.len() as u64;
        assert_eq!(
            secret.validate(),
            Err(BundleContractErrorV1::SecretMaterialDetected)
        );

        let mut network_profile = profile;
        let network_fixture = network_profile
            .fixtures
            .iter_mut()
            .find(|fixture| fixture.modes == [ExecutionModeV1::AirGapped])
            .ok_or("missing air-gapped fixture")?;
        network_fixture.capability_policy.network_allowed = true;
        let (members, expected_results) = bundle_inputs(&network_profile, BundleModeV1::AirGapped)?;
        assert_eq!(
            ConformanceBundleV1::materialize(
                &network_profile,
                BundleModeV1::AirGapped,
                members.clone(),
                expected_results.clone(),
            ),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
        let manifest = BundleManifestV1 {
            magic: CONFORMANCE_BUNDLE_MAGIC_V1.to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            mode: BundleModeV1::AirGapped,
            profile_digest: network_profile.profile_digest,
            members: Vec::new(),
            expected_results,
        };
        let mut manifest = manifest;
        manifest.members = members
            .iter()
            .map(|member| BundleMemberDescriptorV1 {
                path: member.path.clone(),
                size_bytes: member.bytes.len() as u64,
                digest: member.digest,
                role: member.role,
            })
            .collect();
        let expected_error = validate_expected_results(&network_profile, &manifest, &members);
        assert_eq!(expected_error, Err(BundleContractErrorV1::AirGappedNetwork));
        Ok(())
    }

    fn replace_array_field(
        value: &Value,
        index: usize,
        replacement: Value,
    ) -> Result<Value, std::io::Error> {
        let Value::Array(mut fields) = value.clone() else {
            return Err(std::io::Error::other("expected array"));
        };
        fields[index] = replacement;
        Ok(Value::Array(fields))
    }

    fn replace_member_field(
        value: &Value,
        index: usize,
        replacement: Value,
    ) -> Result<Value, std::io::Error> {
        let Value::Array(mut fields) = value.clone() else {
            return Err(std::io::Error::other("expected manifest array"));
        };
        let Value::Array(members) = &mut fields[4] else {
            return Err(std::io::Error::other("expected member array"));
        };
        let Value::Array(member) = &mut members[0] else {
            return Err(std::io::Error::other("expected member fields"));
        };
        member[index] = replacement;
        Ok(Value::Array(fields))
    }

    fn replace_expected_field(
        value: &Value,
        index: usize,
        replacement: Value,
    ) -> Result<Value, std::io::Error> {
        let Value::Array(mut fields) = value.clone() else {
            return Err(std::io::Error::other("expected manifest array"));
        };
        let Value::Array(expected_results) = &mut fields[5] else {
            return Err(std::io::Error::other("expected result array"));
        };
        let Value::Array(expected) = &mut expected_results[0] else {
            return Err(std::io::Error::other("expected result fields"));
        };
        expected[index] = replacement;
        Ok(Value::Array(fields))
    }

    #[test]
    fn archive_decoder_rejection_matrix_is_exercised() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let manifest = manifest_value(&bundle.manifest);
        for (index, replacement) in [
            (0, Value::Null),
            (1, Value::Integer(99_u64.into())),
            (2, Value::Integer(99_u64.into())),
            (3, Value::Null),
        ] {
            assert!(decode_manifest(&replace_array_field(&manifest, index, replacement)?).is_err());
        }
        assert!(decode_manifest(&replace_array_field(&manifest, 4, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_array_field(&manifest, 5, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_member_field(&manifest, 0, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_member_field(
            &manifest,
            1,
            Value::Integer((-1_i64).into()),
        )?)
        .is_err());
        assert!(decode_manifest(&replace_member_field(&manifest, 2, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_member_field(
            &manifest,
            3,
            Value::Integer(99_u64.into()),
        )?)
        .is_err());
        assert!(decode_manifest(&replace_member_field(&manifest, 3, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 0, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(
            &manifest,
            1,
            Value::Integer(99_u64.into()),
        )?)
        .is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 1, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 2, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(
            &manifest,
            3,
            Value::Integer(99_u64.into()),
        )?)
        .is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 3, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 4, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 5, Value::Null)?).is_err());

        for field in [1, 2] {
            assert!(decode_manifest(&replace_array_field(&manifest, field, Value::Null)?).is_err());
        }

        let mut member_fields = vec![
            Value::Text("member".to_owned()),
            Value::Bytes(vec![1]),
            Value::Integer(0_u64.into()),
        ];
        member_fields[0] = Value::Null;
        assert!(decode_member(&Value::Array(member_fields.clone())).is_err());
        member_fields[0] = Value::Text("member".to_owned());
        member_fields[1] = Value::Null;
        assert!(decode_member(&Value::Array(member_fields.clone())).is_err());
        member_fields[1] = Value::Bytes(vec![1]);
        member_fields[2] = Value::Integer(99_u64.into());
        assert!(decode_member(&Value::Array(member_fields)).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod instrumented_public_entrypoints {
    use super::tests;
    use super::*;
    use ed25519_dalek::Signer;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signed_draft_bundle() -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let (members, expected_results) = tests::bundle_inputs(&profile, BundleModeV1::Local)?;
        let bundle = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        Ok(bundle.sign(&signing_key)?)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn valid_draft_bundle_reaches_public_validation() -> Result<(), Box<dyn std::error::Error>> {
        assert!(signed_draft_bundle()?.validate().is_ok());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_members_are_required_and_profile_bound() -> Result<(), Box<dyn std::error::Error>>
    {
        let profile = tests::profile();
        let (members, expected_results) = tests::bundle_inputs(&profile, BundleModeV1::Local)?;
        assert!(ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members.clone(),
            expected_results.clone(),
        )
        .is_ok());

        let mut missing_inventory = members.clone();
        missing_inventory.retain(|member| member.role != BundleMemberRoleV1::AuthorityInventory);
        assert_eq!(
            ConformanceBundleV1::materialize(
                &profile,
                BundleModeV1::Local,
                missing_inventory,
                expected_results.clone(),
            ),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut unbound_inventory = members;
        let provenance = unbound_inventory
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or(BundleContractErrorV1::MemberMissing)?;
        provenance.bytes = b"{}".to_vec();
        provenance.digest = *blake3::hash(&provenance.bytes).as_bytes();
        assert_eq!(
            ConformanceBundleV1::materialize(
                &profile,
                BundleModeV1::Local,
                unbound_inventory,
                expected_results,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_bundle_contract_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let (members, expected_results) = tests::bundle_inputs(&profile, BundleModeV1::Local)?;
        let unsigned = ConformanceBundleV1::materialize(
            &profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let bundle = unsigned.sign(&signing_key)?;
        assert!(bundle.validate().is_ok());
        let archive = bundle.to_canonical_cbor()?;
        assert_eq!(ConformanceBundleV1::from_canonical_cbor(&archive)?, bundle);
        assert_eq!(verify_archive_independently(&archive), Ok(()));
        assert!(bundle.bundle_digest()?.iter().any(|byte| *byte != 0));

        let mut invalid_magic = bundle.clone();
        invalid_magic.manifest.magic = "invalid".to_owned();
        assert_eq!(
            invalid_magic.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_profile = bundle.clone();
        invalid_profile.manifest.profile_digest = [0; 32];
        assert_eq!(
            invalid_profile.validate(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );

        let mut invalid_member = bundle.clone();
        invalid_member.members[0].bytes.push(0);
        assert_eq!(
            invalid_member.validate(),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_expected = bundle;
        invalid_expected.manifest.expected_results[0].digest = [0; 32];
        assert_eq!(
            invalid_expected.validate(),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );

        let mut trailing = archive;
        trailing.push(0);
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&trailing),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            verify_archive_independently(&trailing),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut air_gapped_profile = profile;
        air_gapped_profile.profile_digest = air_gapped_profile.digest();
        let (air_gapped_members, air_gapped_expected) =
            tests::bundle_inputs(&air_gapped_profile, BundleModeV1::AirGapped)?;
        let air_gapped = ConformanceBundleV1::materialize(
            &air_gapped_profile,
            BundleModeV1::AirGapped,
            air_gapped_members,
            air_gapped_expected,
        )?
        .sign(&signing_key)?;
        assert_eq!(
            verify_archive_independently(&air_gapped.to_canonical_cbor()?),
            Ok(())
        );

        Ok(())
    }

    fn public_archive_decode_boundaries(archive: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        for malformed in [
            vec![0x01, 0],
            vec![0xa0],
            vec![0xc0],
            vec![0xfa, 0, 0, 0, 0],
        ] {
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&malformed),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
            assert_eq!(
                verify_archive_independently(&malformed),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }

        let mut encoded_value: ciborium::value::Value =
            ciborium::from_reader(std::io::Cursor::new(&archive))?;
        let ciborium::value::Value::Array(fields) = &mut encoded_value else {
            return Err("encoded bundle is not an array".into());
        };
        let ciborium::value::Value::Array(members) = &mut fields[3] else {
            return Err("encoded members are not an array".into());
        };
        let ciborium::value::Value::Array(member) = &mut members[0] else {
            return Err("encoded member is not an array".into());
        };
        member[2] = ciborium::value::Value::Integer(14_u64.into());
        let mut invalid_member_role = Vec::new();
        ciborium::into_writer(&encoded_value, &mut invalid_member_role)?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&invalid_member_role),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        public_archive_rejects_unknown_member_role(archive)?;

        let mut invalid_magic: ciborium::value::Value =
            ciborium::from_reader(std::io::Cursor::new(archive))?;
        let ciborium::value::Value::Array(fields) = &mut invalid_magic else {
            return Err("encoded bundle is not an array".into());
        };
        fields[0] = ciborium::value::Value::Null;
        let mut invalid_magic_bytes = Vec::new();
        ciborium::into_writer(&invalid_magic, &mut invalid_magic_bytes)?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&invalid_magic_bytes),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut nested = vec![0x81; 34];
        nested.push(0xf6);
        assert!(verify_archive_independently(&nested).is_err());

        let raw_archive = |first: &[u8], members: &[u8]| {
            let mut bytes = vec![0x86];
            bytes.extend_from_slice(first);
            bytes.extend_from_slice(&[0x01, 0x80]);
            bytes.extend_from_slice(members);
            bytes.extend_from_slice(&[0x58, 0x20]);
            bytes.extend_from_slice(&[0; 32]);
            bytes.extend_from_slice(&[0x58, 0x40]);
            bytes.extend_from_slice(&[0; 64]);
            bytes
        };
        for members in [
            vec![0x81, 0x83, 0x60, 0x40, 0x00],
            vec![0x81, 0x83, 0x60, 0x41],
            vec![0x81, 0x83, 0x79, 0x01, 0x01],
            vec![0x81, 0x82, 0x60, 0x40],
        ] {
            assert!(verify_archive_independently(&raw_archive(&[0x60], &members)).is_err());
        }
        let mut exact_members = vec![0x9a, 0, 1, 0, 0];
        for _ in 0..65_536 {
            exact_members.extend_from_slice(&[0x83, 0x60, 0x40, 0x00]);
        }
        assert!(verify_archive_independently(&raw_archive(&[0x60], &exact_members)).is_err());

        public_archive_rejects_malformed_member_container();
        public_archive_rejects_missing_profile(archive)?;
        Ok(())
    }

    fn public_archive_rejects_malformed_member_container() {
        let mut malformed = vec![0x86, 0x60, 0x01, 0x80, 0x81, 0x00, 0x58, 0x20];
        malformed.extend_from_slice(&[0; 32]);
        malformed.extend_from_slice(&[0x58, 0x40]);
        malformed.extend_from_slice(&[0; 64]);
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&malformed),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            verify_archive_independently(&malformed),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
    }

    fn public_archive_rejects_missing_profile(
        archive: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut missing_profile: ciborium::value::Value =
            ciborium::from_reader(std::io::Cursor::new(archive))?;
        let ciborium::value::Value::Array(fields) = &mut missing_profile else {
            return Err("encoded bundle is not an array".into());
        };
        let ciborium::value::Value::Array(members) = &mut fields[3] else {
            return Err("encoded members are not an array".into());
        };
        members.retain(|member| {
            !matches!(
                member,
                ciborium::value::Value::Array(member_fields)
                    if member_fields.first()
                        == Some(&ciborium::value::Value::Text(PROFILE_MEMBER_PATH.to_owned()))
            )
        });
        let ciborium::value::Value::Array(manifest) = &mut fields[2] else {
            return Err("encoded manifest is not an array".into());
        };
        let ciborium::value::Value::Array(descriptors) = &mut manifest[4] else {
            return Err("encoded descriptors are not an array".into());
        };
        descriptors.retain(|descriptor| {
            !matches!(
                descriptor,
                ciborium::value::Value::Array(descriptor_fields)
                    if descriptor_fields.first()
                        == Some(&ciborium::value::Value::Text(PROFILE_MEMBER_PATH.to_owned()))
            )
        });
        let missing_profile = encode_archive_value(&missing_profile)?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&missing_profile),
            Err(BundleContractErrorV1::MemberMissing)
        );
        Ok(())
    }

    fn public_archive_rejects_unknown_member_role(
        archive: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut value: ciborium::value::Value =
            ciborium::from_reader(std::io::Cursor::new(archive))?;
        let ciborium::value::Value::Array(fields) = &mut value else {
            return Err("encoded bundle is not an array".into());
        };
        {
            let ciborium::value::Value::Array(members) = &mut fields[3] else {
                return Err("encoded members are not an array".into());
            };
            let ciborium::value::Value::Array(member) = &mut members[0] else {
                return Err("encoded member is not an array".into());
            };
            member[2] = ciborium::value::Value::Integer(14_u64.into());
            let ciborium::value::Value::Array(manifest) = &mut fields[2] else {
                return Err("encoded manifest is not an array".into());
            };
            let ciborium::value::Value::Array(descriptors) = &mut manifest[4] else {
                return Err("encoded descriptors are not an array".into());
            };
            let ciborium::value::Value::Array(descriptor) = &mut descriptors[0] else {
                return Err("encoded descriptor is not an array".into());
            };
            descriptor[3] = ciborium::value::Value::Integer(14_u64.into());
        }
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let mut manifest_bytes = Vec::new();
        ciborium::into_writer(&fields[2], &mut manifest_bytes)?;
        fields[4] = ciborium::value::Value::Bytes(signing_key.verifying_key().to_bytes().to_vec());
        fields[5] =
            ciborium::value::Value::Bytes(signing_key.sign(&manifest_bytes).to_bytes().to_vec());
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded)?;
        assert_eq!(
            verify_archive_independently(&encoded),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        Ok(())
    }

    fn public_archive_malformed_shapes_are_rejected() {
        for malformed in [
            &[0x00][..],
            &[0x84, 0x00, 0x00, 0x00, 0x00][..],
            &[0x84, 0x00, 0x00, 0x81, 0x00][..],
        ] {
            assert_eq!(
                verify_archive_independently(malformed),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
            assert!(public_archive_decode_boundaries(malformed).is_err());
        }

        for malformed in [
            &[0x00][..],
            &[0x84, 0x00, 0x00, 0x00, 0x00][..],
            &[0x84, 0x00, 0x00, 0x81, 0x00][..],
            &[0x84, 0x00, 0x00, 0x00, 0x81, 0x83, 0x60, 0x40, 0x00][..],
            &[
                0x84, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x83, 0x60, 0x40, 0x00,
            ][..],
            &[
                0x84, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x81, 0x83, 0x60, 0x40,
                0x00,
            ][..],
        ] {
            assert_eq!(
                verify_archive_independently(malformed),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
            assert!(public_archive_rejects_unknown_member_role(malformed).is_err());
        }
    }

    #[test]
    fn public_archive_helpers_reject_a_non_array_member_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let malformed = ciborium::value::Value::Array(vec![
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Null,
            ciborium::value::Value::Array(vec![ciborium::value::Value::Null]),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&malformed, &mut encoded)?;

        assert!(public_archive_decode_boundaries(&encoded).is_err());
        assert!(public_archive_rejects_unknown_member_role(&encoded).is_err());
        Ok(())
    }

    fn public_archive_validation_boundaries(bundle: &ConformanceBundleV1) {
        let mut invalid_unsigned = bundle.clone();
        invalid_unsigned.manifest.lifecycle = ProfileLifecycleV1::Stable;
        assert_eq!(
            invalid_unsigned.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );
        let mut invalid_signature = bundle.clone();
        invalid_signature.signature = Signature::from_bytes([0; 64]);
        assert_eq!(
            invalid_signature.validate(),
            Err(BundleContractErrorV1::SignatureInvalid)
        );
        let mut missing_profile = bundle.clone();
        missing_profile
            .members
            .retain(|member| member.role != BundleMemberRoleV1::Profile);
        assert_eq!(
            missing_profile.validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );
    }

    fn public_archive_cap_boundaries(
        profile: &super::ConformanceProfileV1,
        bundle: &ConformanceBundleV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let max_member_path_bytes = bundle
            .members
            .iter()
            .filter(|member| member.role != BundleMemberRoleV1::Profile)
            .map(|member| member.path.len())
            .max()
            .ok_or("bundle has no non-profile members")?;
        let max_member_bytes = bundle
            .members
            .iter()
            .filter(|member| member.role != BundleMemberRoleV1::Profile)
            .map(|member| member.bytes.len())
            .max()
            .ok_or("bundle has no non-profile members")?;
        let non_profile_member_bytes = bundle
            .members
            .iter()
            .filter(|member| member.role != BundleMemberRoleV1::Profile)
            .map(|member| u64::try_from(member.bytes.len()).unwrap_or(u64::MAX))
            .sum::<u64>();
        let mut limited_profiles = [profile.clone(), profile.clone(), profile.clone()];
        limited_profiles[0]
            .evaluator_protocol
            .hard_caps
            .max_member_path_bytes = u16::try_from(max_member_path_bytes.saturating_sub(1))?;
        limited_profiles[1]
            .evaluator_protocol
            .hard_caps
            .max_member_bytes = u64::try_from(max_member_bytes.saturating_sub(1))?;
        limited_profiles[2]
            .evaluator_protocol
            .hard_caps
            .max_total_bundle_bytes = non_profile_member_bytes;
        for mut limited_profile in limited_profiles {
            limited_profile.profile_digest = limited_profile.digest();
            let (limited_members, limited_expected) =
                tests::bundle_inputs(&limited_profile, BundleModeV1::Local)?;
            assert_eq!(
                ConformanceBundleV1::materialize(
                    &limited_profile,
                    BundleModeV1::Local,
                    limited_members,
                    limited_expected,
                ),
                Err(BundleContractErrorV1::MemberOutOfBounds)
            );
        }
        Ok(())
    }

    fn exercise_public_archive_boundaries(
        profile: &super::ConformanceProfileV1,
        members: Vec<super::BundleMemberV1>,
        expected_results: Vec<super::BundleExpectedResultV1>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let bundle = ConformanceBundleV1::materialize(
            profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?
        .sign(&signing_key)?;
        let archive = bundle.to_canonical_cbor()?;
        assert_eq!(ConformanceBundleV1::from_canonical_cbor(&archive)?, bundle);
        assert_eq!(verify_archive_independently(&archive), Ok(()));
        public_archive_decode_boundaries(&archive)?;
        public_archive_malformed_shapes_are_rejected();
        public_archive_validation_boundaries(&bundle);
        public_archive_cap_boundaries(profile, &bundle)
    }

    #[test]
    fn public_archive_boundaries_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let (members, expected_results) = tests::bundle_inputs(&profile, BundleModeV1::Local)?;
        let mut invalid_profile = profile.clone();
        invalid_profile.lifecycle = ProfileLifecycleV1::Stable;
        assert!(exercise_public_archive_boundaries(
            &invalid_profile,
            members.clone(),
            expected_results.clone(),
        )
        .is_err());
        assert!(exercise_public_archive_boundaries(&profile, members, expected_results).is_ok());
        Ok(())
    }

    fn profile_value(profile: &ConformanceProfileV1) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(ciborium::from_reader(Cursor::new(
            profile.to_canonical_cbor()?,
        ))?)
    }

    fn independent_records(
        value: &Value,
    ) -> Result<Vec<IndependentMember<'_>>, BundleContractErrorV1> {
        let fields = independent_array(value, 6)?;
        let manifest = independent_array(&fields[2], 6)?;
        let members = independent_array_bounded(&fields[3])?;
        let descriptors = independent_array_bounded(&manifest[4])?;
        independent_member_records(members, descriptors).map(|(records, _)| records)
    }

    fn raw_independent_member<'a>(
        path: &'a str,
        bytes: &'a [u8],
        role: BundleMemberRoleV1,
    ) -> IndependentMember<'a> {
        IndependentMember {
            path,
            bytes,
            digest: *blake3::hash(bytes).as_bytes(),
            role,
        }
    }

    fn raw_authority_members<'a>(
        inventory: &'a [u8],
        matrix: &'a [u8],
        provenance: &'a [u8],
    ) -> Vec<IndependentMember<'a>> {
        vec![
            raw_independent_member(
                AUTHORITY_INVENTORY_MEMBER_PATH,
                inventory,
                BundleMemberRoleV1::AuthorityInventory,
            ),
            raw_independent_member(
                EXECUTION_MATRIX_MEMBER_PATH,
                matrix,
                BundleMemberRoleV1::ExecutionMatrix,
            ),
            raw_independent_member(
                "support/provenance.json",
                provenance,
                BundleMemberRoleV1::Provenance,
            ),
        ]
    }

    #[test]
    fn remaining_archive_and_independent_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_draft_bundle()?;
        let archive = bundle.to_canonical_cbor()?;

        let mut noncanonical = archive.clone();
        assert_eq!(noncanonical[6], 1);
        noncanonical.remove(6);
        noncanonical.splice(6..6, [0x18, 0x01]);
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&noncanonical),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut wide_integer = archive;
        wide_integer.remove(6);
        wide_integer.splice(6..6, [0x1b, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(archive_preflight::scan(&wide_integer).is_ok());

        let mut duplicate_profile = bundle_value(&bundle);
        let Value::Array(fields) = &mut duplicate_profile else {
            return Err("bundle must be an array".into());
        };
        let Value::Array(members) = &mut fields[3] else {
            return Err("members must be an array".into());
        };
        let profile_member = members
            .iter()
            .find(|member| {
                matches!(
                    member,
                    Value::Array(fields)
                        if fields.first() == Some(&Value::Text(PROFILE_MEMBER_PATH.to_owned()))
                )
            })
            .cloned()
            .ok_or("missing profile member")?;
        members.push(profile_member);
        assert!(matches!(
            archive_preflight::scan(&encode_archive_value(&duplicate_profile)?),
            Err(BundleContractErrorV1::MemberMissing)
        ));

        let nested = (0..34).fold(Value::Null, |value, _| Value::Array(vec![value]));
        let mut deeply_nested = bundle_value(&bundle);
        if let Value::Array(fields) = &mut deeply_nested {
            fields[1] = nested;
        }
        assert!(matches!(
            archive_preflight::scan(&encode_archive_value(&deeply_nested)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        ));

        let huge_member = vec![
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0xf6, 0x81, 0x83, 0x61, b'x', 0x5a, 0x04,
            0x00, 0x00, 0x01,
        ];
        assert!(matches!(
            archive_preflight::scan(&huge_member),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        ));

        let huge_array = vec![
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0x9a, 0x00, 0x01, 0x00, 0x01,
        ];
        assert!(matches!(
            archive_preflight::scan(&huge_array),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        ));

        let invalid_simple = vec![0x86, 0xf7];
        assert!(matches!(
            archive_preflight::scan(&invalid_simple),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        ));

        let mut unlisted_expected_result = signed_draft_bundle()?;
        let expected_member = unlisted_expected_result
            .members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::ExpectedResult)
            .ok_or("missing expected-result member")?;
        expected_member.path = "expected/unlisted.bin".to_owned();
        assert!(bundle_pair_payloads(&unlisted_expected_result)
            .iter()
            .any(|(identity, _, _)| identity == "expected/unlisted.bin"));

        Ok(())
    }

    #[test]
    fn independent_member_order_error_region_is_exercised() {
        let member = Value::Array(vec![
            Value::Text("b".to_owned()),
            Value::Bytes(vec![1]),
            Value::Integer(0_u64.into()),
        ]);
        let descriptor = Value::Array(vec![
            Value::Text("b".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Bytes(blake3::hash([1].as_slice()).as_bytes().to_vec()),
            Value::Integer(0_u64.into()),
        ]);
        let earlier_member = Value::Array(vec![
            Value::Text("a".to_owned()),
            Value::Bytes(vec![2]),
            Value::Integer(0_u64.into()),
        ]);
        let earlier_descriptor = Value::Array(vec![
            Value::Text("a".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Bytes(blake3::hash([2].as_slice()).as_bytes().to_vec()),
            Value::Integer(0_u64.into()),
        ]);
        assert!(matches!(
            independent_member_records(
                &[member, earlier_member],
                &[descriptor, earlier_descriptor]
            ),
            Err(BundleContractErrorV1::NonCanonicalOrder)
        ));
    }

    #[test]
    fn independent_expected_result_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let bundle = signed_draft_bundle()?;
        let profile_value = profile_value(&profile)?;
        let value = bundle_value(&bundle);
        let records = independent_records(&value)?;
        let fields = independent_array(&value, 6)?;
        let manifest = independent_array(&fields[2], 6)?;
        let expected_results = independent_array_bounded(&manifest[5])?;
        assert_eq!(
            independent_verify_expected_results(
                expected_results,
                &records,
                &profile_value,
                BundleModeV1::Local.code(),
            ),
            Ok(())
        );

        let mut malformed_fixture_profile = profile_value.clone();
        if let Value::Array(fields) = &mut malformed_fixture_profile {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            fixtures[0] = Value::Null;
        }
        assert!(independent_verify_expected_results(
            &[expected_results[1].clone()],
            &records,
            &malformed_fixture_profile,
            BundleModeV1::Local.code(),
        )
        .is_err());

        let mut non_boolean_mandatory = profile_value.clone();
        if let Value::Array(fields) = &mut non_boolean_mandatory {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            let Value::Array(fixture) = &mut fixtures[0] else {
                return Err("fixture must be an array".into());
            };
            fixture[1] = Value::Null;
        }
        assert_eq!(
            independent_verify_expected_results(
                &[],
                &[],
                &non_boolean_mandatory,
                BundleModeV1::Local.code(),
            ),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
        assert_eq!(
            independent_verify_expected_results(
                &[],
                &[],
                &profile_value,
                BundleModeV1::Local.code(),
            ),
            Err(BundleContractErrorV1::MemberMissing)
        );

        Ok(())
    }

    #[test]
    fn independent_expected_result_encoding_error_regions_are_exercised() {
        let canonical_result = Value::Array(vec![
            Value::Integer(0_u64.into()),
            Value::Bytes(vec![1]),
            Value::Bytes(vec![0; 32]),
            Value::Null,
            Value::Null,
        ]);
        assert_eq!(
            independent_expected_result_bytes(&canonical_result),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
        for code in [1_u64, 2_u64] {
            let typed_result = Value::Array(vec![
                Value::Integer(code.into()),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ]);
            assert!(independent_expected_result_bytes(&typed_result).is_ok());
        }
        let unknown_result = Value::Array(vec![
            Value::Integer(3_u64.into()),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ]);
        assert_eq!(
            independent_expected_result_bytes(&unknown_result),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
    }

    #[test]
    fn independent_fixture_and_support_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let bundle = signed_draft_bundle()?;
        let profile_value = profile_value(&profile)?;
        let value = bundle_value(&bundle);
        let records = independent_records(&value)?;
        let mut duplicate_input_profile = profile_value.clone();
        if let Value::Array(fields) = &mut duplicate_input_profile {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            let Value::Array(fixture) = &mut fixtures[0] else {
                return Err("fixture must be an array".into());
            };
            let Value::Array(inputs) = &mut fixture[7] else {
                return Err("inputs must be an array".into());
            };
            inputs.push(inputs[0].clone());
        }
        assert_eq!(
            independent_verify_fixture_inputs(&records, &duplicate_input_profile, 0),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let input_index = records
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::FixtureInput)
            .ok_or("missing input record")?;
        let mut wrong_input_role = independent_records(&value)?;
        wrong_input_role[input_index].role = BundleMemberRoleV1::ExpectedResult;
        assert_eq!(
            independent_verify_fixture_inputs(&wrong_input_role, &profile_value, 0),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut no_declared_inputs = profile_value;
        if let Value::Array(fields) = &mut no_declared_inputs {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            for fixture in fixtures {
                let Value::Array(fixture) = fixture else {
                    return Err("fixture must be an array".into());
                };
                fixture[7] = Value::Array(Vec::new());
            }
        }
        assert_eq!(
            independent_verify_fixture_inputs(&records, &no_declared_inputs, 0),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        Ok(())
    }

    #[test]
    fn independent_support_error_regions_are_exercised() -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let bundle = signed_draft_bundle()?;
        let profile_value = profile_value(&profile)?;
        for (role, fixture_replacement) in [
            (BundleMemberRoleV1::Schema, Value::Null),
            (BundleMemberRoleV1::Notice, Value::Null),
            (BundleMemberRoleV1::Sbom, Value::Null),
        ] {
            let mut malformed_support_profile = profile_value.clone();
            if let Value::Array(fields) = &mut malformed_support_profile {
                let Value::Array(fixtures) = &mut fields[8] else {
                    return Err("fixtures must be an array".into());
                };
                let Value::Array(fixture) = &mut fixtures[0] else {
                    return Err("fixture must be an array".into());
                };
                if role == BundleMemberRoleV1::Schema {
                    fixtures[0] = fixture_replacement;
                } else {
                    fixture[15] = fixture_replacement;
                }
            }
            let fields = independent_array(&malformed_support_profile, 17)?;
            let fixtures = independent_array_bounded(&fields[8])?;
            assert!(independent_support_digests(fields, fixtures, role).is_err());
        }
        let mut malformed_provenance = profile_value.clone();
        if let Value::Array(fields) = &mut malformed_provenance {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            let Value::Array(fixture) = &mut fixtures[0] else {
                return Err("fixture must be an array".into());
            };
            fixture[15] = Value::Array(vec![Value::Null; 7]);
        }
        let fields = independent_array(&malformed_provenance, 17)?;
        let fixtures = independent_array_bounded(&fields[8])?;
        assert!(
            independent_support_digests(fields, fixtures, BundleMemberRoleV1::Provenance).is_err()
        );
        let profile_fields = independent_array(&profile_value, 17)?;
        let profile_fixtures = independent_array_bounded(&profile_fields[8])?;
        assert!(independent_support_digests(
            profile_fields,
            profile_fixtures,
            BundleMemberRoleV1::FixtureInput
        )
        .is_ok());

        let profile_fields = independent_array(&profile_value, 17)?;
        let profile_fixtures = independent_array_bounded(&profile_fields[8])?;
        assert!(!independent_support_digests(
            profile_fields,
            profile_fixtures,
            BundleMemberRoleV1::Licence
        )?
        .is_empty());

        let mut malformed_limitations = profile_value.clone();
        if let Value::Array(fields) = &mut malformed_limitations {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            let Value::Array(fixture) = &mut fixtures[0] else {
                return Err("fixture must be an array".into());
            };
            let Value::Array(provenance) = &mut fixture[15] else {
                return Err("provenance must be an array".into());
            };
            provenance[6] = Value::Null;
        }
        let fields = independent_array(&malformed_limitations, 17)?;
        let fixtures = independent_array_bounded(&fields[8])?;
        assert!(
            independent_support_digests(fields, fixtures, BundleMemberRoleV1::Limitations).is_err()
        );

        let bundle_value = bundle_value(&bundle);
        let mut bad_support_records = independent_records(&bundle_value)?;
        let schema = bad_support_records
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Schema)
            .ok_or("missing schema member")?;
        schema.digest = [0; 32];
        assert_eq!(
            independent_verify_supporting_members(&bad_support_records, &profile_value),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        Ok(())
    }

    #[test]
    fn independent_authority_error_regions_are_exercised() -> Result<(), Box<dyn std::error::Error>>
    {
        let profile = tests::profile();
        let bundle = signed_draft_bundle()?;
        let profile_value = profile_value(&profile)?;
        let value = bundle_value(&bundle);
        for role in [
            BundleMemberRoleV1::AuthorityInventory,
            BundleMemberRoleV1::ExecutionMatrix,
            BundleMemberRoleV1::Provenance,
        ] {
            let mut missing = independent_records(&value)?;
            missing.retain(|member| member.role != role);
            assert_eq!(
                independent_verify_authority_members(&missing, &profile_value),
                Err(BundleContractErrorV1::MemberMissing)
            );
        }
        let duplicate_authority = vec![
            raw_independent_member(
                AUTHORITY_INVENTORY_MEMBER_PATH,
                b"{}",
                BundleMemberRoleV1::AuthorityInventory,
            ),
            raw_independent_member(
                AUTHORITY_INVENTORY_MEMBER_PATH,
                b"{}",
                BundleMemberRoleV1::AuthorityInventory,
            ),
        ];
        assert!(matches!(
            independent_unique_member(
                &duplicate_authority,
                BundleMemberRoleV1::AuthorityInventory,
                AUTHORITY_INVENTORY_MEMBER_PATH,
            ),
            Err(BundleContractErrorV1::MemberMissing)
        ));

        Ok(())
    }

    #[test]
    fn independent_authority_json_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let profile_value = profile_value(&profile)?;
        let mut no_matrix_binding = profile_value;
        if let Value::Array(fields) = &mut no_matrix_binding {
            fields[2] = Value::Text("pigloros.w8.artifact-integrity.1.0.0".to_owned());
        }
        let bad_metadata_inventory =
            br#"{"lifecycle":"Draft","magic":"BAD","version":1,"digest_algorithm":"BLAKE3-256"}"#;
        let valid_metadata_matrix = br#"{"lifecycle":"Draft","magic":"NIM1","version":1}"#;
        let provenance = b"{}";
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(bad_metadata_inventory, valid_metadata_matrix, provenance,),
                &no_matrix_binding,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let wrong_entries = serde_json::json!({
            "lifecycle": "Draft",
            "magic": "W8H1",
            "version": 1,
            "digest_algorithm": "BLAKE3-256",
            "entries": [{"fixture_id": "wrong"}]
        });
        let wrong_entries_bytes = serde_json::to_vec(&wrong_entries)?;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&wrong_entries_bytes, valid_metadata_matrix, provenance,),
                &no_matrix_binding,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let pending_entries = AUTHORITY_FIXTURE_IDS
            .iter()
            .map(|fixture_id| {
                serde_json::json!({
                    "fixture_id": fixture_id,
                    "materialization_status": "pending",
                    "fixture_bytes_path": null,
                    "fixture_bytes_digest": null,
                    "expected_result_path": null,
                    "expected_result_digest": null
                })
            })
            .collect::<Vec<_>>();
        let mut pending_inventory = serde_json::json!({
            "lifecycle": "Draft",
            "magic": "W8H1",
            "version": 1,
            "digest_algorithm": "BLAKE3-256",
            "entries": pending_entries
        });
        pending_inventory["entries"][0]["materialization_status"] =
            JsonValue::String("materialized".to_owned());
        let pending_inventory_bytes = serde_json::to_vec(&pending_inventory)?;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&pending_inventory_bytes, valid_metadata_matrix, provenance,),
                &no_matrix_binding,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        assert_eq!(
            independent_matrix_digest("pigloros.w8.knowledge-non-interference.1.0.0"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(
            independent_matrix_digest("pigloros.w8.knowledge-non-interference.1.0.0#matrix=bad"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(
            independent_matrix_digest(&format!(
                "pigloros.w8.knowledge-non-interference.1.0.0#matrix={}",
                "0".repeat(64)
            )),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        Ok(())
    }

    #[test]
    fn independent_authority_metadata_and_entry_shapes_are_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = tests::profile();
        profile.profile_id = "pigloros.w8.artifact-integrity.1.0.0".to_owned();
        profile.profile_digest = profile.digest();
        let profile_value = profile_value(&profile)?;
        let valid_matrix = br#"{"lifecycle":"Draft","magic":"NIM1","version":1}"#;
        let entries = AUTHORITY_FIXTURE_IDS
            .iter()
            .map(|fixture_id| {
                serde_json::json!({
                    "fixture_id": fixture_id,
                    "materialization_status": "pending",
                    "fixture_bytes_path": null,
                    "fixture_bytes_digest": null,
                    "expected_result_path": null,
                    "expected_result_digest": null
                })
            })
            .collect::<Vec<_>>();
        let valid_inventory = serde_json::json!({
            "lifecycle": "Draft",
            "magic": "W8H1",
            "version": 1,
            "digest_algorithm": "BLAKE3-256",
            "entries": entries
        });
        let valid_inventory_bytes = serde_json::to_vec(&valid_inventory)?;
        let wrong_matrix_version = br#"{"lifecycle":"Draft","magic":"NIM1","version":2}"#;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&valid_inventory_bytes, wrong_matrix_version, b"{}"),
                &profile_value,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let stable_matrix = br#"{"lifecycle":"Stable","magic":"NIM1","version":1}"#;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&valid_inventory_bytes, stable_matrix, b"{}"),
                &profile_value,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut no_entries = valid_inventory.clone();
        no_entries["entries"] = JsonValue::Null;
        let no_entries_bytes = serde_json::to_vec(&no_entries)?;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&no_entries_bytes, valid_matrix, b"{}"),
                &profile_value,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut wrong_fixture_id = valid_inventory.clone();
        wrong_fixture_id["entries"][0]["fixture_id"] = JsonValue::String("wrong".to_owned());
        let wrong_fixture_id_bytes = serde_json::to_vec(&wrong_fixture_id)?;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&wrong_fixture_id_bytes, valid_matrix, b"{}"),
                &profile_value,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        for field in [
            "materialization_status",
            "fixture_bytes_path",
            "fixture_bytes_digest",
            "expected_result_path",
            "expected_result_digest",
        ] {
            let mut invalid_entries = valid_inventory["entries"].clone();
            match field {
                "materialization_status" => {
                    invalid_entries[0][field] = JsonValue::String("materialized".to_owned());
                }
                _ => invalid_entries[0][field] = JsonValue::String("present".to_owned()),
            }
            let mut invalid_inventory = valid_inventory.clone();
            invalid_inventory["entries"] = invalid_entries;
            let invalid_inventory_bytes = serde_json::to_vec(&invalid_inventory)?;
            assert_eq!(
                independent_verify_authority_members(
                    &raw_authority_members(&invalid_inventory_bytes, valid_matrix, b"{}"),
                    &profile_value,
                ),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn direct_authority_and_matrix_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let bundle = signed_draft_bundle()?;
        let mut artifact_profile = tests::profile();
        artifact_profile.profile_id = "pigloros.w8.artifact-integrity.1.0.0".to_owned();
        artifact_profile.fixtures.retain(|fixture| {
            fixture.claim_layer == ClaimLayerV1::ArtifactIntegrity
                && fixture.modes == [ExecutionModeV1::Local]
        });
        artifact_profile.profile_digest = artifact_profile.digest();
        let (artifact_members, artifact_expected) =
            tests::bundle_inputs(&artifact_profile, BundleModeV1::Local)?;
        let artifact_bundle = ConformanceBundleV1::materialize(
            &artifact_profile,
            BundleModeV1::Local,
            artifact_members,
            artifact_expected,
        )?
        .sign(&ed25519_dalek::SigningKey::from_bytes(&[42; 32]))?;
        let mut stable_authority_members = artifact_bundle.members;
        let stable_matrix = br#"{"lifecycle":"Stable"}"#;
        let stable_matrix_digest = blake3::hash(stable_matrix).to_hex().to_string();
        let stable_provenance = serde_json::to_vec(&serde_json::json!({
            "authority_inventory": {
                "digest_algorithm": "SHA-256",
                "path": "expected-authority/inventory.json",
                "status": "Draft"
            },
            "adr_059_execution_matrix": {
                "digest_algorithm": "BLAKE3-256",
                "blake3_digest": stable_matrix_digest,
                "executed_case_count": 0,
                "path": "matrix/execution-matrix.json",
                "status": "Draft"
            }
        }))?;
        for member in &mut stable_authority_members {
            match member.role {
                BundleMemberRoleV1::AuthorityInventory | BundleMemberRoleV1::ExecutionMatrix => {
                    member.bytes = stable_matrix.to_vec();
                    member.digest = *blake3::hash(&member.bytes).as_bytes();
                }
                BundleMemberRoleV1::Provenance => {
                    member.bytes = stable_provenance.clone();
                    member.digest = artifact_profile.provenance_digest;
                }
                _ => {}
            }
        }
        assert_eq!(
            validate_authority_members(&artifact_profile, &stable_authority_members),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut missing_matrix = bundle.members;
        missing_matrix.retain(|member| member.role != BundleMemberRoleV1::ExecutionMatrix);
        assert_eq!(
            validate_authority_members(&profile, &missing_matrix),
            Err(BundleContractErrorV1::MemberMissing)
        );
        assert_eq!(
            validate_provenance_authority_binding(&serde_json::json!({
                "authority_inventory": {
                    "path": "wrong",
                    "digest_algorithm": "SHA-256",
                    "status": "Draft"
                },
                "adr_059_execution_matrix": {
                    "path": "matrix/execution-matrix.json",
                    "digest_algorithm": "BLAKE3-256",
                    "status": "Draft",
                    "executed_case_count": 0
                }
            })),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(
            validate_matrix_provenance_digest(
                &serde_json::json!({
                    "adr_059_execution_matrix": {"blake3_digest": "00".repeat(32)}
                }),
                b"matrix",
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        Ok(())
    }

    #[test]
    fn matrix_and_secret_error_regions_are_exercised() -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let matrix_bytes =
            include_bytes!("../../../fixtures/conformance/matrix/execution-matrix.json");
        let matrix: JsonValue = serde_json::from_slice(matrix_bytes)?;
        let mut invalid_matrix = matrix.clone();
        if let JsonValue::Object(fields) = &mut invalid_matrix {
            fields.insert("magic".to_owned(), JsonValue::String("NIM0".to_owned()));
        }
        assert_eq!(
            validate_execution_matrix(&invalid_matrix),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_predicates = matrix;
        if let JsonValue::Object(fields) = &mut invalid_predicates {
            let JsonValue::Array(predicates) = fields
                .get_mut("equality_predicates")
                .ok_or("missing equality predicates")?
            else {
                return Err("equality predicates must be an array".into());
            };
            let JsonValue::Object(predicate) =
                predicates.first_mut().ok_or("missing equality predicate")?
            else {
                return Err("equality predicate must be an object".into());
            };
            predicate.insert("AuthEq".to_owned(), JsonValue::String("wrong".to_owned()));
        }
        assert_eq!(
            validate_execution_matrix(&invalid_predicates),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        assert_eq!(
            required_support_digests(&profile, BundleMemberRoleV1::FixtureInput),
            BTreeSet::new()
        );
        assert!(contains_secret_marker(br#"{"password":1}"#));
        assert!(!contains_jwt(b"eyj"));
        assert!(!contains_jwt(b"eyjshort.x.y"));
        assert!(contains_jwt(b"eyjabcdefgh.klmnopqrst.uvwxyzabcd"));
        assert_eq!(token_length(b"abc!def", 0), 3);
        assert_eq!(token_length(b"abc", 9), 0);
        assert!(is_empty_sensitive_value(&JsonValue::Null));
        assert!(is_empty_sensitive_value(&JsonValue::String(String::new())));
        assert!(!is_empty_sensitive_value(&JsonValue::Bool(false)));
        assert_eq!(value_depth(&Value::Tag(1, Box::new(Value::Null))), 2);
        assert_eq!(
            value_depth(&Value::Map(vec![(
                Value::Text("key".to_owned()),
                Value::Array(vec![Value::Null]),
            )])),
            3
        );
        let support = BundleMemberV1::supporting(
            "support/schema.cddl",
            b"schema".to_vec(),
            BundleMemberRoleV1::Schema,
        );
        assert_eq!(support.role, BundleMemberRoleV1::Schema);
        let authority = BundleMemberV1::authority(
            AUTHORITY_INVENTORY_MEMBER_PATH,
            b"inventory".to_vec(),
            BundleMemberRoleV1::AuthorityInventory,
        );
        assert_eq!(authority.role, BundleMemberRoleV1::AuthorityInventory);
        assert_eq!(decode_lifecycle(1), Ok(ProfileLifecycleV1::Candidate));
        Ok(())
    }

    #[test]
    fn unsigned_validation_reaches_count_and_profile_guards(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut too_many_members = signed_draft_bundle()?;
        too_many_members.members =
            vec![BundleMemberV1::new("placeholder", Vec::new(), false); MAX_MEMBERS + 1];
        assert_eq!(
            too_many_members.validate_unsigned(),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );

        let mut invalid_profile = signed_draft_bundle()?;
        invalid_profile
            .members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Profile)
            .ok_or("missing profile member")?
            .bytes = b"not a profile".to_vec();
        assert_eq!(
            invalid_profile.validate_unsigned(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
        Ok(())
    }

    #[test]
    fn public_decoder_reaches_structural_field_guards() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_draft_bundle()?;
        let archive = bundle.to_canonical_cbor()?;
        let mut value: Value = ciborium::from_reader(Cursor::new(&archive))?;
        {
            let Value::Array(fields) = &mut value else {
                return Err("archive must be an array".into());
            };
            fields[0] = Value::Text("wrong".to_owned());
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&value)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        {
            let Value::Array(fields) = &mut value else {
                return Err("archive must be an array".into());
            };
            fields[0] = Value::Text(CONFORMANCE_BUNDLE_MAGIC_V1.to_owned());
            fields[1] = Value::Integer(2_u64.into());
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&value)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        {
            let Value::Array(fields) = &mut value else {
                return Err("archive must be an array".into());
            };
            fields[1] = Value::Integer(1_u64.into());
            fields[2] = Value::Null;
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&value)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        let mut invalid_profile: Value = ciborium::from_reader(Cursor::new(&archive))?;
        let Value::Array(invalid_fields) = &mut invalid_profile else {
            return Err("archive must be an array".into());
        };
        let Value::Array(members) = &mut invalid_fields[3] else {
            return Err("members must be an array".into());
        };
        let profile_member = members
            .iter_mut()
            .find(|member| {
                matches!(member, Value::Array(fields) if fields[0]
                    == Value::Text(PROFILE_MEMBER_PATH.to_owned()))
            })
            .ok_or("missing profile member")?;
        let Value::Array(profile_fields) = profile_member else {
            return Err("profile member must be an array".into());
        };
        profile_fields[1] = Value::Bytes(b"not a profile".to_vec());
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&invalid_profile)?),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
        Ok(())
    }

    fn exercise_independent_expected_result_regions(
        profile_value: &Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(independent_verify_expected_results(
            &[],
            &[],
            &Value::Null,
            BundleModeV1::Local.code(),
        )
        .is_err());
        let mut malformed_fixtures = profile_value.clone();
        if let Value::Array(fields) = &mut malformed_fixtures {
            fields[8] = Value::Array(vec![Value::Null]);
        }
        assert!(independent_verify_expected_results(
            &[],
            &[],
            &malformed_fixtures,
            BundleModeV1::Local.code(),
        )
        .is_err());
        let mut malformed_modes = profile_value.clone();
        if let Value::Array(fields) = &mut malformed_modes {
            let Value::Array(fixtures) = &mut fields[8] else {
                return Err("fixtures must be an array".into());
            };
            let Value::Array(fixture) = &mut fixtures[0] else {
                return Err("fixture must be an array".into());
            };
            fixture[5] = Value::Null;
        }
        assert!(independent_verify_expected_results(
            &[],
            &[],
            &malformed_modes,
            BundleModeV1::Local.code(),
        )
        .is_err());
        for field in [0, 2, 3] {
            let mut malformed_identity = profile_value.clone();
            if let Value::Array(fields) = &mut malformed_identity {
                let Value::Array(fixtures) = &mut fields[8] else {
                    return Err("fixtures must be an array".into());
                };
                let Value::Array(fixture) = &mut fixtures[0] else {
                    return Err("fixture must be an array".into());
                };
                fixture[field] = Value::Null;
            }
            assert!(independent_verify_expected_results(
                &[],
                &[],
                &malformed_identity,
                BundleModeV1::Local.code(),
            )
            .is_err());
        }
        for value in [
            Value::Null,
            Value::Array(vec![Value::Null]),
            Value::Array(vec![Value::Null; 5]),
        ] {
            assert!(independent_expected_result_bytes(&value).is_err());
        }
        for value in [
            Value::Array(vec![
                Value::Integer(0_u64.into()),
                Value::Null,
                Value::Bytes(vec![0; 32]),
                Value::Null,
                Value::Null,
            ]),
            Value::Array(vec![
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![1]),
                Value::Null,
                Value::Null,
                Value::Null,
            ]),
        ] {
            assert!(independent_expected_result_bytes(&value).is_err());
        }
        Ok(())
    }

    fn exercise_independent_fixture_input_regions(
        profile_value: &Value,
        records: &[IndependentMember<'_>],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for field in [0, 2, 3, 7] {
            let mut malformed_inputs = profile_value.clone();
            if let Value::Array(fields) = &mut malformed_inputs {
                let Value::Array(fixtures) = &mut fields[8] else {
                    return Err("fixtures must be an array".into());
                };
                let Value::Array(fixture) = &mut fixtures[0] else {
                    return Err("fixture must be an array".into());
                };
                fixture[field] = Value::Null;
            }
            assert!(independent_verify_fixture_inputs(
                records,
                &malformed_inputs,
                BundleModeV1::Local.code(),
            )
            .is_err());
        }
        for field in [0, 1, 2] {
            let mut malformed_input = profile_value.clone();
            if let Value::Array(fields) = &mut malformed_input {
                let Value::Array(fixtures) = &mut fields[8] else {
                    return Err("fixtures must be an array".into());
                };
                let Value::Array(fixture) = &mut fixtures[0] else {
                    return Err("fixture must be an array".into());
                };
                let Value::Array(inputs) = &mut fixture[7] else {
                    return Err("inputs must be an array".into());
                };
                let Value::Array(input) = &mut inputs[0] else {
                    return Err("input must be an array".into());
                };
                input[field] = Value::Null;
            }
            assert!(independent_verify_fixture_inputs(
                records,
                &malformed_input,
                BundleModeV1::Local.code(),
            )
            .is_err());
        }
        assert!(independent_verify_fixture_inputs(
            records,
            &Value::Null,
            BundleModeV1::Local.code(),
        )
        .is_err());
        let mut missing_fixture_array = profile_value.clone();
        if let Value::Array(fields) = &mut missing_fixture_array {
            fields[8] = Value::Null;
        }
        assert!(independent_verify_fixture_inputs(
            records,
            &missing_fixture_array,
            BundleModeV1::Local.code(),
        )
        .is_err());
        Ok(())
    }

    fn exercise_independent_support_regions(
        profile_value: &Value,
        records: &[IndependentMember<'_>],
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(independent_verify_supporting_members(&[], &Value::Null).is_err());
        let mut missing_support_fixtures = profile_value.clone();
        if let Value::Array(fields) = &mut missing_support_fixtures {
            fields[8] = Value::Null;
        }
        assert!(independent_verify_supporting_members(records, &missing_support_fixtures).is_err());
        for role in [
            BundleMemberRoleV1::NormativeSpecification,
            BundleMemberRoleV1::Schema,
            BundleMemberRoleV1::Licence,
            BundleMemberRoleV1::Notice,
            BundleMemberRoleV1::Sbom,
            BundleMemberRoleV1::Provenance,
            BundleMemberRoleV1::Limitations,
        ] {
            let fields = independent_array(profile_value, 17)?;
            let fixtures = independent_array_bounded(&fields[8])?;
            assert!(!independent_support_digests(fields, fixtures, role)?.is_empty());
        }
        let mut malformed_support_profile = profile_value.clone();
        if let Value::Array(fields) = &mut malformed_support_profile {
            fields[5] = Value::Null;
        }
        assert!(
            independent_verify_supporting_members(records, &malformed_support_profile).is_err()
        );
        for role in [
            BundleMemberRoleV1::Licence,
            BundleMemberRoleV1::Notice,
            BundleMemberRoleV1::Sbom,
            BundleMemberRoleV1::Provenance,
            BundleMemberRoleV1::Limitations,
        ] {
            let mut malformed_provenance = profile_value.clone();
            if let Value::Array(fields) = &mut malformed_provenance {
                let Value::Array(fixtures) = &mut fields[8] else {
                    return Err("fixtures must be an array".into());
                };
                let Value::Array(fixture) = &mut fixtures[0] else {
                    return Err("fixture must be an array".into());
                };
                fixture[15] = Value::Null;
            }
            let fields = independent_array(&malformed_provenance, 17)?;
            let fixtures = independent_array_bounded(&fields[8])?;
            assert!(independent_support_digests(fields, fixtures, role).is_err());
        }
        Ok(())
    }

    #[test]
    fn remaining_independent_contract_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let profile_value = profile_value(&profile)?;
        let bundle = signed_draft_bundle()?;
        let encoded_bundle = bundle_value(&bundle);
        let records = independent_records(&encoded_bundle)?;
        exercise_independent_expected_result_regions(&profile_value)?;
        exercise_independent_fixture_input_regions(&profile_value, &records)?;
        exercise_independent_support_regions(&profile_value, &records)?;
        Ok(())
    }

    #[test]
    fn independent_archive_cap_predicates_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        for (index, replacement) in [
            (0, 0),
            (0, MAX_PROFILE_BYTES + 1),
            (1, 0),
            (1, u64::try_from(MAX_MEMBERS)? + 1),
            (2, 0),
            (2, u64::try_from(MAX_MEMBERS)? + 1),
            (3, 0),
            (3, u64::try_from(MAX_MEMBER_PATH_BYTES)? + 1),
            (4, 0),
            (4, MAX_MEMBER_BYTES + 1),
            (5, 0),
            (5, MAX_TOTAL_BUNDLE_BYTES + 1),
            (6, 0),
            (6, u64::from(u32::MAX) + 1),
            (7, 0),
            (7, u64::from(MAX_STRUCTURAL_NESTING) + 1),
        ] {
            let mut encoded_profile = profile_value(&profile)?;
            let Value::Array(fields) = &mut encoded_profile else {
                return Err("profile must encode as an array".into());
            };
            let Value::Array(protocol) = &mut fields[10] else {
                return Err("profile protocol must encode as an array".into());
            };
            let Value::Array(caps) = &mut protocol[4] else {
                return Err("profile hard caps must encode as an array".into());
            };
            caps[index] = Value::Integer(replacement.into());
            let encoded_profile = encode_archive_value(&encoded_profile)?;
            assert!(matches!(
                independent_archive_caps(&encoded_profile),
                Err(BundleContractErrorV1::MemberOutOfBounds)
            ));
        }
        Ok(())
    }

    fn exercise_archive_preflight_regions() {
        assert!(archive_preflight::scan(&[0x98]).is_err());
        assert!(archive_preflight::scan(&[0x86]).is_err());
        assert!(archive_preflight::scan(&[0x86, 0x18]).is_err());
        assert!(archive_preflight::scan(&[
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0xf6, 0x81, 0x83, 0x62, b'a', 0x40, 0x00,
            0xf6, 0xf6,
        ])
        .is_err());
        assert!(archive_preflight::scan(&[
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0xf6, 0x81, 0x82, 0x60, 0x40, 0x00, 0xf6,
            0xf6,
        ])
        .is_err());
        assert!(archive_preflight::scan(&[
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0xf6, 0x81, 0x83, 0x00, 0x40, 0x00, 0xf6,
            0xf6,
        ])
        .is_err());
        assert!(independent_archive_caps(b"not cbor").is_err());
        assert!(independent_archive_caps(&[0x81, 0x18, 0x00]).is_err());

        let empty_manifest = || {
            Value::Array(vec![
                Value::Text(CONFORMANCE_BUNDLE_MAGIC_V1.to_owned()),
                Value::Integer(0_u64.into()),
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Array(Vec::new()),
                Value::Array(Vec::new()),
            ])
        };
        let invalid_descriptor = Value::Array(vec![
            Value::Text("member".to_owned()),
            Value::Integer(0_u64.into()),
            Value::Bytes(vec![0; 32]),
            Value::Integer(99_u64.into()),
        ]);
        let mut manifest = empty_manifest();
        if let Value::Array(fields) = &mut manifest {
            fields[4] = Value::Array(vec![invalid_descriptor]);
        }
        assert!(decode_manifest(&manifest).is_err());
        for field in [1, 3] {
            let mut invalid_expected = empty_manifest();
            if let Value::Array(fields) = &mut invalid_expected {
                fields[5] = Value::Array(vec![Value::Array(vec![
                    Value::Text("case".to_owned()),
                    Value::Integer(0_u64.into()),
                    Value::Bytes(vec![0; 32]),
                    Value::Integer(0_u64.into()),
                    Value::Text("expected/member".to_owned()),
                    Value::Bytes(vec![0; 32]),
                ])]);
                if let Value::Array(expected) = &mut fields[5] {
                    if let Value::Array(values) = &mut expected[0] {
                        values[field] = Value::Integer(99_u64.into());
                    }
                }
            }
            assert!(decode_manifest(&invalid_expected).is_err());
        }
        for value in [Value::Null, Value::Integer(99_u64.into())] {
            let mut invalid_manifest = empty_manifest();
            if let Value::Array(fields) = &mut invalid_manifest {
                fields[0] = value;
            }
            assert!(decode_manifest(&invalid_manifest).is_err());
        }
    }

    fn exercise_archive_profile_regions(
        bundle: &ConformanceBundleV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut missing_profile = bundle.clone();
        missing_profile
            .members
            .retain(|member| member.role != BundleMemberRoleV1::Profile);
        assert_eq!(
            validate_archive_caps(&missing_profile, &Value::Null, 0),
            Err(BundleContractErrorV1::MemberMissing)
        );
        let mut invalid_profile = bundle.clone();
        invalid_profile
            .members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Profile)
            .ok_or("missing profile member")?
            .bytes = b"invalid profile".to_vec();
        assert_eq!(
            validate_archive_caps(&invalid_profile, &Value::Null, 0),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
        Ok(())
    }

    fn exercise_authority_valid_regions(
        profile: &ConformanceProfileV1,
        bundle: &ConformanceBundleV1,
        inventory_json: &JsonValue,
        matrix_json: &JsonValue,
        provenance_json: &JsonValue,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(validate_authority_members(profile, &bundle.members), Ok(()));
        assert_eq!(
            validate_provenance_authority_binding(provenance_json),
            Ok(())
        );
        let inventory = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory")?;
        let matrix = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix")?;
        assert_eq!(
            validate_authority_inventory_digest(provenance_json, &inventory.bytes),
            Ok(())
        );
        assert_eq!(
            validate_matrix_provenance_digest(provenance_json, &matrix.bytes),
            Ok(())
        );
        assert_eq!(validate_authority_inventory(inventory_json), Ok(()));
        assert_eq!(validate_execution_matrix(matrix_json), Ok(()));
        let rows = matrix_json
            .get("rows")
            .and_then(JsonValue::as_array)
            .ok_or("missing rows")?;
        assert!(!json_string_array(&rows[0], "variants")?.is_empty());
        let cases = matrix_json
            .get("cases")
            .and_then(JsonValue::as_array)
            .ok_or("missing cases")?;
        assert!(matrix_cases_are_open(cases));
        let mut executed_case = cases.clone();
        executed_case[0]["executed"] = JsonValue::Bool(true);
        assert!(!matrix_cases_are_open(&executed_case));
        let mut bound_case = cases.clone();
        bound_case[0]["expected_result_digest"] = JsonValue::String("bound".to_owned());
        assert!(!matrix_cases_are_open(&bound_case));
        for field in [
            "authority_fixture_id",
            "authority_result_digest",
            "expected_result",
        ] {
            let mut claimed_case = cases.clone();
            claimed_case[0][field] = JsonValue::String("claimed".to_owned());
            assert!(!matrix_cases_are_open(&claimed_case));
        }

        let mut no_provenance = bundle.members.clone();
        no_provenance.retain(|member| member.role != BundleMemberRoleV1::Provenance);
        assert_eq!(
            validate_authority_members(profile, &no_provenance),
            Err(BundleContractErrorV1::MemberMissing)
        );
        for role in [
            BundleMemberRoleV1::Provenance,
            BundleMemberRoleV1::AuthorityInventory,
            BundleMemberRoleV1::ExecutionMatrix,
        ] {
            let mut malformed = bundle.members.clone();
            malformed
                .iter_mut()
                .find(|member| member.role == role)
                .ok_or("missing authority member")?
                .bytes = b"[".to_vec();
            assert_eq!(
                validate_authority_members(profile, &malformed),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        Ok(())
    }

    fn exercise_authority_json_guard_regions(
        inventory_json: &JsonValue,
        matrix_json: &JsonValue,
        provenance_json: &JsonValue,
        inventory_bytes: &[u8],
        matrix_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut invalid_provenance = provenance_json.clone();
        invalid_provenance["authority_inventory"]["path"] = JsonValue::String("wrong".to_owned());
        assert!(validate_provenance_authority_binding(&invalid_provenance).is_err());
        let mut invalid_inventory_digest = provenance_json.clone();
        invalid_inventory_digest["authority_inventory"]["sha256_digest"] =
            JsonValue::String("00".repeat(32));
        assert!(
            validate_authority_inventory_digest(&invalid_inventory_digest, inventory_bytes)
                .is_err()
        );
        let mut invalid_matrix_digest = provenance_json.clone();
        invalid_matrix_digest["adr_059_execution_matrix"]["blake3_digest"] =
            JsonValue::String("00".repeat(32));
        assert!(validate_matrix_provenance_digest(&invalid_matrix_digest, matrix_bytes).is_err());

        for field in ["magic", "version", "digest_algorithm"] {
            let mut invalid = inventory_json.clone();
            invalid[field] = match field {
                "version" => JsonValue::Number(2.into()),
                _ => JsonValue::String("wrong".to_owned()),
            };
            assert!(validate_authority_inventory(&invalid).is_err());
        }
        let mut missing_entries = inventory_json.clone();
        missing_entries["entries"] = JsonValue::Null;
        assert!(validate_authority_inventory(&missing_entries).is_err());
        let mut wrong_entries = inventory_json.clone();
        wrong_entries["entries"][0]["fixture_id"] = JsonValue::String("wrong".to_owned());
        assert!(validate_authority_inventory(&wrong_entries).is_err());
        let mut bad_entry = inventory_json.clone();
        bad_entry["entries"][0]["materialization_status"] =
            JsonValue::String("materialized".to_owned());
        assert!(validate_authority_inventory(&bad_entry).is_err());

        for field in [
            "magic",
            "version",
            "lifecycle",
            "row_count",
            "variant_count",
            "mode_count",
            "case_count",
            "executed_case_count",
        ] {
            let mut invalid = matrix_json.clone();
            invalid[field] = match field {
                "version"
                | "row_count"
                | "variant_count"
                | "mode_count"
                | "case_count"
                | "executed_case_count" => JsonValue::Number(2.into()),
                _ => JsonValue::String("wrong".to_owned()),
            };
            assert!(validate_execution_matrix(&invalid).is_err());
        }
        let rows = matrix_json
            .get("rows")
            .and_then(JsonValue::as_array)
            .ok_or("missing rows")?;
        let mut missing_rows = matrix_json.clone();
        missing_rows["rows"] = JsonValue::Null;
        assert!(validate_execution_matrix(&missing_rows).is_err());
        let mut missing_cases = matrix_json.clone();
        missing_cases["cases"] = JsonValue::Null;
        assert!(validate_execution_matrix(&missing_cases).is_err());
        let mut missing_predicates = matrix_json.clone();
        missing_predicates["equality_predicates"] = JsonValue::Null;
        assert!(validate_execution_matrix(&missing_predicates).is_err());
        assert!(json_string_array(&rows[0], "missing").is_err());
        assert!(independent_matrix_digest(&format!(
            "pigloros.w8.knowledge-non-interference.1.0.0#matrix={}",
            "z".repeat(64)
        ))
        .is_err());
        Ok(())
    }

    fn exercise_authority_independent_regions(
        profile_value: &Value,
        records: &[IndependentMember<'_>],
        bundle: &ConformanceBundleV1,
        inventory_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(independent_verify_profile(b"not cbor", 0, &Value::Bytes(vec![0; 32])).is_err());
        assert!(independent_verify_profile(
            &encode_archive_value(&Value::Array(Vec::new()))?,
            0,
            &Value::Bytes(vec![0; 32]),
        )
        .is_err());

        let mut tied_payloads = bundle.clone();
        tied_payloads.members.push(BundleMemberV1::authority(
            AUTHORITY_INVENTORY_MEMBER_PATH,
            inventory_bytes.to_vec(),
            BundleMemberRoleV1::AuthorityInventory,
        ));
        let payloads = bundle_pair_payloads(&tied_payloads);
        assert!(payloads.windows(2).any(|pair| pair[0] == pair[1]));
        assert!(!records.is_empty());
        let mut no_matrix_binding = profile_value.clone();
        if let Value::Array(fields) = &mut no_matrix_binding {
            fields[2] = Value::Null;
        }
        assert!(independent_verify_authority_members(records, &no_matrix_binding).is_err());
        Ok(())
    }

    fn profile_with_field(
        profile_value: &Value,
        field: usize,
        replacement: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut profile = profile_value.clone();
        let Value::Array(fields) = &mut profile else {
            return Err("profile must be an array".into());
        };
        fields[field] = replacement;
        Ok(profile)
    }

    fn profile_with_fixture_field(
        profile_value: &Value,
        field: usize,
        replacement: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut profile = profile_value.clone();
        let Value::Array(fields) = &mut profile else {
            return Err("profile must be an array".into());
        };
        let Value::Array(fixtures) = &mut fields[8] else {
            return Err("fixtures must be an array".into());
        };
        let Value::Array(fixture) = &mut fixtures[0] else {
            return Err("fixture must be an array".into());
        };
        fixture[field] = replacement;
        Ok(profile)
    }

    fn profile_with_fixture_provenance_field(
        profile_value: &Value,
        field: usize,
        replacement: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut profile = profile_value.clone();
        let Value::Array(fields) = &mut profile else {
            return Err("profile must be an array".into());
        };
        let Value::Array(fixtures) = &mut fields[8] else {
            return Err("fixtures must be an array".into());
        };
        let Value::Array(fixture) = &mut fixtures[0] else {
            return Err("fixture must be an array".into());
        };
        let Value::Array(provenance) = &mut fixture[15] else {
            return Err("provenance must be an array".into());
        };
        provenance[field] = replacement;
        Ok(profile)
    }

    fn raw_record_member(path: Value, bytes: Value, role: Value) -> Value {
        Value::Array(vec![path, bytes, role])
    }

    fn raw_record_descriptor(path: Value, size: Value, digest: Value, role: Value) -> Value {
        Value::Array(vec![path, size, digest, role])
    }

    #[test]
    fn independent_member_shape_errors_are_exercised() {
        let member = || {
            raw_record_member(
                Value::Text("member".to_owned()),
                Value::Bytes(vec![1]),
                Value::Integer(0_u64.into()),
            )
        };
        let descriptor = || {
            raw_record_descriptor(
                Value::Text("member".to_owned()),
                Value::Integer(1_u64.into()),
                Value::Bytes(blake3::hash([1].as_slice()).as_bytes().to_vec()),
                Value::Integer(0_u64.into()),
            )
        };
        assert!(independent_member_records(&[Value::Null], &[descriptor()]).is_err());
        assert!(independent_member_records(&[member()], &[Value::Null]).is_err());
        assert!(independent_member_records(
            &[raw_record_member(
                Value::Null,
                Value::Bytes(vec![1]),
                Value::Integer(0_u64.into()),
            )],
            &[descriptor()],
        )
        .is_err());
        assert!(independent_member_records(
            &[raw_record_member(
                Value::Text("member".to_owned()),
                Value::Null,
                Value::Integer(0_u64.into()),
            )],
            &[descriptor()],
        )
        .is_err());
        assert!(independent_member_records(
            &[raw_record_member(
                Value::Text("member".to_owned()),
                Value::Bytes(vec![1]),
                Value::Integer(99_u64.into()),
            )],
            &[descriptor()],
        )
        .is_err());
        assert!(independent_member_records(
            &[member()],
            &[raw_record_descriptor(
                Value::Text("member".to_owned()),
                Value::Integer(1_u64.into()),
                Value::Bytes(blake3::hash([1].as_slice()).as_bytes().to_vec()),
                Value::Integer(99_u64.into()),
            )],
        )
        .is_err());
        assert!(independent_member_records(
            &[raw_record_member(
                Value::Text("/member".to_owned()),
                Value::Bytes(vec![1]),
                Value::Integer(0_u64.into()),
            )],
            &[raw_record_descriptor(
                Value::Text("/member".to_owned()),
                Value::Integer(1_u64.into()),
                Value::Bytes(blake3::hash([1].as_slice()).as_bytes().to_vec()),
                Value::Integer(0_u64.into()),
            )],
        )
        .is_err());
        assert!(independent_member_records(
            &[raw_record_member(
                Value::Text("member".to_owned()),
                Value::Bytes(vec![1]),
                Value::Null,
            )],
            &[descriptor()],
        )
        .is_err());
    }

    #[test]
    fn independent_member_metadata_predicates_fail_closed() {
        let digest = Value::Bytes(blake3::hash([1].as_slice()).as_bytes().to_vec());
        let member = raw_record_member(
            Value::Text("member".to_owned()),
            Value::Bytes(vec![1]),
            Value::Integer(BundleMemberRoleV1::Profile.code().into()),
        );
        let descriptor = |path: &str, size: u64, member_digest: Value, role: u64| {
            raw_record_descriptor(
                Value::Text(path.to_owned()),
                Value::Integer(size.into()),
                member_digest,
                Value::Integer(role.into()),
            )
        };
        assert!(matches!(
            independent_member_records(
                std::slice::from_ref(&member),
                &[descriptor(
                    "other",
                    1,
                    digest.clone(),
                    BundleMemberRoleV1::Profile.code()
                )],
            ),
            Err(BundleContractErrorV1::UndeclaredMember)
        ));
        assert!(matches!(
            independent_member_records(
                std::slice::from_ref(&member),
                &[descriptor(
                    "member",
                    1,
                    digest.clone(),
                    BundleMemberRoleV1::FixtureInput.code(),
                )],
            ),
            Err(BundleContractErrorV1::UndeclaredMember)
        ));
        assert!(matches!(
            independent_member_records(
                std::slice::from_ref(&member),
                &[descriptor(
                    "member",
                    0,
                    digest,
                    BundleMemberRoleV1::Profile.code()
                )],
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        ));
        assert!(matches!(
            independent_member_records(
                std::slice::from_ref(&member),
                &[descriptor(
                    "member",
                    1,
                    Value::Bytes(vec![0; 32]),
                    BundleMemberRoleV1::Profile.code(),
                )],
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        ));
    }

    #[test]
    fn independent_expected_and_input_shape_errors_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let profile_value = profile_value(&profile)?;
        let bundle = signed_draft_bundle()?;
        let encoded_bundle = bundle_value(&bundle);
        let records = independent_records(&encoded_bundle)?;
        let archive_fields = independent_array(&encoded_bundle, 6)?;
        let manifest = independent_array(&archive_fields[2], 6)?;
        let expected_results = independent_array_bounded(&manifest[5])?;

        let malformed_expected = profile_with_fixture_field(&profile_value, 8, Value::Null)?;
        assert!(independent_verify_expected_results(
            expected_results,
            &records,
            &malformed_expected,
            BundleModeV1::Local.code(),
        )
        .is_err());
        let malformed_fixture = profile_with_fixture_field(&profile_value, 7, Value::Null)?;
        assert!(independent_verify_fixture_inputs(
            &records,
            &malformed_fixture,
            BundleModeV1::Local.code(),
        )
        .is_err());
        let malformed_modes = profile_with_fixture_field(&profile_value, 5, Value::Null)?;
        assert!(independent_verify_fixture_inputs(
            &records,
            &malformed_modes,
            BundleModeV1::Local.code(),
        )
        .is_err());
        for (field, replacement) in [
            (0, Value::Null),
            (2, Value::Null),
            (3, Value::Null),
            (7, Value::Array(vec![Value::Null])),
        ] {
            let malformed = profile_with_fixture_field(&profile_value, field, replacement)?;
            assert!(independent_verify_fixture_inputs(
                &records,
                &malformed,
                BundleModeV1::Local.code(),
            )
            .is_err());
        }
        Ok(())
    }

    fn assert_support_digest_error(
        profile_value: &Value,
        role: BundleMemberRoleV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fields = independent_array(profile_value, 17)?;
        let fixtures = independent_array_bounded(&fields[8])?;
        assert!(independent_support_digests(fields, fixtures, role).is_err());
        Ok(())
    }

    #[test]
    fn independent_support_digest_shape_errors_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile_value = profile_value(&tests::profile())?;
        assert_support_digest_error(
            &profile_with_field(&profile_value, 5, Value::Null)?,
            BundleMemberRoleV1::NormativeSpecification,
        )?;
        assert_support_digest_error(
            &profile_with_field(&profile_value, 7, Value::Null)?,
            BundleMemberRoleV1::Schema,
        )?;
        assert_support_digest_error(
            &profile_with_field(&profile_value, 7, Value::Array(vec![Value::Null]))?,
            BundleMemberRoleV1::Schema,
        )?;
        assert_support_digest_error(
            &profile_with_fixture_field(&profile_value, 4, Value::Null)?,
            BundleMemberRoleV1::Schema,
        )?;
        assert_support_digest_error(
            &profile_with_fixture_field(&profile_value, 15, Value::Null)?,
            BundleMemberRoleV1::Licence,
        )?;
        for (role, field) in [
            (BundleMemberRoleV1::Licence, 0),
            (BundleMemberRoleV1::Notice, 1),
            (BundleMemberRoleV1::Sbom, 2),
            (BundleMemberRoleV1::Provenance, 3),
            (BundleMemberRoleV1::Limitations, 6),
        ] {
            assert_support_digest_error(
                &profile_with_fixture_provenance_field(&profile_value, field, Value::Null)?,
                role,
            )?;
        }
        assert_support_digest_error(
            &profile_with_field(&profile_value, 14, Value::Null)?,
            BundleMemberRoleV1::Provenance,
        )?;
        assert_support_digest_error(
            &profile_with_fixture_field(&profile_value, 15, Value::Null)?,
            BundleMemberRoleV1::Notice,
        )?;
        assert_support_digest_error(
            &profile_with_fixture_field(&profile_value, 15, Value::Null)?,
            BundleMemberRoleV1::Sbom,
        )?;
        assert_support_digest_error(
            &profile_with_fixture_field(&profile_value, 15, Value::Null)?,
            BundleMemberRoleV1::Provenance,
        )?;
        assert_support_digest_error(
            &profile_with_field(&profile_value, 13, Value::Null)?,
            BundleMemberRoleV1::Limitations,
        )?;
        assert_support_digest_error(
            &profile_with_fixture_field(&profile_value, 15, Value::Null)?,
            BundleMemberRoleV1::Limitations,
        )?;
        Ok(())
    }

    fn profile_without_matrix_binding(
        profile_value: &Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        profile_with_field(
            profile_value,
            2,
            Value::Text("pigloros.w8.artifact-integrity.1.0.0".to_owned()),
        )
    }

    fn mutate_authority_member_json(
        members: &mut [BundleMemberV1],
        role: BundleMemberRoleV1,
        update: impl FnOnce(&mut JsonValue),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let member = members
            .iter_mut()
            .find(|member| member.role == role)
            .ok_or("missing authority member")?;
        let mut value: JsonValue = serde_json::from_slice(&member.bytes)?;
        update(&mut value);
        member.bytes = serde_json::to_vec(&value)?;
        Ok(())
    }

    fn authority_members_with_json(
        bundle: &ConformanceBundleV1,
        role: BundleMemberRoleV1,
        update: impl FnOnce(&mut JsonValue),
    ) -> Result<Vec<BundleMemberV1>, Box<dyn std::error::Error>> {
        let mut members = bundle.members.clone();
        mutate_authority_member_json(&mut members, role, update)?;
        Ok(members)
    }

    #[test]
    fn independent_authority_parse_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile_value = profile_value(&tests::profile())?;
        let profile_without_binding = profile_without_matrix_binding(&profile_value)?;
        let inventory = br#"{"lifecycle":"Draft","magic":"W8H1","version":1,"digest_algorithm":"BLAKE3-256","entries":[]}"#;
        let matrix = br#"{"lifecycle":"Draft","magic":"NIM1","version":1}"#;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(b"[", matrix, b"{}"),
                &profile_without_binding,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(inventory, b"[", b"{}"),
                &profile_without_binding,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(inventory, matrix, b"{}"),
                &Value::Null,
            ),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let invalid_matrix_binding = profile_with_field(
            &profile_value,
            2,
            Value::Text("pigloros.w8.knowledge-non-interference.1.0.0#matrix=bad".to_owned()),
        )?;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(inventory, matrix, b"{}"),
                &invalid_matrix_binding,
            ),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn independent_authority_metadata_error_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile_value = profile_value(&tests::profile())?;
        let profile = profile_without_matrix_binding(&profile_value)?;
        let inventory = br#"{"lifecycle":"Draft","magic":"W8H1","version":1,"digest_algorithm":"BLAKE3-256","entries":[]}"#;
        let matrix = br#"{"lifecycle":"Draft","magic":"NIM1","version":1}"#;
        let missing_inventory_lifecycle =
            br#"{"magic":"W8H1","version":1,"digest_algorithm":"BLAKE3-256","entries":[]}"#;
        assert!(independent_verify_authority_members(
            &raw_authority_members(missing_inventory_lifecycle, matrix, b"{}"),
            &profile,
        )
        .is_err());
        let missing_matrix_lifecycle = br#"{"magic":"NIM1","version":1}"#;
        assert!(independent_verify_authority_members(
            &raw_authority_members(inventory, missing_matrix_lifecycle, b"{}"),
            &profile,
        )
        .is_err());
        for field in ["magic", "version", "digest_algorithm"] {
            let mut invalid: JsonValue = serde_json::from_slice(inventory)?;
            invalid[field] = match field {
                "version" => JsonValue::Number(2.into()),
                _ => JsonValue::String("wrong".to_owned()),
            };
            let invalid_bytes = serde_json::to_vec(&invalid)?;
            assert!(independent_verify_authority_members(
                &raw_authority_members(&invalid_bytes, matrix, b"{}"),
                &profile,
            )
            .is_err());
        }
        for field in ["magic", "version"] {
            let mut invalid: JsonValue = serde_json::from_slice(matrix)?;
            invalid[field] = match field {
                "version" => JsonValue::Number(2.into()),
                _ => JsonValue::String("wrong".to_owned()),
            };
            let invalid_bytes = serde_json::to_vec(&invalid)?;
            assert!(independent_verify_authority_members(
                &raw_authority_members(inventory, &invalid_bytes, b"{}"),
                &profile,
            )
            .is_err());
        }
        for (field, value) in [
            ("magic", JsonValue::Null),
            ("version", JsonValue::String("wrong".to_owned())),
            ("digest_algorithm", JsonValue::Null),
        ] {
            let mut invalid: JsonValue = serde_json::from_slice(inventory)?;
            invalid[field] = value;
            let invalid_bytes = serde_json::to_vec(&invalid)?;
            assert!(independent_verify_authority_members(
                &raw_authority_members(&invalid_bytes, matrix, b"{}"),
                &profile,
            )
            .is_err());
        }
        for (field, value) in [
            ("magic", JsonValue::Null),
            ("version", JsonValue::String("wrong".to_owned())),
        ] {
            let mut invalid: JsonValue = serde_json::from_slice(matrix)?;
            invalid[field] = value;
            let invalid_bytes = serde_json::to_vec(&invalid)?;
            assert!(independent_verify_authority_members(
                &raw_authority_members(inventory, &invalid_bytes, b"{}"),
                &profile,
            )
            .is_err());
        }
        Ok(())
    }

    fn exercise_validate_authority_error_regions(
        profile: &ConformanceProfileV1,
        bundle: &ConformanceBundleV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bad_matrix_digest =
            authority_members_with_json(bundle, BundleMemberRoleV1::Provenance, |value| {
                value["adr_059_execution_matrix"]["blake3_digest"] =
                    JsonValue::String("00".repeat(32));
            })?;
        assert_eq!(
            validate_authority_members(profile, &bad_matrix_digest),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        for (role, field) in [
            (BundleMemberRoleV1::AuthorityInventory, "lifecycle"),
            (BundleMemberRoleV1::ExecutionMatrix, "lifecycle"),
        ] {
            let invalid = authority_members_with_json(bundle, role, |value| {
                value[field] = JsonValue::Null;
            })?;
            assert_eq!(
                validate_authority_members(profile, &invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        let bad_binding =
            authority_members_with_json(bundle, BundleMemberRoleV1::Provenance, |value| {
                value["authority_inventory"]["path"] = JsonValue::String("wrong".to_owned());
            })?;
        assert_eq!(
            validate_authority_members(profile, &bad_binding),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut bad_matrix =
            authority_members_with_json(bundle, BundleMemberRoleV1::ExecutionMatrix, |value| {
                value["magic"] = JsonValue::String("NIM0".to_owned());
            })?;
        let matrix_bytes = bad_matrix
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix")?
            .bytes
            .clone();
        mutate_authority_member_json(&mut bad_matrix, BundleMemberRoleV1::Provenance, |value| {
            value["adr_059_execution_matrix"]["blake3_digest"] =
                JsonValue::String(blake3::hash(&matrix_bytes).to_hex().to_string());
        })?;
        assert_eq!(
            validate_authority_members(profile, &bad_matrix),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    fn exercise_provenance_json_error_regions(
        provenance: &JsonValue,
        inventory_bytes: &[u8],
        matrix_bytes: &[u8],
    ) {
        assert!(validate_provenance_authority_binding(&JsonValue::Null).is_err());
        let mut missing_inventory = provenance.clone();
        missing_inventory["authority_inventory"] = JsonValue::Null;
        assert!(validate_provenance_authority_binding(&missing_inventory).is_err());
        let mut missing_matrix = provenance.clone();
        missing_matrix["adr_059_execution_matrix"] = JsonValue::Null;
        assert!(validate_provenance_authority_binding(&missing_matrix).is_err());
        for field in ["path", "digest_algorithm", "status"] {
            let mut invalid = provenance.clone();
            invalid["authority_inventory"][field] = JsonValue::Null;
            assert!(validate_provenance_authority_binding(&invalid).is_err());
        }
        for field in ["path", "digest_algorithm", "status", "executed_case_count"] {
            let mut invalid = provenance.clone();
            invalid["adr_059_execution_matrix"][field] = JsonValue::Null;
            assert!(validate_provenance_authority_binding(&invalid).is_err());
        }

        assert!(validate_authority_inventory_digest(&JsonValue::Null, inventory_bytes).is_err());
        let mut missing_digest = provenance.clone();
        missing_digest["authority_inventory"] = JsonValue::Null;
        assert!(validate_authority_inventory_digest(&missing_digest, inventory_bytes).is_err());
        let mut invalid_digest = provenance.clone();
        invalid_digest["authority_inventory"]["sha256_digest"] =
            JsonValue::String("not-hex".to_owned());
        assert!(validate_authority_inventory_digest(&invalid_digest, inventory_bytes).is_err());

        assert!(validate_matrix_provenance_digest(&JsonValue::Null, matrix_bytes).is_err());
        let mut missing_matrix_digest = provenance.clone();
        missing_matrix_digest["adr_059_execution_matrix"] = JsonValue::Null;
        assert!(validate_matrix_provenance_digest(&missing_matrix_digest, matrix_bytes).is_err());
        let mut invalid_matrix_digest = provenance.clone();
        invalid_matrix_digest["adr_059_execution_matrix"]["blake3_digest"] =
            JsonValue::String("not-hex".to_owned());
        assert!(validate_matrix_provenance_digest(&invalid_matrix_digest, matrix_bytes).is_err());
        let mut missing_matrix_digest_shape = provenance.clone();
        missing_matrix_digest_shape["adr_059_execution_matrix"]["blake3_digest"] = JsonValue::Null;
        assert!(
            validate_matrix_provenance_digest(&missing_matrix_digest_shape, matrix_bytes).is_err()
        );
    }

    fn exercise_inventory_json_error_regions(inventory: &JsonValue) {
        for field in ["magic", "version", "lifecycle", "digest_algorithm"] {
            let mut invalid = inventory.clone();
            invalid[field] = JsonValue::Null;
            assert!(validate_authority_inventory(&invalid).is_err());
        }
        let mut invalid_status = inventory.clone();
        invalid_status["entries"][0]["materialization_status"] = JsonValue::Null;
        assert!(validate_authority_inventory(&invalid_status).is_err());
    }

    fn exercise_matrix_json_error_regions(matrix: &JsonValue) {
        for field in [
            "magic",
            "version",
            "lifecycle",
            "row_count",
            "variant_count",
            "mode_count",
            "case_count",
            "executed_case_count",
        ] {
            let mut invalid = matrix.clone();
            invalid[field] = JsonValue::Null;
            assert!(validate_execution_matrix(&invalid).is_err());
        }
        let mut missing_rows = matrix.clone();
        missing_rows["rows"] = JsonValue::Null;
        assert!(validate_execution_matrix(&missing_rows).is_err());
        let mut missing_cases = matrix.clone();
        missing_cases["cases"] = JsonValue::Null;
        assert!(validate_execution_matrix(&missing_cases).is_err());
        let mut missing_predicates = matrix.clone();
        missing_predicates["equality_predicates"] = JsonValue::Null;
        assert!(validate_execution_matrix(&missing_predicates).is_err());
    }

    #[test]
    fn direct_authority_json_error_regions_are_exercised() -> Result<(), Box<dyn std::error::Error>>
    {
        let bundle = signed_draft_bundle()?;
        let inventory = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory")?;
        let matrix = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix")?;
        let provenance = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance")?;
        let inventory_json: JsonValue = serde_json::from_slice(&inventory.bytes)?;
        let matrix_json: JsonValue = serde_json::from_slice(&matrix.bytes)?;
        let provenance_json: JsonValue = serde_json::from_slice(&provenance.bytes)?;
        exercise_provenance_json_error_regions(&provenance_json, &inventory.bytes, &matrix.bytes);
        exercise_inventory_json_error_regions(&inventory_json);
        exercise_matrix_json_error_regions(&matrix_json);
        let mut profile = tests::profile();
        profile.profile_id = "pigloros.w8.artifact-integrity.1.0.0".to_owned();
        exercise_validate_authority_error_regions(&profile, &bundle)?;
        Ok(())
    }

    #[test]
    fn remaining_archive_shape_and_secret_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(archive_preflight::scan(&[
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0xf6, 0x81, 0x83, 0x62, b'x',
        ])
        .is_err());
        assert!(archive_preflight::scan(&[
            0x86, 0x64, b'C', b'F', b'B', b'1', 0x01, 0xf6, 0x81, 0x82, 0xf6, 0xf6,
        ])
        .is_err());
        assert!(contains_aws_access_key(b"akiaABCDEFGHIJKLMNOP"));
        assert!(contains_aws_access_key(b"asiaABCDEFGHIJKLMNOP"));

        let profile_value = profile_value(&tests::profile())?;
        assert!(independent_archive_caps(&[0x81, 0x18, 0x00]).is_err());
        assert!(validate_selected_bundle_caps(
            &tests::profile(),
            &ConformanceBundleV1 {
                members: Vec::new(),
                ..signed_draft_bundle()?
            },
        )
        .is_err());
        let archive = signed_draft_bundle()?;
        let manifest = manifest_value(&archive.manifest);
        assert!(decode_manifest(&manifest).is_ok());
        assert!(profile_value.is_array());
        Ok(())
    }

    #[test]
    fn malformed_fixture_containers_reach_independent_error_boundaries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile_value = profile_value(&tests::profile())?;
        let malformed = profile_with_field(&profile_value, 8, Value::Array(vec![Value::Null]))?;
        assert!(
            independent_verify_fixture_inputs(&[], &malformed, BundleModeV1::Local.code(),)
                .is_err()
        );
        for role in [
            BundleMemberRoleV1::Licence,
            BundleMemberRoleV1::Notice,
            BundleMemberRoleV1::Sbom,
            BundleMemberRoleV1::Provenance,
            BundleMemberRoleV1::Limitations,
        ] {
            assert_support_digest_error(&malformed, role)?;
        }
        Ok(())
    }

    #[test]
    fn independent_authority_valid_metadata_is_verified() -> Result<(), Box<dyn std::error::Error>>
    {
        let bundle = signed_draft_bundle()?;
        let profile = profile_without_matrix_binding(&profile_value(&tests::profile())?)?;
        let inventory = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory")?;
        let matrix = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix")?;
        let provenance = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance")?;
        assert_eq!(
            independent_verify_authority_members(
                &raw_authority_members(&inventory.bytes, &matrix.bytes, &provenance.bytes),
                &profile,
            ),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn authority_matrix_lifecycle_shape_is_checked_after_digest_binding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = tests::profile();
        profile.profile_id = "pigloros.w8.artifact-integrity.1.0.0".to_owned();
        let bundle = signed_draft_bundle()?;
        let mut members = bundle.members;
        mutate_authority_member_json(&mut members, BundleMemberRoleV1::ExecutionMatrix, |value| {
            value["lifecycle"] = JsonValue::Null;
        })?;
        let matrix_bytes = members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix")?
            .bytes
            .clone();
        mutate_authority_member_json(&mut members, BundleMemberRoleV1::Provenance, |value| {
            value["adr_059_execution_matrix"]["blake3_digest"] =
                JsonValue::String(blake3::hash(&matrix_bytes).to_hex().to_string());
        })?;
        assert_eq!(
            validate_authority_members(&profile, &members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn remaining_archive_and_authority_regions_are_exercised(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let profile_value = profile_value(&profile)?;
        let bundle = signed_draft_bundle()?;
        let encoded_bundle = bundle_value(&bundle);
        let records = independent_records(&encoded_bundle)?;
        exercise_archive_preflight_regions();
        exercise_archive_profile_regions(&bundle)?;

        let inventory = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory")?;
        let matrix = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix")?;
        let provenance = bundle
            .members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance")?;
        let inventory_json: JsonValue = serde_json::from_slice(&inventory.bytes)?;
        let matrix_json: JsonValue = serde_json::from_slice(&matrix.bytes)?;
        let provenance_json: JsonValue = serde_json::from_slice(&provenance.bytes)?;
        exercise_authority_valid_regions(
            &profile,
            &bundle,
            &inventory_json,
            &matrix_json,
            &provenance_json,
        )?;
        exercise_authority_json_guard_regions(
            &inventory_json,
            &matrix_json,
            &provenance_json,
            &inventory.bytes,
            &matrix.bytes,
        )?;
        exercise_authority_independent_regions(
            &profile_value,
            &records,
            &bundle,
            &inventory.bytes,
        )?;
        Ok(())
    }
}
