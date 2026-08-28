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
const MANIFEST_STRUCTURAL_DEPTH_V1: usize = 3;
const PROFILE_MEMBER_PATH: &str = "profile/CPF1.cbor";
const INPUT_MEMBER_PREFIX: &str = "inputs/";
const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/execution-matrix.json";
const AUTHORITY_INVENTORY_KEYS: [&str; 6] = [
    "magic",
    "version",
    "lifecycle",
    "digest_algorithm",
    "source",
    "entries",
];
const AUTHORITY_INVENTORY_ENTRY_KEYS: [&str; 8] = [
    "fixture_id",
    "execution_class",
    "expected_outcome",
    "fixture_bytes_path",
    "fixture_bytes_digest",
    "expected_result_path",
    "expected_result_digest",
    "materialization_status",
];
const EXECUTION_MATRIX_KEYS: [&str; 14] = [
    "magic",
    "version",
    "matrix_id",
    "lifecycle",
    "source",
    "row_count",
    "variant_count",
    "mode_count",
    "case_count",
    "cases",
    "expected_result_policy",
    "equality_predicates",
    "executed_case_count",
    "rows",
];
const EXECUTION_MATRIX_ROW_KEYS: [&str; 10] = [
    "fixture_id",
    "classification",
    "channel",
    "variants",
    "modes",
    "equality",
    "observable_surfaces",
    "sole_unauthorized_delta",
    "case_count",
    "executed_case_count",
];
const EXECUTION_MATRIX_CASE_KEYS: [&str; 9] = [
    "case_id",
    "fixture_id",
    "variant",
    "mode",
    "executed",
    "authority_fixture_id",
    "authority_result_digest",
    "expected_result",
    "expected_result_digest",
];
const EXECUTION_MATRIX_PREDICATE_KEYS: [&str; 4] = ["fixture_id", "AuthEq", "PublicEq", "OpEq"];
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
    /// A release filename is not the canonical CFB1 archive address.
    #[error("conformance bundle release filename is invalid")]
    ReleaseFilenameInvalid,
    /// The supplied archive bytes do not match their expected CFB1 address.
    #[error("conformance bundle archive digest does not match its bytes")]
    ArchiveDigestMismatch,
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
}

impl BundleMemberV1 {
    fn with_role(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        let digest = *blake3::hash(&bytes).as_bytes();
        Self {
            path: path.into(),
            bytes,
            digest,
            role,
        }
    }

    /// Construct a fixture-input member and derive its content address.
    #[must_use]
    pub fn fixture_input(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::with_role(path, bytes, BundleMemberRoleV1::FixtureInput)
    }

    /// Construct an expected-result member and derive its content address.
    #[must_use]
    pub fn expected_result(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::with_role(path, bytes, BundleMemberRoleV1::ExpectedResult)
    }

    /// Construct the sole canonical profile member.
    #[must_use]
    pub fn profile(bytes: Vec<u8>) -> Self {
        Self::with_role(PROFILE_MEMBER_PATH, bytes, BundleMemberRoleV1::Profile)
    }

    /// Construct a typed public support artifact member.
    #[must_use]
    pub fn supporting(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        debug_assert!(role.is_supporting());
        Self::with_role(path, bytes, role)
    }

    /// Construct the sole authority-inventory member.
    #[must_use]
    pub fn authority_inventory(bytes: Vec<u8>) -> Self {
        Self::with_role(
            AUTHORITY_INVENTORY_MEMBER_PATH,
            bytes,
            BundleMemberRoleV1::AuthorityInventory,
        )
    }

    /// Construct the sole execution-matrix member.
    #[must_use]
    pub fn execution_matrix(bytes: Vec<u8>) -> Self {
        Self::with_role(
            EXECUTION_MATRIX_MEMBER_PATH,
            bytes,
            BundleMemberRoleV1::ExecutionMatrix,
        )
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
        let profile_member = BundleMemberV1::profile(profile_bytes);
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
        bundle.validate_unsigned().map(|_| bundle)
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
        self.validate_unsigned().and_then(|_| {
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
        self.validated_profile().map(|_| ())
    }

    fn validated_profile(&self) -> Result<ConformanceProfileV1, BundleContractErrorV1> {
        self.validate_unsigned().and_then(|profile| {
            signing::verifying_key_from_public_key(&self.signer_public_key)
                .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                .and_then(|key| {
                    self.manifest_bytes().and_then(|bytes| {
                        signing::verify(&key, &CanonicalBytes::from_vec(bytes), &self.signature)
                            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                            .map(|()| profile)
                    })
                })
        })
    }

    /// Return the domain-separated content address of the canonical manifest.
    ///
    /// # Errors
    ///
    /// Returns [`BundleContractErrorV1::EncodingFailed`] if canonical encoding
    /// fails.
    pub fn manifest_digest(&self) -> Result<[u8; 32], BundleContractErrorV1> {
        self.manifest_bytes().map(|bytes| {
            let mut input = Vec::with_capacity(32 + bytes.len());
            input.extend_from_slice(b"PiglorOS.ConformanceBundle.v1\0");
            input.extend_from_slice(&bytes);
            *blake3::hash(&input).as_bytes()
        })
    }

    /// Return the content address of the exact canonical signed CFB1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed error when this bundle cannot be encoded as a valid
    /// canonical signed archive.
    pub fn archive_digest(&self) -> Result<[u8; 32], BundleContractErrorV1> {
        self.to_canonical_cbor()
            .map(|bytes| *blake3::hash(&bytes).as_bytes())
    }

    /// Return the only public CFB1 release filename for this signed archive.
    ///
    /// The lowercase hexadecimal digest identifies the exact signed bytes,
    /// including the embedded verification key and signature.
    ///
    /// # Errors
    ///
    /// Returns a closed error when this bundle cannot be encoded as a valid
    /// canonical signed archive.
    pub fn release_filename(&self) -> Result<String, BundleContractErrorV1> {
        self.archive_digest()
            .map(|digest| format!("{}.cfb1", crate::hex_digest(&digest)))
    }

    fn validate_unsigned(&self) -> Result<ConformanceProfileV1, BundleContractErrorV1> {
        if self.manifest.magic != CONFORMANCE_BUNDLE_MAGIC_V1
            || !matches!(self.manifest.lifecycle, ProfileLifecycleV1::Draft)
            || self.members.is_empty()
        {
            return Err(BundleContractErrorV1::LifecycleInvalid);
        }
        let profile_member = self
            .members
            .iter()
            .find(|member| {
                member.path == PROFILE_MEMBER_PATH && member.role == BundleMemberRoleV1::Profile
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
        validate_selected_bundle_caps(&profile, self, profile_member)?;
        validate_fixture_inputs_for_mode(&profile, Some(self.manifest.mode), &self.members)?;
        if self.manifest.members.len() != self.members.len()
            || !crate::strictly_ordered(&self.manifest.members)
            || !members_strictly_ordered(&self.members)
        {
            return Err(BundleContractErrorV1::NonCanonicalOrder);
        }
        for (member, descriptor) in self.members.iter().zip(&self.manifest.members) {
            validate_member_path(&member.path)?;
            let expected_reference_count = self
                .manifest
                .expected_results
                .iter()
                .filter(|expected| expected.member_path == member.path)
                .count();
            let declared_fixture_input = profile
                .fixtures
                .iter()
                .filter(|fixture| fixture.modes.contains(&execution_mode))
                .any(|fixture| {
                    fixture.inputs.iter().any(|input| {
                        member.path
                            == fixture_input_member_path(
                                &fixture.case_id,
                                fixture.claim_layer,
                                &fixture.execution_profile_digest,
                                &input.member_id,
                            )
                    })
                });
            let undeclared = [
                descriptor.path != member.path,
                descriptor.role != member.role,
                member.role == BundleMemberRoleV1::ExpectedResult && expected_reference_count != 1,
                member.role == BundleMemberRoleV1::FixtureInput && !declared_fixture_input,
                member.role == BundleMemberRoleV1::Profile && member.path != PROFILE_MEMBER_PATH,
            ];
            if undeclared.contains(&true) {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if descriptor.size_bytes != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
                || descriptor.digest != member.digest
                || member.digest != *blake3::hash(&member.bytes).as_bytes()
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            if contains_secret_marker(&member.bytes) {
                return Err(BundleContractErrorV1::SecretMaterialDetected);
            }
        }
        validate_supporting_members(&profile, &self.members)?;
        validate_authority_members(&profile, &self.members)?;
        validate_expected_results(&profile, &self.manifest, &self.members).map(|()| profile)
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
        self.validated_profile().and_then(|profile| {
            let value = bundle_value(self);
            encode_archive_value(&value)
                .and_then(|bytes| validate_archive_caps(&profile, bytes.len()).map(|()| bytes))
        })
    }

    /// Decode and validate complete canonical public archive bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed/noncanonical bytes, invalid bundle
    /// declarations, a profile-cap violation, or an invalid signature.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleContractErrorV1> {
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
        if !encode_archive_value(&archive)
            .is_ok_and(|canonical_bytes| canonical_bytes.as_slice() == bytes)
        {
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
    let preflight = preflight_archive_caps(bytes)?;
    let profile_bytes = preflight
        .profile_bytes
        .ok_or(BundleContractErrorV1::MemberMissing)?;
    let (profile, caps) = independent_archive_profile(profile_bytes)?;
    validate_independent_preflight_caps(&caps, &preflight, bytes.len())?;
    let profile = independent_verify_cpf1(&profile, &caps)?;
    let archive: (Value, Value, Value, Vec<Value>, Value, Value) =
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
    if !encode_archive_value(&archive)
        .is_ok_and(|canonical_bytes| canonical_bytes.as_slice() == bytes)
    {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    let (magic, version, manifest_value, members, public_key, signature) = archive;
    if archive_text(&magic)? != CONFORMANCE_BUNDLE_MAGIC_V1 || archive_u64(&version)? != 1 {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    let manifest = independent_array(&manifest_value, 6)?;
    if archive_text(&manifest[0])? != CONFORMANCE_BUNDLE_MAGIC_V1 {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
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
    let expected_records = independent_expected_result_records(expected_results)?;
    independent_verify_expected_results(&expected_records, &member_records, &profile, bundle_mode)?;
    independent_verify_fixture_inputs(&member_records, &profile, bundle_mode)?;
    independent_verify_supporting_members(&member_records, &profile)?;
    independent_verify_authority_members(&member_records, &profile)?;
    independent_verify_profile_contract(&profile, &manifest[3])
}

/// Independently verify an archive after binding it to its sole canonical
/// release filename.
///
/// A CFB1 release filename is exactly 64 lowercase hexadecimal BLAKE3 digits
/// followed by `.cfb1`; every other filename is rejected.
/// The exact archive bytes are checked against that address before semantic
/// archive validation begins.
///
/// # Errors
///
/// Returns a closed error when the filename is noncanonical, the archive bytes
/// do not match it, or independent archive verification fails.
pub fn verify_archive_release_filename(
    bytes: &[u8],
    filename: &str,
) -> Result<(), BundleContractErrorV1> {
    let expected_digest = release_filename_digest(filename)?;
    if expected_digest != *blake3::hash(bytes).as_bytes() {
        return Err(BundleContractErrorV1::ArchiveDigestMismatch);
    }
    verify_archive_independently(bytes)
}

fn release_filename_digest(filename: &str) -> Result<[u8; 32], BundleContractErrorV1> {
    let Some(encoded) = filename.strip_suffix(".cfb1") else {
        return Err(BundleContractErrorV1::ReleaseFilenameInvalid);
    };
    if encoded.len() != 64 {
        return Err(BundleContractErrorV1::ReleaseFilenameInvalid);
    }
    if !encoded
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BundleContractErrorV1::ReleaseFilenameInvalid);
    }
    crate::decode_hex_digest(encoded).ok_or(BundleContractErrorV1::ReleaseFilenameInvalid)
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

struct IndependentDescriptor<'a> {
    path: &'a str,
    size: u64,
    digest: [u8; 32],
    role: BundleMemberRoleV1,
}

fn independent_member_fields(
    value: &Value,
) -> Result<(&str, &[u8], BundleMemberRoleV1), BundleContractErrorV1> {
    independent_array(value, 3).and_then(|fields| {
        archive_text(&fields[0]).and_then(|path| {
            archive_bytes(&fields[1]).and_then(|bytes| {
                archive_u64(&fields[2])
                    .and_then(decode_member_role)
                    .map(|role| (path, bytes, role))
            })
        })
    })
}

fn independent_descriptor_fields(
    value: &Value,
) -> Result<IndependentDescriptor<'_>, BundleContractErrorV1> {
    independent_array(value, 4).and_then(|fields| {
        archive_text(&fields[0]).and_then(|path| {
            archive_u64(&fields[1]).and_then(|size| {
                independent_digest::<32>(&fields[2]).and_then(|digest| {
                    archive_u64(&fields[3])
                        .and_then(decode_member_role)
                        .map(|role| IndependentDescriptor {
                            path,
                            size,
                            digest,
                            role,
                        })
                })
            })
        })
    })
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
        let (member_path, member_bytes, member_role) = independent_member_fields(member_value)?;
        let descriptor = independent_descriptor_fields(descriptor_value)?;
        validate_member_path(member_path)?;
        if previous_member_path.is_some_and(|previous| previous >= member_path)
            || !normalized_member_paths.insert(member_path.to_ascii_lowercase())
        {
            return Err(BundleContractErrorV1::NonCanonicalOrder);
        }
        previous_member_path = Some(member_path);
        if descriptor.path != member_path || descriptor.role != member_role {
            return Err(BundleContractErrorV1::UndeclaredMember);
        }
        if descriptor.size != u64::try_from(member_bytes.len()).unwrap_or(u64::MAX)
            || descriptor.digest != *blake3::hash(member_bytes).as_bytes()
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
            digest: descriptor.digest,
            role: member_role,
        });
    }
    Ok((records, profile_bytes))
}

fn independent_expected_result_records(
    expected_results: &[Value],
) -> Result<Vec<BundleExpectedResultV1>, BundleContractErrorV1> {
    let records = expected_results
        .iter()
        .map(independent_expected_result_record)
        .collect::<Result<Vec<_>, _>>()?;
    if crate::strictly_ordered(&records) {
        Ok(records)
    } else {
        Err(BundleContractErrorV1::NonCanonicalOrder)
    }
}

fn independent_expected_result_record(
    value: &Value,
) -> Result<BundleExpectedResultV1, BundleContractErrorV1> {
    let fields = independent_array(value, 6)?;
    Ok(BundleExpectedResultV1 {
        case_id: archive_text(&fields[0])?.to_owned(),
        claim_layer: decode_claim_layer(archive_u64(&fields[1])?)?,
        execution_profile_digest: independent_digest::<32>(&fields[2])?,
        mode: decode_bundle_mode(archive_u64(&fields[3])?)?,
        member_path: archive_text(&fields[4])?.to_owned(),
        digest: independent_digest::<32>(&fields[5])?,
    })
}

fn independent_verify_expected_results(
    expected_results: &[BundleExpectedResultV1],
    members: &[IndependentMember<'_>],
    profile: &IndependentCpf1,
    bundle_mode: u64,
) -> Result<(), BundleContractErrorV1> {
    let mut referenced_expected_results = BTreeSet::new();
    let mut referenced_fixture_identities = BTreeSet::new();
    for expected in expected_results {
        let path = expected.member_path.as_str();
        referenced_expected_results.insert(path.to_owned());
        let Some(member) = members.iter().find(|member| member.path == path) else {
            return Err(BundleContractErrorV1::MemberMissing);
        };
        if member.role != BundleMemberRoleV1::ExpectedResult || expected.digest != member.digest {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let case_id = expected.case_id.as_str();
        let claim_layer_code = u64::from(claim_layer_code(expected.claim_layer));
        let execution_profile_digest = expected.execution_profile_digest;
        referenced_fixture_identities.insert((
            case_id.to_owned(),
            claim_layer_code,
            execution_profile_digest,
        ));
        let expected_mode = expected.mode.code();
        let Some(fixture) = profile.fixtures.iter().find(|fixture| {
            expected_mode == bundle_mode
                && fixture.case_id == case_id
                && fixture.claim_layer == claim_layer_code
                && fixture.execution_profile_digest == execution_profile_digest
                && fixture.modes.contains(&bundle_mode)
        }) else {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        };
        if path
            != independent_expected_member_path(
                case_id,
                expected.claim_layer,
                &execution_profile_digest,
            )
            || member.bytes != fixture.expected_bytes.as_slice()
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
    for fixture in &profile.fixtures {
        let selected = fixture.modes.contains(&bundle_mode);
        let fixture_identity = (
            fixture.case_id.clone(),
            fixture.claim_layer,
            fixture.execution_profile_digest,
        );
        if fixture.mandatory
            && selected
            && !referenced_fixture_identities.contains(&fixture_identity)
        {
            return Err(BundleContractErrorV1::MemberMissing);
        }
    }
    Ok(())
}

fn independent_verify_fixture_inputs(
    members: &[IndependentMember<'_>],
    profile: &IndependentCpf1,
    bundle_mode: u64,
) -> Result<(), BundleContractErrorV1> {
    let mut declared_paths = BTreeSet::new();
    for fixture in &profile.fixtures {
        if !fixture.modes.contains(&bundle_mode) {
            continue;
        }
        for input in &fixture.inputs {
            let path = independent_input_member_path(
                &fixture.case_id,
                fixture.claim_layer,
                &fixture.execution_profile_digest,
                &input.member_id,
            );
            declared_paths.insert(path.clone());
            let Some(member) = members.iter().find(|member| member.path == path) else {
                return Err(BundleContractErrorV1::MemberMissing);
            };
            if member.role != BundleMemberRoleV1::FixtureInput
                || member.bytes.is_empty()
                || input.size != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
                || input.digest != member.digest
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

#[derive(Clone, Copy)]
enum SupportRole {
    NormativeSpecification,
    Schema,
    Licence,
    Notice,
    Sbom,
    Provenance,
    Limitations,
}

const SUPPORT_MEMBERS: [(SupportRole, BundleMemberRoleV1, &str); 7] = [
    (
        SupportRole::NormativeSpecification,
        BundleMemberRoleV1::NormativeSpecification,
        "support/normative-requirements.md",
    ),
    (
        SupportRole::Schema,
        BundleMemberRoleV1::Schema,
        "support/schema-cpf1-v1.cddl",
    ),
    (
        SupportRole::Licence,
        BundleMemberRoleV1::Licence,
        "support/LICENSE",
    ),
    (
        SupportRole::Notice,
        BundleMemberRoleV1::Notice,
        "support/NOTICE",
    ),
    (
        SupportRole::Sbom,
        BundleMemberRoleV1::Sbom,
        "support/sbom.json",
    ),
    (
        SupportRole::Provenance,
        BundleMemberRoleV1::Provenance,
        "support/provenance.json",
    ),
    (
        SupportRole::Limitations,
        BundleMemberRoleV1::Limitations,
        "support/limitations.md",
    ),
];

fn independent_verify_supporting_members(
    members: &[IndependentMember<'_>],
    profile: &IndependentCpf1,
) -> Result<(), BundleContractErrorV1> {
    for (support_role, member_role, path) in SUPPORT_MEMBERS {
        let matching = members
            .iter()
            .filter(|member| member.role == member_role)
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].path != path || matching[0].bytes.is_empty() {
            return Err(BundleContractErrorV1::MemberMissing);
        }
        let expected_digests = independent_support_digests(profile, support_role);
        if !expected_digests.contains(&matching[0].digest) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
}

fn independent_support_digests(profile: &IndependentCpf1, role: SupportRole) -> BTreeSet<[u8; 32]> {
    let mut digests = BTreeSet::new();
    match role {
        SupportRole::NormativeSpecification => {
            digests.insert(profile.normative_spec_digest);
        }
        SupportRole::Schema => {
            digests.extend(profile.public_schema_digests.iter().copied());
            for fixture in &profile.fixtures {
                digests.insert(fixture.public_schema_digest);
            }
        }
        SupportRole::Licence => {
            for fixture in &profile.fixtures {
                let mut bytes = fixture.provenance.licence_id.as_bytes().to_vec();
                bytes.push(b'\n');
                digests.insert(*blake3::hash(&bytes).as_bytes());
            }
        }
        SupportRole::Notice => {
            for fixture in &profile.fixtures {
                digests.insert(fixture.provenance.notices_digest);
            }
        }
        SupportRole::Sbom => {
            for fixture in &profile.fixtures {
                digests.insert(fixture.provenance.sbom_digest);
            }
        }
        SupportRole::Provenance => {
            digests.insert(profile.provenance_digest);
            for fixture in &profile.fixtures {
                digests.insert(fixture.provenance.source_digest);
                digests.insert(fixture.provenance.build_digest);
                digests.insert(fixture.provenance.publication_review_digest);
            }
        }
        SupportRole::Limitations => {
            digests.insert(profile.limitations_digest);
            for fixture in &profile.fixtures {
                digests.insert(fixture.provenance.limitations_digest);
            }
        }
    }
    digests
}

fn independent_verify_authority_members(
    members: &[IndependentMember<'_>],
    profile: &IndependentCpf1,
) -> Result<(), BundleContractErrorV1> {
    let inventory = independent_required_member(
        members,
        BundleMemberRoleV1::AuthorityInventory,
        AUTHORITY_INVENTORY_MEMBER_PATH,
    )?;
    let matrix = independent_required_member(
        members,
        BundleMemberRoleV1::ExecutionMatrix,
        EXECUTION_MATRIX_MEMBER_PATH,
    )?;
    let inventory_json = parse_authority_json(inventory.bytes)?;
    let matrix_json = parse_authority_json(matrix.bytes)?;
    if profile.execution_matrix_digest != *blake3::hash(matrix.bytes).as_bytes() {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    independent_validate_authority_inventory(&inventory_json)
        .and_then(|()| independent_validate_execution_matrix(&matrix_json))
}

fn independent_validate_authority_inventory(
    inventory: &JsonValue,
) -> Result<(), BundleContractErrorV1> {
    // This deliberately does not call `validate_authority_inventory`: archive
    // verification has an independent authority for the accepted Draft
    // inventory. JSON-value equality retains the complete contract while
    // accepting harmless JSON whitespace and member-order differences.
    if serde_json::from_slice::<JsonValue>(include_bytes!(
        "../../../fixtures/conformance/expected-authority/inventory.json"
    ))
    .is_ok_and(|expected| inventory == &expected)
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn independent_validate_execution_matrix(matrix: &JsonValue) -> Result<(), BundleContractErrorV1> {
    // This deliberately does not call `validate_execution_matrix`: archive
    // verification has an independent authority for the accepted Draft matrix.
    // JSON-value equality retains the complete contract while accepting harmless
    // JSON whitespace and member-order differences.
    if serde_json::from_slice::<JsonValue>(include_bytes!(
        "../../../fixtures/conformance/matrix/execution-matrix.json"
    ))
    .is_ok_and(|expected| matrix == &expected)
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn independent_required_member<'a>(
    members: &'a [IndependentMember<'a>],
    role: BundleMemberRoleV1,
    path: &str,
) -> Result<&'a IndependentMember<'a>, BundleContractErrorV1> {
    members
        .iter()
        .filter(|member| member.role == role)
        .find(|member| member.path == path)
        .ok_or(BundleContractErrorV1::MemberMissing)
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

fn independent_verify_profile_contract(
    profile: &IndependentCpf1,
    manifest_profile_digest: &Value,
) -> Result<(), BundleContractErrorV1> {
    independent_digest::<32>(manifest_profile_digest).and_then(|manifest_digest| {
        if profile.profile_digest == manifest_digest {
            Ok(())
        } else {
            Err(BundleContractErrorV1::MemberDigestMismatch)
        }
    })
}

struct IndependentCpf1Root {
    normative_spec: [u8; 32],
    execution_matrix: [u8; 32],
    limitations: [u8; 32],
    provenance: [u8; 32],
}

struct IndependentCpf1Input {
    member_id: String,
    size: u64,
    digest: [u8; 32],
}

struct IndependentCpf1Provenance {
    licence_id: String,
    notices_digest: [u8; 32],
    sbom_digest: [u8; 32],
    source_digest: [u8; 32],
    build_digest: [u8; 32],
    publication_review_digest: [u8; 32],
    limitations_digest: [u8; 32],
}

struct IndependentCpf1Fixture {
    case_id: String,
    mandatory: bool,
    claim_layer: u64,
    execution_profile_digest: [u8; 32],
    public_schema_digest: [u8; 32],
    modes: Vec<u64>,
    inputs: Vec<IndependentCpf1Input>,
    expected_bytes: Vec<u8>,
    provenance: IndependentCpf1Provenance,
}

struct IndependentCpf1 {
    normative_spec_digest: [u8; 32],
    execution_matrix_digest: [u8; 32],
    public_schema_digests: Vec<[u8; 32]>,
    fixtures: Vec<IndependentCpf1Fixture>,
    limitations_digest: [u8; 32],
    provenance_digest: [u8; 32],
    profile_digest: [u8; 32],
}

fn independent_verify_cpf1(
    profile: &Value,
    caps: &IndependentArchiveCaps,
) -> Result<IndependentCpf1, BundleContractErrorV1> {
    independent_profile_array(profile, 18).and_then(|fields| {
        independent_verify_cpf1_header(fields)
            .and_then(|()| {
                independent_profile_digests(&fields[7]).and_then(|execution_profiles| {
                    independent_profile_digests(&fields[8])
                        .map(|public_schemas| (execution_profiles, public_schemas))
                })
            })
            .and_then(|(execution_profiles, public_schemas)| {
                independent_verify_cpf1_root(fields, &execution_profiles, &public_schemas)
                    .and_then(|root| {
                        independent_verify_cpf1_requirements(&fields[12]).map(|()| root)
                    })
                    .and_then(|root| {
                        independent_verify_cpf1_allowed_divergences(
                            &fields[10],
                            caps.coordinate_bytes,
                        )
                        .map(|allowed_divergences| (root, allowed_divergences))
                    })
                    .and_then(|(root, allowed_divergences)| {
                        independent_verify_cpf1_fixtures(
                            &fields[9],
                            &allowed_divergences,
                            &execution_profiles,
                            &public_schemas,
                            caps,
                        )
                        .map(|fixtures| (root, fixtures))
                    })
                    .and_then(|(root, fixtures)| {
                        independent_verify_cpf1_selected_caps(fixtures.len(), caps)
                            .map(|()| (root, fixtures))
                    })
                    .and_then(|(root, fixtures)| {
                        independent_verify_cpf1_digest(fields).map(|profile_digest| {
                            IndependentCpf1 {
                                normative_spec_digest: root.normative_spec,
                                execution_matrix_digest: root.execution_matrix,
                                public_schema_digests: public_schemas,
                                fixtures,
                                limitations_digest: root.limitations,
                                provenance_digest: root.provenance,
                                profile_digest,
                            }
                        })
                    })
            })
    })
}

fn independent_verify_cpf1_header(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    let invalid = [
        independent_profile_text(&fields[0], 4)? != "CPF1",
        independent_profile_u64(&fields[1])? != 1,
        independent_profile_u64(&fields[4])? != 0,
    ];
    if invalid.contains(&true) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn independent_verify_cpf1_root(
    fields: &[Value],
    execution_profiles: &[[u8; 32]],
    public_schemas: &[[u8; 32]],
) -> Result<IndependentCpf1Root, BundleContractErrorV1> {
    let root = IndependentCpf1Root {
        normative_spec: independent_profile_digest(&fields[5])?,
        execution_matrix: independent_profile_digest(&fields[6])?,
        limitations: independent_profile_digest(&fields[14])?,
        provenance: independent_profile_digest(&fields[15])?,
    };
    let trust_policy_snapshot_digest = independent_profile_digest(&fields[13])?;
    let invalid = [
        !independent_semantic_version(independent_profile_text(&fields[3], 256)?),
        independent_profile_text(&fields[2], 256)?.contains("#matrix="),
        root.normative_spec == [0; 32],
        root.execution_matrix == [0; 32],
        trust_policy_snapshot_digest == [0; 32],
        root.limitations == [0; 32],
        root.provenance == [0; 32],
        execution_profiles.is_empty(),
        execution_profiles.len() > 64,
        execution_profiles.contains(&[0; 32]),
        public_schemas.contains(&[0; 32]),
        !independent_strictly_ordered(execution_profiles),
        !independent_strictly_ordered(public_schemas),
    ];
    if invalid.contains(&true) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    match &fields[16] {
        Value::Null => Ok(root),
        value => independent_profile_digest(value).and_then(|digest| {
            if digest == [0; 32] {
                Err(BundleContractErrorV1::ProfileInvalid)
            } else {
                Ok(root)
            }
        }),
    }
}

fn independent_verify_cpf1_requirements(value: &Value) -> Result<(), BundleContractErrorV1> {
    let fields = independent_profile_array(value, 5)?;
    if fields[..3]
        .iter()
        .any(|field| !matches!(field, Value::Bool(_)))
        || independent_profile_digest(&fields[3])? == [0; 32]
        || independent_profile_digest(&fields[4])? == [0; 32]
    {
        Err(BundleContractErrorV1::ProfileInvalid)
    } else {
        Ok(())
    }
}

fn independent_verify_cpf1_allowed_divergences(
    value: &Value,
    max_coordinate_bytes: u64,
) -> Result<Vec<(u64, Vec<u8>)>, BundleContractErrorV1> {
    let values = independent_profile_array_bounded(value)?;
    let records = values
        .iter()
        .map(|value| {
            let fields = independent_profile_array(value, 2)?;
            let classification = independent_profile_divergence(&fields[0])?;
            let coordinate = independent_profile_bytes(&fields[1])?;
            if coordinate.is_empty()
                || u64::try_from(coordinate.len()).unwrap_or(u64::MAX) > max_coordinate_bytes
            {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            Ok((classification, coordinate.to_vec()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if independent_strictly_ordered(&records) {
        Ok(records)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_verify_cpf1_fixtures(
    value: &Value,
    allowed_divergences: &[(u64, Vec<u8>)],
    execution_profiles: &[[u8; 32]],
    public_schemas: &[[u8; 32]],
    caps: &IndependentArchiveCaps,
) -> Result<Vec<IndependentCpf1Fixture>, BundleContractErrorV1> {
    let fixtures = independent_profile_array_bounded(value)?;
    let mut previous = None;
    let mut verified = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        let fixture = independent_verify_cpf1_fixture(
            fixture,
            allowed_divergences,
            execution_profiles,
            public_schemas,
            caps,
        )?;
        let key = (
            fixture.case_id.clone(),
            fixture.claim_layer,
            fixture.execution_profile_digest,
        );
        if previous.as_ref().is_some_and(|prior| prior >= &key) {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        previous = Some(key);
        verified.push(fixture);
    }
    Ok(verified)
}

fn independent_verify_cpf1_fixture(
    value: &Value,
    allowed: &[(u64, Vec<u8>)],
    execution_profiles: &[[u8; 32]],
    public_schemas: &[[u8; 32]],
    caps: &IndependentArchiveCaps,
) -> Result<IndependentCpf1Fixture, BundleContractErrorV1> {
    let fields = independent_profile_array(value, 17)?;
    let case_id = independent_profile_text(&fields[0], 128)?.to_owned();
    let mandatory = match &fields[1] {
        Value::Bool(value) => *value,
        _ => return Err(BundleContractErrorV1::ProfileInvalid),
    };
    let claim_layer = independent_profile_claim_layer(&fields[2])?;
    let execution_profile = independent_profile_digest(&fields[3])?;
    let public_schema = independent_profile_digest(&fields[4])?;
    if public_schema == [0; 32]
        || !execution_profiles.contains(&execution_profile)
        || !public_schemas.contains(&public_schema)
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let modes = independent_profile_modes(&fields[5])?;
    independent_profile_adapter(&fields[6])?;
    let inputs = independent_verify_cpf1_fixture_inputs(&fields[7], caps)?;
    let (expected_kind, expected_bytes) = independent_verify_cpf1_expected(&fields[8], allowed)?;
    independent_verify_cpf1_fixture_outcome(expected_kind, &fields[9], &fields[10])?;
    independent_verify_cpf1_fixture_claim(&fields[11], &fields[12])?;
    independent_verify_cpf1_bounds(&fields[13])?;
    independent_verify_cpf1_expected_bounds(&fields[8], &fields[13], caps)?;
    let network_enabled = independent_verify_cpf1_capabilities(&fields[14])?;
    let provenance = independent_verify_cpf1_provenance(&fields[15])?;
    if independent_profile_digest(&fields[16])? == [0; 32]
        || (modes.contains(&1) && network_enabled)
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(IndependentCpf1Fixture {
        case_id,
        mandatory,
        claim_layer,
        execution_profile_digest: execution_profile,
        public_schema_digest: public_schema,
        modes,
        inputs,
        expected_bytes,
        provenance,
    })
}

fn independent_verify_cpf1_fixture_inputs(
    value: &Value,
    caps: &IndependentArchiveCaps,
) -> Result<Vec<IndependentCpf1Input>, BundleContractErrorV1> {
    let inputs = independent_profile_array_bounded(value)?;
    let mut previous = None;
    let mut verified = Vec::with_capacity(inputs.len());
    for input in inputs {
        let fields = independent_profile_array(input, 4)?;
        let member_id = independent_profile_ascii(&fields[0], 256)?.to_owned();
        let size = independent_profile_u64(&fields[1])?;
        let digest = independent_profile_digest(&fields[2])?;
        let provenance_digest = independent_profile_digest(&fields[3])?;
        if size == 0
            || size > MAX_MEMBER_BYTES
            || size > caps.member_bytes
            || u64::try_from(member_id.len()).unwrap_or(u64::MAX) > caps.member_path_bytes
            || digest == [0; 32]
            || provenance_digest == [0; 32]
            || previous
                .as_ref()
                .is_some_and(|prior: &String| prior >= &member_id)
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        verified.push(IndependentCpf1Input {
            member_id: member_id.clone(),
            size,
            digest,
        });
        previous = Some(member_id);
    }
    Ok(verified)
}

#[derive(Clone, Copy)]
enum IndependentExpectedKind {
    CanonicalBytes,
    TypedFailure(u64),
    AllowedDivergence,
}

fn independent_verify_cpf1_expected(
    value: &Value,
    allowed: &[(u64, Vec<u8>)],
) -> Result<(IndependentExpectedKind, Vec<u8>), BundleContractErrorV1> {
    let fields = independent_profile_array(value, 5)?;
    match independent_profile_u64(&fields[0])? {
        0 => {
            let bytes = independent_profile_bytes(&fields[1])?;
            if bytes.is_empty() {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            if *blake3::hash(bytes).as_bytes() != independent_profile_digest(&fields[2])? {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            Ok((IndependentExpectedKind::CanonicalBytes, bytes.to_vec()))
        }
        1 => independent_profile_safe_error(&fields[3]).and_then(|error| {
            encode_archive_value(value)
                .map(|bytes| (IndependentExpectedKind::TypedFailure(error), bytes))
        }),
        2 => {
            let divergence = independent_profile_array(&fields[4], 2)?;
            let classification = independent_profile_divergence(&divergence[0])?;
            let coordinate = independent_profile_bytes(&divergence[1])?;
            if !allowed
                .iter()
                .any(|value| value.0 == classification && value.1.as_slice() == coordinate)
            {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            encode_archive_value(value)
                .map(|bytes| (IndependentExpectedKind::AllowedDivergence, bytes))
        }
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn independent_verify_cpf1_fixture_outcome(
    expected_kind: IndependentExpectedKind,
    outcome: &Value,
    error: &Value,
) -> Result<(), BundleContractErrorV1> {
    let outcome = independent_profile_outcome(outcome)?;
    let error = independent_profile_optional_safe_error(error)?;
    if independent_outcome_matches_expected(expected_kind, outcome, error) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_outcome_matches_expected(
    expected_kind: IndependentExpectedKind,
    outcome: u64,
    error: Option<u64>,
) -> bool {
    match expected_kind {
        IndependentExpectedKind::CanonicalBytes => {
            (outcome == 0 && error.is_none()) || (outcome == 3 && error == Some(12))
        }
        IndependentExpectedKind::TypedFailure(expected) => match (outcome, error) {
            (2 | 4 | 5, Some(error)) => error == expected,
            (3, Some(12)) => expected == 12,
            _ => false,
        },
        IndependentExpectedKind::AllowedDivergence => outcome == 1 && error.is_none(),
    }
}

fn independent_verify_cpf1_fixture_claim(
    replay_claim: &Value,
    redaction: &Value,
) -> Result<(), BundleContractErrorV1> {
    let claim = independent_profile_replay_claim(replay_claim)?;
    let redaction = independent_profile_redaction(redaction)?;
    if claim == 4 || matches!((claim, redaction), (0, 0) | (1, 1) | (2, 2) | (3, 3)) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_verify_cpf1_expected_bounds(
    expected: &Value,
    bounds: &Value,
    caps: &IndependentArchiveCaps,
) -> Result<(), BundleContractErrorV1> {
    independent_profile_array(expected, 5).and_then(|expected| {
        independent_profile_u64(&expected[0]).and_then(|kind| {
            if kind == 0 {
                independent_profile_bytes(&expected[1]).and_then(|bytes| {
                    independent_profile_array(bounds, 8).and_then(|bounds| {
                        independent_profile_u64(&bounds[3]).and_then(|maximum| {
                            let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                            if length > maximum || length > caps.member_bytes {
                                Err(BundleContractErrorV1::ProfileInvalid)
                            } else {
                                Ok(())
                            }
                        })
                    })
                })
            } else {
                Ok(())
            }
        })
    })
}

fn independent_verify_cpf1_bounds(value: &Value) -> Result<(), BundleContractErrorV1> {
    if independent_profile_array(value, 8)?
        .iter()
        .map(independent_profile_u64)
        .collect::<Result<Vec<_>, _>>()?
        .contains(&0)
    {
        Err(BundleContractErrorV1::ProfileInvalid)
    } else {
        Ok(())
    }
}

fn independent_verify_cpf1_capabilities(value: &Value) -> Result<bool, BundleContractErrorV1> {
    let fields = independent_profile_array(value, 2)?;
    let network_enabled = match &fields[0] {
        Value::Bool(value) => *value,
        _ => return Err(BundleContractErrorV1::ProfileInvalid),
    };
    let ids = independent_profile_array_bounded(&fields[1])?
        .iter()
        .map(|value| independent_profile_text(value, 128).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if independent_strictly_ordered(&ids) {
        Ok(network_enabled)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_verify_cpf1_provenance(
    value: &Value,
) -> Result<IndependentCpf1Provenance, BundleContractErrorV1> {
    independent_profile_array(value, 7).and_then(|fields| {
        independent_profile_text(&fields[0], 128).and_then(|licence_id| {
            fields[1..]
                .iter()
                .map(independent_profile_digest)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|digests| {
                    if digests.contains(&[0; 32]) {
                        Err(BundleContractErrorV1::ProfileInvalid)
                    } else {
                        Ok(IndependentCpf1Provenance {
                            licence_id: licence_id.to_owned(),
                            notices_digest: digests[0],
                            sbom_digest: digests[1],
                            source_digest: digests[2],
                            build_digest: digests[3],
                            publication_review_digest: digests[4],
                            limitations_digest: digests[5],
                        })
                    }
                })
        })
    })
}

fn independent_verify_cpf1_selected_caps(
    fixture_count: usize,
    caps: &IndependentArchiveCaps,
) -> Result<(), BundleContractErrorV1> {
    if u64::try_from(fixture_count).unwrap_or(u64::MAX) > caps.cases {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(())
}

fn independent_verify_cpf1_digest(fields: &[Value]) -> Result<[u8; 32], BundleContractErrorV1> {
    independent_profile_digest(&fields[17]).and_then(|expected| {
        independent_cpf1_digest(
            b"PiglorOS.ConformanceProfileStableEvidence.v1",
            &Value::Array(Vec::new()),
        )
        .and_then(|stable_evidence| {
            let mut identity = fields.to_vec();
            identity[17] = Value::Null;
            independent_cpf1_digest(
                b"PiglorOS.ConformanceProfile.v1",
                &Value::Array(vec![
                    Value::Array(identity),
                    Value::Bytes(stable_evidence.to_vec()),
                ]),
            )
        })
        .and_then(|actual| {
            if expected == actual {
                Ok(expected)
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn independent_profile_array(
    value: &Value,
    length: usize,
) -> Result<&[Value], BundleContractErrorV1> {
    independent_array(value, length).map_err(|_| BundleContractErrorV1::ProfileInvalid)
}

fn independent_profile_array_bounded(value: &Value) -> Result<&[Value], BundleContractErrorV1> {
    independent_array_bounded(value).map_err(|_| BundleContractErrorV1::ProfileInvalid)
}

fn independent_profile_text(value: &Value, maximum: usize) -> Result<&str, BundleContractErrorV1> {
    let text = archive_text(value).map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    if text.is_empty() {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    if text.len() > maximum {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    Ok(text)
}

fn independent_profile_ascii(value: &Value, maximum: usize) -> Result<&str, BundleContractErrorV1> {
    let text = independent_profile_text(value, maximum)?;
    if text.is_ascii() {
        Ok(text)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_bytes(value: &Value) -> Result<&[u8], BundleContractErrorV1> {
    archive_bytes(value).map_err(|_| BundleContractErrorV1::ProfileInvalid)
}

fn independent_profile_u64(value: &Value) -> Result<u64, BundleContractErrorV1> {
    archive_u64(value).map_err(|_| BundleContractErrorV1::ProfileInvalid)
}

fn independent_profile_digest(value: &Value) -> Result<[u8; 32], BundleContractErrorV1> {
    independent_digest(value).map_err(|_| BundleContractErrorV1::ProfileInvalid)
}

fn independent_profile_claim_layer(value: &Value) -> Result<u64, BundleContractErrorV1> {
    let code = independent_profile_u64(value)?;
    if code <= 6 {
        Ok(code)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_modes(value: &Value) -> Result<Vec<u64>, BundleContractErrorV1> {
    let modes = independent_profile_array_bounded(value)?
        .iter()
        .map(independent_profile_u64)
        .collect::<Result<Vec<_>, _>>()?;
    if modes.is_empty()
        || modes.iter().any(|mode| *mode > 3)
        || !independent_strictly_ordered(&modes)
    {
        Err(BundleContractErrorV1::ProfileInvalid)
    } else {
        Ok(modes)
    }
}

fn independent_profile_adapter(value: &Value) -> Result<(), BundleContractErrorV1> {
    if independent_profile_u64(value)? <= 2 {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_divergence(value: &Value) -> Result<u64, BundleContractErrorV1> {
    let code = independent_profile_u64(value)?;
    if code <= 8 {
        Ok(code)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_safe_error(value: &Value) -> Result<u64, BundleContractErrorV1> {
    let code = independent_profile_u64(value)?;
    if code <= 13 {
        Ok(code)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_optional_safe_error(
    value: &Value,
) -> Result<Option<u64>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        independent_profile_safe_error(value).map(Some)
    }
}

fn independent_profile_outcome(value: &Value) -> Result<u64, BundleContractErrorV1> {
    let code = independent_profile_u64(value)?;
    if code <= 5 {
        Ok(code)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_replay_claim(value: &Value) -> Result<u64, BundleContractErrorV1> {
    let code = independent_profile_u64(value)?;
    if code <= 4 {
        Ok(code)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_redaction(value: &Value) -> Result<u64, BundleContractErrorV1> {
    let code = independent_profile_u64(value)?;
    if code <= 3 {
        Ok(code)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn independent_profile_digests(value: &Value) -> Result<Vec<[u8; 32]>, BundleContractErrorV1> {
    independent_profile_array_bounded(value)?
        .iter()
        .map(independent_profile_digest)
        .collect()
}

fn independent_strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn independent_semantic_version(value: &str) -> bool {
    let (core_and_prerelease, build) = match value.split_once('+') {
        Some((core, build)) if !build.is_empty() => (core, build),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, prerelease) = match core_and_prerelease.split_once('-') {
        Some((core, prerelease)) if !prerelease.is_empty() => (core, prerelease),
        Some(_) => return false,
        None => (core_and_prerelease, ""),
    };
    let core_parts = core.split('.').collect::<Vec<_>>();
    core_parts.len() == 3
        && core_parts
            .iter()
            .all(|part| independent_numeric_identifier(part))
        && independent_semver_identifiers(prerelease, true)
        && independent_semver_identifiers(build, false)
}

fn independent_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn independent_semver_identifiers(value: &str, forbid_numeric_leading_zero: bool) -> bool {
    value.is_empty()
        || value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!forbid_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || independent_numeric_identifier(identifier))
        })
}

fn independent_cpf1_digest(
    domain: &[u8],
    value: &Value,
) -> Result<[u8; 32], BundleContractErrorV1> {
    encode_archive_value(value).map(|bytes| {
        let mut source = Vec::with_capacity(domain.len() + bytes.len() + 1);
        source.extend_from_slice(domain);
        source.push(0);
        source.extend_from_slice(&bytes);
        *blake3::hash(&source).as_bytes()
    })
}

fn independent_array(value: &Value, length: usize) -> Result<&[Value], BundleContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn independent_array_bounded(value: &Value) -> Result<&[Value], BundleContractErrorV1> {
    // `verify_archive_independently` preflights every array against
    // `MAX_MEMBERS` before decoding. Rechecking the same bound here would be
    // unreachable through the public verifier and would duplicate the parser's
    // resource limit.
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(BundleContractErrorV1::ArchiveEncodingInvalid),
    }
}

fn independent_digest<const N: usize>(value: &Value) -> Result<[u8; N], BundleContractErrorV1> {
    archive_bytes(value)?
        .try_into()
        .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
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
    encode_archive_value_to_writer(value, &mut bytes).map(|()| bytes)
}

fn encode_archive_value_to_writer<T: serde::Serialize, W: std::io::Write>(
    value: &T,
    writer: W,
) -> Result<(), BundleContractErrorV1> {
    ciborium::into_writer(value, writer).map_err(|_| BundleContractErrorV1::EncodingFailed)
}

struct ArchivePreflight<'a> {
    profile_bytes: Option<&'a [u8]>,
    member_count: usize,
    largest_member_bytes: u64,
    largest_member_path_bytes: usize,
}

struct ScannedArchiveItem<'a> {
    bytes: Option<&'a [u8]>,
    text_bytes: Option<usize>,
    unsigned: Option<u64>,
}

struct IndependentArchiveCaps {
    profile_bytes: u64,
    cases: u64,
    bundle_members: u64,
    member_path_bytes: u64,
    member_bytes: u64,
    total_bundle_bytes: u64,
    coordinate_bytes: u64,
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
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
        Ok(length)
    }

    fn item<'a>(
        bytes: &'a [u8],
        index: &mut usize,
        depth: usize,
    ) -> Result<ScannedArchiveItem<'a>, BundleContractErrorV1> {
        if depth > usize::from(MAX_STRUCTURAL_NESTING) {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
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
        };
        match major {
            0 => scanned.unsigned = Some(item_length),
            1 => {}
            2 => {
                if item_length > MAX_MEMBER_BYTES {
                    return Err(BundleContractErrorV1::MemberOutOfBounds);
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
                    return Err(BundleContractErrorV1::MemberOutOfBounds);
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
                    return Err(BundleContractErrorV1::MemberOutOfBounds);
                }
                for _ in 0..item_length {
                    item(bytes, index, depth + 1)?;
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
    ) -> Result<ArchivePreflight<'a>, BundleContractErrorV1> {
        let member_count = array_length(bytes, index)?;
        let mut result = ArchivePreflight {
            profile_bytes: None,
            member_count: usize::try_from(member_count).unwrap_or(usize::MAX),
            largest_member_bytes: 0,
            largest_member_path_bytes: 0,
        };
        for _ in 0..member_count {
            if array_length(bytes, index)? != 3 {
                return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
            }
            let path = item(bytes, index, 4)?;
            let member = item(bytes, index, 4)?;
            let role = item(bytes, index, 4)?;
            let path_bytes = path
                .text_bytes
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
            let member_bytes = member
                .bytes
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
            let role = role
                .unsigned
                .ok_or(BundleContractErrorV1::ArchiveEncodingInvalid)?;
            result.largest_member_path_bytes = result.largest_member_path_bytes.max(path_bytes);
            result.largest_member_bytes = result
                .largest_member_bytes
                .max(u64::try_from(member_bytes.len()).unwrap_or(u64::MAX));
            if role == BundleMemberRoleV1::Profile.code()
                && result.profile_bytes.replace(member_bytes).is_some()
            {
                return Err(BundleContractErrorV1::MemberMissing);
            }
        }
        Ok(result)
    }

    pub(super) fn scan(bytes: &[u8]) -> Result<ArchivePreflight<'_>, BundleContractErrorV1> {
        let mut index = 0;
        if array_length(bytes, &mut index)? != 6 {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        for _ in 0..3 {
            item(bytes, &mut index, 2)?;
        }
        let result = members(bytes, &mut index)?;
        for _ in 0..2 {
            item(bytes, &mut index, 2)?;
        }
        if index != bytes.len() {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
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
    if u64::try_from(encoded_len).unwrap_or(u64::MAX) > caps.max_total_bundle_bytes {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    if preflight.member_count > usize::try_from(caps.max_bundle_members).unwrap_or(usize::MAX) {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    if preflight.largest_member_path_bytes > usize::from(caps.max_member_path_bytes) {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    if preflight.largest_member_bytes > caps.max_member_bytes {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    caps.validate_compression_expansion(
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
    )
    .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)
}

fn independent_archive_profile(
    profile_bytes: &[u8],
) -> Result<(Value, IndependentArchiveCaps), BundleContractErrorV1> {
    let profile: Value = ciborium::from_reader(Cursor::new(profile_bytes))
        .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    if !encode_archive_value(&profile)
        .is_ok_and(|canonical_bytes| canonical_bytes.as_slice() == profile_bytes)
    {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let fields =
        independent_array(&profile, 18).map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    let protocol =
        independent_array(&fields[11], 5).map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
    if independent_profile_text(&protocol[0], 128).is_err() {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    if [1_usize, 2, 3].iter().any(|index| {
        !matches!(
            independent_profile_digest(&protocol[*index]),
            Ok(digest) if digest != [0; 32]
        )
    }) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
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
    let max_coordinate_bytes = &values[8];
    let max_log_bytes = &values[9];
    let bounded_caps = [
        (*max_profile_bytes, MAX_PROFILE_BYTES),
        (*max_cases, u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX)),
        (
            *max_bundle_members,
            u64::try_from(MAX_MEMBERS).unwrap_or(u64::MAX),
        ),
        (
            *max_member_path_bytes,
            u64::try_from(MAX_MEMBER_PATH_BYTES).unwrap_or(u64::MAX),
        ),
        (*max_member_bytes, MAX_MEMBER_BYTES),
        (*max_total_bundle_bytes, MAX_TOTAL_BUNDLE_BYTES),
        (*max_compression_expansion, 100),
        (*max_structural_nesting, u64::from(MAX_STRUCTURAL_NESTING)),
        (*max_coordinate_bytes, 128),
    ];
    if bounded_caps.iter().any(|(value, _)| *value == 0) {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    if bounded_caps.iter().any(|(value, maximum)| value > maximum) {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    if *max_log_bytes > 1024 * 1024 {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    Ok((
        profile,
        IndependentArchiveCaps {
            profile_bytes: *max_profile_bytes,
            cases: *max_cases,
            bundle_members: *max_bundle_members,
            member_path_bytes: *max_member_path_bytes,
            member_bytes: *max_member_bytes,
            total_bundle_bytes: *max_total_bundle_bytes,
            coordinate_bytes: *max_coordinate_bytes,
        },
    ))
}

fn validate_independent_preflight_caps(
    caps: &IndependentArchiveCaps,
    preflight: &ArchivePreflight<'_>,
    encoded_len: usize,
) -> Result<(), BundleContractErrorV1> {
    let encoded_len = u64::try_from(encoded_len).unwrap_or(u64::MAX);
    let limits_exceeded = [
        encoded_len > caps.total_bundle_bytes,
        u64::try_from(preflight.profile_bytes.map_or(0, <[u8]>::len)).unwrap_or(u64::MAX)
            > caps.profile_bytes,
        u64::try_from(preflight.member_count).unwrap_or(u64::MAX) > caps.bundle_members,
        u64::try_from(preflight.largest_member_path_bytes).unwrap_or(u64::MAX)
            > caps.member_path_bytes,
        preflight.largest_member_bytes > caps.member_bytes,
    ];
    if limits_exceeded.contains(&true) {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    }
    Ok(())
}

fn validate_archive_caps(
    profile: &ConformanceProfileV1,
    encoded_len: usize,
) -> Result<(), BundleContractErrorV1> {
    let caps = &profile.evaluator_protocol.hard_caps;
    if u64::try_from(encoded_len).unwrap_or(u64::MAX) > caps.max_total_bundle_bytes {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    caps.validate_compression_expansion(
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
    )
    .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)
}

fn decode_manifest(value: &Value) -> Result<BundleManifestV1, BundleContractErrorV1> {
    archive_array_exact(value, 6).and_then(|fields| {
        archive_array(&fields[4])
            .and_then(|values| {
                values
                    .iter()
                    .map(decode_member_descriptor)
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|members| {
                archive_array(&fields[5])
                    .and_then(|values| {
                        values
                            .iter()
                            .map(decode_expected_result)
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .and_then(|expected_results| {
                        decode_manifest_header(fields, members, expected_results)
                    })
            })
    })
}

fn decode_member_descriptor(
    value: &Value,
) -> Result<BundleMemberDescriptorV1, BundleContractErrorV1> {
    archive_array_exact(value, 4).and_then(|fields| {
        archive_text(&fields[0]).and_then(|path| {
            archive_u64(&fields[1]).and_then(|size_bytes| {
                archive_digest(&fields[2]).and_then(|digest| {
                    archive_u64(&fields[3])
                        .and_then(decode_member_role)
                        .map(|role| BundleMemberDescriptorV1 {
                            path: path.to_owned(),
                            size_bytes,
                            digest,
                            role,
                        })
                })
            })
        })
    })
}

fn decode_expected_result(value: &Value) -> Result<BundleExpectedResultV1, BundleContractErrorV1> {
    archive_array_exact(value, 6).and_then(|fields| {
        archive_text(&fields[0]).and_then(|case_id| {
            archive_u64(&fields[1])
                .and_then(decode_claim_layer)
                .and_then(|claim_layer| {
                    archive_digest(&fields[2]).and_then(|execution_profile_digest| {
                        archive_u64(&fields[3])
                            .and_then(decode_bundle_mode)
                            .and_then(|mode| {
                                archive_text(&fields[4]).and_then(|member_path| {
                                    archive_digest(&fields[5]).map(|digest| {
                                        BundleExpectedResultV1 {
                                            case_id: case_id.to_owned(),
                                            claim_layer,
                                            execution_profile_digest,
                                            mode,
                                            member_path: member_path.to_owned(),
                                            digest,
                                        }
                                    })
                                })
                            })
                    })
                })
        })
    })
}

fn decode_manifest_header(
    fields: &[Value],
    members: Vec<BundleMemberDescriptorV1>,
    expected_results: Vec<BundleExpectedResultV1>,
) -> Result<BundleManifestV1, BundleContractErrorV1> {
    archive_text(&fields[0]).and_then(|magic| {
        archive_u64(&fields[1])
            .and_then(decode_lifecycle)
            .and_then(|lifecycle| {
                archive_u64(&fields[2])
                    .and_then(decode_bundle_mode)
                    .and_then(|mode| {
                        archive_digest(&fields[3]).map(|profile_digest| BundleManifestV1 {
                            magic: magic.to_owned(),
                            lifecycle,
                            mode,
                            profile_digest,
                            members,
                            expected_results,
                        })
                    })
            })
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

fn archive_array(value: &Value) -> Result<&[Value], BundleContractErrorV1> {
    // The raw-byte preflight rejects arrays larger than `MAX_MEMBERS` before
    // CBOR decoding. Repeating that limit here would be unreachable through
    // the public decoder and would duplicate the allocation boundary.
    match value {
        Value::Array(values) => Ok(values),
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
            if member.role != BundleMemberRoleV1::FixtureInput {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if member.bytes.is_empty() {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            if member.bytes.len() as u64 != input.size_bytes {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            if member.digest != input.digest {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            if member.digest != *blake3::hash(&member.bytes).as_bytes() {
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
        if self.local.manifest.profile_digest != self.air_gapped.manifest.profile_digest {
            return Err(BundleContractErrorV1::ModeParityMismatch);
        }
        if self.local.manifest.mode != BundleModeV1::Local {
            return Err(BundleContractErrorV1::ModeParityMismatch);
        }
        if self.air_gapped.manifest.mode != BundleModeV1::AirGapped {
            return Err(BundleContractErrorV1::ModeParityMismatch);
        }
        // Each validated bundle binds authority inventory and execution-matrix
        // bytes through the shared profile digest. Expected-result presence is
        // compared separately because optional cases may be executed in only
        // one mode.
        if expected_identity(&self.local.manifest.expected_results)
            != expected_identity(&self.air_gapped.manifest.expected_results)
        {
            return Err(BundleContractErrorV1::ModeParityMismatch);
        }
        Ok(())
    }
}

fn validate_expected_results(
    profile: &ConformanceProfileV1,
    manifest: &BundleManifestV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    if !crate::strictly_ordered(&manifest.expected_results) {
        return Err(BundleContractErrorV1::NonCanonicalOrder);
    }
    for expected in &manifest.expected_results {
        if expected.mode != manifest.mode {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        if expected.digest == [0; 32] {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let Some(member) = members
            .iter()
            .find(|member| member.path == expected.member_path)
        else {
            return Err(BundleContractErrorV1::MemberMissing);
        };
        if member.role != BundleMemberRoleV1::ExpectedResult {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        if member.bytes.is_empty() {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        if member.digest != expected.digest {
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
                if *digest != expected.digest {
                    return Err(BundleContractErrorV1::ExpectedResultMismatch);
                }
                bytes.clone()
            }
            typed_or_divergent => typed_or_divergent
                .to_canonical_bytes()
                .map_err(|_| BundleContractErrorV1::EncodingFailed)?,
        };
        if member.bytes != expected_bytes {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
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
        .map(|value| ExpectedIdentityRecord {
            case_id: value.case_id.as_str(),
            claim_layer: value.claim_layer,
            digest: value.digest,
        })
        .collect::<Vec<_>>();
    identity.sort_unstable();
    ExpectedIdentity(identity)
}

#[derive(Eq, PartialEq)]
struct ExpectedIdentity<'a>(Vec<ExpectedIdentityRecord<'a>>);

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct ExpectedIdentityRecord<'a> {
    case_id: &'a str,
    claim_layer: ClaimLayerV1,
    digest: [u8; 32],
}

fn validate_supporting_members(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    for (support_role, member_role, path) in SUPPORT_MEMBERS {
        let matching = members
            .iter()
            .filter(|member| member.role == member_role && member.path == path)
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].bytes.is_empty() {
            return Err(BundleContractErrorV1::MemberMissing);
        }
        if !required_support_digests(profile, support_role).contains(&matching[0].digest) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    if members
        .iter()
        .filter(|member| member.role.is_supporting())
        .count()
        != SUPPORT_MEMBERS.len()
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
        .filter(|member| member.role == BundleMemberRoleV1::Provenance)
        .find(|member| member.digest == profile.provenance_digest)
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
    if profile.execution_matrix_digest == [0; 32]
        || profile.execution_matrix_digest != *blake3::hash(&matrix.bytes).as_bytes()
    {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
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
    let [member] = matched.as_slice() else {
        return Err(BundleContractErrorV1::MemberMissing);
    };
    if member.path != path {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    if member.bytes.is_empty() {
        Err(BundleContractErrorV1::MemberMissing)
    } else {
        Ok(member)
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

fn json_has_exact_keys(value: &JsonValue, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key))
    })
}

fn validate_provenance_authority_binding(
    provenance: &JsonValue,
) -> Result<(), BundleContractErrorV1> {
    json_object(provenance, "authority_inventory").and_then(|inventory| {
        json_object(provenance, "adr_059_execution_matrix").and_then(|matrix| {
            let valid = [
                json_text(inventory, "path") == Ok("expected-authority/inventory.json"),
                json_text(inventory, "digest_algorithm") == Ok("SHA-256"),
                json_text(inventory, "status") == Ok("Draft"),
                json_text(matrix, "path") == Ok("matrix/execution-matrix.json"),
                json_text(matrix, "digest_algorithm") == Ok("BLAKE3-256"),
                json_text(matrix, "status") == Ok("Draft"),
                json_u64(matrix, "executed_case_count") == Ok(0),
            ];
            if valid.contains(&false) {
                Err(BundleContractErrorV1::MemberDigestMismatch)
            } else {
                Ok(())
            }
        })
    })
}

fn validate_authority_inventory_digest(
    provenance: &JsonValue,
    inventory_bytes: &[u8],
) -> Result<(), BundleContractErrorV1> {
    let actual: [u8; 32] = Sha256::digest(inventory_bytes).into();
    declared_provenance_digest(provenance, "authority_inventory", "sha256_digest").and_then(
        |declared| {
            if declared == actual {
                Ok(())
            } else {
                Err(BundleContractErrorV1::MemberDigestMismatch)
            }
        },
    )
}

fn validate_matrix_provenance_digest(
    provenance: &JsonValue,
    matrix_bytes: &[u8],
) -> Result<(), BundleContractErrorV1> {
    declared_provenance_digest(provenance, "adr_059_execution_matrix", "blake3_digest").and_then(
        |declared| {
            if declared == *blake3::hash(matrix_bytes).as_bytes() {
                Ok(())
            } else {
                Err(BundleContractErrorV1::MemberDigestMismatch)
            }
        },
    )
}

fn declared_provenance_digest(
    provenance: &JsonValue,
    section: &str,
    field: &str,
) -> Result<[u8; 32], BundleContractErrorV1> {
    json_object(provenance, section)
        .and_then(|record| json_text(record, field))
        .and_then(|encoded| {
            crate::decode_hex_digest(encoded).ok_or(BundleContractErrorV1::MemberDigestMismatch)
        })
}

fn validate_authority_inventory(inventory: &JsonValue) -> Result<(), BundleContractErrorV1> {
    let valid_header = [
        json_has_exact_keys(inventory, &AUTHORITY_INVENTORY_KEYS),
        json_text(inventory, "magic") == Ok("W8H1"),
        json_u64(inventory, "version") == Ok(1),
        json_text(inventory, "lifecycle") == Ok("Draft"),
        json_text(inventory, "digest_algorithm") == Ok("BLAKE3-256"),
    ];
    if valid_header.contains(&false) {
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
    for entry in entries {
        let valid_entry = [
            json_has_exact_keys(entry, &AUTHORITY_INVENTORY_ENTRY_KEYS),
            json_text(entry, "materialization_status") == Ok("pending"),
            entry
                .get("fixture_bytes_path")
                .is_some_and(JsonValue::is_null),
            entry
                .get("fixture_bytes_digest")
                .is_some_and(JsonValue::is_null),
            entry
                .get("expected_result_path")
                .is_some_and(JsonValue::is_null),
            entry
                .get("expected_result_digest")
                .is_some_and(JsonValue::is_null),
        ];
        if valid_entry.contains(&false) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
}

fn validate_execution_matrix(matrix: &JsonValue) -> Result<(), BundleContractErrorV1> {
    if !json_has_exact_keys(matrix, &EXECUTION_MATRIX_KEYS) {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let rows = matrix
        .get("rows")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    let cases = matrix
        .get("cases")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    let valid_header = [
        json_text(matrix, "magic") == Ok("NIM1"),
        json_u64(matrix, "version") == Ok(1),
        json_text(matrix, "lifecycle") == Ok("Draft"),
        json_u64(matrix, "row_count") == Ok(12),
        json_u64(matrix, "variant_count") == Ok(4),
        json_u64(matrix, "mode_count") == Ok(4),
        json_u64(matrix, "case_count") == Ok(192),
        json_u64(matrix, "executed_case_count") == Ok(0),
        rows.len() == 12,
        cases.len() == 192,
    ];
    if valid_header.contains(&false) {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    validate_execution_matrix_rows(rows)?;
    validate_execution_matrix_cases(cases)?;
    if !matrix_cases_are_open(cases) {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let predicates = matrix
        .get("equality_predicates")
        .and_then(JsonValue::as_array)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    validate_execution_matrix_predicates(predicates)
}

fn validate_execution_matrix_rows(rows: &[JsonValue]) -> Result<(), BundleContractErrorV1> {
    for (index, row) in rows.iter().enumerate() {
        let valid_row = [
            json_has_exact_keys(row, &EXECUTION_MATRIX_ROW_KEYS),
            json_text(row, "fixture_id") == Ok(NON_INTERFERENCE_ROW_IDS[index]),
            json_string_array(row, "variants")
                .is_ok_and(|value| value == NON_INTERFERENCE_VARIANTS),
            json_string_array(row, "modes").is_ok_and(|value| value == NON_INTERFERENCE_MODES),
            json_u64(row, "case_count") == Ok(16),
            json_u64(row, "executed_case_count") == Ok(0),
        ];
        if valid_row.contains(&false) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
}

fn validate_execution_matrix_cases(cases: &[JsonValue]) -> Result<(), BundleContractErrorV1> {
    for (index, case) in cases.iter().enumerate() {
        let row_index = index / 16;
        let variant_index = (index % 16) / 4;
        let mode_index = index % 4;
        let expected_case_id = format!(
            "{}-{}-{}",
            NON_INTERFERENCE_ROW_IDS[row_index],
            NON_INTERFERENCE_VARIANTS[variant_index],
            NON_INTERFERENCE_MODES[mode_index]
        );
        let valid_case = [
            json_has_exact_keys(case, &EXECUTION_MATRIX_CASE_KEYS),
            json_text(case, "fixture_id") == Ok(NON_INTERFERENCE_ROW_IDS[row_index]),
            json_text(case, "variant") == Ok(NON_INTERFERENCE_VARIANTS[variant_index]),
            json_text(case, "mode") == Ok(NON_INTERFERENCE_MODES[mode_index]),
            json_text(case, "case_id").is_ok_and(|value| value == expected_case_id),
        ];
        if valid_case.contains(&false) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
}

fn validate_execution_matrix_predicates(
    predicates: &[JsonValue],
) -> Result<(), BundleContractErrorV1> {
    if predicates.len() != NON_INTERFERENCE_ROW_IDS.len() {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    for (index, predicate) in predicates.iter().enumerate() {
        let valid_predicate = [
            json_has_exact_keys(predicate, &EXECUTION_MATRIX_PREDICATE_KEYS),
            json_text(predicate, "fixture_id") == Ok(NON_INTERFERENCE_ROW_IDS[index]),
            json_text(predicate, "AuthEq") == Ok(NON_INTERFERENCE_AUTH_EQ),
            json_text(predicate, "PublicEq") == Ok(NON_INTERFERENCE_PUBLIC_EQ[index]),
            json_text(predicate, "OpEq") == Ok(NON_INTERFERENCE_OP_EQ[index]),
        ];
        if valid_predicate.contains(&false) {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
    }
    Ok(())
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
    role: SupportRole,
) -> BTreeSet<[u8; 32]> {
    let mut digests = BTreeSet::new();
    match role {
        SupportRole::NormativeSpecification => {
            digests.insert(profile.normative_spec_digest);
        }
        SupportRole::Schema => {
            digests.extend(profile.public_schema_digests.iter().copied());
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.public_schema_digest),
            );
        }
        SupportRole::Licence => {
            digests.extend(profile.fixtures.iter().map(|fixture| {
                let identity = format!("{}\n", fixture.provenance.licence_id);
                *blake3::hash(identity.as_bytes()).as_bytes()
            }));
        }
        SupportRole::Notice => {
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.provenance.notices_digest),
            );
        }
        SupportRole::Sbom => {
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.provenance.sbom_digest),
            );
        }
        SupportRole::Provenance => {
            digests.insert(profile.provenance_digest);
            digests.extend(profile.fixtures.iter().flat_map(|fixture| {
                [
                    fixture.provenance.source_digest,
                    fixture.provenance.build_digest,
                    fixture.provenance.publication_review_digest,
                ]
            }));
        }
        SupportRole::Limitations => {
            digests.insert(profile.limitations_digest);
            digests.extend(
                profile
                    .fixtures
                    .iter()
                    .map(|fixture| fixture.provenance.limitations_digest),
            );
        }
    }
    digests
}

fn validate_selected_bundle_caps(
    profile: &ConformanceProfileV1,
    bundle: &ConformanceBundleV1,
    profile_member: &BundleMemberV1,
) -> Result<(), BundleContractErrorV1> {
    let caps = &profile.evaluator_protocol.hard_caps;
    let bundle_limits_exceeded = [
        u64::try_from(profile_member.bytes.len()).unwrap_or(u64::MAX) > caps.max_profile_bytes,
        MANIFEST_STRUCTURAL_DEPTH_V1 > usize::from(caps.max_structural_nesting),
        bundle.members.len() > usize::try_from(caps.max_bundle_members).unwrap_or(usize::MAX),
    ];
    if bundle_limits_exceeded.contains(&true) {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    let mut total_bytes = 0_u64;
    for member in &bundle.members {
        let member_limits_exceeded = [
            member.path.len() > usize::from(caps.max_member_path_bytes),
            u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) > caps.max_member_bytes,
        ];
        if member_limits_exceeded.contains(&true) {
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
    let invalid_path = [
        path.is_empty(),
        path.len() > MAX_MEMBER_PATH_BYTES,
        path.starts_with('/'),
        !path.is_ascii(),
        path.contains('\\'),
        path.contains(':'),
        path.bytes().any(|byte| byte < 0x20),
        path.bytes().any(|byte| byte == 0x7f),
        path.split('/').any(str::is_empty),
        path.split('/').any(|segment| segment == "."),
        path.split('/').any(|segment| segment == ".."),
    ];
    if invalid_path.contains(&true) {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

fn contains_secret_marker(bytes: &[u8]) -> bool {
    let lowercase = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let textual_marker = [
        b"private key".as_slice(),
        b"private_key".as_slice(),
        b"begin secret".as_slice(),
    ]
    .iter()
    .any(|marker| {
        lowercase
            .windows(marker.len())
            .any(|window| window == *marker)
    });
    [
        textual_marker,
        json_contains_secret_value(bytes),
        standalone_secret_string(bytes),
        contains_prefixed_secret(&lowercase, b"bearer ", 16),
        contains_prefixed_secret(&lowercase, b"basic ", 16),
        contains_prefixed_secret(&lowercase, b"ghp_", 20),
        contains_prefixed_secret(&lowercase, b"github_pat_", 20),
        contains_prefixed_secret(&lowercase, b"glpat-", 20),
        contains_prefixed_secret(&lowercase, b"xoxb-", 20),
        contains_prefixed_secret(&lowercase, b"xoxp-", 20),
        contains_prefixed_secret(&lowercase, b"sk_live_", 16),
        contains_prefixed_secret(&lowercase, b"sk_test_", 16),
        contains_prefixed_secret(&lowercase, b"aiza", 30),
        contains_aws_access_key(&lowercase),
        contains_jwt(&lowercase),
    ]
    .contains(&true)
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

fn members_strictly_ordered(values: &[BundleMemberV1]) -> bool {
    let mut normalized = BTreeSet::new();
    normalized.extend(values.iter().map(|value| value.path.to_ascii_lowercase()));
    normalized.len() == values.len()
        && values
            .windows(2)
            .all(|pair| pair[0].path.as_str().cmp(pair[1].path.as_str()).is_lt())
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
