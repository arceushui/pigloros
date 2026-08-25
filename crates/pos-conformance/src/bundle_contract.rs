//! Signed, content-addressed Draft/Candidate conformance bundles.
//!
//! This boundary materializes public bytes and expected results. It never
//! invokes the implementation under test: callers provide fixture and
//! expected-result members, while this module recomputes their digests,
//! validates them against CPF1, and verifies the bundle signature.

use ciborium::value::Value;
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
const MAX_MEMBER_PATH_BYTES: usize = 256;
const MAX_MEMBERS: usize = 65_536;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_STRUCTURAL_NESTING: u8 = 32;
const PROFILE_MEMBER_PATH: &str = "profile/CPF1.cbor";
const INPUT_MEMBER_PREFIX: &str = "inputs/";
const AUTHORITY_INVENTORY_MEMBER_PATH: &str = "authority/expected-authority-inventory.json";
const EXECUTION_MATRIX_MEMBER_PATH: &str = "authority/adr-059-execution-matrix.json";
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
    /// Only Draft and Candidate bundles may be materialized by this ticket.
    #[error("conformance bundle lifecycle is not Draft or Candidate")]
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
    /// Candidate publication lacks bound deletion and secret-review evidence.
    #[error("Candidate conformance bundle lacks publication review evidence")]
    CandidateEvidenceMissing,
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
    /// One checked-in #172 fixture byte vector named by the authority inventory.
    AuthorityFixture,
    /// One checked-in #172 expected-result byte vector named by the authority inventory.
    AuthorityExpectedResult,
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
            Self::AuthorityFixture => 12,
            Self::AuthorityExpectedResult => 13,
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

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority(path: impl Into<String>, bytes: Vec<u8>, role: BundleMemberRoleV1) -> Self {
        debug_assert!(matches!(
            role,
            BundleMemberRoleV1::AuthorityInventory
                | BundleMemberRoleV1::ExecutionMatrix
                | BundleMemberRoleV1::AuthorityFixture
                | BundleMemberRoleV1::AuthorityExpectedResult
        ));
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
    /// Draft or Candidate lifecycle.
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

/// One signed, immutable Draft or Candidate bundle.
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
    /// pointers cannot form a valid Draft/Candidate bundle.
    pub fn materialize(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
        mut members: Vec<BundleMemberV1>,
        expected_results: Vec<BundleExpectedResultV1>,
    ) -> Result<Self, BundleContractErrorV1> {
        if !matches!(
            profile.lifecycle,
            ProfileLifecycleV1::Draft | ProfileLifecycleV1::Candidate
        ) {
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
        self.validate_unsigned()?;
        let bytes = self.manifest_bytes()?;
        self.signer_public_key = PublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        self.signature = signing::sign(signing_key, &CanonicalBytes::from_vec(bytes));
        self.validate()
            .map(|()| self)
            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
    }

    /// Validate bytes, manifest declarations, profile binding, expected
    /// results, and the cryptographic signature.
    ///
    /// # Errors
    ///
    /// Returns a closed error for any content, archive, profile, or signature
    /// violation.
    pub fn validate(&self) -> Result<(), BundleContractErrorV1> {
        self.validate_unsigned()?;
        let key = signing::verifying_key_from_public_key(&self.signer_public_key)
            .map_err(|_| BundleContractErrorV1::SignatureInvalid)?;
        let bytes = self.manifest_bytes()?;
        signing::verify(&key, &CanonicalBytes::from_vec(bytes), &self.signature)
            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
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
            || !matches!(
                self.manifest.lifecycle,
                ProfileLifecycleV1::Draft | ProfileLifecycleV1::Candidate
            )
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
                    fixture.inputs.iter().any(|input| {
                        member.path
                            == fixture_input_path(
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
            validate_member_size(member.bytes.len() as u64)?;
            total_bytes = total_bytes.saturating_add(descriptor.size_bytes);
            if contains_secret_marker(&member.bytes) {
                return Err(BundleContractErrorV1::SecretMaterialDetected);
            }
        }
        validate_total_bytes(total_bytes)?;
        validate_supporting_members(&profile, &self.members)?;
        validate_authority_members(&profile, &self.members)?;
        if profile.lifecycle == ProfileLifecycleV1::Candidate {
            validate_candidate_publication(&profile, &self.members)?;
        }
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
        self.validate()?;
        let value = bundle_value(self);
        let bytes = encode_archive_value(&value)?;
        validate_archive_caps(self, &value, bytes.len())?;
        Ok(bytes)
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
        let value = ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        let canonical_bytes = encode_archive_value(&value)
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        if canonical_bytes.as_slice() != bytes {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let fields = archive_array_exact(&value, 6)?;
        if archive_text(&fields[0])? != CONFORMANCE_BUNDLE_MAGIC_V1 || archive_u64(&fields[1])? != 1
        {
            return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
        }
        let manifest = decode_manifest(&fields[2])?;
        let members = archive_array_bounded(&fields[3], MAX_MEMBERS)?
            .iter()
            .map(decode_member)
            .collect::<Result<Vec<_>, _>>()?;
        let signer_public_key = archive_digest::<32>(&fields[4])
            .map(PublicKey::from_bytes)
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        let signature = archive_digest::<64>(&fields[5])
            .map(Signature::from_bytes)
            .map_err(|_| BundleContractErrorV1::ArchiveEncodingInvalid)?;
        let bundle = Self {
            manifest,
            members,
            signer_public_key,
            signature,
        };
        validate_archive_caps(&bundle, &value, bytes.len())?;
        preflight_profile
            .evaluator_protocol
            .hard_caps
            .validate_compression_expansion(bytes.len() as u64, bytes.len() as u64)
            .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?;
        bundle.validate().map(|()| bundle)
    }
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

fn encode_archive_value(value: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| BundleContractErrorV1::EncodingFailed)
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
    caps.validate_case_count(u32::try_from(profile.fixtures.len()).unwrap_or(u32::MAX))
        .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)?;
    caps.validate_compression_expansion(
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
        u64::try_from(encoded_len).unwrap_or(u64::MAX),
    )
    .map_err(|_| BundleContractErrorV1::MemberOutOfBounds)
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
    let fields = archive_array_exact(value, 3)?;
    let path = archive_text(&fields[0])?.to_owned();
    let bytes = archive_bytes(&fields[1])?.to_vec();
    let role = decode_member_role(archive_u64(&fields[2])?)?;
    Ok(BundleMemberV1 {
        path,
        digest: *blake3::hash(&bytes).as_bytes(),
        bytes,
        role,
        expected_result: role == BundleMemberRoleV1::ExpectedResult,
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
        12 => Ok(BundleMemberRoleV1::AuthorityFixture),
        13 => Ok(BundleMemberRoleV1::AuthorityExpectedResult),
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
        Err(BundleContractErrorV1::LifecycleInvalid)
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

fn fixture_input_path(
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

fn expected_member_path(
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

fn validate_fixture_inputs_for_mode(
    profile: &ConformanceProfileV1,
    mode: Option<BundleModeV1>,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let execution_mode = mode.map(|mode| match mode {
        BundleModeV1::Local => ExecutionModeV1::Local,
        BundleModeV1::AirGapped => ExecutionModeV1::AirGapped,
    });
    for fixture in &profile.fixtures {
        if execution_mode.is_some_and(|execution_mode| !fixture.modes.contains(&execution_mode)) {
            continue;
        }
        for input in &fixture.inputs {
            let path = fixture_input_path(
                &fixture.case_id,
                fixture.claim_layer,
                &fixture.execution_profile_digest,
                &input.member_id,
            );
            let Some(member) = members.iter().find(|member| member.path == path) else {
                return Err(BundleContractErrorV1::MemberMissing);
            };
            if member.role != BundleMemberRoleV1::FixtureInput
                || member.expected_result
                || member.bytes.is_empty()
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
    /// Validate both signatures and their byte-for-byte expected-result parity.
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
            != expected_member_path(
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
            typed_or_divergent => crate::expected_result_bytes(typed_or_divergent)
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
    const REQUIRED_ROLES: [BundleMemberRoleV1; 7] = [
        BundleMemberRoleV1::NormativeSpecification,
        BundleMemberRoleV1::Schema,
        BundleMemberRoleV1::Licence,
        BundleMemberRoleV1::Notice,
        BundleMemberRoleV1::Sbom,
        BundleMemberRoleV1::Provenance,
        BundleMemberRoleV1::Limitations,
    ];
    if REQUIRED_ROLES.iter().any(|role| {
        let required = required_support_digests(profile, *role);
        let provided = members
            .iter()
            .filter(|member| member.role == *role)
            .map(|member| member.digest)
            .collect::<BTreeSet<_>>();
        required.is_empty() || !required.is_subset(&provided)
    }) {
        Err(BundleContractErrorV1::MemberMissing)
    } else if members.iter().any(|member| {
        (member.role.is_supporting() && member.bytes.is_empty())
            || (member.role.is_supporting()
                && !matches!(
                    member.role,
                    BundleMemberRoleV1::AuthorityInventory | BundleMemberRoleV1::ExecutionMatrix
                )
                && !support_digest_is_bound(profile, member.role, &member.digest))
    }) {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    } else {
        Ok(())
    }
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
    let inventory_lifecycle = json_text(&inventory_json, "lifecycle")?;
    if profile.lifecycle == ProfileLifecycleV1::Candidate && inventory_lifecycle != "Candidate" {
        return Err(BundleContractErrorV1::CandidateEvidenceMissing);
    }
    validate_provenance_authority_binding(&provenance, inventory_lifecycle)?;
    validate_authority_inventory_digest(&provenance, &inventory.bytes)?;
    validate_authority_inventory(&inventory_json, members)?;
    validate_execution_matrix(&matrix_json)
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
    inventory_lifecycle: &str,
) -> Result<(), BundleContractErrorV1> {
    let inventory = json_object(provenance, "authority_inventory")?;
    let matrix = json_object(provenance, "adr_059_execution_matrix")?;
    if json_text(inventory, "path")? != "expected-authority/inventory.json"
        || json_text(inventory, "digest_algorithm")? != "SHA-256"
        || json_text(inventory, "status")? != inventory_lifecycle
        || !matches!(inventory_lifecycle, "Draft" | "Candidate")
        || json_text(matrix, "path")? != "matrix/adr-059-complete.json"
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
    let declared = decode_blake3_hex(json_text(inventory, "sha256_digest")?)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    let actual: [u8; 32] = Sha256::digest(inventory_bytes).into();
    if declared == actual {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn validate_authority_inventory(
    inventory: &JsonValue,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    if json_text(inventory, "magic")? != "W8H1"
        || json_u64(inventory, "version")? != 1
        || !matches!(json_text(inventory, "lifecycle")?, "Draft" | "Candidate")
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
    if json_text(inventory, "lifecycle")? == "Draft" {
        let mut fixture_ids = BTreeSet::new();
        for entry in entries {
            if !fixture_ids.insert(json_text(entry, "fixture_id")?)
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
        return Ok(());
    }
    if members
        .iter()
        .filter(|member| member.role == BundleMemberRoleV1::AuthorityFixture)
        .count()
        != entries.len()
        || members
            .iter()
            .filter(|member| member.role == BundleMemberRoleV1::AuthorityExpectedResult)
            .count()
            != entries.len()
    {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    let mut fixture_ids = BTreeSet::new();
    for entry in entries {
        let fixture_id = json_text(entry, "fixture_id")?;
        if !fixture_ids.insert(fixture_id)
            || json_text(entry, "materialization_status")? != "materialized"
        {
            return Err(BundleContractErrorV1::MemberDigestMismatch);
        }
        validate_authority_artifact(
            entry,
            fixture_id,
            "fixture_bytes_path",
            "fixture_bytes_digest",
            BundleMemberRoleV1::AuthorityFixture,
            members,
        )?;
        validate_authority_artifact(
            entry,
            fixture_id,
            "expected_result_path",
            "expected_result_digest",
            BundleMemberRoleV1::AuthorityExpectedResult,
            members,
        )?;
    }
    Ok(())
}

fn validate_authority_artifact(
    entry: &JsonValue,
    fixture_id: &str,
    path_field: &str,
    digest_field: &str,
    role: BundleMemberRoleV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    let source_path = json_text(entry, path_field)?;
    let digest = decode_blake3_hex(json_text(entry, digest_field)?)
        .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
    let archive_path = format!("authority/{source_path}");
    let matching = members
        .iter()
        .filter(|member| member.role == role && member.path == archive_path)
        .collect::<Vec<_>>();
    if matching.len() != 1 || matching[0].bytes.is_empty() {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    let member = matching[0];
    if member.digest != digest || member.digest != *blake3::hash(&member.bytes).as_bytes() {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    let artifact = parse_authority_json(&member.bytes)?;
    if json_text(&artifact, "fixture_id")? != fixture_id {
        return Err(BundleContractErrorV1::MemberDigestMismatch);
    }
    Ok(())
}

fn decode_blake3_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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
        || json_u64(matrix, "case_count")? != 192
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
        || rows
            .iter()
            .any(|row| row.get("executed_case_count").and_then(JsonValue::as_u64) != Some(0))
        || cases.iter().any(|case| {
            case.get("executed").and_then(JsonValue::as_bool) != Some(false)
                || !case
                    .get("expected_result_digest")
                    .is_some_and(JsonValue::is_null)
        })
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
        | BundleMemberRoleV1::ExecutionMatrix
        | BundleMemberRoleV1::AuthorityFixture
        | BundleMemberRoleV1::AuthorityExpectedResult => {}
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
    [
        b"PRIVATE KEY".as_slice(),
        b"BEGIN SECRET".as_slice(),
        b"PRIVATE_KEY".as_slice(),
        b"SUBJECT_SECRET".as_slice(),
        b"\"PRIVATEKEY\"".as_slice(),
        b"\"SUBJECTSECRET\"".as_slice(),
        b"\"PASSWORD\"".as_slice(),
        b"\"CREDENTIAL\"".as_slice(),
        b"\"ACCESS_TOKEN\"".as_slice(),
        b"\"CLIENT_SECRET\"".as_slice(),
        b"\"private_key\"".as_slice(),
        b"\"subject_secret\"".as_slice(),
        b"\"password\"".as_slice(),
        b"\"credential\"".as_slice(),
        b"\"access_token\"".as_slice(),
        b"\"client_secret\"".as_slice(),
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn validate_candidate_publication(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    if profile.lifecycle != ProfileLifecycleV1::Candidate {
        return Err(BundleContractErrorV1::CandidateEvidenceMissing);
    }
    if profile.fixtures.iter().any(|fixture| {
        fixture.redaction_state == crate::RedactionStateV1::EvidenceMissing
            || fixture.replay_claim == crate::ReplayClaimV1::UnverifiableArtifactsMissing
    }) {
        return Err(BundleContractErrorV1::CandidateEvidenceMissing);
    }
    let provenance = members
        .iter()
        .find(|member| {
            member.role == BundleMemberRoleV1::Provenance
                && member.digest == profile.provenance_digest
        })
        .ok_or(BundleContractErrorV1::CandidateEvidenceMissing)?;
    let evidence = parse_authority_json(&provenance.bytes)
        .map_err(|_| BundleContractErrorV1::CandidateEvidenceMissing)?;
    if json_text(&evidence, "candidate_status") != Ok("approved")
        || json_text(&evidence, "deletion_review") != Ok("approved")
        || json_text(&evidence, "secret_scan") != Ok("clean")
    {
        return Err(BundleContractErrorV1::CandidateEvidenceMissing);
    }
    let review_digest = *blake3::hash(&provenance.bytes).as_bytes();
    if profile
        .fixtures
        .iter()
        .any(|fixture| fixture.provenance.publication_review_digest != review_digest)
    {
        return Err(BundleContractErrorV1::CandidateEvidenceMissing);
    }
    Ok(())
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
        Value::Integer(manifest.lifecycle.code().into()),
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

trait BundleLifecycleCode {
    fn code(self) -> u64;
}

impl BundleLifecycleCode for ProfileLifecycleV1 {
    fn code(self) -> u64 {
        match self {
            Self::Draft => 0,
            Self::Candidate => 1,
            Self::Stable => 2,
            Self::Retired => 3,
        }
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
            include_bytes!("../../../fixtures/conformance/inputs/artifact-positive.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/replay-negative.json").as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/knowledge-malformed.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/gateway-resource-limit.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/plugin-deletion.json").as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/metric-downgrade.json").as_slice(),
            include_bytes!("../../../fixtures/conformance/inputs/empirical-independent.json")
                .as_slice(),
        ][index]
            .to_vec()
    }

    fn fixture_expected_bytes(index: usize) -> Vec<u8> {
        [
            include_bytes!("../../../fixtures/conformance/expected/artifact-positive.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/replay-negative.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/knowledge-malformed.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/gateway-resource-limit.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/plugin-deletion.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/metric-downgrade.json")
                .as_slice(),
            include_bytes!("../../../fixtures/conformance/expected/empirical-independent.json")
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
            modes: vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped],
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
        let fixtures = claim_layers
            .into_iter()
            .enumerate()
            .map(|(index, claim_layer)| profile_fixture(index, claim_layer))
            .collect();
        let mut profile = ConformanceProfileV1 {
            profile_id: "pigloros.w8.conformance-bundle".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            normative_spec_digest: digest(12),
            execution_profile_digests: vec![digest(1)],
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
        profile.profile_digest = profile.digest();
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

    fn profile_for_claim_layer(index: usize, claim_layer: ClaimLayerV1) -> ConformanceProfileV1 {
        let mut profile = profile();
        profile.profile_id = claim_layer_profile_id(claim_layer).to_owned();
        profile.fixtures = vec![profile.fixtures[index].clone()];
        profile.profile_digest = profile.digest();
        profile
    }

    fn profile_for_claim_layer_families(claim_layer: ClaimLayerV1) -> ConformanceProfileV1 {
        let mut profile = profile();
        profile.profile_id = claim_layer_profile_id(claim_layer).to_owned();
        for fixture in &mut profile.fixtures {
            fixture.claim_layer = claim_layer;
        }
        profile.profile_digest = profile.digest();
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
                    fixture_input_path(
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
                typed_or_divergent => crate::expected_result_bytes(typed_or_divergent)?,
            };
            let path = expected_member_path(
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
        members.extend([
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
                include_bytes!("../../../fixtures/conformance/matrix/adr-059-complete.json")
                    .to_vec(),
                BundleMemberRoleV1::ExecutionMatrix,
            ),
        ]);
        append_authority_artifacts(&mut members)?;
        Ok((members, expected_results))
    }

    fn append_authority_artifacts(
        members: &mut Vec<BundleMemberV1>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authority_inventory = parse_authority_json(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        if json_text(&authority_inventory, "lifecycle")? == "Candidate" {
            members.extend(authority_artifact_members_from_inventory()?);
        }
        Ok(())
    }

    fn authority_artifact_members_from_inventory(
    ) -> Result<Vec<BundleMemberV1>, Box<dyn std::error::Error>> {
        let inventory_bytes =
            include_bytes!("../../../fixtures/conformance/expected-authority/inventory.json");
        let inventory = parse_authority_json(inventory_bytes)?;
        let entries = inventory
            .get("entries")
            .and_then(JsonValue::as_array)
            .ok_or(BundleContractErrorV1::MemberDigestMismatch)?;
        let fixture_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance");
        let mut members = Vec::with_capacity(entries.len() * 2);
        for entry in entries {
            let fixture_path = json_text(entry, "fixture_bytes_path")?;
            let result_path = json_text(entry, "expected_result_path")?;
            validate_member_path(fixture_path)?;
            validate_member_path(result_path)?;
            let fixture_bytes = std::fs::read(fixture_root.join(fixture_path))?;
            let result_bytes = std::fs::read(fixture_root.join(result_path))?;
            members.push(BundleMemberV1::authority(
                format!("authority/{fixture_path}"),
                fixture_bytes,
                BundleMemberRoleV1::AuthorityFixture,
            ));
            members.push(BundleMemberV1::authority(
                format!("authority/{result_path}"),
                result_bytes,
                BundleMemberRoleV1::AuthorityExpectedResult,
            ));
        }
        Ok(members)
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

    fn expected_member_index(bundle: &ConformanceBundleV1) -> Option<usize> {
        bundle
            .members
            .iter()
            .position(|member| member.expected_result)
    }

    fn materialized_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            value.push(HEX[usize::from(byte >> 4)] as char);
            value.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        value
    }

    fn write_materialized_file(
        root: &std::path::Path,
        relative: impl AsRef<std::path::Path>,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn materialization_signing_key() -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error>>
    {
        let encoded = std::env::var("PIGLOROS_CONFORMANCE_SIGNING_KEY")?;
        let bytes = decode_blake3_hex(&encoded).ok_or("invalid conformance signing key")?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn materialize_fixture_bundles_when_requested() -> Result<(), Box<dyn std::error::Error>> {
        let Some(output_root) = std::env::var_os("PIGLOROS_MATERIALIZE_CONFORMANCE") else {
            return Ok(());
        };
        let output_root = std::path::PathBuf::from(output_root);
        let signing_key = materialization_signing_key()?;
        let layers = [
            (ClaimLayerV1::ArtifactIntegrity, "artifact-integrity"),
            (ClaimLayerV1::ReplayConformance, "replay-conformance"),
            (
                ClaimLayerV1::KnowledgeNonInterference,
                "knowledge-non-interference",
            ),
            (
                ClaimLayerV1::GatewayClientConformance,
                "gateway-client-conformance",
            ),
            (ClaimLayerV1::PluginConformance, "plugin-conformance"),
            (ClaimLayerV1::MetricConformance, "metric-conformance"),
            (ClaimLayerV1::EmpiricalEvaluation, "empirical-evaluation"),
        ];
        let authority_inventory = parse_authority_json(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        let lifecycles = match json_text(&authority_inventory, "lifecycle")? {
            "Draft" => vec![(ProfileLifecycleV1::Draft, "draft")],
            "Candidate" => vec![
                (ProfileLifecycleV1::Draft, "draft"),
                (ProfileLifecycleV1::Candidate, "candidate"),
            ],
            _ => return Err("unsupported authority inventory lifecycle".into()),
        };
        for (claim_layer, layer_name) in layers {
            let template = profile_for_claim_layer_families(claim_layer);
            for (lifecycle, lifecycle_name) in &lifecycles {
                let mut profile = template.clone();
                profile.lifecycle = *lifecycle;
                profile.profile_digest = profile.digest();
                let profile_bytes = profile.to_canonical_cbor()?;
                let profile_name = format!(
                    "{layer_name}/{lifecycle_name}/CPF1-{}.cbor",
                    materialized_hex(&profile.profile_digest)
                );
                write_materialized_file(&output_root, profile_name, &profile_bytes)?;
                for (mode, mode_name) in [
                    (BundleModeV1::Local, "local"),
                    (BundleModeV1::AirGapped, "air-gapped"),
                ] {
                    let (members, expected_results) = bundle_inputs(&profile, mode)?;
                    let bundle = ConformanceBundleV1::materialize(
                        &profile,
                        mode,
                        members,
                        expected_results,
                    )?
                    .sign(&signing_key)?;
                    let archive = bundle.to_canonical_cbor()?;
                    let bundle_digest = materialized_hex(&bundle.bundle_digest()?);
                    let prefix = format!("{layer_name}/{lifecycle_name}");
                    write_materialized_file(
                        &output_root,
                        format!("{prefix}/manifest-{mode_name}-{bundle_digest}.cbor"),
                        &bundle.manifest_bytes()?,
                    )?;
                    write_materialized_file(
                        &output_root,
                        format!("{prefix}/bundle-{mode_name}-{bundle_digest}.cfb1"),
                        &archive,
                    )?;
                }
            }
        }
        Ok(())
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
        assert!(!contains_secret_marker(b"public expected result"));
    }

    #[test]
    fn derived_member_paths_bind_complete_fixture_identity() {
        let first = digest(1);
        let second = digest(2);
        assert_ne!(
            fixture_input_path(
                "case/a",
                ClaimLayerV1::ArtifactIntegrity,
                &first,
                "member/b",
            ),
            fixture_input_path(
                "case",
                ClaimLayerV1::ArtifactIntegrity,
                &first,
                "a/member/b",
            )
        );
        assert_ne!(
            fixture_input_path("case", ClaimLayerV1::ArtifactIntegrity, &first, "member"),
            fixture_input_path("case", ClaimLayerV1::ArtifactIntegrity, &second, "member")
        );
        assert_ne!(
            fixture_input_path("case", ClaimLayerV1::ArtifactIntegrity, &first, "member"),
            fixture_input_path("case", ClaimLayerV1::ReplayConformance, &first, "member")
        );
        assert_ne!(
            expected_member_path("case", ClaimLayerV1::ArtifactIntegrity, &first),
            expected_member_path("case", ClaimLayerV1::ArtifactIntegrity, &second)
        );
    }

    #[test]
    fn total_bundle_size_limit_is_closed() {
        assert_eq!(MAX_MEMBER_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_TOTAL_BUNDLE_BYTES, 1024 * 1024 * 1024);
        assert_eq!(validate_member_count(MAX_MEMBERS), Ok(()));
        assert_eq!(
            validate_member_count(MAX_MEMBERS + 1),
            Err(BundleContractErrorV1::LifecycleInvalid)
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
        assert_eq!(BundleMemberRoleV1::AuthorityFixture.code(), 12);
        assert_eq!(BundleMemberRoleV1::AuthorityExpectedResult.code(), 13);
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
            assert_eq!(lifecycle.code(), expected_code);
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
            assert_eq!(profile.fixtures.len(), 7);
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
    fn draft_bundle_skips_candidate_evidence_gate() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut invalid_role = bundle_value(&bundle);
        if let Value::Array(fields) = &mut invalid_role {
            if let Value::Array(members) = &mut fields[3] {
                if let Value::Array(member) = &mut members[0] {
                    member[2] = Value::Integer(99_u64.into());
                }
            }
        }
        let invalid_role_bytes = encode_archive_value(&invalid_role)?;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&invalid_role_bytes),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
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
            Err(BundleContractErrorV1::MemberDigestMismatch)
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
            Err(BundleContractErrorV1::MemberMissing)
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
        let local_with_air_mode = local_with_air_mode.sign(&signing_key)?;
        assert_eq!(
            (ConformanceBundlePairV1 {
                local: local_with_air_mode,
                air_gapped: air_gapped.clone(),
            })
            .validate(),
            Err(BundleContractErrorV1::ModeParityMismatch)
        );

        let mut air_with_local_mode = air_gapped.clone();
        air_with_local_mode.manifest.mode = BundleModeV1::Local;
        for expected in &mut air_with_local_mode.manifest.expected_results {
            expected.mode = BundleModeV1::Local;
        }
        let air_with_local_mode = air_with_local_mode.sign(&signing_key)?;
        assert_eq!(
            (ConformanceBundlePairV1 {
                local: signed_bundle(&profile, BundleModeV1::Local)?,
                air_gapped: air_with_local_mode,
            })
            .validate(),
            Err(BundleContractErrorV1::ModeParityMismatch)
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
        let typed_bytes = crate::expected_result_bytes(&typed_profile.fixtures[0].expected)?;
        let typed_digest = *blake3::hash(&typed_bytes).as_bytes();
        let mut typed_members = bundle.members;
        let typed_path = expected_member_path(
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
        let typed = crate::expected_result_bytes(&ExpectedResultV1::TypedFailure(
            SafeErrorCodeV1::InvalidEncoding,
        ))?;
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
    fn candidate_publication_requires_review_and_deletion_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let draft_profile = profile();
        let mut malformed_provenance_value: serde_json::Value = serde_json::from_slice(
            include_bytes!("../../../fixtures/conformance/support/provenance.json"),
        )?;
        malformed_provenance_value["candidate_status"] =
            serde_json::Value::String("pending".to_owned());
        let malformed_provenance = serde_json::to_vec(&malformed_provenance_value)?;
        let malformed_provenance_digest = *blake3::hash(&malformed_provenance).as_bytes();
        let mut missing_review_profile = draft_profile;
        missing_review_profile.lifecycle = ProfileLifecycleV1::Candidate;
        missing_review_profile.provenance_digest = malformed_provenance_digest;
        for fixture in &mut missing_review_profile.fixtures {
            fixture.provenance.source_digest = malformed_provenance_digest;
            fixture.provenance.build_digest = malformed_provenance_digest;
            fixture.provenance.publication_review_digest = malformed_provenance_digest;
        }
        missing_review_profile.profile_digest = missing_review_profile.digest();
        let (mut missing_review_members, _) =
            bundle_inputs(&missing_review_profile, BundleModeV1::Local)?;
        let provenance_index = missing_review_members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        missing_review_members[provenance_index].bytes = malformed_provenance;
        missing_review_members[provenance_index].digest = malformed_provenance_digest;
        assert_eq!(
            validate_candidate_publication(&missing_review_profile, &missing_review_members),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );

        let mut missing_deletion = missing_review_profile.clone();
        missing_deletion.fixtures[0].redaction_state = RedactionStateV1::EvidenceMissing;
        missing_deletion.fixtures[0].replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing;
        assert_eq!(
            validate_candidate_publication(&missing_deletion, &missing_review_members),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );

        let mut approved_profile = missing_review_profile;
        let mut approved_provenance_value: serde_json::Value = serde_json::from_slice(
            include_bytes!("../../../fixtures/conformance/support/provenance.json"),
        )?;
        approved_provenance_value["candidate_status"] =
            serde_json::Value::String("approved".to_owned());
        approved_provenance_value["deletion_review"] =
            serde_json::Value::String("approved".to_owned());
        let approved_provenance = serde_json::to_vec(&approved_provenance_value)?;
        let approved_provenance_digest = *blake3::hash(&approved_provenance).as_bytes();
        approved_profile.provenance_digest = approved_provenance_digest;
        for fixture in &mut approved_profile.fixtures {
            fixture.redaction_state = RedactionStateV1::None;
            fixture.replay_claim = ReplayClaimV1::Exact;
            fixture.provenance.source_digest = approved_provenance_digest;
            fixture.provenance.build_digest = approved_provenance_digest;
            fixture.provenance.publication_review_digest = approved_provenance_digest;
        }
        approved_profile.profile_digest = approved_profile.digest();
        let (mut approved_members, _) = bundle_inputs(&approved_profile, BundleModeV1::Local)?;
        let provenance_index = approved_members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        approved_members[provenance_index].bytes = approved_provenance;
        approved_members[provenance_index].digest = approved_provenance_digest;
        assert_eq!(
            validate_candidate_publication(&approved_profile, &approved_members),
            Ok(())
        );
        let mut mismatched_review_profile = approved_profile.clone();
        mismatched_review_profile.fixtures[0]
            .provenance
            .publication_review_digest = [9; 32];
        assert_eq!(
            validate_candidate_publication(&mismatched_review_profile, &approved_members),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );
        Ok(())
    }

    #[test]
    fn candidate_bundle_reaches_publication_evidence_gate() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut candidate_profile = profile();
        candidate_profile.lifecycle = ProfileLifecycleV1::Candidate;
        let mut approved_provenance_value: serde_json::Value = serde_json::from_slice(
            include_bytes!("../../../fixtures/conformance/support/provenance.json"),
        )?;
        approved_provenance_value["candidate_status"] =
            serde_json::Value::String("approved".to_owned());
        approved_provenance_value["deletion_review"] =
            serde_json::Value::String("approved".to_owned());
        approved_provenance_value["authority_inventory"]["status"] =
            serde_json::Value::String("Candidate".to_owned());
        let (candidate_inventory, authority_members) = authority_inventory_materialized_path()?;
        let candidate_inventory_bytes = serde_json::to_vec(&candidate_inventory)?;
        let candidate_inventory_digest = *blake3::hash(&candidate_inventory_bytes).as_bytes();
        approved_provenance_value["authority_inventory"]["sha256_digest"] = JsonValue::String(
            materialized_hex(&Sha256::digest(&candidate_inventory_bytes)),
        );
        let approved_provenance = serde_json::to_vec(&approved_provenance_value)?;
        let approved_provenance_digest = *blake3::hash(&approved_provenance).as_bytes();
        candidate_profile.provenance_digest = approved_provenance_digest;
        for fixture in &mut candidate_profile.fixtures {
            fixture.provenance.source_digest = approved_provenance_digest;
            fixture.provenance.build_digest = approved_provenance_digest;
            fixture.provenance.publication_review_digest = approved_provenance_digest;
        }
        candidate_profile.profile_digest = candidate_profile.digest();
        let (mut members, expected_results) =
            bundle_inputs(&candidate_profile, BundleModeV1::Local)?;
        let provenance_member = members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        provenance_member.bytes = approved_provenance;
        provenance_member.digest = approved_provenance_digest;
        let inventory_member = members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing authority inventory member")?;
        inventory_member.bytes = candidate_inventory_bytes;
        inventory_member.digest = candidate_inventory_digest;
        members.extend(authority_members);
        let bundle = ConformanceBundleV1::materialize(
            &candidate_profile,
            BundleModeV1::Local,
            members,
            expected_results,
        )?;
        assert_eq!(bundle.manifest.lifecycle, ProfileLifecycleV1::Candidate);
        Ok(())
    }

    #[test]
    fn authority_validation_rejection_seams_are_counted() -> Result<(), Box<dyn std::error::Error>>
    {
        let profile = profile();
        let (members, _) = bundle_inputs(&profile, BundleModeV1::Local)?;
        assert_eq!(validate_authority_members(&profile, &members), Ok(()));

        let mut missing_provenance = members.clone();
        missing_provenance.retain(|member| member.role != BundleMemberRoleV1::Provenance);
        assert_eq!(
            validate_authority_members(&profile, &missing_provenance),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut malformed_inventory = members.clone();
        malformed_inventory
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory member")?
            .bytes = b"not-json".to_vec();
        assert_eq!(
            validate_authority_members(&profile, &malformed_inventory),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut malformed_matrix = members;
        malformed_matrix
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::ExecutionMatrix)
            .ok_or("missing matrix member")?
            .bytes = b"not-json".to_vec();
        assert_eq!(
            validate_authority_members(&profile, &malformed_matrix),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let provenance: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        assert_eq!(
            validate_provenance_authority_binding(&provenance, "Draft"),
            Ok(())
        );
        for (section, field, value) in [
            ("authority_inventory", "path", "wrong-path"),
            ("authority_inventory", "digest_algorithm", "BLAKE3-256"),
            ("authority_inventory", "status", "Candidate"),
            ("adr_059_execution_matrix", "path", "wrong-path"),
            ("adr_059_execution_matrix", "digest_algorithm", "SHA-256"),
            ("adr_059_execution_matrix", "status", "Candidate"),
        ] {
            let mut invalid = provenance.clone();
            invalid[section][field] = JsonValue::String(value.to_owned());
            assert_eq!(
                validate_provenance_authority_binding(&invalid, "Draft"),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }

        let inventory: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        for (field, value) in [
            ("magic", JsonValue::String("wrong".to_owned())),
            ("version", JsonValue::Number(2_u64.into())),
            ("lifecycle", JsonValue::String("Stable".to_owned())),
            ("digest_algorithm", JsonValue::String("SHA-256".to_owned())),
        ] {
            let mut invalid = inventory.clone();
            invalid[field] = value;
            assert_eq!(
                validate_authority_inventory(&invalid, &[]),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn candidate_evidence_rejection_seams_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let mut candidate = profile();
        candidate.lifecycle = ProfileLifecycleV1::Candidate;
        candidate.profile_digest = candidate.digest();
        let (members, _) = bundle_inputs(&candidate, BundleModeV1::Local)?;
        let mut missing_provenance = members.clone();
        missing_provenance.retain(|member| member.role != BundleMemberRoleV1::Provenance);
        assert_eq!(
            validate_candidate_publication(&candidate, &missing_provenance),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );

        let mut malformed_provenance = members;
        let provenance = malformed_provenance
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        provenance.bytes = b"not-json".to_vec();
        provenance.digest = candidate.provenance_digest;
        assert_eq!(
            validate_candidate_publication(&candidate, &malformed_provenance),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );
        Ok(())
    }

    #[test]
    fn supporting_validation_seams_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let (members, _) = bundle_inputs(&profile, BundleModeV1::Local)?;
        assert_eq!(validate_supporting_members(&profile, &members), Ok(()));

        let mut missing = members.clone();
        missing.retain(|member| member.role != BundleMemberRoleV1::NormativeSpecification);
        assert_eq!(
            validate_supporting_members(&profile, &missing),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut empty = members.clone();
        empty
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::NormativeSpecification)
            .ok_or("missing normative member")?
            .bytes
            .clear();
        assert_eq!(
            validate_supporting_members(&profile, &empty),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut unbound = members;
        unbound.push(BundleMemberV1::supporting(
            "support/unbound",
            b"unbound".to_vec(),
            BundleMemberRoleV1::Notice,
        ));
        assert_eq!(
            validate_supporting_members(&profile, &unbound),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn authority_json_validation_seams_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        authority_provenance_json_validation_seams()?;
        authority_inventory_json_validation_seams()?;
        authority_matrix_json_validation_seams()?;
        Ok(())
    }

    fn authority_provenance_json_validation_seams() -> Result<(), Box<dyn std::error::Error>> {
        let provenance: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        assert!(json_object(&provenance, "authority_inventory").is_ok());
        assert_eq!(
            json_object(&provenance, "missing"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(json_text(&provenance, "candidate_status"), Ok("pending"));
        assert_eq!(
            json_u64(&provenance, "candidate_status"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        assert_eq!(
            validate_provenance_authority_binding(&provenance, "Draft"),
            Ok(())
        );
        let inventory_bytes =
            include_bytes!("../../../fixtures/conformance/expected-authority/inventory.json");
        assert_eq!(
            validate_authority_inventory_digest(&provenance, inventory_bytes),
            Ok(())
        );
        let mut invalid_inventory_digest = provenance.clone();
        invalid_inventory_digest["authority_inventory"]["sha256_digest"] =
            JsonValue::String("00".repeat(32));
        assert_eq!(
            validate_authority_inventory_digest(&invalid_inventory_digest, inventory_bytes),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut missing_matrix = provenance;
        missing_matrix["adr_059_execution_matrix"] = JsonValue::Null;
        assert_eq!(
            validate_provenance_authority_binding(&missing_matrix, "Draft"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    fn authority_inventory_json_validation_seams() -> Result<(), Box<dyn std::error::Error>> {
        let inventory: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        assert_eq!(validate_authority_inventory(&inventory, &[]), Ok(()));
        let mut missing_entries = inventory.clone();
        missing_entries["entries"] = JsonValue::Null;
        assert_eq!(
            validate_authority_inventory(&missing_entries, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut wrong_entry_count = inventory.clone();
        wrong_entry_count["entries"] = JsonValue::Array(Vec::new());
        assert_eq!(
            validate_authority_inventory(&wrong_entry_count, &[]),
            Err(BundleContractErrorV1::MemberMissing)
        );
        let mut wrong_id = inventory.clone();
        wrong_id["entries"][0]["fixture_id"] = JsonValue::String("wrong".to_owned());
        assert_eq!(
            validate_authority_inventory(&wrong_id, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut wrong_pending_field = inventory;
        wrong_pending_field["entries"][0]["fixture_bytes_digest"] =
            JsonValue::String("00".repeat(32));
        assert_eq!(
            validate_authority_inventory(&wrong_pending_field, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    fn authority_matrix_json_validation_seams() -> Result<(), Box<dyn std::error::Error>> {
        let matrix: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/matrix/adr-059-complete.json"
        ))?;
        assert_eq!(validate_execution_matrix(&matrix), Ok(()));
        for (section, field, value) in [
            ("rows", "fixture_id", JsonValue::String("wrong".to_owned())),
            (
                "rows",
                "variants",
                JsonValue::Array(vec![JsonValue::String("X".to_owned())]),
            ),
            (
                "rows",
                "modes",
                JsonValue::Array(vec![JsonValue::String("X".to_owned())]),
            ),
            (
                "equality_predicates",
                "AuthEq",
                JsonValue::String("wrong".to_owned()),
            ),
            ("cases", "case_id", JsonValue::String("wrong".to_owned())),
            ("cases", "variant", JsonValue::String("X".to_owned())),
            ("cases", "mode", JsonValue::String("X".to_owned())),
        ] {
            let mut invalid = matrix.clone();
            invalid[section][0][field] = value;
            assert_eq!(
                validate_execution_matrix(&invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        for (field, value) in [
            ("magic", JsonValue::String("wrong".to_owned())),
            ("version", JsonValue::Number(2_u64.into())),
            ("lifecycle", JsonValue::String("Candidate".to_owned())),
            ("row_count", JsonValue::Number(11_u64.into())),
            ("case_count", JsonValue::Number(191_u64.into())),
        ] {
            let mut invalid = matrix.clone();
            invalid[field] = value;
            assert_eq!(
                validate_execution_matrix(&invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        for field in ["rows", "cases"] {
            let mut invalid = matrix.clone();
            invalid[field] = JsonValue::Null;
            assert_eq!(
                validate_execution_matrix(&invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn authority_missing_json_field_seams_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let provenance: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        for (section, field) in [
            ("authority_inventory", "path"),
            ("authority_inventory", "digest_algorithm"),
            ("authority_inventory", "status"),
            ("adr_059_execution_matrix", "path"),
            ("adr_059_execution_matrix", "digest_algorithm"),
            ("adr_059_execution_matrix", "status"),
            ("adr_059_execution_matrix", "executed_case_count"),
        ] {
            let mut invalid = provenance.clone();
            invalid[section][field] = JsonValue::Null;
            assert_eq!(
                validate_provenance_authority_binding(&invalid, "Draft"),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }

        let inventory: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        for field in ["magic", "version", "lifecycle", "digest_algorithm"] {
            let mut invalid = inventory.clone();
            invalid[field] = JsonValue::Null;
            assert_eq!(
                validate_authority_inventory(&invalid, &[]),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }

        let matrix: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/matrix/adr-059-complete.json"
        ))?;
        for field in ["magic", "version", "lifecycle", "row_count", "case_count"] {
            let mut invalid = matrix.clone();
            invalid[field] = JsonValue::Null;
            assert_eq!(
                validate_execution_matrix(&invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn authority_materialized_error_seams_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let (candidate_inventory, members) = authority_inventory_materialized_path()?;

        let mut invalid_status = candidate_inventory.clone();
        invalid_status["entries"][0]["materialization_status"] = JsonValue::Null;
        assert_eq!(
            validate_authority_inventory(&invalid_status, &members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_path = candidate_inventory.clone();
        invalid_path["entries"][0]["fixture_bytes_path"] = JsonValue::Null;
        assert_eq!(
            validate_authority_inventory(&invalid_path, &members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_digest = candidate_inventory.clone();
        invalid_digest["entries"][0]["fixture_bytes_digest"] = JsonValue::Null;
        assert_eq!(
            validate_authority_inventory(&invalid_digest, &members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut malformed_members = members.clone();
        let fixture = malformed_members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityFixture)
            .ok_or("missing fixture member")?;
        fixture.bytes = b"not-json".to_vec();
        fixture.digest = *blake3::hash(&fixture.bytes).as_bytes();
        let mut malformed_inventory = candidate_inventory.clone();
        malformed_inventory["entries"][0]["fixture_bytes_digest"] =
            JsonValue::String(materialized_hex(&fixture.digest));
        assert_eq!(
            validate_authority_inventory(&malformed_inventory, &malformed_members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_id_members = members.clone();
        let fixture = invalid_id_members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityFixture)
            .ok_or("missing fixture member")?;
        fixture.bytes = b"{}".to_vec();
        fixture.digest = *blake3::hash(&fixture.bytes).as_bytes();
        let mut invalid_id_inventory = candidate_inventory.clone();
        invalid_id_inventory["entries"][0]["fixture_bytes_digest"] =
            JsonValue::String(materialized_hex(&fixture.digest));
        assert_eq!(
            validate_authority_inventory(&invalid_id_inventory, &invalid_id_members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_nibble = candidate_inventory;
        invalid_nibble["entries"][0]["fixture_bytes_digest"] = JsonValue::String("0g".repeat(32));
        assert_eq!(
            validate_authority_inventory(&invalid_nibble, &members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn authority_member_pipeline_error_seams_are_counted() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut missing_lifecycle_profile = profile();
        let (mut missing_lifecycle, _) =
            bundle_inputs(&missing_lifecycle_profile, BundleModeV1::Local)?;
        let inventory = missing_lifecycle
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory member")?;
        let mut invalid_inventory: JsonValue = serde_json::from_slice(&inventory.bytes)?;
        invalid_inventory["lifecycle"] = JsonValue::Null;
        inventory.bytes = serde_json::to_vec(&invalid_inventory)?;
        inventory.digest = *blake3::hash(&inventory.bytes).as_bytes();
        bind_inventory_digest_to_provenance(
            &mut missing_lifecycle_profile,
            &mut missing_lifecycle,
        )?;
        assert_eq!(
            validate_authority_members(&missing_lifecycle_profile, &missing_lifecycle),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let (mut invalid_entries, _) = bundle_inputs(&profile(), BundleModeV1::Local)?;
        let inventory = invalid_entries
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory member")?;
        let mut invalid_inventory: JsonValue = serde_json::from_slice(&inventory.bytes)?;
        invalid_inventory["entries"] = JsonValue::Array(Vec::new());
        inventory.bytes = serde_json::to_vec(&invalid_inventory)?;
        inventory.digest = *blake3::hash(&inventory.bytes).as_bytes();
        let mut invalid_entries_profile = profile();
        bind_inventory_digest_to_provenance(&mut invalid_entries_profile, &mut invalid_entries)?;
        assert_eq!(
            validate_authority_members(&invalid_entries_profile, &invalid_entries),
            Err(BundleContractErrorV1::MemberMissing)
        );
        Ok(())
    }

    fn bind_inventory_digest_to_provenance(
        profile: &mut ConformanceProfileV1,
        members: &mut [BundleMemberV1],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inventory = members
            .iter()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityInventory)
            .ok_or("missing inventory member")?;
        let inventory_sha256 = materialized_hex(&Sha256::digest(&inventory.bytes));
        let provenance = members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        let mut provenance_json: JsonValue = serde_json::from_slice(&provenance.bytes)?;
        provenance_json["authority_inventory"]["sha256_digest"] =
            JsonValue::String(inventory_sha256);
        provenance.bytes = serde_json::to_vec(&provenance_json)?;
        provenance.digest = *blake3::hash(&provenance.bytes).as_bytes();
        profile.provenance_digest = provenance.digest;
        Ok(())
    }

    #[test]
    fn public_archive_rejects_non_integer_manifest_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let bundle = signed_bundle(&profile(), BundleModeV1::Local)?;
        let archive: Value =
            ciborium::from_reader(std::io::Cursor::new(bundle.to_canonical_cbor()?))?;
        for path in [
            &[2, 1][..],
            &[2, 2][..],
            &[2, 4, 0, 3][..],
            &[2, 5, 0, 1][..],
            &[2, 5, 0, 3][..],
        ] {
            let invalid = replace_nested_array_field(
                &archive,
                path,
                Value::Text("not-an-integer".to_owned()),
            )?;
            let mut invalid_bytes = Vec::new();
            ciborium::into_writer(&invalid, &mut invalid_bytes)?;
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&invalid_bytes),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }
        Ok(())
    }

    #[test]
    fn candidate_evidence_status_seams_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let mut candidate = profile();
        candidate.lifecycle = ProfileLifecycleV1::Candidate;
        let mut approved: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        approved["candidate_status"] = JsonValue::String("approved".to_owned());
        approved["deletion_review"] = JsonValue::String("approved".to_owned());
        approved["secret_scan"] = JsonValue::String("clean".to_owned());
        let approved_bytes = serde_json::to_vec(&approved)?;
        let approved_digest = *blake3::hash(&approved_bytes).as_bytes();
        candidate.provenance_digest = approved_digest;
        for fixture in &mut candidate.fixtures {
            fixture.provenance.source_digest = approved_digest;
            fixture.provenance.build_digest = approved_digest;
            fixture.provenance.publication_review_digest = approved_digest;
        }
        candidate.profile_digest = candidate.digest();
        let (mut members, _) = bundle_inputs(&candidate, BundleModeV1::Local)?;
        let provenance = members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        provenance.bytes = approved_bytes;
        provenance.digest = approved_digest;
        assert_eq!(validate_candidate_publication(&candidate, &members), Ok(()));
        for field in ["candidate_status", "deletion_review", "secret_scan"] {
            let mut invalid = approved.clone();
            invalid[field] = JsonValue::String("pending".to_owned());
            let bytes = serde_json::to_vec(&invalid)?;
            let digest = *blake3::hash(&bytes).as_bytes();
            let mut invalid_members = members.clone();
            let provenance = invalid_members
                .iter_mut()
                .find(|member| member.role == BundleMemberRoleV1::Provenance)
                .ok_or("missing provenance member")?;
            provenance.bytes = bytes;
            provenance.digest = digest;
            let mut invalid_candidate = candidate.clone();
            invalid_candidate.provenance_digest = digest;
            for fixture in &mut invalid_candidate.fixtures {
                fixture.provenance.publication_review_digest = digest;
            }
            invalid_candidate.profile_digest = invalid_candidate.digest();
            assert_eq!(
                validate_candidate_publication(&invalid_candidate, &invalid_members),
                Err(BundleContractErrorV1::CandidateEvidenceMissing)
            );
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_rejection_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        authority_member_rejections(&profile)?;
        authority_provenance_rejections()?;
        authority_inventory_rejections()?;
        authority_matrix_rejection()?;
        authority_candidate_rejections(&profile)?;
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_member_rejections(
        profile: &ConformanceProfileV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut members, _) = bundle_inputs(profile, BundleModeV1::Local)?;
        let provenance_index = members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        members[provenance_index].bytes = b"not-json".to_vec();
        members[provenance_index].digest = profile.provenance_digest;
        assert_eq!(
            validate_authority_members(profile, &members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut missing_matrix_members = bundle_inputs(profile, BundleModeV1::Local)?.0;
        missing_matrix_members.retain(|member| member.role != BundleMemberRoleV1::ExecutionMatrix);
        assert_eq!(
            validate_authority_members(profile, &missing_matrix_members),
            Err(BundleContractErrorV1::MemberMissing)
        );
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_provenance_rejections() -> Result<(), Box<dyn std::error::Error>> {
        let mut provenance: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        provenance["authority_inventory"] = JsonValue::Null;
        assert_eq!(
            validate_provenance_authority_binding(&provenance, "Candidate"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_status_provenance: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        invalid_status_provenance["authority_inventory"]["status"] =
            JsonValue::String("Draft".to_owned());
        assert_eq!(
            validate_provenance_authority_binding(&invalid_status_provenance, "Candidate"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        for (section, field, value) in [
            ("authority_inventory", "path", "wrong-path"),
            ("authority_inventory", "digest_algorithm", "BLAKE3-256"),
            ("authority_inventory", "status", "Draft"),
            ("adr_059_execution_matrix", "path", "wrong-path"),
            ("adr_059_execution_matrix", "digest_algorithm", "SHA-256"),
            ("adr_059_execution_matrix", "status", "Candidate"),
        ] {
            let mut invalid: JsonValue = serde_json::from_slice(include_bytes!(
                "../../../fixtures/conformance/support/provenance.json"
            ))?;
            invalid[section][field] = JsonValue::String(value.to_owned());
            assert_eq!(
                validate_provenance_authority_binding(&invalid, "Candidate"),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        let mut invalid_executed_count: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/support/provenance.json"
        ))?;
        invalid_executed_count["adr_059_execution_matrix"]["executed_case_count"] =
            JsonValue::Number(1_u64.into());
        assert_eq!(
            validate_provenance_authority_binding(&invalid_executed_count, "Candidate"),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_inventory_rejections() -> Result<(), Box<dyn std::error::Error>> {
        let inventory_bytes =
            include_bytes!("../../../fixtures/conformance/expected-authority/inventory.json");
        authority_inventory_header_rejections(inventory_bytes)?;
        let mut invalid_inventory: JsonValue = serde_json::from_slice(inventory_bytes)?;
        invalid_inventory["magic"] = JsonValue::String("wrong".to_owned());
        assert_eq!(
            validate_authority_inventory(&invalid_inventory, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        invalid_inventory["magic"] = JsonValue::String("W8H1".to_owned());
        invalid_inventory["entries"] = JsonValue::Array(Vec::new());
        assert_eq!(
            validate_authority_inventory(&invalid_inventory, &[]),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut pending_inventory: JsonValue = serde_json::from_slice(inventory_bytes)?;
        pending_inventory["entries"][0]["materialization_status"] =
            JsonValue::String("materialized".to_owned());
        assert_eq!(
            validate_authority_inventory(&pending_inventory, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        authority_inventory_membership_rejections(inventory_bytes, &[])?;
        let mut candidate_inventory: JsonValue = serde_json::from_slice(inventory_bytes)?;
        candidate_inventory["lifecycle"] = JsonValue::String("Candidate".to_owned());
        assert_eq!(
            validate_authority_inventory(&candidate_inventory, &[]),
            Err(BundleContractErrorV1::MemberMissing)
        );
        let _ = authority_inventory_materialized_path()?;

        let mut duplicate_inventory: JsonValue = serde_json::from_slice(inventory_bytes)?;
        duplicate_inventory["entries"][1]["fixture_id"] =
            duplicate_inventory["entries"][0]["fixture_id"].clone();
        assert_eq!(
            validate_authority_inventory(&duplicate_inventory, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut nonnull_path_inventory: JsonValue = serde_json::from_slice(inventory_bytes)?;
        nonnull_path_inventory["entries"][0]["fixture_bytes_path"] =
            JsonValue::String("expected-authority/fixtures/RPL-001.json".to_owned());
        assert_eq!(
            validate_authority_inventory(&nonnull_path_inventory, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_inventory_materialized_path(
    ) -> Result<(JsonValue, Vec<BundleMemberV1>), Box<dyn std::error::Error>> {
        let mut candidate_inventory: JsonValue = serde_json::from_slice(include_bytes!(
            "../../../fixtures/conformance/expected-authority/inventory.json"
        ))?;
        candidate_inventory["lifecycle"] = JsonValue::String("Candidate".to_owned());
        let entries = candidate_inventory["entries"]
            .as_array_mut()
            .ok_or("missing authority entries")?;
        let mut members = Vec::with_capacity(entries.len() * 2);
        for entry in entries {
            let fixture_id = entry["fixture_id"]
                .as_str()
                .ok_or("missing authority fixture id")?
                .to_owned();
            let fixture_bytes = serde_json::to_vec(&serde_json::json!({
                "fixture_id": fixture_id.clone(),
            }))?;
            let result_bytes = serde_json::to_vec(&serde_json::json!({
                "fixture_id": fixture_id.clone(),
                "expected": true,
            }))?;
            let fixture_digest = *blake3::hash(&fixture_bytes).as_bytes();
            let result_digest = *blake3::hash(&result_bytes).as_bytes();
            let fixture_path = format!("fixtures/{fixture_id}.json");
            let result_path = format!("results/{fixture_id}.json");
            entry["materialization_status"] = JsonValue::String("materialized".to_owned());
            entry["fixture_bytes_path"] = JsonValue::String(fixture_path.clone());
            entry["fixture_bytes_digest"] = JsonValue::String(materialized_hex(&fixture_digest));
            entry["expected_result_path"] = JsonValue::String(result_path.clone());
            entry["expected_result_digest"] = JsonValue::String(materialized_hex(&result_digest));
            members.push(BundleMemberV1::authority(
                format!("authority/{fixture_path}"),
                fixture_bytes,
                BundleMemberRoleV1::AuthorityFixture,
            ));
            members.push(BundleMemberV1::authority(
                format!("authority/{result_path}"),
                result_bytes,
                BundleMemberRoleV1::AuthorityExpectedResult,
            ));
        }
        assert_eq!(
            validate_authority_inventory(&candidate_inventory, &members),
            Ok(())
        );
        authority_inventory_materialized_rejections(&candidate_inventory, &members)?;
        Ok((candidate_inventory, members))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_inventory_materialized_rejections(
        candidate_inventory: &JsonValue,
        members: &[BundleMemberV1],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut invalid_status = candidate_inventory.clone();
        invalid_status["entries"][0]["materialization_status"] =
            JsonValue::String("pending".to_owned());
        assert_eq!(
            validate_authority_inventory(&invalid_status, members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut missing_fixture = members.to_vec();
        missing_fixture.retain(|member| member.role != BundleMemberRoleV1::AuthorityFixture);
        assert_eq!(
            validate_authority_inventory(candidate_inventory, &missing_fixture),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut missing_result = members.to_vec();
        missing_result.retain(|member| member.role != BundleMemberRoleV1::AuthorityExpectedResult);
        assert_eq!(
            validate_authority_inventory(candidate_inventory, &missing_result),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut invalid_fixture_digest = members.to_vec();
        invalid_fixture_digest
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityFixture)
            .ok_or("missing fixture member")?
            .digest = [0; 32];
        assert_eq!(
            validate_authority_inventory(candidate_inventory, &invalid_fixture_digest),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_fixture_id = members.to_vec();
        let fixture_member = invalid_fixture_id
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::AuthorityFixture)
            .ok_or("missing fixture member")?;
        fixture_member.bytes = br#"{"fixture_id":"OTHER"}"#.to_vec();
        fixture_member.digest = *blake3::hash(&fixture_member.bytes).as_bytes();
        let mut invalid_fixture_id_inventory = candidate_inventory.clone();
        let fixture_entry = invalid_fixture_id_inventory["entries"]
            .as_array_mut()
            .ok_or("missing authority entries")?
            .first_mut()
            .ok_or("missing first authority entry")?;
        fixture_entry["fixture_bytes_digest"] =
            JsonValue::String(materialized_hex(&fixture_member.digest));
        assert_eq!(
            validate_authority_inventory(&invalid_fixture_id_inventory, &invalid_fixture_id),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_fixture_path = candidate_inventory.clone();
        invalid_fixture_path["entries"][0]["fixture_bytes_path"] =
            JsonValue::String("fixtures/missing.json".to_owned());
        assert_eq!(
            validate_authority_inventory(&invalid_fixture_path, members),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut invalid_result_path = candidate_inventory.clone();
        invalid_result_path["entries"][0]["expected_result_path"] =
            JsonValue::String("results/missing.json".to_owned());
        assert_eq!(
            validate_authority_inventory(&invalid_result_path, members),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut invalid_digest_length = candidate_inventory.clone();
        invalid_digest_length["entries"][0]["fixture_bytes_digest"] =
            JsonValue::String("00".to_owned());
        assert_eq!(
            validate_authority_inventory(&invalid_digest_length, members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut invalid_digest_nibble = candidate_inventory.clone();
        invalid_digest_nibble["entries"][0]["fixture_bytes_digest"] =
            JsonValue::String("gg".repeat(32));
        assert_eq!(
            validate_authority_inventory(&invalid_digest_nibble, members),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_inventory_header_rejections(
        inventory_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (field, value) in [
            ("magic", JsonValue::String("wrong".to_owned())),
            ("version", JsonValue::Number(2_u64.into())),
            ("lifecycle", JsonValue::String("Stable".to_owned())),
            ("digest_algorithm", JsonValue::String("SHA-256".to_owned())),
        ] {
            let mut invalid: JsonValue = serde_json::from_slice(inventory_bytes)?;
            invalid[field] = value;
            assert_eq!(
                validate_authority_inventory(&invalid, &[]),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_inventory_membership_rejections(
        inventory_bytes: &[u8],
        _authority_members: &[BundleMemberV1],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let valid_inventory: JsonValue = serde_json::from_slice(inventory_bytes)?;
        assert_eq!(validate_authority_inventory(&valid_inventory, &[]), Ok(()));
        let mut nonnull_digest_inventory = valid_inventory;
        nonnull_digest_inventory["entries"][0]["fixture_bytes_digest"] =
            JsonValue::String("00".repeat(32));
        assert_eq!(
            validate_authority_inventory(&nonnull_digest_inventory, &[]),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_matrix_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let matrix_bytes =
            include_bytes!("../../../fixtures/conformance/matrix/adr-059-complete.json");
        for (field, value) in [
            ("magic", JsonValue::String("wrong".to_owned())),
            ("lifecycle", JsonValue::String("Candidate".to_owned())),
        ] {
            let mut invalid: JsonValue = serde_json::from_slice(matrix_bytes)?;
            invalid[field] = value;
            assert_eq!(
                validate_execution_matrix(&invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        for (field, value) in [("version", 2_u64), ("row_count", 11), ("case_count", 191)] {
            let mut invalid: JsonValue = serde_json::from_slice(matrix_bytes)?;
            invalid[field] = JsonValue::Number(value.into());
            assert_eq!(
                validate_execution_matrix(&invalid),
                Err(BundleContractErrorV1::MemberDigestMismatch)
            );
        }
        let mut invalid_rows: JsonValue = serde_json::from_slice(matrix_bytes)?;
        invalid_rows["rows"] = JsonValue::Array(Vec::new());
        assert_eq!(
            validate_execution_matrix(&invalid_rows),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_row_execution: JsonValue = serde_json::from_slice(matrix_bytes)?;
        invalid_row_execution["rows"][0]["executed_case_count"] = JsonValue::Number(1_u64.into());
        assert_eq!(
            validate_execution_matrix(&invalid_row_execution),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_case_execution: JsonValue = serde_json::from_slice(matrix_bytes)?;
        invalid_case_execution["cases"][0]["executed"] = JsonValue::Bool(true);
        assert_eq!(
            validate_execution_matrix(&invalid_case_execution),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_case_digest: JsonValue = serde_json::from_slice(matrix_bytes)?;
        invalid_case_digest["cases"][0]["expected_result_digest"] =
            JsonValue::String("00".to_owned());
        assert_eq!(
            validate_execution_matrix(&invalid_case_digest),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_matrix: JsonValue = serde_json::from_slice(matrix_bytes)?;
        invalid_matrix["cases"] = JsonValue::Array(Vec::new());
        assert_eq!(
            validate_execution_matrix(&invalid_matrix),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authority_candidate_rejections(
        profile: &ConformanceProfileV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut members, _) = bundle_inputs(profile, BundleModeV1::Local)?;
        members.retain(|member| member.role != BundleMemberRoleV1::Provenance);
        assert_eq!(
            validate_candidate_publication(profile, &members),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );
        let (mut malformed_members, _) = bundle_inputs(profile, BundleModeV1::Local)?;
        let provenance = malformed_members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or("missing provenance member")?;
        provenance.bytes = b"not-json".to_vec();
        provenance.digest = profile.provenance_digest;
        assert_eq!(
            validate_candidate_publication(profile, &malformed_members),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );
        Ok(())
    }

    #[test]
    fn validation_binds_each_profile_input_to_public_member_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let input_index = bundle
            .members
            .iter()
            .position(|member| member.path.starts_with(INPUT_MEMBER_PREFIX))
            .ok_or("missing fixture input member")?;

        let mut tampered = bundle.clone();
        tampered.members[input_index].bytes = b"different public input".to_vec();
        tampered.members[input_index].digest =
            *blake3::hash(&tampered.members[input_index].bytes).as_bytes();
        tampered.manifest.members[input_index].digest = tampered.members[input_index].digest;
        tampered.manifest.members[input_index].size_bytes =
            tampered.members[input_index].bytes.len() as u64;
        assert_eq!(
            tampered.validate(),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut missing = bundle.clone();
        missing.members.remove(input_index);
        missing.manifest.members.remove(input_index);
        assert_eq!(
            missing.validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut marked_as_expected = bundle.clone();
        marked_as_expected.members[input_index].expected_result = true;
        assert_eq!(
            marked_as_expected.validate(),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );

        let mut undeclared = bundle;
        undeclared.members.push(BundleMemberV1::new(
            "inputs/case-00/undeclared.json",
            b"extra public input".to_vec(),
            false,
        ));
        undeclared.rebuild_member_descriptors();
        assert_eq!(
            undeclared.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );

        let mut undeclared_expected = signed_bundle(&profile, BundleModeV1::Local)?;
        undeclared_expected.members.push(BundleMemberV1::new(
            "expected/undeclared.bin",
            b"undeclared expected result".to_vec(),
            true,
        ));
        undeclared_expected.rebuild_member_descriptors();
        assert_eq!(
            undeclared_expected.validate(),
            Err(BundleContractErrorV1::UndeclaredMember)
        );
        Ok(())
    }

    #[test]
    fn fixture_input_guards_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile_for_claim_layer(0, ClaimLayerV1::ArtifactIntegrity);
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
            Err(BundleContractErrorV1::MemberDigestMismatch)
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
        network_profile.fixtures[0]
            .capability_policy
            .network_allowed = true;
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
            lifecycle: ProfileLifecycleV1::Candidate,
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

    fn replace_nested_array_field(
        value: &Value,
        path: &[usize],
        replacement: Value,
    ) -> Result<Value, std::io::Error> {
        let Some((&index, remaining)) = path.split_first() else {
            return Ok(replacement);
        };
        let Value::Array(mut fields) = value.clone() else {
            return Err(std::io::Error::other("expected array"));
        };
        let field = fields
            .get(index)
            .ok_or_else(|| std::io::Error::other("array index out of bounds"))?;
        fields[index] = replace_nested_array_field(field, remaining, replacement)?;
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
        assert!(decode_manifest(&replace_expected_field(&manifest, 0, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(
            &manifest,
            1,
            Value::Integer(99_u64.into()),
        )?)
        .is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 2, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(
            &manifest,
            3,
            Value::Integer(99_u64.into()),
        )?)
        .is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 4, Value::Null)?).is_err());
        assert!(decode_manifest(&replace_expected_field(&manifest, 5, Value::Null)?).is_err());

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
mod coverage_entrypoints {
    use super::tests;
    use super::{
        archive_array_bounded, archive_array_exact, archive_bytes, archive_text, archive_u64,
        bundle_value, encode_archive_value, manifest_value, preflight_archive,
        preflight_archive_caps, required_support_digests, validate_archive_caps,
        validate_expected_results, validate_fixture_inputs_for_mode, validate_member_count,
        validate_member_size, validate_preflight_archive_caps, validate_selected_bundle_caps,
        validate_supporting_members, validate_total_bytes, BundleContractErrorV1,
        BundleMemberRoleV1, BundleModeV1, ConformanceBundlePairV1, ConformanceBundleV1, PublicKey,
        Value, MAX_MEMBERS, MAX_MEMBER_BYTES, MAX_MEMBER_PATH_BYTES, MAX_STRUCTURAL_NESTING,
        MAX_TOTAL_BUNDLE_BYTES,
    };

    pub(super) fn signed_bundle() -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        signed_bundle_for(&tests::profile(), BundleModeV1::Local)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signed_bundle_for(
        profile: &super::ConformanceProfileV1,
        mode: BundleModeV1,
    ) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        let (members, expected_results) = tests::bundle_inputs(profile, mode)?;
        let unsigned = ConformanceBundleV1::materialize(profile, mode, members, expected_results)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        Ok(unsigned.sign(&signing_key)?)
    }

    fn raw_archive_with_header(top_header: &[u8], first: &[u8], members: &[u8]) -> Vec<u8> {
        let mut bytes = top_header.to_vec();
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(&[0x01, 0x80]);
        bytes.extend_from_slice(members);
        bytes.extend_from_slice(&[0x58, 0x20]);
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&[0x58, 0x40]);
        bytes.extend_from_slice(&[0; 64]);
        bytes
    }

    fn raw_archive(first: &[u8], members: &[u8]) -> Vec<u8> {
        raw_archive_with_header(&[0x86], first, members)
    }

    fn exact_member_array() -> Vec<u8> {
        let mut bytes = vec![0x9a, 0, 1, 0, 0];
        for _ in 0..MAX_MEMBERS {
            bytes.extend_from_slice(&[0x83, 0x60, 0x40, 0x00]);
        }
        bytes
    }

    fn exact_null_array() -> Vec<u8> {
        let mut bytes = vec![0x9a, 0, 1, 0, 0];
        bytes.extend(std::iter::repeat_n(0xf6, MAX_MEMBERS));
        bytes
    }

    fn exact_path_member() -> Vec<u8> {
        let mut bytes = vec![0x81, 0x83, 0x79, 1, 0];
        bytes.extend(std::iter::repeat_n(b'a', MAX_MEMBER_PATH_BYTES));
        bytes.extend_from_slice(&[0x40, 0x00]);
        bytes
    }

    fn exact_bytes_member() -> Vec<u8> {
        let length = usize::try_from(MAX_MEMBER_BYTES).unwrap_or_default();
        let mut bytes = Vec::with_capacity(length + 14);
        bytes.extend_from_slice(&[0x81, 0x83, 0x60, 0x5b]);
        bytes.extend_from_slice(&MAX_MEMBER_BYTES.to_be_bytes());
        bytes.extend(std::iter::repeat_n(0_u8, length));
        bytes.push(0x00);
        bytes
    }

    fn manifest_with_member(member: Value) -> Value {
        Value::Array(vec![
            Value::Text(super::CONFORMANCE_BUNDLE_MAGIC_V1.to_owned()),
            Value::Integer(0_u64.into()),
            Value::Integer(0_u64.into()),
            Value::Bytes(vec![0; 32]),
            Value::Array(vec![member]),
            Value::Array(Vec::new()),
        ])
    }

    fn manifest_with_expected(expected: Value) -> Value {
        Value::Array(vec![
            Value::Text(super::CONFORMANCE_BUNDLE_MAGIC_V1.to_owned()),
            Value::Integer(0_u64.into()),
            Value::Integer(0_u64.into()),
            Value::Bytes(vec![0; 32]),
            Value::Array(Vec::new()),
            Value::Array(vec![expected]),
        ])
    }

    #[test]
    fn public_bundle_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        let manifest = bundle.manifest_bytes()?;
        assert!(!manifest.is_empty());
        assert_eq!(
            manifest,
            encode_archive_value(&manifest_value(&bundle.manifest))?
        );
        assert!(bundle.bundle_digest()?.iter().any(|byte| *byte != 0));
        bundle.validate()?;
        let encoded = bundle.to_canonical_cbor()?;
        let decoded = ConformanceBundleV1::from_canonical_cbor(&encoded)?;
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.to_canonical_cbor()?, encoded);
        let preflight = preflight_archive_caps(&encoded)?;
        assert_eq!(preflight.member_count, bundle.members.len());
        assert_eq!(
            preflight.maximum_depth,
            super::value_depth(&bundle_value(&bundle))
        );
        Ok(())
    }

    #[test]
    fn public_bundle_rejection_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        let mut invalid_magic = bundle.clone();
        invalid_magic.manifest.magic = "invalid".to_owned();
        assert_eq!(
            invalid_magic.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_lifecycle = bundle.clone();
        invalid_lifecycle.manifest.lifecycle = super::ProfileLifecycleV1::Stable;
        assert_eq!(
            invalid_lifecycle.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_profile = bundle.clone();
        invalid_profile
            .members
            .retain(|member| member.role != BundleMemberRoleV1::Profile);
        assert_eq!(
            invalid_profile.validate(),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut trailing = bundle.to_canonical_cbor()?;
        trailing.push(0);
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&trailing),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        for bytes in [
            vec![0x01, 0],
            vec![0xa0],
            vec![0xc0],
            vec![0xfa, 0, 0, 0, 0],
        ] {
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&bytes),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&raw_archive(
                &[0x60],
                &[0x81, 0x83, 0x60, 0x40, 0x00],
            )),
            Err(BundleContractErrorV1::MemberMissing)
        );
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&raw_archive(
                &[0x60],
                &[0x81, 0x83, 0x60, 0x41, 0x01, 0x02],
            )),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
        Ok(())
    }

    #[test]
    fn archive_scanner_accepts_inclusive_limits_and_tracks_depth(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut exact_depth = vec![0x60];
        for _ in 0..(usize::from(MAX_STRUCTURAL_NESTING) - 2) {
            let mut next = vec![0x81];
            next.extend_from_slice(&exact_depth);
            exact_depth = next;
        }
        let exact_depth_archive = raw_archive(&exact_depth, &[0x80]);
        let exact_depth_scan = super::archive_preflight::scan(&exact_depth_archive)?;
        assert_eq!(
            exact_depth_scan.maximum_depth,
            usize::from(MAX_STRUCTURAL_NESTING)
        );
        let mut over_depth = vec![0x81];
        over_depth.extend_from_slice(&exact_depth);
        assert!(super::archive_preflight::scan(&raw_archive(&over_depth, &[0x80])).is_err());

        let exact_member_archive = raw_archive(&[0x60], &exact_member_array());
        let exact_members = super::archive_preflight::scan(&exact_member_archive)?;
        assert_eq!(exact_members.member_count, MAX_MEMBERS);
        assert_eq!(exact_members.maximum_depth, 4);
        assert!(super::archive_preflight::scan(&raw_archive_with_header(
            &[0x86],
            &exact_null_array(),
            &[0x80],
        ))
        .is_ok());
        assert!(
            super::archive_preflight::scan(&raw_archive(&[0x60], &exact_path_member(),)).is_ok()
        );
        assert!(
            super::archive_preflight::scan(&raw_archive(&[0x60], &exact_bytes_member(),)).is_ok()
        );
        Ok(())
    }

    #[test]
    fn archive_scanner_rejection_paths_are_instrumented() {
        let valid_member = [0x81, 0x83, 0x60, 0x40, 0x00];
        assert!(super::archive_preflight::scan(&raw_archive(&[0x60], &valid_member)).is_ok());
        assert!(super::archive_preflight::scan(&raw_archive_with_header(
            &[0x9a, 0, 0, 0, 6],
            &[0x60],
            &[0x80],
        ))
        .is_ok());
        assert!(super::archive_preflight::scan(&raw_archive_with_header(
            &[0x9b, 0, 0, 0, 0, 0, 0, 0, 6],
            &[0x60],
            &[0x80],
        ))
        .is_ok());
        assert!(super::archive_preflight::scan(&[0x9f]).is_err());
        assert!(super::archive_preflight::scan(&raw_archive(&[0xf0], &[])).is_err());
        assert!(super::archive_preflight::scan(&raw_archive(&[0xa0], &[])).is_err());
        assert!(super::archive_preflight::scan(&[0x80]).is_err());
        assert!(super::archive_preflight::scan(&[0x87]).is_err());

        let too_many_members = [0x9a, 0, 1, 0, 1];
        assert!(super::archive_preflight::scan(&raw_archive(&[0x60], &too_many_members,)).is_err());

        let mut huge_member = vec![0x81, 0x83, 0x60, 0x5b];
        huge_member.extend_from_slice(&(MAX_MEMBER_BYTES + 1).to_be_bytes());
        assert!(super::archive_preflight::scan(&raw_archive(&[0x60], &huge_member)).is_err());

        let long_path = [0x81, 0x83, 0x79, 0x01, 0x01];
        assert!(super::archive_preflight::scan(&raw_archive(&[0x60], &long_path)).is_err());
        let oversized_member_array = [0x81, 0x83, 0x9a, 0, 1, 0, 1];
        assert!(
            super::archive_preflight::scan(&raw_archive(&[0x60], &oversized_member_array)).is_err()
        );
        assert!(
            super::archive_preflight::scan(&raw_archive(&[0x60], &[0x81, 0x82, 0x60, 0x40],))
                .is_err()
        );
        assert!(super::archive_preflight::scan(&raw_archive(
            &[0x60],
            &[0x81, 0x83, 0x00, 0x40, 0x00],
        ))
        .is_err());
        assert!(super::archive_preflight::scan(&raw_archive(
            &[0x60],
            &[0x81, 0x83, 0x60, 0x00, 0x00],
        ))
        .is_err());
        assert!(super::archive_preflight::scan(&raw_archive(
            &[0x60],
            &[0x81, 0x83, 0x60, 0x40, 0x40],
        ))
        .is_err());

        let profile_member = [0x83, 0x60, 0x40, 0x02];
        let duplicate_profiles = [
            0x82,
            profile_member[0],
            profile_member[1],
            profile_member[2],
            profile_member[3],
            profile_member[0],
            profile_member[1],
            profile_member[2],
            profile_member[3],
        ];
        assert!(
            super::archive_preflight::scan(&raw_archive(&[0x60], &duplicate_profiles)).is_err()
        );

        let mut nested = vec![0x60];
        for _ in 0..=usize::from(MAX_STRUCTURAL_NESTING) {
            let mut next = vec![0x81];
            next.extend_from_slice(&nested);
            nested = next;
        }
        assert!(super::archive_preflight::scan(&raw_archive(&nested, &[])).is_err());

        let mut trailing = raw_archive(&[0x60], &[0x80]);
        trailing.push(0);
        assert!(super::archive_preflight::scan(&trailing).is_err());
        assert!(super::archive_preflight::scan(&[]).is_err());
        assert!(super::archive_preflight::scan(&[0x9b]).is_err());
        assert!(super::archive_preflight::scan(&[0x86]).is_err());
        assert!(super::archive_preflight::scan(&[0x86, 0x9b]).is_err());
        assert!(
            super::archive_preflight::scan(&raw_archive(&[0x60], &[0x81, 0x83, 0x60, 0x40],))
                .is_err()
        );
        assert!(
            preflight_archive(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err()
        );
        assert!(
            preflight_archive(&[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err()
        );
    }

    fn exercise_manifest_decoder_errors() {
        assert!(super::decode_manifest(&Value::Array(vec![
            Value::Null,
            Value::Integer(0_u64.into()),
            Value::Integer(0_u64.into()),
            Value::Bytes(vec![0; 32]),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
        ]))
        .is_err());
        assert!(super::decode_manifest(&Value::Array(vec![
            Value::Text(super::CONFORMANCE_BUNDLE_MAGIC_V1.to_owned()),
            Value::Integer(99_u64.into()),
            Value::Integer(99_u64.into()),
            Value::Null,
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
        ]))
        .is_err());
        assert!(super::decode_manifest(&manifest_with_member(Value::Array(Vec::new()))).is_err());
        for fields in [
            vec![
                Value::Null,
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(0_u64.into()),
            ],
            vec![
                Value::Text("member".to_owned()),
                Value::Null,
                Value::Bytes(vec![0; 32]),
                Value::Integer(0_u64.into()),
            ],
            vec![
                Value::Text("member".to_owned()),
                Value::Integer(0_u64.into()),
                Value::Null,
                Value::Integer(0_u64.into()),
            ],
            vec![
                Value::Text("member".to_owned()),
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(99_u64.into()),
            ],
        ] {
            assert!(super::decode_manifest(&manifest_with_member(Value::Array(fields))).is_err());
        }
        assert!(super::decode_manifest(&manifest_with_expected(Value::Array(Vec::new()))).is_err());
        for fields in [
            vec![
                Value::Null,
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(0_u64.into()),
                Value::Text("member".to_owned()),
                Value::Bytes(vec![0; 32]),
            ],
            vec![
                Value::Text("case".to_owned()),
                Value::Integer(99_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(0_u64.into()),
                Value::Text("member".to_owned()),
                Value::Bytes(vec![0; 32]),
            ],
            vec![
                Value::Text("case".to_owned()),
                Value::Integer(0_u64.into()),
                Value::Null,
                Value::Integer(0_u64.into()),
                Value::Text("member".to_owned()),
                Value::Bytes(vec![0; 32]),
            ],
            vec![
                Value::Text("case".to_owned()),
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(99_u64.into()),
                Value::Text("member".to_owned()),
                Value::Bytes(vec![0; 32]),
            ],
            vec![
                Value::Text("case".to_owned()),
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(0_u64.into()),
                Value::Null,
                Value::Bytes(vec![0; 32]),
            ],
            vec![
                Value::Text("case".to_owned()),
                Value::Integer(0_u64.into()),
                Value::Bytes(vec![0; 32]),
                Value::Integer(0_u64.into()),
                Value::Text("member".to_owned()),
                Value::Null,
            ],
        ] {
            assert!(super::decode_manifest(&manifest_with_expected(Value::Array(fields))).is_err());
        }
    }

    fn exercise_member_decoder_errors() {
        for fields in [
            vec![
                Value::Null,
                Value::Bytes(vec![1]),
                Value::Integer(0_u64.into()),
            ],
            vec![
                Value::Text("member".to_owned()),
                Value::Null,
                Value::Integer(0_u64.into()),
            ],
            vec![
                Value::Text("member".to_owned()),
                Value::Bytes(vec![1]),
                Value::Integer(99_u64.into()),
            ],
        ] {
            assert!(super::decode_member(&Value::Array(fields)).is_err());
        }
    }

    #[test]
    fn archive_decoder_and_cap_rejection_paths_are_instrumented(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        let mut invalid_unsigned = bundle.clone();
        invalid_unsigned.manifest.magic = "invalid".to_owned();
        assert_eq!(
            invalid_unsigned.to_canonical_cbor(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        assert_eq!(
            invalid_unsigned.sign(&signing_key),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );

        let mut invalid_profile = bundle.clone();
        let profile_member = invalid_profile
            .members
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Profile)
            .ok_or(BundleContractErrorV1::MemberMissing)?;
        profile_member.bytes = vec![0x01];
        assert_eq!(
            invalid_profile.validate(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );

        let canonical = bundle.to_canonical_cbor()?;
        let magic_len = super::CONFORMANCE_BUNDLE_MAGIC_V1.len();
        let version_index = 1 + 1 + usize::from(magic_len >= 24) + magic_len;
        assert_eq!(canonical[version_index], 1);
        let mut noncanonical = canonical.clone();
        noncanonical.splice(version_index..=version_index, [0x18, 0x01]);
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&noncanonical),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        let mut negative_version = canonical;
        negative_version[version_index] = 0x20;
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&negative_version),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut bad_magic_value = bundle_value(&bundle);
        if let Value::Array(fields) = &mut bad_magic_value {
            fields[0] = Value::Text("wrong magic".to_owned());
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&bad_magic_value)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        for field_index in [4_usize, 5] {
            let mut invalid_value = bundle_value(&bundle);
            if let Value::Array(fields) = &mut invalid_value {
                fields[field_index] = Value::Bytes(Vec::new());
            }
            assert_eq!(
                ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&invalid_value)?),
                Err(BundleContractErrorV1::ArchiveEncodingInvalid)
            );
        }

        assert_eq!(
            super::decode_manifest(&Value::Null),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            super::decode_member(&Value::Null),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        exercise_manifest_decoder_errors();
        exercise_member_decoder_errors();
        assert_eq!(
            archive_u64(&Value::Integer((-1_i64).into())),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            super::archive_digest::<32>(&Value::Bytes(Vec::new())),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        for code in 0..=14 {
            assert_eq!(super::decode_member_role(code).is_ok(), code < 14);
        }
        for code in 0..=2 {
            assert_eq!(super::decode_bundle_mode(code).is_ok(), code < 2);
        }
        for code in 0..=4 {
            assert_eq!(super::decode_lifecycle(code).is_ok(), code < 4);
        }
        for code in 0..=7 {
            assert_eq!(super::decode_claim_layer(code).is_ok(), code < 7);
        }

        Ok(())
    }

    #[test]
    fn archive_field_rejection_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        let mut invalid_key = bundle.clone();
        let mut invalid_key_bytes = [0_u8; 32];
        invalid_key_bytes[31] = 0xff;
        invalid_key.signer_public_key = PublicKey::from_bytes(invalid_key_bytes);
        assert_eq!(
            invalid_key.validate(),
            Err(BundleContractErrorV1::SignatureInvalid)
        );

        let mut invalid_field_type = bundle_value(&bundle);
        if let Value::Array(fields) = &mut invalid_field_type {
            fields[0] = Value::Null;
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&invalid_field_type)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        let mut invalid_manifest = bundle_value(&bundle);
        if let Value::Array(fields) = &mut invalid_manifest {
            fields[2] = Value::Null;
        }
        assert_eq!(
            ConformanceBundleV1::from_canonical_cbor(&encode_archive_value(&invalid_manifest)?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        Ok(())
    }

    #[test]
    fn bundle_cap_rejection_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        assert_eq!(
            validate_member_count(MAX_MEMBERS + 1),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );
        assert_eq!(
            validate_member_size(MAX_MEMBER_BYTES + 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(
            validate_total_bytes(MAX_TOTAL_BUNDLE_BYTES + 1),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        for role in [
            BundleMemberRoleV1::FixtureInput,
            BundleMemberRoleV1::ExpectedResult,
            BundleMemberRoleV1::Profile,
        ] {
            assert!(required_support_digests(&tests::profile(), role).is_empty());
        }

        let mut path_limited = tests::profile();
        path_limited
            .evaluator_protocol
            .hard_caps
            .max_member_path_bytes = 1;
        assert_eq!(
            validate_selected_bundle_caps(&path_limited, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        let mut member_limited = tests::profile();
        member_limited.evaluator_protocol.hard_caps.max_member_bytes = 1;
        assert_eq!(
            validate_selected_bundle_caps(&member_limited, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        let mut total_limited = tests::profile();
        total_limited
            .evaluator_protocol
            .hard_caps
            .max_total_bundle_bytes = 1;
        total_limited.evaluator_protocol.hard_caps.max_member_bytes = 64 * 1024 * 1024;
        assert_eq!(
            validate_selected_bundle_caps(&total_limited, &bundle),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        let mut invalid_profile = tests::profile();
        invalid_profile.lifecycle = super::ProfileLifecycleV1::Stable;
        assert!(signed_bundle_for(&invalid_profile, BundleModeV1::Local).is_err());
        Ok(())
    }

    #[test]
    fn private_archive_and_cap_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        let value = bundle_value(&bundle);
        assert!(matches!(value, Value::Array(_)));
        assert_eq!(
            preflight_archive(&encode_archive_value(&Value::Null)?),
            Ok(())
        );
        assert_eq!(
            preflight_archive(&encode_archive_value(&Value::Array(vec![Value::Null]))?),
            Ok(())
        );
        assert_eq!(
            preflight_archive(&encode_archive_value(&Value::Text("a".repeat(257)))?),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );

        assert_eq!(
            archive_array_exact(&Value::Array(vec![Value::Null]), 0),
            Err(BundleContractErrorV1::ArchiveEncodingInvalid)
        );
        assert_eq!(
            archive_array_bounded(&Value::Array(vec![Value::Null]), 0),
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
            validate_archive_caps(&bundle, &Value::Null, usize::MAX),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert_eq!(validate_archive_caps(&bundle, &Value::Null, 1), Ok(()));
        let profile = tests::profile();
        let exact_total =
            usize::try_from(profile.evaluator_protocol.hard_caps.max_total_bundle_bytes)?;
        assert_eq!(
            validate_archive_caps(&bundle, &Value::Null, exact_total),
            Ok(())
        );
        let profile_bytes = [1_u8];
        let preflight = super::ArchivePreflight {
            profile_bytes: Some(&profile_bytes),
            member_count: 1,
            total_member_bytes: 1,
            largest_member_bytes: 1,
            largest_member_path_bytes: 1,
            maximum_depth: 1,
        };
        assert_eq!(
            validate_preflight_archive_caps(&profile, &preflight, 1),
            Ok(())
        );
        assert_eq!(validate_selected_bundle_caps(&profile, &bundle), Ok(()));
        let mut invalid_inputs = bundle.members;
        let input_index = invalid_inputs
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::FixtureInput)
            .ok_or("missing fixture input")?;
        invalid_inputs[input_index].bytes.clear();
        assert_eq!(
            validate_fixture_inputs_for_mode(&profile, None, &invalid_inputs),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let nested = (0..usize::from(MAX_STRUCTURAL_NESTING))
            .fold(Value::Null, |value, _| Value::Array(vec![value]));
        assert_eq!(
            super::value_depth(&nested),
            usize::from(MAX_STRUCTURAL_NESTING) + 1
        );
        Ok(())
    }

    #[test]
    fn bundle_validation_error_paths_are_instrumented() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = signed_bundle()?;
        let profile = tests::profile();
        let mut missing_profile = bundle.clone();
        missing_profile
            .members
            .retain(|member| member.role != BundleMemberRoleV1::Profile);
        assert_eq!(
            validate_archive_caps(&missing_profile, &Value::Null, 1),
            Err(BundleContractErrorV1::MemberMissing)
        );
        assert_eq!(
            validate_selected_bundle_caps(&profile, &missing_profile),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let profile_index = bundle
            .members
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Profile)
            .ok_or("missing profile")?;
        let mut invalid_profile = bundle.clone();
        invalid_profile.members[profile_index].bytes = vec![1];
        assert_eq!(
            validate_archive_caps(&invalid_profile, &Value::Null, 1),
            Err(BundleContractErrorV1::ProfileInvalid)
        );

        let mut missing_support = bundle.members.clone();
        missing_support.retain(|member| member.role != BundleMemberRoleV1::Schema);
        assert_eq!(
            validate_supporting_members(&profile, &missing_support),
            Err(BundleContractErrorV1::MemberMissing)
        );
        let mut empty_support = bundle.members.clone();
        let support_index = empty_support
            .iter()
            .position(|member| member.role == BundleMemberRoleV1::Schema)
            .ok_or("missing schema support member")?;
        empty_support[support_index].bytes.clear();
        assert_eq!(
            validate_supporting_members(&profile, &empty_support),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        let mut invalid_expected = bundle.manifest.clone();
        invalid_expected.expected_results[0].digest = [0; 32];
        assert_eq!(
            validate_expected_results(&profile, &invalid_expected, &bundle.members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
        Ok(())
    }

    #[test]
    fn bundle_pair_rejects_invalid_local_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let profile = tests::profile();
        let mut local = signed_bundle_for(&profile, BundleModeV1::Local)?;
        local.manifest.magic = "invalid".to_owned();
        let pair = ConformanceBundlePairV1 {
            local,
            air_gapped: signed_bundle_for(&profile, BundleModeV1::AirGapped)?,
        };
        assert_eq!(
            pair.validate(),
            Err(BundleContractErrorV1::LifecycleInvalid)
        );
        Ok(())
    }
}

#[cfg(test)]
mod instrumented_candidate_entrypoints {
    use super::tests;
    use super::{BundleContractErrorV1, BundleMemberRoleV1, BundleModeV1, ConformanceBundleV1};

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
        let mut profile = tests::profile();
        let (members, _) = tests::bundle_inputs(&profile, BundleModeV1::Local)?;
        assert_eq!(
            super::validate_authority_members(&profile, &members),
            Ok(())
        );

        let mut missing_inventory = members.clone();
        missing_inventory.retain(|member| member.role != BundleMemberRoleV1::AuthorityInventory);
        assert_eq!(
            super::validate_authority_members(&profile, &missing_inventory),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut unbound_inventory = members;
        let provenance = unbound_inventory
            .iter_mut()
            .find(|member| member.role == BundleMemberRoleV1::Provenance)
            .ok_or(BundleContractErrorV1::MemberMissing)?;
        provenance.bytes = b"{}".to_vec();
        provenance.digest = *blake3::hash(&provenance.bytes).as_bytes();
        profile.provenance_digest = provenance.digest;
        assert_eq!(
            super::validate_authority_members(&profile, &unbound_inventory),
            Err(BundleContractErrorV1::MemberDigestMismatch)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn draft_validation_omits_pending_authority_artifacts() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut draft = signed_draft_bundle()?;
        draft.members.retain(|member| {
            !matches!(
                member.role,
                BundleMemberRoleV1::AuthorityFixture | BundleMemberRoleV1::AuthorityExpectedResult
            )
        });
        draft.rebuild_member_descriptors();
        assert!(draft.validate().is_ok());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn candidate_requires_concrete_authority_inventory() -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = tests::profile();
        profile.lifecycle = super::ProfileLifecycleV1::Candidate;
        profile.profile_digest = profile.digest();
        let (members, expected_results) = tests::bundle_inputs(&profile, BundleModeV1::Local)?;
        assert_eq!(
            ConformanceBundleV1::materialize(
                &profile,
                BundleModeV1::Local,
                members,
                expected_results,
            ),
            Err(BundleContractErrorV1::CandidateEvidenceMissing)
        );
        Ok(())
    }
}
