//! Signed, content-addressed Draft/Candidate conformance bundles.
//!
//! This boundary materializes public bytes and expected results. It never
//! invokes the implementation under test: callers provide fixture and
//! expected-result members, while this module recomputes their digests,
//! validates them against CPF1, and verifies the bundle signature.

use std::collections::BTreeSet;

use ciborium::value::Value;
use pos_core::{CanonicalBytes, PublicKey, Signature};
use pos_crypto::{canonical, signing};
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
const PROFILE_MEMBER_PATH: &str = "profile/CPF1.cbor";

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

/// One byte-bearing member in a materialized bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleMemberV1 {
    /// Canonical relative archive path.
    pub path: String,
    /// Raw public bytes.
    pub bytes: Vec<u8>,
    /// Recomputed BLAKE3 content address.
    pub digest: [u8; 32],
    /// Whether this member is an expected-result payload.
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
            expected_result,
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
        members.push(BundleMemberV1::new(
            PROFILE_MEMBER_PATH,
            profile_bytes,
            false,
        ));
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
            || self.members.len() > MAX_MEMBERS
        {
            return Err(BundleContractErrorV1::LifecycleInvalid);
        }
        let profile_member = self
            .members
            .iter()
            .find(|member| member.path == PROFILE_MEMBER_PATH)
            .ok_or(BundleContractErrorV1::MemberMissing)?;
        let profile = ConformanceProfileV1::from_canonical_cbor(&profile_member.bytes)
            .map_err(|_| BundleContractErrorV1::ProfileInvalid)?;
        if profile.lifecycle != self.manifest.lifecycle
            || profile.profile_digest != self.manifest.profile_digest
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
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
            if descriptor.size_bytes != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
                || descriptor.digest != member.digest
                || member.bytes.is_empty()
                || member.bytes.len() as u64 > MAX_MEMBER_BYTES
                || member.digest != *blake3::hash(&member.bytes).as_bytes()
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            total_bytes = total_bytes
                .checked_add(descriptor.size_bytes)
                .ok_or(BundleContractErrorV1::MemberOutOfBounds)?;
            if contains_secret_marker(&member.bytes) {
                return Err(BundleContractErrorV1::SecretMaterialDetected);
            }
        }
        if total_bytes > MAX_TOTAL_BUNDLE_BYTES {
            return Err(BundleContractErrorV1::MemberOutOfBounds);
        }
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
            })
            .collect();
        self.manifest.expected_results.sort_unstable();
    }

    fn manifest_bytes(&self) -> Result<Vec<u8>, BundleContractErrorV1> {
        canonical::encode(&manifest_value(&self.manifest))
            .map(|bytes| bytes.as_slice().to_vec())
            .map_err(|_| BundleContractErrorV1::EncodingFailed)
    }
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
    let required_layers = [
        ClaimLayerV1::ArtifactIntegrity,
        ClaimLayerV1::ReplayConformance,
        ClaimLayerV1::KnowledgeNonInterference,
        ClaimLayerV1::GatewayClientConformance,
        ClaimLayerV1::PluginConformance,
        ClaimLayerV1::MetricConformance,
        ClaimLayerV1::EmpiricalEvaluation,
    ];
    if !required_layers.iter().all(|required_layer| {
        profile.fixtures.iter().any(|fixture| {
            fixture.claim_layer == *required_layer
                && fixture.modes.iter().any(|mode| {
                    matches!(
                        (manifest.mode, mode),
                        (BundleModeV1::Local, ExecutionModeV1::Local)
                            | (BundleModeV1::AirGapped, ExecutionModeV1::AirGapped)
                    )
                })
        })
    }) {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    let mut seen = BTreeSet::new();
    for expected in &manifest.expected_results {
        if expected.mode != manifest.mode
            || !seen.insert((
                expected.case_id.as_str(),
                expected.claim_layer,
                expected.mode,
            ))
            || expected.digest == [0; 32]
        {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let Some(member) = members
            .iter()
            .find(|member| member.path == expected.member_path)
        else {
            return Err(BundleContractErrorV1::MemberMissing);
        };
        if !member.expected_result || member.bytes.is_empty() || member.digest != expected.digest {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        let Some(fixture) = profile.fixtures.iter().find(|fixture| {
            fixture.case_id == expected.case_id && fixture.claim_layer == expected.claim_layer
        }) else {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        };
        if !fixture.modes.contains(&match expected.mode {
            BundleModeV1::Local => ExecutionModeV1::Local,
            BundleModeV1::AirGapped => ExecutionModeV1::AirGapped,
        }) {
            return Err(BundleContractErrorV1::ExpectedResultMismatch);
        }
        if let ExpectedResultV1::CanonicalBytes { digest, bytes } = &fixture.expected {
            if *digest != expected.digest || bytes.is_empty() {
                return Err(BundleContractErrorV1::ExpectedResultMismatch);
            }
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
                expected.case_id == fixture.case_id && expected.claim_layer == fixture.claim_layer
            })
    }) {
        return Err(BundleContractErrorV1::MemberMissing);
    }
    Ok(())
}

fn expected_identity(values: &[BundleExpectedResultV1]) -> Vec<(&str, ClaimLayerV1, [u8; 32])> {
    values
        .iter()
        .map(|value| (value.case_id.as_str(), value.claim_layer, value.digest))
        .collect()
}

fn validate_member_path(path: &str) -> Result<(), BundleContractErrorV1> {
    if path.is_empty()
        || path.len() > MAX_MEMBER_PATH_BYTES
        || path.starts_with('/')
        || path.contains("..")
        || path.split('/').any(str::is_empty)
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
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn members_strictly_ordered(values: &[BundleMemberV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].path.as_str() < pair[1].path.as_str())
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
                        Value::Integer(expected.mode.code().into()),
                        Value::Integer(claim_layer_code(expected.claim_layer).into()),
                        Value::Text(expected.member_path.clone()),
                        Value::Bytes(expected.digest.to_vec()),
                    ])
                })
                .collect(),
        ),
    ])
}

const fn claim_layer_code(layer: ClaimLayerV1) -> u64 {
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
        RedactionStateV1, ReplayClaimV1, SubjectAdapterKindV1, VerificationOutcomeV1,
    };

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn profile() -> ConformanceProfileV1 {
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
            .map(|(index, claim_layer)| {
                let expected_bytes = format!("expected-result-{index}").into_bytes();
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
                        size_bytes: 1,
                        digest: digest(3),
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
            })
            .collect();
        let mut profile = ConformanceProfileV1 {
            profile_id: "pigloros.w8.conformance-bundle".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Candidate,
            normative_spec_digest: digest(12),
            execution_profile_digests: vec![digest(1)],
            public_schema_digests: vec![digest(2)],
            fixtures,
            allowed_divergences: Vec::new(),
            evaluator_protocol: EvaluatorProtocolV1 {
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
            },
            independence_requirements: IndependenceRequirementsV1 {
                technical_independence_required: true,
                authorship_independence_required: true,
                organizational_independence_required: false,
                trust_policy_snapshot_digest: digest(16),
                requirements_digest: digest(17),
            },
            compatibility_digest: digest(18),
            limitations_digest: digest(19),
            provenance_digest: digest(20),
            previous_profile_digest: None,
            stable_evidence: Vec::new(),
            profile_digest: [0; 32],
        };
        profile.profile_digest = profile.digest();
        profile
    }

    fn bundle_inputs(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
    ) -> (Vec<BundleMemberV1>, Vec<BundleExpectedResultV1>) {
        let execution_mode = match mode {
            BundleModeV1::Local => ExecutionModeV1::Local,
            BundleModeV1::AirGapped => ExecutionModeV1::AirGapped,
        };
        let mut members = Vec::new();
        let mut expected_results = Vec::new();
        for (index, fixture) in profile.fixtures.iter().enumerate() {
            let bytes = match &fixture.expected {
                ExpectedResultV1::CanonicalBytes { bytes, .. } => bytes.clone(),
                ExpectedResultV1::TypedFailure(_) | ExpectedResultV1::AllowedDivergence { .. } => {
                    format!("expected-result-{index}").into_bytes()
                }
            };
            let path = format!("expected/case-{index:02}.bin");
            let member = BundleMemberV1::new(path.clone(), bytes, true);
            expected_results.push(BundleExpectedResultV1 {
                case_id: fixture.case_id.clone(),
                claim_layer: fixture.claim_layer,
                mode,
                member_path: path,
                digest: member.digest,
            });
            assert!(fixture.modes.contains(&execution_mode));
            members.push(member);
        }
        (members, expected_results)
    }

    fn signed_bundle(
        profile: &ConformanceProfileV1,
        mode: BundleModeV1,
    ) -> Result<ConformanceBundleV1, Box<dyn std::error::Error>> {
        let (members, expected_results) = bundle_inputs(profile, mode);
        let bundle = ConformanceBundleV1::materialize(profile, mode, members, expected_results)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        Ok(bundle.sign(&signing_key)?)
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
            validate_member_path("../secret"),
            Err(BundleContractErrorV1::MemberOutOfBounds)
        );
        assert!(contains_secret_marker(b"PUBLIC PRIVATE_KEY material"));
        assert!(!contains_secret_marker(b"public expected result"));
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
            }],
            expected_results: vec![BundleExpectedResultV1 {
                case_id: "case".to_owned(),
                claim_layer: ClaimLayerV1::ArtifactIntegrity,
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
        assert_ne!(bundle.bundle_digest()?, [0; 32]);
        assert_eq!(bundle.manifest.profile_digest, profile.profile_digest);
        Ok(())
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

        let mut changed_profile = profile.clone();
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
    fn validation_rejects_profile_and_manifest_contract_mismatches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut stable_profile = profile.clone();
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
            Err(BundleContractErrorV1::MemberMissing)
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

        let mut not_an_expected_result = bundle.members.clone();
        not_an_expected_result[0].expected_result = false;
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
            Err(BundleContractErrorV1::MemberMissing)
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

        let mut missing_expected = bundle.manifest;
        missing_expected.expected_results.remove(0);
        assert_eq!(
            validate_expected_results(&profile, &missing_expected, &bundle.members),
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
        tampered.members[0].bytes[0] ^= 1;
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

        let mut undeclared = signed_bundle(&profile, BundleModeV1::Local)?;
        undeclared.manifest.members[0].path = "expected/case-00-wrong".to_owned();
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
    fn validation_rejects_secret_payloads_and_air_gapped_network_access(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let mut secret = signed_bundle(&profile, BundleModeV1::Local)?;
        secret.members[0].bytes = b"PRIVATE KEY material".to_vec();
        secret.members[0].digest = *blake3::hash(&secret.members[0].bytes).as_bytes();
        secret.manifest.members[0].digest = secret.members[0].digest;
        secret.manifest.members[0].size_bytes = secret.members[0].bytes.len() as u64;
        assert_eq!(
            secret.validate(),
            Err(BundleContractErrorV1::SecretMaterialDetected)
        );

        let mut network_profile = profile;
        network_profile.fixtures[0]
            .capability_policy
            .network_allowed = true;
        let (members, expected_results) = bundle_inputs(&network_profile, BundleModeV1::AirGapped);
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
            })
            .collect();
        let expected_error = validate_expected_results(&network_profile, &manifest, &members);
        assert_eq!(expected_error, Err(BundleContractErrorV1::AirGappedNetwork));
        Ok(())
    }
}
