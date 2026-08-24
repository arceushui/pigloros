//! Signed, content-addressed Draft/Candidate conformance bundles.
//!
//! This boundary materializes public bytes and expected results. It never
//! invokes the implementation under test: callers provide fixture and
//! expected-result members, while this module recomputes their digests,
//! validates them against CPF1, and verifies the bundle signature.

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
const INPUT_MEMBER_PREFIX: &str = "inputs/";

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
        {
            return Err(BundleContractErrorV1::LifecycleInvalid);
        }
        validate_member_count(self.members.len())?;
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
        validate_fixture_inputs(&profile, &self.members)?;
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
            let expected_reference_count = self
                .manifest
                .expected_results
                .iter()
                .filter(|expected| expected.member_path == member.path)
                .count();
            if member.expected_result && expected_reference_count != 1 {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if !member.expected_result
                && member.path != PROFILE_MEMBER_PATH
                && !profile.fixtures.iter().any(|fixture| {
                    fixture.inputs.iter().any(|input| {
                        member.path
                            == fixture_input_path(
                                &fixture.case_id,
                                &fixture.execution_profile_digest,
                                &input.member_id,
                            )
                    })
                })
            {
                return Err(BundleContractErrorV1::UndeclaredMember);
            }
            if descriptor.size_bytes != u64::try_from(member.bytes.len()).unwrap_or(u64::MAX)
                || descriptor.digest != member.digest
                || member.bytes.is_empty()
                || member.digest != *blake3::hash(&member.bytes).as_bytes()
            {
                return Err(BundleContractErrorV1::MemberDigestMismatch);
            }
            validate_member_size(member.bytes.len() as u64)?;
            total_bytes = total_bytes
                .checked_add(descriptor.size_bytes)
                .ok_or(BundleContractErrorV1::MemberOutOfBounds)?;
            if contains_secret_marker(&member.bytes) {
                return Err(BundleContractErrorV1::SecretMaterialDetected);
            }
        }
        validate_total_bytes(total_bytes)?;
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

fn validate_total_bytes(total_bytes: u64) -> Result<(), BundleContractErrorV1> {
    if total_bytes > MAX_TOTAL_BUNDLE_BYTES {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_member_count(member_count: usize) -> Result<(), BundleContractErrorV1> {
    if member_count > MAX_MEMBERS {
        Err(BundleContractErrorV1::LifecycleInvalid)
    } else {
        Ok(())
    }
}

fn validate_member_size(member_size: u64) -> Result<(), BundleContractErrorV1> {
    if member_size > MAX_MEMBER_BYTES {
        Err(BundleContractErrorV1::MemberOutOfBounds)
    } else {
        Ok(())
    }
}

fn fixture_input_path(
    case_id: &str,
    execution_profile_digest: &[u8; 32],
    member_id: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"PiglorOS.CPF1InputPath.v1\0");
    append_path_component(&mut input, case_id);
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
    input.push(claim_layer_code(claim_layer) as u8);
    input.extend_from_slice(execution_profile_digest);
    format!("expected/{}.bin", blake3::hash(&input).to_hex())
}

fn append_path_component(input: &mut Vec<u8>, value: &str) {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
}

fn validate_fixture_inputs(
    profile: &ConformanceProfileV1,
    members: &[BundleMemberV1],
) -> Result<(), BundleContractErrorV1> {
    for fixture in &profile.fixtures {
        for input in &fixture.inputs {
            let path = fixture_input_path(
                &fixture.case_id,
                &fixture.execution_profile_digest,
                &input.member_id,
            );
            let Some(member) = members.iter().find(|member| member.path == path) else {
                return Err(BundleContractErrorV1::MemberMissing);
            };
            if member.expected_result
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
        if !member.expected_result || member.bytes.is_empty() || member.digest != expected.digest {
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
                if *digest != expected.digest
                    || *digest != *blake3::hash(bytes).as_bytes()
                    || bytes.is_empty()
                {
                    return Err(BundleContractErrorV1::ExpectedResultMismatch);
                }
                bytes.clone()
            }
            typed_or_divergent => {
                crate::profile_contract::expected_result_bytes(typed_or_divergent)
                    .map_err(|_| BundleContractErrorV1::ExpectedResultMismatch)?
            }
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

fn expected_identity(
    values: &[BundleExpectedResultV1],
) -> Vec<(&str, ClaimLayerV1, [u8; 32], &str, [u8; 32])> {
    values
        .iter()
        .map(|value| {
            (
                value.case_id.as_str(),
                value.claim_layer,
                value.execution_profile_digest,
                value.member_path.as_str(),
                value.digest,
            )
        })
        .collect()
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
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn members_strictly_ordered(values: &[BundleMemberV1]) -> bool {
    values.windows(2).all(|pair| {
        pair[0].path.as_str() < pair[1].path.as_str()
            && !pair[0].path.eq_ignore_ascii_case(&pair[1].path)
    })
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
        RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, SubjectAdapterKindV1,
        VerificationOutcomeV1,
    };

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn profile_fixture(index: usize, claim_layer: ClaimLayerV1) -> FixtureDescriptorV1 {
        let expected_bytes = format!("expected-result-{index}").into_bytes();
        let input_bytes = format!("fixture-input-{index}").into_bytes();
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
            .map(|(index, claim_layer)| profile_fixture(index, claim_layer))
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
            evaluator_protocol: evaluator_protocol(),
            independence_requirements: independence_requirements(),
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
            for input in &fixture.inputs {
                let input_bytes = format!("fixture-input-{index}").into_bytes();
                members.push(BundleMemberV1::new(
                    fixture_input_path(
                        &fixture.case_id,
                        &fixture.execution_profile_digest,
                        &input.member_id,
                    ),
                    input_bytes,
                    false,
                ));
            }
            let bytes = match &fixture.expected {
                ExpectedResultV1::CanonicalBytes { bytes, .. } => bytes.clone(),
                typed_or_divergent => {
                    crate::profile_contract::expected_result_bytes(typed_or_divergent)
                        .expect("test fixture expected result must encode")
                }
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

    fn expected_member_index(bundle: &ConformanceBundleV1) -> usize {
        bundle
            .members
            .iter()
            .position(|member| member.expected_result)
            .expect("test bundle has an expected-result member")
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
        assert!(validate_member_path("nested/result").is_ok());
        assert!(contains_secret_marker(b"PUBLIC PRIVATE_KEY material"));
        assert!(!contains_secret_marker(b"public expected result"));
    }

    #[test]
    fn derived_member_paths_bind_complete_fixture_identity() {
        let first = digest(1);
        let second = digest(2);
        assert_ne!(
            fixture_input_path("case/a", &first, "member/b"),
            fixture_input_path("case", &first, "a/member/b")
        );
        assert_ne!(
            fixture_input_path("case", &first, "member"),
            fixture_input_path("case", &second, "member")
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
        let mut descending = ordered.clone();
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
        let expected_index = expected_member_index(&air_with_other_path);
        air_with_other_path.members[expected_index].path = alternate_path.clone();
        air_with_other_path.manifest.members[expected_index].path = alternate_path.clone();
        air_with_other_path.manifest.expected_results[0].member_path = alternate_path;
        let air_with_other_path = air_with_other_path.sign(&signing_key)?;
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

        let mut typed_profile = profile.clone();
        typed_profile.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::InvalidEncoding);
        let typed_bytes =
            crate::profile_contract::expected_result_bytes(&typed_profile.fixtures[0].expected)
                .expect("typed failure has a canonical public representation");
        let typed_digest = *blake3::hash(&typed_bytes).as_bytes();
        let mut typed_members = bundle.members.clone();
        let typed_path = expected_member_path(
            &typed_profile.fixtures[0].case_id,
            typed_profile.fixtures[0].claim_layer,
            &typed_profile.fixtures[0].execution_profile_digest,
        );
        let typed_member_index = typed_members
            .iter()
            .position(|member| member.path == typed_path)
            .expect("case-00 expected member");
        typed_members[typed_member_index] = BundleMemberV1::new(typed_path, typed_bytes, true);
        let mut typed_manifest = bundle.manifest.clone();
        typed_manifest.expected_results[0].digest = typed_digest;
        assert_eq!(
            validate_expected_results(&typed_profile, &typed_manifest, &typed_members),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn expected_result_member_guards_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;

        let mut wrong_digest_members = bundle.members.clone();
        let expected_index = expected_member_index(&bundle);
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
        let expected_index = expected_member_index(&bundle);
        empty_members[expected_index].bytes.clear();
        empty_members[expected_index].digest =
            *blake3::hash(&empty_members[expected_index].bytes).as_bytes();
        let mut empty_manifest = bundle.manifest.clone();
        empty_manifest.expected_results[0].digest = empty_members[expected_index].digest;
        assert_eq!(
            validate_expected_results(&empty_profile, &empty_manifest, &empty_members),
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        );
        Ok(())
    }

    #[test]
    fn mandatory_fixture_matching_requires_case_and_layer_and_execution_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut profile = profile();
        let same_layer = profile_fixture(7, profile.fixtures[0].claim_layer);
        profile.fixtures.push(same_layer);
        profile.profile_digest = profile.digest();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let mut manifest = bundle.manifest.clone();
        manifest
            .expected_results
            .retain(|expected| expected.case_id != "case-00");
        assert_eq!(
            validate_expected_results(&profile, &manifest, &bundle.members),
            Err(BundleContractErrorV1::MemberMissing)
        );

        let mut profile = profile();
        let mut same_case_and_layer = profile_fixture(7, profile.fixtures[0].claim_layer);
        same_case_and_layer.case_id = profile.fixtures[0].case_id.clone();
        same_case_and_layer.execution_profile_digest = digest(99);
        profile.execution_profile_digests.push(digest(99));
        profile.fixtures.push(same_case_and_layer);
        profile.profile_digest = profile.digest();
        let bundle = signed_bundle(&profile, BundleModeV1::Local)?;
        let mut manifest = bundle.manifest.clone();
        manifest
            .expected_results
            .retain(|expected| expected.execution_profile_digest != digest(99));
        assert_eq!(
            validate_expected_results(&profile, &manifest, &bundle.members),
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
        let expected_index = expected_member_index(&tampered);
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
    fn validation_rejects_secret_payloads_and_air_gapped_network_access(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile();
        let mut secret = signed_bundle(&profile, BundleModeV1::Local)?;
        let expected_index = expected_member_index(&secret);
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
