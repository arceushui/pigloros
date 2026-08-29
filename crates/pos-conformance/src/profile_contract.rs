//! Immutable public conformance-profile and evaluator-request contracts.
//!
//! This module deliberately references an execution profile only by digest.
//! ADR-058 owns execution behaviour; this contract owns the fixture oracle,
//! evaluator identity, independence evidence, and lifecycle claim.

use crate::{
    ArtifactDescriptorV1, CaseOutcomeStatusV1, ClaimLayerV1, ConformanceReportV1,
    DivergenceMismatchKindV1, ExecutionModeV1, FixtureFamilyV1, FixtureProviderKeyV1,
    FixtureProviderRegistryBindingV1, ImplementationIdentityV1, IndependenceEvidenceV1,
    ProfileCaseOutcomeV1, RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, VerificationOutcomeV1,
};
use ciborium::value::Value;
use pos_core::{CanonicalBytes, PublicKey, Signature};
use pos_crypto::signing;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Magic for the immutable CPF1 conformance-profile record.
pub const CONFORMANCE_PROFILE_MAGIC_V1: &str = "CPF1";
/// Magic for the public evaluator request record.
pub const EVALUATOR_REQUEST_MAGIC_V1: &str = "EVR1";
type CaseOutcomeV1 = ProfileCaseOutcomeV1;
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXECUTION_PROFILES: usize = 64;
const MAX_FIXTURES: usize = 65_536;
const MAX_STRING_BYTES: usize = 256;
const MAX_SEMVER_COMPONENT_BYTES: usize = 10;
const MAX_COORDINATE_BYTES: usize = 128;
const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_COMPRESSION_EXPANSION: u32 = 100;
const MAX_STRUCTURAL_NESTING: u8 = 32;
/// Closed safe errors exposed by the CPF1 and evaluator-request interfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ConformanceContractError {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// A required value exceeds its specified bound.
    FieldOutOfBounds,
    /// A pre-sorted record list is not canonical or contains a duplicate identity.
    NonCanonicalOrder,
    /// A content-addressed value does not match its declared digest.
    FixtureDigestMismatch,
    /// A fixture omitted its immutable expected result.
    ExpectedResultMissing,
    /// Required independent implementation evidence is absent or insufficient.
    IndependenceEvidenceMissing,
    /// A result differs without its exact declared divergence class and coordinate.
    DivergenceClassificationMismatch,
    /// The requested profile lifecycle transition is invalid.
    ProfileLifecycleInvalid,
    /// Required source, build, licence, or publication provenance is absent.
    ProvenanceMissing,
    /// A fixture references an execution profile outside the CPF1 inventory.
    UnknownExecutionProfile,
    /// A fixture references a provider that the profile did not require.
    UnknownFixtureProvider,
    /// A fixture's replay claim is stronger than its redaction state permits;
    /// `IncompatibleProfile` remains orthogonal to that state.
    ClaimRedactionMismatch,
}

impl std::fmt::Display for ConformanceContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid conformance contract encoding",
            Self::UnsupportedVersion => "unsupported conformance contract version",
            Self::FieldOutOfBounds => "conformance contract field is out of bounds",
            Self::NonCanonicalOrder => "conformance contract records are not canonically ordered",
            Self::FixtureDigestMismatch => "content does not match its expected digest",
            Self::ExpectedResultMissing => "fixture has no immutable expected result",
            Self::IndependenceEvidenceMissing => "independent implementation evidence is missing",
            Self::DivergenceClassificationMismatch => "divergence is not classified by the profile",
            Self::ProfileLifecycleInvalid => "profile lifecycle transition is invalid",
            Self::ProvenanceMissing => "required conformance provenance is missing",
            Self::UnknownExecutionProfile => "fixture references an unknown execution profile",
            Self::UnknownFixtureProvider => "fixture references an unknown fixture provider",
            Self::ClaimRedactionMismatch => {
                "fixture replay claim is incompatible with its redaction state"
            }
        })
    }
}

impl std::error::Error for ConformanceContractError {}

/// Immutable lifecycle states. There is no reverse or skip transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProfileLifecycleV1 {
    Draft,
    Candidate,
    Stable,
    Retired,
}

impl ProfileLifecycleV1 {
    pub(crate) const fn from_wire_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Draft),
            1 => Some(Self::Candidate),
            2 => Some(Self::Stable),
            3 => Some(Self::Retired),
            _ => None,
        }
    }

    pub(crate) const fn wire_code(self) -> u64 {
        match self {
            Self::Draft => 0,
            Self::Candidate => 1,
            Self::Stable => 2,
            Self::Retired => 3,
        }
    }
}

/// A public adapter used by an evaluator; private Rust and storage access are absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SubjectAdapterKindV1 {
    ExportedArtifact,
    PublicGatewayProtocol,
    PublicPluginProtocol,
}

impl SubjectAdapterKindV1 {
    /// Decode the canonical public catalog name for an evaluator adapter.
    #[must_use]
    pub fn from_catalog_name(name: &str) -> Option<Self> {
        match name {
            "exported-artifact" => Some(Self::ExportedArtifact),
            "public-gateway-protocol" => Some(Self::PublicGatewayProtocol),
            "public-plugin-protocol" => Some(Self::PublicPluginProtocol),
            _ => None,
        }
    }
}

/// One profile-approved classified divergence and its first canonical coordinate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedDivergenceV1 {
    pub classification: DivergenceMismatchKindV1,
    pub first_coordinate: Vec<u8>,
}

/// A namespaced public failure asserted by a strict fixture oracle.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NamespacedFailureV1 {
    pub owner_id: String,
    pub contract_version: String,
    pub code_id: String,
}

/// Exact strict-oracle discriminant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum StrictOracleKindV1 {
    Output,
    Failure,
    Divergence,
}

impl StrictOracleKindV1 {
    const fn wire_code(self) -> u64 {
        match self {
            Self::Output => 0,
            Self::Failure => 1,
            Self::Divergence => 2,
        }
    }

    const fn from_wire_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Output),
            1 => Some(Self::Failure),
            2 => Some(Self::Divergence),
            _ => None,
        }
    }
}

/// A strict fixture oracle. Inactive variant fields are encoded as CBOR null.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictOracleV1 {
    pub kind: StrictOracleKindV1,
    pub output: Option<ArtifactDescriptorV1>,
    pub failure: Option<NamespacedFailureV1>,
    pub divergence: Option<AllowedDivergenceV1>,
}

/// Deterministic resource limits required by every fixture execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicBudgetV1 {
    pub memory_bytes: u64,
    pub cpu_fuel: u64,
    pub host_calls: u64,
    pub event_count: u64,
    pub output_bytes: u64,
    pub storage_bytes: u64,
    pub execution_steps: u64,
    pub simulation_time_ns: u64,
}

/// Operational watchdog information. It is deliberately distinct from the
/// deterministic budget: expiry produces a non-executed result, not evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalSafetyV1 {
    pub watchdog_ms: u64,
}

/// Default-deny network and capability declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityPolicyV1 {
    pub network_allowed: bool,
    pub capability_ids: Vec<String>,
}

/// Required licence and supply-chain provenance for a fixture.
///
/// Draft-only profiles may use domain-separated metadata bindings for the
/// source, build, and publication-review fields. Those bindings identify the
/// records used to construct the draft; they are not attestations that those
/// activities or any conformance execution have been independently verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureProvenanceV1 {
    pub licence_id: String,
    pub notices_digest: [u8; 32],
    pub sbom_digest: [u8; 32],
    pub source_digest: [u8; 32],
    pub build_digest: [u8; 32],
    pub publication_review_digest: [u8; 32],
    pub limitations_digest: [u8; 32],
}

/// A provider-key transition admitted only for a downgrade fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureContractTransitionV1 {
    pub from: FixtureProviderKeyV1,
    pub to: FixtureProviderKeyV1,
}

/// One ordered current-only fixture contract in a CPF1 profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureDescriptorV1 {
    pub case_id: String,
    pub mandatory: bool,
    pub claim_layer: ClaimLayerV1,
    pub family: FixtureFamilyV1,
    pub provider_key: FixtureProviderKeyV1,
    pub subject_adapter: SubjectAdapterKindV1,
    pub execution_profile_digest: [u8; 32],
    pub modes: Vec<ExecutionModeV1>,
    pub schema: ArtifactDescriptorV1,
    pub payload: ArtifactDescriptorV1,
    pub auxiliary: Vec<ArtifactDescriptorV1>,
    pub strict_oracle: StrictOracleV1,
    pub expected_verification_outcome: VerificationOutcomeV1,
    pub expected_verification_error: Option<NamespacedFailureV1>,
    pub replay_claim: ReplayClaimV1,
    pub redaction_state: RedactionStateV1,
    pub deterministic_budget: DeterministicBudgetV1,
    pub operational_safety: OperationalSafetyV1,
    pub capability_policy: CapabilityPolicyV1,
    pub trust_policy_snapshot_digest: Option<[u8; 32]>,
    pub release_admission_digest: Option<[u8; 32]>,
    pub provenance: FixtureProvenanceV1,
    pub transition: Option<FixtureContractTransitionV1>,
    pub fixture_digest: [u8; 32],
}

impl FixtureDescriptorV1 {
    /// Compute the ADR-068 identity from canonical fixture fields zero through
    /// twenty-two, including the domain separator and encoded-length binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        contract_digest(
            b"PiglorOS.Conformance.Fixture.v1",
            &Value::Array(fixture_fields(self)),
        )
    }
}

/// Exact evaluator protocol and its compiled hard ceilings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorHardCapsV1 {
    pub max_profile_bytes: u64,
    pub max_cases: u32,
    pub max_bundle_members: u32,
    pub max_member_path_bytes: u16,
    pub max_member_bytes: u64,
    pub max_total_bundle_bytes: u64,
    pub max_compression_expansion: u32,
    pub max_structural_nesting: u8,
    pub max_coordinate_bytes: u16,
    pub max_diagnostic_bytes: u64,
}

impl EvaluatorHardCapsV1 {
    /// Return the canonical identity of this exact hard-cap record.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest_bytes(b"PiglorOS.EvaluatorHardCaps.v1", &encode_hard_caps(self))
    }

    /// Validate a report or fixture case count against the selected cap.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceContractError::FieldOutOfBounds`] when either the
    /// cap record or the requested count is outside the selected authority.
    pub fn validate_case_count(&self, case_count: u32) -> Result<(), ConformanceContractError> {
        validate_hard_caps(self).and({
            if case_count <= self.max_cases {
                Ok(())
            } else {
                Err(ConformanceContractError::FieldOutOfBounds)
            }
        })
    }

    /// Validate compressed and expanded bundle sizes against the ratio cap.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceContractError::FieldOutOfBounds`] for an empty
    /// input or when expansion exceeds the selected ratio.
    pub fn validate_compression_expansion(
        &self,
        compressed_bytes: u64,
        expanded_bytes: u64,
    ) -> Result<(), ConformanceContractError> {
        validate_hard_caps(self).and_then(|()| {
            let maximum_expanded = compressed_bytes
                .checked_mul(u64::from(self.max_compression_expansion))
                .ok_or(ConformanceContractError::FieldOutOfBounds)?;
            if compressed_bytes == 0 || expanded_bytes == 0 || expanded_bytes > maximum_expanded {
                Err(ConformanceContractError::FieldOutOfBounds)
            } else {
                Ok(())
            }
        })
    }
}

/// Evaluator protocol identity and report/request schema identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorProtocolV1 {
    pub protocol_id: String,
    /// Externally governed identity of the evaluator protocol bundle. CPF1
    /// commits every protocol field, while request validation requires this
    /// declared identity to match the selected profile; this crate does not
    /// invent a second canonical protocol bundle outside CPF1.
    pub protocol_digest: [u8; 32],
    pub request_schema_digest: [u8; 32],
    pub report_schema_digest: [u8; 32],
    pub hard_caps: EvaluatorHardCapsV1,
}

/// The minimum independence labels required by a profile lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependenceRequirementsV1 {
    pub technical_independence_required: bool,
    pub authorship_independence_required: bool,
    pub organizational_independence_required: bool,
    /// Digest of the externally supplied trusted-root policy snapshot.
    pub trust_policy_snapshot_digest: [u8; 32],
    pub requirements_digest: [u8; 32],
}

/// Externally supplied trust authority for Stable evidence.
///
/// A CPF1 profile may name the policy snapshot it requires, but it cannot
/// select the keys in that policy. Callers must supply this root set when
/// validating Stable evidence; a signer is accepted only when its public key
/// is a member of this independently obtained set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedRootPolicyV1 {
    pub trusted_root_public_keys: Vec<[u8; 32]>,
    pub trust_policy_snapshot_digest: [u8; 32],
}

impl TrustedRootPolicyV1 {
    /// Return the content identity of this root-set snapshot.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest_bytes(
            b"PiglorOS.ConformanceTrustPolicy.v1",
            &Value::Array(
                self.trusted_root_public_keys
                    .iter()
                    .map(|key| Value::Bytes(key.to_vec()))
                    .collect(),
            ),
        )
    }

    /// Validate the externally supplied policy and its canonical root order.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceContractError::IndependenceEvidenceMissing`] when
    /// the root set is empty, invalidly ordered, or has a mismatched digest.
    pub fn validate(&self) -> Result<(), ConformanceContractError> {
        if self.trusted_root_public_keys.is_empty()
            || self.trusted_root_public_keys.len() > 64
            || self.trusted_root_public_keys.iter().any(zero_digest)
            || !crate::strictly_ordered(&self.trusted_root_public_keys)
            || self.trust_policy_snapshot_digest != self.digest()
        {
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        } else {
            Ok(())
        }
    }

    #[must_use]
    fn contains(&self, key: &[u8; 32]) -> bool {
        self.trusted_root_public_keys.binary_search(key).is_ok()
    }
}

/// Evidence from one separately developed implementation under test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableImplementationEvidenceV1 {
    pub implementation: ImplementationIdentityV1,
    pub independence: IndependenceEvidenceV1,
    pub evaluator_protocol_digest: [u8; 32],
    pub report: ConformanceReportV1,
    pub case_outcomes: Vec<ProfileCaseOutcomeV1>,
    /// Authenticated attribution for this evidence. Stable evidence is not
    /// accepted from the implementation's self-authored metadata alone.
    pub attestation: StableEvidenceAttestationV1,
}

/// Signature-bearing trust-root evidence for one Stable implementation.
///
/// The signer key is content-addressed by `trust_root_digest`; the signature
/// covers the implementation identity, independence declaration, evaluator
/// protocol, and every profile case outcome. A caller that accepts Stable
/// evidence must additionally find the signer in its externally supplied
/// trusted-root policy; a bare declaration or reviewer string is never
/// sufficient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableEvidenceAttestationV1 {
    pub signer_public_key: [u8; 32],
    pub signature: [u8; 64],
    pub trust_root_digest: [u8; 32],
}

/// Immutable CPF1 public contract. It deliberately carries no aggregate pass flag.
///
/// `profile_digest` commits exactly the current 18-field CPF1 wire record.
/// Stable-promotion evidence is validated as a separately transported sidecar
/// and is never hidden in a non-wire digest extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceProfileV1 {
    pub profile_id: String,
    pub semantic_version: String,
    pub lifecycle: ProfileLifecycleV1,
    pub normative_spec_digest: [u8; 32],
    /// Exact digest of the canonical `authority/execution-matrix.json` member.
    pub execution_matrix_digest: [u8; 32],
    pub execution_profile_digests: Vec<[u8; 32]>,
    pub fixture_provider_registry: FixtureProviderRegistryBindingV1,
    pub fixtures: Vec<FixtureDescriptorV1>,
    pub allowed_divergences: Vec<AllowedDivergenceV1>,
    pub evaluator_protocol: EvaluatorProtocolV1,
    pub independence_requirements: IndependenceRequirementsV1,
    pub fixture_contract_policy_digest: [u8; 32],
    pub limitations_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
    pub previous_profile_digest: Option<[u8; 32]>,
    /// Stable-promotion evidence is a signed sidecar, not a CPF1 wire field.
    /// It must be supplied when validating or decoding a Stable profile.
    pub stable_evidence: Vec<StableImplementationEvidenceV1>,
    pub profile_digest: [u8; 32],
}

/// Bounded output authority supplied to the evaluator process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorOutputCapabilityV1 {
    pub capability_digest: [u8; 32],
    pub report_bytes_limit: u64,
    pub diagnostic_bytes_limit: u64,
}

/// Exact public evaluator input request; it binds all authority-relevant identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorRequestV1 {
    pub request_id: [u8; 16],
    pub conformance_profile_digest: [u8; 32],
    pub fixture_bundle_digest: [u8; 32],
    pub subject_adapter: SubjectAdapterKindV1,
    pub subject_artifact_digest: [u8; 32],
    pub implementation: ImplementationIdentityV1,
    pub execution_profile_digest: [u8; 32],
    pub trust_policy_snapshot_digest: [u8; 32],
    pub output_capability: EvaluatorOutputCapabilityV1,
    pub evaluator_protocol_digest: [u8; 32],
    pub evaluator_hard_caps_digest: [u8; 32],
    pub request_digest: [u8; 32],
}

impl ConformanceProfileV1 {
    /// Validate the closed CPF1 contract without reading private implementation state.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when an invariant is absent or invalid.
    pub fn validate(&self) -> Result<(), ConformanceContractError> {
        validate_profile(self, None).and_then(|()| {
            if self.profile_digest == self.digest() {
                Ok(())
            } else {
                Err(ConformanceContractError::FixtureDigestMismatch)
            }
        })
    }

    /// Return canonical CPF1 bytes after validating the immutable contract and digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when encoding, validation, or digest verification fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ConformanceContractError> {
        self.validate()
            .and_then(|()| encode_bounded(&encode_profile(self, true)))
    }

    /// Validate and encode a Stable profile using an externally supplied root policy.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the policy, profile, or encoded contract is invalid.
    pub fn to_canonical_cbor_with_trust_policy(
        &self,
        policy: &TrustedRootPolicyV1,
    ) -> Result<Vec<u8>, ConformanceContractError> {
        self.validate_with_trust_policy(policy)
            .and_then(|()| encode_bounded(&encode_profile(self, true)))
    }

    /// Decode exact-length canonical CPF1 bytes and validate every contract invariant.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, or invalid CPF1 bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ConformanceContractError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        decode_value(bytes)
            .and_then(|value| decode_profile(&value))
            .and_then(|profile| profile.validate().map(|()| profile))
    }

    /// Decode and validate a profile without attaching Stable sidecar evidence.
    ///
    /// Stable profiles require [`Self::from_canonical_cbor_with_stable_evidence`]
    /// so their separately transported promotion evidence is available for
    /// validation and digest verification.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, or policy-incompatible CPF1 bytes.
    pub fn from_canonical_cbor_with_trust_policy(
        bytes: &[u8],
        policy: &TrustedRootPolicyV1,
    ) -> Result<Self, ConformanceContractError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        decode_value(bytes)
            .and_then(|value| decode_profile(&value))
            .and_then(|profile| profile.validate_with_trust_policy(policy).map(|()| profile))
    }

    /// Decode a Stable CPF1 record together with its separately transported
    /// signed promotion evidence and external trust policy.
    ///
    /// Stable evidence is intentionally a sidecar: the exact CPF1 wire record
    /// does not contain an undocumented evidence field. Callers transport and
    /// authenticate it through the evidence channel rather than extending CPF1.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the profile, sidecar evidence, or
    /// external policy is invalid or the sidecar does not match the profile
    /// digest.
    pub fn from_canonical_cbor_with_stable_evidence(
        bytes: &[u8],
        stable_evidence: Vec<StableImplementationEvidenceV1>,
        policy: &TrustedRootPolicyV1,
    ) -> Result<Self, ConformanceContractError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        decode_value(bytes).and_then(|value| {
            decode_profile(&value).and_then(|mut profile| {
                profile.stable_evidence = stable_evidence;
                profile.validate_with_trust_policy(policy).map(|()| profile)
            })
        })
    }

    /// Validate a profile, requiring a trusted-root policy for Stable profiles.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the policy, profile, or profile digest is invalid.
    pub fn validate_with_trust_policy(
        &self,
        policy: &TrustedRootPolicyV1,
    ) -> Result<(), ConformanceContractError> {
        policy.validate()?;
        validate_profile(self, Some(policy)).and_then(|()| {
            if self.profile_digest == self.digest() {
                Ok(())
            } else {
                Err(ConformanceContractError::FixtureDigestMismatch)
            }
        })
    }

    /// Digest the exact current CPF1 wire fields excluding the self digest.
    ///
    /// Stable evidence remains a separately transported validation input; it is
    /// intentionally not smuggled into the fixed 18-field CPF1 record.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        contract_digest(
            b"PiglorOS.ConformanceProfile.v1",
            &encode_profile_fields(self),
        )
    }

    /// Promote only along the closed lifecycle graph and never manufacture Stable evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error if the transition or its independent evidence is invalid.
    pub fn transition_to(
        &self,
        target: ProfileLifecycleV1,
        stable_evidence: Vec<StableImplementationEvidenceV1>,
    ) -> Result<Self, ConformanceContractError> {
        let permitted = matches!(
            (self.lifecycle, target),
            (ProfileLifecycleV1::Draft, ProfileLifecycleV1::Candidate)
                | (
                    ProfileLifecycleV1::Candidate,
                    ProfileLifecycleV1::Stable | ProfileLifecycleV1::Retired
                )
                | (ProfileLifecycleV1::Stable, ProfileLifecycleV1::Retired)
        );
        if !permitted {
            return Err(ConformanceContractError::ProfileLifecycleInvalid);
        }
        let mut next = self.clone();
        next.lifecycle = target;
        next.stable_evidence = stable_evidence;
        // The selected CPF identity excludes Stable evidence, so it can be
        // computed before structural Stable validation and used by the report
        // binding checks below.
        next.profile_digest = next.digest();
        if target == ProfileLifecycleV1::Stable {
            // This constructor performs only structural checks. The returned
            // Stable value is not publishable or validatable without the
            // external policy supplied to `validate_with_trust_policy`.
            validate_stable_evidence(&next, None)?;
        } else if !next.stable_evidence.is_empty() {
            return Err(ConformanceContractError::ProfileLifecycleInvalid);
        }
        if target == ProfileLifecycleV1::Stable {
            Ok(next)
        } else {
            next.validate().map(|()| next)
        }
    }

    /// Promote a profile to Stable only after validating evidence against an
    /// externally supplied trusted-root policy.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the lifecycle transition, evidence, policy, or digest is invalid.
    pub fn transition_to_with_trust_policy(
        &self,
        target: ProfileLifecycleV1,
        stable_evidence: Vec<StableImplementationEvidenceV1>,
        policy: &TrustedRootPolicyV1,
    ) -> Result<Self, ConformanceContractError> {
        let next = self.transition_to(target, stable_evidence)?;
        if target == ProfileLifecycleV1::Stable {
            next.validate_with_trust_policy(policy)?;
        }
        Ok(next)
    }
}

impl EvaluatorRequestV1 {
    /// Validate this public-only evaluator request.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when a request identity or output cap is invalid.
    pub fn validate(&self) -> Result<(), ConformanceContractError> {
        if self.request_id == [0; 16]
            || zero_digest(&self.conformance_profile_digest)
            || zero_digest(&self.fixture_bundle_digest)
            || zero_digest(&self.subject_artifact_digest)
            || zero_digest(&self.execution_profile_digest)
            || zero_digest(&self.trust_policy_snapshot_digest)
            || zero_digest(&self.evaluator_protocol_digest)
            || zero_digest(&self.evaluator_hard_caps_digest)
            || zero_digest(&self.output_capability.capability_digest)
            || self.output_capability.report_bytes_limit == 0
            || self.output_capability.report_bytes_limit > MAX_PROFILE_BYTES as u64
            || self.output_capability.diagnostic_bytes_limit > MAX_DIAGNOSTIC_BYTES
            || self.output_capability.capability_digest != self.expected_output_capability_digest()
        {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        validate_identity(&self.implementation).and_then(|()| {
            if self.request_digest == self.digest() {
                Ok(())
            } else {
                Err(ConformanceContractError::FixtureDigestMismatch)
            }
        })
    }

    /// Validate this request against the selected immutable CPF1 inventory.
    ///
    /// A structurally valid request is not enough: the profile, fixture
    /// bundle, execution profile, adapter, evaluator protocol, and output
    /// capability must all be identities from the same selected profile.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the request or any selected profile identity is invalid.
    pub fn validate_against_profile(
        &self,
        profile: &ConformanceProfileV1,
    ) -> Result<(), ConformanceContractError> {
        self.validate().and_then(|()| {
            profile.validate()?;
            self.validate_against_validated_profile(profile)
        })
    }

    /// Validate this request against a Stable CPF and its external trust policy.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the request, profile, policy, or selected identity is invalid.
    pub fn validate_against_profile_with_trust_policy(
        &self,
        profile: &ConformanceProfileV1,
        policy: &TrustedRootPolicyV1,
    ) -> Result<(), ConformanceContractError> {
        self.validate().and_then(|()| {
            profile.validate_with_trust_policy(policy)?;
            self.validate_against_validated_profile(profile)
        })
    }

    fn validate_against_validated_profile(
        &self,
        profile: &ConformanceProfileV1,
    ) -> Result<(), ConformanceContractError> {
        if self.conformance_profile_digest != profile.profile_digest
            || self.fixture_bundle_digest != fixture_bundle_digest(profile)
            || self.trust_policy_snapshot_digest
                != profile
                    .independence_requirements
                    .trust_policy_snapshot_digest
        {
            return Err(ConformanceContractError::FixtureDigestMismatch);
        }
        if !profile
            .execution_profile_digests
            .contains(&self.execution_profile_digest)
        {
            return Err(ConformanceContractError::UnknownExecutionProfile);
        }
        if self.evaluator_protocol_digest != profile.evaluator_protocol.protocol_digest
            || self.evaluator_hard_caps_digest != profile.evaluator_protocol.hard_caps.digest()
            || !profile.fixtures.iter().any(|fixture| {
                fixture.execution_profile_digest == self.execution_profile_digest
                    && fixture.subject_adapter == self.subject_adapter
            })
        {
            return Err(ConformanceContractError::FixtureDigestMismatch);
        }
        if self.output_capability.report_bytes_limit
            > profile.evaluator_protocol.hard_caps.max_profile_bytes
            || self.output_capability.diagnostic_bytes_limit
                > profile.evaluator_protocol.hard_caps.max_diagnostic_bytes
        {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        Ok(())
    }

    /// Derive the output-capability identity from all selected authorities.
    /// Limits remain separately bounded fields; changing a limit requires a
    /// fresh request digest but does not silently change the capability owner.
    #[must_use]
    pub fn expected_output_capability_digest(&self) -> [u8; 32] {
        digest_bytes(
            b"PiglorOS.EvaluatorOutputCapability.v1",
            &Value::Array(vec![
                digest(&self.conformance_profile_digest),
                digest(&self.fixture_bundle_digest),
                adapter(self.subject_adapter),
                digest(&self.subject_artifact_digest),
                encode_identity(&self.implementation),
                digest(&self.execution_profile_digest),
                digest(&self.trust_policy_snapshot_digest),
                digest(&self.evaluator_protocol_digest),
                digest(&self.evaluator_hard_caps_digest),
            ]),
        )
    }

    /// Validate this request against the selected evaluator hard caps.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the request or either requested output
    /// limit exceeds the selected report and diagnostic authorities.
    pub fn validate_with_hard_caps(
        &self,
        caps: &EvaluatorHardCapsV1,
    ) -> Result<(), ConformanceContractError> {
        self.validate().and_then(|()| {
            validate_hard_caps(caps)?;
            if self.output_capability.report_bytes_limit > caps.max_profile_bytes
                || self.output_capability.diagnostic_bytes_limit > caps.max_diagnostic_bytes
            {
                Err(ConformanceContractError::FieldOutOfBounds)
            } else if self.evaluator_hard_caps_digest != caps.digest() {
                Err(ConformanceContractError::FixtureDigestMismatch)
            } else {
                Ok(())
            }
        })
    }

    /// Validate the request against one selected, immutable evaluator
    /// protocol. The protocol identity and the canonical hard-cap identity are
    /// checked together so a caller cannot validate a request with unrelated
    /// limits or a different report schema.
    ///
    /// # Errors
    /// Returns a closed safe error when either selected identity or any output
    /// limit does not match the request.
    pub fn validate_with_protocol(
        &self,
        protocol: &EvaluatorProtocolV1,
    ) -> Result<(), ConformanceContractError> {
        self.validate().and_then(|()| {
            validate_protocol(protocol)?;
            if self.evaluator_protocol_digest != protocol.protocol_digest
                || self.evaluator_hard_caps_digest != protocol.hard_caps.digest()
            {
                return Err(ConformanceContractError::FixtureDigestMismatch);
            }
            if self.output_capability.report_bytes_limit > protocol.hard_caps.max_profile_bytes
                || self.output_capability.diagnostic_bytes_limit
                    > protocol.hard_caps.max_diagnostic_bytes
            {
                Err(ConformanceContractError::FieldOutOfBounds)
            } else {
                Ok(())
            }
        })
    }

    /// Return exact canonical evaluator-request bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when encoding, validation, or digest verification fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ConformanceContractError> {
        self.validate()
            .and_then(|()| encode_bounded(&encode_request(self, true)))
    }

    /// Decode and verify exact canonical evaluator-request bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, or invalid request bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ConformanceContractError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        decode_value(bytes)
            .and_then(|value| decode_request(&value))
            .and_then(|request| request.validate().map(|()| request))
    }

    /// Digest the request fields excluding its self-referential digest field.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest_bytes(
            b"PiglorOS.EvaluatorRequest.v1",
            &encode_request(self, false),
        )
    }
}

fn validate_profile(
    profile: &ConformanceProfileV1,
    policy: Option<&TrustedRootPolicyV1>,
) -> Result<(), ConformanceContractError> {
    if !valid_identifier(&profile.profile_id)
        || profile.profile_id.contains("#matrix=")
        || !semantic_version(&profile.semantic_version)
        || zero_digest(&profile.normative_spec_digest)
        || zero_digest(&profile.execution_matrix_digest)
        || zero_digest(&profile.fixture_contract_policy_digest)
        || zero_digest(&profile.limitations_digest)
        || zero_digest(&profile.provenance_digest)
        || profile.execution_profile_digests.is_empty()
        || profile.execution_profile_digests.len() > MAX_EXECUTION_PROFILES
        || profile.execution_profile_digests.iter().any(zero_digest)
        || profile
            .previous_profile_digest
            .is_some_and(|digest| zero_digest(&digest))
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    if !crate::strictly_ordered(&profile.execution_profile_digests) {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    validate_protocol(&profile.evaluator_protocol)
        .and_then(|()| validate_independence_requirements(&profile.independence_requirements))
        .and_then(|()| {
            profile
                .fixture_provider_registry
                .validate()
                .map_err(|_| ConformanceContractError::FieldOutOfBounds)
        })
        .and_then(|()| validate_fixtures(profile))
        .and_then(|()| validate_selected_caps(profile))
        .and_then(|()| validate_allowed_divergences(&profile.allowed_divergences))
        .and_then(|()| match profile.lifecycle {
            _ if profile.fixtures.is_empty() => {
                Err(ConformanceContractError::ExpectedResultMissing)
            }
            ProfileLifecycleV1::Stable => {
                if policy.is_none() {
                    Err(ConformanceContractError::IndependenceEvidenceMissing)
                } else {
                    validate_stable_evidence(profile, policy)
                }
            }
            _ if profile.stable_evidence.is_empty() => Ok(()),
            _ => Err(ConformanceContractError::ProfileLifecycleInvalid),
        })
}

fn validate_fixtures(profile: &ConformanceProfileV1) -> Result<(), ConformanceContractError> {
    if profile
        .fixtures
        .windows(2)
        .any(|pair| fixture_key(&pair[0]) >= fixture_key(&pair[1]))
    {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    profile.fixtures.iter().try_for_each(|fixture| {
        validate_fixture(fixture, profile)
            .and_then(|()| {
                validate_strict_oracle(&fixture.strict_oracle, &profile.allowed_divergences)
            })
            .and_then(|()| validate_fixture_verification_outcome(fixture))
            .and_then(|()| validate_fixture_claim(fixture))
    })
}

fn validate_fixture_claim(fixture: &FixtureDescriptorV1) -> Result<(), ConformanceContractError> {
    if fixture.replay_claim == ReplayClaimV1::IncompatibleProfile {
        return Ok(());
    }
    let coherent = match fixture.redaction_state {
        RedactionStateV1::None => true,
        RedactionStateV1::RedactedViews => {
            fixture.replay_claim == ReplayClaimV1::ExactAuthoritativeWithRedactedViews
        }
        RedactionStateV1::StructuralOnly => fixture.replay_claim == ReplayClaimV1::StructuralOnly,
        RedactionStateV1::EvidenceMissing => {
            fixture.replay_claim == ReplayClaimV1::UnverifiableArtifactsMissing
        }
    };
    if coherent {
        Ok(())
    } else {
        Err(ConformanceContractError::ClaimRedactionMismatch)
    }
}

fn validate_selected_caps(profile: &ConformanceProfileV1) -> Result<(), ConformanceContractError> {
    let caps = &profile.evaluator_protocol.hard_caps;
    caps.validate_case_count(u32::try_from(profile.fixtures.len()).unwrap_or(u32::MAX))?;
    let encoded_value = encode_profile(profile, true);
    encode_value(&encoded_value).and_then(|encoded| {
        validate_selected_caps_encoded(profile, caps, &encoded_value, encoded.len())
    })
}

fn validate_selected_caps_encoded(
    profile: &ConformanceProfileV1,
    caps: &EvaluatorHardCapsV1,
    encoded_value: &Value,
    encoded_len: usize,
) -> Result<(), ConformanceContractError> {
    if u64::try_from(encoded_len).unwrap_or(u64::MAX) > caps.max_profile_bytes
        || value_depth(encoded_value) > usize::from(caps.max_structural_nesting)
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }

    let registry = &profile.fixture_provider_registry.registry_artifact;
    if registry.member_path.len() > usize::from(caps.max_member_path_bytes)
        || registry.byte_length > caps.max_member_bytes
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    let mut member_count = 1_u64;
    let mut bundle_bytes = registry.byte_length;
    for fixture in &profile.fixtures {
        for member in fixture_artifacts(fixture) {
            member_count = member_count.saturating_add(1);
            bundle_bytes = bundle_bytes.saturating_add(member.byte_length);
            if member.member_path.len() > usize::from(caps.max_member_path_bytes)
                || member.byte_length > caps.max_member_bytes
            {
                return Err(ConformanceContractError::FieldOutOfBounds);
            }
        }
    }
    if member_count > u64::from(caps.max_bundle_members)
        || bundle_bytes > caps.max_total_bundle_bytes
        || profile.allowed_divergences.iter().any(|divergence| {
            divergence.first_coordinate.len() > usize::from(caps.max_coordinate_bytes)
        })
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    Ok(())
}

fn value_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(value_depth).max().unwrap_or_default(),
        _ => 1,
    }
}

fn validate_fixture(
    fixture: &FixtureDescriptorV1,
    profile: &ConformanceProfileV1,
) -> Result<(), ConformanceContractError> {
    if !bounded_fixture_id(&fixture.case_id)
        || !valid_fixture_provider_key(&fixture.provider_key)
        || !profile
            .execution_profile_digests
            .contains(&fixture.execution_profile_digest)
        || !profile
            .fixture_provider_registry
            .required_provider_keys
            .contains(&fixture.provider_key)
        || fixture.modes.is_empty()
    {
        return Err(
            if !profile
                .execution_profile_digests
                .contains(&fixture.execution_profile_digest)
            {
                ConformanceContractError::UnknownExecutionProfile
            } else if !profile
                .fixture_provider_registry
                .required_provider_keys
                .contains(&fixture.provider_key)
            {
                ConformanceContractError::UnknownFixtureProvider
            } else {
                ConformanceContractError::FieldOutOfBounds
            },
        );
    }
    if !crate::strictly_ordered(&fixture.modes)
        || fixture
            .auxiliary
            .windows(2)
            .any(|pair| pair[0].member_path >= pair[1].member_path)
    {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    let artifacts = fixture_artifacts(fixture);
    let paths = artifacts
        .iter()
        .map(|artifact| artifact.member_path.as_str())
        .collect::<BTreeSet<_>>();
    if paths.len() != artifacts.len() {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    fixture_artifacts(fixture)
        .into_iter()
        .try_for_each(validate_artifact_descriptor)
        .and_then(|()| {
            let artifact_bytes = fixture_artifacts(fixture)
                .into_iter()
                .fold(0_u64, |total, artifact| {
                    total.saturating_add(artifact.byte_length)
                });
            if artifact_bytes > profile.evaluator_protocol.hard_caps.max_total_bundle_bytes
                || fixture.modes.contains(&ExecutionModeV1::AirGapped)
                    && fixture.capability_policy.network_allowed
                || fixture.subject_adapter == SubjectAdapterKindV1::PublicPluginProtocol
                    && fixture.capability_policy.network_allowed
            {
                Err(ConformanceContractError::FieldOutOfBounds)
            } else {
                Ok(())
            }
        })
        .and_then(|()| validate_deterministic_budget(&fixture.deterministic_budget))
        .and_then(|()| validate_operational_safety(&fixture.operational_safety))
        .and_then(|()| validate_capability_policy(&fixture.capability_policy))
        .and_then(|()| validate_fixture_provenance(&fixture.provenance))
        .and_then(|()| validate_failure_ownership(fixture))
        .and_then(|()| validate_fixture_downgrade(fixture))
        .and_then(|()| {
            if fixture.fixture_digest == fixture.digest() {
                Ok(())
            } else {
                Err(ConformanceContractError::FixtureDigestMismatch)
            }
        })
}

fn validate_stable_evidence(
    profile: &ConformanceProfileV1,
    policy: Option<&TrustedRootPolicyV1>,
) -> Result<(), ConformanceContractError> {
    if !profile
        .independence_requirements
        .technical_independence_required
        || !profile
            .independence_requirements
            .authorship_independence_required
        || profile.stable_evidence.len() != 2
    {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    let first = &profile.stable_evidence[0];
    let second = &profile.stable_evidence[1];
    validate_identity(&first.implementation)?;
    validate_identity(&second.implementation)?;
    if first.implementation.implementation_id >= second.implementation.implementation_id
        || first.implementation.source_digest == second.implementation.source_digest
        || first.implementation.build_digest == second.implementation.build_digest
        || first.implementation.binary_digest == second.implementation.binary_digest
        || first.implementation.public_contract_digest
            != second.implementation.public_contract_digest
        || first.report.subject_artifact_digest != second.report.subject_artifact_digest
        || first.report.report_digest == second.report.report_digest
    {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    validate_stable_implementation(first, profile, policy)
        .and_then(|()| validate_stable_implementation(second, profile, policy))
        .and_then(|()| {
            validate_report_binding(first, profile)
                .and_then(|()| validate_report_binding(second, profile))
        })
}

fn validate_stable_implementation(
    evidence: &StableImplementationEvidenceV1,
    profile: &ConformanceProfileV1,
    policy: Option<&TrustedRootPolicyV1>,
) -> Result<(), ConformanceContractError> {
    let seen = evidence
        .case_outcomes
        .iter()
        .map(stable_case_key)
        .collect::<BTreeSet<_>>();
    profile
        .evaluator_protocol
        .hard_caps
        .validate_case_count(u32::try_from(evidence.case_outcomes.len()).unwrap_or(u32::MAX))?;
    if evidence.case_outcomes.iter().any(|case| {
        case.first_coordinate.as_ref().is_some_and(|coordinate| {
            coordinate.len()
                > usize::from(profile.evaluator_protocol.hard_caps.max_coordinate_bytes)
        })
    }) {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    let required = profile
        .fixtures
        .iter()
        .filter(|fixture| fixture.mandatory)
        .flat_map(|fixture| {
            fixture
                .modes
                .iter()
                .filter(|&&mode| {
                    matches!(mode, ExecutionModeV1::Local | ExecutionModeV1::AirGapped)
                })
                .map(move |mode| {
                    (
                        fixture.case_id.as_str(),
                        *mode,
                        fixture.claim_layer,
                        fixture.digest(),
                    )
                })
        })
        .collect::<BTreeSet<_>>();
    if !required.iter().all(|key| seen.contains(key)) {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    validate_identity(&evidence.implementation)
        .and_then(|()| {
            validate_independence_evidence(
                &evidence.independence,
                &profile.independence_requirements,
            )
        })
        .and_then(|()| {
            validate_stable_attestation(evidence, &profile.independence_requirements, policy)
        })
        .and_then(|()| {
            if profile
                .fixtures
                .iter()
                .filter(|fixture| fixture.mandatory)
                .flat_map(|fixture| {
                    fixture
                        .modes
                        .iter()
                        .filter(|mode| {
                            matches!(mode, ExecutionModeV1::Local | ExecutionModeV1::AirGapped)
                        })
                        .map(move |mode| (fixture, *mode))
                })
                .any(|(fixture, mode)| {
                    !evidence
                        .case_outcomes
                        .iter()
                        .any(|case| case.mode == mode && case_matches_fixture(case, fixture))
                })
            {
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            } else {
                Ok(())
            }
        })
}

fn validate_stable_attestation(
    evidence: &StableImplementationEvidenceV1,
    requirements: &IndependenceRequirementsV1,
    policy: Option<&TrustedRootPolicyV1>,
) -> Result<(), ConformanceContractError> {
    let attestation = &evidence.attestation;
    validate_stable_attestation_fields(attestation, requirements, policy)
        .and_then(|()| {
            signing::verifying_key_from_public_key(&PublicKey::from_bytes(
                attestation.signer_public_key,
            ))
            .map_err(|_| ConformanceContractError::IndependenceEvidenceMissing)
        })
        .and_then(|key| {
            let signature = Signature::from_bytes(attestation.signature);
            encode_value(&stable_attestation_payload(evidence)).and_then(|payload| {
                signing::verify(&key, &CanonicalBytes::from_vec(payload), &signature)
                    .map_err(|_| ConformanceContractError::IndependenceEvidenceMissing)
            })
        })
}

fn validate_stable_attestation_fields(
    attestation: &StableEvidenceAttestationV1,
    requirements: &IndependenceRequirementsV1,
    policy: Option<&TrustedRootPolicyV1>,
) -> Result<(), ConformanceContractError> {
    if zero_digest(&attestation.signer_public_key)
        || attestation.signature == [0; 64]
        || zero_digest(&attestation.trust_root_digest)
        || attestation.trust_root_digest
            != digest_bytes(
                b"PiglorOS.ConformanceTrustRoot.v1",
                &Value::Bytes(attestation.signer_public_key.to_vec()),
            )
        || policy.is_some_and(|value| {
            requirements.trust_policy_snapshot_digest != value.trust_policy_snapshot_digest
                || !value.contains(&attestation.signer_public_key)
        })
    {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    Ok(())
}

fn stable_attestation_payload(evidence: &StableImplementationEvidenceV1) -> Value {
    Value::Array(vec![
        encode_identity(&evidence.implementation),
        encode_independence(&evidence.independence),
        digest(&evidence.evaluator_protocol_digest),
        digest(&evidence.report.report_digest),
        Value::Array(evidence.case_outcomes.iter().map(encode_case).collect()),
        digest(&evidence.attestation.signer_public_key),
        digest(&evidence.attestation.trust_root_digest),
    ])
}

fn stable_case_key(case: &CaseOutcomeV1) -> (&str, ExecutionModeV1, ClaimLayerV1, [u8; 32]) {
    (
        &case.case_id,
        case.mode,
        case.claim_layer,
        case.fixture_digest,
    )
}

fn validate_report_binding(
    evidence: &StableImplementationEvidenceV1,
    profile: &ConformanceProfileV1,
) -> Result<(), ConformanceContractError> {
    let report = &evidence.report;
    report
        .validate()
        .map_err(|_| ConformanceContractError::IndependenceEvidenceMissing)?;
    if report.implementation != evidence.implementation
        || report.independence != evidence.independence
        || report.evaluator_protocol_digest != profile.evaluator_protocol.protocol_digest
        || evidence.evaluator_protocol_digest != profile.evaluator_protocol.protocol_digest
        || report.normative_spec_digest != profile.normative_spec_digest
        || report.limitations_digest != profile.limitations_digest
        || report.provenance_digest != profile.provenance_digest
        || report.fixture_bundle_digest != fixture_bundle_digest(profile)
        || report.profile_digest != selected_profile_digest(profile)
        || !profile
            .execution_profile_digests
            .contains(&report.execution_profile_digest)
        || report.cases.iter().any(|report_case| {
            !profile.fixtures.iter().any(|fixture| {
                fixture.case_id == report_case.case_id
                    && fixture.claim_layer == report_case.claim_layer
                    && fixture.digest() == report_case.fixture_digest
                    && fixture.execution_profile_digest == report_case.execution_profile_digest
                    && fixture.modes.contains(&report_case.mode)
            })
        })
        || report.cases.len() != evidence.case_outcomes.len()
    {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    if report
        .cases
        .iter()
        .zip(&evidence.case_outcomes)
        .any(|(report_case, profile_case)| {
            report_case.case_id != profile_case.case_id
                || report_case.fixture_digest != profile_case.fixture_digest
                || report_case.execution_profile_digest != profile_case.execution_profile_digest
                || report_case.mode != profile_case.mode
                || report_case.claim_layer != profile_case.claim_layer
                || report_case.outcome != profile_case.outcome
                || report_case.first_coordinate != profile_case.first_coordinate
                || report_case.expected_digest != profile_case.expected_digest
                || report_case.actual_digest != profile_case.actual_digest
                || report_case.expected_error != profile_case.expected_error
                || report_case.actual_error != profile_case.actual_error
                || report_case.replay_claim != profile_case.replay_claim
                || report_case.redaction_state != profile_case.redaction_state
                || report_case.provenance_digest != profile_case.provenance_digest
        })
    {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    Ok(())
}

fn selected_profile_digest(profile: &ConformanceProfileV1) -> [u8; 32] {
    profile.digest()
}

fn fixture_bundle_digest(profile: &ConformanceProfileV1) -> [u8; 32] {
    contract_digest(
        b"PiglorOS.ConformanceFixtureBundle.v1",
        &Value::Array(profile.fixtures.iter().map(encode_fixture).collect()),
    )
}

fn case_matches_fixture(case: &CaseOutcomeV1, fixture: &FixtureDescriptorV1) -> bool {
    if case.case_id != fixture.case_id
        || case.fixture_digest != fixture.digest()
        || case.claim_layer != fixture.claim_layer
        || case.execution_profile_digest != fixture.execution_profile_digest
        || case.outcome != CaseOutcomeStatusV1::Pass
        || case.replay_claim != fixture.replay_claim
        || case.redaction_state != fixture.redaction_state
        || case.provenance_digest != fixture_provenance_digest(&fixture.provenance)
    {
        return false;
    }
    match fixture.strict_oracle.kind {
        StrictOracleKindV1::Output => match case.verification_outcome {
            VerificationOutcomeV1::VerifiedExact => {
                fixture.strict_oracle.output.as_ref().is_some_and(|output| {
                    case.expected_digest == Some(output.blake3_digest)
                        && case.actual_digest == Some(output.blake3_digest)
                })
            }
            VerificationOutcomeV1::UnverifiableArtifactsMissing => {
                case.expected_digest.is_none() && case.actual_digest.is_none()
            }
            _ => false,
        },
        StrictOracleKindV1::Failure => {
            case.verification_outcome == fixture.expected_verification_outcome
        }
        StrictOracleKindV1::Divergence => {
            case.verification_outcome == VerificationOutcomeV1::Diverged
                && fixture
                    .strict_oracle
                    .divergence
                    .as_ref()
                    .is_some_and(|divergence| {
                        case.divergence_kind == Some(divergence.classification)
                            && case.first_coordinate.as_ref() == Some(&divergence.first_coordinate)
                    })
        }
    }
}

fn fixture_provenance_digest(provenance: &FixtureProvenanceV1) -> [u8; 32] {
    digest_bytes(
        b"PiglorOS.ConformanceFixtureProvenance.v1",
        &encode_fixture_provenance(provenance),
    )
}

fn validate_identity(identity: &ImplementationIdentityV1) -> Result<(), ConformanceContractError> {
    if !bounded_text(&identity.implementation_id, 128)
        || identity
            .organization_id
            .as_ref()
            .is_some_and(|id| !bounded_text(id, 128))
        || zero_digest(&identity.source_digest)
        || zero_digest(&identity.build_digest)
        || zero_digest(&identity.binary_digest)
        || zero_digest(&identity.public_contract_digest)
    {
        Err(ConformanceContractError::ProvenanceMissing)
    } else {
        Ok(())
    }
}

fn validate_independence_evidence(
    evidence: &IndependenceEvidenceV1,
    requirements: &IndependenceRequirementsV1,
) -> Result<(), ConformanceContractError> {
    if (requirements.technical_independence_required && !evidence.technical_independent)
        || (requirements.authorship_independence_required && !evidence.authorship_independent)
        || (requirements.organizational_independence_required
            && !evidence.organizational_independent)
        || evidence.reviewer_ids.is_empty()
        || evidence.reviewer_ids.len() > 32
        || evidence
            .reviewer_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || evidence.reviewer_ids.iter().any(|id| !valid_identifier(id))
        || zero_digest(&evidence.declaration_digest)
        || zero_digest(&evidence.shared_code_audit_digest)
    {
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    } else {
        Ok(())
    }
}

fn validate_independence_requirements(
    requirements: &IndependenceRequirementsV1,
) -> Result<(), ConformanceContractError> {
    if zero_digest(&requirements.trust_policy_snapshot_digest)
        || zero_digest(&requirements.requirements_digest)
    {
        Err(ConformanceContractError::IndependenceEvidenceMissing)
    } else {
        Ok(())
    }
}

fn validate_protocol(protocol: &EvaluatorProtocolV1) -> Result<(), ConformanceContractError> {
    if !bounded_text(&protocol.protocol_id, 128)
        || zero_digest(&protocol.protocol_digest)
        || zero_digest(&protocol.request_schema_digest)
        || zero_digest(&protocol.report_schema_digest)
    {
        Err(ConformanceContractError::ProvenanceMissing)
    } else {
        validate_hard_caps(&protocol.hard_caps)
    }
}

const fn validate_hard_caps(caps: &EvaluatorHardCapsV1) -> Result<(), ConformanceContractError> {
    if caps.max_profile_bytes == 0
        || caps.max_profile_bytes > MAX_PROFILE_BYTES as u64
        || caps.max_cases == 0
        || caps.max_cases as usize > MAX_FIXTURES
        || caps.max_bundle_members == 0
        || caps.max_bundle_members as usize > MAX_FIXTURES
        || caps.max_member_path_bytes == 0
        || caps.max_member_path_bytes as usize > MAX_STRING_BYTES
        || caps.max_member_bytes == 0
        || caps.max_member_bytes > MAX_MEMBER_BYTES
        || caps.max_total_bundle_bytes == 0
        || caps.max_total_bundle_bytes > MAX_TOTAL_BUNDLE_BYTES
        || caps.max_compression_expansion == 0
        || caps.max_compression_expansion > MAX_COMPRESSION_EXPANSION
        || caps.max_structural_nesting == 0
        || caps.max_structural_nesting > MAX_STRUCTURAL_NESTING
        || caps.max_coordinate_bytes == 0
        || caps.max_coordinate_bytes as usize > MAX_COORDINATE_BYTES
        || caps.max_diagnostic_bytes > MAX_DIAGNOSTIC_BYTES
    {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn fixture_artifacts(fixture: &FixtureDescriptorV1) -> Vec<&ArtifactDescriptorV1> {
    let mut artifacts = Vec::with_capacity(fixture.auxiliary.len().saturating_add(3));
    artifacts.push(&fixture.schema);
    artifacts.push(&fixture.payload);
    artifacts.extend(fixture.auxiliary.iter());
    if let Some(output) = fixture.strict_oracle.output.as_ref() {
        artifacts.push(output);
    }
    artifacts
}

fn validate_artifact_descriptor(
    descriptor: &ArtifactDescriptorV1,
) -> Result<(), ConformanceContractError> {
    // These field names are intentionally localized here: ADR-068 owns their
    // exact representation in provider_contract.rs.
    if !valid_member_path(&descriptor.member_path)
        || !valid_media_type(&descriptor.media_type)
        || descriptor.byte_length == 0
        || descriptor.byte_length > MAX_MEMBER_BYTES
        || zero_digest(&descriptor.blake3_digest)
    {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_deterministic_budget(
    budget: &DeterministicBudgetV1,
) -> Result<(), ConformanceContractError> {
    if [
        budget.memory_bytes,
        budget.cpu_fuel,
        budget.host_calls,
        budget.event_count,
        budget.output_bytes,
        budget.storage_bytes,
        budget.execution_steps,
        budget.simulation_time_ns,
    ]
    .contains(&0)
    {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_operational_safety(
    safety: &OperationalSafetyV1,
) -> Result<(), ConformanceContractError> {
    if safety.watchdog_ms == 0 {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_capability_policy(policy: &CapabilityPolicyV1) -> Result<(), ConformanceContractError> {
    if policy
        .capability_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        Err(ConformanceContractError::NonCanonicalOrder)
    } else if policy.capability_ids.iter().any(|id| !valid_identifier(id)) {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_fixture_provenance(
    value: &FixtureProvenanceV1,
) -> Result<(), ConformanceContractError> {
    if !bounded_text(&value.licence_id, 128)
        || zero_digest(&value.notices_digest)
        || zero_digest(&value.sbom_digest)
        || zero_digest(&value.source_digest)
        || zero_digest(&value.build_digest)
        || zero_digest(&value.publication_review_digest)
        || zero_digest(&value.limitations_digest)
    {
        Err(ConformanceContractError::ProvenanceMissing)
    } else {
        Ok(())
    }
}

fn validate_strict_oracle(
    oracle: &StrictOracleV1,
    allowed: &[AllowedDivergenceV1],
) -> Result<(), ConformanceContractError> {
    match (
        oracle.kind,
        oracle.output.as_ref(),
        oracle.failure.as_ref(),
        oracle.divergence.as_ref(),
    ) {
        (StrictOracleKindV1::Output, Some(output), None, None) => {
            validate_artifact_descriptor(output)
        }
        (StrictOracleKindV1::Failure, None, Some(failure), None) => {
            validate_namespaced_failure(failure)
        }
        (StrictOracleKindV1::Divergence, None, None, Some(divergence)) => {
            validate_allowed_divergence(divergence, allowed)
        }
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}

fn validate_fixture_verification_outcome(
    fixture: &FixtureDescriptorV1,
) -> Result<(), ConformanceContractError> {
    let valid = match fixture.strict_oracle.kind {
        StrictOracleKindV1::Output => {
            fixture.expected_verification_outcome == VerificationOutcomeV1::VerifiedExact
                && fixture.expected_verification_error.is_none()
        }
        StrictOracleKindV1::Failure => {
            fixture.expected_verification_error.as_ref() == fixture.strict_oracle.failure.as_ref()
                && !matches!(
                    fixture.expected_verification_outcome,
                    VerificationOutcomeV1::VerifiedExact | VerificationOutcomeV1::Diverged
                )
        }
        StrictOracleKindV1::Divergence => {
            fixture.expected_verification_outcome == VerificationOutcomeV1::Diverged
                && fixture.expected_verification_error.is_none()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ConformanceContractError::ExpectedResultMissing)
    }
}

fn validate_namespaced_failure(
    failure: &NamespacedFailureV1,
) -> Result<(), ConformanceContractError> {
    if valid_identifier(&failure.owner_id)
        && contract_version(&failure.contract_version)
        && valid_identifier(&failure.code_id)
    {
        Ok(())
    } else {
        Err(ConformanceContractError::FieldOutOfBounds)
    }
}

fn validate_allowed_divergence(
    divergence: &AllowedDivergenceV1,
    allowed: &[AllowedDivergenceV1],
) -> Result<(), ConformanceContractError> {
    if divergence.first_coordinate.is_empty()
        || divergence.first_coordinate.len() > MAX_COORDINATE_BYTES
    {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else if allowed.iter().any(|value| value == divergence) {
        Ok(())
    } else {
        Err(ConformanceContractError::DivergenceClassificationMismatch)
    }
}

fn validate_fixture_downgrade(
    fixture: &FixtureDescriptorV1,
) -> Result<(), ConformanceContractError> {
    let is_downgrade = fixture.family == FixtureFamilyV1::Downgrade;
    let has_all = fixture.trust_policy_snapshot_digest.is_some()
        && fixture.release_admission_digest.is_some()
        && fixture.transition.is_some();
    if !is_downgrade {
        if fixture.trust_policy_snapshot_digest.is_none()
            && fixture.release_admission_digest.is_none()
            && fixture.transition.is_none()
        {
            return Ok(());
        }
        return Err(ConformanceContractError::ProfileLifecycleInvalid);
    }
    if !has_all
        || fixture
            .trust_policy_snapshot_digest
            .is_some_and(|digest| zero_digest(&digest))
        || fixture
            .release_admission_digest
            .is_some_and(|digest| zero_digest(&digest))
    {
        return Err(ConformanceContractError::ProvenanceMissing);
    }
    let Some(transition) = fixture.transition.as_ref() else {
        return Err(ConformanceContractError::ProfileLifecycleInvalid);
    };
    if !valid_fixture_provider_key(&transition.from)
        || !valid_fixture_provider_key(&transition.to)
        || transition.from == transition.to
    {
        Err(ConformanceContractError::ProfileLifecycleInvalid)
    } else {
        Ok(())
    }
}

fn validate_failure_ownership(
    fixture: &FixtureDescriptorV1,
) -> Result<(), ConformanceContractError> {
    let Some(failure) = fixture.strict_oracle.failure.as_ref() else {
        return Ok(());
    };
    if failure.owner_id == "pigloros.core"
        || (failure.owner_id == fixture.provider_key.provider_id
            && failure.contract_version == fixture.provider_key.contract_version)
    {
        Ok(())
    } else {
        Err(ConformanceContractError::ProvenanceMissing)
    }
}

fn validate_allowed_divergences(
    values: &[AllowedDivergenceV1],
) -> Result<(), ConformanceContractError> {
    if values.iter().any(|value| {
        value.first_coordinate.is_empty() || value.first_coordinate.len() > MAX_COORDINATE_BYTES
    }) {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    if values
        .windows(2)
        .any(|pair| divergence_key(&pair[0]) >= divergence_key(&pair[1]))
    {
        Err(ConformanceContractError::NonCanonicalOrder)
    } else {
        Ok(())
    }
}

const fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}

const fn bounded_ascii(value: &str, maximum: usize) -> bool {
    bounded_text(value, maximum) && value.is_ascii()
}

fn bounded_fixture_id(value: &str) -> bool {
    valid_identifier(value)
}

fn valid_identifier(value: &str) -> bool {
    bounded_ascii(value, 128)
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

fn valid_member_path(value: &str) -> bool {
    let components = value.split('/').collect::<Vec<_>>();
    bounded_ascii(value, 512)
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && (1..=16).contains(&components.len())
        && components.iter().all(|component| {
            !component.is_empty()
                && *component != "."
                && *component != ".."
                && component.len() <= 128
        })
}

fn valid_media_type(value: &str) -> bool {
    let Some((type_name, subtype)) = value.split_once('/') else {
        return false;
    };
    (3..=127).contains(&value.len())
        && !type_name.is_empty()
        && !subtype.is_empty()
        && value.bytes().filter(|byte| *byte == b'/').count() == 1
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        })
}

fn semantic_version(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_STRING_BYTES {
        return false;
    }
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
        && core_parts.iter().all(|part| numeric_identifier(part))
        && valid_identifiers(prerelease, true)
        && valid_identifiers(build, false)
}

fn contract_version(value: &str) -> bool {
    value.len() <= 64 && semantic_version(value)
}

fn numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEMVER_COMPONENT_BYTES
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_identifiers(value: &str, numeric_leading_zero_forbidden: bool) -> bool {
    if value.is_empty() {
        return true;
    }
    value.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (!numeric_leading_zero_forbidden
                || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                || numeric_identifier(identifier))
    })
}

fn zero_digest(value: &[u8; 32]) -> bool {
    *value == [0; 32]
}

fn provider_key_fields(value: &FixtureProviderKeyV1) -> (&str, &str, u16, u16) {
    (
        &value.provider_id,
        &value.contract_version,
        value.abi_major,
        value.abi_minor,
    )
}

fn valid_fixture_provider_key(value: &FixtureProviderKeyV1) -> bool {
    valid_identifier(&value.provider_id) && contract_version(&value.contract_version)
}

fn fixture_key(
    value: &FixtureDescriptorV1,
) -> (
    (&str, &str, u16, u16),
    FixtureFamilyV1,
    &str,
    [u8; 32],
    &[ExecutionModeV1],
) {
    (
        provider_key_fields(&value.provider_key),
        value.family,
        &value.case_id,
        value.execution_profile_digest,
        &value.modes,
    )
}

fn divergence_key(value: &AllowedDivergenceV1) -> (DivergenceMismatchKindV1, &[u8]) {
    (value.classification, &value.first_coordinate)
}

fn digest_bytes(domain: &[u8], value: &Value) -> [u8; 32] {
    // A digest must never be computed over fallback bytes. The public digest
    // APIs cannot return an encoding error, so an impossible in-memory encoding
    // failure terminates rather than manufacturing a different identity.
    let bytes = crate::strict_codec::encode_value_infallible(value);
    let mut source = Vec::with_capacity(domain.len() + bytes.len() + 1);
    source.extend_from_slice(domain);
    source.push(0);
    source.extend_from_slice(&bytes);
    *blake3::hash(&source).as_bytes()
}

fn contract_digest(domain: &[u8], value: &Value) -> [u8; 32] {
    let bytes = crate::strict_codec::encode_value_infallible(value);
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes();
    let mut source = Vec::with_capacity(domain.len() + length.len() + bytes.len() + 1);
    source.extend_from_slice(domain);
    source.push(0);
    source.extend_from_slice(&length);
    source.extend_from_slice(&bytes);
    *blake3::hash(&source).as_bytes()
}

fn encode_profile(profile: &ConformanceProfileV1, include_digest: bool) -> Value {
    let mut fields = profile_fields(profile);
    fields.push(if include_digest {
        digest(&profile.profile_digest)
    } else {
        Value::Null
    });
    Value::Array(fields)
}

fn encode_profile_fields(profile: &ConformanceProfileV1) -> Value {
    Value::Array(profile_fields(profile))
}

fn profile_fields(profile: &ConformanceProfileV1) -> Vec<Value> {
    vec![
        text(CONFORMANCE_PROFILE_MAGIC_V1),
        uint(1),
        text(&profile.profile_id),
        text(&profile.semantic_version),
        lifecycle(profile.lifecycle),
        digest(&profile.normative_spec_digest),
        digest(&profile.execution_matrix_digest),
        digest_list(&profile.execution_profile_digests),
        encode_provider_registry_binding(&profile.fixture_provider_registry),
        Value::Array(profile.fixtures.iter().map(encode_fixture).collect()),
        Value::Array(
            profile
                .allowed_divergences
                .iter()
                .map(encode_divergence)
                .collect(),
        ),
        encode_protocol(&profile.evaluator_protocol),
        encode_requirements(&profile.independence_requirements),
        digest(&profile.fixture_contract_policy_digest),
        digest(&profile.limitations_digest),
        digest(&profile.provenance_digest),
        optional(profile.previous_profile_digest.as_ref().map(digest)),
    ]
}

fn encode_fixture(value: &FixtureDescriptorV1) -> Value {
    let mut fields = fixture_fields(value);
    fields.push(digest(&value.fixture_digest));
    Value::Array(fields)
}

fn fixture_fields(value: &FixtureDescriptorV1) -> Vec<Value> {
    vec![
        text(&value.case_id),
        Value::Bool(value.mandatory),
        claim_layer(value.claim_layer),
        family(value.family),
        encode_provider_key(&value.provider_key),
        adapter(value.subject_adapter),
        digest(&value.execution_profile_digest),
        Value::Array(value.modes.iter().copied().map(mode).collect()),
        encode_artifact_descriptor(&value.schema),
        encode_artifact_descriptor(&value.payload),
        Value::Array(
            value
                .auxiliary
                .iter()
                .map(encode_artifact_descriptor)
                .collect(),
        ),
        encode_strict_oracle(&value.strict_oracle),
        verification_outcome(value.expected_verification_outcome),
        optional(
            value
                .expected_verification_error
                .as_ref()
                .map(encode_namespaced_failure),
        ),
        replay_claim(value.replay_claim),
        redaction(value.redaction_state),
        encode_deterministic_budget(&value.deterministic_budget),
        encode_operational_safety(&value.operational_safety),
        encode_capability_policy(&value.capability_policy),
        optional(value.trust_policy_snapshot_digest.as_ref().map(digest)),
        optional(value.release_admission_digest.as_ref().map(digest)),
        encode_fixture_provenance(&value.provenance),
        optional(value.transition.as_ref().map(encode_transition)),
    ]
}

fn encode_artifact_descriptor(value: &ArtifactDescriptorV1) -> Value {
    Value::Array(vec![
        text(&value.member_path),
        text(&value.media_type),
        uint(value.byte_length),
        digest(&value.blake3_digest),
    ])
}

fn encode_provider_key(value: &FixtureProviderKeyV1) -> Value {
    Value::Array(vec![
        text(&value.provider_id),
        text(&value.contract_version),
        uint(u64::from(value.abi_major)),
        uint(u64::from(value.abi_minor)),
    ])
}

fn encode_provider_registry_binding(value: &FixtureProviderRegistryBindingV1) -> Value {
    Value::Array(vec![
        encode_artifact_descriptor(&value.registry_artifact),
        Value::Array(
            value
                .required_provider_keys
                .iter()
                .map(encode_provider_key)
                .collect(),
        ),
    ])
}

fn encode_strict_oracle(value: &StrictOracleV1) -> Value {
    Value::Array(vec![
        uint(value.kind.wire_code()),
        optional(value.output.as_ref().map(encode_artifact_descriptor)),
        optional(value.failure.as_ref().map(encode_namespaced_failure)),
        optional(value.divergence.as_ref().map(encode_divergence)),
    ])
}

fn encode_divergence(value: &AllowedDivergenceV1) -> Value {
    Value::Array(vec![
        divergence_mismatch(value.classification),
        Value::Bytes(value.first_coordinate.clone()),
    ])
}

fn encode_deterministic_budget(value: &DeterministicBudgetV1) -> Value {
    Value::Array(vec![
        uint(value.memory_bytes),
        uint(value.cpu_fuel),
        uint(value.host_calls),
        uint(value.event_count),
        uint(value.output_bytes),
        uint(value.storage_bytes),
        uint(value.execution_steps),
        uint(value.simulation_time_ns),
    ])
}

fn encode_operational_safety(value: &OperationalSafetyV1) -> Value {
    Value::Array(vec![uint(value.watchdog_ms)])
}

fn encode_namespaced_failure(value: &NamespacedFailureV1) -> Value {
    Value::Array(vec![
        text(&value.owner_id),
        text(&value.contract_version),
        text(&value.code_id),
    ])
}

fn encode_transition(value: &FixtureContractTransitionV1) -> Value {
    Value::Array(vec![
        encode_provider_key(&value.from),
        encode_provider_key(&value.to),
    ])
}

fn encode_capability_policy(value: &CapabilityPolicyV1) -> Value {
    Value::Array(vec![
        Value::Bool(value.network_allowed),
        strings(&value.capability_ids),
    ])
}

fn encode_fixture_provenance(value: &FixtureProvenanceV1) -> Value {
    Value::Array(vec![
        text(&value.licence_id),
        digest(&value.notices_digest),
        digest(&value.sbom_digest),
        digest(&value.source_digest),
        digest(&value.build_digest),
        digest(&value.publication_review_digest),
        digest(&value.limitations_digest),
    ])
}

fn encode_protocol(value: &EvaluatorProtocolV1) -> Value {
    Value::Array(vec![
        text(&value.protocol_id),
        digest(&value.protocol_digest),
        digest(&value.request_schema_digest),
        digest(&value.report_schema_digest),
        encode_hard_caps(&value.hard_caps),
    ])
}

fn encode_hard_caps(value: &EvaluatorHardCapsV1) -> Value {
    Value::Array(vec![
        uint(value.max_profile_bytes),
        uint(u64::from(value.max_cases)),
        uint(u64::from(value.max_bundle_members)),
        uint(u64::from(value.max_member_path_bytes)),
        uint(value.max_member_bytes),
        uint(value.max_total_bundle_bytes),
        uint(u64::from(value.max_compression_expansion)),
        uint(u64::from(value.max_structural_nesting)),
        uint(u64::from(value.max_coordinate_bytes)),
        uint(value.max_diagnostic_bytes),
    ])
}

fn encode_requirements(value: &IndependenceRequirementsV1) -> Value {
    Value::Array(vec![
        Value::Bool(value.technical_independence_required),
        Value::Bool(value.authorship_independence_required),
        Value::Bool(value.organizational_independence_required),
        digest(&value.trust_policy_snapshot_digest),
        digest(&value.requirements_digest),
    ])
}

fn encode_request(request: &EvaluatorRequestV1, include_digest: bool) -> Value {
    Value::Array(vec![
        text(EVALUATOR_REQUEST_MAGIC_V1),
        uint(1),
        digest16(&request.request_id),
        digest(&request.conformance_profile_digest),
        digest(&request.fixture_bundle_digest),
        adapter(request.subject_adapter),
        digest(&request.subject_artifact_digest),
        encode_identity(&request.implementation),
        digest(&request.execution_profile_digest),
        digest(&request.trust_policy_snapshot_digest),
        encode_output_capability(&request.output_capability),
        digest(&request.evaluator_protocol_digest),
        digest(&request.evaluator_hard_caps_digest),
        if include_digest {
            digest(&request.request_digest)
        } else {
            Value::Null
        },
    ])
}

fn encode_output_capability(value: &EvaluatorOutputCapabilityV1) -> Value {
    Value::Array(vec![
        digest(&value.capability_digest),
        uint(value.report_bytes_limit),
        uint(value.diagnostic_bytes_limit),
    ])
}

fn decode_profile(value: &Value) -> Result<ConformanceProfileV1, ConformanceContractError> {
    let fields = array_values(value)?;
    let Some(magic) = fields.first() else {
        return Err(ConformanceContractError::InvalidEncoding);
    };
    let Some(version) = fields.get(1) else {
        return Err(ConformanceContractError::InvalidEncoding);
    };
    if text_value(magic)? != CONFORMANCE_PROFILE_MAGIC_V1 || uint_value(version)? != 1 {
        return Err(ConformanceContractError::UnsupportedVersion);
    }
    let fields = array(value, 18)?;
    Ok(ConformanceProfileV1 {
        profile_id: text_value(&fields[2])?,
        semantic_version: text_value(&fields[3])?,
        lifecycle: decode_lifecycle(&fields[4])?,
        normative_spec_digest: digest_value(&fields[5])?,
        execution_matrix_digest: digest_value(&fields[6])?,
        execution_profile_digests: digest_list_value(&fields[7])?,
        fixture_provider_registry: decode_provider_registry_binding(&fields[8])?,
        fixtures: array_values(&fields[9])?
            .iter()
            .map(decode_fixture)
            .collect::<Result<Vec<_>, _>>()?,
        allowed_divergences: array_values(&fields[10])?
            .iter()
            .map(decode_divergence)
            .collect::<Result<Vec<_>, _>>()?,
        evaluator_protocol: decode_protocol(&fields[11])?,
        independence_requirements: decode_requirements(&fields[12])?,
        fixture_contract_policy_digest: digest_value(&fields[13])?,
        limitations_digest: digest_value(&fields[14])?,
        provenance_digest: digest_value(&fields[15])?,
        previous_profile_digest: optional_digest(&fields[16])?,
        stable_evidence: Vec::new(),
        profile_digest: digest_value(&fields[17])?,
    })
}

fn decode_fixture(value: &Value) -> Result<FixtureDescriptorV1, ConformanceContractError> {
    let fields = array(value, 24)?;
    Ok(FixtureDescriptorV1 {
        case_id: text_value(&fields[0])?,
        mandatory: bool_value(&fields[1])?,
        claim_layer: decode_claim_layer(&fields[2])?,
        family: decode_family(&fields[3])?,
        provider_key: decode_provider_key(&fields[4])?,
        subject_adapter: decode_adapter(&fields[5])?,
        execution_profile_digest: digest_value(&fields[6])?,
        modes: array_values(&fields[7])?
            .iter()
            .map(decode_mode)
            .collect::<Result<Vec<_>, _>>()?,
        schema: decode_artifact_descriptor(&fields[8])?,
        payload: decode_artifact_descriptor(&fields[9])?,
        auxiliary: array_values(&fields[10])?
            .iter()
            .map(decode_artifact_descriptor)
            .collect::<Result<Vec<_>, _>>()?,
        strict_oracle: decode_strict_oracle(&fields[11])?,
        expected_verification_outcome: decode_verification_outcome(&fields[12])?,
        expected_verification_error: optional_namespaced_failure(&fields[13])?,
        replay_claim: decode_replay_claim(&fields[14])?,
        redaction_state: decode_redaction(&fields[15])?,
        deterministic_budget: decode_deterministic_budget(&fields[16])?,
        operational_safety: decode_operational_safety(&fields[17])?,
        capability_policy: decode_capability_policy(&fields[18])?,
        trust_policy_snapshot_digest: optional_digest(&fields[19])?,
        release_admission_digest: optional_digest(&fields[20])?,
        provenance: decode_fixture_provenance(&fields[21])?,
        transition: optional_transition(&fields[22])?,
        fixture_digest: digest_value(&fields[23])?,
    })
}

fn decode_artifact_descriptor(
    value: &Value,
) -> Result<ArtifactDescriptorV1, ConformanceContractError> {
    let fields = array(value, 4)?;
    Ok(ArtifactDescriptorV1 {
        member_path: text_value(&fields[0])?,
        media_type: text_value(&fields[1])?,
        byte_length: uint_value(&fields[2])?,
        blake3_digest: digest_value(&fields[3])?,
    })
}

fn decode_provider_key(value: &Value) -> Result<FixtureProviderKeyV1, ConformanceContractError> {
    let fields = array(value, 4)?;
    Ok(FixtureProviderKeyV1 {
        provider_id: text_value(&fields[0])?,
        contract_version: text_value(&fields[1])?,
        abi_major: u16_value(&fields[2])?,
        abi_minor: u16_value(&fields[3])?,
    })
}

fn decode_provider_registry_binding(
    value: &Value,
) -> Result<FixtureProviderRegistryBindingV1, ConformanceContractError> {
    let fields = array(value, 2)?;
    Ok(FixtureProviderRegistryBindingV1 {
        registry_artifact: decode_artifact_descriptor(&fields[0])?,
        required_provider_keys: array_values(&fields[1])?
            .iter()
            .map(decode_provider_key)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn decode_strict_oracle(value: &Value) -> Result<StrictOracleV1, ConformanceContractError> {
    let fields = array(value, 4)?;
    Ok(StrictOracleV1 {
        kind: StrictOracleKindV1::from_wire_code(uint_value(&fields[0])?)
            .ok_or(ConformanceContractError::InvalidEncoding)?,
        output: optional_artifact_descriptor(&fields[1])?,
        failure: optional_namespaced_failure(&fields[2])?,
        divergence: optional_divergence(&fields[3])?,
    })
}

fn decode_divergence(value: &Value) -> Result<AllowedDivergenceV1, ConformanceContractError> {
    let fields = array(value, 2)?;
    Ok(AllowedDivergenceV1 {
        classification: decode_divergence_mismatch(&fields[0])?,
        first_coordinate: bytes_value(&fields[1])?,
    })
}

fn decode_deterministic_budget(
    value: &Value,
) -> Result<DeterministicBudgetV1, ConformanceContractError> {
    let fields = array(value, 8)?;
    Ok(DeterministicBudgetV1 {
        memory_bytes: uint_value(&fields[0])?,
        cpu_fuel: uint_value(&fields[1])?,
        host_calls: uint_value(&fields[2])?,
        event_count: uint_value(&fields[3])?,
        output_bytes: uint_value(&fields[4])?,
        storage_bytes: uint_value(&fields[5])?,
        execution_steps: uint_value(&fields[6])?,
        simulation_time_ns: uint_value(&fields[7])?,
    })
}

fn decode_operational_safety(
    value: &Value,
) -> Result<OperationalSafetyV1, ConformanceContractError> {
    let fields = array(value, 1)?;
    Ok(OperationalSafetyV1 {
        watchdog_ms: uint_value(&fields[0])?,
    })
}

fn decode_namespaced_failure(
    value: &Value,
) -> Result<NamespacedFailureV1, ConformanceContractError> {
    let fields = array(value, 3)?;
    Ok(NamespacedFailureV1 {
        owner_id: text_value(&fields[0])?,
        contract_version: text_value(&fields[1])?,
        code_id: text_value(&fields[2])?,
    })
}

fn optional_namespaced_failure(
    value: &Value,
) -> Result<Option<NamespacedFailureV1>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        decode_namespaced_failure(value).map(Some)
    }
}

fn optional_artifact_descriptor(
    value: &Value,
) -> Result<Option<ArtifactDescriptorV1>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        decode_artifact_descriptor(value).map(Some)
    }
}

fn optional_divergence(
    value: &Value,
) -> Result<Option<AllowedDivergenceV1>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        decode_divergence(value).map(Some)
    }
}

fn optional_transition(
    value: &Value,
) -> Result<Option<FixtureContractTransitionV1>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        return Ok(None);
    }
    let fields = array(value, 2)?;
    Ok(Some(FixtureContractTransitionV1 {
        from: decode_provider_key(&fields[0])?,
        to: decode_provider_key(&fields[1])?,
    }))
}

fn decode_capability_policy(value: &Value) -> Result<CapabilityPolicyV1, ConformanceContractError> {
    let fields = array(value, 2)?;
    Ok(CapabilityPolicyV1 {
        network_allowed: bool_value(&fields[0])?,
        capability_ids: strings_value(&fields[1])?,
    })
}

fn decode_fixture_provenance(
    value: &Value,
) -> Result<FixtureProvenanceV1, ConformanceContractError> {
    let fields = array(value, 7)?;
    Ok(FixtureProvenanceV1 {
        licence_id: text_value(&fields[0])?,
        notices_digest: digest_value(&fields[1])?,
        sbom_digest: digest_value(&fields[2])?,
        source_digest: digest_value(&fields[3])?,
        build_digest: digest_value(&fields[4])?,
        publication_review_digest: digest_value(&fields[5])?,
        limitations_digest: digest_value(&fields[6])?,
    })
}

fn decode_protocol(value: &Value) -> Result<EvaluatorProtocolV1, ConformanceContractError> {
    let fields = array(value, 5)?;
    Ok(EvaluatorProtocolV1 {
        protocol_id: text_value(&fields[0])?,
        protocol_digest: digest_value(&fields[1])?,
        request_schema_digest: digest_value(&fields[2])?,
        report_schema_digest: digest_value(&fields[3])?,
        hard_caps: decode_hard_caps(&fields[4])?,
    })
}

fn decode_hard_caps(value: &Value) -> Result<EvaluatorHardCapsV1, ConformanceContractError> {
    let fields = array(value, 10)?;
    Ok(EvaluatorHardCapsV1 {
        max_profile_bytes: uint_value(&fields[0])?,
        max_cases: u32_value(&fields[1])?,
        max_bundle_members: u32_value(&fields[2])?,
        max_member_path_bytes: u16_value(&fields[3])?,
        max_member_bytes: uint_value(&fields[4])?,
        max_total_bundle_bytes: uint_value(&fields[5])?,
        max_compression_expansion: u32_value(&fields[6])?,
        max_structural_nesting: u8_value(&fields[7])?,
        max_coordinate_bytes: u16_value(&fields[8])?,
        max_diagnostic_bytes: uint_value(&fields[9])?,
    })
}

fn decode_requirements(
    value: &Value,
) -> Result<IndependenceRequirementsV1, ConformanceContractError> {
    let fields = array(value, 5)?;
    Ok(IndependenceRequirementsV1 {
        technical_independence_required: bool_value(&fields[0])?,
        authorship_independence_required: bool_value(&fields[1])?,
        organizational_independence_required: bool_value(&fields[2])?,
        trust_policy_snapshot_digest: digest_value(&fields[3])?,
        requirements_digest: digest_value(&fields[4])?,
    })
}

fn decode_request(value: &Value) -> Result<EvaluatorRequestV1, ConformanceContractError> {
    let fields = array(value, 14)?;
    if text_value(&fields[0])? != EVALUATOR_REQUEST_MAGIC_V1 || uint_value(&fields[1])? != 1 {
        return Err(ConformanceContractError::UnsupportedVersion);
    }
    Ok(EvaluatorRequestV1 {
        request_id: digest16_value(&fields[2])?,
        conformance_profile_digest: digest_value(&fields[3])?,
        fixture_bundle_digest: digest_value(&fields[4])?,
        subject_adapter: decode_adapter(&fields[5])?,
        subject_artifact_digest: digest_value(&fields[6])?,
        implementation: decode_identity(&fields[7])?,
        execution_profile_digest: digest_value(&fields[8])?,
        trust_policy_snapshot_digest: digest_value(&fields[9])?,
        output_capability: decode_output_capability(&fields[10])?,
        evaluator_protocol_digest: digest_value(&fields[11])?,
        evaluator_hard_caps_digest: digest_value(&fields[12])?,
        request_digest: digest_value(&fields[13])?,
    })
}

fn decode_output_capability(
    value: &Value,
) -> Result<EvaluatorOutputCapabilityV1, ConformanceContractError> {
    let fields = array(value, 3)?;
    Ok(EvaluatorOutputCapabilityV1 {
        capability_digest: digest_value(&fields[0])?,
        report_bytes_limit: uint_value(&fields[1])?,
        diagnostic_bytes_limit: uint_value(&fields[2])?,
    })
}

fn encode_identity(value: &ImplementationIdentityV1) -> Value {
    Value::Array(vec![
        text(&value.implementation_id),
        digest(&value.source_digest),
        digest(&value.build_digest),
        digest(&value.binary_digest),
        digest(&value.public_contract_digest),
        optional(value.organization_id.as_deref().map(text)),
    ])
}

fn decode_identity(value: &Value) -> Result<ImplementationIdentityV1, ConformanceContractError> {
    let fields = array(value, 6)?;
    Ok(ImplementationIdentityV1 {
        implementation_id: text_value(&fields[0])?,
        source_digest: digest_value(&fields[1])?,
        build_digest: digest_value(&fields[2])?,
        binary_digest: digest_value(&fields[3])?,
        public_contract_digest: digest_value(&fields[4])?,
        organization_id: optional_text(&fields[5])?,
    })
}

fn encode_independence(value: &IndependenceEvidenceV1) -> Value {
    Value::Array(vec![
        Value::Bool(value.technical_independent),
        Value::Bool(value.authorship_independent),
        Value::Bool(value.organizational_independent),
        digest(&value.declaration_digest),
        digest(&value.shared_code_audit_digest),
        strings(&value.reviewer_ids),
    ])
}

fn encode_case(value: &CaseOutcomeV1) -> Value {
    Value::Array(vec![
        text(&value.case_id),
        digest(&value.fixture_digest),
        digest(&value.execution_profile_digest),
        mode(value.mode),
        claim_layer(value.claim_layer),
        case_outcome(value.outcome),
        verification_outcome(value.verification_outcome),
        optional(value.divergence_kind.map(divergence_mismatch)),
        optional(
            value
                .first_coordinate
                .as_ref()
                .map(|coordinate| Value::Bytes(coordinate.clone())),
        ),
        optional(value.expected_digest.as_ref().map(digest)),
        optional(value.actual_digest.as_ref().map(digest)),
        optional(value.expected_error.map(safe_error)),
        optional(value.actual_error.map(safe_error)),
        replay_claim(value.replay_claim),
        redaction(value.redaction_state),
        digest(&value.provenance_digest),
    ])
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ConformanceContractError> {
    let mut bytes = Vec::new();
    encode_value_to_writer(value, &mut bytes).map(|()| bytes)
}

fn encode_value_to_writer<W: std::io::Write>(
    value: &Value,
    writer: W,
) -> Result<(), ConformanceContractError> {
    ciborium::into_writer(value, writer).map_err(|_| ConformanceContractError::InvalidEncoding)
}

fn encode_bounded(value: &Value) -> Result<Vec<u8>, ConformanceContractError> {
    encode_value(value).and_then(|bytes| {
        if bytes.len() > MAX_PROFILE_BYTES {
            Err(ConformanceContractError::FieldOutOfBounds)
        } else {
            Ok(bytes)
        }
    })
}

fn decode_value(bytes: &[u8]) -> Result<Value, ConformanceContractError> {
    preflight_cbor(bytes)?;
    let value = ciborium::from_reader(Cursor::new(bytes))
        .map_err(|_| ConformanceContractError::InvalidEncoding)?;
    encode_value(&value).and_then(|canonical| {
        if canonical == bytes {
            Ok(value)
        } else {
            Err(ConformanceContractError::InvalidEncoding)
        }
    })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), ConformanceContractError> {
    fn read_length(
        bytes: &[u8],
        index: &mut usize,
        additional: u8,
    ) -> Result<u64, ConformanceContractError> {
        let width = match additional {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(ConformanceContractError::InvalidEncoding),
        };
        let end = index.saturating_add(width);
        let value = bytes
            .get(*index..end)
            .ok_or(ConformanceContractError::InvalidEncoding)?;
        *index = end;
        let mut encoded = [0_u8; 8];
        encoded[8 - width..].copy_from_slice(value);
        Ok(u64::from_be_bytes(encoded))
    }
    fn item(bytes: &[u8], index: &mut usize, depth: u8) -> Result<(), ConformanceContractError> {
        if depth > MAX_STRUCTURAL_NESTING {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        let initial = *bytes
            .get(*index)
            .ok_or(ConformanceContractError::InvalidEncoding)?;
        *index += 1;
        let major = initial >> 5;
        let length = read_length(bytes, index, initial & 0x1f)?;
        match major {
            0 | 1 => Ok(()),
            7 => match initial & 0x1f {
                20..=22 => Ok(()),
                _ => Err(ConformanceContractError::InvalidEncoding),
            },
            2 | 3 => {
                let count = usize::try_from(length).unwrap_or(usize::MAX);
                let end = index
                    .checked_add(count)
                    .ok_or(ConformanceContractError::FieldOutOfBounds)?;
                bytes
                    .get(*index..end)
                    .ok_or(ConformanceContractError::InvalidEncoding)?;
                *index = end;
                Ok(())
            }
            4 => {
                if length > MAX_FIXTURES as u64 {
                    return Err(ConformanceContractError::FieldOutOfBounds);
                }
                for _ in 0..length {
                    item(bytes, index, depth.saturating_add(1))?;
                }
                Ok(())
            }
            _ => Err(ConformanceContractError::InvalidEncoding),
        }
    }
    let mut index = 0;
    item(bytes, &mut index, 0)?;
    if index == bytes.len() {
        Ok(())
    } else {
        Err(ConformanceContractError::InvalidEncoding)
    }
}

fn array(value: &Value, length: usize) -> Result<&[Value], ConformanceContractError> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}

fn array_values(value: &Value) -> Result<&[Value], ConformanceContractError> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, ConformanceContractError> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn optional_text(value: &Value) -> Result<Option<String>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        text_value(value).map(Some)
    }
}
fn bytes_value(value: &Value) -> Result<Vec<u8>, ConformanceContractError> {
    match value {
        Value::Bytes(value) => Ok(value.clone()),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
const fn bool_value(value: &Value) -> Result<bool, ConformanceContractError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn uint_value(value: &Value) -> Result<u64, ConformanceContractError> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| ConformanceContractError::InvalidEncoding)
        }
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn u8_value(value: &Value) -> Result<u8, ConformanceContractError> {
    u8::try_from(uint_value(value)?).map_err(|_| ConformanceContractError::FieldOutOfBounds)
}
fn u16_value(value: &Value) -> Result<u16, ConformanceContractError> {
    u16::try_from(uint_value(value)?).map_err(|_| ConformanceContractError::FieldOutOfBounds)
}
fn u32_value(value: &Value) -> Result<u32, ConformanceContractError> {
    u32::try_from(uint_value(value)?).map_err(|_| ConformanceContractError::FieldOutOfBounds)
}
fn digest_value(value: &Value) -> Result<[u8; 32], ConformanceContractError> {
    bytes_value(value).and_then(|value| {
        value
            .as_slice()
            .try_into()
            .map_err(|_| ConformanceContractError::InvalidEncoding)
    })
}
fn digest16_value(value: &Value) -> Result<[u8; 16], ConformanceContractError> {
    bytes_value(value).and_then(|value| {
        value
            .as_slice()
            .try_into()
            .map_err(|_| ConformanceContractError::InvalidEncoding)
    })
}
fn optional_digest(value: &Value) -> Result<Option<[u8; 32]>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        digest_value(value).map(Some)
    }
}
fn digest_list_value(value: &Value) -> Result<Vec<[u8; 32]>, ConformanceContractError> {
    array_values(value).and_then(|values| values.iter().map(digest_value).collect())
}
fn strings_value(value: &Value) -> Result<Vec<String>, ConformanceContractError> {
    array_values(value).and_then(|values| values.iter().map(text_value).collect())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn digest(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}
fn digest16(value: &[u8; 16]) -> Value {
    Value::Bytes(value.to_vec())
}
fn optional(value: Option<Value>) -> Value {
    value.unwrap_or(Value::Null)
}
fn digest_list(values: &[[u8; 32]]) -> Value {
    Value::Array(values.iter().map(digest).collect())
}
fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| text(value)).collect())
}

fn lifecycle(value: ProfileLifecycleV1) -> Value {
    uint(value.wire_code())
}
fn decode_lifecycle(value: &Value) -> Result<ProfileLifecycleV1, ConformanceContractError> {
    ProfileLifecycleV1::from_wire_code(uint_value(value)?)
        .ok_or(ConformanceContractError::UnsupportedVersion)
}
fn adapter(value: SubjectAdapterKindV1) -> Value {
    uint(match value {
        SubjectAdapterKindV1::ExportedArtifact => 0,
        SubjectAdapterKindV1::PublicGatewayProtocol => 1,
        SubjectAdapterKindV1::PublicPluginProtocol => 2,
    })
}
fn decode_adapter(value: &Value) -> Result<SubjectAdapterKindV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(SubjectAdapterKindV1::ExportedArtifact),
        1 => Ok(SubjectAdapterKindV1::PublicGatewayProtocol),
        2 => Ok(SubjectAdapterKindV1::PublicPluginProtocol),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn mode(value: ExecutionModeV1) -> Value {
    uint(match value {
        ExecutionModeV1::Local => 0,
        ExecutionModeV1::AirGapped => 1,
        ExecutionModeV1::Replay => 2,
        ExecutionModeV1::Fork => 3,
    })
}
fn decode_mode(value: &Value) -> Result<ExecutionModeV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(ExecutionModeV1::Local),
        1 => Ok(ExecutionModeV1::AirGapped),
        2 => Ok(ExecutionModeV1::Replay),
        3 => Ok(ExecutionModeV1::Fork),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn claim_layer(value: ClaimLayerV1) -> Value {
    uint(u64::from(value.wire_code()))
}
fn decode_claim_layer(value: &Value) -> Result<ClaimLayerV1, ConformanceContractError> {
    u8::try_from(uint_value(value)?)
        .ok()
        .and_then(ClaimLayerV1::from_wire_code)
        .ok_or(ConformanceContractError::InvalidEncoding)
}
fn family(value: FixtureFamilyV1) -> Value {
    uint(match value {
        FixtureFamilyV1::Positive => 0,
        FixtureFamilyV1::Denied => 1,
        FixtureFamilyV1::Malformed => 2,
        FixtureFamilyV1::ResourceExhaustion => 3,
        FixtureFamilyV1::DeletionRedaction => 4,
        FixtureFamilyV1::Downgrade => 5,
        FixtureFamilyV1::IndependentEvaluation => 6,
    })
}
fn decode_family(value: &Value) -> Result<FixtureFamilyV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(FixtureFamilyV1::Positive),
        1 => Ok(FixtureFamilyV1::Denied),
        2 => Ok(FixtureFamilyV1::Malformed),
        3 => Ok(FixtureFamilyV1::ResourceExhaustion),
        4 => Ok(FixtureFamilyV1::DeletionRedaction),
        5 => Ok(FixtureFamilyV1::Downgrade),
        6 => Ok(FixtureFamilyV1::IndependentEvaluation),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn case_outcome(value: CaseOutcomeStatusV1) -> Value {
    uint(match value {
        CaseOutcomeStatusV1::Pass => 0,
        CaseOutcomeStatusV1::Fail => 1,
        CaseOutcomeStatusV1::Skip => 2,
        CaseOutcomeStatusV1::Unavailable => 3,
        CaseOutcomeStatusV1::NotApplicable => 4,
    })
}
fn verification_outcome(value: VerificationOutcomeV1) -> Value {
    uint(match value {
        VerificationOutcomeV1::VerifiedExact => 0,
        VerificationOutcomeV1::Diverged => 1,
        VerificationOutcomeV1::InvalidManifest => 2,
        VerificationOutcomeV1::UnverifiableArtifactsMissing => 3,
        VerificationOutcomeV1::IncompatibleProfile => 4,
        VerificationOutcomeV1::ResourceLimitExceeded => 5,
    })
}
fn decode_verification_outcome(
    value: &Value,
) -> Result<VerificationOutcomeV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(VerificationOutcomeV1::VerifiedExact),
        1 => Ok(VerificationOutcomeV1::Diverged),
        2 => Ok(VerificationOutcomeV1::InvalidManifest),
        3 => Ok(VerificationOutcomeV1::UnverifiableArtifactsMissing),
        4 => Ok(VerificationOutcomeV1::IncompatibleProfile),
        5 => Ok(VerificationOutcomeV1::ResourceLimitExceeded),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn divergence_mismatch(value: DivergenceMismatchKindV1) -> Value {
    uint(match value {
        DivergenceMismatchKindV1::EventIdentity => 0,
        DivergenceMismatchKindV1::EventOrder => 1,
        DivergenceMismatchKindV1::CanonicalBytes => 2,
        DivergenceMismatchKindV1::ProjectionCheckpoint => 3,
        DivergenceMismatchKindV1::TypedFailure => 4,
        DivergenceMismatchKindV1::Artifact => 5,
        DivergenceMismatchKindV1::SchemaOrUpcaster => 6,
        DivergenceMismatchKindV1::NumericProfile => 7,
        DivergenceMismatchKindV1::ProhibitedOperationalInput => 8,
    })
}
fn decode_divergence_mismatch(
    value: &Value,
) -> Result<DivergenceMismatchKindV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(DivergenceMismatchKindV1::EventIdentity),
        1 => Ok(DivergenceMismatchKindV1::EventOrder),
        2 => Ok(DivergenceMismatchKindV1::CanonicalBytes),
        3 => Ok(DivergenceMismatchKindV1::ProjectionCheckpoint),
        4 => Ok(DivergenceMismatchKindV1::TypedFailure),
        5 => Ok(DivergenceMismatchKindV1::Artifact),
        6 => Ok(DivergenceMismatchKindV1::SchemaOrUpcaster),
        7 => Ok(DivergenceMismatchKindV1::NumericProfile),
        8 => Ok(DivergenceMismatchKindV1::ProhibitedOperationalInput),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn replay_claim(value: ReplayClaimV1) -> Value {
    uint(match value {
        ReplayClaimV1::Exact => 0,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews => 1,
        ReplayClaimV1::StructuralOnly => 2,
        ReplayClaimV1::UnverifiableArtifactsMissing => 3,
        ReplayClaimV1::IncompatibleProfile => 4,
    })
}
fn decode_replay_claim(value: &Value) -> Result<ReplayClaimV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(ReplayClaimV1::Exact),
        1 => Ok(ReplayClaimV1::ExactAuthoritativeWithRedactedViews),
        2 => Ok(ReplayClaimV1::StructuralOnly),
        3 => Ok(ReplayClaimV1::UnverifiableArtifactsMissing),
        4 => Ok(ReplayClaimV1::IncompatibleProfile),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn redaction(value: RedactionStateV1) -> Value {
    uint(match value {
        RedactionStateV1::None => 0,
        RedactionStateV1::RedactedViews => 1,
        RedactionStateV1::StructuralOnly => 2,
        RedactionStateV1::EvidenceMissing => 3,
    })
}
fn decode_redaction(value: &Value) -> Result<RedactionStateV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(RedactionStateV1::None),
        1 => Ok(RedactionStateV1::RedactedViews),
        2 => Ok(RedactionStateV1::StructuralOnly),
        3 => Ok(RedactionStateV1::EvidenceMissing),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn safe_error(value: SafeErrorCodeV1) -> Value {
    uint(match value {
        SafeErrorCodeV1::InvalidEncoding => 0,
        SafeErrorCodeV1::UnsupportedVersion => 1,
        SafeErrorCodeV1::FieldOutOfBounds => 2,
        SafeErrorCodeV1::NonCanonicalOrder => 3,
        SafeErrorCodeV1::DigestMismatch => 4,
        SafeErrorCodeV1::SignatureInvalid => 5,
        SafeErrorCodeV1::TrustRootUnknown => 6,
        SafeErrorCodeV1::TrustSnapshotRollback => 7,
        SafeErrorCodeV1::ArtifactRevoked => 8,
        SafeErrorCodeV1::ClosureIncomplete => 9,
        SafeErrorCodeV1::ProfileClassMismatch => 10,
        SafeErrorCodeV1::ProfileUnsupported => 11,
        SafeErrorCodeV1::ProvenanceMissing => 12,
        SafeErrorCodeV1::ResourceLimitExceeded => 13,
    })
}
#[cfg(test)]
mod current_wire_contract_tests {
    use super::*;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn artifact(path: &str, seed: u8) -> ArtifactDescriptorV1 {
        ArtifactDescriptorV1 {
            member_path: path.to_owned(),
            media_type: "application/cbor".to_owned(),
            byte_length: 1,
            blake3_digest: digest(seed),
        }
    }

    fn provider_key() -> FixtureProviderKeyV1 {
        FixtureProviderKeyV1 {
            provider_id: "pigloros.core".to_owned(),
            contract_version: "1.0.0".to_owned(),
            abi_major: 1,
            abi_minor: 0,
        }
    }

    fn registry() -> FixtureProviderRegistryBindingV1 {
        FixtureProviderRegistryBindingV1 {
            registry_artifact: artifact("authority/fixture-provider-registry.cbor", 1),
            required_provider_keys: vec![provider_key()],
        }
    }

    fn fixture() -> FixtureDescriptorV1 {
        let mut value = FixtureDescriptorV1 {
            case_id: "core/positive/one".to_owned(),
            mandatory: true,
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            family: FixtureFamilyV1::Positive,
            provider_key: provider_key(),
            subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
            execution_profile_digest: digest(2),
            modes: vec![ExecutionModeV1::Local],
            schema: artifact("schemas/positive.cddl", 3),
            payload: artifact("payloads/positive.cbor", 4),
            auxiliary: vec![artifact("auxiliary/one.cbor", 5)],
            strict_oracle: StrictOracleV1 {
                kind: StrictOracleKindV1::Output,
                output: Some(artifact("expected/positive.cbor", 6)),
                failure: None,
                divergence: None,
            },
            expected_verification_outcome: VerificationOutcomeV1::VerifiedExact,
            expected_verification_error: None,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            deterministic_budget: DeterministicBudgetV1 {
                memory_bytes: 1,
                cpu_fuel: 1,
                host_calls: 1,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
            },
            operational_safety: OperationalSafetyV1 { watchdog_ms: 1 },
            capability_policy: CapabilityPolicyV1 {
                network_allowed: false,
                capability_ids: vec!["read-public-bundle".to_owned()],
            },
            trust_policy_snapshot_digest: None,
            release_admission_digest: None,
            provenance: FixtureProvenanceV1 {
                licence_id: "MIT".to_owned(),
                notices_digest: digest(7),
                sbom_digest: digest(8),
                source_digest: digest(9),
                build_digest: digest(10),
                publication_review_digest: digest(11),
                limitations_digest: digest(12),
            },
            transition: None,
            fixture_digest: [0; 32],
        };
        value.fixture_digest = value.digest();
        value
    }

    fn profile() -> ConformanceProfileV1 {
        let mut value = ConformanceProfileV1 {
            profile_id: "pigloros.current.conformance".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            normative_spec_digest: digest(13),
            execution_matrix_digest: digest(14),
            execution_profile_digests: vec![digest(2)],
            fixture_provider_registry: registry(),
            fixtures: vec![fixture()],
            allowed_divergences: vec![],
            evaluator_protocol: EvaluatorProtocolV1 {
                protocol_id: "pigloros.evaluator.v1".to_owned(),
                protocol_digest: digest(15),
                request_schema_digest: digest(16),
                report_schema_digest: digest(17),
                hard_caps: EvaluatorHardCapsV1 {
                    max_profile_bytes: MAX_PROFILE_BYTES as u64,
                    max_cases: u32::try_from(MAX_FIXTURES).unwrap_or(u32::MAX),
                    max_bundle_members: u32::try_from(MAX_FIXTURES).unwrap_or(u32::MAX),
                    max_member_path_bytes: 256,
                    max_member_bytes: MAX_MEMBER_BYTES,
                    max_total_bundle_bytes: MAX_TOTAL_BUNDLE_BYTES,
                    max_compression_expansion: MAX_COMPRESSION_EXPANSION,
                    max_structural_nesting: MAX_STRUCTURAL_NESTING,
                    max_coordinate_bytes: 128,
                    max_diagnostic_bytes: MAX_DIAGNOSTIC_BYTES,
                },
            },
            independence_requirements: IndependenceRequirementsV1 {
                technical_independence_required: true,
                authorship_independence_required: true,
                organizational_independence_required: false,
                trust_policy_snapshot_digest: digest(18),
                requirements_digest: digest(19),
            },
            fixture_contract_policy_digest: digest(20),
            limitations_digest: digest(21),
            provenance_digest: digest(22),
            previous_profile_digest: None,
            stable_evidence: vec![],
            profile_digest: [0; 32],
        };
        value.profile_digest = value.digest();
        value
    }

    fn refresh(value: &mut ConformanceProfileV1) {
        for fixture in &mut value.fixtures {
            fixture.fixture_digest = fixture.digest();
        }
        value.profile_digest = value.digest();
    }

    fn reject(value: ConformanceProfileV1) {
        assert!(value.validate().is_err());
    }

    #[test]
    fn cpf1_current_wire_contract_round_trips_exact_field_counts() {
        let value = profile();
        let bytes = value.to_canonical_cbor().expect("current CPF1 encodes");
        assert_eq!(ConformanceProfileV1::from_canonical_cbor(&bytes), Ok(value));
        assert_eq!(
            array_values(&encode_profile(&profile(), true)).map(|fields| fields.len()),
            Ok(18)
        );
        assert_eq!(
            array_values(&encode_fixture(&fixture())).map(|fields| fields.len()),
            Ok(24)
        );
    }

    #[test]
    fn public_decoder_rejects_malformed_current_record_lengths() {
        let mut malformed_profile = encode_profile(&profile(), true);
        let Value::Array(fields) = &mut malformed_profile else {
            panic!("profile codec is an array");
        };
        fields.pop();
        let profile_bytes = encode_value(&malformed_profile).expect("mutated CBOR encodes");
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&profile_bytes),
            Err(ConformanceContractError::InvalidEncoding)
        );

        let mut malformed_fixture = encode_profile(&profile(), true);
        let Value::Array(fields) = &mut malformed_fixture else {
            panic!("profile codec is an array");
        };
        let Value::Array(fixtures) = &mut fields[9] else {
            panic!("fixture inventory is an array");
        };
        let Value::Array(fixture_fields) = &mut fixtures[0] else {
            panic!("fixture is an array");
        };
        fixture_fields.pop();
        let fixture_bytes = encode_value(&malformed_fixture).expect("mutated CBOR encodes");
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&fixture_bytes),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }

    #[test]
    fn profile_and_fixture_digests_bind_canonical_length_prefixed_fields() {
        let value = profile();
        assert_eq!(value.fixtures[0].digest(), value.fixtures[0].fixture_digest);
        assert_eq!(value.digest(), value.profile_digest);
        assert_ne!(
            contract_digest(
                b"PiglorOS.Conformance.Fixture.v1",
                &encode_fixture(&value.fixtures[0])
            ),
            value.fixtures[0].fixture_digest
        );
    }

    #[test]
    fn provider_membership_ordering_and_artifact_paths_fail_closed() {
        let mut unknown = profile();
        unknown.fixtures[0].provider_key.provider_id = "other.provider".to_owned();
        refresh(&mut unknown);
        reject(unknown);

        let mut unsorted = profile();
        unsorted.fixtures[0]
            .auxiliary
            .push(artifact("auxiliary/one.cbor", 23));
        refresh(&mut unsorted);
        reject(unsorted);

        let mut invalid_path = profile();
        invalid_path.fixtures[0].payload.member_path = "../payload.cbor".to_owned();
        refresh(&mut invalid_path);
        reject(invalid_path);
    }

    #[test]
    fn execution_modes_budgets_and_plugin_network_policy_fail_closed() {
        let mut empty_modes = profile();
        empty_modes.fixtures[0].modes.clear();
        refresh(&mut empty_modes);
        reject(empty_modes);

        for zero_budget in 0..8 {
            let mut value = profile();
            match zero_budget {
                0 => value.fixtures[0].deterministic_budget.memory_bytes = 0,
                1 => value.fixtures[0].deterministic_budget.cpu_fuel = 0,
                2 => value.fixtures[0].deterministic_budget.host_calls = 0,
                3 => value.fixtures[0].deterministic_budget.event_count = 0,
                4 => value.fixtures[0].deterministic_budget.output_bytes = 0,
                5 => value.fixtures[0].deterministic_budget.storage_bytes = 0,
                6 => value.fixtures[0].deterministic_budget.execution_steps = 0,
                _ => value.fixtures[0].deterministic_budget.simulation_time_ns = 0,
            }
            refresh(&mut value);
            reject(value);
        }

        let mut plugin_network = profile();
        plugin_network.fixtures[0].subject_adapter = SubjectAdapterKindV1::PublicPluginProtocol;
        plugin_network.fixtures[0].capability_policy.network_allowed = true;
        refresh(&mut plugin_network);
        reject(plugin_network);
    }

    #[test]
    fn strict_oracle_requires_null_inactive_fields_and_a_consistent_outcome() {
        let mut mixed = profile();
        mixed.fixtures[0].strict_oracle.failure = Some(NamespacedFailureV1 {
            owner_id: "pigloros.core".to_owned(),
            contract_version: "1.0.0".to_owned(),
            code_id: "invalid-input".to_owned(),
        });
        refresh(&mut mixed);
        reject(mixed);

        let mut wrong_outcome = profile();
        wrong_outcome.fixtures[0].expected_verification_outcome =
            VerificationOutcomeV1::InvalidManifest;
        refresh(&mut wrong_outcome);
        reject(wrong_outcome);

        let mut unauthorized_divergence = profile();
        unauthorized_divergence.fixtures[0].strict_oracle = StrictOracleV1 {
            kind: StrictOracleKindV1::Divergence,
            output: None,
            failure: None,
            divergence: Some(AllowedDivergenceV1 {
                classification: DivergenceMismatchKindV1::CanonicalBytes,
                first_coordinate: b"output/0".to_vec(),
            }),
        };
        unauthorized_divergence.fixtures[0].expected_verification_outcome =
            VerificationOutcomeV1::Diverged;
        refresh(&mut unauthorized_divergence);
        reject(unauthorized_divergence);
    }

    #[test]
    fn downgrade_authority_is_complete_and_exclusive() {
        let mut non_downgrade = profile();
        non_downgrade.fixtures[0].trust_policy_snapshot_digest = Some(digest(24));
        refresh(&mut non_downgrade);
        reject(non_downgrade);

        let mut incomplete = profile();
        incomplete.fixtures[0].family = FixtureFamilyV1::Downgrade;
        refresh(&mut incomplete);
        reject(incomplete);

        let mut identical = profile();
        identical.fixtures[0].family = FixtureFamilyV1::Downgrade;
        identical.fixtures[0].trust_policy_snapshot_digest = Some(digest(24));
        identical.fixtures[0].release_admission_digest = Some(digest(25));
        let key = provider_key();
        identical.fixtures[0].transition = Some(FixtureContractTransitionV1 {
            from: key.clone(),
            to: key,
        });
        refresh(&mut identical);
        reject(identical);
    }
}
