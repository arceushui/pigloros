//! Immutable public conformance-profile and evaluator-request contracts.
//!
//! This module deliberately references an execution profile only by digest.
//! ADR-058 owns execution behaviour; this contract owns the fixture oracle,
//! evaluator identity, independence evidence, and lifecycle claim.

use crate::{
    CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1, DivergenceMismatchKindV1, ExecutionModeV1,
    ImplementationIdentityV1, IndependenceEvidenceV1, RedactionStateV1, ReplayClaimV1,
    SafeErrorCodeV1, VerificationOutcomeV1,
};
use ciborium::value::Value;
use std::io::Cursor;

/// Magic for the first immutable conformance-profile record.
pub const CONFORMANCE_PROFILE_MAGIC_V1: &str = "CPF1";
/// Magic for the public evaluator request record.
pub const EVALUATOR_REQUEST_MAGIC_V1: &str = "EVR1";
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXECUTION_PROFILES: usize = 64;
const MAX_FIXTURES: usize = 65_536;
const MAX_STRING_BYTES: usize = 256;
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
    /// A fixture references a public schema outside the CPF1 inventory.
    UnknownPublicSchema,
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
            Self::UnknownPublicSchema => "fixture references an unknown public schema",
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

/// A public adapter used by an evaluator; private Rust and storage access are absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SubjectAdapterKindV1 {
    ExportedArtifact,
    PublicGatewayProtocol,
    PublicPluginProtocol,
}

/// One immutable digest-identified input member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureInputMemberV1 {
    pub member_id: String,
    pub size_bytes: u64,
    pub digest: [u8; 32],
    pub provenance_digest: [u8; 32],
}

/// The expected public result of a fixture. It is data, never an oracle call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedResultV1 {
    CanonicalBytes {
        bytes: Vec<u8>,
        digest: [u8; 32],
    },
    TypedFailure(SafeErrorCodeV1),
    AllowedDivergence {
        classification: DivergenceMismatchKindV1,
        first_coordinate: Vec<u8>,
    },
}

/// One profile-approved classified divergence and its first canonical coordinate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedDivergenceV1 {
    pub classification: DivergenceMismatchKindV1,
    pub first_coordinate: Vec<u8>,
}

/// Deterministic limits required by every fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureBoundsV1 {
    pub cpu_fuel: u64,
    pub memory_bytes: u64,
    pub event_count: u64,
    pub output_bytes: u64,
    pub storage_bytes: u64,
    pub execution_steps: u64,
    pub simulation_time_ns: u64,
    pub watchdog_ms: u64,
}

/// Default-deny network and capability declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityPolicyV1 {
    pub network_allowed: bool,
    pub capability_ids: Vec<String>,
}

/// Required licence and supply-chain provenance for a fixture.
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

/// One ordered fixture/expected-result descriptor in a CPF1 bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureDescriptorV1 {
    pub case_id: String,
    pub mandatory: bool,
    pub claim_layer: ClaimLayerV1,
    pub execution_profile_digest: [u8; 32],
    pub public_schema_digest: [u8; 32],
    pub modes: Vec<ExecutionModeV1>,
    pub subject_adapter: SubjectAdapterKindV1,
    pub inputs: Vec<FixtureInputMemberV1>,
    pub expected: ExpectedResultV1,
    pub expected_verification_outcome: VerificationOutcomeV1,
    pub expected_verification_error: Option<SafeErrorCodeV1>,
    pub replay_claim: ReplayClaimV1,
    pub redaction_state: RedactionStateV1,
    pub bounds: FixtureBoundsV1,
    pub capability_policy: CapabilityPolicyV1,
    pub provenance: FixtureProvenanceV1,
    pub compatibility_digest: [u8; 32],
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

/// Evaluator protocol identity and report/request schema identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorProtocolV1 {
    pub protocol_id: String,
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
    pub requirements_digest: [u8; 32],
}

/// Evidence from one separately developed implementation under test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableImplementationEvidenceV1 {
    pub implementation: ImplementationIdentityV1,
    pub independence: IndependenceEvidenceV1,
    pub evaluator_protocol_digest: [u8; 32],
    pub case_outcomes: Vec<CaseOutcomeV1>,
}

/// Immutable CPF1 public contract. It deliberately carries no aggregate pass flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceProfileV1 {
    pub profile_id: String,
    pub semantic_version: String,
    pub lifecycle: ProfileLifecycleV1,
    pub normative_spec_digest: [u8; 32],
    pub execution_profile_digests: Vec<[u8; 32]>,
    pub public_schema_digests: Vec<[u8; 32]>,
    pub fixtures: Vec<FixtureDescriptorV1>,
    pub allowed_divergences: Vec<AllowedDivergenceV1>,
    pub evaluator_protocol: EvaluatorProtocolV1,
    pub independence_requirements: IndependenceRequirementsV1,
    pub compatibility_digest: [u8; 32],
    pub limitations_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
    pub previous_profile_digest: Option<[u8; 32]>,
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
        validate_profile(self)
    }

    /// Return canonical CPF1 bytes after validating the immutable contract and digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when encoding, validation, or digest verification fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ConformanceContractError> {
        self.validate().and_then(|()| {
            let expected = self.digest();
            if self.profile_digest == expected {
                encode_value(&encode_profile(self, true))
            } else {
                Err(ConformanceContractError::FixtureDigestMismatch)
            }
        })
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
            .and_then(|profile| {
                profile.validate().and_then(|()| {
                    if profile.profile_digest == profile.digest() {
                        Ok(profile)
                    } else {
                        Err(ConformanceContractError::FixtureDigestMismatch)
                    }
                })
            })
    }

    /// Digest the canonical profile fields excluding the self-referential digest field.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest_bytes(
            b"PiglorOS.ConformanceProfile.v1",
            &encode_profile(self, false),
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
        next.profile_digest = [0; 32];
        if target == ProfileLifecycleV1::Stable {
            validate_stable_evidence(&next)?;
        } else if !next.stable_evidence.is_empty() {
            return Err(ConformanceContractError::ProfileLifecycleInvalid);
        }
        next.profile_digest = next.digest();
        next.validate().map(|()| next)
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

    /// Return exact canonical evaluator-request bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when encoding, validation, or digest verification fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ConformanceContractError> {
        self.validate()
            .and_then(|()| encode_value(&encode_request(self, true)))
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

fn validate_profile(profile: &ConformanceProfileV1) -> Result<(), ConformanceContractError> {
    if !bounded_text(&profile.profile_id, MAX_STRING_BYTES)
        || !semantic_version(&profile.semantic_version)
        || zero_digest(&profile.normative_spec_digest)
        || zero_digest(&profile.compatibility_digest)
        || zero_digest(&profile.limitations_digest)
        || zero_digest(&profile.provenance_digest)
        || profile.execution_profile_digests.is_empty()
        || profile.execution_profile_digests.len() > MAX_EXECUTION_PROFILES
        || profile.fixtures.len() > MAX_FIXTURES
        || profile.execution_profile_digests.iter().any(zero_digest)
        || profile.public_schema_digests.iter().any(zero_digest)
        || profile
            .previous_profile_digest
            .is_some_and(|digest| zero_digest(&digest))
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    if !strictly_ordered(&profile.execution_profile_digests)
        || !strictly_ordered(&profile.public_schema_digests)
    {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    validate_protocol(&profile.evaluator_protocol)
        .and_then(|()| validate_independence_requirements(&profile.independence_requirements))
        .and_then(|()| validate_fixtures(profile))
        .and_then(|()| validate_allowed_divergences(&profile.allowed_divergences))
        .and_then(|()| match profile.lifecycle {
            ProfileLifecycleV1::Candidate | ProfileLifecycleV1::Stable
                if profile.fixtures.is_empty() =>
            {
                Err(ConformanceContractError::ExpectedResultMissing)
            }
            ProfileLifecycleV1::Stable => validate_stable_evidence(profile),
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
                validate_expected_result(&fixture.expected, &profile.allowed_divergences)
            })
            .and_then(|()| validate_fixture_verification_outcome(fixture))
    })
}

fn validate_fixture(
    fixture: &FixtureDescriptorV1,
    profile: &ConformanceProfileV1,
) -> Result<(), ConformanceContractError> {
    if !bounded_text(&fixture.case_id, 128)
        || zero_digest(&fixture.public_schema_digest)
        || zero_digest(&fixture.compatibility_digest)
        || !profile
            .execution_profile_digests
            .contains(&fixture.execution_profile_digest)
        || !profile
            .public_schema_digests
            .contains(&fixture.public_schema_digest)
        || fixture.modes.is_empty()
    {
        return Err(if zero_digest(&fixture.public_schema_digest) {
            ConformanceContractError::FieldOutOfBounds
        } else if !profile
            .execution_profile_digests
            .contains(&fixture.execution_profile_digest)
        {
            ConformanceContractError::UnknownExecutionProfile
        } else if !profile
            .public_schema_digests
            .contains(&fixture.public_schema_digest)
        {
            ConformanceContractError::UnknownPublicSchema
        } else {
            ConformanceContractError::FieldOutOfBounds
        });
    }
    if !strictly_ordered(&fixture.modes)
        || fixture
            .inputs
            .windows(2)
            .any(|pair| pair[0].member_id >= pair[1].member_id)
    {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    fixture
        .inputs
        .iter()
        .try_for_each(validate_input_member)
        .and_then(|()| {
            let input_bytes = fixture.inputs.iter().try_fold(0_u64, |total, input| {
                total.checked_add(input.size_bytes)
            });
            if input_bytes.ok_or(ConformanceContractError::FieldOutOfBounds)?
                > profile.evaluator_protocol.hard_caps.max_total_bundle_bytes
                || fixture.modes.contains(&ExecutionModeV1::AirGapped)
                    && fixture.capability_policy.network_allowed
                || matches!(
                    &fixture.expected,
                    ExpectedResultV1::CanonicalBytes { bytes, .. }
                        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > fixture.bounds.output_bytes
                            || u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                                > profile.evaluator_protocol.hard_caps.max_member_bytes
                )
            {
                Err(ConformanceContractError::FieldOutOfBounds)
            } else {
                Ok(())
            }
        })
        .and_then(|()| validate_bounds(&fixture.bounds))
        .and_then(|()| validate_capability_policy(&fixture.capability_policy))
        .and_then(|()| validate_fixture_provenance(&fixture.provenance))
}

fn validate_stable_evidence(
    profile: &ConformanceProfileV1,
) -> Result<(), ConformanceContractError> {
    if profile.stable_evidence.len() != 2 {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    let first = &profile.stable_evidence[0];
    let second = &profile.stable_evidence[1];
    if first.implementation.implementation_id >= second.implementation.implementation_id
        || first.implementation.source_digest == second.implementation.source_digest
        || first.implementation.build_digest == second.implementation.build_digest
        || first.implementation.binary_digest == second.implementation.binary_digest
        || first.evaluator_protocol_digest != profile.evaluator_protocol.protocol_digest
        || second.evaluator_protocol_digest != profile.evaluator_protocol.protocol_digest
    {
        return Err(ConformanceContractError::IndependenceEvidenceMissing);
    }
    validate_stable_implementation(first, profile)
        .and_then(|()| validate_stable_implementation(second, profile))
}

fn validate_stable_implementation(
    evidence: &StableImplementationEvidenceV1,
    profile: &ConformanceProfileV1,
) -> Result<(), ConformanceContractError> {
    validate_identity(&evidence.implementation)
        .and_then(|()| {
            validate_independence_evidence(
                &evidence.independence,
                &profile.independence_requirements,
            )
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

fn case_matches_fixture(case: &CaseOutcomeV1, fixture: &FixtureDescriptorV1) -> bool {
    if case.case_id != fixture.case_id
        || case.fixture_digest != fixture_digest(fixture)
        || case.claim_layer != fixture.claim_layer
        || case.execution_profile_digest != fixture.execution_profile_digest
        || case.outcome != CaseOutcomeStatusV1::Pass
        || case.expected_error != fixture.expected_verification_error
        || case.actual_error != fixture.expected_verification_error
        || case.replay_claim != fixture.replay_claim
        || case.redaction_state != fixture.redaction_state
        || case.provenance_digest != fixture_provenance_digest(&fixture.provenance)
    {
        return false;
    }
    match &fixture.expected {
        ExpectedResultV1::CanonicalBytes { digest, .. } => {
            case.verification_outcome == VerificationOutcomeV1::VerifiedExact
                && case.expected_digest == Some(*digest)
                && case.actual_digest == Some(*digest)
        }
        ExpectedResultV1::TypedFailure(error) => {
            case.verification_outcome == fixture.expected_verification_outcome
                && case.expected_error == Some(*error)
                && case.actual_error == Some(*error)
        }
        ExpectedResultV1::AllowedDivergence {
            classification,
            first_coordinate,
        } => {
            case.verification_outcome == VerificationOutcomeV1::Diverged
                && case.divergence_kind == Some(*classification)
                && case.first_coordinate.as_ref() == Some(first_coordinate)
        }
    }
}

fn fixture_digest(fixture: &FixtureDescriptorV1) -> [u8; 32] {
    digest_bytes(b"PiglorOS.ConformanceFixture.v1", &encode_fixture(fixture))
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
        || evidence
            .reviewer_ids
            .iter()
            .any(|id| !bounded_text(id, 128))
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
    if zero_digest(&requirements.requirements_digest) {
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

fn validate_input_member(member: &FixtureInputMemberV1) -> Result<(), ConformanceContractError> {
    if !bounded_ascii(&member.member_id, MAX_STRING_BYTES)
        || member.size_bytes == 0
        || member.size_bytes > MAX_MEMBER_BYTES
        || zero_digest(&member.digest)
        || zero_digest(&member.provenance_digest)
    {
        Err(ConformanceContractError::ProvenanceMissing)
    } else {
        Ok(())
    }
}

fn validate_bounds(bounds: &FixtureBoundsV1) -> Result<(), ConformanceContractError> {
    if [
        bounds.cpu_fuel,
        bounds.memory_bytes,
        bounds.event_count,
        bounds.output_bytes,
        bounds.storage_bytes,
        bounds.execution_steps,
        bounds.simulation_time_ns,
        bounds.watchdog_ms,
    ]
    .contains(&0)
    {
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
        || policy
            .capability_ids
            .iter()
            .any(|id| !bounded_text(id, 128))
    {
        Err(ConformanceContractError::NonCanonicalOrder)
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

fn validate_expected_result(
    expected: &ExpectedResultV1,
    allowed: &[AllowedDivergenceV1],
) -> Result<(), ConformanceContractError> {
    match expected {
        ExpectedResultV1::CanonicalBytes { bytes, digest } => {
            if bytes.is_empty() || *blake3::hash(bytes).as_bytes() != *digest {
                Err(ConformanceContractError::FixtureDigestMismatch)
            } else {
                Ok(())
            }
        }
        ExpectedResultV1::TypedFailure(_) => Ok(()),
        ExpectedResultV1::AllowedDivergence {
            classification,
            first_coordinate,
        } => {
            if first_coordinate.len() > MAX_COORDINATE_BYTES {
                Err(ConformanceContractError::FieldOutOfBounds)
            } else if !allowed.iter().any(|value| {
                value.classification == *classification
                    && value.first_coordinate == *first_coordinate
            }) {
                Err(ConformanceContractError::DivergenceClassificationMismatch)
            } else {
                Ok(())
            }
        }
    }
}

fn validate_fixture_verification_outcome(
    fixture: &FixtureDescriptorV1,
) -> Result<(), ConformanceContractError> {
    match (
        &fixture.expected,
        fixture.expected_verification_outcome,
        fixture.expected_verification_error,
    ) {
        (ExpectedResultV1::CanonicalBytes { .. }, VerificationOutcomeV1::VerifiedExact, None)
        | (ExpectedResultV1::AllowedDivergence { .. }, VerificationOutcomeV1::Diverged, None) => {
            Ok(())
        }
        (ExpectedResultV1::TypedFailure(error), outcome, Some(expected_error))
            if *error == expected_error
                && !matches!(
                    outcome,
                    VerificationOutcomeV1::VerifiedExact | VerificationOutcomeV1::Diverged
                ) =>
        {
            Ok(())
        }
        _ => Err(ConformanceContractError::ExpectedResultMissing),
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

fn semantic_version(value: &str) -> bool {
    let mut components = value.split('.');
    components.clone().count() == 3
        && components.all(|component| {
            !component.is_empty()
                && component.len() <= 10
                && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn zero_digest(value: &[u8; 32]) -> bool {
    *value == [0; 32]
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn fixture_key(value: &FixtureDescriptorV1) -> (&str, ClaimLayerV1, [u8; 32]) {
    (
        &value.case_id,
        value.claim_layer,
        value.execution_profile_digest,
    )
}

fn divergence_key(value: &AllowedDivergenceV1) -> (DivergenceMismatchKindV1, &[u8]) {
    (value.classification, &value.first_coordinate)
}

fn digest_bytes(domain: &[u8], value: &Value) -> [u8; 32] {
    let bytes = encode_value(value).unwrap_or_default();
    let mut source = Vec::with_capacity(domain.len() + bytes.len() + 1);
    source.extend_from_slice(domain);
    source.push(0);
    source.extend_from_slice(&bytes);
    *blake3::hash(&source).as_bytes()
}

fn encode_profile(profile: &ConformanceProfileV1, include_digest: bool) -> Value {
    Value::Array(vec![
        text(CONFORMANCE_PROFILE_MAGIC_V1),
        uint(1),
        text(&profile.profile_id),
        text(&profile.semantic_version),
        lifecycle(profile.lifecycle),
        digest(&profile.normative_spec_digest),
        digest_list(&profile.execution_profile_digests),
        digest_list(&profile.public_schema_digests),
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
        digest(&profile.compatibility_digest),
        digest(&profile.limitations_digest),
        digest(&profile.provenance_digest),
        optional(profile.previous_profile_digest.as_ref().map(digest)),
        Value::Array(
            profile
                .stable_evidence
                .iter()
                .map(encode_stable_evidence)
                .collect(),
        ),
        if include_digest {
            digest(&profile.profile_digest)
        } else {
            Value::Null
        },
    ])
}

fn encode_fixture(value: &FixtureDescriptorV1) -> Value {
    Value::Array(vec![
        text(&value.case_id),
        Value::Bool(value.mandatory),
        claim_layer(value.claim_layer),
        digest(&value.execution_profile_digest),
        digest(&value.public_schema_digest),
        Value::Array(value.modes.iter().copied().map(mode).collect()),
        adapter(value.subject_adapter),
        Value::Array(value.inputs.iter().map(encode_input).collect()),
        encode_expected(&value.expected),
        verification_outcome(value.expected_verification_outcome),
        optional(value.expected_verification_error.map(safe_error)),
        replay_claim(value.replay_claim),
        redaction(value.redaction_state),
        encode_bounds(&value.bounds),
        encode_capability_policy(&value.capability_policy),
        encode_fixture_provenance(&value.provenance),
        digest(&value.compatibility_digest),
    ])
}

fn encode_input(value: &FixtureInputMemberV1) -> Value {
    Value::Array(vec![
        text(&value.member_id),
        uint(value.size_bytes),
        digest(&value.digest),
        digest(&value.provenance_digest),
    ])
}

fn encode_expected(value: &ExpectedResultV1) -> Value {
    match value {
        ExpectedResultV1::CanonicalBytes {
            bytes,
            digest: value_digest,
        } => Value::Array(vec![
            uint(0),
            Value::Bytes(bytes.clone()),
            digest(value_digest),
            Value::Null,
            Value::Null,
        ]),
        ExpectedResultV1::TypedFailure(error) => Value::Array(vec![
            uint(1),
            Value::Null,
            Value::Null,
            safe_error(*error),
            Value::Null,
        ]),
        ExpectedResultV1::AllowedDivergence {
            classification,
            first_coordinate,
        } => Value::Array(vec![
            uint(2),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Array(vec![
                divergence_mismatch(*classification),
                Value::Bytes(first_coordinate.clone()),
            ]),
        ]),
    }
}

fn encode_divergence(value: &AllowedDivergenceV1) -> Value {
    Value::Array(vec![
        divergence_mismatch(value.classification),
        Value::Bytes(value.first_coordinate.clone()),
    ])
}

fn encode_bounds(value: &FixtureBoundsV1) -> Value {
    Value::Array(vec![
        uint(value.cpu_fuel),
        uint(value.memory_bytes),
        uint(value.event_count),
        uint(value.output_bytes),
        uint(value.storage_bytes),
        uint(value.execution_steps),
        uint(value.simulation_time_ns),
        uint(value.watchdog_ms),
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
        digest(&value.requirements_digest),
    ])
}

fn encode_stable_evidence(value: &StableImplementationEvidenceV1) -> Value {
    Value::Array(vec![
        encode_identity(&value.implementation),
        encode_independence(&value.independence),
        digest(&value.evaluator_protocol_digest),
        Value::Array(value.case_outcomes.iter().map(encode_case).collect()),
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
    let fields = array(value, 18)?;
    if text_value(&fields[0])? != CONFORMANCE_PROFILE_MAGIC_V1 || uint_value(&fields[1])? != 1 {
        return Err(ConformanceContractError::UnsupportedVersion);
    }
    Ok(ConformanceProfileV1 {
        profile_id: text_value(&fields[2])?,
        semantic_version: text_value(&fields[3])?,
        lifecycle: decode_lifecycle(&fields[4])?,
        normative_spec_digest: digest_value(&fields[5])?,
        execution_profile_digests: digest_list_value(&fields[6])?,
        public_schema_digests: digest_list_value(&fields[7])?,
        fixtures: array_values(&fields[8])?
            .iter()
            .map(decode_fixture)
            .collect::<Result<Vec<_>, _>>()?,
        allowed_divergences: array_values(&fields[9])?
            .iter()
            .map(decode_divergence)
            .collect::<Result<Vec<_>, _>>()?,
        evaluator_protocol: decode_protocol(&fields[10])?,
        independence_requirements: decode_requirements(&fields[11])?,
        compatibility_digest: digest_value(&fields[12])?,
        limitations_digest: digest_value(&fields[13])?,
        provenance_digest: digest_value(&fields[14])?,
        previous_profile_digest: optional_digest(&fields[15])?,
        stable_evidence: array_values(&fields[16])?
            .iter()
            .map(decode_stable_evidence)
            .collect::<Result<Vec<_>, _>>()?,
        profile_digest: digest_value(&fields[17])?,
    })
}

fn decode_fixture(value: &Value) -> Result<FixtureDescriptorV1, ConformanceContractError> {
    let fields = array(value, 17)?;
    Ok(FixtureDescriptorV1 {
        case_id: text_value(&fields[0])?,
        mandatory: bool_value(&fields[1])?,
        claim_layer: decode_claim_layer(&fields[2])?,
        execution_profile_digest: digest_value(&fields[3])?,
        public_schema_digest: digest_value(&fields[4])?,
        modes: array_values(&fields[5])?
            .iter()
            .map(decode_mode)
            .collect::<Result<Vec<_>, _>>()?,
        subject_adapter: decode_adapter(&fields[6])?,
        inputs: array_values(&fields[7])?
            .iter()
            .map(decode_input)
            .collect::<Result<Vec<_>, _>>()?,
        expected: decode_expected(&fields[8])?,
        expected_verification_outcome: decode_verification_outcome(&fields[9])?,
        expected_verification_error: optional_safe_error(&fields[10])?,
        replay_claim: decode_replay_claim(&fields[11])?,
        redaction_state: decode_redaction(&fields[12])?,
        bounds: decode_bounds(&fields[13])?,
        capability_policy: decode_capability_policy(&fields[14])?,
        provenance: decode_fixture_provenance(&fields[15])?,
        compatibility_digest: digest_value(&fields[16])?,
    })
}

fn decode_input(value: &Value) -> Result<FixtureInputMemberV1, ConformanceContractError> {
    let fields = array(value, 4)?;
    Ok(FixtureInputMemberV1 {
        member_id: text_value(&fields[0])?,
        size_bytes: uint_value(&fields[1])?,
        digest: digest_value(&fields[2])?,
        provenance_digest: digest_value(&fields[3])?,
    })
}

fn decode_expected(value: &Value) -> Result<ExpectedResultV1, ConformanceContractError> {
    let fields = array(value, 5)?;
    match uint_value(&fields[0])? {
        0 => Ok(ExpectedResultV1::CanonicalBytes {
            bytes: bytes_value(&fields[1])?,
            digest: digest_value(&fields[2])?,
        }),
        1 => Ok(ExpectedResultV1::TypedFailure(decode_safe_error(
            &fields[3],
        )?)),
        2 => {
            let divergence = array(&fields[4], 2)?;
            Ok(ExpectedResultV1::AllowedDivergence {
                classification: decode_divergence_mismatch(&divergence[0])?,
                first_coordinate: bytes_value(&divergence[1])?,
            })
        }
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}

fn decode_divergence(value: &Value) -> Result<AllowedDivergenceV1, ConformanceContractError> {
    let fields = array(value, 2)?;
    Ok(AllowedDivergenceV1 {
        classification: decode_divergence_mismatch(&fields[0])?,
        first_coordinate: bytes_value(&fields[1])?,
    })
}

fn decode_bounds(value: &Value) -> Result<FixtureBoundsV1, ConformanceContractError> {
    let fields = array(value, 8)?;
    Ok(FixtureBoundsV1 {
        cpu_fuel: uint_value(&fields[0])?,
        memory_bytes: uint_value(&fields[1])?,
        event_count: uint_value(&fields[2])?,
        output_bytes: uint_value(&fields[3])?,
        storage_bytes: uint_value(&fields[4])?,
        execution_steps: uint_value(&fields[5])?,
        simulation_time_ns: uint_value(&fields[6])?,
        watchdog_ms: uint_value(&fields[7])?,
    })
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
    let fields = array(value, 4)?;
    Ok(IndependenceRequirementsV1 {
        technical_independence_required: bool_value(&fields[0])?,
        authorship_independence_required: bool_value(&fields[1])?,
        organizational_independence_required: bool_value(&fields[2])?,
        requirements_digest: digest_value(&fields[3])?,
    })
}

fn decode_stable_evidence(
    value: &Value,
) -> Result<StableImplementationEvidenceV1, ConformanceContractError> {
    let fields = array(value, 4)?;
    Ok(StableImplementationEvidenceV1 {
        implementation: decode_identity(&fields[0])?,
        independence: decode_independence(&fields[1])?,
        evaluator_protocol_digest: digest_value(&fields[2])?,
        case_outcomes: array_values(&fields[3])?
            .iter()
            .map(decode_case)
            .collect::<Result<Vec<_>, _>>()?,
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

fn decode_independence(value: &Value) -> Result<IndependenceEvidenceV1, ConformanceContractError> {
    let fields = array(value, 6)?;
    Ok(IndependenceEvidenceV1 {
        technical_independent: bool_value(&fields[0])?,
        authorship_independent: bool_value(&fields[1])?,
        organizational_independent: bool_value(&fields[2])?,
        declaration_digest: digest_value(&fields[3])?,
        shared_code_audit_digest: digest_value(&fields[4])?,
        reviewer_ids: strings_value(&fields[5])?,
    })
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

fn decode_case(value: &Value) -> Result<CaseOutcomeV1, ConformanceContractError> {
    let fields = array(value, 16)?;
    Ok(CaseOutcomeV1 {
        case_id: text_value(&fields[0])?,
        fixture_digest: digest_value(&fields[1])?,
        execution_profile_digest: digest_value(&fields[2])?,
        mode: decode_mode(&fields[3])?,
        claim_layer: decode_claim_layer(&fields[4])?,
        outcome: decode_case_outcome(&fields[5])?,
        verification_outcome: decode_verification_outcome(&fields[6])?,
        divergence_kind: optional_divergence_mismatch(&fields[7])?,
        first_coordinate: optional_bytes(&fields[8])?,
        expected_digest: optional_digest(&fields[9])?,
        actual_digest: optional_digest(&fields[10])?,
        expected_error: optional_safe_error(&fields[11])?,
        actual_error: optional_safe_error(&fields[12])?,
        replay_claim: decode_replay_claim(&fields[13])?,
        redaction_state: decode_redaction(&fields[14])?,
        provenance_digest: digest_value(&fields[15])?,
    })
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ConformanceContractError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ConformanceContractError::InvalidEncoding)
}

fn decode_value(bytes: &[u8]) -> Result<Value, ConformanceContractError> {
    preflight_cbor(bytes)?;
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor)
        .map_err(|_| ConformanceContractError::InvalidEncoding)?;
    if cursor.position() != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(ConformanceContractError::InvalidEncoding);
    }
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
        let end = index
            .checked_add(width)
            .ok_or(ConformanceContractError::FieldOutOfBounds)?;
        let value = bytes
            .get(*index..end)
            .ok_or(ConformanceContractError::InvalidEncoding)?;
        *index = end;
        Ok(value
            .iter()
            .fold(0_u64, |total, byte| total << 8 | u64::from(*byte)))
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
            7 if matches!(initial & 0x1f, 20..=22) => Ok(()),
            2 | 3 => {
                let count = usize::try_from(length)
                    .map_err(|_| ConformanceContractError::FieldOutOfBounds)?;
                let end = index
                    .checked_add(count)
                    .ok_or(ConformanceContractError::FieldOutOfBounds)?;
                if end > bytes.len() {
                    return Err(ConformanceContractError::InvalidEncoding);
                }
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
    uint(match value {
        ProfileLifecycleV1::Draft => 0,
        ProfileLifecycleV1::Candidate => 1,
        ProfileLifecycleV1::Stable => 2,
        ProfileLifecycleV1::Retired => 3,
    })
}
fn decode_lifecycle(value: &Value) -> Result<ProfileLifecycleV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(ProfileLifecycleV1::Draft),
        1 => Ok(ProfileLifecycleV1::Candidate),
        2 => Ok(ProfileLifecycleV1::Stable),
        3 => Ok(ProfileLifecycleV1::Retired),
        _ => Err(ConformanceContractError::UnsupportedVersion),
    }
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
    uint(match value {
        ClaimLayerV1::ArtifactIntegrity => 0,
        ClaimLayerV1::ReplayConformance => 1,
        ClaimLayerV1::KnowledgeNonInterference => 2,
        ClaimLayerV1::GatewayClientConformance => 3,
        ClaimLayerV1::PluginConformance => 4,
        ClaimLayerV1::MetricConformance => 5,
        ClaimLayerV1::EmpiricalEvaluation => 6,
    })
}
fn decode_claim_layer(value: &Value) -> Result<ClaimLayerV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(ClaimLayerV1::ArtifactIntegrity),
        1 => Ok(ClaimLayerV1::ReplayConformance),
        2 => Ok(ClaimLayerV1::KnowledgeNonInterference),
        3 => Ok(ClaimLayerV1::GatewayClientConformance),
        4 => Ok(ClaimLayerV1::PluginConformance),
        5 => Ok(ClaimLayerV1::MetricConformance),
        6 => Ok(ClaimLayerV1::EmpiricalEvaluation),
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
fn decode_case_outcome(value: &Value) -> Result<CaseOutcomeStatusV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(CaseOutcomeStatusV1::Pass),
        1 => Ok(CaseOutcomeStatusV1::Fail),
        2 => Ok(CaseOutcomeStatusV1::Skip),
        3 => Ok(CaseOutcomeStatusV1::Unavailable),
        4 => Ok(CaseOutcomeStatusV1::NotApplicable),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
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
fn optional_divergence_mismatch(
    value: &Value,
) -> Result<Option<DivergenceMismatchKindV1>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        decode_divergence_mismatch(value).map(Some)
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
fn decode_safe_error(value: &Value) -> Result<SafeErrorCodeV1, ConformanceContractError> {
    match uint_value(value)? {
        0 => Ok(SafeErrorCodeV1::InvalidEncoding),
        1 => Ok(SafeErrorCodeV1::UnsupportedVersion),
        2 => Ok(SafeErrorCodeV1::FieldOutOfBounds),
        3 => Ok(SafeErrorCodeV1::NonCanonicalOrder),
        4 => Ok(SafeErrorCodeV1::DigestMismatch),
        5 => Ok(SafeErrorCodeV1::SignatureInvalid),
        6 => Ok(SafeErrorCodeV1::TrustRootUnknown),
        7 => Ok(SafeErrorCodeV1::TrustSnapshotRollback),
        8 => Ok(SafeErrorCodeV1::ArtifactRevoked),
        9 => Ok(SafeErrorCodeV1::ClosureIncomplete),
        10 => Ok(SafeErrorCodeV1::ProfileClassMismatch),
        11 => Ok(SafeErrorCodeV1::ProfileUnsupported),
        12 => Ok(SafeErrorCodeV1::ProvenanceMissing),
        13 => Ok(SafeErrorCodeV1::ResourceLimitExceeded),
        _ => Err(ConformanceContractError::InvalidEncoding),
    }
}
fn optional_safe_error(value: &Value) -> Result<Option<SafeErrorCodeV1>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        decode_safe_error(value).map(Some)
    }
}
fn optional_bytes(value: &Value) -> Result<Option<Vec<u8>>, ConformanceContractError> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes_value(value).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_FIXTURE_COUNT: u32 = 65_536;
    const MAX_MEMBER_PATH_BYTES: u16 = 256;
    const MAX_COORDINATE_COUNT_BYTES: u16 = 128;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn profile() -> ConformanceProfileV1 {
        let expected_bytes = b"public expected bytes".to_vec();
        let fixture = FixtureDescriptorV1 {
            case_id: "ART-001".to_owned(),
            mandatory: true,
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            execution_profile_digest: digest(1),
            public_schema_digest: digest(2),
            modes: vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped],
            subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
            inputs: vec![FixtureInputMemberV1 {
                member_id: "fixture.json".to_owned(),
                size_bytes: 12,
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
        };
        let mut profile = ConformanceProfileV1 {
            profile_id: "pigloros.w8.artifact-integrity".to_owned(),
            semantic_version: "1.0.0".to_owned(),
            lifecycle: ProfileLifecycleV1::Draft,
            normative_spec_digest: digest(12),
            execution_profile_digests: vec![digest(1)],
            public_schema_digests: vec![digest(2)],
            fixtures: vec![fixture],
            allowed_divergences: vec![],
            evaluator_protocol: EvaluatorProtocolV1 {
                protocol_id: "pigloros.evaluator.v1".to_owned(),
                protocol_digest: digest(13),
                request_schema_digest: digest(14),
                report_schema_digest: digest(15),
                hard_caps: EvaluatorHardCapsV1 {
                    max_profile_bytes: MAX_PROFILE_BYTES as u64,
                    max_cases: MAX_FIXTURE_COUNT,
                    max_bundle_members: MAX_FIXTURE_COUNT,
                    max_member_path_bytes: MAX_MEMBER_PATH_BYTES,
                    max_member_bytes: MAX_MEMBER_BYTES,
                    max_total_bundle_bytes: MAX_TOTAL_BUNDLE_BYTES,
                    max_compression_expansion: MAX_COMPRESSION_EXPANSION,
                    max_structural_nesting: MAX_STRUCTURAL_NESTING,
                    max_coordinate_bytes: MAX_COORDINATE_COUNT_BYTES,
                    max_diagnostic_bytes: MAX_DIAGNOSTIC_BYTES,
                },
            },
            independence_requirements: IndependenceRequirementsV1 {
                technical_independence_required: true,
                authorship_independence_required: true,
                organizational_independence_required: false,
                requirements_digest: digest(16),
            },
            compatibility_digest: digest(17),
            limitations_digest: digest(18),
            provenance_digest: digest(19),
            previous_profile_digest: None,
            stable_evidence: vec![],
            profile_digest: [0; 32],
        };
        profile.profile_digest = profile.digest();
        profile
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn case_outcome_record(mode: ExecutionModeV1) -> CaseOutcomeV1 {
        let fixture = &profile().fixtures[0];
        let expected_digest = match &fixture.expected {
            ExpectedResultV1::CanonicalBytes { digest, .. } => *digest,
            ExpectedResultV1::TypedFailure(_) | ExpectedResultV1::AllowedDivergence { .. } => {
                [22; 32]
            }
        };
        CaseOutcomeV1 {
            case_id: fixture.case_id.clone(),
            fixture_digest: fixture_digest(fixture),
            execution_profile_digest: fixture.execution_profile_digest,
            mode,
            claim_layer: fixture.claim_layer,
            outcome: CaseOutcomeStatusV1::Pass,
            verification_outcome: fixture.expected_verification_outcome,
            divergence_kind: None,
            first_coordinate: None,
            expected_digest: Some(expected_digest),
            actual_digest: Some(expected_digest),
            expected_error: None,
            actual_error: None,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            provenance_digest: fixture_provenance_digest(&fixture.provenance),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_evidence(implementation_id: &str, seed: u8) -> StableImplementationEvidenceV1 {
        StableImplementationEvidenceV1 {
            implementation: ImplementationIdentityV1 {
                implementation_id: implementation_id.to_owned(),
                source_digest: digest(seed),
                build_digest: digest(seed.saturating_add(1)),
                binary_digest: digest(seed.saturating_add(2)),
                public_contract_digest: digest(seed.saturating_add(3)),
                organization_id: Some(format!("organization-{seed}")),
            },
            independence: IndependenceEvidenceV1 {
                technical_independent: true,
                authorship_independent: true,
                organizational_independent: true,
                declaration_digest: digest(seed.saturating_add(4)),
                shared_code_audit_digest: digest(seed.saturating_add(5)),
                reviewer_ids: vec![format!("reviewer-{seed}")],
            },
            evaluator_protocol_digest: digest(13),
            case_outcomes: vec![
                case_outcome_record(ExecutionModeV1::Local),
                case_outcome_record(ExecutionModeV1::AirGapped),
            ],
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn typed_failure_evidence(
        implementation_id: &str,
        seed: u8,
        fixture_digest: [u8; 32],
    ) -> StableImplementationEvidenceV1 {
        let mut evidence = stable_evidence(implementation_id, seed);
        for case in &mut evidence.case_outcomes {
            case.fixture_digest = fixture_digest;
            case.expected_digest = None;
            case.actual_digest = None;
            case.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
            case.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete);
            case.verification_outcome = VerificationOutcomeV1::InvalidManifest;
        }
        evidence
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn request() -> EvaluatorRequestV1 {
        let mut request = EvaluatorRequestV1 {
            request_id: [1; 16],
            conformance_profile_digest: digest(1),
            fixture_bundle_digest: digest(2),
            subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
            subject_artifact_digest: digest(3),
            implementation: ImplementationIdentityV1 {
                implementation_id: "independent-impl".to_owned(),
                source_digest: digest(4),
                build_digest: digest(5),
                binary_digest: digest(6),
                public_contract_digest: digest(7),
                organization_id: Some("independent-org".to_owned()),
            },
            execution_profile_digest: digest(8),
            trust_policy_snapshot_digest: digest(9),
            output_capability: EvaluatorOutputCapabilityV1 {
                capability_digest: digest(10),
                report_bytes_limit: 1,
                diagnostic_bytes_limit: MAX_DIAGNOSTIC_BYTES,
            },
            evaluator_protocol_digest: digest(11),
            evaluator_hard_caps_digest: digest(12),
            request_digest: [0; 32],
        };
        request.request_digest = request.digest();
        request
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reject_each_field<T, F>(value: &Value, exclusions: &[usize], decoder: F)
    where
        F: Fn(&Value) -> Result<T, ConformanceContractError>,
    {
        if let Value::Array(fields) = value {
            for index in 0..fields.len() {
                if !exclusions.contains(&index) {
                    let mut malformed = fields.clone();
                    malformed[index] = Value::Map(Vec::new());
                    assert!(decoder(&Value::Array(malformed)).is_err());
                }
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn zero_bound_variants() -> [FixtureBoundsV1; 8] {
        [
            FixtureBoundsV1 {
                cpu_fuel: 0,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 0,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 0,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 0,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 0,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 0,
                simulation_time_ns: 1,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 0,
                watchdog_ms: 1,
            },
            FixtureBoundsV1 {
                cpu_fuel: 1,
                memory_bytes: 1,
                event_count: 1,
                output_bytes: 1,
                storage_bytes: 1,
                execution_steps: 1,
                simulation_time_ns: 1,
                watchdog_ms: 0,
            },
        ]
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn narrow_decoder_errors(divergence_expected: &ExpectedResultV1) {
        if let Value::Array(mut fields) = encode_expected(divergence_expected) {
            fields[4] = Value::Array(vec![uint(u64::from(u8::MAX) + 1), Value::Bytes(vec![1])]);
            assert_eq!(
                decode_expected(&Value::Array(fields)),
                Err(ConformanceContractError::InvalidEncoding)
            );
        }
        assert_eq!(
            u16_value(&uint(u64::from(u16::MAX) + 1)),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            u32_value(&uint(u64::from(u32::MAX) + 1)),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert!(digest_value(&Value::Bytes(vec![1])).is_err());
        assert!(digest16_value(&Value::Bytes(vec![1])).is_err());
        assert!(digest_list_value(&Value::Array(vec![Value::Bytes(vec![1])])).is_err());
        assert!(strings_value(&Value::Array(vec![Value::Bytes(vec![1])])).is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reject_profile_change(
        change: impl FnOnce(&mut ConformanceProfileV1),
        expected: ConformanceContractError,
    ) {
        let mut value = profile();
        change(&mut value);
        value.profile_digest = value.digest();
        assert_eq!(value.validate(), Err(expected));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn original_hard_caps() -> EvaluatorHardCapsV1 {
        EvaluatorHardCapsV1 {
            max_profile_bytes: 16_777_216,
            max_cases: 65_536,
            max_bundle_members: 65_536,
            max_member_path_bytes: 256,
            max_member_bytes: 67_108_864,
            max_total_bundle_bytes: 1_073_741_824,
            max_compression_expansion: 100,
            max_structural_nesting: 32,
            max_coordinate_bytes: 128,
            max_diagnostic_bytes: 1_048_576,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn profile_with_hard_caps(caps: EvaluatorHardCapsV1) -> ConformanceProfileV1 {
        let mut value = profile();
        let bytes = vec![1];
        value.fixtures[0].expected = ExpectedResultV1::CanonicalBytes {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        };
        value.fixtures[0].bounds.output_bytes = 1;
        value.fixtures[0].inputs[0].size_bytes = 1;
        value.evaluator_protocol.hard_caps = caps;
        value.profile_digest = value.digest();
        value
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn candidate() -> ConformanceProfileV1 {
        profile()
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reject_stable_change(change: impl FnOnce(&mut StableImplementationEvidenceV1)) {
        let mut first = stable_evidence("alpha", 30);
        change(&mut first);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![first, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn cpf1_round_trips_exactly_and_uses_a_self_verifying_digest() {
        let value = profile();
        let bytes = value.to_canonical_cbor().unwrap_or_default();
        assert_eq!(ConformanceProfileV1::from_canonical_cbor(&bytes), Ok(value));
    }

    #[test]
    fn cpf1_rejects_mutated_profile_digest_and_unknown_execution_profile() {
        let mut value = profile();
        value.profile_digest = digest(200);
        assert_eq!(
            value.to_canonical_cbor(),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );
        let mut value = profile();
        value.fixtures[0].execution_profile_digest = digest(200);
        value.profile_digest = value.digest();
        assert_eq!(
            value.validate(),
            Err(ConformanceContractError::UnknownExecutionProfile)
        );
    }

    #[test]
    fn lifecycle_cannot_skip_or_fabricate_stable_evidence() {
        let value = profile();
        assert_eq!(
            value.transition_to(ProfileLifecycleV1::Stable, vec![]),
            Err(ConformanceContractError::ProfileLifecycleInvalid)
        );
        let candidate = value
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        assert_eq!(
            candidate.transition_to(ProfileLifecycleV1::Stable, vec![]),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn stable_requires_two_independent_implementations_and_all_mandatory_cases() {
        let candidate = profile()
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let stable = candidate.transition_to(
            ProfileLifecycleV1::Stable,
            vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
        );
        assert!(stable.is_ok());

        let mut incomplete = stable_evidence("alpha", 30);
        incomplete.case_outcomes.pop();
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![incomplete, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn evaluator_request_round_trips_with_all_identity_bindings() {
        let request = request();
        let bytes = request.to_canonical_cbor().unwrap_or_default();
        assert_eq!(EvaluatorRequestV1::from_canonical_cbor(&bytes), Ok(request));
    }

    #[test]
    fn closed_errors_are_safe_and_output_limits_fail_closed() {
        for value in [
            ConformanceContractError::InvalidEncoding,
            ConformanceContractError::UnsupportedVersion,
            ConformanceContractError::NonCanonicalOrder,
            ConformanceContractError::FieldOutOfBounds,
            ConformanceContractError::FixtureDigestMismatch,
            ConformanceContractError::ExpectedResultMissing,
            ConformanceContractError::IndependenceEvidenceMissing,
            ConformanceContractError::DivergenceClassificationMismatch,
            ConformanceContractError::ProfileLifecycleInvalid,
            ConformanceContractError::ProvenanceMissing,
            ConformanceContractError::UnknownExecutionProfile,
            ConformanceContractError::UnknownPublicSchema,
        ] {
            assert!(!value.to_string().is_empty());
        }
        let mut invalid = request();
        invalid.output_capability.diagnostic_bytes_limit = MAX_DIAGNOSTIC_BYTES + 1;
        assert_eq!(
            invalid.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    fn closed_enums_encode_every_declared_value_and_reject_unknown_values() {
        for value in [
            ProfileLifecycleV1::Draft,
            ProfileLifecycleV1::Candidate,
            ProfileLifecycleV1::Stable,
            ProfileLifecycleV1::Retired,
        ] {
            assert_eq!(decode_lifecycle(&lifecycle(value)), Ok(value));
        }
        for value in [
            SubjectAdapterKindV1::ExportedArtifact,
            SubjectAdapterKindV1::PublicGatewayProtocol,
            SubjectAdapterKindV1::PublicPluginProtocol,
        ] {
            assert_eq!(decode_adapter(&adapter(value)), Ok(value));
        }
        for value in [
            ExecutionModeV1::Local,
            ExecutionModeV1::AirGapped,
            ExecutionModeV1::Replay,
            ExecutionModeV1::Fork,
        ] {
            assert_eq!(decode_mode(&mode(value)), Ok(value));
        }
        for value in [
            ClaimLayerV1::ArtifactIntegrity,
            ClaimLayerV1::ReplayConformance,
            ClaimLayerV1::KnowledgeNonInterference,
            ClaimLayerV1::GatewayClientConformance,
            ClaimLayerV1::PluginConformance,
            ClaimLayerV1::MetricConformance,
            ClaimLayerV1::EmpiricalEvaluation,
        ] {
            assert_eq!(decode_claim_layer(&claim_layer(value)), Ok(value));
        }
        for value in [
            CaseOutcomeStatusV1::Pass,
            CaseOutcomeStatusV1::Fail,
            CaseOutcomeStatusV1::Skip,
            CaseOutcomeStatusV1::Unavailable,
            CaseOutcomeStatusV1::NotApplicable,
        ] {
            assert_eq!(decode_case_outcome(&case_outcome(value)), Ok(value));
        }
        for value in [
            ReplayClaimV1::Exact,
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            ReplayClaimV1::StructuralOnly,
            ReplayClaimV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::IncompatibleProfile,
        ] {
            assert_eq!(decode_replay_claim(&replay_claim(value)), Ok(value));
        }
        for value in [
            RedactionStateV1::None,
            RedactionStateV1::RedactedViews,
            RedactionStateV1::StructuralOnly,
            RedactionStateV1::EvidenceMissing,
        ] {
            assert_eq!(decode_redaction(&redaction(value)), Ok(value));
        }
        for value in [
            SafeErrorCodeV1::InvalidEncoding,
            SafeErrorCodeV1::UnsupportedVersion,
            SafeErrorCodeV1::FieldOutOfBounds,
            SafeErrorCodeV1::NonCanonicalOrder,
            SafeErrorCodeV1::DigestMismatch,
            SafeErrorCodeV1::SignatureInvalid,
            SafeErrorCodeV1::TrustRootUnknown,
            SafeErrorCodeV1::TrustSnapshotRollback,
            SafeErrorCodeV1::ArtifactRevoked,
            SafeErrorCodeV1::ClosureIncomplete,
            SafeErrorCodeV1::ProfileClassMismatch,
            SafeErrorCodeV1::ProfileUnsupported,
            SafeErrorCodeV1::ProvenanceMissing,
            SafeErrorCodeV1::ResourceLimitExceeded,
        ] {
            assert_eq!(decode_safe_error(&safe_error(value)), Ok(value));
        }
        let unknown = uint(99);
        assert!(decode_lifecycle(&unknown).is_err());
        assert!(decode_adapter(&unknown).is_err());
        assert!(decode_mode(&unknown).is_err());
        assert!(decode_claim_layer(&unknown).is_err());
        assert!(decode_case_outcome(&unknown).is_err());
        assert!(decode_replay_claim(&unknown).is_err());
        assert!(decode_redaction(&unknown).is_err());
        assert!(decode_safe_error(&unknown).is_err());
        assert!(decode_verification_outcome(&unknown).is_err());
        assert!(decode_divergence_mismatch(&unknown).is_err());
    }

    #[test]
    fn public_closed_result_codecs_cover_each_v1_discriminant() {
        for outcome in [
            VerificationOutcomeV1::VerifiedExact,
            VerificationOutcomeV1::Diverged,
            VerificationOutcomeV1::InvalidManifest,
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            VerificationOutcomeV1::IncompatibleProfile,
            VerificationOutcomeV1::ResourceLimitExceeded,
        ] {
            assert_eq!(
                decode_verification_outcome(&verification_outcome(outcome)),
                Ok(outcome)
            );
        }
        for kind in [
            DivergenceMismatchKindV1::EventIdentity,
            DivergenceMismatchKindV1::EventOrder,
            DivergenceMismatchKindV1::CanonicalBytes,
            DivergenceMismatchKindV1::ProjectionCheckpoint,
            DivergenceMismatchKindV1::TypedFailure,
            DivergenceMismatchKindV1::Artifact,
            DivergenceMismatchKindV1::SchemaOrUpcaster,
            DivergenceMismatchKindV1::NumericProfile,
            DivergenceMismatchKindV1::ProhibitedOperationalInput,
        ] {
            assert_eq!(
                decode_divergence_mismatch(&divergence_mismatch(kind)),
                Ok(kind)
            );
        }
    }

    #[test]
    fn expected_typed_failure_and_classified_divergence_are_profile_data() {
        let mut typed_failure = profile();
        typed_failure.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed_failure.fixtures[0].expected_verification_outcome =
            VerificationOutcomeV1::InvalidManifest;
        typed_failure.fixtures[0].expected_verification_error =
            Some(SafeErrorCodeV1::ClosureIncomplete);
        typed_failure.profile_digest = typed_failure.digest();
        let typed_bytes = typed_failure.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&typed_bytes),
            Ok(typed_failure)
        );

        let mut divergence = profile();
        divergence.allowed_divergences = vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        }];
        divergence.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        };
        divergence.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        divergence.profile_digest = divergence.digest();
        assert!(divergence.to_canonical_cbor().is_ok());
        divergence.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::Artifact,
            first_coordinate: b"timeline/8".to_vec(),
        };
        divergence.profile_digest = divergence.digest();
        assert_eq!(
            divergence.validate(),
            Err(ConformanceContractError::DivergenceClassificationMismatch)
        );
    }

    #[test]
    fn strict_decoder_rejects_trailing_unknown_and_forbidden_cbor_forms() {
        let mut trailing = profile().to_canonical_cbor().unwrap_or_default();
        trailing.push(0);
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&trailing),
            Err(ConformanceContractError::InvalidEncoding)
        );
        for value in [
            Value::Array(vec![]),
            Value::Map(vec![]),
            Value::Tag(0, Box::new(Value::Null)),
            Value::Float(1.0),
        ] {
            let mut malformed = Vec::new();
            let result = ciborium::into_writer(&value, &mut malformed);
            assert!(result.is_ok());
            assert_eq!(
                ConformanceProfileV1::from_canonical_cbor(&malformed),
                Err(ConformanceContractError::InvalidEncoding)
            );
        }
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&[
                0x9f, 0x64, b'C', b'P', b'F', b'1', 0x01, 0xff
            ]),
            Err(ConformanceContractError::InvalidEncoding)
        );
        let mut too_deep = vec![0x81; usize::from(MAX_STRUCTURAL_NESTING) + 2];
        too_deep.push(0xf6);
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&too_deep),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            EvaluatorRequestV1::from_canonical_cbor(&[0x5a, 0xff, 0xff, 0xff, 0xff]),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }

    #[test]
    fn bounds_ordering_and_provenance_fail_closed() {
        for bounds in zero_bound_variants() {
            let mut value = profile();
            value.fixtures[0].bounds = bounds;
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }
        let mut unordered = profile();
        unordered.execution_profile_digests = vec![digest(2), digest(1)];
        unordered.profile_digest = unordered.digest();
        assert_eq!(
            unordered.validate(),
            Err(ConformanceContractError::NonCanonicalOrder)
        );
        let mut invalid_version = profile();
        invalid_version.semantic_version = "1.0".to_owned();
        assert_eq!(
            invalid_version.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        let mut zero_predecessor = profile();
        zero_predecessor.previous_profile_digest = Some([0; 32]);
        assert_eq!(
            zero_predecessor.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        let mut missing_provenance = profile();
        missing_provenance.fixtures[0].provenance.sbom_digest = [0; 32];
        missing_provenance.profile_digest = missing_provenance.digest();
        assert_eq!(
            missing_provenance.validate(),
            Err(ConformanceContractError::ProvenanceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_descriptor_decoders_reject_each_required_field() {
        let profile = profile();
        let fixture = &profile.fixtures[0];
        let input = &fixture.inputs[0];
        let request = request();
        let evidence = stable_evidence("alpha", 30);
        let canonical_expected = &fixture.expected;
        let typed_expected = ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        let divergence_expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        };
        let divergence = AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        };

        reject_each_field(&encode_profile(&profile, true), &[], decode_profile);
        reject_each_field(&encode_fixture(fixture), &[], decode_fixture);
        reject_each_field(&encode_input(input), &[], decode_input);
        reject_each_field(
            &encode_expected(canonical_expected),
            &[3, 4],
            decode_expected,
        );
        reject_each_field(
            &encode_expected(&typed_expected),
            &[1, 2, 4],
            decode_expected,
        );
        reject_each_field(
            &encode_expected(&divergence_expected),
            &[1, 2, 3],
            decode_expected,
        );
        reject_each_field(&encode_divergence(&divergence), &[], decode_divergence);
        reject_each_field(&encode_bounds(&fixture.bounds), &[], decode_bounds);
        reject_each_field(
            &encode_capability_policy(&fixture.capability_policy),
            &[],
            decode_capability_policy,
        );
        reject_each_field(
            &encode_fixture_provenance(&fixture.provenance),
            &[],
            decode_fixture_provenance,
        );
        reject_each_field(
            &encode_protocol(&profile.evaluator_protocol),
            &[],
            decode_protocol,
        );
        reject_each_field(
            &encode_hard_caps(&profile.evaluator_protocol.hard_caps),
            &[],
            decode_hard_caps,
        );
        reject_each_field(
            &encode_requirements(&profile.independence_requirements),
            &[],
            decode_requirements,
        );
        reject_each_field(
            &encode_stable_evidence(&evidence),
            &[],
            decode_stable_evidence,
        );
        reject_each_field(&encode_request(&request, true), &[], decode_request);
        reject_each_field(
            &encode_output_capability(&request.output_capability),
            &[],
            decode_output_capability,
        );
        reject_each_field(
            &encode_identity(&request.implementation),
            &[],
            decode_identity,
        );
        reject_each_field(
            &encode_independence(&evidence.independence),
            &[],
            decode_independence,
        );
        reject_each_field(&encode_case(&evidence.case_outcomes[0]), &[], decode_case);

        narrow_decoder_errors(&divergence_expected);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cpf1_public_validation_rejects_each_retained_descriptor_invariant() {
        let reject = |change: &dyn Fn(&mut ConformanceProfileV1), error| {
            let mut value = profile();
            change(&mut value);
            value.profile_digest = value.digest();
            assert_eq!(value.validate(), Err(error));
        };
        reject(
            &|value| value.profile_id.clear(),
            ConformanceContractError::FieldOutOfBounds,
        );
        reject(
            &|value| value.semantic_version.clear(),
            ConformanceContractError::FieldOutOfBounds,
        );
        reject(
            &|value| value.normative_spec_digest = [0; 32],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject(
            &|value| value.execution_profile_digests.clear(),
            ConformanceContractError::FieldOutOfBounds,
        );
        reject(
            &|value| value.public_schema_digests = vec![digest(3), digest(2)],
            ConformanceContractError::NonCanonicalOrder,
        );
        reject(
            &|value| value.fixtures[0].modes.clear(),
            ConformanceContractError::FieldOutOfBounds,
        );
        reject(
            &|value| value.fixtures[0].inputs[0].size_bytes = 0,
            ConformanceContractError::ProvenanceMissing,
        );
        reject(
            &|value| {
                value.fixtures[0].capability_policy.capability_ids =
                    vec!["x".to_owned(), "x".to_owned()];
            },
            ConformanceContractError::NonCanonicalOrder,
        );
        reject(
            &|value| value.fixtures[0].provenance.licence_id.clear(),
            ConformanceContractError::ProvenanceMissing,
        );
        reject(
            &|value| {
                value.fixtures[0].expected = ExpectedResultV1::CanonicalBytes {
                    bytes: vec![],
                    digest: digest(1),
                }
            },
            ConformanceContractError::FixtureDigestMismatch,
        );
        reject(
            &|value| {
                value.allowed_divergences = vec![AllowedDivergenceV1 {
                    classification: DivergenceMismatchKindV1::EventOrder,
                    first_coordinate: vec![],
                }];
            },
            ConformanceContractError::FieldOutOfBounds,
        );

        let mut candidate = profile();
        candidate.fixtures.clear();
        candidate.lifecycle = ProfileLifecycleV1::Candidate;
        candidate.profile_digest = candidate.digest();
        assert_eq!(
            candidate.validate(),
            Err(ConformanceContractError::ExpectedResultMissing)
        );
        let mut draft_with_evidence = profile();
        draft_with_evidence.stable_evidence = vec![stable_evidence("alpha", 30)];
        draft_with_evidence.profile_digest = draft_with_evidence.digest();
        assert_eq!(
            draft_with_evidence.validate(),
            Err(ConformanceContractError::ProfileLifecycleInvalid)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_and_request_public_validation_reject_retained_identity_invariants() {
        let candidate = profile()
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let mut wrong_protocol = stable_evidence("alpha", 30);
        wrong_protocol.evaluator_protocol_digest = digest(99);
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![wrong_protocol, stable_evidence("beta", 40)]
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid_identity = stable_evidence("alpha", 30);
        invalid_identity.implementation.source_digest = [0; 32];
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![invalid_identity, stable_evidence("beta", 40)]
            ),
            Err(ConformanceContractError::ProvenanceMissing)
        );
        let mut invalid_independence = stable_evidence("alpha", 30);
        invalid_independence.independence.technical_independent = false;
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![invalid_independence, stable_evidence("beta", 40)]
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut invalid_request = request();
        invalid_request.request_id = [0; 16];
        assert_eq!(
            invalid_request.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        let mut request = request();
        request.request_digest = digest(99);
        assert_eq!(
            request.validate(),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );
        let oversized = vec![0; MAX_PROFILE_BYTES + 1];
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&oversized),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            EvaluatorRequestV1::from_canonical_cbor(&oversized),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cpf1_public_seams_cover_remaining_identity_order_and_stable_result_variants() {
        assert_rejects_mutated_profile_digest();

        let candidate = profile()
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        assert!(candidate.validate().is_ok());
        let mut unordered = candidate;
        let mut later = unordered.fixtures[0].clone();
        later.case_id = "ZZZ".to_owned();
        unordered.fixtures = vec![later, unordered.fixtures[0].clone()];
        unordered.profile_digest = unordered.digest();
        assert_eq!(
            unordered.validate(),
            Err(ConformanceContractError::NonCanonicalOrder)
        );

        let mut invalid_protocol = profile();
        invalid_protocol.evaluator_protocol.request_schema_digest = [0; 32];
        invalid_protocol.profile_digest = invalid_protocol.digest();
        assert_eq!(
            invalid_protocol.validate(),
            Err(ConformanceContractError::ProvenanceMissing)
        );
        let mut invalid_requirements = profile();
        invalid_requirements
            .independence_requirements
            .requirements_digest = [0; 32];
        invalid_requirements.profile_digest = invalid_requirements.digest();
        assert_eq!(
            invalid_requirements.validate(),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid_caps = profile();
        invalid_caps
            .evaluator_protocol
            .hard_caps
            .max_coordinate_bytes = MAX_COORDINATE_COUNT_BYTES + 1;
        invalid_caps.profile_digest = invalid_caps.digest();
        assert_eq!(
            invalid_caps.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        assert_stable_typed_and_divergent_result_variants();
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_rejects_mutated_profile_digest() {
        let mut wrong_digest = profile();
        wrong_digest.profile_digest = digest(99);
        let bytes = encode_value(&encode_profile(&wrong_digest, true)).unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_stable_typed_and_divergent_result_variants() {
        let mut typed = profile();
        typed.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        typed.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        let typed_candidate = typed
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let typed_fixture_digest = fixture_digest(&typed_candidate.fixtures[0]);
        let typed_evidence = typed_failure_evidence("alpha", 30, typed_fixture_digest);
        let typed_evidence_second = typed_failure_evidence("beta", 40, typed_fixture_digest);
        assert!(typed_candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![typed_evidence, typed_evidence_second]
            )
            .is_ok());

        let mut divergent = profile();
        divergent.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        };
        divergent.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        divergent.allowed_divergences = vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        }];
        let divergent_candidate = divergent
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let mut divergent_evidence = stable_evidence("alpha", 30);
        let mut divergent_second = stable_evidence("beta", 40);
        for evidence in [&mut divergent_evidence, &mut divergent_second] {
            for case in &mut evidence.case_outcomes {
                case.fixture_digest = fixture_digest(&divergent_candidate.fixtures[0]);
                case.first_coordinate = Some(b"timeline/7".to_vec());
                case.verification_outcome = VerificationOutcomeV1::Diverged;
                case.divergence_kind = Some(DivergenceMismatchKindV1::TypedFailure);
            }
        }
        let mut wrong_divergence_kind = divergent_evidence.clone();
        wrong_divergence_kind.case_outcomes[0].divergence_kind =
            Some(DivergenceMismatchKindV1::Artifact);
        assert_eq!(
            divergent_candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![wrong_divergence_kind, divergent_second.clone()],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        assert!(divergent_candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![divergent_evidence, divergent_second]
            )
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_decoders_reject_wrong_closed_record_identities() {
        let value = profile();
        if let Value::Array(mut fields) = encode_profile(&value, true) {
            fields[0] = text("CPF9");
            let bytes = encode_value(&Value::Array(fields)).unwrap_or_default();
            assert_eq!(
                ConformanceProfileV1::from_canonical_cbor(&bytes),
                Err(ConformanceContractError::UnsupportedVersion)
            );
        }
        let request = request();
        if let Value::Array(mut fields) = encode_request(&request, true) {
            fields[0] = text("EVR9");
            let bytes = encode_value(&Value::Array(fields)).unwrap_or_default();
            assert_eq!(
                EvaluatorRequestV1::from_canonical_cbor(&bytes),
                Err(ConformanceContractError::UnsupportedVersion)
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_lifecycle_and_divergence_seams_reject_remaining_closed_cases() {
        let candidate = profile()
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Retired,
                vec![stable_evidence("alpha", 30)]
            ),
            Err(ConformanceContractError::ProfileLifecycleInvalid)
        );
        let stable = candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
            )
            .unwrap_or_else(|_| profile());
        let stable_bytes = stable.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&stable_bytes),
            Ok(stable)
        );

        let mut mismatched = stable_evidence("alpha", 30);
        mismatched.case_outcomes[0].outcome = CaseOutcomeStatusV1::Fail;
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![mismatched, stable_evidence("beta", 40)]
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut organization_required = profile();
        organization_required
            .independence_requirements
            .organizational_independence_required = true;
        let organization_candidate = organization_required
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let mut organization_evidence = stable_evidence("alpha", 30);
        organization_evidence
            .independence
            .organizational_independent = false;
        assert_eq!(
            organization_candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![organization_evidence, stable_evidence("beta", 40)]
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut divergent = profile();
        divergent.allowed_divergences = vec![
            AllowedDivergenceV1 {
                classification: DivergenceMismatchKindV1::EventOrder,
                first_coordinate: b"a".to_vec(),
            },
            AllowedDivergenceV1 {
                classification: DivergenceMismatchKindV1::CanonicalBytes,
                first_coordinate: b"b".to_vec(),
            },
        ];
        divergent.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::EventOrder,
            first_coordinate: b"a".to_vec(),
        };
        divergent.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        divergent.profile_digest = divergent.digest();
        let bytes = divergent.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Ok(divergent)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_contract_digests_and_literal_ceiling_are_not_interchangeable() {
        let value = profile();
        assert_ne!(value.digest(), [0; 32]);
        assert_ne!(value.digest(), [1; 32]);
        let request = request();
        assert_ne!(request.digest(), [0; 32]);
        assert_ne!(request.digest(), [1; 32]);

        let exact_ceiling = vec![0; 16_777_216];
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&exact_ceiling),
            Err(ConformanceContractError::InvalidEncoding)
        );
        assert_eq!(
            EvaluatorRequestV1::from_canonical_cbor(&exact_ceiling),
            Err(ConformanceContractError::InvalidEncoding)
        );

        let mut exact_caps = profile();
        exact_caps.evaluator_protocol.hard_caps = original_hard_caps();
        exact_caps.profile_digest = exact_caps.digest();
        assert!(exact_caps.validate().is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_identity_and_order_validation_reject_each_single_change() {
        reject_profile_change(
            |value| value.compatibility_digest = [0; 32],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.limitations_digest = [0; 32],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.provenance_digest = [0; 32],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.execution_profile_digests = vec![digest(1), digest(1)],
            ConformanceContractError::NonCanonicalOrder,
        );
        reject_profile_change(
            |value| value.public_schema_digests = vec![digest(2), digest(2)],
            ConformanceContractError::NonCanonicalOrder,
        );
        reject_profile_change(
            |value| value.execution_profile_digests = vec![[0; 32]],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.public_schema_digests = vec![[0; 32]],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.fixtures[0].case_id = String::new(),
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.fixtures[0].public_schema_digest = [0; 32],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.fixtures[0].public_schema_digest = digest(99),
            ConformanceContractError::UnknownPublicSchema,
        );
        reject_profile_change(
            |value| value.fixtures[0].compatibility_digest = [0; 32],
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.fixtures[0].modes = vec![ExecutionModeV1::Local, ExecutionModeV1::Local],
            ConformanceContractError::NonCanonicalOrder,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_request_identity_validation_rejects_each_authority_binding() {
        let reject = |change: &dyn Fn(&mut EvaluatorRequestV1)| {
            let mut value = request();
            change(&mut value);
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        };
        reject(&|value| value.conformance_profile_digest = [0; 32]);
        reject(&|value| value.fixture_bundle_digest = [0; 32]);
        reject(&|value| value.subject_artifact_digest = [0; 32]);
        reject(&|value| value.execution_profile_digest = [0; 32]);
        reject(&|value| value.trust_policy_snapshot_digest = [0; 32]);
        reject(&|value| value.evaluator_protocol_digest = [0; 32]);
        reject(&|value| value.evaluator_hard_caps_digest = [0; 32]);
        reject(&|value| value.output_capability.capability_digest = [0; 32]);
        reject(&|value| value.output_capability.report_bytes_limit = 0);
        reject(&|value| value.output_capability.diagnostic_bytes_limit = 1_048_577);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_fixture_members_provenance_and_divergence_reject_each_single_change() {
        reject_profile_change(
            |value| {
                let input = value.fixtures[0].inputs[0].clone();
                value.fixtures[0].inputs = vec![input.clone(), input];
            },
            ConformanceContractError::NonCanonicalOrder,
        );
        reject_profile_change(
            |value| value.fixtures[0].inputs[0].member_id = String::new(),
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].inputs[0].digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].inputs[0].provenance_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].provenance.notices_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].provenance.source_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].provenance.build_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].provenance.publication_review_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].provenance.limitations_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| {
                value.fixtures[0].expected = ExpectedResultV1::CanonicalBytes {
                    bytes: vec![1],
                    digest: digest(99),
                }
            },
            ConformanceContractError::FixtureDigestMismatch,
        );
        reject_profile_change(
            |value| {
                value.allowed_divergences = vec![
                    AllowedDivergenceV1 {
                        classification: DivergenceMismatchKindV1::EventOrder,
                        first_coordinate: b"b".to_vec(),
                    },
                    AllowedDivergenceV1 {
                        classification: DivergenceMismatchKindV1::EventOrder,
                        first_coordinate: b"a".to_vec(),
                    },
                ];
            },
            ConformanceContractError::NonCanonicalOrder,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_hard_cap_u64_boundaries_are_exact() {
        let reject = |change: &dyn Fn(&mut EvaluatorHardCapsV1)| {
            let mut caps = original_hard_caps();
            change(&mut caps);
            assert_eq!(
                profile_with_hard_caps(caps).validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        };
        let accept = |change: &dyn Fn(&mut EvaluatorHardCapsV1)| {
            let mut caps = original_hard_caps();
            change(&mut caps);
            assert!(profile_with_hard_caps(caps).validate().is_ok());
        };
        reject(&|caps| caps.max_profile_bytes = 0);
        reject(&|caps| caps.max_cases = 0);
        reject(&|caps| caps.max_bundle_members = 0);
        reject(&|caps| caps.max_member_bytes = 0);
        reject(&|caps| caps.max_total_bundle_bytes = 0);
        reject(&|caps| caps.max_compression_expansion = 0);
        accept(&|caps| caps.max_profile_bytes = 1);
        accept(&|caps| caps.max_cases = 1);
        accept(&|caps| caps.max_bundle_members = 1);
        accept(&|caps| caps.max_member_bytes = 1);
        accept(&|caps| caps.max_total_bundle_bytes = 1);
        accept(&|caps| caps.max_compression_expansion = 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_hard_cap_small_boundaries_are_exact() {
        let reject = |change: &dyn Fn(&mut EvaluatorHardCapsV1)| {
            let mut caps = original_hard_caps();
            change(&mut caps);
            assert_eq!(
                profile_with_hard_caps(caps).validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        };
        let accept = |change: &dyn Fn(&mut EvaluatorHardCapsV1)| {
            let mut caps = original_hard_caps();
            change(&mut caps);
            assert!(profile_with_hard_caps(caps).validate().is_ok());
        };
        reject(&|caps| caps.max_member_path_bytes = 0);
        reject(&|caps| caps.max_structural_nesting = 0);
        reject(&|caps| caps.max_coordinate_bytes = 0);
        accept(&|caps| caps.max_member_path_bytes = 1);
        accept(&|caps| caps.max_structural_nesting = 1);
        accept(&|caps| caps.max_coordinate_bytes = 1);
        accept(&|caps| caps.max_diagnostic_bytes = 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_identity_and_independence_requirements_are_individual() {
        let reject_identity = |change: &dyn Fn(&mut ImplementationIdentityV1)| {
            let mut first = stable_evidence("alpha", 30);
            change(&mut first.implementation);
            assert_eq!(
                candidate().transition_to(
                    ProfileLifecycleV1::Stable,
                    vec![first, stable_evidence("beta", 40)],
                ),
                Err(ConformanceContractError::ProvenanceMissing)
            );
        };
        reject_identity(&|identity| identity.implementation_id.clear());
        reject_identity(&|identity| identity.organization_id = Some(String::new()));
        reject_identity(&|identity| identity.build_digest = [0; 32]);
        reject_identity(&|identity| identity.binary_digest = [0; 32]);
        reject_identity(&|identity| identity.public_contract_digest = [0; 32]);

        reject_stable_change(|value| value.independence.authorship_independent = false);
        reject_stable_change(|value| value.independence.reviewer_ids.clear());
        reject_stable_change(|value| {
            value.independence.reviewer_ids = vec!["z".to_owned(), "a".to_owned()];
        });
        reject_stable_change(|value| value.independence.reviewer_ids = vec![String::new()]);
        reject_stable_change(|value| value.independence.declaration_digest = [0; 32]);
        reject_stable_change(|value| value.independence.shared_code_audit_digest = [0; 32]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_case_matching_rejects_each_authoritative_field_mismatch() {
        reject_stable_change(|value| value.case_outcomes[0].fixture_digest = digest(99));
        reject_stable_change(|value| value.case_outcomes[0].case_id = "wrong".to_owned());
        reject_stable_change(|value| {
            value.case_outcomes[0].claim_layer = ClaimLayerV1::ReplayConformance;
        });
        reject_stable_change(|value| value.case_outcomes[0].execution_profile_digest = digest(99));
        reject_stable_change(|value| value.case_outcomes[0].outcome = CaseOutcomeStatusV1::Fail);
        reject_stable_change(|value| value.case_outcomes[0].expected_digest = Some(digest(99)));
        reject_stable_change(|value| value.case_outcomes[0].actual_digest = Some(digest(99)));
        reject_stable_change(|value| {
            value.case_outcomes[0].replay_claim = ReplayClaimV1::StructuralOnly;
        });
        reject_stable_change(|value| {
            value.case_outcomes[0].redaction_state = RedactionStateV1::RedactedViews;
        });
        reject_stable_change(|value| value.case_outcomes[0].provenance_digest = digest(99));

        let mut first = stable_evidence("beta", 30);
        let second = stable_evidence("alpha", 40);
        assert_eq!(
            candidate().transition_to(ProfileLifecycleV1::Stable, vec![first.clone(), second]),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        first.implementation.implementation_id = "alpha".to_owned();
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![first, stable_evidence("alpha", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_matching_uses_the_declared_execution_mode() {
        let mut local_only = profile();
        local_only.fixtures[0].modes = vec![ExecutionModeV1::Local];
        let candidate = local_only
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        first.case_outcomes.truncate(1);
        second.case_outcomes.truncate(1);
        first.case_outcomes[0].fixture_digest = fixture_digest(&candidate.fixtures[0]);
        second.case_outcomes[0].fixture_digest = fixture_digest(&candidate.fixtures[0]);
        assert!(candidate
            .transition_to(ProfileLifecycleV1::Stable, vec![first, second])
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_protocol_member_and_provenance_boundaries_are_exact() {
        reject_profile_change(
            |value| value.evaluator_protocol.protocol_id.clear(),
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.evaluator_protocol.protocol_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.evaluator_protocol.report_schema_digest = [0; 32],
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].inputs[0].member_id = "é".to_owned(),
            ConformanceContractError::ProvenanceMissing,
        );
        reject_profile_change(
            |value| value.fixtures[0].inputs[0].size_bytes = 67_108_865,
            ConformanceContractError::ProvenanceMissing,
        );

        let mut exact_member = profile();
        exact_member.fixtures[0].inputs[0].size_bytes = 67_108_864;
        exact_member.profile_digest = exact_member.digest();
        assert!(exact_member.validate().is_ok());

        let mut many_reviewers = stable_evidence("alpha", 30);
        many_reviewers.independence.reviewer_ids =
            (0..33).map(|number| format!("r{number:02}")).collect();
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![many_reviewers, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_typed_failure_matching_requires_both_error_identities() {
        let mut typed = profile();
        typed.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        typed.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        let typed_candidate = typed
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let reject = |mut first: StableImplementationEvidenceV1| {
            for case in &mut first.case_outcomes {
                case.expected_digest = None;
                case.actual_digest = None;
                case.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
                case.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete);
                case.verification_outcome = VerificationOutcomeV1::InvalidManifest;
            }
            first
        };
        let mut wrong_expected = reject(stable_evidence("alpha", 30));
        wrong_expected.case_outcomes[0].expected_error = Some(SafeErrorCodeV1::DigestMismatch);
        assert_eq!(
            typed_candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![wrong_expected, reject(stable_evidence("beta", 40))],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut wrong_actual = reject(stable_evidence("alpha", 30));
        wrong_actual.case_outcomes[0].actual_error = Some(SafeErrorCodeV1::DigestMismatch);
        assert_eq!(
            typed_candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![wrong_actual, reject(stable_evidence("beta", 40))],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_divergence_identity_and_coordinate_bounds_are_exact() {
        let allowed = AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: b"timeline/7".to_vec(),
        };
        reject_profile_change(
            |value| {
                value.allowed_divergences = vec![allowed.clone()];
                value.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
                    classification: DivergenceMismatchKindV1::Artifact,
                    first_coordinate: b"timeline/7".to_vec(),
                };
            },
            ConformanceContractError::DivergenceClassificationMismatch,
        );
        reject_profile_change(
            |value| {
                value.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
            },
            ConformanceContractError::ExpectedResultMissing,
        );
        reject_profile_change(
            |value| {
                value.allowed_divergences = vec![allowed.clone()];
                value.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
                    classification: DivergenceMismatchKindV1::TypedFailure,
                    first_coordinate: b"timeline/8".to_vec(),
                };
            },
            ConformanceContractError::DivergenceClassificationMismatch,
        );
        reject_profile_change(
            |value| {
                value.allowed_divergences = vec![AllowedDivergenceV1 {
                    classification: DivergenceMismatchKindV1::TypedFailure,
                    first_coordinate: vec![b'a'; 129],
                }];
            },
            ConformanceContractError::FieldOutOfBounds,
        );

        let mut exact = profile();
        exact.allowed_divergences = vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: vec![b'a'; 128],
        }];
        exact.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: vec![b'a'; 128],
        };
        exact.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        exact.profile_digest = exact.digest();
        assert!(exact.validate().is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_execution_inventory_limits_are_exact() {
        let mut at_limit = profile();
        at_limit.execution_profile_digests = (1..=64).map(digest).collect();
        assert!(at_limit.validate().is_ok());

        let mut above_limit = at_limit;
        above_limit.execution_profile_digests = (1..=65).map(digest).collect();
        assert_eq!(
            above_limit.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_fixture_inventory_limits_are_exact() {
        let template = profile().fixtures[0].clone();
        let mut at_limit = profile();
        at_limit.fixtures = (0..65_536)
            .map(|number| {
                let mut fixture = template.clone();
                fixture.case_id = format!("case-{number:05}");
                fixture
            })
            .collect();
        assert!(at_limit.validate().is_ok());

        let mut above_limit = profile();
        above_limit.fixtures = vec![template; 65_537];
        assert_eq!(
            above_limit.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_optional_and_required_organizational_independence_differ() {
        let mut optional = profile();
        optional
            .independence_requirements
            .organizational_independence_required = false;
        let optional_candidate = optional
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let mut optional_first = stable_evidence("alpha", 30);
        optional_first.independence.organizational_independent = false;
        let mut optional_second = stable_evidence("beta", 40);
        optional_second.independence.organizational_independent = false;
        assert!(optional_candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![optional_first, optional_second],
            )
            .is_ok());

        let mut required = profile();
        required
            .independence_requirements
            .organizational_independence_required = true;
        let required_candidate = required
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        assert!(required_candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
            )
            .is_ok());
        let mut required_first = stable_evidence("alpha", 30);
        required_first.independence.organizational_independent = false;
        assert_eq!(
            required_candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![required_first, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_reviewer_and_divergence_empty_boundaries_are_exact() {
        let mut first = stable_evidence("alpha", 30);
        first.independence.reviewer_ids = (0..32).map(|number| format!("r{number:02}")).collect();
        let mut second = stable_evidence("beta", 40);
        second.independence.reviewer_ids = (0..32).map(|number| format!("s{number:02}")).collect();
        assert!(candidate()
            .transition_to(ProfileLifecycleV1::Stable, vec![first, second])
            .is_ok());

        reject_profile_change(
            |value| {
                value.allowed_divergences = vec![AllowedDivergenceV1 {
                    classification: DivergenceMismatchKindV1::TypedFailure,
                    first_coordinate: b"a".to_vec(),
                }];
                value.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
                    classification: DivergenceMismatchKindV1::TypedFailure,
                    first_coordinate: Vec::new(),
                };
            },
            ConformanceContractError::DivergenceClassificationMismatch,
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_lifecycle_and_fixture_resource_limits_fail_closed() {
        let mut empty = profile();
        empty.fixtures.clear();
        assert_eq!(
            empty.transition_to(ProfileLifecycleV1::Candidate, vec![]),
            Err(ConformanceContractError::ExpectedResultMissing)
        );
        empty.lifecycle = ProfileLifecycleV1::Stable;
        empty.profile_digest = empty.digest();
        assert_eq!(
            empty.validate(),
            Err(ConformanceContractError::ExpectedResultMissing)
        );

        reject_profile_change(
            |value| value.fixtures[0].capability_policy.network_allowed = true,
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.fixtures[0].bounds.output_bytes = 1,
            ConformanceContractError::FieldOutOfBounds,
        );
        reject_profile_change(
            |value| value.evaluator_protocol.hard_caps.max_total_bundle_bytes = 1,
            ConformanceContractError::FieldOutOfBounds,
        );
        let mut request = request();
        request.output_capability.report_bytes_limit = 16_777_217;
        assert_eq!(
            request.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }
}
