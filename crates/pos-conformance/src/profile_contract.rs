//! Immutable public conformance-profile and evaluator-request contracts.
//!
//! This module deliberately references an execution profile only by digest.
//! ADR-058 owns execution behaviour; this contract owns the fixture oracle,
//! evaluator identity, independence evidence, and lifecycle claim.

use crate::{
    CaseOutcomeStatusV1, ClaimLayerV1, ConformanceReportV1, DivergenceMismatchKindV1,
    ExecutionModeV1, ImplementationIdentityV1, IndependenceEvidenceV1, ProfileCaseOutcomeV1,
    RedactionStateV1, ReplayClaimV1, SafeErrorCodeV1, VerificationOutcomeV1,
};
use ciborium::value::Value;
use pos_core::{CanonicalBytes, PublicKey, Signature};
use pos_crypto::{canonical, signing};
use std::collections::BTreeSet;
use std::io::Cursor;

/// Magic for the first immutable conformance-profile record.
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
const EXECUTION_MATRIX_BINDING_MARKER: &str = "#matrix=";
const KNOWLEDGE_PROFILE_ID: &str = "pigloros.w8.knowledge-non-interference.1.0.0";

/// Typed content identity for the ADR-059 execution matrix.
///
/// The CPF1 V1 wire record has no dedicated matrix field. To preserve its
/// canonical 17-field encoding, the knowledge profile carries this value in
/// the profile-ID binding suffix and validates it as part of its identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutionMatrixBindingV1 {
    digest: [u8; 32],
}

impl ExecutionMatrixBindingV1 {
    const fn from_digest(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    fn is_valid(self) -> bool {
        self.digest != [0; 32]
    }
}

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
            Self::UnknownPublicSchema => "fixture references an unknown public schema",
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

impl ExpectedResultV1 {
    /// Encode this expected result using the canonical CPF1 wire representation.
    ///
    /// This is the same representation used by the bundle expected-result
    /// member, including typed failures and allowed divergences.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceContractError::InvalidEncoding`] when canonical
    /// encoding fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ConformanceContractError> {
        canonical::encode(&encode_expected(self))
            .map(|bytes| bytes.as_slice().to_vec())
            .map_err(|_| ConformanceContractError::InvalidEncoding)
    }
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
/// `profile_digest` commits the selected profile and a nested digest of the
/// separately transported Stable-evidence sidecar. Signed Stable reports bind
/// the evidence-independent selected profile identity so their signature does
/// not become recursively self-referential.
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
    /// Stable evidence is intentionally a sidecar: ADR-062's exact CPF1 wire
    /// record does not contain an undocumented evidence field. The profile
    /// digest still commits the canonical sidecar so the two artifacts cannot
    /// be substituted independently.
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

    /// Bind the canonical ADR-059 execution matrix to this profile identity.
    ///
    /// The digest is carried in a structured profile-ID suffix because the
    /// CPF1 V1 record has no spare wire field. The suffix is not free-form
    /// metadata: it is parsed, bounded, and included in `profile_digest`.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the digest is zero, the existing
    /// profile-ID binding is malformed, or the resulting profile is invalid.
    pub fn bind_execution_matrix_digest(
        &mut self,
        matrix_digest: [u8; 32],
    ) -> Result<(), ConformanceContractError> {
        let binding = ExecutionMatrixBindingV1::from_digest(matrix_digest);
        if !binding.is_valid() {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        let base_profile_id = if self.profile_id.contains(EXECUTION_MATRIX_BINDING_MARKER) {
            matrix_binding_parts(&self.profile_id)?.0
        } else {
            self.profile_id.as_str()
        };
        if base_profile_id != KNOWLEDGE_PROFILE_ID {
            return Err(ConformanceContractError::FieldOutOfBounds);
        }
        let suffix = format!(
            "{EXECUTION_MATRIX_BINDING_MARKER}{}",
            crate::hex_digest(&binding.digest)
        );
        let mut bound = self.clone();
        bound.profile_id = format!("{base_profile_id}{suffix}");
        bound.profile_digest = bound.digest();
        bound.validate().map(|()| *self = bound)
    }

    /// Return the bound ADR-059 matrix digest.
    ///
    /// Only the knowledge-non-interference profile may carry this binding.
    /// Other profiles omit it because ADR-059 execution belongs to #193.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when a profile-ID binding is missing or malformed.
    pub fn execution_matrix_digest(&self) -> Result<[u8; 32], ConformanceContractError> {
        matrix_binding_parts(&self.profile_id).map(|(_, binding)| binding.digest)
    }

    /// Digest the immutable CPF fields and the attached Stable-evidence commitment.
    ///
    /// Stable evidence contains reports that attest the selected-profile digest,
    /// so the evidence is committed through a separate nested digest rather than
    /// by recursively embedding the outer profile digest in the signed report.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let stable_evidence_digest = digest_bytes(
            b"PiglorOS.ConformanceProfileStableEvidence.v1",
            &Value::Array(
                self.stable_evidence
                    .iter()
                    .map(encode_stable_evidence)
                    .collect(),
            ),
        );
        let mut identity = self.clone();
        // The report inside Stable evidence signs the selected-profile digest,
        // not this enclosing evidence commitment. Normalize lifecycle and omit
        // the recursive fields before hashing the selected CPF identity.
        identity.stable_evidence.clear();
        if identity.lifecycle == ProfileLifecycleV1::Stable {
            identity.lifecycle = ProfileLifecycleV1::Candidate;
        }
        identity.profile_digest = [0; 32];
        digest_bytes(
            b"PiglorOS.ConformanceProfile.v1",
            &Value::Array(vec![
                encode_profile(&identity, false),
                digest(&stable_evidence_digest),
            ]),
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
    if !bounded_text(&profile.profile_id, MAX_STRING_BYTES)
        || !semantic_version(&profile.semantic_version)
        || zero_digest(&profile.normative_spec_digest)
        || zero_digest(&profile.compatibility_digest)
        || zero_digest(&profile.limitations_digest)
        || zero_digest(&profile.provenance_digest)
        || profile.execution_profile_digests.is_empty()
        || profile.execution_profile_digests.len() > MAX_EXECUTION_PROFILES
        || profile.execution_profile_digests.iter().any(zero_digest)
        || profile.public_schema_digests.iter().any(zero_digest)
        || profile
            .previous_profile_digest
            .is_some_and(|digest| zero_digest(&digest))
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    if !crate::strictly_ordered(&profile.execution_profile_digests)
        || !crate::strictly_ordered(&profile.public_schema_digests)
    {
        return Err(ConformanceContractError::NonCanonicalOrder);
    }
    if crate::requires_execution_matrix_binding(&profile.profile_id)
        || profile.profile_id.contains(EXECUTION_MATRIX_BINDING_MARKER)
    {
        matrix_binding_parts(&profile.profile_id)?;
    }
    validate_protocol(&profile.evaluator_protocol)
        .and_then(|()| validate_independence_requirements(&profile.independence_requirements))
        .and_then(|()| validate_fixtures(profile))
        .and_then(|()| validate_selected_caps(profile))
        .and_then(|()| validate_allowed_divergences(&profile.allowed_divergences))
        .and_then(|()| match profile.lifecycle {
            ProfileLifecycleV1::Candidate | ProfileLifecycleV1::Stable
                if profile.fixtures.is_empty() =>
            {
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
                validate_expected_result(&fixture.expected, &profile.allowed_divergences)
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
    let encoded = encode_value(&encoded_value)?;
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > caps.max_profile_bytes
        || value_depth(&encoded_value) > usize::from(caps.max_structural_nesting)
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }

    let mut member_count = 0_u64;
    let mut bundle_bytes = 0_u64;
    for fixture in &profile.fixtures {
        for member in &fixture.inputs {
            member_count = member_count.saturating_add(1);
            bundle_bytes = bundle_bytes.saturating_add(member.size_bytes);
            if member.member_id.len() > usize::from(caps.max_member_path_bytes)
                || member.size_bytes > caps.max_member_bytes
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
    if !crate::strictly_ordered(&fixture.modes)
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
            let input_bytes = fixture
                .inputs
                .iter()
                .fold(0_u64, |total, input| total.saturating_add(input.size_bytes));
            if input_bytes > profile.evaluator_protocol.hard_caps.max_total_bundle_bytes
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
                        fixture_digest(fixture),
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
    validate_stable_attestation_fields(attestation, requirements, policy)?;
    let key = signing::verifying_key_from_public_key(&PublicKey::from_bytes(
        attestation.signer_public_key,
    ))
    .map_err(|_| ConformanceContractError::IndependenceEvidenceMissing)?;
    let signature = Signature::from_bytes(attestation.signature);
    let payload = encode_value(&stable_attestation_payload(evidence))?;
    signing::verify(&key, &CanonicalBytes::from_vec(payload), &signature)
        .map_err(|_| ConformanceContractError::IndependenceEvidenceMissing)
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
                    && fixture_digest(fixture) == report_case.fixture_digest
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
    let mut selected = profile.clone();
    selected.lifecycle = ProfileLifecycleV1::Candidate;
    selected.stable_evidence.clear();
    selected.profile_digest = [0; 32];
    selected.digest()
}

fn fixture_bundle_digest(profile: &ConformanceProfileV1) -> [u8; 32] {
    digest_bytes(
        b"PiglorOS.ConformanceFixtureBundle.v1",
        &Value::Array(profile.fixtures.iter().map(encode_fixture).collect()),
    )
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
        ExpectedResultV1::CanonicalBytes { digest, .. } => match case.verification_outcome {
            VerificationOutcomeV1::VerifiedExact => {
                case.expected_digest == Some(*digest) && case.actual_digest == Some(*digest)
            }
            VerificationOutcomeV1::UnverifiableArtifactsMissing => {
                case.expected_digest.is_none() && case.actual_digest.is_none()
            }
            _ => false,
        },
        // The preceding identity binding already requires both recorded errors
        // to equal the fixture's typed verification error.  Keeping that
        // authoritative comparison in one place avoids a redundant predicate
        // whose alternatives cannot be observed through the public contract.
        ExpectedResultV1::TypedFailure(_) => {
            case.verification_outcome == fixture.expected_verification_outcome
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
        | (
            ExpectedResultV1::CanonicalBytes { .. }
            | ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ProvenanceMissing),
            VerificationOutcomeV1::UnverifiableArtifactsMissing,
            Some(SafeErrorCodeV1::ProvenanceMissing),
        )
        | (ExpectedResultV1::AllowedDivergence { .. }, VerificationOutcomeV1::Diverged, None) => {
            Ok(())
        }
        (ExpectedResultV1::TypedFailure(error), outcome, Some(expected_error)) => {
            if *error == expected_error {
                match outcome {
                    VerificationOutcomeV1::VerifiedExact
                    | VerificationOutcomeV1::Diverged
                    | VerificationOutcomeV1::UnverifiableArtifactsMissing => {
                        Err(ConformanceContractError::ExpectedResultMissing)
                    }
                    VerificationOutcomeV1::InvalidManifest
                    | VerificationOutcomeV1::IncompatibleProfile
                    | VerificationOutcomeV1::ResourceLimitExceeded => Ok(()),
                }
            } else {
                Err(ConformanceContractError::ExpectedResultMissing)
            }
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

fn matrix_binding_parts(
    profile_id: &str,
) -> Result<(&str, ExecutionMatrixBindingV1), ConformanceContractError> {
    let Some((base, encoded_digest)) = profile_id.split_once(EXECUTION_MATRIX_BINDING_MARKER)
    else {
        return Err(ConformanceContractError::FieldOutOfBounds);
    };
    if base.is_empty()
        || encoded_digest.contains(EXECUTION_MATRIX_BINDING_MARKER)
        || encoded_digest.len() != 64
        || base != KNOWLEDGE_PROFILE_ID
    {
        return Err(ConformanceContractError::FieldOutOfBounds);
    }
    let digest = crate::decode_hex_digest(encoded_digest)
        .ok_or(ConformanceContractError::FieldOutOfBounds)?;
    let binding = ExecutionMatrixBindingV1::from_digest(digest);
    if binding.is_valid() {
        Ok((base, binding))
    } else {
        Err(ConformanceContractError::FieldOutOfBounds)
    }
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
        digest(&value.trust_policy_snapshot_digest),
        digest(&value.requirements_digest),
    ])
}

fn encode_stable_evidence(value: &StableImplementationEvidenceV1) -> Value {
    Value::Array(vec![
        encode_identity(&value.implementation),
        encode_independence(&value.independence),
        digest(&value.evaluator_protocol_digest),
        crate::strict_codec::encode_report_value(&value.report, true),
        Value::Array(value.case_outcomes.iter().map(encode_case).collect()),
        encode_stable_attestation(&value.attestation),
    ])
}

fn encode_stable_attestation(value: &StableEvidenceAttestationV1) -> Value {
    Value::Array(vec![
        digest(&value.signer_public_key),
        Value::Bytes(value.signature.to_vec()),
        digest(&value.trust_root_digest),
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
    let fields = array(value, 17)?;
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
        stable_evidence: Vec::new(),
        profile_digest: digest_value(&fields[16])?,
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
        1 => decode_safe_error(&fields[3]).map(ExpectedResultV1::TypedFailure),
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
    encode_value_to_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn encode_value_to_writer<W: std::io::Write>(
    value: &Value,
    writer: W,
) -> Result<(), ConformanceContractError> {
    ciborium::into_writer(value, writer).map_err(|_| ConformanceContractError::InvalidEncoding)
}

fn encode_bounded(value: &Value) -> Result<Vec<u8>, ConformanceContractError> {
    let bytes = encode_value(value)?;
    if bytes.len() > MAX_PROFILE_BYTES {
        Err(ConformanceContractError::FieldOutOfBounds)
    } else {
        Ok(bytes)
    }
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
                let count = usize::try_from(length)
                    .map_err(|_| ConformanceContractError::FieldOutOfBounds)?;
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
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    // The public contract tests below exercise canonical CBOR, validation,
    // lifecycle transitions, and hard-cap entrypoints. Closed enum mapping
    // tests below only enumerate the representation used by those seams.
    use super::*;
    use ed25519_dalek::Signer;

    const MAX_FIXTURE_COUNT: u32 = 65_536;
    const MAX_MEMBER_PATH_BYTES: u16 = 256;
    const MAX_COORDINATE_COUNT_BYTES: u16 = 128;

    #[test]
    fn canonical_encoding_maps_write_failures() {
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
            encode_value_to_writer(&Value::Null, FailingWriter),
            Err(ConformanceContractError::InvalidEncoding)
        );
    }

    #[test]
    fn preflight_rejects_oversized_bytes() {
        assert_eq!(
            decode_value(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn trusted_root_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
    }

    fn trusted_root_digest() -> [u8; 32] {
        let public_key = trusted_root_signing_key().verifying_key().to_bytes();
        digest_bytes(
            b"PiglorOS.ConformanceTrustRoot.v1",
            &Value::Bytes(public_key.to_vec()),
        )
    }

    fn trusted_root_policy() -> TrustedRootPolicyV1 {
        let key = trusted_root_signing_key().verifying_key().to_bytes();
        let mut policy = TrustedRootPolicyV1 {
            trusted_root_public_keys: vec![key],
            trust_policy_snapshot_digest: [0; 32],
        };
        policy.trust_policy_snapshot_digest = policy.digest();
        policy
    }

    fn selected_profile_digest(profile: &ConformanceProfileV1) -> [u8; 32] {
        let mut selected = profile.clone();
        selected.lifecycle = ProfileLifecycleV1::Candidate;
        selected.stable_evidence.clear();
        selected.profile_digest = [0; 32];
        selected.digest()
    }

    fn profile() -> ConformanceProfileV1 {
        let expected_bytes = b"public expected bytes".to_vec();
        let fixture = FixtureDescriptorV1 {
            case_id: "ART-001".to_owned(),
            mandatory: true,
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            execution_profile_digest: digest(1),
            public_schema_digest: digest(2),
            modes: vec![ExecutionModeV1::Local],
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
            profile_id: "pigloros.w8.knowledge-non-interference.1.0.0#matrix=0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
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
                trust_policy_snapshot_digest: trusted_root_policy().trust_policy_snapshot_digest,
                requirements_digest: digest(16),
            },
            compatibility_digest: digest(17),
            limitations_digest: digest(18),
            provenance_digest: digest(19),
            previous_profile_digest: None,
            stable_evidence: Vec::new(),
            profile_digest: [0; 32],
        };
        profile.profile_digest = profile.digest();
        profile
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn profile_at_canonical_byte_limit() -> (ConformanceProfileV1, Vec<u8>) {
        let mut value = profile();
        value.fixtures[0].bounds.output_bytes = MAX_MEMBER_BYTES;
        value.evaluator_protocol.hard_caps.max_member_bytes = MAX_MEMBER_BYTES;
        for _ in 0..4 {
            let encoded = encode_value(&encode_profile(&value, true)).unwrap_or_default();
            if encoded.len() == MAX_PROFILE_BYTES {
                return (value, encoded);
            }
            let current_len = match &value.fixtures[0].expected {
                ExpectedResultV1::CanonicalBytes { bytes, .. } => bytes.len(),
                ExpectedResultV1::TypedFailure(_) | ExpectedResultV1::AllowedDivergence { .. } => 0,
            };
            let next_len = if encoded.len() < MAX_PROFILE_BYTES {
                current_len + (MAX_PROFILE_BYTES - encoded.len())
            } else {
                current_len - (encoded.len() - MAX_PROFILE_BYTES)
            };
            let bytes = vec![0; next_len];
            value.fixtures[0].expected = ExpectedResultV1::CanonicalBytes {
                digest: *blake3::hash(&bytes).as_bytes(),
                bytes,
            };
            value.profile_digest = value.digest();
        }
        let encoded = encode_value(&encode_profile(&value, true)).unwrap_or_default();
        assert_eq!(encoded.len(), MAX_PROFILE_BYTES);
        (value, encoded)
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
    fn report_template(
        implementation: &ImplementationIdentityV1,
        independence: &IndependenceEvidenceV1,
        cases: Vec<crate::CaseOutcomeV1>,
    ) -> ConformanceReportV1 {
        let mut report = ConformanceReportV1 {
            report_id: [1; 16],
            subject_artifact_digest: digest(60),
            profile_digest: selected_profile_digest(&profile()),
            normative_spec_digest: digest(12),
            execution_profile_digest: digest(1),
            fixture_bundle_digest: fixture_bundle_digest(&profile()),
            evaluator_source_digest: digest(61),
            evaluator_binary_digest: digest(62),
            evaluator_protocol_digest: digest(13),
            implementation: implementation.clone(),
            independence: independence.clone(),
            cases,
            passed: 0,
            failed: 0,
            skipped: 0,
            unavailable: 0,
            not_applicable: 0,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            limitations_digest: digest(18),
            provenance_digest: digest(19),
            report_digest: [0; 32],
        };
        refresh_report_counts(&mut report);
        report.report_digest = report.digest().unwrap_or([0; 32]);
        report
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn refresh_report_counts(report: &mut ConformanceReportV1) {
        report.passed = u32::try_from(
            report
                .cases
                .iter()
                .filter(|case| case.outcome == CaseOutcomeStatusV1::Pass)
                .count(),
        )
        .unwrap_or(u32::MAX);
        report.failed = u32::try_from(
            report
                .cases
                .iter()
                .filter(|case| case.outcome == CaseOutcomeStatusV1::Fail)
                .count(),
        )
        .unwrap_or(u32::MAX);
        report.skipped = u32::try_from(
            report
                .cases
                .iter()
                .filter(|case| case.outcome == CaseOutcomeStatusV1::Skip)
                .count(),
        )
        .unwrap_or(u32::MAX);
        report.unavailable = u32::try_from(
            report
                .cases
                .iter()
                .filter(|case| case.outcome == CaseOutcomeStatusV1::Unavailable)
                .count(),
        )
        .unwrap_or(u32::MAX);
        report.not_applicable = u32::try_from(
            report
                .cases
                .iter()
                .filter(|case| case.outcome == CaseOutcomeStatusV1::NotApplicable)
                .count(),
        )
        .unwrap_or(u32::MAX);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn refresh_stable_report(evidence: &mut StableImplementationEvidenceV1) {
        evidence.report.implementation = evidence.implementation.clone();
        evidence.report.independence = evidence.independence.clone();
        evidence.report.cases = evidence
            .case_outcomes
            .iter()
            .map(|case| crate::CaseOutcomeV1 {
                case_id: case.case_id.clone(),
                fixture_digest: case.fixture_digest,
                execution_profile_digest: case.execution_profile_digest,
                mode: case.mode,
                claim_layer: case.claim_layer,
                outcome: case.outcome,
                first_coordinate: case.first_coordinate.clone(),
                expected_digest: case.expected_digest,
                actual_digest: case.actual_digest,
                expected_error: case.expected_error,
                actual_error: case.actual_error,
                replay_claim: case.replay_claim,
                redaction_state: case.redaction_state,
                provenance_digest: case.provenance_digest,
            })
            .collect();
        refresh_report_counts(&mut evidence.report);
        evidence.report.report_digest = evidence.report.digest().unwrap_or([0; 32]);
        refresh_stable_attestation(evidence);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn refresh_stable_report_for_profile(
        evidence: &mut StableImplementationEvidenceV1,
        profile: &ConformanceProfileV1,
    ) {
        refresh_stable_report(evidence);
        evidence.report.profile_digest = selected_profile_digest(profile);
        evidence.report.normative_spec_digest = profile.normative_spec_digest;
        evidence.report.limitations_digest = profile.limitations_digest;
        evidence.report.provenance_digest = profile.provenance_digest;
        evidence.report.fixture_bundle_digest = fixture_bundle_digest(profile);
        evidence.report.report_digest = evidence.report.digest().unwrap_or([0; 32]);
        refresh_stable_attestation(evidence);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_evidence(implementation_id: &str, seed: u8) -> StableImplementationEvidenceV1 {
        let mut evidence = StableImplementationEvidenceV1 {
            implementation: ImplementationIdentityV1 {
                implementation_id: implementation_id.to_owned(),
                source_digest: digest(seed),
                build_digest: digest(seed.saturating_add(1)),
                binary_digest: digest(seed.saturating_add(2)),
                public_contract_digest: digest(7),
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
            report: report_template(
                &ImplementationIdentityV1 {
                    implementation_id: implementation_id.to_owned(),
                    source_digest: digest(seed),
                    build_digest: digest(seed.saturating_add(1)),
                    binary_digest: digest(seed.saturating_add(2)),
                    public_contract_digest: digest(7),
                    organization_id: Some(format!("organization-{seed}")),
                },
                &IndependenceEvidenceV1 {
                    technical_independent: true,
                    authorship_independent: true,
                    organizational_independent: true,
                    declaration_digest: digest(seed.saturating_add(4)),
                    shared_code_audit_digest: digest(seed.saturating_add(5)),
                    reviewer_ids: vec![format!("reviewer-{seed}")],
                },
                vec![],
            ),
            case_outcomes: vec![case_outcome_record(ExecutionModeV1::Local)],
            attestation: StableEvidenceAttestationV1 {
                signer_public_key: [0; 32],
                signature: [0; 64],
                trust_root_digest: [0; 32],
            },
        };
        refresh_stable_report(&mut evidence);
        refresh_stable_attestation(&mut evidence);
        evidence
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn refresh_stable_attestation(evidence: &mut StableImplementationEvidenceV1) {
        let signing_key = trusted_root_signing_key();
        evidence.attestation.signer_public_key = signing_key.verifying_key().to_bytes();
        evidence.attestation.trust_root_digest = trusted_root_digest();
        let payload = encode_value(&stable_attestation_payload(evidence)).unwrap_or_default();
        evidence.attestation.signature = signing_key.sign(&payload).to_bytes();
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
        refresh_stable_report(&mut evidence);
        refresh_stable_attestation(&mut evidence);
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
            execution_profile_digest: digest(1),
            trust_policy_snapshot_digest: trusted_root_policy().trust_policy_snapshot_digest,
            output_capability: EvaluatorOutputCapabilityV1 {
                capability_digest: [0; 32],
                report_bytes_limit: 1,
                diagnostic_bytes_limit: MAX_DIAGNOSTIC_BYTES,
            },
            evaluator_protocol_digest: digest(13),
            evaluator_hard_caps_digest: original_hard_caps().digest(),
            request_digest: [0; 32],
        };
        request.conformance_profile_digest = profile().profile_digest;
        request.fixture_bundle_digest = fixture_bundle_digest(&profile());
        request.output_capability.capability_digest = request.expected_output_capability_digest();
        request.request_digest = request.digest();
        request
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replace_profile_path(value: &mut Value, path: &[usize], replacement: Value) {
        if let Some(index) = path.first().copied() {
            if path.len() == 1 {
                if let Value::Array(fields) = value {
                    fields[index] = replacement;
                }
            } else if let Value::Array(fields) = value {
                replace_profile_path(&mut fields[index], &path[1..], replacement);
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn malformed_profile_bytes(
        profile: &ConformanceProfileV1,
        path: &[usize],
        replacement: Value,
    ) -> Result<Vec<u8>, ConformanceContractError> {
        let mut encoded = encode_profile(profile, true);
        replace_profile_path(&mut encoded, path, replacement);
        encode_value(&encoded)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn malformed_request_bytes(
        path: &[usize],
        replacement: Value,
    ) -> Result<Vec<u8>, ConformanceContractError> {
        let mut encoded = encode_request(&request(), true);
        replace_profile_path(&mut encoded, path, replacement);
        encode_value(&encoded)
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
    fn stable_profile() -> ConformanceProfileV1 {
        candidate()
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
            )
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
        assert_eq!(
            value.validate(),
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
    fn stable_validation_requires_external_root_membership_and_policy_identity() {
        let candidate_profile = candidate();
        let stable = candidate_profile
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
            )
            .unwrap_or_else(|_| profile());
        assert_eq!(
            stable.validate(),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let policy = trusted_root_policy();
        assert_eq!(stable.validate_with_trust_policy(&policy), Ok(()));
        assert!(candidate()
            .transition_to_with_trust_policy(
                ProfileLifecycleV1::Stable,
                vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
                &policy,
            )
            .is_ok());
        let mut untrusted = policy.clone();
        untrusted.trusted_root_public_keys = vec![ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()];
        untrusted.trust_policy_snapshot_digest = untrusted.digest();
        assert_eq!(
            stable.validate_with_trust_policy(&untrusted),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let bytes = encode_value(&encode_profile(&stable, true)).unwrap_or_default();
        assert!(matches!(
            encode_profile(&stable, true),
            Value::Array(fields) if fields.len() == 17
        ));
        assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
                &bytes,
                stable.stable_evidence.clone(),
                &policy,
            ),
            Ok(stable)
        );

        let oversized = vec![0; MAX_PROFILE_BYTES + 1];
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_trust_policy(&oversized, &policy),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
                &oversized,
                Vec::new(),
                &policy,
            ),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut tampered = encode_profile(&candidate_profile, true);
        replace_profile_path(&mut tampered, &[16], Value::Bytes(digest(99).to_vec()));
        let tampered_bytes = encode_value(&tampered).unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_trust_policy(&tampered_bytes, &policy,),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut invalid_candidate = candidate_profile;
        invalid_candidate.profile_digest = digest(99);
        assert_eq!(
            invalid_candidate.validate_with_trust_policy(&policy),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_decoders_accept_the_inclusive_wire_ceiling() {
        let (value, bytes) = profile_at_canonical_byte_limit();
        assert_eq!(bytes.len(), MAX_PROFILE_BYTES);
        assert_eq!(value.to_canonical_cbor(), Ok(bytes.clone()));
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&bytes),
            Ok(value.clone())
        );
        let policy = trusted_root_policy();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_trust_policy(&bytes, &policy),
            Ok(value.clone())
        );
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
                &bytes,
                Vec::new(),
                &policy,
            ),
            Ok(value)
        );
    }

    #[test]
    fn public_stable_transition_with_policy_validates_the_published_profile() {
        let policy = trusted_root_policy();
        let candidate = candidate();
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        refresh_stable_report_for_profile(&mut first, &candidate);
        refresh_stable_report_for_profile(&mut second, &candidate);
        let stable = candidate
            .transition_to_with_trust_policy(
                ProfileLifecycleV1::Stable,
                vec![first, second],
                &policy,
            )
            .unwrap_or_else(|_| profile());
        assert_eq!(stable.validate_with_trust_policy(&policy), Ok(()));
    }

    #[test]
    fn public_stable_transition_rejects_an_invalid_external_policy() {
        let candidate = candidate();
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        refresh_stable_report_for_profile(&mut first, &candidate);
        refresh_stable_report_for_profile(&mut second, &candidate);
        let mut invalid_policy = trusted_root_policy();
        invalid_policy.trust_policy_snapshot_digest = digest(99);
        assert_eq!(
            candidate.transition_to_with_trust_policy(
                ProfileLifecycleV1::Stable,
                vec![first, second],
                &invalid_policy,
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn public_retirement_with_policy_skips_stable_validation() {
        let candidate = candidate();
        assert!(candidate
            .transition_to_with_trust_policy(
                ProfileLifecycleV1::Retired,
                vec![],
                &trusted_root_policy()
            )
            .is_ok());
    }

    #[test]
    fn public_stable_validator_rejects_report_shape_mismatches() {
        let mut value = stable_profile();
        value.stable_evidence[0].report.cases.pop();
        refresh_report_counts(&mut value.stable_evidence[0].report);
        value.stable_evidence[0].report.report_digest =
            value.stable_evidence[0].report.digest().unwrap_or([0; 32]);
        refresh_stable_attestation(&mut value.stable_evidence[0]);
        assert_eq!(
            value.validate_with_trust_policy(&trusted_root_policy()),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut value = stable_profile();
        value.stable_evidence[0].report.cases[0].outcome = CaseOutcomeStatusV1::Fail;
        refresh_report_counts(&mut value.stable_evidence[0].report);
        value.stable_evidence[0].report.report_digest =
            value.stable_evidence[0].report.digest().unwrap_or([0; 32]);
        refresh_stable_attestation(&mut value.stable_evidence[0]);
        assert_eq!(
            value.validate_with_trust_policy(&trusted_root_policy()),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn public_stable_validator_rejects_case_identity_mismatch() {
        let mut value = stable_profile();
        value.stable_evidence[0].case_outcomes[0].provenance_digest = digest(99);
        refresh_stable_report(&mut value.stable_evidence[0]);
        assert_eq!(
            value.validate_with_trust_policy(&trusted_root_policy()),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn public_stable_validator_rejects_report_case_outcome_mismatch() {
        let mut value = stable_profile();
        value.stable_evidence[0].report.cases[0].replay_claim = ReplayClaimV1::StructuralOnly;
        value.stable_evidence[0].report.replay_claim = ReplayClaimV1::StructuralOnly;
        value.stable_evidence[0].report.report_digest =
            value.stable_evidence[0].report.digest().unwrap_or([0; 32]);
        refresh_stable_attestation(&mut value.stable_evidence[0]);
        assert_eq!(
            value.validate_with_trust_policy(&trusted_root_policy()),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn trusted_root_policy_public_validation_covers_closed_rejection_paths() {
        let valid = trusted_root_policy();
        assert_eq!(valid.validate(), Ok(()));

        let mut empty = valid.clone();
        empty.trusted_root_public_keys.clear();
        assert_eq!(
            empty.validate(),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut zero = valid.clone();
        zero.trusted_root_public_keys = vec![[0; 32]];
        zero.trust_policy_snapshot_digest = zero.digest();
        assert_eq!(
            zero.validate(),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut unordered = valid.clone();
        unordered.trusted_root_public_keys = vec![[2; 32], [1; 32]];
        unordered.trust_policy_snapshot_digest = unordered.digest();
        assert_eq!(
            unordered.validate(),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut mismatched_digest = valid;
        mismatched_digest.trust_policy_snapshot_digest = [9; 32];
        assert_eq!(
            mismatched_digest.validate(),
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
    fn evaluator_request_public_validation_binds_protocol_and_caps_together() {
        let request = request();
        let protocol = profile().evaluator_protocol;
        assert_eq!(request.validate_with_protocol(&protocol), Ok(()));
        assert_eq!(request.validate_against_profile(&profile()), Ok(()));
        assert_eq!(
            request.validate_against_profile_with_trust_policy(&profile(), &trusted_root_policy()),
            Ok(())
        );

        let mut unrelated_profile = profile();
        unrelated_profile.fixtures[0].execution_profile_digest = digest(99);
        unrelated_profile.execution_profile_digests = vec![digest(99)];
        unrelated_profile.profile_digest = unrelated_profile.digest();
        assert_eq!(
            request.validate_against_profile(&unrelated_profile),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut invalid_profile_digest = profile();
        invalid_profile_digest.profile_digest = digest(99);
        assert_eq!(
            request.validate_against_profile(&invalid_profile_digest),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut protocol_profile = profile();
        protocol_profile.evaluator_protocol.protocol_digest = digest(99);
        protocol_profile.profile_digest = protocol_profile.digest();
        let mut protocol_request = request.clone();
        protocol_request.conformance_profile_digest = protocol_profile.profile_digest;
        protocol_request.fixture_bundle_digest = fixture_bundle_digest(&protocol_profile);
        protocol_request.output_capability.capability_digest =
            protocol_request.expected_output_capability_digest();
        protocol_request.request_digest = protocol_request.digest();
        assert_eq!(
            protocol_request.validate_against_profile(&protocol_profile),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut unknown_execution = request.clone();
        unknown_execution.execution_profile_digest = digest(99);
        unknown_execution.output_capability.capability_digest =
            unknown_execution.expected_output_capability_digest();
        unknown_execution.request_digest = unknown_execution.digest();
        assert_eq!(
            unknown_execution.validate_against_profile(&profile()),
            Err(ConformanceContractError::UnknownExecutionProfile)
        );

        let mut wrong_protocol = protocol.clone();
        wrong_protocol.protocol_digest = digest(99);
        assert_eq!(
            request.validate_with_protocol(&wrong_protocol),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut wrong_caps = protocol.clone();
        wrong_caps.hard_caps.max_cases = 1;
        assert_eq!(
            request.validate_with_protocol(&wrong_caps),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut wrong_caps = original_hard_caps();
        wrong_caps.max_cases = wrong_caps.max_cases.saturating_sub(1);
        assert_eq!(
            request.validate_with_hard_caps(&wrong_caps),
            Err(ConformanceContractError::FixtureDigestMismatch)
        );

        let mut capped_request = request;
        let mut capped_protocol = protocol;
        capped_protocol.hard_caps.max_profile_bytes = 1;
        capped_request.output_capability.report_bytes_limit = 2;
        capped_request.evaluator_hard_caps_digest = capped_protocol.hard_caps.digest();
        capped_request.output_capability.capability_digest =
            capped_request.expected_output_capability_digest();
        capped_request.request_digest = capped_request.digest();
        assert_eq!(
            capped_request.validate_with_protocol(&capped_protocol),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
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
            ConformanceContractError::ClaimRedactionMismatch,
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
        assert!(decode_replay_claim(&unknown).is_err());
        assert!(decode_redaction(&unknown).is_err());
        assert!(decode_safe_error(&unknown).is_err());
        assert!(decode_verification_outcome(&unknown).is_err());
        assert!(decode_divergence_mismatch(&unknown).is_err());

        for (outcome, code) in [
            (CaseOutcomeStatusV1::Pass, 0),
            (CaseOutcomeStatusV1::Fail, 1),
            (CaseOutcomeStatusV1::Skip, 2),
            (CaseOutcomeStatusV1::Unavailable, 3),
            (CaseOutcomeStatusV1::NotApplicable, 4),
        ] {
            assert_eq!(case_outcome(outcome), uint(code));
        }
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
    fn public_stable_report_binding_and_hard_cap_divergence_seams_are_fail_closed() {
        let mut mismatched_report = stable_evidence("alpha", 30);
        mismatched_report.report.cases[0].outcome = CaseOutcomeStatusV1::Fail;
        mismatched_report.report.cases[0].actual_digest = Some([99; 32]);
        mismatched_report.report.cases[0].first_coordinate = Some(vec![1]);
        refresh_report_counts(&mut mismatched_report.report);
        refresh_stable_attestation(&mut mismatched_report);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![mismatched_report, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut missing_report_case = stable_evidence("alpha", 30);
        missing_report_case.report.cases.pop();
        refresh_report_counts(&mut missing_report_case.report);
        refresh_stable_attestation(&mut missing_report_case);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![missing_report_case, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut invalid_case = stable_evidence("alpha", 30);
        invalid_case.case_outcomes[0].verification_outcome = VerificationOutcomeV1::Diverged;
        invalid_case.case_outcomes[0].divergence_kind =
            Some(DivergenceMismatchKindV1::TypedFailure);
        refresh_stable_report(&mut invalid_case);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![invalid_case, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut capped = profile();
        let coordinate = vec![b'a'; 129];
        capped.allowed_divergences = vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate.clone(),
        }];
        capped.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate,
        };
        capped.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        capped.evaluator_protocol.hard_caps.max_coordinate_bytes = 128;
        capped.profile_digest = capped.digest();
        assert_eq!(
            capped.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    fn strict_decoder_rejects_trailing_unknown_and_forbidden_cbor_forms() {
        let mut wide_integer = profile();
        wide_integer.fixtures[0].bounds.cpu_fuel = u64::from(u32::MAX) + 1;
        wide_integer.profile_digest = wide_integer.digest();
        let wide_integer_bytes = wide_integer.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&wide_integer_bytes),
            Ok(wide_integer)
        );

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
        // The structural preflight accepts text by length; the canonical
        // decoder must still reject invalid UTF-8 in that text item.
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&[0x61, 0xff]),
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
        let oversized_value = Value::Bytes(vec![0; MAX_PROFILE_BYTES]);
        assert_eq!(
            encode_bounded(&oversized_value),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    fn public_profile_codec_round_trips_nested_stable_report_variants() {
        let mut typed = profile();
        typed.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        typed.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        typed.profile_digest = typed.digest();
        let typed_bytes = typed.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&typed_bytes),
            Ok(typed)
        );

        let mut divergent = profile();
        let coordinate = b"timeline/7".to_vec();
        divergent.allowed_divergences = vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate.clone(),
        }];
        divergent.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate,
        };
        divergent.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        divergent.profile_digest = divergent.digest();
        let candidate = divergent
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let fixture_digest = fixture_digest(&candidate.fixtures[0]);
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        for evidence in [&mut first, &mut second] {
            for case in &mut evidence.case_outcomes {
                case.fixture_digest = fixture_digest;
                case.first_coordinate = Some(b"timeline/7".to_vec());
                case.actual_digest = Some([99; 32]);
                case.verification_outcome = VerificationOutcomeV1::Diverged;
                case.divergence_kind = Some(DivergenceMismatchKindV1::TypedFailure);
            }
            refresh_stable_report_for_profile(evidence, &candidate);
        }
        let stable = candidate
            .transition_to(ProfileLifecycleV1::Stable, vec![first, second])
            .unwrap_or_else(|_| profile());
        let stable_bytes = stable
            .to_canonical_cbor_with_trust_policy(&trusted_root_policy())
            .unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
                &stable_bytes,
                stable.stable_evidence.clone(),
                &trusted_root_policy(),
            ),
            Ok(stable)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_and_request_codecs_reject_nested_malformed_records() {
        let reject_profile = |value: Value| {
            let bytes = encode_value(&value).unwrap_or_default();
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        };
        let reject_request = |value: Value| {
            let bytes = encode_value(&value).unwrap_or_default();
            assert!(EvaluatorRequestV1::from_canonical_cbor(&bytes).is_err());
        };

        if let Value::Array(fields) = encode_profile(&profile(), true) {
            for index in 0..17 {
                let mut malformed = fields.clone();
                if let Value::Array(fixtures) = &mut malformed[8] {
                    if let Value::Array(fixture) = &mut fixtures[0] {
                        fixture[index] = Value::Map(Vec::new());
                    }
                }
                reject_profile(Value::Array(malformed));
            }
            for index in 0..5 {
                let mut malformed = fields.clone();
                if let Value::Array(protocol) = &mut malformed[10] {
                    protocol[index] = Value::Map(Vec::new());
                }
                reject_profile(Value::Array(malformed));
            }
            for index in 0..5 {
                let mut malformed = fields.clone();
                if let Value::Array(requirements) = &mut malformed[11] {
                    requirements[index] = Value::Map(Vec::new());
                }
                reject_profile(Value::Array(malformed));
            }

            let mut oversized_fixtures = fields;
            oversized_fixtures[8] = Value::Array(vec![Value::Null; MAX_FIXTURES + 1]);
            reject_profile(Value::Array(oversized_fixtures));
        }

        if let Value::Array(fields) = encode_request(&request(), true) {
            for index in 0..6 {
                let mut malformed = fields.clone();
                if let Value::Array(identity) = &mut malformed[7] {
                    identity[index] = Value::Map(Vec::new());
                }
                reject_request(Value::Array(malformed));
            }
            for index in 0..3 {
                let mut malformed = fields.clone();
                if let Value::Array(output) = &mut malformed[10] {
                    output[index] = Value::Map(Vec::new());
                }
                reject_request(Value::Array(malformed));
            }
        }

        let mut typed = profile();
        typed.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        typed.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        typed.profile_digest = typed.digest();
        if let Value::Array(mut fields) = encode_profile(&typed, true) {
            if let Value::Array(fixtures) = &mut fields[8] {
                if let Value::Array(fixture) = &mut fixtures[0] {
                    if let Value::Array(expected) = &mut fixture[8] {
                        expected[3] = Value::Map(Vec::new());
                    }
                }
            }
            reject_profile(Value::Array(fields));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_seams_cover_closed_helper_errors() {
        let reject_profile = |value: Value| {
            let bytes = encode_value(&value).unwrap_or_default();
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        };

        let fields = encode_profile(&profile(), true)
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut wrong_array = fields.clone();
        wrong_array[8] = Value::Bool(true);
        reject_profile(Value::Array(wrong_array));

        let mut wrong_text = fields.clone();
        wrong_text[2] = Value::Bool(true);
        reject_profile(Value::Array(wrong_text));

        let mut wrong_uint = fields.clone();
        wrong_uint[1] = Value::Bool(true);
        reject_profile(Value::Array(wrong_uint));

        let mut wrong_bytes = fields.clone();
        wrong_bytes[5] = Value::Bool(true);
        reject_profile(Value::Array(wrong_bytes));

        let mut wrong_bool = fields.clone();
        if let Some(fixtures) = wrong_bool[8].as_array_mut() {
            if let Some(fixture) = fixtures[0].as_array_mut() {
                fixture[1] = Value::Null;
            }
        }
        reject_profile(Value::Array(wrong_bool));

        let mut wrong_typed_error = fields.clone();
        if let Some(fixtures) = wrong_typed_error[8].as_array_mut() {
            if let Some(fixture) = fixtures[0].as_array_mut() {
                if let Some(expected) = fixture[8].as_array_mut() {
                    expected[0] = uint(1);
                    expected[3] = Value::Bool(true);
                }
            }
        }
        reject_profile(Value::Array(wrong_typed_error));

        let mut trailing = encode_value(&Value::Array(fields)).unwrap_or_default();
        trailing.push(0);
        assert!(ConformanceProfileV1::from_canonical_cbor(&trailing).is_err());

        let mut invalid_bounds = profile();
        invalid_bounds.fixtures[0].bounds.cpu_fuel = 0;
        invalid_bounds.profile_digest = invalid_bounds.digest();
        assert_eq!(
            invalid_bounds.to_canonical_cbor(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut fields = encode_request(&request(), true)
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(identity) = fields[7].as_array_mut() {
            identity[5] = Value::Null;
        }
        let bytes = encode_value(&Value::Array(fields)).unwrap_or_default();
        assert!(EvaluatorRequestV1::from_canonical_cbor(&bytes).is_err());

        let candidate = profile()
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let fixture_digest = fixture_digest(&candidate.fixtures[0]);
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        for evidence in [&mut first, &mut second] {
            for case in &mut evidence.case_outcomes {
                case.fixture_digest = fixture_digest;
            }
            refresh_stable_report_for_profile(evidence, &candidate);
        }
        first.report.cases[0].provenance_digest = [88; 32];
        first.report.report_digest = first.report.digest().unwrap_or([0; 32]);
        assert_eq!(
            candidate.transition_to(ProfileLifecycleV1::Stable, vec![first, second]),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    fn public_profile_decoder_reaches_top_level_invalid_field_seams(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value = profile();
        for index in 0..17 {
            // `previous_profile_digest` is an optional field; CBOR null is
            // valid there, so use a wrong type for that one schema path.
            let replacement = if index == 15 {
                Value::Bool(true)
            } else {
                Value::Null
            };
            let bytes = malformed_profile_bytes(&value, &[index], replacement)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..17 {
            let replacement = if index == 10 {
                Value::Bool(true)
            } else {
                Value::Null
            };
            let bytes = malformed_profile_bytes(&value, &[8, 0, index], replacement)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..4 {
            let bytes = malformed_profile_bytes(&value, &[8, 0, 7, 0, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..8 {
            let bytes = malformed_profile_bytes(&value, &[8, 0, 13, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..2 {
            let bytes = malformed_profile_bytes(&value, &[8, 0, 14, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..7 {
            let bytes = malformed_profile_bytes(&value, &[8, 0, 15, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..5 {
            let bytes = malformed_profile_bytes(&value, &[10, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..10 {
            let bytes = malformed_profile_bytes(&value, &[10, 4, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..5 {
            let bytes = malformed_profile_bytes(&value, &[11, index], Value::Null)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        for expected in [
            Value::Array(vec![
                uint(0),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ]),
            Value::Array(vec![
                uint(1),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ]),
            Value::Array(vec![
                uint(2),
                Value::Null,
                Value::Null,
                Value::Array(vec![Value::Null, Value::Null]),
                Value::Null,
            ]),
        ] {
            let bytes = malformed_profile_bytes(&value, &[8, 0, 8], expected)?;
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        }
        Ok(())
    }

    #[test]
    fn public_profile_decoder_round_trips_expected_variants() {
        let mut typed = profile();
        typed.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        typed.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        typed.profile_digest = typed.digest();
        let typed_bytes = typed.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&typed_bytes),
            Ok(typed)
        );

        let mut divergent = profile();
        let coordinate = b"timeline/7".to_vec();
        divergent.allowed_divergences = vec![AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate.clone(),
        }];
        divergent.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate,
        };
        divergent.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        divergent.profile_digest = divergent.digest();
        let divergent_bytes = divergent.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&divergent_bytes),
            Ok(divergent)
        );
    }

    #[test]
    fn public_stable_profile_decoder_round_trips_sidecar_evidence() {
        let policy = trusted_root_policy();
        let value = profile();
        let candidate_result = value.transition_to(ProfileLifecycleV1::Candidate, vec![]);
        assert!(candidate_result.is_ok());
        let candidate = candidate_result.unwrap_or_else(|_| value.clone());
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        refresh_stable_report_for_profile(&mut first, &candidate);
        refresh_stable_report_for_profile(&mut second, &candidate);
        let stable_result =
            candidate.transition_to(ProfileLifecycleV1::Stable, vec![first, second]);
        assert!(stable_result.is_ok());
        let stable = stable_result.unwrap_or_else(|_| value.clone());
        let stable_bytes_result = stable.to_canonical_cbor_with_trust_policy(&policy);
        assert!(stable_bytes_result.is_ok());
        let stable_bytes = stable_bytes_result.unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
                &stable_bytes,
                stable.stable_evidence.clone(),
                &policy,
            ),
            Ok(stable)
        );
    }

    #[test]
    fn public_request_decoder_reaches_nested_invalid_field_seams(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for index in 0..14 {
            let bytes = malformed_request_bytes(&[index], Value::Null)?;
            assert!(EvaluatorRequestV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..6 {
            let bytes = malformed_request_bytes(&[7, index], Value::Null)?;
            assert!(EvaluatorRequestV1::from_canonical_cbor(&bytes).is_err());
        }
        for index in 0..3 {
            let bytes = malformed_request_bytes(&[10, index], Value::Null)?;
            assert!(EvaluatorRequestV1::from_canonical_cbor(&bytes).is_err());
        }

        let mut invalid_caps = profile();
        invalid_caps.evaluator_protocol.hard_caps.max_cases = 0;
        invalid_caps.profile_digest = invalid_caps.digest();
        assert!(invalid_caps.validate().is_err());
        Ok(())
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
        for version in ["1.0.0.0", "1..0", "1.alpha.0"] {
            let mut invalid_version = profile();
            invalid_version.semantic_version = version.to_owned();
            assert_eq!(
                invalid_version.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }
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

        let mut draft_unavailable = profile();
        draft_unavailable.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ProvenanceMissing);
        draft_unavailable.fixtures[0].expected_verification_outcome =
            VerificationOutcomeV1::UnverifiableArtifactsMissing;
        draft_unavailable.fixtures[0].expected_verification_error =
            Some(SafeErrorCodeV1::ProvenanceMissing);
        draft_unavailable.profile_digest = draft_unavailable.digest();
        assert_eq!(draft_unavailable.validate(), Ok(()));
        assert!(draft_unavailable.fixtures[0]
            .expected
            .to_canonical_bytes()
            .is_ok());
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
        let mut typed_evidence = typed_failure_evidence("alpha", 30, typed_fixture_digest);
        let mut typed_evidence_second = typed_failure_evidence("beta", 40, typed_fixture_digest);
        refresh_stable_report_for_profile(&mut typed_evidence, &typed_candidate);
        refresh_stable_report_for_profile(&mut typed_evidence_second, &typed_candidate);
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
                case.actual_digest = Some([99; 32]);
                case.verification_outcome = VerificationOutcomeV1::Diverged;
                case.divergence_kind = Some(DivergenceMismatchKindV1::TypedFailure);
            }
            refresh_stable_report_for_profile(evidence, &divergent_candidate);
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
    fn public_profile_and_request_codecs_reject_malformed_fields() {
        let reject_profile = |value: Value| {
            let bytes = encode_value(&value).unwrap_or_default();
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_err());
        };
        let reject_request = |value: Value| {
            let bytes = encode_value(&value).unwrap_or_default();
            assert!(EvaluatorRequestV1::from_canonical_cbor(&bytes).is_err());
        };

        let profile_value = encode_profile(&profile(), true);
        if let Value::Array(fields) = &profile_value {
            for index in 0..fields.len() {
                let mut malformed = fields.clone();
                malformed[index] = Value::Map(Vec::new());
                reject_profile(Value::Array(malformed));
            }
        }
        let request_value = encode_request(&request(), true);
        if let Value::Array(fields) = &request_value {
            for index in 0..fields.len() {
                let mut malformed = fields.clone();
                malformed[index] = Value::Map(Vec::new());
                reject_request(Value::Array(malformed));
            }
        }

        let mut fixture_profile = profile();
        if matches!(
            &fixture_profile.fixtures[0].expected,
            ExpectedResultV1::CanonicalBytes { .. }
        ) {
            fixture_profile.fixtures[0].expected =
                ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
            fixture_profile.fixtures[0].expected_verification_outcome =
                VerificationOutcomeV1::InvalidManifest;
            fixture_profile.fixtures[0].expected_verification_error =
                Some(SafeErrorCodeV1::ClosureIncomplete);
            fixture_profile.profile_digest = fixture_profile.digest();
            let bytes = fixture_profile.to_canonical_cbor().unwrap_or_default();
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_ok());

            fixture_profile.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
                classification: DivergenceMismatchKindV1::TypedFailure,
                first_coordinate: b"timeline/7".to_vec(),
            };
            fixture_profile.allowed_divergences = vec![AllowedDivergenceV1 {
                classification: DivergenceMismatchKindV1::TypedFailure,
                first_coordinate: b"timeline/7".to_vec(),
            }];
            fixture_profile.fixtures[0].expected_verification_outcome =
                VerificationOutcomeV1::Diverged;
            fixture_profile.fixtures[0].expected_verification_error = None;
            fixture_profile.profile_digest = fixture_profile.digest();
            let bytes = fixture_profile.to_canonical_cbor().unwrap_or_default();
            assert!(ConformanceProfileV1::from_canonical_cbor(&bytes).is_ok());
        }

        let mut malformed = encode_profile(&profile(), true);
        if let Value::Array(fields) = &mut malformed {
            if let Value::Array(fixtures) = &mut fields[8] {
                if let Value::Array(fixture) = &mut fixtures[0] {
                    fixture[8] = Value::Array(vec![
                        Value::Integer(99_u64.into()),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                    ]);
                }
            }
        }
        reject_profile(malformed);

        let canonical = profile().to_canonical_cbor().unwrap_or_default();
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(ConformanceProfileV1::from_canonical_cbor(&trailing).is_err());
        let mut noncanonical = canonical;
        if let Some(index) = noncanonical.iter().position(|byte| *byte == 1) {
            noncanonical.splice(index..=index, [0x18, 1]);
        }
        assert!(ConformanceProfileV1::from_canonical_cbor(&noncanonical).is_err());
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
        let stable_bytes = stable
            .to_canonical_cbor_with_trust_policy(&trusted_root_policy())
            .unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor_with_stable_evidence(
                &stable_bytes,
                stable.stable_evidence.clone(),
                &trusted_root_policy(),
            ),
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
        let mut multi_mode = profile();
        multi_mode.fixtures[0].modes = vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped];
        multi_mode.profile_digest = multi_mode.digest();
        assert_eq!(multi_mode.validate(), Ok(()));
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

        let mut exact_report_cap = request();
        exact_report_cap.output_capability.report_bytes_limit = MAX_PROFILE_BYTES as u64;
        exact_report_cap.request_digest = exact_report_cap.digest();
        assert!(exact_report_cap.validate().is_ok());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn request_profile_output_caps_are_independently_enforced() {
        let mut capped_profile = profile();
        capped_profile
            .evaluator_protocol
            .hard_caps
            .max_profile_bytes = MAX_PROFILE_BYTES as u64 - 1;
        capped_profile
            .evaluator_protocol
            .hard_caps
            .max_diagnostic_bytes = MAX_DIAGNOSTIC_BYTES - 1;
        capped_profile.profile_digest = capped_profile.digest();
        let mut over_cap = request();
        over_cap.conformance_profile_digest = capped_profile.profile_digest;
        over_cap.fixture_bundle_digest = fixture_bundle_digest(&capped_profile);
        over_cap.evaluator_hard_caps_digest = capped_profile.evaluator_protocol.hard_caps.digest();
        over_cap.output_capability.report_bytes_limit = MAX_PROFILE_BYTES as u64;
        over_cap.output_capability.diagnostic_bytes_limit = MAX_DIAGNOSTIC_BYTES;
        over_cap.output_capability.capability_digest = over_cap.expected_output_capability_digest();
        over_cap.request_digest = over_cap.digest();
        assert_eq!(
            over_cap.validate_against_profile(&capped_profile),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        over_cap.output_capability.report_bytes_limit = capped_profile
            .evaluator_protocol
            .hard_caps
            .max_profile_bytes;
        over_cap.output_capability.capability_digest = over_cap.expected_output_capability_digest();
        over_cap.request_digest = over_cap.digest();
        assert_eq!(
            over_cap.validate_against_profile(&capped_profile),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        over_cap.output_capability.report_bytes_limit = capped_profile
            .evaluator_protocol
            .hard_caps
            .max_profile_bytes;
        over_cap.output_capability.diagnostic_bytes_limit = capped_profile
            .evaluator_protocol
            .hard_caps
            .max_diagnostic_bytes
            + 1;
        over_cap.output_capability.capability_digest = over_cap.expected_output_capability_digest();
        over_cap.request_digest = over_cap.digest();
        assert_eq!(
            over_cap.validate_against_profile(&capped_profile),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        over_cap.output_capability.diagnostic_bytes_limit = capped_profile
            .evaluator_protocol
            .hard_caps
            .max_diagnostic_bytes;
        over_cap.output_capability.capability_digest = over_cap.expected_output_capability_digest();
        over_cap.request_digest = over_cap.digest();
        assert_eq!(over_cap.validate_against_profile(&capped_profile), Ok(()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_request_authorities_are_revalidated_after_each_identity_change() {
        let reject = |change: fn(&mut EvaluatorRequestV1)| {
            let mut value = request();
            change(&mut value);
            value.output_capability.capability_digest = value.expected_output_capability_digest();
            value.request_digest = value.digest();
            assert!(value.validate().is_err());
        };
        reject(|value| value.conformance_profile_digest = [0; 32]);
        reject(|value| value.fixture_bundle_digest = [0; 32]);
        reject(|value| value.subject_artifact_digest = [0; 32]);
        reject(|value| value.execution_profile_digest = [0; 32]);
        reject(|value| value.trust_policy_snapshot_digest = [0; 32]);
        reject(|value| value.evaluator_protocol_digest = [0; 32]);
        reject(|value| value.evaluator_hard_caps_digest = [0; 32]);
        reject(|value| value.output_capability.report_bytes_limit = 0);
        reject(|value| value.output_capability.diagnostic_bytes_limit = MAX_DIAGNOSTIC_BYTES + 1);
        let mut invalid_capability = request();
        invalid_capability.output_capability.capability_digest = [0; 32];
        invalid_capability.request_digest = invalid_capability.digest();
        assert_eq!(
            invalid_capability.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let value = request();
        assert_ne!(value.expected_output_capability_digest(), [1; 32]);
        assert_eq!(value.validate_against_profile(&profile()), Ok(()));

        let reject_against_profile = |change: fn(&mut EvaluatorRequestV1)| {
            let mut value = request();
            change(&mut value);
            value.output_capability.capability_digest = value.expected_output_capability_digest();
            value.request_digest = value.digest();
            assert!(value.validate_against_profile(&profile()).is_err());
        };
        reject_against_profile(|value| value.conformance_profile_digest = [99; 32]);
        reject_against_profile(|value| value.fixture_bundle_digest = [99; 32]);
        reject_against_profile(|value| value.trust_policy_snapshot_digest = [99; 32]);
        reject_against_profile(|value| value.evaluator_protocol_digest = [99; 32]);
        reject_against_profile(|value| value.evaluator_hard_caps_digest = [99; 32]);
        reject_against_profile(|value| {
            value.subject_adapter = SubjectAdapterKindV1::PublicGatewayProtocol;
        });

        let mut invalid_profile = profile();
        invalid_profile.normative_spec_digest = [0; 32];
        invalid_profile.profile_digest = invalid_profile.digest();
        assert_eq!(
            request().validate_against_profile_with_trust_policy(
                &invalid_profile,
                &trusted_root_policy(),
            ),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let protocol = profile().evaluator_protocol;
        let mut exact = request();
        exact.output_capability.report_bytes_limit = protocol.hard_caps.max_profile_bytes;
        exact.output_capability.diagnostic_bytes_limit = protocol.hard_caps.max_diagnostic_bytes;
        exact.output_capability.capability_digest = exact.expected_output_capability_digest();
        exact.request_digest = exact.digest();
        assert_eq!(exact.validate_with_protocol(&protocol), Ok(()));
        assert_eq!(request().validate_with_protocol(&protocol), Ok(()));

        request_profile_output_caps_are_independently_enforced();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_digest_commits_attached_stable_evidence() {
        let stable = stable_profile();
        let mut changed = stable.clone();
        changed.stable_evidence[0].implementation.implementation_id =
            "changed-independent-impl".to_owned();
        assert_ne!(stable.digest(), changed.digest());
        changed.profile_digest = stable.profile_digest;
        assert!(changed
            .to_canonical_cbor_with_trust_policy(&trusted_root_policy())
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_and_encoding_boundaries_are_inclusive() {
        let caps = original_hard_caps();
        assert_eq!(caps.validate_compression_expansion(7, 700), Ok(()));
        assert_eq!(
            caps.validate_compression_expansion(7, 701),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut at_profile_limit = profile();
        for _ in 0..8 {
            let encoded_len = encode_value(&encode_profile(&at_profile_limit, true))
                .unwrap_or_default()
                .len();
            at_profile_limit
                .evaluator_protocol
                .hard_caps
                .max_profile_bytes = u64::try_from(encoded_len).unwrap_or(u64::MAX);
            at_profile_limit.profile_digest = at_profile_limit.digest();
        }
        let encoded_len = encode_value(&encode_profile(&at_profile_limit, true))
            .unwrap_or_default()
            .len();
        at_profile_limit
            .evaluator_protocol
            .hard_caps
            .max_profile_bytes = u64::try_from(encoded_len).unwrap_or(u64::MAX);
        at_profile_limit.profile_digest = at_profile_limit.digest();
        assert!(at_profile_limit.validate().is_ok());

        let mut below = at_profile_limit;
        below.evaluator_protocol.hard_caps.max_profile_bytes = below
            .evaluator_protocol
            .hard_caps
            .max_profile_bytes
            .saturating_sub(1);
        below.profile_digest = below.digest();
        assert_eq!(
            below.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let exact_bytes = Value::Bytes(vec![0; MAX_PROFILE_BYTES - 5]);
        assert_eq!(
            encode_bounded(&exact_bytes).map(|bytes| bytes.len()),
            Ok(MAX_PROFILE_BYTES)
        );
        let over_bytes = Value::Bytes(vec![0; MAX_PROFILE_BYTES - 4]);
        assert_eq!(
            encode_bounded(&over_bytes),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_incompatible_claim_is_orthogonal_to_redaction() {
        for redaction_state in [
            RedactionStateV1::RedactedViews,
            RedactionStateV1::StructuralOnly,
            RedactionStateV1::EvidenceMissing,
        ] {
            let mut value = profile();
            value.fixtures[0].replay_claim = ReplayClaimV1::IncompatibleProfile;
            value.fixtures[0].redaction_state = redaction_state;
            value.profile_digest = value.digest();
            assert_eq!(value.validate(), Ok(()));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_preconditions_and_policy_membership_fail_closed() {
        let profile_value = candidate();
        let mut first = stable_evidence("alpha", 30);
        let mut second = stable_evidence("beta", 40);
        refresh_stable_report_for_profile(&mut first, &profile_value);
        refresh_stable_report_for_profile(&mut second, &profile_value);

        let mut same_source = first.clone();
        same_source.implementation.source_digest = second.implementation.source_digest;
        refresh_stable_report_for_profile(&mut same_source, &profile_value);
        let mut same_source_profile = profile_value.clone();
        same_source_profile.stable_evidence = vec![same_source, second.clone()];
        assert_eq!(
            validate_stable_evidence(&same_source_profile, Some(&trusted_root_policy())),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut wrong_subject = first.clone();
        wrong_subject.report.subject_artifact_digest = [99; 32];
        wrong_subject.report.report_digest = wrong_subject.report.digest().unwrap_or([0; 32]);
        refresh_stable_attestation(&mut wrong_subject);
        let mut pair_profile = profile_value.clone();
        pair_profile.stable_evidence = vec![wrong_subject.clone(), second.clone()];
        assert_eq!(
            validate_stable_evidence(&pair_profile, Some(&trusted_root_policy())),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let reject_pair = |change: &dyn Fn(&mut StableImplementationEvidenceV1)| {
            let mut changed_first = first.clone();
            let changed_second = second.clone();
            change(&mut changed_first);
            let mut changed_profile = profile_value.clone();
            changed_profile.stable_evidence = vec![changed_first, changed_second];
            assert_eq!(
                validate_stable_evidence(&changed_profile, Some(&trusted_root_policy()),),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        };
        reject_pair(&|value| {
            value.implementation.public_contract_digest = digest(55);
            refresh_stable_report(value);
        });
        reject_pair(&|value| value.evaluator_protocol_digest = digest(99));
        reject_pair(&|value| value.report.report_digest = [0; 32]);

        let mut same_report = first.clone();
        same_report.report.report_digest = second.report.report_digest;
        let mut same_report_profile = profile_value.clone();
        same_report_profile.stable_evidence = vec![same_report, second.clone()];
        assert_eq!(
            validate_stable_evidence(&same_report_profile, Some(&trusted_root_policy()),),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut wrong_key_policy = trusted_root_policy();
        wrong_key_policy.trusted_root_public_keys =
            vec![ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes()];
        wrong_key_policy.trust_policy_snapshot_digest = profile_value
            .independence_requirements
            .trust_policy_snapshot_digest;
        assert_eq!(
            validate_stable_attestation(
                &first,
                &profile_value.independence_requirements,
                Some(&wrong_key_policy),
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        assert_ne!(trusted_root_policy().digest(), [1; 32]);
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
    fn public_contract_boundary_values_cover_mutation_seams() {
        let protocol = profile().evaluator_protocol;
        let request = request();
        assert_eq!(request.validate_with_protocol(&protocol), Ok(()));
        assert_eq!(request.validate_with_hard_caps(&protocol.hard_caps), Ok(()));

        let mut too_many_profiles = profile();
        too_many_profiles.execution_profile_digests = (1_u8..=65).map(digest).collect();
        too_many_profiles.profile_digest = too_many_profiles.digest();
        assert_eq!(
            too_many_profiles.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut exact_depth = profile();
        let depth = value_depth(&encode_profile(&exact_depth, true));
        exact_depth
            .evaluator_protocol
            .hard_caps
            .max_structural_nesting = u8::try_from(depth).unwrap_or(u8::MAX);
        exact_depth.profile_digest = exact_depth.digest();
        assert_eq!(exact_depth.validate(), Ok(()));

        let mut exact_member_path = profile();
        exact_member_path
            .evaluator_protocol
            .hard_caps
            .max_member_path_bytes = 255;
        exact_member_path.fixtures[0].inputs[0].member_id = "x".repeat(256);
        exact_member_path.profile_digest = exact_member_path.digest();
        assert_eq!(
            exact_member_path.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut exact_diagnostic = request;
        exact_diagnostic.output_capability.diagnostic_bytes_limit = MAX_DIAGNOSTIC_BYTES;
        exact_diagnostic.output_capability.capability_digest =
            exact_diagnostic.expected_output_capability_digest();
        exact_diagnostic.request_digest = exact_diagnostic.digest();
        assert_eq!(exact_diagnostic.validate_with_protocol(&protocol), Ok(()));

        let mut oversized_policy = trusted_root_policy();
        oversized_policy.trusted_root_public_keys = (1_u8..=65).map(digest).collect();
        oversized_policy.trust_policy_snapshot_digest = oversized_policy.digest();
        assert_eq!(
            oversized_policy.validate(),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        assert!(semantic_version("1.2.3+build.7"));
        assert!(!semantic_version("1.2.3+bad!"));
    }

    #[test]
    fn fixture_redaction_state_cannot_overclaim_replay_strength() {
        reject_profile_change(
            |value| value.fixtures[0].redaction_state = RedactionStateV1::RedactedViews,
            ConformanceContractError::ClaimRedactionMismatch,
        );
        reject_profile_change(
            |value| value.fixtures[0].redaction_state = RedactionStateV1::StructuralOnly,
            ConformanceContractError::ClaimRedactionMismatch,
        );
        reject_profile_change(
            |value| value.fixtures[0].redaction_state = RedactionStateV1::EvidenceMissing,
            ConformanceContractError::ClaimRedactionMismatch,
        );

        let mut coherent = profile();
        coherent.fixtures[0].replay_claim = ReplayClaimV1::StructuralOnly;
        coherent.fixtures[0].redaction_state = RedactionStateV1::StructuralOnly;
        coherent.profile_digest = coherent.digest();
        assert_eq!(coherent.validate(), Ok(()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn case_matching_checks_each_authoritative_field() {
        let fixture = &profile().fixtures[0];
        let base = case_outcome_record(ExecutionModeV1::Local);
        assert!(case_matches_fixture(&base, fixture));

        let mut pending_fixture = fixture.clone();
        pending_fixture.expected_verification_outcome =
            VerificationOutcomeV1::UnverifiableArtifactsMissing;
        pending_fixture.expected_verification_error = Some(SafeErrorCodeV1::ProvenanceMissing);
        pending_fixture.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing;
        pending_fixture.redaction_state = RedactionStateV1::EvidenceMissing;
        let mut pending = base.clone();
        pending.fixture_digest = fixture_digest(&pending_fixture);
        pending.expected_error = Some(SafeErrorCodeV1::ProvenanceMissing);
        pending.actual_error = Some(SafeErrorCodeV1::ProvenanceMissing);
        pending.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing;
        pending.redaction_state = RedactionStateV1::EvidenceMissing;
        pending.verification_outcome = VerificationOutcomeV1::UnverifiableArtifactsMissing;
        pending.expected_digest = None;
        pending.actual_digest = None;
        assert!(case_matches_fixture(&pending, &pending_fixture));

        let mut changed = base.clone();
        changed.case_id.push('x');
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.fixture_digest = digest(99);
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.claim_layer = ClaimLayerV1::MetricConformance;
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.execution_profile_digest = digest(99);
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.outcome = CaseOutcomeStatusV1::Fail;
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.replay_claim = ReplayClaimV1::StructuralOnly;
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.redaction_state = RedactionStateV1::StructuralOnly;
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.provenance_digest = digest(99);
        assert!(!case_matches_fixture(&changed, fixture));

        let mut changed = base.clone();
        changed.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        assert!(!case_matches_fixture(&changed, fixture));

        let mut changed = base.clone();
        changed.verification_outcome = VerificationOutcomeV1::Diverged;
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base.clone();
        changed.expected_digest = Some(digest(99));
        assert!(!case_matches_fixture(&changed, fixture));
        let mut changed = base;
        changed.actual_digest = Some(digest(99));
        assert!(!case_matches_fixture(&changed, fixture));

        let coordinate = b"timeline/7".to_vec();
        let mut divergent_fixture = fixture.clone();
        divergent_fixture.expected = ExpectedResultV1::AllowedDivergence {
            classification: DivergenceMismatchKindV1::TypedFailure,
            first_coordinate: coordinate.clone(),
        };
        divergent_fixture.expected_verification_outcome = VerificationOutcomeV1::Diverged;
        let mut divergent = case_outcome_record(ExecutionModeV1::Local);
        divergent.fixture_digest = fixture_digest(&divergent_fixture);
        divergent.expected_digest = Some(digest(20));
        divergent.actual_digest = Some(digest(21));
        divergent.verification_outcome = VerificationOutcomeV1::Diverged;
        divergent.divergence_kind = Some(DivergenceMismatchKindV1::TypedFailure);
        divergent.first_coordinate = Some(coordinate);
        assert!(case_matches_fixture(&divergent, &divergent_fixture));
        let mut changed = divergent.clone();
        changed.divergence_kind = Some(DivergenceMismatchKindV1::CanonicalBytes);
        assert!(!case_matches_fixture(&changed, &divergent_fixture));
        let mut changed = divergent;
        changed.first_coordinate = Some(b"timeline/8".to_vec());
        assert!(!case_matches_fixture(&changed, &divergent_fixture));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn independence_evidence_rejects_each_mismatch() {
        let requirements = profile().independence_requirements;
        let evidence = stable_evidence("alpha", 30);
        assert_eq!(
            validate_independence_evidence(&evidence.independence, &requirements),
            Ok(())
        );

        let mut invalid = evidence.independence.clone();
        invalid.technical_independent = false;
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid = evidence.independence.clone();
        invalid.authorship_independent = false;
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut organization_required = requirements.clone();
        organization_required.organizational_independence_required = true;
        let mut invalid = evidence.independence.clone();
        invalid.organizational_independent = false;
        assert_eq!(
            validate_independence_evidence(&invalid, &organization_required),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid = evidence.independence.clone();
        invalid.reviewer_ids.clear();
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid = evidence.independence.clone();
        invalid.reviewer_ids = (0..33)
            .map(|index| format!("reviewer-{index:02}"))
            .collect();
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid = evidence.independence.clone();
        invalid.reviewer_ids = vec!["zulu".to_owned(), "alpha".to_owned()];
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid = evidence.independence.clone();
        invalid.reviewer_ids = vec!["x".repeat(129)];
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut invalid = evidence.independence.clone();
        invalid.declaration_digest = [0; 32];
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        invalid.declaration_digest = evidence.independence.declaration_digest;
        invalid.shared_code_audit_digest = [0; 32];
        assert_eq!(
            validate_independence_evidence(&invalid, &requirements),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_report_binding_rejects_each_mismatch() {
        let mut evidence = stable_evidence("alpha", 30);
        let profile_value = candidate();
        refresh_stable_report_for_profile(&mut evidence, &profile_value);
        assert_eq!(validate_report_binding(&evidence, &profile_value), Ok(()));
        assert_ne!(evidence.report.fixture_bundle_digest, digest(1));
        let reject_report = |change: &dyn Fn(&mut StableImplementationEvidenceV1)| {
            let mut changed = stable_evidence("alpha", 30);
            change(&mut changed);
            refresh_report_counts(&mut changed.report);
            changed.report.report_digest = changed.report.digest().unwrap_or([0; 32]);
            assert_eq!(
                validate_report_binding(&changed, &profile_value),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        };
        reject_report(&|value| value.report.normative_spec_digest = digest(99));
        reject_report(&|value| value.report.implementation.source_digest = digest(99));
        reject_report(&|value| value.report.independence.declaration_digest = digest(99));
        reject_report(&|value| value.report.evaluator_protocol_digest = digest(99));
        reject_report(&|value| value.evaluator_protocol_digest = digest(99));
        reject_report(&|value| value.report.limitations_digest = digest(99));
        reject_report(&|value| value.report.provenance_digest = digest(99));
        reject_report(&|value| value.report.fixture_bundle_digest = digest(99));
        reject_report(&|value| value.report.profile_digest = digest(99));
        reject_report(&|value| value.report.execution_profile_digest = digest(99));
        reject_report(&|value| {
            value.report.cases.pop();
        });
        reject_report(&|value| value.report.cases[0].case_id.push('x'));
        reject_report(&|value| value.report.cases[0].fixture_digest = digest(99));
        reject_report(&|value| value.report.cases[0].execution_profile_digest = digest(99));
        reject_report(&|value| value.report.cases[0].claim_layer = ClaimLayerV1::MetricConformance);
        reject_report(&|value| value.report.cases[0].mode = ExecutionModeV1::Fork);
        reject_report(&|value| value.report.cases[0].replay_claim = ReplayClaimV1::StructuralOnly);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_case_binding_rejects_each_mismatch() {
        let profile_value = candidate();
        let mut evidence = stable_evidence("alpha", 30);
        refresh_stable_report_for_profile(&mut evidence, &profile_value);
        let reject_case = |change: &dyn Fn(&mut CaseOutcomeV1)| {
            let mut changed = evidence.clone();
            change(&mut changed.case_outcomes[0]);
            assert_eq!(
                validate_report_binding(&changed, &profile_value),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        };
        reject_case(&|case| case.case_id.push('x'));
        reject_case(&|case| case.fixture_digest = digest(99));
        reject_case(&|case| case.execution_profile_digest = digest(99));
        reject_case(&|case| case.mode = ExecutionModeV1::Fork);
        reject_case(&|case| case.claim_layer = ClaimLayerV1::MetricConformance);
        reject_case(&|case| case.outcome = CaseOutcomeStatusV1::Fail);
        reject_case(&|case| case.expected_digest = Some(digest(99)));
        reject_case(&|case| case.actual_digest = Some(digest(99)));
        reject_case(&|case| case.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete));
        reject_case(&|case| case.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete));
        reject_case(&|case| case.replay_claim = ReplayClaimV1::StructuralOnly);
        reject_case(&|case| case.redaction_state = RedactionStateV1::StructuralOnly);
        reject_case(&|case| case.provenance_digest = digest(99));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_identity_binding_rejects_each_independent_change() {
        let changes: [fn(&mut StableImplementationEvidenceV1, &mut StableImplementationEvidenceV1);
            5] = [
            |first, second| {
                first.implementation.source_digest = second.implementation.source_digest;
            },
            |first, second| first.implementation.build_digest = second.implementation.build_digest,
            |first, second| {
                first.implementation.binary_digest = second.implementation.binary_digest;
            },
            |first, _second| first.implementation.public_contract_digest = digest(55),
            |first, _second| first.evaluator_protocol_digest = digest(99),
        ];
        let profile_value = candidate();
        for change in changes {
            let mut first = stable_evidence("alpha", 30);
            let mut second = stable_evidence("beta", 40);
            change(&mut first, &mut second);
            refresh_stable_report_for_profile(&mut first, &profile_value);
            refresh_stable_report_for_profile(&mut second, &profile_value);
            let mut changed_profile = profile_value.clone();
            changed_profile.stable_evidence = vec![first, second];
            assert_eq!(
                validate_stable_evidence(&changed_profile, Some(&trusted_root_policy())),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        }

        for zero_first in [true, false] {
            let mut first = stable_evidence("alpha", 30);
            let second = stable_evidence("beta", 40);
            first.report.report_digest = if zero_first { [0; 32] } else { digest(40) };
            let mut changed_profile = profile_value.clone();
            changed_profile.stable_evidence = if zero_first {
                vec![first, second]
            } else {
                let mut changed_second = second;
                changed_second.report.report_digest = [0; 32];
                vec![first, changed_second]
            };
            assert_eq!(
                changed_profile.transition_to_with_trust_policy(
                    ProfileLifecycleV1::Stable,
                    changed_profile.stable_evidence.clone(),
                    &trusted_root_policy(),
                ),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        }

        let mut invalid_identity = stable_evidence("alpha", 30);
        invalid_identity.implementation.source_digest = [0; 32];
        let mut invalid_profile = profile_value;
        invalid_profile.stable_evidence = vec![invalid_identity, stable_evidence("beta", 40)];
        assert_eq!(
            invalid_profile.transition_to_with_trust_policy(
                ProfileLifecycleV1::Stable,
                invalid_profile.stable_evidence.clone(),
                &trusted_root_policy(),
            ),
            Err(ConformanceContractError::ProvenanceMissing)
        );

        let mut invalid_second_identity = stable_evidence("beta", 40);
        invalid_second_identity.implementation.build_digest = [0; 32];
        let mut invalid_second_profile = candidate();
        invalid_second_profile.stable_evidence =
            vec![stable_evidence("alpha", 30), invalid_second_identity];
        assert_eq!(
            invalid_second_profile.transition_to_with_trust_policy(
                ProfileLifecycleV1::Stable,
                invalid_second_profile.stable_evidence.clone(),
                &trusted_root_policy(),
            ),
            Err(ConformanceContractError::ProvenanceMissing)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_implementation_coordinate_cap_is_enforced() {
        let mut constrained = candidate();
        constrained.fixtures[0]
            .modes
            .extend([ExecutionModeV1::Replay, ExecutionModeV1::Fork]);
        constrained
            .evaluator_protocol
            .hard_caps
            .max_coordinate_bytes = 127;
        constrained.profile_digest = constrained.digest();
        let mut evidence = stable_evidence("alpha", 30);
        for case in &mut evidence.case_outcomes {
            case.first_coordinate = Some(vec![b'x'; 128]);
        }
        refresh_stable_attestation(&mut evidence);
        assert_eq!(
            validate_stable_implementation(&evidence, &constrained, None),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut at_limit = stable_evidence("alpha", 30);
        for case in &mut at_limit.case_outcomes {
            case.first_coordinate = Some(vec![b'x'; 127]);
            case.fixture_digest = fixture_digest(&constrained.fixtures[0]);
        }
        refresh_stable_report_for_profile(&mut at_limit, &constrained);
        let mut second = stable_evidence("beta", 40);
        for case in &mut second.case_outcomes {
            case.fixture_digest = fixture_digest(&constrained.fixtures[0]);
        }
        refresh_stable_report_for_profile(&mut second, &constrained);
        assert_eq!(
            validate_stable_implementation(&at_limit, &constrained, None),
            Ok(())
        );

        constrained.evaluator_protocol.hard_caps.max_cases = 0;
        assert_eq!(
            constrained.transition_to(ProfileLifecycleV1::Stable, vec![at_limit, second]),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_attestation_zero_fields_are_rejected() {
        let requirements = profile().independence_requirements;
        for change in [
            0_u8, // signer
            1,    // signature
            2,    // trust-root digest
        ] {
            let mut evidence = stable_evidence("alpha", 30);
            match change {
                0 => evidence.attestation.signer_public_key = [0; 32],
                1 => evidence.attestation.signature = [0; 64],
                _ => evidence.attestation.trust_root_digest = [0; 32],
            }
            assert_eq!(
                validate_stable_attestation(&evidence, &requirements, None),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
            assert_eq!(
                candidate().transition_to(
                    ProfileLifecycleV1::Stable,
                    vec![evidence, stable_evidence("beta", 40)],
                ),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        }

        let valid = stable_evidence("alpha", 30).attestation;
        let mut zero_signer = valid.clone();
        zero_signer.signer_public_key = [0; 32];
        zero_signer.trust_root_digest = digest_bytes(
            b"PiglorOS.ConformanceTrustRoot.v1",
            &Value::Bytes(vec![0; 32]),
        );
        assert_eq!(
            validate_stable_attestation_fields(&zero_signer, &requirements, None),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut zero_signature = valid.clone();
        zero_signature.signature = [0; 64];
        assert_eq!(
            validate_stable_attestation_fields(&zero_signature, &requirements, None),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut zero_root = valid.clone();
        zero_root.trust_root_digest = [0; 32];
        assert_eq!(
            validate_stable_attestation_fields(&zero_root, &requirements, None),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut wrong_nonzero_root = valid;
        wrong_nonzero_root.trust_root_digest = digest(99);
        assert_eq!(
            validate_stable_attestation_fields(&wrong_nonzero_root, &requirements, None),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut invalid_key_evidence = stable_evidence("alpha", 30);
        invalid_key_evidence.attestation.signer_public_key = [0xff; 32];
        invalid_key_evidence.attestation.trust_root_digest = digest_bytes(
            b"PiglorOS.ConformanceTrustRoot.v1",
            &Value::Bytes(vec![0xff; 32]),
        );
        assert_eq!(
            validate_stable_attestation(&invalid_key_evidence, &requirements, None),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![invalid_key_evidence, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stable_report_fixture_membership_rejects_each_identity_change() {
        let profile_value = candidate();
        let mut evidence = stable_evidence("alpha", 30);
        refresh_stable_report_for_profile(&mut evidence, &profile_value);
        let reject = |change: &dyn Fn(&mut ProfileCaseOutcomeV1, &mut crate::CaseOutcomeV1)| {
            let mut changed = evidence.clone();
            change(&mut changed.case_outcomes[0], &mut changed.report.cases[0]);
            changed.report.report_digest = changed.report.digest().unwrap_or([0; 32]);
            assert_eq!(
                validate_report_binding(&changed, &profile_value),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        };
        reject(&|profile_case, report_case| {
            profile_case.case_id = "unknown-case".to_owned();
            report_case.case_id = "unknown-case".to_owned();
        });
        reject(&|profile_case, report_case| {
            profile_case.claim_layer = ClaimLayerV1::MetricConformance;
            report_case.claim_layer = ClaimLayerV1::MetricConformance;
        });
        reject(&|profile_case, report_case| {
            profile_case.fixture_digest = digest(99);
            report_case.fixture_digest = digest(99);
        });
        reject(&|profile_case, report_case| {
            profile_case.execution_profile_digest = digest(99);
            report_case.execution_profile_digest = digest(99);
        });
        reject(&|profile_case, report_case| {
            profile_case.mode = ExecutionModeV1::Replay;
            report_case.mode = ExecutionModeV1::Replay;
        });
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn independence_and_stable_report_bindings_reject_each_mismatch() {
        independence_evidence_rejects_each_mismatch();
        stable_report_binding_rejects_each_mismatch();
        stable_case_binding_rejects_each_mismatch();
        stable_identity_binding_rejects_each_independent_change();
        stable_implementation_coordinate_cap_is_enforced();
        stable_attestation_zero_fields_are_rejected();
        stable_report_fixture_membership_rejects_each_identity_change();
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
        reject(&|caps| caps.max_profile_bytes = 1);
        accept(&|caps| caps.max_cases = 1);
        accept(&|caps| caps.max_bundle_members = 1);
        accept(&|caps| caps.max_member_bytes = 1);
        accept(&|caps| caps.max_total_bundle_bytes = 1);
        accept(&|caps| caps.max_compression_expansion = 1);
        reject(&|caps| caps.max_cases = 65_537);
        reject(&|caps| {
            caps.max_bundle_members = 65_537;
        });
        reject(&|caps| {
            caps.max_member_path_bytes = 257;
        });
        reject(&|caps| caps.max_member_bytes = MAX_MEMBER_BYTES + 1);
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
        reject(&|caps| caps.max_member_path_bytes = 1);
        reject(&|caps| caps.max_structural_nesting = 1);
        accept(&|caps| caps.max_coordinate_bytes = 1);
        accept(&|caps| caps.max_diagnostic_bytes = 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_selected_caps_authoritatively_bound_each_resource() {
        assert_selected_caps_bound_inventory_and_members();
        assert_selected_caps_bound_compression_and_requests();
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_selected_caps_bound_inventory_and_members() {
        let mut too_many_members = profile();
        too_many_members
            .evaluator_protocol
            .hard_caps
            .max_bundle_members = 1;
        too_many_members.fixtures[0]
            .inputs
            .push(FixtureInputMemberV1 {
                member_id: "z".to_owned(),
                size_bytes: 1,
                digest: digest(50),
                provenance_digest: digest(51),
            });
        too_many_members.profile_digest = too_many_members.digest();
        assert_eq!(
            too_many_members.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        for field in ["path", "member", "total"] {
            let mut value = profile();
            if field == "path" {
                value.evaluator_protocol.hard_caps.max_member_path_bytes = 1;
            } else if field == "member" {
                value.evaluator_protocol.hard_caps.max_member_bytes = 11;
            } else {
                value.evaluator_protocol.hard_caps.max_total_bundle_bytes = 11;
            }
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }

        let mut divergence = profile();
        let declared = AllowedDivergenceV1 {
            classification: DivergenceMismatchKindV1::EventOrder,
            first_coordinate: b"xy".to_vec(),
        };
        divergence.allowed_divergences = vec![declared.clone()];
        divergence.fixtures[0].expected = ExpectedResultV1::AllowedDivergence {
            classification: declared.classification,
            first_coordinate: declared.first_coordinate,
        };
        divergence.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::Diverged;
        divergence.evaluator_protocol.hard_caps.max_coordinate_bytes = 1;
        divergence.profile_digest = divergence.digest();
        assert_eq!(
            divergence.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut limited = profile();
        limited.evaluator_protocol.hard_caps.max_cases = 0;
        limited.profile_digest = limited.digest();
        assert_eq!(
            limited.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_selected_caps_bound_compression_and_requests() {
        let caps = original_hard_caps();
        assert_eq!(caps.validate_compression_expansion(1, 1), Ok(()));
        assert_eq!(
            caps.validate_compression_expansion(1, 101),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            caps.validate_compression_expansion(1, 0),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            caps.validate_compression_expansion(u64::MAX, 1),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        assert_eq!(
            caps.validate_compression_expansion(0, 0),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut request = request();
        let mut request_caps = original_hard_caps();
        request.output_capability.report_bytes_limit = 2;
        request.request_digest = request.digest();
        request_caps.max_profile_bytes = 1;
        assert_eq!(
            request.validate_with_hard_caps(&request_caps),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        request_caps = original_hard_caps();
        assert_eq!(request.validate_with_hard_caps(&request_caps), Ok(()));

        let mut expected_bytes = profile();
        expected_bytes.fixtures[0].inputs[0].size_bytes = 1;
        expected_bytes.evaluator_protocol.hard_caps.max_member_bytes = 1;
        expected_bytes.profile_digest = expected_bytes.digest();
        assert_eq!(
            expected_bytes.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
        request.output_capability.report_bytes_limit = 1;
        request.output_capability.diagnostic_bytes_limit = 2;
        request.request_digest = request.digest();
        request_caps.max_profile_bytes = MAX_PROFILE_BYTES as u64;
        request_caps.max_diagnostic_bytes = 1;
        assert_eq!(
            request.validate_with_hard_caps(&request_caps),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_case_coordinates_obey_selected_cap() {
        let mut limited = profile();
        limited.evaluator_protocol.hard_caps.max_coordinate_bytes = 1;
        let candidate = limited
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let mut first = stable_evidence("alpha", 30);
        first.case_outcomes[0].first_coordinate = Some(vec![b'x'; 2]);
        refresh_stable_report(&mut first);
        assert_eq!(
            candidate.transition_to(
                ProfileLifecycleV1::Stable,
                vec![first, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::FieldOutOfBounds)
        );
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

        let mut same_build = stable_evidence("alpha", 30);
        let independent_build = stable_evidence("beta", 40);
        same_build.implementation.build_digest = independent_build.implementation.build_digest;
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![same_build, independent_build],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut same_binary = stable_evidence("alpha", 30);
        let independent_binary = stable_evidence("beta", 40);
        same_binary.implementation.binary_digest = independent_binary.implementation.binary_digest;
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![same_binary, independent_binary],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut different_contract = stable_evidence("alpha", 30);
        different_contract.implementation.public_contract_digest = digest(55);
        refresh_stable_report(&mut different_contract);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![different_contract, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_case_matching_rejects_each_authoritative_field_mismatch() {
        assert!(candidate()
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![stable_evidence("alpha", 30), stable_evidence("beta", 40)],
            )
            .is_ok());
        reject_stable_change(|value| value.case_outcomes[0].fixture_digest = [0; 32]);
        reject_stable_change(|value| value.case_outcomes[0].fixture_digest = digest(99));
        reject_stable_change(|value| value.case_outcomes[0].case_id = "wrong".to_owned());
        reject_stable_change(|value| {
            value.case_outcomes[0].claim_layer = ClaimLayerV1::ReplayConformance;
        });
        reject_stable_change(|value| value.case_outcomes[0].execution_profile_digest = digest(99));
        reject_stable_change(|value| value.case_outcomes[0].outcome = CaseOutcomeStatusV1::Fail);
        reject_stable_change(|value| value.case_outcomes[0].expected_digest = Some(digest(99)));
        reject_stable_change(|value| value.case_outcomes[0].actual_digest = Some(digest(99)));
        reject_stable_change(|value| value.case_outcomes.clear());
        reject_stable_change(|value| {
            value.case_outcomes[0].replay_claim = ReplayClaimV1::StructuralOnly;
        });
        reject_stable_change(|value| {
            value.case_outcomes[0].redaction_state = RedactionStateV1::RedactedViews;
        });
        reject_stable_change(|value| value.case_outcomes[0].provenance_digest = digest(99));
        reject_stable_change(|value| value.report.report_digest = [0; 32]);
        reject_stable_change(|value| value.report.report_digest = digest(99));

        let mut mismatched_report = stable_evidence("alpha", 30);
        mismatched_report.report.profile_digest = digest(99);
        mismatched_report.report.report_digest =
            mismatched_report.report.digest().unwrap_or([0; 32]);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![mismatched_report, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
        let mut report_case_mismatch = stable_evidence("alpha", 30);
        report_case_mismatch.report.cases[0].outcome = CaseOutcomeStatusV1::Fail;
        refresh_report_counts(&mut report_case_mismatch.report);
        report_case_mismatch.report.report_digest =
            report_case_mismatch.report.digest().unwrap_or([0; 32]);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![report_case_mismatch, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

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
        refresh_stable_report_for_profile(&mut first, &candidate);
        refresh_stable_report_for_profile(&mut second, &candidate);
        assert!(candidate
            .transition_to(ProfileLifecycleV1::Stable, vec![first, second])
            .is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_stable_evidence_requires_complete_ordered_unique_case_matrix() {
        let mut incomplete = stable_evidence("alpha", 30);
        incomplete.case_outcomes.pop();
        refresh_stable_report(&mut incomplete);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![incomplete, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );

        let mut duplicate = stable_evidence("alpha", 30);
        duplicate
            .case_outcomes
            .push(duplicate.case_outcomes[0].clone());
        refresh_stable_report(&mut duplicate);
        assert_eq!(
            candidate().transition_to(
                ProfileLifecycleV1::Stable,
                vec![duplicate, stable_evidence("beta", 40)],
            ),
            Err(ConformanceContractError::IndependenceEvidenceMissing)
        );
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
        typed.profile_digest = typed.digest();
        let typed_candidate = typed
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let typed_fixture_digest = fixture_digest(&typed_candidate.fixtures[0]);
        let reject = |mut first: StableImplementationEvidenceV1| {
            for case in &mut first.case_outcomes {
                case.fixture_digest = typed_fixture_digest;
                case.expected_digest = None;
                case.actual_digest = None;
                case.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
                case.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete);
                case.verification_outcome = VerificationOutcomeV1::InvalidManifest;
            }
            refresh_stable_report_for_profile(&mut first, &typed_candidate);
            first
        };
        assert!(typed_candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![
                    reject(stable_evidence("alpha", 30)),
                    reject(stable_evidence("beta", 40)),
                ],
            )
            .is_ok());
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
    fn public_typed_failure_outcomes_are_closed_and_error_bound() {
        for (outcome, error) in [
            (
                VerificationOutcomeV1::InvalidManifest,
                SafeErrorCodeV1::ClosureIncomplete,
            ),
            (
                VerificationOutcomeV1::UnverifiableArtifactsMissing,
                SafeErrorCodeV1::ProvenanceMissing,
            ),
            (
                VerificationOutcomeV1::IncompatibleProfile,
                SafeErrorCodeV1::ClosureIncomplete,
            ),
            (
                VerificationOutcomeV1::ResourceLimitExceeded,
                SafeErrorCodeV1::ClosureIncomplete,
            ),
        ] {
            let mut typed = profile();
            typed.fixtures[0].expected = ExpectedResultV1::TypedFailure(error);
            typed.fixtures[0].expected_verification_outcome = outcome;
            typed.fixtures[0].expected_verification_error = Some(error);
            typed.profile_digest = typed.digest();
            assert!(typed.validate().is_ok());
        }
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
        at_limit.profile_digest = at_limit.digest();
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
        assert_eq!(
            at_limit.validate(),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut above_limit = at_limit;
        let mut extra = template;
        extra.case_id = "case-65536".to_owned();
        above_limit.fixtures.push(extra);
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
        refresh_stable_report(&mut optional_first);
        refresh_stable_report(&mut optional_second);
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
        let mut required_stable_first = stable_evidence("alpha", 30);
        let mut required_stable_second = stable_evidence("beta", 40);
        refresh_stable_report_for_profile(&mut required_stable_first, &required_candidate);
        refresh_stable_report_for_profile(&mut required_stable_second, &required_candidate);
        assert!(required_candidate
            .transition_to(
                ProfileLifecycleV1::Stable,
                vec![required_stable_first, required_stable_second],
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
    fn public_stable_requires_technical_and_authorship_independence() {
        for disable_technical in [true, false] {
            let mut configured = profile();
            if disable_technical {
                configured
                    .independence_requirements
                    .technical_independence_required = false;
            } else {
                configured
                    .independence_requirements
                    .authorship_independence_required = false;
            }
            let candidate = configured
                .transition_to(ProfileLifecycleV1::Candidate, vec![])
                .unwrap_or_else(|_| profile());
            let mut first = stable_evidence("alpha", 30);
            let mut second = stable_evidence("beta", 40);
            refresh_stable_report_for_profile(&mut first, &candidate);
            refresh_stable_report_for_profile(&mut second, &candidate);

            assert_eq!(
                candidate.transition_to(ProfileLifecycleV1::Stable, vec![first, second]),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_reviewer_and_divergence_empty_boundaries_are_exact() {
        let mut first = stable_evidence("alpha", 30);
        first.independence.reviewer_ids = (0..32).map(|number| format!("r{number:02}")).collect();
        let mut second = stable_evidence("beta", 40);
        second.independence.reviewer_ids = (0..32).map(|number| format!("s{number:02}")).collect();
        refresh_stable_report(&mut first);
        refresh_stable_report(&mut second);
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
            |value| {
                value.fixtures[0].modes = vec![ExecutionModeV1::AirGapped];
                value.fixtures[0].capability_policy.network_allowed = true;
            },
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_contract_boundaries_are_individual_and_not_accidental() {
        // The output cap is inclusive at its documented maximum.
        let mut request_at_limit = request();
        request_at_limit.output_capability.report_bytes_limit = MAX_PROFILE_BYTES as u64;
        request_at_limit.request_digest = request_at_limit.digest();
        assert_eq!(request_at_limit.validate(), Ok(()));

        // Each independence identity is authoritative on its own.  Keeping the
        // other two digests distinct prevents a weakened conjunction from
        // accepting a stable profile.
        let identity_changes: [fn(&mut StableImplementationEvidenceV1); 3] = [
            |e: &mut StableImplementationEvidenceV1| e.implementation.source_digest = digest(40),
            |e: &mut StableImplementationEvidenceV1| e.implementation.build_digest = digest(41),
            |e: &mut StableImplementationEvidenceV1| e.implementation.binary_digest = digest(42),
        ];
        for change in identity_changes {
            let profile_value = candidate();
            let mut first = stable_evidence("alpha", 30);
            let mut second = stable_evidence("beta", 40);
            change(&mut first);
            refresh_stable_report_for_profile(&mut first, &profile_value);
            refresh_stable_report_for_profile(&mut second, &profile_value);
            assert_eq!(
                profile_value.transition_to(ProfileLifecycleV1::Stable, vec![first, second]),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
        }

        // A case match is a conjunction of independent public identities.
        let mut typed = profile();
        typed.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        typed.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        typed.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::ClosureIncomplete);
        let typed = typed
            .transition_to(ProfileLifecycleV1::Candidate, vec![])
            .unwrap_or_else(|_| profile());
        let fixture = &typed.fixtures[0];
        let expected_fixture_digest = fixture_digest(fixture);
        let expected_provenance_digest = fixture_provenance_digest(&fixture.provenance);
        let mut matching = stable_evidence("alpha", 30);
        for case in &mut matching.case_outcomes {
            case.fixture_digest = expected_fixture_digest;
            case.expected_digest = None;
            case.actual_digest = None;
            case.expected_error = Some(SafeErrorCodeV1::ClosureIncomplete);
            case.actual_error = Some(SafeErrorCodeV1::ClosureIncomplete);
            case.replay_claim = fixture.replay_claim;
            case.provenance_digest = expected_provenance_digest;
            case.verification_outcome = VerificationOutcomeV1::InvalidManifest;
        }
        refresh_stable_report_for_profile(&mut matching, &typed);
        let mut accepted = matching.clone();
        let second = {
            let mut value = stable_evidence("beta", 40);
            value.case_outcomes = accepted.case_outcomes.clone();
            refresh_stable_report_for_profile(&mut value, &typed);
            value
        };
        assert!(typed
            .transition_to(ProfileLifecycleV1::Stable, vec![accepted.clone(), second])
            .is_ok());
        let case_changes: [fn(&mut CaseOutcomeV1); 3] = [
            |case: &mut CaseOutcomeV1| case.actual_error = Some(SafeErrorCodeV1::DigestMismatch),
            |case: &mut CaseOutcomeV1| case.fixture_digest = [0; 32],
            |case: &mut CaseOutcomeV1| case.provenance_digest = [0; 32],
        ];
        for change in case_changes {
            change(&mut accepted.case_outcomes[0]);
            let mut second = matching.clone();
            second.case_outcomes[0] = accepted.case_outcomes[0].clone();
            assert_eq!(
                typed.transition_to(ProfileLifecycleV1::Stable, vec![accepted.clone(), second]),
                Err(ConformanceContractError::IndependenceEvidenceMissing)
            );
            accepted = matching.clone();
        }

        assert_public_hard_cap_boundaries_are_fail_closed();
        assert_public_fixture_boundaries_are_fail_closed();
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_public_hard_cap_boundaries_are_fail_closed() {
        let reject_cap = |change: &dyn Fn(&mut EvaluatorHardCapsV1)| {
            let mut caps = original_hard_caps();
            change(&mut caps);
            assert_eq!(
                profile_with_hard_caps(caps).validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        };
        reject_cap(&|c| c.max_profile_bytes = 0);
        reject_cap(&|c| c.max_profile_bytes = MAX_PROFILE_BYTES as u64 + 1);
        reject_cap(&|c| c.max_cases = 0);
        reject_cap(&|c| c.max_cases = 65_537);
        reject_cap(&|c| c.max_bundle_members = 0);
        reject_cap(&|c| c.max_bundle_members = 65_537);
        reject_cap(&|c| c.max_member_path_bytes = 0);
        reject_cap(&|c| c.max_member_path_bytes = 257);
        reject_cap(&|c| c.max_member_bytes = 0);
        reject_cap(&|c| c.max_member_bytes = MAX_MEMBER_BYTES + 1);
        reject_cap(&|c| c.max_total_bundle_bytes = 0);
        reject_cap(&|c| c.max_total_bundle_bytes = MAX_TOTAL_BUNDLE_BYTES + 1);
        reject_cap(&|c| c.max_compression_expansion = 0);
        reject_cap(&|c| c.max_compression_expansion = MAX_COMPRESSION_EXPANSION + 1);
        reject_cap(&|c| c.max_structural_nesting = 0);
        reject_cap(&|c| c.max_structural_nesting = MAX_STRUCTURAL_NESTING + 1);
        reject_cap(&|c| c.max_coordinate_bytes = 0);
        reject_cap(&|c| c.max_coordinate_bytes = 129);
        reject_cap(&|c| c.max_diagnostic_bytes = MAX_DIAGNOSTIC_BYTES + 1);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_public_fixture_boundaries_are_fail_closed() {
        for bounds in zero_bound_variants() {
            let mut value = profile();
            value.fixtures[0].bounds = bounds;
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_fixture_digests_are_not_sentinel_replacements() {
        let fixture = &profile().fixtures[0];
        assert_ne!(fixture_digest(fixture), [1; 32]);
        assert_ne!(fixture_provenance_digest(&fixture.provenance), [0; 32]);
        assert_ne!(fixture_provenance_digest(&fixture.provenance), [1; 32]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_fixture_bounds_reject_each_zero_field() {
        for bounds in zero_bound_variants() {
            let mut value = profile();
            value.fixtures[0].bounds = bounds;
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_semantic_versions_and_typed_failures_reject_each_wrong_shape() {
        for version in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1..3",
            "1.2.",
            "1.2.a",
            "1.12345678901.3",
        ] {
            let mut value = profile();
            value.semantic_version = version.to_owned();
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }
        let mut ten_digit_component = profile();
        ten_digit_component.semantic_version = "1234567890.0.0".to_owned();
        ten_digit_component.profile_digest = ten_digit_component.digest();
        assert_eq!(ten_digit_component.validate(), Ok(()));

        for version in ["1.2.3-alpha.1", "1.2.3+build.7", "1.2.3-alpha+build.7"] {
            let mut value = profile();
            value.semantic_version = version.to_owned();
            value.profile_digest = value.digest();
            assert_eq!(value.validate(), Ok(()));
        }
        for version in ["01.2.3", "1.2.3-01", "1.2.3-", "1.2.3+"] {
            let mut value = profile();
            value.semantic_version = version.to_owned();
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::FieldOutOfBounds)
            );
        }

        for outcome in [
            VerificationOutcomeV1::VerifiedExact,
            VerificationOutcomeV1::Diverged,
        ] {
            let mut value = profile();
            value.fixtures[0].expected =
                ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
            value.fixtures[0].expected_verification_outcome = outcome;
            value.fixtures[0].expected_verification_error =
                Some(SafeErrorCodeV1::ClosureIncomplete);
            value.profile_digest = value.digest();
            assert_eq!(
                value.validate(),
                Err(ConformanceContractError::ExpectedResultMissing)
            );
        }
        let mut value = profile();
        value.fixtures[0].expected =
            ExpectedResultV1::TypedFailure(SafeErrorCodeV1::ClosureIncomplete);
        value.fixtures[0].expected_verification_outcome = VerificationOutcomeV1::InvalidManifest;
        value.fixtures[0].expected_verification_error = Some(SafeErrorCodeV1::DigestMismatch);
        value.profile_digest = value.digest();
        assert_eq!(
            value.validate(),
            Err(ConformanceContractError::ExpectedResultMissing)
        );

        assert!(!valid_identifiers("01", true));
        assert!(valid_identifiers("01", false));
        assert!(semantic_version("1.2.3"));
        let exact_length = format!("1.2.3+{}", "x".repeat(MAX_STRING_BYTES - 6));
        assert_eq!(exact_length.len(), MAX_STRING_BYTES);
        assert!(semantic_version(&exact_length));
        let over_length = format!("1.2.3+{}", "x".repeat(MAX_STRING_BYTES - 5));
        assert!(!semantic_version(&over_length));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_profile_decoder_reaches_cbor_length_and_depth_guards() {
        // A valid, multi-byte CBOR length exercises the byte-folding path.
        let mut value = profile();
        let bytes = vec![b'x'; 256];
        value.fixtures[0].expected = ExpectedResultV1::CanonicalBytes {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        };
        value.fixtures[0].bounds.output_bytes = 256;
        value.fixtures[0].inputs[0].size_bytes = 256;
        value.profile_digest = value.digest();
        let encoded = value.to_canonical_cbor().unwrap_or_default();
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&encoded),
            Ok(value)
        );

        assert!(
            ConformanceProfileV1::from_canonical_cbor(&[0x9b_u8, 0, 0, 0, 0, 0, 0, 0, 1,]).is_err()
        );
        assert!(ConformanceProfileV1::from_canonical_cbor(&[0x7f_u8, 0xff]).is_err());
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&[0x58, 0x02, 0]),
            Err(ConformanceContractError::InvalidEncoding)
        );
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&[0x58]),
            Err(ConformanceContractError::InvalidEncoding)
        );
        let mut overflowing_bytes = vec![0x5b_u8];
        overflowing_bytes.extend([0xff; 8]);
        assert_eq!(
            ConformanceProfileV1::from_canonical_cbor(&overflowing_bytes),
            Err(ConformanceContractError::FieldOutOfBounds)
        );

        let mut exact_depth = vec![0x81; usize::from(MAX_STRUCTURAL_NESTING)];
        exact_depth.push(0xf6);
        assert_eq!(preflight_cbor(&exact_depth), Ok(()));

        let mut exact_fixture_count = vec![0x9a, 0, 1, 0, 0];
        exact_fixture_count.extend(std::iter::repeat_n(0xf6, MAX_FIXTURES));
        assert_eq!(preflight_cbor(&exact_fixture_count), Ok(()));
    }

    #[test]
    fn public_decoders_reject_wrong_top_level_shapes() {
        let invalid = Value::Null;
        assert!(decode_profile(&invalid).is_err());
        assert!(decode_fixture(&invalid).is_err());
        assert!(decode_input(&invalid).is_err());
        assert!(decode_expected(&invalid).is_err());
        assert!(decode_divergence(&invalid).is_err());
        assert!(decode_bounds(&invalid).is_err());
        assert!(decode_capability_policy(&invalid).is_err());
        assert!(decode_fixture_provenance(&invalid).is_err());
        assert!(decode_protocol(&invalid).is_err());
        assert!(decode_hard_caps(&invalid).is_err());
        assert!(decode_requirements(&invalid).is_err());
        assert!(decode_request(&invalid).is_err());
        assert!(decode_output_capability(&invalid).is_err());
        assert!(decode_identity(&invalid).is_err());
        assert!(decode_lifecycle(&invalid).is_err());
        assert!(decode_adapter(&invalid).is_err());
        assert!(decode_mode(&invalid).is_err());
        assert!(decode_claim_layer(&invalid).is_err());
        assert!(decode_verification_outcome(&invalid).is_err());
        assert!(decode_divergence_mismatch(&invalid).is_err());
        assert!(decode_replay_claim(&invalid).is_err());
        assert!(decode_redaction(&invalid).is_err());
        assert!(decode_safe_error(&invalid).is_err());
    }

    #[test]
    fn public_decoders_reject_each_nested_field_shape() {
        fn reject_fields(
            value: &Value,
            field_count: usize,
            optional_fields: &[usize],
            decode: impl Fn(&Value) -> Result<(), ConformanceContractError>,
        ) {
            for index in 0..field_count {
                let mut malformed = value.clone();
                let replacement = if optional_fields.contains(&index) {
                    Value::Bool(true)
                } else {
                    Value::Null
                };
                replace_profile_path(&mut malformed, &[index], replacement);
                assert!(
                    decode(&malformed).is_err(),
                    "field {index} unexpectedly decoded"
                );
            }
        }

        let fixture = profile().fixtures[0].clone();
        reject_fields(&encode_fixture(&fixture), 17, &[10], |value| {
            decode_fixture(value).map(|_| ())
        });
        reject_fields(&encode_input(&fixture.inputs[0]), 4, &[], |value| {
            decode_input(value).map(|_| ())
        });
        reject_fields(
            &encode_divergence(&AllowedDivergenceV1 {
                classification: DivergenceMismatchKindV1::TypedFailure,
                first_coordinate: vec![1],
            }),
            2,
            &[],
            |value| decode_divergence(value).map(|_| ()),
        );
        reject_fields(&encode_bounds(&fixture.bounds), 8, &[], |value| {
            decode_bounds(value).map(|_| ())
        });
        reject_fields(
            &encode_capability_policy(&fixture.capability_policy),
            2,
            &[],
            |value| decode_capability_policy(value).map(|_| ()),
        );
        reject_fields(
            &encode_fixture_provenance(&fixture.provenance),
            6,
            &[],
            |value| decode_fixture_provenance(value).map(|_| ()),
        );
        reject_fields(
            &encode_protocol(&profile().evaluator_protocol),
            5,
            &[],
            |value| decode_protocol(value).map(|_| ()),
        );
        reject_fields(
            &encode_hard_caps(&profile().evaluator_protocol.hard_caps),
            10,
            &[],
            |value| decode_hard_caps(value).map(|_| ()),
        );
        reject_fields(
            &encode_requirements(&profile().independence_requirements),
            5,
            &[],
            |value| decode_requirements(value).map(|_| ()),
        );
        reject_fields(
            &encode_identity(&stable_evidence("alpha", 30).implementation),
            6,
            &[5],
            |value| decode_identity(value).map(|_| ()),
        );
        reject_fields(&encode_request(&request(), true), 14, &[], |value| {
            decode_request(value).map(|_| ())
        });
    }
}
