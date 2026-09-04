//! Independent CPF1 profile decoding and selection.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;
use ed25519_dalek::Verifier;

use crate::evaluator_protocol::{
    array, array_values, bool_value, contract_digest, contract_digest_matches, decode_canonical,
    encode, fixed_bytes, text, uint, EvaluationRequest, ProtocolError, SubjectAdapterKind,
};
use crate::signed_bundle::{ExpectedResultKey, VerifiedBundle, VerifiedMember};

const MAX_FIXTURES: usize = 65_536;
const MAX_AUXILIARY: usize = 64;
const MAX_CAPABILITIES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PROVIDERS: usize = 4_096;

/// Exact public fixture-provider identity carried by CPF1.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderKey {
    pub provider_id: String,
    pub contract_version: String,
    pub abi_major: u16,
    pub abi_minor: u16,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AllowedDivergence {
    classification: u8,
    first_coordinate: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderTransition {
    from: ProviderKey,
    to: ProviderKey,
}

/// Immutable public archive member identity carried by CPF1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDescriptor {
    pub member_path: String,
    pub media_type: String,
    pub byte_length: u64,
    pub digest: [u8; 32],
}

/// Closed oracle declaration for one fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictOracle {
    Output(ArtifactDescriptor),
    Failure(NamespacedFailure),
    Divergence {
        classification: u8,
        first_coordinate: Vec<u8>,
    },
}

/// Provider-owned typed failure identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacedFailure {
    pub owner_id: String,
    pub contract_version: String,
    pub code_id: String,
}

/// Resource ceilings selected by one fixture attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicBudget {
    pub memory_bytes: u64,
    pub cpu_fuel: u64,
    pub host_calls: u64,
    pub event_count: u64,
    pub output_bytes: u64,
    pub storage_bytes: u64,
    pub execution_steps: u64,
    pub simulation_time_ns: u64,
}

impl DeterministicBudget {
    fn from_value(value: &Value) -> Result<Self, ProfileError> {
        let fields = array(value, 8)?;
        let values = fields.iter().map(uint).collect::<Result<Vec<_>, _>>()?;
        if values.contains(&0) {
            return Err(ProfileError::FieldOutOfBounds);
        }
        Ok(Self {
            memory_bytes: values[0],
            cpu_fuel: values[1],
            host_calls: values[2],
            event_count: values[3],
            output_bytes: values[4],
            storage_bytes: values[5],
            execution_steps: values[6],
            simulation_time_ns: values[7],
        })
    }
}

/// Compiled evaluator maxima selected by CPF1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluatorHardCaps {
    pub max_profile_bytes: u64,
    pub max_cases: u64,
    pub max_bundle_members: u64,
    pub max_member_path_bytes: u64,
    pub max_member_bytes: u64,
    pub max_total_bundle_bytes: u64,
    pub max_compression_expansion: u64,
    pub max_structural_nesting: u64,
    pub max_coordinate_bytes: u64,
    pub max_diagnostic_bytes: u64,
    pub max_deterministic_memory_bytes: u64,
    pub max_deterministic_cpu_fuel: u64,
    pub max_deterministic_host_calls: u64,
    pub max_deterministic_event_count: u64,
    pub max_deterministic_output_bytes: u64,
    pub max_deterministic_storage_bytes: u64,
    pub max_deterministic_execution_steps: u64,
    pub max_deterministic_simulation_time_ns: u64,
}

/// Independence properties required by one CPF1 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndependenceRequirements {
    pub technical: bool,
    pub authorship: bool,
    pub organizational: bool,
    pub declaration_digest: [u8; 32],
}

impl EvaluatorHardCaps {
    const fn values(self) -> [u64; 18] {
        [
            self.max_profile_bytes,
            self.max_cases,
            self.max_bundle_members,
            self.max_member_path_bytes,
            self.max_member_bytes,
            self.max_total_bundle_bytes,
            self.max_compression_expansion,
            self.max_structural_nesting,
            self.max_coordinate_bytes,
            self.max_diagnostic_bytes,
            self.max_deterministic_memory_bytes,
            self.max_deterministic_cpu_fuel,
            self.max_deterministic_host_calls,
            self.max_deterministic_event_count,
            self.max_deterministic_output_bytes,
            self.max_deterministic_storage_bytes,
            self.max_deterministic_execution_steps,
            self.max_deterministic_simulation_time_ns,
        ]
    }

    /// Canonical digest of the exact eighteen-field hard-cap record.
    ///
    /// # Errors
    /// Returns an encoding failure if the selected record cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], ProfileError> {
        let value = Value::Array(
            self.values()
                .iter()
                .copied()
                .map(|value| Value::Integer(value.into()))
                .collect(),
        );
        contract_digest(b"PiglorOS.EvaluatorHardCaps.v1", &value).map_err(Into::into)
    }

    /// Require a fixture's deterministic limits to be no greater than the
    /// selected evaluator ceilings.
    ///
    /// # Errors
    /// Returns a bound failure when any fixture limit exceeds its ceiling.
    pub fn admits(&self, budget: DeterministicBudget) -> Result<(), ProfileError> {
        let requested = [
            budget.memory_bytes,
            budget.cpu_fuel,
            budget.host_calls,
            budget.event_count,
            budget.output_bytes,
            budget.storage_bytes,
            budget.execution_steps,
            budget.simulation_time_ns,
        ];
        if requested
            .iter()
            .zip(&self.values()[10..])
            .any(|(request, maximum)| *request == 0 || request > maximum)
        {
            Err(ProfileError::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }
}

/// One selected execution coordinate from CPF1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fixture {
    pub case_id: String,
    pub mandatory: bool,
    pub claim_layer: u8,
    pub family: u8,
    pub provider: ProviderKey,
    pub subject_adapter: SubjectAdapterKind,
    pub execution_profile_digest: [u8; 32],
    pub modes: Vec<u8>,
    pub schema: ArtifactDescriptor,
    pub payload: ArtifactDescriptor,
    pub auxiliary: Vec<ArtifactDescriptor>,
    pub oracle: StrictOracle,
    pub expected_verification_outcome: u8,
    pub expected_verification_error: Option<NamespacedFailure>,
    pub replay_claim: u8,
    pub redaction_state: u8,
    pub deterministic_budget: DeterministicBudget,
    pub watchdog_ms: u64,
    pub network_allowed: bool,
    pub capability_ids: Vec<String>,
    pub provenance_digest: [u8; 32],
    pub fixture_digest: [u8; 32],
    release_admission: Option<ReleaseAdmissionBinding>,
}

struct FixtureHeader {
    case_id: String,
    mandatory: bool,
    claim_layer: u8,
    family: u8,
    provider: ProviderKey,
    subject_adapter: SubjectAdapterKind,
    execution_profile_digest: [u8; 32],
    modes: Vec<u8>,
}

struct FixtureEvidence {
    schema: ArtifactDescriptor,
    payload: ArtifactDescriptor,
    auxiliary: Vec<ArtifactDescriptor>,
    oracle: StrictOracle,
    expected_verification_outcome: u8,
    expected_verification_error: Option<NamespacedFailure>,
    replay_claim: u8,
    redaction_state: u8,
}

struct FixturePolicy {
    deterministic_budget: DeterministicBudget,
    watchdog_ms: u64,
    network_allowed: bool,
    capability_ids: Vec<String>,
    release_admission: Option<ReleaseAdmissionBinding>,
    provenance_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseAdmissionBinding {
    trust_policy_snapshot_digest: [u8; 32],
    release_admission_digest: [u8; 32],
    transition: ProviderTransition,
}

/// Validated current-only CPF1 information needed by the evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub profile_id: String,
    pub profile_digest: [u8; 32],
    pub normative_spec_digest: [u8; 32],
    pub execution_profile_digests: Vec<[u8; 32]>,
    pub fixtures: Vec<Fixture>,
    pub evaluator_protocol_digest: [u8; 32],
    pub evaluator_hard_caps: EvaluatorHardCaps,
    pub independence_requirements: IndependenceRequirements,
    pub trust_policy_snapshot_digest: [u8; 32],
    pub limitations_digest: [u8; 32],
    pub provenance_digest: [u8; 32],
}

/// Closed CPF1/profile-closure failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProfileError {
    #[error("profile encoding is invalid")]
    InvalidEncoding,
    #[error("profile version is unsupported")]
    UnsupportedVersion,
    #[error("profile field exceeds its bound")]
    FieldOutOfBounds,
    #[error("profile records are not in canonical order")]
    NonCanonicalOrder,
    #[error("profile digest does not match")]
    DigestMismatch,
    #[error("profile archive closure is incomplete")]
    ClosureIncomplete,
}

impl From<ProtocolError> for ProfileError {
    fn from(value: ProtocolError) -> Self {
        match value {
            ProtocolError::UnsupportedVersion => Self::UnsupportedVersion,
            ProtocolError::FieldOutOfBounds => Self::FieldOutOfBounds,
            ProtocolError::NonCanonicalOrder => Self::NonCanonicalOrder,
            ProtocolError::DigestMismatch => Self::DigestMismatch,
            ProtocolError::InvalidEncoding => Self::InvalidEncoding,
        }
    }
}

impl Profile {
    /// Authenticate the selected archive caps from a digest-bound CPF1 member.
    ///
    /// This narrow decode is used after CFB1 manifest authentication and before
    /// archive-wide member allocation.
    ///
    /// # Errors
    /// Returns a closed profile failure for malformed bytes or identity mismatch.
    pub fn authenticated_hard_caps(
        bytes: &[u8],
        request: &EvaluationRequest,
    ) -> Result<EvaluatorHardCaps, ProfileError> {
        let value = decode_canonical(bytes)?;
        let fields = array(&value, 18)?;
        let profile_digest = fixed_bytes(&fields[17])?;
        if !contract_digest_matches(
            b"PiglorOS.ConformanceProfile.v1",
            &Value::Array(fields[..17].to_vec()),
            profile_digest,
        ) || profile_digest != request.profile_digest
        {
            return Err(ProfileError::DigestMismatch);
        }
        let (evaluator_artifacts, caps) = decode_protocol(&fields[11])?;
        if evaluator_artifacts[0] != request.evaluator_protocol_digest
            || caps.digest()? != request.evaluator_hard_caps_digest
        {
            return Err(ProfileError::DigestMismatch);
        }
        if bytes.len() as u64 > caps.max_profile_bytes {
            return Err(ProfileError::FieldOutOfBounds);
        }
        Ok(caps)
    }

    /// Decode the sole current eighteen-field CPF1 profile and verify its
    /// self-digest and the request-selected identities.
    ///
    /// # Errors
    /// Returns a closed failure for malformed, obsolete, unbounded, unordered,
    /// or identity-inconsistent profile bytes.
    pub fn from_bundle(
        bundle: &VerifiedBundle,
        request: &EvaluationRequest,
    ) -> Result<Self, ProfileError> {
        let bytes = bundle.profile_bytes();
        let value = decode_canonical(bytes)?;
        let fields = array(&value, 18)?;
        let header = decode_profile_header(fields)?;
        let profile_digest = fixed_bytes(&fields[17])?;
        if !contract_digest_matches(
            b"PiglorOS.ConformanceProfile.v1",
            &Value::Array(fields[..17].to_vec()),
            profile_digest,
        ) || profile_digest != bundle.profile_digest
            || profile_digest != request.profile_digest
        {
            return Err(ProfileError::DigestMismatch);
        }

        let execution_profile_digests = digest_list(&fields[7])?;
        let (registry, required_providers) = decode_provider_binding(&fields[8])?;
        let (evaluator_artifact_digests, hard_caps) = decode_protocol(&fields[11])?;
        let fixtures = decode_fixtures(&fields[9], hard_caps)?;
        let allowed_divergences = decode_allowed_divergences(&fields[10])?;
        let (independence_requirements, trust_policy_snapshot_digest) =
            decode_requirements(&fields[12])?;
        let profile_claim_layer = fixtures[0].claim_layer;
        validate_optional_digest(&fields[16])?;
        validate_profile_relationships(
            &fixtures,
            &required_providers,
            &execution_profile_digests,
            &allowed_divergences,
            profile_claim_layer,
        )?;
        validate_selected_caps(
            bytes.len(),
            &value,
            bundle,
            &fixtures,
            &allowed_divergences,
            hard_caps,
        )?;
        let registry_member = validate_support_closure(
            bundle,
            &header,
            &registry,
            &fixtures,
            &execution_profile_digests,
            evaluator_artifact_digests,
            trust_policy_snapshot_digest,
        )?;
        let profile = Self {
            profile_id: header.profile_id,
            profile_digest,
            normative_spec_digest: header.normative_spec_digest,
            execution_profile_digests,
            fixtures,
            evaluator_protocol_digest: evaluator_artifact_digests[0],
            evaluator_hard_caps: hard_caps,
            independence_requirements,
            trust_policy_snapshot_digest,
            limitations_digest: header.limitations_digest,
            provenance_digest: header.publication_digest,
        };
        profile.validate_request(request)?;
        profile.validate_bundle_closure(bundle)?;
        validate_release_admissions(bundle, &profile.fixtures)?;
        validate_provider_contracts(
            bundle,
            registry_member,
            &required_providers,
            profile_claim_layer,
            &profile.fixtures,
        )?;
        Ok(profile)
    }

    /// Select exactly the fixtures admitted by the request's adapter and
    /// `ExecutionProfile` in canonical CPF1 order.
    #[must_use]
    pub fn selected_fixtures(&self, request: &EvaluationRequest) -> Vec<&Fixture> {
        self.fixtures
            .iter()
            .filter(|fixture| {
                fixture.subject_adapter == request.subject_adapter
                    && fixture.execution_profile_digest == request.execution_profile_digest
            })
            .collect()
    }

    fn validate_request(&self, request: &EvaluationRequest) -> Result<(), ProfileError> {
        if !self
            .execution_profile_digests
            .contains(&request.execution_profile_digest)
            || self.evaluator_protocol_digest != request.evaluator_protocol_digest
            || self.evaluator_hard_caps.digest()? != request.evaluator_hard_caps_digest
            || self.trust_policy_snapshot_digest != request.trust_policy_snapshot_digest
            || self.selected_fixtures(request).is_empty()
            || request.output_capability.report_bytes_limit
                > self.evaluator_hard_caps.max_profile_bytes
            || request.output_capability.diagnostic_bytes_limit
                > self.evaluator_hard_caps.max_diagnostic_bytes
        {
            return Err(ProfileError::DigestMismatch);
        }
        Ok(())
    }

    fn validate_bundle_closure(&self, bundle: &VerifiedBundle) -> Result<(), ProfileError> {
        for fixture in &self.fixtures {
            validate_descriptor_roles(bundle, &fixture.schema, &[4])?;
            validate_descriptor_roles(bundle, &fixture.payload, &[0])?;
            fixture.auxiliary.iter().try_for_each(|descriptor| {
                validate_descriptor_roles(bundle, descriptor, &[0, 1, 17]).map(|_| ())
            })?;
            if let StrictOracle::Output(descriptor) = &fixture.oracle {
                validate_descriptor_roles(bundle, descriptor, &[1])?;
            }
            if fixture.modes.contains(&bundle.mode) {
                let evidence_count = fixture
                    .auxiliary
                    .iter()
                    .filter(|descriptor| {
                        bundle
                            .member(&descriptor.member_path)
                            .is_some_and(|member| member.role == 17)
                    })
                    .count();
                if evidence_count != 1 {
                    return Err(ProfileError::ClosureIncomplete);
                }
            }
        }
        validate_expected_results(bundle, &self.fixtures)
    }
}

fn validate_release_admissions(
    bundle: &VerifiedBundle,
    fixtures: &[Fixture],
) -> Result<(), ProfileError> {
    let selected = fixtures
        .iter()
        .filter(|fixture| fixture.modes.contains(&bundle.mode))
        .filter_map(|fixture| {
            fixture
                .release_admission
                .as_ref()
                .map(|binding| (fixture, binding))
        })
        .collect::<Vec<_>>();
    let expected = selected
        .iter()
        .map(|(_, binding)| binding.release_admission_digest)
        .collect::<BTreeSet<_>>();
    let actual_members = bundle
        .members
        .values()
        .filter(|member| member.role == 16)
        .collect::<Vec<_>>();
    let actual = actual_members
        .iter()
        .map(|member| (member.digest, member))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != selected.len()
        || actual_members.len() != selected.len()
        || actual.keys().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    selected.into_iter().try_for_each(|(fixture, binding)| {
        validate_release_admission(
            bundle,
            fixture,
            binding,
            actual[&binding.release_admission_digest],
        )
    })
}

fn validate_release_admission(
    bundle: &VerifiedBundle,
    fixture: &Fixture,
    binding: &ReleaseAdmissionBinding,
    member: &VerifiedMember,
) -> Result<(), ProfileError> {
    let value = decode_canonical(&member.bytes)?;
    let fields = array(&value, 11)?;
    let from = decode_provider_key(&fields[6])?;
    let to = decode_provider_key(&fields[7])?;
    if text(&fields[0])? != "RAD1"
        || uint(&fields[1])? != 1
        || uint(&fields[2])? != 0
        || text(&fields[3])? != fixture.case_id
        || fixed_bytes::<32>(&fields[4])? != fixture.execution_profile_digest
        || fixed_bytes::<32>(&fields[5])? != binding.trust_policy_snapshot_digest
        || from != binding.transition.from
        || to != binding.transition.to
        || bool_value(&fields[8])?
        || text(&fields[9])? != bundle.authority_key_id
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    let signature: [u8; 64] = fixed_bytes(&fields[10])?;
    let unsigned = encode(&Value::Array(fields[..10].to_vec()))?;
    bundle
        .authority_verifying_key
        .verify(&unsigned, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| ProfileError::InvalidEncoding)
}

fn decode_fixtures(
    value: &Value,
    hard_caps: EvaluatorHardCaps,
) -> Result<Vec<Fixture>, ProfileError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > MAX_FIXTURES {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let fixtures = values
        .iter()
        .map(|fixture| decode_fixture(fixture, hard_caps))
        .collect::<Result<Vec<_>, _>>()?;
    if !fixtures
        .windows(2)
        .all(|pair| fixture_key(&pair[0]) < fixture_key(&pair[1]))
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    Ok(fixtures)
}

fn decode_fixture(value: &Value, hard_caps: EvaluatorHardCaps) -> Result<Fixture, ProfileError> {
    let fields = array(value, 24)?;
    let fixture_digest = validate_fixture_digest(fields)?;
    let header = decode_fixture_header(fields)?;
    let evidence = decode_fixture_evidence(fields)?;
    let policy = decode_fixture_policy(fields, header.family, hard_caps)?;
    let fixture = Fixture {
        case_id: header.case_id,
        mandatory: header.mandatory,
        claim_layer: header.claim_layer,
        family: header.family,
        provider: header.provider,
        subject_adapter: header.subject_adapter,
        execution_profile_digest: header.execution_profile_digest,
        modes: header.modes,
        schema: evidence.schema,
        payload: evidence.payload,
        auxiliary: evidence.auxiliary,
        oracle: evidence.oracle,
        expected_verification_outcome: evidence.expected_verification_outcome,
        expected_verification_error: evidence.expected_verification_error,
        replay_claim: evidence.replay_claim,
        redaction_state: evidence.redaction_state,
        deterministic_budget: policy.deterministic_budget,
        watchdog_ms: policy.watchdog_ms,
        network_allowed: policy.network_allowed,
        capability_ids: policy.capability_ids,
        provenance_digest: policy.provenance_digest,
        fixture_digest,
        release_admission: policy.release_admission,
    };
    validate_fixture(&fixture).map(|()| fixture)
}

fn validate_fixture_digest(fields: &[Value]) -> Result<[u8; 32], ProfileError> {
    let fixture_digest = fixed_bytes(&fields[23])?;
    if !contract_digest_matches(
        b"PiglorOS.Conformance.Fixture.v1",
        &Value::Array(fields[..23].to_vec()),
        fixture_digest,
    ) {
        return Err(ProfileError::DigestMismatch);
    }
    Ok(fixture_digest)
}

fn decode_fixture_header(fields: &[Value]) -> Result<FixtureHeader, ProfileError> {
    Ok(FixtureHeader {
        case_id: identifier(&fields[0])?,
        mandatory: bool_value(&fields[1])?,
        claim_layer: bounded_code(&fields[2], 6)?,
        family: bounded_code(&fields[3], 6)?,
        provider: decode_provider_key(&fields[4])?,
        subject_adapter: decode_subject_adapter(&fields[5])?,
        execution_profile_digest: fixed_bytes(&fields[6])?,
        modes: decode_fixture_modes(&fields[7])?,
    })
}

fn decode_fixture_modes(value: &Value) -> Result<Vec<u8>, ProfileError> {
    let modes = array_values(value)?
        .iter()
        .map(|value| u8::try_from(uint(value)?).map_err(|_| ProfileError::InvalidEncoding))
        .collect::<Result<Vec<_>, _>>()?;
    if modes.is_empty()
        || !modes.windows(2).all(|pair| pair[0] < pair[1])
        || modes.iter().any(|mode| *mode > 3)
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    Ok(modes)
}

fn decode_subject_adapter(value: &Value) -> Result<SubjectAdapterKind, ProfileError> {
    Ok(match uint(value)? {
        0 => SubjectAdapterKind::ExportedArtifact,
        1 => SubjectAdapterKind::PublicGatewayProtocol,
        2 => SubjectAdapterKind::PublicPluginProtocol,
        _ => return Err(ProfileError::InvalidEncoding),
    })
}

fn decode_fixture_evidence(fields: &[Value]) -> Result<FixtureEvidence, ProfileError> {
    let schema = decode_descriptor(&fields[8])?;
    let payload = decode_descriptor(&fields[9])?;
    let auxiliary = array_values(&fields[10])?
        .iter()
        .map(decode_descriptor)
        .collect::<Result<Vec<_>, _>>()?;
    let oracle = decode_oracle(&fields[11])?;
    validate_artifact_paths(&schema, &payload, &auxiliary, &oracle)?;
    Ok(FixtureEvidence {
        schema,
        payload,
        auxiliary,
        oracle,
        expected_verification_outcome: bounded_code(&fields[12], 5)?,
        expected_verification_error: optional_failure(&fields[13])?,
        replay_claim: bounded_code(&fields[14], 4)?,
        redaction_state: bounded_code(&fields[15], 3)?,
    })
}

fn decode_fixture_policy(
    fields: &[Value],
    family: u8,
    hard_caps: EvaluatorHardCaps,
) -> Result<FixturePolicy, ProfileError> {
    let deterministic_budget = DeterministicBudget::from_value(&fields[16])?;
    hard_caps.admits(deterministic_budget)?;
    let safety = array(&fields[17], 1)?;
    let capability = array(&fields[18], 2)?;
    let capability_ids = string_list(&capability[1])?;
    if capability_ids.len() > MAX_CAPABILITIES {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let release_fields = (
        optional_digest(&fields[19])?,
        optional_digest(&fields[20])?,
        optional_transition(&fields[22])?,
    );
    let release_admission = match (family, release_fields) {
        (_, (None, None, None)) if family != 5 => None,
        (
            5,
            (Some(trust_policy_snapshot_digest), Some(release_admission_digest), Some(transition)),
        ) => Some(ReleaseAdmissionBinding {
            trust_policy_snapshot_digest,
            release_admission_digest,
            transition,
        }),
        _ => return Err(ProfileError::ClosureIncomplete),
    };
    Ok(FixturePolicy {
        deterministic_budget,
        watchdog_ms: uint(&safety[0])?,
        network_allowed: bool_value(&capability[0])?,
        capability_ids,
        release_admission,
        provenance_digest: decode_provenance(&fields[21])?,
    })
}

struct ProfileHeader {
    profile_id: String,
    normative_spec_digest: [u8; 32],
    execution_matrix_digest: [u8; 32],
    fixture_policy_digest: [u8; 32],
    limitations_digest: [u8; 32],
    publication_digest: [u8; 32],
}

fn decode_profile_header(fields: &[Value]) -> Result<ProfileHeader, ProfileError> {
    if text(&fields[0])? != "CPF1" || uint(&fields[1])? != 1 {
        return Err(ProfileError::UnsupportedVersion);
    }
    let header = ProfileHeader {
        profile_id: identifier(&fields[2])?,
        normative_spec_digest: fixed_bytes(&fields[5])?,
        execution_matrix_digest: fixed_bytes(&fields[6])?,
        fixture_policy_digest: fixed_bytes(&fields[13])?,
        limitations_digest: fixed_bytes(&fields[14])?,
        publication_digest: fixed_bytes(&fields[15])?,
    };
    if !semantic_version(text(&fields[3])?, Some(10))
        || uint(&fields[4])? != 0
        || [
            header.normative_spec_digest,
            header.execution_matrix_digest,
            header.fixture_policy_digest,
            header.limitations_digest,
            header.publication_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(header)
}

fn decode_provider_binding(
    value: &Value,
) -> Result<(ArtifactDescriptor, Vec<ProviderKey>), ProfileError> {
    let fields = array(value, 2)?;
    let registry = decode_descriptor(&fields[0])?;
    let values = array_values(&fields[1])?;
    if values.is_empty() || values.len() > MAX_PROVIDERS {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let providers = values
        .iter()
        .map(decode_provider_key)
        .collect::<Result<Vec<_>, _>>()?;
    if !providers.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ProfileError::NonCanonicalOrder);
    }
    Ok((registry, providers))
}

fn decode_provider_key(value: &Value) -> Result<ProviderKey, ProfileError> {
    let fields = array(value, 4)?;
    let provider_id = text(&fields[0])?;
    let contract_version = text(&fields[1])?;
    if !valid_identifier(provider_id) || !semantic_version(contract_version, None) {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(ProviderKey {
        provider_id: provider_id.to_owned(),
        contract_version: contract_version.to_owned(),
        abi_major: u16::try_from(uint(&fields[2])?).map_err(|_| ProfileError::FieldOutOfBounds)?,
        abi_minor: u16::try_from(uint(&fields[3])?).map_err(|_| ProfileError::FieldOutOfBounds)?,
    })
}

fn decode_protocol(value: &Value) -> Result<([[u8; 32]; 3], EvaluatorHardCaps), ProfileError> {
    let fields = array(value, 5)?;
    let protocol_id = text(&fields[0])?;
    let digests = [
        fixed_bytes(&fields[1])?,
        fixed_bytes(&fields[2])?,
        fixed_bytes(&fields[3])?,
    ];
    if !valid_identifier(protocol_id) || digests.contains(&[0; 32]) {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok((digests, decode_hard_caps(&fields[4])?))
}

fn decode_requirements(
    value: &Value,
) -> Result<(IndependenceRequirements, [u8; 32]), ProfileError> {
    let fields = array(value, 5)?;
    let requirements = IndependenceRequirements {
        technical: bool_value(&fields[0])?,
        authorship: bool_value(&fields[1])?,
        organizational: bool_value(&fields[2])?,
        declaration_digest: fixed_bytes(&fields[4])?,
    };
    let trust = fixed_bytes(&fields[3])?;
    if trust == [0; 32] || requirements.declaration_digest == [0; 32] {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok((requirements, trust))
    }
}

fn decode_allowed_divergences(value: &Value) -> Result<Vec<AllowedDivergence>, ProfileError> {
    let divergences = array_values(value)?
        .iter()
        .map(decode_divergence)
        .collect::<Result<Vec<_>, _>>()?;
    if divergences.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(ProfileError::NonCanonicalOrder)
    } else {
        Ok(divergences)
    }
}

fn decode_divergence(value: &Value) -> Result<AllowedDivergence, ProfileError> {
    let fields = array(value, 2)?;
    let classification = bounded_code(&fields[0], 6)?;
    let first_coordinate = byte_string(&fields[1])?;
    if first_coordinate.is_empty() || first_coordinate.len() > 128 {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(AllowedDivergence {
        classification,
        first_coordinate,
    })
}

fn validate_optional_digest(value: &Value) -> Result<(), ProfileError> {
    optional_digest(value).and_then(|digest| {
        if digest == Some([0; 32]) {
            Err(ProfileError::FieldOutOfBounds)
        } else {
            Ok(())
        }
    })
}

fn optional_digest(value: &Value) -> Result<Option<[u8; 32]>, ProfileError> {
    if *value == Value::Null {
        Ok(None)
    } else {
        fixed_bytes(value).map(Some).map_err(Into::into)
    }
}

fn optional_transition(value: &Value) -> Result<Option<ProviderTransition>, ProfileError> {
    if *value == Value::Null {
        return Ok(None);
    }
    let fields = array(value, 2)?;
    Ok(Some(ProviderTransition {
        from: decode_provider_key(&fields[0])?,
        to: decode_provider_key(&fields[1])?,
    }))
}

fn decode_provenance(value: &Value) -> Result<[u8; 32], ProfileError> {
    let fields = array(value, 7)?;
    let source = text(&fields[0])?;
    if source.is_empty() || source.len() > 128 {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let digests = fields[1..]
        .iter()
        .map(fixed_bytes)
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    if digests.contains(&[0; 32]) {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(digests[4])
    }
}

fn validate_profile_relationships(
    fixtures: &[Fixture],
    required_providers: &[ProviderKey],
    execution_profiles: &[[u8; 32]],
    allowed_divergences: &[AllowedDivergence],
    profile_claim_layer: u8,
) -> Result<(), ProfileError> {
    let claim_layer = fixtures[0].claim_layer;
    let required = required_providers.iter().cloned().collect::<BTreeSet<_>>();
    let executions = execution_profiles.iter().copied().collect::<BTreeSet<_>>();
    let allowed = allowed_divergences.iter().cloned().collect::<BTreeSet<_>>();
    let mut inventory = BTreeMap::<(ProviderKey, [u8; 32], u8), BTreeSet<u8>>::new();
    let mut declared = BTreeSet::new();
    for fixture in fixtures {
        if fixture.claim_layer != claim_layer
            || !required.contains(&fixture.provider)
            || !executions.contains(&fixture.execution_profile_digest)
        {
            return Err(ProfileError::ClosureIncomplete);
        }
        for mode in &fixture.modes {
            if !inventory
                .entry((
                    fixture.provider.clone(),
                    fixture.execution_profile_digest,
                    *mode,
                ))
                .or_default()
                .insert(fixture.family)
            {
                return Err(ProfileError::NonCanonicalOrder);
            }
        }
        if let StrictOracle::Divergence {
            classification,
            first_coordinate,
        } = &fixture.oracle
        {
            let divergence = AllowedDivergence {
                classification: *classification,
                first_coordinate: first_coordinate.clone(),
            };
            if !allowed.contains(&divergence) {
                return Err(ProfileError::ClosureIncomplete);
            }
            declared.insert(divergence);
        }
    }
    let required_families = BTreeSet::from([0, 1, 2, 3, 4, 5, 6]);
    if claim_layer != profile_claim_layer
        || inventory
            .values()
            .any(|families| families != &required_families)
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    for provider in &required {
        for execution in &executions {
            for mode in [0, 1] {
                if inventory
                    .get(&(provider.clone(), *execution, mode))
                    .is_none_or(|families| families != &required_families)
                {
                    return Err(ProfileError::ClosureIncomplete);
                }
            }
        }
    }
    if declared == allowed {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_fixture(fixture: &Fixture) -> Result<(), ProfileError> {
    if !valid_identifier(&fixture.case_id)
        || fixture.execution_profile_digest == [0; 32]
        || fixture.watchdog_ms == 0
        || fixture.auxiliary.len() > MAX_AUXILIARY
        || fixture.network_allowed
            && (fixture.subject_adapter == SubjectAdapterKind::PublicPluginProtocol
                || fixture.modes.contains(&1))
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    validate_outcome_relationship(fixture)?;
    validate_claim_relationship(fixture)?;
    validate_downgrade_relationship(fixture)
}

fn validate_outcome_relationship(fixture: &Fixture) -> Result<(), ProfileError> {
    let valid = match &fixture.oracle {
        StrictOracle::Output(_) => {
            fixture.expected_verification_outcome == 0
                && fixture.expected_verification_error.is_none()
        }
        StrictOracle::Failure(expected) => {
            !matches!(fixture.expected_verification_outcome, 0 | 1)
                && fixture.expected_verification_error.as_ref() == Some(expected)
                && (expected.owner_id == "pigloros.core"
                    || expected.owner_id == fixture.provider.provider_id
                        && expected.contract_version == fixture.provider.contract_version)
        }
        StrictOracle::Divergence { .. } => {
            fixture.expected_verification_outcome == 1
                && fixture.expected_verification_error.is_none()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_claim_relationship(fixture: &Fixture) -> Result<(), ProfileError> {
    let coherent = fixture.replay_claim == 4
        || [
            true,
            fixture.replay_claim == 1,
            fixture.replay_claim == 2,
            fixture.replay_claim == 3,
        ][usize::from(fixture.redaction_state)];
    if coherent {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_downgrade_relationship(fixture: &Fixture) -> Result<(), ProfileError> {
    if fixture.family != 5 {
        return Ok(());
    }
    let valid = fixture.release_admission.as_ref().is_some_and(|binding| {
        binding.trust_policy_snapshot_digest != [0; 32]
            && binding.release_admission_digest != [0; 32]
            && {
                let transition = &binding.transition;
                let targets_selected_provider = transition.to == fixture.provider;
                let preserves_provider = transition.from.provider_id == transition.to.provider_id;
                let preserves_contract =
                    transition.from.contract_version == transition.to.contract_version;
                let preserves_major = transition.from.abi_major == transition.to.abi_major;
                let downgrades_minor = transition.from.abi_minor > transition.to.abi_minor;
                targets_selected_provider
                    && preserves_provider
                    && preserves_contract
                    && preserves_major
                    && downgrades_minor
            }
    });
    if valid {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_artifact_paths(
    schema: &ArtifactDescriptor,
    payload: &ArtifactDescriptor,
    auxiliary: &[ArtifactDescriptor],
    oracle: &StrictOracle,
) -> Result<(), ProfileError> {
    if auxiliary.len() > MAX_AUXILIARY
        || auxiliary
            .windows(2)
            .any(|pair| pair[0].member_path >= pair[1].member_path)
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    let mut paths = BTreeSet::from([schema.member_path.as_str(), payload.member_path.as_str()]);
    for artifact in auxiliary {
        if !paths.insert(&artifact.member_path) {
            return Err(ProfileError::NonCanonicalOrder);
        }
    }
    if let StrictOracle::Output(output) = oracle {
        if !paths.insert(&output.member_path) {
            return Err(ProfileError::NonCanonicalOrder);
        }
    }
    Ok(())
}

fn validate_selected_caps(
    encoded_len: usize,
    value: &Value,
    bundle: &VerifiedBundle,
    fixtures: &[Fixture],
    allowed: &[AllowedDivergence],
    caps: EvaluatorHardCaps,
) -> Result<(), ProfileError> {
    if encoded_len as u64 > caps.max_profile_bytes
        || value_depth(value) as u64 > caps.max_structural_nesting
        || fixtures.len() as u64 > caps.max_cases
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let member_count = bundle.members.len() as u64;
    let total_bytes = bundle.members.values().fold(0_u64, |total, member| {
        total.saturating_add(member.bytes.len() as u64)
    });
    if member_count > caps.max_bundle_members
        || total_bytes > caps.max_total_bundle_bytes
        || bundle.members.iter().any(|(path, member)| {
            path.len() as u64 > caps.max_member_path_bytes
                || member.bytes.len() as u64 > caps.max_member_bytes
        })
        || allowed
            .iter()
            .any(|item| item.first_coordinate.len() as u64 > caps.max_coordinate_bytes)
    {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn value_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(value_depth).max().unwrap_or_default(),
        _ => 1,
    }
}

fn validate_support_closure<'a>(
    bundle: &'a VerifiedBundle,
    header: &ProfileHeader,
    registry: &ArtifactDescriptor,
    fixtures: &[Fixture],
    execution_profiles: &[[u8; 32]],
    evaluator_artifacts: [[u8; 32]; 3],
    trust_policy_digest: [u8; 32],
) -> Result<&'a VerifiedMember, ProfileError> {
    if registry.member_path != "authority/fixture-provider-registry.cbor"
        || registry.media_type != "application/cbor"
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    let registry_member = validate_descriptor_roles(bundle, registry, &[12])?;
    let support = [
        (
            "support/normative-requirements.md",
            3,
            header.normative_spec_digest,
        ),
        (
            "support/fixture-family-contract.json",
            18,
            header.fixture_policy_digest,
        ),
        ("support/limitations.md", 9, header.limitations_digest),
        (
            "support/publication-review.json",
            8,
            header.publication_digest,
        ),
        (
            "support/evaluator-protocol-v1.json",
            4,
            evaluator_artifacts[0],
        ),
        (
            "support/evaluator-request-v1.cddl",
            4,
            evaluator_artifacts[1],
        ),
        (
            "support/evaluator-report-v1.cddl",
            4,
            evaluator_artifacts[2],
        ),
        (
            "authority/trust-policy-snapshot.tps1",
            15,
            trust_policy_digest,
        ),
    ];
    for (path, role, digest) in support {
        validate_member_binding(bundle, path, role, digest)?;
    }
    validate_execution_matrix(bundle, header.execution_matrix_digest)?;
    let actual_execution_profiles = bundle
        .members
        .iter()
        .filter(|(_, member)| member.role == 14)
        .map(|(path, member)| -> Result<[u8; 32], ProfileError> {
            let maximum = validate_execution_profile(path, &member.bytes, member.digest)?;
            validate_fixture_execution_budget(member.digest, maximum, fixtures)?;
            Ok(member.digest)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let declared_execution_profiles = execution_profiles.iter().copied().collect::<BTreeSet<_>>();
    if actual_execution_profiles == declared_execution_profiles
        && actual_execution_profiles.len() == execution_profiles.len()
    {
        Ok(registry_member)
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_execution_matrix(
    bundle: &VerifiedBundle,
    digest: [u8; 32],
) -> Result<(), ProfileError> {
    let member = validate_member_binding(bundle, "authority/execution-matrix.json", 11, digest)?;
    let root: serde_json::Value =
        serde_json::from_slice(&member.bytes).map_err(|_| ProfileError::InvalidEncoding)?;
    let root = json_object(&root)?;
    validate_execution_matrix_header(root)?;
    validate_matrix_inventory(root)
}

fn validate_execution_matrix_header(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ProfileError> {
    require_json_fields(
        root,
        &[
            "case_count",
            "cases",
            "equality_predicates",
            "executed_case_count",
            "expected_result_policy",
            "lifecycle",
            "magic",
            "matrix_id",
            "mode_count",
            "row_count",
            "rows",
            "source",
            "variant_count",
            "version",
        ],
    )?;
    if json_text(root, "magic")? != "NIM1"
        || json_u64(root, "version")? != 1
        || json_text(root, "lifecycle")? != "Draft"
        || json_u64(root, "row_count")? != 12
        || json_u64(root, "variant_count")? != 4
        || json_u64(root, "mode_count")? != 4
        || json_u64(root, "case_count")? != 192
        || json_text(root, "matrix_id")?.is_empty()
        || json_text(root, "source")?.is_empty()
        || json_text(root, "expected_result_policy")?.is_empty()
    {
        Err(ProfileError::ClosureIncomplete)
    } else {
        Ok(())
    }
}

fn validate_matrix_inventory(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ProfileError> {
    const FIXTURES: [&str; 12] = [
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
    const VARIANTS: [&str; 4] = ["S", "D", "W", "C"];
    const MODES: [&str; 4] = ["L", "A", "R", "F"];
    let rows = json_array(root, "rows")?;
    let predicates = json_array(root, "equality_predicates")?;
    let cases = json_array(root, "cases")?;
    if rows.len() != FIXTURES.len() || predicates.len() != FIXTURES.len() || cases.len() != 192 {
        return Err(ProfileError::ClosureIncomplete);
    }
    let mut executed_total = 0_u64;
    for (fixture_index, fixture_id) in FIXTURES.iter().enumerate() {
        let declared_executed = validate_matrix_row(&rows[fixture_index], fixture_id)?;
        validate_matrix_predicate(&predicates[fixture_index], fixture_id)?;
        let mut row_executed = 0_u64;
        for (variant_index, variant) in VARIANTS.iter().enumerate() {
            for (mode_index, mode) in MODES.iter().enumerate() {
                let index = fixture_index * 16 + variant_index * 4 + mode_index;
                if validate_matrix_case(&cases[index], fixture_id, variant, mode)? {
                    row_executed += 1;
                }
            }
        }
        if declared_executed != row_executed {
            return Err(ProfileError::ClosureIncomplete);
        }
        executed_total += row_executed;
    }
    if json_u64(root, "executed_case_count")? == executed_total {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_matrix_row(value: &serde_json::Value, fixture_id: &str) -> Result<u64, ProfileError> {
    let row = json_object(value)?;
    require_json_fields(
        row,
        &[
            "case_count",
            "channel",
            "classification",
            "equality",
            "executed_case_count",
            "fixture_id",
            "modes",
            "observable_surfaces",
            "sole_unauthorized_delta",
            "variants",
        ],
    )?;
    if json_text(row, "fixture_id")? != fixture_id
        || row.get("variants") != Some(&serde_json::json!(["S", "D", "W", "C"]))
        || row.get("modes") != Some(&serde_json::json!(["L", "A", "R", "F"]))
        || json_u64(row, "case_count")? != 16
        || !json_fields_nonempty(
            row,
            &[
                "channel",
                "classification",
                "equality",
                "sole_unauthorized_delta",
            ],
        )?
        || json_array(row, "observable_surfaces")?.is_empty()
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    json_u64(row, "executed_case_count")
}

fn validate_matrix_predicate(
    value: &serde_json::Value,
    fixture_id: &str,
) -> Result<(), ProfileError> {
    let predicate = json_object(value)?;
    require_json_fields(predicate, &["AuthEq", "OpEq", "PublicEq", "fixture_id"])?;
    if json_text(predicate, "fixture_id")? != fixture_id
        || !json_fields_nonempty(predicate, &["AuthEq", "PublicEq", "OpEq"])?
    {
        Err(ProfileError::ClosureIncomplete)
    } else {
        Ok(())
    }
}

fn validate_matrix_case(
    value: &serde_json::Value,
    fixture_id: &str,
    variant: &str,
    mode: &str,
) -> Result<bool, ProfileError> {
    let case = json_object(value)?;
    require_json_fields(
        case,
        &[
            "authority_fixture_id",
            "authority_result_digest",
            "case_id",
            "executed",
            "expected_result",
            "expected_result_digest",
            "fixture_id",
            "mode",
            "variant",
        ],
    )?;
    let executed = case
        .get("executed")
        .and_then(serde_json::Value::as_bool)
        .ok_or(ProfileError::InvalidEncoding)?;
    if json_text(case, "case_id")? != format!("{fixture_id}-{variant}-{mode}")
        || json_text(case, "fixture_id")? != fixture_id
        || json_text(case, "variant")? != variant
        || json_text(case, "mode")? != mode
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    let evidence = [
        "authority_fixture_id",
        "authority_result_digest",
        "expected_result",
        "expected_result_digest",
    ];
    if !executed && evidence.iter().any(|field| !case[*field].is_null())
        || executed
            && (case["expected_result"].is_null()
                || !json_digest(case.get("expected_result_digest")))
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    Ok(executed)
}

fn json_object(
    value: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, ProfileError> {
    value.as_object().ok_or(ProfileError::InvalidEncoding)
}

fn require_json_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
) -> Result<(), ProfileError> {
    if object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)) {
        Ok(())
    } else {
        Err(ProfileError::InvalidEncoding)
    }
}

fn json_text<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, ProfileError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(ProfileError::InvalidEncoding)
}

fn json_fields_nonempty(
    object: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
) -> Result<bool, ProfileError> {
    fields.iter().try_fold(true, |all_nonempty, field| {
        Ok(all_nonempty && !json_text(object, field)?.is_empty())
    })
}

fn json_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, ProfileError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or(ProfileError::InvalidEncoding)
}

fn json_array<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a [serde_json::Value], ProfileError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ProfileError::InvalidEncoding)
}

fn json_digest(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn validate_execution_profile(
    path: &str,
    bytes: &[u8],
    member_digest: [u8; 32],
) -> Result<[u64; 8], ProfileError> {
    let value = decode_canonical(bytes)?;
    let fields = array(&value, 17)?;
    validate_execution_profile_identity(fields, path)?;
    let maximum = validate_execution_profile_contract(fields)?;
    let expected = fixed_bytes::<32>(&fields[16])?;
    if !contract_digest_matches(
        b"PiglorOS.ExecutionProfile.v1",
        &Value::Array(fields[..16].to_vec()),
        expected,
    ) || member_digest != *blake3::hash(bytes).as_bytes()
    {
        return Err(ProfileError::DigestMismatch);
    }
    Ok(maximum)
}

fn validate_execution_profile_identity(fields: &[Value], path: &str) -> Result<(), ProfileError> {
    let profile_id = text(&fields[2])?;
    if text(&fields[0])? != "EPF1"
        || uint(&fields[1])? != 1
        || !valid_identifier(profile_id)
        || path != format!("authority/execution-profiles/{profile_id}.epf1")
        || !semantic_version(text(&fields[3])?, None)
        || fields[4]
            != Value::Array(vec![
                Value::Integer(0_u64.into()),
                Value::Integer(1_u64.into()),
            ])
        || !valid_text_list(&fields[5], false)?
        || !valid_text_list(&fields[6], false)?
        || !valid_text_list(&fields[7], false)?
        || !valid_identifier(text(&fields[8])?)
    {
        Err(ProfileError::ClosureIncomplete)
    } else {
        Ok(())
    }
}

fn validate_execution_profile_contract(fields: &[Value]) -> Result<[u64; 8], ProfileError> {
    if !valid_text_list(&fields[9], false)?
        || !valid_text_list(&fields[10], false)?
        || !valid_text_list(&fields[13], true)?
        || fields[15] != Value::Null
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    let network = array(&fields[11], 2)?;
    if bool_value(&network[0])? || !valid_text_list(&network[1], true)? {
        return Err(ProfileError::ClosureIncomplete);
    }
    let maximum = execution_budget(&fields[12])?;
    let versions = array(&fields[14], 2)?;
    if !semantic_version(text(&versions[0])?, None) || !semantic_version(text(&versions[1])?, None)
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(maximum)
}

fn validate_fixture_execution_budget(
    execution_profile_digest: [u8; 32],
    maximum: [u64; 8],
    fixtures: &[Fixture],
) -> Result<(), ProfileError> {
    for fixture in fixtures
        .iter()
        .filter(|fixture| fixture.execution_profile_digest == execution_profile_digest)
    {
        let requested = [
            fixture.deterministic_budget.memory_bytes,
            fixture.deterministic_budget.cpu_fuel,
            fixture.deterministic_budget.host_calls,
            fixture.deterministic_budget.event_count,
            fixture.deterministic_budget.output_bytes,
            fixture.deterministic_budget.storage_bytes,
            fixture.deterministic_budget.execution_steps,
            fixture.deterministic_budget.simulation_time_ns,
        ];
        if requested
            .iter()
            .zip(maximum)
            .any(|(requested, maximum)| *requested > maximum)
        {
            return Err(ProfileError::FieldOutOfBounds);
        }
    }
    Ok(())
}

fn execution_budget(value: &Value) -> Result<[u64; 8], ProfileError> {
    let values = array(value, 8)?;
    let mut budget = [0_u64; 8];
    for (target, value) in budget.iter_mut().zip(values) {
        *target = uint(value)?;
    }
    if budget.contains(&0) {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(budget)
    }
}

fn valid_text_list(value: &Value, empty_allowed: bool) -> Result<bool, ProfileError> {
    let values = array_values(value)?;
    if values.len() > 256 || !empty_allowed && values.is_empty() {
        return Ok(false);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        let item = text(value)?;
        if !valid_identifier(item) || !seen.insert(item) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_member_binding<'a>(
    bundle: &'a VerifiedBundle,
    path: &str,
    role: u8,
    digest: [u8; 32],
) -> Result<&'a VerifiedMember, ProfileError> {
    bundle
        .member(path)
        .filter(|member| member.role == role && member.digest == digest)
        .ok_or(ProfileError::ClosureIncomplete)
}

fn decode_oracle(value: &Value) -> Result<StrictOracle, ProfileError> {
    let fields = array(value, 4)?;
    match uint(&fields[0])? {
        0 if fields[2] == Value::Null && fields[3] == Value::Null => {
            optional_descriptor(&fields[1])?
                .map(StrictOracle::Output)
                .ok_or(ProfileError::InvalidEncoding)
        }
        1 if fields[1] == Value::Null && fields[3] == Value::Null => optional_failure(&fields[2])?
            .map(StrictOracle::Failure)
            .ok_or(ProfileError::InvalidEncoding),
        2 if fields[1] == Value::Null && fields[2] == Value::Null => {
            let divergence = array(&fields[3], 2)?;
            let classification = bounded_code(&divergence[0], 6)?;
            let first_coordinate = byte_string(&divergence[1])?;
            if first_coordinate.is_empty() || first_coordinate.len() > 128 {
                return Err(ProfileError::FieldOutOfBounds);
            }
            Ok(StrictOracle::Divergence {
                classification,
                first_coordinate,
            })
        }
        _ => Err(ProfileError::InvalidEncoding),
    }
}

fn decode_descriptor(value: &Value) -> Result<ArtifactDescriptor, ProfileError> {
    let fields = array(value, 4)?;
    let member_path = text(&fields[0])?.to_owned();
    let media_type = text(&fields[1])?.to_owned();
    let byte_length = uint(&fields[2])?;
    let digest = fixed_bytes(&fields[3])?;
    if member_path.is_empty()
        || !valid_member_path(&member_path)
        || !valid_media_type(&media_type)
        || byte_length == 0
        || byte_length > 64 * 1024 * 1024
        || digest == [0; 32]
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(ArtifactDescriptor {
        member_path,
        media_type,
        byte_length,
        digest,
    })
}

fn optional_descriptor(value: &Value) -> Result<Option<ArtifactDescriptor>, ProfileError> {
    if *value == Value::Null {
        Ok(None)
    } else {
        decode_descriptor(value).map(Some)
    }
}

fn optional_failure(value: &Value) -> Result<Option<NamespacedFailure>, ProfileError> {
    if *value == Value::Null {
        return Ok(None);
    }
    let fields = array(value, 3)?;
    let failure = NamespacedFailure {
        owner_id: identifier(&fields[0])?,
        contract_version: text(&fields[1])?.to_owned(),
        code_id: identifier(&fields[2])?,
    };
    if semantic_version(&failure.contract_version, None) {
        Ok(Some(failure))
    } else {
        Err(ProfileError::FieldOutOfBounds)
    }
}

fn decode_hard_caps(value: &Value) -> Result<EvaluatorHardCaps, ProfileError> {
    let fields = array(value, 18)?;
    let mut values = [0_u64; 18];
    for (target, field) in values.iter_mut().zip(fields) {
        *target = uint(field)?;
    }
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
    if values
        .iter()
        .zip(maxima)
        .enumerate()
        .any(|(index, (selected, maximum))| *selected > maximum || (index != 9 && *selected == 0))
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(EvaluatorHardCaps {
        max_profile_bytes: values[0],
        max_cases: values[1],
        max_bundle_members: values[2],
        max_member_path_bytes: values[3],
        max_member_bytes: values[4],
        max_total_bundle_bytes: values[5],
        max_compression_expansion: values[6],
        max_structural_nesting: values[7],
        max_coordinate_bytes: values[8],
        max_diagnostic_bytes: values[9],
        max_deterministic_memory_bytes: values[10],
        max_deterministic_cpu_fuel: values[11],
        max_deterministic_host_calls: values[12],
        max_deterministic_event_count: values[13],
        max_deterministic_output_bytes: values[14],
        max_deterministic_storage_bytes: values[15],
        max_deterministic_execution_steps: values[16],
        max_deterministic_simulation_time_ns: values[17],
    })
}

fn validate_descriptor<'a>(
    bundle: &'a VerifiedBundle,
    descriptor: &ArtifactDescriptor,
) -> Result<&'a VerifiedMember, ProfileError> {
    let member = bundle
        .member(&descriptor.member_path)
        .ok_or(ProfileError::ClosureIncomplete)?;
    if member.bytes.len() as u64 != descriptor.byte_length || member.digest != descriptor.digest {
        Err(ProfileError::DigestMismatch)
    } else {
        Ok(member)
    }
}

fn validate_descriptor_roles<'a>(
    bundle: &'a VerifiedBundle,
    descriptor: &ArtifactDescriptor,
    roles: &[u8],
) -> Result<&'a VerifiedMember, ProfileError> {
    let member = validate_descriptor(bundle, descriptor)?;
    if roles.contains(&member.role) {
        Ok(member)
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_expected_results(
    bundle: &VerifiedBundle,
    fixtures: &[Fixture],
) -> Result<(), ProfileError> {
    let selected = fixtures
        .iter()
        .filter(|fixture| fixture.modes.contains(&bundle.mode))
        .map(|fixture| {
            (
                ExpectedResultKey {
                    case_id: fixture.case_id.clone(),
                    claim_layer: fixture.claim_layer,
                    execution_profile_digest: fixture.execution_profile_digest,
                    mode: bundle.mode,
                },
                fixture,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if bundle.expected_results.len() != selected.len()
        || bundle.expected_results.keys().ne(selected.keys())
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    for (key, path) in &bundle.expected_results {
        let fixture = selected[key];
        let member = bundle.member(path).ok_or(ProfileError::ClosureIncomplete)?;
        let member_length = member.bytes.len() as u64;
        let bound = fixture.auxiliary.iter().any(|artifact| {
            artifact.member_path == path.as_str()
                && artifact.digest == member.digest
                && artifact.byte_length == member_length
        }) || matches!(
            &fixture.oracle,
            StrictOracle::Output(artifact)
                if artifact.member_path == path.as_str()
                    && artifact.digest == member.digest
                    && artifact.byte_length == member_length
        );
        if member.role != 1 || !bound {
            return Err(ProfileError::ClosureIncomplete);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderRecord {
    key: ProviderKey,
    claim_layer: u8,
    adapter: SubjectAdapterKind,
    package: ArtifactDescriptor,
    schemas: Vec<ArtifactDescriptor>,
}

fn validate_provider_contracts(
    bundle: &VerifiedBundle,
    registry_member: &VerifiedMember,
    required: &[ProviderKey],
    profile_claim_layer: u8,
    fixtures: &[Fixture],
) -> Result<(), ProfileError> {
    let value = decode_canonical(&registry_member.bytes)?;
    let fields = array(&value, 4)?;
    if text(&fields[0])? != "FPR1" || uint(&fields[1])? != 1 {
        return Err(ProfileError::UnsupportedVersion);
    }
    let expected_digest = fixed_bytes::<32>(&fields[3])?;
    if !contract_digest_matches(
        b"PiglorOS.Conformance.ProviderRegistry.v1",
        &Value::Array(fields[..3].to_vec()),
        expected_digest,
    ) {
        return Err(ProfileError::DigestMismatch);
    }
    let entries = array_values(&fields[2])?;
    if entries.is_empty() || entries.len() > MAX_PROVIDERS {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let providers = entries
        .iter()
        .map(|entry| decode_provider_record(entry, bundle))
        .collect::<Result<Vec<_>, _>>()?;
    if !providers.windows(2).all(|pair| pair[0].key < pair[1].key) {
        return Err(ProfileError::NonCanonicalOrder);
    }
    let selected = providers
        .iter()
        .filter(|provider| provider.claim_layer == profile_claim_layer)
        .map(|provider| provider.key.clone())
        .collect::<Vec<_>>();
    if selected != required {
        return Err(ProfileError::ClosureIncomplete);
    }
    let declared_packages = providers
        .iter()
        .map(|provider| provider.package.member_path.as_str())
        .collect::<BTreeSet<_>>();
    if bundle
        .members
        .iter()
        .any(|(path, member)| member.role == 13 && !declared_packages.contains(path.as_str()))
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    for fixture in fixtures {
        let provider = providers
            .iter()
            .find(|provider| {
                let identifies_provider = provider.key == fixture.provider;
                let supports_layer = provider.claim_layer == fixture.claim_layer;
                let supports_adapter = provider.adapter == fixture.subject_adapter;
                identifies_provider && supports_layer && supports_adapter
            })
            .ok_or(ProfileError::ClosureIncomplete)?;
        if provider
            .schemas
            .get(usize::from(fixture.family))
            .is_none_or(|schema| schema != &fixture.schema)
        {
            return Err(ProfileError::ClosureIncomplete);
        }
    }
    Ok(())
}

fn decode_provider_record(
    value: &Value,
    bundle: &VerifiedBundle,
) -> Result<ProviderRecord, ProfileError> {
    let fields = array(value, 7)?;
    let key = decode_provider_key(&Value::Array(fields[..4].to_vec()))?;
    let claim_layer =
        u8::try_from(uint(&fields[4])?).map_err(|_| ProfileError::FieldOutOfBounds)?;
    if claim_layer > 6 {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let adapter = decode_adapter(&fields[5])?;
    let package = decode_descriptor(&fields[6])?;
    if package.media_type != "application/cbor" {
        return Err(ProfileError::ClosureIncomplete);
    }
    let package_member = validate_descriptor_roles(bundle, &package, &[13])?;
    let schemas = validate_provider_package(bundle, package_member, &key, claim_layer, adapter)?;
    Ok(ProviderRecord {
        key,
        claim_layer,
        adapter,
        package,
        schemas,
    })
}

fn validate_provider_package(
    bundle: &VerifiedBundle,
    package: &VerifiedMember,
    key: &ProviderKey,
    claim_layer: u8,
    adapter: SubjectAdapterKind,
) -> Result<Vec<ArtifactDescriptor>, ProfileError> {
    let value = decode_canonical(&package.bytes)?;
    let fields = array(&value, 12)?;
    if text(&fields[0])? != "FPP1"
        || uint(&fields[1])? != 1
        || decode_provider_key(&fields[2])? != *key
        || uint(&fields[3])? != u64::from(claim_layer)
        || decode_adapter(&fields[4])? != adapter
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    let schema_values = array(&fields[5], 7)?;
    let schemas = schema_values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let fields = array(value, 2)?;
            if uint(&fields[0])? != index as u64 {
                return Err(ProfileError::NonCanonicalOrder);
            }
            let descriptor = decode_descriptor(&fields[1])?;
            validate_descriptor_roles(bundle, &descriptor, &[4])?;
            Ok(descriptor)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let support_roles = [5, 6, 7, 8, 9];
    let support = fields[6..11]
        .iter()
        .zip(support_roles)
        .map(
            |(value, role)| -> Result<ArtifactDescriptor, ProfileError> {
                let descriptor = decode_descriptor(value)?;
                validate_descriptor_roles(bundle, &descriptor, &[role])?;
                Ok(descriptor)
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    let unique_paths = schemas
        .iter()
        .chain(&support)
        .map(|artifact| artifact.member_path.as_str())
        .collect::<BTreeSet<_>>();
    if unique_paths.len() != schemas.len() + support.len() {
        return Err(ProfileError::NonCanonicalOrder);
    }
    let expected_digest = fixed_bytes::<32>(&fields[11])?;
    if !contract_digest_matches(
        b"PiglorOS.Conformance.ProviderPackage.v1",
        &Value::Array(fields[..11].to_vec()),
        expected_digest,
    ) {
        return Err(ProfileError::DigestMismatch);
    }
    Ok(schemas)
}

fn decode_adapter(value: &Value) -> Result<SubjectAdapterKind, ProfileError> {
    match uint(value)? {
        0 => Ok(SubjectAdapterKind::ExportedArtifact),
        1 => Ok(SubjectAdapterKind::PublicGatewayProtocol),
        2 => Ok(SubjectAdapterKind::PublicPluginProtocol),
        _ => Err(ProfileError::FieldOutOfBounds),
    }
}

type FixtureKey<'a> = (
    (&'a [u8], &'a [u8], u16, u16),
    u8,
    &'a [u8],
    [u8; 32],
    &'a [u8],
);

fn fixture_key(value: &Fixture) -> FixtureKey<'_> {
    (
        (
            value.provider.provider_id.as_bytes(),
            value.provider.contract_version.as_bytes(),
            value.provider.abi_major,
            value.provider.abi_minor,
        ),
        value.family,
        value.case_id.as_bytes(),
        value.execution_profile_digest,
        &value.modes,
    )
}

fn digest_list(value: &Value) -> Result<Vec<[u8; 32]>, ProfileError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > 64 {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let digests = values
        .iter()
        .map(fixed_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    if !digests.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ProfileError::NonCanonicalOrder);
    }
    Ok(digests)
}

fn string_list(value: &Value) -> Result<Vec<String>, ProfileError> {
    let values = array_values(value)?;
    let strings = values
        .iter()
        .map(identifier)
        .collect::<Result<Vec<_>, _>>()?;
    if !strings
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    Ok(strings)
}

fn identifier(value: &Value) -> Result<String, ProfileError> {
    let value = text(value)?;
    if valid_identifier(value) {
        Ok(value.to_owned())
    } else {
        Err(ProfileError::FieldOutOfBounds)
    }
}

fn byte_string(value: &Value) -> Result<Vec<u8>, ProfileError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(ProfileError::InvalidEncoding),
    }
}

fn bounded_code(value: &Value, maximum: u8) -> Result<u8, ProfileError> {
    let value = u8::try_from(uint(value)?).map_err(|_| ProfileError::InvalidEncoding)?;
    if value <= maximum {
        Ok(value)
    } else {
        Err(ProfileError::InvalidEncoding)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
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

fn valid_member_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value.split('/').count() <= 16
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 128)
}

fn valid_media_type(value: &str) -> bool {
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

fn semantic_version(value: &str, maximum_numeric_bytes: Option<usize>) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let (core_pre, build) = match value.split_once('+') {
        Some((left, right)) if !right.is_empty() && !right.contains('+') => (left, right),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, pre) = match core_pre.split_once('-') {
        Some((left, right)) if !right.is_empty() => (left, right),
        Some(_) => return false,
        None => (core_pre, ""),
    };
    let mut parts = core.split('.');
    parts
        .next()
        .is_some_and(|part| numeric_version(part, maximum_numeric_bytes))
        && parts
            .next()
            .is_some_and(|part| numeric_version(part, maximum_numeric_bytes))
        && parts
            .next()
            .is_some_and(|part| numeric_version(part, maximum_numeric_bytes))
        && parts.next().is_none()
        && version_identifiers(pre, true, maximum_numeric_bytes)
        && version_identifiers(build, false, maximum_numeric_bytes)
}

fn numeric_version(value: &str, maximum_bytes: Option<usize>) -> bool {
    !value.is_empty()
        && maximum_bytes.is_none_or(|maximum| value.len() <= maximum)
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn version_identifiers(
    value: &str,
    no_leading_zero: bool,
    maximum_numeric_bytes: Option<usize>,
) -> bool {
    value.is_empty()
        || value.split('.').all(|item| {
            !item.is_empty()
                && item
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!no_leading_zero
                    || !item.bytes().all(|byte| byte.is_ascii_digit())
                    || numeric_version(item, maximum_numeric_bytes))
        })
}
