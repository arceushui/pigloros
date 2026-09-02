//! Independent CPF1 profile decoding and selection.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;

use crate::evaluator_protocol::{
    array, array_values, bool_value, contract_digest, decode_canonical, fixed_bytes, text, uint,
    EvaluationRequest, ProtocolError, SubjectAdapterKind,
};
use crate::signed_bundle::{BundleError, VerifiedBundle};

const MAX_FIXTURES: usize = 65_536;
const MAX_AUXILIARY: usize = 64;
const MAX_CAPABILITIES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProviderKey {
    provider_id: String,
    contract_version: String,
    abi_major: u16,
    abi_minor: u16,
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
    pub values: [u64; 18],
}

impl EvaluatorHardCaps {
    /// Canonical digest of the exact eighteen-field hard-cap record.
    ///
    /// # Errors
    /// Returns an encoding failure if the selected record cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], ProfileError> {
        let value = Value::Array(
            self.values
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
            .zip(&self.values[10..])
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
    pub provider_id: String,
    pub provider_contract_version: String,
    pub provider_abi_major: u16,
    pub provider_abi_minor: u16,
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

    provider: ProviderKey,
    trust_policy_snapshot_digest: Option<[u8; 32]>,
    release_admission_digest: Option<[u8; 32]>,
    transition: Option<ProviderTransition>,
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

impl From<BundleError> for ProfileError {
    fn from(value: BundleError) -> Self {
        match value {
            BundleError::FieldOutOfBounds => Self::FieldOutOfBounds,
            BundleError::NonCanonicalOrder => Self::NonCanonicalOrder,
            BundleError::DigestMismatch => Self::DigestMismatch,
            BundleError::ClosureIncomplete => Self::ClosureIncomplete,
            BundleError::InvalidEncoding
            | BundleError::SignatureInvalid
            | BundleError::TrustPolicyMismatch => Self::InvalidEncoding,
        }
    }
}

impl Profile {
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
        validate_profile_header(fields)?;
        let actual_digest = contract_digest(
            b"PiglorOS.ConformanceProfile.v1",
            &Value::Array(fields[..17].to_vec()),
        )?;
        let profile_digest = fixed_bytes(&fields[17])?;
        if actual_digest != profile_digest
            || profile_digest != bundle.profile_digest
            || profile_digest != request.profile_digest
        {
            return Err(ProfileError::DigestMismatch);
        }

        let execution_profile_digests = digest_list(&fields[7])?;
        let (registry, required_providers) = decode_provider_binding(&fields[8])?;
        let (evaluator_artifact_digests, hard_caps) = decode_protocol(&fields[11])?;
        let fixtures = decode_fixtures(&fields[9], hard_caps)?;
        let allowed_divergences = decode_allowed_divergences(&fields[10])?;
        let trust_policy_snapshot_digest = decode_requirements(&fields[12])?;
        validate_optional_digest(&fields[16])?;
        validate_profile_relationships(
            &fixtures,
            &required_providers,
            &execution_profile_digests,
            &allowed_divergences,
        )?;
        validate_selected_caps(
            bytes.len(),
            &value,
            &registry,
            &fixtures,
            &allowed_divergences,
            hard_caps,
        )?;
        validate_support_closure(
            bundle,
            fields,
            &registry,
            &execution_profile_digests,
            evaluator_artifact_digests,
            trust_policy_snapshot_digest,
        )?;
        let profile = Self {
            profile_id: identifier(&fields[2])?,
            profile_digest,
            normative_spec_digest: fixed_bytes(&fields[5])?,
            execution_profile_digests,
            fixtures,
            evaluator_protocol_digest: evaluator_artifact_digests[0],
            evaluator_hard_caps: hard_caps,
            trust_policy_snapshot_digest,
            limitations_digest: fixed_bytes(&fields[14])?,
            provenance_digest: fixed_bytes(&fields[15])?,
        };
        profile.validate_request(request)?;
        profile.validate_bundle_closure(bundle, &registry)?;
        Ok(profile)
    }

    /// Select exactly the fixtures admitted by the request's adapter and
    /// ExecutionProfile in canonical CPF1 order.
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
            || request.output_capability.report_bytes_limit > self.evaluator_hard_caps.values[0]
            || request.output_capability.diagnostic_bytes_limit > self.evaluator_hard_caps.values[9]
        {
            return Err(ProfileError::DigestMismatch);
        }
        self.fixtures.iter().try_for_each(|fixture| {
            self.evaluator_hard_caps
                .admits(fixture.deterministic_budget)
        })
    }

    fn validate_bundle_closure(
        &self,
        bundle: &VerifiedBundle,
        registry: &ArtifactDescriptor,
    ) -> Result<(), ProfileError> {
        validate_descriptor(bundle, registry)?;
        for fixture in &self.fixtures {
            validate_descriptor(bundle, &fixture.schema)?;
            validate_descriptor(bundle, &fixture.payload)?;
            fixture
                .auxiliary
                .iter()
                .try_for_each(|descriptor| validate_descriptor(bundle, descriptor))?;
            if let StrictOracle::Output(descriptor) = &fixture.oracle {
                validate_descriptor(bundle, descriptor)?;
            }
        }
        Ok(())
    }
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
    let actual_digest = contract_digest(
        b"PiglorOS.Conformance.Fixture.v1",
        &Value::Array(fields[..23].to_vec()),
    )?;
    let fixture_digest = fixed_bytes(&fields[23])?;
    if actual_digest != fixture_digest {
        return Err(ProfileError::DigestMismatch);
    }
    let modes = array_values(&fields[7])?
        .iter()
        .map(|value| u8::try_from(uint(value)?).map_err(|_| ProfileError::InvalidEncoding))
        .collect::<Result<Vec<_>, _>>()?;
    if modes.is_empty()
        || !modes.windows(2).all(|pair| pair[0] < pair[1])
        || modes.iter().any(|mode| *mode > 3)
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    let subject_adapter = match uint(&fields[5])? {
        0 => SubjectAdapterKind::ExportedArtifact,
        1 => SubjectAdapterKind::PublicGatewayProtocol,
        2 => SubjectAdapterKind::PublicPluginProtocol,
        _ => return Err(ProfileError::InvalidEncoding),
    };
    let safety = array(&fields[17], 1)?;
    let capability = array(&fields[18], 2)?;
    let capability_ids = string_list(&capability[1])?;
    if capability_ids.len() > MAX_CAPABILITIES {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let provider = decode_provider_key(&fields[4])?;
    let claim_layer = bounded_code(&fields[2], 6)?;
    let family = bounded_code(&fields[3], 6)?;
    let expected_verification_outcome = bounded_code(&fields[12], 5)?;
    let replay_claim = bounded_code(&fields[14], 4)?;
    let redaction_state = bounded_code(&fields[15], 3)?;
    let deterministic_budget = DeterministicBudget::from_value(&fields[16])?;
    hard_caps.admits(deterministic_budget)?;
    let schema = decode_descriptor(&fields[8])?;
    let payload = decode_descriptor(&fields[9])?;
    let auxiliary = array_values(&fields[10])?
        .iter()
        .map(decode_descriptor)
        .collect::<Result<Vec<_>, _>>()?;
    let oracle = decode_oracle(&fields[11])?;
    validate_artifact_paths(&schema, &payload, &auxiliary, &oracle)?;
    let expected_verification_error = optional_failure(&fields[13])?;
    let watchdog_ms = uint(&safety[0])?;
    let network_allowed = bool_value(&capability[0])?;
    let trust_policy_snapshot_digest = optional_digest(&fields[19])?;
    let release_admission_digest = optional_digest(&fields[20])?;
    let provenance_digest = decode_provenance(&fields[21])?;
    let transition = optional_transition(&fields[22])?;
    let fixture = Fixture {
        case_id: identifier(&fields[0])?,
        mandatory: bool_value(&fields[1])?,
        claim_layer,
        family,
        provider_id: provider.provider_id.clone(),
        provider_contract_version: provider.contract_version.clone(),
        provider_abi_major: provider.abi_major,
        provider_abi_minor: provider.abi_minor,
        subject_adapter,
        execution_profile_digest: fixed_bytes(&fields[6])?,
        modes,
        schema,
        payload,
        auxiliary,
        oracle,
        expected_verification_outcome,
        expected_verification_error,
        replay_claim,
        redaction_state,
        deterministic_budget,
        watchdog_ms,
        network_allowed,
        capability_ids,
        provenance_digest,
        fixture_digest,
        provider,
        trust_policy_snapshot_digest,
        release_admission_digest,
        transition,
    };
    validate_fixture(&fixture).map(|()| fixture)
}

fn validate_profile_header(fields: &[Value]) -> Result<(), ProfileError> {
    if text(&fields[0])? != "CPF1" || uint(&fields[1])? != 1 {
        return Err(ProfileError::UnsupportedVersion);
    }
    if !valid_identifier(text(&fields[2])?)
        || !semantic_version(text(&fields[3])?, Some(10))
        || uint(&fields[4])? != 0
        || [5, 6, 13, 14, 15]
            .into_iter()
            .map(|index| fixed_bytes::<32>(&fields[index]))
            .collect::<Result<Vec<_>, _>>()?
            .contains(&[0; 32])
    {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn decode_provider_binding(
    value: &Value,
) -> Result<(ArtifactDescriptor, Vec<ProviderKey>), ProfileError> {
    let fields = array(value, 2)?;
    let registry = decode_descriptor(&fields[0])?;
    let values = array_values(&fields[1])?;
    if values.is_empty() || values.len() > 256 {
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

fn decode_requirements(value: &Value) -> Result<[u8; 32], ProfileError> {
    let fields = array(value, 5)?;
    bool_value(&fields[0])?;
    bool_value(&fields[1])?;
    bool_value(&fields[2])?;
    let trust = fixed_bytes(&fields[3])?;
    let declaration = fixed_bytes(&fields[4])?;
    if trust == [0; 32] || declaration == [0; 32] {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(trust)
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
    if text(&fields[0])?.is_empty() || text(&fields[0])?.len() > 128 {
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
) -> Result<(), ProfileError> {
    let claim_layer = fixtures
        .first()
        .map(|fixture| fixture.claim_layer)
        .ok_or(ProfileError::ClosureIncomplete)?;
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
    if inventory
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
                    || expected.owner_id == fixture.provider_id
                        && expected.contract_version == fixture.provider_contract_version)
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
        || match fixture.redaction_state {
            0 => true,
            1 => fixture.replay_claim == 1,
            2 => fixture.replay_claim == 2,
            3 => fixture.replay_claim == 3,
            _ => false,
        };
    if coherent {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_downgrade_relationship(fixture: &Fixture) -> Result<(), ProfileError> {
    if fixture.family != 5 {
        return if fixture.trust_policy_snapshot_digest.is_none()
            && fixture.release_admission_digest.is_none()
            && fixture.transition.is_none()
        {
            Ok(())
        } else {
            Err(ProfileError::ClosureIncomplete)
        };
    }
    let valid = fixture
        .trust_policy_snapshot_digest
        .is_some_and(|digest| digest != [0; 32])
        && fixture
            .release_admission_digest
            .is_some_and(|digest| digest != [0; 32])
        && fixture.transition.as_ref().is_some_and(|transition| {
            transition.to == fixture.provider
                && transition.from.provider_id == transition.to.provider_id
                && transition.from.contract_version == transition.to.contract_version
                && transition.from.abi_major == transition.to.abi_major
                && transition.from.abi_minor > transition.to.abi_minor
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
    registry: &ArtifactDescriptor,
    fixtures: &[Fixture],
    allowed: &[AllowedDivergence],
    caps: EvaluatorHardCaps,
) -> Result<(), ProfileError> {
    if u64::try_from(encoded_len).map_err(|_| ProfileError::FieldOutOfBounds)? > caps.values[0]
        || u64::try_from(value_depth(value)).map_err(|_| ProfileError::FieldOutOfBounds)?
            > caps.values[7]
        || u64::try_from(fixtures.len()).map_err(|_| ProfileError::FieldOutOfBounds)?
            > caps.values[1]
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let mut member_count = 1_u64;
    let mut total_bytes = registry.byte_length;
    validate_artifact_caps(registry, caps, &mut member_count, &mut total_bytes, false)?;
    for fixture in fixtures {
        for artifact in [&fixture.schema, &fixture.payload]
            .into_iter()
            .chain(&fixture.auxiliary)
        {
            validate_artifact_caps(artifact, caps, &mut member_count, &mut total_bytes, true)?;
        }
        if let StrictOracle::Output(output) = &fixture.oracle {
            validate_artifact_caps(output, caps, &mut member_count, &mut total_bytes, true)?;
        }
    }
    let coordinate_limit =
        usize::try_from(caps.values[8]).map_err(|_| ProfileError::FieldOutOfBounds)?;
    if member_count > caps.values[2]
        || total_bytes > caps.values[5]
        || allowed
            .iter()
            .any(|item| item.first_coordinate.len() > coordinate_limit)
    {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_artifact_caps(
    artifact: &ArtifactDescriptor,
    caps: EvaluatorHardCaps,
    member_count: &mut u64,
    total_bytes: &mut u64,
    increment: bool,
) -> Result<(), ProfileError> {
    if increment {
        *member_count = member_count.saturating_add(1);
    }
    *total_bytes = if increment {
        total_bytes.saturating_add(artifact.byte_length)
    } else {
        *total_bytes
    };
    if u64::try_from(artifact.member_path.len()).map_err(|_| ProfileError::FieldOutOfBounds)?
        > caps.values[3]
        || artifact.byte_length > caps.values[4]
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

fn validate_support_closure(
    bundle: &VerifiedBundle,
    profile_fields: &[Value],
    registry: &ArtifactDescriptor,
    execution_profiles: &[[u8; 32]],
    evaluator_artifacts: [[u8; 32]; 3],
    trust_policy_digest: [u8; 32],
) -> Result<(), ProfileError> {
    if registry.member_path != "authority/fixture-provider-registry.fpr1"
        || registry.media_type != "application/cbor"
    {
        return Err(ProfileError::ClosureIncomplete);
    }
    let support = [
        (
            "support/normative-requirements.md",
            3,
            fixed_bytes(&profile_fields[5])?,
        ),
        (
            "authority/execution-matrix.json",
            11,
            fixed_bytes(&profile_fields[6])?,
        ),
        (
            "support/fixture-family-contract.json",
            18,
            fixed_bytes(&profile_fields[13])?,
        ),
        (
            "support/limitations.md",
            9,
            fixed_bytes(&profile_fields[14])?,
        ),
        (
            "support/publication-review.json",
            8,
            fixed_bytes(&profile_fields[15])?,
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
        (registry.member_path.as_str(), 12, registry.digest),
        (
            "authority/trust-policy-snapshot.tps1",
            15,
            trust_policy_digest,
        ),
    ];
    for (path, role, digest) in support {
        validate_member_binding(bundle, path, role, digest)?;
    }
    let actual_execution_profiles = bundle
        .members
        .values()
        .filter(|member| member.role == 14)
        .map(|member| member.digest)
        .collect::<BTreeSet<_>>();
    let declared_execution_profiles = execution_profiles.iter().copied().collect::<BTreeSet<_>>();
    if actual_execution_profiles == declared_execution_profiles
        && actual_execution_profiles.len() == execution_profiles.len()
    {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
}

fn validate_member_binding(
    bundle: &VerifiedBundle,
    path: &str,
    role: u8,
    digest: [u8; 32],
) -> Result<(), ProfileError> {
    if bundle
        .member(path)
        .is_some_and(|member| member.role == role && member.digest == digest)
    {
        Ok(())
    } else {
        Err(ProfileError::ClosureIncomplete)
    }
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
    if member_path.is_empty()
        || !valid_member_path(&member_path)
        || !valid_media_type(&media_type)
        || uint(&fields[2])? == 0
        || uint(&fields[2])? > 64 * 1024 * 1024
        || fixed_bytes::<32>(&fields[3])? == [0; 32]
    {
        return Err(ProfileError::FieldOutOfBounds);
    }
    Ok(ArtifactDescriptor {
        member_path,
        media_type,
        byte_length: uint(&fields[2])?,
        digest: fixed_bytes(&fields[3])?,
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
    Ok(EvaluatorHardCaps { values })
}

fn validate_descriptor(
    bundle: &VerifiedBundle,
    descriptor: &ArtifactDescriptor,
) -> Result<(), ProfileError> {
    let member = bundle
        .member(&descriptor.member_path)
        .ok_or(ProfileError::ClosureIncomplete)?;
    if u64::try_from(member.bytes.len()).map_err(|_| ProfileError::FieldOutOfBounds)?
        != descriptor.byte_length
        || member.digest != descriptor.digest
    {
        Err(ProfileError::DigestMismatch)
    } else {
        Ok(())
    }
}

fn fixture_key(value: &Fixture) -> ((&[u8], &[u8], u16, u16), u8, &[u8], [u8; 32], &[u8]) {
    (
        (
            value.provider_id.as_bytes(),
            value.provider_contract_version.as_bytes(),
            value.provider_abi_major,
            value.provider_abi_minor,
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
    if !valid_identifier(value) {
        Err(ProfileError::FieldOutOfBounds)
    } else {
        Ok(value.to_owned())
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
