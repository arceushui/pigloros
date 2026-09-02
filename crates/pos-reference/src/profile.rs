//! Independent CPF1 profile decoding and selection.

use ciborium::value::Value;

use crate::evaluator_protocol::{
    array, array_values, bool_value, contract_digest, decode_canonical, fixed_bytes, text, uint,
    EvaluationRequest, ProtocolError, SubjectAdapterKind,
};
use crate::signed_bundle::{BundleError, VerifiedBundle};

const MAX_FIXTURES: usize = 65_536;
const MAX_IDENTIFIER_BYTES: usize = 128;

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
            .any(|(request, maximum)| request > maximum)
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
    pub fixture_digest: [u8; 32],
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
        if text(&fields[0])? != "CPF1" || uint(&fields[1])? != 1 {
            return Err(ProfileError::UnsupportedVersion);
        }
        if uint(&fields[4])? != 0 {
            return Err(ProfileError::InvalidEncoding);
        }
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
        let fixtures = decode_fixtures(&fields[9])?;
        let protocol = array(&fields[11], 5)?;
        let hard_caps = decode_hard_caps(&protocol[4])?;
        let requirements = array(&fields[12], 5)?;
        let profile = Self {
            profile_id: identifier(&fields[2])?,
            profile_digest,
            normative_spec_digest: fixed_bytes(&fields[5])?,
            execution_profile_digests,
            fixtures,
            evaluator_protocol_digest: fixed_bytes(&protocol[1])?,
            evaluator_hard_caps: hard_caps,
            trust_policy_snapshot_digest: fixed_bytes(&requirements[3])?,
            limitations_digest: fixed_bytes(&fields[14])?,
            provenance_digest: fixed_bytes(&fields[15])?,
        };
        profile.validate_request(request)?;
        profile.validate_bundle_closure(bundle)?;
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

    fn validate_bundle_closure(&self, bundle: &VerifiedBundle) -> Result<(), ProfileError> {
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

fn decode_fixtures(value: &Value) -> Result<Vec<Fixture>, ProfileError> {
    let values = array_values(value)?;
    if values.is_empty() || values.len() > MAX_FIXTURES {
        return Err(ProfileError::FieldOutOfBounds);
    }
    let fixtures = values
        .iter()
        .map(decode_fixture)
        .collect::<Result<Vec<_>, _>>()?;
    if !fixtures
        .windows(2)
        .all(|pair| fixture_key(&pair[0]) < fixture_key(&pair[1]))
    {
        return Err(ProfileError::NonCanonicalOrder);
    }
    Ok(fixtures)
}

fn decode_fixture(value: &Value) -> Result<Fixture, ProfileError> {
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
    let provider = array(&fields[4], 4)?;
    let claim_layer = bounded_code(&fields[2], 6)?;
    let family = bounded_code(&fields[3], 6)?;
    let expected_verification_outcome = bounded_code(&fields[12], 5)?;
    let replay_claim = bounded_code(&fields[14], 4)?;
    let redaction_state = bounded_code(&fields[15], 3)?;
    let deterministic_budget = DeterministicBudget::from_value(&fields[16])?;
    Ok(Fixture {
        case_id: identifier(&fields[0])?,
        mandatory: bool_value(&fields[1])?,
        claim_layer,
        family,
        provider_id: identifier(&provider[0])?,
        provider_contract_version: identifier(&provider[1])?,
        provider_abi_major: u16::try_from(uint(&provider[2])?)
            .map_err(|_| ProfileError::FieldOutOfBounds)?,
        provider_abi_minor: u16::try_from(uint(&provider[3])?)
            .map_err(|_| ProfileError::FieldOutOfBounds)?,
        subject_adapter,
        execution_profile_digest: fixed_bytes(&fields[6])?,
        modes,
        schema: decode_descriptor(&fields[8])?,
        payload: decode_descriptor(&fields[9])?,
        auxiliary: array_values(&fields[10])?
            .iter()
            .map(decode_descriptor)
            .collect::<Result<Vec<_>, _>>()?,
        oracle: decode_oracle(&fields[11])?,
        expected_verification_outcome,
        expected_verification_error: optional_failure(&fields[13])?,
        replay_claim,
        redaction_state,
        deterministic_budget,
        watchdog_ms: uint(&safety[0])?,
        network_allowed: bool_value(&capability[0])?,
        capability_ids,
        fixture_digest,
    })
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
            let classification = bounded_code(&divergence[0], 8)?;
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
        || member_path.len() > 256
        || !member_path.is_ascii()
        || media_type.is_empty()
        || media_type.len() > 128
        || media_type.bytes().any(|byte| byte.is_ascii_uppercase())
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
    Ok(Some(NamespacedFailure {
        owner_id: identifier(&fields[0])?,
        contract_version: identifier(&fields[1])?,
        code_id: identifier(&fields[2])?,
    }))
}

fn decode_hard_caps(value: &Value) -> Result<EvaluatorHardCaps, ProfileError> {
    let fields = array(value, 18)?;
    let mut values = [0_u64; 18];
    for (target, field) in values.iter_mut().zip(fields) {
        *target = uint(field)?;
    }
    if values.contains(&0)
        || values[0] > 16 * 1024 * 1024
        || values[1] > 65_536
        || values[2] > 65_536
        || values[3] > 256
        || values[4] > 64 * 1024 * 1024
        || values[5] > 1024 * 1024 * 1024
        || values[6] > 100
        || values[7] > 32
        || values[8] > 128
        || values[9] > 1024 * 1024
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
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
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
