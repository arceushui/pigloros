//! Independent EVR1 request and CNR1 report codecs.
//!
//! This module intentionally owns its wire decoding instead of importing the
//! producer-side `pos-conformance` crate. The executable and external callers
//! therefore cross the same small public interface while the strict CBOR,
//! identity, ordering, and aggregate checks remain private.

use std::cmp::Ordering;
use std::io::Cursor;

use ciborium::value::Value;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASES: usize = 65_536;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_COORDINATE_BYTES: usize = 128;
const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;
const MAX_NESTING: usize = 32;

/// Closed failures emitted before any subject operation starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid canonical encoding")]
    InvalidEncoding,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("field exceeds its declared bound")]
    FieldOutOfBounds,
    #[error("records are not in canonical order")]
    NonCanonicalOrder,
    #[error("digest does not match canonical content")]
    DigestMismatch,
}

/// Public subject protocol selected by EVR1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SubjectAdapterKind {
    ExportedArtifact,
    PublicGatewayProtocol,
    PublicPluginProtocol,
}

impl SubjectAdapterKind {
    const fn from_code(code: u64) -> Result<Self, ProtocolError> {
        match code {
            0 => Ok(Self::ExportedArtifact),
            1 => Ok(Self::PublicGatewayProtocol),
            2 => Ok(Self::PublicPluginProtocol),
            _ => Err(ProtocolError::InvalidEncoding),
        }
    }

    /// Return the exact EVR1 wire discriminant.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::ExportedArtifact => 0,
            Self::PublicGatewayProtocol => 1,
            Self::PublicPluginProtocol => 2,
        }
    }
}

/// Digest-bound identity of the implementation under evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationIdentity {
    pub implementation_id: String,
    pub source_digest: [u8; 32],
    pub build_digest: [u8; 32],
    pub binary_digest: [u8; 32],
    pub public_contract_digest: [u8; 32],
    pub organization_id: Option<String>,
}

/// Authority to emit only bounded report and diagnostic bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputCapability {
    pub capability_digest: [u8; 32],
    pub report_bytes_limit: u64,
    pub diagnostic_bytes_limit: u64,
}

/// Exact public EVR1 request consumed by the standalone evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationRequest {
    pub request_id: [u8; 16],
    pub profile_digest: [u8; 32],
    pub fixture_bundle_digest: [u8; 32],
    pub subject_adapter: SubjectAdapterKind,
    pub subject_artifact_digest: [u8; 32],
    pub implementation: ImplementationIdentity,
    pub execution_profile_digest: [u8; 32],
    pub trust_policy_snapshot_digest: [u8; 32],
    pub output_capability: OutputCapability,
    pub evaluator_protocol_digest: [u8; 32],
    pub evaluator_hard_caps_digest: [u8; 32],
    pub request_digest: [u8; 32],
}

impl EvaluationRequest {
    /// Decode and fully validate an exact canonical EVR1 request.
    ///
    /// # Errors
    /// Returns a closed failure for malformed, noncanonical, oversized, or
    /// self-inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let value = decode_canonical(bytes)?;
        let fields = array(&value, 14)?;
        if text(&fields[0])? != "EVR1" || uint(&fields[1])? != 1 {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let request = Self {
            request_id: fixed_bytes(&fields[2])?,
            profile_digest: fixed_bytes(&fields[3])?,
            fixture_bundle_digest: fixed_bytes(&fields[4])?,
            subject_adapter: SubjectAdapterKind::from_code(uint(&fields[5])?)?,
            subject_artifact_digest: fixed_bytes(&fields[6])?,
            implementation: decode_identity(&fields[7])?,
            execution_profile_digest: fixed_bytes(&fields[8])?,
            trust_policy_snapshot_digest: fixed_bytes(&fields[9])?,
            output_capability: decode_output_capability(&fields[10])?,
            evaluator_protocol_digest: fixed_bytes(&fields[11])?,
            evaluator_hard_caps_digest: fixed_bytes(&fields[12])?,
            request_digest: fixed_bytes(&fields[13])?,
        };
        request.validate().map(|()| request)
    }

    /// Encode the exact canonical EVR1 request after validating it.
    ///
    /// # Errors
    /// Returns a closed failure when an identity, bound, or digest is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        encode(&request_value(self, true))
    }

    /// Compute the EVR1 self-digest over the request with a null digest field.
    ///
    /// # Errors
    /// Returns an encoding failure if the in-memory value cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], ProtocolError> {
        Ok(domain_digest(
            b"PiglorOS.EvaluatorRequest.v1",
            &encode(&request_value(self, false))?,
        ))
    }

    /// Derive the capability identity from every selected authority.
    ///
    /// # Errors
    /// Returns an encoding failure if the in-memory value cannot be encoded.
    pub fn expected_output_capability_digest(&self) -> Result<[u8; 32], ProtocolError> {
        let value = Value::Array(vec![
            bytes(&self.profile_digest),
            bytes(&self.fixture_bundle_digest),
            unsigned(self.subject_adapter.code()),
            bytes(&self.subject_artifact_digest),
            identity_value(&self.implementation),
            bytes(&self.execution_profile_digest),
            bytes(&self.trust_policy_snapshot_digest),
            bytes(&self.evaluator_protocol_digest),
            bytes(&self.evaluator_hard_caps_digest),
        ]);
        Ok(domain_digest(
            b"PiglorOS.EvaluatorOutputCapability.v1",
            &encode(&value)?,
        ))
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_identity(&self.implementation)?;
        let digests = [
            self.profile_digest,
            self.fixture_bundle_digest,
            self.subject_artifact_digest,
            self.execution_profile_digest,
            self.trust_policy_snapshot_digest,
            self.output_capability.capability_digest,
            self.evaluator_protocol_digest,
            self.evaluator_hard_caps_digest,
            self.request_digest,
        ];
        if self.request_id == [0; 16]
            || digests.contains(&[0; 32])
            || self.output_capability.report_bytes_limit == 0
            || self.output_capability.report_bytes_limit > 16 * 1024 * 1024
            || self.output_capability.diagnostic_bytes_limit > MAX_DIAGNOSTIC_BYTES
        {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        if self.output_capability.capability_digest != self.expected_output_capability_digest()?
            || self.request_digest != self.digest()?
        {
            return Err(ProtocolError::DigestMismatch);
        }
        Ok(())
    }
}

/// Independently declared evaluator/reviewer separation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependenceEvidence {
    pub technical_independent: bool,
    pub authorship_independent: bool,
    pub organizational_independent: bool,
    pub declaration_digest: [u8; 32],
    pub shared_code_audit_digest: [u8; 32],
    pub reviewer_ids: Vec<String>,
}

/// One exact CNR1 case status.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CaseStatus {
    Pass,
    Fail,
    Skip,
    Unavailable,
    NotApplicable,
}

impl CaseStatus {
    /// Return the exact CNR1 wire discriminant.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Skip => 2,
            Self::Unavailable => 3,
            Self::NotApplicable => 4,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Skip => 2,
            Self::Unavailable => 3,
            Self::NotApplicable => 4,
        }
    }
}

/// One exact fourteen-field CNR1 case result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseOutcome {
    pub case_id: String,
    pub fixture_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub mode: u8,
    pub claim_layer: u8,
    pub outcome: CaseStatus,
    pub first_coordinate: Option<Vec<u8>>,
    pub expected_digest: Option<[u8; 32]>,
    pub actual_digest: Option<[u8; 32]>,
    pub expected_error: Option<u8>,
    pub actual_error: Option<u8>,
    pub replay_claim: u8,
    pub redaction_state: u8,
    pub provenance_digest: [u8; 32],
}

/// Exact current CNR1 report emitted by the evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    pub report_id: [u8; 16],
    pub subject_artifact_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub normative_spec_digest: [u8; 32],
    pub execution_profile_digest: [u8; 32],
    pub fixture_bundle_digest: [u8; 32],
    pub evaluator_source_digest: [u8; 32],
    pub evaluator_binary_digest: [u8; 32],
    pub evaluator_protocol_digest: [u8; 32],
    pub implementation: ImplementationIdentity,
    pub independence: IndependenceEvidence,
    pub cases: Vec<CaseOutcome>,
    pub replay_claim: u8,
    pub redaction_state: u8,
    pub limitations_digest: [u8; 32],
    pub evaluator_build_provenance_digest: [u8; 32],
    pub report_digest: [u8; 32],
}

impl ConformanceReport {
    /// Encode and validate exact canonical CNR1 bytes.
    ///
    /// # Errors
    /// Returns a closed failure for invalid ordering, counts, identities, or
    /// self-digest.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        encode(&report_value(self, true))
    }

    /// Decode and validate exact canonical CNR1 bytes.
    ///
    /// # Errors
    /// Returns a closed failure for malformed, noncanonical, or inconsistent
    /// report bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let value = decode_canonical(bytes)?;
        decode_report(&value).and_then(|report| report.validate().map(|()| report))
    }

    /// Compute the report digest over fields zero through twenty-two.
    ///
    /// # Errors
    /// Returns an encoding failure if the report fields cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], ProtocolError> {
        Ok(domain_digest(
            b"PiglorOS.ConformanceReport.v1",
            &encode(&report_value(self, false))?,
        ))
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_identity(&self.implementation)?;
        validate_independence(&self.independence)?;
        if self.report_id == [0; 16]
            || self.cases.is_empty()
            || self.cases.len() > MAX_CASES
            || self.replay_claim > 4
            || self.redaction_state > 3
            || [
                self.subject_artifact_digest,
                self.profile_digest,
                self.normative_spec_digest,
                self.execution_profile_digest,
                self.fixture_bundle_digest,
                self.evaluator_source_digest,
                self.evaluator_binary_digest,
                self.evaluator_protocol_digest,
                self.limitations_digest,
                self.evaluator_build_provenance_digest,
                self.report_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(ProtocolError::FieldOutOfBounds);
        }
        let mut prior: Option<&CaseOutcome> = None;
        for case in &self.cases {
            validate_case(case)?;
            if prior.is_some_and(|value| compare_cases(value, case) != Ordering::Less) {
                return Err(ProtocolError::NonCanonicalOrder);
            }
            prior = Some(case);
        }
        let weakest_replay = self
            .cases
            .iter()
            .map(|case| case.replay_claim)
            .max()
            .unwrap_or(4);
        let weakest_redaction = self
            .cases
            .iter()
            .map(|case| case.redaction_state)
            .max()
            .unwrap_or(3);
        if self.replay_claim != weakest_replay
            || self.redaction_state != weakest_redaction
            || self.report_digest != self.digest()?
        {
            return Err(ProtocolError::DigestMismatch);
        }
        Ok(())
    }
}

fn validate_identity(value: &ImplementationIdentity) -> Result<(), ProtocolError> {
    validate_identifier(&value.implementation_id)?;
    if let Some(organization) = value.organization_id.as_deref() {
        validate_identifier(organization)?;
    }
    if [
        value.source_digest,
        value.build_digest,
        value.binary_digest,
        value.public_contract_digest,
    ]
    .contains(&[0; 32])
    {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    Ok(())
}

fn validate_case_evidence(value: &CaseOutcome) -> Result<(), ProtocolError> {
    if valid_redaction(value) && nonpass_has_difference(value) && evidence_matches_outcome(value) {
        Ok(())
    } else {
        Err(ProtocolError::InvalidEncoding)
    }
}

fn evidence_matches_outcome(value: &CaseOutcome) -> bool {
    value.outcome != CaseStatus::Pass
        || exact_evidence(value)
        || typed_failure_evidence(value)
        || allowed_divergence_evidence(value)
}

fn exact_evidence(value: &CaseOutcome) -> bool {
    value.expected_digest.is_some()
        && value.expected_digest == value.actual_digest
        && value.expected_error.is_none()
        && value.actual_error.is_none()
        && value.first_coordinate.is_none()
}

fn typed_failure_evidence(value: &CaseOutcome) -> bool {
    value.expected_digest.is_none()
        && value.actual_digest.is_none()
        && value.expected_error.is_some()
        && value.expected_error == value.actual_error
        && value.first_coordinate.is_none()
}

fn allowed_divergence_evidence(value: &CaseOutcome) -> bool {
    value.expected_digest.is_some()
        && value.actual_digest.is_some()
        && value.expected_digest != value.actual_digest
        && value.expected_error.is_none()
        && value.actual_error.is_none()
        && value.first_coordinate.is_some()
}

fn valid_redaction(value: &CaseOutcome) -> bool {
    match value.redaction_state {
        0 => true,
        1 => value.replay_claim == 1 || value.replay_claim == 4,
        2 => (value.replay_claim == 2 || value.replay_claim == 4) && empty_case_evidence(value),
        3 => {
            (value.replay_claim == 3 || value.replay_claim == 4)
                && value.outcome != CaseStatus::Pass
                && empty_case_evidence(value)
        }
        _ => false,
    }
}

fn nonpass_has_difference(value: &CaseOutcome) -> bool {
    value.outcome == CaseStatus::Pass
        || value.redaction_state >= 2
        || value.expected_digest != value.actual_digest
        || value.expected_error != value.actual_error
}

const fn empty_case_evidence(value: &CaseOutcome) -> bool {
    value.expected_digest.is_none()
        && value.actual_digest.is_none()
        && value.expected_error.is_none()
        && value.actual_error.is_none()
        && value.first_coordinate.is_none()
}

fn validate_independence(value: &IndependenceEvidence) -> Result<(), ProtocolError> {
    if !value.technical_independent
        || value.declaration_digest == [0; 32]
        || value.shared_code_audit_digest == [0; 32]
        || value.reviewer_ids.is_empty()
        || value.reviewer_ids.len() > 32
    {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    let mut prior: Option<&str> = None;
    for reviewer in &value.reviewer_ids {
        validate_identifier(reviewer)?;
        if prior.is_some_and(|previous| previous.as_bytes() >= reviewer.as_bytes()) {
            return Err(ProtocolError::NonCanonicalOrder);
        }
        prior = Some(reviewer);
    }
    Ok(())
}

fn validate_case(value: &CaseOutcome) -> Result<(), ProtocolError> {
    validate_identifier(&value.case_id)?;
    if value.fixture_digest == [0; 32]
        || value.execution_profile_digest == [0; 32]
        || value.provenance_digest == [0; 32]
        || value.mode > 3
        || value.claim_layer > 6
        || value.replay_claim > 4
        || value.redaction_state > 3
        || value.expected_error.is_some_and(|code| code > 13)
        || value.actual_error.is_some_and(|code| code > 13)
        || value.first_coordinate.as_ref().is_some_and(|coordinate| {
            coordinate.is_empty() || coordinate.len() > MAX_COORDINATE_BYTES
        })
    {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    validate_case_evidence(value)
}

fn compare_cases(left: &CaseOutcome, right: &CaseOutcome) -> Ordering {
    left.case_id
        .as_bytes()
        .cmp(right.case_id.as_bytes())
        .then(left.mode.cmp(&right.mode))
        .then(left.claim_layer.cmp(&right.claim_layer))
        .then(left.fixture_digest.cmp(&right.fixture_digest))
}

fn decode_report(value: &Value) -> Result<ConformanceReport, ProtocolError> {
    let fields = array(value, 24)?;
    if text(&fields[0])? != "CNR1" || uint(&fields[1])? != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let cases = array_values(&fields[13])?
        .iter()
        .map(decode_case)
        .collect::<Result<Vec<_>, _>>()?;
    let counts = [
        uint(&fields[14])?,
        uint(&fields[15])?,
        uint(&fields[16])?,
        uint(&fields[17])?,
        uint(&fields[18])?,
    ];
    let actual_counts = cases.iter().fold([0_u64; 5], |mut totals, case| {
        totals[case.outcome.index()] += 1;
        totals
    });
    if counts != actual_counts {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    Ok(ConformanceReport {
        report_id: fixed_bytes(&fields[2])?,
        subject_artifact_digest: fixed_bytes(&fields[3])?,
        profile_digest: fixed_bytes(&fields[4])?,
        normative_spec_digest: fixed_bytes(&fields[5])?,
        execution_profile_digest: fixed_bytes(&fields[6])?,
        fixture_bundle_digest: fixed_bytes(&fields[7])?,
        evaluator_source_digest: fixed_bytes(&fields[8])?,
        evaluator_binary_digest: fixed_bytes(&fields[9])?,
        evaluator_protocol_digest: fixed_bytes(&fields[10])?,
        implementation: decode_identity(&fields[11])?,
        independence: decode_independence(&fields[12])?,
        cases,
        replay_claim: u8_value(&fields[19])?,
        redaction_state: u8_value(&fields[20])?,
        limitations_digest: fixed_bytes(&fields[21])?,
        evaluator_build_provenance_digest: fixed_bytes(&fields[22])?,
        report_digest: fixed_bytes(&fields[23])?,
    })
}

fn decode_identity(value: &Value) -> Result<ImplementationIdentity, ProtocolError> {
    let fields = array(value, 6)?;
    Ok(ImplementationIdentity {
        implementation_id: identifier(&fields[0])?,
        source_digest: fixed_bytes(&fields[1])?,
        build_digest: fixed_bytes(&fields[2])?,
        binary_digest: fixed_bytes(&fields[3])?,
        public_contract_digest: fixed_bytes(&fields[4])?,
        organization_id: optional_text(&fields[5])?,
    })
}

fn decode_output_capability(value: &Value) -> Result<OutputCapability, ProtocolError> {
    let fields = array(value, 3)?;
    Ok(OutputCapability {
        capability_digest: fixed_bytes(&fields[0])?,
        report_bytes_limit: uint(&fields[1])?,
        diagnostic_bytes_limit: uint(&fields[2])?,
    })
}

fn decode_independence(value: &Value) -> Result<IndependenceEvidence, ProtocolError> {
    let fields = array(value, 6)?;
    Ok(IndependenceEvidence {
        technical_independent: bool_value(&fields[0])?,
        authorship_independent: bool_value(&fields[1])?,
        organizational_independent: bool_value(&fields[2])?,
        declaration_digest: fixed_bytes(&fields[3])?,
        shared_code_audit_digest: fixed_bytes(&fields[4])?,
        reviewer_ids: array_values(&fields[5])?
            .iter()
            .map(identifier)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn decode_case(value: &Value) -> Result<CaseOutcome, ProtocolError> {
    let fields = array(value, 14)?;
    let outcome = match uint(&fields[5])? {
        0 => CaseStatus::Pass,
        1 => CaseStatus::Fail,
        2 => CaseStatus::Skip,
        3 => CaseStatus::Unavailable,
        4 => CaseStatus::NotApplicable,
        _ => return Err(ProtocolError::InvalidEncoding),
    };
    Ok(CaseOutcome {
        case_id: identifier(&fields[0])?,
        fixture_digest: fixed_bytes(&fields[1])?,
        execution_profile_digest: fixed_bytes(&fields[2])?,
        mode: u8_value(&fields[3])?,
        claim_layer: u8_value(&fields[4])?,
        outcome,
        first_coordinate: optional_bytes(&fields[6])?,
        expected_digest: optional_fixed_bytes(&fields[7])?,
        actual_digest: optional_fixed_bytes(&fields[8])?,
        expected_error: optional_u8(&fields[9])?,
        actual_error: optional_u8(&fields[10])?,
        replay_claim: u8_value(&fields[11])?,
        redaction_state: u8_value(&fields[12])?,
        provenance_digest: fixed_bytes(&fields[13])?,
    })
}

fn request_value(value: &EvaluationRequest, include_digest: bool) -> Value {
    Value::Array(vec![
        Value::Text("EVR1".to_owned()),
        unsigned(1),
        bytes(&value.request_id),
        bytes(&value.profile_digest),
        bytes(&value.fixture_bundle_digest),
        unsigned(value.subject_adapter.code()),
        bytes(&value.subject_artifact_digest),
        identity_value(&value.implementation),
        bytes(&value.execution_profile_digest),
        bytes(&value.trust_policy_snapshot_digest),
        Value::Array(vec![
            bytes(&value.output_capability.capability_digest),
            unsigned(value.output_capability.report_bytes_limit),
            unsigned(value.output_capability.diagnostic_bytes_limit),
        ]),
        bytes(&value.evaluator_protocol_digest),
        bytes(&value.evaluator_hard_caps_digest),
        if include_digest {
            bytes(&value.request_digest)
        } else {
            Value::Null
        },
    ])
}

fn report_value(value: &ConformanceReport, include_digest: bool) -> Value {
    let counts = value.cases.iter().fold([0_u64; 5], |mut totals, case| {
        totals[case.outcome.index()] += 1;
        totals
    });
    let mut fields = vec![
        Value::Text("CNR1".to_owned()),
        unsigned(1),
        bytes(&value.report_id),
        bytes(&value.subject_artifact_digest),
        bytes(&value.profile_digest),
        bytes(&value.normative_spec_digest),
        bytes(&value.execution_profile_digest),
        bytes(&value.fixture_bundle_digest),
        bytes(&value.evaluator_source_digest),
        bytes(&value.evaluator_binary_digest),
        bytes(&value.evaluator_protocol_digest),
        identity_value(&value.implementation),
        independence_value(&value.independence),
        Value::Array(value.cases.iter().map(case_value).collect()),
    ];
    fields.extend(counts.map(unsigned));
    fields.extend([
        unsigned(u64::from(value.replay_claim)),
        unsigned(u64::from(value.redaction_state)),
        bytes(&value.limitations_digest),
        bytes(&value.evaluator_build_provenance_digest),
    ]);
    if include_digest {
        fields.push(bytes(&value.report_digest));
    }
    Value::Array(fields)
}

fn identity_value(value: &ImplementationIdentity) -> Value {
    Value::Array(vec![
        Value::Text(value.implementation_id.clone()),
        bytes(&value.source_digest),
        bytes(&value.build_digest),
        bytes(&value.binary_digest),
        bytes(&value.public_contract_digest),
        value
            .organization_id
            .as_ref()
            .map_or(Value::Null, |id| Value::Text(id.clone())),
    ])
}

fn independence_value(value: &IndependenceEvidence) -> Value {
    Value::Array(vec![
        Value::Bool(value.technical_independent),
        Value::Bool(value.authorship_independent),
        Value::Bool(value.organizational_independent),
        bytes(&value.declaration_digest),
        bytes(&value.shared_code_audit_digest),
        Value::Array(
            value
                .reviewer_ids
                .iter()
                .cloned()
                .map(Value::Text)
                .collect(),
        ),
    ])
}

fn case_value(value: &CaseOutcome) -> Value {
    Value::Array(vec![
        Value::Text(value.case_id.clone()),
        bytes(&value.fixture_digest),
        bytes(&value.execution_profile_digest),
        unsigned(u64::from(value.mode)),
        unsigned(u64::from(value.claim_layer)),
        unsigned(value.outcome.code()),
        optional_bytes_value(value.first_coordinate.as_deref()),
        optional_digest_value(value.expected_digest.as_ref()),
        optional_digest_value(value.actual_digest.as_ref()),
        optional_u8_value(value.expected_error),
        optional_u8_value(value.actual_error),
        unsigned(u64::from(value.replay_claim)),
        unsigned(u64::from(value.redaction_state)),
        bytes(&value.provenance_digest),
    ])
}

pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Value, ProtocolError> {
    decode_canonical_with_limit(bytes, MAX_DOCUMENT_BYTES)
}

pub(crate) fn decode_canonical_with_limit(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<Value, ProtocolError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    preflight_cbor(bytes, maximum_bytes, false)?;
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| ProtocolError::InvalidEncoding)?;
    if encode_with_limit(&value, maximum_bytes)? != bytes {
        return Err(ProtocolError::InvalidEncoding);
    }
    Ok(value)
}

fn read_cbor_length(bytes: &[u8], index: &mut usize, additional: u8) -> Result<u64, ProtocolError> {
    let width = match additional {
        value @ 0..=23 => return Ok(u64::from(value)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(ProtocolError::InvalidEncoding),
    };
    let encoded = bytes
        .get(*index..)
        .and_then(|remaining| remaining.get(..width))
        .ok_or(ProtocolError::InvalidEncoding)?;
    *index += width;
    let mut value = [0_u8; 8];
    value[8 - width..].copy_from_slice(encoded);
    Ok(u64::from_be_bytes(value))
}

fn preflight_cbor_item(
    bytes: &[u8],
    index: &mut usize,
    depth: usize,
    maximum_bytes: usize,
    allow_maps_and_tags: bool,
) -> Result<(), ProtocolError> {
    if depth > MAX_NESTING {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    let initial = bytes
        .get(*index)
        .copied()
        .ok_or(ProtocolError::InvalidEncoding)?;
    *index += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let length = read_cbor_length(bytes, index, additional)?;
    match major {
        0 | 1 => Ok(()),
        2 | 3 => preflight_bytes(bytes, index, length, maximum_bytes),
        4 => preflight_items(
            bytes,
            index,
            depth,
            length,
            maximum_bytes,
            allow_maps_and_tags,
        ),
        5 if allow_maps_and_tags => preflight_items(
            bytes,
            index,
            depth,
            length
                .checked_mul(2)
                .ok_or(ProtocolError::FieldOutOfBounds)?,
            maximum_bytes,
            allow_maps_and_tags,
        ),
        6 if allow_maps_and_tags => {
            preflight_cbor_item(bytes, index, depth + 1, maximum_bytes, allow_maps_and_tags)
        }
        7 if matches!(additional, 20..=22) => Ok(()),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

fn preflight_bytes(
    bytes: &[u8],
    index: &mut usize,
    length: u64,
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    let length = usize::try_from(length).map_err(|_| ProtocolError::FieldOutOfBounds)?;
    if length > maximum_bytes {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    bytes
        .get(*index..)
        .and_then(|remaining| remaining.get(..length))
        .ok_or(ProtocolError::InvalidEncoding)?;
    *index += length;
    Ok(())
}

fn preflight_items(
    bytes: &[u8],
    index: &mut usize,
    depth: usize,
    item_count: u64,
    maximum_bytes: usize,
    allow_maps_and_tags: bool,
) -> Result<(), ProtocolError> {
    let item_count = usize::try_from(item_count).map_err(|_| ProtocolError::FieldOutOfBounds)?;
    if item_count > MAX_CASES {
        return Err(ProtocolError::FieldOutOfBounds);
    }
    (0..item_count).try_for_each(|_| {
        preflight_cbor_item(bytes, index, depth + 1, maximum_bytes, allow_maps_and_tags)
    })
}

pub(crate) fn preflight_cbor(
    bytes: &[u8],
    maximum_bytes: usize,
    allow_maps_and_tags: bool,
) -> Result<(), ProtocolError> {
    let mut index = 0;
    preflight_cbor_item(bytes, &mut index, 0, maximum_bytes, allow_maps_and_tags)?;
    if index == bytes.len() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidEncoding)
    }
}

pub(crate) fn encode(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    encode_with_limit(value, MAX_DOCUMENT_BYTES)
}

pub(crate) fn encode_with_limit(
    value: &Value,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ProtocolError::InvalidEncoding)?;
    if bytes.len() > maximum_bytes {
        Err(ProtocolError::FieldOutOfBounds)
    } else {
        Ok(bytes)
    }
}

pub(crate) fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

pub(crate) fn contract_digest(domain: &[u8], value: &Value) -> Result<[u8; 32], ProtocolError> {
    let bytes = encode(value)?;
    let mut input = Vec::with_capacity(domain.len() + 9 + bytes.len());
    input.extend_from_slice(domain);
    input.push(0);
    let encoded_length = bytes.len() as u64;
    input.extend_from_slice(&encoded_length.to_be_bytes());
    input.extend_from_slice(&bytes);
    Ok(*blake3::hash(&input).as_bytes())
}

pub(crate) fn contract_digest_matches(domain: &[u8], value: &Value, expected: [u8; 32]) -> bool {
    contract_digest(domain, value).is_ok_and(|actual| actual == expected)
}

pub(crate) fn array(value: &Value, width: usize) -> Result<&[Value], ProtocolError> {
    match value {
        Value::Array(fields) if fields.len() == width => Ok(fields),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

pub(crate) fn array_values(value: &Value) -> Result<&[Value], ProtocolError> {
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

pub(crate) fn text(value: &Value) -> Result<&str, ProtocolError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

fn identifier(value: &Value) -> Result<String, ProtocolError> {
    let value = text(value)?;
    validate_identifier(value).map(|()| value.to_owned())
}

fn validate_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        Err(ProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

pub(crate) const fn bool_value(value: &Value) -> Result<bool, ProtocolError> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

pub(crate) fn uint(value: &Value) -> Result<u64, ProtocolError> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| ProtocolError::InvalidEncoding),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

fn u8_value(value: &Value) -> Result<u8, ProtocolError> {
    u8::try_from(uint(value)?).map_err(|_| ProtocolError::InvalidEncoding)
}

pub(crate) fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], ProtocolError> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidEncoding),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

fn optional_text(value: &Value) -> Result<Option<String>, ProtocolError> {
    match value {
        Value::Null => Ok(None),
        _ => identifier(value).map(Some),
    }
}

fn optional_bytes(value: &Value) -> Result<Option<Vec<u8>>, ProtocolError> {
    match value {
        Value::Null => Ok(None),
        Value::Bytes(value) => Ok(Some(value.clone())),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

fn optional_fixed_bytes<const N: usize>(value: &Value) -> Result<Option<[u8; N]>, ProtocolError> {
    match value {
        Value::Null => Ok(None),
        _ => fixed_bytes(value).map(Some),
    }
}

fn optional_u8(value: &Value) -> Result<Option<u8>, ProtocolError> {
    match value {
        Value::Null => Ok(None),
        _ => u8_value(value).map(Some),
    }
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn optional_bytes_value(value: Option<&[u8]>) -> Value {
    value.map_or(Value::Null, bytes)
}

fn optional_digest_value(value: Option<&[u8; 32]>) -> Value {
    value.map_or(Value::Null, |digest| bytes(digest))
}

fn optional_u8_value(value: Option<u8>) -> Value {
    value.map_or(Value::Null, |code| unsigned(u64::from(code)))
}
