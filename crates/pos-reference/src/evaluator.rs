//! Resource-bounded black-box evaluation behind one public operation.

use std::cmp::Ordering;

use crate::evaluator_protocol::{
    CaseOutcome, CaseStatus, ConformanceReport, EvaluationRequest, IndependenceEvidence,
    ProtocolError, SubjectAdapterKind,
};
use crate::profile::{
    DeterministicBudget, Fixture, NamespacedFailure, Profile, ProfileError, StrictOracle,
};
use crate::signed_bundle::{verify_signed_bundle, BundleError, VerifiedBundle};

/// Evaluator build and review identity recorded in every CNR1 report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorIdentity {
    pub source_digest: [u8; 32],
    pub binary_digest: [u8; 32],
    pub independence: IndependenceEvidence,
}

/// Deterministic resource consumption reported by a public subject adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub cpu_fuel: u64,
    pub host_calls: u64,
    pub event_count: u64,
    pub output_bytes: u64,
    pub storage_bytes: u64,
    pub execution_steps: u64,
    pub simulation_time_ns: u64,
}

impl ResourceUsage {
    fn exceeds(self, budget: DeterministicBudget) -> bool {
        self.memory_bytes > budget.memory_bytes
            || self.cpu_fuel > budget.cpu_fuel
            || self.host_calls > budget.host_calls
            || self.event_count > budget.event_count
            || self.output_bytes > budget.output_bytes
            || self.storage_bytes > budget.storage_bytes
            || self.execution_steps > budget.execution_steps
            || self.simulation_time_ns > budget.simulation_time_ns
    }
}

/// Exact public inputs supplied to an adapter for one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseAttempt {
    pub case_id: String,
    pub claim_layer: u8,
    pub family: u8,
    pub mode: u8,
    pub fixture_digest: [u8; 32],
    pub schema: Vec<u8>,
    pub payload: Vec<u8>,
    pub auxiliary: Vec<Vec<u8>>,
    pub budget: DeterministicBudget,
    pub watchdog_ms: u64,
    pub network_allowed: bool,
    pub capability_ids: Vec<String>,
}

/// Closed semantic result returned by a public adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectResult {
    Output(Vec<u8>),
    Failure(NamespacedFailure),
    Divergence {
        classification: u8,
        first_coordinate: Vec<u8>,
    },
    Unavailable,
}

/// One adapter result together with deterministic counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectObservation {
    pub result: SubjectResult,
    pub usage: ResourceUsage,
}

/// Public-only subject seam. Implementations may speak the exported-artifact,
/// Gateway, or Plugin protocol, but receive no private Rust or storage handle.
pub trait SubjectAdapter {
    /// Identify the exact public protocol implemented by this adapter.
    fn kind(&self) -> SubjectAdapterKind;

    /// Identify the immutable implementation artifact reached by the adapter.
    fn subject_artifact_digest(&self) -> [u8; 32];

    /// Execute one independent, reset-budget fixture attempt.
    ///
    /// # Errors
    /// Returning an error means the subject operation was operationally
    /// unavailable; it is never converted into a deterministic typed failure.
    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError>;
}

/// Operational adapter failure. Details are intentionally bounded and cannot
/// carry subject payloads, credentials, host paths, or process output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterError {
    #[error("subject adapter was unavailable")]
    Unavailable,
    #[error("subject adapter watchdog expired")]
    WatchdogExpired,
    #[error("subject adapter protocol failed")]
    ProtocolFailure,
}

/// Bytes emitted by a successful evaluator process invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationArtifacts {
    pub report: ConformanceReport,
    pub report_bytes: Vec<u8>,
    pub report_digest: [u8; 32],
    pub diagnostic_bytes: Option<Vec<u8>>,
}

/// Closed failures that prevent a structurally valid CNR1 from being emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvaluatorError {
    #[error("EVR1 request is invalid")]
    Request,
    #[error("CFB1 bundle is invalid")]
    Bundle,
    #[error("CPF1 profile is invalid")]
    Profile,
    #[error("subject adapter identity does not match EVR1")]
    AdapterIdentity,
    #[error("CNR1 output exceeds its capability")]
    OutputLimit,
    #[error("CNR1 self-verification failed")]
    ReportVerification,
}

impl From<ProtocolError> for EvaluatorError {
    fn from(_: ProtocolError) -> Self {
        Self::Request
    }
}

impl From<BundleError> for EvaluatorError {
    fn from(_: BundleError) -> Self {
        Self::Bundle
    }
}

impl From<ProfileError> for EvaluatorError {
    fn from(_: ProfileError) -> Self {
        Self::Profile
    }
}

/// Execute a complete, independently parsed evaluation and emit reverified
/// CNR1 bytes. Exit/process policy belongs to the thin executable adapter.
///
/// # Errors
/// Returns a closed failure when the request, bundle, profile, adapter
/// identity, output capability, or emitted report is invalid. Individual
/// subject crashes and watchdog expiry become `Unavailable` case outcomes.
pub fn evaluate(
    request_bytes: &[u8],
    archive_bytes: &[u8],
    trust_policy_bytes: &[u8],
    evaluator: &EvaluatorIdentity,
    adapter: &mut impl SubjectAdapter,
) -> Result<EvaluationArtifacts, EvaluatorError> {
    let request = EvaluationRequest::from_canonical_cbor(request_bytes)?;
    if adapter.kind() != request.subject_adapter
        || adapter.subject_artifact_digest() != request.subject_artifact_digest
    {
        return Err(EvaluatorError::AdapterIdentity);
    }
    let bundle = verify_signed_bundle(archive_bytes, trust_policy_bytes, &request)?;
    let profile = Profile::from_bundle(&bundle, &request)?;
    let mut cases = evaluate_cases(&profile, &bundle, &request, adapter)?;
    cases.sort_by(compare_case_outcomes);

    let replay_claim = cases
        .iter()
        .map(|case| case.replay_claim)
        .max()
        .unwrap_or(4);
    let redaction_state = cases
        .iter()
        .map(|case| case.redaction_state)
        .max()
        .unwrap_or(3);
    let mut report = ConformanceReport {
        report_id: request.request_id,
        subject_artifact_digest: request.subject_artifact_digest,
        profile_digest: profile.profile_digest,
        normative_spec_digest: profile.normative_spec_digest,
        execution_profile_digest: request.execution_profile_digest,
        fixture_bundle_digest: bundle.archive_digest,
        evaluator_source_digest: evaluator.source_digest,
        evaluator_binary_digest: evaluator.binary_digest,
        evaluator_protocol_digest: profile.evaluator_protocol_digest,
        implementation: request.implementation.clone(),
        independence: evaluator.independence.clone(),
        cases,
        replay_claim,
        redaction_state,
        limitations_digest: profile.limitations_digest,
        provenance_digest: profile.provenance_digest,
        report_digest: [0; 32],
    };
    report.report_digest = report
        .digest()
        .map_err(|_| EvaluatorError::ReportVerification)?;
    let report_bytes = report
        .to_canonical_cbor()
        .map_err(|_| EvaluatorError::ReportVerification)?;
    if u64::try_from(report_bytes.len()).map_err(|_| EvaluatorError::OutputLimit)?
        > request.output_capability.report_bytes_limit
    {
        return Err(EvaluatorError::OutputLimit);
    }
    let verified = ConformanceReport::from_canonical_cbor(&report_bytes)
        .map_err(|_| EvaluatorError::ReportVerification)?;
    if verified != report {
        return Err(EvaluatorError::ReportVerification);
    }
    let diagnostic_bytes = diagnostics(&report, request.output_capability.diagnostic_bytes_limit)?;
    Ok(EvaluationArtifacts {
        report_digest: report.report_digest,
        report,
        report_bytes,
        diagnostic_bytes,
    })
}

fn evaluate_cases(
    profile: &Profile,
    bundle: &VerifiedBundle,
    request: &EvaluationRequest,
    adapter: &mut impl SubjectAdapter,
) -> Result<Vec<CaseOutcome>, EvaluatorError> {
    let mut outcomes = Vec::new();
    for fixture in profile.selected_fixtures(request) {
        if !fixture.modes.contains(&bundle.mode) {
            continue;
        }
        let attempt = case_attempt(bundle, fixture, bundle.mode)?;
        let observation = adapter.execute(&attempt);
        outcomes.push(case_outcome(fixture, bundle.mode, observation)?);
    }
    if outcomes.is_empty() {
        Err(EvaluatorError::Profile)
    } else {
        Ok(outcomes)
    }
}

fn case_attempt(
    bundle: &VerifiedBundle,
    fixture: &Fixture,
    mode: u8,
) -> Result<CaseAttempt, EvaluatorError> {
    let member_bytes = |path: &str| {
        bundle
            .member(path)
            .map(|member| member.bytes.clone())
            .ok_or(EvaluatorError::Bundle)
    };
    let schema = member_bytes(&fixture.schema.member_path)?;
    let payload = member_bytes(&fixture.payload.member_path)?;
    let auxiliary = fixture
        .auxiliary
        .iter()
        .map(|descriptor| member_bytes(&descriptor.member_path))
        .collect::<Result<Vec<_>, _>>()?;
    if mode == 1 && (fixture.network_allowed || !fixture.capability_ids.is_empty()) {
        return Err(EvaluatorError::Profile);
    }
    Ok(CaseAttempt {
        case_id: fixture.case_id.clone(),
        claim_layer: fixture.claim_layer,
        family: fixture.family,
        mode,
        fixture_digest: fixture.fixture_digest,
        schema,
        payload,
        auxiliary,
        budget: fixture.deterministic_budget,
        watchdog_ms: fixture.watchdog_ms,
        network_allowed: fixture.network_allowed,
        capability_ids: fixture.capability_ids.clone(),
    })
}

fn case_outcome(
    fixture: &Fixture,
    mode: u8,
    observation: Result<SubjectObservation, AdapterError>,
) -> Result<CaseOutcome, EvaluatorError> {
    let mut outcome = CaseOutcome {
        case_id: fixture.case_id.clone(),
        fixture_digest: fixture.fixture_digest,
        execution_profile_digest: fixture.execution_profile_digest,
        mode,
        claim_layer: fixture.claim_layer,
        outcome: CaseStatus::Unavailable,
        first_coordinate: None,
        expected_digest: None,
        actual_digest: None,
        expected_error: None,
        actual_error: None,
        replay_claim: fixture.replay_claim,
        redaction_state: fixture.redaction_state,
        provenance_digest: fixture.provenance_digest,
    };
    match &fixture.oracle {
        StrictOracle::Output(expected) => outcome.expected_digest = Some(expected.digest),
        StrictOracle::Failure(expected) => {
            outcome.expected_digest = Some(failure_digest(expected)?);
        }
        StrictOracle::Divergence {
            classification,
            first_coordinate,
        } => {
            outcome.expected_digest = Some(expected_divergence_digest(
                *classification,
                first_coordinate,
            )?);
        }
    }
    if outcome.redaction_state >= 2 {
        outcome.expected_digest = None;
        return Ok(outcome);
    }
    let Ok(observation) = observation else {
        return Ok(outcome);
    };
    if observation.usage.exceeds(fixture.deterministic_budget) {
        outcome.outcome = CaseStatus::Fail;
        outcome.actual_error = Some(13);
        return Ok(outcome);
    }
    match (&fixture.oracle, observation.result) {
        (StrictOracle::Output(expected), SubjectResult::Output(actual)) => {
            let actual_digest = *blake3::hash(&actual).as_bytes();
            outcome.actual_digest = Some(actual_digest);
            outcome.outcome = if u64::try_from(actual.len())
                .map_err(|_| EvaluatorError::OutputLimit)?
                == expected.byte_length
                && actual_digest == expected.digest
            {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            };
        }
        (StrictOracle::Failure(expected), SubjectResult::Failure(actual)) => {
            let actual_digest = failure_digest(&actual)?;
            outcome.actual_digest = Some(actual_digest);
            outcome.outcome = if expected == &actual {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            };
        }
        (
            StrictOracle::Divergence {
                classification,
                first_coordinate,
            },
            SubjectResult::Divergence {
                classification: actual_classification,
                first_coordinate: actual_coordinate,
            },
        ) => {
            outcome.first_coordinate = Some(actual_coordinate.clone());
            outcome.actual_digest = Some(actual_divergence_digest(
                actual_classification,
                &actual_coordinate,
            )?);
            outcome.outcome = if *classification == actual_classification
                && first_coordinate == &actual_coordinate
            {
                CaseStatus::Pass
            } else {
                CaseStatus::Fail
            };
        }
        (_, SubjectResult::Unavailable) => {}
        _ => outcome.outcome = CaseStatus::Fail,
    }
    Ok(outcome)
}

fn failure_digest(value: &NamespacedFailure) -> Result<[u8; 32], EvaluatorError> {
    let mut bytes = b"PiglorOS.NamespacedFailure.v1\0".to_vec();
    for field in [&value.owner_id, &value.contract_version, &value.code_id] {
        let length = u64::try_from(field.len()).map_err(|_| EvaluatorError::OutputLimit)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn expected_divergence_digest(
    classification: u8,
    coordinate: &[u8],
) -> Result<[u8; 32], EvaluatorError> {
    divergence_digest(
        b"PiglorOS.ExpectedDivergence.v1\0",
        classification,
        coordinate,
    )
}

fn actual_divergence_digest(
    classification: u8,
    coordinate: &[u8],
) -> Result<[u8; 32], EvaluatorError> {
    divergence_digest(
        b"PiglorOS.ActualDivergence.v1\0",
        classification,
        coordinate,
    )
}

fn divergence_digest(
    domain: &[u8],
    classification: u8,
    coordinate: &[u8],
) -> Result<[u8; 32], EvaluatorError> {
    let mut bytes = domain.to_vec();
    bytes.push(classification);
    let length = u64::try_from(coordinate.len()).map_err(|_| EvaluatorError::OutputLimit)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(coordinate);
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn compare_case_outcomes(left: &CaseOutcome, right: &CaseOutcome) -> Ordering {
    left.case_id
        .as_bytes()
        .cmp(right.case_id.as_bytes())
        .then(left.mode.cmp(&right.mode))
        .then(left.claim_layer.cmp(&right.claim_layer))
        .then(left.fixture_digest.cmp(&right.fixture_digest))
}

fn diagnostics(report: &ConformanceReport, limit: u64) -> Result<Option<Vec<u8>>, EvaluatorError> {
    if limit == 0 {
        return Ok(None);
    }
    let unavailable = report
        .cases
        .iter()
        .filter(|case| case.outcome == CaseStatus::Unavailable)
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    let failed = report
        .cases
        .iter()
        .filter(|case| case.outcome == CaseStatus::Fail)
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "magic": "CND1",
        "version": 1,
        "report_digest": hexadecimal(&report.report_digest),
        "failed_case_ids": failed,
        "unavailable_case_ids": unavailable,
    });
    let bytes = serde_json::to_vec(&value).map_err(|_| EvaluatorError::ReportVerification)?;
    if u64::try_from(bytes.len()).map_err(|_| EvaluatorError::OutputLimit)? > limit {
        Err(EvaluatorError::OutputLimit)
    } else {
        Ok(Some(bytes))
    }
}

fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
