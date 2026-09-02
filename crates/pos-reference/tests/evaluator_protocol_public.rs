pub mod support;

use std::error::Error;

use ciborium::value::Value;
use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, EvaluatorIdentity, ResourceUsage, SubjectAdapter,
    SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{
    CaseStatus, ConformanceReport, EvaluationRequest, IndependenceEvidence, ProtocolError,
    SubjectAdapterKind,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct PassingAdapter {
    subject_digest: [u8; 32],
    output: Vec<u8>,
}

impl SubjectAdapter for PassingAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, _: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        Ok(SubjectObservation {
            result: SubjectResult::Output(self.output.clone()),
            usage: ResourceUsage::default(),
        })
    }
}

fn evaluator_identity() -> EvaluatorIdentity {
    EvaluatorIdentity {
        source_digest: [61; 32],
        binary_digest: [62; 32],
        independence: IndependenceEvidence {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [63; 32],
            shared_code_audit_digest: [64; 32],
            reviewer_ids: vec!["reviewer-one".to_owned()],
        },
    }
}

fn valid_request() -> TestResult<EvaluationRequest> {
    let corpus = support::corpus()?;
    Ok(EvaluationRequest::from_canonical_cbor(&corpus.request)?)
}

fn valid_report() -> TestResult<ConformanceReport> {
    let corpus = support::corpus()?;
    let mut adapter = PassingAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    Ok(evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut adapter,
    )?
    .report)
}

fn reseal(report: &mut ConformanceReport) -> TestResult {
    report.replay_claim = report
        .cases
        .iter()
        .map(|case| case.replay_claim)
        .max()
        .ok_or("report has no cases")?;
    report.redaction_state = report
        .cases
        .iter()
        .map(|case| case.redaction_state)
        .max()
        .ok_or("report has no cases")?;
    report.report_digest = report.digest()?;
    Ok(())
}

fn canonical(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn decoded_value(bytes: &[u8]) -> TestResult<Value> {
    Ok(ciborium::from_reader(bytes)?)
}

fn replace_field(value: &mut Value, index: usize, replacement: Value) -> TestResult {
    let Value::Array(fields) = value else {
        return Err("test value is not an array".into());
    };
    *fields
        .get_mut(index)
        .ok_or("test field index is out of bounds")? = replacement;
    Ok(())
}

#[test]
fn request_rejects_every_public_identity_and_capability_boundary() -> TestResult {
    let valid = valid_request()?;

    let mut request = valid.clone();
    request.request_id = [0; 16];
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut request = valid.clone();
    request.profile_digest = [0; 32];
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    for (report_limit, diagnostic_limit) in [(0, 0), (16 * 1024 * 1024 + 1, 0), (1, 1_048_577)] {
        let mut request = valid.clone();
        request.output_capability.report_bytes_limit = report_limit;
        request.output_capability.diagnostic_bytes_limit = diagnostic_limit;
        assert_eq!(
            request.to_canonical_cbor(),
            Err(ProtocolError::FieldOutOfBounds)
        );
    }

    let mut request = valid.clone();
    request.implementation.implementation_id = "Invalid".to_owned();
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut request = valid.clone();
    request.implementation.organization_id = Some(String::new());
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut request = valid.clone();
    request.implementation.build_digest = [0; 32];
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut request = valid.clone();
    request.output_capability.capability_digest = [9; 32];
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::DigestMismatch)
    );

    let mut request = valid;
    request.request_digest = [9; 32];
    assert_eq!(
        request.to_canonical_cbor(),
        Err(ProtocolError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn request_decoder_rejects_protocol_shapes_codes_and_noncanonical_bytes() -> TestResult {
    let request = valid_request()?;
    let encoded = request.to_canonical_cbor()?;
    let mut value = decoded_value(&encoded)?;

    for (index, replacement, expected) in [
        (
            0,
            Value::Text("EVR0".to_owned()),
            ProtocolError::UnsupportedVersion,
        ),
        (
            5,
            Value::Integer(9_u64.into()),
            ProtocolError::InvalidEncoding,
        ),
        (2, Value::Bytes(vec![1; 15]), ProtocolError::InvalidEncoding),
        (7, Value::Null, ProtocolError::InvalidEncoding),
    ] {
        let mut changed = value.clone();
        replace_field(&mut changed, index, replacement)?;
        assert_eq!(
            EvaluationRequest::from_canonical_cbor(&canonical(&changed)?),
            Err(expected)
        );
    }

    let Value::Array(fields) = &mut value else {
        return Err("request is not an array".into());
    };
    fields.pop();
    assert_eq!(
        EvaluationRequest::from_canonical_cbor(&canonical(&value)?),
        Err(ProtocolError::InvalidEncoding)
    );
    assert_eq!(
        EvaluationRequest::from_canonical_cbor(&[]),
        Err(ProtocolError::FieldOutOfBounds)
    );
    assert_eq!(
        EvaluationRequest::from_canonical_cbor(&[0x9f, 0xff]),
        Err(ProtocolError::InvalidEncoding)
    );
    assert_eq!(
        EvaluationRequest::from_canonical_cbor(&[0x81, 0x00, 0x00]),
        Err(ProtocolError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn report_round_trips_every_status_and_evidence_shape() -> TestResult {
    let template = valid_report()?;
    let base = template.cases[0].clone();
    let mut cases = Vec::new();

    let mut exact = base.clone();
    exact.case_id = "status-pass".to_owned();
    cases.push(exact);

    let mut typed = base.clone();
    typed.case_id = "status-typed".to_owned();
    typed.expected_digest = None;
    typed.actual_digest = None;
    typed.expected_error = Some(4);
    typed.actual_error = Some(4);
    cases.push(typed);

    let mut divergence = base.clone();
    divergence.case_id = "status-divergence".to_owned();
    divergence.outcome = CaseStatus::Fail;
    divergence.actual_digest = Some([91; 32]);
    divergence.first_coordinate = Some(vec![1, 2]);
    cases.push(divergence);

    let mut skipped = base.clone();
    skipped.case_id = "status-skip".to_owned();
    skipped.outcome = CaseStatus::Skip;
    skipped.actual_digest = Some([92; 32]);
    cases.push(skipped);

    let mut unavailable = base.clone();
    unavailable.case_id = "status-unavailable".to_owned();
    unavailable.outcome = CaseStatus::Unavailable;
    unavailable.actual_digest = Some([93; 32]);
    cases.push(unavailable);

    let mut not_applicable = base;
    not_applicable.case_id = "status-not-applicable".to_owned();
    not_applicable.outcome = CaseStatus::NotApplicable;
    not_applicable.actual_digest = Some([94; 32]);
    cases.push(not_applicable);

    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    let mut report = template;
    report.cases = cases;
    reseal(&mut report)?;
    let bytes = report.to_canonical_cbor()?;
    assert_eq!(ConformanceReport::from_canonical_cbor(&bytes), Ok(report));
    Ok(())
}

#[test]
fn report_accepts_each_bounded_redaction_contract() -> TestResult {
    let template = valid_report()?;
    for (redaction, replay) in [(1, 1), (1, 4), (2, 2), (2, 4), (3, 3), (3, 4)] {
        let mut report = template.clone();
        let case = &mut report.cases[0];
        case.redaction_state = redaction;
        case.replay_claim = replay;
        if redaction >= 2 {
            case.outcome = CaseStatus::Unavailable;
            case.expected_digest = None;
            case.actual_digest = None;
            case.expected_error = None;
            case.actual_error = None;
            case.first_coordinate = None;
        }
        reseal(&mut report)?;
        let bytes = report.to_canonical_cbor()?;
        assert_eq!(ConformanceReport::from_canonical_cbor(&bytes), Ok(report));
    }
    Ok(())
}

#[test]
fn report_rejects_invalid_identity_order_aggregate_and_case_contracts() -> TestResult {
    let valid = valid_report()?;

    let mut report = valid.clone();
    report.report_id = [0; 16];
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut report = valid.clone();
    report.cases.clear();
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut report = valid.clone();
    report.independence.technical_independent = false;
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut report = valid.clone();
    report.independence.reviewer_ids = vec!["same".to_owned(), "same".to_owned()];
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::NonCanonicalOrder)
    );

    let mut report = valid.clone();
    report.cases.swap(0, 1);
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::NonCanonicalOrder)
    );

    let mut report = valid.clone();
    report.replay_claim = 4;
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::DigestMismatch)
    );

    let mut report = valid.clone();
    report.cases[0].first_coordinate = Some(Vec::new());
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::FieldOutOfBounds)
    );

    let mut report = valid.clone();
    report.cases[0].actual_digest = None;
    report.cases[0].outcome = CaseStatus::Pass;
    assert_eq!(
        report.to_canonical_cbor(),
        Err(ProtocolError::InvalidEncoding)
    );

    let mut encoded = decoded_value(&valid.to_canonical_cbor()?)?;
    replace_field(&mut encoded, 14, Value::Integer(99_u64.into()))?;
    assert_eq!(
        ConformanceReport::from_canonical_cbor(&canonical(&encoded)?),
        Err(ProtocolError::FieldOutOfBounds)
    );
    Ok(())
}
