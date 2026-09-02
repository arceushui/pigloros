pub mod support;

use std::error::Error;

use ciborium::value::Value;
use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, EvaluatorError, EvaluatorIdentity, ResourceUsage,
    SubjectAdapter, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{
    CaseStatus, ConformanceReport, EvaluationRequest, IndependenceEvidence, ProtocolError,
    SubjectAdapterKind,
};
use pos_reference::profile::ProfileError;
use pos_reference::signed_bundle::BundleError;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn public_error_boundaries_preserve_closed_failure_classes() {
    assert_eq!(
        BundleError::from(ProtocolError::FieldOutOfBounds),
        BundleError::FieldOutOfBounds
    );
    assert_eq!(
        BundleError::from(ProtocolError::NonCanonicalOrder),
        BundleError::NonCanonicalOrder
    );
    assert_eq!(
        BundleError::from(ProtocolError::DigestMismatch),
        BundleError::DigestMismatch
    );
    assert_eq!(
        BundleError::from(ProtocolError::UnsupportedVersion),
        BundleError::InvalidEncoding
    );
    assert_eq!(
        BundleError::from(ProtocolError::InvalidEncoding),
        BundleError::InvalidEncoding
    );

    assert_eq!(
        ProfileError::from(ProtocolError::UnsupportedVersion),
        ProfileError::UnsupportedVersion
    );
    assert_eq!(
        ProfileError::from(ProtocolError::FieldOutOfBounds),
        ProfileError::FieldOutOfBounds
    );
    assert_eq!(
        ProfileError::from(ProtocolError::NonCanonicalOrder),
        ProfileError::NonCanonicalOrder
    );
    assert_eq!(
        ProfileError::from(ProtocolError::DigestMismatch),
        ProfileError::DigestMismatch
    );
    assert_eq!(
        ProfileError::from(ProtocolError::InvalidEncoding),
        ProfileError::InvalidEncoding
    );

    for error in [
        ProtocolError::InvalidEncoding,
        ProtocolError::UnsupportedVersion,
        ProtocolError::FieldOutOfBounds,
        ProtocolError::NonCanonicalOrder,
        ProtocolError::DigestMismatch,
    ] {
        assert_eq!(EvaluatorError::from(error), EvaluatorError::Request);
    }
}

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

fn assert_report_rejected(
    template: &ConformanceReport,
    update: impl FnOnce(&mut ConformanceReport),
    expected: ProtocolError,
) {
    let mut report = template.clone();
    update(&mut report);
    assert_eq!(report.to_canonical_cbor(), Err(expected));
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

fn replace_path(value: &mut Value, path: &[usize], replacement: Value) -> TestResult {
    let (&index, remainder) = path.split_first().ok_or("test path is empty")?;
    let Value::Array(fields) = value else {
        return Err("test path does not select an array".into());
    };
    let field = fields
        .get_mut(index)
        .ok_or("test path index is out of bounds")?;
    if remainder.is_empty() {
        *field = replacement;
        Ok(())
    } else {
        replace_path(field, remainder, replacement)
    }
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
fn request_round_trips_every_adapter_and_optional_identity_shape() -> TestResult {
    for adapter in [
        SubjectAdapterKind::ExportedArtifact,
        SubjectAdapterKind::PublicGatewayProtocol,
        SubjectAdapterKind::PublicPluginProtocol,
    ] {
        let mut request = valid_request()?;
        request.subject_adapter = adapter;
        request.implementation.organization_id = Some("test-organization".to_owned());
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
        let encoded = request.to_canonical_cbor()?;
        assert_eq!(
            EvaluationRequest::from_canonical_cbor(&encoded),
            Ok(request)
        );
    }
    Ok(())
}

#[test]
fn request_rejects_each_identifier_boundary() -> TestResult {
    for identifier in [
        String::new(),
        "a".repeat(129),
        "café".to_owned(),
        "Invalid".to_owned(),
        "invalid@identifier".to_owned(),
    ] {
        let mut request = valid_request()?;
        request.implementation.implementation_id = identifier.clone();
        assert_eq!(
            request.to_canonical_cbor(),
            Err(ProtocolError::FieldOutOfBounds)
        );
        let mut request = valid_request()?;
        request.implementation.organization_id = Some(identifier);
        assert_eq!(
            request.to_canonical_cbor(),
            Err(ProtocolError::FieldOutOfBounds)
        );
    }
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
fn public_decoders_reject_each_canonical_cbor_framing_boundary() {
    let mut excessive_depth = vec![0x81; 66];
    excessive_depth.push(0x00);
    let malformed = [
        Vec::new(),
        vec![0xff],
        vec![0x81],
        vec![0x58, 0x02, 0x01],
        vec![0x78, 0x02, b'a'],
        vec![0x9a, 0x00, 0x01, 0x00, 0x01],
        vec![0xa0],
        vec![0xc0, 0x00],
        vec![0xfa, 0x00, 0x00, 0x00, 0x00],
        vec![0x18, 0x00],
        vec![0x80, 0x00],
        excessive_depth,
    ];
    for bytes in malformed {
        assert!(EvaluationRequest::from_canonical_cbor(&bytes).is_err());
        assert!(ConformanceReport::from_canonical_cbor(&bytes).is_err());
    }
}

#[test]
fn request_and_report_decoders_reject_wrong_types_at_every_required_field() -> TestResult {
    let request_bytes = valid_request()?.to_canonical_cbor()?;
    let request = decoded_value(&request_bytes)?;
    for path in (0..14)
        .map(|index| vec![index])
        .chain((0..5).map(|index| vec![7, index]))
        .chain((0..3).map(|index| vec![10, index]))
    {
        let mut changed = request.clone();
        replace_path(&mut changed, &path, Value::Null)?;
        assert!(EvaluationRequest::from_canonical_cbor(&canonical(&changed)?).is_err());
    }

    let report_bytes = valid_report()?.to_canonical_cbor()?;
    let report = decoded_value(&report_bytes)?;
    for (path, replacement) in (0..24)
        .map(|index| (vec![index], Value::Null))
        .chain((0..6).map(|index| (vec![11, index], Value::Bool(false))))
        .chain((0..6).map(|index| (vec![12, index], Value::Null)))
        .chain((0..14).map(|index| (vec![13, 0, index], Value::Bool(false))))
    {
        let mut changed = report.clone();
        replace_path(&mut changed, &path, replacement)?;
        assert!(ConformanceReport::from_canonical_cbor(&canonical(&changed)?).is_err());
    }
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

#[test]
fn report_rejects_public_identity_reviewer_and_case_identifier_boundaries() -> TestResult {
    let valid = valid_report()?;

    assert_report_rejected(
        &valid,
        |report| report.implementation.implementation_id = "Invalid".to_owned(),
        ProtocolError::FieldOutOfBounds,
    );
    assert_report_rejected(
        &valid,
        |report| report.independence.reviewer_ids[0] = "Invalid".to_owned(),
        ProtocolError::FieldOutOfBounds,
    );
    assert_report_rejected(
        &valid,
        |report| report.cases[0].case_id = "Invalid".to_owned(),
        ProtocolError::FieldOutOfBounds,
    );
    Ok(())
}

#[test]
fn report_decoder_rejects_each_outer_and_nested_contract_shape() -> TestResult {
    let encoded = valid_report()?.to_canonical_cbor()?;
    let valid = decoded_value(&encoded)?;
    for (path, replacement, expected) in [
        (
            vec![0],
            Value::Text("CNR0".to_owned()),
            ProtocolError::UnsupportedVersion,
        ),
        (
            vec![1],
            Value::Integer(2_u64.into()),
            ProtocolError::UnsupportedVersion,
        ),
        (
            vec![13, 0],
            Value::Array(Vec::new()),
            ProtocolError::InvalidEncoding,
        ),
        (
            vec![13, 0, 5],
            Value::Integer(5_u64.into()),
            ProtocolError::InvalidEncoding,
        ),
        (vec![12, 5, 0], Value::Null, ProtocolError::InvalidEncoding),
    ] {
        let mut changed = valid.clone();
        replace_path(&mut changed, &path, replacement)?;
        assert_eq!(
            ConformanceReport::from_canonical_cbor(&canonical(&changed)?),
            Err(expected)
        );
    }

    let mut wrong_width = valid;
    let Value::Array(fields) = &mut wrong_width else {
        return Err("report is not an array".into());
    };
    fields.pop();
    assert_eq!(
        ConformanceReport::from_canonical_cbor(&canonical(&wrong_width)?),
        Err(ProtocolError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn report_rejects_every_top_level_and_independence_boundary() -> TestResult {
    let valid = valid_report()?;
    assert_report_rejected(
        &valid,
        |report| report.replay_claim = 5,
        ProtocolError::FieldOutOfBounds,
    );
    assert_report_rejected(
        &valid,
        |report| report.redaction_state = 4,
        ProtocolError::FieldOutOfBounds,
    );
    for index in 0..10 {
        assert_report_rejected(
            &valid,
            |report| match index {
                0 => report.subject_artifact_digest = [0; 32],
                1 => report.profile_digest = [0; 32],
                2 => report.normative_spec_digest = [0; 32],
                3 => report.execution_profile_digest = [0; 32],
                4 => report.fixture_bundle_digest = [0; 32],
                5 => report.evaluator_source_digest = [0; 32],
                6 => report.evaluator_binary_digest = [0; 32],
                7 => report.evaluator_protocol_digest = [0; 32],
                8 => report.limitations_digest = [0; 32],
                _ => report.provenance_digest = [0; 32],
            },
            ProtocolError::FieldOutOfBounds,
        );
    }
    for update in 0..4 {
        assert_report_rejected(
            &valid,
            |report| match update {
                0 => report.independence.declaration_digest = [0; 32],
                1 => report.independence.shared_code_audit_digest = [0; 32],
                2 => report.independence.reviewer_ids.clear(),
                _ => {
                    report.independence.reviewer_ids = (0..33)
                        .map(|value| format!("reviewer-{value:02}"))
                        .collect();
                }
            },
            ProtocolError::FieldOutOfBounds,
        );
    }
    Ok(())
}

#[test]
fn report_rejects_every_case_bound_and_evidence_boundary() -> TestResult {
    let valid = valid_report()?;
    for update in 0..10 {
        assert_report_rejected(
            &valid,
            |report| match update {
                0 => report.cases[0].fixture_digest = [0; 32],
                1 => report.cases[0].execution_profile_digest = [0; 32],
                2 => report.cases[0].provenance_digest = [0; 32],
                3 => report.cases[0].mode = 4,
                4 => report.cases[0].claim_layer = 7,
                5 => report.cases[0].replay_claim = 5,
                6 => report.cases[0].redaction_state = 4,
                7 => report.cases[0].expected_error = Some(14),
                8 => report.cases[0].actual_error = Some(14),
                _ => report.cases[0].first_coordinate = Some(vec![1; 129]),
            },
            ProtocolError::FieldOutOfBounds,
        );
    }
    assert_report_rejected(
        &valid,
        |report| {
            report.cases[0].outcome = CaseStatus::Fail;
            report.cases[0].expected_digest = None;
            report.cases[0].actual_digest = None;
        },
        ProtocolError::InvalidEncoding,
    );
    assert_report_rejected(
        &valid,
        |report| {
            report.cases[0].redaction_state = 1;
            report.cases[0].replay_claim = 2;
        },
        ProtocolError::InvalidEncoding,
    );
    Ok(())
}
