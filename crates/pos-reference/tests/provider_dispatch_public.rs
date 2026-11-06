//! ADR-062 Revision 8 slice N6 (#1234): exact ADR-068 provider dispatch at the public
//! `evaluate` seam.
//!
//! A selected fixture reaches its subject adapter only through exactly one
//! `FixtureExecutorV1` declaration naming its exact CPF1 provider ID, contract version, ABI
//! and schema digest. Every mismatch is a typed non-executed `Unavailable` case with no result
//! claim, and the adapter is never called for it. The tests use the signed test-provider
//! corpus and scripted adapters; the real Plugin worker half lives in
//! `apps/pos-plugin-worker/tests/provider_dispatch_public.rs`.

pub mod support;

use std::error::Error;
use std::io;
use std::sync::OnceLock;

use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, FixtureExecutorV1, ResourceUsage, SubjectAdapter,
    SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_build_identity::VerifiedEvaluatorBuildIdentity;
use pos_reference::evaluator_domain::SafeErrorCode;
use pos_reference::evaluator_protocol::{
    CaseOutcome, CaseStatus, ConformanceReport, EvaluationRequest, SubjectAdapterKind,
};
use support::Corpus;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

type Script = fn(&CaseAttempt, &[u8]) -> Result<SubjectObservation, AdapterError>;

const CASES: [&str; 7] = [
    "case-0", "case-1", "case-2", "case-3", "case-4", "case-5", "case-6",
];

/// A public adapter that records the cases it is asked to execute.
struct Recording {
    kind: SubjectAdapterKind,
    subject_digest: [u8; 32],
    output: Vec<u8>,
    script: Script,
    executed: Vec<String>,
}

impl Recording {
    fn new(corpus: &Corpus, kind: SubjectAdapterKind, script: Script) -> Self {
        Self {
            kind,
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output.clone(),
            script,
            executed: Vec::new(),
        }
    }
}

impl SubjectAdapter for Recording {
    fn kind(&self) -> SubjectAdapterKind {
        self.kind
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.executed.push(attempt.case_id.clone());
        (self.script)(attempt, &self.output)
    }
}

/// The faithful subject: it outputs the oracle of every case.
const FAITHFUL: Script = |_, output| {
    Ok(SubjectObservation {
        result: SubjectResult::Output(output.to_vec()),
        usage: ResourceUsage::default(),
    })
};

/// One declaration mismatch: its label, the edit, and the cases it leaves non-executed.
type Mismatch = (
    &'static str,
    fn(&mut FixtureExecutorV1),
    &'static [&'static str],
);

fn evaluator_identity() -> TestResult<VerifiedEvaluatorBuildIdentity> {
    static IDENTITY: OnceLock<Result<VerifiedEvaluatorBuildIdentity, String>> = OnceLock::new();
    match IDENTITY
        .get_or_init(|| support::verified_evaluator_identity().map_err(|error| error.to_string()))
    {
        Ok(identity) => Ok(identity.clone()),
        Err(error) => Err(io::Error::other(error.clone()).into()),
    }
}

fn run(
    corpus: &Corpus,
    request: &[u8],
    executors: &[FixtureExecutorV1],
    adapter: &mut Recording,
) -> TestResult<ConformanceReport> {
    Ok(evaluate(
        request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity()?,
        executors,
        adapter,
    )?
    .report)
}

fn case<'a>(report: &'a ConformanceReport, id: &str) -> TestResult<&'a CaseOutcome> {
    report
        .cases
        .iter()
        .find(|outcome| outcome.case_id == id)
        .ok_or_else(|| io::Error::other(format!("{id} is absent from the report")).into())
}

/// Assert that exactly the `unavailable` cases are non-executed with no result claim and were
/// never dispatched, and that every other case passed.
fn assert_dispatch(
    report: &ConformanceReport,
    adapter: &Recording,
    unavailable: &[&str],
    label: &str,
) -> TestResult {
    assert_eq!(report.cases.len(), CASES.len(), "{label}");
    for id in CASES {
        let outcome = case(report, id)?;
        if unavailable.contains(&id) {
            assert_eq!(outcome.outcome, CaseStatus::Unavailable, "{label}: {id}");
            assert_eq!(outcome.actual_digest, None, "{label}: {id}");
            assert_eq!(outcome.actual_error, None, "{label}: {id}");
            assert_eq!(outcome.first_coordinate, None, "{label}: {id}");
            assert!(
                !adapter.executed.iter().any(|seen| seen == id),
                "{label}: {id}"
            );
        } else {
            assert_eq!(outcome.outcome, CaseStatus::Pass, "{label}: {id}");
            assert!(
                adapter.executed.iter().any(|seen| seen == id),
                "{label}: {id}"
            );
        }
    }
    Ok(())
}

fn exported() -> FixtureExecutorV1 {
    support::test_executor(SubjectAdapterKind::ExportedArtifact)
}

#[test]
fn the_exact_cpf1_provider_identity_dispatches_every_case() -> TestResult {
    let corpus = support::corpus()?;
    let mut adapter = Recording::new(&corpus, SubjectAdapterKind::ExportedArtifact, FAITHFUL);
    let report = run(&corpus, &corpus.request, &[exported()], &mut adapter)?;
    assert_dispatch(&report, &adapter, &[], "exact identity")?;
    assert_eq!(adapter.executed.len(), CASES.len());
    Ok(())
}

#[test]
fn a_different_provider_contract_abi_or_schema_is_not_executed() -> TestResult {
    let corpus = support::corpus()?;
    let mismatches: [Mismatch; 9] = [
        (
            "provider id",
            |executor| executor.provider.provider_id = "other-provider".to_owned(),
            &CASES,
        ),
        (
            "contract version",
            |executor| executor.provider.contract_version = "1.0.1".to_owned(),
            &CASES,
        ),
        (
            "abi major",
            |executor| executor.provider.abi_major = 2,
            &CASES,
        ),
        (
            "abi minor",
            |executor| executor.provider.abi_minor = 0,
            &CASES,
        ),
        (
            "schema digest",
            |executor| executor.schema_digests[2] = [7; 32],
            &["case-2"],
        ),
        (
            "subject adapter",
            |executor| executor.subject_adapter = SubjectAdapterKind::PublicGatewayProtocol,
            &CASES,
        ),
        (
            "implementation digest",
            |executor| executor.implementation_digest = [7; 32],
            &CASES,
        ),
        (
            "undeclared capability",
            |executor| executor.capability_ids.clear(),
            &CASES,
        ),
        (
            "other capability",
            |executor| executor.capability_ids = vec!["mutate-subject".to_owned()],
            &CASES,
        ),
    ];
    for (label, mutate, unavailable) in mismatches {
        let mut executor = exported();
        mutate(&mut executor);
        let mut adapter = Recording::new(&corpus, SubjectAdapterKind::ExportedArtifact, FAITHFUL);
        let report = run(&corpus, &corpus.request, &[executor], &mut adapter)?;
        assert_dispatch(&report, &adapter, unavailable, label)?;
    }
    Ok(())
}

#[test]
fn a_missing_or_duplicated_executor_is_not_executed() -> TestResult {
    let corpus = support::corpus()?;
    let mut other_digest = exported();
    other_digest.implementation_digest = [7; 32];
    let registries = [
        ("no executor", Vec::new()),
        ("duplicate executor", vec![exported(), exported()]),
        ("same key twice", vec![exported(), other_digest]),
    ];
    for (label, executors) in registries {
        let mut adapter = Recording::new(&corpus, SubjectAdapterKind::ExportedArtifact, FAITHFUL);
        let report = run(&corpus, &corpus.request, &executors, &mut adapter)?;
        assert_dispatch(&report, &adapter, &CASES, label)?;
        assert!(adapter.executed.is_empty(), "{label}");
    }
    Ok(())
}

#[test]
fn each_public_protocol_dispatches_only_through_its_own_declaration() -> TestResult {
    let kinds = [
        SubjectAdapterKind::ExportedArtifact,
        SubjectAdapterKind::PublicGatewayProtocol,
        SubjectAdapterKind::PublicPluginProtocol,
    ];
    for kind in kinds {
        let corpus = support::corpus_for_adapter(kind)?;
        let mut adapter = Recording::new(&corpus, kind, FAITHFUL);
        let report = run(
            &corpus,
            &corpus.request,
            &support::test_executors(),
            &mut adapter,
        )?;
        assert_dispatch(&report, &adapter, &[], "own declaration")?;
        let others: Vec<FixtureExecutorV1> = kinds
            .iter()
            .filter(|other| **other != kind)
            .map(|other| support::test_executor(*other))
            .collect();
        let mut adapter = Recording::new(&corpus, kind, FAITHFUL);
        let report = run(&corpus, &corpus.request, &others, &mut adapter)?;
        assert_dispatch(&report, &adapter, &CASES, "other declarations")?;
    }
    Ok(())
}

/// `corpus`'s request rebound to another subject artifact digest.
fn request_for_subject(corpus: &Corpus, subject: [u8; 32]) -> TestResult<Vec<u8>> {
    let mut request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    request.subject_artifact_digest = subject;
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request.to_canonical_cbor()?)
}

#[test]
fn the_executor_digest_is_provenance_and_never_changes_an_outcome() -> TestResult {
    let corpus = support::corpus()?;
    let mut reports = Vec::new();
    for subject in [[41; 32], [77; 32]] {
        let request = request_for_subject(&corpus, subject)?;
        let mut executor = exported();
        executor.implementation_digest = subject;
        let mut adapter = Recording::new(&corpus, SubjectAdapterKind::ExportedArtifact, FAITHFUL);
        adapter.subject_digest = subject;
        let report = run(&corpus, &request, &[executor], &mut adapter)?;
        assert_dispatch(&report, &adapter, &[], "executor digest")?;
        assert_eq!(report.subject_artifact_digest, subject);
        reports.push(report);
    }
    assert_eq!(reports[0].cases, reports[1].cases);
    Ok(())
}

#[test]
fn an_over_budget_attempt_fails_and_publishes_no_output() -> TestResult {
    let corpus = support::corpus()?;
    let mut adapter = Recording::new(
        &corpus,
        SubjectAdapterKind::ExportedArtifact,
        |attempt, output| {
            let mut usage = ResourceUsage::default();
            if attempt.case_id == "case-0" {
                usage.event_count = attempt.budget.event_count + 1;
            }
            Ok(SubjectObservation {
                result: SubjectResult::Output(output.to_vec()),
                usage,
            })
        },
    );
    let report = run(&corpus, &corpus.request, &[exported()], &mut adapter)?;
    let over = case(&report, "case-0")?;
    assert_eq!(over.outcome, CaseStatus::Fail);
    assert_eq!(
        over.actual_error,
        Some(SafeErrorCode::ResourceLimitExceeded)
    );
    assert_eq!(over.actual_digest, None);
    assert_eq!(case(&report, "case-1")?.outcome, CaseStatus::Pass);
    Ok(())
}

#[test]
fn a_watchdog_expiry_cannot_satisfy_resource_exhaustion() -> TestResult {
    let corpus = support::corpus()?;
    let mut adapter = Recording::new(
        &corpus,
        SubjectAdapterKind::ExportedArtifact,
        |attempt, output| {
            if attempt.case_id == "case-3" {
                return Err(AdapterError::WatchdogExpired);
            }
            FAITHFUL(attempt, output)
        },
    );
    let report = run(&corpus, &corpus.request, &[exported()], &mut adapter)?;
    let expired = case(&report, "case-3")?;
    assert_eq!(expired.outcome, CaseStatus::Unavailable);
    assert_eq!(expired.actual_digest, None);
    assert_eq!(expired.actual_error, None);
    assert!(adapter.executed.iter().any(|id| id == "case-3"));
    Ok(())
}
