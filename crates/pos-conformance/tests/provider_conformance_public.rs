//! The provider-neutral conformance suite through its public interface:
//! a faithful reference provider passes, and every kind of deviation fails.

use pos_conformance::{
    evaluate, run_suite, verify_gate, CaseVerdict, ExpectedPublicOutcome, FailureReason, GateError,
    ObservedAttempt, ObservedPublic, ProviderConformanceCase, ProviderRun, ProviderRunError,
    ProviderUnderTest, ReportArchitecture, SandboxArchitectureV1, SandboxProviderErrorCodeV1,
    SandboxProviderErrorV1, SandboxProviderResultV1, SandboxTerminalOutcomeV1, SuiteReport,
    CONCURRENT_ATTEMPTS_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn attempt_id(index: usize) -> Option<[u8; 16]> {
    let mut id = [1_u8; 16];
    id[0] = u8::try_from(index + 1).ok()?;
    Some(id)
}

/// The observation a faithful provider shows for one attempt of a case,
/// written out here independently of `ProviderConformanceCase::expectation`.
fn faithful_attempt(case: ProviderConformanceCase, index: usize) -> ObservedAttempt {
    use ProviderConformanceCase as Case;
    use SandboxTerminalOutcomeV1 as Outcome;
    let terminal = |outcome, terminal_code| ObservedPublic::Terminal {
        outcome,
        terminal_code,
    };
    let public = match case {
        Case::FilesystemEscape
        | Case::ReadOnlyRootWrite
        | Case::WorkAreaExhaustion
        | Case::NetworkEscape
        | Case::ForeignSignals
        | Case::OrphanedChild
        | Case::ConcurrentAttempts => terminal(Outcome::Completed, None),
        Case::OversizedOutput => terminal(Outcome::UnavailableAfterAdmission, Some(7)),
        Case::TaskExhaustion => terminal(Outcome::UnavailableAfterAdmission, Some(5)),
        Case::MemoryExhaustion => terminal(Outcome::UnavailableAfterAdmission, Some(4)),
        Case::WatchdogExpiry => terminal(Outcome::UnavailableAfterAdmission, Some(6)),
        Case::AdapterCrash => terminal(Outcome::UnavailableAfterAdmission, Some(8)),
        Case::MalformedOutput => terminal(Outcome::UnavailableAfterAdmission, Some(10)),
        Case::BrokerCrashRecovery => terminal(Outcome::UnavailableAfterAdmission, Some(2)),
        Case::CancelBeforeRelease | Case::CancelWhileRunning | Case::RevokedWhileRunning => {
            terminal(Outcome::Cancelled, Some(1))
        }
        Case::RevokedBeforeAdmission => {
            ObservedPublic::Refused(SandboxProviderErrorCodeV1::TrustRevoked)
        }
        Case::MissingHostFeature => {
            ObservedPublic::Refused(SandboxProviderErrorCodeV1::SandboxUnavailable)
        }
    };
    ObservedAttempt {
        attempt_id: attempt_id(index),
        request_id: Some([9; 16]),
        public,
    }
}

fn faithful_run(case: ProviderConformanceCase) -> ProviderRun {
    ProviderRun {
        attempts: (0..case.attempts())
            .map(|index| faithful_attempt(case, index))
            .collect(),
        leaked_resources: 0,
    }
}

struct Reference {
    broken: Option<(ProviderConformanceCase, ProviderRun)>,
    unrunnable: Option<ProviderConformanceCase>,
}

impl ProviderUnderTest for Reference {
    fn run_case(&mut self, case: ProviderConformanceCase) -> Result<ProviderRun, ProviderRunError> {
        if self.unrunnable == Some(case) {
            return Err(ProviderRunError("unrunnable".to_owned()));
        }
        match &self.broken {
            Some((broken, run)) if *broken == case => Ok(run.clone()),
            _ => Ok(faithful_run(case)),
        }
    }
}

fn report_for(
    architecture: SandboxArchitectureV1,
    broken: Option<(ProviderConformanceCase, ProviderRun)>,
) -> SuiteReport {
    run_suite(
        &mut Reference {
            broken,
            unrunnable: None,
        },
        architecture,
    )
}

fn passing_reports() -> Vec<SuiteReport> {
    vec![
        report_for(SandboxArchitectureV1::X86_64, None),
        report_for(SandboxArchitectureV1::Aarch64, None),
    ]
}

const fn terminal(
    case: ProviderConformanceCase,
) -> Option<(SandboxTerminalOutcomeV1, &'static [u8])> {
    match case.expectation() {
        ExpectedPublicOutcome::Terminal { outcome, codes } => Some((outcome, codes)),
        ExpectedPublicOutcome::Refused(_) => None,
    }
}

#[test]
fn case_ids_are_unique_and_round_trip() {
    for (index, case) in ProviderConformanceCase::ALL.into_iter().enumerate() {
        assert_eq!(ProviderConformanceCase::from_id(case.id()), Some(case));
        for other in &ProviderConformanceCase::ALL[index + 1..] {
            assert_ne!(case.id(), other.id());
        }
    }
    assert_eq!(ProviderConformanceCase::from_id("no-such-case"), None);
}

#[test]
fn only_the_concurrency_case_runs_several_attempts() {
    for case in ProviderConformanceCase::ALL {
        let expected = if case == ProviderConformanceCase::ConcurrentAttempts {
            CONCURRENT_ATTEMPTS_V1
        } else {
            1
        };
        assert_eq!(case.attempts(), expected, "{}", case.id());
    }
    assert_eq!(CONCURRENT_ATTEMPTS_V1, 8);
}

#[test]
fn the_expected_outcomes_follow_the_adr_069_precedence_table() {
    use ProviderConformanceCase as Case;
    use SandboxTerminalOutcomeV1 as Outcome;
    for case in [
        Case::FilesystemEscape,
        Case::ReadOnlyRootWrite,
        Case::NetworkEscape,
        Case::ForeignSignals,
        Case::OrphanedChild,
        Case::WorkAreaExhaustion,
        Case::ConcurrentAttempts,
    ] {
        assert_eq!(
            terminal(case),
            Some((Outcome::Completed, &[][..])),
            "{}",
            case.id()
        );
    }
    let unavailable = Outcome::UnavailableAfterAdmission;
    assert_eq!(
        terminal(Case::OversizedOutput),
        Some((unavailable, &[7][..]))
    );
    assert_eq!(
        terminal(Case::TaskExhaustion),
        Some((unavailable, &[5][..]))
    );
    assert_eq!(
        terminal(Case::MemoryExhaustion),
        Some((unavailable, &[3, 4][..]))
    );
    assert_eq!(
        terminal(Case::WatchdogExpiry),
        Some((unavailable, &[6][..]))
    );
    assert_eq!(terminal(Case::AdapterCrash), Some((unavailable, &[8][..])));
    assert_eq!(
        terminal(Case::MalformedOutput),
        Some((unavailable, &[10][..]))
    );
    assert_eq!(
        terminal(Case::BrokerCrashRecovery),
        Some((unavailable, &[2, 3, 4, 5, 6, 7, 8, 9, 10][..]))
    );
    for case in [
        Case::CancelBeforeRelease,
        Case::CancelWhileRunning,
        Case::RevokedWhileRunning,
    ] {
        assert_eq!(
            terminal(case),
            Some((Outcome::Cancelled, &[1][..])),
            "{}",
            case.id()
        );
    }
    assert_eq!(
        Case::MissingHostFeature.expectation(),
        ExpectedPublicOutcome::Refused(&[
            SandboxProviderErrorCodeV1::SandboxUnavailable,
            SandboxProviderErrorCodeV1::ProviderCapabilityMissing,
        ])
    );
    assert_eq!(
        Case::RevokedBeforeAdmission.expectation(),
        ExpectedPublicOutcome::Refused(&[
            SandboxProviderErrorCodeV1::TrustRevoked,
            SandboxProviderErrorCodeV1::AuthorityMismatch,
        ])
    );
}

#[test]
fn a_faithful_provider_passes_every_case_and_the_gate() -> TestResult {
    let reports = passing_reports();
    for report in &reports {
        assert_eq!(report.cases.len(), ProviderConformanceCase::ALL.len());
        assert!(report
            .cases
            .iter()
            .all(|record| record.verdict == CaseVerdict::Passed));
    }
    verify_gate(&reports)?;
    Ok(())
}

#[test]
fn every_accepted_terminal_code_passes_and_no_other_does() {
    for case in ProviderConformanceCase::ALL {
        let Some((outcome, codes)) = terminal(case) else {
            continue;
        };
        for shown in (0..=12_u8).map(Some).chain([None]) {
            let mut run = faithful_run(case);
            for attempt in &mut run.attempts {
                attempt.public = ObservedPublic::Terminal {
                    outcome,
                    terminal_code: shown,
                };
            }
            let accepted = shown.map_or(codes.is_empty(), |code| codes.contains(&code));
            let expected = if accepted {
                CaseVerdict::Passed
            } else {
                CaseVerdict::Failed(FailureReason::TerminalCode)
            };
            assert_eq!(evaluate(case, &run), expected, "{} {shown:?}", case.id());
        }
    }
}

#[test]
fn a_wrong_outcome_fails() {
    let every_outcome = [
        SandboxTerminalOutcomeV1::Completed,
        SandboxTerminalOutcomeV1::Cancelled,
        SandboxTerminalOutcomeV1::UnavailableBeforeAdmission,
        SandboxTerminalOutcomeV1::Rejected,
        SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
    ];
    let case = ProviderConformanceCase::FilesystemEscape;
    for outcome in every_outcome {
        let mut run = faithful_run(case);
        run.attempts[0].public = ObservedPublic::Terminal {
            outcome,
            terminal_code: None,
        };
        let expected = if outcome == SandboxTerminalOutcomeV1::Completed {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed(FailureReason::Outcome)
        };
        assert_eq!(evaluate(case, &run), expected);
    }
    // A refusal where a result is required, and a result where a refusal is.
    let mut refused = faithful_run(case);
    refused.attempts[0].public = ObservedPublic::Refused(SandboxProviderErrorCodeV1::TrustRevoked);
    assert_eq!(
        evaluate(case, &refused),
        CaseVerdict::Failed(FailureReason::Outcome)
    );
    for refusal_case in [
        ProviderConformanceCase::RevokedBeforeAdmission,
        ProviderConformanceCase::MissingHostFeature,
    ] {
        let mut result = faithful_run(refusal_case);
        result.attempts[0].public = ObservedPublic::Terminal {
            outcome: SandboxTerminalOutcomeV1::Rejected,
            terminal_code: None,
        };
        assert_eq!(
            evaluate(refusal_case, &result),
            CaseVerdict::Failed(FailureReason::Outcome)
        );
    }
}

const ALL_REFUSAL_CODES: [SandboxProviderErrorCodeV1; 18] = [
    SandboxProviderErrorCodeV1::InvalidEncoding,
    SandboxProviderErrorCodeV1::UnsupportedVersion,
    SandboxProviderErrorCodeV1::FieldOutOfBounds,
    SandboxProviderErrorCodeV1::NonCanonicalOrder,
    SandboxProviderErrorCodeV1::DigestMismatch,
    SandboxProviderErrorCodeV1::SignatureInvalid,
    SandboxProviderErrorCodeV1::TrustRevoked,
    SandboxProviderErrorCodeV1::AuthorityMismatch,
    SandboxProviderErrorCodeV1::ProviderCapabilityMissing,
    SandboxProviderErrorCodeV1::ImageIdentityMismatch,
    SandboxProviderErrorCodeV1::SelfTestFailed,
    SandboxProviderErrorCodeV1::SandboxUnavailable,
    SandboxProviderErrorCodeV1::AdmissionBusy,
    SandboxProviderErrorCodeV1::AuditUnavailable,
    SandboxProviderErrorCodeV1::CleanupFailed,
    SandboxProviderErrorCodeV1::UnknownAttempt,
    SandboxProviderErrorCodeV1::RequestIdentityConflict,
    SandboxProviderErrorCodeV1::PayloadTransferTimeout,
];

#[test]
fn the_refusal_sets_accept_exactly_their_codes() {
    use SandboxProviderErrorCodeV1 as Code;
    for (case, accepted) in [
        (
            ProviderConformanceCase::MissingHostFeature,
            [Code::SandboxUnavailable, Code::ProviderCapabilityMissing],
        ),
        (
            ProviderConformanceCase::RevokedBeforeAdmission,
            [Code::TrustRevoked, Code::AuthorityMismatch],
        ),
    ] {
        for code in ALL_REFUSAL_CODES {
            let mut run = faithful_run(case);
            run.attempts[0].public = ObservedPublic::Refused(code);
            let expected = if accepted.contains(&code) {
                CaseVerdict::Passed
            } else {
                CaseVerdict::Failed(FailureReason::Refusal)
            };
            assert_eq!(evaluate(case, &run), expected, "{} {code:?}", case.id());
        }
    }
}

#[test]
fn any_deviating_concurrent_attempt_fails_the_case() {
    let case = ProviderConformanceCase::ConcurrentAttempts;
    for deviant in 0..CONCURRENT_ATTEMPTS_V1 {
        let mut run = faithful_run(case);
        run.attempts[deviant].public = ObservedPublic::Terminal {
            outcome: SandboxTerminalOutcomeV1::Cancelled,
            terminal_code: Some(1),
        };
        assert_eq!(
            evaluate(case, &run),
            CaseVerdict::Failed(FailureReason::Outcome)
        );
    }
}

#[test]
fn the_attempt_count_must_match() {
    for case in [
        ProviderConformanceCase::FilesystemEscape,
        ProviderConformanceCase::ConcurrentAttempts,
    ] {
        let mut short = faithful_run(case);
        short.attempts.pop();
        assert_eq!(
            evaluate(case, &short),
            CaseVerdict::Failed(FailureReason::AttemptCount)
        );
        let mut long = faithful_run(case);
        long.attempts.push(faithful_attempt(case, 9));
        assert_eq!(
            evaluate(case, &long),
            CaseVerdict::Failed(FailureReason::AttemptCount)
        );
    }
}

#[test]
fn concurrent_attempts_need_distinct_named_identities() {
    let case = ProviderConformanceCase::ConcurrentAttempts;
    for (first, second) in [(0, 1), (0, CONCURRENT_ATTEMPTS_V1 - 1), (6, 7)] {
        let mut run = faithful_run(case);
        run.attempts[second].attempt_id = run.attempts[first].attempt_id;
        assert_eq!(
            evaluate(case, &run),
            CaseVerdict::Failed(FailureReason::AttemptIdentity)
        );
    }
    for unnamed in [0, CONCURRENT_ATTEMPTS_V1 - 1] {
        let mut run = faithful_run(case);
        run.attempts[unnamed].attempt_id = None;
        assert_eq!(
            evaluate(case, &run),
            CaseVerdict::Failed(FailureReason::AttemptIdentity)
        );
    }
    // Every single answer names its own authenticated identity.
    for (case, attempt) in [
        (ProviderConformanceCase::FilesystemEscape, true),
        (ProviderConformanceCase::RevokedBeforeAdmission, false),
    ] {
        let mut run = faithful_run(case);
        if attempt {
            run.attempts[0].attempt_id = None;
        } else {
            run.attempts[0].request_id = None;
        }
        assert_eq!(
            evaluate(case, &run),
            CaseVerdict::Failed(FailureReason::AttemptIdentity)
        );
        // The other identity is not required.
        let mut other = faithful_run(case);
        if attempt {
            other.attempts[0].request_id = None;
        } else {
            other.attempts[0].attempt_id = None;
        }
        assert_eq!(evaluate(case, &other), CaseVerdict::Passed);
    }
}

#[test]
fn leaked_resources_fail_every_case() {
    for case in ProviderConformanceCase::ALL {
        let mut run = faithful_run(case);
        run.leaked_resources = 1;
        assert_eq!(
            evaluate(case, &run),
            CaseVerdict::Failed(FailureReason::ResourceLeak)
        );
    }
}

#[test]
fn a_case_the_provider_cannot_run_fails_as_not_run() {
    for case in ProviderConformanceCase::ALL {
        let report = run_suite(
            &mut Reference {
                broken: None,
                unrunnable: Some(case),
            },
            SandboxArchitectureV1::X86_64,
        );
        let failed: Vec<_> = report
            .cases
            .iter()
            .filter(|record| record.verdict != CaseVerdict::Passed)
            .collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].case, case.id());
        assert_eq!(
            failed[0].verdict,
            CaseVerdict::Failed(FailureReason::NotRun)
        );
    }
}

const fn spy1(outcome: SandboxTerminalOutcomeV1, events: Vec<u64>) -> SandboxProviderResultV1 {
    SandboxProviderResultV1 {
        request_id: [2; 16],
        attempt_id: [3; 16],
        outcome,
        output: None,
        agr1_digest: None,
        spr1_digest: None,
        operational_events: events,
        runtime_attestation_key_id: String::new(),
        result_digest: [0; 32],
        signature: [0; 64],
    }
}

#[test]
fn spy1_is_read_through_its_public_fields() {
    // Lifecycle codes 11..13 precede the terminal code.
    let observed = ObservedAttempt::from_result(&spy1(
        SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
        vec![11, 12, 13, 6],
    ));
    assert_eq!(observed.attempt_id, Some([3; 16]));
    assert_eq!(observed.request_id, Some([2; 16]));
    assert_eq!(
        observed.public,
        ObservedPublic::Terminal {
            outcome: SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
            terminal_code: Some(6),
        }
    );
    for (events, code) in [
        (vec![], None),
        (vec![11, 12], None),
        (vec![11, 12, 13], None),
        (vec![10], Some(10)),
        (vec![11], None),
        (vec![u64::from(u8::MAX) + 2], None),
        (vec![0], Some(0)),
    ] {
        let observed =
            ObservedAttempt::from_result(&spy1(SandboxTerminalOutcomeV1::Completed, events));
        assert!(matches!(
            observed.public,
            ObservedPublic::Terminal { terminal_code, .. } if terminal_code == code
        ));
    }
}

#[test]
fn spe1_is_read_through_its_public_fields() {
    let error = SandboxProviderErrorV1 {
        operation: Some(1),
        request_id: Some([2; 16]),
        request_digest: None,
        attempt_id: Some([4; 16]),
        code: SandboxProviderErrorCodeV1::TrustRevoked,
        safe_detail: None,
        runtime_attestation_key_id: String::new(),
        error_digest: [0; 32],
        signature: [0; 64],
    };
    let refusal = ObservedAttempt::from_error(&error);
    assert_eq!(refusal.attempt_id, Some([4; 16]));
    assert_eq!(refusal.request_id, Some([2; 16]));
    assert_eq!(
        refusal.public,
        ObservedPublic::Refused(SandboxProviderErrorCodeV1::TrustRevoked)
    );
}

#[test]
fn the_gate_needs_exactly_one_report_per_required_architecture() {
    let mut reports = passing_reports();
    reports.pop();
    assert_eq!(
        verify_gate(&reports),
        Err(GateError::ArchitectureCoverage(ReportArchitecture::Aarch64))
    );
    reports.remove(0);
    assert_eq!(
        verify_gate(&reports),
        Err(GateError::ArchitectureCoverage(ReportArchitecture::X86_64))
    );
    let mut doubled = passing_reports();
    doubled.push(doubled[0].clone());
    assert_eq!(
        verify_gate(&doubled),
        Err(GateError::ArchitectureCoverage(ReportArchitecture::X86_64))
    );
    assert_eq!(
        verify_gate(&[]),
        Err(GateError::ArchitectureCoverage(ReportArchitecture::X86_64))
    );
}

#[test]
fn the_gate_rejects_unknown_missing_and_repeated_cases() {
    let mut unknown = passing_reports();
    unknown[1].cases[0].case = "invented".to_owned();
    assert_eq!(
        verify_gate(&unknown),
        Err(GateError::UnknownCase("invented".to_owned()))
    );
    for (index, case) in ProviderConformanceCase::ALL.into_iter().enumerate() {
        let mut missing = passing_reports();
        let removed = missing[0].cases.remove(index);
        assert_eq!(
            verify_gate(&missing),
            Err(GateError::CaseCoverage(case.id()))
        );
        let mut repeated = passing_reports();
        repeated[0].cases.push(removed);
        assert_eq!(
            verify_gate(&repeated),
            Err(GateError::CaseCoverage(case.id()))
        );
    }
}

#[test]
fn the_gate_names_the_first_failing_case_and_architecture() {
    let broken = ProviderRun {
        attempts: vec![],
        leaked_resources: 0,
    };
    let reports = vec![
        report_for(SandboxArchitectureV1::X86_64, None),
        report_for(
            SandboxArchitectureV1::Aarch64,
            Some((ProviderConformanceCase::TaskExhaustion, broken)),
        ),
    ];
    let error = verify_gate(&reports).err();
    assert_eq!(
        error,
        Some(GateError::Failed {
            architecture: ReportArchitecture::Aarch64,
            case: "task-exhaustion",
            reason: FailureReason::AttemptCount,
        })
    );
    assert_eq!(
        error.map(|error| error.to_string()).as_deref(),
        Some("case task-exhaustion failed on Aarch64: AttemptCount")
    );
}

#[test]
fn reports_round_trip_through_json() -> TestResult {
    let mut report = report_for(SandboxArchitectureV1::Aarch64, None);
    report.cases[3].verdict = CaseVerdict::Failed(FailureReason::ResourceLeak);
    let text = serde_json::to_string(&report)?;
    assert!(text.contains(r#""architecture":"aarch64""#));
    assert!(text.contains(
        r#"{"case":"network-escape","verdict":{"status":"failed","reason":"resource_leak"}}"#
    ));
    assert!(text.contains(r#"{"case":"filesystem-escape","verdict":{"status":"passed"}}"#));
    let parsed: SuiteReport = serde_json::from_str(&text)?;
    assert_eq!(parsed, report);
    let x86 = serde_json::to_string(&report_for(SandboxArchitectureV1::X86_64, None))?;
    assert!(x86.contains(r#""architecture":"x86_64""#));
    Ok(())
}

#[test]
fn failures_are_reported_in_the_documented_order() {
    let case = ProviderConformanceCase::ConcurrentAttempts;
    let mut run = faithful_run(case);
    run.leaked_resources = 3;
    run.attempts[1].attempt_id = run.attempts[0].attempt_id;
    assert_eq!(
        evaluate(case, &run),
        CaseVerdict::Failed(FailureReason::AttemptIdentity)
    );
    run.attempts[2].public = ObservedPublic::Terminal {
        outcome: SandboxTerminalOutcomeV1::Cancelled,
        terminal_code: Some(1),
    };
    assert_eq!(
        evaluate(case, &run),
        CaseVerdict::Failed(FailureReason::Outcome)
    );
    run.attempts.pop();
    assert_eq!(
        evaluate(case, &run),
        CaseVerdict::Failed(FailureReason::AttemptCount)
    );
    let single = ProviderConformanceCase::TaskExhaustion;
    let mut wrong = faithful_run(single);
    wrong.attempts[0].public = ObservedPublic::Terminal {
        outcome: SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
        terminal_code: Some(4),
    };
    wrong.leaked_resources = 1;
    assert_eq!(
        evaluate(single, &wrong),
        CaseVerdict::Failed(FailureReason::TerminalCode)
    );
}

#[test]
fn every_gate_error_names_what_failed() {
    let errors = [
        (
            GateError::ArchitectureCoverage(ReportArchitecture::X86_64),
            "expected exactly one report for X86_64",
        ),
        (
            GateError::UnknownCase("odd".to_owned()),
            "report names an unknown case odd",
        ),
        (
            GateError::CaseCoverage("adapter-crash"),
            "report does not list case adapter-crash exactly once",
        ),
        (
            GateError::Failed {
                architecture: ReportArchitecture::X86_64,
                case: "adapter-crash",
                reason: FailureReason::NotRun,
            },
            "case adapter-crash failed on X86_64: NotRun",
        ),
    ];
    for (error, text) in errors {
        assert_eq!(error.to_string(), text);
    }
    assert_eq!(
        ProviderRunError("no broker".to_owned()).to_string(),
        "the provider could not run the case: no broker"
    );
}

#[test]
fn every_verdict_and_architecture_round_trips() -> TestResult {
    let reasons = [
        (FailureReason::NotRun, "not_run"),
        (FailureReason::AttemptCount, "attempt_count"),
        (FailureReason::Outcome, "outcome"),
        (FailureReason::TerminalCode, "terminal_code"),
        (FailureReason::Refusal, "refusal"),
        (FailureReason::AttemptIdentity, "attempt_identity"),
        (FailureReason::ResourceLeak, "resource_leak"),
    ];
    for (reason, name) in reasons {
        let text = serde_json::to_string(&reason)?;
        assert_eq!(text, format!("\"{name}\""));
        assert_eq!(serde_json::from_str::<FailureReason>(&text)?, reason);
        let verdict = CaseVerdict::Failed(reason);
        let text = serde_json::to_string(&verdict)?;
        assert_eq!(serde_json::from_str::<CaseVerdict>(&text)?, verdict);
    }
    let passed = serde_json::to_string(&CaseVerdict::Passed)?;
    assert_eq!(
        serde_json::from_str::<CaseVerdict>(&passed)?,
        CaseVerdict::Passed
    );
    for (architecture, name) in [
        (ReportArchitecture::X86_64, "x86_64"),
        (ReportArchitecture::Aarch64, "aarch64"),
    ] {
        let text = serde_json::to_string(&architecture)?;
        assert_eq!(text, format!("\"{name}\""));
        assert_eq!(
            serde_json::from_str::<ReportArchitecture>(&text)?,
            architecture
        );
    }
    assert_eq!(ReportArchitecture::REQUIRED.len(), 2);
    Ok(())
}

/// A provider that refuses with the second accepted code of each refusal case.
struct AlternateRefusals;

impl ProviderUnderTest for AlternateRefusals {
    fn run_case(&mut self, case: ProviderConformanceCase) -> Result<ProviderRun, ProviderRunError> {
        let mut run = faithful_run(case);
        let alternate = match case {
            ProviderConformanceCase::MissingHostFeature => {
                Some(SandboxProviderErrorCodeV1::ProviderCapabilityMissing)
            }
            ProviderConformanceCase::RevokedBeforeAdmission => {
                Some(SandboxProviderErrorCodeV1::AuthorityMismatch)
            }
            _ => None,
        };
        if let Some(code) = alternate {
            run.attempts[0].public = ObservedPublic::Refused(code);
        }
        Ok(run)
    }
}

#[test]
fn the_second_accepted_refusal_codes_pass_the_whole_suite() -> TestResult {
    let reports = [
        run_suite(&mut AlternateRefusals, SandboxArchitectureV1::X86_64),
        run_suite(&mut AlternateRefusals, SandboxArchitectureV1::Aarch64),
    ];
    verify_gate(&reports)?;
    Ok(())
}
