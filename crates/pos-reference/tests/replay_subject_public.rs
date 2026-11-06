//! Public black-box tests of the independent evaluator against the `replay-conformance` provider
//! budgets (ADR-061 R11, #1269).
//!
//! A scripted `SubjectAdapter` stands in for the replay subject adapter and reports the usage the
//! real adapter measures. The tests exercise only the public `evaluate` operation and the CNR1
//! report it returns; they import no host crate. The subject half,
//! `apps/pos-experiment/tests/replay_conformance_adapter.rs`, asserts the same literals
//! (`MEASURED_USAGE`) on the real adapter; keep the two in step.

pub mod support;

use std::error::Error;
use std::fs;
use std::io;
use std::sync::OnceLock;

use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, ResourceUsage, SubjectAdapter, SubjectObservation,
    SubjectResult,
};
use pos_reference::evaluator_build_identity::VerifiedEvaluatorBuildIdentity;
use pos_reference::evaluator_domain::{ClaimLayer, SafeErrorCode};
use pos_reference::evaluator_protocol::{
    CaseOutcome, CaseStatus, ConformanceReport, SubjectAdapterKind,
};
use support::Corpus;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The usage of an attempt that runs `execution_steps` legs and folds `event_count` Events. The
/// adapter meters only these two counters (ADR-062 R8 section 7); the other six are 0.
const fn usage(event_count: u64, execution_steps: u64) -> ResourceUsage {
    ResourceUsage {
        memory_bytes: 0,
        cpu_fuel: 0,
        host_calls: 0,
        event_count,
        output_bytes: 0,
        storage_bytes: 0,
        execution_steps,
        simulation_time_ns: 0,
    }
}

/// ADR-061 R11: the usage the replay subject adapter measures for each family's attempt, by
/// family code, in Local and Air-Gapped: one execution step per leg and every Event the attempt
/// folds (a run refused before its fold counts none).
const MEASURED_USAGE: [ResourceUsage; 7] = [
    // positive: pos.1 (1 leg, 3 Events), pos.2 (1 leg, 4 Events), pos.3 (2 legs, 2 refused).
    usage(11, 4),
    // denied: den.1a, den.1b (2 legs) and den.2; 6 Events folded.
    usage(6, 4),
    // malformed: mal.1a, mal.1b (2 legs) and mal.2, every leg refused before its fold.
    usage(0, 4),
    // resource-exhaustion: res.1, refused at its `resource_limit` before any Event is read.
    usage(0, 1),
    // deletion-redaction: del.1 folds 2 Events; del.2a and del.2b (2 legs) are refused.
    usage(2, 4),
    // downgrade: dgr.1a and dgr.1b (2 legs), every leg refused before its fold.
    usage(0, 3),
    // independent-evaluation: ind.1, one leg folding 3 Events.
    usage(3, 1),
];

/// The provider manifest of the checked-in replay conformance fixtures.
const REPLAY_PROVIDER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/conformance/providers/replay-conformance/provider.json"
);

/// The provider's family names, by family code.
const PROVIDER_FAMILIES: [&str; 7] = [
    "positive",
    "denied",
    "malformed",
    "resource-exhaustion",
    "deletion-redaction",
    "downgrade",
    "independent-evaluation",
];

/// The budget counters, in `ResourceUsage` order.
const COUNTERS: [&str; 8] = [
    "memory_bytes",
    "cpu_fuel",
    "host_calls",
    "event_count",
    "output_bytes",
    "storage_bytes",
    "execution_steps",
    "simulation_time_ns",
];

/// The Execution Modes of the evaluator corpus: 0 is Local and 1 is Air-Gapped.
const CORPUS_MODES: [u64; 2] = [0, 1];

const FAMILY_COUNT: u8 = 7;

struct Scripted<F> {
    subject_digest: [u8; 32],
    script: F,
}

impl<F> SubjectAdapter for Scripted<F>
where
    F: FnMut(&CaseAttempt) -> Result<SubjectObservation, AdapterError>,
{
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        (self.script)(attempt)
    }
}

fn evaluator_identity() -> TestResult<VerifiedEvaluatorBuildIdentity> {
    static IDENTITY: OnceLock<Result<VerifiedEvaluatorBuildIdentity, String>> = OnceLock::new();
    match IDENTITY
        .get_or_init(|| support::verified_evaluator_identity().map_err(|error| error.to_string()))
    {
        Ok(identity) => Ok(identity.clone()),
        Err(error) => Err(io::Error::other(error.clone()).into()),
    }
}

/// The eight counters of `usage` in `COUNTERS` order.
const fn counters(usage: ResourceUsage) -> [u64; 8] {
    [
        usage.memory_bytes,
        usage.cpu_fuel,
        usage.host_calls,
        usage.event_count,
        usage.output_bytes,
        usage.storage_bytes,
        usage.execution_steps,
        usage.simulation_time_ns,
    ]
}

/// ADR-061 R11: the lowest budget `usage` passes, per counter. A counter measured at 0 takes 1,
/// because a zero budget is rejected.
fn measured_floor(usage: ResourceUsage) -> [u64; 8] {
    counters(usage).map(|counter| counter.max(1))
}

/// The Draft budgets of the checked-in replay provider manifest, by family code.
fn provider_budgets() -> TestResult<[[u64; 8]; 7]> {
    let provider: serde_json::Value = serde_json::from_slice(&fs::read(REPLAY_PROVIDER)?)?;
    let mut budgets = [[0; 8]; 7];
    for (budget, family) in budgets.iter_mut().zip(PROVIDER_FAMILIES) {
        let declared = &provider["fixture_contracts"][family]["deterministic_budget"];
        for (counter, name) in budget.iter_mut().zip(COUNTERS) {
            *counter = declared[name]
                .as_u64()
                .ok_or_else(|| io::Error::other(format!("{family} has no {name} budget")))?;
        }
    }
    Ok(budgets)
}

fn case(report: &ConformanceReport, family: u8) -> TestResult<&CaseOutcome> {
    let id = format!("case-{family}");
    report
        .cases
        .iter()
        .find(|outcome| outcome.case_id == id)
        .ok_or_else(|| io::Error::other(format!("{id} is absent from the report")).into())
}

fn expect_status(report: &ConformanceReport, family: u8, expected: CaseStatus) -> TestResult {
    let actual = case(report, family)?.outcome;
    if actual == expected {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "case-{family}: expected {expected:?}, got {actual:?}"
    ))
    .into())
}

/// The report of a subject that gives every case its oracle output and its family's measured
/// usage, over a `replay-conformance` corpus in `mode` whose fixture of family code `n` has
/// budget `budgets[n]`.
fn measured_report(mode: u64, budgets: &[[u64; 8]; 7]) -> TestResult<ConformanceReport> {
    let corpus: Corpus = support::replay_corpus_with_budgets(mode, budgets)?;
    let mut adapter = Scripted {
        subject_digest: corpus.subject_digest,
        script: |attempt: &CaseAttempt| {
            assert_eq!(attempt.claim_layer, ClaimLayer::ReplayConformance);
            Ok(SubjectObservation {
                result: SubjectResult::Output(corpus.expected_output.clone()),
                usage: MEASURED_USAGE[usize::from(attempt.family.code())],
            })
        },
    };
    let artifacts = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity()?,
        &mut adapter,
    )?;
    Ok(artifacts.report)
}

/// ADR-061 R11: the Draft budget of every family in the replay provider manifest is the lowest
/// budget its measured usage passes, so a change in measured usage fails here until the literals
/// and `provider.json` move together.
#[test]
fn replay_provider_budgets_are_the_floor_of_the_measured_usage() -> TestResult {
    assert_eq!(provider_budgets()?, MEASURED_USAGE.map(measured_floor));
    Ok(())
}

/// ADR-061 R11 at the replay provider budgets: with every family reporting its measured usage,
/// every case passes, and a budget one below in any counter of one family fails that case
/// `ResourceLimitExceeded` while the others pass, in Local and Air-Gapped. A counter whose budget
/// is 1, the lowest legal budget (a zero budget is rejected), has no below case.
#[test]
fn replay_measured_usage_passes_at_the_provider_budgets_and_fails_one_below() -> TestResult {
    let budgets = provider_budgets()?;
    for mode in CORPUS_MODES {
        let equal = measured_report(mode, &budgets)?;
        (0..FAMILY_COUNT)
            .try_for_each(|family| expect_status(&equal, family, CaseStatus::Pass))
            .map_err(|error| io::Error::other(format!("mode {mode} at the budget: {error}")))?;
        for (family, budget) in budgets.iter().enumerate() {
            let code = u8::try_from(family)?;
            let lowered = COUNTERS
                .iter()
                .enumerate()
                .filter(|(index, _)| budget[*index] > 1);
            for (index, name) in lowered {
                let mut below = budgets;
                below[family][index] -= 1;
                let report = measured_report(mode, &below)?;
                let lowered_case = case(&report, code)?;
                assert_eq!(
                    (lowered_case.outcome, lowered_case.actual_error),
                    (CaseStatus::Fail, Some(SafeErrorCode::ResourceLimitExceeded)),
                    "case-{code} {name} mode {mode}"
                );
                for other in (0..FAMILY_COUNT).filter(|other| *other != code) {
                    expect_status(&report, other, CaseStatus::Pass)?;
                }
            }
        }
    }
    Ok(())
}
