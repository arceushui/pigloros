//! Helpers shared by the worker's conformance tests.
//!
//! They cover the observation of an attempt from the adapter library over the real worker, the
//! provider's typed failures, single-sub-case attempts and the oracle and budget assertions.

use std::path::PathBuf;

use pos_plugin_conformance_adapter::{run_with, SupervisorRunnerV1};
use pos_plugin_supervisor::WorkerProgramV1;
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{CaseAttempt, SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_reference::profile::NamespacedFailure;
use serde_json::Value;

use super::attempts::{attempt_from_fixture_files, family_budget, oracle_bytes, rewrite_subcases};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The worker binary of this package.
pub const WORKER: &str = env!("CARGO_BIN_EXE_pos-plugin-worker");

/// The observation of `attempt` from the adapter library over the real worker.
///
/// # Errors
/// Returns the error of building the runner, running the attempt or decoding the observation.
pub fn observe_attempt(attempt: &CaseAttempt) -> TestResult<SubjectObservation> {
    let program = WorkerProgramV1::new(PathBuf::from(WORKER)).ok_or("an invalid worker path")?;
    let runner = SupervisorRunnerV1::new(program);
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut out = Vec::new();
    run_with(&runner, stream.as_slice(), &mut out)?;
    Ok(read_observation(out.as_slice(), 1_048_576)?)
}

/// The provider's typed failure with code `code_id`.
#[must_use]
pub fn failure(code_id: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: "pigloros.fixture.plugin-conformance".to_owned(),
        contract_version: "2.0.0".to_owned(),
        code_id: code_id.to_owned(),
    })
}

/// The attempt of `family` with only the sub-case `id`, which `edit` may change.
///
/// # Errors
/// Returns the error of building or rewriting the attempt.
pub fn one_subcase(
    family: FixtureFamily,
    id: &str,
    edit: impl Fn(&mut Value),
) -> TestResult<CaseAttempt> {
    let attempt = attempt_from_fixture_files(family, ExecutionMode::Local)?;
    rewrite_subcases(attempt, |subcase| {
        let keep = subcase["id"] == id;
        if keep {
            edit(subcase);
        }
        keep
    })
}

/// The edit that sets the expected `error` of a sub-case.
pub fn expecting(error: &'static str) -> impl Fn(&mut Value) {
    move |subcase| subcase["expect"]["error"] = error.into()
}

/// The measured usage of the observation stays within the budget the provider declares.
///
/// # Errors
/// Returns the error of reading the provider manifest.
///
/// # Panics
/// Panics when a counter exceeds its budget.
pub fn assert_within_budget(family: FixtureFamily, observation: &SubjectObservation) -> TestResult {
    let (budget, usage) = (family_budget(family)?, observation.usage);
    let pairs = [
        (usage.memory_bytes, budget.memory_bytes),
        (usage.cpu_fuel, budget.cpu_fuel),
        (usage.host_calls, budget.host_calls),
        (usage.event_count, budget.event_count),
        (usage.output_bytes, budget.output_bytes),
        (usage.storage_bytes, budget.storage_bytes),
        (usage.execution_steps, budget.execution_steps),
        (usage.simulation_time_ns, budget.simulation_time_ns),
    ];
    assert!(
        pairs.iter().all(|(used, limit)| used <= limit),
        "{family:?} {usage:?}"
    );
    Ok(())
}

/// The observation equals the oracle member of `family` byte for byte and stays within budget.
///
/// # Errors
/// Returns the error of reading the oracle or the provider manifest.
///
/// # Panics
/// Panics when the observation differs from the oracle or exceeds the budget.
pub fn assert_output_is_the_oracle(
    family: FixtureFamily,
    observation: &SubjectObservation,
) -> TestResult {
    let oracle = SubjectResult::Output(oracle_bytes(family)?);
    assert_eq!(observation.result, oracle, "{family:?}");
    assert_within_budget(family, observation)
}
