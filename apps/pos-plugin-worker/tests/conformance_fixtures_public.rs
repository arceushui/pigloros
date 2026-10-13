#![cfg(target_os = "linux")]

//! R8-F7a: the committed prototype guests run the checked-in Plugin conformance fixtures on
//! the real `pos-plugin-worker` (ADR-061 revision 8 decision 8).
//!
//! The attempts are built from the files of `fixtures/conformance` and run through the adapter
//! library's `run_with` with the real worker, so the digests the generator computed from the
//! specification (`H1` of both guests, `H2` of the carried state, the release identities and
//! the profile digest of `ind.*`, the `FuelExhausted` of `res.1`, the redaction of `del.1`)
//! are the ones the host computes. No fixture type is named here.

pub mod support;

use std::path::PathBuf;

use pos_plugin_conformance_adapter::{run_with, SupervisorRunnerV1};
use pos_plugin_supervisor::WorkerProgramV1;
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_reference::profile::NamespacedFailure;
use support::attempts::{attempt_from_fixture_files, family_budget, oracle_bytes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKER: &str = env!("CARGO_BIN_EXE_pos-plugin-worker");

/// The observation of `family` in `mode` from the adapter library over the real worker.
fn observe(family: FixtureFamily, mode: ExecutionMode) -> TestResult<SubjectObservation> {
    let program = WorkerProgramV1::new(PathBuf::from(WORKER)).ok_or("an invalid worker path")?;
    let runner = SupervisorRunnerV1::new(program);
    let mut stream = Vec::new();
    write_attempt(&mut stream, &attempt_from_fixture_files(family, mode)?)?;
    let mut out = Vec::new();
    run_with(&runner, stream.as_slice(), &mut out)?;
    Ok(read_observation(out.as_slice(), 1_048_576)?)
}

/// The measured usage of the observation stays within the budget the provider declares.
fn assert_within_budget(family: FixtureFamily, observation: &SubjectObservation) -> TestResult {
    let (budget, usage) = (family_budget(family)?, observation.usage);
    assert!(
        usage.memory_bytes <= budget.memory_bytes,
        "{family:?} {usage:?}"
    );
    assert!(usage.cpu_fuel <= budget.cpu_fuel, "{family:?} {usage:?}");
    assert!(
        usage.host_calls <= budget.host_calls,
        "{family:?} {usage:?}"
    );
    assert!(
        usage.event_count <= budget.event_count,
        "{family:?} {usage:?}"
    );
    assert!(
        usage.output_bytes <= budget.output_bytes,
        "{family:?} {usage:?}"
    );
    assert!(
        usage.storage_bytes <= budget.storage_bytes,
        "{family:?} {usage:?}"
    );
    assert!(
        usage.execution_steps <= budget.execution_steps,
        "{family:?} {usage:?}"
    );
    assert!(
        usage.simulation_time_ns <= budget.simulation_time_ns,
        "{family:?} {usage:?}"
    );
    Ok(())
}

/// The observation equals the oracle member byte for byte and stays within the budget.
fn assert_output_is_the_oracle(family: FixtureFamily, mode: ExecutionMode) -> TestResult {
    let observation = observe(family, mode)?;
    assert_eq!(
        observation.result,
        SubjectResult::Output(oracle_bytes(family)?),
        "{family:?} {mode:?}"
    );
    assert_within_budget(family, &observation)
}

#[test]
fn both_guests_commit_the_literals_in_local_and_air_gapped() -> TestResult {
    let oracle = SubjectResult::Output(oracle_bytes(FixtureFamily::Positive)?);
    let local = observe(FixtureFamily::Positive, ExecutionMode::Local)?;
    let air_gapped = observe(FixtureFamily::Positive, ExecutionMode::AirGapped)?;
    assert_eq!(local.result, oracle);
    assert_eq!(air_gapped.result, oracle);
    assert_eq!(local.usage, air_gapped.usage);
    assert!(local.usage.cpu_fuel > 0);
    assert_within_budget(FixtureFamily::Positive, &local)
}

#[test]
fn the_independent_evaluation_literals_are_the_hosts() -> TestResult {
    assert_output_is_the_oracle(FixtureFamily::IndependentEvaluation, ExecutionMode::Local)
}

#[test]
fn a_starved_fuel_budget_is_the_resource_limit_failure() -> TestResult {
    let observation = observe(FixtureFamily::ResourceExhaustion, ExecutionMode::Local)?;
    assert_eq!(
        observation.result,
        SubjectResult::Failure(NamespacedFailure {
            owner_id: "pigloros.fixture.plugin-conformance".to_owned(),
            contract_version: "2.0.0".to_owned(),
            code_id: "resource-limit".to_owned(),
        })
    );
    assert_within_budget(FixtureFamily::ResourceExhaustion, &observation)
}

#[test]
fn the_synthetic_marker_is_absent_from_every_committed_record() -> TestResult {
    assert_output_is_the_oracle(FixtureFamily::DeletionRedaction, ExecutionMode::Local)
}
