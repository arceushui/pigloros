#![cfg(target_os = "linux")]

//! R8-F7a: the committed prototype guests run the checked-in Plugin conformance fixtures on
//! the real `pos-plugin-worker` (ADR-061 revision 8 decision 8).
//!
//! The attempts are built from the files of `fixtures/conformance` and run through the adapter
//! library's `run_with` with the real worker, so the digests the generator computed from the
//! specification (`H1` of both guests, `H2` of the carried state, the release identities and
//! the profile digest of `ind.*`, the `FuelExhausted` of `res.1`, the redaction of `del.1` and
//! `del.2`) are the ones the host computes. No fixture type is named here.
//!
//! R8-F7b: `res.2` to `res.4` (memory, host-call and `event_bytes` limits of the signed release)
//! and the `del.2` inputs run on the real worker.
//!
//! R8-F2c: the load-time link failures `den.03` to `den.12` of the `denied` family give
//! `IncompatibleAbi` from the real worker. The `denied` case, which also holds the sub-cases
//! that refuse before a launch, is the failure of its oracle only when every sub-case matched;
//! each link failure is also run alone, with a control whose expectation is changed.

pub mod support;

use pos_reference::evaluator::{SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use serde_json::Value;
use support::attempts::{attempt_from_fixture_files, oracle_bytes};
use support::subcase::{
    assert_within_budget, expecting, failure, observe_attempt, one_subcase,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The observation of `family` in `mode` from the adapter library over the real worker.
fn observe(family: FixtureFamily, mode: ExecutionMode) -> TestResult<SubjectObservation> {
    observe_attempt(&attempt_from_fixture_files(family, mode)?)
}

/// The observation equals the oracle member byte for byte and stays within the budget.
fn assert_output_is_the_oracle(family: FixtureFamily, mode: ExecutionMode) -> TestResult {
    support::subcase::assert_output_is_the_oracle(family, &observe(family, mode)?)
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

/// The IDs of the sub-cases of `resource-exhaustion`, one per limit of the signed release.
const RESOURCE_LIMITS: [&str; 4] = ["res.1", "res.2", "res.3", "res.4"];

#[test]
fn starved_budgets_are_the_resource_limit_failure() -> TestResult {
    for mode in [ExecutionMode::Local, ExecutionMode::AirGapped] {
        let observation = observe(FixtureFamily::ResourceExhaustion, mode)?;
        assert_eq!(observation.result, failure("resource-limit"), "{mode:?}");
        assert_within_budget(FixtureFamily::ResourceExhaustion, &observation)?;
    }
    Ok(())
}

/// R8-F7b: each limit of the signed release gives its own error at pass level. The case code
/// `resource-limit` is the failure of the family oracle only when every sub-case matched, so
/// each sub-case is run alone, with a control whose expected error is another well-formed one.
#[test]
fn each_resource_limit_gives_its_error_from_the_real_worker() -> TestResult {
    let family = FixtureFamily::ResourceExhaustion;
    assert_eq!(subcase_ids(family)?, RESOURCE_LIMITS);
    for id in RESOURCE_LIMITS {
        let matched = observe_attempt(&one_subcase(family, id, unchanged)?)?;
        assert_eq!(matched.result, failure("resource-limit"), "{id}");
        let other = observe_attempt(&one_subcase(family, id, expecting("ComponentTrap"))?)?;
        assert_eq!(other.result, failure("subcase-mismatch"), "{id}");
    }
    Ok(())
}

#[test]
fn the_synthetic_marker_is_absent_from_every_committed_record() -> TestResult {
    assert_output_is_the_oracle(FixtureFamily::DeletionRedaction, ExecutionMode::Local)
}

/// The marker of the control: the Plugin ID text, which the outcome record holds as CBOR text.
const OUTCOME_MARKER: &str = "compatibility-prototype";

/// The edit that makes the `scan` of a sub-case search for [`OUTCOME_MARKER`] in the outcome
/// record only; the expectation names the same marker, as the grammar requires.
fn scanning_the_outcome(subcase: &mut Value) {
    let scan = subcase["steps"]
        .as_array_mut()
        .and_then(|steps| steps.last_mut());
    if let Some(scan) = scan {
        scan["in"] = serde_json::json!(["outcome"]);
        scan["marker"] = OUTCOME_MARKER.into();
    }
    subcase["expect"]["marker"] = OUTCOME_MARKER.into();
}

/// The text of the canonical output the observation gives.
fn output_text(observation: &SubjectObservation) -> TestResult<String> {
    let SubjectResult::Output(bytes) = &observation.result else {
        return Err("the observation is not an output".into());
    };
    Ok(String::from_utf8(bytes.clone())?)
}

/// R8-F7b: the log text `drive` is in no committed Event payload or state of the real worker.
/// The control searches the outcome record for the Plugin ID text it holds: the scan finds it
/// there, so the sub-case is written as `{"id","kind":"mismatch"}` and never as an `absent`
/// entry (the Event type is not in the `POB1` outcome record, so `drive` itself is not used).
#[test]
fn the_log_text_is_absent_from_events_and_state_but_a_scan_finds_the_outcome_text() -> TestResult {
    let family = FixtureFamily::DeletionRedaction;
    let absent = "\"id\":\"del.2\",\"kind\":\"absent\",\"prohibited_data_present\":false";
    let matched = output_text(&observe_attempt(&one_subcase(family, "del.2", unchanged)?)?)?;
    assert!(matched.contains(absent), "unexpected output: {matched}");
    let found = observe_attempt(&one_subcase(family, "del.2", scanning_the_outcome)?)?;
    let control = output_text(&found)?;
    assert!(
        control.contains("\"id\":\"del.2\",\"kind\":\"mismatch\""),
        "unexpected control output: {control}"
    );
    Ok(())
}

/// The IDs of the sub-cases of `denied` that fail at load on the real worker.
fn link_failures() -> impl Iterator<Item = String> {
    (3..=12).map(|number| format!("den.{number:02}"))
}

/// The edit that leaves a sub-case as it is.
const fn unchanged(_subcase: &mut Value) {}

/// The IDs of the sub-cases of `family` in its checked-in payload.
fn subcase_ids(family: FixtureFamily) -> TestResult<Vec<String>> {
    let attempt = attempt_from_fixture_files(family, ExecutionMode::Local)?;
    let payload: Value = serde_json::from_slice(&attempt.payload.bytes)?;
    let subcases = payload["subcases"].as_array().ok_or("no sub-cases")?;
    Ok(subcases
        .iter()
        .filter_map(|subcase| subcase["id"].as_str().map(str::to_owned))
        .collect())
}

#[test]
fn each_load_time_link_failure_is_incompatible_abi_from_the_real_worker() -> TestResult {
    for id in link_failures() {
        let matched = observe_attempt(&one_subcase(FixtureFamily::Denied, &id, unchanged)?)?;
        assert_eq!(matched.result, failure("capability-denied"), "{id}");
        // The case code `capability-denied` is the observable of `IncompatibleAbi`: the case is
        // that failure only when every sub-case matched, and `den.03` to `den.12` expect that
        // refusal. The control: the same sub-case expecting another well-formed refusal
        // (`InvalidManifest` needs no `basis` and no `index`) reaches the matcher and does not
        // match.
        let altered = expecting("InvalidManifest");
        let other = observe_attempt(&one_subcase(FixtureFamily::Denied, &id, altered)?)?;
        assert_eq!(other.result, failure("subcase-mismatch"), "{id}");
    }
    Ok(())
}
