#![cfg(target_os = "linux")]

//! R8-F2b and R8-F4: the checked-in attempts of the Plugin provider, built from the files of
//! `fixtures/conformance` the way the evaluator delivers them.
//!
//! For every family the attempt has at most three auxiliary members, the schema member has the
//! digest the adapter pins, and the payload grammar and the composite pieces decode. With
//! `/bin/false` as the worker program, every present sub-case that refuses before a worker
//! launch (`denied`, `malformed` and `downgrade`) gives its closed error, so the case gives the
//! failure of the family oracle. The positive and independent-evaluation attempts launch a
//! worker and are decoded only; the real worker proves them in `pos-plugin-worker`.

use std::fs;
use std::path::PathBuf;

use pos_plugin_conformance_adapter::payload::{family_text, CaseV1};
use pos_plugin_conformance_adapter::schema_digests::pinned_digest;
use pos_plugin_conformance_adapter::world::PreparedV1;
use pos_plugin_conformance_adapter::{run_with, PiecesV1, SupervisorRunnerV1};
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{AttemptArtifact, AttemptTransportCaps, CaseAttempt, SubjectResult};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::{DeterministicBudget, NamespacedFailure};
use serde_json::Value;

const MODES: [ExecutionMode; 2] = [ExecutionMode::Local, ExecutionMode::AirGapped];

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

fn artifact(bytes: Vec<u8>) -> AttemptArtifact {
    AttemptArtifact {
        digest: *blake3::hash(&bytes).as_bytes(),
        bytes,
    }
}

/// The `fixture_contracts` entry of `family` in the provider manifest.
fn family_contract(family: FixtureFamily) -> TestResult<Value> {
    let provider = fs::read(fixture_root().join("providers/plugin-conformance/provider.json"))?;
    let provider: Value = serde_json::from_slice(&provider)?;
    Ok(provider["fixture_contracts"][family_text(family)].clone())
}

fn counter(budget: &Value, key: &str) -> TestResult<u64> {
    Ok(budget[key].as_u64().ok_or("a budget counter is absent")?)
}

/// The deterministic budget the provider declares for `family`.
fn family_budget(family: FixtureFamily) -> TestResult<DeterministicBudget> {
    let contract = family_contract(family)?;
    let budget = &contract["deterministic_budget"];
    Ok(DeterministicBudget {
        memory_bytes: counter(budget, "memory_bytes")?,
        cpu_fuel: counter(budget, "cpu_fuel")?,
        host_calls: counter(budget, "host_calls")?,
        event_count: counter(budget, "event_count")?,
        output_bytes: counter(budget, "output_bytes")?,
        storage_bytes: counter(budget, "storage_bytes")?,
        execution_steps: counter(budget, "execution_steps")?,
        simulation_time_ns: counter(budget, "simulation_time_ns")?,
    })
}

/// The bytes of the oracle member of `family`.
fn oracle_bytes(family: FixtureFamily) -> TestResult<Vec<u8>> {
    let name = family_text(family);
    let path = fixture_root().join(format!("oracles/plugin-conformance/{name}.json"));
    Ok(fs::read(path)?)
}

/// The attempt of `family` in `mode` from the checked-in `inputs/`, schema, composite, oracle
/// and evidence-status members, in descriptor (bundle path) order. A namespaced-failure oracle
/// is an auxiliary member, as the evaluator delivers it.
///
/// The same helper lives in `apps/pos-plugin-conformance-adapter/tests/fixture_attempts_public.rs`
/// and `apps/pos-plugin-worker/tests/support/attempts.rs`; keep the two in step.
fn attempt_from_fixture_files(
    family: FixtureFamily,
    mode: ExecutionMode,
) -> TestResult<CaseAttempt> {
    let root = fixture_root();
    let name = family_text(family);
    let read = |relative: String| fs::read(root.join(relative));
    let payload = read(format!("inputs/plugin-conformance/{name}.json"))?;
    let evidence = read(format!("expected/plugin-conformance/{name}.json"))?;
    let composite = read(format!("inputs/plugin-conformance/{name}.pcw2"))?;
    let schema = read(format!("providers/plugin-conformance/schemas/{name}.schema.json"))?;
    let oracle = oracle_bytes(family)?;
    let kind = serde_json::from_slice::<Value>(&oracle)?["oracle"]["kind"].clone();
    let contract = family_contract(family)?;
    let mut auxiliary = vec![artifact(evidence)];
    if kind == "namespaced-failure" {
        auxiliary.push(artifact(oracle));
    }
    auxiliary.push(artifact(composite));
    Ok(CaseAttempt {
        case_id: format!("plugin-conformance-{name}"),
        claim_layer: ClaimLayer::PluginConformance,
        family,
        mode,
        fixture_digest: *blake3::hash(&payload).as_bytes(),
        schema: artifact(schema),
        payload: artifact(payload),
        auxiliary,
        budget: family_budget(family)?,
        watchdog_ms: contract["watchdog_ms"].as_u64().ok_or("no watchdog")?,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 16_777_216,
            max_attempt_bytes: 67_108_864,
        },
    })
}

#[test]
fn every_attempt_names_the_pinned_schema_and_decodes() -> TestResult {
    for family in FixtureFamily::ALL.iter().copied() {
        for mode in MODES {
            let attempt = attempt_from_fixture_files(family, mode)?;
            assert!(attempt.auxiliary.len() <= 3, "{family:?}");
            assert_eq!(attempt.schema.digest, pinned_digest(family), "{family:?}");
            let pieces = PiecesV1::find(&attempt.auxiliary)?;
            let case = CaseV1::parse(&attempt.payload.bytes, family)?;
            assert!(!case.subcases.is_empty(), "{family:?}");
            for subcase in &case.subcases {
                assert!(
                    PreparedV1::build(subcase, &pieces).is_ok(),
                    "{family:?} {}",
                    subcase.id.as_str()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn sub_cases_that_refuse_before_a_launch_give_the_family_failure_without_a_worker() -> TestResult {
    let runner = SupervisorRunnerV1::with_program("/bin/false").ok_or("a relative program")?;
    for family in [
        FixtureFamily::Denied,
        FixtureFamily::Malformed,
        FixtureFamily::Downgrade,
    ] {
        let oracle: Value = serde_json::from_slice(&oracle_bytes(family)?)?;
        let text = |key: &str| oracle["oracle"][key].as_str().map(str::to_owned);
        let expected = SubjectResult::Failure(NamespacedFailure {
            owner_id: text("owner_id").ok_or("no owner")?,
            contract_version: text("contract_version").ok_or("no version")?,
            code_id: text("code_id").ok_or("no code")?,
        });
        for mode in MODES {
            let mut stream = Vec::new();
            write_attempt(&mut stream, &attempt_from_fixture_files(family, mode)?)?;
            let mut out = Vec::new();
            run_with(&runner, stream.as_slice(), &mut out)?;
            let observation = read_observation(out.as_slice(), 1_048_576)?;
            assert_eq!(observation.result, expected, "{family:?} {mode:?}");
        }
    }
    Ok(())
}
