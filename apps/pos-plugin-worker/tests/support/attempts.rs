//! Case attempts built from the checked-in files of the Plugin conformance fixtures.
//!
//! The helper reads the payload, schema, composite, oracle and evidence-status members of
//! `fixtures/conformance` and delivers them as the evaluator would (EAI1): the schema and the
//! payload, then the auxiliary members in descriptor (bundle path) order. It names no fixture
//! type; the adapter library receives the stream through `run_with`.

use std::fs;
use std::path::PathBuf;

use pos_plugin_conformance_adapter::payload::family_text;
use pos_reference::evaluator::{AttemptArtifact, AttemptTransportCaps, CaseAttempt};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;
use serde_json::Value;

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
///
/// # Errors
/// Returns the error of reading or parsing the provider manifest.
pub fn family_budget(family: FixtureFamily) -> TestResult<DeterministicBudget> {
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
///
/// # Errors
/// Returns the error of reading the file.
pub fn oracle_bytes(family: FixtureFamily) -> TestResult<Vec<u8>> {
    let name = family_text(family);
    let path = fixture_root().join(format!("oracles/plugin-conformance/{name}.json"));
    Ok(fs::read(path)?)
}

/// The attempt of `family` in `mode` from the checked-in fixture files.
///
/// The members are the `inputs/`, schema, composite, oracle and evidence-status files, in
/// descriptor (bundle path) order. A namespaced-failure oracle is an auxiliary member, as the
/// evaluator delivers it.
///
/// The same helper lives in `apps/pos-plugin-conformance-adapter/tests/fixture_attempts_public.rs`
/// and `apps/pos-plugin-worker/tests/support/attempts.rs`; keep the two in step.
///
/// # Errors
/// Returns the error of reading or parsing a file.
pub fn attempt_from_fixture_files(
    family: FixtureFamily,
    mode: ExecutionMode,
) -> TestResult<CaseAttempt> {
    let root = fixture_root();
    let name = family_text(family);
    let read = |relative: String| fs::read(root.join(relative));
    let payload = read(format!("inputs/plugin-conformance/{name}.json"))?;
    let evidence = read(format!("expected/plugin-conformance/{name}.json"))?;
    let composite = read(format!("inputs/plugin-conformance/{name}.pcw2"))?;
    let schema = read(format!(
        "providers/plugin-conformance/schemas/{name}.schema.json"
    ))?;
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
