#![cfg(target_os = "linux")]

//! R8-F2b and R8-F4: the checked-in attempts of the Plugin provider, built from the files of
//! `fixtures/conformance` the way the evaluator delivers them.
//!
//! For every family the attempt has at most three auxiliary members, the schema member has the
//! digest the adapter pins, and the payload grammar and the composite pieces decode. With
//! `/bin/false` as the worker program, every present sub-case that refuses before a worker
//! launch (`den.01`, `den.02`, `den.13` to `den.22`, every `mal.*` and every `dgr.*`) gives its
//! closed error, so the case gives the failure of the family oracle. The positive and
//! independent-evaluation attempts launch a worker and are decoded only, and so are the link
//! failures `den.03` to `den.12`, which only a worker can give: with `/bin/false` they make the
//! whole `denied` case `Unavailable`. The real worker proves them in `pos-plugin-worker`.

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

/// Whether the sub-case `id` is a link failure that only a launched worker can give.
fn launches_a_worker(id: &str) -> bool {
    id.strip_prefix("den.")
        .and_then(|number| number.parse::<u32>().ok())
        .is_some_and(|number| (3..=12).contains(&number))
}

/// `attempt` with the sub-cases that launch a worker taken out of its payload.
///
/// The worker's `tests/support/attempts.rs` has the general form (`rewrite_subcases`); the two
/// test crates cannot share a helper, so keep them in step.
fn without_launches(mut attempt: CaseAttempt) -> TestResult<CaseAttempt> {
    let mut payload: Value = serde_json::from_slice(&attempt.payload.bytes)?;
    let subcases = payload["subcases"].as_array_mut().ok_or("no sub-cases")?;
    subcases.retain(|subcase| !subcase["id"].as_str().is_some_and(launches_a_worker));
    let mut bytes = serde_json::to_vec(&payload)?;
    bytes.push(b'\n');
    attempt.fixture_digest = *blake3::hash(&bytes).as_bytes();
    attempt.payload = artifact(bytes);
    Ok(attempt)
}

fn subcase_ids(attempt: &CaseAttempt) -> TestResult<Vec<String>> {
    let payload: Value = serde_json::from_slice(&attempt.payload.bytes)?;
    let subcases = payload["subcases"].as_array().ok_or("no sub-cases")?;
    Ok(subcases
        .iter()
        .filter_map(|subcase| subcase["id"].as_str().map(str::to_owned))
        .collect())
}

/// The observation of `attempt` with `/bin/false` as the worker program.
fn observe_without_worker(attempt: &CaseAttempt) -> TestResult<SubjectResult> {
    let runner = SupervisorRunnerV1::with_program("/bin/false").ok_or("a relative program")?;
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut out = Vec::new();
    run_with(&runner, stream.as_slice(), &mut out)?;
    Ok(read_observation(out.as_slice(), 1_048_576)?.result)
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
            let attempt = without_launches(attempt_from_fixture_files(family, mode)?)?;
            let result = observe_without_worker(&attempt)?;
            assert_eq!(result, expected, "{family:?} {mode:?}");
        }
    }
    Ok(())
}

#[test]
fn the_denied_sub_cases_split_into_link_failures_and_refusals_before_a_launch() -> TestResult {
    let attempt = attempt_from_fixture_files(FixtureFamily::Denied, ExecutionMode::Local)?;
    let all = subcase_ids(&attempt)?;
    let expected: Vec<String> = (1..=22).map(|number| format!("den.{number:02}")).collect();
    assert_eq!(all, expected);
    let remaining = subcase_ids(&without_launches(attempt.clone())?)?;
    let mut refusals = vec!["den.01".to_owned(), "den.02".to_owned()];
    refusals.extend((13..=22).map(|number| format!("den.{number}")));
    assert_eq!(remaining, refusals);
    // The link failures give no verdict without a worker: the case is Unavailable.
    assert_eq!(
        observe_without_worker(&attempt)?,
        SubjectResult::Unavailable
    );
    Ok(())
}

/// R8-F5 (with `scripts/check_plugin_conformance_expected.py`): the Local and Air-Gapped attempts
/// of a family carry the same payload digest, and it is the one the pending record binds.
#[test]
fn both_modes_bind_the_digest_of_the_pending_record() -> TestResult {
    for family in FixtureFamily::ALL.iter().copied() {
        let local = attempt_from_fixture_files(family, ExecutionMode::Local)?;
        let air_gapped = attempt_from_fixture_files(family, ExecutionMode::AirGapped)?;
        assert_eq!(local.fixture_digest, air_gapped.fixture_digest, "{family:?}");
        let name = family_text(family);
        let path = fixture_root().join(format!("expected/plugin-conformance/{name}.json"));
        let record: Value = serde_json::from_slice(&fs::read(path)?)?;
        assert_eq!(record["status"], "pending", "{family:?}");
        let digest: String = local.fixture_digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(record["input_blake3_digest"], digest, "{family:?}");
    }
    Ok(())
}
