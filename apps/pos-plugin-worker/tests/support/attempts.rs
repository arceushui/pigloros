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

/// Whether the oracle of `family` is a namespaced failure, which the evaluator delivers to the
/// adapter as an auxiliary member.
const fn has_failure_oracle(family: FixtureFamily) -> bool {
    matches!(
        family,
        FixtureFamily::Denied
            | FixtureFamily::Malformed
            | FixtureFamily::ResourceExhaustion
            | FixtureFamily::Downgrade
    )
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

/// The attempt of `family` in `mode`.
///
/// # Errors
/// Returns the error of reading a file.
pub fn attempt_from_fixture_files(
    family: FixtureFamily,
    mode: ExecutionMode,
) -> TestResult<CaseAttempt> {
    let root = fixture_root();
    let name = family_text(family);
    let read = |relative: String| fs::read(root.join(relative));
    let payload = read(format!("inputs/plugin-conformance/{name}.json"))?;
    let schema = read(format!("providers/plugin-conformance/schemas/{name}.schema.json"))?;
    let evidence = read(format!("expected/plugin-conformance/{name}.json"))?;
    let composite = read(format!("inputs/plugin-conformance/{name}.pcw2"))?;
    let mut auxiliary = vec![artifact(evidence)];
    if has_failure_oracle(family) {
        auxiliary.push(artifact(oracle_bytes(family)?));
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
        budget: DeterministicBudget {
            memory_bytes: 8_388_608,
            cpu_fuel: 1_000_000,
            host_calls: 100,
            event_count: 1000,
            output_bytes: 1_048_576,
            storage_bytes: 8_388_608,
            execution_steps: 100_000,
            simulation_time_ns: 1_000_000_000,
        },
        watchdog_ms: 3_000_000,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 16_777_216,
            max_attempt_bytes: 67_108_864,
        },
    })
}
