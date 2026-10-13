#![cfg(target_os = "linux")]

//! R8-A7: the binary at its process boundary. The tests never read the real standard input.

use std::io::Write;
use std::process::{Command, Stdio};

use pos_plugin_conformance_adapter::schema_digests::placeholder_schema;
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-plugin-conformance-adapter");

fn artifact(bytes: &[u8]) -> AttemptArtifact {
    AttemptArtifact {
        digest: *blake3::hash(bytes).as_bytes(),
        bytes: bytes.to_vec(),
    }
}

/// An attempt of another claim layer: the adapter answers it without running anything.
fn foreign_layer_attempt() -> CaseAttempt {
    let family = FixtureFamily::Positive;
    CaseAttempt {
        case_id: "case-1".to_owned(),
        claim_layer: ClaimLayer::ArtifactIntegrity,
        family,
        mode: ExecutionMode::Local,
        fixture_digest: [9; 32],
        schema: artifact(placeholder_schema(family)),
        payload: artifact(b"{}"),
        auxiliary: Vec::new(),
        budget: DeterministicBudget {
            memory_bytes: 1,
            cpu_fuel: 1,
            host_calls: 1,
            event_count: 1,
            output_bytes: 1_048_576,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
        },
        watchdog_ms: 60_000,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 1_048_576,
            max_attempt_bytes: 2_097_152,
        },
    }
}

#[test]
fn a_null_stdin_gives_no_observation_and_a_non_zero_exit() -> TestResult {
    let output = Command::new(BINARY)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(output.status.code(), Some(2), "a wire fault");
    assert!(output.stdout.is_empty(), "no EAO1 stream");
    Ok(())
}

#[test]
fn an_attempt_on_stdin_gives_one_observation_on_stdout() -> TestResult {
    let mut stream = Vec::new();
    write_attempt(&mut stream, &foreign_layer_attempt())?;
    let mut child = Command::new(BINARY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(&stream)?;
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    let observation = read_observation(output.stdout.as_slice(), 1_048_576)?;
    assert_eq!(observation.result, SubjectResult::Unavailable);
    assert_eq!(observation.usage, ResourceUsage::default());
    Ok(())
}

#[test]
fn an_attempt_that_is_not_executed_gives_no_observation_and_a_non_zero_exit() -> TestResult {
    let mut attempt = foreign_layer_attempt();
    attempt.claim_layer = ClaimLayer::PluginConformance;
    attempt.payload = artifact(br#"{"schema":"pigloros.plugin-conformance.case.v1"}"#);
    let mut stream = Vec::new();
    write_attempt(&mut stream, &attempt)?;
    let mut child = Command::new(BINARY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(&stream)?;
    let output = child.wait_with_output()?;
    assert_eq!(output.status.code(), Some(3), "not executed");
    assert!(output.stdout.is_empty());
    Ok(())
}
