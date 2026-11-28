#![cfg(target_os = "linux")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests of the #444 evidence adapter: the real binary reads
//! a real EAI1 stream on stdin and writes a valid EAO1 observation, through
//! the pos-reference codec, as the DDI's `/adapter` does inside the unit.

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt as _;
use std::process::{Command, Stdio};

use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;
use pos_sandbox_evidence_adapter::{exit_code, observe, run, AdapterRunError, Mode, MODES};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-sandbox-evidence-adapter");

#[cfg_attr(coverage_nightly, coverage(off))]
fn artifact(bytes: &[u8]) -> AttemptArtifact {
    AttemptArtifact {
        digest: *blake3::hash(bytes).as_bytes(),
        bytes: bytes.to_vec(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn attempt(payload: &[u8]) -> CaseAttempt {
    CaseAttempt {
        case_id: "evidence-honest".to_owned(),
        claim_layer: ClaimLayer::MetricConformance,
        family: FixtureFamily::Positive,
        mode: ExecutionMode::AirGapped,
        fixture_digest: *blake3::hash(payload).as_bytes(),
        schema: artifact(b"schema"),
        payload: artifact(payload),
        auxiliary: Vec::new(),
        budget: DeterministicBudget {
            memory_bytes: 1 << 20,
            cpu_fuel: 1 << 20,
            host_calls: 1 << 10,
            event_count: 1 << 10,
            output_bytes: 1 << 10,
            storage_bytes: 1 << 20,
            execution_steps: 1 << 20,
            simulation_time_ns: 1 << 30,
        },
        watchdog_ms: 1_000,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 1 << 20,
            max_attempt_bytes: 1 << 22,
        },
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn encoded(payload: &[u8]) -> TestResult<Vec<u8>> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, &attempt(payload))?;
    Ok(stream)
}

/// Run the real binary with `arguments`, feeding it `input`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn(arguments: &[&str], input: &[u8]) -> TestResult<std::process::Output> {
    let mut child = Command::new(BINARY)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(input)
        .or_else(|error| {
            // A refused run may close stdin before reading it.
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(error)
            }
        })?;
    Ok(child.wait_with_output()?)
}

#[test]
fn the_binary_reports_the_payload_digest_as_a_valid_observation() -> TestResult {
    let output = spawn(&["honest"], &encoded(b"the payload")?)?;
    assert!(output.status.success());
    let observation = read_observation(output.stdout.as_slice(), 1 << 10)?;
    assert_eq!(
        observation.result,
        SubjectResult::Output(blake3::hash(b"the payload").as_bytes().to_vec())
    );
    assert_eq!(
        observation.usage,
        ResourceUsage {
            output_bytes: 32,
            ..ResourceUsage::default()
        }
    );
    Ok(())
}

#[test]
fn the_output_depends_on_the_payload_not_on_a_constant() {
    let first = observe(Mode::Honest, &attempt(b"one"));
    let second = observe(Mode::Honest, &attempt(b"two"));
    assert_ne!(first.result, second.result);
}

#[test]
fn a_bad_mode_or_argument_count_writes_nothing_and_exits_64() -> TestResult {
    for arguments in [&[][..], &["unknown"][..], &["honest", "extra"][..]] {
        let output = spawn(arguments, &encoded(b"payload")?)?;
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn a_non_utf8_mode_is_a_usage_failure() {
    let result = run([OsString::from_vec(vec![0xff])], io::empty(), io::sink());
    assert_eq!(result, Err(AdapterRunError::Usage));
}

#[test]
fn the_table_starts_with_the_honest_mode() {
    assert_eq!(MODES[0], ("honest", Mode::Honest));
}

#[test]
fn a_stream_that_is_not_one_exact_eai1_attempt_writes_nothing_and_exits_2() -> TestResult {
    let valid = encoded(b"payload")?;
    let mut trailing = valid.clone();
    trailing.push(0);
    for input in [
        b"not an attempt".to_vec(),
        Vec::new(),
        trailing,
        valid[..valid.len() - 1].to_vec(),
    ] {
        let output = spawn(&["honest"], &input)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

/// A writer that accepts nothing, or accepts everything and refuses to flush,
/// and counts the `write` calls it gets.
struct Refusing {
    accepted: Vec<u8>,
    writes: usize,
    refuse_write: bool,
}

impl Write for Refusing {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.refuse_write {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            self.accepted.extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn an_unwritable_or_unflushable_output_is_an_output_failure() -> TestResult {
    for refuse_write in [true, false] {
        let mut writer = Refusing {
            accepted: Vec::new(),
            writes: 0,
            refuse_write,
        };
        let result = run(
            ["honest"].map(OsString::from),
            encoded(b"payload")?.as_slice(),
            &mut writer,
        );
        assert_eq!(result, Err(AdapterRunError::Output));
        // The complete stream is handed over in exactly one write, never in frames.
        assert_eq!(writer.writes, 1);
        if refuse_write {
            assert!(writer.accepted.is_empty());
        } else {
            assert!(read_observation(writer.accepted.as_slice(), 1 << 10).is_ok());
        }
    }
    Ok(())
}

#[test]
fn every_failure_has_its_own_exit_code_and_message() {
    let failures = [
        (AdapterRunError::Usage, 64),
        (AdapterRunError::Wire, 2),
        (AdapterRunError::Output, 4),
    ];
    for (failure, code) in failures {
        assert_eq!(failure.code(), code);
        assert_eq!(exit_code(Err(failure)), std::process::ExitCode::from(code));
        assert!(!failure.to_string().is_empty());
    }
    assert_eq!(exit_code(Ok(())), std::process::ExitCode::SUCCESS);
}
