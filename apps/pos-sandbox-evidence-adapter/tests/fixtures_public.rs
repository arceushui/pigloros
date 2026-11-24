#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! The #216 malicious and limit fixtures through the adapter's public
//! interface. Every probe is aimed at a target whose answer is known on the
//! test host; the fixed in-sandbox targets are only counted, because their
//! answers depend on who runs the test. Limits use tiny bounds.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, ResourceUsage, SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;
use pos_sandbox_evidence_adapter::fixture::{
    exhaust_memory, exhaust_tasks, fill_work_area, judge, leave_orphan,
};
use pos_sandbox_evidence_adapter::probe::{
    self, connect_tcp, connect_unix, contained, create_directory, create_file, create_socket,
    mount_tmpfs, open_read, open_write, remove_file, signal_foreign, udp_exchange,
};
use pos_sandbox_evidence_adapter::{apply, exit_code, run, AdapterRunError, After, Fixture, Mode};
use rustix::net::{AddressFamily, SocketType};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BINARY: &str = env!("CARGO_BIN_EXE_pos-sandbox-evidence-adapter");

const EVERY_FIXTURE: [Fixture; 13] = [
    Fixture::FilesystemEscape,
    Fixture::ReadOnlyRootWrite,
    Fixture::WorkAreaExhaustion(7),
    Fixture::NetworkEscape,
    Fixture::ForeignSignals,
    Fixture::OrphanedChild,
    Fixture::TaskExhaustion(7),
    Fixture::MemoryExhaustion(7),
    Fixture::WatchdogExpiry(7),
    Fixture::OversizedOutput(7),
    Fixture::AdapterCrash,
    Fixture::MalformedOutput,
    Fixture::Idle(7),
];

#[cfg_attr(coverage_nightly, coverage(off))]
fn artifact(bytes: &[u8]) -> AttemptArtifact {
    AttemptArtifact {
        digest: *blake3::hash(bytes).as_bytes(),
        bytes: bytes.to_vec(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn encoded() -> TestResult<Vec<u8>> {
    let attempt = CaseAttempt {
        case_id: "fixture".to_owned(),
        claim_layer: ClaimLayer::MetricConformance,
        family: FixtureFamily::Positive,
        mode: ExecutionMode::AirGapped,
        fixture_digest: *blake3::hash(b"payload").as_bytes(),
        schema: artifact(b"schema"),
        payload: artifact(b"payload"),
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
    };
    let mut stream = Vec::new();
    write_attempt(&mut stream, &attempt)?;
    Ok(stream)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn run_mode(values: &[&str]) -> TestResult<(Result<(), AdapterRunError>, Vec<u8>)> {
    let mut output = Vec::new();
    let result = run(arguments(values), encoded()?.as_slice(), &mut output);
    Ok((result, output))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn has_net_raw() -> TestResult<bool> {
    let status = fs::read_to_string("/proc/self/status")?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .ok_or("no CapEff")?;
    Ok(u64::from_str_radix(effective.trim(), 16)? & (1 << 13) != 0)
}

#[test]
fn contained_needs_at_least_one_attempt_and_every_attempt_denied() {
    let denied = || Err(std::io::ErrorKind::PermissionDenied.into());
    assert!(!contained(&[]));
    assert!(contained(&[denied()]));
    assert!(contained(&[denied(), denied()]));
    assert!(!contained(&[Ok(())]));
    assert!(!contained(&[denied(), Ok(()), denied()]));
    assert!(!contained(&[Ok(()), denied()]));
}

#[test]
fn judge_reports_only_a_fully_denied_run() {
    let denied = || Err(std::io::ErrorKind::PermissionDenied.into());
    assert_eq!(judge(&[denied()]), Ok(After::Report));
    assert_eq!(judge(&[denied(), Ok(())]), Err(AdapterRunError::Escaped));
    assert_eq!(judge(&[]), Err(AdapterRunError::Escaped));
}

#[test]
fn file_probes_succeed_where_allowed_and_fail_where_not() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("file");
    let missing = dir.path().join("missing");
    assert!(open_read(&file).is_err());
    assert!(open_write(&file).is_err());
    assert!(remove_file(&file).is_err());
    assert!(create_file(&file).is_ok());
    assert!(create_file(&file).is_err());
    assert!(open_read(&file).is_ok());
    assert!(open_write(&file).is_ok());
    assert!(remove_file(&file).is_ok());
    assert!(open_read(&missing).is_err());
    let sub = dir.path().join("sub");
    assert!(create_directory(&sub).is_ok());
    assert!(create_directory(&sub).is_err());
    assert!(mount_tmpfs(&missing).is_err());
    Ok(())
}

#[test]
fn network_probes_follow_what_listens() -> TestResult {
    let dir = tempfile::tempdir()?;
    let tcp = TcpListener::bind("127.0.0.1:0")?;
    assert!(connect_tcp(&tcp.local_addr()?).is_ok());
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?
    };
    assert!(connect_tcp(&closed).is_err());

    let socket_path = dir.path().join("bus");
    assert!(connect_unix(&socket_path).is_err());
    let _listener = UnixListener::bind(&socket_path)?;
    assert!(connect_unix(&socket_path).is_ok());

    let echo = UdpSocket::bind("127.0.0.1:0")?;
    let echo_address = echo.local_addr()?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let mut buffer = [0_u8; 16];
        let (length, peer) = echo.recv_from(&mut buffer)?;
        echo.send_to(&buffer[..length], peer).map(drop)
    });
    assert!(udp_exchange(&echo_address).is_ok());
    server.join().map_err(|_| "echo thread panicked")??;
    assert!(udp_exchange(&echo_address).is_err());
    let unbound = {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.local_addr()?
    };
    assert!(udp_exchange(&unbound).is_err());
    assert!(udp_exchange(&"[::1]:9".parse()?).is_err());

    assert!(create_socket(AddressFamily::INET, SocketType::DGRAM).is_ok());
    assert_eq!(
        create_socket(AddressFamily::INET, SocketType::RAW).is_ok(),
        has_net_raw()?
    );
    Ok(())
}

#[test]
fn signalling_skips_the_adapter_itself_and_reaches_other_processes() {
    assert!(signal_foreign(0).is_err());
    assert!(signal_foreign(u32::MAX).is_err());
    let own = std::process::id();
    assert!(signal_foreign(own).is_err());
    let parent = std::os::unix::process::parent_id();
    assert!(signal_foreign(parent).is_ok());
}

#[test]
fn every_probe_fixture_lists_the_attempts_it_makes() -> TestResult {
    assert_eq!(probe::filesystem_escape().len(), 5);
    assert_eq!(probe::network_escape().len(), 5);
    assert_eq!(probe::foreign_signals(8).len(), 8);
    assert!(probe::foreign_signals(0).is_empty());
    assert_eq!(probe::LAST_PROBED_PID, 4096);

    let dir = tempfile::tempdir()?;
    let writable = probe::read_only_root_write(dir.path());
    assert_eq!(writable.len(), 4);
    // The adapter file is missing, so only its two probes fail.
    assert_eq!(
        writable.iter().map(Result::is_ok).collect::<Vec<_>>(),
        [true, false, true, false]
    );
    let again = probe::read_only_root_write(dir.path());
    assert_eq!(
        again.iter().map(Result::is_ok).collect::<Vec<_>>(),
        [false, false, false, false]
    );
    fs::write(dir.path().join("adapter"), b"x")?;
    let removable = probe::read_only_root_write(dir.path());
    assert_eq!(
        removable.iter().map(Result::is_ok).collect::<Vec<_>>(),
        [false, true, false, true]
    );
    Ok(())
}

#[test]
fn fixtures_name_themselves_and_parse_back() {
    let mut seen = Vec::new();
    for fixture in EVERY_FIXTURE {
        let id = fixture.id();
        assert!(!seen.contains(&id));
        seen.push(id);
        assert_eq!(Fixture::parse(id, fixture.bound()), Some(fixture));
        let mode = Mode::Fixture(fixture);
        assert_eq!(mode.argument(), id);
        assert_eq!(mode.bound(), fixture.bound());
        match fixture.bound() {
            Some(_) => {
                assert_eq!(Fixture::parse(id, None), None);
                assert_eq!(Fixture::parse(id, Some(0)), None);
            }
            None => assert_eq!(Fixture::parse(id, Some(1)), None),
        }
    }
    assert_eq!(Fixture::parse("honest", None), None);
    assert_eq!(Fixture::parse("unknown", None), None);
    assert_eq!(Mode::Honest.bound(), None);
}

#[test]
fn the_mode_arguments_are_one_id_and_an_optional_decimal_bound() -> TestResult {
    for bad in [
        &[][..],
        &["unknown"][..],
        &["honest", "1"][..],
        &["adapter-crash", "1"][..],
        &["memory-exhaustion"][..],
        &["memory-exhaustion", "0"][..],
        &["memory-exhaustion", "-1"][..],
        &["memory-exhaustion", "x"][..],
        &["memory-exhaustion", "1", "1"][..],
    ] {
        let (result, output) = run_mode(bad)?;
        assert_eq!(result, Err(AdapterRunError::Usage), "{bad:?}");
        assert!(output.is_empty());
    }
    let non_utf8 = [OsString::from_vec(vec![0xff, 0xfe])];
    assert_eq!(
        run(non_utf8, encoded()?.as_slice(), Vec::new()),
        Err(AdapterRunError::Usage)
    );
    Ok(())
}

#[test]
fn the_crash_and_escape_failures_have_their_own_codes() {
    assert_eq!(AdapterRunError::Escaped.code(), 3);
    assert_eq!(AdapterRunError::Crashed.code(), 70);
    assert_eq!(exit_code(Err(AdapterRunError::Crashed)), ExitCode::from(70));
    assert_ne!(
        AdapterRunError::Escaped.to_string(),
        AdapterRunError::Crashed.to_string()
    );
}

#[test]
fn the_crash_fixture_fails_and_the_malformed_fixture_writes_no_frame() -> TestResult {
    let (crash, output) = run_mode(&["adapter-crash"])?;
    assert_eq!(crash, Err(AdapterRunError::Crashed));
    assert!(output.is_empty());

    let (malformed, output) = run_mode(&["malformed-output"])?;
    assert_eq!(malformed, Ok(()));
    assert_eq!(output, b"not an EAO1 stream\n");
    assert!(read_observation(output.as_slice(), 1 << 10).is_err());
    Ok(())
}

#[test]
fn the_oversized_fixture_writes_exactly_its_bound_of_filler() -> TestResult {
    for bound in [1_u64, 65_536, 65_537, 200_000] {
        let (result, output) = run_mode(&["oversized-output", &bound.to_string()])?;
        assert_eq!(result, Ok(()));
        assert_eq!(output.len() as u64, bound);
        assert!(output.iter().all(|byte| *byte == 0x5a));
    }
    Ok(())
}

#[test]
fn a_fixture_that_is_not_stopped_goes_on_to_report_honestly() -> TestResult {
    for values in [
        &["work-area-exhaustion", "1"][..],
        &["task-exhaustion", "2"][..],
        &["memory-exhaustion", "1048577"][..],
        &["watchdog-expiry", "1"][..],
        &["idle", "1"][..],
        &["orphaned-child"][..],
    ] {
        let (result, output) = run_mode(values)?;
        assert_eq!(result, Ok(()), "{values:?}");
        let observation = read_observation(output.as_slice(), 1 << 10)?;
        assert_eq!(
            observation.result,
            SubjectResult::Output(blake3::hash(b"payload").as_bytes().to_vec())
        );
        assert_eq!(
            observation.usage,
            ResourceUsage {
                output_bytes: 32,
                ..ResourceUsage::default()
            }
        );
    }
    Ok(())
}

#[test]
fn a_probe_fixture_reports_or_escapes_never_anything_else() -> TestResult {
    for values in [
        &["filesystem-escape"][..],
        &["read-only-root-write"][..],
        &["network-escape"][..],
        &["foreign-signals"][..],
    ] {
        let (result, output) = run_mode(values)?;
        match result {
            Ok(()) => assert!(read_observation(output.as_slice(), 1 << 10).is_ok()),
            Err(error) => {
                assert_eq!(error, AdapterRunError::Escaped, "{values:?}");
                assert!(output.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn apply_runs_each_effect_and_says_who_writes_the_output() {
    for (fixture, after) in [
        (Fixture::WatchdogExpiry(1), After::Report),
        (Fixture::Idle(1), After::Report),
        (Fixture::TaskExhaustion(2), After::Report),
        (Fixture::MemoryExhaustion(1), After::Report),
        (Fixture::WorkAreaExhaustion(1), After::Report),
        (Fixture::OrphanedChild, After::Report),
        (Fixture::MalformedOutput, After::Written),
        (Fixture::OversizedOutput(3), After::Written),
    ] {
        let mut output = Vec::new();
        assert_eq!(apply(fixture, &mut output), Ok(after), "{fixture:?}");
    }
    let mut output = Vec::new();
    assert_eq!(
        apply(Fixture::AdapterCrash, &mut output),
        Err(AdapterRunError::Crashed)
    );
}

struct FlushFails;
impl Write for FlushFails {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn a_broken_output_stream_is_an_output_failure_for_the_fixtures_that_own_it() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for fixture in [Fixture::MalformedOutput, Fixture::OversizedOutput(1)] {
        assert_eq!(
            apply(fixture, &mut Closed),
            Err(AdapterRunError::Output),
            "{fixture:?}"
        );
    }
    assert_eq!(
        apply(Fixture::MalformedOutput, &mut FlushFails),
        Err(AdapterRunError::Output)
    );
}

#[test]
fn the_work_area_fixture_writes_its_bound_and_stops_at_a_full_area() -> TestResult {
    let dir = tempfile::tempdir()?;
    fill_work_area(dir.path(), 200_000);
    assert_eq!(fs::metadata(dir.path().join("fill"))?.len(), 200_000);
    fill_work_area(dir.path(), 10);
    assert_eq!(fs::metadata(dir.path().join("fill"))?.len(), 10);

    // A full area refuses the write; the fixture stops without failing.
    let full = tempfile::tempdir()?;
    symlink("/dev/full", full.path().join("fill"))?;
    fill_work_area(full.path(), 1 << 20);

    // A missing area has nothing to fill.
    let missing = dir.path().join("missing");
    fill_work_area(&missing, 10);
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn the_task_and_memory_fixtures_hold_their_bound_while_they_run() {
    let started = Instant::now();
    exhaust_tasks(3);
    assert!(started.elapsed() >= Duration::from_millis(1_500));
    exhaust_memory(3 << 20);
    exhaust_memory(1);
    leave_orphan();
}

#[test]
fn the_binary_applies_the_mode_arguments() -> TestResult {
    let mut child = Command::new(BINARY)
        .args(["malformed-output"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(&encoded()?)?;
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"not an EAO1 stream\n");

    let mut crash = Command::new(BINARY)
        .args(["adapter-crash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    crash
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(&encoded()?)?;
    let output = crash.wait_with_output()?;
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert!(Path::new(BINARY).exists());
    Ok(())
}
