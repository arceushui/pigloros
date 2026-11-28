#![cfg(target_os = "linux")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! The #216 malicious and limit fixtures through the adapter's public
//! interface. Every probe is aimed at a target whose answer is known on the
//! test host; the fixed in-sandbox targets are only counted, because their
//! answers depend on who runs the test. Limits use tiny bounds.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use pos_reference::adapter_transport::{read_attempt, read_observation, write_attempt};
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
    mount_tmpfs, open_read, open_write, remove_file, signal_foreign, udp_exchange, Targets,
};
use pos_sandbox_evidence_adapter::{
    apply, exit_code, run, AdapterRunError, After, Fixture, Mode, MODES,
};
use rustix::io::Errno;
use rustix::net::{bind, getsockname, ipproto, socket, AddressFamily, SocketType};
use rustix::process::{kill_process, waitpid, Pid, Signal, WaitOptions, WaitStatus};

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
fn encoded() -> TestResult<Vec<u8>> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, &case_attempt(b"payload"))?;
    Ok(stream)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn case_attempt(payload: &[u8]) -> CaseAttempt {
    CaseAttempt {
        case_id: "fixture".to_owned(),
        claim_layer: ClaimLayer::MetricConformance,
        family: FixtureFamily::Positive,
        mode: ExecutionMode::AirGapped,
        fixture_digest: *blake3::hash(b"payload").as_bytes(),
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
fn attempt() -> TestResult<CaseAttempt> {
    Ok(read_attempt(encoded()?.as_slice())?)
}

/// Targets whose every path is `missing` (nothing there, so every probe of
/// it is denied) and whose sockets are the two given local addresses.
#[cfg_attr(coverage_nightly, coverage(off))]
const fn aimed_at(missing: &str, tcp: SocketAddr, resolver: SocketAddr) -> Targets<'_> {
    Targets {
        read_denied: [missing; 3],
        write_denied: missing,
        work: missing,
        root: missing,
        tcp,
        resolver,
        bus: missing,
        last_pid: 0,
    }
}

/// A loopback TCP address that refuses every connection, a resolver address
/// that cannot be reached, and the socket that holds the TCP port: keep it
/// alive for the whole test, so no other process can take the port.
///
/// The TCP socket is bound but never listens, so a connect to it is refused at
/// once on every host, whatever the runner's routing. The resolver is an IPv6
/// address, which the IPv4 datagram probe cannot send to on any host.
#[cfg_attr(coverage_nightly, coverage(off))]
fn silent_addresses() -> TestResult<(SocketAddr, SocketAddr, OwnedFd)> {
    let closed = socket(AddressFamily::INET, SocketType::STREAM, None)?;
    bind(&closed, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let tcp = SocketAddrV4::try_from(getsockname(&closed)?)?;
    Ok((tcp.into(), "[::1]:9".parse()?, closed))
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
    // Whether a datagram to a closed port is refused (an ICMP error that a
    // connected socket reads as ECONNREFUSED) depends on the host, so the
    // refusal is tested on the classification of the reply, in probe.rs.
    // A receiver that takes the datagram and never answers is reached: an
    // escape, not a denial. The probe cannot tell a closed port from a silent
    // receiver here: the CI baseline host did not deliver the ICMP
    // port-unreachable for a closed loopback UDP port, so only silence was
    // seen. The refusal classifier is unit-tested in probe.rs instead.
    let silent = UdpSocket::bind("127.0.0.1:0")?;
    assert!(udp_exchange(&silent.local_addr()?).is_ok());
    assert!(udp_exchange(&"[::1]:9".parse()?).is_err());

    assert!(create_socket(AddressFamily::INET, SocketType::DGRAM, None).is_ok());
    assert_eq!(
        create_socket(AddressFamily::INET, SocketType::RAW, Some(ipproto::ICMP)).is_ok(),
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
    // The parent can be signalled unless it is another user's process (or
    // there is none, as in some containers): then it is denied, not an error.
    let parent = std::os::unix::process::parent_id();
    match signal_foreign(parent) {
        Ok(()) => {}
        Err(error) => {
            assert!(
                parent == 0 || error.kind() == std::io::ErrorKind::PermissionDenied,
                "{error}"
            );
        }
    }
}

#[test]
fn every_probe_fixture_lists_the_attempts_it_makes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    let missing = missing.to_str().ok_or("path")?;
    let (tcp, udp, _silent) = silent_addresses()?;
    let targets = aimed_at(missing, tcp, udp);
    assert_eq!(probe::filesystem_escape(&targets).len(), 5);
    assert_eq!(probe::network_escape(&targets).len(), 5);
    assert_eq!(probe::foreign_signals(8).len(), 8);
    assert!(probe::foreign_signals(0).is_empty());
    assert_eq!(probe::LAST_PROBED_PID, 4096);

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
fn the_table_names_every_mode_once_and_marks_the_bounded_rows() -> TestResult {
    let names: Vec<&str> = MODES.iter().map(|(name, _)| *name).collect();
    assert_eq!(names.len(), 14);
    for (index, name) in names.iter().enumerate() {
        assert!(!names[index + 1..].contains(name), "{name}");
    }
    assert_eq!(MODES[0], ("honest", Mode::Honest));
    let bounded = [
        "work-area-exhaustion",
        "task-exhaustion",
        "memory-exhaustion",
        "watchdog-expiry",
        "oversized-output",
        "idle",
    ];
    for (name, mode) in MODES {
        let Mode::Fixture(fixture) = mode else {
            // The honest mode takes no bound.
            let (result, _) = run_mode(&[*name, "1"])?;
            assert_eq!(result, Err(AdapterRunError::Usage));
            continue;
        };
        // A table row's bound is the placeholder zero, and the parser
        // accepts a bound exactly where the row has one; none of these
        // runs reaches an effect.
        assert_eq!(
            fixture.bound(),
            bounded.contains(name).then_some(0),
            "{name}"
        );
        let wrong: &[&str] = if bounded.contains(name) {
            &[*name]
        } else {
            &[*name, "1"]
        };
        assert_eq!(run_mode(wrong)?.0, Err(AdapterRunError::Usage), "{name}");
        if bounded.contains(name) {
            assert_eq!(
                run_mode(&[*name, "0"])?.0,
                Err(AdapterRunError::Usage),
                "{name}"
            );
        }
    }
    Ok(())
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
        &["memory-exhaustion", "+5"][..],
        &["memory-exhaustion", "007"][..],
        &["memory-exhaustion", ""][..],
        &["memory-exhaustion", " 5"][..],
        &["memory-exhaustion", "1", "1"][..],
    ] {
        let (result, output) = run_mode(bad)?;
        assert_eq!(result, Err(AdapterRunError::Usage), "{bad:?}");
        assert!(output.is_empty());
    }
    let non_utf8_name = [OsString::from_vec(vec![0xff, 0xfe])];
    assert_eq!(
        run(non_utf8_name, encoded()?.as_slice(), Vec::new()),
        Err(AdapterRunError::Usage)
    );
    let non_utf8_bound = [
        OsString::from("memory-exhaustion"),
        OsString::from_vec(vec![0xff, 0xfe]),
    ];
    assert_eq!(
        run(non_utf8_bound, encoded()?.as_slice(), Vec::new()),
        Err(AdapterRunError::Usage)
    );
    Ok(())
}

#[test]
fn a_zero_bound_is_refused_by_every_bounded_fixture_itself() {
    // The argument parser already refuses a leading zero, so only the fixture's
    // own rule can refuse a zero that reaches it.
    let bounded: [fn(u64) -> Fixture; 6] = [
        Fixture::WorkAreaExhaustion,
        Fixture::TaskExhaustion,
        Fixture::MemoryExhaustion,
        Fixture::WatchdogExpiry,
        Fixture::OversizedOutput,
        Fixture::Idle,
    ];
    for make in bounded {
        assert_eq!(make(7).with_bound(Some(0)), None, "{:?}", make(7));
        assert_eq!(make(7).with_bound(Some(1)), Some(make(1)), "{:?}", make(7));
        assert_eq!(make(7).with_bound(None), None, "{:?}", make(7));
    }
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
        &["task-exhaustion", "2"][..],
        &["memory-exhaustion", "1048577"][..],
        &["watchdog-expiry", "1"][..],
        &["idle", "1"][..],
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
fn a_probe_fixture_aimed_at_denied_targets_reports_and_at_open_ones_escapes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    let missing = missing.to_str().ok_or("path")?;
    let open = dir.path().to_str().ok_or("path")?;
    let (tcp, udp, _silent) = silent_addresses()?;
    let attempt = attempt()?;
    let run_one =
        |fixture, targets: &Targets<'_>| apply(fixture, &attempt, targets, &mut Vec::new());

    let denied = aimed_at(missing, tcp, udp);
    assert_eq!(
        run_one(Fixture::FilesystemEscape, &denied),
        Ok(After::Report)
    );
    assert_eq!(
        run_one(Fixture::ReadOnlyRootWrite, &denied),
        Ok(After::Report)
    );
    // Raw sockets are denied only without CAP_NET_RAW.
    let expected = if has_net_raw()? {
        Err(AdapterRunError::Escaped)
    } else {
        Ok(After::Report)
    };
    assert_eq!(run_one(Fixture::NetworkEscape, &denied), expected);
    // No process ID is probed, so nothing was denied either.
    assert_eq!(
        run_one(Fixture::ForeignSignals, &denied),
        Err(AdapterRunError::Escaped)
    );

    // One readable file, a writable root: each is an escape.
    let readable = Targets {
        read_denied: [missing, open, missing],
        ..denied
    };
    assert_eq!(
        run_one(Fixture::FilesystemEscape, &readable),
        Err(AdapterRunError::Escaped)
    );
    let writable = Targets {
        root: open,
        ..denied
    };
    assert_eq!(
        run_one(Fixture::ReadOnlyRootWrite, &writable),
        Err(AdapterRunError::Escaped)
    );
    // A listening TCP port is an escape too.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let reachable = Targets {
        tcp: listener.local_addr()?,
        ..denied
    };
    assert_eq!(
        run_one(Fixture::NetworkEscape, &reachable),
        Err(AdapterRunError::Escaped)
    );
    Ok(())
}

#[test]
fn the_guest_targets_are_the_in_sandbox_places() {
    let guest = Targets::GUEST;
    assert_eq!(
        guest.read_denied,
        ["/etc/shadow", "/run/pigloros/sandbox", "/dev/mem"]
    );
    assert_eq!(guest.write_denied, "/sys/fs/cgroup/cgroup.procs");
    assert_eq!((guest.work, guest.root), ("/work", "/"));
    assert_eq!(guest.tcp.to_string(), "192.0.2.1:9");
    assert_eq!(guest.resolver.to_string(), "127.0.0.53:53");
    assert_eq!(guest.bus, "/run/dbus/system_bus_socket");
    assert_eq!(guest.last_pid, probe::LAST_PROBED_PID);
}

#[test]
fn apply_runs_each_effect_and_says_who_writes_the_output() -> TestResult {
    let dir = tempfile::tempdir()?;
    let work = dir.path().to_str().ok_or("path")?;
    let (tcp, udp, _silent) = silent_addresses()?;
    let targets = aimed_at(work, tcp, udp);
    let attempt = attempt()?;
    for (fixture, after) in [
        (Fixture::WatchdogExpiry(1), After::Report),
        (Fixture::Idle(1), After::Report),
        (Fixture::TaskExhaustion(2), After::Report),
        (Fixture::MemoryExhaustion(1), After::Report),
        (Fixture::WorkAreaExhaustion(1), After::Report),
        (Fixture::MalformedOutput, After::Written),
        (Fixture::OversizedOutput(3), After::Written),
    ] {
        let mut output = Vec::new();
        assert_eq!(
            apply(fixture, &attempt, &targets, &mut output),
            Ok(after),
            "{fixture:?}"
        );
    }
    // The work-area fixture wrote its bound where the targets put the area.
    assert_eq!(fs::metadata(dir.path().join("fill"))?.len(), 1);
    // A refused work area (here, one that does not exist) is a denied
    // operation: the run still reports honestly, as the suite expects of a
    // contained adapter (the kernel evidence, not this report, tells an
    // enforced ceiling from an unenforced one).
    let refused = aimed_at("/nonexistent/work", tcp, udp);
    assert_eq!(
        apply(
            Fixture::WorkAreaExhaustion(1),
            &attempt,
            &refused,
            &mut Vec::new()
        ),
        Ok(After::Report)
    );
    assert!(!Path::new("/nonexistent/work").exists());
    let mut output = Vec::new();
    assert_eq!(
        apply(Fixture::AdapterCrash, &attempt, &targets, &mut output),
        Err(AdapterRunError::Crashed)
    );
    Ok(())
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
fn a_broken_output_stream_is_an_output_failure_for_the_fixtures_that_own_it() -> TestResult {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let attempt = attempt()?;
    let (tcp, udp, _silent) = silent_addresses()?;
    let targets = aimed_at("/nonexistent", tcp, udp);
    for fixture in [Fixture::MalformedOutput, Fixture::OversizedOutput(1)] {
        assert_eq!(
            apply(fixture, &attempt, &targets, &mut Closed),
            Err(AdapterRunError::Output),
            "{fixture:?}"
        );
    }
    assert_eq!(
        apply(
            Fixture::MalformedOutput,
            &attempt,
            &targets,
            &mut FlushFails
        ),
        Err(AdapterRunError::Output)
    );
    Ok(())
}

#[test]
fn the_work_area_fixture_writes_its_bound_and_stops_at_a_full_area() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert_eq!(fill_work_area(dir.path(), 200_000)?, 200_000);
    assert_eq!(fs::metadata(dir.path().join("fill"))?.len(), 200_000);
    assert_eq!(fill_work_area(dir.path(), 10)?, 10);
    assert_eq!(fs::metadata(dir.path().join("fill"))?.len(), 10);

    // A full area refuses the write; the run goes on without failing.
    let full = tempfile::tempdir()?;
    symlink("/dev/full", full.path().join("fill"))?;
    assert!(fill_work_area(full.path(), 1 << 20).is_err());

    // A missing area has nothing to fill.
    let missing = dir.path().join("missing");
    assert!(fill_work_area(&missing, 10).is_err());
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn the_task_and_memory_fixtures_report_what_they_held() {
    let lifetime = Duration::from_millis(50);
    let started = Instant::now();
    assert_eq!(exhaust_tasks(3, lifetime), 3);
    assert!(started.elapsed() >= lifetime);
    assert_eq!(exhaust_tasks(0, lifetime), 0);
    assert_eq!(exhaust_memory(3 << 20), 3 << 20);
    assert_eq!(exhaust_memory(1), 1 << 20);
    assert_eq!(exhaust_memory(0), 0);
}

/// The environment variable that marks the orphans of one test run.
const MARKER: &str = "PIGLOR_ORPHAN_TEST";

/// A marker value no other test run shares: this process and the time.
#[cfg_attr(coverage_nightly, coverage(off))]
fn unique_marker() -> TestResult<String> {
    let nanoseconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{}-{nanoseconds}", std::process::id()))
}

/// The live process IDs whose command line is exactly the orphan's (this
/// binary, `idle`, and the orphan's bound) and whose environment carries
/// `marker`, so that another test run on the same host is never counted.
#[cfg_attr(coverage_nightly, coverage(off))]
fn idle_orphans(marker: &str) -> TestResult<Vec<u32>> {
    let wanted = format!("{BINARY}\0idle\0600000\0").into_bytes();
    let tagged = format!("{MARKER}={marker}").into_bytes();
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let name = entry?.file_name();
        let pid = name.to_str().and_then(|name| name.parse::<u32>().ok());
        if let Some(pid) = pid.filter(|pid| process_state(*pid) != Some('Z')) {
            let has_name =
                fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|bytes| bytes == wanted);
            let has_tag = fs::read(format!("/proc/{pid}/environ")).is_ok_and(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .any(|entry| entry == tagged.as_slice())
            });
            if has_name && has_tag {
                found.push(pid);
            }
        }
    }
    Ok(found)
}

/// The state letter of `pid` in `/proc`, or nothing once it is gone.
#[cfg_attr(coverage_nightly, coverage(off))]
fn process_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?.1.trim_start().chars().next()
}

/// Wait for the child `pid`, again if a signal interrupted the wait.
#[cfg_attr(coverage_nightly, coverage(off))]
fn wait_for(pid: Pid) -> TestResult<WaitStatus> {
    loop {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Err(Errno::INTR) => {}
            other => {
                return other?
                    .map(|(_, status)| status)
                    .ok_or_else(|| "no wait status".into())
            }
        }
    }
}

/// A child of this process that must not outlive the test, however the test
/// ends: dropping it kills and reaps it, ignoring errors there.
struct Orphan(Option<(u32, Pid)>);

impl Orphan {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn of(raw: u32) -> TestResult<Self> {
        let pid = i32::try_from(raw)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or("pid")?;
        Ok(Self(Some((raw, pid))))
    }

    /// Kill the child and reap it, which shows death by SIGKILL and leaves
    /// no process behind, not even a zombie.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn kill_and_reap(&mut self) -> TestResult {
        let (raw, pid) = self.0.ok_or("already reaped")?;
        kill_process(pid, Signal::KILL)?;
        let waited = wait_for(pid);
        // Reaped, or the wait failed for good: either way the pid may be
        // reused, so the guard lets go of it before anything below can fail.
        self.0 = None;
        let status = waited?;
        assert_eq!(status.terminating_signal(), Some(Signal::KILL.as_raw()));
        assert_eq!(process_state(raw), None);
        Ok(())
    }
}

impl Drop for Orphan {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn drop(&mut self) {
        if let Some((_, pid)) = self.0.take() {
            kill_process(pid, Signal::KILL).ok();
            wait_for(pid).ok();
        }
    }
}

/// On drop, kills every orphan that carries the marker, whatever ended the
/// test: no failure path leaves a 600 s idle process behind. Errors are
/// ignored there.
struct Sweep(String);

impl Drop for Sweep {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn drop(&mut self) {
        for raw in idle_orphans(&self.0).unwrap_or_default() {
            if let Some(pid) = i32::try_from(raw).ok().and_then(Pid::from_raw) {
                kill_process(pid, Signal::KILL).ok();
            }
        }
    }
}

/// Kill `pid`, which is not a child of this process (its parent exited, so
/// its new parent reaps it), and wait until it is gone or a zombie.
#[cfg_attr(coverage_nightly, coverage(off))]
fn kill_and_wait(pid: u32) -> TestResult {
    let target = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or("pid")?;
    kill_process(target, Signal::KILL)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(process_state(pid), None | Some('Z')) {
        assert!(Instant::now() < deadline, "{pid} did not die");
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// The command line of `pid`, read once the kernel has published it. `spawn`
/// returns when the child's exec-error pipe closes, which happens before the
/// new image's argument area is set, so a read right after it can be empty.
#[cfg_attr(coverage_nightly, coverage(off))]
fn cmdline_after_exec(pid: u32) -> TestResult<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // A process that vanishes mid-poll fails the test, which is right.
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
        if !cmdline.is_empty() {
            return Ok(cmdline);
        }
        assert!(
            Instant::now() < deadline,
            "cmdline still empty after 10 s: {pid}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn the_orphan_outlives_the_adapter_that_left_it() -> TestResult {
    let marker = unique_marker()?;
    let _sweep = Sweep(marker.clone());
    assert!(idle_orphans(&marker)?.is_empty());

    // Through the real binary: the adapter exits, its child does not.
    let mut parent = Command::new(BINARY)
        .env(MARKER, &marker)
        .arg("orphaned-child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    parent
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(&encoded()?)?;
    let output = parent.wait_with_output()?;
    assert!(output.status.success());
    assert!(read_observation(output.stdout.as_slice(), 1 << 10).is_ok());
    let orphans = idle_orphans(&marker)?;
    assert_eq!(orphans.len(), 1, "{orphans:?}");
    // It is alive and idle: it decoded the attempt it was fed, which an
    // adapter that failed to read it would not have survived.
    assert!(matches!(process_state(orphans[0]), Some('S' | 'R')));
    kill_and_wait(orphans[0])?;
    assert!(idle_orphans(&marker)?.is_empty());

    // Directly: the orphan is a child of this process, left running.
    let direct = leave_orphan(Path::new(BINARY), &attempt()?).ok_or("no orphan")?;
    let mut guard = Orphan::of(direct)?;
    assert!(matches!(process_state(direct), Some('S' | 'R')));
    assert_eq!(
        cmdline_after_exec(direct)?,
        format!("{BINARY}\0idle\0600000\0").into_bytes()
    );
    guard.kill_and_reap()?;
    // An executable that exits without reading its attempt is not fed (the
    // attempt is larger than a pipe's buffer, so the write fails): nothing is
    // left, and the child is killed and waited for.
    assert!(
        Command::new("true").status()?.success(),
        "the `true` executable must be on PATH for this test"
    );
    assert_eq!(
        leave_orphan(Path::new("true"), &case_attempt(&vec![7; 1 << 19])),
        None
    );
    // An executable that cannot start leaves nothing.
    assert_eq!(
        leave_orphan(Path::new("/nonexistent/adapter"), &attempt()?),
        None
    );
    Ok(())
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
