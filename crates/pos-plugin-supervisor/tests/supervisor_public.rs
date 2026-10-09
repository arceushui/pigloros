//! Black-box tests of the community Plugin worker supervisor (ADR-061 r4).
//!
//! Every test drives the public supervisor API against the `test-support`
//! probe worker, which runs the real worker process checks and then reports
//! its own process state from the inside or misbehaves in one named way. The
//! Component worker itself is tested in `apps/pos-plugin-worker`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pos_plugin_supervisor::test_support::{
    self, negotiated_under, negotiated_with, ok, METERING, SMALL_BUDGET,
};
use pos_plugin_supervisor::{
    CommunityPluginSupervisorV1, WorkerProgramV1, WorkerResourceCeilingsV1, FORWARDED_ENVIRONMENT,
    RUNTIME_ENVIRONMENT,
};
use pos_runtime::community_plugin_host::{
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginHostErrorV1,
    CommunityPluginModeV1, ComponentTrapClassV1, HostInputs, InvocationReportV1,
    NegotiatedCommunityPluginV1, PluginInvocationV1, PluginOutputV1, TrapReproductionV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = CommunityPluginHostErrorV1;
type Produced = Result<InvocationReportV1<PluginOutputV1>, Error>;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
const ARGV_PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-argv-probe");
/// A generous watchdog for invocations that should finish promptly.
const PROMPT: Duration = Duration::from_mins(1);
/// A short watchdog for invocations that must be stopped.
const SHORT: Duration = Duration::from_secs(1);
/// Well below the probe's 60-second linger, well above the short watchdog.
const STOPPED_WITHIN: Duration = Duration::from_secs(30);
const EXIT_HELPER: &str = "POS_PLUGIN_SUPERVISOR_EXIT_HELPER";
const INPUTS: HostInputs = HostInputs { simulation_time: 7 };

fn negotiated() -> NegotiatedCommunityPluginV1 {
    negotiated_with("plugin-a", SMALL_BUDGET, Vec::new())
}

fn invocation() -> PluginInvocationV1 {
    test_support::invocation(b"observation")
}

fn supervisor(program: &str, watchdog: Duration) -> CommunityPluginSupervisorV1 {
    WorkerProgramV1::new(PathBuf::from(program))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, watchdog))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor")))
}

/// `reduce` against the probe, whose behaviour `mode` names.
fn reduce_with(watchdog: Duration, mode: &[u8]) -> Produced {
    supervisor(PROBE, watchdog).reduce(&negotiated(), mode, &invocation(), INPUTS)
}

fn reduce(mode: &[u8]) -> Produced {
    reduce_with(PROMPT, mode)
}

/// The probe's `name=value` report of its own process state.
fn report() -> BTreeMap<String, String> {
    let report = ok(reduce(b"report"));
    let state = ok(report.result).next_state_bytes;
    String::from_utf8_lossy(&state)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

fn field<'a>(report: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    report.get(name).map_or("", String::as_str)
}

#[test]
fn the_worker_sees_a_scrubbed_environment_and_only_its_pipes() {
    let report = report();
    let environment = field(&report, "env");
    assert!(
        environment
            .split(',')
            .filter(|name| !name.is_empty())
            .all(
                |name| FORWARDED_ENVIRONMENT.contains(&name) || RUNTIME_ENVIRONMENT.contains(&name)
            ),
        "{environment}"
    );
    assert!(std::env::vars_os().next().is_some());
    assert_eq!(field(&report, "fds"), "0,1,2");
    assert_eq!(field(&report, "cwd"), "/");
    assert_eq!(field(&report, "ppid"), std::process::id().to_string());
}

/// Assert the worker's own report of each `(name, ceiling)` rlimit.
fn assert_rlimits(report: &BTreeMap<String, String>, expected: &[(&str, u64)]) {
    for (name, value) in expected {
        assert_eq!(field(report, name), format!("{value}:{value}"), "{name}");
    }
}

fn ceilings() -> WorkerResourceCeilingsV1 {
    let limits = negotiated().limits().values();
    let ceilings = WorkerResourceCeilingsV1::for_invocation(&limits, PROMPT);
    assert_eq!(ceilings.cpu_seconds, 62);
    ceilings
}

#[cfg(not(asan_build))]
#[test]
fn the_worker_runs_under_its_rlimit_ceilings() {
    let report = report();
    let ceilings = ceilings();
    assert_rlimits(
        &report,
        &[
            ("cpu", ceilings.cpu_seconds),
            ("data", ceilings.data_bytes),
            ("fsize", ceilings.file_size_bytes),
            ("core", ceilings.core_bytes),
        ],
    );
    // Allocating 1 GiB exceeds the data ceiling, so the worker aborts.
    assert_eq!(reduce(b"allocate"), Err(Error::WorkerCrashed));
}

/// An AddressSanitizer build lifts only the data ceiling (see build.rs).
#[cfg(asan_build)]
#[test]
fn the_worker_runs_under_its_rlimit_ceilings_except_data() {
    let report = report();
    let ceilings = ceilings();
    assert_rlimits(
        &report,
        &[
            ("cpu", ceilings.cpu_seconds),
            ("fsize", ceilings.file_size_bytes),
            ("core", ceilings.core_bytes),
        ],
    );
}

#[test]
fn every_invocation_gets_a_fresh_worker_process() {
    let first = report();
    let second = report();
    let own = std::process::id().to_string();
    assert_ne!(field(&first, "pid"), field(&second, "pid"));
    assert_ne!(field(&first, "pid"), "");
    assert_ne!(field(&first, "pid"), own);
    assert_eq!(field(&first, "ppid"), field(&second, "ppid"));
}

#[test]
fn returned_values_are_checked_by_the_supervisor() {
    let report = ok(reduce(b"output"));
    assert_eq!(report.metering, METERING);
    assert_eq!(ok(report.result).invocation_id, invocation().invocation_id);
    let drive = supervisor(PROBE, PROMPT).drive(&negotiated(), b"output", &invocation(), INPUTS);
    assert!(drive.is_ok_and(|report| report.result.is_ok()));
    assert_eq!(reduce(b"bad-digest"), Err(Error::InvalidGuestOutput));
    let describe = |mode: &[u8]| supervisor(PROBE, PROMPT).describe(&negotiated(), mode, INPUTS);
    let described = ok(describe(b"describe"));
    assert_eq!(ok(described.result).plugin_id, "plugin-a");
    assert_eq!(
        describe(b"foreign-descriptor"),
        Err(Error::InvalidGuestOutput)
    );
    // A return of the other export's kind is a protocol fault.
    assert_eq!(describe(b"output"), Err(Error::WorkerCrashed));
    assert_eq!(reduce(b"describe"), Err(Error::WorkerCrashed));
}

#[test]
fn engine_failures_and_traps_keep_their_closed_names() {
    assert_eq!(reduce(b"fuel"), Err(Error::FuelExhausted));
    let drive = supervisor(PROBE, PROMPT).drive(&negotiated(), b"fuel", &invocation(), INPUTS);
    assert_eq!(drive, Err(Error::FuelExhausted));
    assert_eq!(
        reduce(b"trap"),
        Err(Error::ComponentTrap {
            class: ComponentTrapClassV1::StackExhausted,
            reproduction: TrapReproductionV1::Unverified,
        })
    );
}

#[test]
fn worker_death_and_ipc_faults_are_worker_crashed() {
    for mode in [
        &b"exit"[..],
        b"abort",
        b"garbage",
        b"noncanonical",
        b"truncated",
        b"oversize",
        b"trailing",
        b"exit-after-reply",
        b"unknown-mode",
    ] {
        assert_eq!(
            reduce(mode),
            Err(Error::WorkerCrashed),
            "{}",
            String::from_utf8_lossy(mode)
        );
    }
}

#[test]
fn launch_and_invocation_faults_fail_before_any_guest_runs() {
    let missing = supervisor("/nonexistent/pos-plugin-worker", PROMPT);
    let result = missing.describe(&negotiated(), b"describe", INPUTS);
    assert_eq!(result, Err(Error::WorkerCrashed));
    let mut oversized = invocation();
    oversized.observation_bytes = vec![0; 1_048_577];
    let result = supervisor(PROBE, PROMPT).reduce(&negotiated(), b"output", &oversized, INPUTS);
    assert_eq!(result, Err(Error::InvalidInvocation));
    let result = supervisor(PROBE, PROMPT).drive(&negotiated(), b"output", &oversized, INPUTS);
    assert_eq!(result, Err(Error::InvalidInvocation));
    let component = vec![0; 33_554_433];
    let result = supervisor(PROBE, PROMPT).describe(&negotiated(), &component, INPUTS);
    assert_eq!(result, Err(Error::InvalidInvocation));
}

#[test]
fn the_wall_time_watchdog_is_an_operational_stop() {
    for mode in [&b"hang"[..], b"linger-after-reply", b"close-then-linger"] {
        let started = Instant::now();
        let result = reduce_with(SHORT, mode);
        assert_eq!(
            result,
            Err(Error::OperationalWatchdogStop),
            "{}",
            String::from_utf8_lossy(mode)
        );
        assert!(
            started.elapsed() < STOPPED_WITHIN,
            "{:?}",
            started.elapsed()
        );
    }
}

/// `(parent, state)` from `/proc/<pid>/stat`, if the process exists.
fn process_status(pid: u32) -> Option<(u32, char)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let parent = fields.next()?.parse().ok()?;
    Some((parent, state))
}

fn child_of(parent: u32) -> Option<u32> {
    std::fs::read_dir("/proc")
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .find(|pid| process_status(*pid).is_some_and(|(of, _)| of == parent))
}

fn within<T>(limit: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let started = Instant::now();
    loop {
        if let Some(found) = probe() {
            return Some(found);
        }
        if started.elapsed() > limit {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_worker_dies_with_its_supervisor() -> TestResult {
    if std::env::var_os(EXIT_HELPER).is_some() {
        // The helper supervisor: blocks until the outer test kills it.
        drop(reduce(b"hang"));
        return Ok(());
    }
    let mut helper = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "a_worker_dies_with_its_supervisor",
            "--test-threads=1",
        ])
        .env(EXIT_HELPER, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let worker = within(STOPPED_WITHIN, || child_of(helper.id()));
    helper.kill()?;
    helper.wait()?;
    let worker = worker.ok_or("the helper never launched a worker")?;
    let dead = within(STOPPED_WITHIN, || {
        process_status(worker)
            .is_none_or(|(_, state)| state == 'Z')
            .then_some(())
    });
    assert!(dead.is_some(), "worker {worker} outlived its supervisor");
    Ok(())
}

/// R7-P6: the argv-recording worker shows that a record of mode M always
/// launches with exactly the supervisor's process ID and the token for M.
#[test]
fn a_record_launches_with_the_token_of_its_mode() {
    let modes = [
        (CommunityPluginModeV1::Local, "local"),
        (CommunityPluginModeV1::AirGapped, "air-gapped"),
    ];
    for (mode, token) in modes {
        let ceilings = CommunityPluginCeilingsV1::V1;
        let profile = CommunityPluginExecutionProfileV1::new(mode, ceilings, None);
        let record = negotiated_under("plugin-a", SMALL_BUDGET, Vec::new(), &profile);
        assert_eq!(record.mode(), mode);
        let worker = supervisor(ARGV_PROBE, PROMPT);
        let report = ok(worker.drive(&record, b"component", &invocation(), INPUTS));
        let recorded = ok(report.result).next_state_bytes;
        let expected = format!("{} {token}", std::process::id());
        assert_eq!(String::from_utf8_lossy(&recorded), expected, "{mode:?}");
    }
}
