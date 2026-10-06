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

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1,
    PluginExecutionProjectionV1,
};
use pos_crypto::plugin_worker_ipc::{WorkerExportV1, MAX_WORKER_INVOCATION_BYTES_V1};
use pos_plugin_supervisor::{
    CommunityPluginSupervisorV1, WorkerInvocationV1, WorkerProgramV1, WorkerReportV1,
    WorkerResourceCeilingsV1, FORWARDED_ENVIRONMENT,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginHostAbiV1, CommunityPluginHostErrorV1, CommunityPluginModeV1,
    ComponentTrapClassV1, NegotiatedCommunityPluginV1, TrapReproductionV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Invocation<T> = Result<WorkerReportV1<T>, CommunityPluginHostErrorV1>;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
/// A generous watchdog for invocations that should finish promptly.
const PROMPT: Duration = Duration::from_mins(1);
/// A short watchdog for invocations that must be stopped.
const SHORT: Duration = Duration::from_secs(1);
/// Well below the probe's 60-second linger, well above the short watchdog.
const STOPPED_WITHIN: Duration = Duration::from_secs(30);
const EXIT_HELPER: &str = "POS_PLUGIN_SUPERVISOR_EXIT_HELPER";

fn negotiated() -> NegotiatedCommunityPluginV1 {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: "plugin-a".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 0,
            required_features: Vec::new(),
        },
        capabilities: Vec::new(),
        budget: DeterministicBudgetV1 {
            memory_bytes: 65_536,
            fuel: 1_000,
            ..DeterministicBudgetV1::MAXIMA
        },
    };
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    );
    let execution = PluginExecutionProjectionV1::from(fixture);
    negotiate_community_plugin_v1(&execution, &CommunityPluginHostAbiV1::v1(), &profile)
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn supervisor(program: &str, watchdog: Duration) -> CommunityPluginSupervisorV1 {
    WorkerProgramV1::new(PathBuf::from(program))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, watchdog))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor")))
}

fn invoke_with<T>(
    watchdog: Duration,
    mode: &[u8],
    validate: impl FnOnce(&[u8]) -> Option<T>,
) -> Invocation<T> {
    let invocation = WorkerInvocationV1 {
        export: WorkerExportV1::Reduce,
        component: b"not a component",
        simulation_time: 7,
        invocation: mode,
    };
    supervisor(PROBE, watchdog).invoke(&negotiated(), &invocation, validate)
}

fn invoke(mode: &[u8]) -> Invocation<Vec<u8>> {
    invoke_with(PROMPT, mode, |payload| Some(payload.to_vec()))
}

/// The probe's `name=value` report of its own process state.
fn report() -> BTreeMap<String, String> {
    let report = invoke(b"report")
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
    String::from_utf8_lossy(&report.output)
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
            .all(|name| FORWARDED_ENVIRONMENT.contains(&name)),
        "{environment}"
    );
    assert!(std::env::vars_os().next().is_some());
    assert_eq!(field(&report, "fds"), "0,1,2");
    assert_eq!(field(&report, "cwd"), "/");
    assert_eq!(field(&report, "ppid"), std::process::id().to_string());
}

#[test]
fn the_worker_runs_under_its_rlimit_ceilings() {
    let report = report();
    let ceilings = WorkerResourceCeilingsV1::for_invocation(&negotiated().limits().values(), PROMPT);
    for (name, value) in [
        ("cpu", ceilings.cpu_seconds),
        ("data", ceilings.data_bytes),
        ("fsize", ceilings.file_size_bytes),
        ("core", ceilings.core_bytes),
    ] {
        assert_eq!(field(&report, name), format!("{value}:{value}"), "{name}");
    }
    assert_eq!(ceilings.cpu_seconds, 62);
    // Allocating 1 GiB exceeds the data ceiling, so the worker aborts.
    assert_eq!(invoke(b"allocate"), Err(CommunityPluginHostErrorV1::WorkerCrashed));
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
fn a_valid_payload_is_validated_by_the_host() {
    let report = invoke_with(PROMPT, b"payload", |payload| {
        (payload == b"payload").then_some("validated")
    });
    let expected = WorkerReportV1 {
        output: "validated",
        startup_fuel: 1,
        call_fuel: 2,
        memory_bytes: 65_536,
    };
    assert_eq!(report, Ok(expected));
    let rejected = invoke_with(PROMPT, b"payload", |_| None::<()>);
    assert_eq!(rejected, Err(CommunityPluginHostErrorV1::InvalidGuestOutput));
}

#[test]
fn engine_failures_and_traps_keep_their_closed_names() {
    assert_eq!(invoke(b"fuel"), Err(CommunityPluginHostErrorV1::FuelExhausted));
    assert_eq!(
        invoke(b"trap"),
        Err(CommunityPluginHostErrorV1::ComponentTrap {
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
            invoke(mode),
            Err(CommunityPluginHostErrorV1::WorkerCrashed),
            "{}",
            String::from_utf8_lossy(mode)
        );
    }
}

#[test]
fn launch_and_request_faults_fail_before_any_guest_runs() {
    let invocation = WorkerInvocationV1 {
        export: WorkerExportV1::Describe,
        component: b"",
        simulation_time: 0,
        invocation: b"",
    };
    let missing = supervisor("/nonexistent/pos-plugin-worker", PROMPT);
    let result = missing.invoke(&negotiated(), &invocation, |_| Some(()));
    assert_eq!(result, Err(CommunityPluginHostErrorV1::WorkerCrashed));
    let oversized = vec![0; MAX_WORKER_INVOCATION_BYTES_V1 + 1];
    let result = invoke(&oversized);
    assert_eq!(result, Err(CommunityPluginHostErrorV1::InvalidInvocation));
}

#[test]
fn the_wall_time_watchdog_is_an_operational_stop() {
    for mode in [&b"hang"[..], b"linger-after-reply"] {
        let started = Instant::now();
        let result = invoke_with(SHORT, mode, |_| Some(()));
        assert_eq!(
            result,
            Err(CommunityPluginHostErrorV1::OperationalWatchdogStop),
            "{}",
            String::from_utf8_lossy(mode)
        );
        assert!(started.elapsed() < STOPPED_WITHIN, "{:?}", started.elapsed());
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
        drop(invoke(b"hang"));
        return Ok(());
    }
    let mut helper = Command::new(std::env::current_exe()?)
        .args(["--exact", "a_worker_dies_with_its_supervisor", "--test-threads=1"])
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
