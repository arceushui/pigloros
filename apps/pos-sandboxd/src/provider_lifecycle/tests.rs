//! `SystemdProviderLifecycle` against a fake systemd manager peer and a
//! temporary cgroup tree.

use std::{
    error::Error,
    fs::{self, File},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use pos_reference::selector::runtime_lifecycle::{
    process_start_time_ticks, ObservationChallenge, ProviderLifecycleError, ProviderLifecyclePort,
    RuntimeSlotTarget,
};
use zbus::{fdo, object_server::SignalEmitter, BoxDBusError, OwnedObjectPath, OwnedVariant};

use super::*;
use crate::system_bus::peer_connections;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type UnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const UNIT_PATHS: [&str; 3] = [
    "/org/freedesktop/systemd1/unit/slot0",
    "/org/freedesktop/systemd1/unit/slot1",
    "/org/freedesktop/systemd1/unit/slot2",
];
const OTHER_PATH: &str = "/org/freedesktop/systemd1/unit/other";
const STOP_JOB: &str = "/org/freedesktop/systemd1/job/7";
const START_JOB: &str = "/org/freedesktop/systemd1/job/9";
const SCOPE: [u8; 16] = [0x5c; 16];

#[derive(Clone, Debug, Default)]
struct FakeUnit {
    name: String,
    loaded: bool,
    active: String,
    control_group: String,
    main_pid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    List(Vec<String>, Vec<String>),
    Stop(String, String),
    Reset(String),
    Start {
        name: String,
        mode: String,
        properties: Vec<(String, String, String)>,
        auxiliary: usize,
    },
}

/// The one fault a fake manager injects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Fault {
    #[default]
    None,
    /// `ListUnitsByPatterns` is denied.
    List,
    /// Every `ControlGroup` read is denied.
    ControlGroup,
    /// `ResetFailedUnit` leaves the unit loaded.
    KeepLoaded,
    /// `ResetFailedUnit` unloads the unit but keeps its cgroup.
    KeepCgroup,
    /// `ResetFailedUnit` loads the unit in this slot once.
    LoadOnReset(usize),
    /// `StartTransientUnit` is denied.
    RefuseStart,
    /// The start job ends with this result.
    StartResult(&'static str),
    /// The start job's completion names this unit.
    CompletionUnit(&'static str),
    /// The started unit's final identity re-check resolves to another object.
    Substitute,
    /// Listing call number `n` (from 1) and every later one is denied.
    ListFailsFrom(usize),
    /// The runtime listing also names a noncanonical unit.
    BadListing,
    /// The listing repeats every row.
    DuplicateListing,
    /// Every `GetUnit` is denied.
    LookupDenied,
    /// A listed unit resolves to another object.
    ListedElsewhere,
    /// Lookup number `n` (from 1) of the started unit and every later one is denied.
    StartedLookupFailsFrom(usize),
    /// Every `MainPID` read is denied.
    MainPid,
}

#[derive(Default)]
struct State {
    units: Vec<FakeUnit>,
    calls: Vec<Call>,
    subscribed: bool,
    started: Option<FakeUnit>,
    started_lookups: usize,
    lists: usize,
    fault: Fault,
    cgroups: PathBuf,
}

fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.systemd1")]
enum ManagerError {
    NoSuchUnit(String),
}

struct Manager(Arc<Mutex<State>>);

impl Manager {
    fn lock(&self) -> fdo::Result<std::sync::MutexGuard<'_, State>> {
        self.0.lock().map_err(failed)
    }
}

fn render(value: OwnedVariant) -> fdo::Result<(String, String)> {
    let signature = value.value_signature().to_string();
    let rendered = match signature.as_str() {
        "s" => String::try_from(value).map_err(failed)?,
        "t" => u64::try_from(value).map_err(failed)?.to_string(),
        "u" => u32::try_from(value).map_err(failed)?.to_string(),
        _ => format!("{value:?}"),
    };
    Ok((signature, rendered))
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager", spawn = false)]
impl Manager {
    fn subscribe(&self) -> fdo::Result<()> {
        self.lock()?.subscribed = true;
        Ok(())
    }

    fn list_units_by_patterns(
        &self,
        states: Vec<String>,
        patterns: Vec<String>,
    ) -> fdo::Result<Vec<UnitRow>> {
        let prefix = patterns
            .first()
            .and_then(|pattern| pattern.strip_suffix('*'))
            .ok_or_else(|| failed("no pattern"))?
            .to_owned();
        let mut state = self.lock()?;
        state.calls.push(Call::List(states, patterns));
        state.lists += 1;
        let denied = match state.fault {
            Fault::List => true,
            Fault::ListFailsFrom(first) => state.lists >= first,
            _ => false,
        };
        if denied {
            return Err(fdo::Error::AccessDenied("listing denied".to_owned()));
        }
        let mut rows = Vec::new();
        for (slot, unit) in state.units.iter().enumerate() {
            if unit.loaded && unit.name.starts_with(&prefix) {
                let path = OwnedObjectPath::try_from(UNIT_PATHS[slot]).map_err(failed)?;
                rows.push((
                    unit.name.clone(),
                    String::new(),
                    "loaded".to_owned(),
                    unit.active.clone(),
                    "dead".to_owned(),
                    String::new(),
                    path.clone(),
                    0,
                    String::new(),
                    path,
                ));
            }
        }
        match state.fault {
            Fault::BadListing if prefix.ends_with("runtime-") => {
                let mut bad = rows.first().cloned().ok_or_else(|| failed("no row"))?;
                bad.0 = format!("{prefix}zz.service");
                rows.push(bad);
            }
            Fault::DuplicateListing => rows.extend(rows.clone()),
            _ => {}
        }
        drop(state);
        Ok(rows)
    }

    fn get_unit(&self, name: String) -> Result<OwnedObjectPath, BoxDBusError> {
        let mut state = self.lock()?;
        if state.fault == Fault::LookupDenied {
            return Err(fdo::Error::AccessDenied("lookup denied".to_owned()).into());
        }
        if state.started.as_ref().is_some_and(|unit| unit.name == name) {
            state.started_lookups += 1;
            let substitute = state.fault == Fault::Substitute && state.started_lookups > 2;
            if matches!(state.fault, Fault::StartedLookupFailsFrom(first) if state.started_lookups >= first)
            {
                return Err(fdo::Error::AccessDenied("lookup denied".to_owned()).into());
            }
            drop(state);
            let path = if substitute {
                OTHER_PATH
            } else {
                UNIT_PATHS[0]
            };
            return OwnedObjectPath::try_from(path).map_err(|error| failed(error).into());
        }
        let slot = state
            .units
            .iter()
            .position(|unit| unit.loaded && unit.name == name);
        let elsewhere = state.fault == Fault::ListedElsewhere;
        drop(state);
        if elsewhere && slot.is_some() {
            return OwnedObjectPath::try_from(OTHER_PATH).map_err(|error| failed(error).into());
        }
        slot.map_or_else(
            || Err(Box::new(ManagerError::NoSuchUnit(name)) as BoxDBusError),
            |slot| {
                OwnedObjectPath::try_from(UNIT_PATHS[slot]).map_err(|error| failed(error).into())
            },
        )
    }

    #[zbus(name = "GetUnitByControlGroup")]
    fn get_unit_by_control_group(&self, control_group: &str) -> fdo::Result<OwnedObjectPath> {
        let slot = self
            .lock()?
            .units
            .iter()
            .position(|unit| unit.control_group == control_group)
            .ok_or_else(|| failed("no such cgroup"))?;
        OwnedObjectPath::try_from(UNIT_PATHS[slot]).map_err(failed)
    }

    async fn stop_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<OwnedObjectPath> {
        let directory = {
            let mut state = self.lock()?;
            state.calls.push(Call::Stop(name.clone(), mode));
            let control_group = state
                .units
                .iter()
                .find(|unit| unit.name == name)
                .map(|unit| unit.control_group.clone())
                .unwrap_or_default();
            state.cgroups.join(control_group.trim_start_matches('/'))
        };
        fs::write(directory.join("cgroup.events"), b"populated 0\n").map_err(failed)?;
        let job = OwnedObjectPath::try_from(STOP_JOB).map_err(failed)?;
        Self::job_removed(&emitter, 7, job.clone(), name, "done".to_owned())
            .await
            .map_err(failed)?;
        Ok(job)
    }

    fn reset_failed_unit(&self, name: &str) -> fdo::Result<()> {
        let mut state = self.lock()?;
        state.calls.push(Call::Reset(name.to_owned()));
        let fault = state.fault;
        let keep_loaded = fault == Fault::KeepLoaded;
        let keep_cgroup = fault == Fault::KeepCgroup;
        let load = match fault {
            Fault::LoadOnReset(slot) => {
                state.fault = Fault::None;
                Some(slot)
            }
            _ => None,
        };
        let cgroups = state.cgroups.clone();
        let mut removed = None;
        if let Some(unit) = state.units.iter_mut().find(|unit| unit.name == name) {
            unit.loaded = keep_loaded;
            if !unit.control_group.is_empty() && !keep_cgroup {
                removed = Some(cgroups.join(unit.control_group.trim_start_matches('/')));
            }
        }
        if let Some(slot) = load {
            state.units[slot].loaded = true;
        }
        drop(state);
        if let Some(directory) = removed {
            fs::remove_dir_all(directory).map_err(failed)?;
        }
        Ok(())
    }

    async fn start_transient_unit(
        &self,
        name: String,
        mode: String,
        properties: Vec<(String, OwnedVariant)>,
        auxiliary: Vec<(String, Vec<(String, OwnedVariant)>)>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<OwnedObjectPath> {
        let mut rendered = Vec::new();
        for (property, value) in properties {
            let (signature, value) = render(value)?;
            rendered.push((property, signature, value));
        }
        let (result, completion) = {
            let mut state = self.lock()?;
            if !state.subscribed {
                return Err(failed("StartTransientUnit before Subscribe"));
            }
            state.calls.push(Call::Start {
                name: name.clone(),
                mode,
                properties: rendered,
                auxiliary: auxiliary.len(),
            });
            if state.fault == Fault::RefuseStart {
                return Err(fdo::Error::AccessDenied("start denied".to_owned()));
            }
            if let Some(started) = state.started.as_mut() {
                started.name.clone_from(&name);
                started.loaded = true;
            }
            let result = match state.fault {
                Fault::StartResult(result) => result,
                _ => "done",
            };
            let completion = match state.fault {
                Fault::CompletionUnit(unit) => unit.to_owned(),
                _ => name.clone(),
            };
            drop(state);
            (result.to_owned(), completion)
        };
        let job = OwnedObjectPath::try_from(START_JOB).map_err(failed)?;
        Self::job_removed(&emitter, 9, job.clone(), completion, result)
            .await
            .map_err(failed)?;
        Ok(job)
    }

    #[zbus(signal)]
    async fn job_removed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;
}

/// One unit object: slot 0 doubles as the started runtime unit.
struct Object {
    state: Arc<Mutex<State>>,
    slot: usize,
}

impl Object {
    fn unit(&self) -> fdo::Result<FakeUnit> {
        let state = self.state.lock().map_err(failed)?;
        let started = state.started.clone().filter(|_| self.slot == 0);
        let unit = started.or_else(|| state.units.get(self.slot).cloned());
        drop(state);
        unit.ok_or_else(|| failed("no unit in this slot"))
    }
}

struct Service(Object);

#[zbus::interface(name = "org.freedesktop.systemd1.Service", spawn = false)]
impl Service {
    #[zbus(property, name = "ControlGroup")]
    fn control_group(&self) -> fdo::Result<String> {
        if self.0.state.lock().map_err(failed)?.fault == Fault::ControlGroup {
            return Err(fdo::Error::AccessDenied("ControlGroup denied".to_owned()));
        }
        self.0.unit().map(|unit| unit.control_group)
    }

    #[zbus(property, name = "MainPID")]
    fn main_pid(&self) -> fdo::Result<u32> {
        if self.0.state.lock().map_err(failed)?.fault == Fault::MainPid {
            return Err(fdo::Error::AccessDenied("MainPID denied".to_owned()));
        }
        self.0.unit().map(|unit| unit.main_pid)
    }
}

struct Unit(Object);

#[zbus::interface(name = "org.freedesktop.systemd1.Unit", spawn = false)]
impl Unit {
    #[zbus(property, name = "ActiveState")]
    fn active_state(&self) -> fdo::Result<String> {
        self.0.unit().map(|unit| unit.active)
    }
}

struct Harness {
    lifecycle: SystemdProviderLifecycle,
    state: Arc<Mutex<State>>,
    _server: zbus::Connection,
    cgroups: tempfile::TempDir,
}

impl Harness {
    fn new(units: Vec<FakeUnit>, fault: Fault) -> TestResult<Self> {
        let cgroups = tempfile::tempdir()?;
        for unit in &units {
            if !unit.control_group.is_empty() {
                let directory = cgroups
                    .path()
                    .join(unit.control_group.trim_start_matches('/'));
                fs::create_dir_all(&directory)?;
                fs::write(directory.join("cgroup.events"), b"populated 1\n")?;
                fs::write(directory.join("cgroup.kill"), b"0")?;
            }
        }
        let state = Arc::new(Mutex::new(State {
            units,
            fault,
            cgroups: cgroups.path().to_owned(),
            ..State::default()
        }));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let shared = Arc::clone(&state);
        let (server, client) = runtime.block_on(peer_connections(move |server| {
            let mut builder = server.serve_at(MANAGER_PATH, Manager(Arc::clone(&shared)));
            for (slot, path) in UNIT_PATHS.into_iter().enumerate() {
                builder = builder
                    .serve_at(
                        path,
                        Service(Object {
                            state: Arc::clone(&shared),
                            slot,
                        }),
                    )
                    .serve_at(
                        path,
                        Unit(Object {
                            state: Arc::clone(&shared),
                            slot,
                        }),
                    );
            }
            builder
        }))?;
        let transport = runtime.block_on(SystemdTransientUnitTransport::from_connection(client))?;
        let root = cgroups.path().to_owned();
        let lifecycle = SystemdProviderLifecycle::from_parts(
            runtime,
            transport,
            Box::new(move || {
                File::open(&root)
                    .map(CgroupRoot::for_test)
                    .map_err(|_| AttemptCgroupError::RootOpen(rustix::io::Errno::NOENT))
            }),
        );
        Ok(Self {
            lifecycle,
            state,
            _server: server,
            cgroups,
        })
    }

    fn calls(&self) -> TestResult<Vec<Call>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "poisoned fake")?
            .calls
            .clone())
    }

    fn terminate(&self, within: Duration) -> Result<StaleUnitsObservation, ProviderLifecycleError> {
        self.lifecycle.terminate_stale_runtimes(
            ObservationChallenge::for_test([0x11; 16]),
            std::time::Instant::now() + within,
        )
    }
}

fn runtime_name(id: u8) -> String {
    format!(
        "pigloros-provider-runtime-{}.service",
        format!("{id:02x}").repeat(16)
    )
}

fn recovery_name(id: u8) -> String {
    format!(
        "pigloros-provider-recovery-{}.service",
        format!("{id:02x}").repeat(16)
    )
}

fn loaded(name: String, active: &str, control_group: &str) -> FakeUnit {
    FakeUnit {
        name,
        loaded: true,
        active: active.to_owned(),
        control_group: control_group.to_owned(),
        main_pid: 0,
    }
}

fn listing(prefix: &str) -> Call {
    Call::List(Vec::new(), vec![format!("{prefix}*")])
}

const RUNTIME_PREFIX: &str = "pigloros-provider-runtime-";
const RECOVERY_PREFIX: &str = "pigloros-provider-recovery-";

#[test]
fn stale_units_of_both_families_are_stopped_and_proven_gone() -> TestResult {
    let runtime = runtime_name(1);
    let recovery = recovery_name(2);
    let harness = Harness::new(
        vec![
            loaded(
                runtime.clone(),
                "active",
                &format!("/system.slice/{runtime}"),
            ),
            loaded(recovery.clone(), "failed", ""),
        ],
        Fault::None,
    )?;
    let observed = harness.terminate(Duration::from_secs(10))?;
    assert_eq!(
        observed.challenge(),
        ObservationChallenge::for_test([0x11; 16])
    );
    assert_eq!(observed.stopped_unit_count(), 2);
    assert_eq!(
        harness.calls()?,
        vec![
            listing(RUNTIME_PREFIX),
            Call::Stop(runtime.clone(), "replace".to_owned()),
            Call::Reset(runtime.clone()),
            listing(RECOVERY_PREFIX),
            Call::Reset(recovery),
            listing(RUNTIME_PREFIX),
            listing(RECOVERY_PREFIX),
        ]
    );
    assert!(!harness
        .cgroups
        .path()
        .join(format!("system.slice/{runtime}"))
        .exists());
    Ok(())
}

#[test]
fn no_stale_unit_is_an_empty_termination() -> TestResult {
    let harness = Harness::new(Vec::new(), Fault::None)?;
    assert_eq!(
        harness
            .terminate(Duration::from_secs(10))?
            .stopped_unit_count(),
        0
    );
    assert_eq!(
        harness.calls()?,
        vec![
            listing(RUNTIME_PREFIX),
            listing(RECOVERY_PREFIX),
            listing(RUNTIME_PREFIX),
            listing(RECOVERY_PREFIX),
        ]
    );
    Ok(())
}

#[test]
fn a_unit_that_returns_or_keeps_its_cgroup_is_residual() -> TestResult {
    let returning = Harness::new(
        vec![
            loaded(runtime_name(1), "failed", ""),
            FakeUnit {
                loaded: false,
                ..loaded(runtime_name(3), "active", "")
            },
        ],
        Fault::LoadOnReset(1),
    )?;
    assert_eq!(
        returning.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::ResidualResource)
    );

    let name = runtime_name(4);
    let kept = Harness::new(
        vec![loaded(
            name.clone(),
            "active",
            &format!("/system.slice/{name}"),
        )],
        Fault::KeepCgroup,
    )?;
    assert_eq!(
        kept.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::ResidualResource)
    );
    Ok(())
}

#[test]
fn a_unit_that_stays_loaded_misses_its_absence_deadline() -> TestResult {
    let harness = Harness::new(
        vec![loaded(recovery_name(5), "failed", "")],
        Fault::KeepLoaded,
    )?;
    let started = std::time::Instant::now();
    assert_eq!(
        harness.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::DeadlineExceeded)
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(3), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    Ok(())
}

#[test]
fn the_caller_deadline_bounds_the_whole_termination() -> TestResult {
    let harness = Harness::new(
        vec![loaded(recovery_name(6), "failed", "")],
        Fault::KeepLoaded,
    )?;
    let started = std::time::Instant::now();
    assert_eq!(
        harness.terminate(Duration::from_millis(200)),
        Err(ProviderLifecycleError::DeadlineExceeded)
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    Ok(())
}

#[test]
fn manager_failures_are_unavailable_or_residual() -> TestResult {
    let listing_denied = Harness::new(Vec::new(), Fault::List)?;
    assert_eq!(
        listing_denied.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::Unavailable)
    );
    let unreadable = Harness::new(
        vec![loaded(runtime_name(7), "failed", "")],
        Fault::ControlGroup,
    )?;
    assert_eq!(
        unreadable.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::Unavailable)
    );
    let active_without_cgroup =
        Harness::new(vec![loaded(runtime_name(8), "active", "")], Fault::None)?;
    assert_eq!(
        active_without_cgroup.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::ResidualResource)
    );
    Ok(())
}

fn binary_path(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex: String = digest
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect();
    format!("/var/lib/pigloros/sandbox/providers/{hex}")
}

fn starting(main_pid: u32, control_group: &str, fault: Fault) -> TestResult<Harness> {
    let harness = Harness::new(Vec::new(), fault)?;
    harness.state.lock().map_err(|_| "poisoned fake")?.started = Some(FakeUnit {
        name: String::new(),
        loaded: false,
        active: "active".to_owned(),
        control_group: control_group.to_owned(),
        main_pid,
    });
    Ok(harness)
}

fn start(
    harness: &Harness,
    scope: [u8; 16],
    path: &str,
    within: Duration,
) -> Result<StartedRuntimeObservation, ProviderLifecycleError> {
    let target = RuntimeSlotTarget::for_test(
        ObservationChallenge::for_test([0x22; 16]),
        [0x33; 16],
        scope,
        path,
        [0x44; 32],
    );
    harness
        .lifecycle
        .start_provider_runtime(&target, std::time::Instant::now() + within)
}

#[test]
fn the_runtime_unit_is_started_with_exactly_the_r11_properties() -> TestResult {
    let pid = std::process::id();
    let control_group = "/system.slice/runtime.service";
    let harness = starting(pid, control_group, Fault::None)?;
    let path = binary_path([0x44; 32]);
    let observed = start(&harness, SCOPE, &path, Duration::from_secs(32))?;
    assert_eq!(
        observed.challenge(),
        ObservationChallenge::for_test([0x22; 16])
    );
    assert_eq!(observed.lifecycle_scope_id(), SCOPE);
    assert_eq!(observed.main_pid().get(), u64::from(pid));
    assert_eq!(
        observed.main_start_time_ticks(),
        process_start_time_ticks(observed.main_pid())?
    );
    assert_eq!(observed.control_group().as_str(), control_group);

    let calls = harness.calls()?;
    let [Call::Start {
        name,
        mode,
        properties,
        auxiliary,
    }] = calls.as_slice()
    else {
        return Err(format!("unexpected calls {calls:?}").into());
    };
    assert_eq!(
        name,
        &format!("pigloros-provider-runtime-{}.service", "5c".repeat(16))
    );
    assert_eq!(mode, "fail");
    assert_eq!(*auxiliary, 0);
    let expected = [
        ("Type", "s", "notify"),
        ("NotifyAccess", "s", "main"),
        ("ExitType", "s", "main"),
        ("KillMode", "s", "control-group"),
        ("Restart", "s", "no"),
        ("TimeoutStartUSec", "t", "30000000"),
        ("CollectMode", "s", "inactive-or-failed"),
        ("UMask", "u", "63"),
        ("StandardInput", "s", "null"),
    ];
    assert_eq!(properties.len(), expected.len() + 1);
    for ((name, signature, value), (expected_name, expected_signature, expected_value)) in
        properties.iter().zip(expected)
    {
        assert_eq!(
            (name.as_str(), signature.as_str(), value.as_str()),
            (expected_name, expected_signature, expected_value)
        );
    }
    let (exec_name, exec_signature, exec_value) = &properties[expected.len()];
    assert_eq!(
        (exec_name.as_str(), exec_signature.as_str()),
        ("ExecStart", "a(sasb)")
    );
    assert_eq!(exec_value.matches(path.as_str()).count(), 2, "{exec_value}");
    assert!(exec_value.contains("\"provider-runtime\""), "{exec_value}");
    assert!(exec_value.contains("false"), "{exec_value}");
    Ok(())
}

#[test]
fn a_refused_or_failed_start_is_unavailable() -> TestResult {
    let path = binary_path([0x44; 32]);
    let pid = std::process::id();
    for fault in [
        Fault::RefuseStart,
        Fault::StartResult("timeout"),
        Fault::StartResult("failed"),
    ] {
        let harness = starting(pid, "/system.slice/runtime.service", fault)?;
        assert_eq!(
            start(&harness, SCOPE, &path, Duration::from_secs(32)),
            Err(ProviderLifecycleError::Unavailable)
        );
    }
    Ok(())
}

#[test]
fn contradictory_start_evidence_is_refused() -> TestResult {
    let path = binary_path([0x44; 32]);
    let pid = std::process::id();
    for (main_pid, control_group, fault) in [
        (
            pid,
            "/system.slice/runtime.service",
            Fault::CompletionUnit("other.service"),
        ),
        (pid, "/system.slice/runtime.service", Fault::Substitute),
        (0, "/system.slice/runtime.service", Fault::None),
        (u32::MAX, "/system.slice/runtime.service", Fault::None),
        (pid, "system.slice/runtime.service", Fault::None),
    ] {
        let harness = starting(main_pid, control_group, fault)?;
        assert_eq!(
            start(&harness, SCOPE, &path, Duration::from_secs(32)),
            Err(ProviderLifecycleError::Contradiction),
            "{main_pid} {control_group}"
        );
    }
    Ok(())
}

#[test]
fn an_invalid_target_starts_nothing() -> TestResult {
    let harness = starting(
        std::process::id(),
        "/system.slice/runtime.service",
        Fault::None,
    )?;
    for (scope, path) in [
        ([0; 16], binary_path([0x44; 32])),
        (SCOPE, binary_path([0x45; 32])),
    ] {
        assert_eq!(
            start(&harness, scope, &path, Duration::from_secs(32)),
            Err(ProviderLifecycleError::Contradiction)
        );
    }
    assert!(harness.calls()?.is_empty());
    Ok(())
}

#[test]
fn the_start_is_bounded_by_the_caller_deadline() -> TestResult {
    let harness = starting(
        std::process::id(),
        "/system.slice/runtime.service",
        Fault::None,
    )?;
    assert_eq!(
        start(&harness, SCOPE, &binary_path([0x44; 32]), Duration::ZERO),
        Err(ProviderLifecycleError::DeadlineExceeded)
    );
    Ok(())
}

#[test]
fn the_runtime_request_names_only_the_digest_object_path() {
    let digest = [0xa1; 32];
    let path = binary_path(digest);
    assert!(ProviderRuntimeUnitRequest::new(&path, digest).is_ok());
    for invalid in [
        binary_path([0xa2; 32]),
        path.to_uppercase(),
        path.replace("/providers/", "/images/"),
        format!("{path}/"),
        path[..path.len() - 1].to_owned(),
    ] {
        assert!(
            ProviderRuntimeUnitRequest::new(&invalid, digest).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn only_start_identity_failures_are_contradictions() {
    assert_eq!(
        start_failure(&SystemdTransientUnitTransportError::CgroupUnitMismatch),
        ProviderLifecycleError::Contradiction
    );
    assert_eq!(
        start_failure(&SystemdTransientUnitTransportError::JobIdentityMismatch {
            expected: String::new(),
            actual: String::new(),
        }),
        ProviderLifecycleError::Contradiction
    );
    assert_eq!(
        start_failure(&SystemdTransientUnitTransportError::JobSignalEnded),
        ProviderLifecycleError::Unavailable
    );
}

/// The parent runs `connect` in a child whose system-bus address is a
/// non-socket, so the real connection path fails closed.
#[test]
fn connect_fails_closed_without_a_usable_system_bus() -> TestResult {
    const CHILD: &str = "PIGLOROS_PROVIDER_LIFECYCLE_CONNECT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(
            SystemdProviderLifecycle::connect().err(),
            Some(ProviderLifecycleError::Unavailable)
        );
        return Ok(());
    }
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "provider_lifecycle::tests::connect_fails_closed_without_a_usable_system_bus",
        ])
        .env(CHILD, "1")
        .env("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/dev/null")
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
fn inconsistent_listings_are_unavailable() -> TestResult {
    for fault in [
        Fault::BadListing,
        Fault::DuplicateListing,
        Fault::LookupDenied,
        Fault::ListedElsewhere,
    ] {
        let harness = Harness::new(vec![loaded(runtime_name(9), "failed", "")], fault)?;
        assert_eq!(
            harness.terminate(Duration::from_secs(10)),
            Err(ProviderLifecycleError::Unavailable),
            "{fault:?}"
        );
    }
    Ok(())
}

#[test]
fn an_unprovable_final_listing_is_residual() -> TestResult {
    let harness = Harness::new(
        vec![loaded(runtime_name(10), "failed", "")],
        Fault::ListFailsFrom(3),
    )?;
    assert_eq!(
        harness.terminate(Duration::from_secs(10)),
        Err(ProviderLifecycleError::ResidualResource)
    );
    Ok(())
}

#[test]
fn unreadable_started_unit_evidence_is_unavailable() -> TestResult {
    let path = binary_path([0x44; 32]);
    for fault in [
        Fault::LookupDenied,
        Fault::MainPid,
        Fault::ControlGroup,
        Fault::StartedLookupFailsFrom(3),
    ] {
        let harness = starting(std::process::id(), "/system.slice/runtime.service", fault)?;
        assert_eq!(
            start(&harness, SCOPE, &path, Duration::from_secs(32)),
            Err(ProviderLifecycleError::Unavailable),
            "{fault:?}"
        );
    }
    Ok(())
}

#[test]
fn manager_setup_failures_never_start_a_unit() -> TestResult {
    let harness = Harness::new(Vec::new(), Fault::None)?;
    let transport = &harness.lifecycle.transport;
    let name = TransientServiceUnitName::provider_unit(ProviderUnitFamily::Runtime, SCOPE)?;
    let runtime = &harness.lifecycle.runtime;
    assert!(matches!(
        runtime.block_on(SystemdTransientUnitTransport::observe_provider_units_with(
            Err(zbus::Error::Failure("no proxy".to_owned())),
            ProviderUnitFamily::Runtime,
        )),
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));
    assert!(matches!(
        runtime.block_on(transport.start_runtime_with(
            Err(zbus::Error::Failure("no proxy".to_owned())),
            &name,
            Ok(Vec::new()),
        )),
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));
    let subscribe_failure = runtime.block_on(async {
        let proxy = zbus_systemd::systemd1::ManagerProxy::new(transport.connection()).await?;
        let started = transport
            .start_runtime_with_completions(
                &proxy,
                Err(zbus::Error::Failure("no subscription".to_owned())),
                &name,
                Ok(Vec::new()),
            )
            .await;
        Ok::<_, zbus::Error>(started)
    })?;
    assert!(matches!(
        subscribe_failure,
        Err(SystemdTransientUnitTransportError::JobSignalSubscribe(_))
    ));
    let serialization_failure = runtime.block_on(async {
        let proxy = zbus_systemd::systemd1::ManagerProxy::new(transport.connection()).await?;
        let completions = proxy.receive_job_removed().await;
        let started = transport
            .start_runtime_with_completions(
                &proxy,
                completions,
                &name,
                Err(zbus::Error::IncorrectType),
            )
            .await;
        Ok::<_, zbus::Error>(started)
    })?;
    assert!(matches!(
        serialization_failure,
        Err(SystemdTransientUnitTransportError::Serialization(_))
    ));
    assert!(harness.calls()?.is_empty());
    Ok(())
}
