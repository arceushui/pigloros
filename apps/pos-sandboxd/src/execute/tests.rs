use std::{
    fs::File,
    future::Future,
    os::{
        fd::{AsFd, OwnedFd as StdOwnedFd},
        unix::net::UnixStream,
    },
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use pos_conformance::SandboxSyscallSetV1;
use pos_reference::sandbox_provider_protocol::{
    NetworkCaptureStore, NetworkExchangePlan, NetworkExchangeReply, NetworkExchangeRequest,
    SandboxArchitecture, SandboxExecutionMode, SandboxLimit,
};
use zvariant::OwnedFd;

use super::*;
use crate::test_fixtures::{
    authority, capability, capture_store, grant_authority, plan, remote, LoopbackConnector,
    TestResult, ATTEMPT, OTHER, REQUEST, RESPONSE,
};
use crate::{
    EstablishedNetwork, LocalProxyBindError, SystemdTransientUnitValue, TransientServiceUnitName,
};

const X86_64: &[u8] = include_bytes!(
    "../../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor"
);
const HOST_SERVICE: &str = "piglor-host-service-v1";
const RELEASE: &str = "piglor-release-v1";
const WORK: &str = "size=4096,nosuid,nodev,noexec";
const GENEROUS_WATCHDOG_MS: u64 = 30_000;

#[derive(Debug, thiserror::Error)]
#[error("injected failure")]
struct Injected;

type Log = Arc<Mutex<Vec<String>>>;

fn record(log: &Log, entry: &str) {
    if let Ok(mut log) = log.lock() {
        log.push(entry.to_owned());
    }
}

fn recorded(log: &Log) -> Vec<String> {
    log.lock().map(|log| log.clone()).unwrap_or_default()
}

/// What the fake host saw in the compiled request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Observed {
    root: String,
    descriptors: Vec<String>,
    families: (bool, Vec<String>),
    work: Vec<(String, String)>,
}

enum AdapterScript {
    /// Do nothing with FD 3.
    None,
    /// Send one planned NXQ1, read its reply, then close.
    Exchange(NetworkExchangePlan),
    /// Hold FD 3 open and silent until the test ends.
    Silent,
}

struct FakeHost {
    log: Log,
    fail_start: bool,
    fail_bind: bool,
    fail_kill: bool,
    observed: Arc<Mutex<Observed>>,
    adapter: AdapterScript,
    adapter_reply: Arc<Mutex<Option<Result<Vec<u8>, String>>>>,
    held: Arc<Mutex<Vec<UnixStream>>>,
    empty_after: usize,
    fail_read: bool,
    fail_cgroup_kill: bool,
    polls: Arc<AtomicUsize>,
    cgroup_kills: Arc<AtomicUsize>,
}

impl FakeHost {
    fn new(log: &Log) -> Self {
        Self {
            log: Arc::clone(log),
            fail_start: false,
            fail_bind: false,
            fail_kill: false,
            observed: Arc::default(),
            adapter: AdapterScript::None,
            adapter_reply: Arc::default(),
            held: Arc::default(),
            empty_after: 0,
            fail_read: false,
            fail_cgroup_kill: false,
            polls: Arc::default(),
            cgroup_kills: Arc::default(),
        }
    }

    fn observe(&self, request: &TransientUnitRequest) -> Option<StdOwnedFd> {
        let mut observed = Observed::default();
        let mut adapter_end = None;
        for property in request.requested_properties() {
            match property.value() {
                SystemdTransientUnitValue::RootDirectory(root) => observed.root.clone_from(root),
                SystemdTransientUnitValue::RestrictAddressFamilies(families) => {
                    observed.families.clone_from(families);
                }
                SystemdTransientUnitValue::TemporaryFileSystem(work) => {
                    observed.work.clone_from(work);
                }
                SystemdTransientUnitValue::ExtraFileDescriptors(descriptors) => {
                    observed.descriptors =
                        descriptors.iter().map(|(_, name)| name.clone()).collect();
                    adapter_end = descriptors
                        .iter()
                        .find(|(_, name)| name == HOST_SERVICE)
                        .and_then(|(descriptor, _)| descriptor.as_fd().try_clone_to_owned().ok());
                }
                _other => {}
            }
        }
        if let Ok(mut slot) = self.observed.lock() {
            *slot = observed;
        }
        adapter_end
    }

    fn drive(&self, adapter_end: StdOwnedFd) {
        let mut stream = UnixStream::from(adapter_end);
        match &self.adapter {
            AdapterScript::None => {}
            AdapterScript::Silent => {
                if let Ok(mut held) = self.held.lock() {
                    held.push(stream);
                }
            }
            AdapterScript::Exchange(plan) => {
                let plan = plan.clone();
                let reply = Arc::clone(&self.adapter_reply);
                thread::spawn(move || {
                    let outcome = NetworkExchangeRequest::new(&plan, REQUEST)
                        .map_err(|error| error.to_string())
                        .and_then(|request| {
                            request
                                .write_to(&mut stream)
                                .map_err(|error| error.to_string())
                        })
                        .and_then(|()| {
                            NetworkExchangeReply::read_from(&mut stream, ATTEMPT, &plan)
                                .map_err(|error| error.to_string())
                        })
                        .and_then(|reply| {
                            reply
                                .response_bytes()
                                .map(<[u8]>::to_vec)
                                .ok_or_else(|| "the reply was not captured".to_owned())
                        });
                    if let Ok(mut slot) = reply.lock() {
                        *slot = Some(outcome);
                    }
                });
            }
        }
    }

    fn observed(&self) -> Observed {
        self.observed
            .lock()
            .map(|observed| observed.clone())
            .unwrap_or_default()
    }
}

struct FakeCgroup {
    polls: Arc<AtomicUsize>,
    kills: Arc<AtomicUsize>,
    empty_after: usize,
    fail_read: bool,
    fail_kill: bool,
}

impl UnitCgroup for FakeCgroup {
    type Error = Injected;

    fn is_empty(&mut self) -> Result<bool, Injected> {
        let polls = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_read {
            Err(Injected)
        } else {
            Ok(polls > self.empty_after)
        }
    }

    fn kill_all(&mut self) -> Result<(), Injected> {
        self.kills.fetch_add(1, Ordering::SeqCst);
        if self.fail_kill {
            Err(Injected)
        } else {
            Ok(())
        }
    }
}

impl UnitHost for FakeHost {
    type Started = String;
    type Cgroup = FakeCgroup;
    type Error = Injected;

    fn start(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
    ) -> impl Future<Output = Result<String, Injected>> + Send {
        record(&self.log, "start");
        let adapter_end = self.observe(&request);
        let outcome = if self.fail_start {
            Err(Injected)
        } else {
            if let Some(adapter_end) = adapter_end {
                self.drive(adapter_end);
            }
            Ok(unit_name.as_str().to_owned())
        };
        async move { outcome }
    }

    fn bind_cgroup(
        &self,
        _started: &String,
    ) -> impl Future<Output = Result<FakeCgroup, Injected>> + Send {
        record(&self.log, "bind_cgroup");
        let outcome = if self.fail_bind {
            Err(Injected)
        } else {
            Ok(FakeCgroup {
                polls: Arc::clone(&self.polls),
                kills: Arc::clone(&self.cgroup_kills),
                empty_after: self.empty_after,
                fail_read: self.fail_read,
                fail_kill: self.fail_cgroup_kill,
            })
        };
        async move { outcome }
    }

    fn stop(
        &self,
        _unit_name: TransientServiceUnitName,
    ) -> impl Future<Output = Result<(), Injected>> + Send {
        record(&self.log, "stop");
        async move { Ok(()) }
    }

    fn kill(
        &self,
        _unit_name: TransientServiceUnitName,
    ) -> impl Future<Output = Result<(), Injected>> + Send {
        record(&self.log, "kill");
        let outcome = if self.fail_kill {
            Err(Injected)
        } else {
            Ok(())
        };
        async move { outcome }
    }
}

struct FakeBarrier {
    log: Log,
    fail_take: bool,
    fail_release: bool,
}

impl FakeBarrier {
    fn new(log: &Log) -> Self {
        Self {
            log: Arc::clone(log),
            fail_take: false,
            fail_release: false,
        }
    }
}

impl LaunchBarrier for FakeBarrier {
    type Error = Injected;

    fn take_unit_end(&mut self) -> Result<OwnedFd, Injected> {
        record(&self.log, "take_unit_end");
        if self.fail_take {
            return Err(Injected);
        }
        File::open("/dev/null")
            .map(|file| OwnedFd::from(StdOwnedFd::from(file)))
            .map_err(|_| Injected)
    }

    fn release(
        &mut self,
        _attempt: &ActiveAttempt,
    ) -> impl Future<Output = Result<(), Injected>> + Send {
        record(&self.log, "release");
        let outcome = if self.fail_release {
            Err(Injected)
        } else {
            Ok(())
        };
        async move { outcome }
    }
}

struct LoopbackNetwork;

impl LocalNetworkPort for LoopbackNetwork {
    type Connector = LoopbackConnector;

    fn establish(&self, attempt_id: [u8; 16]) -> EstablishedNetwork<LoopbackConnector> {
        EstablishedNetwork::new(attempt_id, LoopbackConnector)
    }
}

/// A port whose namespace belongs to another attempt.
struct ForeignNetwork;

impl LocalNetworkPort for ForeignNetwork {
    type Connector = LoopbackConnector;

    fn establish(&self, _attempt_id: [u8; 16]) -> EstablishedNetwork<LoopbackConnector> {
        EstablishedNetwork::new(OTHER, LoopbackConnector)
    }
}

fn limits(watchdog_ms: u64) -> Vec<SandboxLimit> {
    (0..=16)
        .map(|limit_id| SandboxLimit {
            limit_id,
            value: match limit_id {
                0 => 134_217_728,
                1 => 0,
                2 => 16,
                3 => 500_000,
                4 => watchdog_ms,
                5 => 64,
                6 => 4_096,
                9 => 4_096,
                _ => 1_000,
            },
        })
        .collect()
}

fn attempt(mode: SandboxExecutionMode) -> TestResult<AdmittedAttempt> {
    Ok(AdmittedAttempt::for_test(ATTEMPT, authority(), mode)?)
}

fn job(
    attempt: AdmittedAttempt,
    mode: ModePlan,
    store: &Arc<NetworkCaptureStore>,
    watchdog_ms: u64,
) -> TestResult<ExecuteJob> {
    let record = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    Ok(ExecuteJob {
        attempt,
        launcher_source: LauncherSource::new("/usr/lib/pigloros/release-launcher")?,
        system_call_filter: SystemCallFilter::from_selected_record(
            X86_64,
            record.syscall_set_digest,
            SandboxArchitecture::X86_64,
        )?,
        service_limits: SystemdServiceLimits::from_effective_limits(&limits(watchdog_ms))?,
        mode,
        capture_store: Arc::clone(store),
    })
}

fn root_for(
    log: &Log,
    attempt_id: [u8; 16],
) -> impl FnOnce() -> Result<CheckedRoot, ImageActivationError> + Send {
    let log = Arc::clone(log);
    let component = TransientServiceUnitName::from_attempt_id(attempt_id)
        .map(|name| name.attempt_component().to_owned())
        .unwrap_or_default();
    move || {
        record(&log, "recheck");
        Ok(CheckedRoot::for_test(ActivatedRootDirectory::for_attempt(
            &component,
        )))
    }
}

fn root_path(attempt_id: [u8; 16]) -> String {
    TransientServiceUnitName::from_attempt_id(attempt_id)
        .map(|name| {
            ActivatedRootDirectory::for_attempt(name.attempt_component())
                .as_str()
                .to_owned()
        })
        .unwrap_or_default()
}

fn names(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_owned()).collect()
}

async fn run(
    host: &FakeHost,
    barrier: &mut FakeBarrier,
    job: ExecuteJob,
    log: &Log,
) -> Result<AttemptExecution<String, FakeCgroup>, ExecuteFailure> {
    execute(host, barrier, &LoopbackNetwork, job, root_for(log, ATTEMPT)).await
}

fn failure<T>(result: Result<T, ExecuteFailure>) -> TestResult<ExecuteFailure> {
    result
        .err()
        .ok_or_else(|| "the execution unexpectedly succeeded".into())
}

#[tokio::test]
async fn a_local_attempt_serves_fd3_once_released_and_reports_its_transcripts() -> TestResult {
    let (address, remote) = remote()?;
    let plan = plan()?;
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let mut host = FakeHost::new(&log);
    host.adapter = AdapterScript::Exchange(plan.clone());
    let mut barrier = FakeBarrier::new(&log);
    let admission = crate::test_fixtures::admission(
        ATTEMPT,
        grant_authority(),
        [4, 5, 6],
        vec![(plan.clone(), capability(address))],
    );
    let mode = ModePlan::Local {
        admission: Box::new(admission),
    };
    let job = job(
        attempt(SandboxExecutionMode::Local)?,
        mode,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;

    let execution = run(&host, &mut barrier, job, &log).await?;

    // The recheck sits last before the start, and nothing is served before
    // the launcher releases the adapter.
    assert_eq!(
        recorded(&log),
        [
            "take_unit_end",
            "recheck",
            "start",
            "bind_cgroup",
            "release"
        ]
    );
    assert_eq!(
        host.observed(),
        Observed {
            root: root_path(ATTEMPT),
            descriptors: names(&[HOST_SERVICE, RELEASE]),
            families: (true, names(&["AF_UNIX"])),
            work: vec![("/work".to_owned(), WORK.to_owned())],
        }
    );
    assert_eq!(execution.attempt_id, ATTEMPT);
    assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
    assert_eq!(execution.network.termination(), None);
    let digests = execution.network.transcript_digests();
    assert_eq!(digests.len(), 1);
    assert_eq!(
        remote.join().map_err(|_| "remote thread")??,
        REQUEST.to_vec()
    );
    assert_eq!(
        host.adapter_reply
            .lock()
            .map_err(|error| error.to_string())?
            .clone(),
        Some(Ok(RESPONSE.to_vec()))
    );

    // The retained capture replays offline into a later Replay attempt.
    let replay_log = Log::default();
    let replay_host = FakeHost::new(&replay_log);
    let mut replay_barrier = FakeBarrier::new(&replay_log);
    let replay_attempt = [0x43; 16];
    let replay = ModePlan::Replay {
        exchanges: vec![ReplayRequest {
            attempt_id: ATTEMPT,
            plan,
            transcript_digest: digests[0],
        }],
    };
    let replayed = execute(
        &replay_host,
        &mut replay_barrier,
        &LoopbackNetwork,
        job_for(replay_attempt, SandboxExecutionMode::Replay, replay, &store)?,
        root_for(&replay_log, replay_attempt),
    )
    .await?;
    assert_eq!(replayed.network.transcript_digests(), digests);
    assert_eq!(replayed.network.termination(), None);
    assert_eq!(
        replay_host.observed(),
        Observed {
            root: root_path(replay_attempt),
            descriptors: names(&[RELEASE]),
            families: (true, Vec::new()),
            work: vec![("/work".to_owned(), WORK.to_owned())],
        }
    );
    Ok(())
}

fn job_for(
    attempt_id: [u8; 16],
    mode: SandboxExecutionMode,
    plan: ModePlan,
    store: &Arc<NetworkCaptureStore>,
) -> TestResult<ExecuteJob> {
    job(
        AdmittedAttempt::for_test(attempt_id, authority(), mode)?,
        plan,
        store,
        GENEROUS_WATCHDOG_MS,
    )
}

#[tokio::test]
async fn air_gapped_and_fork_attempts_get_only_the_release_descriptor() -> TestResult {
    let (_root, store) = capture_store()?;
    for (mode, plan) in [
        (SandboxExecutionMode::AirGapped, ModePlan::AirGapped),
        (SandboxExecutionMode::Fork, ModePlan::Fork),
    ] {
        let log = Log::default();
        let host = FakeHost::new(&log);
        let mut barrier = FakeBarrier::new(&log);
        let job = job(attempt(mode)?, plan, &store, GENEROUS_WATCHDOG_MS)?;
        let execution = run(&host, &mut barrier, job, &log).await?;
        assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
        assert!(matches!(execution.network, NetworkEvidence::None));
        assert!(execution.network.transcript_digests().is_empty());
        assert_eq!(execution.network.termination(), None);
        assert_eq!(
            host.observed(),
            Observed {
                root: root_path(ATTEMPT),
                descriptors: names(&[RELEASE]),
                families: (true, Vec::new()),
                work: vec![("/work".to_owned(), WORK.to_owned())],
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn nothing_starts_when_the_plan_is_not_the_admitted_mode() -> TestResult {
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let host = FakeHost::new(&log);
    let mut barrier = FakeBarrier::new(&log);
    let job = job(
        attempt(SandboxExecutionMode::Local)?,
        ModePlan::AirGapped,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(run(&host, &mut barrier, job, &log).await)?;
    assert!(matches!(failed.error, ExecuteError::ModeMismatch));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(recorded(&log).is_empty());
    Ok(())
}

#[tokio::test]
async fn an_unavailable_replay_capture_stops_before_the_launcher() -> TestResult {
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let host = FakeHost::new(&log);
    let mut barrier = FakeBarrier::new(&log);
    let replay = ModePlan::Replay {
        exchanges: vec![ReplayRequest {
            attempt_id: ATTEMPT,
            plan: plan()?,
            transcript_digest: [0x77; 32],
        }],
    };
    let job = job(
        attempt(SandboxExecutionMode::Replay)?,
        replay,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(run(&host, &mut barrier, job, &log).await)?;
    assert!(matches!(failed.error, ExecuteError::ReplayUnavailable));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(recorded(&log).is_empty());
    Ok(())
}

#[tokio::test]
async fn the_barrier_must_hand_over_its_end_before_the_root_is_rechecked() -> TestResult {
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let host = FakeHost::new(&log);
    let mut barrier = FakeBarrier::new(&log);
    barrier.fail_take = true;
    let job = job(
        attempt(SandboxExecutionMode::AirGapped)?,
        ModePlan::AirGapped,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(run(&host, &mut barrier, job, &log).await)?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert_eq!(recorded(&log), ["take_unit_end"]);
    Ok(())
}

#[tokio::test]
async fn a_failed_or_foreign_root_recheck_never_starts_the_unit() -> TestResult {
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let host = FakeHost::new(&log);
    let mut barrier = FakeBarrier::new(&log);
    let job_failed = job(
        attempt(SandboxExecutionMode::AirGapped)?,
        ModePlan::AirGapped,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(
        execute(&host, &mut barrier, &LoopbackNetwork, job_failed, || {
            Err(ImageActivationError::EvidenceMismatch)
        })
        .await,
    )?;
    assert!(matches!(
        failed.error,
        ExecuteError::Recheck(ImageActivationError::EvidenceMismatch)
    ));
    assert_eq!(failed.unit, UnitState::NotStarted);

    let job_foreign = job(
        attempt(SandboxExecutionMode::AirGapped)?,
        ModePlan::AirGapped,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(
        execute(
            &host,
            &mut barrier,
            &LoopbackNetwork,
            job_foreign,
            root_for(&log, OTHER),
        )
        .await,
    )?;
    assert!(matches!(failed.error, ExecuteError::RootIdentity));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(!recorded(&log).iter().any(|entry| entry == "start"));
    Ok(())
}

#[tokio::test]
async fn a_unit_that_fails_to_start_or_bind_is_killed() -> TestResult {
    let (_root, store) = capture_store()?;
    for (fail_start, fail_kill, expected_unit) in [
        (true, false, UnitState::Killed),
        (true, true, UnitState::KillFailed),
        (false, false, UnitState::Killed),
    ] {
        let log = Log::default();
        let mut host = FakeHost::new(&log);
        host.fail_start = fail_start;
        host.fail_bind = !fail_start;
        host.fail_kill = fail_kill;
        let mut barrier = FakeBarrier::new(&log);
        let job = job(
            attempt(SandboxExecutionMode::AirGapped)?,
            ModePlan::AirGapped,
            &store,
            GENEROUS_WATCHDOG_MS,
        )?;
        let failed = failure(run(&host, &mut barrier, job, &log).await)?;
        if fail_start {
            assert!(matches!(failed.error, ExecuteError::Unit(_)));
        } else {
            assert!(matches!(failed.error, ExecuteError::Cgroup(_)));
        }
        assert_eq!(failed.unit, expected_unit);
        // The barrier never released the adapter.
        assert!(!recorded(&log).iter().any(|entry| entry == "release"));
        assert!(recorded(&log).ends_with(&names(&["kill", "stop"])));
        assert_eq!(host.cgroup_kills.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn a_refused_release_kills_the_unit_and_its_cgroup() -> TestResult {
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let host = FakeHost::new(&log);
    let mut barrier = FakeBarrier::new(&log);
    barrier.fail_release = true;
    let job = job(
        attempt(SandboxExecutionMode::AirGapped)?,
        ModePlan::AirGapped,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(run(&host, &mut barrier, job, &log).await)?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert_eq!(
        recorded(&log),
        [
            "take_unit_end",
            "recheck",
            "start",
            "bind_cgroup",
            "release",
            "kill",
            "stop"
        ]
    );
    assert_eq!(host.cgroup_kills.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_foreign_admission_or_namespace_is_killed_before_release() -> TestResult {
    let (address, _remote) = remote()?;
    let plan = plan()?;
    let (_root, store) = capture_store()?;
    for (admission_attempt, foreign_network, expected) in [
        (OTHER, false, LocalProxyBindError::Attempt),
        (ATTEMPT, true, LocalProxyBindError::Namespace),
    ] {
        let log = Log::default();
        let host = FakeHost::new(&log);
        let mut barrier = FakeBarrier::new(&log);
        let admission = crate::test_fixtures::admission(
            admission_attempt,
            grant_authority(),
            [4, 5, 6],
            vec![(plan.clone(), capability(address))],
        );
        let job = job(
            attempt(SandboxExecutionMode::Local)?,
            ModePlan::Local {
                admission: Box::new(admission),
            },
            &store,
            GENEROUS_WATCHDOG_MS,
        )?;
        let failed = if foreign_network {
            failure(
                execute(
                    &host,
                    &mut barrier,
                    &ForeignNetwork,
                    job,
                    root_for(&log, ATTEMPT),
                )
                .await,
            )?
        } else {
            failure(run(&host, &mut barrier, job, &log).await)?
        };
        assert!(matches!(failed.error, ExecuteError::Bind(bound) if bound == expected));
        assert_eq!(failed.unit, UnitState::Killed);
        assert!(!recorded(&log).iter().any(|entry| entry == "release"));
        assert_eq!(host.cgroup_kills.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
async fn an_unreadable_cgroup_terminates_the_unit() -> TestResult {
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let mut host = FakeHost::new(&log);
    host.fail_read = true;
    let mut barrier = FakeBarrier::new(&log);
    let job = job(
        attempt(SandboxExecutionMode::Fork)?,
        ModePlan::Fork,
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(run(&host, &mut barrier, job, &log).await)?;
    assert!(matches!(failed.error, ExecuteError::Cgroup(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert!(recorded(&log).ends_with(&names(&["release", "kill", "stop"])));
    Ok(())
}

#[tokio::test]
async fn the_watchdog_kills_an_attempt_that_never_empties() -> TestResult {
    let (_root, store) = capture_store()?;
    // A failed cgroup kill does not change the outcome: the unit kill covers it.
    for fail_cgroup_kill in [false, true] {
        let log = Log::default();
        let mut host = FakeHost::new(&log);
        host.empty_after = usize::MAX;
        host.fail_cgroup_kill = fail_cgroup_kill;
        let mut barrier = FakeBarrier::new(&log);
        let job = job(
            attempt(SandboxExecutionMode::AirGapped)?,
            ModePlan::AirGapped,
            &store,
            100,
        )?;
        let started = Instant::now();
        let execution = run(&host, &mut barrier, job, &log).await?;
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert_eq!(execution.ending, AttemptEnding::WatchdogKilled);
        assert!(recorded(&log).ends_with(&names(&["release", "kill", "stop"])));
        assert_eq!(host.cgroup_kills.load(Ordering::SeqCst), 1);
    }

    // An unacknowledged SIGKILL is reported, not hidden.
    let log = Log::default();
    let mut host = FakeHost::new(&log);
    host.empty_after = usize::MAX;
    host.fail_kill = true;
    let mut barrier = FakeBarrier::new(&log);
    let job = job(
        attempt(SandboxExecutionMode::AirGapped)?,
        ModePlan::AirGapped,
        &store,
        100,
    )?;
    let execution = run(&host, &mut barrier, job, &log).await?;
    assert_eq!(execution.ending, AttemptEnding::WatchdogKillFailed);
    Ok(())
}

#[tokio::test]
async fn the_watchdog_closes_a_silent_fd3_and_kills_the_unit() -> TestResult {
    let plan = plan()?;
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let mut host = FakeHost::new(&log);
    host.adapter = AdapterScript::Silent;
    let mut barrier = FakeBarrier::new(&log);
    let admission = crate::test_fixtures::admission(
        ATTEMPT,
        grant_authority(),
        [4, 5, 6],
        vec![(
            plan,
            capability(std::net::SocketAddr::from(([127, 0, 0, 1], 9))),
        )],
    );
    let job = job(
        attempt(SandboxExecutionMode::Local)?,
        ModePlan::Local {
            admission: Box::new(admission),
        },
        &store,
        150,
    )?;
    let execution = run(&host, &mut barrier, job, &log).await?;
    assert_eq!(execution.ending, AttemptEnding::WatchdogKilled);
    assert!(matches!(
        &execution.network,
        NetworkEvidence::Local(served) if served.watchdog_expired
    ));
    assert!(execution.network.transcript_digests().is_empty());
    assert!(recorded(&log).ends_with(&names(&["release", "kill", "stop"])));
    Ok(())
}

struct PanickingNetwork;

struct PanickingConnector;

impl pos_reference::sandbox_provider_protocol::NetworkEndpointConnector for PanickingConnector {
    fn connect(
        &mut self,
        _endpoint: std::net::SocketAddr,
        _timeout: Duration,
    ) -> std::io::Result<std::net::TcpStream> {
        std::panic::resume_unwind(Box::new("the connector failed"))
    }
}

impl LocalNetworkPort for PanickingNetwork {
    type Connector = PanickingConnector;

    fn establish(&self, attempt_id: [u8; 16]) -> EstablishedNetwork<PanickingConnector> {
        EstablishedNetwork::new(attempt_id, PanickingConnector)
    }
}

#[tokio::test]
async fn a_failed_proxy_task_terminates_the_unit() -> TestResult {
    let plan = plan()?;
    let (_root, store) = capture_store()?;
    let log = Log::default();
    let mut host = FakeHost::new(&log);
    host.adapter = AdapterScript::Exchange(plan.clone());
    let mut barrier = FakeBarrier::new(&log);
    let admission = crate::test_fixtures::admission(
        ATTEMPT,
        grant_authority(),
        [4, 5, 6],
        vec![(
            plan,
            capability(std::net::SocketAddr::from(([127, 0, 0, 1], 9))),
        )],
    );
    let job = job(
        attempt(SandboxExecutionMode::Local)?,
        ModePlan::Local {
            admission: Box::new(admission),
        },
        &store,
        GENEROUS_WATCHDOG_MS,
    )?;
    let failed = failure(
        execute(
            &host,
            &mut barrier,
            &PanickingNetwork,
            job,
            root_for(&log, ATTEMPT),
        )
        .await,
    )?;
    assert!(matches!(failed.error, ExecuteError::Serve(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert_eq!(host.cgroup_kills.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn the_failure_names_its_cause_and_the_unit_state() {
    let failure = ExecuteFailure {
        error: ExecuteError::ModeMismatch,
        unit: UnitState::KillFailed,
    };
    assert_eq!(
        failure.to_string(),
        "execution failed with the unit KillFailed"
    );
    assert!(std::error::Error::source(&failure).is_some());
}
