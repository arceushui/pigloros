use std::{
    fs::File,
    future::Future,
    io::Write,
    net::SocketAddr,
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
    LocalNetworkTermination, NetworkCaptureStore, NetworkExchangePlan, NetworkExchangeReply,
    NetworkExchangeRequest, SandboxArchitecture, SandboxExecutionMode, SandboxLimit,
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
    /// Send a zero-length frame, then hold FD 3 open.
    ProtocolViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Start,
    Bind,
    Kill,
    ReadCgroup,
    KillCgroup,
    HangStart,
    HangBind,
    HangKill,
    HangStop,
}

type ExecCommands = Vec<(String, Vec<String>, bool)>;

type Reply = Arc<Mutex<Option<Result<Vec<u8>, String>>>>;

struct FakeHost {
    log: Log,
    faults: Vec<Fault>,
    observed: Arc<Mutex<Observed>>,
    exec_start: Arc<Mutex<ExecCommands>>,
    adapter: AdapterScript,
    adapter_reply: Reply,
    held: Arc<Mutex<Vec<UnixStream>>>,
    empty_after: usize,
    polls: Arc<AtomicUsize>,
    cgroup_kills: Arc<AtomicUsize>,
}

impl FakeHost {
    fn new(log: &Log) -> Self {
        Self {
            log: Arc::clone(log),
            faults: Vec::new(),
            observed: Arc::default(),
            exec_start: Arc::default(),
            adapter: AdapterScript::None,
            adapter_reply: Arc::default(),
            held: Arc::default(),
            empty_after: 0,
            polls: Arc::default(),
            cgroup_kills: Arc::default(),
        }
    }

    fn observe(&self, request: &TransientUnitRequest) -> Option<StdOwnedFd> {
        let mut observed = Observed::default();
        for property in request.requested_properties() {
            absorb(&mut observed, property.value());
        }
        observed.descriptors = extra_descriptors(request)
            .iter()
            .map(|(_, name)| name.clone())
            .collect();
        if let Ok(mut slot) = self.observed.lock() {
            *slot = observed;
        }
        if let Ok(mut slot) = self.exec_start.lock() {
            *slot = exec_start_of(request);
        }
        extra_descriptors(request)
            .iter()
            .find(|(_, name)| name == HOST_SERVICE)
            .and_then(|(descriptor, _)| descriptor.as_fd().try_clone_to_owned().ok())
    }

    fn hold(&self, stream: UnixStream) {
        if let Ok(mut held) = self.held.lock() {
            held.push(stream);
        }
    }

    fn drive(&self, adapter_end: StdOwnedFd) {
        let mut stream = UnixStream::from(adapter_end);
        match &self.adapter {
            AdapterScript::None => {}
            AdapterScript::Silent => self.hold(stream),
            AdapterScript::ProtocolViolation => {
                stream.write_all(&[0, 0, 0, 0]).ok();
                self.hold(stream);
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

    fn faulty(&self, fault: Fault) -> bool {
        self.faults.contains(&fault)
    }

    fn observed(&self) -> Observed {
        self.observed
            .lock()
            .map(|observed| observed.clone())
            .unwrap_or_default()
    }
}

fn absorb(observed: &mut Observed, value: &SystemdTransientUnitValue) {
    match value {
        SystemdTransientUnitValue::RootDirectory(root) => observed.root.clone_from(root),
        SystemdTransientUnitValue::RestrictAddressFamilies(families) => {
            observed.families.clone_from(families);
        }
        SystemdTransientUnitValue::TemporaryFileSystem(work) => observed.work.clone_from(work),
        _other => {}
    }
}

fn exec_start_of(request: &TransientUnitRequest) -> ExecCommands {
    request
        .requested_properties()
        .iter()
        .find_map(|property| match property.value() {
            SystemdTransientUnitValue::ExecStart(commands) => Some(commands.clone()),
            _other => None,
        })
        .unwrap_or_default()
}

fn extra_descriptors(request: &TransientUnitRequest) -> &[(OwnedFd, String)] {
    request
        .requested_properties()
        .iter()
        .find_map(|property| match property.value() {
            SystemdTransientUnitValue::ExtraFileDescriptors(descriptors) => {
                Some(descriptors.as_slice())
            }
            _other => None,
        })
        .unwrap_or_default()
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
    type Killer = FakeKiller;

    fn killer(&self) -> FakeKiller {
        FakeKiller {
            log: Arc::clone(&self.log),
        }
    }

    fn start(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
    ) -> impl Future<Output = Result<String, Injected>> + Send {
        record(&self.log, "start");
        let adapter_end = self.observe(&request);
        let outcome = if self.faulty(Fault::Start) {
            Err(Injected)
        } else {
            if let Some(adapter_end) = adapter_end {
                self.drive(adapter_end);
            }
            Ok(unit_name.as_str().to_owned())
        };
        let hang = self.faulty(Fault::HangStart);
        async move {
            hang_if(hang).await;
            outcome
        }
    }

    fn bind_cgroup(
        &self,
        _started: &String,
    ) -> impl Future<Output = Result<FakeCgroup, Injected>> + Send {
        record(&self.log, "bind_cgroup");
        let outcome = if self.faulty(Fault::Bind) {
            Err(Injected)
        } else {
            Ok(FakeCgroup {
                polls: Arc::clone(&self.polls),
                kills: Arc::clone(&self.cgroup_kills),
                empty_after: self.empty_after,
                fail_read: self.faulty(Fault::ReadCgroup),
                fail_kill: self.faulty(Fault::KillCgroup),
            })
        };
        let hang = self.faulty(Fault::HangBind);
        async move {
            hang_if(hang).await;
            outcome
        }
    }

    fn stop(
        &self,
        _unit_name: TransientServiceUnitName,
    ) -> impl Future<Output = Result<(), Injected>> + Send {
        record(&self.log, "stop");
        let hang = self.faulty(Fault::HangStop);
        async move {
            hang_if(hang).await;
            Ok(())
        }
    }

    fn kill(
        &self,
        _unit_name: TransientServiceUnitName,
    ) -> impl Future<Output = Result<(), Injected>> + Send {
        record(&self.log, "kill");
        let outcome = if self.faulty(Fault::Kill) {
            Err(Injected)
        } else {
            Ok(())
        };
        let hang = self.faulty(Fault::HangKill);
        async move {
            hang_if(hang).await;
            outcome
        }
    }
}

/// Never finishes when `hang` is set.
async fn hang_if(hang: bool) {
    if hang {
        std::future::pending::<()>().await;
    }
}

/// The kill handle an execution that was dropped falls back on.
struct FakeKiller {
    log: Log,
}

impl UnitKiller for FakeKiller {
    async fn kill(self, _unit_name: TransientServiceUnitName) {
        record(&self.log, "guard_kill");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BarrierFault {
    None,
    Take,
    Invocation,
    Release,
    Hang,
}

struct FakeBarrier {
    log: Log,
    released: Arc<Mutex<Vec<(String, Instant)>>>,
    fault: BarrierFault,
}

impl FakeBarrier {
    fn new(log: &Log) -> Self {
        Self {
            log: Arc::clone(log),
            released: Arc::default(),
            fault: BarrierFault::None,
        }
    }
}

impl LaunchBarrier for FakeBarrier {
    type Error = Injected;

    fn launcher_invocation(&self) -> Result<LauncherInvocation, Injected> {
        if self.fault == BarrierFault::Invocation {
            return Err(Injected);
        }
        crate::test_fixtures::invocation().map_err(|_| Injected)
    }

    fn take_unit_end(&mut self) -> Result<OwnedFd, Injected> {
        record(&self.log, "take_unit_end");
        if self.fault == BarrierFault::Take {
            return Err(Injected);
        }
        File::open("/dev/null")
            .map(|file| OwnedFd::from(StdOwnedFd::from(file)))
            .map_err(|_| Injected)
    }

    fn release(
        &mut self,
        attempt: &ActiveAttempt,
    ) -> impl Future<Output = Result<(), Injected>> + Send {
        record(&self.log, "release");
        if let Ok(mut released) = self.released.lock() {
            released.push((attempt.unit_name().as_str().to_owned(), attempt.deadline()));
        }
        let outcome = if self.fault == BarrierFault::Release {
            Err(Injected)
        } else {
            Ok(())
        };
        let hang = self.fault == BarrierFault::Hang;
        async move {
            if hang {
                std::future::pending::<()>().await;
            }
            outcome
        }
    }
}

struct LoopbackNetwork;

impl LocalNetworkPort for LoopbackNetwork {
    type Connector = LoopbackConnector;
    type Error = Injected;

    fn establish(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<LoopbackConnector>, Injected> {
        Ok(EstablishedNetwork::new(attempt_id, LoopbackConnector))
    }
}

/// A port whose namespace belongs to another attempt.
struct ForeignNetwork;

impl LocalNetworkPort for ForeignNetwork {
    type Connector = LoopbackConnector;
    type Error = Injected;

    fn establish(
        &self,
        _attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<LoopbackConnector>, Injected> {
        Ok(EstablishedNetwork::new(OTHER, LoopbackConnector))
    }
}

/// A port that cannot establish a namespace.
struct BrokenNetwork;

impl LocalNetworkPort for BrokenNetwork {
    type Connector = LoopbackConnector;
    type Error = Injected;

    fn establish(
        &self,
        _attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<LoopbackConnector>, Injected> {
        Err(Injected)
    }
}

/// A connector whose drop is the namespace teardown the port contract asks for.
struct TornDownConnector {
    torn_down: Arc<AtomicUsize>,
}

impl Drop for TornDownConnector {
    fn drop(&mut self) {
        self.torn_down.fetch_add(1, Ordering::SeqCst);
    }
}

impl pos_reference::sandbox_provider_protocol::NetworkEndpointConnector for TornDownConnector {
    fn connect(
        &mut self,
        _endpoint: SocketAddr,
        _timeout: Duration,
    ) -> std::io::Result<std::net::TcpStream> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

struct TornDownNetwork {
    torn_down: Arc<AtomicUsize>,
}

impl LocalNetworkPort for TornDownNetwork {
    type Connector = TornDownConnector;
    type Error = Injected;

    fn establish(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<TornDownConnector>, Injected> {
        Ok(EstablishedNetwork::new(
            attempt_id,
            TornDownConnector {
                torn_down: Arc::clone(&self.torn_down),
            },
        ))
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
                6 | 9 => 4_096,
                _ => 1_000,
            },
        })
        .collect()
}

type Outcome = Result<AttemptExecution<String, FakeCgroup>, ExecuteFailure>;

fn filter() -> TestResult<SystemCallFilter> {
    let record = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    Ok(SystemCallFilter::from_selected_record(
        X86_64,
        record.syscall_set_digest,
        SandboxArchitecture::X86_64,
    )?)
}

fn root_for(
    log: &Log,
    attempt_id: [u8; 16],
) -> impl FnOnce() -> Result<CheckedRoot, ImageActivationError> + Send + use<> {
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

fn failure<T>(result: Result<T, ExecuteFailure>) -> TestResult<ExecuteFailure> {
    result
        .err()
        .ok_or_else(|| "the execution unexpectedly succeeded".into())
}

/// The fake ports and the capture store of one execution.
struct Scenario {
    log: Log,
    host: FakeHost,
    barrier: FakeBarrier,
    store: Arc<NetworkCaptureStore>,
    _root: Option<tempfile::TempDir>,
}

impl Scenario {
    fn new() -> TestResult<Self> {
        let (root, store) = capture_store()?;
        Ok(Self::holding(&store, Some(root)))
    }

    fn sharing(store: &Arc<NetworkCaptureStore>) -> Self {
        Self::holding(store, None)
    }

    fn holding(store: &Arc<NetworkCaptureStore>, root: Option<tempfile::TempDir>) -> Self {
        let log = Log::default();
        Self {
            host: FakeHost::new(&log),
            barrier: FakeBarrier::new(&log),
            log,
            store: Arc::clone(store),
            _root: root,
        }
    }

    fn entries(&self) -> Vec<String> {
        recorded(&self.log)
    }

    fn job(
        &self,
        attempt_id: [u8; 16],
        mode: SandboxExecutionMode,
        plan: ModePlan,
        watchdog_ms: u64,
    ) -> TestResult<ExecuteJob> {
        Ok(ExecuteJob {
            attempt: AdmittedAttempt::for_test(attempt_id, authority(), mode)?,
            launcher_source: LauncherSource::new("/usr/lib/pigloros/release-launcher")?,
            system_call_filter: filter()?,
            service_limits: SystemdServiceLimits::from_effective_limits(&limits(watchdog_ms))?,
            mode: plan,
            capture_store: Arc::clone(&self.store),
        })
    }

    async fn run_on<N: LocalNetworkPort + Sync>(
        &mut self,
        network: &N,
        job: ExecuteJob,
        recheck: impl FnOnce() -> Result<CheckedRoot, ImageActivationError> + Send,
    ) -> Outcome {
        execute(&self.host, &mut self.barrier, network, job, recheck).await
    }

    async fn run_as(
        &mut self,
        attempt_id: [u8; 16],
        mode: SandboxExecutionMode,
        plan: ModePlan,
    ) -> TestResult<Outcome> {
        let job = self.job(attempt_id, mode, plan, GENEROUS_WATCHDOG_MS)?;
        let recheck = root_for(&self.log, attempt_id);
        Ok(self.run_on(&LoopbackNetwork, job, recheck).await)
    }

    async fn run(&mut self, mode: SandboxExecutionMode, plan: ModePlan) -> TestResult<Outcome> {
        self.run_as(ATTEMPT, mode, plan).await
    }

    async fn run_watched(
        &mut self,
        mode: SandboxExecutionMode,
        plan: ModePlan,
        watchdog_ms: u64,
    ) -> TestResult<Outcome> {
        let job = self.job(ATTEMPT, mode, plan, watchdog_ms)?;
        let recheck = root_for(&self.log, ATTEMPT);
        Ok(self.run_on(&LoopbackNetwork, job, recheck).await)
    }

    async fn air_gapped(&mut self) -> TestResult<Outcome> {
        self.run(SandboxExecutionMode::AirGapped, ModePlan::AirGapped)
            .await
    }

    async fn fails(&mut self) -> TestResult<ExecuteFailure> {
        let outcome = self.air_gapped().await?;
        failure(outcome)
    }

    fn cgroup_kills(&self) -> usize {
        self.host.cgroup_kills.load(Ordering::SeqCst)
    }
}

fn local_plan(address: SocketAddr) -> TestResult<(NetworkExchangePlan, ModePlan)> {
    let plan = plan()?;
    let admission = crate::test_fixtures::admission(
        ATTEMPT,
        grant_authority(),
        [4, 5, 6],
        vec![(plan.clone(), capability(address))],
    );
    let mode = ModePlan::Local {
        admission: Box::new(admission),
    };
    Ok((plan, mode))
}

const UNUSED_ENDPOINT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9);

/// A finished Local attempt with its remote and adapter observations.
struct LocalRun {
    scenario: Scenario,
    execution: AttemptExecution<String, FakeCgroup>,
    plan: NetworkExchangePlan,
    remote: thread::JoinHandle<std::io::Result<Vec<u8>>>,
}

type LocalSetup = (
    thread::JoinHandle<std::io::Result<Vec<u8>>>,
    NetworkExchangePlan,
    ModePlan,
);

fn local_setup() -> TestResult<LocalSetup> {
    let (address, remote) = remote()?;
    let (plan, mode) = local_plan(address)?;
    Ok((remote, plan, mode))
}

impl LocalRun {
    async fn start() -> TestResult<Self> {
        let (remote, plan, mode) = local_setup()?;
        let mut scenario = Scenario::new()?;
        scenario.host.adapter = AdapterScript::Exchange(plan.clone());
        let outcome = scenario.run(SandboxExecutionMode::Local, mode).await?;
        Ok(Self {
            execution: outcome?,
            scenario,
            plan,
            remote,
        })
    }

    fn remote_request(self) -> TestResult<Vec<u8>> {
        Ok(self.remote.join().map_err(|_| "remote thread")??)
    }

    fn adapter_reply(&self) -> TestResult<Option<Result<Vec<u8>, String>>> {
        let reply = self.scenario.host.adapter_reply.lock();
        Ok(reply.map_err(|error| error.to_string())?.clone())
    }
}

#[tokio::test]
async fn a_local_attempt_serves_fd3_once_released_and_reports_its_transcripts() -> TestResult {
    let run = LocalRun::start().await?;
    // The recheck sits last before the start, and nothing is served before
    // the launcher releases the adapter.
    assert_eq!(
        run.scenario.entries(),
        [
            "take_unit_end",
            "recheck",
            "start",
            "bind_cgroup",
            "release"
        ]
    );
    assert_eq!(
        run.scenario.host.observed(),
        Observed {
            root: root_path(ATTEMPT),
            descriptors: names(&[HOST_SERVICE, RELEASE]),
            families: (true, names(&["AF_UNIX"])),
            work: vec![("/work".to_owned(), WORK.to_owned())],
        }
    );
    assert_eq!(run.execution.attempt_id, ATTEMPT);
    assert_eq!(run.execution.ending, AttemptEnding::CgroupEmpty);
    assert_eq!(run.execution.network.termination(), None);
    assert_eq!(run.execution.network.transcript_digests().len(), 1);
    assert_eq!(run.adapter_reply()?, Some(Ok(RESPONSE.to_vec())));
    assert_eq!(run.remote_request()?, REQUEST.to_vec());
    Ok(())
}

#[test]
fn the_barrier_sees_the_active_attempt() -> TestResult {
    // The barrier is given the attempt's unit and a live deadline.
    let log = Log::default();
    let mut barrier = FakeBarrier::new(&log);
    let active = crate::test_fixtures::active()?;
    let released = Arc::clone(&barrier.released);
    assert_eq!(active.attempt_id(), ATTEMPT);
    let _release = barrier.release(&active);
    let seen = released.lock().map_err(|error| error.to_string())?.clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].0,
        TransientServiceUnitName::from_attempt_id(ATTEMPT)?.as_str()
    );
    assert!(seen[0].1 > Instant::now());
    Ok(())
}

#[tokio::test]
async fn a_retained_capture_replays_offline_into_a_later_attempt() -> TestResult {
    let run = LocalRun::start().await?;
    let digests = run.execution.network.transcript_digests();
    let mut replay = Scenario::sharing(&run.scenario.store);
    let replay_attempt = [0x43; 16];
    let exchanges = vec![ReplayRequest {
        attempt_id: ATTEMPT,
        plan: run.plan.clone(),
        transcript_digest: digests[0],
    }];
    let outcome = replay
        .run_as(
            replay_attempt,
            SandboxExecutionMode::Replay,
            ModePlan::Replay { exchanges },
        )
        .await?;
    let replayed = outcome?;
    assert_eq!(replayed.network.transcript_digests(), digests);
    assert_eq!(replayed.network.termination(), None);
    assert_eq!(
        replay.host.observed(),
        Observed {
            root: root_path(replay_attempt),
            descriptors: names(&[RELEASE]),
            families: (true, Vec::new()),
            work: vec![("/work".to_owned(), WORK.to_owned())],
        }
    );
    Ok(())
}

#[tokio::test]
async fn air_gapped_and_fork_attempts_get_only_the_release_descriptor() -> TestResult {
    for (mode, plan) in [
        (SandboxExecutionMode::AirGapped, ModePlan::AirGapped),
        (SandboxExecutionMode::Fork, ModePlan::Fork),
    ] {
        let mut scenario = Scenario::new()?;
        let execution = scenario.run(mode, plan).await??;
        assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
        assert!(matches!(execution.network, NetworkEvidence::None));
        assert!(execution.network.transcript_digests().is_empty());
        assert_eq!(execution.network.termination(), None);
        assert_eq!(scenario.host.observed().descriptors, names(&[RELEASE]));
        assert_eq!(scenario.host.observed().families, (true, Vec::new()));
    }
    Ok(())
}

#[tokio::test]
async fn the_unit_runs_the_launcher_in_launch_barrier_mode() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.air_gapped().await??;
    let commands = scenario
        .host
        .exec_start
        .lock()
        .map_err(|error| error.to_string())?
        .clone();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].1[1], "launch-barrier");
    Ok(())
}

#[tokio::test]
async fn nothing_starts_when_the_plan_is_not_the_admitted_mode() -> TestResult {
    let mut scenario = Scenario::new()?;
    let outcome = scenario
        .run(SandboxExecutionMode::Local, ModePlan::AirGapped)
        .await?;
    let failed = failure(outcome)?;
    assert!(matches!(failed.error, ExecuteError::ModeMismatch));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    Ok(())
}

#[tokio::test]
async fn an_unavailable_replay_capture_stops_before_the_launcher() -> TestResult {
    let mut scenario = Scenario::new()?;
    let exchanges = vec![ReplayRequest {
        attempt_id: ATTEMPT,
        plan: plan()?,
        transcript_digest: [0x77; 32],
    }];
    let outcome = scenario
        .run(SandboxExecutionMode::Replay, ModePlan::Replay { exchanges })
        .await?;
    let failed = failure(outcome)?;
    assert!(matches!(failed.error, ExecuteError::ReplayUnavailable(_)));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    Ok(())
}

#[tokio::test]
async fn the_barrier_must_hand_over_its_end_before_the_root_is_rechecked() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.barrier.fault = BarrierFault::Take;
    let failed = scenario.fails().await?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert_eq!(scenario.entries(), ["take_unit_end"]);
    Ok(())
}

#[tokio::test]
async fn an_unencodable_launch_never_reaches_the_recheck() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.barrier.fault = BarrierFault::Invocation;
    let failed = scenario.fails().await?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::NotStarted);
    Ok(())
}

async fn recheck_failure(
    recheck: impl FnOnce() -> Result<CheckedRoot, ImageActivationError> + Send,
) -> TestResult<(Scenario, ExecuteFailure)> {
    let mut scenario = Scenario::new()?;
    let job = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::AirGapped,
        ModePlan::AirGapped,
        GENEROUS_WATCHDOG_MS,
    )?;
    let outcome = scenario.run_on(&LoopbackNetwork, job, recheck).await;
    let failed = failure(outcome)?;
    Ok((scenario, failed))
}

#[tokio::test]
async fn a_failed_root_recheck_never_starts_the_unit() -> TestResult {
    let (scenario, failed) =
        recheck_failure(|| Err(ImageActivationError::EvidenceMismatch)).await?;
    assert!(matches!(
        failed.error,
        ExecuteError::Recheck(ImageActivationError::EvidenceMismatch)
    ));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(!scenario.entries().iter().any(|entry| entry == "start"));
    Ok(())
}

#[tokio::test]
async fn a_root_of_another_attempt_never_starts_the_unit() -> TestResult {
    let (scenario, failed) = recheck_failure(root_for(&Log::default(), OTHER)).await?;
    assert!(matches!(failed.error, ExecuteError::RootIdentity));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(!scenario.entries().iter().any(|entry| entry == "start"));
    Ok(())
}

/// Run an Air-Gapped attempt whose host fails with `faults`.
async fn faulted(faults: &[Fault]) -> TestResult<(Scenario, ExecuteFailure)> {
    let mut scenario = Scenario::new()?;
    scenario.host.faults.extend_from_slice(faults);
    let failed = scenario.fails().await?;
    Ok((scenario, failed))
}

#[tokio::test]
async fn a_unit_that_fails_to_start_is_killed() -> TestResult {
    let (scenario, failed) = faulted(&[Fault::Start]).await?;
    assert!(matches!(failed.error, ExecuteError::Unit(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert!(scenario.entries().ends_with(&names(&["kill", "stop"])));
    assert_eq!(scenario.cgroup_kills(), 0);
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_kill_after_a_failed_start_leaves_the_unit_unknown() -> TestResult {
    let (_scenario, failed) = faulted(&[Fault::Start, Fault::Kill]).await?;
    assert!(matches!(failed.error, ExecuteError::Unit(_)));
    assert_eq!(failed.unit, UnitState::Unknown);
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_kill_after_a_started_unit_is_reported_as_running() -> TestResult {
    let (_scenario, failed) = faulted(&[Fault::Bind, Fault::Kill]).await?;
    assert!(matches!(failed.error, ExecuteError::Cgroup(_)));
    assert_eq!(failed.unit, UnitState::KillFailed);
    Ok(())
}

#[tokio::test]
async fn a_unit_whose_cgroup_cannot_be_bound_is_killed_before_release() -> TestResult {
    let (scenario, failed) = faulted(&[Fault::Bind]).await?;
    assert!(matches!(failed.error, ExecuteError::Cgroup(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert!(!scenario.entries().iter().any(|entry| entry == "release"));
    assert_eq!(scenario.cgroup_kills(), 0);
    Ok(())
}

#[tokio::test]
async fn a_barrier_that_never_answers_is_cut_off_at_the_deadline() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.barrier.fault = BarrierFault::Hang;
    let started = Instant::now();
    let run = scenario.run_watched(SandboxExecutionMode::AirGapped, ModePlan::AirGapped, 100);
    let outcome = tokio::time::timeout(Duration::from_secs(10), run).await??;
    let failed = failure(outcome)?;
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(matches!(failed.error, ExecuteError::ReleaseTimeout));
    assert_eq!(failed.unit, UnitState::Killed);
    assert_eq!(scenario.cgroup_kills(), 1);
    Ok(())
}

/// Run an Air-Gapped attempt under a 100 ms watchdog with `faults`, optionally
/// refusing the release so that the termination calls run.
async fn timed_out(
    faults: &[Fault],
    refuse_release: bool,
) -> TestResult<(Scenario, ExecuteFailure)> {
    let mut scenario = Scenario::new()?;
    scenario.host.faults.extend_from_slice(faults);
    scenario.barrier.fault = if refuse_release {
        BarrierFault::Release
    } else {
        BarrierFault::None
    };
    let run = scenario.run_watched(SandboxExecutionMode::AirGapped, ModePlan::AirGapped, 100);
    let outcome = tokio::time::timeout(Duration::from_secs(10), run).await??;
    Ok((scenario, failure(outcome)?))
}

#[tokio::test]
async fn a_start_that_never_answers_is_cut_off_and_the_unit_killed() -> TestResult {
    let (scenario, failed) = timed_out(&[Fault::HangStart], false).await?;
    assert!(matches!(failed.error, ExecuteError::HostTimeout));
    assert_eq!(failed.unit, UnitState::Killed);
    assert!(scenario
        .entries()
        .ends_with(&names(&["start", "kill", "stop"])));
    Ok(())
}

#[tokio::test]
async fn a_cgroup_bind_that_never_answers_is_cut_off_and_the_unit_killed() -> TestResult {
    let (_scenario, failed) = timed_out(&[Fault::HangBind], false).await?;
    assert!(matches!(failed.error, ExecuteError::HostTimeout));
    assert_eq!(failed.unit, UnitState::Killed);
    Ok(())
}

#[tokio::test]
async fn a_kill_that_never_answers_is_reported_as_unacknowledged() -> TestResult {
    let started = Instant::now();
    let (_scenario, failed) = timed_out(&[Fault::HangKill], true).await?;
    assert_eq!(failed.unit, UnitState::KillFailed);
    assert!(started.elapsed() >= Duration::from_millis(100));
    Ok(())
}

#[tokio::test]
async fn a_stop_that_never_answers_does_not_hold_the_failure() -> TestResult {
    let (scenario, failed) = timed_out(&[Fault::HangStop], true).await?;
    assert_eq!(failed.unit, UnitState::Killed);
    assert!(scenario.entries().ends_with(&names(&["kill", "stop"])));
    Ok(())
}

/// Wait until `entry` is logged, for at most five seconds.
async fn logged(log: &Log, entry: &str) -> bool {
    for _ in 0..500 {
        if recorded(log).iter().any(|logged| logged == entry) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn a_dropped_execution_kills_the_submitted_unit() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.barrier.fault = BarrierFault::Hang;
    let log = Arc::clone(&scenario.log);
    let run = scenario.run(SandboxExecutionMode::AirGapped, ModePlan::AirGapped);
    // The caller gives up while the barrier is still waiting.
    assert!(tokio::time::timeout(Duration::from_millis(200), run)
        .await
        .is_err());
    assert!(logged(&log, "guard_kill").await);
    Ok(())
}

fn guard_kills(scenario: &Scenario) -> bool {
    scenario.entries().iter().any(|entry| entry == "guard_kill")
}

#[tokio::test]
async fn a_finished_execution_leaves_nothing_for_the_guard() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.air_gapped().await??;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!guard_kills(&scenario));
    Ok(())
}

#[tokio::test]
async fn a_refused_execution_leaves_nothing_for_the_guard() -> TestResult {
    let mut refused = Scenario::new()?;
    refused.barrier.fault = BarrierFault::Release;
    refused.fails().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!guard_kills(&refused));
    Ok(())
}

#[test]
fn a_guard_dropped_outside_a_runtime_spawns_nothing() -> TestResult {
    let log = Log::default();
    let mut guard = SubmissionGuard::new();
    guard.arm(
        FakeKiller {
            log: Arc::clone(&log),
        },
        TransientServiceUnitName::from_attempt_id(ATTEMPT)?,
        Duration::from_secs(1),
    );
    drop(guard);
    assert!(recorded(&log).is_empty());
    Ok(())
}

#[tokio::test]
async fn a_refused_release_kills_the_unit_and_its_cgroup() -> TestResult {
    let mut scenario = Scenario::new()?;
    scenario.barrier.fault = BarrierFault::Release;
    let failed = scenario.fails().await?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert_eq!(
        scenario.entries(),
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
    assert_eq!(scenario.cgroup_kills(), 1);
    Ok(())
}

/// Run a Local attempt whose admission names `admission_attempt`, on `network`.
async fn local_failure<N: LocalNetworkPort + Sync>(
    network: &N,
    admission_attempt: [u8; 16],
) -> TestResult<(Scenario, ExecuteFailure)> {
    let plan = plan()?;
    let admission = crate::test_fixtures::admission(
        admission_attempt,
        grant_authority(),
        [4, 5, 6],
        vec![(plan, capability(UNUSED_ENDPOINT))],
    );
    let mode = ModePlan::Local {
        admission: Box::new(admission),
    };
    let mut scenario = Scenario::new()?;
    let job = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::Local,
        mode,
        GENEROUS_WATCHDOG_MS,
    )?;
    let recheck = root_for(&scenario.log, ATTEMPT);
    let outcome = scenario.run_on(network, job, recheck).await;
    Ok((scenario, failure(outcome)?))
}

#[tokio::test]
async fn an_admission_of_another_attempt_never_submits_a_unit() -> TestResult {
    let (scenario, failed) = local_failure(&LoopbackNetwork, OTHER).await?;
    assert!(matches!(
        failed.error,
        ExecuteError::Bind(LocalProxyBindError::Attempt)
    ));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_namespace_of_another_attempt_never_submits_a_unit() -> TestResult {
    let (scenario, failed) = local_failure(&ForeignNetwork, ATTEMPT).await?;
    assert!(matches!(
        failed.error,
        ExecuteError::Bind(LocalProxyBindError::Namespace)
    ));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_network_that_cannot_be_established_never_submits_a_unit() -> TestResult {
    let (scenario, failed) = local_failure(&BrokenNetwork, ATTEMPT).await?;
    assert!(matches!(failed.error, ExecuteError::Network(_)));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    Ok(())
}

/// Run a Local attempt on a network that counts its teardowns, with `fault`
/// injected into the barrier, and return how many namespaces were torn down.
async fn teardowns(
    configure: impl FnOnce(&mut Scenario),
    network_attempt: [u8; 16],
) -> TestResult<(usize, ExecuteFailure)> {
    let torn_down = Arc::new(AtomicUsize::new(0));
    let network = TornDownNetwork {
        torn_down: Arc::clone(&torn_down),
    };
    let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
    let mut scenario = Scenario::new()?;
    configure(&mut scenario);
    let job = scenario.job(
        network_attempt,
        SandboxExecutionMode::Local,
        mode,
        GENEROUS_WATCHDOG_MS,
    )?;
    let recheck = root_for(&scenario.log, ATTEMPT);
    let outcome = scenario.run_on(&network, job, recheck).await;
    Ok((torn_down.load(Ordering::SeqCst), failure(outcome)?))
}

#[tokio::test]
async fn the_namespace_is_torn_down_when_the_unit_end_cannot_be_taken() -> TestResult {
    let (torn_down, failed) = teardowns(
        |scenario| scenario.barrier.fault = BarrierFault::Take,
        ATTEMPT,
    )
    .await?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert_eq!(torn_down, 1);
    Ok(())
}

#[tokio::test]
async fn the_namespace_is_torn_down_when_the_recheck_fails() -> TestResult {
    let torn_down = Arc::new(AtomicUsize::new(0));
    let network = TornDownNetwork {
        torn_down: Arc::clone(&torn_down),
    };
    let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
    let mut scenario = Scenario::new()?;
    let job = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::Local,
        mode,
        GENEROUS_WATCHDOG_MS,
    )?;
    let outcome = scenario
        .run_on(&network, job, || {
            Err(ImageActivationError::EvidenceMismatch)
        })
        .await;
    assert!(matches!(
        failure(outcome)?.error,
        ExecuteError::Recheck(ImageActivationError::EvidenceMismatch)
    ));
    assert_eq!(torn_down.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn the_namespace_is_torn_down_when_the_release_is_refused() -> TestResult {
    let (torn_down, failed) = teardowns(
        |scenario| scenario.barrier.fault = BarrierFault::Release,
        ATTEMPT,
    )
    .await?;
    assert!(matches!(failed.error, ExecuteError::Barrier(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert_eq!(torn_down, 1);
    Ok(())
}

#[tokio::test]
async fn an_unreadable_cgroup_terminates_the_unit() -> TestResult {
    let (scenario, failed) = faulted(&[Fault::ReadCgroup]).await?;
    assert!(matches!(failed.error, ExecuteError::Cgroup(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert!(scenario
        .entries()
        .ends_with(&names(&["release", "kill", "stop"])));
    Ok(())
}

/// Run an Air-Gapped attempt whose cgroup never empties, under `faults`.
async fn expired(faults: &[Fault]) -> TestResult<(Scenario, AttemptExecution<String, FakeCgroup>)> {
    let mut scenario = Scenario::new()?;
    scenario.host.empty_after = usize::MAX;
    scenario.host.faults.extend_from_slice(faults);
    // A watchdog that does not fire would wait forever: bound the wait.
    let run = scenario.run_watched(SandboxExecutionMode::AirGapped, ModePlan::AirGapped, 100);
    let outcome = tokio::time::timeout(Duration::from_secs(10), run).await??;
    Ok((scenario, outcome?))
}

#[tokio::test]
async fn the_watchdog_kills_an_attempt_that_never_empties() -> TestResult {
    let started = Instant::now();
    let (scenario, execution) = expired(&[]).await?;
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(execution.ending, AttemptEnding::WatchdogKilled);
    assert!(scenario
        .entries()
        .ends_with(&names(&["release", "kill", "stop"])));
    assert_eq!(scenario.cgroup_kills(), 1);
    Ok(())
}

#[tokio::test]
async fn a_failed_cgroup_kill_does_not_change_the_watchdog_outcome() -> TestResult {
    let (scenario, execution) = expired(&[Fault::KillCgroup]).await?;
    assert_eq!(execution.ending, AttemptEnding::WatchdogKilled);
    assert_eq!(scenario.cgroup_kills(), 1);
    Ok(())
}

#[tokio::test]
async fn an_unacknowledged_kill_is_reported_not_hidden() -> TestResult {
    let (_scenario, execution) = expired(&[Fault::Kill]).await?;
    assert_eq!(execution.ending, AttemptEnding::WatchdogKillFailed);
    Ok(())
}

#[tokio::test]
async fn the_watchdog_closes_a_silent_fd3_and_kills_the_unit() -> TestResult {
    let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
    let mut scenario = Scenario::new()?;
    scenario.host.adapter = AdapterScript::Silent;
    let execution = scenario
        .run_watched(SandboxExecutionMode::Local, mode, 150)
        .await??;
    assert_eq!(execution.ending, AttemptEnding::WatchdogKilled);
    assert!(matches!(
        &execution.network,
        NetworkEvidence::Local(served) if served.watchdog_expired
    ));
    assert!(execution.network.transcript_digests().is_empty());
    assert!(scenario
        .entries()
        .ends_with(&names(&["release", "kill", "stop"])));
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
    type Error = Injected;

    fn establish(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<PanickingConnector>, Injected> {
        Ok(EstablishedNetwork::new(attempt_id, PanickingConnector))
    }
}

#[tokio::test]
async fn a_protocol_violation_on_fd3_is_reported_for_classification() -> TestResult {
    let (_, mode) = local_plan(UNUSED_ENDPOINT)?;
    let mut scenario = Scenario::new()?;
    scenario.host.adapter = AdapterScript::ProtocolViolation;
    let execution = scenario.run(SandboxExecutionMode::Local, mode).await??;
    assert_eq!(execution.ending, AttemptEnding::CgroupEmpty);
    assert_eq!(
        execution.network.termination(),
        Some(LocalNetworkTermination::ProtocolFailure)
    );
    assert!(execution.network.transcript_digests().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_failed_proxy_task_terminates_the_unit() -> TestResult {
    let (plan, mode) = local_plan(UNUSED_ENDPOINT)?;
    let mut scenario = Scenario::new()?;
    scenario.host.adapter = AdapterScript::Exchange(plan);
    let job = scenario.job(
        ATTEMPT,
        SandboxExecutionMode::Local,
        mode,
        GENEROUS_WATCHDOG_MS,
    )?;
    let recheck = root_for(&scenario.log, ATTEMPT);
    let outcome = scenario.run_on(&PanickingNetwork, job, recheck).await;
    let failed = failure(outcome)?;
    assert!(matches!(failed.error, ExecuteError::Serve(_)));
    assert_eq!(failed.unit, UnitState::Killed);
    assert_eq!(scenario.cgroup_kills(), 1);
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
