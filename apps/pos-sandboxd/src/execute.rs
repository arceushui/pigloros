//! The bounded provider execute path (ADR-069 sections 4, 6 and 7, #441).
//!
//! [`execute`] composes one reserved, admitted attempt from its rechecked
//! root to its end:
//!
//! 1. the admitted execution mode must be the planned one; Replay resolves
//!    every captured exchange first, and Local creates the FD 3 socket pair
//!    and establishes its namespace;
//! 2. the verified root is rechecked and becomes the only `RootDirectory`;
//! 3. the typed transient unit is started and its requested state verified,
//!    including the exact `/work` mount and the descriptor layout;
//! 4. the unit's cgroup is bound, the attempt is recorded as active, and a
//!    Local admission is bound to it;
//! 5. the launcher barrier releases the adapter, exactly once;
//! 6. a Local proxy serves FD 3 until the channel ends or the attempt
//!    watchdog closes it, and the cgroup is observed until it is empty or the
//!    watchdog expires, which kills the unit.
//!
//! Any failure after the unit was started terminates it. The result carries
//! the evidence the later signed records need: the ordered NXT1 transcript
//! digests for SPR1 and the proxy termination for the SAU1 terminal
//! classification (#443 signs and classifies). Unmounting the root, removing
//! the attempt directory and releasing the reservation stay with the attempt
//! lifecycle (#442).
//!
//! The unit host, the launcher barrier and the Local network are ports, so the
//! composition is exercised without systemd, a launcher or a namespace.

use std::error::Error;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_reference::sandbox_provider_protocol::{
    LocalNetworkAdmission, LocalNetworkTermination, NetworkCaptureStore, NetworkCaptureStoreError,
    NetworkEndpointConnector, NetworkExchangePlan, NetworkExchangeTranscript,
    ReplayedNetworkExchange, SandboxExecutionMode,
};
use zbus::OwnedFd;

use crate::{
    ActivatedRootDirectory, ActiveAttempt, AdmittedAttempt, BoundLocalProxy, CheckedLocal,
    CheckedRoot, HostServiceChannel, ImageActivationError, LaunchMode, LauncherInvocation,
    LauncherSource, LocalNetworkPort, LocalProxyBindError, ServeError, ServedProxy,
    SystemCallFilter, SystemdServiceLimits, TransientServiceUnitName, TransientUnitLaunchInputs,
    TransientUnitRequest,
};

/// The least time a terminating host call is given, however short the
/// attempt's watchdog.
const MIN_TERMINATION_CALL: Duration = Duration::from_secs(1);

/// The most time a terminating host call is given, however long the attempt's
/// watchdog. An abort is two such calls at worst.
const MAX_TERMINATION_CALL: Duration = Duration::from_secs(10);

/// How often the attempt cgroup is polled for emptiness.
const EMPTY_POLL: Duration = Duration::from_millis(10);

/// The systemd operations the execute path needs, behind one port.
///
/// The production implementation is the typed D-Bus transport.
pub trait UnitHost {
    /// The verified start, with its requested-state readback.
    type Started: Send + Sync;
    /// The retained handle on the attempt cgroup.
    type Cgroup: UnitCgroup + Send;
    /// The host's failure type.
    type Error: Error + Send + Sync + 'static;
    /// An owned, `'static` handle that can kill a unit after the execute
    /// future was dropped.
    type Killer: UnitKiller;

    /// A handle for `SubmissionGuard`'s best-effort kill.
    fn killer(&self) -> Self::Killer;

    /// Submit the compiled request and verify its requested state.
    fn start(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
    ) -> impl Future<Output = Result<Self::Started, Self::Error>> + Send;

    /// Bind the started unit to its kernel cgroup.
    fn bind_cgroup(
        &self,
        started: &Self::Started,
    ) -> impl Future<Output = Result<Self::Cgroup, Self::Error>> + Send;

    /// Stop the unit, replacing a queued start job.
    fn stop(
        &self,
        unit_name: TransientServiceUnitName,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Send SIGKILL to every process of the unit.
    fn kill(
        &self,
        unit_name: TransientServiceUnitName,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A `'static` handle that kills one unit, used when an execution is dropped.
pub trait UnitKiller: Send + 'static {
    /// Best-effort SIGKILL and stop of `unit_name`; failures are not reported
    /// because nothing is left to report them to.
    fn kill(self, unit_name: TransientServiceUnitName) -> impl Future<Output = ()> + Send;
}

/// The attempt cgroup operations the execute path needs.
pub trait UnitCgroup {
    /// The cgroup's failure type.
    type Error: Error + Send + Sync + 'static;

    /// Whether no process remains in the attempt cgroup.
    ///
    /// # Errors
    /// Fails if the cgroup cannot be read.
    fn is_empty(&mut self) -> Result<bool, Self::Error>;

    /// Kill every process of the attempt cgroup.
    ///
    /// # Errors
    /// Fails if the kill cannot be issued.
    fn kill_all(&mut self) -> Result<(), Self::Error>;
}

/// The launcher barrier of ADR-069 section 6, behind one port.
///
/// The implementation owns the release channel, the single-use nonce and the
/// signed `ReleaseV1`.
pub trait LaunchBarrier {
    /// The barrier's failure type.
    type Error: Error + Send + Sync + 'static;

    /// The launcher-mode command for this launch: the exact LPV1 parameters the
    /// unit's `ExecStart=` passes to the launcher.
    ///
    /// # Errors
    /// Fails if the parameters cannot be encoded.
    fn launcher_invocation(&self) -> Result<LauncherInvocation, Self::Error>;

    /// Hand over, once, the unit's end of the release channel, which becomes
    /// `piglor-release-v1`.
    ///
    /// # Errors
    /// Fails if the channel is unavailable or was already handed over.
    fn take_unit_end(&mut self) -> Result<OwnedFd, Self::Error>;

    /// Await `ReadyV1`, recheck every binding, and send exactly one
    /// `ReleaseV1`, all before the attempt's deadline.
    ///
    /// # Errors
    /// Fails, releasing nothing, if the launcher is not ready in time, any
    /// binding differs, or the release cannot be sent.
    fn release(
        &mut self,
        attempt: &ActiveAttempt,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// One exchange to resolve from the capture store for a Replay attempt.
///
/// The authorized report supplies the capturing attempt, the exact plan and
/// the NXT1 digest it recorded; retained bytes never choose their own lookup.
#[derive(Clone, Debug)]
pub struct ReplayRequest {
    /// The attempt that captured the exchange.
    pub attempt_id: [u8; 16],
    /// The exact NXP1 plan of the occurrence.
    pub plan: NetworkExchangePlan,
    /// The NXT1 transcript digest the report recorded.
    pub transcript_digest: [u8; 32],
}

/// The planned network behaviour of an attempt; one variant per ADR-069 mode.
#[derive(Debug)]
pub enum ModePlan {
    /// Bounded Local exchanges through the FD 3 proxy.
    Local {
        /// The admission of the exact endpoints and plans.
        admission: Box<LocalNetworkAdmission>,
    },
    /// No network authority and no live descriptor.
    AirGapped,
    /// Offline Replay of captured exchanges, resolved before launch.
    Replay {
        /// The exchanges to resolve, in plan order.
        exchanges: Vec<ReplayRequest>,
    },
    /// Deterministic Fork: no network authority and no live descriptor.
    Fork,
}

impl ModePlan {
    const fn execution_mode(&self) -> SandboxExecutionMode {
        match self {
            Self::Local { .. } => SandboxExecutionMode::Local,
            Self::AirGapped => SandboxExecutionMode::AirGapped,
            Self::Replay { .. } => SandboxExecutionMode::Replay,
            Self::Fork => SandboxExecutionMode::Fork,
        }
    }
}

/// Everything one execution needs beyond the ports.
pub struct ExecuteJob {
    /// The facts of the reserved, admitted attempt.
    pub attempt: AdmittedAttempt,
    /// The admitted launcher binary to bind into the root.
    pub launcher_source: LauncherSource,
    /// The selected, digest-bound syscall filter.
    pub system_call_filter: SystemCallFilter,
    /// The effective ELM1 limits systemd enforces.
    pub service_limits: SystemdServiceLimits,
    /// The planned network behaviour; it must match the admitted mode.
    pub mode: ModePlan,
    /// The durable capture store, opened over a root-owned directory.
    pub capture_store: Arc<NetworkCaptureStore>,
}

/// Why an execution could not start or continue.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// The directory was prepared for another attempt or SIM1.
    #[error("the attempt directory belongs to another attempt")]
    DirectoryIdentity,
    /// The planned mode is not the admitted launch policy's mode.
    #[error("the planned mode differs from the admitted launch policy")]
    ModeMismatch,
    /// A Replay exchange is missing or does not match its authority.
    #[error("a replayed exchange is unavailable")]
    ReplayUnavailable(#[source] NetworkCaptureStoreError),
    /// The Local network could not be established.
    #[error("the Local network could not be established")]
    Network(#[source] Box<dyn Error + Send + Sync>),
    /// A systemd operation did not finish within its bound.
    #[error("a systemd operation did not finish within its bound")]
    HostTimeout,
    /// The FD 3 socket pair could not be created.
    #[error("the host-service channel could not be created")]
    HostService(#[source] io::Error),
    /// The launcher barrier failed.
    #[error("the launcher barrier failed")]
    Barrier(#[source] Box<dyn Error + Send + Sync>),
    /// The barrier did not release the adapter before the attempt deadline.
    #[error("the launcher barrier did not release before the attempt deadline")]
    ReleaseTimeout,
    /// The verified root could not be rechecked.
    #[error("the verified root could not be rechecked")]
    Recheck(#[source] ImageActivationError),
    /// The rechecked root is not this attempt's root.
    #[error("the rechecked root belongs to another attempt")]
    RootIdentity,
    /// A systemd unit operation failed.
    #[error("a systemd unit operation failed")]
    Unit(#[source] Box<dyn Error + Send + Sync>),
    /// The attempt cgroup could not be observed.
    #[error("the attempt cgroup could not be observed")]
    Cgroup(#[source] Box<dyn Error + Send + Sync>),
    /// The Local admission could not be bound to the active attempt.
    #[error(transparent)]
    Bind(#[from] LocalProxyBindError),
    /// The Local proxy could not be served.
    #[error(transparent)]
    Serve(#[from] ServeError),
}

/// What is known of the unit when an execution failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitState {
    /// No unit was submitted.
    NotStarted,
    /// The unit was started or submitted, and SIGKILL was acknowledged for it.
    ///
    /// This is a command acknowledgement, not proof that the cgroup is empty.
    Killed,
    /// The unit was started and could not be killed; it may still run and the
    /// lifecycle must reconcile it.
    KillFailed,
    /// The start did not complete and the kill was not acknowledged. The unit
    /// may or may not exist, so it is neither known to run nor known absent;
    /// the lifecycle (#442) must inventory it.
    Unknown,
}

/// A failed execution and the state of its unit.
#[derive(Debug, thiserror::Error)]
#[error("execution failed with the unit {unit:?}")]
pub struct ExecuteFailure {
    /// Why the execution failed.
    #[source]
    pub error: ExecuteError,
    /// What is known of the unit.
    pub unit: UnitState,
}

/// How a released attempt ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptEnding {
    /// The attempt cgroup was observed empty before the watchdog expired.
    CgroupEmpty,
    /// The watchdog expired; the unit was killed (acknowledged, not proven).
    WatchdogKilled,
    /// The watchdog expired and the kill could not be issued.
    WatchdogKillFailed,
    /// The Local proxy session ended in a protocol failure; the unit was
    /// killed (acknowledged, not proven) and the evidence kept for the
    /// classifier (#443).
    ProtocolFailureKilled,
    /// The proxy session ended in a protocol failure and the kill could not be
    /// issued.
    ProtocolFailureKillFailed,
}

/// The network evidence of one attempt, for SPR1 and SAU1.
#[derive(Debug)]
pub enum NetworkEvidence {
    /// No network authority was granted (Air-Gapped and Fork).
    None,
    /// The Local proxy session and whether the watchdog closed the channel.
    Local(ServedProxy),
    /// The captured exchanges resolved for Replay.
    Replay(Vec<ReplayedNetworkExchange>),
}

impl NetworkEvidence {
    /// The ordered NXT1 digests for the SPR1 network transcript field.
    #[must_use]
    pub fn transcript_digests(&self) -> Vec<[u8; 32]> {
        match self {
            Self::None => Vec::new(),
            Self::Local(served) => served
                .session
                .transcripts()
                .iter()
                .map(NetworkExchangeTranscript::digest)
                .collect(),
            Self::Replay(replayed) => replayed
                .iter()
                .map(|exchange| exchange.transcript().digest())
                .collect(),
        }
    }

    /// How the Local proxy session ended, for attempt classification.
    ///
    /// `None` means no Local session, or a clean close at a frame boundary.
    /// A watchdog that closed the channel also reads as a clean close here:
    /// the classifier (#443) must consult [`ServedProxy::watchdog_expired`] as
    /// well. A protocol failure leaves the unit running until it empties or the
    /// watchdog fires; classifying it is #443's, not an early kill.
    #[must_use]
    pub const fn termination(&self) -> Option<LocalNetworkTermination> {
        match self {
            Self::Local(served) => served.session.termination(),
            Self::None | Self::Replay(_) => None,
        }
    }
}

/// A completed execution.
#[derive(Debug)]
pub struct AttemptExecution<S, C> {
    /// The attempt identity.
    pub attempt_id: [u8; 16],
    /// The verified start and its requested-state readback.
    pub started: S,
    /// The retained attempt cgroup, for limit events and emptiness proof.
    pub cgroup: C,
    /// How the attempt ended.
    pub ending: AttemptEnding,
    /// The network evidence.
    pub network: NetworkEvidence,
}

/// The network behaviour prepared before the unit starts.
enum Planned<C> {
    None,
    Local(Box<CheckedLocal<C>>),
    Replay(Vec<ReplayedNetworkExchange>),
}

/// The network behaviour once the active attempt it belongs to is recorded.
enum Bound<C> {
    None,
    Local(Box<BoundLocalProxy>, C),
    Replay(Vec<ReplayedNetworkExchange>),
}

struct Prepared<C> {
    attempt: AdmittedAttempt,
    request: TransientUnitRequest,
    planned: Planned<C>,
    watchdog: Duration,
    store: Arc<NetworkCaptureStore>,
}

/// Run one reserved, admitted attempt from its rechecked root to its end.
///
/// `recheck` rechecks, immediately before the unit starts, current authority
/// and the attached root (ADR-087 section 2 step 7) and returns the only
/// `RootDirectory` a unit may use. Production passes
/// `|| root.recheck(&directory, &entry)` with the same entry and directory
/// that built the job's [`AdmittedAttempt`]; the rechecked root must name that
/// attempt's own root, so a root of another attempt is refused. The recheck
/// consumes nothing and does not detach the mount when it fails, and neither
/// does this function: the caller owns the `VerifiedRootMount`, and the
/// attempt lifecycle (#442) detaches or drops it on every terminal path.
///
/// `recheck` blocks: it mounts, reads and verifies. The production barrier
/// wraps its own recheck for the multi-thread runtime (owner decision on `block_in_place`, #441); a caller that
/// passes a slow closure here stalls one worker until it returns.
///
/// After a watchdog expiry the unit is killed once the Local proxy thread has
/// joined, which a slow connector can delay up to the proxy's own network
/// deadline; `RuntimeMaxUSec` is the backstop. If observing the cgroup fails
/// after a Local session, the failure is returned without the session's
/// transcripts.
///
/// The runtime must have its time driver enabled.
///
/// Dropping the returned future after the unit was submitted spawns a
/// best-effort kill and stop of that unit on the current runtime, bounded like
/// any other termination, so cancellation does not leave a released-looking
/// unit running. A drop outside a runtime cannot spawn it; the lifecycle
/// (#442) reconciles any unit left behind.
///
/// # Errors
/// An [`ExecuteFailure`] names the error and what is known of the unit. Any
/// failure after the unit was submitted kills it.
pub async fn execute<H, B, N>(
    host: &H,
    barrier: &mut B,
    network: &N,
    job: ExecuteJob,
    recheck: impl FnOnce() -> Result<CheckedRoot, ImageActivationError> + Send,
) -> Result<AttemptExecution<H::Started, H::Cgroup>, ExecuteFailure>
where
    H: UnitHost + Sync,
    B: LaunchBarrier + Send,
    N: LocalNetworkPort + Sync,
{
    let mut guard = SubmissionGuard::new();
    let result = drive(host, barrier, network, job, recheck, &mut guard).await;
    guard.disarm();
    result
}

/// The wall-clock bounds of one attempt: the unit's watchdog deadline for the
/// steps before and during the run, and a fixed bound (the watchdog clamped to
/// [`MIN_TERMINATION_CALL`] and [`MAX_TERMINATION_CALL`]) for each
/// termination call, which must still run after the deadline passed.
#[derive(Clone, Copy)]
struct Bounds {
    deadline: Instant,
    call: Duration,
}

/// Whether the unit is known to exist when an execution is aborted.
#[derive(Clone, Copy)]
enum Submission {
    /// The start completed.
    Confirmed,
    /// The start failed or timed out; the unit may or may not exist.
    Unconfirmed,
}

async fn drive<H, B, N>(
    host: &H,
    barrier: &mut B,
    network: &N,
    job: ExecuteJob,
    recheck: impl FnOnce() -> Result<CheckedRoot, ImageActivationError> + Send,
    guard: &mut SubmissionGuard<H::Killer>,
) -> Result<AttemptExecution<H::Started, H::Cgroup>, ExecuteFailure>
where
    H: UnitHost + Sync,
    B: LaunchBarrier + Send,
    N: LocalNetworkPort + Sync,
{
    let prepared = prepare(barrier, network, job, recheck).map_err(|error| ExecuteFailure {
        error,
        unit: UnitState::NotStarted,
    })?;
    let Prepared {
        attempt,
        request,
        planned,
        watchdog,
        store,
    } = prepared;
    let unit = attempt.unit_name().clone();
    let bounds = Bounds {
        deadline: Instant::now() + watchdog,
        call: watchdog.clamp(MIN_TERMINATION_CALL, MAX_TERMINATION_CALL),
    };
    let deadline = bounds.deadline;
    guard.arm(host.killer(), unit.clone(), bounds.call);
    let (started, mut cgroup) = submit(host, &unit, request, bounds).await?;
    let attempt_id = attempt.attempt_id();
    let active = ActiveAttempt::record(attempt, deadline);
    let bound = bind_planned(planned);
    // Release must arrive before the attempt deadline (ADR-069), whatever the
    // port does.
    let refused = match until(deadline, barrier.release(&active)).await {
        Some(Ok(())) => None,
        Some(Err(error)) => Some(ExecuteError::Barrier(Box::new(error))),
        None => Some(ExecuteError::ReleaseTimeout),
    };
    if let Some(error) = refused {
        let aborted = abort(
            host,
            &unit,
            Some(&mut cgroup),
            error,
            Submission::Confirmed,
            bounds,
        );
        return Err(aborted.await);
    }
    let supervised = supervise(host, &unit, &mut cgroup, bound, store, bounds).await;
    let (network, finish) = match supervised {
        Ok(supervised) => supervised,
        Err(error) => {
            let aborted = abort(
                host,
                &unit,
                Some(&mut cgroup),
                error,
                Submission::Confirmed,
                bounds,
            );
            return Err(aborted.await);
        }
    };
    let ending = finish.ending();
    Ok(AttemptExecution {
        attempt_id,
        started,
        cgroup,
        ending,
        network,
    })
}

/// Submit the unit and bind its cgroup, both before the attempt deadline. A
/// failure of either kills the unit.
async fn submit<H>(
    host: &H,
    unit: &TransientServiceUnitName,
    request: TransientUnitRequest,
    bounds: Bounds,
) -> Result<(H::Started, H::Cgroup), ExecuteFailure>
where
    H: UnitHost + Sync,
{
    let started = match until(bounds.deadline, host.start(unit.clone(), request)).await {
        Some(Ok(started)) => started,
        Some(Err(error)) => {
            let error = ExecuteError::Unit(Box::new(error));
            return Err(abort(host, unit, None, error, Submission::Unconfirmed, bounds).await);
        }
        None => {
            let error = ExecuteError::HostTimeout;
            return Err(abort(host, unit, None, error, Submission::Unconfirmed, bounds).await);
        }
    };
    let bound = until(bounds.deadline, host.bind_cgroup(&started)).await;
    match bound {
        Some(Ok(cgroup)) => Ok((started, cgroup)),
        Some(Err(error)) => {
            let error = ExecuteError::Cgroup(Box::new(error));
            Err(abort(host, unit, None, error, Submission::Confirmed, bounds).await)
        }
        None => {
            let error = ExecuteError::HostTimeout;
            Err(abort(host, unit, None, error, Submission::Confirmed, bounds).await)
        }
    }
}

/// Await `future` until `deadline`; `None` if it did not finish by then.
async fn until<T>(deadline: Instant, future: impl Future<Output = T>) -> Option<T> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .ok()
}

/// Await `future` for at most `limit`; `None` if it did not finish in time.
async fn within<T>(limit: Duration, future: impl Future<Output = T>) -> Option<T> {
    tokio::time::timeout(limit, future).await.ok()
}

/// Kills a submitted unit when an execution is dropped before it finished.
///
/// It is armed just before the unit is submitted and disarmed when the
/// execution returns, so only a dropped (cancelled) execution fires it.
struct SubmissionGuard<K: UnitKiller> {
    pending: Option<(K, TransientServiceUnitName, Duration)>,
}

impl<K: UnitKiller> SubmissionGuard<K> {
    const fn new() -> Self {
        Self { pending: None }
    }

    fn arm(&mut self, killer: K, unit: TransientServiceUnitName, bound: Duration) {
        self.pending = Some((killer, unit, bound));
    }

    fn disarm(&mut self) {
        self.pending = None;
    }
}

impl<K: UnitKiller> Drop for SubmissionGuard<K> {
    fn drop(&mut self) {
        if let (Some((killer, unit, bound)), Ok(runtime)) =
            (self.pending.take(), tokio::runtime::Handle::try_current())
        {
            runtime.spawn(async move {
                within(bound, killer.kill(unit)).await;
            });
        }
    }
}

fn prepare<B, N>(
    barrier: &mut B,
    network: &N,
    job: ExecuteJob,
    recheck: impl FnOnce() -> Result<CheckedRoot, ImageActivationError>,
) -> Result<Prepared<N::Connector>, ExecuteError>
where
    B: LaunchBarrier,
    N: LocalNetworkPort,
{
    let ExecuteJob {
        attempt,
        launcher_source,
        system_call_filter,
        service_limits,
        mode,
        capture_store,
    } = job;
    if mode.execution_mode() != attempt.mode() {
        return Err(ExecuteError::ModeMismatch);
    }
    let (launch_mode, planned) = match mode {
        ModePlan::Local { admission } => {
            let (adapter_end, channel) = HostServiceChannel::pair(attempt.attempt_id())
                .map_err(ExecuteError::HostService)?;
            let established = network
                .establish(attempt.attempt_id())
                .map_err(|error| ExecuteError::Network(Box::new(error)))?;
            // A bad admission, namespace or channel never reaches the start.
            let checked = attempt.check_local(*admission, established, channel)?;
            (
                LaunchMode::Local {
                    host_service: adapter_end,
                },
                Planned::Local(Box::new(checked)),
            )
        }
        ModePlan::AirGapped => (LaunchMode::AirGapped, Planned::None),
        ModePlan::Fork => (LaunchMode::Fork, Planned::None),
        ModePlan::Replay { exchanges } => (
            LaunchMode::Replay,
            Planned::Replay(resolve_replay(&capture_store, &exchanges)?),
        ),
    };
    let release = barrier
        .take_unit_end()
        .map_err(|error| ExecuteError::Barrier(Box::new(error)))?;
    let invocation = barrier
        .launcher_invocation()
        .map_err(|error| ExecuteError::Barrier(Box::new(error)))?;
    // The recheck comes last, so nothing but compilation separates it from
    // the start of the unit.
    let checked = recheck().map_err(ExecuteError::Recheck)?;
    if checked.root_directory()
        != &ActivatedRootDirectory::for_attempt(attempt.unit_name().attempt_component())
    {
        return Err(ExecuteError::RootIdentity);
    }
    let inputs =
        TransientUnitLaunchInputs::new(checked, launcher_source, launch_mode, release, invocation);
    Ok(Prepared {
        request: TransientUnitRequest::compile(inputs, system_call_filter, &service_limits),
        watchdog: service_limits.watchdog(),
        attempt,
        planned,
        store: capture_store,
    })
}

fn resolve_replay(
    store: &NetworkCaptureStore,
    exchanges: &[ReplayRequest],
) -> Result<Vec<ReplayedNetworkExchange>, ExecuteError> {
    exchanges
        .iter()
        .map(|request| store.replay(request.attempt_id, &request.plan, request.transcript_digest))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ExecuteError::ReplayUnavailable)
}

fn bind_planned<C>(planned: Planned<C>) -> Bound<C> {
    match planned {
        Planned::None => Bound::None,
        Planned::Replay(replayed) => Bound::Replay(replayed),
        Planned::Local(checked) => {
            let (binding, connector) = checked.bind();
            Bound::Local(Box::new(binding), connector)
        }
    }
}

/// How the supervision of a released attempt ended.
#[derive(Clone, Copy)]
enum Finish {
    /// The cgroup was observed empty before the watchdog expired.
    Empty,
    /// The watchdog expired; `killed` is whether SIGKILL was acknowledged.
    Watchdog { killed: bool },
    /// The proxy session ended in a protocol failure and the unit was killed.
    ProtocolFailure { killed: bool },
}

impl Finish {
    const fn ending(self) -> AttemptEnding {
        match self {
            Self::Empty => AttemptEnding::CgroupEmpty,
            Self::Watchdog { killed: true } => AttemptEnding::WatchdogKilled,
            Self::Watchdog { killed: false } => AttemptEnding::WatchdogKillFailed,
            Self::ProtocolFailure { killed: true } => AttemptEnding::ProtocolFailureKilled,
            Self::ProtocolFailure { killed: false } => AttemptEnding::ProtocolFailureKillFailed,
        }
    }
}

/// Serve the Local proxy, if any, then observe the cgroup until it is empty or
/// the watchdog expires. A watchdog expiry or a proxy protocol failure kills
/// the unit; the network evidence is kept either way.
async fn supervise<H, C>(
    host: &H,
    unit: &TransientServiceUnitName,
    cgroup: &mut H::Cgroup,
    bound: Bound<C>,
    store: Arc<NetworkCaptureStore>,
    bounds: Bounds,
) -> Result<(NetworkEvidence, Finish), ExecuteError>
where
    H: UnitHost + Sync,
    C: NetworkEndpointConnector + Send + 'static,
{
    let evidence = match bound {
        Bound::None => NetworkEvidence::None,
        Bound::Replay(replayed) => NetworkEvidence::Replay(replayed),
        Bound::Local(binding, connector) => {
            return serve_local(host, unit, cgroup, (*binding, connector), store, bounds).await;
        }
    };
    let finish = observe(host, unit, cgroup, bounds).await?;
    Ok((evidence, finish))
}

/// Serve the Local proxy. At the watchdog the unit is killed while the proxy
/// thread is still being joined, so a slow connector cannot delay the kill.
async fn serve_local<H, C>(
    host: &H,
    unit: &TransientServiceUnitName,
    cgroup: &mut H::Cgroup,
    (binding, connector): (BoundLocalProxy, C),
    store: Arc<NetworkCaptureStore>,
    bounds: Bounds,
) -> Result<(NetworkEvidence, Finish), ExecuteError>
where
    H: UnitHost + Sync,
    C: NetworkEndpointConnector + Send + 'static,
{
    let (served, expired) = binding
        .serve_until_or(
            connector,
            store,
            bounds.deadline,
            kill_unit(host, unit, bounds.call),
        )
        .await;
    let served = served.map_err(ExecuteError::from)?;
    let protocol_failure =
        served.session.termination() == Some(LocalNetworkTermination::ProtocolFailure);
    let finish = match expired {
        Some(killed) => {
            // The unit kill ran during the join; this is the belt and braces.
            cgroup.kill_all().ok();
            Finish::Watchdog { killed }
        }
        None if protocol_failure => Finish::ProtocolFailure {
            killed: kill_everything(host, unit, Some(cgroup), bounds.call).await,
        },
        None => observe(host, unit, cgroup, bounds).await?,
    };
    Ok((NetworkEvidence::Local(served), finish))
}

/// Observe the cgroup until it is empty; kill the unit at the watchdog.
async fn observe<H>(
    host: &H,
    unit: &TransientServiceUnitName,
    cgroup: &mut H::Cgroup,
    bounds: Bounds,
) -> Result<Finish, ExecuteError>
where
    H: UnitHost + Sync,
{
    if wait_empty(cgroup, bounds.deadline).await? {
        return Ok(Finish::Empty);
    }
    Ok(Finish::Watchdog {
        killed: kill_everything(host, unit, Some(cgroup), bounds.call).await,
    })
}

/// Poll until the cgroup is empty (`true`) or `deadline` passes (`false`).
async fn wait_empty<K>(cgroup: &mut K, deadline: Instant) -> Result<bool, ExecuteError>
where
    K: UnitCgroup + Send,
{
    loop {
        let empty = cgroup
            .is_empty()
            .map_err(|error| ExecuteError::Cgroup(Box::new(error)))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if empty || remaining.is_zero() {
            return Ok(empty);
        }
        tokio::time::sleep(EMPTY_POLL.min(remaining)).await;
    }
}

/// Terminate the unit after `error`.
async fn abort<H>(
    host: &H,
    unit: &TransientServiceUnitName,
    cgroup: Option<&mut H::Cgroup>,
    error: ExecuteError,
    submission: Submission,
    bounds: Bounds,
) -> ExecuteFailure
where
    H: UnitHost + Sync,
{
    let killed = kill_everything(host, unit, cgroup, bounds.call).await;
    ExecuteFailure {
        error,
        unit: match (killed, submission) {
            (true, _) => UnitState::Killed,
            (false, Submission::Confirmed) => UnitState::KillFailed,
            (false, Submission::Unconfirmed) => UnitState::Unknown,
        },
    }
}

/// SIGKILL the unit and stop its job, each host call bounded by `call`;
/// `true` when SIGKILL was acknowledged.
async fn kill_unit<H>(host: &H, unit: &TransientServiceUnitName, call: Duration) -> bool
where
    H: UnitHost + Sync,
{
    let killed = within(call, async { host.kill(unit.clone()).await.is_ok() })
        .await
        .unwrap_or(false);
    // Replacing a queued start job is best effort: the unit kill covers it.
    within(call, async { host.stop(unit.clone()).await.ok() }).await;
    killed
}

/// [`kill_unit`], then kill the cgroup when bound (a synchronous write that
/// returns promptly; belt and braces for the unit kill).
async fn kill_everything<H>(
    host: &H,
    unit: &TransientServiceUnitName,
    cgroup: Option<&mut H::Cgroup>,
    call: Duration,
) -> bool
where
    H: UnitHost + Sync,
{
    let killed = kill_unit(host, unit, call).await;
    if let Some(cgroup) = cgroup {
        cgroup.kill_all().ok();
    }
    killed
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
