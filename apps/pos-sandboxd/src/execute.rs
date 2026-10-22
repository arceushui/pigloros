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
    LocalNetworkAdmission, LocalNetworkTermination, NetworkCaptureStore, NetworkEndpointConnector,
    NetworkExchangePlan, NetworkExchangeTranscript, ReplayedNetworkExchange, SandboxExecutionMode,
};
use zvariant::OwnedFd;

use crate::{
    ActivatedRootDirectory, ActiveAttempt, AdmittedAttempt, BoundLocalProxy, CheckedRoot,
    EstablishedNetwork, HostServiceChannel, ImageActivationError, LaunchMode, LauncherSource,
    LocalNetworkPort, LocalProxyBindError, ServeError, ServedProxy, SystemCallFilter,
    SystemdServiceLimits, TransientServiceUnitName, TransientUnitLaunchInputs,
    TransientUnitRequest,
};

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
    ReplayUnavailable,
    /// The FD 3 socket pair could not be created.
    #[error("the host-service channel could not be created")]
    HostService(#[source] io::Error),
    /// The launcher barrier failed.
    #[error("the launcher barrier failed")]
    Barrier(#[source] Box<dyn Error + Send + Sync>),
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
    /// The unit was started or submitted and could not be killed; it may
    /// still run and the lifecycle must reconcile it.
    KillFailed,
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

struct LocalPreparation<C> {
    admission: LocalNetworkAdmission,
    network: EstablishedNetwork<C>,
    channel: HostServiceChannel,
}

/// The network behaviour prepared before the unit starts.
enum Planned<C> {
    None,
    Local(Box<LocalPreparation<C>>),
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
/// `|| root.recheck(&directory, &entry)`.
///
/// The runtime must have its time driver enabled.
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
    let deadline = Instant::now() + watchdog;
    let started = match host.start(unit.clone(), request).await {
        Ok(started) => started,
        Err(error) => {
            return Err(abort(host, &unit, None, ExecuteError::Unit(Box::new(error))).await)
        }
    };
    let mut cgroup = match host.bind_cgroup(&started).await {
        Ok(cgroup) => cgroup,
        Err(error) => {
            return Err(abort(host, &unit, None, ExecuteError::Cgroup(Box::new(error))).await)
        }
    };
    let attempt_id = attempt.attempt_id();
    let active = ActiveAttempt::record(attempt, deadline);
    let bound = match bind_planned(&active, planned) {
        Ok(bound) => bound,
        Err(error) => return Err(abort(host, &unit, Some(&mut cgroup), error).await),
    };
    if let Err(error) = barrier.release(&active).await {
        let error = ExecuteError::Barrier(Box::new(error));
        return Err(abort(host, &unit, Some(&mut cgroup), error).await);
    }
    let (network, empty) = match supervise(&mut cgroup, bound, store, deadline).await {
        Ok(supervised) => supervised,
        Err(error) => return Err(abort(host, &unit, Some(&mut cgroup), error).await),
    };
    let ending = if empty {
        AttemptEnding::CgroupEmpty
    } else if kill_everything(host, &unit, Some(&mut cgroup)).await {
        AttemptEnding::WatchdogKilled
    } else {
        AttemptEnding::WatchdogKillFailed
    };
    Ok(AttemptExecution {
        attempt_id,
        started,
        cgroup,
        ending,
        network,
    })
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
            let preparation = Box::new(LocalPreparation {
                admission: *admission,
                network: network.establish(attempt.attempt_id()),
                channel,
            });
            (
                LaunchMode::Local {
                    host_service: adapter_end,
                },
                Planned::Local(preparation),
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
    // The recheck comes last, so nothing but compilation separates it from
    // the start of the unit.
    let checked = recheck().map_err(ExecuteError::Recheck)?;
    if checked.root_directory()
        != &ActivatedRootDirectory::for_attempt(attempt.unit_name().attempt_component())
    {
        return Err(ExecuteError::RootIdentity);
    }
    let inputs = TransientUnitLaunchInputs::new(&checked, launcher_source, launch_mode, release);
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
        .map_err(|_| ExecuteError::ReplayUnavailable)
}

fn bind_planned<C>(active: &ActiveAttempt, planned: Planned<C>) -> Result<Bound<C>, ExecuteError> {
    match planned {
        Planned::None => Ok(Bound::None),
        Planned::Replay(replayed) => Ok(Bound::Replay(replayed)),
        Planned::Local(local) => active
            .bind_local_proxy(local.admission, local.network, local.channel)
            .map(|(binding, connector)| Bound::Local(Box::new(binding), connector))
            .map_err(ExecuteError::from),
    }
}

/// Serve the Local proxy, if any, then observe the cgroup until it is empty or
/// the watchdog expires. The flag is `true` when the cgroup was observed empty.
async fn supervise<C, K>(
    cgroup: &mut K,
    bound: Bound<C>,
    store: Arc<NetworkCaptureStore>,
    deadline: Instant,
) -> Result<(NetworkEvidence, bool), ExecuteError>
where
    C: NetworkEndpointConnector + Send + 'static,
    K: UnitCgroup + Send,
{
    let evidence = match bound {
        Bound::None => NetworkEvidence::None,
        Bound::Replay(replayed) => NetworkEvidence::Replay(replayed),
        Bound::Local(binding, connector) => NetworkEvidence::Local(
            binding
                .serve_until(connector, store, deadline)
                .await
                .map_err(ExecuteError::from)?,
        ),
    };
    let expired = matches!(&evidence, NetworkEvidence::Local(served) if served.watchdog_expired);
    let empty = !expired && wait_empty(cgroup, deadline).await?;
    Ok((evidence, empty))
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
) -> ExecuteFailure
where
    H: UnitHost + Sync,
{
    let killed = kill_everything(host, unit, cgroup).await;
    ExecuteFailure {
        error,
        unit: if killed {
            UnitState::Killed
        } else {
            UnitState::KillFailed
        },
    }
}

/// SIGKILL the unit, kill its cgroup when bound, and stop its job; `true`
/// when SIGKILL was acknowledged.
async fn kill_everything<H>(
    host: &H,
    unit: &TransientServiceUnitName,
    cgroup: Option<&mut H::Cgroup>,
) -> bool
where
    H: UnitHost + Sync,
{
    let killed = host.kill(unit.clone()).await.is_ok();
    if let Some(cgroup) = cgroup {
        // The cgroup kill is belt and braces: the unit kill already covers it.
        cgroup.kill_all().ok();
    }
    // Replacing a queued start job is best effort for the same reason.
    host.stop(unit.clone()).await.ok();
    killed
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
