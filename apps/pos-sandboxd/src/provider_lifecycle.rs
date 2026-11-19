//! The one production [`ProviderLifecyclePort`]: the selector-owned provider
//! runtime and recovery peer as systemd transient units (ADR-069 R11 §5.0,
//! §5.2; R12 §4.2, §7).
//!
//! Only `apps/pos-root-selector` composes [`SystemdProviderLifecycle`]. It
//! owns one current-thread Tokio runtime and one system-bus connection, opened
//! with [`SystemdTransientUnitTransport::connect_system`] (Unix transport only).
//! It never creates a process itself: systemd starts the runtime and peer
//! units when the manager runs `StartTransientUnit` (ADR-087 A.3).

use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::time::Duration;

use pos_reference::selector::recovery::{
    PreviousRuntimeObservation, PreviousRuntimeTarget, RecoveryPeerLaunch, RecoveryPeerObservation,
    RecoverySlotObservation, RecoverySlotTarget,
};
use pos_reference::selector::runtime_lifecycle::{
    process_start_time_ticks, CgroupPath, ObservationChallenge, ProviderLifecycleError,
    ProviderLifecyclePort, RuntimeSlotTarget, StaleUnitsObservation, StartedRuntimeObservation,
};
use tokio::runtime::Runtime;
use tokio::time::{timeout_at, Instant};
use zbus::OwnedObjectPath;

use crate::provider_runtime::recovery_peer::RECOVERY_PEER_ARGUMENT;
use crate::{
    reconcile_cleanup, AttemptCgroupError, AttemptShutdownDeadlines, CgroupRoot,
    NetlinkNamespaceControl, NetworkNamespaces, OrphanNetworkCleanup, ProviderInstallation,
    RestartReconciliationError, SystemdAttemptRecovery, SystemdTransientUnitTransport,
    SystemdTransientUnitTransportError, TransientServiceUnitName, TransientUnitRequestError,
};

/// Fixed stop phases of one stale unit, measured from the start of its stop.
/// They fit inside ADR-069 §9's 5 s per-unit forced-cleanup ceiling; normal
/// open reads no SPI1 (owner reading, 2026-11-15). The selector bounds the
/// whole operation by §9's 10 s restart bound.
const STALE_STOP_GRACE: Duration = Duration::from_millis(500);
const STALE_UNIT_KILL: Duration = Duration::from_secs(1);
const STALE_SHUTDOWN: Duration = Duration::from_millis(1_500);
const STALE_UNIT_ABSENT: Duration = Duration::from_secs(3);

/// Opens the cgroup2 mount for one cgroup observation.
pub(crate) type CgroupRootSource =
    Box<dyn Fn() -> Result<CgroupRoot, AttemptCgroupError> + Send + Sync>;

/// The previous runtime's reconciled attempts, or why they are not.
type Reconciled<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<[u8; 16]>, ProviderLifecycleError>> + 'a>>;

/// R12 §7.1 steps 3 to 7 on this host, after the runtime unit is gone: the
/// cleanup part of restart reconciliation over the previous-live set, by
/// the deadline, with the registry lock released before it resolves.
pub(crate) type PreviousRuntimeCleanup = Box<
    dyn for<'a> Fn(&'a SystemdTransientUnitTransport, &'a [[u8; 16]], Instant) -> Reconciled<'a>
        + Send
        + Sync,
>;

/// The two selector-owned unit families (ADR-069 R12 §7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderUnitFamily {
    /// `pigloros-provider-runtime-<hex(lifecycle-scope-id)>.service` (R11 D7).
    Runtime,
    /// `pigloros-provider-recovery-<hex(recovery-lifecycle-scope-id)>.service`.
    Recovery,
}

impl ProviderUnitFamily {
    const ALL: [Self; 2] = [Self::Runtime, Self::Recovery];

    pub(crate) const fn prefix(self) -> &'static str {
        match self {
            Self::Runtime => "pigloros-provider-runtime-",
            Self::Recovery => "pigloros-provider-recovery-",
        }
    }
}

/// One loaded provider unit, resolved back to its listed object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderUnit {
    name: TransientServiceUnitName,
    path: OwnedObjectPath,
}

impl ProviderUnit {
    pub(crate) const fn new(name: TransientServiceUnitName, path: OwnedObjectPath) -> Self {
        Self { name, path }
    }

    pub(crate) const fn name(&self) -> &TransientServiceUnitName {
        &self.name
    }

    pub(crate) const fn path(&self) -> &OwnedObjectPath {
        &self.path
    }
}

/// The started runtime unit's `MainPID` and `ControlGroup`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartedProviderUnit {
    main_pid: u32,
    control_group: String,
}

impl StartedProviderUnit {
    pub(crate) const fn new(main_pid: u32, control_group: String) -> Self {
        Self {
            main_pid,
            control_group,
        }
    }
}

/// The directory of the SIC1 kind-11 provider binaries (ADR-069 R11 §5.2).
const PROVIDER_BINARY_DIRECTORY: &str = "/var/lib/pigloros/sandbox/providers/";
/// The provider daemon mode's only argument (ADR-069 R11 §5.1 step 1).
pub(crate) const PROVIDER_RUNTIME_ARGUMENT: &str = "provider-runtime";
/// The runtime's start-to-`READY=1` bound, 30 s (R11 §5.2, owner decision O7).
const PROVIDER_RUNTIME_START_TIMEOUT_USEC: u64 = 30_000_000;
/// The recovery peer's start-to-`READY=1` bound, 5 s (R12 §7.3, O2).
const RECOVERY_PEER_START_TIMEOUT_USEC: u64 = 5_000_000;
/// The recovery peer's whole lifetime, 5 s + 100 ms + 5 s, as defense in
/// depth only (R12 §7.3 item 2).
const RECOVERY_PEER_RUNTIME_MAX_USEC: u64 = 10_100_000;
/// Owner-only files and directories (R11 §5.2, owner decision O9).
const PROVIDER_UNIT_UMASK: u32 = 0o077;
/// The runtime unit's control group, `/system.slice/<unit>` (R12 §7.1 step 8).
const SYSTEM_SLICE: &str = "/system.slice/";

/// The exact property set of one provider unit: the runtime unit or the
/// recovery-peer unit.
///
/// R11 §5.2 is the single normative owner of the common properties:
/// `Type=notify`, `NotifyAccess=main`, `ExitType=main`,
/// `KillMode=control-group`, `Restart=no`, `CollectMode=inactive-or-failed`,
/// `UMask=0077` and `StandardInput=null`, and nothing else: no environment,
/// socket, descriptor or credential property. #444 owns the additional
/// shared confinement set.
///
/// - The runtime unit adds `TimeoutStartUSec=30s` and
///   `ExecStart=[<binary>, [<binary>, "provider-runtime"], false]`, and has
///   no `RuntimeMaxUSec`.
/// - The recovery-peer unit (R12 §7.3) adds `TimeoutStartUSec=5s`,
///   `RuntimeMaxUSec=10.1s` and
///   `ExecStart=[<binary>, [<binary>, "recovery-peer", <hex endpoint ID>], false]`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ProviderUnitRequest {
    binary_path: String,
    arguments: Vec<String>,
    timeout_start_usec: u64,
    runtime_max_usec: Option<u64>,
}

impl ProviderUnitRequest {
    /// The runtime unit of the kind-11 object whose content digest is `digest`.
    ///
    /// # Errors
    /// Rejects a path other than the digest's fixed SIC1 object path.
    pub(crate) fn runtime(
        binary_path: &str,
        digest: [u8; 32],
    ) -> Result<Self, TransientUnitRequestError> {
        Self::checked(binary_path, digest).map(|binary_path| Self {
            binary_path,
            arguments: vec![PROVIDER_RUNTIME_ARGUMENT.to_owned()],
            timeout_start_usec: PROVIDER_RUNTIME_START_TIMEOUT_USEC,
            runtime_max_usec: None,
        })
    }

    /// The recovery-peer unit of the previous kind-11 object whose content
    /// digest is `digest`, for the endpoint `endpoint_id` (R12 §7.3).
    ///
    /// # Errors
    /// Rejects a path other than the digest's fixed SIC1 object path.
    pub(crate) fn recovery_peer(
        binary_path: &str,
        digest: [u8; 32],
        endpoint_id: [u8; 16],
    ) -> Result<Self, TransientUnitRequestError> {
        Self::checked(binary_path, digest).map(|binary_path| Self {
            binary_path,
            arguments: vec![RECOVERY_PEER_ARGUMENT.to_owned(), lower_hex(&endpoint_id)],
            timeout_start_usec: RECOVERY_PEER_START_TIMEOUT_USEC,
            runtime_max_usec: Some(RECOVERY_PEER_RUNTIME_MAX_USEC),
        })
    }

    /// `binary_path`, when it is the digest's fixed SIC1 object path.
    fn checked(binary_path: &str, digest: [u8; 32]) -> Result<String, TransientUnitRequestError> {
        if binary_path.strip_prefix(PROVIDER_BINARY_DIRECTORY) == Some(lower_hex(&digest).as_str())
        {
            Ok(binary_path.to_owned())
        } else {
            Err(TransientUnitRequestError::InvalidLauncherSource)
        }
    }

    /// The `StartTransientUnit` properties, in submission order.
    ///
    /// # Errors
    /// Returns a D-Bus value-conversion failure.
    pub(crate) fn properties(&self) -> Result<Vec<(String, zbus::OwnedVariant)>, zbus::Error> {
        let mut argv = vec![self.binary_path.clone()];
        argv.extend(self.arguments.iter().cloned());
        let exec_start = vec![(self.binary_path.clone(), argv, false)];
        let runtime_max = self
            .runtime_max_usec
            .map(|usec| ("RuntimeMaxUSec", zbus::Variant::from(usec)));
        [
            ("Type", zbus::Variant::from("notify".to_owned())),
            ("NotifyAccess", zbus::Variant::from("main".to_owned())),
            ("ExitType", zbus::Variant::from("main".to_owned())),
            ("KillMode", zbus::Variant::from("control-group".to_owned())),
            ("Restart", zbus::Variant::from("no".to_owned())),
            (
                "TimeoutStartUSec",
                zbus::Variant::from(self.timeout_start_usec),
            ),
            (
                "CollectMode",
                zbus::Variant::from("inactive-or-failed".to_owned()),
            ),
            ("UMask", zbus::Variant::from(PROVIDER_UNIT_UMASK)),
            ("StandardInput", zbus::Variant::from("null".to_owned())),
        ]
        .into_iter()
        .chain(runtime_max)
        .chain([("ExecStart", zbus::Variant::from(exec_start))])
        .map(|(name, value)| {
            zbus::OwnedVariant::try_from(value).map(|value| (name.to_owned(), value))
        })
        .collect()
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut hex, byte| {
        // Writing to a `String` cannot fail.
        write!(hex, "{byte:02x}").ok();
        hex
    })
}

/// The systemd adapter of the selector-owned provider-runtime lifecycle.
pub struct SystemdProviderLifecycle {
    /// Declared first, so the bus connection drops before the runtime that
    /// drives its tasks.
    transport: SystemdTransientUnitTransport,
    runtime: Runtime,
    cgroup_root: CgroupRootSource,
    previous_cleanup: PreviousRuntimeCleanup,
}

impl SystemdProviderLifecycle {
    /// Connect to the host system bus and subscribe to manager signals.
    ///
    /// # Errors
    /// Returns [`ProviderLifecycleError::Unavailable`] when the runtime cannot
    /// be built or the system bus is unavailable or not a Unix socket.
    pub fn connect() -> Result<Self, ProviderLifecycleError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProviderLifecycleError::Unavailable)
            .and_then(|runtime| {
                let transport = runtime.block_on(SystemdTransientUnitTransport::connect_system());
                transport
                    .map_err(|_| ProviderLifecycleError::Unavailable)
                    .map(|transport| {
                        Self::from_parts(
                            runtime,
                            transport,
                            Box::new(CgroupRoot::system),
                            Box::new(|transport, previous_live, deadline| {
                                Box::pin(host_cleanup(transport, previous_live, deadline, || {
                                    NetlinkNamespaceControl::new(NetworkNamespaces::system())
                                }))
                            }),
                        )
                    })
            })
    }

    const fn from_parts(
        runtime: Runtime,
        transport: SystemdTransientUnitTransport,
        cgroup_root: CgroupRootSource,
        previous_cleanup: PreviousRuntimeCleanup,
    ) -> Self {
        Self {
            transport,
            runtime,
            cgroup_root,
            previous_cleanup,
        }
    }

    async fn observe(
        &self,
        family: ProviderUnitFamily,
    ) -> Result<Vec<ProviderUnit>, ProviderLifecycleError> {
        self.transport
            .observe_provider_units(family)
            .await
            .map_err(|_| ProviderLifecycleError::Unavailable)
    }

    /// Stop one listed unit through the bounded stop phases, by `deadline`.
    async fn stop(
        &self,
        unit: &ProviderUnit,
        deadline: Instant,
    ) -> Result<(), ProviderLifecycleError> {
        let started = Instant::now();
        let shutdown = AttemptShutdownDeadlines::new(
            started + STALE_STOP_GRACE,
            started + STALE_UNIT_KILL,
            started + STALE_SHUTDOWN,
        )
        .map_err(|_| ProviderLifecycleError::DeadlineExceeded)?;
        let unit_deadline = deadline.min(started + STALE_UNIT_ABSENT);
        timeout_at(
            unit_deadline,
            self.transport
                .stop_provider_unit(unit, &self.cgroup_root, shutdown, unit_deadline),
        )
        .await
        .unwrap_or(Err(ProviderLifecycleError::DeadlineExceeded))
    }

    /// Stop the loaded unit of `family` named `name`, if any, and prove it
    /// unloaded (R12 §7.3: "stop the peer unit, if loaded"). Any other unit
    /// of the family is then foreign: the named unit is stopped first, so a
    /// foreign unit never keeps it running.
    async fn stop_only(
        &self,
        family: ProviderUnitFamily,
        name: &TransientServiceUnitName,
        deadline: Instant,
    ) -> Result<(), ProviderLifecycleError> {
        for unit in self.observe(family).await? {
            if unit.name() == name {
                self.stop(&unit, deadline).await?;
            }
        }
        let remaining = self.observe(family).await;
        remaining
            .map_err(|_| ProviderLifecycleError::ResidualResource)
            .and_then(|units| only_foreign(&units, name))
    }

    /// R12 §7.1 steps 1 and 2: stop the runtime unit and prove it unloaded;
    /// no other runtime unit, and no recovery unit but the SIR1 slot's, may
    /// be loaded.
    async fn terminate_previous_unit(
        &self,
        runtime: &TransientServiceUnitName,
        slot: &TransientServiceUnitName,
        deadline: Instant,
    ) -> Result<(), ProviderLifecycleError> {
        self.stop_only(ProviderUnitFamily::Runtime, runtime, deadline)
            .await?;
        let recovery = self.observe(ProviderUnitFamily::Recovery).await?;
        if recovery.iter().all(|unit| unit.name() == slot) {
            Ok(())
        } else {
            Err(ProviderLifecycleError::ForeignResource)
        }
    }

    /// Stop every loaded unit of both families, then list both again: any
    /// unit that is still, or again, loaded is a residue.
    async fn terminate_stale(&self, deadline: Instant) -> Result<usize, ProviderLifecycleError> {
        let mut stopped = 0;
        for family in ProviderUnitFamily::ALL {
            for unit in self.observe(family).await? {
                self.stop(&unit, deadline).await?;
                stopped += 1;
            }
        }
        for family in ProviderUnitFamily::ALL {
            let remaining = self.observe(family).await;
            if !remaining.is_ok_and(|units| units.is_empty()) {
                return Err(ProviderLifecycleError::ResidualResource);
            }
        }
        Ok(stopped)
    }
}

impl ProviderLifecyclePort for SystemdProviderLifecycle {
    fn terminate_stale_runtimes(
        &self,
        challenge: ObservationChallenge,
        deadline: std::time::Instant,
    ) -> Result<StaleUnitsObservation, ProviderLifecycleError> {
        let deadline = Instant::from_std(deadline);
        // The timer is created inside the runtime: a Tokio timer needs its
        // time driver in context.
        self.runtime
            .block_on(async { timeout_at(deadline, self.terminate_stale(deadline)).await })
            .unwrap_or(Err(ProviderLifecycleError::DeadlineExceeded))
            .map(|stopped| StaleUnitsObservation::new(challenge, stopped))
    }

    fn start_provider_runtime(
        &self,
        slot: &RuntimeSlotTarget<'_>,
        deadline: std::time::Instant,
    ) -> Result<StartedRuntimeObservation, ProviderLifecycleError> {
        let name = TransientServiceUnitName::provider_unit(
            ProviderUnitFamily::Runtime,
            slot.lifecycle_scope_id(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let request = ProviderUnitRequest::runtime(
            slot.provider_binary_path(),
            slot.provider_binary_digest(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let (main_pid, ticks, control_group) = self.start_unit(&name, &request, deadline)?;
        Ok(StartedRuntimeObservation::new(
            slot.challenge(),
            slot.lifecycle_scope_id(),
            main_pid,
            ticks,
            control_group,
        ))
    }

    fn terminate_previous_runtime(
        &self,
        target: &PreviousRuntimeTarget<'_>,
        deadline: std::time::Instant,
    ) -> Result<PreviousRuntimeObservation, ProviderLifecycleError> {
        let runtime = TransientServiceUnitName::provider_unit(
            ProviderUnitFamily::Runtime,
            target.lifecycle_scope_id(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let slot = TransientServiceUnitName::provider_unit(
            ProviderUnitFamily::Recovery,
            target.recovery_lifecycle_scope_id(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let control_group = system_slice(&runtime)?;
        let deadline = Instant::from_std(deadline);
        // The unit stop is bounded by the deadline. The cleanup bounds itself:
        // only its #1200 D2 recent-activation wait may outlast the deadline.
        let reconciled = self.runtime.block_on(async {
            timeout_at(
                deadline,
                self.terminate_previous_unit(&runtime, &slot, deadline),
            )
            .await
            .unwrap_or(Err(ProviderLifecycleError::DeadlineExceeded))?;
            (self.previous_cleanup)(
                &self.transport,
                target.previous_live_attempt_ids(),
                deadline,
            )
            .await
        })?;
        Ok(PreviousRuntimeObservation::new(
            target.challenge(),
            target.lifecycle_scope_id(),
            control_group,
            reconciled,
        ))
    }

    fn reconcile_recovery_slot(
        &self,
        target: &RecoverySlotTarget<'_>,
        deadline: std::time::Instant,
    ) -> Result<RecoverySlotObservation, ProviderLifecycleError> {
        let slot = TransientServiceUnitName::provider_unit(
            ProviderUnitFamily::Recovery,
            target.recovery_lifecycle_scope_id(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let control_group = system_slice(&slot)?;
        let deadline = Instant::from_std(deadline);
        self.runtime
            .block_on(async {
                timeout_at(
                    deadline,
                    self.stop_only(ProviderUnitFamily::Recovery, &slot, deadline),
                )
                .await
            })
            .unwrap_or(Err(ProviderLifecycleError::DeadlineExceeded))
            .map(|()| {
                RecoverySlotObservation::new(
                    target.challenge(),
                    target.recovery_lifecycle_scope_id(),
                    control_group,
                )
            })
    }

    fn start_recovery_peer(
        &self,
        launch: &RecoveryPeerLaunch<'_>,
        deadline: std::time::Instant,
    ) -> Result<RecoveryPeerObservation, ProviderLifecycleError> {
        let scope = launch.slot().recovery_lifecycle_scope_id();
        let name = TransientServiceUnitName::provider_unit(ProviderUnitFamily::Recovery, scope)
            .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let binary = launch.provider_binary();
        let request = ProviderUnitRequest::recovery_peer(
            binary.path(),
            binary.digest(),
            launch.recovery_endpoint_id(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let (main_pid, ticks, control_group) = self.start_unit(&name, &request, deadline)?;
        Ok(RecoveryPeerObservation::new(
            launch.challenge(),
            scope,
            main_pid,
            ticks,
            control_group,
        ))
    }
}

impl SystemdProviderLifecycle {
    /// Start the unit `name` with `request`'s properties by `deadline`, and
    /// read its main process's PID, start ticks and control group.
    fn start_unit(
        &self,
        name: &TransientServiceUnitName,
        request: &ProviderUnitRequest,
        deadline: std::time::Instant,
    ) -> Result<(NonZeroU64, u64, CgroupPath), ProviderLifecycleError> {
        let started = self
            .runtime
            .block_on(async {
                timeout_at(
                    Instant::from_std(deadline),
                    self.transport.start_provider_unit(name, request),
                )
                .await
            })
            .map_err(|_| ProviderLifecycleError::DeadlineExceeded)?
            .map_err(|error| start_failure(&error))?;
        let main_pid = NonZeroU64::new(u64::from(started.main_pid))
            .ok_or(ProviderLifecycleError::Contradiction)?;
        let ticks = process_start_time_ticks(main_pid)?;
        let control_group = CgroupPath::new(&started.control_group)?;
        Ok((main_pid, ticks, control_group))
    }
}

/// After `name` was stopped: it must be gone, and no other unit of its
/// family may be loaded.
fn only_foreign(
    remaining: &[ProviderUnit],
    name: &TransientServiceUnitName,
) -> Result<(), ProviderLifecycleError> {
    if remaining.iter().any(|unit| unit.name() == name) {
        Err(ProviderLifecycleError::ResidualResource)
    } else if remaining.is_empty() {
        Ok(())
    } else {
        Err(ProviderLifecycleError::ForeignResource)
    }
}

/// R12 §7.1 steps 3 to 7 on this host: read the SPI1 cleanup budget, open
/// the registry exclusively, require every committed intent to be one of
/// the previous-live attempts, and run the cleanup part of restart
/// reconciliation with the orphan sweep `network` builds. The registry lock
/// is released when this returns. The egress probe never runs.
pub(crate) async fn host_cleanup<N: OrphanNetworkCleanup + Sync>(
    transport: &SystemdTransientUnitTransport,
    previous_live: &[[u8; 16]],
    deadline: Instant,
    network: impl FnOnce() -> N,
) -> Result<Vec<[u8; 16]>, ProviderLifecycleError> {
    let budget = ProviderInstallation::open()
        .map_err(|_| ProviderLifecycleError::Unavailable)?
        .cleanup_budget();
    let recovery =
        SystemdAttemptRecovery::open().map_err(|_| ProviderLifecycleError::Unavailable)?;
    // R12 §7.1 lists the foreign-intent check (step 6) after the cleanup
    // (step 5). It runs first here, so that cleanup never acts on, or
    // deletes the evidence of, an attempt SIR1 does not name; the reviewed
    // R12 text order is queued for amendment with the owner.
    require_owned_intents(
        recovery
            .entries()
            .iter()
            .map(|entry| (entry.attempt_id(), entry.is_temporary())),
        previous_live,
    )?;
    let network = network();
    let reconciled = reconcile_cleanup(
        transport,
        recovery,
        &network,
        budget.deadlines(Instant::now()),
        deadline,
    )
    .await;
    reconciled
        .map(|reconciled| {
            reconciled
                .attempts()
                .iter()
                .map(crate::PlannedAttemptIntent::attempt_id)
                .collect()
        })
        .map_err(|error| reconciliation_failure(&error))
}

/// R12 §7.1 step 6: every committed intent's attempt must be one of the
/// previous-live attempts. A temporary write names no committed attempt.
fn require_owned_intents(
    mut entries: impl Iterator<Item = ([u8; 16], bool)>,
    previous_live: &[[u8; 16]],
) -> Result<(), ProviderLifecycleError> {
    if entries.all(|(attempt_id, temporary)| temporary || previous_live.contains(&attempt_id)) {
        Ok(())
    } else {
        Err(ProviderLifecycleError::ForeignResource)
    }
}

/// An unrecorded unit is foreign, a missed deadline is one, and every other
/// refusal leaves a residue.
const fn reconciliation_failure(error: &RestartReconciliationError) -> ProviderLifecycleError {
    match error {
        RestartReconciliationError::SurvivingUnit(_) => ProviderLifecycleError::ForeignResource,
        RestartReconciliationError::DeadlineElapsed => ProviderLifecycleError::DeadlineExceeded,
        _ => ProviderLifecycleError::ResidualResource,
    }
}

/// `/system.slice/<unit>`, the unit's control group.
fn system_slice(name: &TransientServiceUnitName) -> Result<CgroupPath, ProviderLifecycleError> {
    CgroupPath::new(&format!("{SYSTEM_SLICE}{}", name.as_str()))
}

/// A start whose evidence names another unit or object is a contradiction;
/// every other failure leaves the manager unavailable for this start.
const fn start_failure(error: &SystemdTransientUnitTransportError) -> ProviderLifecycleError {
    match error {
        SystemdTransientUnitTransportError::JobIdentityMismatch { .. }
        | SystemdTransientUnitTransportError::CgroupUnitMismatch => {
            ProviderLifecycleError::Contradiction
        }
        _ => ProviderLifecycleError::Unavailable,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
