//! The one production [`ProviderLifecyclePort`]: the selector-owned provider
//! runtime as systemd transient units (ADR-069 R11 §5.0, §5.2; R12 §4.2, §7.2).
//!
//! Only `apps/pos-root-selector` composes [`SystemdProviderLifecycle`]. It
//! owns one current-thread Tokio runtime and one system-bus connection, opened
//! with [`SystemdTransientUnitTransport::connect_system`] (Unix transport only).
//! It never creates a process itself: systemd starts the runtime unit when
//! the manager runs `StartTransientUnit` (ADR-087 A.3).

use std::num::NonZeroU64;
use std::time::Duration;

use pos_reference::selector::runtime_lifecycle::{
    process_start_time_ticks, CgroupPath, ObservationChallenge, ProviderLifecycleError,
    ProviderLifecyclePort, RuntimeSlotTarget, StaleUnitsObservation, StartedRuntimeObservation,
};
use tokio::runtime::Runtime;
use tokio::time::{timeout_at, Instant};
use zbus::OwnedObjectPath;

use crate::{
    AttemptCgroupError, AttemptShutdownDeadlines, CgroupRoot, SystemdTransientUnitTransport,
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
const PROVIDER_RUNTIME_ARGUMENT: &str = "provider-runtime";
/// The runtime's start-to-`READY=1` bound, 30 s (R11 §5.2, owner decision O7).
const PROVIDER_RUNTIME_START_TIMEOUT_USEC: u64 = 30_000_000;
/// Owner-only files and directories (R11 §5.2, owner decision O9).
const PROVIDER_UNIT_UMASK: u32 = 0o077;

/// The exact property set of one provider-runtime unit (ADR-069 R11 §5.2,
/// the single normative owner of these values).
///
/// It sets `Type=notify`, `NotifyAccess=main`, `ExitType=main`,
/// `KillMode=control-group`, `Restart=no`, `TimeoutStartUSec=30s`,
/// `CollectMode=inactive-or-failed`, `UMask=0077`, `StandardInput=null` and
/// `ExecStart=[<binary>, [<binary>, "provider-runtime"], false]`, and nothing
/// else: no environment, socket, descriptor or credential property, and no
/// `RuntimeMaxUSec`. #444 owns the additional shared confinement set.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ProviderRuntimeUnitRequest {
    binary_path: String,
}

impl ProviderRuntimeUnitRequest {
    /// The runtime unit of the kind-11 object whose content digest is `digest`.
    ///
    /// # Errors
    /// Rejects a path other than the digest's fixed SIC1 object path.
    pub(crate) fn new(
        binary_path: &str,
        digest: [u8; 32],
    ) -> Result<Self, TransientUnitRequestError> {
        if binary_path.strip_prefix(PROVIDER_BINARY_DIRECTORY) == Some(lower_hex(&digest).as_str())
        {
            Ok(Self {
                binary_path: binary_path.to_owned(),
            })
        } else {
            Err(TransientUnitRequestError::InvalidLauncherSource)
        }
    }

    /// The `StartTransientUnit` properties, in submission order.
    ///
    /// # Errors
    /// Returns a D-Bus value-conversion failure.
    pub(crate) fn properties(&self) -> Result<Vec<(String, zbus::OwnedVariant)>, zbus::Error> {
        let exec_start = vec![(
            self.binary_path.clone(),
            vec![
                self.binary_path.clone(),
                PROVIDER_RUNTIME_ARGUMENT.to_owned(),
            ],
            false,
        )];
        [
            ("Type", zbus::Variant::from("notify".to_owned())),
            ("NotifyAccess", zbus::Variant::from("main".to_owned())),
            ("ExitType", zbus::Variant::from("main".to_owned())),
            ("KillMode", zbus::Variant::from("control-group".to_owned())),
            ("Restart", zbus::Variant::from("no".to_owned())),
            (
                "TimeoutStartUSec",
                zbus::Variant::from(PROVIDER_RUNTIME_START_TIMEOUT_USEC),
            ),
            (
                "CollectMode",
                zbus::Variant::from("inactive-or-failed".to_owned()),
            ),
            ("UMask", zbus::Variant::from(PROVIDER_UNIT_UMASK)),
            ("StandardInput", zbus::Variant::from("null".to_owned())),
            ("ExecStart", zbus::Variant::from(exec_start)),
        ]
        .into_iter()
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
                        Self::from_parts(runtime, transport, Box::new(CgroupRoot::system))
                    })
            })
    }

    const fn from_parts(
        runtime: Runtime,
        transport: SystemdTransientUnitTransport,
        cgroup_root: CgroupRootSource,
    ) -> Self {
        Self {
            transport,
            runtime,
            cgroup_root,
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

    /// Stop every loaded unit of both families, then list both again: any
    /// unit that is still, or again, loaded is a residue.
    async fn terminate_stale(&self, deadline: Instant) -> Result<usize, ProviderLifecycleError> {
        let mut stopped = 0;
        for family in ProviderUnitFamily::ALL {
            for unit in self.observe(family).await? {
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
                    self.transport.stop_provider_unit(
                        &unit,
                        &self.cgroup_root,
                        shutdown,
                        unit_deadline,
                    ),
                )
                .await
                .unwrap_or(Err(ProviderLifecycleError::DeadlineExceeded))?;
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
        let request = ProviderRuntimeUnitRequest::new(
            slot.provider_binary_path(),
            slot.provider_binary_digest(),
        )
        .map_err(|_| ProviderLifecycleError::Contradiction)?;
        let started = self
            .runtime
            .block_on(async {
                timeout_at(
                    Instant::from_std(deadline),
                    self.transport.start_provider_runtime_unit(&name, &request),
                )
                .await
            })
            .map_err(|_| ProviderLifecycleError::DeadlineExceeded)?
            .map_err(|error| start_failure(&error))?;
        let main_pid = NonZeroU64::new(u64::from(started.main_pid))
            .ok_or(ProviderLifecycleError::Contradiction)?;
        let ticks = process_start_time_ticks(main_pid)?;
        let control_group = CgroupPath::new(&started.control_group)?;
        Ok(StartedRuntimeObservation::new(
            slot.challenge(),
            slot.lifecycle_scope_id(),
            main_pid,
            ticks,
            control_group,
        ))
    }
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
