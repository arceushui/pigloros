//! Restart reconciliation before admission opens (ADR-069 R11 §5.1 steps 7
//! and 9 to 11, §5.3).
//!
//! [`prepare_host`] runs step 7 before any socket exists: it connects the
//! single system bus, opens the exclusive [`SystemdAttemptRecovery`], which
//! keeps the registry lock, and opens or creates the input staging directory
//! `/run/pigloros/sandbox/staging/` (UID 0, mode `0700`). A failure exits the
//! runtime before it binds.
//!
//! [`Reconcile::reconcile`] then runs once the runtime is bound and serving
//! in state `Starting`:
//!
//! 9. [`reconcile_restart`] with the SPI1 egress probe through the Local
//!    network port, the orphan sweep, the SPI1 cleanup phases and the fixed
//!    10 s restart bound, which only the recent-activation wait extends;
//!    then the staging sweep (§5.3): every regular file named by 32
//!    lowercase hexadecimal characters is unlinked through the held
//!    directory, and any other entry fails reconciliation closed;
//! 10. on success, the registry owner opens over the reconciled registry, a
//!     ledger with the SPI1 staging cap and the retained control floor, and
//!     the [`AttemptLifecycle`] over both. Admission is then `Open`.
//!
//! The SPI1 attempt network, the provider namespaces and the held
//! [`crate::StagingDirectory`] are used only by the execute port, and are
//! composed with it (#443, R11 §7.3).

use std::fs::File;
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pos_reference::selector::installation::authority::AdmittedSelectorProvider;
use rustix::fs::{fchmod, mkdirat, openat2, statat, unlinkat, AtFlags, Dir, FileType, Mode};
use rustix::io::Errno;
use tokio::runtime::Runtime;
use tokio::time::Instant;

use super::endpoint::{open_parent, DIRECTORY_OPEN, RESOLVE, SANDBOX_STATE};
use super::{ProviderRuntimeError, RuntimeAuthority};
use crate::{
    reconcile_restart, AttemptCleanupDeadlines, AttemptLifecycle, CleanupBudget, ControlFloor,
    EgressProbe, EgressPropertyProbe, HostEgress, LocalEgressProbe, NamespacedLocalNetwork,
    NetlinkNamespaceControl, NetworkNamespaces, NetworkRange, OrphanNetworkCleanup,
    RestartReconciliationError, StagingLedger, StagingLimits, SystemdAttemptRecovery,
    SystemdAttemptRegistry, SystemdAttemptRegistryError, SystemdTransientUnitTransport,
};

/// The staging directory's name beneath `/run/pigloros/sandbox`.
const STAGING: &str = "staging";
/// The staging directory's exact mode.
const STAGING_MODE: u32 = 0o700;
/// The owner of every provider directory.
const ROOT: u32 = 0;
/// The fixed ADR-069 §9 restart bound.
const RESTART_BOUND: Duration = Duration::from_secs(10);

/// Why restart reconciliation left admission closed. The runtime is then
/// `ReconcileFailed` for the life of the process (R11 §5.1 step 11).
#[derive(Debug, thiserror::Error)]
pub(super) enum ReconcileError {
    /// `reconcile_restart` refused.
    #[error(transparent)]
    Restart(#[from] RestartReconciliationError),
    /// The staging directory holds an entry that is not a staged input, or
    /// could not be swept (R11 §5.3).
    #[error("the provider staging directory could not be swept")]
    Staging,
    /// The registry owner could not open over the reconciled registry.
    #[error(transparent)]
    Registry(#[from] SystemdAttemptRegistryError),
}

/// Restart reconciliation, once the runtime serves in state `Starting`.
pub(super) trait Reconcile: Send + 'static {
    /// Reconcile the previous runtime's state and open the lifecycle.
    ///
    /// # Errors
    /// Why admission stays closed.
    fn reconcile(self) -> Result<AttemptLifecycle, ReconcileError>;
}

/// The host side of restart reconciliation, bound before any socket exists:
/// the bus and its runtime, the exclusive recovery owner, the held staging
/// directory, the orphan sweep `network`, the egress probe `egress` and the
/// SPI1 values that open admission.
pub(super) struct HostReconciliation<N, P> {
    // The bus connection is dropped before the runtime that drives it.
    transport: SystemdTransientUnitTransport,
    runtime: Runtime,
    recovery: SystemdAttemptRecovery,
    staging: File,
    network: N,
    egress: P,
    cleanup: CleanupBudget,
    limits: StagingLimits,
    floor: ControlFloor,
}

/// Restart reconciliation over the netlink orphan sweep and the Local
/// network port's egress probe.
pub(super) type NetlinkReconciliation =
    HostReconciliation<NetlinkNamespaceControl, LocalEgressProbe<NetlinkNamespaceControl>>;

/// R11 §5.1 step 7 on this host: the system bus, the netlink orphan sweep
/// and the SPI1 egress probe through the Local network port of the SPI1
/// attempt range.
///
/// # Errors
/// [`ProviderRuntimeError::HostUnavailable`] for any step 7 failure.
pub(super) fn prepare_host(
    authority: &RuntimeAuthority,
) -> Result<NetlinkReconciliation, ProviderRuntimeError> {
    prepare_with(
        authority,
        SystemdTransientUnitTransport::connect_system(),
        netlink_network,
    )
}

/// The netlink orphan sweep, and the `probe` through the Local network port
/// of the attempt `range`, the port attempts use.
fn netlink_network(
    range: NetworkRange,
    probe: EgressProbe,
) -> (
    NetlinkNamespaceControl,
    LocalEgressProbe<NetlinkNamespaceControl>,
) {
    let control = NetlinkNamespaceControl::new(NetworkNamespaces::system());
    let port = NamespacedLocalNetwork::new(
        control.clone(),
        HostEgress::new(),
        NetworkNamespaces::system(),
        range,
    );
    (control, LocalEgressProbe::new(Arc::new(port), probe))
}

/// Step 7 with the bus `connect` yields, and the orphan sweep and egress
/// probe that `network` builds for the SPI1 attempt range and egress probe.
/// The bus is connected, then the recovery owner opened, then the staging
/// directory opened or created; any failure refuses the whole step.
pub(super) fn prepare_with<N, P, E>(
    (admitted, installation, _): &RuntimeAuthority,
    connect: impl Future<Output = Result<SystemdTransientUnitTransport, E>>,
    network: impl FnOnce(NetworkRange, EgressProbe) -> (N, P),
) -> Result<HostReconciliation<N, P>, ProviderRuntimeError> {
    let (network, egress) = network(installation.attempt_range(), installation.egress_probe());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
        .and_then(|runtime| {
            runtime
                .block_on(connect)
                .ok()
                .map(|transport| (runtime, transport))
        })
        .zip(SystemdAttemptRecovery::open().ok())
        .zip(
            open_parent(Path::new(SANDBOX_STATE))
                .ok()
                .and_then(|sandbox| open_staging(&sandbox, ROOT)),
        )
        .map(
            |(((runtime, transport), recovery), staging)| HostReconciliation {
                transport,
                runtime,
                recovery,
                staging,
                network,
                egress,
                cleanup: installation.cleanup_budget(),
                limits: installation.staging_limits(),
                floor: retained_floor(admitted),
            },
        )
        .ok_or(ProviderRuntimeError::HostUnavailable)
}

impl<N, P> Reconcile for HostReconciliation<N, P>
where
    N: OrphanNetworkCleanup + Send + Sync + 'static,
    P: EgressPropertyProbe + Send + Sync + 'static,
{
    fn reconcile(self) -> Result<AttemptLifecycle, ReconcileError> {
        let (cleanup, deadline) = self.restart_bounds(Instant::now());
        self.runtime
            .block_on(reconcile_restart(
                &self.transport,
                self.recovery,
                (&self.network, &self.egress),
                cleanup,
                deadline,
            ))
            .map_err(ReconcileError::from)
            .and_then(|reconciled| sweep_staging(&self.staging).map(|()| reconciled))
            .and_then(|reconciled| {
                SystemdAttemptRegistry::open()
                    .map_err(ReconcileError::from)
                    .map(|registry| {
                        AttemptLifecycle::new(
                            registry,
                            ledger(self.limits, self.floor),
                            &reconciled,
                        )
                    })
            })
    }
}

impl<N, P> HostReconciliation<N, P> {
    /// The SPI1 cleanup phases of a reconciliation that starts at `now`,
    /// and its fixed 10 s bound.
    fn restart_bounds(&self, now: Instant) -> (AttemptCleanupDeadlines, Instant) {
        (self.cleanup.deadlines(now), now + RESTART_BOUND)
    }
}

/// The retained RVS1 revocation epoch and APT1 policy epoch: the lowest
/// epochs the ledger dispatches.
const fn retained_floor(admitted: &AdmittedSelectorProvider) -> ControlFloor {
    ControlFloor {
        revocation_epoch: admitted.bootstrap().revocation().revocation_epoch(),
        policy_epoch: admitted.bootstrap().policy().policy_epoch(),
    }
}

/// A fresh ledger with the SPI1 staging cap and the retained floor raised.
fn ledger(limits: StagingLimits, floor: ControlFloor) -> StagingLedger {
    let ledger = StagingLedger::new(limits);
    ledger.raise_floor(floor);
    ledger
}

/// Open `staging` beneath the held provider state directory `sandbox`,
/// creating it with mode `0700` when absent. It must be a directory that
/// `owner` owns, of mode exactly `0700`, reached without a symlink.
fn open_staging(sandbox: &File, owner: u32) -> Option<File> {
    let open = || openat2(sandbox, STAGING, DIRECTORY_OPEN, Mode::empty(), RESOLVE).map(File::from);
    open()
        .or_else(|error| {
            if error == Errno::NOENT {
                // The umask may strip bits; the explicit mode is harmless.
                mkdirat(sandbox, STAGING, Mode::from_raw_mode(STAGING_MODE))
                    .and_then(|()| open())
                    .and_then(|created| {
                        fchmod(&created, Mode::from_raw_mode(STAGING_MODE)).map(|()| created)
                    })
            } else {
                Err(error)
            }
        })
        .ok()
        .filter(|staging| {
            staging.metadata().is_ok_and(|metadata| {
                metadata.is_dir()
                    && metadata.uid() == owner
                    && metadata.mode() & 0o7777 == STAGING_MODE
            })
        })
}

/// Remove every staged input a previous runtime left (R11 §5.3). A staged
/// input never survives a restart: its AGR1-bound transfer is gone.
///
/// # Errors
/// [`ReconcileError::Staging`] for an entry that is not a regular file named
/// by 32 lowercase hexadecimal characters, or one that cannot be read or
/// removed. Entries are removed in directory order until then.
fn sweep_staging(staging: &File) -> Result<(), ReconcileError> {
    Dir::read_from(staging)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name().to_owned()))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|_| ReconcileError::Staging)
        .and_then(|names| {
            names
                .iter()
                .filter(|name| name.to_bytes() != b"." && name.to_bytes() != b"..")
                .try_for_each(|name| {
                    let staged = staged_input_name(name.to_bytes())
                        && statat(staging, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW).is_ok_and(
                            |metadata| {
                                FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
                            },
                        );
                    staged
                        .then(|| unlinkat(staging, name.as_c_str(), AtFlags::empty()).ok())
                        .flatten()
                        .ok_or(ReconcileError::Staging)
                })
        })
}

/// Whether `name` is the lowercase hexadecimal of a 16-byte staging name.
fn staged_input_name(name: &[u8]) -> bool {
    name.len() == 32
        && name
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
