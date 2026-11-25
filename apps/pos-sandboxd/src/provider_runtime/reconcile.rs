//! Restart reconciliation before admission opens (ADR-069 R11 §5.1 steps 7
//! and 9 to 11, §5.3).
//!
//! [`prepare_host`] runs step 7 before any socket exists: it connects the
//! single system bus, opens the exclusive [`SystemdAttemptRecovery`], which
//! keeps the registry lock, opens or creates the input staging directory
//! `/run/pigloros/sandbox/staging/` (UID 0, mode `0700`), and opens or
//! creates the network capture store `/var/lib/pigloros/sandbox/captures/`
//! beneath the held SIC1 artifact root, without crossing a link or a mount
//! (UID 0, mode `0700`, R11 Amendment 1 §5.4). A failure exits the runtime
//! before it binds.
//!
//! [`Reconcile::reconcile`] then runs once the runtime is bound and serving
//! in state `Starting`:
//!
//! 9. [`reconcile_restart`] with the SPI1 egress probe through the Local
//!    network port, the orphan sweep, the SPI1 cleanup phases and the fixed
//!    10 s restart bound, which only the recent-activation wait extends;
//!    then the staging sweep (§5.3): every regular file named by 32
//!    lowercase hexadecimal characters is unlinked through the held
//!    directory, and any other entry fails reconciliation closed; then the
//!    capture store sweep (Amendment 1 §5.4): unpublished temporaries are
//!    unlinked, published records kept unread, and any other entry fails
//!    reconciliation closed;
//! 10. on success, the registry owner opens over the reconciled registry, a
//!     ledger with the SPI1 staging cap and the retained control floor, and
//!     the [`AttemptLifecycle`] over both. They are handed over as the
//!     execute port, with the held staging directory and capture store, the
//!     provider namespaces step 7 retained (R9's `provider-namespaces`), the
//!     SPI1 cleanup budget, and the bus transport with the multi-thread
//!     runtime that drives it, which outlive reconciliation. Admission is
//!     then `Open`.
//!
//! The SPI1 attempt network is used only by Local attempts, which the port
//! refuses until #1488 serves it.

use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use pos_reference::held_directory::entry_names;
use pos_reference::sandbox_provider_protocol::NetworkCaptureStore;
use pos_reference::selector::installation::authority::AdmittedSelectorProvider;
use pos_reference::selector::installation::InstalledSelectorState;
use rustix::fs::{fchmod, mkdirat, openat2, statat, unlinkat, AtFlags, FileType, Mode};
use rustix::io::Errno;
use tokio::runtime::Runtime;
use tokio::time::Instant;

use super::endpoint::{open_parent, DIRECTORY_OPEN, RESOLVE, SANDBOX_STATE};
use super::port::ExecutePort;
use super::{ProviderRuntimeError, RuntimeAuthority};
use crate::{
    fb_tunnels_isolated, reconcile_restart, AttemptCleanupDeadlines, AttemptLifecycle,
    CleanupBudget, ControlFloor, EgressProbe, EgressPropertyProbe, HostEgress, LocalEgressProbe,
    NamespacedLocalNetwork, NetlinkNamespaceControl, NetworkNamespaces, NetworkRange,
    OrphanNetworkCleanup, ProviderNamespaces, RestartReconciliationError, StagingDirectory,
    StagingLedger, StagingLimits, SystemdAttemptRecovery, SystemdAttemptRegistry,
    SystemdAttemptRegistryError, SystemdTransientUnitTransport, FB_TUNNELS_SYSCTL,
};

/// The staging directory's name beneath `/run/pigloros/sandbox`.
const STAGING: &str = "staging";
/// The staging directory's exact mode.
const STAGING_MODE: u32 = 0o700;
/// The capture store's only entries: its two retention directories.
const CAPTURE_DIRECTORIES: [&[u8]; 2] = [b"responses", b"transcripts"];
/// The owner of every provider directory.
const ROOT: u32 = 0;
/// The worker threads of the runtime that drives the bus and the attempts;
/// each serving thread blocks on it, so two suffice to drive its I/O.
const RUNTIME_WORKERS: usize = 2;
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
    /// The capture store holds an entry that is neither a published record
    /// nor an unpublished temporary, or could not be swept (R11 Amendment 1
    /// §5.4).
    #[error("the network capture store could not be swept")]
    Captures,
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
    fn reconcile(self) -> Result<ExecutePort, ReconcileError>;
}

/// The host side of restart reconciliation, bound before any socket exists:
/// the bus and its runtime, the exclusive recovery owner, the held staging
/// directory and capture store, the orphan sweep `network`, the egress probe
/// `egress` and the SPI1 values that open admission.
pub(super) struct HostReconciliation<N, P> {
    // The bus connection is dropped before the runtime that drives it.
    transport: SystemdTransientUnitTransport,
    runtime: Runtime,
    recovery: SystemdAttemptRecovery,
    staging: (File, StagingDirectory),
    captures: File,
    store: NetworkCaptureStore,
    namespaces: ProviderNamespaces,
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
        || fb_tunnels_isolated(Path::new(FB_TUNNELS_SYSCTL)),
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
/// `isolated` is the fallback-tunnel sysctl probe (ADR-069 R14 N12): the
/// unit network check is sound only when it holds, so a host where it does
/// not is refused first, before anything is opened.
///
/// The bus is connected, then the recovery owner opened, then the staging
/// directory and the capture store opened or created; any failure refuses
/// the whole step.
pub(super) fn prepare_with<N, P, E>(
    (admitted, installation, _): &RuntimeAuthority,
    isolated: impl FnOnce() -> bool,
    connect: impl Future<Output = Result<SystemdTransientUnitTransport, E>>,
    network: impl FnOnce(NetworkRange, EgressProbe) -> (N, P),
) -> Result<HostReconciliation<N, P>, ProviderRuntimeError> {
    if !isolated() {
        writeln!(
            std::io::stderr(),
            "pos-sandboxd: {FB_TUNNELS_SYSCTL} must be at least 1 (ADR-069 R14 N12)"
        )
        .ok();
        return Err(ProviderRuntimeError::HostUnavailable);
    }
    let (network, egress) = network(installation.attempt_range(), installation.egress_probe());
    // Multi-thread: every attempt's release barrier blocks in place on it.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(RUNTIME_WORKERS)
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
                .and_then(|sandbox| open_staging(&sandbox, ROOT))
                .and_then(|staging| held_staging(staging, ROOT)),
        )
        .zip(ProviderNamespaces::observe().ok())
        // The store is opened, or created, only once every earlier step
        // succeeded.
        .and_then(
            |((((runtime, transport), recovery), staging), namespaces)| {
                open_capture_store(admitted.bootstrap().installed(), ROOT).map(
                    |(captures, store)| HostReconciliation {
                        transport,
                        runtime,
                        recovery,
                        staging,
                        captures,
                        store,
                        namespaces,
                        network,
                        egress,
                        cleanup: installation.cleanup_budget(),
                        limits: installation.staging_limits(),
                        floor: retained_floor(admitted),
                    },
                )
            },
        )
        .ok_or(ProviderRuntimeError::HostUnavailable)
}

impl<N, P> Reconcile for HostReconciliation<N, P>
where
    N: OrphanNetworkCleanup + Send + Sync + 'static,
    P: EgressPropertyProbe + Send + Sync + 'static,
{
    fn reconcile(self) -> Result<ExecutePort, ReconcileError> {
        let (cleanup, deadline) = self.restart_bounds(Instant::now());
        let Self {
            transport,
            runtime,
            recovery,
            staging: (swept, staging),
            captures,
            store,
            namespaces,
            network,
            egress,
            cleanup: budget,
            limits,
            floor,
        } = self;
        runtime
            .block_on(reconcile_restart(
                &transport,
                recovery,
                (&network, &egress),
                cleanup,
                deadline,
            ))
            .map_err(ReconcileError::from)
            .and_then(|reconciled| sweep_staging(&swept).map(|()| reconciled))
            .and_then(|reconciled| sweep_captures(&captures, &store, ROOT).map(|()| reconciled))
            .and_then(|reconciled| {
                SystemdAttemptRegistry::open()
                    .map_err(ReconcileError::from)
                    .map(|registry| {
                        let ledger = ledger(limits, floor);
                        ExecutePort {
                            lifecycle: AttemptLifecycle::new(registry, ledger.clone(), &reconciled),
                            ledger,
                            staging,
                            captures: Arc::new(store),
                            namespaces,
                            budget,
                            closed: AtomicBool::new(false),
                            transport,
                            runtime,
                        }
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

/// The held `staging` directory, kept for the sweep, and the private
/// staging directory over a second descriptor of it that the execute port
/// creates inputs in, checked for `owner` and mode `0700` (R11 §5.3).
fn held_staging(staging: File, owner: u32) -> Option<(File, StagingDirectory)> {
    staging
        .try_clone()
        .ok()
        .and_then(|held| StagingDirectory::from_held_directory(held, owner).ok())
        .map(|directory| (staging, directory))
}

/// Open, or create, the capture store's root beneath the held SIC1 artifact
/// root of `installed`: a directory `owner` owns, of mode exactly `0700`,
/// reached without a link or a mount crossing (R11 Amendment 1 §5.4). The
/// exact mode is checked there, since the store's own root check is weaker.
fn open_capture_store(
    installed: &InstalledSelectorState,
    owner: u32,
) -> Option<(File, NetworkCaptureStore)> {
    installed
        .open_capture_store_root(owner)
        .ok()
        .and_then(capture_store_over)
}

/// The store over its checked `root`, which opens or creates its two
/// retention directories, each of mode exactly `0700`.
fn capture_store_over(root: File) -> Option<(File, NetworkCaptureStore)> {
    NetworkCaptureStore::open(&root)
        .ok()
        .map(|store| (root, store))
}

/// Sweep the capture store after a restart (R11 Amendment 1 §5.4): its root
/// may hold only its two retention directories, whose unpublished
/// temporaries are removed and whose published records of `owner` are kept.
///
/// The root is checked before any child is swept, as §5.4 orders it. No
/// other writer exists while this runs: admission is closed and the runtime
/// holds the only descriptors, so nothing can change between the passes.
///
/// # Errors
/// [`ReconcileError::Captures`] for any other entry at either level, or one
/// that cannot be read or removed.
fn sweep_captures(
    root: &File,
    store: &NetworkCaptureStore,
    owner: u32,
) -> Result<(), ReconcileError> {
    entry_names(root)
        .ok()
        .filter(|names| {
            names
                .iter()
                .all(|name| CAPTURE_DIRECTORIES.contains(&name.to_bytes()))
        })
        .ok_or(ReconcileError::Captures)
        .and_then(|_| {
            store
                .sweep_unpublished(owner)
                .map_err(|_| ReconcileError::Captures)
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
    entry_names(staging)
        .map_err(|_| ReconcileError::Staging)
        .and_then(|names| {
            names.iter().try_for_each(|name| {
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
