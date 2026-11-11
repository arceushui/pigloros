//! Restart reconciliation of the previous runtime's attempts (ADR-087 §3).
//!
//! [`reconcile_restart`] runs while admission stays closed: the exclusive
//! [`SystemdAttemptRecovery`] keeps the registry lock, so no attempt can be
//! committed until it returns. Within one deadline it:
//!
//! 1. stops every unit still loaded in the `pigloros-attempt-` namespace. A
//!    unit is the previous runtime's only when its name and `AttemptId` match
//!    a committed intent; any other unit keeps admission closed. Each unit's
//!    cgroup is bound from the listing, with the manager's unit-to-cgroup
//!    mapping checked in both directions, and the unit is stopped with
//!    bounded grace and escalation, its cgroup observed empty and the unit
//!    observed unloaded, all within the cleanup's unit phases. A unit with no
//!    cgroup is proven empty only when it is inactive or failed, since
//!    systemd removes a cgroup only once it is empty (the owner's reading of
//!    ADR-087 §3, decision A, 2026-11-10); a failed one is reset, and either
//!    is then observed unloaded. A unit without a cgroup in any other state
//!    keeps admission closed;
//! 2. proves the exact unit of every recorded attempt and temporary write
//!    absent, including a unit the listing may have hidden;
//! 3. detaches a root still mounted on a recorded attempt directory. The
//!    mount is read back through the held directory and detached by
//!    descriptor only when it is exactly a provider root without submounts,
//!    on a loop device backed by a provider image, matching the PAI3 record
//!    if there is one; its mapper and loop generations are then awaited
//!    absent by the cleanup's release deadline. Anything else is left mounted
//!    and keeps admission closed;
//! 4. removes every provider-owned orphaned network namespace, host veth
//!    end, host nftables table and recorded forwarding change through
//!    [`OrphanNetworkCleanup`] (ADR-069 §8), by the overall deadline, so it
//!    cannot use up the detach budget;
//! 5. proves the Local egress property through [`EgressPropertyProbe`]
//!    (ADR-069 §1: an absent or ineffective property closes admission), on
//!    the network the sweep left clean, by the overall deadline. The probe
//!    runs only after the sweep, which removes whatever an earlier,
//!    interrupted probe left;
//! 6. proves every PAI3 root's recorded loop/dm generations absent now;
//! 7. waits until no `MountImage` request of the previous runtime can still
//!    attach a loop device (owner decision D2). The registry's activation
//!    marker records the boot and `CLOCK_MONOTONIC` time of the last request,
//!    written durably before it was sent. mountfsd may still complete a
//!    request after the client lost its connection, so a request can attach
//!    a loop device until the activator deadline (60 s) plus a fixed server
//!    margin (10 s) after it was sent. When the last request was sent on this
//!    boot less than those 70 s ago, admission stays closed until they have
//!    passed. Only in that recent-activation case does reconciliation outlast
//!    ADR-069's 10 s restart bound, by at most that remaining wait of 70 s;
//!    the sweep below then has the time the deadline had left. An explicit
//!    "no request yet" marker, a request of another boot, or one at least
//!    70 s old needs no wait. A missing marker while a directory stage is
//!    recorded, which only an altered registry can show, a malformed marker,
//!    or an unreadable boot ID or clock fails closed;
//! 8. proves no loop device is backed by a provider image, swept once after
//!    that wait. An activation that reached mountfsd but crashed before its
//!    PAI3 record left no recorded generations, so this sweep is what proves
//!    its devices absent.
//!
//! Only then are the unmounted directories removed and each intent deleted
//! last. That removal is local, bounded filesystem work under the held
//! registry lock, done after the deadline-bound proofs; the deadline does
//! not interrupt it. Every recognized crash state is covered: a temporary
//! write, a planned-only intent, a directory created before its identity
//! extension, a recorded tree with its root, its root removed but its attempt
//! directory present, or both removed, a surviving unit and a still-mounted
//! root. An unknown unit or mount, an unknown directory, a contradiction or
//! the deadline keeps admission closed. Stopping and detaching act only on
//! resources positively identified as the previous runtime's, and nothing is
//! removed from the registry unless every step succeeded.

use std::error::Error;
use std::future::Future;
use std::io;

use futures_util::future::join_all;
use tokio::time::{sleep, timeout_at, Instant};

use crate::{
    AttemptCleanupDeadlines, AttemptShutdownDeadlines, BootInstant, ImageActivationError,
    PlannedAttemptIntent, RecordedRootEntry, SystemdAttemptRecovery, SystemdAttemptRegistryError,
    SystemdAttemptUnitObservation, SystemdAttemptUnitTeardownError, SystemdTransientUnitTransport,
    SystemdTransientUnitTransportError, TransientServiceUnitName,
};

/// Enumerates and removes orphaned provider-owned `piglor-*` network state.
///
/// The implementation must remove every namespace, veth and host nftables
/// chain the provider owns, including those of attempts with no surviving
/// record, and read back their absence before succeeding. It is called only
/// after every attempt unit was observed absent.
pub trait OrphanNetworkCleanup {
    /// The cleanup's failure type.
    type Error: Error + Send + Sync + 'static;

    /// Remove all orphaned provider network state and prove it absent.
    fn remove_orphans(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Proves the Local egress property before admission opens: forwarded
/// sandbox traffic passes the host and is masqueraded.
///
/// The implementation must exercise the same path as every Local attempt,
/// remove everything it made, and fail unless the property was observed. It
/// is called only after [`OrphanNetworkCleanup`] succeeded, so it starts
/// from a network with no provider-owned state.
pub trait EgressPropertyProbe {
    /// The probe's failure type.
    type Error: Error + Send + Sync + 'static;

    /// Observe the egress property, and fail if it is absent or ineffective.
    fn probe_egress(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// The previous runtime's attempts, every one reconciled to absent.
///
/// Only [`reconcile_restart`] creates it, after the directories and intents
/// were removed. It is the exact identity handoff for sealed recovery (#349):
/// the committed planned intents, in canonical `AttemptId` order. It grants no
/// admission by itself; current control-floor checks still apply.
#[derive(Debug, Eq, PartialEq)]
pub struct ReconciledRestart {
    attempts: Vec<PlannedAttemptIntent>,
}

impl ReconciledRestart {
    /// A reconciliation of a previous runtime that left no attempts, for
    /// lifecycle tests that start over an empty registry.
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self {
            attempts: Vec::new(),
        }
    }

    /// The committed attempts whose units, roots and directories were absent
    /// and whose intents were deleted.
    #[must_use]
    pub fn attempts(&self) -> &[PlannedAttemptIntent] {
        &self.attempts
    }
}

/// The attempts whose recorded roots' loop/dm generations were observed
/// absent by a fresh probe, after which no loop device was found backed by a
/// provider image.
///
/// That sweep runs only once no previous-runtime `MountImage` request can
/// still attach a loop device.
///
/// Only restart reconciliation's device proof creates it, so registry removal
/// cannot be handed released-root evidence that no probe produced. It has no
/// public constructor and grants nothing by itself.
#[derive(Debug)]
pub struct RootsReleased(Vec<[u8; 16]>);

impl RootsReleased {
    /// Whether the recorded root of `attempt_id` was observed released.
    pub(crate) fn contains(&self, attempt_id: [u8; 16]) -> bool {
        self.0.contains(&attempt_id)
    }

    /// Evidence for registry tests that have no devices to probe.
    #[cfg(test)]
    pub(crate) const fn for_test(attempt_ids: Vec<[u8; 16]>) -> Self {
        Self(attempt_ids)
    }
}

/// Why restart reconciliation left admission closed.
///
/// No variant reports successful cleanup; the next restart inventories the
/// surviving state again.
#[derive(Debug, thiserror::Error)]
pub enum RestartReconciliationError {
    /// The attempt unit namespace could not be listed.
    #[error("the attempt unit namespace could not be observed")]
    Units(#[source] SystemdTransientUnitTransportError),
    /// A unit is loaded in the attempt namespace that no committed intent
    /// records, so it is not positively the previous runtime's.
    #[error("an unrecorded attempt unit is loaded: {0:?}")]
    SurvivingUnit(TransientServiceUnitName),
    /// A recorded attempt's surviving unit could not be bound, stopped and
    /// observed empty and unloaded.
    #[error("a surviving attempt unit was not stopped")]
    UnitStop(#[source] SystemdAttemptUnitTeardownError),
    /// A recorded attempt's exact unit was not observed absent in time.
    #[error("a recorded attempt unit was not observed absent")]
    UnitAbsence(#[source] SystemdTransientUnitTransportError),
    /// Orphaned network state could not be removed.
    #[error("orphaned network state could not be removed")]
    Network(#[source] Box<dyn Error + Send + Sync>),
    /// The Local egress property is absent or ineffective, or could not be
    /// observed.
    #[error("the Local egress property was not observed")]
    Egress(#[source] Box<dyn Error + Send + Sync>),
    /// A root still mounted on a recorded attempt directory was not a
    /// provider root, or was not detached with its devices observed absent.
    #[error("a still-mounted attempt root was not released")]
    Root(#[source] ImageActivationError),
    /// A recorded root's loop/dm generations were not observed absent.
    #[error("a recorded root's devices were not observed absent")]
    Devices(#[source] Option<ImageActivationError>),
    /// A loop device is still backed by a provider image (`None`), or the
    /// loop devices could not be swept.
    #[error("a loop device backed by a provider image was not observed absent")]
    ProviderLoops(#[source] Option<ImageActivationError>),
    /// The deadline elapsed.
    #[error("restart reconciliation deadline elapsed")]
    DeadlineElapsed,
    /// The registry or directories changed, are mounted or unknown, or could
    /// not be removed.
    #[error(transparent)]
    Registry(#[from] SystemdAttemptRegistryError),
}

type Reconciled<T> = Result<T, RestartReconciliationError>;

/// Reconcile every previous-runtime attempt within `deadline`.
///
/// `cleanup` bounds the work on surviving resources: a surviving unit's
/// process shutdown phases and unit absence, then the release of a
/// still-mounted root. Its phases should end before `deadline`, which bounds
/// every step; ADR-069 targets 2 s of cleanup within a 10 s restart.
/// `network` removes orphaned network state, then `egress` proves the egress
/// property on the clean network.
///
/// # Errors
/// Returns the first [`RestartReconciliationError`]. Nothing is removed from
/// the registry unless every unit, network, egress and device step succeeded
/// first.
pub async fn reconcile_restart<N, P>(
    transport: &SystemdTransientUnitTransport,
    recovery: SystemdAttemptRecovery,
    (network, egress): (&N, &P),
    cleanup: AttemptCleanupDeadlines,
    deadline: Instant,
) -> Reconciled<ReconciledRestart>
where
    N: OrphanNetworkCleanup + Sync,
    P: EgressPropertyProbe + Sync,
{
    reconcile_with(
        transport,
        recovery,
        (network, egress),
        &Host {
            transport,
            detach: crate::RootResourceIdentity::detach_recovered,
        },
        (cleanup, deadline),
        (
            crate::RootResourceIdentity::recorded_generations_absent,
            crate::RootResourceIdentity::provider_loops_absent,
            SystemdAttemptRecovery::boot_instant,
        ),
    )
    .await
}

/// The previous runtime's surviving units and mounted roots, behind a port
/// so that they can be faked without systemd cgroups or kernel mounts.
trait Survivors: Sync {
    /// Bind, stop and remove a listed unit of a committed intent.
    fn stop(
        &self,
        unit: &SystemdAttemptUnitObservation,
        shutdown: AttemptShutdownDeadlines,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), SystemdAttemptUnitTeardownError>> + Send;

    /// Detach the root still mounted on a recorded attempt directory, if
    /// any, and observe its devices absent.
    fn detach(
        &self,
        entry: RecordedRootEntry,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), ImageActivationError>> + Send;
}

/// The host's systemd manager, and its kernel's restart detachment.
struct Host<'a, D> {
    transport: &'a SystemdTransientUnitTransport,
    detach: D,
}

impl<D, F> Survivors for Host<'_, D>
where
    D: Fn(RecordedRootEntry, Instant) -> F + Sync,
    F: Future<Output = Result<(), ImageActivationError>> + Send,
{
    fn stop(
        &self,
        unit: &SystemdAttemptUnitObservation,
        shutdown: AttemptShutdownDeadlines,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), SystemdAttemptUnitTeardownError>> + Send {
        self.transport.stop_listed_unit(unit, shutdown, deadline)
    }

    fn detach(
        &self,
        entry: RecordedRootEntry,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), ImageActivationError>> + Send {
        (self.detach)(entry, deadline)
    }
}

/// The recorded loop/dm generations of one root, mapper first.
type Generations = [((u32, u32), u64); 2];

/// `network` is the orphan sweep and the egress probe; `deadlines` are the
/// surviving-resource cleanup and the overall deadline; `probes` are the
/// recorded-generation probe, the provider loop sweep and the boot clock.
async fn reconcile_with<N, E, S, P, F, L, G, C>(
    transport: &SystemdTransientUnitTransport,
    recovery: SystemdAttemptRecovery,
    network: (&N, &E),
    survivors: &S,
    (cleanup, deadline): (AttemptCleanupDeadlines, Instant),
    probes: (P, L, C),
) -> Reconciled<ReconciledRestart>
where
    N: OrphanNetworkCleanup + Sync,
    E: EgressPropertyProbe + Sync,
    S: Survivors,
    P: Fn(Generations) -> F,
    F: Future<Output = Result<bool, ImageActivationError>>,
    L: FnOnce() -> G,
    G: Future<Output = Result<bool, ImageActivationError>>,
    C: FnOnce() -> io::Result<BootInstant>,
{
    let stopped = stop_units(transport, &recovery, survivors, cleanup, deadline).await;
    let absent = match stopped {
        Ok(()) => units_absent(transport, &recovery, deadline).await,
        Err(error) => Err(error),
    };
    let cleaned = match absent {
        Ok(absent) => release_survivors(&recovery, network, survivors, cleanup, deadline)
            .await
            .map(|()| absent),
        Err(error) => Err(error),
    };
    let released = match cleaned {
        Ok(absent) => roots_released(&recovery, probes, deadline)
            .await
            .map(|roots| (absent, roots)),
        Err(error) => Err(error),
    };
    released.and_then(|(absent, roots)| {
        recovery
            .remove_reconciled(&absent, &roots)
            .map(|attempts| ReconciledRestart { attempts })
            .map_err(RestartReconciliationError::from)
    })
}

/// Stop every listed unit, each only when a committed intent records it.
async fn stop_units<S: Survivors>(
    transport: &SystemdTransientUnitTransport,
    recovery: &SystemdAttemptRecovery,
    survivors: &S,
    cleanup: AttemptCleanupDeadlines,
    deadline: Instant,
) -> Reconciled<()> {
    let listed = timeout_at(deadline, transport.observe_attempt_units()).await;
    let units = match listed {
        Err(_elapsed) => return Err(RestartReconciliationError::DeadlineElapsed),
        Ok(Err(error)) => return Err(RestartReconciliationError::Units(error)),
        Ok(Ok(units)) => units,
    };
    if let Some(unrecorded) = units
        .iter()
        .find(|unit| !committed(recovery, unit.attempt_id()))
    {
        return Err(RestartReconciliationError::SurvivingUnit(
            unrecorded.unit_name().clone(),
        ));
    }
    let stop_by = cleanup.unit_absent().min(deadline);
    let stopped = join_all(units.iter().map(|unit| {
        timeout_at(
            stop_by,
            survivors.stop(unit, cleanup.shutdown(), cleanup.unit_absent()),
        )
    }))
    .await;
    let mut stopped = stopped.into_iter();
    stopped.try_for_each(|stopped| match stopped {
        Err(_elapsed) => Err(RestartReconciliationError::DeadlineElapsed),
        Ok(result) => result.map_err(RestartReconciliationError::UnitStop),
    })
}

/// Whether a committed intent, not an interrupted write, records `attempt_id`.
fn committed(recovery: &SystemdAttemptRecovery, attempt_id: [u8; 16]) -> bool {
    recovery
        .entries()
        .iter()
        .any(|entry| !entry.is_temporary() && entry.attempt_id() == attempt_id)
}

/// Release every surviving resource, then prove the egress property by the
/// overall deadline. The probe runs only once the orphan network state is
/// gone, so it cannot observe a previous runtime's rules.
async fn release_survivors<N, E, S>(
    recovery: &SystemdAttemptRecovery,
    (network, egress): (&N, &E),
    survivors: &S,
    cleanup: AttemptCleanupDeadlines,
    deadline: Instant,
) -> Reconciled<()>
where
    N: OrphanNetworkCleanup + Sync,
    E: EgressPropertyProbe + Sync,
    S: Survivors,
{
    match release_resources(recovery, network, survivors, cleanup, deadline).await {
        Ok(()) => prove_egress(egress, deadline).await,
        Err(error) => Err(error),
    }
}

/// Detach every still-mounted root by the cleanup's release deadline, then
/// remove orphaned network state by the overall deadline. Each step has its
/// own bound, so a slow network cleanup cannot use up the detach budget.
async fn release_resources<N: OrphanNetworkCleanup + Sync, S: Survivors>(
    recovery: &SystemdAttemptRecovery,
    network: &N,
    survivors: &S,
    cleanup: AttemptCleanupDeadlines,
    deadline: Instant,
) -> Reconciled<()> {
    match detach_roots(recovery, survivors, cleanup.released().min(deadline)).await {
        Ok(()) => remove_network(network, deadline).await,
        Err(error) => Err(error),
    }
}

/// Detach every root still mounted on a recorded attempt directory.
async fn detach_roots<S: Survivors>(
    recovery: &SystemdAttemptRecovery,
    survivors: &S,
    deadline: Instant,
) -> Reconciled<()> {
    let entries = recovery.recorded_root_entries()?;
    let detached = join_all(
        entries
            .into_iter()
            .map(|entry| timeout_at(deadline, survivors.detach(entry, deadline))),
    )
    .await;
    let mut detached = detached.into_iter();
    detached.try_for_each(|detached| match detached {
        Err(_elapsed) => Err(RestartReconciliationError::DeadlineElapsed),
        Ok(result) => result.map_err(RestartReconciliationError::Root),
    })
}

async fn units_absent(
    transport: &SystemdTransientUnitTransport,
    recovery: &SystemdAttemptRecovery,
    deadline: Instant,
) -> Reconciled<Vec<crate::SystemdAttemptUnitAbsenceObservation>> {
    let mut absent = Vec::with_capacity(recovery.entries().len());
    for entry in recovery.entries() {
        let observed = transport
            .wait_for_attempt_unit_absence(entry.unit_name().clone(), deadline)
            .await;
        absent.push(observed.map_err(RestartReconciliationError::UnitAbsence)?);
    }
    Ok(absent)
}

async fn remove_network<N: OrphanNetworkCleanup + Sync>(
    network: &N,
    deadline: Instant,
) -> Reconciled<()> {
    let removed = timeout_at(deadline, network.remove_orphans()).await;
    match removed {
        Err(_elapsed) => Err(RestartReconciliationError::DeadlineElapsed),
        Ok(result) => result.map_err(|error| RestartReconciliationError::Network(Box::new(error))),
    }
}

/// Prove the egress property by `deadline`. No probe starts once the
/// deadline has passed. A probe still running at the deadline is no longer
/// awaited and admission stays closed; whatever it leaves, the next
/// restart's sweep removes.
async fn prove_egress<E: EgressPropertyProbe + Sync>(
    egress: &E,
    deadline: Instant,
) -> Reconciled<()> {
    if Instant::now() >= deadline {
        return Err(RestartReconciliationError::DeadlineElapsed);
    }
    let probed = timeout_at(deadline, egress.probe_egress()).await;
    match probed {
        Err(_elapsed) => Err(RestartReconciliationError::DeadlineElapsed),
        Ok(result) => result.map_err(|error| RestartReconciliationError::Egress(Box::new(error))),
    }
}

/// Mint the released-root evidence only once no loop device is backed by a
/// provider image, and none can still be attached by a previous-runtime
/// `MountImage` request.
async fn roots_released<P, F, L, G, C>(
    recovery: &SystemdAttemptRecovery,
    (probe, sweep, now): (P, L, C),
    deadline: Instant,
) -> Reconciled<RootsReleased>
where
    P: Fn(Generations) -> F,
    F: Future<Output = Result<bool, ImageActivationError>>,
    L: FnOnce() -> G,
    G: Future<Output = Result<bool, ImageActivationError>>,
    C: FnOnce() -> io::Result<BootInstant>,
{
    let probed = timeout_at(deadline, probe_roots(recovery, probe)).await;
    let released = probed.unwrap_or(Err(RestartReconciliationError::DeadlineElapsed))?;
    let wait = now()
        .map_err(SystemdAttemptRegistryError::from)
        .and_then(|now| recovery.activation_wait(now))?
        .unwrap_or_default();
    // The sweep keeps the time the deadline had left, after the wait.
    let swept_by = deadline
        .checked_add(wait)
        .ok_or(RestartReconciliationError::DeadlineElapsed)?;
    sleep(wait).await;
    timeout_at(swept_by, sweep_loops(sweep))
        .await
        .unwrap_or(Err(RestartReconciliationError::DeadlineElapsed))
        .map(|()| RootsReleased(released))
}

/// Prove that no loop device is backed by a provider image.
async fn sweep_loops<L, G>(sweep: L) -> Reconciled<()>
where
    L: FnOnce() -> G,
    G: Future<Output = Result<bool, ImageActivationError>>,
{
    let swept = sweep().await;
    match swept {
        Ok(true) => Ok(()),
        Ok(false) => Err(RestartReconciliationError::ProviderLoops(None)),
        Err(error) => Err(RestartReconciliationError::ProviderLoops(Some(error))),
    }
}

async fn probe_roots<P, F>(recovery: &SystemdAttemptRecovery, probe: P) -> Reconciled<Vec<[u8; 16]>>
where
    P: Fn(Generations) -> F,
    F: Future<Output = Result<bool, ImageActivationError>>,
{
    let mut released = Vec::new();
    for entry in recovery.entries() {
        let Some(generations) = entry
            .intent()
            .and_then(crate::RecoveredAttemptIntent::recorded_generations)
        else {
            continue;
        };
        let probed = probe(generations).await;
        match probed {
            Ok(true) => released.push(entry.attempt_id()),
            Ok(false) => return Err(RestartReconciliationError::Devices(None)),
            Err(error) => return Err(RestartReconciliationError::Devices(Some(error))),
        }
    }
    Ok(released)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod crash_restart;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
#[cfg(test)]
pub use crash_restart::cases::{restart_after_crash, CrashSurvivors, UncertainProof};
