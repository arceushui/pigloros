//! Restart reconciliation of the previous runtime's attempts (ADR-087 §3).
//!
//! [`reconcile_restart`] runs while admission stays closed: the exclusive
//! [`SystemdAttemptRecovery`] keeps the registry lock, so no attempt can be
//! committed until it returns. It proves, within one deadline:
//!
//! 1. no unit is loaded in the `pigloros-attempt-` namespace;
//! 2. the exact unit of every recorded attempt and temporary write is absent,
//!    including a unit the listing may have hidden;
//! 3. orphaned provider network state is removed through
//!    [`OrphanNetworkCleanup`], the seam for the #911 enumerate-and-remove
//!    primitive;
//! 4. every PAI3 root's recorded loop/dm generations are absent now;
//! 5. no `MountImage` request of the previous runtime can still attach a
//!    loop device (owner decision D2). The registry's activation marker
//!    records the boot and `CLOCK_MONOTONIC` time of the last request, written
//!    durably before it was sent. mountfsd may still complete a request after
//!    the client lost its connection, so a request can attach a loop device
//!    until the activator deadline (60 s) plus a fixed server margin (10 s)
//!    after it was sent. When the last request was sent on this boot less
//!    than those 70 s ago, admission stays closed until they have passed.
//!    Only in that recent-activation case does reconciliation outlast
//!    ADR-069's 10 s restart bound, by at most that remaining wait of 70 s;
//!    the sweep below then has the time the deadline had left. An explicit
//!    "no request yet" marker, a request of another boot, or one at least
//!    70 s old needs no wait. A missing marker while a directory stage is
//!    recorded, which only an altered registry can show, a malformed marker,
//!    or an unreadable boot ID or clock fails closed.
//! 6. no loop device is backed by a provider image, swept once after that
//!    wait. An activation that reached mountfsd but crashed before its PAI3
//!    record left no recorded generations, so this sweep is what proves its
//!    devices absent.
//!
//! Only then are the unmounted directories removed and each intent deleted
//! last. That removal is local, bounded filesystem work under the held
//! registry lock, done after the deadline-bound proofs; the deadline does
//! not interrupt it. Every recognized pre-launch crash state is covered: a
//! temporary write, a planned-only intent, a directory created before its
//! identity extension, and a recorded tree with its root, its root removed but
//! its attempt directory present, or both removed. A loaded unit, a mounted or unknown
//! directory, a contradiction or the deadline keeps admission closed and
//! removes nothing; stopping a surviving unit and detaching a mounted root are
//! not attempted here, so either keeps admission closed until the remaining
//! #1200 recovery lands.

use std::error::Error;
use std::future::Future;
use std::io;

use tokio::time::{sleep, timeout_at, Instant};

use crate::{
    BootInstant, ImageActivationError, PlannedAttemptIntent, SystemdAttemptRecovery,
    SystemdAttemptRegistryError, SystemdTransientUnitTransport, SystemdTransientUnitTransportError,
    TransientServiceUnitName,
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
    /// A unit is still loaded in the attempt namespace.
    #[error("an attempt unit is still loaded: {0:?}")]
    SurvivingUnit(TransientServiceUnitName),
    /// A recorded attempt's exact unit was not observed absent in time.
    #[error("a recorded attempt unit was not observed absent")]
    UnitAbsence(#[source] SystemdTransientUnitTransportError),
    /// Orphaned network state could not be removed.
    #[error("orphaned network state could not be removed")]
    Network(#[source] Box<dyn Error + Send + Sync>),
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
/// # Errors
/// Returns the first [`RestartReconciliationError`]. Nothing is removed unless
/// every unit, network and device observation succeeded first.
pub async fn reconcile_restart<N: OrphanNetworkCleanup + Sync>(
    transport: &SystemdTransientUnitTransport,
    recovery: SystemdAttemptRecovery,
    network: &N,
    deadline: Instant,
) -> Reconciled<ReconciledRestart> {
    reconcile_with(
        transport,
        recovery,
        network,
        deadline,
        (
            crate::RootResourceIdentity::recorded_generations_absent,
            crate::RootResourceIdentity::provider_loops_absent,
            SystemdAttemptRecovery::boot_instant,
        ),
    )
    .await
}

/// The recorded loop/dm generations of one root, mapper first.
type Generations = [((u32, u32), u64); 2];

/// `probes` are the recorded-generation probe, the provider loop sweep and
/// the boot clock.
async fn reconcile_with<N, P, F, L, G, C>(
    transport: &SystemdTransientUnitTransport,
    recovery: SystemdAttemptRecovery,
    network: &N,
    deadline: Instant,
    probes: (P, L, C),
) -> Reconciled<ReconciledRestart>
where
    N: OrphanNetworkCleanup + Sync,
    P: Fn(Generations) -> F,
    F: Future<Output = Result<bool, ImageActivationError>>,
    L: FnOnce() -> G,
    G: Future<Output = Result<bool, ImageActivationError>>,
    C: FnOnce() -> io::Result<BootInstant>,
{
    let units = observe_units(transport, deadline).await;
    let absent = match units {
        Ok(()) => units_absent(transport, &recovery, deadline).await,
        Err(error) => Err(error),
    };
    let cleaned = match absent {
        Ok(absent) => remove_network(network, deadline).await.map(|()| absent),
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

async fn observe_units(
    transport: &SystemdTransientUnitTransport,
    deadline: Instant,
) -> Reconciled<()> {
    let listed = timeout_at(deadline, transport.observe_attempt_units()).await;
    match listed {
        Err(_elapsed) => Err(RestartReconciliationError::DeadlineElapsed),
        Ok(Err(error)) => Err(RestartReconciliationError::Units(error)),
        Ok(Ok(units)) => units.first().map_or(Ok(()), |unit| {
            Err(RestartReconciliationError::SurvivingUnit(
                unit.unit_name().clone(),
            ))
        }),
    }
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
mod tests;
