//! Restart reconciliation over the state a crash left, for the attempt
//! lifecycle's crash-point acceptance suite (#1200).
//!
//! The registry and the attempt directories are exactly what the crashed
//! owner left on disk. A unit that survived is listed by a fake systemd
//! manager and stopped by a fake teardown that unloads it; a root that
//! survived mounted is read back and detached by the real restart detachment
//! over a fake kernel. Every other proof is given, unless the one
//! [`UncertainProof`] withholds it to show that reconciliation fails closed.

use std::fs::File;
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::Either;
use tokio::time::Instant;
use zbus::{fdo, BoxDBusError, OwnedObjectPath};

use super::{
    reconcile_with, OrphanNetworkCleanup, ReconciledRestart, RestartReconciliationError, Survivors,
};
use crate::test_fixtures::{peer_connections, FakeRecoveredRoots, TestResult};
use crate::{
    AttemptCleanupDeadlines, AttemptShutdownDeadlines, ImageActivationError, RecordedRootEntry,
    SystemdAttemptRecovery, SystemdAttemptUnitObservation, SystemdAttemptUnitTeardownError,
    SystemdTransientUnitTransport, TransientServiceUnitName,
};

/// The one restart proof a crash test withholds, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UncertainProof {
    /// Every proof holds.
    None,
    /// The surviving unit cannot be stopped.
    UnitStop,
    /// A recorded attempt root cannot be read back and detached.
    RootDetach,
    /// Orphaned provider network state cannot be removed.
    Network,
    /// A PAI3 root's recorded loop/dm generations are still present.
    RecordedDevices,
    /// A loop device is still backed by a provider image.
    ProviderLoops,
}

/// What a crash left beyond the registry and the attempt directories.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrashSurvivors {
    /// The attempt unit still loaded, if any.
    pub unit: Option<TransientServiceUnitName>,
    /// The attempt whose root is still mounted, if any.
    pub mounted: Option<[u8; 16]>,
}

type UnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.systemd1")]
enum ManagerError {
    NoSuchUnit(String),
}

/// The unit names the fake manager has loaded.
type Loaded = Arc<Mutex<Vec<String>>>;

/// Lists the loaded attempt units; `GetUnit` finds only those.
struct Manager {
    subscriptions: AtomicUsize,
    loaded: Loaded,
}

fn loaded_names(loaded: &Loaded) -> fdo::Result<Vec<String>> {
    loaded
        .lock()
        .map(|names| names.clone())
        .map_err(|error| fdo::Error::Failed(error.to_string()))
}

/// Each loaded unit's own object path, named by its attempt component.
fn unit_path(name: &str) -> fdo::Result<OwnedObjectPath> {
    let component = name
        .strip_prefix("pigloros-attempt-")
        .and_then(|rest| rest.strip_suffix(".service"))
        .ok_or_else(|| fdo::Error::Failed("not an attempt unit".to_owned()))?;
    OwnedObjectPath::try_from(format!(
        "/org/freedesktop/systemd1/unit/crashed_{component}"
    ))
    .map_err(|error| fdo::Error::Failed(error.to_string()))
}

fn row(name: &str) -> fdo::Result<UnitRow> {
    let path = unit_path(name)?;
    Ok((
        name.to_owned(),
        String::new(),
        "loaded".to_owned(),
        "active".to_owned(),
        "running".to_owned(),
        String::new(),
        path.clone(),
        0,
        String::new(),
        path,
    ))
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    fn subscribe(&self) {
        self.subscriptions.fetch_add(1, Ordering::SeqCst);
    }

    fn list_units_by_patterns(
        &self,
        states: Vec<String>,
        patterns: Vec<String>,
    ) -> fdo::Result<Vec<UnitRow>> {
        drop((states, patterns));
        loaded_names(&self.loaded)?
            .iter()
            .map(String::as_str)
            .map(row)
            .collect()
    }

    fn get_unit(&self, name: String) -> Result<OwnedObjectPath, BoxDBusError> {
        if loaded_names(&self.loaded)?.contains(&name) {
            unit_path(&name).map_err(Into::into)
        } else {
            Err(Box::new(ManagerError::NoSuchUnit(name)))
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("injected network cleanup failure")]
struct NetworkFailure;

/// Orphaned network cleanup that removes everything unless it `fails`.
struct Network {
    fails: bool,
}

impl OrphanNetworkCleanup for Network {
    type Error = NetworkFailure;

    fn remove_orphans(&self) -> impl Future<Output = Result<(), NetworkFailure>> + Send {
        std::future::ready(if self.fails {
            Err(NetworkFailure)
        } else {
            Ok(())
        })
    }
}

/// The crashed runtime's surviving unit and roots.
struct Crashed {
    loaded: Loaded,
    uncertain: UncertainProof,
    roots: FakeRecoveredRoots,
}

impl Survivors for Crashed {
    fn stop(
        &self,
        unit: &SystemdAttemptUnitObservation,
        _: AttemptShutdownDeadlines,
        _: Instant,
    ) -> impl Future<Output = Result<(), SystemdAttemptUnitTeardownError>> + Send {
        let name = unit.unit_name().as_str();
        let stopped = if self.uncertain == UncertainProof::UnitStop {
            Err(SystemdAttemptUnitTeardownError::DeadlineElapsed)
        } else {
            // A stopped unit is unloaded.
            self.loaded
                .lock()
                .map(|mut loaded| loaded.retain(|loaded| loaded != name))
                .map_err(|_| SystemdAttemptUnitTeardownError::InvalidDeadlines)
        };
        std::future::ready(stopped)
    }

    fn detach(
        &self,
        entry: RecordedRootEntry,
        deadline: Instant,
    ) -> impl Future<Output = Result<(), ImageActivationError>> + Send {
        if self.uncertain == UncertainProof::RootDetach {
            Either::Left(std::future::ready(Err(
                ImageActivationError::EvidenceMismatch,
            )))
        } else {
            Either::Right(self.roots.detach(entry, deadline))
        }
    }
}

/// Generous phases: no fake step waits, and a refused proof fails at once.
fn cleanup() -> TestResult<AttemptCleanupDeadlines> {
    let now = Instant::now();
    Ok(AttemptCleanupDeadlines::new(
        AttemptShutdownDeadlines::new(
            now + Duration::from_secs(1),
            now + Duration::from_secs(2),
            now + Duration::from_secs(3),
        )?,
        now + Duration::from_secs(4),
        now + Duration::from_secs(5),
    )?)
}

/// Reconcile the registry under `runtime`, the provider's
/// `/run/pigloros/sandbox`, after a crash that left `survivors`, with the
/// `uncertain` proof withheld.
///
/// The last activation request is reported as sent on another boot, so no
/// wait applies; the activation-wait gate is covered by the `restart` tests.
///
/// # Errors
/// Returns a fixture failure; the reconciliation's own result is the value.
pub async fn restart_after_crash(
    runtime: &Path,
    survivors: &CrashSurvivors,
    uncertain: UncertainProof,
) -> TestResult<Result<ReconciledRestart, RestartReconciliationError>> {
    let loaded: Loaded = Arc::new(Mutex::new(
        survivors
            .unit
            .iter()
            .map(|unit| unit.as_str().to_owned())
            .collect(),
    ));
    let manager = Manager {
        subscriptions: AtomicUsize::new(0),
        loaded: Arc::clone(&loaded),
    };
    let (_server, client) =
        peer_connections(|server| server.serve_at("/org/freedesktop/systemd1", manager)).await?;
    let transport = SystemdTransientUnitTransport::from_connection(client).await?;
    let parent = File::open(runtime)?;
    let recovery =
        SystemdAttemptRecovery::from_runtime_directory(&parent, parent.metadata()?.uid())?;
    let crashed = Crashed {
        loaded,
        uncertain,
        // No attempt has the zero identity: nothing is mounted.
        roots: FakeRecoveredRoots::mounted_on(survivors.mounted.unwrap_or_default()),
    };
    let network = Network {
        fails: uncertain == UncertainProof::Network,
    };
    let deadlines = (cleanup()?, Instant::now() + Duration::from_secs(6));
    let reconciled = reconcile_with(
        &transport,
        recovery,
        &network,
        &crashed,
        deadlines,
        (
            |_generations| std::future::ready(Ok(uncertain != UncertainProof::RecordedDevices)),
            || std::future::ready(Ok(uncertain != UncertainProof::ProviderLoops)),
            || Ok(([0xee; 16], Duration::from_secs(1_000))),
        ),
    )
    .await;
    Ok(reconciled)
}
