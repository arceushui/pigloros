//! Restart reconciliation over the state a crash left, for the attempt
//! lifecycle's crash-point acceptance suite (#1200).
//!
//! The registry and the attempt directories are exactly what the crashed
//! owner left on disk. A unit that survived is listed by a fake systemd
//! manager and stopped by a fake teardown that unloads it; a root that
//! survived mounted is read back and detached by the real restart detachment
//! over a fake kernel. Every other proof is given, unless the one
//! `UncertainProof` withholds it to show that reconciliation fails closed.
//! What the restart did to those fakes is returned for the caller to check.

// The declaration in `restart.rs` already turns coverage off; this `cfg(test)`
// also keeps the CRAP gate, which reads each file alone, from scoring the
// harness as production code.
#[cfg(test)]
pub(super) mod cases {
    use std::fs::{self, File};
    use std::future::Future;
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use futures_util::future::Either;
    use tokio::time::Instant;
    use zbus::{fdo, BoxDBusError, OwnedObjectPath};

    use super::super::{
        reconcile_with, OrphanNetworkCleanup, ReconciledRestart, RestartReconciliationError,
        Survivors,
    };
    use crate::test_fixtures::{peer_connections, FakeRecoveredRoots, TestResult};
    use crate::{
        AttemptCleanupDeadlines, AttemptShutdownDeadlines, BootInstant, ImageActivationError,
        RecordedRootEntry, SystemdAttemptRecovery, SystemdAttemptUnitObservation,
        SystemdAttemptUnitTeardownError, SystemdTransientUnitTransport, TransientServiceUnitName,
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
        /// The provider loop sweep never returns.
        SweepHangs,
    }

    /// When the restart runs, relative to the last `MountImage` request that
    /// the registry's activation marker records.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum RestartClock {
        /// On another boot: no previous request can still be served.
        OtherBoot,
        /// On the marker's boot, one second after its request was sent, so
        /// the request could still attach a loop device for 69 seconds.
        SameBootSoon,
        /// As `SameBootSoon`, with an overall deadline of one second, far
        /// shorter than that wait.
        SameBootSoonShortDeadline,
    }

    /// What a crash left beyond the registry and the attempt directories.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct CrashSurvivors {
        /// The attempt unit still loaded, if any.
        pub unit: Option<TransientServiceUnitName>,
        /// The attempt whose root is still mounted, if any.
        pub mounted: Option<[u8; 16]>,
    }

    /// One restart and what it did to the fake host.
    #[derive(Debug)]
    pub struct Restarted {
        /// The reconciliation's result; a recovery owner that could not be
        /// opened is its registry error.
        pub result: Result<ReconciledRestart, RestartReconciliationError>,
        /// The attempt units the fake manager still has loaded.
        pub still_loaded: Vec<String>,
        /// The attempts whose mounted root restart detachment detached.
        pub detached: Vec<[u8; 16]>,
        /// Whether orphaned network state was removed.
        pub network_cleaned: bool,
        /// Whether the marker recorded a request on this restart's boot.
        pub request_pending: bool,
        /// When the provider loop sweep ran, measured from the restart's
        /// start, and whether the registry and directories were unchanged
        /// then; `None` when it did not run.
        pub swept: Option<(Duration, bool)>,
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
        subscriptions: Arc<AtomicUsize>,
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
            _states: Vec<String>,
            _patterns: Vec<String>,
        ) -> fdo::Result<Vec<UnitRow>> {
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

    /// Orphaned network cleanup that removes everything unless it `fails`,
    /// counting its removals.
    struct Network {
        fails: bool,
        removed: AtomicUsize,
    }

    impl OrphanNetworkCleanup for Network {
        type Error = NetworkFailure;

        fn remove_orphans(&self) -> impl Future<Output = Result<(), NetworkFailure>> + Send {
            let removed = if self.fails {
                Err(NetworkFailure)
            } else {
                self.removed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            };
            std::future::ready(removed)
        }
    }

    /// The fake restart `Survivors` port: a stop unloads the unit from the
    /// fake manager, and a detach runs the real restart detachment over a
    /// fake kernel on which only the crashed root, if any, is mounted.
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

    /// The boot and send time of the `MountImage` request the registry's
    /// activation marker records, if it records one: an independent PAA1
    /// byte oracle.
    fn recorded_request(runtime: &Path) -> Option<BootInstant> {
        let bytes = fs::read(runtime.join("registry/activation")).ok()?;
        let word = |at: usize| -> Option<u64> {
            bytes
                .get(at..at + 8)?
                .try_into()
                .ok()
                .map(u64::from_le_bytes)
        };
        let boot: [u8; 16] = bytes.get(4..20)?.try_into().ok()?;
        let sent = Duration::new(word(20)?, u32::try_from(word(28)?).ok()?);
        (bytes.len() == 36 && bytes.starts_with(b"PAA1") && boot != [0; 16]).then_some((boot, sent))
    }

    /// Every path below the registry and the attempt directories, with each
    /// file's bytes.
    fn tree(runtime: &Path) -> io::Result<Vec<(PathBuf, Vec<u8>)>> {
        let mut tree = Vec::new();
        let mut pending = vec![runtime.join("registry"), runtime.join("attempts")];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let path = entry?.path();
                let bytes = if path.is_dir() {
                    pending.push(path.clone());
                    Vec::new()
                } else {
                    fs::read(&path)?
                };
                tree.push((path, bytes));
            }
        }
        tree.sort();
        Ok(tree)
    }

    /// Reconcile the registry under `runtime`, the provider's
    /// `/run/pigloros/sandbox`, after a crash that left `survivors`.
    ///
    /// The `uncertain` proof is withheld, and the restart runs at `clock`.
    ///
    /// # Errors
    /// Returns a fixture failure; the reconciliation's own result is in the
    /// value.
    pub async fn restart_after_crash(
        runtime: &Path,
        survivors: &CrashSurvivors,
        uncertain: UncertainProof,
        clock: RestartClock,
    ) -> TestResult<Restarted> {
        let loaded: Loaded = Arc::new(Mutex::new(
            survivors
                .unit
                .iter()
                .map(|unit| unit.as_str().to_owned())
                .collect(),
        ));
        let subscriptions = Arc::new(AtomicUsize::new(0));
        let manager = Manager {
            subscriptions: Arc::clone(&subscriptions),
            loaded: Arc::clone(&loaded),
        };
        let (_server, client) =
            peer_connections(|server| server.serve_at("/org/freedesktop/systemd1", manager))
                .await?;
        let transport = SystemdTransientUnitTransport::from_connection(client).await?;
        assert_eq!(subscriptions.load(Ordering::SeqCst), 1);
        let request = recorded_request(runtime);
        let same_boot = clock != RestartClock::OtherBoot;
        let now: BootInstant = match request.filter(|_| same_boot) {
            Some((boot, sent)) => (boot, sent + Duration::from_secs(1)),
            None => ([0xee; 16], Duration::from_secs(1_000)),
        };
        let overall = if clock == RestartClock::SameBootSoonShortDeadline {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(6)
        };
        let before = tree(runtime)?;
        let start = Instant::now();
        let swept = Mutex::new(None);
        let crashed = Crashed {
            loaded: Arc::clone(&loaded),
            uncertain,
            // No attempt has the zero identity: nothing is mounted.
            roots: FakeRecoveredRoots::mounted_on(survivors.mounted.unwrap_or_default()),
        };
        let network = Network {
            fails: uncertain == UncertainProof::Network,
            removed: AtomicUsize::new(0),
        };
        let parent = File::open(runtime)?;
        let owner = parent.metadata()?.uid();
        let deadlines = (cleanup()?, Instant::now() + overall);
        let opened = SystemdAttemptRecovery::from_runtime_directory(&parent, owner);
        let result = match opened {
            Err(error) => Err(RestartReconciliationError::from(error)),
            Ok(recovery) => {
                reconcile_with(
                    &transport,
                    recovery,
                    &network,
                    &crashed,
                    deadlines,
                    (
                        |_generations| {
                            std::future::ready(Ok(uncertain != UncertainProof::RecordedDevices))
                        },
                        || {
                            let unchanged = tree(runtime).is_ok_and(|current| current == before);
                            *swept.lock().unwrap_or_else(PoisonError::into_inner) =
                                Some((start.elapsed(), unchanged));
                            let outcome = Ok(uncertain != UncertainProof::ProviderLoops);
                            if uncertain == UncertainProof::SweepHangs {
                                Either::Left(std::future::pending())
                            } else {
                                Either::Right(std::future::ready(outcome))
                            }
                        },
                        move || Ok(now),
                    ),
                )
                .await
            }
        };
        let detached = crashed
            .roots
            .detached()?
            .into_iter()
            .filter(|(_, detaches)| *detaches > 0)
            .map(|(attempt, _)| attempt)
            .collect();
        let still_loaded = loaded.lock().map_err(|_| "poisoned fake manager")?.clone();
        let swept = *swept.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(Restarted {
            result,
            still_loaded,
            detached,
            network_cleaned: network.removed.load(Ordering::SeqCst) == 1,
            request_pending: same_boot && request.is_some(),
            swept,
        })
    }
}
