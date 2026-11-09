//! Restart reconciliation over a fake systemd manager and the real registry.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use zbus::{fdo, BoxDBusError, OwnedObjectPath};

    use super::super::*;
    use crate::test_fixtures::{in_lock_test_process, peer_connections};
    use crate::{AttemptUnitTermination, PreparedAttemptDirectory, SystemdAttemptRegistry};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
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

    /// The recorded attempt whose PAI3 root facts are committed.
    const ROOT_ATTEMPT: u8 = 4;
    /// The fixture root's recorded mapper and loop generations.
    const FIXTURE_GENERATIONS: Generations = [((253, 3), 102), ((7, 7), 101)];

    #[derive(Clone, Copy)]
    enum Listing {
        Empty,
        Surviving,
        Fails,
        Hangs,
    }

    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.systemd1")]
    enum ManagerError {
        NoSuchUnit(String),
    }

    /// Lists units by `listing`; `GetUnit` finds only the `loaded` names.
    struct Manager {
        subscriptions: AtomicUsize,
        listing: Listing,
        loaded: Vec<String>,
        lookups: Arc<Mutex<Vec<String>>>,
    }

    fn row(name: &str) -> TestResult<UnitRow> {
        let path = OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/survivor")?;
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

        async fn list_units_by_patterns(
            &self,
            states: Vec<String>,
            patterns: Vec<String>,
        ) -> fdo::Result<Vec<UnitRow>> {
            drop((states, patterns));
            match self.listing {
                Listing::Empty => Ok(Vec::new()),
                Listing::Surviving => self
                    .loaded
                    .iter()
                    .map(|name| row(name).map_err(|error| fdo::Error::Failed(error.to_string())))
                    .collect(),
                Listing::Fails => Err(fdo::Error::AccessDenied("listing denied".to_owned())),
                Listing::Hangs => std::future::pending().await,
            }
        }

        fn get_unit(&self, name: String) -> Result<OwnedObjectPath, BoxDBusError> {
            self.lookups
                .lock()
                .map_err(|error| fdo::Error::Failed(error.to_string()))?
                .push(name.clone());
            if self.loaded.contains(&name) {
                OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/survivor")
                    .map_err(|error| fdo::Error::Failed(error.to_string()).into())
            } else {
                Err(Box::new(ManagerError::NoSuchUnit(name)))
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Cleanup {
        Removes,
        Fails,
        Hangs,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("injected network cleanup failure")]
    struct NetworkFailure;

    struct Network {
        cleanup: Cleanup,
        calls: AtomicUsize,
    }

    impl Network {
        const fn new(cleanup: Cleanup) -> Self {
            Self {
                cleanup,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl OrphanNetworkCleanup for Network {
        type Error = NetworkFailure;

        async fn remove_orphans(&self) -> Result<(), NetworkFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.cleanup {
                Cleanup::Removes => Ok(()),
                Cleanup::Fails => Err(NetworkFailure),
                Cleanup::Hangs => std::future::pending().await,
            }
        }
    }

    struct Host {
        _server: zbus::Connection,
        transport: SystemdTransientUnitTransport,
        lookups: Arc<Mutex<Vec<String>>>,
    }

    async fn host(listing: Listing, loaded: Vec<String>) -> TestResult<Host> {
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let manager = Manager {
            subscriptions: AtomicUsize::new(0),
            listing,
            loaded,
            lookups: Arc::clone(&lookups),
        };
        let (server, client) =
            peer_connections(|server| server.serve_at("/org/freedesktop/systemd1", manager))
                .await?;
        let transport = SystemdTransientUnitTransport::from_connection(client).await?;
        Ok(Host {
            _server: server,
            transport,
            lookups,
        })
    }

    fn intent(id: u8) -> TestResult<PlannedAttemptIntent> {
        Ok(PlannedAttemptIntent::new([id; 16], [2; 32])?)
    }

    fn unit(id: u8) -> TestResult<String> {
        Ok(intent(id)?.unit_name().as_str().to_owned())
    }

    fn private_directory(path: &Path) -> TestResult {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    /// How the live owner left the recorded PAI3 attempt before the crash.
    type RootEnding = fn(PreparedAttemptDirectory) -> TestResult;

    /// The owner crashed with the recorded attempt still prepared.
    fn abandoned(prepared: PreparedAttemptDirectory) -> TestResult {
        drop(prepared);
        Ok(())
    }

    /// The execution requested its unit start but failed before binding the
    /// unit's cgroup, so the live owner's cleanup is refused and the intent is
    /// left for restart reconciliation.
    fn started_without_cgroup(prepared: PreparedAttemptDirectory) -> TestResult {
        let ownership = prepared.execution_ownership();
        ownership.claim()?;
        ownership.submit()?;
        let refused = prepared.finish_terminal_cleanup(AttemptUnitTermination::Unsubmitted, None);
        assert!(
            matches!(refused, Err(SystemdAttemptRegistryError::CleanupEvidence)),
            "{refused:?}"
        );
        Ok(())
    }

    /// 1 planned only; 2 the recorded tree; 3 its root removed but its attempt
    /// directory present (#721); 4 a recorded PAI3 root, unmounted; 5 an
    /// interrupted temporary write. With `with_root` false, attempt 4 is omitted.
    fn seed(with_root: bool) -> TestResult<tempfile::TempDir> {
        seed_with(with_root.then_some::<RootEnding>(abandoned))
    }

    /// [`seed`], with attempt 4 left by `root`, if any.
    fn seed_with(root: Option<RootEnding>) -> TestResult<tempfile::TempDir> {
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
        private_directory(&runtime.path().join("registry"))?;
        private_directory(&runtime.path().join("attempts"))?;
        let parent = File::open(runtime.path())?;
        let registry =
            SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        registry.commit_planned(&intent(1)?)?;
        drop(registry.commit_planned(&intent(2)?)?.prepare_directory()?);
        drop(registry.commit_planned(&intent(3)?)?.prepare_directory()?);
        fs::remove_dir(
            runtime
                .path()
                .join("attempts")
                .join(intent(3)?.unit_name().attempt_component())
                .join("root"),
        )?;
        if let Some(ending) = root {
            let prepared = registry
                .commit_planned(&intent(ROOT_ATTEMPT)?)?
                .prepare_directory()?;
            let identity = crate::test_fixtures::recorded_identity(&prepared)?;
            prepared.record_root(&identity, || Ok(()))?;
            ending(prepared)?;
        }
        drop(registry);
        let key = intent(5)?.unit_name().attempt_component().to_owned();
        let temporary = runtime
            .path()
            .join("registry")
            .join(format!(".planned-{key}-1-1"));
        // An interrupted PAI1 write: its tag and the first attempt-ID bytes.
        fs::write(&temporary, [b"PAI1".as_slice(), &[5; 26]].concat())?;
        fs::set_permissions(temporary, fs::Permissions::from_mode(0o600))?;
        Ok(runtime)
    }

    fn recovery(runtime: &Path) -> TestResult<SystemdAttemptRecovery> {
        let parent = File::open(runtime)?;
        Ok(SystemdAttemptRecovery::from_runtime_directory(
            &parent,
            parent.metadata()?.uid(),
        )?)
    }

    fn count(path: &Path) -> TestResult<usize> {
        Ok(fs::read_dir(path)?.count())
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_millis(500)
    }

    /// After a refused reconciliation nothing was removed.
    fn assert_untouched(runtime: &Path, records: usize) -> TestResult {
        assert_eq!(count(&runtime.join("registry"))?, records);
        assert_eq!(count(&runtime.join("attempts"))?, records - 2);
        Ok(())
    }

    #[tokio::test]
    async fn every_previous_runtime_attempt_is_reconciled_with_its_intent_last() -> TestResult {
        if !in_lock_test_process(
        "restart::tests::cases::every_previous_runtime_attempt_is_reconciled_with_its_intent_last",
    )? {
        return Ok(());
    }
        let runtime = seed(true)?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let network = Network::new(Cleanup::Removes);
        let probed = Mutex::new(Vec::new());
        let reconciled = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            &network,
            deadline(),
            |generations| {
                let pushed = probed.lock().map(|mut probed| probed.push(generations));
                std::future::ready(
                    pushed
                        .map(|()| true)
                        .map_err(|_| ImageActivationError::Transport),
                )
            },
        )
        .await?;
        let expected = (1..=4).map(intent).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(reconciled.attempts(), expected.as_slice());
        assert_eq!(count(&runtime.path().join("registry"))?, 0);
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        assert_eq!(network.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *probed.lock().map_err(|_| "probes")?,
            vec![FIXTURE_GENERATIONS]
        );
        // The temporary write's unit is checked first: its name sorts first.
        let mut names = (1..=5).map(unit).collect::<Result<Vec<_>, _>>()?;
        names.rotate_right(1);
        assert_eq!(*host.lookups.lock().map_err(|_| "lookups")?, names);
        // Admission can reopen: a new owner commits over the empty registry.
        let parent = File::open(runtime.path())?;
        SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?
            .commit_planned(&intent(9)?)?;
        Ok(())
    }

    #[tokio::test]
    async fn the_public_entry_reconciles_without_a_recorded_root() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::the_public_entry_reconciles_without_a_recorded_root",
        )? {
            return Ok(());
        }
        let runtime = seed(false)?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let reconciled = reconcile_restart(
            &host.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
        )
        .await?;
        assert_eq!(reconciled.attempts().len(), 3);
        assert_eq!(count(&runtime.path().join("registry"))?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_surviving_unlisted_or_unobservable_unit_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
        "restart::tests::cases::a_surviving_unlisted_or_unobservable_unit_keeps_admission_closed",
    )? {
        return Ok(());
    }
        for listing in [
            Listing::Surviving,
            Listing::Empty,
            Listing::Fails,
            Listing::Hangs,
        ] {
            let runtime = seed(true)?;
            // Attempt 2's unit is still loaded; only `Surviving` lists it.
            let host = host(listing, vec![unit(2)?]).await?;
            let network = Network::new(Cleanup::Removes);
            let result = reconcile_restart(
                &host.transport,
                recovery(runtime.path())?,
                &network,
                deadline(),
            )
            .await;
            let refused = match (listing, &result) {
                (Listing::Surviving, Err(RestartReconciliationError::SurvivingUnit(name))) => {
                    name.as_str() == unit(2)?
                }
                (Listing::Empty, Err(RestartReconciliationError::UnitAbsence(_)))
                | (Listing::Fails, Err(RestartReconciliationError::Units(_)))
                | (Listing::Hangs, Err(RestartReconciliationError::DeadlineElapsed)) => true,
                _ => false,
            };
            assert!(refused, "{result:?}");
            assert_eq!(network.calls.load(Ordering::SeqCst), 0);
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn failed_network_or_device_proof_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::failed_network_or_device_proof_keeps_admission_closed",
        )? {
            return Ok(());
        }
        // Network failure, network deadline, devices present, devices unverified.
        for case in 0..4 {
            let runtime = seed(true)?;
            let host = host(Listing::Empty, Vec::new()).await?;
            let cleanup = [
                Cleanup::Fails,
                Cleanup::Hangs,
                Cleanup::Removes,
                Cleanup::Removes,
            ][case];
            let network = Network::new(cleanup);
            let result = reconcile_with(
                &host.transport,
                recovery(runtime.path())?,
                &network,
                deadline(),
                |_| {
                    std::future::ready(
                        [
                            Ok(false),
                            Err(ImageActivationError::ResourceAbsenceUnverified),
                        ][usize::from(case == 3)],
                    )
                },
            )
            .await;
            let refused = matches!(
                (case, &result),
                (0, Err(RestartReconciliationError::Network(_)))
                    | (1, Err(RestartReconciliationError::DeadlineElapsed))
                    | (2, Err(RestartReconciliationError::Devices(None)))
                    | (3, Err(RestartReconciliationError::Devices(Some(_))))
            );
            assert!(refused, "case {case}: {result:?}");
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_device_probe_past_the_deadline_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_device_probe_past_the_deadline_keeps_admission_closed",
        )? {
            return Ok(());
        }
        let runtime = seed(true)?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let result = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
            |_| std::future::pending::<Result<bool, ImageActivationError>>(),
        )
        .await;
        assert!(
            matches!(result, Err(RestartReconciliationError::DeadlineElapsed)),
            "{result:?}"
        );
        assert_untouched(runtime.path(), 5)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_unit_start_without_a_bound_cgroup_waits_for_its_unit_to_be_absent() -> TestResult {
        if !in_lock_test_process(
        "restart::tests::cases::a_unit_start_without_a_bound_cgroup_waits_for_its_unit_to_be_absent",
    )? {
        return Ok(());
    }
        let runtime = seed_with(Some(started_without_cgroup))?;
        // The unit that the requested start may have created is still loaded:
        // nothing is removed and admission stays closed.
        let host_with_unit = host(Listing::Surviving, vec![unit(ROOT_ATTEMPT)?]).await?;
        let result = reconcile_with(
            &host_with_unit.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
            |_| std::future::ready(Ok(true)),
        )
        .await;
        assert!(
            matches!(result, Err(RestartReconciliationError::SurvivingUnit(_))),
            "{result:?}"
        );
        assert_untouched(runtime.path(), 5)?;
        // Once the unit is absent, the next restart removes the attempt with
        // its intent last.
        let host = host(Listing::Empty, Vec::new()).await?;
        let reconciled = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
            |_| std::future::ready(Ok(true)),
        )
        .await?;
        assert_eq!(reconciled.attempts().len(), 4);
        assert_eq!(count(&runtime.path().join("registry"))?, 0);
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_registry_contradiction_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_registry_contradiction_keeps_admission_closed",
        )? {
            return Ok(());
        }
        let runtime = seed(true)?;
        // A directory that no committed intent owns.
        private_directory(
            &runtime
                .path()
                .join("attempts")
                .join(intent(8)?.unit_name().attempt_component()),
        )?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let result = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
            |_| std::future::ready(Ok(true)),
        )
        .await;
        assert!(
            matches!(result, Err(RestartReconciliationError::Registry(_))),
            "{result:?}"
        );
        assert_eq!(count(&runtime.path().join("registry"))?, 5);
        Ok(())
    }
}
