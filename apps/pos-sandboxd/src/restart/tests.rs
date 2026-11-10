//! Restart reconciliation over a fake systemd manager and the real registry.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::fs::{self, File};
    use std::io;
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
    type RootEnding = fn(PreparedAttemptDirectory);

    /// The execution requested its unit start but failed before binding the
    /// unit's cgroup, so the live owner's cleanup is refused and the intent is
    /// left for restart reconciliation.
    fn started_without_cgroup(prepared: PreparedAttemptDirectory) {
        let ownership = prepared.execution_ownership();
        let started = ownership.claim().and_then(|()| ownership.submit());
        let refused = prepared.finish_terminal_cleanup(AttemptUnitTermination::Unsubmitted, None);
        assert!(
            started.is_ok() && matches!(refused, Err(SystemdAttemptRegistryError::CleanupEvidence)),
            "{started:?} {refused:?}"
        );
    }

    /// 1 planned only; 2 the recorded tree; 3 its root removed but its attempt
    /// directory present (#721); 4 a recorded PAI3 root, unmounted; 5 an
    /// interrupted temporary write. With `with_root` false, attempt 4 is omitted.
    fn seed(with_root: bool) -> TestResult<tempfile::TempDir> {
        // The owner crashed with the recorded attempt still prepared.
        seed_with(with_root.then_some::<RootEnding>(drop))
    }

    /// `seed`, with attempt 4 left by `root`, if any.
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
            ending(prepared);
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
        // The last request was sent on another boot: no wait.
        mark(runtime.path(), OTHER_BOOT, 5)?;
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

    /// A provider loop sweep that finds no loop over a provider image.
    fn swept() -> impl Fn() -> std::future::Ready<Result<bool, ImageActivationError>> + Sync {
        || std::future::ready(Ok(true))
    }

    /// The boot the seeded activation marker was not written on.
    const THIS_BOOT: [u8; 16] = [0x11; 16];
    /// The boot of the seeded activation marker.
    const OTHER_BOOT: [u8; 16] = [0xee; 16];

    /// This boot's clock, 100 s after it started.
    fn this_boot() -> impl FnOnce() -> io::Result<BootInstant> {
        || Ok((THIS_BOOT, Duration::from_secs(100)))
    }

    /// Replace the registry's activation marker: a request sent on `boot`,
    /// `seconds` after it started. An independent PAA1 byte oracle.
    fn mark(runtime: &Path, boot: [u8; 16], seconds: u64) -> TestResult {
        let path = runtime.join("registry").join("activation");
        let bytes = [
            b"PAA1".as_slice(),
            &boot,
            &seconds.to_le_bytes(),
            &0_u64.to_le_bytes(),
        ]
        .concat();
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_millis(500)
    }

    /// After a refused reconciliation nothing was removed; the activation
    /// marker is always kept.
    fn assert_untouched(runtime: &Path, records: usize) -> TestResult {
        assert_eq!(count(&runtime.join("registry"))?, records + 1);
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
        let sweeps = AtomicUsize::new(0);
        let reconciled = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            &network,
            deadline(),
            (
                |generations| {
                    let pushed = probed.lock().map(|mut probed| probed.push(generations));
                    std::future::ready(
                        pushed
                            .map(|()| true)
                            .map_err(|_| ImageActivationError::Transport),
                    )
                },
                || {
                    sweeps.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(true))
                },
                this_boot(),
            ),
        )
        .await?;
        let expected = (1..=4).map(intent).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(reconciled.attempts(), expected.as_slice());
        // Only the activation marker remains in the registry.
        assert_eq!(count(&runtime.path().join("registry"))?, 1);
        assert!(runtime.path().join("registry/activation").is_file());
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        assert_eq!(network.calls.load(Ordering::SeqCst), 1);
        assert_eq!(sweeps.load(Ordering::SeqCst), 1);
        assert_eq!(
            *probed.lock().map_err(|_| "probes")?,
            vec![FIXTURE_GENERATIONS]
        );
        // The temporary write's unit is checked first: its name sorts first.
        let mut names = (1..=5).map(unit).collect::<Result<Vec<_>, _>>()?;
        names.rotate_right(1);
        assert_eq!(*host.lookups.lock().map_err(|_| "lookups")?, names);
        // Admission can reopen: a new owner commits beside the marker.
        let parent = File::open(runtime.path())?;
        SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?
            .commit_planned(&intent(9)?)?;
        Ok(())
    }

    #[tokio::test]
    async fn the_public_entry_removes_all_or_nothing() -> TestResult {
        if !in_lock_test_process("restart::tests::cases::the_public_entry_removes_all_or_nothing")?
        {
            return Ok(());
        }
        let runtime = seed(false)?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let result = reconcile_restart(
            &host.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
        )
        .await;
        // The real host's loop sweep decides; a host without a provider
        // installation cannot resolve the image directory and fails closed.
        let reconciled = result
            .as_ref()
            .is_ok_and(|reconciled| reconciled.attempts().len() == 3);
        let removed = count(&runtime.path().join("registry"))? == 1;
        assert_eq!(removed, reconciled, "{result:?}");
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
                (
                    |_| {
                        std::future::ready(
                            [
                                Ok(false),
                                Err(ImageActivationError::ResourceAbsenceUnverified),
                            ][usize::from(case == 3)],
                        )
                    },
                    swept(),
                    this_boot(),
                ),
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
            (
                |_| std::future::pending::<Result<bool, ImageActivationError>>(),
                swept(),
                this_boot(),
            ),
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
    async fn an_unbound_unit_start_waits_for_unit_absence() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::an_unbound_unit_start_waits_for_unit_absence",
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
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
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
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
        )
        .await?;
        assert_eq!(reconciled.attempts().len(), 4);
        assert_eq!(count(&runtime.path().join("registry"))?, 1);
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_provider_loop_or_an_unverifiable_sweep_keeps_pai2_intents() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_provider_loop_or_an_unverifiable_sweep_keeps_pai2_intents",
        )? {
            return Ok(());
        }
        // Without a recorded root, only the sweep can prove that an activation
        // which crashed before its PAI3 record left no loop/dm devices.
        for unverified in [false, true] {
            let runtime = seed(false)?;
            let host = host(Listing::Empty, Vec::new()).await?;
            let result = reconcile_with(
                &host.transport,
                recovery(runtime.path())?,
                &Network::new(Cleanup::Removes),
                deadline(),
                (
                    |_| std::future::ready(Ok(true)),
                    || {
                        std::future::ready(
                            [
                                Ok(false),
                                Err(ImageActivationError::ResourceAbsenceUnverified),
                            ][usize::from(unverified)],
                        )
                    },
                    this_boot(),
                ),
            )
            .await;
            let refused = matches!(
                (unverified, &result),
                (false, Err(RestartReconciliationError::ProviderLoops(None)))
                    | (
                        true,
                        Err(RestartReconciliationError::ProviderLoops(Some(_)))
                    )
            );
            assert!(refused, "unverified {unverified}: {result:?}");
            assert_untouched(runtime.path(), 4)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_loop_sweep_past_the_deadline_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_loop_sweep_past_the_deadline_keeps_admission_closed",
        )? {
            return Ok(());
        }
        let runtime = seed(false)?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let result = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            &Network::new(Cleanup::Removes),
            deadline(),
            (
                |_| std::future::ready(Ok(true)),
                std::future::pending::<Result<bool, ImageActivationError>>,
                this_boot(),
            ),
        )
        .await;
        assert!(
            matches!(result, Err(RestartReconciliationError::DeadlineElapsed)),
            "{result:?}"
        );
        assert_untouched(runtime.path(), 4)?;
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
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
        )
        .await;
        assert!(
            matches!(result, Err(RestartReconciliationError::Registry(_))),
            "{result:?}"
        );
        assert_eq!(count(&runtime.path().join("registry"))?, 6);
        Ok(())
    }

    /// The sweep after the wait: passes, passes within the time the deadline
    /// left, finds a provider loop, or hangs.
    #[derive(Clone, Copy, Debug)]
    enum Resweep {
        Passes,
        Slow,
        Finds,
        Hangs,
    }

    /// Sweep times, the first sweep behaving as `resweep`.
    async fn timed_sweep(
        sweeps: &Mutex<Vec<Instant>>,
        resweep: Resweep,
    ) -> Result<bool, ImageActivationError> {
        let swept = sweeps
            .lock()
            .map(|mut sweeps| {
                sweeps.push(Instant::now());
                sweeps.len()
            })
            .ok();
        match (swept, resweep) {
            (Some(1), Resweep::Hangs) => std::future::pending().await,
            (Some(1), Resweep::Slow) => {
                tokio::time::sleep(Duration::from_millis(400)).await;
                Ok(true)
            }
            (Some(1), Resweep::Finds) => Ok(false),
            (Some(_), _) => Ok(true),
            (None, _) => Err(ImageActivationError::Transport),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_recent_request_of_this_boot_is_waited_out_before_the_sweep() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_recent_request_of_this_boot_is_waited_out_before_the_sweep",
        )? {
            return Ok(());
        }
        for resweep in [
            Resweep::Passes,
            Resweep::Slow,
            Resweep::Finds,
            Resweep::Hangs,
        ] {
            // PAI2 intents, and a request sent on this boot 10 s ago.
            let runtime = seed(false)?;
            mark(runtime.path(), THIS_BOOT, 90)?;
            let recovery = recovery(runtime.path())?;
            let sweeps = Mutex::new(Vec::new());
            let start = Instant::now();
            let released = roots_released(
                &recovery,
                (
                    |_| std::future::ready(Ok(true)),
                    || timed_sweep(&sweeps, resweep),
                    this_boot(),
                ),
                start + Duration::from_millis(500),
            )
            .await;
            let outcome = matches!(
                (resweep, &released),
                (Resweep::Passes | Resweep::Slow, Ok(_))
                    | (
                        Resweep::Finds,
                        Err(RestartReconciliationError::ProviderLoops(None))
                    )
                    | (
                        Resweep::Hangs,
                        Err(RestartReconciliationError::DeadlineElapsed)
                    )
            );
            assert!(outcome, "{resweep:?}: {released:?}");
            // The only sweep runs exactly when the 60 s activator deadline and
            // the 10 s server margin have passed.
            let times = sweeps.lock().map_err(|_| "sweeps")?.clone();
            assert_eq!(times, vec![start + Duration::from_mins(1)]);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_of_another_boot_or_past_its_deadline_needs_no_wait() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_request_of_another_boot_or_past_its_deadline_needs_no_wait",
        )? {
            return Ok(());
        }
        // No request yet, another boot 1 s ago, and this boot exactly 70 s
        // and 90 s ago.
        for (boot, seconds) in [
            ([0; 16], 0),
            (OTHER_BOOT, 99),
            (THIS_BOOT, 30),
            (THIS_BOOT, 10),
        ] {
            let runtime = seed(false)?;
            mark(runtime.path(), boot, seconds)?;
            let recovery = recovery(runtime.path())?;
            let sweeps = Mutex::new(Vec::new());
            let start = Instant::now();
            roots_released(
                &recovery,
                (
                    |_| std::future::ready(Ok(true)),
                    || timed_sweep(&sweeps, Resweep::Passes),
                    this_boot(),
                ),
                start + Duration::from_millis(500),
            )
            .await?;
            assert_eq!(*sweeps.lock().map_err(|_| "sweeps")?, vec![start]);
            assert_eq!(Instant::now(), start);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_past_the_latest_instant_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_wait_past_the_latest_instant_keeps_admission_closed",
        )? {
            return Ok(());
        }
        // A request sent on this boot 10 s ago, and a deadline so late that
        // no wait fits after it.
        let runtime = seed(false)?;
        mark(runtime.path(), THIS_BOOT, 90)?;
        let latest = (0..64).rev().fold(Instant::now(), |at, bit| {
            at.checked_add(Duration::from_secs(1 << bit)).unwrap_or(at)
        });
        let released = roots_released(
            &recovery(runtime.path())?,
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
            latest,
        )
        .await;
        assert!(
            matches!(released, Err(RestartReconciliationError::DeadlineElapsed)),
            "{released:?}"
        );
        assert_untouched(runtime.path(), 4)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_future_or_malformed_marker_or_an_unread_clock_fails_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_missing_future_or_malformed_marker_or_an_unread_clock_fails_closed",
        )? {
            return Ok(());
        }
        let registry = |result: &Reconciled<RootsReleased>| match result {
            Err(RestartReconciliationError::Registry(error)) => Some(error.to_string()),
            _ => None,
        };
        // PAI2 intents without any marker.
        let runtime = seed(false)?;
        fs::remove_file(runtime.path().join("registry/activation"))?;
        let missing = roots_released(
            &recovery(runtime.path())?,
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
            deadline(),
        )
        .await;
        assert_eq!(
            registry(&missing),
            Some(SystemdAttemptRegistryError::ActivationMarker.to_string())
        );
        // A request in this boot's future.
        mark(runtime.path(), THIS_BOOT, 101)?;
        let future = roots_released(
            &recovery(runtime.path())?,
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
            deadline(),
        )
        .await;
        assert_eq!(registry(&future), registry(&missing));
        // An unreadable boot ID or clock.
        let unread = roots_released(
            &recovery(runtime.path())?,
            (
                |_| std::future::ready(Ok(true)),
                swept(),
                || Err(io::Error::other("no boot ID")),
            ),
            deadline(),
        )
        .await;
        assert_eq!(registry(&unread), Some("no boot ID".to_owned()));
        // A malformed marker never enters the recovery inventory.
        fs::write(runtime.path().join("registry/activation"), b"PAA1")?;
        assert!(matches!(
            recovery(runtime.path()).map_err(|error| error.to_string()),
            Err(message) if message == SystemdAttemptRegistryError::InvalidIntent.to_string()
        ));
        assert_untouched(runtime.path(), 4)?;
        Ok(())
    }
}
