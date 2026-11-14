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
    use crate::test_fixtures::{in_lock_test_process, peer_connections, FakeRecoveredRoots};
    use crate::{
        AttemptCleanupDeadlines, AttemptShutdownDeadlines, AttemptUnitTermination,
        PreparedAttemptDirectory, SystemdAttemptRegistry,
    };

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

    /// The unit names the fake manager has loaded.
    type Loaded = Arc<Mutex<Vec<String>>>;

    /// Lists units by `listing`; `GetUnit` finds only the `loaded` names.
    struct Manager {
        subscriptions: AtomicUsize,
        listing: Listing,
        loaded: Loaded,
        lookups: Arc<Mutex<Vec<String>>>,
        resets: Loaded,
    }

    /// The service object of a failed unit whose cgroup systemd removed.
    struct FailedService(String);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl FailedService {
        #[zbus(property, name = "ControlGroup")]
        fn control_group(&self) -> String {
            self.0.clone()
        }
    }

    /// The unit object of a failed unit.
    struct FailedUnit(String);

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl FailedUnit {
        #[zbus(property, name = "ActiveState")]
        fn active_state(&self) -> String {
            self.0.clone()
        }
    }

    fn loaded_names(loaded: &Loaded) -> fdo::Result<Vec<String>> {
        loaded
            .lock()
            .map(|names| names.clone())
            .map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    /// Each loaded unit's own object path, named by its attempt component.
    fn unit_path(name: &str) -> TestResult<OwnedObjectPath> {
        let component = name
            .strip_prefix("pigloros-attempt-")
            .and_then(|rest| rest.strip_suffix(".service"))
            .ok_or("not an attempt unit")?;
        Ok(OwnedObjectPath::try_from(format!(
            "/org/freedesktop/systemd1/unit/survivor_{component}"
        ))?)
    }

    fn row(name: &str) -> TestResult<UnitRow> {
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

        async fn list_units_by_patterns(
            &self,
            states: Vec<String>,
            patterns: Vec<String>,
        ) -> fdo::Result<Vec<UnitRow>> {
            drop((states, patterns));
            match self.listing {
                Listing::Empty => Ok(Vec::new()),
                Listing::Surviving => loaded_names(&self.loaded)?
                    .iter()
                    .map(|name| row(name).map_err(|error| fdo::Error::Failed(error.to_string())))
                    .collect(),
                Listing::Fails => Err(fdo::Error::AccessDenied("listing denied".to_owned())),
                Listing::Hangs => std::future::pending().await,
            }
        }

        /// Clearing the failed state unloads the unit.
        fn reset_failed_unit(&self, name: &str) -> fdo::Result<()> {
            self.resets
                .lock()
                .map_err(|error| fdo::Error::Failed(error.to_string()))?
                .push(name.to_owned());
            self.loaded
                .lock()
                .map_err(|error| fdo::Error::Failed(error.to_string()))?
                .retain(|loaded| loaded != name);
            Ok(())
        }

        fn get_unit(&self, name: String) -> Result<OwnedObjectPath, BoxDBusError> {
            self.lookups
                .lock()
                .map_err(|error| fdo::Error::Failed(error.to_string()))?
                .push(name.clone());
            if loaded_names(&self.loaded)?.contains(&name) {
                unit_path(&name).map_err(|error| fdo::Error::Failed(error.to_string()).into())
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

    /// The network steps in the order they ran, each with the number of
    /// registry entries it saw: admission is still closed while all remain.
    type Steps = Arc<Mutex<Vec<(&'static str, usize)>>>;

    /// Record `step` in `log`, if there is one, with the registry it saw.
    fn log_step(log: Option<&(Steps, std::path::PathBuf)>, step: &'static str) {
        if let Some((steps, runtime)) = log {
            let records = count(&runtime.join("registry")).unwrap_or(usize::MAX);
            steps
                .lock()
                .map(|mut steps| steps.push((step, records)))
                .ok();
        }
    }

    struct Network {
        cleanup: Cleanup,
        calls: AtomicUsize,
        log: Option<(Steps, std::path::PathBuf)>,
    }

    impl Network {
        const fn new(cleanup: Cleanup) -> Self {
            Self {
                cleanup,
                calls: AtomicUsize::new(0),
                log: None,
            }
        }
    }

    impl OrphanNetworkCleanup for Network {
        type Error = NetworkFailure;

        async fn remove_orphans(&self) -> Result<(), NetworkFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            log_step(self.log.as_ref(), "network");
            match self.cleanup {
                Cleanup::Removes => Ok(()),
                Cleanup::Fails => Err(NetworkFailure),
                Cleanup::Hangs => std::future::pending().await,
            }
        }
    }

    /// What the fake egress probe observes.
    #[derive(Clone, Copy)]
    enum Property {
        Present,
        /// Forwarded traffic does not pass the host.
        Absent,
        /// Forwarded traffic passes but is not masqueraded.
        Ineffective,
        Hangs,
    }

    struct Egress {
        property: Property,
        calls: AtomicUsize,
        log: Option<(Steps, std::path::PathBuf)>,
    }

    impl Egress {
        const fn new(property: Property) -> Self {
            Self {
                property,
                calls: AtomicUsize::new(0),
                log: None,
            }
        }
    }

    impl EgressPropertyProbe for Egress {
        type Error = crate::EgressProbeError;

        async fn probe_egress(&self) -> Result<(), crate::EgressProbeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            log_step(self.log.as_ref(), "egress");
            match self.property {
                Property::Present => Ok(()),
                Property::Absent => Err(crate::EgressProbeError::Blocked(
                    io::ErrorKind::TimedOut.into(),
                )),
                Property::Ineffective => Err(crate::EgressProbeError::NotMasqueraded),
                Property::Hangs => std::future::pending().await,
            }
        }
    }

    /// An egress probe that observes the property.
    const fn present() -> Egress {
        Egress::new(Property::Present)
    }

    /// An orphan sweep that removes and an egress probe that observes
    /// `property`, both logging into the returned steps what they saw of
    /// `runtime`'s registry.
    fn logged(runtime: &Path, property: Property) -> (Network, Egress, Steps) {
        let steps = Steps::default();
        let log = Some((Arc::clone(&steps), runtime.to_path_buf()));
        let network = Network {
            log: log.clone(),
            ..Network::new(Cleanup::Removes)
        };
        let egress = Egress {
            log,
            ..Egress::new(property)
        };
        (network, egress, steps)
    }

    struct Host {
        _server: zbus::Connection,
        transport: SystemdTransientUnitTransport,
        lookups: Arc<Mutex<Vec<String>>>,
        loaded: Loaded,
        resets: Loaded,
    }

    async fn host(listing: Listing, loaded: Vec<String>) -> TestResult<Host> {
        host_with_failed(listing, loaded, &[]).await
    }

    /// A fake manager whose `failed` units are failed with no cgroup.
    async fn host_with_failed(
        listing: Listing,
        loaded: Vec<String>,
        failed: &[String],
    ) -> TestResult<Host> {
        let lookups = Arc::new(Mutex::new(Vec::new()));
        let loaded = Arc::new(Mutex::new(loaded));
        let resets = Arc::new(Mutex::new(Vec::new()));
        let manager = Manager {
            subscriptions: AtomicUsize::new(0),
            listing,
            loaded: Arc::clone(&loaded),
            lookups: Arc::clone(&lookups),
            resets: Arc::clone(&resets),
        };
        let paths = failed
            .iter()
            .map(|name| unit_path(name))
            .collect::<TestResult<Vec<_>>>()?;
        let (server, client) = peer_connections(|server| {
            paths.into_iter().fold(
                server.serve_at("/org/freedesktop/systemd1", manager),
                |server, path| {
                    server
                        .serve_at(path.as_str().to_owned(), FailedService(String::new()))
                        .serve_at(path.as_str().to_owned(), FailedUnit("failed".to_owned()))
                },
            )
        })
        .await?;
        let transport = SystemdTransientUnitTransport::from_connection(client).await?;
        Ok(Host {
            _server: server,
            transport,
            lookups,
            loaded,
            resets,
        })
    }

    /// How a fake surviving-resource step ends.
    #[derive(Clone, Copy, Debug)]
    enum Outcome {
        Succeeds,
        Fails,
        Hangs,
    }

    /// Fake unit stops and root detaches, recording what they were asked.
    /// A successful stop unloads the unit from the fake manager.
    struct FakeSurvivors {
        stop: Outcome,
        detach: Outcome,
        loaded: Loaded,
        stopped: Mutex<Vec<String>>,
        detached: Mutex<Vec<[u8; 16]>>,
    }

    impl FakeSurvivors {
        fn new(host: &Host, stop: Outcome, detach: Outcome) -> Self {
            Self {
                stop,
                detach,
                loaded: Arc::clone(&host.loaded),
                stopped: Mutex::new(Vec::new()),
                detached: Mutex::new(Vec::new()),
            }
        }

        /// Both steps succeed.
        fn succeeding(host: &Host) -> Self {
            Self::new(host, Outcome::Succeeds, Outcome::Succeeds)
        }

        fn stopped(&self) -> TestResult<Vec<String>> {
            Ok(self.stopped.lock().map_err(|_| "stops")?.clone())
        }

        fn detached(&self) -> TestResult<Vec<[u8; 16]>> {
            Ok(self.detached.lock().map_err(|_| "detaches")?.clone())
        }
    }

    impl Survivors for FakeSurvivors {
        async fn stop(
            &self,
            unit: &SystemdAttemptUnitObservation,
            _: AttemptShutdownDeadlines,
            _: Instant,
        ) -> Result<(), SystemdAttemptUnitTeardownError> {
            let name = unit.unit_name().as_str().to_owned();
            let poisoned = || SystemdAttemptUnitTeardownError::InvalidDeadlines;
            self.stopped
                .lock()
                .map_err(|_| poisoned())?
                .push(name.clone());
            match self.stop {
                Outcome::Succeeds => {
                    self.loaded
                        .lock()
                        .map_err(|_| poisoned())?
                        .retain(|loaded| *loaded != name);
                    Ok(())
                }
                Outcome::Fails => Err(SystemdAttemptUnitTeardownError::DeadlineElapsed),
                Outcome::Hangs => std::future::pending().await,
            }
        }

        async fn detach(
            &self,
            entry: RecordedRootEntry,
            _: Instant,
        ) -> Result<(), ImageActivationError> {
            self.detached
                .lock()
                .map_err(|_| ImageActivationError::Transport)?
                .push(entry.intent.planned().attempt_id());
            match self.detach {
                Outcome::Succeeds => Ok(()),
                Outcome::Fails => Err(ImageActivationError::EvidenceMismatch),
                Outcome::Hangs => std::future::pending().await,
            }
        }
    }

    /// Unit shutdown, unit absence and root release within the deadline.
    fn cleanup() -> TestResult<AttemptCleanupDeadlines> {
        let now = Instant::now();
        Ok(AttemptCleanupDeadlines::new(
            AttemptShutdownDeadlines::new(
                now + Duration::from_millis(100),
                now + Duration::from_millis(200),
                now + Duration::from_millis(300),
            )?,
            now + Duration::from_millis(400),
            now + Duration::from_millis(450),
        )?)
    }

    /// The cleanup and overall deadlines.
    fn deadlines() -> TestResult<(AttemptCleanupDeadlines, Instant)> {
        Ok((cleanup()?, deadline()))
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
        drop(
            registry
                .commit_planned(&intent(2)?)?
                .prepare_fixture_directory()?,
        );
        drop(
            registry
                .commit_planned(&intent(3)?)?
                .prepare_fixture_directory()?,
        );
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
                .prepare_fixture_directory()?;
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

    /// The public entry's sweep is deterministic only on a host without a
    /// provider installation, as every test host is: the staged installation
    /// fixtures refuse to adopt one.
    fn assert_no_installation() {
        assert!(
            !Path::new(pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT)
                .join("images")
                .exists(),
            "the test host carries a provider installation"
        );
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
        let (network, egress, steps) = logged(runtime.path(), Property::Present);
        let recovered = recovery(runtime.path())?;
        let records = count(&runtime.path().join("registry"))?;
        let probed = Mutex::new(Vec::new());
        let sweeps = AtomicUsize::new(0);
        let survivors = FakeSurvivors::succeeding(&host);
        let reconciled = reconcile_with(
            &host.transport,
            recovered,
            (&network, &egress),
            &survivors,
            deadlines()?,
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
        // The orphan sweep, then the egress probe, each ran once while every
        // record was kept, so admission was still closed.
        assert_eq!(
            *steps.lock().map_err(|_| "steps")?,
            vec![("network", records), ("egress", records)]
        );
        assert_eq!(sweeps.load(Ordering::SeqCst), 1);
        // No unit was listed; the recorded tree's and the PAI3 attempt's
        // roots were checked for a mount, and attempt 3 has no root left.
        assert!(survivors.stopped()?.is_empty());
        assert_eq!(survivors.detached()?, vec![[2; 16], [ROOT_ATTEMPT; 16]]);
        assert_eq!(
            *probed.lock().map_err(|_| "probes")?,
            vec![FIXTURE_GENERATIONS]
        );
        // The temporary write's unit is checked first: its name sorts first.
        let mut names = (1..=5).map(unit).collect::<Result<Vec<_>, _>>()?;
        names.rotate_right(1);
        assert_eq!(*host.lookups.lock().map_err(|_| "lookups")?, names);
        // Admission can reopen: a new owner commits beside the marker, and
        // a fresh staging ledger grants again under the new lifecycle.
        let parent = File::open(runtime.path())?;
        let registry =
            SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        registry.commit_planned(&intent(9)?)?;
        let ledger = crate::StagingLedger::new(crate::StagingLimits {
            aggregate_bytes: 1024,
        });
        let _lifecycle: crate::AttemptLifecycle =
            crate::AttemptLifecycle::new(registry, ledger.clone(), &reconciled);
        ledger.reserve_storage(0)?;
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
            (&Network::new(Cleanup::Removes), &present()),
            cleanup()?,
            deadline(),
        )
        .await;
        // The real host's loop sweep decides: a test host without a provider
        // installation cannot resolve the image directory and fails closed.
        assert_no_installation();
        assert!(
            matches!(
                result,
                Err(RestartReconciliationError::ProviderLoops(Some(
                    ImageActivationError::ResourceAbsenceUnverified
                )))
            ),
            "{result:?}"
        );
        assert_untouched(runtime.path(), 4)?;
        Ok(())
    }

    #[tokio::test]
    async fn the_public_entry_stops_a_failed_unit_and_checks_each_root() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::the_public_entry_stops_a_failed_unit_and_checks_each_root",
        )? {
            return Ok(());
        }
        // Attempt 2's recorded unit survived as a failed unit whose cgroup
        // systemd removed (owner decision A).
        let runtime = seed(false)?;
        let host = host_with_failed(Listing::Surviving, vec![unit(2)?], &[unit(2)?]).await?;
        let network = Network::new(Cleanup::Removes);
        let egress = present();
        let result = reconcile_restart(
            &host.transport,
            recovery(runtime.path())?,
            (&network, &egress),
            cleanup()?,
            deadline(),
        )
        .await;
        // The host reset the unit and observed it unloaded, and found the
        // recorded roots unmounted on the real kernel; the network was then
        // cleaned and the egress property observed. The real host's loop
        // sweep then fails closed on a test host without a provider
        // installation.
        assert_eq!(*host.resets.lock().map_err(|_| "resets")?, vec![unit(2)?]);
        assert!(host.loaded.lock().map_err(|_| "loaded")?.is_empty());
        assert_eq!(network.calls.load(Ordering::SeqCst), 1);
        assert_eq!(egress.calls.load(Ordering::SeqCst), 1);
        assert_no_installation();
        assert!(
            matches!(
                result,
                Err(RestartReconciliationError::ProviderLoops(Some(
                    ImageActivationError::ResourceAbsenceUnverified
                )))
            ),
            "{result:?}"
        );
        assert_untouched(runtime.path(), 4)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_surviving_unit_and_a_mounted_root_are_released_before_any_removal() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_surviving_unit_and_a_mounted_root_are_released_before_any_removal",
        )? {
            return Ok(());
        }
        // Attempt 2's recorded unit survived failed, its cgroup removed by
        // systemd (owner decision A), and attempt 4's PAI3 provider root is
        // still mounted on its attempt directory.
        let runtime = seed(true)?;
        let host = host_with_failed(Listing::Surviving, vec![unit(2)?], &[unit(2)?]).await?;
        // The public entry's host wiring, with restart detachment over a
        // fake kernel in place of the host kernel.
        let roots = FakeRecoveredRoots::mounted_on([ROOT_ATTEMPT; 16]);
        let fake_roots = &roots;
        let survivors = super::super::Host {
            transport: &host.transport,
            detach: move |entry, deadline| fake_roots.detach(entry, deadline),
        };
        let network = Network::new(Cleanup::Removes);
        let probed = Mutex::new(Vec::new());
        // Whether every record and directory was still present at the last
        // proof, the provider loop sweep.
        let kept_until_swept = Mutex::new(None);
        let reconciled = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            (&network, &present()),
            &survivors,
            deadlines()?,
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
                    let kept = assert_untouched(runtime.path(), 5).is_ok();
                    let recorded = kept_until_swept.lock().map(|mut swept| *swept = Some(kept));
                    std::future::ready(
                        recorded
                            .map(|()| true)
                            .map_err(|_| ImageActivationError::Transport),
                    )
                },
                this_boot(),
            ),
        )
        .await?;
        // The unit was reset and observed unloaded. Only attempt 4's root was
        // mounted, and only it was detached; its devices were then probed.
        assert_eq!(*host.resets.lock().map_err(|_| "resets")?, vec![unit(2)?]);
        assert!(host.loaded.lock().map_err(|_| "loaded")?.is_empty());
        assert_eq!(
            roots.detached()?,
            vec![([2; 16], 0), ([ROOT_ATTEMPT; 16], 1)]
        );
        assert_eq!(network.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *probed.lock().map_err(|_| "probes")?,
            vec![FIXTURE_GENERATIONS]
        );
        assert_eq!(*kept_until_swept.lock().map_err(|_| "sweep")?, Some(true));
        // Every attempt was then removed, each intent after its directories:
        // only the activation marker remains.
        let expected = (1..=4).map(intent).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(reconciled.attempts(), expected.as_slice());
        assert_eq!(count(&runtime.path().join("registry"))?, 1);
        assert!(runtime.path().join("registry/activation").is_file());
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_surviving_unlisted_or_unobservable_unit_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
        "restart::tests::cases::a_surviving_unlisted_or_unobservable_unit_keeps_admission_closed",
    )? {
        return Ok(());
    }
        // A listed recorded unit that cannot be bound is covered at the
        // unit-teardown seam; here attempt 2's unit is still loaded but not
        // listed, or the listing fails or hangs.
        for listing in [Listing::Empty, Listing::Fails, Listing::Hangs] {
            let runtime = seed(true)?;
            let host = host(listing, vec![unit(2)?]).await?;
            let network = Network::new(Cleanup::Removes);
            let result = reconcile_restart(
                &host.transport,
                recovery(runtime.path())?,
                (&network, &present()),
                cleanup()?,
                deadline(),
            )
            .await;
            let refused = matches!(
                (listing, &result),
                (
                    Listing::Empty,
                    Err(RestartReconciliationError::UnitAbsence(
                        SystemdTransientUnitTransportError::UnitAbsenceDeadlineElapsed
                    ))
                ) | (
                    Listing::Fails,
                    Err(RestartReconciliationError::Units(
                        SystemdTransientUnitTransportError::InventoryCall(_)
                    ))
                ) | (
                    Listing::Hangs,
                    Err(RestartReconciliationError::DeadlineElapsed)
                )
            );
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
            let egress = present();
            let result = reconcile_with(
                &host.transport,
                recovery(runtime.path())?,
                (&network, &egress),
                &FakeSurvivors::succeeding(&host),
                deadlines()?,
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
                (0, Err(RestartReconciliationError::Network(error)))
                    if error.is::<NetworkFailure>()
            ) || matches!(
                (case, &result),
                (1, Err(RestartReconciliationError::DeadlineElapsed))
                    | (2, Err(RestartReconciliationError::Devices(None)))
                    | (
                        3,
                        Err(RestartReconciliationError::Devices(Some(
                            ImageActivationError::ResourceAbsenceUnverified
                        )))
                    )
            );
            assert!(refused, "case {case}: {result:?}");
            // The egress property is probed only on a network swept clean.
            assert_eq!(
                egress.calls.load(Ordering::SeqCst),
                usize::from(case >= 2),
                "case {case}"
            );
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_absent_ineffective_or_late_egress_property_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::an_absent_ineffective_or_late_egress_property_keeps_admission_closed",
        )? {
            return Ok(());
        }
        for property in [Property::Absent, Property::Ineffective, Property::Hangs] {
            let runtime = seed(true)?;
            let host = host(Listing::Empty, Vec::new()).await?;
            let (network, egress, steps) = logged(runtime.path(), property);
            let recovered = recovery(runtime.path())?;
            let records = count(&runtime.path().join("registry"))?;
            let devices = AtomicUsize::new(0);
            let result = reconcile_with(
                &host.transport,
                recovered,
                (&network, &egress),
                &FakeSurvivors::succeeding(&host),
                deadlines()?,
                (
                    |_| {
                        devices.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(true))
                    },
                    swept(),
                    this_boot(),
                ),
            )
            .await;
            let refused = match (property, &result) {
                (Property::Absent, Err(RestartReconciliationError::Egress(error))) => matches!(
                    error.downcast_ref::<crate::EgressProbeError>(),
                    Some(crate::EgressProbeError::Blocked(_))
                ),
                (Property::Ineffective, Err(RestartReconciliationError::Egress(error))) => {
                    matches!(
                        error.downcast_ref::<crate::EgressProbeError>(),
                        Some(crate::EgressProbeError::NotMasqueraded)
                    )
                }
                (Property::Hangs, Err(RestartReconciliationError::DeadlineElapsed)) => true,
                _ => false,
            };
            assert!(refused, "{result:?}");
            if let Err(error @ RestartReconciliationError::Egress(_)) = &result {
                assert_eq!(
                    error.to_string(),
                    "the Local egress property was not observed"
                );
            }
            // The probe ran on the swept network; no later step ran and
            // every record is kept.
            assert_eq!(
                *steps.lock().map_err(|_| "steps")?,
                vec![("network", records), ("egress", records)]
            );
            assert_eq!(devices.load(Ordering::SeqCst), 0);
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn no_egress_probe_starts_once_the_deadline_has_passed() {
        let egress = present();
        let late = prove_egress(&egress, Instant::now()).await;
        assert!(
            matches!(late, Err(RestartReconciliationError::DeadlineElapsed)),
            "{late:?}"
        );
        assert_eq!(egress.calls.load(Ordering::SeqCst), 0);
        // With time left, the probe runs.
        let timely = prove_egress(&egress, Instant::now() + Duration::from_millis(1)).await;
        assert!(timely.is_ok(), "{timely:?}");
        assert_eq!(egress.calls.load(Ordering::SeqCst), 1);
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
            (&Network::new(Cleanup::Removes), &present()),
            &FakeSurvivors::succeeding(&host),
            deadlines()?,
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
    async fn a_surviving_recorded_unit_is_stopped_before_its_attempt_is_removed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_surviving_recorded_unit_is_stopped_before_its_attempt_is_removed",
        )? {
            return Ok(());
        }
        // The execution requested its unit start but failed before binding the
        // unit's cgroup, so the live owner left its intent here. The unit is
        // still loaded, and its stop fails or hangs: nothing is removed.
        let runtime = seed_with(Some(started_without_cgroup))?;
        for outcome in [Outcome::Fails, Outcome::Hangs] {
            let host = host(Listing::Surviving, vec![unit(ROOT_ATTEMPT)?]).await?;
            let survivors = FakeSurvivors::new(&host, outcome, Outcome::Succeeds);
            let network = Network::new(Cleanup::Removes);
            let result = reconcile_with(
                &host.transport,
                recovery(runtime.path())?,
                (&network, &present()),
                &survivors,
                deadlines()?,
                (|_| std::future::ready(Ok(true)), swept(), this_boot()),
            )
            .await;
            let refused = matches!(
                (outcome, &result),
                (
                    Outcome::Fails,
                    Err(RestartReconciliationError::UnitStop(
                        SystemdAttemptUnitTeardownError::DeadlineElapsed
                    )),
                ) | (
                    Outcome::Hangs,
                    Err(RestartReconciliationError::DeadlineElapsed)
                )
            );
            assert!(refused, "{outcome:?}: {result:?}");
            assert_eq!(survivors.stopped()?, vec![unit(ROOT_ATTEMPT)?]);
            assert_eq!(network.calls.load(Ordering::SeqCst), 0);
            assert!(survivors.detached()?.is_empty());
            assert_untouched(runtime.path(), 5)?;
        }
        // A stop that empties and unloads the unit lets the same restart
        // remove every attempt with its intent last.
        let host = host(Listing::Surviving, vec![unit(ROOT_ATTEMPT)?]).await?;
        let survivors = FakeSurvivors::succeeding(&host);
        let reconciled = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            (&Network::new(Cleanup::Removes), &present()),
            &survivors,
            deadlines()?,
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
        )
        .await?;
        assert_eq!(reconciled.attempts().len(), 4);
        assert_eq!(survivors.stopped()?, vec![unit(ROOT_ATTEMPT)?]);
        assert_eq!(count(&runtime.path().join("registry"))?, 1);
        assert_eq!(count(&runtime.path().join("attempts"))?, 0);
        Ok(())
    }

    /// Cleanup bounds `base` plus 100, 200 and 300 ms of shutdown, then 400 ms
    /// for unit absence and 500 ms for root release, all `offset` later.
    fn cleanup_from(base: Instant, offset: Duration) -> TestResult<AttemptCleanupDeadlines> {
        let at = |millis| base + offset + Duration::from_millis(millis);
        Ok(AttemptCleanupDeadlines::new(
            AttemptShutdownDeadlines::new(at(100), at(200), at(300))?,
            at(400),
            at(500),
        )?)
    }

    #[tokio::test]
    async fn the_overall_deadline_caps_a_hanging_stop_or_detach() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::the_overall_deadline_caps_a_hanging_stop_or_detach",
        )? {
            return Ok(());
        }
        // The overall deadline, 100 ms after setup, comes long before the
        // cleanup's unit and release bounds (at least 5 s), so only it can
        // end a hanging stop or detach. A cleanup bound would also end it
        // with `DeadlineElapsed`; the elapsed bound tells the two apart.
        let runtime = seed_with(Some(started_without_cgroup))?;
        for (stop, detach) in [
            (Outcome::Hangs, Outcome::Succeeds),
            (Outcome::Succeeds, Outcome::Hangs),
        ] {
            let host = host(Listing::Surviving, vec![unit(ROOT_ATTEMPT)?]).await?;
            let survivors = FakeSurvivors::new(&host, stop, detach);
            let network = Network::new(Cleanup::Removes);
            let recovered = recovery(runtime.path())?;
            let started = Instant::now();
            let result = reconcile_with(
                &host.transport,
                recovered,
                (&network, &present()),
                &survivors,
                (
                    cleanup_from(started, Duration::from_secs(5))?,
                    started + Duration::from_millis(100),
                ),
                (|_| std::future::ready(Ok(true)), swept(), this_boot()),
            )
            .await;
            let elapsed = started.elapsed();
            assert!(
                matches!(result, Err(RestartReconciliationError::DeadlineElapsed)),
                "{stop:?}/{detach:?}: {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(3),
                "{stop:?}/{detach:?} ended after {elapsed:?}"
            );
            assert_eq!(survivors.stopped()?, vec![unit(ROOT_ATTEMPT)?]);
            // The hanging detach was entered for both recorded roots; a
            // hanging stop reaches no detach.
            let detached = if matches!(detach, Outcome::Hangs) {
                vec![[2; 16], [ROOT_ATTEMPT; 16]]
            } else {
                Vec::new()
            };
            assert_eq!(survivors.detached()?, detached);
            assert_eq!(network.calls.load(Ordering::SeqCst), 0);
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_hanging_network_cleanup_has_the_overall_budget_after_a_fast_detach() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_hanging_network_cleanup_has_the_overall_budget_after_a_fast_detach",
        )? {
            return Ok(());
        }
        // The roots are released well within the 1.5 s release bound; the
        // network cleanup then hangs and is ended only by the overall
        // deadline, 2.5 s after setup.
        let runtime = seed(true)?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let survivors = FakeSurvivors::succeeding(&host);
        let network = Network::new(Cleanup::Hangs);
        let recovered = recovery(runtime.path())?;
        let started = Instant::now();
        let result = reconcile_with(
            &host.transport,
            recovered,
            (&network, &present()),
            &survivors,
            (
                cleanup_from(started, Duration::from_secs(1))?,
                started + Duration::from_millis(2500),
            ),
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(
            matches!(result, Err(RestartReconciliationError::DeadlineElapsed)),
            "{result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(2500),
            "ended after {elapsed:?}"
        );
        assert_eq!(survivors.detached()?, vec![[2; 16], [ROOT_ATTEMPT; 16]]);
        assert_eq!(network.calls.load(Ordering::SeqCst), 1);
        assert_untouched(runtime.path(), 5)?;
        Ok(())
    }

    #[tokio::test]
    async fn an_unrecorded_or_uncommitted_unit_is_never_stopped() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::an_unrecorded_or_uncommitted_unit_is_never_stopped",
        )? {
            return Ok(());
        }
        // Attempt 8 has no record, and attempt 5 only an interrupted write, so
        // neither unit is positively the previous runtime's. Attempt 2's
        // recorded unit is listed too, and is not stopped either.
        for unrecorded in [8, 5] {
            let runtime = seed(true)?;
            let host = host(Listing::Surviving, vec![unit(2)?, unit(unrecorded)?]).await?;
            let survivors = FakeSurvivors::succeeding(&host);
            let result = reconcile_with(
                &host.transport,
                recovery(runtime.path())?,
                (&Network::new(Cleanup::Removes), &present()),
                &survivors,
                deadlines()?,
                (|_| std::future::ready(Ok(true)), swept(), this_boot()),
            )
            .await;
            let refused = match &result {
                Err(RestartReconciliationError::SurvivingUnit(name)) => {
                    name.as_str() == unit(unrecorded)?
                }
                _ => false,
            };
            assert!(refused, "{unrecorded}: {result:?}");
            assert!(survivors.stopped()?.is_empty());
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_or_late_root_detach_keeps_admission_closed() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_failed_or_late_root_detach_keeps_admission_closed",
        )? {
            return Ok(());
        }
        for outcome in [Outcome::Fails, Outcome::Hangs] {
            let runtime = seed(true)?;
            let host = host(Listing::Empty, Vec::new()).await?;
            let survivors = FakeSurvivors::new(&host, Outcome::Succeeds, outcome);
            let probes = AtomicUsize::new(0);
            let network = Network::new(Cleanup::Removes);
            let result = reconcile_with(
                &host.transport,
                recovery(runtime.path())?,
                (&network, &present()),
                &survivors,
                deadlines()?,
                (
                    |_| {
                        probes.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok(true))
                    },
                    swept(),
                    this_boot(),
                ),
            )
            .await;
            let refused = matches!(
                (outcome, &result),
                (
                    Outcome::Fails,
                    Err(RestartReconciliationError::Root(
                        ImageActivationError::EvidenceMismatch
                    )),
                ) | (
                    Outcome::Hangs,
                    Err(RestartReconciliationError::DeadlineElapsed)
                )
            );
            assert!(refused, "{outcome:?}: {result:?}");
            // Both recorded roots that are present are detached together,
            // before any device is probed.
            assert_eq!(survivors.detached()?, vec![[2; 16], [ROOT_ATTEMPT; 16]]);
            assert_eq!(probes.load(Ordering::SeqCst), 0);
            // Roots are detached before the network cleanup, which never runs.
            assert_eq!(network.calls.load(Ordering::SeqCst), 0);
            assert_untouched(runtime.path(), 5)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_replaced_attempt_directory_is_never_detached() -> TestResult {
        if !in_lock_test_process(
            "restart::tests::cases::a_replaced_attempt_directory_is_never_detached",
        )? {
            return Ok(());
        }
        let runtime = seed(true)?;
        // Attempt 2's directories are replaced by new ones of the same names;
        // the originals are kept so their inodes cannot be reused.
        let attempt = runtime
            .path()
            .join("attempts")
            .join(intent(2)?.unit_name().attempt_component());
        fs::rename(&attempt, runtime.path().join("replaced"))?;
        private_directory(&attempt)?;
        private_directory(&attempt.join("root"))?;
        let host = host(Listing::Empty, Vec::new()).await?;
        let survivors = FakeSurvivors::succeeding(&host);
        let result = reconcile_with(
            &host.transport,
            recovery(runtime.path())?,
            (&Network::new(Cleanup::Removes), &present()),
            &survivors,
            deadlines()?,
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(RestartReconciliationError::Registry(
                    SystemdAttemptRegistryError::UnsafeRegistry
                ))
            ),
            "{result:?}"
        );
        assert!(survivors.detached()?.is_empty());
        assert_untouched(runtime.path(), 5)?;
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
                (&Network::new(Cleanup::Removes), &present()),
                &FakeSurvivors::succeeding(&host),
                deadlines()?,
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
            (&Network::new(Cleanup::Removes), &present()),
            &FakeSurvivors::succeeding(&host),
            deadlines()?,
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
            (&Network::new(Cleanup::Removes), &present()),
            &FakeSurvivors::succeeding(&host),
            deadlines()?,
            (|_| std::future::ready(Ok(true)), swept(), this_boot()),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(RestartReconciliationError::Registry(
                    SystemdAttemptRegistryError::InvalidIntent
                ))
            ),
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
