//! The attempt lifecycle over the real registry, the real terminal cleanup
//! and a fake systemd manager per attempt.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {

    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};

    use pos_reference::sandbox_provider_protocol::{RequestAuthority, SandboxExecutionMode};

    use super::super::*;
    use crate::test_fixtures::{
        authority, checked_root, fake_root_release, release_fake_root, TeardownFixture,
        TeardownReset, TeardownStop, TestResult,
    };
    use crate::{BoundAttemptCgroup, ReleasedAttemptRoot, UnitCgroup};

    const SIM1: [u8; 32] = [9; 32];

    /// How the fake admission activates its root.
    #[derive(Clone, Copy, Debug)]
    enum Activation {
        /// A fixture root whose devices are then observed absent.
        Released,
        /// The same, after the activation yielded to other tasks a few times.
        Slow,
        /// A fixture root whose devices are never observed absent.
        Retained,
        /// Activation fails before any request.
        Refused,
    }

    /// A fake admission of the attempt `[id; 16]`.
    #[derive(Debug)]
    struct FakeInput {
        id: u8,
        attempt: [u8; 16],
        sim1: [u8; 32],
        activation: Activation,
        // A staging reservation the admission holds until it is released.
        charge: Option<crate::StagingCharge>,
        // A run whose cancellation is requested while its directory is
        // prepared, after it started and before anything can be fenced.
        cancel_while_preparing: Option<Arc<std::sync::OnceLock<Arc<RunState>>>>,
        // The admitted facts belong to another directory.
        foreign: bool,
    }

    impl FakeInput {
        const fn new(id: u8) -> Self {
            Self {
                id,
                attempt: [id; 16],
                sim1: SIM1,
                activation: Activation::Released,
                charge: None,
                cancel_while_preparing: None,
                foreign: false,
            }
        }

        /// The attempt numbered `number`, beyond the 255 single-byte ones.
        const fn numbered(number: u16) -> Self {
            let [high, low] = number.to_be_bytes();
            let mut input = Self::new(0);
            input.attempt = [1; 16];
            input.attempt[0] = high;
            input.attempt[1] = low;
            input
        }

        const fn activating(mut self, activation: Activation) -> Self {
            self.activation = activation;
            self
        }
    }

    /// The AGR1 digest of the fake attempt `[id; 16]`.
    const fn grant(id: u8) -> [u8; 32] {
        [id ^ 0xa5; 32]
    }

    /// A fixture root, released through the controller's root port.
    struct FakeRoot(crate::test_fixtures::FakeRootRelease);

    impl RootRelease for FakeRoot {
        fn release(
            self,
            directory: &PreparedAttemptDirectory,
            deadline: Instant,
        ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_
        {
            release_fake_root(self.0, directory, deadline)
        }
    }

    impl AdmittedInput for FakeInput {
        type Root = FakeRoot;

        fn attempt_id(&self) -> [u8; 16] {
            self.attempt
        }

        fn sim1_digest(&self) -> [u8; 32] {
            self.sim1
        }

        fn grant_digest(&self) -> [u8; 32] {
            grant(self.id)
        }

        fn prepare(
            &self,
            planned: CommittedPlannedAttempt,
        ) -> Result<PreparedAttemptDirectory, SystemdAttemptRegistryError> {
            if let Some(state) = self
                .cancel_while_preparing
                .as_ref()
                .and_then(|state| state.get())
            {
                state.cancel();
            }
            planned.prepare_fixture_directory()
        }

        fn activate<'a>(
            &'a self,
            directory: &'a PreparedAttemptDirectory,
        ) -> impl Future<Output = Result<FakeRoot, ImageActivationError>> + Send + 'a {
            let activated = match self.activation {
                Activation::Refused => Err(ImageActivationError::EvidenceMismatch),
                Activation::Released | Activation::Slow | Activation::Retained => {
                    let absent = !matches!(self.activation, Activation::Retained);
                    fake_root_release(directory, absent)
                        .map(FakeRoot)
                        .map_err(|_| ImageActivationError::EvidenceMismatch)
                }
            };
            let slow = matches!(self.activation, Activation::Slow);
            async move {
                for _ in 0..usize::from(slow) * 4 {
                    tokio::task::yield_now().await;
                }
                activated
            }
        }

        fn attempt(
            &self,
            directory: &PreparedAttemptDirectory,
        ) -> Result<AdmittedAttempt, ExecuteError> {
            if self.foreign {
                return Err(ExecuteError::DirectoryIdentity);
            }
            AdmittedAttempt::for_test(
                self.attempt_id(),
                authority(),
                SandboxExecutionMode::AirGapped,
            )
            .map(|attempt| attempt.with_execution(directory.execution_ownership()))
            .map_err(|_| ExecuteError::DirectoryIdentity)
        }

        fn checker(
            &self,
        ) -> impl Fn(&FakeRoot, &PreparedAttemptDirectory) -> Result<CheckedRoot, ImageActivationError>
               + Send
               + Sync
               + '_ {
            move |_root: &FakeRoot, directory: &PreparedAttemptDirectory| {
                self.attempt(directory)
                    .map(|attempt| checked_root(&attempt))
                    .map_err(|_| ImageActivationError::EvidenceMismatch)
            }
        }
    }

    /// How the fake execution behaves once it bound its cgroup.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Behaviour {
        /// The cgroup empties at once.
        Completes,
        /// The attempt runs until it is cancelled.
        RunsUntilCancelled,
        /// The attempt never returns, even when cancelled.
        Hangs,
        /// The execution fails after binding its cgroup.
        Fails,
        /// The execution binds another cgroup than the one it returns.
        Substitutes,
    }

    /// The fake execution over one fake systemd manager, and the real terminal
    /// cleanup through that manager's transport.
    struct FixtureSteps<'f> {
        transport: &'f crate::SystemdTransientUnitTransport,
        cgroup: std::sync::Mutex<Option<BoundAttemptCgroup>>,
        behaviour: Behaviour,
        executing: AtomicBool,
        /// Runs once the terminal cleanup finished, before the run ends.
        after_cleanup: Option<Box<dyn Fn() + Send + Sync + 'f>>,
    }

    /// A fake manager for the attempt `[id; 16]` whose stop empties the cgroup.
    async fn manager(id: u8) -> TestResult<TeardownFixture> {
        TeardownFixture::new(id, TeardownStop::Empty, TeardownReset::Unload).await
    }

    impl<'f> FixtureSteps<'f> {
        /// Steps over a fixture's transport and its bound cgroup.
        const fn over(
            transport: &'f crate::SystemdTransientUnitTransport,
            cgroup: BoundAttemptCgroup,
        ) -> Self {
            Self {
                transport,
                cgroup: std::sync::Mutex::new(Some(cgroup)),
                behaviour: Behaviour::Completes,
                executing: AtomicBool::new(false),
                after_cleanup: None,
            }
        }

        const fn behaving(mut self, behaviour: Behaviour) -> Self {
            self.behaviour = behaviour;
            self
        }

        /// Wait until the execution bound its cgroup.
        async fn executing(&self) {
            while !self.executing.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    impl AttemptSteps<FakeInput> for FixtureSteps<'_> {
        type Launch = ();
        type Started = ();
        type Cgroup = BoundAttemptCgroup;

        fn execute<'a>(
            &'a self,
            (): (),
            attempt: AdmittedAttempt,
            _recheck: Recheck<'a>,
            cancel: CancelSignal,
        ) -> impl Future<Output = Executed<(), BoundAttemptCgroup>> + Send + 'a {
            let ownership = attempt.execution_for_test();
            let attempt_id = attempt.attempt_id();
            async move {
                if let Err(error) = ownership.claim().and_then(|()| ownership.submit()) {
                    return Err(ExecuteFailure {
                        error,
                        unit: UnitState::NotStarted,
                        cgroup: None,
                    });
                }
                let cgroup = lock(&self.cgroup).take().ok_or_else(|| ExecuteFailure {
                    error: ExecuteError::HostTimeout,
                    unit: UnitState::Unknown,
                    cgroup: None,
                })?;
                let bound = if self.behaviour == Behaviour::Substitutes {
                    (cgroup.identity().0, cgroup.identity().1 + 1)
                } else {
                    cgroup.identity()
                };
                ownership.bind_cgroup(bound);
                self.executing.store(true, Ordering::SeqCst);
                let ending = match self.behaviour {
                    Behaviour::RunsUntilCancelled => {
                        cancel.requested().await;
                        AttemptEnding::Cancelled { watchdog: None }
                    }
                    Behaviour::Hangs => std::future::pending().await,
                    Behaviour::Fails => {
                        return Err(ExecuteFailure {
                            error: ExecuteError::HostTimeout,
                            unit: UnitState::Killed,
                            cgroup: Some(cgroup),
                        })
                    }
                    Behaviour::Completes | Behaviour::Substitutes => AttemptEnding::CgroupEmpty,
                };
                Ok(AttemptExecution {
                    attempt_id,
                    started: (),
                    cgroup,
                    ending,
                    network: NetworkEvidence::None,
                })
            }
        }

        fn finish(
            &self,
            directory: PreparedAttemptDirectory,
            cgroup: Option<BoundAttemptCgroup>,
            root: Option<FakeRoot>,
            deadlines: AttemptCleanupDeadlines,
        ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + '_
        {
            let cleanup = finish_with(self.transport, directory, cgroup, root, deadlines);
            async move {
                let cleaned = cleanup.await;
                if let Some(after) = &self.after_cleanup {
                    after();
                }
                cleaned
            }
        }
    }

    /// A private runtime tree and its registry.
    struct Runtime {
        directory: tempfile::TempDir,
        ledger: crate::StagingLedger,
        lifecycle: AttemptLifecycle<FakeInput>,
    }

    impl Runtime {
        fn new() -> TestResult<Self> {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            for child in ["registry", "attempts"] {
                fs::create_dir(directory.path().join(child))?;
                fs::set_permissions(
                    directory.path().join(child),
                    fs::Permissions::from_mode(0o700),
                )?;
            }
            let parent = File::open(directory.path())?;
            let registry =
                SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())?;
            let ledger = crate::StagingLedger::new(crate::StagingLimits {
                aggregate_bytes: 1024,
            });
            let reconciled = crate::ReconciledRestart::for_test();
            Ok(Self {
                directory,
                lifecycle: AttemptLifecycle::new(registry, ledger.clone(), &reconciled),
                ledger,
            })
        }

        fn record(&self, id: u8) -> TestResult<PathBuf> {
            let unit = crate::TransientServiceUnitName::from_attempt_id([id; 16])?;
            Ok(self
                .directory
                .path()
                .join("registry")
                .join(unit.attempt_component()))
        }

        fn attempt_directory(&self, id: u8) -> TestResult<PathBuf> {
            let unit = crate::TransientServiceUnitName::from_attempt_id([id; 16])?;
            Ok(self
                .directory
                .path()
                .join("attempts")
                .join(unit.attempt_component()))
        }

        /// The fake admission of `[id; 16]`, holding one reserved byte.
        fn charged(&self, id: u8) -> TestResult<FakeInput> {
            let mut input = FakeInput::new(id);
            input.charge = Some(self.ledger.reserve_storage(1)?);
            Ok(input)
        }

        /// The staging bytes admissions still hold.
        fn reserved(&self) -> u64 {
            self.ledger.usage().reserved_bytes
        }

        /// Whether a new grant can still be issued: the staging ledger's
        /// gate before AGR1.
        fn grants(&self) -> bool {
            self.ledger.reserve_storage(0).is_ok()
        }

        /// Whether a new grant can still be issued and a new intent committed.
        fn admits(&self) -> TestResult<bool> {
            let commits = self
                .lifecycle
                .registry
                .commit_planned(&PlannedAttemptIntent::new([0xee; 16], SIM1)?)
                .is_ok();
            Ok(self.grants() && commits)
        }

        async fn run(
            &self,
            input: FakeInput,
            steps: &FixtureSteps<'_>,
        ) -> TestResult<EndedAttempt<()>> {
            let owned = self.lifecycle.admit_input(input)?;
            let budget = budget()?;
            let ended = Box::pin(owned.run_with(steps, (), budget)).await;
            Ok(ended)
        }
    }

    /// Grace ends at 100 ms, the unit kill at 200 ms, shutdown at 300 ms, the
    /// unit is absent by 500 ms and the root released by 700 ms.
    fn budget() -> TestResult<CleanupBudget> {
        Ok(CleanupBudget::new(
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(300),
            Duration::from_millis(500),
            Duration::from_millis(700),
        )?)
    }

    const fn authority_of(id: u8) -> RequestAuthority {
        RequestAuthority {
            request_id: [id; 16],
            apt1_digest: [1; 32],
            policy_epoch: 6,
            nonce: [id; 16],
        }
    }

    const fn cancel_request(id: u8, grant_digest: [u8; 32]) -> SandboxCancelRequest {
        SandboxCancelRequest {
            request: authority_of(id),
            attempt_id: [id; 16],
            agr1_digest: grant_digest,
            request_digest: [3; 32],
        }
    }

    const fn reconcile_request(id: u8, grant_digest: [u8; 32]) -> SandboxReconcileRequest {
        SandboxReconcileRequest {
            request: authority_of(id),
            attempt_id: [id; 16],
            agr1_digest: grant_digest,
            request_digest: [4; 32],
        }
    }

    /// The completed cleanup of `ended`, or why there is none.
    fn cleaned<S>(ended: &EndedAttempt<S>) -> TestResult<&CompletedAttemptCleanup> {
        match ended.cleanup() {
            Ok(Some(cleaned)) => Ok(cleaned),
            Ok(None) => Err("the attempt was withdrawn".into()),
            Err(error) => Err(error.to_string().into()),
        }
    }

    fn exists(path: &Path) -> bool {
        path.symlink_metadata().is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn eight_attempts_run_to_proved_cleanup_and_are_reconciled_once() -> TestResult {
        let runtime = Runtime::new()?;
        for id in 1..=8 {
            let fixture = manager(id).await?;
            let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
            let ended = runtime.run(FakeInput::new(id), &steps).await?;
            assert_eq!(ended.attempt_id(), [id; 16]);
            assert!(!ended.cancelled());
            assert!(matches!(
                ended.progress(),
                AttemptProgress::Executed {
                    ending: AttemptEnding::CgroupEmpty,
                    ..
                }
            ));
            assert_eq!(cleaned(&ended)?.intent().attempt_id(), [id; 16]);
            // Unit first, then the directories, and the intent last.
            assert!(!exists(&runtime.attempt_directory(id)?));
            assert!(!exists(&runtime.record(id)?));
        }
        for id in 1..=8 {
            let reconciled = runtime
                .lifecycle
                .reconcile(&reconcile_request(id, grant(id)))?;
            assert_eq!(reconciled.attempt_id(), [id; 16]);
            // A repeated reconcile reports the same attempt, for its grant only.
            assert_eq!(
                runtime
                    .lifecycle
                    .reconcile(&reconcile_request(id, grant(id)))?,
                reconciled
            );
            assert!(matches!(
                runtime
                    .lifecycle
                    .reconcile(&reconcile_request(id, grant(id + 1))),
                Err(AttemptLifecycleError::GrantMismatch)
            ));
            // The reconciled attempt is unknown to cancel, and is never relaunched.
            assert!(matches!(
                runtime
                    .lifecycle
                    .cancel(&cancel_request(id, grant(id)))
                    .await,
                Err(AttemptLifecycleError::UnknownAttempt)
            ));
            assert!(matches!(
                runtime.lifecycle.admit_input(FakeInput::new(id)),
                Err(AttemptLifecycleError::AttemptKnown)
            ));
        }
        assert!(runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_has_one_owner_while_it_runs_and_after_it_ended() -> TestResult {
        let runtime = Runtime::new()?;
        let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        assert!(matches!(
            runtime.lifecycle.admit_input(FakeInput::new(1)),
            Err(AttemptLifecycleError::AttemptKnown)
        ));
        // A running attempt is not clean yet.
        assert!(matches!(
            runtime.lifecycle.reconcile(&reconcile_request(1, grant(1))),
            Err(AttemptLifecycleError::AttemptActive)
        ));
        let fixture = manager(1).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        cleaned(&Box::pin(owned.run_with(&steps, (), budget()?)).await)?;
        assert!(matches!(
            runtime.lifecycle.admit_input(FakeInput::new(1)),
            Err(AttemptLifecycleError::AttemptKnown)
        ));
        // Cancelling an ended attempt changes nothing.
        assert_eq!(
            runtime
                .lifecycle
                .cancel(&cancel_request(1, grant(1)))
                .await?,
            SandboxCancellationResult::AlreadyTerminal
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn requests_for_another_attempt_or_grant_are_refused() -> TestResult {
        let runtime = Runtime::new()?;
        let _owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        assert!(matches!(
            runtime.lifecycle.cancel(&cancel_request(2, grant(2))).await,
            Err(AttemptLifecycleError::UnknownAttempt)
        ));
        assert!(matches!(
            runtime.lifecycle.reconcile(&reconcile_request(2, grant(2))),
            Err(AttemptLifecycleError::UnknownAttempt)
        ));
        assert!(matches!(
            runtime.lifecycle.cancel(&cancel_request(1, grant(2))).await,
            Err(AttemptLifecycleError::GrantMismatch)
        ));
        assert!(matches!(
            runtime.lifecycle.reconcile(&reconcile_request(1, grant(2))),
            Err(AttemptLifecycleError::GrantMismatch)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancellation_before_activation_cleans_up_without_a_root_or_unit() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let calls = fixture.calls();
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let hook = Arc::new(std::sync::OnceLock::new());
        let mut input = FakeInput::new(1);
        input.cancel_while_preparing = Some(Arc::clone(&hook));
        let owned = runtime.lifecycle.admit_input(input)?;
        let state = lock(&runtime.lifecycle.attempts)
            .get(&[1; 16])
            .and_then(|slot| match slot {
                Slot::Running { state, .. } => Some(Arc::clone(state)),
                Slot::Ended { .. } | Slot::Reconciled { .. } => None,
            });
        hook.set(state.ok_or("no running slot")?)
            .map_err(|_| "hook already set")?;
        // The cancellation lands after the run started, before its directory
        // could be fenced: the run sees it before activating anything.
        let ended = Box::pin(owned.run_with(&steps, (), budget()?)).await;
        assert!(ended.cancelled());
        assert!(matches!(
            ended.progress(),
            AttemptProgress::CancelledBeforeActivation
        ));
        cleaned(&ended)?;
        assert_eq!(calls.count()?, 0);
        assert!(!exists(&runtime.record(1)?));
        assert!(runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_execution_is_stopped_through_its_cgroup_and_cleaned() -> TestResult {
        for stop in [TeardownStop::Empty, TeardownStop::LeavesPopulated] {
            let runtime = Runtime::new()?;
            let fixture = TeardownFixture::new(1, stop, TeardownReset::Unload).await?;
            let steps = FixtureSteps::over(&fixture.transport, fixture.bound)
                .behaving(Behaviour::RunsUntilCancelled);
            let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
            let cancel = async {
                steps.executing().await;
                runtime.lifecycle.cancel(&cancel_request(1, grant(1))).await
            };
            let (cancelled, ended) =
                tokio::join!(cancel, Box::pin(owned.run_with(&steps, (), budget()?)));
            assert_eq!(cancelled?, SandboxCancellationResult::CancelledAndCleaned);
            assert!(ended.cancelled());
            assert!(matches!(
                ended.progress(),
                AttemptProgress::Executed {
                    ending: AttemptEnding::Cancelled { watchdog: None },
                    ..
                }
            ));
            cleaned(&ended)?;
            assert!(!exists(&runtime.record(1)?));
            runtime
                .lifecycle
                .reconcile(&reconcile_request(1, grant(1)))?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancellation_during_activation_fences_the_unit_start() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let owned = runtime
            .lifecycle
            .admit_input(FakeInput::new(1).activating(Activation::Slow))?;
        // Cancel once the directory exists, while the root is being activated:
        // the execution's claim of the directory is then fenced.
        let run = Box::pin(owned.run_with(&steps, (), budget()?));
        let fenced = async {
            loop {
                let running = lock(&runtime.lifecycle.attempts)
                    .get(&[1; 16])
                    .and_then(|slot| match slot {
                        Slot::Running { state, .. } => Some(Arc::clone(state)),
                        Slot::Ended { .. } | Slot::Reconciled { .. } => None,
                    });
                let held = running.filter(|state| lock(&state.fence).is_some());
                if let Some(state) = held {
                    state.cancel();
                    return;
                }
                tokio::task::yield_now().await;
            }
        };
        let ((), ended) = tokio::join!(fenced, run);
        assert!(ended.cancelled());
        assert!(matches!(
            ended.progress(),
            AttemptProgress::Failed {
                error: ExecuteError::AttemptAlreadyClaimed,
                unit: UnitState::NotStarted
            }
        ));
        cleaned(&ended)?;
        assert!(!exists(&runtime.record(1)?));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_run_quarantines_and_never_reports_cleanup() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps =
            FixtureSteps::over(&fixture.transport, fixture.bound).behaving(Behaviour::Hangs);
        let owned = runtime.lifecycle.admit_input(runtime.charged(1)?)?;
        assert_eq!(runtime.reserved(), 1);
        let cancel = async {
            steps.executing().await;
            runtime.lifecycle.cancel(&cancel_request(1, grant(1))).await
        };
        // The broker dies after the cancellation was requested.
        let died = async {
            let run = Box::pin(owned.run_with(&steps, (), budget()?));
            let abandoned = tokio::time::timeout(Duration::from_secs(1), run).await;
            assert!(abandoned.is_err());
            TestResult::Ok(())
        };
        let (cancelled, died) = tokio::join!(cancel, died);
        died?;
        assert!(matches!(
            cancelled,
            Err(AttemptLifecycleError::CleanupFailed)
        ));
        // Its intent and directory are left for restart reconciliation; its
        // input, and its staging reservation, went with the dropped run.
        assert!(exists(&runtime.record(1)?));
        assert!(exists(&runtime.attempt_directory(1)?));
        assert_eq!(runtime.reserved(), 0);
        assert!(!runtime.grants());
        assert!(!runtime.admits()?);
        assert!(matches!(
            runtime.lifecycle.reconcile(&reconcile_request(1, grant(1))),
            Err(AttemptLifecycleError::CleanupFailed)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_owner_dropped_before_its_run_started_is_withdrawn() -> TestResult {
        let runtime = Runtime::new()?;
        drop(runtime.lifecycle.admit_input(runtime.charged(1)?)?);
        let fixture = manager(2).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let owned = runtime.lifecycle.admit_input(FakeInput::new(2))?;
        drop(Box::pin(owned.run_with(&steps, (), budget()?)));
        // Nothing was committed, so nothing needs restart reconciliation.
        assert!(!exists(&runtime.record(1)?));
        assert!(runtime.admits()?);
        assert_eq!(runtime.reserved(), 0);
        // Each attempt had its one owner; it is withdrawn, with nothing to
        // clean up, and no longer live.
        for id in [1, 2] {
            assert!(matches!(
                runtime.lifecycle.admit_input(FakeInput::new(id)),
                Err(AttemptLifecycleError::AttemptKnown)
            ));
            let reconciled = runtime
                .lifecycle
                .reconcile(&reconcile_request(id, grant(id)))?;
            assert_eq!(reconciled.attempt_id(), [id; 16]);
            assert!(reconciled.intent().is_none());
            assert!(matches!(
                runtime
                    .lifecycle
                    .cancel(&cancel_request(id, grant(id)))
                    .await,
                Err(AttemptLifecycleError::UnknownAttempt)
            ));
        }
        assert!(runtime
            .lifecycle
            .fence_and_snapshot()
            .await?
            .attempts()
            .is_empty());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancellation_withdraws_an_attempt_that_never_started() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let calls = fixture.calls();
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        // The owner has not run it: the cancellation needs no wait.
        assert_eq!(
            runtime
                .lifecycle
                .cancel(&cancel_request(1, grant(1)))
                .await?,
            SandboxCancellationResult::CancelledAndCleaned
        );
        let ended = Box::pin(owned.run_with(&steps, (), budget()?)).await;
        assert!(ended.cancelled());
        assert!(matches!(ended.progress(), AttemptProgress::Withdrawn));
        assert!(matches!(ended.cleanup(), Ok(None)));
        let (progress, cleanup) = ended.into_parts();
        assert!(matches!(
            (progress, cleanup),
            (AttemptProgress::Withdrawn, Ok(None))
        ));
        assert!(!exists(&runtime.record(1)?));
        assert_eq!(calls.count()?, 0);
        assert!(runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancellation_after_cleanup_is_reported_with_the_ending() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let mut steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        // The cancellation lands once the cleanup finished, before the run
        // records its end: the run reports it, and a later cancel finds the
        // attempt terminal.
        let lifecycle = &runtime.lifecycle;
        steps.after_cleanup = Some(Box::new(move || {
            assert!(lifecycle.signal_cancel([1; 16], grant(1)).is_ok());
        }));
        let ended = runtime.run(FakeInput::new(1), &steps).await?;
        assert!(ended.cancelled());
        cleaned(&ended)?;
        assert_eq!(
            runtime
                .lifecycle
                .cancel(&cancel_request(1, grant(1)))
                .await?,
            SandboxCancellationResult::AlreadyTerminal
        );
        Ok(())
    }

    /// Run one attempt that cannot be proved clean, and check what it leaves.
    async fn unproved(input: FakeInput, steps: FixtureSteps<'_>) -> TestResult<EndedAttempt<()>> {
        let runtime = Runtime::new()?;
        let id = input.id;
        let mut input = input;
        input.charge = Some(runtime.ledger.reserve_storage(1)?);
        let ended = runtime.run(input, &steps).await?;
        assert!(ended.cleanup().is_err(), "{:?}", ended.cleanup());
        // The ended attempt keeps its admission, and its reservation.
        assert_eq!(runtime.reserved(), 1);
        // A request for another grant is refused before anything else.
        assert!(matches!(
            runtime
                .lifecycle
                .cancel(&cancel_request(id, grant(id + 1)))
                .await,
            Err(AttemptLifecycleError::GrantMismatch)
        ));
        assert!(matches!(
            runtime
                .lifecycle
                .reconcile(&reconcile_request(id, grant(id + 1))),
            Err(AttemptLifecycleError::GrantMismatch)
        ));
        assert!(exists(&runtime.record(id)?));
        // Admission is closed before AGR1 as well as to new intents.
        assert!(!runtime.grants());
        assert!(!runtime.admits()?);
        assert!(matches!(
            runtime
                .lifecycle
                .reconcile(&reconcile_request(id, grant(id))),
            Err(AttemptLifecycleError::CleanupFailed)
        ));
        // An unproved attempt never looks cleanly terminal to a cancellation.
        assert!(matches!(
            runtime
                .lifecycle
                .cancel(&cancel_request(id, grant(id)))
                .await,
            Err(AttemptLifecycleError::CleanupFailed)
        ));
        Ok(ended)
    }

    #[tokio::test(start_paused = true)]
    async fn a_substituted_cgroup_is_never_stopped_and_quarantines() -> TestResult {
        let fixture = manager(1).await?;
        let calls = fixture.calls();
        let steps =
            FixtureSteps::over(&fixture.transport, fixture.bound).behaving(Behaviour::Substitutes);
        let ended = unproved(FakeInput::new(1), steps).await?;
        assert!(matches!(
            ended.cleanup(),
            Err(AttemptLifecycleError::Cleanup(
                AttemptCleanupError::Registry(SystemdAttemptRegistryError::CleanupEvidence)
            ))
        ));
        assert_eq!(calls.count()?, 0);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_unit_not_removed_before_the_cleanup_deadline_quarantines() -> TestResult {
        let fixture = TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Hang).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let ended = unproved(FakeInput::new(1), steps).await?;
        assert!(matches!(
            ended.cleanup(),
            Err(AttemptLifecycleError::Cleanup(AttemptCleanupError::Unit(_)))
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_root_whose_devices_remain_quarantines() -> TestResult {
        let fixture = manager(1).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let input = FakeInput::new(1).activating(Activation::Retained);
        let ended = unproved(input, steps).await?;
        assert!(matches!(
            ended.cleanup(),
            Err(AttemptLifecycleError::Cleanup(AttemptCleanupError::Root(_)))
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_execution_is_still_cleaned_through_its_cgroup() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps =
            FixtureSteps::over(&fixture.transport, fixture.bound).behaving(Behaviour::Fails);
        let ended = runtime.run(FakeInput::new(1), &steps).await?;
        assert!(matches!(
            ended.progress(),
            AttemptProgress::Failed {
                error: ExecuteError::HostTimeout,
                unit: UnitState::Killed
            }
        ));
        cleaned(&ended)?;
        assert!(runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn admitted_facts_of_another_directory_never_activate_a_root() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let mut input = FakeInput::new(1);
        input.foreign = true;
        let ended = runtime.run(input, &steps).await?;
        assert!(matches!(
            ended.progress(),
            AttemptProgress::Failed {
                error: ExecuteError::DirectoryIdentity,
                unit: UnitState::NotStarted
            }
        ));
        cleaned(&ended)?;
        assert!(runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_activation_cleans_the_unmounted_directory() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let input = FakeInput::new(1).activating(Activation::Refused);
        let ended = runtime.run(input, &steps).await?;
        assert!(matches!(
            ended.progress(),
            AttemptProgress::NotActivated(ImageActivationError::EvidenceMismatch)
        ));
        cleaned(&ended)?;
        assert!(!exists(&runtime.record(1)?));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn an_unpreparable_attempt_quarantines_before_any_resource() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let mut input = FakeInput::new(1);
        input.sim1 = [0; 32];
        let ended = runtime.run(input, &steps).await?;
        assert!(matches!(ended.progress(), AttemptProgress::NotPrepared));
        assert!(matches!(
            ended.cleanup(),
            Err(AttemptLifecycleError::Registry(
                SystemdAttemptRegistryError::InvalidIntent
            ))
        ));
        assert!(!exists(&runtime.attempt_directory(1)?));
        assert!(!runtime.grants());
        assert!(!runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_budget_made_earlier_still_gives_every_phase_its_full_length() -> TestResult {
        let runtime = Runtime::new()?;
        let budget = budget()?;
        tokio::time::advance(Duration::from_secs(5)).await;
        // The stop leaves the cgroup populated, so grace runs out and the
        // escalation follows within the unit-kill phase.
        let fixture =
            TeardownFixture::new(1, TeardownStop::LeavesPopulated, TeardownReset::Unload).await?;
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        cleaned(&Box::pin(owned.run_with(&steps, (), budget)).await)?;
        assert!(runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_recycled_main_pid_never_redirects_termination() -> TestResult {
        let runtime = Runtime::new()?;
        // The unit's MainPID was recycled: the manager now reports this test
        // process, which lives in another cgroup. An implementation that
        // signalled the MainPID, or killed the cgroup it maps to, would kill
        // this test or write the recycled cgroup's kill file.
        let recycled = tempfile::tempdir()?;
        let pid = std::process::id();
        fs::write(recycled.path().join("cgroup.procs"), format!("{pid}\n"))?;
        fs::write(recycled.path().join("cgroup.kill"), b"0")?;
        // The stop leaves the bound cgroup populated, so escalation follows.
        let fixture =
            TeardownFixture::new(1, TeardownStop::LeavesPopulated, TeardownReset::Unload).await?;
        fixture.report_main_pid(pid)?;
        let bound = fixture.cgroup_directory().to_owned();
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        cleaned(&runtime.run(FakeInput::new(1), &steps).await?)?;
        // Only the bound cgroup was killed, through its descriptor.
        assert_eq!(fs::read(bound.join("cgroup.kill"))?, b"1");
        assert_eq!(fs::read(recycled.path().join("cgroup.kill"))?, b"0");
        assert_eq!(
            fs::read_to_string(recycled.path().join("cgroup.procs"))?,
            format!("{pid}\n")
        );
        Ok(())
    }

    /// Admit `input` and start its run without running it, then drop it:
    /// the attempt ended without proved cleanup and nothing was committed.
    fn started_and_dropped(runtime: &Runtime, input: FakeInput) -> TestResult {
        let mut owned = runtime.lifecycle.admit_input(input)?;
        assert!(owned.claim.begin());
        drop(owned);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_recovery_snapshot_lists_live_attempts_in_order_and_closes_admission() -> TestResult
    {
        let runtime = Runtime::new()?;
        // Attempt 1 ended clean and was reconciled: it is not live.
        let first = manager(1).await?;
        let steps = FixtureSteps::over(&first.transport, first.bound);
        cleaned(&runtime.run(FakeInput::new(1), &steps).await?)?;
        runtime
            .lifecycle
            .reconcile(&reconcile_request(1, grant(1)))?;
        // Attempt 2 bound a cgroup its cleanup could not prove: its intent
        // and directories remain.
        let second = manager(2).await?;
        let bound = second.bound.identity();
        let steps =
            FixtureSteps::over(&second.transport, second.bound).behaving(Behaviour::Substitutes);
        assert!(runtime
            .run(FakeInput::new(2), &steps)
            .await?
            .cleanup()
            .is_err());
        // Attempts 7 and 6 started and were dropped before committing.
        started_and_dropped(&runtime, FakeInput::new(7))?;
        started_and_dropped(&runtime, FakeInput::new(6))?;
        // Attempt 3 was admitted and never started: it is withdrawn.
        let idle = runtime.lifecycle.admit_input(FakeInput::new(3))?;
        let snapshot = runtime.lifecycle.fence_and_snapshot().await?;
        let attempts = snapshot.attempts();
        assert_eq!(
            attempts
                .iter()
                .map(LiveAttemptIdentity::attempt_id)
                .collect::<Vec<_>>(),
            vec![[2; 16], [6; 16], [7; 16]]
        );
        let unproved = &attempts[0];
        assert_eq!(unproved.unit_name().attempt_component().len(), 32);
        assert_eq!(unproved.sim1_digest(), SIM1);
        assert_eq!(unproved.image(), Some(crate::FIXTURE_IMAGE));
        assert!(unproved.directories().is_some());
        assert_eq!(unproved.cgroup(), Some((bound.0, bound.1 + 1)));
        assert!(unproved.root().is_none());
        let dropped = &attempts[1];
        assert_eq!(dropped.sim1_digest(), SIM1);
        assert_eq!(
            (dropped.image(), dropped.directories(), dropped.cgroup()),
            (None, None, None)
        );
        // The withdrawn attempt cannot start any more.
        let ended = Box::pin(idle.run_with(&steps, (), budget()?)).await;
        assert!(matches!(ended.progress(), AttemptProgress::Withdrawn));
        // Admission is closed for good, and the snapshot is handed out once.
        assert!(matches!(
            runtime.lifecycle.admit_input(FakeInput::new(4)),
            Err(AttemptLifecycleError::Fenced)
        ));
        assert!(matches!(
            runtime.lifecycle.fence_and_snapshot().await,
            Err(AttemptLifecycleError::Fenced)
        ));
        assert!(!runtime.grants());
        assert!(!runtime.admits()?);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_recovery_fence_quiesces_an_attempt_mid_activation() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let calls = fixture.calls();
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound);
        let owned = runtime
            .lifecycle
            .admit_input(FakeInput::new(1).activating(Activation::Slow))?;
        let run = Box::pin(owned.run_with(&steps, (), budget()?));
        // Fence once the directory exists, while the root is being activated.
        let fence = async {
            loop {
                let held = lock(&runtime.lifecycle.attempts)
                    .get(&[1; 16])
                    .and_then(|slot| match slot {
                        Slot::Running { state, .. } => Some(Arc::clone(state)),
                        Slot::Ended { .. } | Slot::Reconciled { .. } => None,
                    })
                    .is_some_and(|state| lock(&state.fence).is_some());
                if held {
                    return runtime.lifecycle.fence_and_snapshot().await;
                }
                tokio::task::yield_now().await;
            }
        };
        let (ended, snapshot) = tokio::join!(run, fence);
        // The execution's claim was fenced: no unit could start.
        assert!(ended.cancelled());
        assert!(matches!(
            ended.progress(),
            AttemptProgress::Failed {
                error: ExecuteError::AttemptAlreadyClaimed,
                unit: UnitState::NotStarted
            }
        ));
        cleaned(&ended)?;
        assert_eq!(calls.count()?, 0);
        // The snapshot was taken only after the attempt ended: its intent is
        // gone and no cgroup was bound.
        let snapshot = snapshot?;
        let attempts = snapshot.attempts();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].attempt_id(), [1; 16]);
        assert_eq!((attempts[0].image(), attempts[0].cgroup()), (None, None));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_running_attempt_is_waited_for_by_the_fence() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let cgroup = fixture.bound.identity();
        let steps = FixtureSteps::over(&fixture.transport, fixture.bound)
            .behaving(Behaviour::RunsUntilCancelled);
        let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        let run = Box::pin(owned.run_with(&steps, (), budget()?));
        let fence = async {
            steps.executing().await;
            runtime.lifecycle.fence_and_snapshot().await
        };
        let (ended, snapshot) = tokio::join!(run, fence);
        assert!(ended.cancelled());
        cleaned(&ended)?;
        let snapshot = snapshot?;
        assert_eq!(snapshot.attempts()[0].cgroup(), Some(cgroup));
        assert_eq!(snapshot.attempts()[0].image(), None);
        Ok(())
    }

    #[tokio::test]
    async fn the_live_attempts_are_capped_at_what_one_snapshot_carries() -> TestResult {
        let runtime = Runtime::new()?;
        for number in (1..=256).rev() {
            started_and_dropped(&runtime, FakeInput::numbered(number))?;
        }
        assert!(matches!(
            runtime.lifecycle.admit_input(FakeInput::numbered(300)),
            Err(AttemptLifecycleError::TooManyLiveAttempts)
        ));
        let snapshot = runtime.lifecycle.fence_and_snapshot().await?;
        let ids = snapshot
            .attempts()
            .iter()
            .map(LiveAttemptIdentity::attempt_id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 256);
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        Ok(())
    }

    #[test]
    fn a_withdrawn_attempt_frees_its_place_under_the_cap() -> TestResult {
        let runtime = Runtime::new()?;
        for number in 1..=255 {
            started_and_dropped(&runtime, FakeInput::numbered(number))?;
        }
        let last = runtime.lifecycle.admit_input(FakeInput::numbered(256))?;
        assert!(matches!(
            runtime.lifecycle.admit_input(FakeInput::numbered(257)),
            Err(AttemptLifecycleError::TooManyLiveAttempts)
        ));
        drop(last);
        drop(runtime.lifecycle.admit_input(FakeInput::numbered(257))?);
        Ok(())
    }

    #[tokio::test]
    async fn a_snapshot_that_cannot_read_an_identity_can_be_retried() -> TestResult {
        let runtime = Runtime::new()?;
        started_and_dropped(&runtime, FakeInput::new(5))?;
        let record = runtime.record(5)?;
        fs::write(&record, b"junk")?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            runtime.lifecycle.fence_and_snapshot().await,
            Err(AttemptLifecycleError::Registry(_))
        ));
        // Admission stays closed, but no snapshot was handed out.
        assert!(matches!(
            runtime.lifecycle.admit_input(FakeInput::new(6)),
            Err(AttemptLifecycleError::Fenced)
        ));
        assert!(!runtime.grants());
        fs::remove_file(&record)?;
        let snapshot = runtime.lifecycle.fence_and_snapshot().await?;
        assert_eq!(snapshot.attempts()[0].attempt_id(), [5; 16]);
        assert!(matches!(
            runtime.lifecycle.fence_and_snapshot().await,
            Err(AttemptLifecycleError::Fenced)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn an_attempt_without_a_unit_name_fails_the_snapshot_closed() -> TestResult {
        let runtime = Runtime::new()?;
        let mut input = FakeInput::new(1);
        input.attempt = [0; 16];
        started_and_dropped(&runtime, input)?;
        assert!(matches!(
            runtime.lifecycle.fence_and_snapshot().await,
            Err(AttemptLifecycleError::Registry(
                SystemdAttemptRegistryError::InvalidIntent
            ))
        ));
        assert!(!runtime.grants());
        Ok(())
    }

    #[test]
    fn recorded_root_facts_are_read_through_their_accessors() {
        let root = crate::RecordedRoot {
            mount_id: 1,
            inode: 2,
            mapper: ((3, 4), 5),
            mapper_uuid: "mapper".to_owned(),
            loop_name: "loop6".to_owned(),
            loop_device: ((7, 8), 9),
        };
        assert_eq!(
            (
                root.mount_id(),
                root.inode(),
                root.mapper(),
                root.loop_device()
            ),
            (1, 2, ((3, 4), 5), ((7, 8), 9))
        );
        assert_eq!((root.mapper_uuid(), root.loop_name()), ("mapper", "loop6"));
    }

    #[test]
    fn cleanup_budget_phases_must_be_strictly_increasing() {
        let millis = Duration::from_millis;
        for (phases, valid) in [
            ([1, 2, 3, 4, 5], true),
            ([2, 2, 3, 4, 5], false),
            ([1, 3, 3, 4, 5], false),
            ([1, 2, 4, 4, 5], false),
            ([1, 2, 3, 5, 5], false),
        ] {
            let [grace, kill, shutdown, absent, released] = phases.map(millis);
            assert_eq!(
                CleanupBudget::new(grace, kill, shutdown, absent, released).is_ok(),
                valid,
                "{phases:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_deadlines_start_when_the_execution_returns() -> TestResult {
        let budget = budget()?;
        tokio::time::advance(Duration::from_secs(5)).await;
        let start = Instant::now();
        let deadlines = budget.deadlines(start);
        assert_eq!(
            deadlines.shutdown().overall(),
            start + Duration::from_millis(300)
        );
        assert_eq!(deadlines.unit_absent(), start + Duration::from_millis(500));
        assert_eq!(deadlines.released(), start + Duration::from_millis(700));
        Ok(())
    }

    /// The production steps over a fake manager, and the production admission
    /// of a staged, authenticated attempt in the isolated container.
    mod production {

        use std::os::fd::OwnedFd as StdOwnedFd;

        use super::*;
        use crate::test_fixtures::attempt_directory::{fixed_registry, require_isolated_root};
        use crate::{ActiveAttempt, FailClosedLocalNetwork, LauncherInvocation};

        #[derive(Debug, thiserror::Error)]
        #[error("refused by the test")]
        struct Refused;

        /// A barrier that hands over `/dev/null` and releases at once.
        struct OpenBarrier;

        impl LaunchBarrier for OpenBarrier {
            type Error = Refused;

            fn prepare(
                &mut self,
                _attempt: &AdmittedAttempt,
            ) -> Result<(LauncherInvocation, zbus::OwnedFd), Refused> {
                let invocation = crate::test_fixtures::invocation().map_err(|_| Refused)?;
                File::open("/dev/null")
                    .map(|file| (invocation, zbus::OwnedFd::from(StdOwnedFd::from(file))))
                    .map_err(|_| Refused)
            }

            fn release(
                &mut self,
                _attempt: &ActiveAttempt,
            ) -> impl Future<Output = Result<(), Refused>> + Send {
                std::future::ready(Ok(()))
            }
        }

        type BarrierFactory = fn(&AdmittedAttempt) -> Result<OpenBarrier, Refused>;

        const fn launch(barrier: BarrierFactory) -> AttemptLaunch<BarrierFactory> {
            AttemptLaunch {
                mode: ModePlan::AirGapped,
                barrier,
            }
        }

        async fn run_production(
            runtime: &Runtime,
            transport: &crate::SystemdTransientUnitTransport,
            barrier: BarrierFactory,
        ) -> TestResult<EndedAttempt<SystemdVerifiedStart>> {
            let (_store_root, store) = crate::test_fixtures::capture_store()?;
            let steps = SystemdAttemptSteps::new(transport, &FailClosedLocalNetwork, store);
            let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
            let budget = budget()?;
            let ended = Box::pin(owned.run_with(&steps, launch(barrier), budget)).await;
            Ok(ended)
        }

        #[tokio::test(start_paused = true)]
        async fn a_barrier_that_cannot_be_built_starts_nothing_and_is_cleaned() -> TestResult {
            let runtime = Runtime::new()?;
            let fixture = manager(1).await?;
            let calls = fixture.calls();
            let ended = run_production(&runtime, &fixture.transport, |_| Err(Refused)).await?;
            assert!(matches!(
                ended.progress(),
                AttemptProgress::Failed {
                    error: ExecuteError::Barrier(_),
                    unit: UnitState::NotStarted
                }
            ));
            cleaned(&ended)?;
            assert_eq!(calls.count()?, 0);
            assert!(!exists(&runtime.record(1)?));
            assert!(runtime.admits()?);
            Ok(())
        }

        #[tokio::test(start_paused = true)]
        async fn a_requested_unit_start_without_a_bound_cgroup_quarantines() -> TestResult {
            let runtime = Runtime::new()?;
            let fixture = manager(1).await?;
            let ended = run_production(&runtime, &fixture.transport, |_| Ok(OpenBarrier)).await?;
            // The fake manager refuses the start, so no cgroup proves the unit gone.
            assert!(matches!(ended.progress(), AttemptProgress::Failed { .. }));
            assert!(matches!(
                ended.cleanup(),
                Err(AttemptLifecycleError::Cleanup(
                    AttemptCleanupError::Registry(SystemdAttemptRegistryError::CleanupEvidence)
                ))
            ));
            assert!(exists(&runtime.record(1)?));
            assert!(!runtime.admits()?);
            Ok(())
        }

        #[tokio::test]
        async fn an_authenticated_attempt_whose_root_cannot_activate_is_cleaned_and_reconciled(
        ) -> TestResult {
            if !require_isolated_root(
        "lifecycle::attempts::tests::cases::production::an_authenticated_attempt_whose_root_cannot_activate_is_cleaned_and_reconciled",
    )
    .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
            let installation =
        pos_reference::provider_admission::test_support::StagedInstallation::stage_execution()
            .map_err(|error| error.to_string())?;
            let ledger = crate::StagingLedger::new(crate::StagingLimits {
                aggregate_bytes: 512 * 1024 * 1024,
            });
            let (_staging, input) =
                crate::test_fixtures::staged_execution::verified_input(&installation, &ledger)
                    .map_err(|error| error.to_string())?;
            fixed_registry().map_err(|error| error.to_string())?;
            let lifecycle: AttemptLifecycle = AttemptLifecycle::new(
                SystemdAttemptRegistry::open()?,
                ledger.clone(),
                &crate::ReconciledRestart::for_test(),
            );
            let request = input.entry().admission().snapshot().request().clone();
            let grant_digest = input.entry().grant_digest();
            let owned = lifecycle.admit(input)?;
            assert_eq!(ledger.usage().attempts, 1);
            let fixture = manager(1).await?;
            let (_store_root, store) = crate::test_fixtures::capture_store()?;
            let steps =
                SystemdAttemptSteps::new(&fixture.transport, &FailClosedLocalNetwork, store);
            let ended = Box::pin(owned.run(&steps, launch(|_| Ok(OpenBarrier)), budget()?)).await;
            assert_eq!(ended.attempt_id(), request.attempt_id);
            // No mountfsd serves the container: nothing was mounted or started.
            assert!(matches!(ended.progress(), AttemptProgress::NotActivated(_)));
            assert_eq!(
                cleaned(&ended)?.intent().sim1_digest(),
                request.authority.sim1_digest
            );
            // The admission is retained until the attempt is reconciled.
            assert_eq!(ledger.usage().attempts, 1);
            let reconcile = SandboxReconcileRequest {
                request: authority_of(1),
                attempt_id: request.attempt_id,
                agr1_digest: grant_digest,
                request_digest: [4; 32],
            };
            lifecycle.reconcile(&reconcile)?;
            assert_eq!(ledger.usage().attempts, 0);
            // A quarantined lifecycle refuses the next exchange before AGR1.
            lifecycle.quarantine();
            let (mut provider, mut selector) = std::os::unix::net::UnixStream::pair()?;
            installation.write_source(&mut selector)?;
            let refused =
                pos_reference::provider_admission::execution::PreparedProviderExecution::receive(
                    &mut provider,
                    &ledger,
                );
            assert!(matches!(
                refused,
                Err(pos_reference::provider_admission::execution::StagingError::CleanupFailed)
            ));
            Ok(())
        }
    }
}
