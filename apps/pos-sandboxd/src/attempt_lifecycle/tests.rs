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
        sim1: [u8; 32],
        activation: Activation,
    }

    impl FakeInput {
        const fn new(id: u8) -> Self {
            Self {
                id,
                sim1: SIM1,
                activation: Activation::Released,
            }
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
            [self.id; 16]
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
            AdmittedAttempt::for_test(
                self.attempt_id(),
                authority(),
                SandboxExecutionMode::AirGapped,
            )
            .map(|attempt| attempt.with_execution(directory.execution_ownership()))
            .map_err(|_| ExecuteError::DirectoryIdentity)
        }

        fn recheck(
            &self,
            _root: &FakeRoot,
            directory: &PreparedAttemptDirectory,
        ) -> Result<CheckedRoot, ImageActivationError> {
            self.attempt(directory)
                .map(|attempt| checked_root(&attempt))
                .map_err(|_| ImageActivationError::EvidenceMismatch)
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
    }

    /// A fake manager for the attempt `[id; 16]` whose stop empties the cgroup.
    async fn manager(id: u8) -> TestResult<TeardownFixture> {
        TeardownFixture::new(id, TeardownStop::Empty, TeardownReset::Unload).await
    }

    impl<'f> FixtureSteps<'f> {
        /// Steps over a fixture's transport and its bound cgroup.
        fn over(
            transport: &'f crate::SystemdTransientUnitTransport,
            cgroup: BoundAttemptCgroup,
        ) -> Self {
            Self {
                transport,
                cgroup: std::sync::Mutex::new(Some(cgroup)),
                behaviour: Behaviour::Completes,
                executing: AtomicBool::new(false),
            }
        }

        fn behaving(mut self, behaviour: Behaviour) -> Self {
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
            input: &'a FakeInput,
            directory: &'a PreparedAttemptDirectory,
            _root: &'a FakeRoot,
            cancel: CancelSignal,
        ) -> impl Future<Output = Executed<(), BoundAttemptCgroup>> + Send + 'a {
            let ownership = directory.execution_ownership();
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
                        AttemptEnding::Cancelled
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
                    attempt_id: input.attempt_id(),
                    started: (),
                    cgroup,
                    ending,
                    network: NetworkEvidence::None,
                })
            }
        }

        fn finish<'a>(
            &'a self,
            directory: PreparedAttemptDirectory,
            cgroup: Option<BoundAttemptCgroup>,
            root: Option<FakeRoot>,
            deadlines: AttemptCleanupDeadlines,
        ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + 'a
        {
            crate::lifecycle::finish_with(self.transport, directory, cgroup, root, deadlines)
        }
    }

    /// A private runtime tree and its registry.
    struct Runtime {
        directory: tempfile::TempDir,
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
            Ok(Self {
                directory,
                lifecycle: AttemptLifecycle::new(registry),
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

        /// Whether a new intent can still be committed.
        fn admits(&self) -> TestResult<bool> {
            Ok(self
                .lifecycle
                .registry
                .commit_planned(&PlannedAttemptIntent::new([0xee; 16], SIM1)?)
                .is_ok())
        }

        async fn run(
            &self,
            input: FakeInput,
            steps: &FixtureSteps<'_>,
        ) -> TestResult<EndedAttempt<()>> {
            let owned = self.lifecycle.admit_input(input)?;
            Ok(owned.run_with(steps, (), budget()?).await)
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

    fn authority_of(id: u8) -> RequestAuthority {
        RequestAuthority {
            request_id: [id; 16],
            apt1_digest: [1; 32],
            policy_epoch: 6,
            nonce: [id; 16],
        }
    }

    fn cancel_request(id: u8, grant_digest: [u8; 32]) -> SandboxCancelRequest {
        SandboxCancelRequest {
            request: authority_of(id),
            attempt_id: [id; 16],
            agr1_digest: grant_digest,
            request_digest: [3; 32],
        }
    }

    fn reconcile_request(id: u8, grant_digest: [u8; 32]) -> SandboxReconcileRequest {
        SandboxReconcileRequest {
            request: authority_of(id),
            attempt_id: [id; 16],
            agr1_digest: grant_digest,
            request_digest: [4; 32],
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
            assert_eq!(ended.attempt_id, [id; 16]);
            assert!(!ended.cancelled);
            assert!(matches!(
                ended.progress,
                AttemptProgress::Executed {
                    ending: AttemptEnding::CgroupEmpty,
                    ..
                }
            ));
            assert_eq!(ended.cleanup?.intent().attempt_id(), [id; 16]);
            // Unit first, then the directories, and the intent last.
            assert!(!exists(&runtime.attempt_directory(id)?));
            assert!(!exists(&runtime.record(id)?));
        }
        for id in 1..=8 {
            let reconciled = runtime
                .lifecycle
                .reconcile(&reconcile_request(id, grant(id)))?;
            assert_eq!(reconciled.intent().attempt_id(), [id; 16]);
            // A repeated reconcile reports the same attempt.
            assert_eq!(
                runtime
                    .lifecycle
                    .reconcile(&reconcile_request(id, grant(id)))?,
                reconciled
            );
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
        owned.run_with(&steps, (), budget()?).await.cleanup?;
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
        let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        // The cancellation is requested before the run prepares anything.
        let (cancelled, ended) = tokio::join!(
            runtime.lifecycle.cancel(&cancel_request(1, grant(1))),
            owned.run_with(&steps, (), budget()?)
        );
        assert_eq!(cancelled?, SandboxCancellationResult::CancelledAndCleaned);
        assert!(ended.cancelled);
        assert!(matches!(
            ended.progress,
            AttemptProgress::CancelledBeforeActivation
        ));
        ended.cleanup?;
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
            let (cancelled, ended) = tokio::join!(cancel, owned.run_with(&steps, (), budget()?));
            assert_eq!(cancelled?, SandboxCancellationResult::CancelledAndCleaned);
            assert!(ended.cancelled);
            assert!(matches!(
                ended.progress,
                AttemptProgress::Executed {
                    ending: AttemptEnding::Cancelled,
                    ..
                }
            ));
            ended.cleanup?;
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
        let run = owned.run_with(&steps, (), budget()?);
        let fenced = async {
            loop {
                if let Some(Slot::Running { state, .. }) =
                    lock(&runtime.lifecycle.attempts).get(&[1; 16])
                {
                    if lock(&state.fence).is_some() {
                        state.cancel();
                        return;
                    }
                }
                tokio::task::yield_now().await;
            }
        };
        let ((), ended) = tokio::join!(fenced, run);
        assert!(ended.cancelled);
        assert!(matches!(
            ended.progress,
            AttemptProgress::Failed {
                error: ExecuteError::AttemptAlreadyClaimed,
                unit: UnitState::NotStarted
            }
        ));
        ended.cleanup?;
        assert!(!exists(&runtime.record(1)?));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_run_quarantines_and_never_reports_cleanup() -> TestResult {
        let runtime = Runtime::new()?;
        let fixture = manager(1).await?;
        let steps =
            FixtureSteps::over(&fixture.transport, fixture.bound).behaving(Behaviour::Hangs);
        let owned = runtime.lifecycle.admit_input(FakeInput::new(1))?;
        let cancel = async {
            steps.executing().await;
            runtime.lifecycle.cancel(&cancel_request(1, grant(1))).await
        };
        // The broker dies after the cancellation was requested.
        let died = async {
            let run = owned.run_with(&steps, (), budget()?);
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
        // Its intent and directory are left for restart reconciliation.
        assert!(exists(&runtime.record(1)?));
        assert!(exists(&runtime.attempt_directory(1)?));
        assert!(!runtime.admits()?);
        assert!(matches!(
            runtime.lifecycle.reconcile(&reconcile_request(1, grant(1))),
            Err(AttemptLifecycleError::CleanupFailed)
        ));
        Ok(())
    }

    /// Run one attempt that cannot be proved clean, and check what it leaves.
    async fn unproved(input: FakeInput, steps: FixtureSteps<'_>) -> TestResult<EndedAttempt<()>> {
        let runtime = Runtime::new()?;
        let id = input.id;
        let ended = runtime.run(input, &steps).await?;
        assert!(ended.cleanup.is_err(), "{:?}", ended.cleanup);
        assert!(exists(&runtime.record(id)?));
        assert!(!runtime.admits()?);
        assert!(matches!(
            runtime
                .lifecycle
                .reconcile(&reconcile_request(id, grant(id))),
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
            ended.cleanup,
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
            ended.cleanup,
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
            ended.cleanup,
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
            ended.progress,
            AttemptProgress::Failed {
                error: ExecuteError::HostTimeout,
                unit: UnitState::Killed
            }
        ));
        ended.cleanup?;
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
            ended.progress,
            AttemptProgress::NotActivated(ImageActivationError::EvidenceMismatch)
        ));
        ended.cleanup?;
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
        assert!(matches!(ended.progress, AttemptProgress::NotPrepared));
        assert!(matches!(
            ended.cleanup,
            Err(AttemptLifecycleError::Registry(
                SystemdAttemptRegistryError::InvalidIntent
            ))
        ));
        assert!(!exists(&runtime.attempt_directory(1)?));
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
        owned.run_with(&steps, (), budget).await.cleanup?;
        assert!(runtime.admits()?);
        Ok(())
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

        fn launch(barrier: BarrierFactory) -> AttemptLaunch<BarrierFactory> {
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
            Ok(owned.run_with(&steps, launch(barrier), budget()?).await)
        }

        #[tokio::test(start_paused = true)]
        async fn a_barrier_that_cannot_be_built_starts_nothing_and_is_cleaned() -> TestResult {
            let runtime = Runtime::new()?;
            let fixture = manager(1).await?;
            let calls = fixture.calls();
            let ended = run_production(&runtime, &fixture.transport, |_| Err(Refused)).await?;
            assert!(matches!(
                ended.progress,
                AttemptProgress::Failed {
                    error: ExecuteError::Barrier(_),
                    unit: UnitState::NotStarted
                }
            ));
            ended.cleanup?;
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
            assert!(matches!(ended.progress, AttemptProgress::Failed { .. }));
            assert!(matches!(
                ended.cleanup,
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
        "attempt_lifecycle::tests::cases::production::an_authenticated_attempt_whose_root_cannot_activate_is_cleaned_and_reconciled",
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
            let lifecycle: AttemptLifecycle =
                AttemptLifecycle::new(SystemdAttemptRegistry::open()?);
            let request = input.entry().admission().snapshot().request().clone();
            let grant_digest = input.entry().grant_digest();
            let owned = lifecycle.admit(input)?;
            assert_eq!(ledger.usage().attempts, 1);
            let fixture = manager(1).await?;
            let (_store_root, store) = crate::test_fixtures::capture_store()?;
            let steps =
                SystemdAttemptSteps::new(&fixture.transport, &FailClosedLocalNetwork, store);
            let ended = owned
                .run(&steps, launch(|_| Ok(OpenBarrier)), budget()?)
                .await;
            assert_eq!(ended.attempt_id, request.attempt_id);
            // No mountfsd serves the container: nothing was mounted or started.
            assert!(matches!(ended.progress, AttemptProgress::NotActivated(_)));
            assert_eq!(
                ended.cleanup?.intent().sim1_digest(),
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
            Ok(())
        }
    }
}
