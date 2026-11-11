//! Restart after a crash at every durable transition of an attempt (#1200).
//!
//! Attempts run through the lifecycle composition over the real registry,
//! the real terminal cleanup, and fake systemd and kernel ports. Five courses
//! are enumerated:
//!
//! * the attempt executes: its planned intent, the attempt and root
//!   directories and their PAI2 extension, the `MountImage` request recorded
//!   in the registry's activation marker, the attached root and its PAI3
//!   extension, the unit start and stop, the root release, the removal of both
//!   directories, and the intent deleted last;
//! * it is cancelled once its unit started, and ends killed;
//! * its activation is refused before any request, so the directories and
//!   the intent are removed without a root;
//! * its request is sent but fails, so the live owner cannot prove cleanup
//!   and leaves the tree for restart;
//! * its launch is refused after the root was attached, so no unit ever
//!   starts and the root is released before the directories are removed.
//!
//! An attempt withdrawn before it ran is checked to do no registry I/O at
//! all.
//!
//! The transitions are not listed by hand. A clean run counts every registry
//! I/O operation (each write, fsync, rename, mkdir, readback, rmdir and
//! unlink) and records every boundary between steps that are not registry
//! I/O (the request sent, the attached root, the unit start, the ended
//! execution, the stopped unit and the released root). A fresh run is then
//! interrupted at each of them in turn:
//!
//! * a crash immediately before an I/O operation, or at a boundary, fails
//!   that and every later registry operation, and every fake port then
//!   refuses to start a unit, attach, stop or release anything, so the disk,
//!   the fake manager's unit and the attached root stay exactly as the crash
//!   left them; the surviving unit is then read from the fake manager;
//! * a failed I/O operation is first handled by the live owner, which must
//!   report cleanup only when it proved all of it and must close itself to
//!   new intents; the process then crashes.
//!
//! Restart reconciliation then runs over what was left. With any one of its
//! consulted proofs withheld it must fail closed, removing nothing while
//! admission stays closed. With every proof given it must stop the surviving
//! unit, detach the surviving root, clean the network, wait out a request
//! still pending on this boot before its loop sweep, and remove everything,
//! the intent last; the same attempts can then be committed again. Restart
//! itself is also crashed at each of its registry operations over three
//! crash states, and the owner open that creates the activation marker at
//! each of its own; a second restart must converge. A same-boot restart
//! sweeps exactly when the pending request lapses, even past a shorter
//! deadline, and a sweep that never returns elapses the deadline the wait
//! extended without removing anything. The counts are pinned,
//! so an unreviewed new transition fails here.

// The declaration in `attempts.rs` already turns coverage off. The CRAP gate
// (cargo-crap 0.2.2) scores a file's functions without the `cfg` of the `mod`
// declaration that includes it, and skips items under a `cfg(test)` in the
// file itself: its report scored this file's helpers until this `cfg(test)`
// was added, and has not since, while the production files stay scored.
#[cfg(test)]
mod cases {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;

    use futures_util::future::{join, Either};
    use pos_reference::sandbox_provider_protocol::{RequestAuthority, SandboxExecutionMode};

    use super::super::*;
    use crate::test_fixtures::{
        authority, checked_root, crash_io_now, fake_root_release, in_lock_test_process, io_count,
        io_crashed, recorded_identity, release_fake_root, restart_after_crash, with_io_crash,
        with_io_fault, CrashSurvivors, FakeRootRelease, RestartClock, Restarted, TeardownFixture,
        TeardownReset, TeardownStop, TestResult, UncertainProof,
    };
    use crate::{
        BoundAttemptCgroup, ReleasedAttemptRoot, RestartReconciliationError,
        TransientServiceUnitName, UnitCgroup,
    };

    const SIM1: [u8; 32] = [9; 32];

    /// The registry I/O operations of opening a registry owner over an empty
    /// registry, which creates its activation marker.
    const OPEN_IO_OPERATIONS: usize = 18;

    /// How long a `MountImage` request sent one second before a same-boot
    /// restart can still attach a loop device: the activator deadline plus
    /// the 10 s `SERVER_MARGIN` of `attempt_registry::activation`, less the
    /// second since it was sent.
    const PENDING_REQUEST: Duration = crate::MountfsdImageActivator::DEADLINE
        .saturating_add(Duration::from_secs(10))
        .saturating_sub(Duration::from_secs(1));

    /// A crash boundary between two lifecycle steps that are not registry I/O.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Boundary {
        /// The `MountImage` request was sent after the activation marker
        /// recorded it: loop/dm devices may exist, nothing is mounted.
        RequestSent,
        /// The root is attached and verified, before its PAI3 record.
        RootAttached,
        /// The unit start was requested, before its cgroup was bound.
        UnitSubmitted,
        /// The execution ended; the unit is still loaded.
        ExecutionEnded,
        /// Terminal cleanup passed its unit step; the root is mounted.
        UnitStopped,
        /// The root was detached and its devices observed absent.
        RootReleased,
    }

    /// The boundaries of a lifecycle that starts its unit.
    const STARTED: &[Boundary] = &[
        Boundary::RequestSent,
        Boundary::RootAttached,
        Boundary::UnitSubmitted,
        Boundary::ExecutionEnded,
        Boundary::UnitStopped,
        Boundary::RootReleased,
    ];

    /// One course of an attempt's lifecycle.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Course {
        /// The attempt executes and is cleaned up.
        Executes,
        /// The attempt is cancelled once its unit started, and ends killed.
        Cancelled,
        /// Activation is refused before any `MountImage` request.
        ActivationRefused,
        /// The `MountImage` request is sent but fails.
        RequestFails,
        /// The launch is refused after the root was attached.
        LaunchRefused,
    }

    impl Course {
        /// The registry I/O operations of one lifecycle on this course.
        const fn io_operations(self) -> usize {
            match self {
                Self::Executes | Self::Cancelled => 173,
                Self::ActivationRefused => 113,
                Self::RequestFails => 90,
                Self::LaunchRefused => 150,
            }
        }

        /// The boundaries of one lifecycle on this course, in order.
        const fn boundaries(self) -> &'static [Boundary] {
            match self {
                Self::Executes | Self::Cancelled => STARTED,
                Self::ActivationRefused => &[],
                Self::RequestFails => &[Boundary::RequestSent],
                Self::LaunchRefused => &[
                    Boundary::RequestSent,
                    Boundary::RootAttached,
                    Boundary::UnitStopped,
                    Boundary::RootReleased,
                ],
            }
        }

        /// Whether the live owner proves the cleanup of this course: a sent
        /// request with no released root leaves its tree for restart.
        const fn proves_cleanup(self) -> bool {
            !matches!(self, Self::RequestFails)
        }
    }

    /// What a run did to the fake host, and the boundary it crashes at.
    ///
    /// After a crash no fake port changes anything, so what is recorded here
    /// is what the crash left. The loaded unit is read from each attempt's
    /// fake manager. The attached root is bookkeeping: the fake kernel's
    /// mount is not observable once its release consumed it, so `attached`
    /// is set when the attach succeeded and cleared only when the release
    /// returned. The unit is read only for an attempt whose start was
    /// requested, because the fake manager reports its unit loaded from its
    /// creation, before any start.
    #[derive(Debug)]
    struct World {
        course: Course,
        /// Crash at this boundary occurrence, counted over the whole run.
        crash_at: Option<usize>,
        /// Whether the run crashed at a boundary.
        crashed: AtomicBool,
        reached: Mutex<Vec<Boundary>>,
        /// The attempt whose unit start was requested.
        submitted: Mutex<Option<[u8; 16]>>,
        /// The attempt whose unit the fake manager still had loaded when its
        /// run ended, read from that manager.
        loaded: Mutex<Option<[u8; 16]>>,
        /// The attempt whose root is attached and not released.
        attached: Mutex<Option<[u8; 16]>>,
    }

    impl World {
        const fn new(course: Course, crash_at: Option<usize>) -> Self {
            Self {
                course,
                crash_at,
                crashed: AtomicBool::new(false),
                reached: Mutex::new(Vec::new()),
                submitted: Mutex::new(None),
                loaded: Mutex::new(None),
                attached: Mutex::new(None),
            }
        }

        /// Whether the run crashed: no fake port acts afterwards.
        fn frozen(&self) -> bool {
            self.crashed.load(Ordering::SeqCst) || io_crashed()
        }

        /// Record `boundary`, and crash there if this occurrence is the one.
        fn reach(&self, boundary: Boundary) {
            if self.frozen() {
                return;
            }
            lock(&self.reached).push(boundary);
            let occurrence = lock(&self.reached).len() - 1;
            if self.crash_at == Some(occurrence) {
                self.crashed.store(true, Ordering::SeqCst);
                crash_io_now();
            }
        }
    }

    /// The admission of the attempt `[id; 16]`, over its fake manager.
    struct CrashInput {
        id: u8,
        world: Arc<World>,
        transport: Arc<SystemdTransientUnitTransport>,
    }

    /// The attached fixture root of one attempt.
    struct CrashRoot {
        fake: FakeRootRelease,
        world: Arc<World>,
        transport: Arc<SystemdTransientUnitTransport>,
    }

    impl RootRelease for CrashRoot {
        fn release(
            self,
            directory: &PreparedAttemptDirectory,
            deadline: Instant,
        ) -> impl Future<Output = Result<ReleasedAttemptRoot, ImageActivationError>> + Send + '_
        {
            let Self {
                fake,
                world,
                transport,
            } = self;
            async move {
                // Terminal cleanup releases the root only after it stopped
                // the unit: a started unit is unloaded from its manager now.
                let id = directory.intent().attempt_id();
                if *lock(&world.submitted) == Some(id) {
                    let absent = transport
                        .wait_for_attempt_unit_absence(
                            directory.intent().unit_name().clone(),
                            Instant::now() + Duration::from_millis(50),
                        )
                        .await;
                    assert!(
                        absent.is_ok(),
                        "attempt {id:?} released with its unit loaded"
                    );
                }
                world.reach(Boundary::UnitStopped);
                if world.frozen() {
                    // A crashed process detaches nothing.
                    return Err(ImageActivationError::ResourceAbsenceUnverified);
                }
                // A crash after the detach but before the release's final
                // registry check reports the root still attached, so restart
                // reads it back and detaches it again: never fewer resources.
                let released = release_fake_root(fake, directory, deadline).await;
                if released.is_ok() {
                    *lock(&world.attached) = None;
                    world.reach(Boundary::RootReleased);
                }
                released
            }
        }
    }

    impl CrashInput {
        /// Send the recorded request and attach the fixture root.
        fn attach(
            &self,
            directory: &PreparedAttemptDirectory,
        ) -> Result<CrashRoot, ImageActivationError> {
            // As in production, the request is recorded durably before it
            // is sent, and nothing is sent when that record fails.
            directory
                .record_activation_request()
                .map_err(|_| ImageActivationError::AttachFailure)
                .and_then(|()| {
                    self.world.reach(Boundary::RequestSent);
                    if self.world.frozen() {
                        return Err(ImageActivationError::AttachFailure);
                    }
                    if self.world.course == Course::RequestFails {
                        // The request reached mountfsd, which may have left
                        // loop/dm devices, and then failed.
                        directory.begin_activation();
                        return Err(ImageActivationError::AttachFailure);
                    }
                    fake_root_release(directory, true)
                        .map_err(|_| ImageActivationError::AttachFailure)
                })
                .map(|fake| {
                    *lock(&self.world.attached) = Some(self.attempt_id());
                    self.world.reach(Boundary::RootAttached);
                    CrashRoot {
                        fake,
                        world: Arc::clone(&self.world),
                        transport: Arc::clone(&self.transport),
                    }
                })
        }
    }

    impl AdmittedInput for CrashInput {
        type Root = CrashRoot;

        fn attempt_id(&self) -> [u8; 16] {
            [self.id; 16]
        }

        fn sim1_digest(&self) -> [u8; 32] {
            SIM1
        }

        fn grant_digest(&self) -> [u8; 32] {
            [self.id ^ 0xa5; 32]
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
        ) -> impl Future<Output = Result<CrashRoot, ImageActivationError>> + Send + 'a {
            // A refused activation, such as a held image that no longer
            // matches, sends no request.
            let activated = if self.world.course == Course::ActivationRefused {
                Err(ImageActivationError::AttachFailure)
            } else {
                self.attach(directory)
            };
            std::future::ready(activated)
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

        fn checker(
            &self,
        ) -> impl Fn(
            &CrashRoot,
            &PreparedAttemptDirectory,
        ) -> Result<CheckedRoot, ImageActivationError>
               + Send
               + Sync
               + '_ {
            // As in production, the root's facts are recorded (PAI3) by the
            // recheck immediately before the unit starts.
            move |_root: &CrashRoot, directory: &PreparedAttemptDirectory| {
                recorded_identity(directory)
                    .map_err(|_| ImageActivationError::EvidenceMismatch)
                    .and_then(|identity| {
                        directory
                            .record_root(&identity, || Ok(()))
                            .map_err(|_| ImageActivationError::EvidenceMismatch)
                    })
                    .and_then(|()| {
                        self.attempt(directory)
                            .map(|attempt| checked_root(&attempt))
                            .map_err(|_| ImageActivationError::EvidenceMismatch)
                    })
            }
        }
    }

    /// The fake execution over one fake systemd manager, and the real terminal
    /// cleanup through that manager's transport.
    struct CrashSteps {
        transport: Arc<SystemdTransientUnitTransport>,
        cgroup: Mutex<Option<BoundAttemptCgroup>>,
        world: Arc<World>,
    }

    impl CrashSteps {
        /// Claim, recheck the root and request the unit start, as production
        /// does, then bind the cgroup; a refused launch stops after the claim.
        fn start(
            &self,
            attempt: &AdmittedAttempt,
            recheck: Recheck<'_>,
        ) -> Result<Option<BoundAttemptCgroup>, ExecuteError> {
            let ownership = attempt.execution_for_test();
            ownership
                .claim()
                .and_then(|()| {
                    if self.world.course == Course::LaunchRefused {
                        Err(ExecuteError::ModeMismatch)
                    } else {
                        recheck().map(|_checked| ()).map_err(ExecuteError::Recheck)
                    }
                })
                .and_then(|()| {
                    // A crashed process starts no unit.
                    if self.world.frozen() {
                        Err(ExecuteError::HostTimeout)
                    } else {
                        ownership.submit()
                    }
                })
                .map(|()| {
                    *lock(&self.world.submitted) = Some(attempt.attempt_id());
                    self.world.reach(Boundary::UnitSubmitted);
                    let taken = lock(&self.cgroup).take();
                    taken.inspect(|cgroup| ownership.bind_cgroup(cgroup.identity()))
                })
        }
    }

    impl AttemptSteps<CrashInput> for CrashSteps {
        type Launch = ();
        type Started = ();
        type Cgroup = BoundAttemptCgroup;

        fn execute<'a>(
            &'a self,
            (): (),
            attempt: AdmittedAttempt,
            recheck: Recheck<'a>,
            cancel: CancelSignal,
        ) -> impl Future<Output = Executed<(), BoundAttemptCgroup>> + Send + 'a {
            let attempt_id = attempt.attempt_id();
            let started = self.start(&attempt, recheck);
            let cancelled = self.world.course == Course::Cancelled;
            async move {
                let cgroup = match started {
                    Ok(Some(cgroup)) => cgroup,
                    Ok(None) => {
                        return Err(ExecuteFailure {
                            error: ExecuteError::HostTimeout,
                            unit: UnitState::Unknown,
                            cgroup: None,
                        })
                    }
                    Err(error) => {
                        return Err(ExecuteFailure {
                            error,
                            unit: UnitState::NotStarted,
                            cgroup: None,
                        })
                    }
                };
                let ending = if cancelled {
                    // Running until cancelled, then stopped and killed.
                    cancel.requested().await;
                    AttemptEnding::Cancelled {
                        watchdog: Some(true),
                    }
                } else {
                    AttemptEnding::CgroupEmpty
                };
                self.world.reach(Boundary::ExecutionEnded);
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
            root: Option<CrashRoot>,
            deadlines: AttemptCleanupDeadlines,
        ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + '_
        {
            if self.world.frozen() {
                // A crashed process stops and removes nothing.
                drop((directory, cgroup, root));
                Either::Left(std::future::ready(Err(AttemptCleanupError::Registry(
                    SystemdAttemptRegistryError::ReconciliationRequired,
                ))))
            } else {
                Either::Right(finish_with(
                    &self.transport,
                    directory,
                    cgroup,
                    root,
                    deadlines,
                ))
            }
        }
    }

    /// A private runtime tree, as the provider's `/run/pigloros/sandbox`.
    fn runtime() -> TestResult<tempfile::TempDir> {
        let runtime = tempfile::tempdir()?;
        for path in [
            runtime.path().to_path_buf(),
            runtime.path().join("registry"),
            runtime.path().join("attempts"),
        ] {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(runtime)
    }

    /// A new registry owner, which admission requires.
    fn registry(
        runtime: &Path,
    ) -> TestResult<Result<SystemdAttemptRegistry, SystemdAttemptRegistryError>> {
        let parent = File::open(runtime)?;
        Ok(SystemdAttemptRegistry::from_runtime_directory(
            &parent,
            parent.metadata()?.uid(),
        ))
    }

    /// A lifecycle over a new registry owner in `runtime`.
    fn lifecycle(runtime: &Path) -> TestResult<AttemptLifecycle<CrashInput>> {
        let ledger = crate::StagingLedger::new(crate::StagingLimits {
            aggregate_bytes: 1024,
        });
        Ok(AttemptLifecycle::new(
            registry(runtime)??,
            ledger,
            &crate::ReconciledRestart::for_test(),
        ))
    }

    /// The planned intent of the attempt `[id; 16]`.
    fn intent(id: u8) -> TestResult<PlannedAttemptIntent> {
        Ok(PlannedAttemptIntent::new([id; 16], SIM1)?)
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

    const fn authority_of(attempt_id: [u8; 16]) -> RequestAuthority {
        RequestAuthority {
            request_id: attempt_id,
            apt1_digest: [1; 32],
            policy_epoch: 6,
            nonce: attempt_id,
        }
    }

    const fn reconcile_request(attempt_id: [u8; 16]) -> SandboxReconcileRequest {
        SandboxReconcileRequest {
            request: authority_of(attempt_id),
            attempt_id,
            agr1_digest: [attempt_id[0] ^ 0xa5; 32],
            request_digest: [4; 32],
        }
    }

    const fn cancel_request(attempt_id: [u8; 16]) -> SandboxCancelRequest {
        SandboxCancelRequest {
            request: authority_of(attempt_id),
            attempt_id,
            agr1_digest: [attempt_id[0] ^ 0xa5; 32],
            request_digest: [3; 32],
        }
    }

    /// A paused current-thread runtime: deadlines and waits pass at once.
    fn paused() -> TestResult<tokio::runtime::Runtime> {
        Ok(tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()?)
    }

    /// The result of an attempt's cancellation, if one was requested.
    type CancelResult = Option<Result<SandboxCancellationResult, AttemptLifecycleError>>;

    /// One attempt's end: its outcome, the registry operations started by
    /// then, and its cancellation.
    type Lived = (EndedAttempt<()>, usize, CancelResult);

    /// Run `owned` to its end; on the cancelled course, cancel it once its
    /// unit started, or once it ended without one.
    async fn live(
        lifecycle: &AttemptLifecycle<CrashInput>,
        owned: OwnedAttempt<'_, CrashInput>,
        steps: &CrashSteps,
        id: [u8; 16],
    ) -> TestResult<(EndedAttempt<()>, CancelResult)> {
        let budget = budget()?;
        if steps.world.course != Course::Cancelled {
            return Ok((Box::pin(owned.run_with(steps, (), budget)).await, None));
        }
        let done = AtomicBool::new(false);
        let run = async {
            let ended = Box::pin(owned.run_with(steps, (), budget)).await;
            done.store(true, Ordering::SeqCst);
            ended
        };
        let cancel = async {
            while lock(&steps.world.submitted).is_none() && !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Box::pin(lifecycle.cancel(&cancel_request(id))).await
        };
        let (ended, cancelled) = join(Box::pin(run), Box::pin(cancel)).await;
        Ok((ended, Some(cancelled)))
    }

    /// Run attempts 1 to `count` one after another, each to its end. The unit
    /// each leaves loaded is read from its fake manager.
    async fn lives(
        lifecycle: &AttemptLifecycle<CrashInput>,
        count: u8,
        world: &Arc<World>,
    ) -> TestResult<Vec<Lived>> {
        let mut lived = Vec::new();
        for id in 1..=count {
            let fixture =
                TeardownFixture::new(id, TeardownStop::Empty, TeardownReset::Unload).await?;
            let transport = Arc::new(fixture.transport);
            let steps = CrashSteps {
                transport: Arc::clone(&transport),
                cgroup: Mutex::new(Some(fixture.bound)),
                world: Arc::clone(world),
            };
            let input = CrashInput {
                id,
                world: Arc::clone(world),
                transport: Arc::clone(&transport),
            };
            let owned = lifecycle.admit_input(input)?;
            let (ended, cancelled) = live(lifecycle, owned, &steps, [id; 16]).await?;
            let ios = io_count();
            if *lock(&world.submitted) == Some([id; 16]) {
                let unit = TransientServiceUnitName::from_attempt_id([id; 16])?;
                let absent = transport
                    .wait_for_attempt_unit_absence(unit, Instant::now() + Duration::from_millis(50))
                    .await;
                if absent.is_err() {
                    *lock(&world.loaded) = Some([id; 16]);
                }
            }
            lived.push((ended, ios, cancelled));
        }
        Ok(lived)
    }

    /// Where a run is interrupted.
    #[derive(Clone, Copy, Debug)]
    enum Interruption {
        /// Nowhere: every attempt runs its course to its end.
        None,
        /// Registry I/O operation `n` fails; the live owner handles it.
        FailsAtIo(usize),
        /// The process crashes immediately before registry I/O operation `n`.
        CrashesAtIo(usize),
        /// The process crashes at boundary occurrence `n`.
        CrashesAtBoundary(usize),
    }

    /// What a run left behind.
    struct Run {
        /// Each attempt's live outcome, as the process reported it.
        ended: Vec<EndedAttempt<()>>,
        /// The registry I/O operations started after each attempt ended.
        ios_after: Vec<usize>,
        /// Each attempt's cancellation result, if one was requested.
        cancelled: Vec<CancelResult>,
        /// The registry I/O operations started.
        ios: usize,
        /// The boundaries reached.
        reached: Vec<Boundary>,
        /// The unit and root still live.
        survivors: CrashSurvivors,
    }

    /// Run `count` lifecycles on `course` in `runtime`, interrupted by
    /// `interruption`, and leave the process state as the crash does.
    fn run(
        runtime: &Path,
        course: Course,
        count: u8,
        interruption: Interruption,
    ) -> TestResult<Run> {
        let tokio = paused()?;
        // The owner open, and the activation marker it creates, are crashed
        // by their own test.
        let lifecycle = lifecycle(runtime)?;
        let crash_at = match interruption {
            Interruption::CrashesAtBoundary(at) => Some(at),
            Interruption::None | Interruption::FailsAtIo(_) | Interruption::CrashesAtIo(_) => None,
        };
        let world = Arc::new(World::new(course, crash_at));
        let live = || tokio.block_on(Box::pin(lives(&lifecycle, count, &world)));
        let (lived, ios) = match interruption {
            Interruption::None => with_io_fault(None, live),
            Interruption::FailsAtIo(at) => with_io_fault(Some(at), live),
            Interruption::CrashesAtIo(at) => with_io_crash(Some(at), live),
            Interruption::CrashesAtBoundary(_) => with_io_crash(None, live),
        };
        let mut ended = Vec::new();
        let mut ios_after = Vec::new();
        let mut cancelled = Vec::new();
        for (attempt, after, cancel) in lived? {
            ended.push(attempt);
            ios_after.push(after);
            cancelled.push(cancel);
        }
        let survivors = CrashSurvivors {
            unit: (*lock(&world.loaded))
                .map(TransientServiceUnitName::from_attempt_id)
                .transpose()?,
            mounted: *lock(&world.attached),
        };
        assert_reported_cleanup_was_complete(&ended, &cancelled, &survivors, runtime, interruption);
        if let Interruption::FailsAtIo(at) = interruption {
            assert_live_owner_fails_closed(&lifecycle, &ended, at)?;
        }
        let reached = lock(&world.reached).clone();
        // The crash: every in-memory owner is gone.
        drop(lifecycle);
        drop(tokio);
        Ok(Run {
            ended,
            ios_after,
            cancelled,
            ios,
            reached,
            survivors,
        })
    }

    /// Every attempt the process reported cleaned, or cancelled and cleaned,
    /// left nothing behind: no record, no directory, no unit and no root.
    /// Proved cleanup is never partial.
    fn assert_reported_cleanup_was_complete(
        ended: &[EndedAttempt<()>],
        cancelled: &[CancelResult],
        survivors: &CrashSurvivors,
        runtime: &Path,
        interruption: Interruption,
    ) {
        for (attempt, cancel) in ended.iter().zip(cancelled) {
            let id = attempt.attempt_id();
            assert!(
                !matches!(attempt.cleanup(), Ok(None)),
                "{interruption:?}: attempt {id:?} was withdrawn"
            );
            if matches!(
                cancel,
                Some(Ok(SandboxCancellationResult::CancelledAndCleaned))
            ) {
                assert!(
                    matches!(attempt.cleanup(), Ok(Some(_))),
                    "{interruption:?}: attempt {id:?} reported cancelled and cleaned"
                );
            }
            if let Ok(Some(cleaned)) = attempt.cleanup() {
                let key = cleaned.intent().unit_name().attempt_component();
                assert!(
                    !runtime.join("registry").join(key).exists()
                        && !runtime.join("attempts").join(key).exists()
                        && survivors.mounted != Some(id)
                        && survivors
                            .unit
                            .as_ref()
                            .is_none_or(|unit| unit != cleaned.intent().unit_name()),
                    "{interruption:?}: attempt {id:?} reported clean over {survivors:?}"
                );
            }
        }
    }

    /// After a failed operation, the live owner reports an attempt reconciled
    /// exactly when its cleanup was proved, and commits no intent, not even
    /// the same attempt's again.
    fn assert_live_owner_fails_closed(
        lifecycle: &AttemptLifecycle<CrashInput>,
        ended: &[EndedAttempt<()>],
        at: usize,
    ) -> TestResult {
        for attempt in ended {
            let reported = lifecycle.reconcile(&reconcile_request(attempt.attempt_id()));
            assert_eq!(
                reported.is_ok(),
                matches!(attempt.cleanup(), Ok(Some(_))),
                "operation {at}: {:?} reported as {reported:?}",
                attempt.cleanup()
            );
            let again = lifecycle
                .registry
                .commit_planned(&PlannedAttemptIntent::new(attempt.attempt_id(), SIM1)?);
            assert!(
                matches!(
                    again,
                    Err(SystemdAttemptRegistryError::ReconciliationRequired)
                ),
                "operation {at}: the failed owner commits its attempt again: {again:?}"
            );
        }
        let refused = lifecycle.registry.commit_planned(&intent(0xee)?);
        assert!(
            matches!(
                refused,
                Err(SystemdAttemptRegistryError::ReconciliationRequired)
            ),
            "operation {at}: the failed owner still commits: {refused:?}"
        );
        Ok(())
    }

    /// Every registry entry with its bytes, and every path below `attempts`.
    #[derive(Debug, Eq, PartialEq)]
    struct Snapshot {
        registry: BTreeMap<String, Vec<u8>>,
        attempts: BTreeSet<PathBuf>,
    }

    fn snapshot(runtime: &Path) -> TestResult<Snapshot> {
        let mut registry = BTreeMap::new();
        for entry in fs::read_dir(runtime.join("registry"))? {
            let entry = entry?;
            registry.insert(
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path())?,
            );
        }
        let mut attempts = BTreeSet::new();
        let mut pending = vec![runtime.join("attempts")];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let path = entry?.path();
                if path.is_dir() {
                    pending.push(path.clone());
                }
                attempts.insert(path.strip_prefix(runtime)?.to_path_buf());
            }
        }
        Ok(Snapshot { registry, attempts })
    }

    /// The attempt records, without temporary writes or the activation marker.
    fn records(snapshot: &Snapshot) -> impl Iterator<Item = (&String, &Vec<u8>)> {
        snapshot
            .registry
            .iter()
            .filter(|(name, _)| !name.starts_with('.') && *name != "activation")
    }

    /// What the crash of the attempt `[id; 16]` left, in words: an interrupted
    /// temporary write, the committed stage, the attempt and root directories,
    /// a loaded unit and a mounted root.
    fn frontier(snapshot: &Snapshot, survivors: &CrashSurvivors, id: u8) -> TestResult<String> {
        let unit = TransientServiceUnitName::from_attempt_id([id; 16])?;
        let key = unit.attempt_component();
        let attempt = Path::new("attempts").join(key);
        let stage = snapshot
            .registry
            .get(key)
            .and_then(|bytes| bytes.get(..4))
            .map_or_else(
                || "none".to_owned(),
                |tag| String::from_utf8_lossy(tag).into_owned(),
            );
        let words = [
            (
                snapshot.registry.keys().any(|name| name.starts_with('.')),
                "tmp",
            ),
            (true, stage.as_str()),
            (snapshot.attempts.contains(&attempt), "attempt"),
            (snapshot.attempts.contains(&attempt.join("root")), "root"),
            (survivors.unit.is_some(), "unit"),
            (survivors.mounted.is_some(), "mounted"),
        ];
        Ok(words
            .iter()
            .filter(|(present, _)| *present)
            .map(|(_, word)| *word)
            .collect::<Vec<_>>()
            .join(" "))
    }

    /// The attempt an interruption on `course` hit, counted from 1.
    fn attempt_of(course: Course, interruption: Interruption) -> TestResult<u8> {
        let index = match interruption {
            Interruption::None => Some(0),
            Interruption::FailsAtIo(at) | Interruption::CrashesAtIo(at) => {
                at.checked_div(course.io_operations())
            }
            Interruption::CrashesAtBoundary(at) => at.checked_div(course.boundaries().len()),
        };
        let index = index.ok_or("an interruption of a course without that step")?;
        Ok(u8::try_from(index + 1)?)
    }

    /// The proofs restart reconciliation consults for this crash state.
    fn consulted_proofs(snapshot: &Snapshot, survivors: &CrashSurvivors) -> Vec<UncertainProof> {
        let mut proofs = vec![UncertainProof::Network, UncertainProof::ProviderLoops];
        if survivors.unit.is_some() {
            proofs.push(UncertainProof::UnitStop);
        }
        let mut detach = false;
        let mut devices = false;
        for (name, bytes) in records(snapshot) {
            let tag = bytes.get(..4);
            let root = Path::new("attempts").join(name).join("root");
            detach |= matches!(tag, Some(b"PAI2" | b"PAI3")) && snapshot.attempts.contains(&root);
            devices |= matches!(tag, Some(b"PAI3"));
        }
        if detach {
            proofs.push(UncertainProof::RootDetach);
        }
        if devices {
            proofs.push(UncertainProof::RecordedDevices);
        }
        proofs
    }

    /// Whether `error` is the refusal of the withheld `proof`.
    const fn refused_by(proof: UncertainProof, error: &RestartReconciliationError) -> bool {
        match proof {
            UncertainProof::None => false,
            UncertainProof::UnitStop => matches!(error, RestartReconciliationError::UnitStop(_)),
            UncertainProof::RootDetach => matches!(error, RestartReconciliationError::Root(_)),
            UncertainProof::Network => matches!(error, RestartReconciliationError::Network(_)),
            UncertainProof::RecordedDevices => {
                matches!(error, RestartReconciliationError::Devices(None))
            }
            UncertainProof::ProviderLoops => {
                matches!(error, RestartReconciliationError::ProviderLoops(None))
            }
            UncertainProof::SweepHangs => {
                matches!(error, RestartReconciliationError::DeadlineElapsed)
            }
        }
    }

    /// One restart over `runtime` on a paused runtime.
    fn restart(
        runtime: &Path,
        survivors: &CrashSurvivors,
        proof: UncertainProof,
        clock: RestartClock,
    ) -> TestResult<Restarted> {
        paused()?.block_on(Box::pin(restart_after_crash(
            runtime, survivors, proof, clock,
        )))
    }

    /// When the restart swept, unless it was refused before: always over an
    /// unchanged tree, and exactly once a request pending on this boot could
    /// no longer attach a loop device.
    fn assert_swept_after_any_pending_request(restarted: &Restarted, label: &str) {
        if let Some((swept_after, unchanged)) = restarted.swept {
            assert!(unchanged, "{label}: removed before the loop sweep");
            let wait = if restarted.request_pending {
                PENDING_REQUEST
            } else {
                Duration::ZERO
            };
            assert_eq!(swept_after, wait, "{label}: when the loop sweep ran");
        }
    }

    /// Restart over a crash state: with each consulted proof withheld it
    /// fails closed and removes nothing, if `withheld`; then it reconciles.
    fn assert_restart_reconciles(
        runtime: &Path,
        survivors: &CrashSurvivors,
        count: u8,
        label: &str,
        withheld: bool,
    ) -> TestResult {
        let crashed = snapshot(runtime)?;
        let proofs = if withheld {
            consulted_proofs(&crashed, survivors)
        } else {
            Vec::new()
        };
        for proof in proofs {
            let label = format!("{label}, {proof:?} withheld");
            let restarted = restart(runtime, survivors, proof, RestartClock::SameBootSoon)?;
            assert_swept_after_any_pending_request(&restarted, &label);
            assert!(
                restarted
                    .result
                    .as_ref()
                    .err()
                    .is_some_and(|error| refused_by(proof, error)),
                "{label}: {:?}",
                restarted.result
            );
            assert_eq!(
                snapshot(runtime)?,
                crashed,
                "{label}: a refused restart removed state"
            );
            assert_admission_closed(runtime, &crashed, &label)?;
        }
        assert_restart_succeeds(runtime, survivors, count, label, UncertainProof::None)
    }

    /// Admission stays closed while anything but the marker remains.
    fn assert_admission_closed(runtime: &Path, crashed: &Snapshot, label: &str) -> TestResult {
        if records(crashed).next().is_some()
            || crashed.registry.keys().any(|name| name.starts_with('.'))
        {
            assert!(
                matches!(
                    registry(runtime)?,
                    Err(SystemdAttemptRegistryError::ReconciliationRequired)
                ),
                "{label}: admission reopened"
            );
        }
        Ok(())
    }

    /// Restart on the activation marker's boot, with `proof` withheld though
    /// this crash state does not consult it: it stops the surviving unit,
    /// detaches the surviving root, cleans the network, waits out a pending
    /// request before its loop sweep, removes exactly the committed attempts,
    /// and admission reopens for the same attempts.
    fn assert_restart_succeeds(
        runtime: &Path,
        survivors: &CrashSurvivors,
        count: u8,
        label: &str,
        proof: UncertainProof,
    ) -> TestResult {
        assert_restart_succeeds_at(
            runtime,
            survivors,
            count,
            label,
            (proof, RestartClock::SameBootSoon),
        )
    }

    /// `assert_restart_succeeds` with `proof` withheld, at `clock`.
    fn assert_restart_succeeds_at(
        runtime: &Path,
        survivors: &CrashSurvivors,
        count: u8,
        label: &str,
        (proof, clock): (UncertainProof, RestartClock),
    ) -> TestResult {
        let crashed = snapshot(runtime)?;
        let restarted = restart(runtime, survivors, proof, clock)?;
        assert_swept_after_any_pending_request(&restarted, label);
        assert!(restarted.swept.is_some(), "{label}: no loop sweep");
        assert!(
            restarted.still_loaded.is_empty(),
            "{label}: {:?} still loaded",
            restarted.still_loaded
        );
        assert_eq!(
            restarted.detached,
            survivors.mounted.into_iter().collect::<Vec<_>>(),
            "{label}: detached roots"
        );
        assert!(restarted.network_cleaned, "{label}: network");
        let reconciled = restarted
            .result
            .map_err(|error| format!("{label}: restart with every proof failed: {error:?}"))?;
        let removed = reconciled
            .attempts()
            .iter()
            .map(|intent| intent.unit_name().attempt_component().to_owned())
            .collect::<BTreeSet<_>>();
        let recorded = records(&crashed)
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(removed, recorded, "{label}: reconciled attempts");
        let clean = snapshot(runtime)?;
        // The activation marker is kept as it was, if there was one.
        assert_eq!(
            clean.registry,
            crashed
                .registry
                .iter()
                .filter(|(name, _)| *name == "activation")
                .map(|(name, bytes)| (name.clone(), bytes.clone()))
                .collect::<BTreeMap<_, _>>(),
            "{label}: registry after restart"
        );
        assert!(clean.attempts.is_empty(), "{label}: {:?}", clean.attempts);
        // Admission reopens over the reconciled registry, for the same
        // attempts too.
        let reopened = registry(runtime)??;
        for id in 1..=count {
            reopened.commit_planned(&intent(id)?)?;
        }
        Ok(())
    }

    /// A clean run of `count` lifecycles on `course`, with its pinned
    /// transition counts.
    fn clean_run(course: Course, count: u8) -> TestResult<Run> {
        let runtime = runtime()?;
        let clean = run(runtime.path(), course, count, Interruption::None)?;
        assert_eq!(clean.ended.len(), usize::from(count));
        for (attempt, cancel) in clean.ended.iter().zip(&clean.cancelled) {
            assert_eq!(
                matches!(attempt.cleanup(), Ok(Some(_))),
                course.proves_cleanup(),
                "{course:?}: {:?}",
                attempt.cleanup()
            );
            if course == Course::Cancelled {
                assert!(attempt.cancelled());
                assert!(matches!(
                    attempt.progress(),
                    AttemptProgress::Executed {
                        ending: AttemptEnding::Cancelled { .. },
                        ..
                    }
                ));
                assert!(
                    matches!(
                        cancel,
                        Some(Ok(SandboxCancellationResult::CancelledAndCleaned))
                    ),
                    "{cancel:?}"
                );
            }
        }
        let each = course.io_operations();
        assert_eq!(
            clean.ios_after,
            (1..=usize::from(count))
                .map(|attempt| attempt * each)
                .collect::<Vec<_>>(),
            "registry I/O operations of {count} lifecycles on {course:?}: review and count the new transitions"
        );
        assert_eq!(clean.ios, each * usize::from(count));
        assert_eq!(
            clean.reached,
            course.boundaries().repeat(usize::from(count))
        );
        assert_eq!(clean.survivors, CrashSurvivors::default());
        if course.proves_cleanup() {
            let left = snapshot(runtime.path())?;
            assert_eq!(left.registry.keys().collect::<Vec<_>>(), ["activation"]);
            assert!(left.attempts.is_empty());
        } else {
            // What the live owner could not prove, restart does.
            let label = format!("{course:?} clean run");
            assert_restart_reconciles(runtime.path(), &clean.survivors, count, &label, true)?;
        }
        Ok(clean)
    }

    /// Crash or fail at every interruption on `course` for `count`
    /// lifecycles, checking restart over each; returns the frontier each
    /// left of the attempt it hit, consecutive repeats merged.
    fn interrupt_each(
        course: Course,
        count: u8,
        interruptions: impl Iterator<Item = Interruption>,
        withheld: bool,
    ) -> TestResult<Vec<String>> {
        let mut frontiers: Vec<String> = Vec::new();
        for interruption in interruptions {
            let runtime = runtime()?;
            let left = run(runtime.path(), course, count, interruption)?;
            let label = format!("{course:?} {interruption:?}");
            match interruption {
                Interruption::CrashesAtIo(at) | Interruption::FailsAtIo(at) => {
                    assert!(left.ios > at, "{label}: not reached");
                }
                Interruption::CrashesAtBoundary(at) => {
                    assert_eq!(left.reached.len(), at + 1, "{label}");
                }
                Interruption::None => {}
            }
            let crashed = snapshot(runtime.path())?;
            let hit = attempt_of(course, interruption)?;
            let state = frontier(&crashed, &left.survivors, hit)?;
            if frontiers.last() != Some(&state) {
                frontiers.push(state.clone());
            }
            assert_restart_reconciles(
                runtime.path(),
                &left.survivors,
                count,
                &format!("{label} at {state}"),
                withheld,
            )?;
        }
        Ok(frontiers)
    }

    /// Every crash before a registry operation, at a boundary, and every
    /// failed operation, of one lifecycle on `course`; returns the frontiers
    /// of the operation crashes and of the boundary crashes.
    fn every_interruption(course: Course) -> TestResult<(Vec<String>, Vec<String>)> {
        let clean = clean_run(course, 1)?;
        let crashes = interrupt_each(
            course,
            1,
            (0..clean.ios).map(Interruption::CrashesAtIo),
            true,
        )?;
        let boundaries = interrupt_each(
            course,
            1,
            (0..clean.reached.len()).map(Interruption::CrashesAtBoundary),
            true,
        )?;
        interrupt_each(
            course,
            1,
            (0..clean.ios).map(Interruption::FailsAtIo),
            false,
        )?;
        Ok((crashes, boundaries))
    }

    /// The frontiers up to the PAI2 tree, which every course passes.
    const PREPARED: [&str; 7] = [
        // The planned intent: nothing, its interrupted write, then PAI1.
        "none",
        "tmp none",
        "PAI1",
        // mkdir of the attempt, then of its root, before PAI2.
        "PAI1 attempt",
        "PAI1 attempt root",
        "tmp PAI1 attempt root",
        "PAI2 attempt root",
    ];

    /// The frontiers after `PREPARED` of a lifecycle that starts its unit.
    const STARTED_FRONTIERS: [&str; 9] = [
        // The activation marker's interrupted write, recording the request
        // before it is sent.
        "tmp PAI2 attempt root",
        "PAI2 attempt root",
        // The attached root, its interrupted PAI3 write, then PAI3; the root
        // release verifies the tree with the unit already stopped.
        "PAI2 attempt root mounted",
        "tmp PAI2 attempt root mounted",
        "PAI3 attempt root mounted",
        // The released root, then the root removed with the attempt present
        // (#721), both removed, and the intent deleted last.
        "PAI3 attempt root",
        "PAI3 attempt",
        "PAI3",
        "none",
    ];

    /// The boundary frontiers of a lifecycle that starts its unit.
    const STARTED_BOUNDARIES: [&str; 5] = [
        // The request was sent: any loop device is the sweep's to find, after
        // a request still pending on this boot.
        "PAI2 attempt root",
        "PAI2 attempt root mounted",
        // A started unit survives until the stop, the root until release.
        "PAI3 attempt root unit mounted",
        "PAI3 attempt root mounted",
        "PAI3 attempt root",
    ];

    /// `PREPARED`, followed by `rest`.
    fn after_prepared(rest: &[&str]) -> Vec<String> {
        PREPARED
            .iter()
            .chain(rest)
            .map(|frontier| (*frontier).to_owned())
            .collect()
    }

    #[test]
    fn a_crash_before_every_registry_operation_reconciles_or_fails_closed() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_crash_before_every_registry_operation_reconciles_or_fails_closed",
        )? {
            return Ok(());
        }
        let clean = clean_run(Course::Executes, 1)?;
        let frontiers = interrupt_each(
            Course::Executes,
            1,
            (0..clean.ios).map(Interruption::CrashesAtIo),
            true,
        )?;
        assert_eq!(frontiers, after_prepared(&STARTED_FRONTIERS));
        Ok(())
    }

    #[test]
    fn a_crash_at_every_lifecycle_boundary_reconciles_or_fails_closed() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_crash_at_every_lifecycle_boundary_reconciles_or_fails_closed",
        )? {
            return Ok(());
        }
        let clean = clean_run(Course::Executes, 1)?;
        let frontiers = interrupt_each(
            Course::Executes,
            1,
            (0..clean.reached.len()).map(Interruption::CrashesAtBoundary),
            true,
        )?;
        assert_eq!(frontiers, STARTED_BOUNDARIES);
        Ok(())
    }

    #[test]
    fn a_failure_of_every_registry_operation_is_never_reported_clean() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_failure_of_every_registry_operation_is_never_reported_clean",
        )? {
            return Ok(());
        }
        let clean = clean_run(Course::Executes, 1)?;
        interrupt_each(
            Course::Executes,
            1,
            (0..clean.ios).map(Interruption::FailsAtIo),
            false,
        )?;
        Ok(())
    }

    #[test]
    fn a_cancelled_attempt_reconciles_at_every_crash() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_cancelled_attempt_reconciles_at_every_crash",
        )? {
            return Ok(());
        }
        let (crashes, boundaries) = every_interruption(Course::Cancelled)?;
        assert_eq!(crashes, after_prepared(&STARTED_FRONTIERS));
        assert_eq!(boundaries, STARTED_BOUNDARIES);
        Ok(())
    }

    #[test]
    fn a_refused_activation_removes_its_tree_without_a_root_at_every_crash() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_refused_activation_removes_its_tree_without_a_root_at_every_crash",
        )? {
            return Ok(());
        }
        let (crashes, boundaries) = every_interruption(Course::ActivationRefused)?;
        assert_eq!(
            crashes,
            // The root removed with the attempt present, both removed, and
            // the intent deleted last; no request was ever recorded.
            after_prepared(&["PAI2 attempt", "PAI2", "none"])
        );
        assert!(boundaries.is_empty());
        Ok(())
    }

    #[test]
    fn a_failed_request_leaves_its_tree_to_restart_at_every_crash() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_failed_request_leaves_its_tree_to_restart_at_every_crash",
        )? {
            return Ok(());
        }
        let (crashes, boundaries) = every_interruption(Course::RequestFails)?;
        assert_eq!(
            crashes,
            after_prepared(&["tmp PAI2 attempt root", "PAI2 attempt root"])
        );
        assert_eq!(boundaries, ["PAI2 attempt root"]);
        Ok(())
    }

    #[test]
    fn a_refused_launch_releases_its_root_without_a_unit_at_every_crash() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_refused_launch_releases_its_root_without_a_unit_at_every_crash",
        )? {
            return Ok(());
        }
        let (crashes, boundaries) = every_interruption(Course::LaunchRefused)?;
        assert_eq!(
            crashes,
            after_prepared(&[
                "tmp PAI2 attempt root",
                "PAI2 attempt root",
                // No PAI3: the launch was refused before its recheck.
                "PAI2 attempt root mounted",
                "PAI2 attempt root",
                "PAI2 attempt",
                "PAI2",
                "none",
            ])
        );
        assert_eq!(
            boundaries,
            [
                "PAI2 attempt root",
                "PAI2 attempt root mounted",
                "PAI2 attempt root",
            ]
        );
        Ok(())
    }

    #[test]
    fn a_withdrawn_attempt_does_no_registry_io() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_withdrawn_attempt_does_no_registry_io",
        )? {
            return Ok(());
        }
        let runtime = runtime()?;
        let tokio = paused()?;
        let lifecycle = lifecycle(runtime.path())?;
        let world = Arc::new(World::new(Course::Executes, None));
        let (withdrawn, operations) = with_io_fault(None, || {
            tokio.block_on(Box::pin(async {
                let fixture =
                    TeardownFixture::new(1, TeardownStop::Empty, TeardownReset::Unload).await?;
                let transport = Arc::new(fixture.transport);
                let steps = CrashSteps {
                    transport: Arc::clone(&transport),
                    cgroup: Mutex::new(Some(fixture.bound)),
                    world: Arc::clone(&world),
                };
                let owned = lifecycle.admit_input(CrashInput {
                    id: 1,
                    world: Arc::clone(&world),
                    transport,
                })?;
                // Cancelled before it ran, the attempt is withdrawn.
                let cancelled = Box::pin(lifecycle.cancel(&cancel_request([1; 16]))).await?;
                let ended = Box::pin(owned.run_with(&steps, (), budget()?)).await;
                Ok::<_, Box<dyn std::error::Error>>((cancelled, ended))
            }))
        });
        let (cancelled, ended) = withdrawn?;
        assert_eq!(cancelled, SandboxCancellationResult::CancelledAndCleaned);
        assert!(matches!(ended.progress(), AttemptProgress::Withdrawn));
        assert!(matches!(ended.cleanup(), Ok(None)));
        assert_eq!(operations, 0);
        assert!(lock(&world.reached).is_empty());
        let left = snapshot(runtime.path())?;
        assert_eq!(left.registry.keys().collect::<Vec<_>>(), ["activation"]);
        assert!(left.attempts.is_empty());
        Ok(())
    }

    #[test]
    fn eight_lifecycles_reconcile_after_a_crash_at_each_operation_offset_and_boundary() -> TestResult
    {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::eight_lifecycles_reconcile_after_a_crash_at_each_operation_offset_and_boundary",
        )? {
            return Ok(());
        }
        // Each attempt's own operations are pinned by the clean run.
        let clean = clean_run(Course::Executes, 8)?;
        let each = Course::Executes.io_operations();
        // Every registry operation of the first and the last attempt, and
        // each operation offset once in the six middle attempts: the offset
        // picks which of them crashes there. Every boundary of every attempt,
        // with each consulted proof withheld.
        let io = (0..clean.ios)
            .filter(|at| {
                let (attempt, offset) = (at / each, at % each);
                attempt == 0 || attempt == 7 || attempt == 1 + offset % 6
            })
            .map(Interruption::CrashesAtIo);
        interrupt_each(Course::Executes, 8, io, false)?;
        let boundaries = (0..clean.reached.len()).map(Interruption::CrashesAtBoundary);
        interrupt_each(Course::Executes, 8, boundaries, true)?;
        Ok(())
    }

    /// A crash state for restart to crash in.
    #[derive(Clone, Copy, Debug)]
    enum Base {
        /// The executing attempt, crashed as its execution ended: PAI3, its
        /// tree, its unit and its mounted root.
        Running,
        /// The executing attempt, crashed once its request was sent: PAI2
        /// and its tree, with the request pending on this boot.
        RequestSent,
        /// Two prepared attempts, as two concurrent owners leave them: two
        /// PAI2 trees, so restart removes several records.
        TwoPrepared,
    }

    impl Base {
        /// The registry I/O operations of one restart over this state.
        const fn restart_io_operations(self) -> usize {
            match self {
                Self::Running => 132,
                Self::RequestSent => 55,
                Self::TwoPrepared => 100,
            }
        }

        /// The crash state, its survivors and its attempts.
        fn crash(self) -> TestResult<(tempfile::TempDir, CrashSurvivors, u8)> {
            let runtime = runtime()?;
            if matches!(self, Self::TwoPrepared) {
                let registry = registry(runtime.path())??;
                for id in 1..=2 {
                    drop(
                        registry
                            .commit_planned(&intent(id)?)?
                            .prepare_fixture_directory()?,
                    );
                }
                return Ok((runtime, CrashSurvivors::default(), 2));
            }
            let crash = if matches!(self, Self::Running) {
                Boundary::ExecutionEnded
            } else {
                Boundary::RequestSent
            };
            let interruption = Interruption::CrashesAtBoundary(boundary(crash)?);
            let left = run(runtime.path(), Course::Executes, 1, interruption)?;
            Ok((runtime, left.survivors, 1))
        }
    }

    /// The occurrence of `crash` in one executing lifecycle.
    fn boundary(crash: Boundary) -> TestResult<usize> {
        Ok(STARTED
            .iter()
            .position(|boundary| *boundary == crash)
            .ok_or("no such boundary")?)
    }

    #[test]
    fn a_crash_inside_restart_reconciliation_converges_on_the_next_restart() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_crash_inside_restart_reconciliation_converges_on_the_next_restart",
        )? {
            return Ok(());
        }
        for base in [Base::Running, Base::RequestSent, Base::TwoPrepared] {
            let operations = {
                let (runtime, survivors, _) = base.crash()?;
                let (restarted, operations) = with_io_fault(None, || {
                    restart(
                        runtime.path(),
                        &survivors,
                        UncertainProof::None,
                        RestartClock::OtherBoot,
                    )
                });
                restarted?.result?;
                operations
            };
            assert_eq!(
                operations,
                base.restart_io_operations(),
                "registry I/O operations of one restart over {base:?}: review and count the new transitions"
            );
            for at in 0..operations {
                let (runtime, survivors, count) = base.crash()?;
                let (restarted, started) = with_io_crash(Some(at), || {
                    restart(
                        runtime.path(),
                        &survivors,
                        UncertainProof::None,
                        RestartClock::OtherBoot,
                    )
                });
                let restarted = restarted?;
                let label = format!("{base:?}, restart crashed at operation {at}");
                assert!(started > at, "{label}: not reached");
                assert!(
                    restarted.result.is_err(),
                    "{label}: a crashed restart reported success"
                );
                // What the crashed restart had already stopped or detached is
                // gone; everything else survives for the next restart.
                let survivors = CrashSurvivors {
                    unit: survivors.unit.filter(|unit| {
                        restarted
                            .still_loaded
                            .iter()
                            .any(|loaded| loaded == unit.as_str())
                    }),
                    mounted: survivors
                        .mounted
                        .filter(|attempt| !restarted.detached.contains(attempt)),
                };
                assert_restart_reconciles(runtime.path(), &survivors, count, &label, false)?;
            }
        }
        Ok(())
    }

    #[test]
    fn a_same_boot_restart_waits_out_a_pending_request_past_its_deadline() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_same_boot_restart_waits_out_a_pending_request_past_its_deadline",
        )? {
            return Ok(());
        }
        // A sweep that never returns elapses the deadline the wait extended,
        // removing nothing.
        let (runtime, survivors, count) = Base::RequestSent.crash()?;
        let crashed = snapshot(runtime.path())?;
        let hung = restart(
            runtime.path(),
            &survivors,
            UncertainProof::SweepHangs,
            RestartClock::SameBootSoonShortDeadline,
        )?;
        assert!(hung.request_pending);
        assert_swept_after_any_pending_request(&hung, "a hung sweep");
        assert!(
            matches!(
                hung.result,
                Err(RestartReconciliationError::DeadlineElapsed)
            ),
            "{:?}",
            hung.result
        );
        assert_eq!(snapshot(runtime.path())?, crashed);
        assert_admission_closed(runtime.path(), &crashed, "a hung sweep")?;
        // The overall deadline is far shorter than the wait, which extends
        // it (owner decision D2): the request is still waited out, and only
        // then are the loop devices swept and the attempt removed.
        assert_restart_succeeds_at(
            runtime.path(),
            &survivors,
            count,
            "a short deadline",
            (
                UncertainProof::None,
                RestartClock::SameBootSoonShortDeadline,
            ),
        )
    }

    #[test]
    fn a_crash_while_an_owner_opens_and_creates_its_marker_reconciles() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_crash_while_an_owner_opens_and_creates_its_marker_reconciles",
        )? {
            return Ok(());
        }
        let operations = {
            let runtime = runtime()?;
            let (opened, operations) = with_io_fault(None, || registry(runtime.path()));
            opened??;
            operations
        };
        assert_eq!(
            operations, OPEN_IO_OPERATIONS,
            "registry I/O operations of an owner open: review and count the new transitions"
        );
        for at in 0..operations {
            let runtime = runtime()?;
            let (opened, _) = with_io_crash(Some(at), || registry(runtime.path()));
            assert!(opened?.is_err(), "owner open operation {at}");
            assert_restart_reconciles(
                runtime.path(),
                &CrashSurvivors::default(),
                1,
                &format!("owner open crashed at operation {at}"),
                true,
            )?;
        }
        Ok(())
    }

    #[test]
    fn a_torn_temporary_write_left_by_a_crash_is_removed() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_torn_temporary_write_left_by_a_crash_is_removed",
        )? {
            return Ok(());
        }
        let clean = clean_run(Course::Executes, 1)?;
        let mut torn = 0;
        for at in 0..clean.ios {
            let runtime = runtime()?;
            let left = run(
                runtime.path(),
                Course::Executes,
                1,
                Interruption::CrashesAtIo(at),
            )?;
            let crashed = snapshot(runtime.path())?;
            let Some((name, bytes)) = crashed
                .registry
                .iter()
                .find(|(name, bytes)| name.starts_with('.') && bytes.len() > 1)
            else {
                continue;
            };
            let length = u64::try_from(bytes.len() / 2)?;
            OpenOptions::new()
                .write(true)
                .open(runtime.path().join("registry").join(name))?
                .set_len(length)?;
            torn += 1;
            assert_restart_reconciles(
                runtime.path(),
                &left.survivors,
                1,
                &format!("torn {name} at operation {at}"),
                false,
            )?;
        }
        // The planned, PAI2, activation-marker and PAI3 writes, each between
        // its write and its rename.
        assert!(torn >= 4, "{torn} torn writes");
        Ok(())
    }

    #[test]
    fn a_withheld_proof_that_restart_does_not_consult_does_not_close_admission() -> TestResult {
        if !in_lock_test_process(
            "lifecycle::attempts::crash_points::cases::a_withheld_proof_that_restart_does_not_consult_does_not_close_admission",
        )? {
            return Ok(());
        }
        for (crash, proof) in [
            // No unit survives a released root.
            (Boundary::RootReleased, UncertainProof::UnitStop),
            // No PAI3 root's devices are recorded before the root attached.
            (Boundary::RequestSent, UncertainProof::RecordedDevices),
        ] {
            let runtime = runtime()?;
            let left = run(
                runtime.path(),
                Course::Executes,
                1,
                Interruption::CrashesAtBoundary(boundary(crash)?),
            )?;
            assert!(
                !consulted_proofs(&snapshot(runtime.path())?, &left.survivors).contains(&proof)
            );
            assert_restart_succeeds(
                runtime.path(),
                &left.survivors,
                1,
                &format!("{crash:?} with {proof:?} withheld"),
                proof,
            )?;
        }
        // No root is recorded before the PAI2 extension.
        let mut planned_only = false;
        for at in 0..Course::Executes.io_operations() {
            let runtime = runtime()?;
            let left = run(
                runtime.path(),
                Course::Executes,
                1,
                Interruption::CrashesAtIo(at),
            )?;
            let crashed = snapshot(runtime.path())?;
            if frontier(&crashed, &left.survivors, 1)? != "PAI1" {
                continue;
            }
            planned_only = true;
            assert!(
                !consulted_proofs(&crashed, &left.survivors).contains(&UncertainProof::RootDetach)
            );
            assert_restart_succeeds(
                runtime.path(),
                &left.survivors,
                1,
                &format!("PAI1 at operation {at} with RootDetach withheld"),
                UncertainProof::RootDetach,
            )?;
        }
        assert!(planned_only);
        Ok(())
    }
}
