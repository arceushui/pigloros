//! The provider's attempt lifecycle (ADR-069 §4 and §8, ADR-087 §2 and §3).
//!
//! [`AttemptLifecycle`] composes the authenticated `execute`, `cancel` and
//! `reconcile` operations over one registry owner:
//!
//! * [`AttemptLifecycle::admit`] takes exclusive ownership of one admitted
//!   attempt. An `AttemptId` has one owner for the whole life of this
//!   runtime, so a repeated execute never launches a second time.
//! * [`OwnedAttempt::run`] commits the planned intent, prepares the attempt
//!   directory for the held image, activates and verifies the root, executes
//!   it, and finishes the terminal cleanup within one [`CleanupBudget`]: the
//!   exact unit is stopped first and its cgroup proved empty, the root is
//!   released and its devices proved absent, the directories are removed and
//!   the intent is deleted last.
//! * [`AttemptLifecycle::cancel`] fences an attempt whose unit start was not
//!   requested yet, signals a running execution, and waits for its cleanup.
//! * [`AttemptLifecycle::reconcile`] reports an attempt whose cleanup was
//!   proved, releases its retained admission, and forgets it: later requests
//!   for that attempt are unknown.
//!
//! Every cancel and reconcile request must name the attempt's AGR1 digest.
//! Any failure to prove cleanup, and any run dropped after it started,
//! quarantines the lifecycle: the registry owner commits no further intent
//! and the staging ledger issues no further grant, before AGR1. Only restart
//! reconciliation and a fresh ledger reopen admission. An attempt whose run
//! ended keeps its admitted input, and with it its staging reservation, until
//! it is reconciled. A run dropped part-way releases its input only after the
//! lifecycle was quarantined, so no grant can use the freed reservation. An
//! attempt withdrawn before it started releases its input at once.
//!
//! The ownership table and its tombstones live in memory, for this runtime
//! only (owner decision, 2026-11-11). A restarted provider forgets them; that
//! is safe because the selector issues a fresh, nonzero `AttemptId` for every
//! attempt and fences the previous runtime with SIR1 before a new one opens
//! (ADR-069 §4.1), so a stale grant of a reconciled attempt cannot be replayed
//! into the new runtime. Restart reconciliation removes every attempt the
//! previous runtime left behind.
//!
//! The attempt steps are ports, so the composition is exercised without
//! systemd, mountfsd or a kernel mount; production composes
//! [`SystemdAttemptSteps`] over the admitted [`VerifiedStagedInput`].

use std::collections::BTreeMap;
use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pos_reference::sandbox_provider_protocol::{
    NetworkCaptureStore, SandboxCancelRequest, SandboxCancellationResult, SandboxReconcileRequest,
};
use tokio::sync::watch;
use tokio::time::Instant;

use super::{finish_with, RootRelease};
use crate::{
    AdmittedAttempt, AttemptCancel, AttemptCleanupDeadlines, AttemptCleanupError, AttemptEnding,
    AttemptExecution, AttemptShutdownDeadlines, AttemptShutdownError, BoundAttemptCgroup,
    CancelSignal, CheckedRoot, CommittedPlannedAttempt, CompletedAttemptCleanup, ExecuteError,
    ExecuteFailure, ExecuteJob, ExecutionOwnership, ImageActivationError, LaunchBarrier,
    LocalNetworkPort, ModePlan, NetworkEvidence, PlannedAttemptIntent, PreparedAttemptDirectory,
    ReconciledRestart, RecordedRoot, RecoveredAttemptIntent, ReleaseOutcome, ReleaseResources,
    ResourceEvidence, StagingLedger, SystemdAttemptRegistry, SystemdAttemptRegistryError,
    SystemdTransientUnitTransport, SystemdVerifiedStart, TransientServiceUnitName, UnitState,
    VerifiedRootMount, VerifiedStagedInput,
};

/// The most live attempts one snapshot carries (ADR-069 §4.1, RCC1).
const MAX_LIVE_ATTEMPTS: usize = 256;

/// One attempt's terminal cleanup budget.
///
/// It is measured from the moment the execution returns and divided into
/// strictly ordered phases.
///
/// The lifecycle chooses no default grace period; the provider configures it.
#[derive(Clone, Copy, Debug)]
pub struct CleanupBudget {
    base: Instant,
    phases: AttemptCleanupDeadlines,
}

impl CleanupBudget {
    /// Bound stop and grace, the unit SIGKILL call, process shutdown, unit
    /// absence and root release, each measured from the end of execution.
    ///
    /// # Errors
    /// Rejects phases that are not strictly increasing.
    pub fn new(
        grace: Duration,
        unit_kill: Duration,
        shutdown: Duration,
        unit_absent: Duration,
        released: Duration,
    ) -> Result<Self, AttemptShutdownError> {
        let base = Instant::now();
        AttemptShutdownDeadlines::new(base + grace, base + unit_kill, base + shutdown)
            .and_then(|shutdown| {
                AttemptCleanupDeadlines::new(shutdown, base + unit_absent, base + released)
            })
            .map(|phases| Self { base, phases })
    }

    /// The absolute deadlines of a cleanup that starts at `start`.
    fn deadlines(self, start: Instant) -> AttemptCleanupDeadlines {
        self.phases
            .shifted(start.saturating_duration_since(self.base))
    }
}

/// Why an attempt operation was refused, or its cleanup not proved.
#[derive(Debug, thiserror::Error)]
pub enum AttemptLifecycleError {
    /// The attempt already has an owner in this runtime.
    #[error("the attempt already has an owner in this runtime")]
    AttemptKnown,
    /// Admission was fenced for recovery; no attempt enters this runtime and
    /// no second snapshot is taken.
    #[error("the runtime was fenced for recovery")]
    Fenced,
    /// The runtime already has 256 live attempts, as many as one recovery
    /// snapshot carries.
    #[error("the runtime already has 256 live attempts")]
    TooManyLiveAttempts,
    /// No attempt with this identity is known, or it was reconciled.
    #[error("the attempt is unknown")]
    UnknownAttempt,
    /// The request names another AGR1 than the attempt was admitted under.
    #[error("the request names another grant than the attempt's")]
    GrantMismatch,
    /// The attempt has not ended yet, so it cannot be proved clean.
    #[error("the attempt has not ended")]
    AttemptActive,
    /// The attempt ended without proved cleanup; the registry is quarantined.
    #[error("the attempt's cleanup was not proved")]
    CleanupFailed,
    /// The planned intent or the attempt directory could not be committed.
    #[error(transparent)]
    Registry(#[from] SystemdAttemptRegistryError),
    /// The terminal cleanup did not complete.
    #[error(transparent)]
    Cleanup(#[from] AttemptCleanupError),
}

/// How far an attempt got before its terminal cleanup.
#[derive(Debug)]
pub enum AttemptProgress<S> {
    /// Cancellation was requested before the run started: nothing was
    /// committed and nothing needs cleanup.
    Withdrawn,
    /// No attempt directory was prepared; see the cleanup's error.
    NotPrepared,
    /// Cancellation was requested before the root was activated.
    CancelledBeforeActivation,
    /// The root could not be activated and verified.
    NotActivated(ImageActivationError),
    /// The execution failed; what is known of its unit.
    Failed {
        /// Why the execution failed.
        error: ExecuteError,
        /// What is known of the unit.
        unit: UnitState,
        /// The resource evidence, once the launcher barrier existed: what it
        /// established, the pre-release evidence once read, and the terminal
        /// evidence of a unit whose cgroup was bound.
        evidence: Option<ResourceEvidence>,
    },
    /// The execution ended.
    Executed {
        /// The verified start: its requested-state readback and the requested
        /// configuration (RQE1's inputs).
        started: S,
        /// How the released attempt ended.
        ending: AttemptEnding,
        /// The network evidence.
        network: NetworkEvidence,
        /// The pre-release, release and terminal resource evidence.
        evidence: ResourceEvidence,
    },
}

impl<S> AttemptProgress<S> {
    /// The verified start, if known, and the resource evidence of an
    /// execution that reached its launcher barrier.
    const fn reached(&mut self) -> Option<(Option<&S>, &mut ResourceEvidence)> {
        match self {
            Self::Executed {
                started, evidence, ..
            } => Some((Some(&*started), evidence)),
            Self::Failed {
                evidence: Some(evidence),
                ..
            } => Some((None, evidence)),
            _ => None,
        }
    }
}

/// The terminal cleanup of an ended attempt.
///
/// It is `Ok(None)` when the attempt was withdrawn before anything was
/// committed.
pub type AttemptCleanup = Result<Option<CompletedAttemptCleanup>, AttemptLifecycleError>;

/// One attempt after its terminal cleanup.
///
/// It is evidence for the attempt's classification and signed terminal
/// records (#443). Only the lifecycle creates one.
#[derive(Debug)]
pub struct EndedAttempt<S> {
    attempt_id: [u8; 16],
    cancelled: bool,
    progress: AttemptProgress<S>,
    cleanup: AttemptCleanup,
}

impl<S> EndedAttempt<S> {
    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// Whether cancellation was requested before the attempt ended; it
    /// outranks every other outcome.
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// How far the attempt got.
    #[must_use]
    pub const fn progress(&self) -> &AttemptProgress<S> {
        &self.progress
    }

    /// The completed cleanup, or why it was not proved. An error leaves the
    /// lifecycle quarantined and the intent for restart reconciliation.
    #[must_use = "the cleanup decides whether the attempt may be reported clean"]
    pub const fn cleanup(&self) -> &AttemptCleanup {
        &self.cleanup
    }

    /// The progress and cleanup by value, for the terminal records.
    pub fn into_parts(self) -> (AttemptProgress<S>, AttemptCleanup) {
        (self.progress, self.cleanup)
    }
}

/// An attempt reported clean and forgotten: its admission was released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledAttempt {
    attempt_id: [u8; 16],
    intent: Option<PlannedAttemptIntent>,
}

impl ReconciledAttempt {
    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The planned ownership whose resources and intent were removed; `None`
    /// for an attempt withdrawn before anything was committed.
    #[must_use]
    pub const fn intent(&self) -> Option<&PlannedAttemptIntent> {
        self.intent.as_ref()
    }
}

/// The authenticated admission of one attempt, behind one port.
///
/// The production implementation is [`VerifiedStagedInput`], whose entry
/// holds the image and the policy of the exact verified exchange.
trait AdmittedInput: Send + Sync {
    /// The attached root this admission activates.
    type Root: RootRelease + Sync + 'static;

    /// The admitted `AttemptId`.
    fn attempt_id(&self) -> [u8; 16];

    /// The admitted SIM1 digest.
    fn sim1_digest(&self) -> [u8; 32];

    /// The self-digest of the AGR1 the attempt was admitted under.
    fn grant_digest(&self) -> [u8; 32];

    /// Create the attempt directory for the held image of this admission.
    fn prepare(
        &self,
        planned: CommittedPlannedAttempt,
    ) -> Result<PreparedAttemptDirectory, SystemdAttemptRegistryError>;

    /// Activate and verify the root of this admission on `directory`.
    fn activate<'a>(
        &'a self,
        directory: &'a PreparedAttemptDirectory,
    ) -> impl Future<Output = Result<Self::Root, ImageActivationError>> + Send + 'a;

    /// The admitted attempt facts, bound to `directory`.
    fn attempt(
        &self,
        directory: &PreparedAttemptDirectory,
    ) -> Result<AdmittedAttempt, ExecuteError>;

    /// The recheck of an activated root against current authority, run
    /// immediately before launch.
    fn checker(
        &self,
    ) -> impl Fn(&Self::Root, &PreparedAttemptDirectory) -> Result<CheckedRoot, ImageActivationError>
           + Send
           + Sync
           + '_;
}

impl AdmittedInput for VerifiedStagedInput {
    type Root = VerifiedRootMount;

    fn attempt_id(&self) -> [u8; 16] {
        self.entry().admission().snapshot().request().attempt_id
    }

    fn sim1_digest(&self) -> [u8; 32] {
        self.entry()
            .admission()
            .snapshot()
            .request()
            .authority
            .sim1_digest
    }

    fn grant_digest(&self) -> [u8; 32] {
        self.entry().grant_digest()
    }

    fn prepare(
        &self,
        planned: CommittedPlannedAttempt,
    ) -> Result<PreparedAttemptDirectory, SystemdAttemptRegistryError> {
        planned.prepare_directory(&self.entry().admission())
    }

    fn activate<'a>(
        &'a self,
        directory: &'a PreparedAttemptDirectory,
    ) -> impl Future<Output = Result<VerifiedRootMount, ImageActivationError>> + Send + 'a {
        let entry = self.entry();
        async move {
            let admission = entry.admission();
            crate::activate_admitted_root(&admission, directory).await
        }
    }

    fn attempt(
        &self,
        directory: &PreparedAttemptDirectory,
    ) -> Result<AdmittedAttempt, ExecuteError> {
        AdmittedAttempt::from_entry(&self.entry(), directory)
    }

    fn checker(
        &self,
    ) -> impl Fn(
        &VerifiedRootMount,
        &PreparedAttemptDirectory,
    ) -> Result<CheckedRoot, ImageActivationError>
           + Send
           + Sync
           + '_ {
        let entry = self.entry();
        move |root: &VerifiedRootMount, directory: &PreparedAttemptDirectory| {
            root.recheck(directory, &entry)
        }
    }
}

/// The recheck an execution runs immediately before its unit starts.
type Recheck<'a> = &'a (dyn Fn() -> Result<CheckedRoot, ImageActivationError> + Sync);

/// The result of one execution step.
type Executed<S, C> =
    Result<AttemptExecution<S, C, ResourceEvidence>, ExecuteFailure<C, ResourceEvidence>>;

/// The execution and terminal cleanup of one attempt, behind one port.
trait AttemptSteps<I: AdmittedInput>: Sync {
    /// What one execution needs beyond the admission.
    type Launch: Send;
    /// The verified start of the unit.
    type Started: Send;
    /// The retained attempt cgroup.
    type Cgroup: Send;

    /// Execute the admitted attempt; `recheck` yields its verified root.
    fn execute<'a>(
        &'a self,
        launch: Self::Launch,
        attempt: AdmittedAttempt,
        recheck: Recheck<'a>,
        cancel: CancelSignal,
    ) -> impl Future<Output = Executed<Self::Started, Self::Cgroup>> + Send + 'a;

    /// Read the terminal evidence of `progress`, then finish the attempt's
    /// terminal cleanup within `deadlines`.
    fn finish<'a>(
        &'a self,
        progress: &'a mut AttemptProgress<Self::Started>,
        directory: PreparedAttemptDirectory,
        cgroup: Option<Self::Cgroup>,
        root: Option<I::Root>,
        deadlines: AttemptCleanupDeadlines,
    ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + 'a;
}

/// What one production execution needs beyond the admission.
pub struct AttemptLaunch<F> {
    /// The planned network behaviour; it must match the admitted mode.
    pub mode: ModePlan,
    /// Builds the launcher barrier for the admitted attempt.
    pub barrier: F,
}

/// The production attempt steps.
///
/// They use the systemd transport, the Local network and the capture store
/// of the provider.
pub struct SystemdAttemptSteps<'a, N, F> {
    transport: &'a SystemdTransientUnitTransport,
    network: &'a N,
    capture_store: Arc<NetworkCaptureStore>,
    barrier: PhantomData<fn(F)>,
}

impl<'a, N, F> SystemdAttemptSteps<'a, N, F> {
    /// Steps over the provider's transport, Local network and capture store.
    #[must_use]
    pub const fn new(
        transport: &'a SystemdTransientUnitTransport,
        network: &'a N,
        capture_store: Arc<NetworkCaptureStore>,
    ) -> Self {
        Self {
            transport,
            network,
            capture_store,
            barrier: PhantomData,
        }
    }
}

impl<I, N, F, B, E> AttemptSteps<I> for SystemdAttemptSteps<'_, N, F>
where
    I: AdmittedInput,
    N: LocalNetworkPort + Sync,
    F: FnOnce(&AdmittedAttempt) -> Result<B, E> + Send,
    B: LaunchBarrier<Evidence = ReleaseOutcome> + Send + 'static,
    E: Error + Send + Sync + 'static,
{
    type Launch = AttemptLaunch<F>;
    type Started = SystemdVerifiedStart;
    type Cgroup = crate::BoundAttemptCgroup;

    fn execute<'a>(
        &'a self,
        launch: AttemptLaunch<F>,
        attempt: AdmittedAttempt,
        recheck: Recheck<'a>,
        cancel: CancelSignal,
    ) -> impl Future<Output = Executed<SystemdVerifiedStart, crate::BoundAttemptCgroup>> + Send + 'a
    {
        let barrier = (launch.barrier)(&attempt);
        let job = ExecuteJob {
            attempt,
            mode: launch.mode,
            capture_store: Arc::clone(&self.capture_store),
            cancel,
        };
        async move {
            match barrier {
                Ok(mut barrier) => {
                    let executed =
                        crate::execute(self.transport, &mut barrier, self.network, job, recheck)
                            .await;
                    with_release(executed, barrier.evidence())
                }
                Err(error) => Err(ExecuteFailure {
                    error: ExecuteError::Barrier(Box::new(error)),
                    unit: UnitState::NotStarted,
                    cgroup: None,
                    evidence: None,
                }),
            }
        }
    }

    async fn finish<'a>(
        &'a self,
        progress: &'a mut AttemptProgress<SystemdVerifiedStart>,
        directory: PreparedAttemptDirectory,
        cgroup: Option<crate::BoundAttemptCgroup>,
        root: Option<I::Root>,
        deadlines: AttemptCleanupDeadlines,
    ) -> Result<CompletedAttemptCleanup, AttemptCleanupError> {
        let unit = directory.intent().unit_name().clone();
        let settle_by = deadlines.shutdown().grace();
        conclude(self.transport, progress, &unit, cgroup.as_ref(), settle_by).await;
        finish_with(self.transport, directory, cgroup, root, deadlines).await
    }
}

/// The production execution's result with what its launcher barrier
/// established.
fn with_release<S, C>(
    executed: Result<AttemptExecution<S, C, ReleaseResources>, ExecuteFailure<C, ReleaseResources>>,
    release: ReleaseOutcome,
) -> Executed<S, C> {
    match executed {
        Ok(execution) => Ok(AttemptExecution {
            attempt_id: execution.attempt_id,
            started: execution.started,
            cgroup: execution.cgroup,
            ending: execution.ending,
            network: execution.network,
            evidence: ResourceEvidence::new(Some(execution.evidence), release),
        }),
        Err(failure) => Err(ExecuteFailure {
            error: failure.error,
            unit: failure.unit,
            cgroup: failure.cgroup,
            evidence: Some(ResourceEvidence::new(failure.evidence, release)),
        }),
    }
}

/// Read the terminal evidence of a pinned unit, before its teardown.
///
/// Only a unit whose cgroup was bound was pinned: `RefUnit` precedes the
/// binding. Its result, counters and `/work` usage are read, then its pin is
/// released, so the teardown's absence wait can see it unloaded.
async fn conclude(
    transport: &SystemdTransientUnitTransport,
    progress: &mut AttemptProgress<SystemdVerifiedStart>,
    unit: &TransientServiceUnitName,
    cgroup: Option<&BoundAttemptCgroup>,
    settle_by: Instant,
) {
    let Some((started, evidence)) = progress.reached() else {
        return;
    };
    let Some(cgroup) = cgroup else {
        return;
    };
    let work = evidence.release().work();
    let terminal = transport
        .conclude(unit, started, cgroup, work, settle_by)
        .await;
    evidence.conclude(terminal);
}

/// What an attempt's run shares with cancellation and the recovery snapshot.
#[derive(Debug)]
struct RunState {
    sim1_digest: [u8; 32],
    cancel: AttemptCancel,
    // Set once the directory exists, so a cancellation can fence it.
    fence: Mutex<Option<ExecutionOwnership>>,
}

impl RunState {
    /// Request cancellation, then fence any unit start not yet requested.
    fn cancel(&self) {
        self.cancel.cancel();
        let held = lock(&self.fence);
        if let Some(fence) = held.as_ref() {
            fence.fence_unsubmitted();
        }
    }

    /// Hold the directory's execution fence for a later cancellation. One
    /// requested before is seen by the run before it activates anything.
    fn hold(&self, fence: ExecutionOwnership) {
        *lock(&self.fence) = Some(fence);
    }

    /// The cgroup the attempt's execution bound, if it bound one.
    fn bound_cgroup(&self) -> Option<(u64, u64)> {
        lock(&self.fence)
            .as_ref()
            .and_then(ExecutionOwnership::bound_cgroup)
    }
}

/// One live attempt of a [`LiveAttemptSnapshot`].
///
/// Its identities are as this runtime and its durable record know them. Each
/// is a claim for the sealed recovery (#349) to correlate with fresh kernel
/// evidence, never evidence itself.
#[derive(Debug, Eq, PartialEq)]
pub struct LiveAttemptIdentity {
    attempt_id: [u8; 16],
    unit_name: TransientServiceUnitName,
    sim1_digest: [u8; 32],
    recorded: Option<RecoveredAttemptIntent>,
    cgroup: Option<(u64, u64)>,
}

impl LiveAttemptIdentity {
    /// The `AttemptId`.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The deterministic unit of the attempt.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// The admitted SIM1 digest.
    #[must_use]
    pub const fn sim1_digest(&self) -> [u8; 32] {
        self.sim1_digest
    }

    /// The held image's `(device, inode)`, once the directory was recorded.
    #[must_use]
    pub fn image(&self) -> Option<(u64, u64)> {
        self.recorded
            .as_ref()
            .and_then(RecoveredAttemptIntent::recorded_image)
    }

    /// The attempt and root directories' `(device, inode)`, once recorded.
    #[must_use]
    pub fn directories(&self) -> Option<[(u64, u64); 2]> {
        self.recorded
            .as_ref()
            .and_then(RecoveredAttemptIntent::directory_identities)
    }

    /// The cgroup the execution bound to the unit, if it bound one.
    #[must_use]
    pub const fn cgroup(&self) -> Option<(u64, u64)> {
        self.cgroup
    }

    /// The PAI3 root facts recorded before launch, if any.
    #[must_use]
    pub fn root(&self) -> Option<&RecordedRoot> {
        self.recorded
            .as_ref()
            .and_then(RecoveredAttemptIntent::recorded_root)
    }
}

/// The live attempts of a runtime fenced for recovery.
///
/// This is the exact identity handoff to the sealed recovery (#349).
///
/// Only [`AttemptLifecycle::fence_and_snapshot`] creates one, once per
/// runtime; it has no public constructor and cannot be cloned.
///
/// The attempts are every one that started in this runtime and was not
/// reconciled, in strictly increasing `AttemptId` order, at most 256.
// Stable rustdoc checks only that these examples fail to compile; nightly
// rustdoc, as the mutation baseline runs it, also checks their error codes.
#[cfg_attr(
    target_os = "linux",
    doc = r"
```compile_fail,E0451
let _forged = pos_sandboxd::LiveAttemptSnapshot { attempts: Vec::new() };
```

```compile_fail,E0277
fn copy(snapshot: &pos_sandboxd::LiveAttemptSnapshot) -> pos_sandboxd::LiveAttemptSnapshot {
    <pos_sandboxd::LiveAttemptSnapshot as Clone>::clone(snapshot)
}
```
"
)]
#[derive(Debug, Eq, PartialEq)]
pub struct LiveAttemptSnapshot {
    attempts: Vec<LiveAttemptIdentity>,
}

impl LiveAttemptSnapshot {
    /// The live attempts, in strictly increasing `AttemptId` order.
    #[must_use]
    pub fn attempts(&self) -> &[LiveAttemptIdentity] {
        &self.attempts
    }
}

#[derive(Debug)]
enum Slot<I> {
    /// Owned by one owner; `started` once its run began to commit. The
    /// admission stays here until the run takes it.
    Running {
        grant: [u8; 32],
        state: Arc<RunState>,
        ended: watch::Receiver<bool>,
        started: bool,
        input: Option<I>,
    },
    /// Ended; `cleaned` is the removed intent when cleanup was proved.
    Ended {
        grant: [u8; 32],
        state: Arc<RunState>,
        cleaned: Option<PlannedAttemptIntent>,
        _input: Option<I>,
    },
    /// Reconciled, or withdrawn before it started (`intent` is `None`):
    /// cancel and execute requests for the attempt are unknown from now on,
    /// and a repeated reconcile names the same grant.
    Reconciled {
        grant: [u8; 32],
        intent: Option<PlannedAttemptIntent>,
    },
}

impl<I> Slot<I> {
    const fn is_live(&self) -> bool {
        !matches!(self, Self::Reconciled { .. })
    }

    const fn grant(&self) -> [u8; 32] {
        match self {
            Self::Running { grant, .. }
            | Self::Ended { grant, .. }
            | Self::Reconciled { grant, .. } => *grant,
        }
    }
}

/// Every attempt of the runtime and how many of them are live.
#[derive(Debug)]
struct Table<I> {
    slots: BTreeMap<[u8; 16], Slot<I>>,
    live: usize,
}

impl<I> Table<I> {
    const fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            live: 0,
        }
    }

    fn get(&self, attempt_id: &[u8; 16]) -> Option<&Slot<I>> {
        self.slots.get(attempt_id)
    }

    /// Replace the slot of `attempt_id`, keeping the live count; the slot it
    /// replaced, to be dropped once the lock is released.
    fn set(&mut self, attempt_id: [u8; 16], slot: Slot<I>) -> Option<Slot<I>> {
        let live = usize::from(slot.is_live());
        let replaced = self.slots.insert(attempt_id, slot);
        let was_live = usize::from(replaced.as_ref().is_some_and(Slot::is_live));
        self.live = self.live + live - was_live;
        replaced
    }

    /// Withdraw an attempt that never started: it is no longer live.
    fn withdraw(&mut self, attempt_id: [u8; 16], grant: [u8; 32]) -> Option<Slot<I>> {
        self.set(
            attempt_id,
            Slot::Reconciled {
                grant,
                intent: None,
            },
        )
    }
}

/// What a cancellation found.
enum Signalled {
    /// The attempt had already ended, clean.
    Terminal,
    /// The attempt had not started; it was withdrawn.
    Withdrawn,
    /// The attempt runs; this wakes when it ended.
    Running(watch::Receiver<bool>),
}

/// The live attempts of one provider runtime over one registry owner.
#[derive(Debug)]
pub struct AttemptLifecycle<I = VerifiedStagedInput> {
    registry: SystemdAttemptRegistry,
    ledger: StagingLedger,
    // Set by the first recovery fence; no attempt is admitted afterwards.
    fenced: AtomicBool,
    // Set once a recovery snapshot was handed out.
    snapshot_taken: AtomicBool,
    attempts: Mutex<Table<I>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<I> AttemptLifecycle<I> {
    /// The lifecycle over the registry owner and the staging ledger opened
    /// after `_reconciled` proved the previous runtime's attempts absent.
    ///
    /// A quarantine closes both: the registry to new intents and the ledger
    /// to new grants, before AGR1. Neither reopens; the next runtime's restart
    /// reconciliation and a fresh ledger do.
    #[must_use]
    pub const fn new(
        registry: SystemdAttemptRegistry,
        ledger: StagingLedger,
        _reconciled: &ReconciledRestart,
    ) -> Self {
        Self {
            registry,
            ledger,
            fenced: AtomicBool::new(false),
            snapshot_taken: AtomicBool::new(false),
            attempts: Mutex::new(Table::new()),
        }
    }

    /// Close admission until restart reconciliation: no new intent can be
    /// committed and no new grant issued.
    fn quarantine(&self) {
        self.registry.quarantine();
        self.ledger.close_for_reconciliation();
    }

    /// Cancel the attempt `request` names, and wait for its cleanup.
    ///
    /// An attempt that has not started is withdrawn at once and its admitted
    /// input, with its staging reservation, released: nothing was committed.
    /// An attempt that ended on its own while the request was waiting is
    /// reported cancelled as well: cancellation outranks every other outcome
    /// (ADR-069 §8). The wait is bounded by the attempt's watchdog and its
    /// cleanup budget.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] and
    /// [`AttemptLifecycleError::GrantMismatch`] refuse a request for another
    /// attempt or grant; [`AttemptLifecycleError::CleanupFailed`] reports an
    /// attempt whose cleanup was not proved.
    pub async fn cancel(
        &self,
        request: &SandboxCancelRequest,
    ) -> Result<SandboxCancellationResult, AttemptLifecycleError> {
        let attempt_id = request.attempt_id;
        let mut ended = match self.signal_cancel(attempt_id, request.agr1_digest)? {
            Signalled::Terminal => return Ok(SandboxCancellationResult::AlreadyTerminal),
            // Nothing was committed, so nothing remains to clean up.
            Signalled::Withdrawn => return Ok(SandboxCancellationResult::CancelledAndCleaned),
            Signalled::Running(ended) => ended,
        };
        // A dropped run ends the wait too; the slot then says what is known.
        ended.wait_for(|ended| *ended).await.ok();
        if self.ended_clean(attempt_id) {
            Ok(SandboxCancellationResult::CancelledAndCleaned)
        } else {
            Err(AttemptLifecycleError::CleanupFailed)
        }
    }

    /// Whether the attempt ended with its cleanup proved.
    fn ended_clean(&self, attempt_id: [u8; 16]) -> bool {
        matches!(
            lock(&self.attempts).get(&attempt_id),
            Some(
                Slot::Ended {
                    cleaned: Some(_),
                    ..
                } | Slot::Reconciled { .. }
            )
        )
    }

    /// Request the cancellation of an attempt under the attempts lock: a
    /// started run is signalled and fenced, an unstarted one is withdrawn.
    fn signal_cancel(
        &self,
        attempt_id: [u8; 16],
        grant_digest: [u8; 32],
    ) -> Result<Signalled, AttemptLifecycleError> {
        let mut attempts = lock(&self.attempts);
        let signalled = match attempts.get(&attempt_id) {
            None | Some(Slot::Reconciled { .. }) => {
                return Err(AttemptLifecycleError::UnknownAttempt)
            }
            Some(slot) if slot.grant() != grant_digest => {
                return Err(AttemptLifecycleError::GrantMismatch)
            }
            Some(Slot::Ended { cleaned: None, .. }) => {
                return Err(AttemptLifecycleError::CleanupFailed)
            }
            Some(Slot::Ended { .. }) => Signalled::Terminal,
            Some(Slot::Running {
                state,
                ended,
                started: true,
                ..
            }) => {
                state.cancel();
                Signalled::Running(ended.clone())
            }
            Some(Slot::Running { state, .. }) => {
                // Its owner may still call run: the request it would read
                // under this lock is already gone with the slot, but the
                // cancel flag keeps every signal of this attempt consistent.
                state.cancel();
                Signalled::Withdrawn
            }
        };
        let withdrawn = matches!(signalled, Signalled::Withdrawn)
            .then(|| attempts.withdraw(attempt_id, grant_digest));
        drop(attempts);
        // The withdrawn admission is released outside the attempts lock.
        drop(withdrawn);
        Ok(signalled)
    }

    /// Report the attempt `request` names as reconciled, release its retained
    /// admission and forget it. A repeated request reports it again.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::UnknownAttempt`] and
    /// [`AttemptLifecycleError::GrantMismatch`] refuse a request for another
    /// attempt or grant; [`AttemptLifecycleError::AttemptActive`] an attempt
    /// that has not ended; [`AttemptLifecycleError::CleanupFailed`] one whose
    /// cleanup was not proved.
    pub fn reconcile(
        &self,
        request: &SandboxReconcileRequest,
    ) -> Result<ReconciledAttempt, AttemptLifecycleError> {
        let attempt_id = request.attempt_id;
        let mut attempts = lock(&self.attempts);
        let slot = attempts
            .get(&attempt_id)
            .ok_or(AttemptLifecycleError::UnknownAttempt)?;
        let grant = slot.grant();
        if grant != request.agr1_digest {
            return Err(AttemptLifecycleError::GrantMismatch);
        }
        let intent = match slot {
            Slot::Reconciled { intent, .. } => {
                return Ok(ReconciledAttempt {
                    attempt_id,
                    intent: intent.clone(),
                })
            }
            Slot::Running { .. } => return Err(AttemptLifecycleError::AttemptActive),
            Slot::Ended { cleaned, .. } => cleaned
                .clone()
                .ok_or(AttemptLifecycleError::CleanupFailed)?,
        };
        let reconciled = Slot::Reconciled {
            grant,
            intent: Some(intent.clone()),
        };
        let released = attempts.set(attempt_id, reconciled);
        drop(attempts);
        // The retained admission is released outside the attempts lock.
        drop(released);
        Ok(ReconciledAttempt {
            attempt_id,
            intent: Some(intent),
        })
    }

    /// Fence this runtime for recovery and snapshot its live attempts: the
    /// exact identity handoff to the sealed recovery (#349).
    ///
    /// Admission closes permanently first: no attempt is admitted afterwards,
    /// the registry commits no new intent and the staging ledger issues no
    /// new grant. Every attempt that has not started is withdrawn, and every
    /// running one is cancelled; the snapshot is taken only once each of
    /// those ended, within its watchdog and cleanup budget, so no unit can
    /// start or directory disappear after it. Every attempt that started and
    /// was not reconciled is live, whether its cleanup was proved or not: its
    /// signed terminal evidence is not known here. That set is fixed under the
    /// attempts lock and the records are read after it is released, so a
    /// concurrent reconcile may already report a listed attempt as forgotten.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::Fenced`] once a snapshot was handed out, and
    /// a live attempt's unreadable or malformed record, after which a later
    /// call may try again. Admission stays closed either way.
    pub async fn fence_and_snapshot(&self) -> Result<LiveAttemptSnapshot, AttemptLifecycleError> {
        if self.snapshot_taken.load(Ordering::Acquire) {
            return Err(AttemptLifecycleError::Fenced);
        }
        let running = self.fence();
        self.quarantine();
        for mut ended in running {
            // A dropped run ends the wait too.
            ended.wait_for(|ended| *ended).await.ok();
        }
        // Every run has ended and nothing is admitted any more, so only
        // ended and reconciled slots remain; the records are read back once
        // the attempts lock is released.
        let mut ended = Vec::new();
        for (attempt_id, slot) in &lock(&self.attempts).slots {
            if let Slot::Ended { state, .. } = slot {
                ended.push((*attempt_id, Arc::clone(state)));
            }
        }
        let attempts = ended
            .into_iter()
            .map(|(attempt_id, state)| self.identity(attempt_id, &state))
            .collect::<Result<Vec<_>, _>>()?;
        // A concurrent call may have handed out its snapshot meanwhile.
        if self.snapshot_taken.swap(true, Ordering::AcqRel) {
            return Err(AttemptLifecycleError::Fenced);
        }
        Ok(LiveAttemptSnapshot { attempts })
    }

    /// Close admission under the attempts lock, withdraw every unstarted
    /// attempt and cancel every running one; the waits for the latter.
    fn fence(&self) -> Vec<watch::Receiver<bool>> {
        let mut attempts = lock(&self.attempts);
        self.fenced.store(true, Ordering::Release);
        let mut running = Vec::new();
        let mut unstarted = Vec::new();
        for (attempt_id, slot) in &attempts.slots {
            if let Slot::Running {
                grant,
                state,
                ended,
                started,
                ..
            } = slot
            {
                // A started run must stop; an unstarted one is withdrawn
                // below, and its cancel flag records why for any signal its
                // owner still holds.
                state.cancel();
                if *started {
                    running.push(ended.clone());
                } else {
                    unstarted.push((*attempt_id, *grant));
                }
            }
        }
        let withdrawn = unstarted
            .into_iter()
            .map(|(attempt_id, grant)| attempts.withdraw(attempt_id, grant))
            .collect::<Vec<_>>();
        drop(attempts);
        // Withdrawn admissions are released outside the attempts lock.
        drop(withdrawn);
        running
    }

    /// One live attempt's identities, its durable record read back.
    fn identity(
        &self,
        attempt_id: [u8; 16],
        state: &RunState,
    ) -> Result<LiveAttemptIdentity, AttemptLifecycleError> {
        let unit_name = TransientServiceUnitName::from_attempt_id(attempt_id)
            .map_err(|_| SystemdAttemptRegistryError::InvalidIntent)?;
        let recorded = self.registry.recorded(&unit_name)?;
        Ok(LiveAttemptIdentity {
            attempt_id,
            unit_name,
            sim1_digest: state.sim1_digest,
            recorded,
            cgroup: state.bound_cgroup(),
        })
    }
}

impl<I> AttemptLifecycle<I> {
    /// Take exclusive ownership of `input`'s attempt.
    fn admit_input(&self, input: I) -> Result<OwnedAttempt<'_, I>, AttemptLifecycleError>
    where
        I: AdmittedInput,
    {
        let attempt_id = input.attempt_id();
        let grant = input.grant_digest();
        let mut attempts = lock(&self.attempts);
        if self.fenced.load(Ordering::Acquire) {
            return Err(AttemptLifecycleError::Fenced);
        }
        if attempts.slots.contains_key(&attempt_id) {
            return Err(AttemptLifecycleError::AttemptKnown);
        }
        // A recovery snapshot must be able to carry every live attempt.
        if attempts.live >= MAX_LIVE_ATTEMPTS {
            return Err(AttemptLifecycleError::TooManyLiveAttempts);
        }
        let state = Arc::new(RunState {
            sim1_digest: input.sim1_digest(),
            cancel: AttemptCancel::new(),
            fence: Mutex::new(None),
        });
        let (ended, waiting) = watch::channel(false);
        let running = Slot::Running {
            grant,
            state: Arc::clone(&state),
            ended: waiting,
            started: false,
            input: Some(input),
        };
        attempts.set(attempt_id, running);
        drop(attempts);
        Ok(OwnedAttempt {
            claim: Claim {
                lifecycle: self,
                attempt_id,
                grant,
                state,
                ended,
                started: false,
                finished: false,
            },
        })
    }
}

impl AttemptLifecycle {
    /// Take exclusive ownership of the attempt `input` admitted.
    ///
    /// The lifecycle keeps the admission, and its staging reservation, until
    /// the attempt is withdrawn before it started, its run is dropped part-way
    /// (after the lifecycle was quarantined), or it is reconciled after it
    /// ended clean. An attempt that ended with its cleanup unproved keeps it:
    /// its reconcile reports [`AttemptLifecycleError::CleanupFailed`].
    ///
    /// # Errors
    /// [`AttemptLifecycleError::Fenced`] once the runtime was fenced for
    /// recovery; [`AttemptLifecycleError::AttemptKnown`] when this runtime
    /// already owns or owned the attempt; and
    /// [`AttemptLifecycleError::TooManyLiveAttempts`] at 256 live attempts.
    /// The refused input is dropped, releasing its reservation.
    pub fn admit(
        &self,
        input: VerifiedStagedInput,
    ) -> Result<OwnedAttempt<'_>, AttemptLifecycleError> {
        self.admit_input(input)
    }
}

/// The exclusive owner of one admitted attempt until it ended.
///
/// Dropping it before its run started withdraws the attempt and releases its
/// admission: nothing was committed. Dropping its run part-way quarantines
/// the lifecycle first, then records the attempt as ended without proved
/// cleanup and releases its admission.
#[derive(Debug)]
pub struct OwnedAttempt<'l, I = VerifiedStagedInput> {
    claim: Claim<'l, I>,
}

/// A started run: its claim and the admission it took.
///
/// Fields drop in declaration order, so a run dropped part-way quarantines
/// the lifecycle through its claim before the admission, and with it the
/// staging reservation, is released.
struct Run<'l, I> {
    claim: Claim<'l, I>,
    input: I,
}

#[derive(Debug)]
struct Claim<'l, I> {
    lifecycle: &'l AttemptLifecycle<I>,
    attempt_id: [u8; 16],
    grant: [u8; 32],
    state: Arc<RunState>,
    ended: watch::Sender<bool>,
    // Set before the first registry commit; an owner dropped earlier left
    // nothing behind.
    started: bool,
    finished: bool,
}

impl<I> Claim<'_, I> {
    /// Mark the run started, before its first commit, and take its
    /// admission; `None` when the attempt was withdrawn first. A withdrawn
    /// claim has nothing to record.
    fn begin(&mut self) -> Option<I> {
        let mut attempts = lock(&self.lifecycle.attempts);
        let input = match attempts.slots.get_mut(&self.attempt_id) {
            Some(Slot::Running { started, input, .. }) => {
                *started = true;
                input.take()
            }
            _ => None,
        };
        drop(attempts);
        self.started = input.is_some();
        self.finished = input.is_none();
        input
    }

    /// Record the attempt as ended, retaining `input` until reconciliation,
    /// then wake every waiting cancellation. Returns whether cancellation was
    /// requested, read under the same lock that a cancellation takes.
    fn end(&mut self, input: Option<I>, cleaned: Option<PlannedAttemptIntent>) -> bool {
        self.finished = true;
        let ended = Slot::Ended {
            grant: self.grant,
            state: Arc::clone(&self.state),
            cleaned,
            _input: input,
        };
        let mut attempts = lock(&self.lifecycle.attempts);
        let cancelled = self.state.cancel.is_requested();
        let replaced = attempts.set(self.attempt_id, ended);
        drop(attempts);
        drop(replaced);
        self.ended.send_replace(true);
        cancelled
    }

    /// Forget an owner that never started: nothing was committed, and its
    /// admission is released.
    fn withdraw(&mut self) {
        self.finished = true;
        let mut attempts = lock(&self.lifecycle.attempts);
        let withdrawn = attempts.withdraw(self.attempt_id, self.grant);
        drop(attempts);
        drop(withdrawn);
        self.ended.send_replace(true);
    }
}

impl<I> Drop for Claim<'_, I> {
    fn drop(&mut self) {
        if !self.finished {
            if self.started {
                // The run was abandoned: nothing about its resources is proved.
                self.lifecycle.quarantine();
                self.end(None, None);
            } else {
                self.withdraw();
            }
        }
    }
}

impl OwnedAttempt<'_> {
    /// Run the attempt to its end and finish its terminal cleanup.
    ///
    /// The attempt's cleanup is proved, or the registry owner is quarantined,
    /// before this returns. The returned value is evidence for the attempt's
    /// classification; it grants no admission.
    pub async fn run<N, F, B, E>(
        self,
        steps: &SystemdAttemptSteps<'_, N, F>,
        launch: AttemptLaunch<F>,
        budget: CleanupBudget,
    ) -> EndedAttempt<SystemdVerifiedStart>
    where
        N: LocalNetworkPort + Sync,
        F: FnOnce(&AdmittedAttempt) -> Result<B, E> + Send,
        B: LaunchBarrier<Evidence = ReleaseOutcome> + Send + 'static,
        E: Error + Send + Sync + 'static,
    {
        self.run_with(steps, launch, budget).await
    }
}

impl<I> OwnedAttempt<'_, I> {
    async fn run_with<S>(
        self,
        steps: &S,
        launch: S::Launch,
        budget: CleanupBudget,
    ) -> EndedAttempt<S::Started>
    where
        I: AdmittedInput,
        S: AttemptSteps<I>,
    {
        let Self { mut claim } = self;
        let attempt_id = claim.attempt_id;
        let Some(input) = claim.begin() else {
            return EndedAttempt {
                attempt_id,
                cancelled: true,
                progress: AttemptProgress::Withdrawn,
                cleanup: Ok(None),
            };
        };
        let run = Run { claim, input };
        let prepared = PlannedAttemptIntent::new(attempt_id, run.input.sim1_digest())
            .and_then(|intent| run.claim.lifecycle.registry.commit_planned(&intent))
            .and_then(|planned| run.input.prepare(planned));
        let ended = match prepared {
            Ok(directory) => {
                run.claim.state.hold(directory.execution_ownership());
                let cancel = run.claim.state.cancel.signal();
                run_prepared(steps, launch, &run.input, directory, cancel, budget).await
            }
            // A planned intent may already exist: only restart
            // reconciliation can remove it.
            Err(error) => (AttemptProgress::NotPrepared, Err(error.into())),
        };
        let (progress, cleanup) = ended;
        let cleaned = cleanup.as_ref().ok().map(|done| done.intent().clone());
        if cleaned.is_none() {
            run.claim.lifecycle.quarantine();
        }
        let Run { mut claim, input } = run;
        let cancelled = claim.end(Some(input), cleaned);
        EndedAttempt {
            attempt_id,
            cancelled,
            progress,
            cleanup: cleanup.map(Some),
        }
    }
}

/// Bind the admitted attempt to its directory, activate its root and execute
/// it: how far it got, its retained cgroup and its root.
async fn activate_and_execute<I: AdmittedInput, S: AttemptSteps<I>>(
    steps: &S,
    launch: S::Launch,
    input: &I,
    directory: &PreparedAttemptDirectory,
    cancel: CancelSignal,
) -> (
    AttemptProgress<S::Started>,
    Option<S::Cgroup>,
    Option<I::Root>,
) {
    let admitted = input.attempt(directory);
    let checker = input.checker();
    let attempt = match admitted {
        Ok(attempt) => attempt,
        Err(error) => {
            let unit = UnitState::NotStarted;
            let evidence = None;
            return (
                AttemptProgress::Failed {
                    error,
                    unit,
                    evidence,
                },
                None,
                None,
            );
        }
    };
    let root = match input.activate(directory).await {
        Ok(root) => root,
        Err(error) => return (AttemptProgress::NotActivated(error), None, None),
    };
    let recheck = || checker(&root, directory);
    let executed = steps.execute(launch, attempt, &recheck, cancel).await;
    let (progress, cgroup) = match executed {
        Ok(execution) => (
            AttemptProgress::Executed {
                started: execution.started,
                ending: execution.ending,
                network: execution.network,
                evidence: execution.evidence,
            },
            Some(execution.cgroup),
        ),
        Err(failure) => (
            AttemptProgress::Failed {
                error: failure.error,
                unit: failure.unit,
                evidence: failure.evidence,
            },
            failure.cgroup,
        ),
    };
    (progress, cgroup, Some(root))
}

type Progressed<S> = (
    AttemptProgress<S>,
    Result<CompletedAttemptCleanup, AttemptLifecycleError>,
);

/// Activate, execute and clean up an attempt whose directory was prepared.
async fn run_prepared<I: AdmittedInput, S: AttemptSteps<I>>(
    steps: &S,
    launch: S::Launch,
    input: &I,
    directory: PreparedAttemptDirectory,
    cancel: CancelSignal,
    budget: CleanupBudget,
) -> Progressed<S::Started> {
    let (mut progress, cgroup, root) = if cancel.is_requested() {
        (AttemptProgress::CancelledBeforeActivation, None, None)
    } else {
        activate_and_execute(steps, launch, input, &directory, cancel).await
    };
    let deadlines = budget.deadlines(Instant::now());
    let cleanup = steps
        .finish(&mut progress, directory, cgroup, root, deadlines)
        .await
        .map_err(AttemptLifecycleError::from);
    (progress, cleanup)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod crash_points;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
