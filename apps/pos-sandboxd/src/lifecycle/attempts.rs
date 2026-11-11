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
//! reconciliation and a fresh ledger reopen admission. A quarantined attempt
//! keeps its admitted input, and with it its staging reservation.
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
    AttemptExecution, AttemptShutdownDeadlines, AttemptShutdownError, CancelSignal, CheckedRoot,
    CommittedPlannedAttempt, CompletedAttemptCleanup, ExecuteError, ExecuteFailure, ExecuteJob,
    ExecutionOwnership, ImageActivationError, LaunchBarrier, LocalNetworkPort, ModePlan,
    NetworkEvidence, PlannedAttemptIntent, PreparedAttemptDirectory, ReconciledRestart,
    RecordedRoot, RecoveredAttemptIntent, StagingLedger, SystemdAttemptRegistry,
    SystemdAttemptRegistryError, SystemdTransientUnitTransport, SystemdVerifiedStart,
    TransientServiceUnitName, UnitState, VerifiedRootMount, VerifiedStagedInput,
};

/// The most live attempts one snapshot carries (ADR-069 §4.1, RCC1).
const MAX_LIVE_ATTEMPTS: usize = 256;

/// One attempt's terminal cleanup budget, measured from the moment its
/// execution returns, divided into strictly ordered phases.
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
    /// More live attempts than one snapshot may carry; admission stays closed.
    #[error("more than 256 live attempts")]
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
    },
    /// The execution ended.
    Executed {
        /// The verified start and its requested-state readback.
        started: S,
        /// How the released attempt ended.
        ending: AttemptEnding,
        /// The network evidence.
        network: NetworkEvidence,
    },
}

/// One attempt after its terminal cleanup, for its classification and
/// signed terminal records (#443).
#[derive(Debug)]
pub struct EndedAttempt<S> {
    /// The attempt identity.
    pub attempt_id: [u8; 16],
    /// Whether cancellation was requested; it outranks every other outcome.
    pub cancelled: bool,
    /// How far the attempt got.
    pub progress: AttemptProgress<S>,
    /// The completed cleanup, or why it was not proved. An error leaves the
    /// registry quarantined and the intent for restart reconciliation.
    pub cleanup: Result<CompletedAttemptCleanup, AttemptLifecycleError>,
}

/// An attempt whose cleanup was proved and whose admission was released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledAttempt {
    intent: PlannedAttemptIntent,
}

impl ReconciledAttempt {
    /// The planned ownership whose resources and intent were removed.
    #[must_use]
    pub const fn intent(&self) -> &PlannedAttemptIntent {
        &self.intent
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

    /// Recheck `root` against current authority immediately before launch.
    fn recheck(
        &self,
        root: &Self::Root,
        directory: &PreparedAttemptDirectory,
    ) -> Result<CheckedRoot, ImageActivationError>;
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

    fn recheck(
        &self,
        root: &VerifiedRootMount,
        directory: &PreparedAttemptDirectory,
    ) -> Result<CheckedRoot, ImageActivationError> {
        root.recheck(directory, &self.entry())
    }
}

/// The result of one execution step.
type Executed<S, C> = Result<AttemptExecution<S, C>, ExecuteFailure<C>>;

/// The execution and terminal cleanup of one attempt, behind one port.
trait AttemptSteps<I: AdmittedInput>: Sync {
    /// What one execution needs beyond the admission.
    type Launch: Send;
    /// The verified start of the unit.
    type Started: Send;
    /// The retained attempt cgroup.
    type Cgroup: Send;

    /// Execute the attempt on its verified `root`.
    fn execute<'a>(
        &'a self,
        launch: Self::Launch,
        input: &'a I,
        directory: &'a PreparedAttemptDirectory,
        root: &'a I::Root,
        cancel: CancelSignal,
    ) -> impl Future<Output = Executed<Self::Started, Self::Cgroup>> + Send + 'a;

    /// Finish the attempt's terminal cleanup within `deadlines`.
    fn finish(
        &self,
        directory: PreparedAttemptDirectory,
        cgroup: Option<Self::Cgroup>,
        root: Option<I::Root>,
        deadlines: AttemptCleanupDeadlines,
    ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + '_;
}

/// What one production execution needs beyond the admission.
pub struct AttemptLaunch<F> {
    /// The planned network behaviour; it must match the admitted mode.
    pub mode: ModePlan,
    /// Builds the launcher barrier for the admitted attempt.
    pub barrier: F,
}

/// The production steps: the systemd transport, the Local network and the
/// capture store of the provider.
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
    B: LaunchBarrier + Send + 'static,
    E: Error + Send + Sync + 'static,
{
    type Launch = AttemptLaunch<F>;
    type Started = SystemdVerifiedStart;
    type Cgroup = crate::BoundAttemptCgroup;

    fn execute<'a>(
        &'a self,
        launch: AttemptLaunch<F>,
        input: &'a I,
        directory: &'a PreparedAttemptDirectory,
        root: &'a I::Root,
        cancel: CancelSignal,
    ) -> impl Future<Output = Executed<SystemdVerifiedStart, crate::BoundAttemptCgroup>> + Send + 'a
    {
        let prepared = input.attempt(directory).and_then(|attempt| {
            (launch.barrier)(&attempt)
                .map(|barrier| (attempt, barrier))
                .map_err(|error| ExecuteError::Barrier(Box::new(error)))
        });
        let job = prepared.map(|(attempt, barrier)| {
            let job = ExecuteJob {
                attempt,
                mode: launch.mode,
                capture_store: Arc::clone(&self.capture_store),
                cancel,
            };
            (job, barrier)
        });
        async move {
            match job {
                Ok((job, mut barrier)) => {
                    let recheck = || input.recheck(root, directory);
                    crate::execute(self.transport, &mut barrier, self.network, job, recheck).await
                }
                Err(error) => Err(ExecuteFailure {
                    error,
                    unit: UnitState::NotStarted,
                    cgroup: None,
                }),
            }
        }
    }

    fn finish(
        &self,
        directory: PreparedAttemptDirectory,
        cgroup: Option<crate::BoundAttemptCgroup>,
        root: Option<I::Root>,
        deadlines: AttemptCleanupDeadlines,
    ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + '_
    {
        finish_with(self.transport, directory, cgroup, root, deadlines)
    }
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

/// One live attempt of a [`LiveAttemptSnapshot`], as this runtime and its
/// durable record know it. Every identity is a claim for the sealed recovery
/// (#349) to correlate with fresh kernel evidence, never evidence itself.
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

/// The live attempts of a runtime fenced for recovery: the exact identity
/// handoff to the sealed recovery (#349).
///
/// Only [`AttemptLifecycle::fence_and_snapshot`] creates one, once per
/// runtime; it has no public constructor and cannot be cloned:
///
/// ```compile_fail,E0451
/// let _forged = pos_sandboxd::LiveAttemptSnapshot { attempts: Vec::new() };
/// ```
///
/// The attempts are every one admitted to this runtime and not reconciled,
/// in strictly increasing `AttemptId` order, at most 256.
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
    /// Owned by one run.
    Running {
        grant: [u8; 32],
        state: Arc<RunState>,
        ended: watch::Receiver<bool>,
    },
    /// Ended; `cleaned` is the removed intent when cleanup was proved.
    Ended {
        grant: [u8; 32],
        state: Arc<RunState>,
        cleaned: Option<PlannedAttemptIntent>,
        _input: Option<I>,
    },
    /// Reconciled; cancel and execute requests for the attempt are unknown
    /// from now on, and a repeated reconcile names the same grant.
    Reconciled {
        grant: [u8; 32],
        intent: PlannedAttemptIntent,
    },
}

/// The live attempts of one provider runtime over one registry owner.
#[derive(Debug)]
pub struct AttemptLifecycle<I = VerifiedStagedInput> {
    registry: SystemdAttemptRegistry,
    ledger: StagingLedger,
    // Set once by the recovery snapshot; no attempt is admitted afterwards.
    fenced: AtomicBool,
    attempts: Mutex<BTreeMap<[u8; 16], Slot<I>>>,
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
            attempts: Mutex::new(BTreeMap::new()),
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
        let signalled = self.signal_cancel(attempt_id, request.agr1_digest)?;
        let Some(mut ended) = signalled else {
            return Ok(SandboxCancellationResult::AlreadyTerminal);
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

    /// Signal a running attempt; `None` when it already ended.
    fn signal_cancel(
        &self,
        attempt_id: [u8; 16],
        grant_digest: [u8; 32],
    ) -> Result<Option<watch::Receiver<bool>>, AttemptLifecycleError> {
        match lock(&self.attempts).get(&attempt_id) {
            None | Some(Slot::Reconciled { .. }) => Err(AttemptLifecycleError::UnknownAttempt),
            Some(Slot::Running { grant, .. } | Slot::Ended { grant, .. })
                if *grant != grant_digest =>
            {
                Err(AttemptLifecycleError::GrantMismatch)
            }
            Some(Slot::Ended { cleaned: None, .. }) => Err(AttemptLifecycleError::CleanupFailed),
            Some(Slot::Ended { .. }) => Ok(None),
            Some(Slot::Running { state, ended, .. }) => {
                state.cancel();
                Ok(Some(ended.clone()))
            }
        }
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
        let mut attempts = lock(&self.attempts);
        let slot = attempts
            .get_mut(&request.attempt_id)
            .ok_or(AttemptLifecycleError::UnknownAttempt)?;
        let (Slot::Running { grant, .. }
        | Slot::Ended { grant, .. }
        | Slot::Reconciled { grant, .. }) = slot;
        let grant = *grant;
        if grant != request.agr1_digest {
            return Err(AttemptLifecycleError::GrantMismatch);
        }
        let intent = match slot {
            Slot::Reconciled { intent, .. } => {
                return Ok(ReconciledAttempt {
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
            intent: intent.clone(),
        };
        let released = std::mem::replace(slot, reconciled);
        drop(attempts);
        // The retained admission is released outside the attempts lock.
        drop(released);
        Ok(ReconciledAttempt { intent })
    }

    /// Fence this runtime for recovery and snapshot its live attempts: the
    /// exact identity handoff to the sealed recovery (#349).
    ///
    /// Admission closes permanently first: no attempt is admitted afterwards,
    /// the registry commits no new intent and the staging ledger issues no
    /// new grant. Every attempt admitted and not reconciled is live, whether
    /// it still runs or ended; an ended one is included conservatively,
    /// since its signed terminal evidence is not known here.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::Fenced`] for every call after the first;
    /// [`AttemptLifecycleError::TooManyLiveAttempts`] above 256 live
    /// attempts; and a live attempt's unreadable or malformed record. Each
    /// leaves admission closed.
    pub fn fence_and_snapshot(&self) -> Result<LiveAttemptSnapshot, AttemptLifecycleError> {
        let attempts = lock(&self.attempts);
        if self.fenced.swap(true, Ordering::AcqRel) {
            return Err(AttemptLifecycleError::Fenced);
        }
        self.quarantine();
        let live: Vec<([u8; 16], Arc<RunState>)> = attempts
            .iter()
            .filter_map(|(attempt_id, slot)| match slot {
                Slot::Running { state, .. } | Slot::Ended { state, .. } => {
                    Some((*attempt_id, Arc::clone(state)))
                }
                Slot::Reconciled { .. } => None,
            })
            .collect();
        drop(attempts);
        if live.len() > MAX_LIVE_ATTEMPTS {
            return Err(AttemptLifecycleError::TooManyLiveAttempts);
        }
        live.into_iter()
            .map(|(attempt_id, state)| self.identity(attempt_id, &state))
            .collect::<Result<Vec<_>, _>>()
            .map(|attempts| LiveAttemptSnapshot { attempts })
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
        let mut attempts = lock(&self.attempts);
        if self.fenced.load(Ordering::Acquire) {
            return Err(AttemptLifecycleError::Fenced);
        }
        if attempts.contains_key(&attempt_id) {
            return Err(AttemptLifecycleError::AttemptKnown);
        }
        let state = Arc::new(RunState {
            sim1_digest: input.sim1_digest(),
            cancel: AttemptCancel::new(),
            fence: Mutex::new(None),
        });
        let (ended, waiting) = watch::channel(false);
        attempts.insert(
            attempt_id,
            Slot::Running {
                grant: input.grant_digest(),
                state: Arc::clone(&state),
                ended: waiting,
            },
        );
        drop(attempts);
        Ok(OwnedAttempt {
            claim: Claim {
                lifecycle: self,
                attempt_id,
                grant: input.grant_digest(),
                state,
                ended,
                started: false,
                finished: false,
            },
            input,
        })
    }
}

impl AttemptLifecycle {
    /// Take exclusive ownership of the attempt `input` admitted.
    ///
    /// # Errors
    /// [`AttemptLifecycleError::AttemptKnown`] when this runtime already owns
    /// or owned the attempt; the refused input is dropped, releasing its
    /// reservation.
    pub fn admit(
        &self,
        input: VerifiedStagedInput,
    ) -> Result<OwnedAttempt<'_>, AttemptLifecycleError> {
        self.admit_input(input)
    }
}

/// The exclusive owner of one admitted attempt until it ended.
///
/// Dropping it before its run finished records the attempt as ended without
/// proved cleanup; once the run started, it also quarantines the registry
/// owner.
#[derive(Debug)]
pub struct OwnedAttempt<'l, I = VerifiedStagedInput> {
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
    /// Record the attempt as ended, retaining `input` until reconciliation;
    /// then wake every waiting cancellation.
    fn end(&mut self, input: Option<I>, cleaned: Option<PlannedAttemptIntent>) {
        self.finished = true;
        let ended = Slot::Ended {
            grant: self.grant,
            state: Arc::clone(&self.state),
            cleaned,
            _input: input,
        };
        lock(&self.lifecycle.attempts).insert(self.attempt_id, ended);
        self.ended.send_replace(true);
    }
}

impl<I> Drop for Claim<'_, I> {
    fn drop(&mut self) {
        if !self.finished {
            if self.started {
                // The run was abandoned: nothing about its resources is proved.
                self.lifecycle.quarantine();
            }
            self.end(None, None);
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
        B: LaunchBarrier + Send + 'static,
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
        let Self { mut claim, input } = self;
        let attempt_id = input.attempt_id();
        claim.started = true;
        let prepared = PlannedAttemptIntent::new(attempt_id, input.sim1_digest())
            .and_then(|intent| claim.lifecycle.registry.commit_planned(&intent))
            .and_then(|planned| input.prepare(planned));
        let ended = match prepared {
            Ok(directory) => {
                claim.state.hold(directory.execution_ownership());
                let cancel = claim.state.cancel.signal();
                run_prepared(steps, launch, &input, directory, cancel, budget).await
            }
            // A planned intent may already exist: only restart
            // reconciliation can remove it.
            Err(error) => (AttemptProgress::NotPrepared, Err(error.into())),
        };
        let (progress, cleanup) = ended;
        let cleaned = cleanup.as_ref().ok().map(|done| done.intent().clone());
        if cleaned.is_none() {
            claim.lifecycle.quarantine();
        }
        let cancelled = claim.state.cancel.is_requested();
        claim.end(Some(input), cleaned);
        EndedAttempt {
            attempt_id,
            cancelled,
            progress,
            cleanup,
        }
    }
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
    let (progress, cgroup, root) = if cancel.is_requested() {
        (AttemptProgress::CancelledBeforeActivation, None, None)
    } else {
        match input.activate(&directory).await {
            Err(error) => (AttemptProgress::NotActivated(error), None, None),
            Ok(root) => {
                let executed = steps
                    .execute(launch, input, &directory, &root, cancel)
                    .await;
                let (progress, cgroup) = match executed {
                    Ok(execution) => (
                        AttemptProgress::Executed {
                            started: execution.started,
                            ending: execution.ending,
                            network: execution.network,
                        },
                        Some(execution.cgroup),
                    ),
                    Err(failure) => (
                        AttemptProgress::Failed {
                            error: failure.error,
                            unit: failure.unit,
                        },
                        failure.cgroup,
                    ),
                };
                (progress, cgroup, Some(root))
            }
        }
    };
    let deadlines = budget.deadlines(Instant::now());
    let cleanup = steps
        .finish(directory, cgroup, root, deadlines)
        .await
        .map_err(AttemptLifecycleError::from);
    (progress, cleanup)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
