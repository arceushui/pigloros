//! The provider's attempt lifecycle (ADR-069 §4 and §8, ADR-087 §2 and §3).
//!
//! [`AttemptLifecycle`] composes the authenticated `execute`, `cancel` and
//! `reconcile` operations over one registry owner:
//!
//! * [`AttemptLifecycle::claim`] claims an attempt for one exchange before
//!   its AGR1, and [`ExchangeClaim::convert`] converts the claim as the last
//!   check before the AGR1 write (ADR-069 R11 Amendment 1, item P8).
//! * [`AttemptLifecycle::admit`] takes exclusive ownership of one admitted
//!   attempt. An `AttemptId` has one owner for the whole life of this
//!   runtime, so a repeated execute never launches a second time.
//! * [`OwnedAttempt::run`] commits the planned intent, prepares the attempt
//!   directory for the held image, activates and verifies the root, executes
//!   it, and finishes the terminal cleanup within one [`CleanupBudget`]: the
//!   exact unit is stopped first and its cgroup proved empty, the root is
//!   released and its devices proved absent, the directories are removed and
//!   the intent is deleted last.
//! * [`AttemptLifecycle::cancel`] records the cancellation of an attempt
//!   awaiting its input, fences one whose unit start was not requested yet,
//!   signals a running execution, and waits for its cleanup;
//!   [`AttemptLifecycle::bind_cancel`] then waits for its signed terminal
//!   response and binds the SCY1 to it (ADR-069 R15 §3.6 item 2).
//! * [`AttemptLifecycle::record_failed_input`] records an attempt whose
//!   input failed after its AGR1 was sent: it ended with nothing committed,
//!   and stays known until it is reconciled.
//! * [`AttemptLifecycle::join`] joins an exact repeated execute to the
//!   attempt it repeats: it waits while the attempt is active and receives
//!   the stored full response, never a second AGR1 (ADR-069 §4).
//! * [`AttemptLifecycle::reconcile`] reports an attempt whose cleanup was
//!   proved, or that ended with nothing committed, and whose signed terminal
//!   response is retained: it builds the attempt's `reconciliation-evidence-v1`
//!   once, releases the retained admission and response, and tombstones the
//!   attempt with the evidence bytes (ADR-069 R15 §3.3 and §3.4). Later
//!   cancel and execute requests for it are unknown; a repeated reconcile
//!   replays the evidence.
//!
//! Only reconcile tombstones an attempt that has an AGR1: one cancelled or
//! whose owner was dropped before its run ends with nothing committed and a
//! signed or faulted response (R15 §3.6 item 2). One request ledger, per
//! runtime, holds the request IDs of SPX1, SCQ1 and SRQ1 alike (R15 N11).
//!
//! Every cancel and reconcile request must name the attempt's AGR1 digest.
//! Any failure to prove cleanup, and any run dropped after it started,
//! quarantines the lifecycle: the registry owner commits no further intent
//! and the staging ledger issues no further grant, before AGR1. Only restart
//! reconciliation and a fresh ledger reopen admission. An attempt whose run
//! ended keeps its admitted input, and with it its staging reservation, until
//! it is reconciled. A run dropped part-way releases its input only after the
//! lifecycle was quarantined, so no grant can use the freed reservation. An
//! attempt that ended before it started releases its input at once.
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

use pos_reference::provider_admission::execution::FailedInput;
use pos_reference::sandbox_provider_protocol::{
    CancelSource, NetworkCaptureStore, ReconciliationEvidence,
};
use tokio::sync::watch;
use tokio::time::Instant;

use super::{finish_with, RootRelease};
use crate::attempt_records::AttemptAdmission;
use crate::{
    AdapterIo, AdmittedAttempt, AttemptCancel, AttemptCleanupDeadlines, AttemptCleanupError,
    AttemptEnding, AttemptExecution, AttemptShutdownDeadlines, AttemptShutdownError,
    BoundAttemptCgroup, CancelSignal, CheckedRoot, CommittedPlannedAttempt,
    CompletedAttemptCleanup, ExecuteError, ExecuteFailure, ExecuteJob, ExecutionOwnership,
    ImageActivationError, LaunchBarrier, LocalNetworkPort, ModePlan, NetworkEvidence,
    NetworkRemovalFailure, PlannedAttemptIntent, PreparedAttemptDirectory, ReconciledRestart,
    RecordedRoot, RecoveredAttemptIntent, ReleaseOutcome, ReleaseResources, ResourceEvidence,
    StagingLedger, SystemdAttemptRegistry, SystemdAttemptRegistryError,
    SystemdTransientUnitTransport, SystemdVerifiedStart, TransientServiceUnitName, UnitState,
    VerifiedRootMount, VerifiedStagedInput,
};
use crate::{AdmittedRuntimeKey, KeyFileRuntimeSigner, ResponseFault, RuntimeAttestationSigner};

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
    pub(crate) fn deadlines(self, start: Instant) -> AttemptCleanupDeadlines {
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
    /// The attempt's terminal response could not be assembled or signed.
    #[error(transparent)]
    Response(#[from] ResponseFault),
    /// The attempt ended and its terminal response is not retained yet.
    #[error("the attempt's terminal response is not retained yet")]
    ResponsePending,
    /// The attempt's terminal response was refused as a provider fault, or
    /// its run was dropped part-way so none will be signed; the lifecycle is
    /// quarantined and restart reconciliation recovers.
    #[error("the attempt's terminal response is unavailable")]
    ResponseUnavailable,
    /// The stored response was already delivered whole, so it is kept and
    /// not re-issued (base ADR-069 §4: every connection receives the same
    /// stored response).
    #[error("the attempt's terminal response was already delivered")]
    ResponseDelivered,
    /// A request reuses a request ID this runtime recorded with other bytes,
    /// or a repeated execute carries other EVR1 or SPX1 bytes than the
    /// attempt was admitted with (ADR-069 §4, R15 N11; SPE1 16
    /// `RequestIdentityConflict`).
    #[error("the request differs from the one recorded under its identity")]
    RequestConflict,
    /// The attempt already holds four cancel or reconcile request IDs, and
    /// this request names a further one (ADR-069 R15 N11; SPE1 12).
    #[error("the attempt holds its four cancel and reconcile request IDs")]
    ControlRequestsExhausted,
}

/// How far an attempt got before its terminal cleanup.
#[derive(Debug)]
pub enum AttemptProgress<S> {
    /// The run never started: it was cancelled first, or its owner was
    /// dropped. Nothing was committed and nothing needs cleanup.
    Withdrawn,
    /// The input failed after AGR1 was sent: nothing was committed and
    /// nothing needs cleanup (TME1 progress 0, `input.complete = false`).
    InputFailed,
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
        /// The verified start, once the unit's start completed.
        started: Option<S>,
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
        /// The adapter's stdin feed and its stdout capture, which stays
        /// fenced until the terminal evidence.
        adapter: AdapterIo,
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
                started,
                evidence: Some(evidence),
                ..
            } => Some((started.as_ref(), evidence)),
            _ => None,
        }
    }
}

/// The terminal cleanup of an ended attempt.
///
/// It is `Ok(None)` when the attempt ended before anything was committed:
/// it never started its run, or its input failed (TME1 `cleanup.result = 2`).
pub type AttemptCleanup = Result<Option<CompletedAttemptCleanup>, AttemptLifecycleError>;

/// One attempt after its terminal cleanup.
///
/// It is evidence for the attempt's classification and signed terminal
/// records (#443). Only the lifecycle creates one.
#[derive(Debug)]
pub struct EndedAttempt<S> {
    attempt_id: [u8; 16],
    admission: AttemptAdmission,
    cancel_source: Option<CancelSource>,
    progress: AttemptProgress<S>,
    cleanup: AttemptCleanup,
    cleanup_finished_at: Option<u64>,
}

impl<S> EndedAttempt<S> {
    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// What the attempt was admitted with: its AGR1, the admitted facts
    /// and its input transfer.
    #[must_use]
    pub const fn admission(&self) -> &AttemptAdmission {
        &self.admission
    }

    /// Who first requested cancellation before the attempt ended, if anyone
    /// did: TME1 `cancel-source`. It outranks every other outcome.
    #[must_use]
    pub const fn cancel_source(&self) -> Option<CancelSource> {
        self.cancel_source
    }

    /// How far the attempt got.
    #[must_use]
    pub const fn progress(&self) -> &AttemptProgress<S> {
        &self.progress
    }

    /// The completed cleanup, or why it was not proved. An error leaves the
    /// lifecycle quarantined, and keeps the intent for restart reconciliation
    /// unless the error is a Local network that could not be removed (the
    /// cleanup had finished by then).
    #[must_use = "the cleanup decides whether the attempt may be reported clean"]
    pub const fn cleanup(&self) -> &AttemptCleanup {
        &self.cleanup
    }

    /// TME1 `cleanup.finished-at`: when the terminal cleanup returned,
    /// proved or not, or when the attempt ended with nothing committed, in
    /// `CLOCK_MONOTONIC` nanoseconds; `None` if the clock could not be read.
    #[must_use]
    pub const fn cleanup_finished_at(&self) -> Option<u64> {
        self.cleanup_finished_at
    }

    /// The progress and cleanup by value, for the terminal records.
    pub fn into_parts(self) -> (AttemptProgress<S>, AttemptCleanup) {
        (self.progress, self.cleanup)
    }

    /// An ended attempt with these parts, for the terminal records' tests.
    #[cfg(test)]
    pub(crate) fn for_test(
        attempt_id: [u8; 16],
        admission: AttemptAdmission,
        cancel_source: Option<CancelSource>,
        progress: AttemptProgress<S>,
        (cleanup, cleanup_finished_at): (AttemptCleanup, Option<u64>),
    ) -> Self {
        Self {
            attempt_id,
            admission,
            cancel_source,
            progress,
            cleanup,
            cleanup_finished_at,
        }
    }
}

/// An attempt reported clean and tombstoned: its admission and response
/// were released, and its reconciliation evidence is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledAttempt {
    attempt_id: [u8; 16],
    evidence: ReconciliationEvidence,
}

impl ReconciledAttempt {
    /// The attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// The exact `reconciliation-evidence-v1` bytes the attempt retains,
    /// built once at its first reconcile (ADR-069 R15 §3.4). No V1
    /// operation sends them; only their digest leaves the provider.
    #[must_use]
    pub const fn evidence(&self) -> &ReconciliationEvidence {
        &self.evidence
    }

    /// SRY1 field 5: the digest of [`Self::evidence`].
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence.digest()
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

    /// What the attempt was admitted with, for its terminal records.
    fn admission(&self) -> AttemptAdmission;

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

    fn admission(&self) -> AttemptAdmission {
        let entry = self.entry();
        AttemptAdmission::new(entry.grant().clone(), entry.transfer())
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

/// An admitted attempt whose input failed after its AGR1 was sent, behind
/// one port.
///
/// The production implementation is [`FailedInput`].
trait FailedAdmission {
    /// The admitted `AttemptId`.
    fn attempt_id(&self) -> [u8; 16];

    /// The self-digest of the AGR1 the attempt was admitted under.
    fn grant_digest(&self) -> [u8; 32];

    /// What the attempt was admitted with, for its terminal records.
    fn admission(&self) -> AttemptAdmission;
}

impl FailedAdmission for FailedInput {
    fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id()
    }

    fn grant_digest(&self) -> [u8; 32] {
        self.grant().digest()
    }

    fn admission(&self) -> AttemptAdmission {
        AttemptAdmission::new(self.grant().clone(), self.transfer())
    }
}

/// The current `CLOCK_MONOTONIC` time in nanoseconds, if the clock could
/// report it; TME1 records an unreadable time as missing evidence.
fn finished_at() -> Option<u64> {
    crate::launcher::clock::monotonic_ns().ok()
}

/// The recheck of an attempt's activated root against current authority.
///
/// It is `|| root.recheck(&directory, &entry)` over the root and directory
/// the lifecycle owns. The execution runs it immediately before the unit
/// starts, and the release barrier's `AuthorityCheck` again before
/// `ReleaseV1`.
pub type RootRecheck<'a> = &'a (dyn Fn() -> Result<CheckedRoot, ImageActivationError> + Sync);

/// The result of one execution step.
type Executed<S, C> =
    Result<AttemptExecution<S, C, ResourceEvidence>, ExecuteFailure<C, ResourceEvidence, S>>;

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
        recheck: RootRecheck<'a>,
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

/// Builds the launcher barrier of one admitted attempt.
///
/// The barrier may borrow the attempt's [`RootRecheck`], which the
/// lifecycle owns for the execution, so the production
/// `ProviderReleaseBarrier` can recheck the attempt's own root and
/// directory in its `AuthorityCheck` before `ReleaseV1`.
pub trait BarrierFactory: Send {
    /// The barrier, which may borrow the root recheck.
    type Barrier<'r>: LaunchBarrier<Evidence = ReleaseOutcome> + Send + 'r;
    /// Why the barrier could not be built.
    type Error: Error + Send + Sync + 'static;

    /// Build the barrier for `attempt`, whose root `root` rechecks and
    /// whose cancellation `cancel` reports: a cancellation requested before
    /// `ReleaseV1` refuses the release.
    ///
    /// # Errors
    /// Fails if the barrier cannot be built; nothing is started then.
    fn barrier<'r>(
        self,
        attempt: &AdmittedAttempt,
        root: RootRecheck<'r>,
        cancel: CancelSignal,
    ) -> Result<Self::Barrier<'r>, Self::Error>;
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

impl<I, N, F> AttemptSteps<I> for SystemdAttemptSteps<'_, N, F>
where
    I: AdmittedInput,
    N: LocalNetworkPort + Sync,
    F: BarrierFactory,
{
    type Launch = AttemptLaunch<F>;
    type Started = SystemdVerifiedStart;
    type Cgroup = crate::BoundAttemptCgroup;

    fn execute<'a>(
        &'a self,
        launch: AttemptLaunch<F>,
        attempt: AdmittedAttempt,
        recheck: RootRecheck<'a>,
        cancel: CancelSignal,
    ) -> impl Future<Output = Executed<SystemdVerifiedStart, crate::BoundAttemptCgroup>> + Send + 'a
    {
        let barrier = launch.barrier.barrier(&attempt, recheck, cancel.clone());
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
                    network_removal: None,
                    error: ExecuteError::Barrier(Box::new(error)),
                    unit: UnitState::NotStarted,
                    cgroup: None,
                    evidence: None,
                    started: None,
                }),
            }
        }
    }

    fn finish<'a>(
        &'a self,
        progress: &'a mut AttemptProgress<SystemdVerifiedStart>,
        directory: PreparedAttemptDirectory,
        cgroup: Option<crate::BoundAttemptCgroup>,
        root: Option<I::Root>,
        deadlines: AttemptCleanupDeadlines,
    ) -> impl Future<Output = Result<CompletedAttemptCleanup, AttemptCleanupError>> + Send + 'a
    {
        let unit = directory.intent().unit_name().clone();
        let settle_by = settle_deadline(Instant::now(), deadlines.shutdown().grace());
        async move {
            conclude(self.transport, progress, &unit, cgroup.as_ref(), settle_by).await;
            finish_with(self.transport, directory, cgroup, root, deadlines).await
        }
    }
}

/// The production execution's result with what its launcher barrier
/// established.
fn with_release<S, C>(
    executed: Result<
        AttemptExecution<S, C, ReleaseResources>,
        ExecuteFailure<C, ReleaseResources, S>,
    >,
    release: ReleaseOutcome,
) -> Executed<S, C> {
    match executed {
        Ok(execution) => Ok(AttemptExecution {
            network_removal: execution.network_removal,
            attempt_id: execution.attempt_id,
            started: execution.started,
            cgroup: execution.cgroup,
            ending: execution.ending,
            network: execution.network,
            evidence: ResourceEvidence::new(Some(execution.evidence), release),
            adapter: execution.adapter,
        }),
        Err(failure) => {
            // DIAGNOSTIC: why the execution failed, for the guest journal.
            std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!(
                    "pos-sandboxd diag: execute failed: {:?} {:?}\n",
                    failure.error, failure.unit
                ),
            )
            .ok();
            Err(ExecuteFailure {
                network_removal: failure.network_removal,
                error: failure.error,
                unit: failure.unit,
                cgroup: failure.cgroup,
                evidence: Some(ResourceEvidence::new(failure.evidence, release)),
                started: failure.started,
            })
        }
    }
}

/// How long an unsettled unit's result may be read again before teardown.
///
/// R9 §4.6.6 reads the result after exit and before `StopUnit`, but leaves
/// the wait for a settling unit open. The wait takes at most half of the
/// time left before the stop's grace deadline, so the stop always keeps the
/// other half for the graceful stop that precedes escalation.
fn settle_deadline(now: Instant, grace: Instant) -> Instant {
    now + grace.saturating_duration_since(now) / 2
}

/// Read the terminal evidence of a pinned unit, before its teardown.
///
/// Only a unit whose cgroup was bound was pinned: `RefUnit` precedes the
/// binding. Its result, counters and `/work` usage are read, then its pin is
/// released, so the teardown's absence wait can see it unloaded. The result
/// is read for the invocation whose cgroup was bound. The provider's `/work`
/// handle is closed here in every case, before `StopUnit` (ADR-069 R15 §3.6
/// item 3, N9).
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
    let work = evidence.take_work();
    let Some(cgroup) = cgroup else {
        return;
    };
    let invocation = cgroup.invocation_id();
    let terminal = transport
        .conclude(unit, started.zip(invocation), cgroup, work, settle_by)
        .await;
    let bound = invocation.map(|invocation| (invocation, crate::UnitCgroup::identity(cgroup)));
    evidence.conclude(bound, terminal);
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
    /// The state of an attempt admitted under SIM1 `sim1_digest`, already
    /// cancelled by `cancelled` while it awaited its input: its run then
    /// records the cancelled ending without committing anything.
    fn admitted(sim1_digest: [u8; 32], cancelled: Option<CancelSource>) -> Arc<Self> {
        let state = Arc::new(Self {
            sim1_digest,
            cancel: AttemptCancel::new(),
            fence: Mutex::new(None),
        });
        if let Some(source) = cancelled {
            state.cancel(source);
        }
        state
    }

    /// Request cancellation from `source`, then fence any unit start not
    /// yet requested.
    fn cancel(&self, source: CancelSource) {
        self.cancel.cancel(source);
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
/// evidence, never evidence itself. Its [`Self::cleanup_proved`] is the one
/// fact the live revocation responder reads (ADR-069 R11 §8.5): only a
/// snapshot whose every attempt proved its cleanup is acknowledged.
#[derive(Debug, Eq, PartialEq)]
pub struct LiveAttemptIdentity {
    attempt_id: [u8; 16],
    unit_name: TransientServiceUnitName,
    sim1_digest: [u8; 32],
    recorded: Option<RecoveredAttemptIntent>,
    cgroup: Option<(u64, u64)>,
    cleanup_proved: bool,
}

impl LiveAttemptIdentity {
    /// Whether the attempt ended with its cleanup proved: its slot is
    /// `Ended` with the removed intent (ADR-069 R11 §8.5). Only then may the
    /// live revocation responder acknowledge it as cancelled; any other live
    /// attempt means no RCA1, and recovery follows (R11 D8).
    #[must_use]
    pub const fn cleanup_proved(&self) -> bool {
        self.cleanup_proved
    }

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
/// This is the exact identity handoff to the sealed recovery (#349), and
/// the live attempt state of the provider's revocation responder (ADR-069
/// R11 §8.1): an attempt that never ran (ended before it started, or
/// ended by a failed input) is never listed.
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
    /// Claimed by one exchange before its AGR1 (ADR-069 R11 Amendment 1,
    /// item P8): `request` is the exchange's SPX1 digest. `changed` wakes
    /// the repeats waiting on it when the slot is converted or removed.
    Claimed {
        request: [u8; 32],
        request_id: [u8; 16],
        changed: watch::Sender<bool>,
    },
    /// Converted from a claim as the last check before its AGR1 write: the
    /// attempt awaits its input. `cancel` is the first cancellation
    /// requested meanwhile, which its recorded ending carries.
    Granted {
        grant: [u8; 32],
        request: [u8; 32],
        request_id: [u8; 16],
        cancel: Option<CancelSource>,
        changed: watch::Sender<bool>,
    },
    /// Owned by one owner; `started` once its run began to commit. The
    /// admission stays here until the run takes it.
    Running {
        grant: [u8; 32],
        request: [u8; 32],
        state: Arc<RunState>,
        ended: watch::Receiver<bool>,
        started: bool,
        input: Option<I>,
    },
    /// Ended, with what its cleanup achieved and its signed terminal
    /// response once retained. `state` is `None` for an attempt that never
    /// ran. `settled` wakes every joined repeat once the response is
    /// retained or refused, and when the slot is replaced.
    Ended {
        grant: [u8; 32],
        request: [u8; 32],
        state: Option<Arc<RunState>>,
        cleaned: Cleaned,
        response: Retained,
        settled: watch::Sender<bool>,
        _input: Option<I>,
    },
    /// Reconciled: cancel and execute requests for the attempt are unknown
    /// from now on, and a repeated reconcile that names the same grant
    /// replays `evidence`, built once (ADR-069 R15 §3.4).
    Reconciled {
        grant: [u8; 32],
        evidence: ReconciliationEvidence,
    },
}

/// What an ended attempt's terminal cleanup achieved.
#[derive(Debug)]
enum Cleaned {
    /// Cleanup was not proved; the lifecycle is quarantined.
    Unproved,
    /// The attempt ended before anything was committed: TME1
    /// `cleanup.result = 2`. R9 §4.6.1 names only a withdrawal; the owner
    /// decision of 2026-11-16 (Redmine #443, journal 22592) also uses it for
    /// a post-AGR1 input failure.
    NothingCommitted,
    /// Cleanup was proved and the intent removed.
    Proved,
}

impl<I> Slot<I> {
    const fn is_live(&self) -> bool {
        !matches!(self, Self::Reconciled { .. })
    }

    /// Mark a running slot's run started and take its admission; `None` for
    /// any other slot.
    const fn start(&mut self) -> Option<I> {
        match self {
            Self::Running { started, input, .. } => {
                *started = true;
                input.take()
            }
            _ => None,
        }
    }

    /// The AGR1 digest; `None` while only claimed.
    const fn agr1_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::Claimed { .. } => None,
            Self::Granted { grant, .. }
            | Self::Running { grant, .. }
            | Self::Ended { grant, .. }
            | Self::Reconciled { grant, .. } => Some(*grant),
        }
    }
}

/// Every attempt of the runtime, how many of them are live, and the
/// request ledger.
#[derive(Debug)]
struct Table<I> {
    slots: BTreeMap<[u8; 16], Slot<I>>,
    live: usize,
    // The request ledger of this runtime (ADR-069 R15 N11): the request
    // self-digest of each recorded SPX1, SCQ1 and SRQ1 request ID, whose
    // domain names its operation.
    requests: BTreeMap<[u8; 16], [u8; 32]>,
    // How many SCQ1 and SRQ1 entries each attempt holds; they live with its
    // slot and tombstone, and never count toward `live`.
    controls: BTreeMap<[u8; 16], u8>,
}

impl<I> Table<I> {
    const fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            live: 0,
            requests: BTreeMap::new(),
            controls: BTreeMap::new(),
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

    /// Remove the slot of `attempt_id`, keeping the live count; the slot it
    /// removed, to be dropped once the lock is released.
    fn remove(&mut self, attempt_id: [u8; 16]) -> Option<Slot<I>> {
        let removed = self.slots.remove(&attempt_id);
        self.live -= usize::from(removed.as_ref().is_some_and(Slot::is_live));
        removed
    }

    /// Release the claimed or granted slot of `attempt_id` before its
    /// attempt was admitted, and free its request ID; the slot it removed,
    /// to be dropped once the lock is released. Only the exchange holding a
    /// claim converts it, and after a fence no exchange claims, so a claimed
    /// or granted slot is the caller's.
    fn release(&mut self, attempt_id: [u8; 16]) -> Option<Slot<I>> {
        let request_id = match self.get(&attempt_id) {
            Some(Slot::Claimed { request_id, .. } | Slot::Granted { request_id, .. }) => {
                *request_id
            }
            _ => return None,
        };
        self.requests.remove(&request_id);
        self.remove(attempt_id)
    }

    /// Record the granted attempt of `attempt_id`, whose exchange ended
    /// without its input, as ended with nothing committed and no response
    /// that will be signed; the slot it replaced.
    fn abandon(&mut self, attempt_id: [u8; 16]) -> Option<Slot<I>> {
        let (grant, request) = match self.get(&attempt_id) {
            Some(Slot::Granted { grant, request, .. }) => (*grant, *request),
            _ => return None,
        };
        let ended = Slot::Ended {
            grant,
            request,
            state: None,
            cleaned: Cleaned::NothingCommitted,
            response: Retained::Faulted,
            settled: watch::channel(false).0,
            _input: None,
        };
        self.set(attempt_id, ended)
    }
}

/// Cancel the slot of `attempt_id` by revocation under the attempts lock:
/// `Some(Err(attempt_id))` for a claim the fence voids, and `Some(Ok(_))`,
/// the wait for its end, for a started run. A granted or unstarted attempt
/// is kept: its ending records the cancellation with nothing committed
/// (ADR-069 R11 Amendment 1, item P8).
fn revoke<I>(
    attempt_id: [u8; 16],
    slot: &mut Slot<I>,
) -> Option<Result<watch::Receiver<bool>, [u8; 16]>> {
    match slot {
        Slot::Claimed { .. } => Some(Err(attempt_id)),
        Slot::Granted { cancel, .. } => {
            cancel.get_or_insert(CancelSource::Revocation);
            None
        }
        Slot::Running {
            state,
            ended,
            started,
            ..
        } => {
            state.cancel(CancelSource::Revocation);
            started.then(|| Ok(ended.clone()))
        }
        Slot::Ended { .. } | Slot::Reconciled { .. } => None,
    }
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
    // Test-only: a step run as an owner begins its run, before it takes
    // the attempts lock, so a test can land a fence exactly there and prove
    // the cancellation is read under that lock (no production behaviour).
    #[cfg(test)]
    before_begin: BeginHook<I>,
    // Test-only: how many reconciliation-evidence tuples were built, so a
    // test can prove each attempt's is built once (ADR-069 R15 §3.4).
    #[cfg(test)]
    evidence_built: std::sync::atomic::AtomicUsize,
}

/// A test's step at the start of [`Claim::begin`].
#[cfg(test)]
type BeginStep<I> = Box<dyn FnOnce(&AttemptLifecycle<I>) + Send>;

/// The one test step [`Claim::begin`] runs before it takes the attempts
/// lock, so a test can interleave a fence there.
#[cfg(test)]
struct BeginHook<I>(Mutex<Option<BeginStep<I>>>);

#[cfg(test)]
impl<I> BeginHook<I> {
    /// Run the test's step, once.
    fn run(&self, lifecycle: &AttemptLifecycle<I>) {
        let step = lock(&self.0).take();
        if let Some(step) = step {
            step(lifecycle);
        }
    }
}

#[cfg(test)]
impl<I> std::fmt::Debug for BeginHook<I> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BeginHook")
    }
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
            #[cfg(test)]
            before_begin: BeginHook(Mutex::new(None)),
            #[cfg(test)]
            evidence_built: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Close admission until restart reconciliation: no new intent can be
    /// committed and no new grant issued.
    fn quarantine(&self) {
        self.registry.quarantine();
        self.ledger.close_for_reconciliation();
    }

    /// Fence this runtime for recovery and snapshot its live attempts: the
    /// exact identity handoff to the sealed recovery (#349).
    ///
    /// Admission closes permanently first: no attempt is admitted afterwards,
    /// the registry commits no new intent and the staging ledger issues no
    /// new grant. Every claim before its AGR1 is voided. An attempt whose
    /// AGR1 was converted but whose run has not started is cancelled by
    /// revocation and kept: its owner records its ending with nothing
    /// committed, so it still gets a stored response (ADR-069 R11 Amendment
    /// 1, item P8). Every running attempt is cancelled; the snapshot is
    /// taken only once each of those ended, within its watchdog and cleanup
    /// budget, so no unit can
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
            // An attempt that never ran left nothing to recover.
            if let Slot::Ended {
                state: Some(state),
                cleaned,
                ..
            } = slot
            {
                ended.push((
                    *attempt_id,
                    Arc::clone(state),
                    matches!(cleaned, Cleaned::Proved),
                ));
            }
        }
        let attempts = ended
            .into_iter()
            .map(|(attempt_id, state, cleanup_proved)| {
                self.identity(attempt_id, &state, cleanup_proved)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // A concurrent call may have handed out its snapshot meanwhile.
        if self.snapshot_taken.swap(true, Ordering::AcqRel) {
            return Err(AttemptLifecycleError::Fenced);
        }
        Ok(LiveAttemptSnapshot { attempts })
    }

    /// Close admission under the attempts lock, void every claim, cancel
    /// every granted and running attempt; the waits for the started runs.
    fn fence(&self) -> Vec<watch::Receiver<bool>> {
        let mut attempts = lock(&self.attempts);
        self.fenced.store(true, Ordering::Release);
        let mut running = Vec::new();
        let mut claimed = Vec::new();
        for (attempt_id, slot) in &mut attempts.slots {
            if let Some(revoked) = revoke(*attempt_id, slot) {
                revoked.map_or_else(|voided| claimed.push(voided), |ended| running.push(ended));
            }
        }
        let voided = claimed
            .into_iter()
            .map(|attempt_id| attempts.release(attempt_id))
            .collect::<Vec<_>>();
        drop(attempts);
        // The voided claims wake their waiters outside the attempts lock.
        drop(voided);
        running
    }

    /// One live attempt's identities, its durable record read back.
    fn identity(
        &self,
        attempt_id: [u8; 16],
        state: &RunState,
        cleanup_proved: bool,
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
            cleanup_proved,
        })
    }
}

/// The claimed SPX1 digest of the granted attempt `attempt_id` whose AGR1
/// digests to `grant`, and its first cancellation, if any; a fence never
/// refuses it (ADR-069 R11 Amendment 1, item P8).
fn granted<I>(
    attempts: &Table<I>,
    attempt_id: [u8; 16],
    grant: [u8; 32],
) -> Result<([u8; 32], Option<CancelSource>), AttemptLifecycleError> {
    match attempts.get(&attempt_id) {
        Some(Slot::Granted {
            grant: granted,
            request,
            cancel,
            ..
        }) if *granted == grant => Ok((*request, *cancel)),
        Some(Slot::Granted { .. }) => Err(AttemptLifecycleError::GrantMismatch),
        None | Some(Slot::Claimed { .. }) => Err(AttemptLifecycleError::UnknownAttempt),
        Some(Slot::Running { .. } | Slot::Ended { .. } | Slot::Reconciled { .. }) => {
            Err(AttemptLifecycleError::AttemptKnown)
        }
    }
}

impl<I> AttemptLifecycle<I> {
    /// Record `failed`'s attempt as ended with nothing committed.
    fn record_failed<S, F: FailedAdmission>(
        &self,
        failed: &F,
    ) -> Result<EndedAttempt<S>, AttemptLifecycleError> {
        let attempt_id = failed.attempt_id();
        let grant = failed.grant_digest();
        let mut attempts = lock(&self.attempts);
        let (request, cancel_source) = granted(&attempts, attempt_id, grant)?;
        let admission = failed.admission();
        let ended = Slot::Ended {
            grant,
            request,
            state: None,
            cleaned: Cleaned::NothingCommitted,
            response: Retained::Pending,
            settled: watch::channel(false).0,
            _input: None,
        };
        let replaced = attempts.set(attempt_id, ended);
        drop(attempts);
        // The granted slot wakes its waiters outside the attempts lock.
        drop(replaced);
        Ok(EndedAttempt {
            attempt_id,
            admission,
            // The first cancellation source wins (owner decision 2026-11-15,
            // #443 journal 22319), and outranks every other outcome (ADR-069
            // §8), even when the input fails afterwards.
            cancel_source,
            progress: AttemptProgress::InputFailed,
            cleanup: Ok(None),
            cleanup_finished_at: finished_at(),
        })
    }

    /// Take exclusive ownership of `input`'s attempt. An owner dropped
    /// before its run signs the attempt's response with `signer` under
    /// `admitted` (ADR-069 R15 §3.6 item 2(b)).
    fn admit_input<'l, R: RuntimeAttestationSigner>(
        &'l self,
        input: I,
        (signer, admitted): (&'l R, AdmittedRuntimeKey<'l>),
    ) -> Result<OwnedAttempt<'l, I, R>, AttemptLifecycleError>
    where
        I: AdmittedInput,
    {
        let attempt_id = input.attempt_id();
        let grant = input.grant_digest();
        let admission = input.admission();
        let mut attempts = lock(&self.attempts);
        let (request, cancel_source) = granted(&attempts, attempt_id, grant)?;
        let state = RunState::admitted(input.sim1_digest(), cancel_source);
        let (ended, waiting) = watch::channel(false);
        let running = Slot::Running {
            grant,
            request,
            state: Arc::clone(&state),
            ended: waiting,
            started: false,
            input: Some(input),
        };
        let replaced = attempts.set(attempt_id, running);
        drop(attempts);
        // The granted slot wakes its waiters outside the attempts lock.
        drop(replaced);
        Ok(OwnedAttempt {
            claim: Claim {
                lifecycle: self,
                attempt_id,
                grant,
                request,
                admission,
                state,
                ended,
                started: false,
                finished: false,
                signer,
                admitted,
            },
        })
    }
}

/// The exclusive owner of one admitted attempt until it ended.
///
/// Dropping it before its run started ends the attempt with nothing
/// committed and releases its admission, then signs and retains its
/// terminal response in `Drop` (ADR-069 R15 §3.6 item 2(b)): an
/// `UnavailableAfterAdmission` by the R9 §4.6.5 code 2 fallback, which
/// quarantines, unless a cancellation was recorded first. The signer must be
/// local and CPU-bound, and the owner is never dropped under the attempts
/// lock. Dropping its run part-way quarantines the lifecycle first, then
/// records the attempt as ended without proved cleanup and releases its
/// admission.
#[derive(Debug)]
pub struct OwnedAttempt<
    'l,
    I = VerifiedStagedInput,
    R: RuntimeAttestationSigner = KeyFileRuntimeSigner,
> {
    claim: Claim<'l, I, R>,
}

/// A started run: its claim and the admission it took.
///
/// Fields drop in declaration order, so a run dropped part-way quarantines
/// the lifecycle through its claim before the admission, and with it the
/// staging reservation, is released.
struct Run<'l, I, R: RuntimeAttestationSigner> {
    claim: Claim<'l, I, R>,
    input: I,
}

#[derive(Debug)]
struct Claim<'l, I, R: RuntimeAttestationSigner> {
    lifecycle: &'l AttemptLifecycle<I>,
    attempt_id: [u8; 16],
    grant: [u8; 32],
    request: [u8; 32],
    admission: AttemptAdmission,
    state: Arc<RunState>,
    ended: watch::Sender<bool>,
    // Set before the first registry commit; an owner dropped earlier left
    // nothing behind.
    started: bool,
    finished: bool,
    // Signs the response of an owner dropped before its run.
    signer: &'l R,
    admitted: AdmittedRuntimeKey<'l>,
}

impl<I, R: RuntimeAttestationSigner> Claim<'_, I, R> {
    /// Mark the run started, before its first commit, and take its
    /// admission; `None` when it was cancelled before it began: it is then
    /// recorded as ended with nothing committed, and its admission is
    /// released.
    fn begin(&mut self) -> Option<I> {
        #[cfg(test)]
        self.lifecycle.before_begin.run(self.lifecycle);
        let mut attempts = lock(&self.lifecycle.attempts);
        // A fence or a cancellation cancels an owner that still holds its
        // slot. Both cancel under the attempts lock, so it is read under
        // that lock too: a fence either sees this run started, and waits
        // for it, or this run sees it.
        let cancelled = self.state.cancel.source().is_some();
        let mut input = attempts
            .slots
            .get_mut(&self.attempt_id)
            .and_then(Slot::start);
        let released = cancelled.then(|| input.take()).flatten().map(|input| {
            (
                input,
                attempts.set(self.attempt_id, self.unstarted_ending()),
            )
        });
        drop(attempts);
        // The released admission is dropped outside the attempts lock.
        drop(released);
        self.started = input.is_some();
        self.finished = input.is_none();
        self.ended.send_replace(self.finished);
        input
    }

    /// The ending of an attempt cancelled before its run began: nothing was
    /// committed, and its response is still to be signed.
    fn unstarted_ending(&self) -> Slot<I> {
        Slot::Ended {
            grant: self.grant,
            request: self.request,
            state: None,
            cleaned: Cleaned::NothingCommitted,
            response: Retained::Pending,
            settled: watch::channel(false).0,
            _input: None,
        }
    }

    /// Record the attempt as ended with its `response`, retaining `input`
    /// until reconciliation, then wake every waiting cancellation and joined
    /// repeat. Returns the first cancellation request's source, read under
    /// the same lock that a cancellation takes.
    fn end(
        &mut self,
        input: Option<I>,
        cleaned: Cleaned,
        response: Retained,
    ) -> Option<CancelSource> {
        self.finished = true;
        let ended = Slot::Ended {
            grant: self.grant,
            request: self.request,
            state: Some(Arc::clone(&self.state)),
            cleaned,
            response,
            settled: watch::channel(false).0,
            _input: input,
        };
        let mut attempts = lock(&self.lifecycle.attempts);
        let cancel_source = self.state.cancel.source();
        let replaced = attempts.set(self.attempt_id, ended);
        drop(attempts);
        drop(replaced);
        self.ended.send_replace(true);
        cancel_source
    }

    /// End an owner dropped before its run: nothing was committed, its
    /// admission is released, and its response is signed and retained here
    /// (ADR-069 R15 §3.6 item 2(b)). With no cancellation recorded, its
    /// facts match no R9 §4.6.5 candidate, so it is the code 2 fallback,
    /// which quarantines; a signing or clock fault is `Faulted` and
    /// quarantines (R9 Amendment 1 change F). Nothing here panics.
    fn drop_unstarted(&mut self) {
        self.finished = true;
        let mut attempts = lock(&self.lifecycle.attempts);
        let cancel_source = self.state.cancel.source();
        let input = attempts
            .slots
            .get_mut(&self.attempt_id)
            .and_then(Slot::start);
        let replaced = attempts.set(self.attempt_id, self.unstarted_ending());
        drop(attempts);
        // The admission is released outside the attempts lock.
        drop((input, replaced));
        let ended = EndedAttempt::<SystemdVerifiedStart> {
            attempt_id: self.attempt_id,
            admission: self.admission.clone(),
            cancel_source,
            progress: AttemptProgress::Withdrawn,
            cleanup: Ok(None),
            cleanup_finished_at: finished_at(),
        };
        drop(
            self.lifecycle
                .retain_response(ended, self.signer, self.admitted),
        );
        self.ended.send_replace(true);
    }
}

impl<I, R: RuntimeAttestationSigner> Drop for Claim<'_, I, R> {
    fn drop(&mut self) {
        if !self.finished {
            if self.started {
                // The run was abandoned: nothing about its resources is
                // proved, and no response will be signed for it.
                self.lifecycle.quarantine();
                self.end(None, Cleaned::Unproved, Retained::Faulted);
            } else {
                self.drop_unstarted();
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
    pub async fn run<N, F>(
        self,
        steps: &SystemdAttemptSteps<'_, N, F>,
        launch: AttemptLaunch<F>,
        budget: CleanupBudget,
    ) -> EndedAttempt<SystemdVerifiedStart>
    where
        N: LocalNetworkPort + Sync,
        F: BarrierFactory,
    {
        self.run_with(steps, launch, budget).await
    }
}

impl<I, R: RuntimeAttestationSigner + Sync> OwnedAttempt<'_, I, R> {
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
            // Only a cancellation ends an owner before its run, and it
            // recorded its source first.
            return EndedAttempt {
                attempt_id,
                admission: claim.admission.clone(),
                cancel_source: claim.state.cancel.source(),
                progress: AttemptProgress::Withdrawn,
                cleanup: Ok(None),
                cleanup_finished_at: finished_at(),
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
        // The cleanup returned, proved or not (R9 §4.6.6).
        let cleanup_finished_at = finished_at();
        let (progress, cleanup) = ended;
        let cleaned = cleanup
            .as_ref()
            .map_or(Cleaned::Unproved, |_| Cleaned::Proved);
        if matches!(cleaned, Cleaned::Unproved) {
            run.claim.lifecycle.quarantine();
        }
        let Run { mut claim, input } = run;
        let cancel_source = claim.end(Some(input), cleaned, Retained::Pending);
        EndedAttempt {
            attempt_id,
            admission: claim.admission.clone(),
            cancel_source,
            progress,
            cleanup: cleanup.map(Some),
            cleanup_finished_at,
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
    Option<NetworkRemovalFailure>,
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
                    started: None,
                    evidence,
                },
                None,
                None,
                None,
            );
        }
    };
    let root = match input.activate(directory).await {
        Ok(root) => root,
        Err(error) => return (AttemptProgress::NotActivated(error), None, None, None),
    };
    let recheck = || checker(&root, directory);
    let executed = steps.execute(launch, attempt, &recheck, cancel).await;
    let (progress, cgroup, removal) = match executed {
        Ok(execution) => (
            AttemptProgress::Executed {
                started: execution.started,
                ending: execution.ending,
                network: execution.network,
                evidence: execution.evidence,
                adapter: execution.adapter,
            },
            Some(execution.cgroup),
            execution.network_removal,
        ),
        Err(failure) => (
            AttemptProgress::Failed {
                error: failure.error,
                unit: failure.unit,
                started: failure.started,
                evidence: failure.evidence,
            },
            failure.cgroup,
            failure.network_removal,
        ),
    };
    (progress, cgroup, Some(root), removal)
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
    let (mut progress, cgroup, root, removal) = if cancel.is_requested() {
        (AttemptProgress::CancelledBeforeActivation, None, None, None)
    } else {
        activate_and_execute(steps, launch, input, &directory, cancel).await
    };
    let deadlines = budget.deadlines(Instant::now());
    let cleanup = steps
        .finish(&mut progress, directory, cgroup, root, deadlines)
        .await
        // A cleanup that failed on its own is the one error reported, and the
        // reason of a network removal failure beside it is not kept. Both
        // leave `cleanup.result` 1 and quarantine, so the record is the same;
        // the port quarantines the network's slot with its own reason.
        .and_then(|completed| removal.map_or(Ok(completed), |failure| Err(failure.into())))
        .map_err(AttemptLifecycleError::from);
    (progress, cleanup)
}

mod claim;
mod control;
mod retention;

pub use claim::{AwaitedInput, ExchangeClaim, GrantWrite, InterruptedInput};
use retention::Retained;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod crash_points;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
