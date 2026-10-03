//! Process-global staged fold executor (ADR-113 §4, §5 and §6).
//!
//! A protected Replay or Compare never runs a Reducer callback on the thread
//! that holds ADR-112's release guard. The guard thread hands a
//! [`StagedFoldPlanV1`] to the one staged-fold worker of the process and
//! waits for it with a monotonic timed wait that ends at `g0 + 27 s`. The
//! worker opens a fresh candidate through the host provider, running each
//! recorded consumer's `build` as its own callback, and folds it with the
//! live fold step. It checks the deadline and cancellation before every
//! callback, including each `build` (E3), the consumer's own admitted
//! callback bound after it (E4) and the staged size after every `apply`
//! (E5). Every callback runs under `catch_unwind`; its panic payload is
//! dropped inside a nested `catch_unwind` and never formatted.
//!
//! When the timed wait expires (E6) the executor is quarantined: the cancel
//! flag is set, the reply is abandoned and every later `acquire`, `fold` and
//! protected release in the process fails closed until the abandoned job
//! ends. The worker is never respawned. A panic in the worker's host code
//! outside every callback quarantines the executor for the rest of the
//! process; the worker survives it and is never left busy.

use std::{
    any::Any,
    cell::Cell,
    io::Write as _,
    marker::PhantomData,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc, Arc, OnceLock,
    },
    time::Duration,
};

use pos_core::{
    staged_install::ProjectionSourceV1,
    trusted_clock::{
        GuardMonotonicSourceV1, MonotonicMarkV1, ReleaseGuardV1, SystemGuardMonotonicSourceV1,
        TRUSTED_CLOCK_GUARD_BUDGET,
    },
    Event,
};
use pos_state::{
    CandidateBuildV1, CandidateReducerV1, CandidateTurnV1, DetachedProjectionCandidateV1,
    InitialStateV1, ProjectionCandidateErrorV1, ProtectedProjectionProviderV1, RecordedConsumerV1,
    StagedLimitErrorV1, StagedProjectionV1, MAX_STAGED_CONSUMERS_V1,
};

/// Fold deadline measured from `g0`; the guard thread decides failure here.
pub const STAGED_FOLD_DEADLINE_V1: Duration = Duration::from_secs(27);
/// Planned end of the handoff work measured from `g0` (P1).
pub const STAGED_HANDOFF_DEADLINE_V1: Duration = Duration::from_secs(29);
/// Largest total canonical Event bytes of one plan (ADR-093).
pub const MAX_STAGED_INPUT_BYTES_V1: u64 = 256 * 1024 * 1024;
/// Planning bound of one exact staged-size pass, pending §10 measurement.
pub const STAGED_ACCOUNTING_PASS_BOUND_V1: Duration = Duration::from_millis(250);
/// Planning bound of the final rechecks, `prepare_install` and the handoff,
/// pending §10 measurement (P1).
pub const MEASURED_PREPARE_BOUND_V1: Duration = Duration::from_millis(500);
/// Planning bound of rollback and unlock after a failure, pending §10
/// measurement (P2).
pub const MEASURED_TEARDOWN_BOUND_V1: Duration = Duration::from_millis(250);
/// Payload-free health signal for a teardown predicted to end after `g0 + 30 s`.
pub const GUARD_RELEASE_LATE_SIGNAL: &str = "guard_release_late";
/// OS name of the one staged-fold worker thread. It fits Linux's 15-byte
/// thread name, so `/proc/self/task/*/comm` shows it whole.
pub const STAGED_FOLD_WORKER_NAME_V1: &str = "pos-staged-fold";

/// The only line the panic hook writes for a panic inside a staged callback.
const STAGED_CALLBACK_PANIC_LINE: &[u8] = b"pigloros: staged reducer callback panicked\n";

const READY: u8 = 0;
const BUSY: u8 = 1;
const QUARANTINED: u8 = 2;

static HEALTH: AtomicU8 = AtomicU8::new(READY);
/// The worker's job queue, or `None` when the worker thread could not start.
static WORKER: OnceLock<Option<mpsc::Sender<StagedJobV1>>> = OnceLock::new();

thread_local! {
    static IN_STAGED_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

/// Process-global health of the staged-fold executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorHealthV1 {
    /// No fold is running.
    Ready,
    /// One fold is running.
    Busy,
    /// An abandoned job may still run; protected release is closed.
    Quarantined,
}

impl ExecutorHealthV1 {
    /// The current process-global health.
    #[must_use]
    pub fn current() -> Self {
        match HEALTH.load(Ordering::SeqCst) {
            READY => Self::Ready,
            BUSY => Self::Busy,
            _ => Self::Quarantined,
        }
    }
}

/// Closed staged-fold failures. Each maps to ADR-093 `Unavailable`; they carry
/// ordinals only, never payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedFoldErrorV1 {
    /// The process was built with `panic = "abort"`.
    UnsupportedPanicStrategy,
    /// The one staged-fold worker thread could not be started.
    WorkerUnavailable,
    /// A recorded consumer has no admitted entry, or its built Plugin is not
    /// the recorded one.
    NotAdmitted,
    /// The recorded consumer set is empty, too large, repeated or stale.
    ConsumerSetMismatch,
    /// The plan is not bound to one Timeline source.
    SourceMismatch,
    /// The plan's Events exceed [`MAX_STAGED_INPUT_BYTES_V1`].
    InputExceeded,
    /// The exact staged size exceeds the staged output limit.
    StagedOutputExceeded,
    /// A consumer holds more entities than allowed.
    EntityLimitExceeded,
    /// An entity grew by more than its declared growth bounds.
    GrowthBoundExceeded,
    /// A callback panicked. A `build` reports its consumer ordinal and event
    /// ordinal `0`; dropping or assembling the candidate reducers reports
    /// consumer ordinal `0` and event ordinal `u32::MAX`.
    ReducerPanicked {
        /// Recorded position of the consumer.
        consumer_ordinal: u16,
        /// Position of the Event in the plan.
        event_ordinal: u32,
    },
    /// A callback ran longer than its admitted bound.
    CallbackBoundExceeded {
        /// Recorded position of the consumer.
        consumer_ordinal: u16,
        /// Position of the Event in the plan.
        event_ordinal: u32,
    },
    /// The fold cannot finish by `g0 + 27 s`.
    DeadlineExceeded,
    /// The guard thread abandoned the job.
    Cancelled,
    /// The executor is quarantined.
    ExecutorQuarantined,
    /// Another fold is running.
    ExecutorBusy,
}

/// Fail closed while the executor is quarantined.
///
/// The release host calls this before every protected release, including
/// releases that fold nothing, before any premise read.
///
/// # Errors
/// Returns [`StagedFoldErrorV1::ExecutorQuarantined`] while quarantined.
pub fn require_staged_release() -> Result<(), StagedFoldErrorV1> {
    if ExecutorHealthV1::current() == ExecutorHealthV1::Quarantined {
        Err(StagedFoldErrorV1::ExecutorQuarantined)
    } else {
        Ok(())
    }
}

/// P1: refuse the handoff work unless it is planned to end by `g0 + 29 s`.
///
/// # Errors
/// Returns [`StagedFoldErrorV1::DeadlineExceeded`]; the caller drops the
/// staged result and tears down.
pub fn check_handoff_reserve(
    clock: &mut dyn GuardMonotonicSourceV1,
    g0: MonotonicMarkV1,
) -> Result<(), StagedFoldErrorV1> {
    if fits_before(
        clock.mark(),
        g0,
        MEASURED_PREPARE_BOUND_V1,
        STAGED_HANDOFF_DEADLINE_V1,
    ) {
        Ok(())
    } else {
        Err(StagedFoldErrorV1::DeadlineExceeded)
    }
}

/// P2: the payload-free [`GUARD_RELEASE_LATE_SIGNAL`] when teardown is
/// predicted to end after `g0 + 30 s`. Teardown runs regardless.
#[must_use]
pub fn teardown_signal(
    clock: &mut dyn GuardMonotonicSourceV1,
    g0: MonotonicMarkV1,
) -> Option<&'static str> {
    let on_time = fits_before(
        clock.mark(),
        g0,
        MEASURED_TEARDOWN_BOUND_V1,
        TRUSTED_CLOCK_GUARD_BUDGET,
    );
    (!on_time).then_some(GUARD_RELEASE_LATE_SIGNAL)
}

fn fits_before(
    now: MonotonicMarkV1,
    g0: MonotonicMarkV1,
    bound: Duration,
    deadline: Duration,
) -> bool {
    now.checked_elapsed_since(g0)
        .and_then(|elapsed| elapsed.checked_add(bound))
        .is_some_and(|planned| planned <= deadline)
}

/// The fold window of one held ADR-112 release guard. It exposes only the
/// guard start `g0` and the cancellation signal.
pub struct GuardedFoldWindowV1<'w> {
    g0: MonotonicMarkV1,
    cancel: Arc<AtomicBool>,
    _guard: PhantomData<&'w ()>,
}

impl<'w> GuardedFoldWindowV1<'w> {
    /// Open the fold window of a held guard.
    #[must_use]
    pub fn new(guard: &'w ReleaseGuardV1<'_>) -> Self {
        Self {
            g0: guard.guard_started_at(),
            cancel: Arc::new(AtomicBool::new(false)),
            _guard: PhantomData,
        }
    }

    /// ADR-112's guard start `g0`.
    #[must_use]
    pub const fn guard_started_at(&self) -> MonotonicMarkV1 {
        self.g0
    }

    /// Whether a fold in this window was abandoned at its deadline.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

/// One protected fold: the recorded consumers, the verified Events read
/// inside the guard, and the source they were read from.
pub struct StagedFoldPlanV1 {
    consumers: Vec<RecordedConsumerV1>,
    events: Vec<Event>,
    source: ProjectionSourceV1,
    clock: Box<dyn GuardMonotonicSourceV1>,
    #[cfg(any(test, feature = "test-support"))]
    host_fault: bool,
}

impl StagedFoldPlanV1 {
    /// Plan a fold of `events` for exactly `consumers`. The plan takes the
    /// verified Events without copying their payloads, and the host drops
    /// consent-closed markers here, once, as the live fold does.
    #[must_use]
    pub fn new(
        consumers: Vec<RecordedConsumerV1>,
        mut events: Vec<Event>,
        source: ProjectionSourceV1,
    ) -> Self {
        events.retain(crate::registry::is_host_projection_event);
        Self {
            consumers,
            events,
            source,
            clock: Box::new(SystemGuardMonotonicSourceV1),
            #[cfg(any(test, feature = "test-support"))]
            host_fault: false,
        }
    }

    /// Use `clock` for the worker's E3 and E4 checks.
    #[must_use]
    pub fn with_worker_clock(mut self, clock: Box<dyn GuardMonotonicSourceV1>) -> Self {
        self.clock = clock;
        self
    }

    /// Make the worker's host code panic outside every callback, to exercise
    /// the worker's last-resort containment. Nonproduction only.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub const fn with_host_fault(mut self) -> Self {
        self.host_fault = true;
        self
    }
}

/// Handle to the process-global staged-fold executor.
#[derive(Debug)]
pub struct StagedFoldExecutorV1 {
    worker: &'static mpsc::Sender<StagedJobV1>,
}

impl StagedFoldExecutorV1 {
    /// Acquire the executor, starting its one worker and installing its
    /// panic hook on first use (E1). The worker is never respawned.
    ///
    /// # Errors
    /// Returns [`StagedFoldErrorV1::ExecutorQuarantined`], or
    /// [`StagedFoldErrorV1::WorkerUnavailable`] when the worker thread could
    /// not be started. A `panic = "abort"` build always returns
    /// [`StagedFoldErrorV1::UnsupportedPanicStrategy`].
    #[cfg(panic = "unwind")]
    pub fn acquire() -> Result<Self, StagedFoldErrorV1> {
        let worker = WORKER.get_or_init(start_worker).as_ref();
        require_staged_release()?;
        worker
            .map(|worker| Self { worker })
            .ok_or(StagedFoldErrorV1::WorkerUnavailable)
    }

    /// E1: callbacks can be contained only when panics unwind, so a
    /// `panic = "abort"` build never starts the worker.
    ///
    /// # Errors
    /// Always returns [`StagedFoldErrorV1::UnsupportedPanicStrategy`].
    #[cfg(not(panic = "unwind"))]
    pub const fn acquire() -> Result<Self, StagedFoldErrorV1> {
        Err(StagedFoldErrorV1::UnsupportedPanicStrategy)
    }

    /// Fold `plan` on the worker and wait for it until `g0 + 27 s`.
    ///
    /// `guard_clock` is the guard thread's monotonic source. No callback
    /// runs on this thread.
    ///
    /// # Errors
    /// Returns a closed [`StagedFoldErrorV1`] before any callback for a
    /// plan that fails E2 or a busy or quarantined executor, and the
    /// worker's failure otherwise. At the deadline it quarantines the
    /// executor and returns [`StagedFoldErrorV1::DeadlineExceeded`].
    pub fn fold(
        &self,
        window: &GuardedFoldWindowV1<'_>,
        guard_clock: &mut dyn GuardMonotonicSourceV1,
        provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync>,
        plan: StagedFoldPlanV1,
    ) -> Result<StagedProjectionV1, StagedFoldErrorV1> {
        let remaining = admit_plan(window, guard_clock, &plan)?;
        claim_worker()?;
        let (reply, outcome) = mpsc::sync_channel(1);
        let job = StagedJobV1 {
            plan,
            provider,
            g0: window.g0,
            cancel: Arc::clone(&window.cancel),
            reply,
        };
        // Invariant: the queue is never closed. Its receiver belongs to the
        // process-global worker, whose sender lives in the `WORKER`
        // `OnceLock` and is never dropped, so `send` cannot fail. The result
        // is discarded rather than branched on, because that branch could
        // never run and would fail the 99% region-coverage gate. Were the
        // queue ever closed, the job and its reply sender would drop here,
        // and the wait below would end at once as a failure (fail closed).
        self.worker.send(job).ok();
        outcome.recv_timeout(remaining).unwrap_or_else(|_| {
            window.cancel.store(true, Ordering::SeqCst);
            // Quarantine only a job still running; `BUSY` leaves only when
            // its job ends. Race: if the worker finished between the
            // timeout and this exchange, it already stored `READY` and its
            // late reply drops with `outcome`, so the exchange fails and the
            // executor stays ready with no abandoned job. Had another
            // thread claimed the worker in that gap, its fold is
            // quarantined until it ends, which fails closed.
            HEALTH
                .compare_exchange(BUSY, QUARANTINED, Ordering::SeqCst, Ordering::SeqCst)
                .ok();
            Err(StagedFoldErrorV1::DeadlineExceeded)
        })
    }
}

/// E2: check the plan on the guard thread, including that its source is
/// bound to one Timeline, and return the wait until `g0 + 27 s`.
fn admit_plan(
    window: &GuardedFoldWindowV1<'_>,
    guard_clock: &mut dyn GuardMonotonicSourceV1,
    plan: &StagedFoldPlanV1,
) -> Result<Duration, StagedFoldErrorV1> {
    if plan.consumers.is_empty() || plan.consumers.len() > MAX_STAGED_CONSUMERS_V1 {
        return Err(StagedFoldErrorV1::ConsumerSetMismatch);
    }
    // An unbound or mixed source can never assemble a candidate, so it is
    // refused here, before any factory code runs on the worker.
    if plan.source.timeline().is_none() {
        return Err(StagedFoldErrorV1::SourceMismatch);
    }
    let input = plan
        .events
        .iter()
        .map(|event| (event.payload.len() + event.event_type.as_str().len()) as u64)
        .fold(0, u64::saturating_add);
    if input > MAX_STAGED_INPUT_BYTES_V1 {
        return Err(StagedFoldErrorV1::InputExceeded);
    }
    guard_clock
        .mark()
        .checked_elapsed_since(window.g0)
        .and_then(|elapsed| STAGED_FOLD_DEADLINE_V1.checked_sub(elapsed))
        .filter(|remaining| !remaining.is_zero())
        .ok_or(StagedFoldErrorV1::DeadlineExceeded)
}

fn claim_worker() -> Result<(), StagedFoldErrorV1> {
    HEALTH
        .compare_exchange(READY, BUSY, Ordering::SeqCst, Ordering::SeqCst)
        .map(drop)
        .map_err(|health| {
            if health == QUARANTINED {
                StagedFoldErrorV1::ExecutorQuarantined
            } else {
                StagedFoldErrorV1::ExecutorBusy
            }
        })
}

/// Start the one named worker thread. It is detached and never respawned;
/// `None` when the thread could not be started.
fn start_worker() -> Option<mpsc::Sender<StagedJobV1>> {
    install_panic_hook();
    let (jobs, queue) = mpsc::channel::<StagedJobV1>();
    std::thread::Builder::new()
        .name(STAGED_FOLD_WORKER_NAME_V1.to_owned())
        .spawn(move || queue.iter().for_each(run_contained_job))
        .ok()
        .map(|_detached| jobs)
}

/// Run one job under a last `catch_unwind`. A panic in host code outside
/// every contained callback ends the job: its payload is dropped without
/// being formatted, and the executor is quarantined for the rest of the
/// process instead of being left busy. The worker survives.
fn run_contained_job(job: StagedJobV1) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(move || run_job(job))) {
        drop_payload(payload);
        HEALTH.store(QUARANTINED, Ordering::SeqCst);
    }
}

/// Chain one process-global hook that writes only a fixed line for a panic
/// inside a staged callback, keyed on a thread-local flag, and delegates
/// every other panic to the previous hook.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if IN_STAGED_CALLBACK.get() {
            // A hook has nowhere to report a failed write; the line is
            // diagnostic only.
            std::io::stderr().write_all(STAGED_CALLBACK_PANIC_LINE).ok();
        } else {
            previous(info);
        }
    }));
}

/// Run one callback under `catch_unwind`, dropping any panic payload inside
/// a nested `catch_unwind` without formatting it.
fn run_callback<T>(callback: impl FnOnce() -> T) -> Option<T> {
    IN_STAGED_CALLBACK.set(true);
    let value = catch_unwind(AssertUnwindSafe(callback))
        .map_err(drop_payload)
        .ok();
    IN_STAGED_CALLBACK.set(false);
    value
}

/// Drop a panic payload without formatting it. A payload whose `Drop`
/// panics again yields a new payload, dropped the same way, so nothing is
/// leaked. A payload chain that never ends keeps the worker inside this
/// callback, as a callback that never returns would, and the guard thread
/// abandons it at its deadline.
///
/// It loops rather than `mem::forget`ting the payload: `mem_forget` is
/// denied workspace-wide, and a deliberate leak would fail the `LSan` job
/// (decision recorded under ADR-113 clarification ticket #515).
fn drop_payload(mut payload: Box<dyn Any + Send>) {
    while let Err(next) = catch_unwind(AssertUnwindSafe(move || drop(payload))) {
        payload = next;
    }
}

/// Drop a value that may own Reducer or factory state under the same
/// panic containment as a callback. A panic in its `Drop` is contained and
/// otherwise ignored here; callers that must report it use
/// [`run_callback`] directly.
fn drop_guarded<T>(value: T) {
    run_callback(move || drop(value));
}

type StagedReplyV1 = Result<StagedProjectionV1, StagedFoldErrorV1>;

/// A panic while dropping or assembling candidate reducers.
const TEARDOWN_PANICKED: StagedFoldErrorV1 = StagedFoldErrorV1::ReducerPanicked {
    consumer_ordinal: 0,
    event_ordinal: u32::MAX,
};

struct StagedJobV1 {
    plan: StagedFoldPlanV1,
    provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync>,
    g0: MonotonicMarkV1,
    cancel: Arc<AtomicBool>,
    reply: mpsc::SyncSender<StagedReplyV1>,
}

fn run_job(job: StagedJobV1) {
    let StagedJobV1 {
        plan,
        provider,
        g0,
        cancel,
        reply,
    } = job;
    let outcome = fold_on_worker(plan, provider, g0, &cancel);
    if cancel.load(Ordering::SeqCst) {
        // An abandoned job's late result is discarded; quarantine clears
        // only now that the job has ended.
        drop_guarded(outcome);
        HEALTH.store(READY, Ordering::SeqCst);
    } else {
        HEALTH.store(READY, Ordering::SeqCst);
        // A guard thread that timed out between the cancel check and this
        // send has dropped its receiver; the reply then drops here, and it
        // holds no reducer instance.
        reply.send(outcome).ok();
    }
}

/// The worker's monotonic checks against `g0` and the cancel flag.
struct WorkerGateV1<'c> {
    clock: Box<dyn GuardMonotonicSourceV1>,
    g0: MonotonicMarkV1,
    cancel: &'c AtomicBool,
}

impl WorkerGateV1<'_> {
    /// E3: refuse a callback or pass that cannot finish by `g0 + 27 s`.
    fn before(&mut self, bound: Duration) -> Result<MonotonicMarkV1, StagedFoldErrorV1> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(StagedFoldErrorV1::Cancelled);
        }
        let now = self.clock.mark();
        if fits_before(now, self.g0, bound, STAGED_FOLD_DEADLINE_V1) {
            Ok(now)
        } else {
            Err(StagedFoldErrorV1::DeadlineExceeded)
        }
    }

    /// E4: refuse a callback that ran longer than its bound.
    fn after(
        &mut self,
        started: MonotonicMarkV1,
        bound: Duration,
        consumer_ordinal: u16,
        event_ordinal: u32,
    ) -> Result<(), StagedFoldErrorV1> {
        let within = self
            .clock
            .mark()
            .checked_elapsed_since(started)
            .is_some_and(|elapsed| elapsed <= bound);
        if within {
            Ok(())
        } else {
            Err(StagedFoldErrorV1::CallbackBoundExceeded {
                consumer_ordinal,
                event_ordinal,
            })
        }
    }
}

fn fold_on_worker(
    plan: StagedFoldPlanV1,
    provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync>,
    g0: MonotonicMarkV1,
    cancel: &AtomicBool,
) -> StagedReplyV1 {
    #[cfg(any(test, feature = "test-support"))]
    {
        if plan.host_fault {
            std::panic::resume_unwind(Box::new(()));
        }
    }
    let StagedFoldPlanV1 {
        consumers,
        events,
        source,
        clock,
        ..
    } = plan;
    let mut gate = WorkerGateV1 { clock, g0, cancel };
    let opened = open_on_worker(&mut gate, &*provider, &consumers, source);
    drop_guarded(provider);
    let mut candidate = opened?;
    let outcome = fold_candidate(&mut gate, &mut candidate, &events);
    // The reducer instances are dropped here, as one more callback; a panic
    // in their `Drop` fails the fold with the teardown event ordinal.
    let dropped = run_callback(move || drop(candidate));
    outcome.and_then(|staged| dropped.map(|()| staged).ok_or(TEARDOWN_PANICKED))
}

/// Open the candidate: resolve the recorded set in host code, run each
/// consumer's `build` as its own callback, then assemble the candidate.
/// Reducers built before a failure, and those a panicking assembly drops,
/// are dropped under callback containment.
fn open_on_worker(
    gate: &mut WorkerGateV1<'_>,
    provider: &dyn ProtectedProjectionProviderV1,
    consumers: &[RecordedConsumerV1],
    source: ProjectionSourceV1,
) -> Result<DetachedProjectionCandidateV1, StagedFoldErrorV1> {
    let builds = provider
        .candidate_builds(consumers)
        .map_err(candidate_error)?;
    let mut reducers = Vec::with_capacity(builds.len());
    let built = builds
        .into_iter()
        .enumerate()
        .try_for_each(|(ordinal, build)| {
            build_on_worker(gate, build, ordinal).map(|reducer| reducers.push(reducer))
        });
    if let Err(error) = built {
        drop_guarded(reducers);
        return Err(error);
    }
    // `admit_plan` refused every source that cannot assemble, and the
    // provider refused repeated consumers, so assembly can only fail by
    // panicking, in which case the reducers are dropped under containment.
    run_callback(move || {
        DetachedProjectionCandidateV1::from_reducers(reducers, InitialStateV1::Empty, source)
    })
    .map_or(Err(TEARDOWN_PANICKED), |assembled| {
        assembled.map_err(candidate_error)
    })
}

/// A consumer's recorded position as a reported ordinal. Plans hold at most
/// [`MAX_STAGED_CONSUMERS_V1`] consumers, so it never saturates.
fn consumer_ordinal(ordinal: usize) -> u16 {
    u16::try_from(ordinal).unwrap_or(u16::MAX)
}

/// One consumer's `build` as one callback, under E3, `catch_unwind` and E4
/// against that consumer's own admitted callback bound.
fn build_on_worker(
    gate: &mut WorkerGateV1<'_>,
    build: CandidateBuildV1<'_>,
    ordinal: usize,
) -> Result<CandidateReducerV1, StagedFoldErrorV1> {
    let consumer_ordinal = consumer_ordinal(ordinal);
    let bound = build.bounds().callback_bound;
    let started = gate.before(bound)?;
    let reducer = run_callback(move || build.build())
        .ok_or(StagedFoldErrorV1::ReducerPanicked {
            consumer_ordinal,
            event_ordinal: 0,
        })?
        .map_err(candidate_error)?;
    match gate.after(started, bound, consumer_ordinal, 0) {
        Ok(()) => Ok(reducer),
        Err(error) => {
            drop_guarded(reducer);
            Err(error)
        }
    }
}

const fn candidate_error(error: ProjectionCandidateErrorV1) -> StagedFoldErrorV1 {
    match error {
        ProjectionCandidateErrorV1::NotAdmitted | ProjectionCandidateErrorV1::PluginMismatch => {
            StagedFoldErrorV1::NotAdmitted
        }
        ProjectionCandidateErrorV1::ConsumerSetMismatch => StagedFoldErrorV1::ConsumerSetMismatch,
        ProjectionCandidateErrorV1::SourceMismatch => StagedFoldErrorV1::SourceMismatch,
    }
}

const fn limit_error(error: StagedLimitErrorV1) -> StagedFoldErrorV1 {
    match error {
        StagedLimitErrorV1::StagedOutputExceeded => StagedFoldErrorV1::StagedOutputExceeded,
        StagedLimitErrorV1::EntityLimitExceeded => StagedFoldErrorV1::EntityLimitExceeded,
        StagedLimitErrorV1::GrowthBoundExceeded => StagedFoldErrorV1::GrowthBoundExceeded,
    }
}

fn fold_candidate(
    gate: &mut WorkerGateV1<'_>,
    candidate: &mut DetachedProjectionCandidateV1,
    events: &[Event],
) -> StagedReplyV1 {
    for (event_ordinal, event) in events.iter().enumerate() {
        let event_ordinal = u32::try_from(event_ordinal).unwrap_or(u32::MAX);
        candidate.fold_event_with(event, |mut turn| fold_turn(gate, &mut turn, event_ordinal))?;
        if candidate.exact_pass_due() {
            exact_pass(gate, candidate)?;
        }
    }
    exact_pass(gate, candidate)?;
    candidate
        .take_staged()
        .ok_or(StagedFoldErrorV1::StagedOutputExceeded)
}

fn exact_pass(
    gate: &mut WorkerGateV1<'_>,
    candidate: &mut DetachedProjectionCandidateV1,
) -> Result<(), StagedFoldErrorV1> {
    gate.before(STAGED_ACCOUNTING_PASS_BOUND_V1)?;
    candidate.exact_pass().map_err(limit_error)
}

/// One consumer's callback at one Event, under E3, `catch_unwind`, E4 and E5.
fn fold_turn(
    gate: &mut WorkerGateV1<'_>,
    turn: &mut CandidateTurnV1<'_>,
    event_ordinal: u32,
) -> Result<(), StagedFoldErrorV1> {
    let consumer_ordinal = consumer_ordinal(turn.ordinal());
    let bound = turn.bounds().callback_bound;
    let started = gate.before(bound)?;
    run_callback(|| turn.apply()).ok_or(StagedFoldErrorV1::ReducerPanicked {
        consumer_ordinal,
        event_ordinal,
    })?;
    gate.after(started, bound, consumer_ordinal, event_ordinal)?;
    turn.account().map_err(limit_error)
}
