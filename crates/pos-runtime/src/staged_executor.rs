//! Process-global staged fold executor (ADR-113 §4, §5 and §6).
//!
//! A protected Replay or Compare never runs a Reducer callback on the thread
//! that holds ADR-112's release guard. The guard thread hands a
//! [`StagedFoldPlanV1`] to the one staged-fold worker of the process and
//! waits for it with a monotonic timed wait that ends at `g0 + 27 s`. The
//! worker opens a fresh candidate through the host provider and folds it
//! with the live fold step, checking the deadline and cancellation before
//! every callback (E3), the admitted per-callback bound after it (E4) and the
//! staged size after every `apply` (E5). Every callback runs under
//! `catch_unwind`; its panic payload is dropped inside a nested
//! `catch_unwind` and never formatted.
//!
//! When the timed wait expires (E6) the executor is quarantined: the cancel
//! flag is set, the reply is abandoned and every later `acquire`, `fold` and
//! protected release in the process fails closed until the abandoned job
//! ends. The worker is never respawned.

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
    CandidateTurnV1, DetachedProjectionCandidateV1, InitialStateV1, ProjectionCandidateErrorV1,
    ProtectedProjectionProviderV1, RecordedConsumerV1, StagedLimitErrorV1, StagedProjectionV1,
    MAX_STAGED_CONSUMERS_V1,
};

use crate::registry::MAX_STAGED_CALLBACK_BOUND_V1;

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

/// The only line the panic hook writes for a panic inside a staged callback.
const STAGED_CALLBACK_PANIC_LINE: &[u8] = b"pigloros: staged reducer callback panicked\n";

const READY: u8 = 0;
const BUSY: u8 = 1;
const QUARANTINED: u8 = 2;

static HEALTH: AtomicU8 = AtomicU8::new(READY);
static WORKER: OnceLock<mpsc::Sender<StagedJobV1>> = OnceLock::new();

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
    /// A callback panicked. Opening the candidate reports ordinals `0, 0`
    /// and dropping its reducers reports event ordinal `u32::MAX`.
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
    events: Arc<[Event]>,
    source: ProjectionSourceV1,
    clock: Box<dyn GuardMonotonicSourceV1>,
}

impl StagedFoldPlanV1 {
    /// Plan a fold of `events` for exactly `consumers`. The host drops
    /// consent-closed markers here, once, as the live fold does.
    #[must_use]
    pub fn new(
        consumers: Vec<RecordedConsumerV1>,
        events: &[Event],
        source: ProjectionSourceV1,
    ) -> Self {
        Self {
            consumers,
            events: crate::registry::host_projection_events(events).into(),
            source,
            clock: Box::new(SystemGuardMonotonicSourceV1),
        }
    }

    /// Use `clock` for the worker's E3 and E4 checks.
    #[must_use]
    pub fn with_worker_clock(mut self, clock: Box<dyn GuardMonotonicSourceV1>) -> Self {
        self.clock = clock;
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
    /// Returns [`StagedFoldErrorV1::UnsupportedPanicStrategy`] under
    /// `panic = "abort"` or [`StagedFoldErrorV1::ExecutorQuarantined`].
    pub fn acquire() -> Result<Self, StagedFoldErrorV1> {
        PANIC_STRATEGY?;
        let worker = WORKER.get_or_init(start_worker);
        require_staged_release()?;
        Ok(Self { worker })
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
        let _ = self.worker.send(job);
        outcome.recv_timeout(remaining).unwrap_or_else(|_| {
            window.cancel.store(true, Ordering::SeqCst);
            let _ = HEALTH.compare_exchange(BUSY, QUARANTINED, Ordering::SeqCst, Ordering::SeqCst);
            Err(StagedFoldErrorV1::DeadlineExceeded)
        })
    }
}

/// E1: callbacks can be contained only when panics unwind.
#[cfg(panic = "unwind")]
const PANIC_STRATEGY: Result<(), StagedFoldErrorV1> = Ok(());
/// E1: callbacks can be contained only when panics unwind.
#[cfg(not(panic = "unwind"))]
const PANIC_STRATEGY: Result<(), StagedFoldErrorV1> =
    Err(StagedFoldErrorV1::UnsupportedPanicStrategy);

/// E2: check the plan on the guard thread and return the wait until
/// `g0 + 27 s`.
fn admit_plan(
    window: &GuardedFoldWindowV1<'_>,
    guard_clock: &mut dyn GuardMonotonicSourceV1,
    plan: &StagedFoldPlanV1,
) -> Result<Duration, StagedFoldErrorV1> {
    if plan.consumers.is_empty() || plan.consumers.len() > MAX_STAGED_CONSUMERS_V1 {
        return Err(StagedFoldErrorV1::ConsumerSetMismatch);
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

fn start_worker() -> mpsc::Sender<StagedJobV1> {
    install_panic_hook();
    let (jobs, queue) = mpsc::channel::<StagedJobV1>();
    let _detached = std::thread::spawn(move || queue.iter().for_each(run_job));
    jobs
}

/// Chain one process-global hook that writes only a fixed line for a panic
/// inside a staged callback, keyed on a thread-local flag, and delegates
/// every other panic to the previous hook.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if IN_STAGED_CALLBACK.get() {
            let _ = std::io::stderr().write_all(STAGED_CALLBACK_PANIC_LINE);
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

fn drop_payload(payload: Box<dyn Any + Send>) {
    if let Err(nested) = catch_unwind(AssertUnwindSafe(move || drop(payload))) {
        // A payload whose `Drop` panicked again is leaked, never formatted.
        std::mem::forget(nested);
    }
}

/// Drop a value that may own Reducer or factory state under the same
/// panic containment as a callback.
fn drop_guarded<T>(value: T) {
    let _ = run_callback(move || drop(value));
}

type StagedReplyV1 = Result<StagedProjectionV1, StagedFoldErrorV1>;

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
        let _ = reply.send(outcome);
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

/// Bound of opening a candidate: one admitted callback bound per `build`.
fn open_bound(consumers: usize) -> Duration {
    MAX_STAGED_CALLBACK_BOUND_V1.saturating_mul(u32::try_from(consumers).unwrap_or(u32::MAX))
}

fn fold_on_worker(
    plan: StagedFoldPlanV1,
    provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync>,
    g0: MonotonicMarkV1,
    cancel: &AtomicBool,
) -> StagedReplyV1 {
    let StagedFoldPlanV1 {
        consumers,
        events,
        source,
        clock,
    } = plan;
    let mut gate = WorkerGateV1 { clock, g0, cancel };
    let opened = open_on_worker(&mut gate, provider.as_ref(), &consumers, source);
    drop_guarded(provider);
    let (mut candidate, started) = opened?;
    let outcome = gate
        .after(started, open_bound(consumers.len()), 0, 0)
        .and_then(|()| fold_candidate(&mut gate, &mut candidate, &events));
    // The reducer instances are dropped here, as one more callback; a panic
    // in their `Drop` fails the fold with the teardown event ordinal.
    let dropped = run_callback(move || drop(candidate));
    outcome.and_then(|staged| {
        dropped
            .map(|()| staged)
            .ok_or(StagedFoldErrorV1::ReducerPanicked {
                consumer_ordinal: 0,
                event_ordinal: u32::MAX,
            })
    })
}

/// Open the candidate as one callback: the provider builds every recorded
/// consumer's factory inside it.
fn open_on_worker(
    gate: &mut WorkerGateV1<'_>,
    provider: &dyn ProtectedProjectionProviderV1,
    consumers: &[RecordedConsumerV1],
    source: ProjectionSourceV1,
) -> Result<(DetachedProjectionCandidateV1, MonotonicMarkV1), StagedFoldErrorV1> {
    let started = gate.before(open_bound(consumers.len()))?;
    run_callback(|| provider.open_candidate(consumers, InitialStateV1::Empty, source))
        .ok_or(StagedFoldErrorV1::ReducerPanicked {
            consumer_ordinal: 0,
            event_ordinal: 0,
        })?
        .map(|candidate| (candidate, started))
        .map_err(candidate_error)
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
    let consumer_ordinal = u16::try_from(turn.ordinal()).unwrap_or(u16::MAX);
    let bound = turn.bounds().callback_bound;
    let started = gate.before(bound)?;
    run_callback(|| turn.apply()).ok_or(StagedFoldErrorV1::ReducerPanicked {
        consumer_ordinal,
        event_ordinal,
    })?;
    gate.after(started, bound, consumer_ordinal, event_ordinal)?;
    turn.account().map_err(limit_error)
}
