//! Dedicated synchronous [`EventStore`] owner.
//!
//! The gateway never holds a synchronous store lock on an async executor
//! worker.  Commands are linearised by one bounded FIFO and executed by one
//! dedicated OS thread.
use pos_core::{
    event::{Event, EventDraft, Kind},
    geo_admission::{
        GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
    },
    ids::{EntityId, EventId, TimelineId},
    store::{
        AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore,
        PurgeOutcome, SeqRange,
    },
    timeline::Timeline,
    ConsentGrantedV1, ConsentRevokedV1, CoreError, OwnTracksIngressInputV1,
    OwnTracksIngressRateKeyV1, OwnTracksIngressStore, EVENT_TYPE_CONSENT_GRANTED_V1,
    EVENT_TYPE_CONSENT_REVOKED_V1,
};
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch, Notify, OwnedSemaphorePermit, Semaphore};

pub(crate) const QUEUE_CAPACITY: usize = 64;
pub(crate) const RESERVED_WRITE_CAPACITY: usize = 8;
const READ_CAPACITY: usize = QUEUE_CAPACITY - RESERVED_WRITE_CAPACITY;
const READ_BURST: u8 = 8;
const COMMAND_DEADLINE: Duration = Duration::from_secs(5);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const OWNTRACKS_RATE_BURST: u8 = 5;
const OWNTRACKS_RATE_KEYS_MAXIMUM: usize = 64;
const OWNTRACKS_RATE_STATE_TTL: Duration = Duration::from_mins(15);

macro_rules! submit {
    ($executor:expr_2021, $build:expr_2021) => {{
        let deadline = Instant::now() + $executor.command_deadline();
        let lifecycle = Arc::new(CommandLifecycle::new());
        let (reply, result) = oneshot::channel();
        match $executor.try_submit($build(reply), deadline, Arc::clone(&lifecycle)) {
            Ok(()) => await_command_result($executor, result, lifecycle, deadline).await,
            Err(error) => Err(error),
        }
    }};
}

enum Command {
    #[allow(dead_code)]
    AdmitOwnTracksIngress {
        basic_handle: [u8; 32],
        basic_secret: [u8; 32],
        payload: pos_core::CanonicalBytes,
        reply: oneshot::Sender<Result<OwnTracksIngressOutcome, StoreExecutorError>>,
    },
    AdmitGeoLocation {
        request: GeoLocationAdmissionRequestV1,
        reply: oneshot::Sender<Result<GeoLocationAdmissionOutcome, StoreExecutorError>>,
    },
    Purge {
        limit: NonZeroUsize,
        reply: oneshot::Sender<Result<PurgeOutcome, StoreExecutorError>>,
    },
    RootCount {
        maximum: usize,
        reply: oneshot::Sender<Result<usize, StoreExecutorError>>,
    },
    Create {
        name: String,
        reply: oneshot::Sender<Result<Timeline, StoreExecutorError>>,
    },
    Read {
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
        reply: oneshot::Sender<Result<Vec<Event>, StoreExecutorError>>,
    },
    ReadOne {
        timeline: TimelineId,
        event: EventId,
        reply: oneshot::Sender<Result<Option<Event>, StoreExecutorError>>,
    },
    Append {
        timeline: TimelineId,
        drafts: Vec<EventDraft>,
        maximum: Option<u64>,
        reply: oneshot::Sender<Result<Vec<Event>, StoreExecutorError>>,
    },
    AppendConsentGrant {
        timeline: TimelineId,
        grant: ConsentGrantedV1,
        maximum: u64,
        reply: oneshot::Sender<Result<Event, StoreExecutorError>>,
    },
    AppendConsentRevocation {
        timeline: TimelineId,
        revocation: ConsentRevokedV1,
        maximum: u64,
        reply: oneshot::Sender<Result<Event, StoreExecutorError>>,
    },
    AppendIdentified {
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
        reply: oneshot::Sender<Result<Option<AppendOrDuplicateOutcome>, StoreExecutorError>>,
    },
    GetTimeline {
        timeline: TimelineId,
        reply: oneshot::Sender<Result<Option<Timeline>, StoreExecutorError>>,
    },
    #[cfg(test)]
    Panic {
        reply: oneshot::Sender<Result<(), StoreExecutorError>>,
    },
    #[cfg(test)]
    PanicRead {
        reply: oneshot::Sender<Result<(), StoreExecutorError>>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandClass {
    Read,
    Write,
}

impl Command {
    const fn class(&self) -> CommandClass {
        match self {
            Self::RootCount { .. }
            | Self::Read { .. }
            | Self::ReadOne { .. }
            | Self::GetTimeline { .. } => CommandClass::Read,
            Self::AdmitOwnTracksIngress { .. }
            | Self::AdmitGeoLocation { .. }
            | Self::Purge { .. }
            | Self::Create { .. }
            | Self::Append { .. }
            | Self::AppendConsentGrant { .. }
            | Self::AppendConsentRevocation { .. }
            | Self::AppendIdentified { .. } => CommandClass::Write,
            #[cfg(test)]
            Self::Panic { .. } => CommandClass::Write,
            #[cfg(test)]
            Self::PanicRead { .. } => CommandClass::Read,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchedulerTrace {
    Admitted {
        ordinal: u64,
        class: CommandClass,
    },
    DrainCompleted {
        pending: usize,
        disconnected: bool,
    },
    Selected {
        ordinal: u64,
        class: CommandClass,
        reads_since_write: u8,
    },
}

#[cfg(test)]
struct SchedulerObserver {
    trace: std::sync::mpsc::SyncSender<SchedulerTrace>,
    gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl SchedulerObserver {
    fn new(capacity: usize) -> (Arc<Self>, std::sync::mpsc::Receiver<SchedulerTrace>) {
        let (trace, records) = std::sync::mpsc::sync_channel(capacity);
        (
            Arc::new(Self {
                trace,
                gate: Mutex::new(None),
            }),
            records,
        )
    }

    fn install_gate(&self, gate: std::sync::mpsc::Receiver<()>) {
        let mut current = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = Some(gate);
    }

    fn record(&self, record: SchedulerTrace) {
        assert!(
            self.trace.try_send(record).is_ok(),
            "scheduler trace receiver accepts every expected record"
        );
    }

    fn admitted(&self, ordinal: u64, class: CommandClass) {
        self.record(SchedulerTrace::Admitted { ordinal, class });
    }

    fn drain_completed(&self, pending: usize, disconnected: bool) {
        self.record(SchedulerTrace::DrainCompleted {
            pending,
            disconnected,
        });
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(gate) = gate {
            assert!(
                gate.recv().is_ok(),
                "scheduler controller releases the worker"
            );
        }
    }

    fn selected(&self, ordinal: u64, class: CommandClass, reads_since_write: u8) {
        self.record(SchedulerTrace::Selected {
            ordinal,
            class,
            reads_since_write,
        });
    }
}

trait GeoLocationGatewayStore: EventStore + GeoLocationAdmissionStore {}

impl<T> GeoLocationGatewayStore for T where T: EventStore + GeoLocationAdmissionStore {}

trait OwnTracksGatewayStore: EventStore + GeoLocationAdmissionStore + OwnTracksIngressStore {}

impl<T> OwnTracksGatewayStore for T where
    T: EventStore + GeoLocationAdmissionStore + OwnTracksIngressStore
{
}

enum ExecutorStore {
    Generic(Box<dyn EventStore>),
    GeoLocation(Box<dyn GeoLocationGatewayStore>),
    OwnTracks(Box<dyn OwnTracksGatewayStore>),
}

impl ExecutorStore {
    fn event_store(&mut self) -> &mut dyn EventStore {
        match self {
            Self::Generic(store) => store.as_mut(),
            Self::GeoLocation(store) => store.as_mut(),
            Self::OwnTracks(store) => store.as_mut(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnTracksIngressOutcome {
    Admitted {
        outcome: GeoLocationAdmissionOutcome,
        timeline: TimelineId,
        entity: EntityId,
    },
    RateLimited,
}

struct OwnTracksRateLimiter {
    buckets: HashMap<OwnTracksIngressRateKeyV1, OwnTracksTokenBucket>,
}

struct OwnTracksTokenBucket {
    tokens: u8,
    last_refill: Instant,
}

impl OwnTracksRateLimiter {
    fn allow(&mut self, key: OwnTracksIngressRateKeyV1) -> bool {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < OWNTRACKS_RATE_STATE_TTL);
        if !self.buckets.contains_key(&key) && self.buckets.len() == OWNTRACKS_RATE_KEYS_MAXIMUM {
            if let Some(oldest) = self
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_refill)
                .map(|(key, _)| *key)
            {
                self.buckets.remove(&oldest);
            }
        }
        let bucket = self.buckets.entry(key).or_insert(OwnTracksTokenBucket {
            tokens: OWNTRACKS_RATE_BURST,
            last_refill: now,
        });
        let replenished = u8::try_from(
            now.duration_since(bucket.last_refill)
                .as_secs()
                .min(u64::from(OWNTRACKS_RATE_BURST)),
        )
        .unwrap_or(OWNTRACKS_RATE_BURST);
        if replenished != 0 {
            bucket.tokens = bucket
                .tokens
                .saturating_add(replenished)
                .min(OWNTRACKS_RATE_BURST);
            bucket.last_refill += Duration::from_secs(u64::from(replenished));
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

struct ExecutorState {
    store: ExecutorStore,
    owntracks_owner_key: Option<[u8; 32]>,
    owntracks_rate_limiter: OwnTracksRateLimiter,
}

#[derive(Debug)]
pub(crate) enum StoreExecutorError {
    Saturated,
    Closed,
    DeadlineExceeded,
    Unhealthy,
    Store(CoreError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifecycleState {
    Open,
    Draining,
    Closed,
    Unhealthy { retryable_shutdown: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JoinOutcome {
    Succeeded,
    Panicked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum CommandPhase {
    Queued = 0,
    Started = 1,
    Expired = 2,
}

enum ExecutionClaim {
    Claimed,
    Expired,
}

struct CommandLifecycle {
    phase: AtomicU8,
}

impl CommandLifecycle {
    const fn new() -> Self {
        Self {
            phase: AtomicU8::new(CommandPhase::Queued as u8),
        }
    }

    fn start(&self) -> bool {
        self.phase
            .compare_exchange(
                CommandPhase::Queued as u8,
                CommandPhase::Started as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn claim_for_execution(&self, deadline: Instant) -> ExecutionClaim {
        if !self.start() {
            return ExecutionClaim::Expired;
        }
        if Instant::now() >= deadline {
            let _transition = self.phase.compare_exchange(
                CommandPhase::Started as u8,
                CommandPhase::Expired as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return ExecutionClaim::Expired;
        }
        ExecutionClaim::Claimed
    }

    fn expire_if_queued(&self) -> bool {
        self.phase
            .compare_exchange(
                CommandPhase::Queued as u8,
                CommandPhase::Expired as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

struct ExecutorControl {
    tx: mpsc::Sender<CommandEnvelope>,
    global_budget: Arc<Semaphore>,
    read_budget: Arc<Semaphore>,
    next_admission_ordinal: Mutex<u64>,
    #[cfg(test)]
    observer: Option<Arc<SchedulerObserver>>,
    state: Arc<Mutex<LifecycleState>>,
    shutdown: Arc<Notify>,
    join: Mutex<Option<JoinHandle<()>>>,
    join_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    join_completion: watch::Sender<Option<JoinOutcome>>,
    command_deadline: Duration,
    shutdown_deadline: Duration,
}

pub(crate) struct CommandEnvelope {
    deadline: Instant,
    lifecycle: Arc<CommandLifecycle>,
    class: CommandClass,
    admission_ordinal: u64,
    global_permit: OwnedSemaphorePermit,
    read_permit: Option<OwnedSemaphorePermit>,
    command: Command,
}

#[derive(Clone)]
pub(crate) struct StoreExecutor {
    control: Arc<ExecutorControl>,
}

impl StoreExecutor {
    pub(crate) fn new(store: Box<dyn EventStore>) -> Self {
        Self::spawn(ExecutorStore::Generic(store), None)
    }

    pub(crate) fn new_with_geo_location_admission<S>(store: S) -> Self
    where
        S: EventStore + GeoLocationAdmissionStore + 'static,
    {
        Self::spawn(ExecutorStore::GeoLocation(Box::new(store)), None)
    }

    pub(crate) fn new_with_owntracks_ingress<S>(store: S, owner_key: [u8; 32]) -> Self
    where
        S: EventStore + GeoLocationAdmissionStore + OwnTracksIngressStore + 'static,
    {
        Self::spawn(ExecutorStore::OwnTracks(Box::new(store)), Some(owner_key))
    }

    fn spawn(store: ExecutorStore, owntracks_owner_key: Option<[u8; 32]>) -> Self {
        Self::spawn_with_deadlines(
            store,
            owntracks_owner_key,
            COMMAND_DEADLINE,
            SHUTDOWN_DEADLINE,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    fn spawn_with_deadlines_for_test(
        store: ExecutorStore,
        command_deadline: Duration,
        shutdown_deadline: Duration,
    ) -> Self {
        Self::spawn_with_deadlines(store, None, command_deadline, shutdown_deadline, None)
    }

    #[cfg(test)]
    fn spawn_with_observer_for_test(
        store: ExecutorStore,
        observer: Arc<SchedulerObserver>,
    ) -> Self {
        Self::spawn_with_deadlines(
            store,
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Some(observer),
        )
    }

    fn spawn_with_deadlines(
        store: ExecutorStore,
        owntracks_owner_key: Option<[u8; 32]>,
        command_deadline: Duration,
        shutdown_deadline: Duration,
        #[cfg(test)] observer: Option<Arc<SchedulerObserver>>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
        let (join_completion, _join_receiver) = watch::channel(None);
        let control = Arc::new(ExecutorControl {
            tx,
            global_budget: Arc::new(Semaphore::new(QUEUE_CAPACITY)),
            read_budget: Arc::new(Semaphore::new(READ_CAPACITY)),
            next_admission_ordinal: Mutex::new(0),
            #[cfg(test)]
            observer: observer.clone(),
            state: Arc::new(Mutex::new(LifecycleState::Open)),
            shutdown: Arc::new(Notify::new()),
            join: Mutex::new(None),
            join_task: Mutex::new(None),
            join_completion,
            command_deadline,
            shutdown_deadline,
        });
        let worker_state = Arc::clone(&control.state);
        let worker_shutdown = Arc::clone(&control.shutdown);
        let worker = thread::Builder::new()
            .name("piglor-store-executor".to_owned())
            .spawn(move || {
                worker_loop(
                    &worker_state,
                    worker_shutdown,
                    &mut rx,
                    store,
                    owntracks_owner_key,
                    #[cfg(test)]
                    observer,
                );
            });
        register_worker(control.as_ref(), worker);
        Self { control }
    }

    #[cfg(test)]
    pub(crate) fn from_sender_for_test(tx: mpsc::Sender<CommandEnvelope>) -> Self {
        Self::from_sender_with_deadlines_for_test(tx, COMMAND_DEADLINE, SHUTDOWN_DEADLINE)
    }

    #[cfg(test)]
    fn from_sender_with_deadlines_for_test(
        tx: mpsc::Sender<CommandEnvelope>,
        command_deadline: Duration,
        shutdown_deadline: Duration,
    ) -> Self {
        let (join_completion, _join_receiver) = watch::channel(None);
        Self {
            control: Arc::new(ExecutorControl {
                tx,
                global_budget: Arc::new(Semaphore::new(QUEUE_CAPACITY)),
                read_budget: Arc::new(Semaphore::new(READ_CAPACITY)),
                next_admission_ordinal: Mutex::new(0),
                observer: None,
                state: Arc::new(Mutex::new(LifecycleState::Open)),
                shutdown: Arc::new(Notify::new()),
                join: Mutex::new(None),
                join_task: Mutex::new(None),
                join_completion,
                command_deadline,
                shutdown_deadline,
            }),
        }
    }

    fn command_deadline(&self) -> Duration {
        self.control.command_deadline
    }

    fn current_state(&self) -> LifecycleState {
        match self.control.state.lock() {
            Ok(state) => *state,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    fn reply_closed_error(&self) -> StoreExecutorError {
        if matches!(self.current_state(), LifecycleState::Unhealthy { .. }) {
            StoreExecutorError::Unhealthy
        } else {
            StoreExecutorError::Closed
        }
    }

    fn try_submit(
        &self,
        command: Command,
        deadline: Instant,
        lifecycle: Arc<CommandLifecycle>,
    ) -> Result<(), StoreExecutorError> {
        self.try_submit_with_admission(command, deadline, lifecycle)
            .map(|_| ())
    }

    #[cfg(test)]
    fn try_submit_with_admission_for_test(
        &self,
        command: Command,
        deadline: Instant,
        lifecycle: Arc<CommandLifecycle>,
    ) -> Result<u64, StoreExecutorError> {
        self.try_submit_with_admission(command, deadline, lifecycle)
            .map(|(_, ordinal)| ordinal)
    }

    fn try_submit_with_admission(
        &self,
        command: Command,
        deadline: Instant,
        lifecycle: Arc<CommandLifecycle>,
    ) -> Result<(CommandClass, u64), StoreExecutorError> {
        let class = command.class();
        let admission = {
            let state = match self.control.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            match *state {
                LifecycleState::Open => {}
                LifecycleState::Draining | LifecycleState::Closed => {
                    return Err(StoreExecutorError::Closed)
                }
                LifecycleState::Unhealthy { .. } => return Err(StoreExecutorError::Unhealthy),
            }
            let global_permit = self
                .control
                .global_budget
                .clone()
                .try_acquire_owned()
                .map_err(|_| StoreExecutorError::Saturated)?;
            let read_permit = match class {
                CommandClass::Read => Some(
                    self.control
                        .read_budget
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| StoreExecutorError::Saturated)?,
                ),
                CommandClass::Write => None,
            };
            let admission_ordinal = match self.control.next_admission_ordinal.lock() {
                Ok(ordinal) => *ordinal,
                Err(poisoned) => *poisoned.into_inner(),
            };
            let next_admission_ordinal = admission_ordinal.checked_add(1).ok_or_else(|| {
                StoreExecutorError::Store(CoreError::Storage(
                    "StoreExecutor admission ordinal overflow".to_owned(),
                ))
            })?;
            let send_result = self.control.tx.try_send(CommandEnvelope {
                deadline,
                lifecycle,
                class,
                admission_ordinal,
                global_permit,
                read_permit,
                command,
            });
            drop(state);
            match send_result {
                Ok(()) => {
                    let mut ordinal = match self.control.next_admission_ordinal.lock() {
                        Ok(ordinal) => ordinal,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    *ordinal = next_admission_ordinal;
                    drop(ordinal);
                    Ok((class, admission_ordinal))
                }
                Err(mpsc::error::TrySendError::Full(_)) => Err(StoreExecutorError::Saturated),
                Err(mpsc::error::TrySendError::Closed(_)) => Err(StoreExecutorError::Closed),
            }
        };
        #[cfg(test)]
        if let Ok((class, ordinal)) = admission {
            if let Some(observer) = &self.control.observer {
                observer.admitted(ordinal, class);
            }
        }
        admission
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.current_state() == LifecycleState::Open
    }

    pub(crate) async fn shutdown(&self) -> Result<(), StoreExecutorError> {
        let deadline = Instant::now() + self.control.shutdown_deadline;
        let notify_worker = {
            let mut state = match self.control.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            let notify_worker = match *state {
                LifecycleState::Open => {
                    *state = LifecycleState::Draining;
                    true
                }
                LifecycleState::Draining => false,
                LifecycleState::Closed => return Err(StoreExecutorError::Closed),
                LifecycleState::Unhealthy { .. } => {
                    if !self.has_join_work() {
                        return Err(StoreExecutorError::Unhealthy);
                    }
                    false
                }
            };
            drop(state);
            notify_worker
        };
        if notify_worker {
            self.control.shutdown.notify_one();
        }

        if !self.ensure_join_task() {
            return Err(self.reply_closed_error());
        }
        match self.wait_for_join(deadline).await {
            Ok(JoinOutcome::Succeeded) => {
                if matches!(
                    self.current_state(),
                    LifecycleState::Unhealthy {
                        retryable_shutdown: false
                    }
                ) {
                    return Err(StoreExecutorError::Unhealthy);
                }
                set_lifecycle_state(self.control.state.as_ref(), LifecycleState::Closed);
            }
            Ok(JoinOutcome::Panicked) => {
                set_lifecycle_state(
                    self.control.state.as_ref(),
                    LifecycleState::Unhealthy {
                        retryable_shutdown: false,
                    },
                );
                return Err(StoreExecutorError::Unhealthy);
            }
            Err(()) => {
                set_lifecycle_state(
                    self.control.state.as_ref(),
                    LifecycleState::Unhealthy {
                        retryable_shutdown: true,
                    },
                );
                return Err(StoreExecutorError::DeadlineExceeded);
            }
        }
        Ok(())
    }

    fn has_join_work(&self) -> bool {
        self.join_outcome().is_some()
            || self.control.join_task.lock().map_or_else(
                |poisoned| poisoned.into_inner().is_some(),
                |join_task| join_task.is_some(),
            )
            || self.control.join.lock().map_or_else(
                |poisoned| poisoned.into_inner().is_some(),
                |join| join.is_some(),
            )
    }

    fn ensure_join_task(&self) -> bool {
        let mut join_task = match self.control.join_task.lock() {
            Ok(join_task) => join_task,
            Err(poisoned) => poisoned.into_inner(),
        };
        if join_task.is_some() {
            return true;
        }
        let join = match self.control.join.lock() {
            Ok(mut join) => join.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        let Some(join) = join else {
            return self.join_outcome().is_some();
        };
        let completion = self.control.join_completion.clone();
        *join_task = Some(tokio::task::spawn_blocking(move || {
            let outcome = if join.join().is_ok() {
                JoinOutcome::Succeeded
            } else {
                JoinOutcome::Panicked
            };
            completion.send_replace(Some(outcome));
        }));
        true
    }

    fn join_outcome(&self) -> Option<JoinOutcome> {
        *self.control.join_completion.borrow()
    }

    async fn wait_for_join(&self, deadline: Instant) -> Result<JoinOutcome, ()> {
        let mut completion = self.control.join_completion.subscribe();
        loop {
            let outcome = *completion.borrow();
            if let Some(outcome) = outcome {
                return Ok(outcome);
            }
            if tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                completion.changed(),
            )
            .await
            .is_err()
            {
                return Err(());
            }
        }
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn panic_for_test(&self) -> Result<(), StoreExecutorError> {
        let result = submit!(self, |reply| Command::Panic { reply });
        drop(
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.is_ready() {
                    tokio::task::yield_now().await;
                }
            })
            .await,
        );
        result
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn panic_read_for_test(&self) -> Result<(), StoreExecutorError> {
        let result = submit!(self, |reply| Command::PanicRead { reply });
        drop(
            tokio::time::timeout(Duration::from_secs(1), async {
                while self.is_ready() {
                    tokio::task::yield_now().await;
                }
            })
            .await,
        );
        result
    }

    pub(crate) async fn purge(
        &self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, StoreExecutorError> {
        submit!(self, |reply| Command::Purge { limit, reply })
    }
    pub(crate) async fn admit_geo_location(
        &self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, StoreExecutorError> {
        submit!(self, |reply| Command::AdmitGeoLocation { request, reply })
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn admit_owntracks_ingress(
        &self,
        basic_handle: [u8; 32],
        basic_secret: [u8; 32],
        payload: pos_core::CanonicalBytes,
    ) -> Result<OwnTracksIngressOutcome, StoreExecutorError> {
        submit!(self, |reply| Command::AdmitOwnTracksIngress {
            basic_handle,
            basic_secret,
            payload,
            reply
        })
    }
    pub(crate) async fn root_count(&self, maximum: usize) -> Result<usize, StoreExecutorError> {
        submit!(self, |reply| Command::RootCount { maximum, reply })
    }
    pub(crate) async fn create(&self, name: String) -> Result<Timeline, StoreExecutorError> {
        submit!(self, |reply| Command::Create { name, reply })
    }
    pub(crate) async fn read(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, StoreExecutorError> {
        submit!(self, |reply| Command::Read {
            timeline,
            range,
            bounds,
            reply,
        })
    }
    pub(crate) async fn read_one(
        &self,
        timeline: TimelineId,
        event: EventId,
    ) -> Result<Option<Event>, StoreExecutorError> {
        submit!(self, |reply| Command::ReadOne {
            timeline,
            event,
            reply,
        })
    }
    pub(crate) async fn append(
        &self,
        timeline: TimelineId,
        drafts: Vec<EventDraft>,
        maximum: Option<u64>,
    ) -> Result<Vec<Event>, StoreExecutorError> {
        submit!(self, |reply| Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        })
    }
    pub(crate) async fn append_consent_grant(
        &self,
        timeline: TimelineId,
        grant: ConsentGrantedV1,
        maximum: u64,
    ) -> Result<Event, StoreExecutorError> {
        submit!(self, |reply| Command::AppendConsentGrant {
            timeline,
            grant,
            maximum,
            reply,
        })
    }
    pub(crate) async fn append_consent_revocation(
        &self,
        timeline: TimelineId,
        revocation: ConsentRevokedV1,
        maximum: u64,
    ) -> Result<Event, StoreExecutorError> {
        submit!(self, |reply| Command::AppendConsentRevocation {
            timeline,
            revocation,
            maximum,
            reply,
        })
    }
    pub(crate) async fn append_identified(
        &self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, StoreExecutorError> {
        submit!(self, |reply| Command::AppendIdentified {
            timeline,
            identity,
            intent,
            maximum,
            reply,
        })
    }
    pub(crate) async fn timeline(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<Timeline>, StoreExecutorError> {
        submit!(self, |reply| Command::GetTimeline { timeline, reply })
    }
}

async fn await_command_result<T>(
    executor: &StoreExecutor,
    mut reply: oneshot::Receiver<Result<T, StoreExecutorError>>,
    lifecycle: Arc<CommandLifecycle>,
    deadline: Instant,
) -> Result<T, StoreExecutorError> {
    let timeout_result =
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut reply).await;
    let result = if let Ok(result) = timeout_result {
        result
    } else {
        if lifecycle.expire_if_queued() {
            return Err(StoreExecutorError::DeadlineExceeded);
        }
        reply.await
    };
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(executor.reply_closed_error()),
    }
}

fn set_lifecycle_state(current_state: &Mutex<LifecycleState>, state: LifecycleState) {
    let mut current = match current_state.lock() {
        Ok(current) => current,
        Err(poisoned) => poisoned.into_inner(),
    };
    *current = state;
}

fn register_worker(control: &ExecutorControl, worker: std::io::Result<JoinHandle<()>>) {
    match worker {
        Ok(worker) => {
            let mut join = match control.join.lock() {
                Ok(join) => join,
                Err(poisoned) => poisoned.into_inner(),
            };
            *join = Some(worker);
            drop(join);
        }
        Err(_) => set_lifecycle_state(
            control.state.as_ref(),
            LifecycleState::Unhealthy {
                retryable_shutdown: false,
            },
        ),
    }
}

fn take_worker_runtime(
    lifecycle_state: &Mutex<LifecycleState>,
    runtime: std::io::Result<tokio::runtime::Runtime>,
) -> Option<tokio::runtime::Runtime> {
    runtime.map_or_else(
        |_| {
            set_lifecycle_state(
                lifecycle_state,
                LifecycleState::Unhealthy {
                    retryable_shutdown: false,
                },
            );
            None
        },
        Some,
    )
}

fn worker_loop(
    lifecycle_state: &Arc<Mutex<LifecycleState>>,
    shutdown: Arc<Notify>,
    receiver: &mut mpsc::Receiver<CommandEnvelope>,
    store: ExecutorStore,
    owntracks_owner_key: Option<[u8; 32]>,
    #[cfg(test)] observer: Option<Arc<SchedulerObserver>>,
) {
    let worker_result = catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = take_worker_runtime(
            lifecycle_state.as_ref(),
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
        ) else {
            return;
        };
        runtime.block_on(worker_loop_async(
            Arc::clone(lifecycle_state),
            shutdown,
            receiver,
            store,
            owntracks_owner_key,
            #[cfg(test)]
            observer,
        ));
    }));
    match worker_result {
        Ok(()) => {
            let mut state = match lifecycle_state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            if matches!(*state, LifecycleState::Open) {
                *state = LifecycleState::Closed;
            }
        }
        Err(_) => set_lifecycle_state(
            lifecycle_state.as_ref(),
            LifecycleState::Unhealthy {
                retryable_shutdown: false,
            },
        ),
    }
}

async fn worker_loop_async(
    lifecycle_state: Arc<Mutex<LifecycleState>>,
    shutdown: Arc<Notify>,
    receiver: &mut mpsc::Receiver<CommandEnvelope>,
    store: ExecutorStore,
    owntracks_owner_key: Option<[u8; 32]>,
    #[cfg(test)] observer: Option<Arc<SchedulerObserver>>,
) {
    let mut state = ExecutorState {
        store,
        owntracks_owner_key,
        owntracks_rate_limiter: OwnTracksRateLimiter {
            buckets: HashMap::new(),
        },
    };
    let mut pending = Vec::new();
    let mut draining = false;
    let mut disconnected = false;
    let mut reads_since_write = 0;
    loop {
        if pending.is_empty() {
            if draining {
                break;
            }
            if disconnected {
                break;
            }
            let next_received = tokio::select! {
                biased;
                envelope = receiver.recv() => envelope,
                () = shutdown.notified() => {
                    draining = true;
                    continue;
                }
            };
            if let Some(envelope) = next_received {
                pending.push(envelope);
            } else {
                disconnected = true;
                continue;
            }
        }

        disconnected |= matches!(
            drain_available(receiver, &mut pending),
            QueueDrainOutcome::Disconnected
        );
        #[cfg(test)]
        if let Some(observer) = &observer {
            observer.drain_completed(pending.len(), disconnected);
        }
        let index = select_pending_index(&pending, reads_since_write);
        if matches!(
            pending[index]
                .lifecycle
                .claim_for_execution(pending[index].deadline),
            ExecutionClaim::Expired
        ) {
            expire_envelope(pending.remove(index));
            continue;
        }
        #[cfg(test)]
        let admission_ordinal = pending[index].admission_ordinal;
        let CommandEnvelope {
            command,
            class,
            global_permit,
            read_permit,
            ..
        } = pending.remove(index);
        let permit_owners = (global_permit, read_permit);
        #[cfg(test)]
        if let Some(observer) = &observer {
            observer.selected(admission_ordinal, class, reads_since_write);
        }
        match class {
            CommandClass::Read => {
                reads_since_write = reads_since_write.saturating_add(1).min(READ_BURST);
            }
            CommandClass::Write => reads_since_write = 0,
        }
        let execution = catch_unwind(AssertUnwindSafe(|| execute(&mut state, command)));
        drop(permit_owners);
        match execution {
            Ok(CommandExecution::Completed) => {}
            Err(payload) => {
                set_lifecycle_state(
                    lifecycle_state.as_ref(),
                    LifecycleState::Unhealthy {
                        retryable_shutdown: false,
                    },
                );
                std::panic::resume_unwind(payload);
            }
        }
    }
    drop(pending);
    drop(state);
}

enum QueueDrainOutcome {
    Open,
    Disconnected,
}

fn drain_available(
    receiver: &mut mpsc::Receiver<CommandEnvelope>,
    pending: &mut Vec<CommandEnvelope>,
) -> QueueDrainOutcome {
    loop {
        match receiver.try_recv() {
            Ok(envelope) => pending.push(envelope),
            Err(mpsc::error::TryRecvError::Empty) => return QueueDrainOutcome::Open,
            Err(mpsc::error::TryRecvError::Disconnected) => return QueueDrainOutcome::Disconnected,
        }
    }
}

fn select_pending_index(pending: &[CommandEnvelope], reads_since_write: u8) -> usize {
    let preferred = if reads_since_write < READ_BURST {
        CommandClass::Read
    } else {
        CommandClass::Write
    };
    let fallback = match preferred {
        CommandClass::Read => CommandClass::Write,
        CommandClass::Write => CommandClass::Read,
    };
    let preferred_index = pending
        .iter()
        .enumerate()
        .filter(|(_, envelope)| envelope.class == preferred)
        .min_by_key(|(_, envelope)| envelope.admission_ordinal);
    preferred_index.map_or_else(
        || {
            pending
                .iter()
                .enumerate()
                .filter(|(_, envelope)| envelope.class == fallback)
                .min_by_key(|(_, envelope)| envelope.admission_ordinal)
                .map_or(0, |(index, _)| index)
        },
        |(index, _)| index,
    )
}

fn expire_command(command: Command) {
    match command {
        Command::AdmitOwnTracksIngress { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::AdmitGeoLocation { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::Purge { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::RootCount { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::Create { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::Read { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::ReadOne { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::Append { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::AppendConsentGrant { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::AppendConsentRevocation { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::AppendIdentified { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        Command::GetTimeline { reply, .. } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        #[cfg(test)]
        Command::Panic { reply } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
        #[cfg(test)]
        Command::PanicRead { reply } => {
            drop(reply.send(Err(StoreExecutorError::DeadlineExceeded)));
        }
    }
}

fn expire_envelope(CommandEnvelope { command, .. }: CommandEnvelope) {
    expire_command(command);
}

fn send_store_result<T>(
    reply: oneshot::Sender<Result<T, StoreExecutorError>>,
    result: Result<T, CoreError>,
) {
    drop(reply.send(result.map_err(StoreExecutorError::Store)));
}

fn execute_owntracks_ingress(
    state: &mut ExecutorState,
    basic_handle: [u8; 32],
    basic_secret: [u8; 32],
    payload: pos_core::CanonicalBytes,
) -> Result<OwnTracksIngressOutcome, CoreError> {
    let ExecutorStore::OwnTracks(store) = &mut state.store else {
        return Err(CoreError::GeographicAdmissionUnavailable);
    };
    let Some(owner_key) = state.owntracks_owner_key else {
        return Err(CoreError::GeographicAdmissionUnavailable);
    };
    let input = owntracks_input(owner_key, basic_handle, basic_secret, payload);
    let prepared = store.prepare_owntracks_ingress(input)?;
    if !state.owntracks_rate_limiter.allow(prepared.rate_key()) {
        return Ok(OwnTracksIngressOutcome::RateLimited);
    }
    let request = prepared.into_admission_request();
    let timeline = request.timeline();
    let entity = request.entity();
    let outcome = store.admit_geo_location(request)?;
    Ok(OwnTracksIngressOutcome::Admitted {
        outcome,
        timeline,
        entity,
    })
}

fn owntracks_input(
    owner_key: [u8; 32],
    basic_handle: [u8; 32],
    basic_secret: [u8; 32],
    payload: pos_core::CanonicalBytes,
) -> OwnTracksIngressInputV1 {
    let mut verifier_material = Vec::with_capacity(96);
    verifier_material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
    verifier_material.extend_from_slice(&basic_handle);
    verifier_material.extend_from_slice(&basic_secret);
    let candidate_verifier = *blake3::keyed_hash(&owner_key, &verifier_material).as_bytes();
    let rate_key = owntracks_key(
        &owner_key,
        b"pigloros/owntracks/rate/v1\0",
        basic_handle,
        basic_secret,
        &payload,
        false,
    );
    let intent = owntracks_key(
        &owner_key,
        b"pigloros/owntracks/intent/v1\0",
        basic_handle,
        basic_secret,
        &payload,
        true,
    );
    let fingerprint = owntracks_key(
        &owner_key,
        b"pigloros/owntracks/fingerprint/v1\0",
        basic_handle,
        basic_secret,
        &payload,
        true,
    );
    OwnTracksIngressInputV1::new(candidate_verifier, rate_key, intent, fingerprint, payload)
}

fn owntracks_key(
    owner_key: &[u8; 32],
    domain: &[u8],
    basic_handle: [u8; 32],
    basic_secret: [u8; 32],
    payload: &pos_core::CanonicalBytes,
    includes_payload: bool,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(owner_key);
    hasher.update(domain);
    hasher.update(&basic_handle);
    if includes_payload {
        hasher.update(&basic_secret);
        hasher.update(payload.as_slice());
    }
    *hasher.finalize().as_bytes()
}

enum CommandExecution {
    Completed,
}

fn execute(state: &mut ExecutorState, command: Command) -> CommandExecution {
    match command {
        Command::AdmitOwnTracksIngress {
            basic_handle,
            basic_secret,
            payload,
            reply,
        } => execute_owntracks_command(state, basic_handle, basic_secret, payload, reply),
        Command::AdmitGeoLocation { request, reply } => {
            execute_geo_location_command(state, request, reply);
        }
        Command::Purge { limit, reply } => execute_purge_command(state, limit, reply),
        Command::RootCount { maximum, reply } => execute_root_count_command(state, maximum, reply),
        Command::Create { name, reply } => execute_create_command(state, &name, reply),
        Command::Read {
            timeline,
            range,
            bounds,
            reply,
        } => execute_read_command(state, timeline, range, bounds, reply),
        Command::ReadOne {
            timeline,
            event,
            reply,
        } => execute_read_one_command(state, timeline, event, reply),
        Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        } => execute_append_command(state, timeline, &drafts, maximum, reply),
        Command::AppendConsentGrant {
            timeline,
            grant,
            maximum,
            reply,
        } => execute_append_consent_grant_command(state, timeline, &grant, maximum, reply),
        Command::AppendConsentRevocation {
            timeline,
            revocation,
            maximum,
            reply,
        } => {
            execute_append_consent_revocation_command(state, timeline, &revocation, maximum, reply);
        }
        Command::AppendIdentified {
            timeline,
            identity,
            intent,
            maximum,
            reply,
        } => execute_append_identified_command(state, timeline, identity, intent, maximum, reply),
        Command::GetTimeline { timeline, reply } => {
            execute_get_timeline_command(state, timeline, reply);
        }
        #[cfg(test)]
        Command::Panic { reply } => {
            drop(reply.send(Err(StoreExecutorError::Unhealthy)));
            std::panic::resume_unwind(Box::new("test store executor worker panic"));
        }
        #[cfg(test)]
        Command::PanicRead { reply } => {
            drop(reply.send(Err(StoreExecutorError::Unhealthy)));
            std::panic::resume_unwind(Box::new("test store executor read worker panic"));
        }
    }
    CommandExecution::Completed
}

fn execute_owntracks_command(
    state: &mut ExecutorState,
    basic_handle: [u8; 32],
    basic_secret: [u8; 32],
    payload: pos_core::CanonicalBytes,
    reply: oneshot::Sender<Result<OwnTracksIngressOutcome, StoreExecutorError>>,
) {
    send_store_result(
        reply,
        execute_owntracks_ingress(state, basic_handle, basic_secret, payload),
    );
}

fn execute_geo_location_command(
    state: &mut ExecutorState,
    request: GeoLocationAdmissionRequestV1,
    reply: oneshot::Sender<Result<GeoLocationAdmissionOutcome, StoreExecutorError>>,
) {
    let result = match &mut state.store {
        ExecutorStore::GeoLocation(store) => store.admit_geo_location(request),
        ExecutorStore::OwnTracks(store) => store.admit_geo_location(request),
        ExecutorStore::Generic(_) => Err(CoreError::GeographicAdmissionUnavailable),
    };
    send_store_result(reply, result);
}

fn execute_purge_command(
    state: &mut ExecutorState,
    limit: NonZeroUsize,
    reply: oneshot::Sender<Result<PurgeOutcome, StoreExecutorError>>,
) {
    send_store_result(
        reply,
        state
            .store
            .event_store()
            .purge_expired_append_identities_bounded(limit),
    );
}

fn execute_root_count_command(
    state: &mut ExecutorState,
    maximum: usize,
    reply: oneshot::Sender<Result<usize, StoreExecutorError>>,
) {
    send_store_result(
        reply,
        state
            .store
            .event_store()
            .root_timeline_count_bounded(maximum),
    );
}

fn execute_create_command(
    state: &mut ExecutorState,
    name: &str,
    reply: oneshot::Sender<Result<Timeline, StoreExecutorError>>,
) {
    send_store_result(reply, state.store.event_store().create_timeline(name));
}

fn execute_read_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    range: SeqRange,
    bounds: EventReadBounds,
    reply: oneshot::Sender<Result<Vec<Event>, StoreExecutorError>>,
) {
    send_store_result(
        reply,
        state
            .store
            .event_store()
            .read_bounded(timeline, range, bounds),
    );
}

fn execute_read_one_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    event: EventId,
    reply: oneshot::Sender<Result<Option<Event>, StoreExecutorError>>,
) {
    send_store_result(
        reply,
        state.store.event_store().read_event_by_id(timeline, event),
    );
}

fn execute_append_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    drafts: &[EventDraft],
    maximum: Option<u64>,
    reply: oneshot::Sender<Result<Vec<Event>, StoreExecutorError>>,
) {
    let store = state.store.event_store();
    let result = match maximum {
        Some(maximum) => store
            .append_bounded(timeline, drafts, maximum)
            .and_then(|events| {
                events.ok_or_else(|| CoreError::Storage("event limit reached".to_owned()))
            }),
        None => store.append(timeline, drafts),
    };
    send_store_result(reply, result);
}

fn execute_append_consent_grant_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    grant: &ConsentGrantedV1,
    maximum: u64,
    reply: oneshot::Sender<Result<Event, StoreExecutorError>>,
) {
    let store = state.store.event_store();
    let result = store
        .logical_head(timeline)
        .and_then(|head| {
            if grant.grant_seq != head.as_u64().saturating_add(1) {
                return Err(CoreError::Storage(
                    "consent grant sequence mismatch".to_owned(),
                ));
            }
            grant
                .encode()
                .map_err(|error| CoreError::Storage(error.to_string()))
        })
        .and_then(|payload| {
            store.append_bounded(
                timeline,
                &[EventDraft::new(
                    grant.subject_id,
                    Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1),
                    payload,
                )],
                maximum,
            )
        })
        .and_then(|events| {
            events.ok_or_else(|| CoreError::Storage("event limit reached".to_owned()))
        })
        .map(|mut events| events.remove(0));
    send_store_result(reply, result);
}

fn execute_append_consent_revocation_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    revocation: &ConsentRevokedV1,
    maximum: u64,
    reply: oneshot::Sender<Result<Event, StoreExecutorError>>,
) {
    let store = state.store.event_store();
    let result = store
        .logical_head(timeline)
        .and_then(|head| {
            if revocation.fence_seq != head.as_u64().saturating_add(1) {
                return Err(CoreError::Storage(
                    "consent revocation fence mismatch".to_owned(),
                ));
            }
            revocation
                .encode()
                .map_err(|error| CoreError::Storage(error.to_string()))
        })
        .and_then(|payload| {
            store.append_bounded(
                timeline,
                &[EventDraft::new(
                    revocation.subject_id,
                    Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1),
                    payload,
                )],
                maximum,
            )
        })
        .and_then(|events| {
            events.ok_or_else(|| CoreError::Storage("event limit reached".to_owned()))
        })
        .map(|mut events| events.remove(0));
    send_store_result(reply, result);
}

fn execute_append_identified_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    identity: AppendIdentity,
    intent: AppendIntent,
    maximum: u64,
    reply: oneshot::Sender<Result<Option<AppendOrDuplicateOutcome>, StoreExecutorError>>,
) {
    send_store_result(
        reply,
        state
            .store
            .event_store()
            .append_intent_or_duplicate_bounded(timeline, identity, intent, maximum),
    );
}

fn execute_get_timeline_command(
    state: &mut ExecutorState,
    timeline: TimelineId,
    reply: oneshot::Sender<Result<Option<Timeline>, StoreExecutorError>>,
) {
    send_store_result(reply, state.store.event_store().get_timeline(timeline));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestResultExt<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
        fn test_err(self) -> Result<E, Box<dyn std::error::Error + Send + Sync>>;
        fn test_value(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
            self.map_err(|error| format!("unexpected error: {error:?}").into())
        }

        fn test_err(self) -> Result<E, Box<dyn std::error::Error + Send + Sync>> {
            self.err().ok_or_else(|| "expected an error".into())
        }

        fn test_value(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    trait TestOptionExt<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
        fn test_value(self) -> T;
    }

    impl<T> TestOptionExt<T> for Option<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
            self.ok_or_else(|| "expected a value".into())
        }

        fn test_value(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected a value")))
        }
    }

    use super::{
        execute_append_command, execute_owntracks_ingress, Command, ExecutorState, ExecutorStore,
        OwnTracksRateLimiter,
    };
    use pos_core::{
        event::{Event, EventDraft},
        geo_admission::{GeoLocationAdmissionInputV1, GeoLocationAdmissionRequestV1},
        store::{
            AppendDedupKey, AppendDedupScope, AppendIdentity, AppendIntent, EventReadBounds,
            EventStore, SeqRange,
        },
        timeline::Timeline,
        CanonicalBytes, ConsentGrantedV1, ConsentRevokedV1, CoreError, EntityId, EventId, Kind,
        OwnTracksIngressRateKeyV1, TimelineId,
    };
    use pos_store::memory::MemoryStore;
    use std::{
        collections::HashMap,
        num::NonZeroUsize,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    struct RecordingBoundedStore {
        calls: Arc<Mutex<Vec<(TimelineId, usize, u64)>>>,
        outcome: Option<Vec<Event>>,
    }

    impl EventStore for RecordingBoundedStore {
        fn create_timeline(&mut self, _name: &str) -> Result<Timeline, CoreError> {
            Err(CoreError::Storage(
                "create_timeline must not be called".to_owned(),
            ))
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            _drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage(
                "ordinary append must not be called when a ceiling is supplied".to_owned(),
            ))
        }

        fn append_bounded(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
            maximum: u64,
        ) -> Result<Option<Vec<Event>>, CoreError> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((timeline, drafts.len(), maximum));
            Ok(self.outcome.take())
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("read must not be called".to_owned()))
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: pos_core::Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            Err(CoreError::Storage("fork must not be called".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            Err(CoreError::Storage(
                "list_timelines must not be called".to_owned(),
            ))
        }

        fn get_timeline(&self, _timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
            Err(CoreError::Storage(
                "get_timeline must not be called by atomic bounded append".to_owned(),
            ))
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn execute_append_command_uses_only_atomic_bounded_append_for_a_ceiling(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timeline = TimelineId::new();
        let drafts = [
            EventDraft::new(
                EntityId::new(),
                Kind::new("world.action"),
                CanonicalBytes::from_static(b"action"),
            ),
            EventDraft::new(
                EntityId::new(),
                Kind::new("society.signal"),
                CanonicalBytes::from_static(b"signal"),
            ),
        ];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut state = ExecutorState {
            store: ExecutorStore::Generic(Box::new(RecordingBoundedStore {
                calls: Arc::clone(&calls),
                outcome: Some(Vec::new()),
            })),
            owntracks_owner_key: None,
            owntracks_rate_limiter: OwnTracksRateLimiter {
                buckets: HashMap::new(),
            },
        };
        let (reply, result) = tokio::sync::oneshot::channel();
        execute_append_command(&mut state, timeline, &drafts, Some(17), reply);
        assert!(result.blocking_recv().test_ok()?.test_ok()?.is_empty());
        assert_eq!(*calls.lock().test_ok()?, vec![(timeline, 2, 17)]);

        let rejected_calls = Arc::new(Mutex::new(Vec::new()));
        let mut rejected_state = ExecutorState {
            store: ExecutorStore::Generic(Box::new(RecordingBoundedStore {
                calls: Arc::clone(&rejected_calls),
                outcome: None,
            })),
            owntracks_owner_key: None,
            owntracks_rate_limiter: OwnTracksRateLimiter {
                buckets: HashMap::new(),
            },
        };
        let (reply, result) = tokio::sync::oneshot::channel();
        execute_append_command(&mut rejected_state, timeline, &drafts[..1], Some(23), reply);
        assert!(matches!(
            result.blocking_recv().test_ok()?,
            Err(super::StoreExecutorError::Store(CoreError::Storage(message)))
                if message == "event limit reached"
        ));
        assert_eq!(*rejected_calls.lock().test_ok()?, vec![(timeline, 1, 23)]);

        Ok(())
    }

    struct BlockingRootCountStore {
        inner: MemoryStore,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl EventStore for BlockingRootCountStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.inner.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: pos_core::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
            assert!(
                self.entered.send(()).is_ok(),
                "root-count observer is alive"
            );
            assert!(self.release.recv().is_ok(), "root-count release is alive");
            self.inner.root_timeline_count_bounded(maximum)
        }

        fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
            self.inner.get_timeline(timeline)
        }

        fn append_intent_or_duplicate_bounded(
            &mut self,
            timeline: TimelineId,
            identity: AppendIdentity,
            intent: AppendIntent,
            max_owned_events: u64,
        ) -> Result<Option<pos_core::store::AppendOrDuplicateOutcome>, CoreError> {
            self.inner.append_intent_or_duplicate_bounded(
                timeline,
                identity,
                intent,
                max_owned_events,
            )
        }
    }

    struct BlockingCreateStore {
        inner: MemoryStore,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
        create_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl EventStore for BlockingCreateStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            if self
                .create_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                assert!(self.entered.send(()).is_ok(), "create observer is alive");
                assert!(self.release.recv().is_ok(), "create release is alive");
            }
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.inner.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: pos_core::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
            self.inner.root_timeline_count_bounded(maximum)
        }

        fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
            self.inner.get_timeline(timeline)
        }
    }

    struct OrderedStore {
        inner: MemoryStore,
        operations: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        created_names: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl EventStore for OrderedStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.operations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("create");
            self.created_names
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(name.to_owned());
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.operations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("read");
            self.inner.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: pos_core::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
            self.operations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("root_count");
            assert!(
                self.entered.send(()).is_ok(),
                "root-count observer is alive"
            );
            assert!(self.release.recv().is_ok(), "root-count release is alive");
            self.inner.root_timeline_count_bounded(maximum)
        }

        fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
            self.operations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("read");
            self.inner.get_timeline(timeline)
        }
    }

    #[tokio::test]
    async fn shutdown_closes_executor_and_readiness_after_join() {
        let result = shutdown_closes_executor_and_readiness_after_join_impl().await;
        assert!(
            result.is_ok(),
            "shutdown_closes_executor_and_readiness_after_join failed: {result:?}"
        );
    }

    async fn shutdown_closes_executor_and_readiness_after_join_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let executor = super::StoreExecutor::new(Box::new(MemoryStore::new()));

        assert!(executor.is_ready());
        executor.shutdown().await.test_ok()?;
        assert!(!executor.is_ready());
        assert!(matches!(
            executor.create("after-shutdown".to_owned()).await,
            Err(super::StoreExecutorError::Closed)
        ));
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Closed)
        ));
        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn expired_queued_command_is_not_executed() {
        let result = expired_queued_command_is_not_executed_impl().await;
        assert!(
            result.is_ok(),
            "expired_queued_command_is_not_executed failed: {result:?}"
        );
    }

    async fn expired_queued_command_is_not_executed_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let executor = super::StoreExecutor::new(Box::new(MemoryStore::new()));
        let (reply, result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "expired".to_owned(),
                    reply,
                },
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(1))
                    .test_ok()?,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;

        assert!(matches!(
            result.await.test_ok()?,
            Err(super::StoreExecutorError::DeadlineExceeded)
        ));
        assert!(executor.create("fresh".to_owned()).await.is_ok());
        executor.shutdown().await.test_ok()?;
        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn queued_command_deadline_returns_before_worker_release() {
        let result = queued_command_deadline_returns_before_worker_release_impl().await;
        assert!(
            result.is_ok(),
            "queued_command_deadline_returns_before_worker_release failed: {result:?}"
        );
    }

    async fn queued_command_deadline_returns_before_worker_release_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(1),
        );
        let blocker = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let started = std::time::Instant::now();
        let result = executor
            .read(
                TimelineId::new(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .await;
        assert!(matches!(
            result,
            Err(super::StoreExecutorError::DeadlineExceeded)
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(250));

        release_sender.send(()).test_ok()?;
        assert!(blocker.await.test_ok()?.is_ok());
        executor.shutdown().await.test_ok()?;
        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn expired_queued_write_never_commits() {
        let result = expired_queued_write_never_commits_impl().await;
        assert!(
            result.is_ok(),
            "expired_queued_write_never_commits failed: {result:?}"
        );
    }

    async fn expired_queued_write_never_commits_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let create_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingCreateStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
                create_calls: std::sync::Arc::clone(&create_calls),
            })),
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(1),
        );
        let first = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.create("first".to_owned()).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        assert!(matches!(
            executor.create("expired".to_owned()).await,
            Err(super::StoreExecutorError::DeadlineExceeded)
        ));
        release_sender.send(()).test_ok()?;
        assert!(first.await.test_ok()?.is_ok());
        executor.shutdown().await.test_ok()?;
        assert_eq!(create_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );
        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn started_write_returns_its_commit_outcome_after_deadline() {
        let result = started_write_returns_its_commit_outcome_after_deadline_impl().await;
        assert!(
            result.is_ok(),
            "started_write_returns_its_commit_outcome_after_deadline failed: {result:?}"
        );
    }

    async fn started_write_returns_its_commit_outcome_after_deadline_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let create_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingCreateStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
                create_calls: std::sync::Arc::clone(&create_calls),
            })),
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(1),
        );
        let first = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.create("started".to_owned()).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        release_sender.send(()).test_ok()?;

        assert!(first.await.test_ok()?.is_ok());
        assert_eq!(create_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    fn assert_expired<T>(
        command: Command,
        receiver: tokio::sync::oneshot::Receiver<Result<T, super::StoreExecutorError>>,
    ) {
        super::expire_command(command);
        assert!(matches!(
            receiver.blocking_recv().test_value(),
            Err(super::StoreExecutorError::DeadlineExceeded)
        ));
    }

    #[test]
    fn expired_admission_commands_reply() {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::AdmitOwnTracksIngress {
                basic_handle: [1; 32],
                basic_secret: [2; 32],
                payload: CanonicalBytes::from_static(b"payload"),
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            TimelineId::new(),
            EntityId::new(),
            CanonicalBytes::from_static(b"payload"),
            0,
            ([0; 32], 0, [0; 32]),
            (0, false, 0),
            ([0; 32], [0; 32]),
        ));
        assert_expired(Command::AdmitGeoLocation { request, reply }, receiver);
    }

    #[test]
    fn expired_store_commands_reply() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::Purge {
                limit: NonZeroUsize::new(1).test_ok()?,
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(Command::RootCount { maximum: 1, reply }, receiver);

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::Create {
                name: "expired".to_owned(),
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::Read {
                timeline: TimelineId::new(),
                range: SeqRange::all(),
                bounds: EventReadBounds::new(1, 1, 1, 1),
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::ReadOne {
                timeline: TimelineId::new(),
                event: EventId::new(),
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::Append {
                timeline: TimelineId::new(),
                drafts: Vec::new(),
                maximum: None,
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("expired"),
            CanonicalBytes::from_static(b"payload"),
        );
        assert_expired(
            Command::AppendIdentified {
                timeline: TimelineId::new(),
                identity: AppendIdentity::new(
                    AppendDedupKey::from_keyed_hash([1; 32]),
                    AppendDedupScope::from_keyed_hash([2; 32]),
                ),
                intent: AppendIntent::new(&draft),
                maximum: 1,
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::GetTimeline {
                timeline: TimelineId::new(),
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(Command::Panic { reply }, receiver);

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(Command::PanicRead { reply }, receiver);

        Ok(())
    }

    #[test]
    fn expired_consent_write_commands_reply() {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::AppendConsentGrant {
                timeline: TimelineId::new(),
                grant: ConsentGrantedV1 {
                    subject_id: EntityId::new(),
                    grantee_id: EntityId::new(),
                    purpose: "expired".to_owned(),
                    modalities: pos_core::MODALITY_LOCATION,
                    min_geo_resolution: 1,
                    fork_permitted: false,
                    export_permitted: false,
                    retention_days: 0,
                    expiry_secs: 0,
                    grant_seq: 1,
                },
                maximum: 1,
                reply,
            },
            receiver,
        );

        let (reply, receiver) = tokio::sync::oneshot::channel();
        assert_expired(
            Command::AppendConsentRevocation {
                timeline: TimelineId::new(),
                revocation: ConsentRevokedV1 {
                    subject_id: EntityId::new(),
                    grantee_id: EntityId::new(),
                    grant_seq: 1,
                    fence_seq: 1,
                },
                maximum: 1,
                reply,
            },
            receiver,
        );
    }

    #[tokio::test]
    async fn shutdown_timeout_retains_join_for_retry() {
        let result = shutdown_timeout_retains_join_for_retry_impl().await;
        assert!(
            result.is_ok(),
            "shutdown_timeout_retains_join_for_retry failed: {result:?}"
        );
    }

    async fn shutdown_timeout_retains_join_for_retry_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let store = BlockingRootCountStore {
            inner: MemoryStore::new(),
            entered: entered_sender,
            release: release_receiver,
        };
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(store)),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(20),
        );
        let count = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::DeadlineExceeded)
        ));
        release_sender.send(()).test_ok()?;
        assert!(count.await.test_ok()?.is_ok());
        executor.shutdown().await.test_ok()?;
        assert!(!executor.is_ready());

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn cancelled_shutdown_does_not_lose_worker_join_ownership() {
        let result = cancelled_shutdown_does_not_lose_worker_join_ownership_impl().await;
        assert!(
            result.is_ok(),
            "cancelled_shutdown_does_not_lose_worker_join_ownership failed: {result:?}"
        );
    }

    async fn cancelled_shutdown_does_not_lose_worker_join_ownership_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let store = BlockingRootCountStore {
            inner: MemoryStore::new(),
            entered: entered_sender,
            release: release_receiver,
        };
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(store)),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );
        let count = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let shutdown = tokio::spawn({
            let executor = executor.clone();
            async move { executor.shutdown().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        shutdown.abort();
        release_sender.send(()).test_ok()?;
        assert!(count.await.test_ok()?.is_ok());
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn shutdown_drains_accepted_channel_and_pending_commands() {
        let result = shutdown_drains_accepted_channel_and_pending_commands_impl().await;
        assert!(
            result.is_ok(),
            "shutdown_drains_accepted_channel_and_pending_commands failed: {result:?}"
        );
    }

    async fn shutdown_drains_accepted_channel_and_pending_commands_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );
        let first = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let read_result = submit_get_timeline(&executor, deadline);
        let (create_reply, create_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "drained-write".to_owned(),
                    reply: create_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;

        let shutdown = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.shutdown().await })
        };
        while executor.is_ready() {
            tokio::task::yield_now().await;
        }
        let (rejected_reply, _rejected_result) = tokio::sync::oneshot::channel();
        assert!(matches!(
            executor.try_submit(
                Command::Create {
                    name: "rejected-after-draining".to_owned(),
                    reply: rejected_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Closed)
        ));

        release_sender.send(()).test_ok()?;
        assert!(first.await.test_ok()?.is_ok());
        assert!(read_result.await.test_ok()?.is_ok());
        assert!(create_result.await.test_ok()?.is_ok());
        assert!(shutdown.await.test_ok()?.is_ok());
        assert!(!executor.is_ready());

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn in_flight_command_returns_its_commit_outcome_after_deadline() {
        let result = in_flight_command_returns_its_commit_outcome_after_deadline_impl().await;
        assert!(
            result.is_ok(),
            "in_flight_command_returns_its_commit_outcome_after_deadline failed: {result:?}"
        );
    }

    async fn in_flight_command_returns_its_commit_outcome_after_deadline_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let store = BlockingRootCountStore {
            inner: MemoryStore::new(),
            entered: entered_sender,
            release: release_receiver,
        };
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(store)),
            std::time::Duration::from_millis(20),
            std::time::Duration::from_secs(1),
        );
        let count = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        release_sender.send(()).test_ok()?;

        assert!(count.await.test_ok()?.is_ok());
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn worker_panic_is_reported_as_unhealthy() {
        let result = worker_panic_is_reported_as_unhealthy_impl().await;
        assert!(
            result.is_ok(),
            "worker_panic_is_reported_as_unhealthy failed: {result:?}"
        );
    }

    async fn worker_panic_is_reported_as_unhealthy_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let executor = super::StoreExecutor::new(Box::new(MemoryStore::new()));

        let panic_result = executor.panic_for_test().await;
        assert!(
            matches!(panic_result, Err(super::StoreExecutorError::Unhealthy)),
            "panic result: {panic_result:?}"
        );
        assert!(!executor.is_ready());
        assert!(matches!(
            executor.create("unhealthy".to_owned()).await,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );
        assert!(executor.control.join.lock().test_ok()?.is_none());

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn read_worker_panic_releases_read_admission_permit() {
        let result = read_worker_panic_releases_read_admission_permit_impl().await;
        assert!(
            result.is_ok(),
            "read_worker_panic_releases_read_admission_permit failed: {result:?}"
        );
    }

    async fn read_worker_panic_releases_read_admission_permit_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let executor = super::StoreExecutor::new(Box::new(MemoryStore::new()));

        let panic_result = executor.panic_read_for_test().await;
        assert!(matches!(
            panic_result,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn executor_reports_unhealthy_and_closed_submission_paths() {
        let result = executor_reports_unhealthy_and_closed_submission_paths_impl().await;
        assert!(
            result.is_ok(),
            "executor_reports_unhealthy_and_closed_submission_paths failed: {result:?}"
        );
    }

    #[test]
    fn worker_startup_fallbacks_mark_the_executor_unhealthy(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        super::register_worker(
            executor.control.as_ref(),
            Err(std::io::Error::other("injected worker spawn failure")),
        );
        assert!(matches!(
            executor.current_state(),
            super::LifecycleState::Unhealthy { .. }
        ));

        *executor.control.state.lock().test_ok()? = super::LifecycleState::Open;
        assert!(super::take_worker_runtime(
            executor.control.state.as_ref(),
            Err(std::io::Error::other("injected runtime failure")),
        )
        .is_none());
        assert!(matches!(
            executor.current_state(),
            super::LifecycleState::Unhealthy { .. }
        ));
        drop(executor);
        Ok(())
    }

    async fn executor_reports_unhealthy_and_closed_submission_paths_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        drop(receiver);
        assert!(matches!(
            executor.create("closed-channel".to_owned()).await,
            Err(super::StoreExecutorError::Closed)
        ));

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        drop(executor);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        *executor.control.state.lock().test_ok()? = super::LifecycleState::Unhealthy {
            retryable_shutdown: false,
        };
        assert!(matches!(
            executor.create("unhealthy".to_owned()).await,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Unhealthy)
        ));

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn executor_recovers_poisoned_control_locks() {
        let result = executor_recovers_poisoned_control_locks_impl().await;
        assert!(
            result.is_ok(),
            "executor_recovers_poisoned_control_locks failed: {result:?}"
        );
    }

    async fn executor_recovers_poisoned_control_locks_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let state = std::sync::Arc::clone(&executor.control.state);
        let _ = std::thread::spawn(move || {
            let _guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison state lock for recovery test"));
        })
        .join()
        .test_err()?;

        assert!(executor.is_ready());
        let (reply, _result) = tokio::sync::oneshot::channel();
        assert!(executor
            .try_submit(
                Command::Create {
                    name: "poisoned-state".to_owned(),
                    reply,
                },
                Instant::now(),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .is_ok());
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Closed)
        ));

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        drop(executor);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = executor
                .control
                .join_task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison join-task lock for recovery test"));
        }))
        .test_err()?;
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Closed)
        ));

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        drop(executor);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = executor
                .control
                .join
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison join lock for recovery test"));
        }))
        .test_err()?;
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Closed)
        ));

        drop(executor);

        Ok(())
    }

    #[test]
    fn submission_and_join_helpers_recover_poisoned_ordinals() {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let control = std::sync::Arc::clone(&executor.control);
        assert!(std::thread::spawn(move || {
            let _guard = control
                .next_admission_ordinal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison ordinal lock for test"));
        })
        .join()
        .is_err());
        let (reply, _result) = tokio::sync::oneshot::channel();
        assert!(executor
            .try_submit(
                Command::Create {
                    name: "poisoned-ordinal".to_owned(),
                    reply,
                },
                Instant::now(),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .is_ok());
        drop(executor);

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let control = std::sync::Arc::clone(&executor.control);
        assert!(std::thread::spawn(move || {
            let _guard = control
                .join_task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison join-task lock for helper test"));
        })
        .join()
        .is_err());
        assert!(!executor.has_join_work());

        let control = std::sync::Arc::clone(&executor.control);
        assert!(std::thread::spawn(move || {
            let _guard = control
                .join
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison join lock for helper test"));
        })
        .join()
        .is_err());
        assert!(!executor.has_join_work());
        drop(executor);
    }

    #[test]
    fn admission_ordinal_overflow_is_typed_and_releases_capacity() {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        *executor.control.next_admission_ordinal.lock().test_value() = u64::MAX;
        let (reply, _result) = tokio::sync::oneshot::channel();
        assert!(matches!(
            executor.try_submit_with_admission_for_test(
                Command::Create {
                    name: "overflow".to_owned(),
                    reply,
                },
                Instant::now(),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Store(CoreError::Storage(message)))
                if message.contains("admission ordinal overflow")
        ));
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        drop(executor);
    }

    #[test]
    fn closed_reply_maps_unhealthy_state_to_unhealthy_error() {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        {
            let mut state = executor.control.state.lock().test_value();
            *state = super::LifecycleState::Unhealthy {
                retryable_shutdown: false,
            };
        }
        assert!(matches!(
            executor.reply_closed_error(),
            super::StoreExecutorError::Unhealthy
        ));
        drop(executor);
    }

    #[tokio::test]
    async fn executor_reaps_successful_and_panicked_join_handles() {
        let result = executor_reaps_successful_and_panicked_join_handles_impl().await;
        assert!(
            result.is_ok(),
            "executor_reaps_successful_and_panicked_join_handles failed: {result:?}"
        );
    }

    async fn executor_reaps_successful_and_panicked_join_handles_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        *executor.control.state.lock().test_ok()? = super::LifecycleState::Unhealthy {
            retryable_shutdown: false,
        };
        *executor.control.join.lock().test_ok()? = Some(std::thread::spawn(|| {}));
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Unhealthy)
        ));

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        drop(executor);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        *executor.control.state.lock().test_ok()? = super::LifecycleState::Unhealthy {
            retryable_shutdown: false,
        };
        *executor.control.join.lock().test_ok()? = Some(std::thread::spawn(|| {
            std::panic::resume_unwind(Box::new("panic join for recovery test"));
        }));
        assert!(matches!(
            executor.shutdown().await,
            Err(super::StoreExecutorError::Unhealthy)
        ));

        drop(executor);

        Ok(())
    }

    #[test]
    fn worker_and_state_helpers_recover_poisoned_mutexes(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = std::sync::Arc::new(std::sync::Mutex::new(super::LifecycleState::Open));
        let poisoned = std::sync::Arc::clone(&state);
        std::thread::spawn(move || {
            let _guard = poisoned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison lifecycle lock for helper test"));
        })
        .join()
        .test_err()?;
        super::set_lifecycle_state(state.as_ref(), super::LifecycleState::Closed);
        assert_eq!(
            *state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            super::LifecycleState::Closed
        );

        let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(super::LifecycleState::Open));
        let poisoned = std::sync::Arc::clone(&lifecycle);
        std::thread::spawn(move || {
            let _guard = poisoned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison worker lifecycle lock for helper test"));
        })
        .join()
        .test_err()?;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        drop(sender);
        super::worker_loop(
            &lifecycle,
            std::sync::Arc::new(tokio::sync::Notify::new()),
            &mut receiver,
            super::ExecutorStore::Generic(Box::new(MemoryStore::new())),
            None,
            None,
        );
        assert_eq!(
            *lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            super::LifecycleState::Closed
        );

        Ok(())
    }

    #[tokio::test]
    async fn disconnected_receiver_drains_pending_commands_through_scheduler() {
        let result = disconnected_receiver_drains_pending_commands_through_scheduler_impl().await;
        assert!(
            result.is_ok(),
            "disconnected_receiver_drains_pending_commands_through_scheduler failed: {result:?}"
        );
    }

    async fn disconnected_receiver_drains_pending_commands_through_scheduler_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let (observer, records) = super::SchedulerObserver::new(8);
        let (gate_sender, gate_receiver) = std::sync::mpsc::channel();
        observer.install_gate(gate_receiver);
        let (read_reply, read_result) = tokio::sync::oneshot::channel();
        let (write_reply, write_result) = tokio::sync::oneshot::channel();
        let read_permit = std::sync::Arc::new(super::Semaphore::new(1))
            .try_acquire_owned()
            .test_ok()?;
        let read_global = std::sync::Arc::new(super::Semaphore::new(1))
            .try_acquire_owned()
            .test_ok()?;
        let write_global = std::sync::Arc::new(super::Semaphore::new(1))
            .try_acquire_owned()
            .test_ok()?;
        let read_lifecycle = std::sync::Arc::new(super::CommandLifecycle::new());
        let write_lifecycle = std::sync::Arc::new(super::CommandLifecycle::new());
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: read_lifecycle,
                class: super::CommandClass::Read,
                admission_ordinal: 0,
                global_permit: read_global,
                read_permit: Some(read_permit),
                command: Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply: read_reply,
                },
            })
            .await
            .test_ok()?;
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: write_lifecycle,
                class: super::CommandClass::Write,
                admission_ordinal: 1,
                global_permit: write_global,
                read_permit: None,
                command: Command::Create {
                    name: "disconnected-write".to_owned(),
                    reply: write_reply,
                },
            })
            .await
            .test_ok()?;
        drop(sender);

        let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(super::LifecycleState::Open));
        let worker_lifecycle = std::sync::Arc::clone(&lifecycle);
        let worker = tokio::task::spawn_blocking(move || {
            super::worker_loop(
                &worker_lifecycle,
                std::sync::Arc::new(tokio::sync::Notify::new()),
                &mut receiver,
                super::ExecutorStore::Generic(Box::new(MemoryStore::new())),
                None,
                Some(observer),
            );
        });

        assert!(matches!(
            records.recv().test_ok()?,
            super::SchedulerTrace::DrainCompleted {
                pending: 2,
                disconnected: true,
            }
        ));
        gate_sender.send(()).test_ok()?;
        assert!(read_result.await.test_ok()?.is_ok());
        assert!(write_result.await.test_ok()?.is_ok());
        worker.await.test_ok()?;
        assert_eq!(*lifecycle.lock().test_ok()?, super::LifecycleState::Closed);
        let selected = records
            .try_iter()
            .filter_map(|record| match record {
                super::SchedulerTrace::Selected { ordinal, .. } => Some(ordinal),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![0, 1]);

        Ok(())
    }

    #[tokio::test]
    async fn expired_pending_read_releases_admission_permits_after_worker_sweep() {
        let result =
            expired_pending_read_releases_admission_permits_after_worker_sweep_impl().await;
        assert!(
            result.is_ok(),
            "expired_pending_read_releases_admission_permits_after_worker_sweep failed: {result:?}"
        );
    }

    async fn expired_pending_read_releases_admission_permits_after_worker_sweep_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );
        let blocker = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let (reply, result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply,
                },
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(1))
                    .test_ok()?,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY - 2
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY - 2
        );

        release_sender.send(()).test_ok()?;
        assert!(blocker.await.test_ok()?.is_ok());
        assert!(matches!(
            result.await.test_ok()?,
            Err(super::StoreExecutorError::DeadlineExceeded)
        ));
        executor.shutdown().await.test_ok()?;
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn worker_unwind_releases_executing_and_pending_read_write_permits() {
        let result = worker_unwind_releases_executing_and_pending_read_write_permits_impl().await;
        assert!(
            result.is_ok(),
            "worker_unwind_releases_executing_and_pending_read_write_permits failed: {result:?}"
        );
    }

    async fn worker_unwind_releases_executing_and_pending_read_write_permits_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(3);
        let global_budget = std::sync::Arc::new(super::Semaphore::new(3));
        let read_budget = std::sync::Arc::new(super::Semaphore::new(2));
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let (panic_reply, panic_result) = tokio::sync::oneshot::channel();
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: std::sync::Arc::new(super::CommandLifecycle::new()),
                class: super::CommandClass::Read,
                admission_ordinal: 0,
                global_permit: global_budget.clone().try_acquire_owned().test_ok()?,
                read_permit: Some(read_budget.clone().try_acquire_owned().test_ok()?),
                command: Command::PanicRead { reply: panic_reply },
            })
            .await
            .test_ok()?;
        let (pending_read_reply, _pending_read_result) = tokio::sync::oneshot::channel();
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: std::sync::Arc::new(super::CommandLifecycle::new()),
                class: super::CommandClass::Read,
                admission_ordinal: 1,
                global_permit: global_budget.clone().try_acquire_owned().test_ok()?,
                read_permit: Some(read_budget.clone().try_acquire_owned().test_ok()?),
                command: Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply: pending_read_reply,
                },
            })
            .await
            .test_ok()?;
        let (pending_write_reply, _pending_write_result) = tokio::sync::oneshot::channel();
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: std::sync::Arc::new(super::CommandLifecycle::new()),
                class: super::CommandClass::Write,
                admission_ordinal: 2,
                global_permit: global_budget.clone().try_acquire_owned().test_ok()?,
                read_permit: None,
                command: Command::Create {
                    name: "pending-unwind".to_owned(),
                    reply: pending_write_reply,
                },
            })
            .await
            .test_ok()?;
        drop(sender);

        let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(super::LifecycleState::Open));
        let worker_lifecycle = std::sync::Arc::clone(&lifecycle);
        let worker = tokio::task::spawn_blocking(move || {
            super::worker_loop(
                &worker_lifecycle,
                std::sync::Arc::new(tokio::sync::Notify::new()),
                &mut receiver,
                super::ExecutorStore::Generic(Box::new(MemoryStore::new())),
                None,
                None,
            );
        });

        worker.await.test_ok()?;
        assert!(matches!(
            panic_result.await.test_ok()?,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert!(matches!(
            *lifecycle.lock().test_ok()?,
            super::LifecycleState::Unhealthy { .. }
        ));
        assert_eq!(global_budget.available_permits(), 3);
        assert_eq!(read_budget.available_permits(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn worker_unwind_releases_envelope_arriving_in_channel() {
        let result = worker_unwind_releases_envelope_arriving_in_channel_impl().await;
        assert!(
            result.is_ok(),
            "worker_unwind_releases_envelope_arriving_in_channel failed: {result:?}"
        );
    }

    async fn worker_unwind_releases_envelope_arriving_in_channel_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let global_budget = std::sync::Arc::new(super::Semaphore::new(2));
        let read_budget = std::sync::Arc::new(super::Semaphore::new(1));
        let (observer, records) = super::SchedulerObserver::new(8);
        let (gate_sender, gate_receiver) = std::sync::mpsc::channel();
        observer.install_gate(gate_receiver);
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let (panic_reply, panic_result) = tokio::sync::oneshot::channel();
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: std::sync::Arc::new(super::CommandLifecycle::new()),
                class: super::CommandClass::Read,
                admission_ordinal: 0,
                global_permit: global_budget.clone().try_acquire_owned().test_ok()?,
                read_permit: Some(read_budget.clone().try_acquire_owned().test_ok()?),
                command: Command::PanicRead { reply: panic_reply },
            })
            .await
            .test_ok()?;
        let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(super::LifecycleState::Open));
        let worker_lifecycle = std::sync::Arc::clone(&lifecycle);
        let worker = tokio::task::spawn_blocking(move || {
            super::worker_loop(
                &worker_lifecycle,
                std::sync::Arc::new(tokio::sync::Notify::new()),
                &mut receiver,
                super::ExecutorStore::Generic(Box::new(MemoryStore::new())),
                None,
                Some(observer),
            );
        });
        assert!(matches!(
            records.recv().test_ok()?,
            super::SchedulerTrace::DrainCompleted {
                pending: 1,
                disconnected: false,
            }
        ));

        let (channel_reply, _channel_result) = tokio::sync::oneshot::channel();
        sender
            .send(super::CommandEnvelope {
                deadline,
                lifecycle: std::sync::Arc::new(super::CommandLifecycle::new()),
                class: super::CommandClass::Write,
                admission_ordinal: 1,
                global_permit: global_budget.clone().try_acquire_owned().test_ok()?,
                read_permit: None,
                command: Command::Create {
                    name: "channel-unwind".to_owned(),
                    reply: channel_reply,
                },
            })
            .await
            .test_ok()?;
        drop(sender);
        gate_sender.send(()).test_ok()?;
        worker.await.test_ok()?;
        assert!(matches!(
            panic_result.await.test_ok()?,
            Err(super::StoreExecutorError::Unhealthy)
        ));
        assert!(matches!(
            *lifecycle.lock().test_ok()?,
            super::LifecycleState::Unhealthy { .. }
        ));
        assert_eq!(global_budget.available_permits(), 2);
        assert_eq!(read_budget.available_permits(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn read_admission_preserves_reserved_write_capacity_with_live_worker() {
        let result = read_admission_preserves_reserved_write_capacity_with_live_worker_impl().await;
        assert!(
            result.is_ok(),
            "read_admission_preserves_reserved_write_capacity_with_live_worker failed: {result:?}"
        );
    }

    async fn read_admission_preserves_reserved_write_capacity_with_live_worker_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let store = BlockingRootCountStore {
            inner: MemoryStore::new(),
            entered: entered_sender,
            release: release_receiver,
        };
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(store)),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );
        let count = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);

        for _ in 0..(super::READ_CAPACITY - 1) {
            let (reply, _result) = tokio::sync::oneshot::channel();
            executor
                .try_submit(
                    Command::GetTimeline {
                        timeline: pos_core::TimelineId::new(),
                        reply,
                    },
                    deadline,
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_ok()?;
        }

        let (reply, _result) = tokio::sync::oneshot::channel();
        assert!(matches!(
            executor.try_submit(
                Command::GetTimeline {
                    timeline: pos_core::TimelineId::new(),
                    reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Saturated)
        ));

        let (reply, result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "reserved-write".to_owned(),
                    reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;

        release_sender.send(()).test_ok()?;
        assert!(count.await.test_ok()?.is_ok());
        assert!(result.await.test_ok()?.is_ok());
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    fn submit_get_timeline(
        executor: &super::StoreExecutor,
        deadline: Instant,
    ) -> tokio::sync::oneshot::Receiver<Result<Option<Timeline>, super::StoreExecutorError>> {
        let (reply, result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_value();
        result
    }

    fn release_scheduler_gate(
        records: &std::sync::mpsc::Receiver<super::SchedulerTrace>,
        gate_sender: &std::sync::mpsc::Sender<()>,
    ) -> Vec<u64> {
        release_scheduler_gate_at_pending(records, gate_sender, 9)
    }

    fn release_scheduler_gate_at_pending(
        records: &std::sync::mpsc::Receiver<super::SchedulerTrace>,
        gate_sender: &std::sync::mpsc::Sender<()>,
        expected_pending: usize,
    ) -> Vec<u64> {
        let mut selected = Vec::new();
        loop {
            match records.recv().test_value() {
                super::SchedulerTrace::DrainCompleted {
                    pending,
                    disconnected: _,
                } if pending == expected_pending => {
                    gate_sender.send(()).test_value();
                    return selected;
                }
                super::SchedulerTrace::Selected { ordinal, .. } => selected.push(ordinal),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. } => {}
            }
        }
    }

    fn collect_selected(records: &std::sync::mpsc::Receiver<super::SchedulerTrace>) -> Vec<u64> {
        records
            .try_iter()
            .filter_map(|record| match record {
                super::SchedulerTrace::Selected { ordinal, .. } => Some(ordinal),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. } => None,
            })
            .collect()
    }

    fn wait_for_selected(
        records: &std::sync::mpsc::Receiver<super::SchedulerTrace>,
        expected_ordinal: u64,
    ) {
        loop {
            match records.recv().test_value() {
                super::SchedulerTrace::Selected { ordinal, .. } if ordinal == expected_ordinal => {
                    return
                }
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. }
                | super::SchedulerTrace::Selected { .. } => {}
            }
        }
    }

    #[tokio::test]
    async fn reads_without_pending_writes_retain_fifo_after_the_burst() {
        let result = reads_without_pending_writes_retain_fifo_after_the_burst_impl().await;
        assert!(
            result.is_ok(),
            "reads_without_pending_writes_retain_fifo_after_the_burst failed: {result:?}"
        );
    }

    async fn reads_without_pending_writes_retain_fifo_after_the_burst_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (observer, records) = super::SchedulerObserver::new(64);
        let executor = super::StoreExecutor::spawn_with_observer_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            observer,
        );
        let (root_reply, root_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::RootCount {
                    maximum: 1,
                    reply: root_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let reads = (0..10)
            .map(|_| submit_get_timeline(&executor, deadline))
            .collect::<Vec<_>>();
        release_sender.send(()).test_ok()?;
        assert!(root_result.await.test_ok()?.is_ok());
        for result in reads {
            assert!(result.await.test_ok()?.is_ok());
        }
        let selected = records
            .try_iter()
            .filter_map(|record| match record {
                super::SchedulerTrace::Selected { ordinal, .. } => Some(ordinal),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(selected, (0..=10).collect::<Vec<_>>());
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn queued_write_is_selected_immediately_without_pending_reads() {
        let result = queued_write_is_selected_immediately_without_pending_reads_impl().await;
        assert!(
            result.is_ok(),
            "queued_write_is_selected_immediately_without_pending_reads failed: {result:?}"
        );
    }

    async fn queued_write_is_selected_immediately_without_pending_reads_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (observer, records) = super::SchedulerObserver::new(16);
        let executor = super::StoreExecutor::spawn_with_observer_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            observer,
        );
        let (root_reply, root_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::RootCount {
                    maximum: 1,
                    reply: root_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let (write_reply, write_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "immediate-write".to_owned(),
                    reply: write_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        release_sender.send(()).test_ok()?;
        assert!(root_result.await.test_ok()?.is_ok());
        assert!(write_result.await.test_ok()?.is_ok());
        let selected = records
            .try_iter()
            .filter_map(|record| match record {
                super::SchedulerTrace::Selected {
                    ordinal,
                    class,
                    reads_since_write,
                } => Some((ordinal, class, reads_since_write)),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                (0, super::CommandClass::Read, 0),
                (1, super::CommandClass::Write, 1)
            ]
        );
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn expired_burst_entries_do_not_change_fairness_priority() {
        let result = expired_burst_entries_do_not_change_fairness_priority_impl().await;
        assert!(
            result.is_ok(),
            "expired_burst_entries_do_not_change_fairness_priority failed: {result:?}"
        );
    }

    async fn expired_burst_entries_do_not_change_fairness_priority_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (observer, records) = super::SchedulerObserver::new(64);
        let executor = super::StoreExecutor::spawn_with_observer_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            std::sync::Arc::clone(&observer),
        );
        let (root_reply, root_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::RootCount {
                    maximum: 1,
                    reply: root_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let live_reads = (0..6)
            .map(|_| submit_get_timeline(&executor, deadline))
            .collect::<Vec<_>>();
        let expired_read = {
            let (reply, result) = tokio::sync::oneshot::channel();
            executor
                .try_submit(
                    Command::GetTimeline {
                        timeline: TimelineId::new(),
                        reply,
                    },
                    Instant::now()
                        .checked_sub(std::time::Duration::from_secs(1))
                        .test_ok()?,
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_ok()?;
            result
        };
        let live_read = submit_get_timeline(&executor, deadline);
        let expired_write = {
            let (reply, result) = tokio::sync::oneshot::channel();
            executor
                .try_submit(
                    Command::Create {
                        name: "expired-priority".to_owned(),
                        reply,
                    },
                    Instant::now()
                        .checked_sub(std::time::Duration::from_secs(1))
                        .test_ok()?,
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_ok()?;
            result
        };
        let (write_reply, write_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "live-priority".to_owned(),
                    reply: write_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        let trailing_read = submit_get_timeline(&executor, deadline);
        let (gate_sender, gate_receiver) = std::sync::mpsc::channel();
        observer.install_gate(gate_receiver);
        release_sender.send(()).test_ok()?;
        let mut selected = release_scheduler_gate_at_pending(&records, &gate_sender, 11);
        assert!(root_result.await.test_ok()?.is_ok());
        for result in live_reads {
            assert!(result.await.test_ok()?.is_ok());
        }
        assert!(expired_read.await.test_ok()?.is_err());
        assert!(live_read.await.test_ok()?.is_ok());
        assert!(expired_write.await.test_ok()?.is_err());
        assert!(write_result.await.test_ok()?.is_ok());
        assert!(trailing_read.await.test_ok()?.is_ok());
        selected.extend(collect_selected(&records));
        assert_eq!(selected, vec![0, 1, 2, 3, 4, 5, 6, 8, 10, 11]);
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn pending_write_is_selected_after_eight_consecutive_reads() {
        let result = pending_write_is_selected_after_eight_consecutive_reads_impl().await;
        assert!(
            result.is_ok(),
            "pending_write_is_selected_after_eight_consecutive_reads failed: {result:?}"
        );
    }

    async fn pending_write_is_selected_after_eight_consecutive_reads_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let created_names = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (observer, records) = super::SchedulerObserver::new(64);
        let executor = super::StoreExecutor::spawn_with_observer_for_test(
            super::ExecutorStore::Generic(Box::new(OrderedStore {
                inner: MemoryStore::new(),
                operations: std::sync::Arc::clone(&operations),
                created_names,
                entered: entered_sender,
                release: release_receiver,
            })),
            std::sync::Arc::clone(&observer),
        );

        let (root_reply, root_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::RootCount {
                    maximum: 1,
                    reply: root_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let read_results = (0..8)
            .map(|_| submit_get_timeline(&executor, deadline))
            .collect::<Vec<_>>();

        let (create_reply, create_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "fair-write".to_owned(),
                    reply: create_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;

        let (gate_sender, gate_receiver) = std::sync::mpsc::channel();
        observer.install_gate(gate_receiver);
        release_sender.send(()).test_ok()?;
        let mut selected = release_scheduler_gate(&records, &gate_sender);
        assert!(root_result.await.test_ok()?.is_ok());
        assert!(create_result.await.test_ok()?.is_ok());
        for result in read_results {
            assert!(result.await.test_ok()?.is_ok());
        }

        let operations = operations.lock().test_ok()?.clone();
        assert_eq!(
            &operations[..10],
            &[
                "root_count",
                "read",
                "read",
                "read",
                "read",
                "read",
                "read",
                "read",
                "create",
                "read",
            ]
        );
        selected.extend(collect_selected(&records));
        assert_eq!(&selected[..10], &[0, 1, 2, 3, 4, 5, 6, 7, 9, 8]);
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn write_admitted_after_eighth_read_probe_is_selected_at_next_boundary() {
        let result =
            write_admitted_after_eighth_read_probe_is_selected_at_next_boundary_impl().await;
        assert!(result.is_ok(), "write_admitted_after_eighth_read_probe_is_selected_at_next_boundary failed: {result:?}");
    }

    async fn write_admitted_after_eighth_read_probe_is_selected_at_next_boundary_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let created_names = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (observer, records) = super::SchedulerObserver::new(64);
        let executor = super::StoreExecutor::spawn_with_observer_for_test(
            super::ExecutorStore::Generic(Box::new(OrderedStore {
                inner: MemoryStore::new(),
                operations: std::sync::Arc::clone(&operations),
                created_names,
                entered: entered_sender,
                release: release_receiver,
            })),
            std::sync::Arc::clone(&observer),
        );

        let (root_reply, root_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::RootCount {
                    maximum: 1,
                    reply: root_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let read_results = (0..8)
            .map(|_| submit_get_timeline(&executor, deadline))
            .collect::<Vec<_>>();
        let (first_gate_sender, first_gate_receiver) = std::sync::mpsc::channel();
        observer.install_gate(first_gate_receiver);
        release_sender.send(()).test_ok()?;
        drop(release_scheduler_gate_at_pending(
            &records,
            &first_gate_sender,
            8,
        ));
        assert!(root_result.await.test_ok()?.is_ok());
        for result in read_results {
            assert!(result.await.test_ok()?.is_ok());
        }
        wait_for_selected(&records, 8);

        let (second_gate_sender, second_gate_receiver) = std::sync::mpsc::channel();
        observer.install_gate(second_gate_receiver);
        let (write_reply, write_result) = tokio::sync::oneshot::channel();
        let write_ordinal = executor
            .try_submit_with_admission_for_test(
                Command::Create {
                    name: "post-probe-write".to_owned(),
                    reply: write_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        let selected_before_write =
            release_scheduler_gate_at_pending(&records, &second_gate_sender, 1);
        assert!(write_result.await.test_ok()?.is_ok());

        let write_burst_counters = records
            .try_iter()
            .filter_map(|record| match record {
                super::SchedulerTrace::Selected {
                    ordinal,
                    class: super::CommandClass::Write,
                    reads_since_write,
                } if ordinal == write_ordinal => Some(reads_since_write),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. }
                | super::SchedulerTrace::Selected { .. } => None,
            })
            .collect::<Vec<_>>();
        assert!(!selected_before_write.contains(&write_ordinal));
        assert_eq!(write_burst_counters, vec![8]);
        assert_eq!(
            &operations.lock().test_ok()?[..10],
            &[
                "root_count",
                "read",
                "read",
                "read",
                "read",
                "read",
                "read",
                "read",
                "read",
                "create",
            ]
        );
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn interleaved_writes_retain_successful_admission_order() {
        let result = interleaved_writes_retain_successful_admission_order_impl().await;
        assert!(
            result.is_ok(),
            "interleaved_writes_retain_successful_admission_order failed: {result:?}"
        );
    }

    async fn interleaved_writes_retain_successful_admission_order_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let created_names = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let executor = super::StoreExecutor::spawn_with_deadlines_for_test(
            super::ExecutorStore::Generic(Box::new(OrderedStore {
                inner: MemoryStore::new(),
                operations,
                created_names: std::sync::Arc::clone(&created_names),
                entered: entered_sender,
                release: release_receiver,
            })),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );

        let (root_reply, root_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::RootCount {
                    maximum: 1,
                    reply: root_reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;

        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        let (first_reply, first_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "write-1".to_owned(),
                    reply: first_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        let read_result = submit_get_timeline(&executor, deadline);
        let (second_reply, second_result) = tokio::sync::oneshot::channel();
        executor
            .try_submit(
                Command::Create {
                    name: "write-2".to_owned(),
                    reply: second_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;

        release_sender.send(()).test_ok()?;
        assert!(root_result.await.test_ok()?.is_ok());
        assert!(first_result.await.test_ok()?.is_ok());
        assert!(read_result.await.test_ok()?.is_ok());
        assert!(second_result.await.test_ok()?.is_ok());
        assert_eq!(
            *created_names.lock().test_ok()?,
            vec!["write-1".to_owned(), "write-2".to_owned()]
        );
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    fn spawn_append_producer(
        executor: std::sync::Arc<super::StoreExecutor>,
        barrier: std::sync::Arc<std::sync::Barrier>,
        timeline: TimelineId,
    ) -> std::thread::JoinHandle<(u64, u64)> {
        std::thread::spawn(move || {
            barrier.wait();
            let (reply, result) = tokio::sync::oneshot::channel();
            let draft = EventDraft::new(
                EntityId::new(),
                Kind::new("concurrent.append"),
                CanonicalBytes::from_static(b"append"),
            );
            let ordinal = executor
                .try_submit_with_admission_for_test(
                    Command::Append {
                        timeline,
                        drafts: vec![draft],
                        maximum: None,
                        reply,
                    },
                    Instant::now() + std::time::Duration::from_secs(1),
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_value();
            let events = result.blocking_recv().test_value().test_value();
            (ordinal, events.into_iter().next().test_value().seq.as_u64())
        })
    }

    fn spawn_identified_producer(
        executor: std::sync::Arc<super::StoreExecutor>,
        barrier: std::sync::Arc<std::sync::Barrier>,
        timeline: TimelineId,
    ) -> std::thread::JoinHandle<(u64, u64)> {
        std::thread::spawn(move || {
            barrier.wait();
            let (reply, result) = tokio::sync::oneshot::channel();
            let draft = EventDraft::new(
                EntityId::new(),
                Kind::new("concurrent.identified"),
                CanonicalBytes::from_static(b"identified"),
            );
            let ordinal = executor
                .try_submit_with_admission_for_test(
                    Command::AppendIdentified {
                        timeline,
                        identity: AppendIdentity::new(
                            AppendDedupKey::from_keyed_hash([7; 32]),
                            AppendDedupScope::from_keyed_hash([8; 32]),
                        ),
                        intent: AppendIntent::new(&draft),
                        maximum: 100,
                        reply,
                    },
                    Instant::now() + std::time::Duration::from_secs(1),
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_value();
            let outcome = result
                .blocking_recv()
                .test_value()
                .test_value()
                .test_value();
            let pos_core::store::AppendOrDuplicateOutcome::Appended(event) = outcome else {
                std::panic::resume_unwind(Box::new("identified producer must append a new event"));
            };
            (ordinal, event.seq.as_u64())
        })
    }

    #[tokio::test]
    async fn coordinated_same_timeline_appends_follow_admission_order() {
        let result = coordinated_same_timeline_appends_follow_admission_order_impl().await;
        assert!(
            result.is_ok(),
            "coordinated_same_timeline_appends_follow_admission_order failed: {result:?}"
        );
    }

    async fn coordinated_same_timeline_appends_follow_admission_order_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (observer, records) = super::SchedulerObserver::new(64);
        let executor = std::sync::Arc::new(super::StoreExecutor::spawn_with_observer_for_test(
            super::ExecutorStore::Generic(Box::new(BlockingRootCountStore {
                inner: MemoryStore::new(),
                entered: entered_sender,
                release: release_receiver,
            })),
            observer,
        ));
        let timeline = executor
            .create("concurrent-appends".to_owned())
            .await
            .test_ok()?;
        let timeline_id = timeline.id();
        let blocker = {
            let executor = executor.clone();
            tokio::spawn(async move { executor.root_count(1).await })
        };
        tokio::task::spawn_blocking(move || {
            assert!(entered_receiver.recv().is_ok());
        })
        .await
        .test_ok()?;
        drop(records.try_iter().collect::<Vec<_>>());

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let append_thread = spawn_append_producer(
            std::sync::Arc::clone(&executor),
            std::sync::Arc::clone(&barrier),
            timeline_id,
        );
        let identified_thread = spawn_identified_producer(
            std::sync::Arc::clone(&executor),
            std::sync::Arc::clone(&barrier),
            timeline_id,
        );

        barrier.wait();
        release_sender.send(()).test_ok()?;
        assert!(blocker.await.test_ok()?.is_ok());
        let mut admitted = [
            append_thread.join().test_ok()?,
            identified_thread.join().test_ok()?,
        ];
        admitted.sort_unstable();
        assert_eq!(
            admitted.iter().map(|(_, seq)| *seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let selected = records
            .try_iter()
            .filter_map(|record| match record {
                super::SchedulerTrace::Selected {
                    ordinal,
                    class: super::CommandClass::Write,
                    ..
                } => Some(ordinal),
                super::SchedulerTrace::Admitted { .. }
                | super::SchedulerTrace::DrainCompleted { .. }
                | super::SchedulerTrace::Selected { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            admitted
                .iter()
                .map(|(ordinal, _)| *ordinal)
                .collect::<Vec<_>>()
        );
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn failed_send_releases_admission_permits() {
        let result = failed_send_releases_admission_permits_impl().await;
        assert!(
            result.is_ok(),
            "failed_send_releases_admission_permits failed: {result:?}"
        );
    }

    async fn failed_send_releases_admission_permits_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let deadline = Instant::now() + std::time::Duration::from_secs(1);

        let (first_reply, _first_result) = tokio::sync::oneshot::channel();
        let first_ordinal = executor
            .try_submit_with_admission_for_test(
                Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply: first_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        assert_eq!(first_ordinal, 0);
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY - 1
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY - 1
        );

        let (second_reply, _second_result) = tokio::sync::oneshot::channel();
        assert!(matches!(
            executor.try_submit(
                Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply: second_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Saturated)
        ));
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY - 1
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY - 1
        );

        drop(receiver.recv().await.test_ok()?);
        let (third_reply, _third_result) = tokio::sync::oneshot::channel();
        let third_ordinal = executor
            .try_submit_with_admission_for_test(
                Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply: third_reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        assert_eq!(third_ordinal, 1);
        drop(receiver.recv().await.test_ok()?);
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn failed_read_acquisition_releases_global_permit() {
        let result = failed_read_acquisition_releases_global_permit_impl();
        assert!(
            result.is_ok(),
            "failed_read_acquisition_releases_global_permit failed: {result:?}"
        );
    }

    fn failed_read_acquisition_releases_global_permit_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(super::QUEUE_CAPACITY);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let deadline = Instant::now() + std::time::Duration::from_secs(1);

        for _ in 0..super::READ_CAPACITY {
            let (reply, _result) = tokio::sync::oneshot::channel();
            executor
                .try_submit(
                    Command::GetTimeline {
                        timeline: TimelineId::new(),
                        reply,
                    },
                    deadline,
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_ok()?;
        }
        assert_eq!(executor.control.global_budget.available_permits(), 8);
        assert_eq!(executor.control.read_budget.available_permits(), 0);

        let (reply, _result) = tokio::sync::oneshot::channel();
        assert!(matches!(
            executor.try_submit(
                Command::GetTimeline {
                    timeline: TimelineId::new(),
                    reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Saturated)
        ));
        assert_eq!(executor.control.global_budget.available_permits(), 8);
        assert_eq!(executor.control.read_budget.available_permits(), 0);

        while let Ok(envelope) = receiver.try_recv() {
            drop(envelope);
        }
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn global_admission_exhaustion_releases_without_consuming_ordinal() {
        let result = global_admission_exhaustion_releases_without_consuming_ordinal_impl().await;
        assert!(
            result.is_ok(),
            "global_admission_exhaustion_releases_without_consuming_ordinal failed: {result:?}"
        );
    }

    async fn global_admission_exhaustion_releases_without_consuming_ordinal_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(super::QUEUE_CAPACITY);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let deadline = Instant::now() + std::time::Duration::from_secs(1);
        for expected in 0..super::QUEUE_CAPACITY {
            let (reply, _result) = tokio::sync::oneshot::channel();
            let ordinal = executor
                .try_submit_with_admission_for_test(
                    Command::Create {
                        name: format!("global-{expected}"),
                        reply,
                    },
                    deadline,
                    std::sync::Arc::new(super::CommandLifecycle::new()),
                )
                .test_ok()?;
            assert_eq!(ordinal, u64::try_from(expected).test_ok()?);
        }
        let (reply, _result) = tokio::sync::oneshot::channel();
        assert!(matches!(
            executor.try_submit_with_admission_for_test(
                Command::Create {
                    name: "global-saturated".to_owned(),
                    reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Saturated)
        ));
        assert_eq!(executor.control.global_budget.available_permits(), 0);
        while let Ok(envelope) = receiver.try_recv() {
            drop(envelope);
        }
        let (reply, _result) = tokio::sync::oneshot::channel();
        let ordinal = executor
            .try_submit_with_admission_for_test(
                Command::Create {
                    name: "after-global-saturation".to_owned(),
                    reply,
                },
                deadline,
                std::sync::Arc::new(super::CommandLifecycle::new()),
            )
            .test_ok()?;
        assert_eq!(ordinal, super::QUEUE_CAPACITY as u64);
        drop(receiver.recv().await.test_ok()?);
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn closed_send_releases_admission_permits() {
        let result = closed_send_releases_admission_permits_impl();
        assert!(
            result.is_ok(),
            "closed_send_releases_admission_permits failed: {result:?}"
        );
    }

    fn closed_send_releases_admission_permits_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        let executor = super::StoreExecutor::from_sender_for_test(sender);
        let (reply, _result) = tokio::sync::oneshot::channel();

        assert!(matches!(
            executor.try_submit_with_admission_for_test(
                Command::Create {
                    name: "closed".to_owned(),
                    reply,
                },
                Instant::now() + std::time::Duration::from_secs(1),
                std::sync::Arc::new(super::CommandLifecycle::new()),
            ),
            Err(super::StoreExecutorError::Closed)
        ));
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );
        assert_eq!(
            *executor.control.next_admission_ordinal.lock().test_ok()?,
            0
        );

        drop(executor);

        Ok(())
    }

    #[tokio::test]
    async fn normal_completion_releases_admission_permits() {
        let result = normal_completion_releases_admission_permits_impl().await;
        assert!(
            result.is_ok(),
            "normal_completion_releases_admission_permits failed: {result:?}"
        );
    }

    async fn normal_completion_releases_admission_permits_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let executor = super::StoreExecutor::new(Box::new(MemoryStore::new()));
        assert!(executor.create("completed".to_owned()).await.is_ok());
        assert!(executor.timeline(TimelineId::new()).await.is_ok());
        tokio::time::timeout(Duration::from_secs(1), async {
            while executor.control.global_budget.available_permits() != super::QUEUE_CAPACITY
                || executor.control.read_budget.available_permits() != super::READ_CAPACITY
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .test_ok()?;
        assert_eq!(
            executor.control.global_budget.available_permits(),
            super::QUEUE_CAPACITY
        );
        assert_eq!(
            executor.control.read_budget.available_permits(),
            super::READ_CAPACITY
        );
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[test]
    fn owntracks_ingress_fails_closed_for_a_generic_store(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut state = ExecutorState {
            store: ExecutorStore::Generic(Box::new(MemoryStore::new())),
            owntracks_owner_key: None,
            owntracks_rate_limiter: OwnTracksRateLimiter {
                buckets: HashMap::new(),
            },
        };
        let error = execute_owntracks_ingress(
            &mut state,
            [1; 32],
            [2; 32],
            CanonicalBytes::from_static(b"payload"),
        )
        .test_err()?;
        assert!(matches!(error, CoreError::GeographicAdmissionUnavailable));

        Ok(())
    }

    #[test]
    fn owntracks_ingress_requires_an_owner_key(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut state = ExecutorState {
            store: ExecutorStore::OwnTracks(Box::new(MemoryStore::new())),
            owntracks_owner_key: None,
            owntracks_rate_limiter: OwnTracksRateLimiter {
                buckets: HashMap::new(),
            },
        };
        let error = execute_owntracks_ingress(
            &mut state,
            [1; 32],
            [2; 32],
            CanonicalBytes::from_static(b"payload"),
        )
        .test_err()?;
        assert!(matches!(error, CoreError::GeographicAdmissionUnavailable));

        Ok(())
    }

    #[tokio::test]
    async fn owntracks_executor_dispatches_geo_admission_commands() {
        let result = owntracks_executor_dispatches_geo_admission_commands_impl().await;
        assert!(
            result.is_ok(),
            "owntracks_executor_dispatches_geo_admission_commands failed: {result:?}"
        );
    }

    async fn owntracks_executor_dispatches_geo_admission_commands_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let executor =
            super::StoreExecutor::new_with_owntracks_ingress(MemoryStore::new(), [0; 32]);
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            TimelineId::new(),
            EntityId::new(),
            CanonicalBytes::from_static(b"payload"),
            0,
            ([0; 32], 0, [0; 32]),
            (0, false, 0),
            ([0; 32], [0; 32]),
        ));
        drop(executor.admit_geo_location(request).await);
        executor.shutdown().await.test_ok()?;

        drop(executor);

        Ok(())
    }

    #[test]
    fn owntracks_rate_state_expires_without_reaching_the_cardinality_limit(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([1; 32]);
        let mut limiter = OwnTracksRateLimiter {
            buckets: HashMap::from([(
                key,
                super::OwnTracksTokenBucket {
                    tokens: 0,
                    last_refill: Instant::now()
                        .checked_sub(super::OWNTRACKS_RATE_STATE_TTL)
                        .test_ok()?,
                },
            )]),
        };
        assert!(limiter.allow(OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([2; 32],)));
        assert_eq!(limiter.buckets.len(), 1);
        assert!(!limiter.buckets.contains_key(&key));

        Ok(())
    }

    #[test]
    fn owntracks_rate_state_evicts_the_oldest_key_at_capacity(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = Instant::now();
        let oldest = OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([1; 32]);
        let newest = OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([2; 32]);
        let replacement = OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([255; 32]);
        let mut buckets = HashMap::new();
        for byte in 0..super::OWNTRACKS_RATE_KEYS_MAXIMUM {
            buckets.insert(
                OwnTracksIngressRateKeyV1::from_owner_keyed_bytes(
                    [u8::try_from(byte).test_ok()?; 32],
                ),
                super::OwnTracksTokenBucket {
                    tokens: 1,
                    last_refill: now,
                },
            );
        }
        buckets.insert(
            oldest,
            super::OwnTracksTokenBucket {
                tokens: 1,
                last_refill: now
                    .checked_sub(std::time::Duration::from_secs(1))
                    .test_ok()?,
            },
        );
        buckets.insert(
            newest,
            super::OwnTracksTokenBucket {
                tokens: 1,
                last_refill: now,
            },
        );
        let mut limiter = OwnTracksRateLimiter { buckets };

        assert!(limiter.allow(replacement));
        assert_eq!(limiter.buckets.len(), super::OWNTRACKS_RATE_KEYS_MAXIMUM);
        assert!(!limiter.buckets.contains_key(&oldest));
        assert!(limiter.buckets.contains_key(&replacement));
        assert!(limiter.buckets.contains_key(&newest));

        Ok(())
    }
}
