//! Dedicated synchronous [`EventStore`] owner.
//!
//! The gateway never holds a synchronous store lock on an async executor
//! worker.  Commands are linearised by one bounded FIFO and executed by one
//! dedicated OS thread.

use pos_core::{
    event::{Event, EventDraft},
    geo_admission::{
        GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
    },
    ids::{EntityId, EventId, TimelineId},
    store::{
        AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore,
        PurgeOutcome, SeqRange,
    },
    timeline::Timeline,
    CoreError, OwnTracksIngressInputV1, OwnTracksIngressRateKeyV1, OwnTracksIngressStore,
};
use std::thread;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

pub(crate) const QUEUE_CAPACITY: usize = 64;
const OWNTRACKS_RATE_BURST: u8 = 5;
const OWNTRACKS_RATE_KEYS_MAXIMUM: usize = 64;

macro_rules! submit {
    ($executor:expr, $build:expr) => {{
        let (reply, result) = oneshot::channel();
        match $executor.tx.try_send($build(reply)) {
            Ok(()) => match result.await {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(error)) => Err(StoreExecutorError::Store(error)),
                Err(_) => Err(StoreExecutorError::Closed),
            },
            Err(error) => Err(match error {
                mpsc::error::TrySendError::Full(_) => StoreExecutorError::Saturated,
                mpsc::error::TrySendError::Closed(_) => StoreExecutorError::Closed,
            }),
        }
    }};
}

pub(super) enum Command {
    #[allow(dead_code)]
    AdmitOwnTracksIngress {
        input: OwnTracksIngressInputV1,
        reply: oneshot::Sender<Result<OwnTracksIngressOutcome, CoreError>>,
    },
    AdmitGeoLocation {
        request: GeoLocationAdmissionRequestV1,
        reply: oneshot::Sender<Result<GeoLocationAdmissionOutcome, CoreError>>,
    },
    Purge {
        limit: NonZeroUsize,
        reply: oneshot::Sender<Result<PurgeOutcome, CoreError>>,
    },
    RootCount {
        maximum: usize,
        reply: oneshot::Sender<Result<usize, CoreError>>,
    },
    Create {
        name: String,
        reply: oneshot::Sender<Result<Timeline, CoreError>>,
    },
    Read {
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
        reply: oneshot::Sender<Result<Vec<Event>, CoreError>>,
    },
    ReadOne {
        timeline: TimelineId,
        event: EventId,
        reply: oneshot::Sender<Result<Option<Event>, CoreError>>,
    },
    Append {
        timeline: TimelineId,
        drafts: Vec<EventDraft>,
        maximum: Option<u64>,
        reply: oneshot::Sender<Result<Vec<Event>, CoreError>>,
    },
    AppendIdentified {
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
        reply: oneshot::Sender<Result<Option<AppendOrDuplicateOutcome>, CoreError>>,
    },
    GetTimeline {
        timeline: TimelineId,
        reply: oneshot::Sender<Result<Option<Timeline>, CoreError>>,
    },
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

impl OwnTracksIngressOutcome {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RateLimited)
    }
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
        .expect("OwnTracks rate refill is bounded by the burst");
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
    owntracks_rate_limiter: OwnTracksRateLimiter,
}

#[derive(Debug)]
pub(crate) enum StoreExecutorError {
    Saturated,
    Closed,
    Store(CoreError),
}

#[derive(Clone)]
pub(crate) struct StoreExecutor {
    pub(super) tx: mpsc::Sender<Command>,
}

impl StoreExecutor {
    pub(crate) fn new(store: Box<dyn EventStore>) -> Self {
        Self::spawn(ExecutorStore::Generic(store))
    }

    pub(crate) fn new_with_geo_location_admission<S>(store: S) -> Self
    where
        S: EventStore + GeoLocationAdmissionStore + 'static,
    {
        Self::spawn(ExecutorStore::GeoLocation(Box::new(store)))
    }

    pub(crate) fn new_with_owntracks_ingress<S>(store: S) -> Self
    where
        S: EventStore + GeoLocationAdmissionStore + OwnTracksIngressStore + 'static,
    {
        Self::spawn(ExecutorStore::OwnTracks(Box::new(store)))
    }

    fn spawn(store: ExecutorStore) -> Self {
        let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
        let _ = thread::Builder::new()
            .name("piglor-store-executor".to_owned())
            .spawn(move || {
                let mut state = ExecutorState {
                    store,
                    owntracks_rate_limiter: OwnTracksRateLimiter {
                        buckets: HashMap::new(),
                    },
                };
                while let Some(command) = rx.blocking_recv() {
                    execute(&mut state, command);
                }
            });
        Self { tx }
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
        input: OwnTracksIngressInputV1,
    ) -> Result<OwnTracksIngressOutcome, StoreExecutorError> {
        submit!(self, |reply| Command::AdmitOwnTracksIngress {
            input,
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

fn execute_owntracks_ingress(
    state: &mut ExecutorState,
    input: OwnTracksIngressInputV1,
) -> Result<OwnTracksIngressOutcome, CoreError> {
    let ExecutorStore::OwnTracks(store) = &mut state.store else {
        return Err(CoreError::GeographicAdmissionUnavailable);
    };
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

fn execute(state: &mut ExecutorState, command: Command) {
    match command {
        Command::AdmitOwnTracksIngress { input, reply } => {
            let result = execute_owntracks_ingress(state, input);
            let _ = reply.send(result);
        }
        Command::AdmitGeoLocation { request, reply } => {
            let result = match &mut state.store {
                ExecutorStore::GeoLocation(store) => store.admit_geo_location(request),
                ExecutorStore::OwnTracks(store) => store.admit_geo_location(request),
                ExecutorStore::Generic(_) => Err(CoreError::GeographicAdmissionUnavailable),
            };
            let _ = reply.send(result);
        }
        Command::Purge { limit, reply } => {
            let _ = reply.send(
                state
                    .store
                    .event_store()
                    .purge_expired_append_identities_bounded(limit),
            );
        }
        Command::RootCount { maximum, reply } => {
            let _ = reply.send(
                state
                    .store
                    .event_store()
                    .root_timeline_count_bounded(maximum),
            );
        }
        Command::Create { name, reply } => {
            let _ = reply.send(state.store.event_store().create_timeline(&name));
        }
        Command::Read {
            timeline,
            range,
            bounds,
            reply,
        } => {
            let _ = reply.send(
                state
                    .store
                    .event_store()
                    .read_bounded(timeline, range, bounds),
            );
        }
        Command::ReadOne {
            timeline,
            event,
            reply,
        } => {
            let _ = reply.send(state.store.event_store().read_event_by_id(timeline, event));
        }
        Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        } => {
            let store = state.store.event_store();
            let result = store.get_timeline(timeline).and_then(|meta| {
                if let (Some(maximum), Some(meta)) = (maximum, meta) {
                    if meta.head.as_u64() >= maximum {
                        return Err(CoreError::Storage("event limit reached".to_owned()));
                    }
                }
                store.append(timeline, &drafts)
            });
            let _ = reply.send(result);
        }
        Command::AppendIdentified {
            timeline,
            identity,
            intent,
            maximum,
            reply,
        } => {
            let _ = reply.send(
                state
                    .store
                    .event_store()
                    .append_intent_or_duplicate_bounded(timeline, identity, intent, maximum),
            );
        }
        Command::GetTimeline { timeline, reply } => {
            let _ = reply.send(state.store.event_store().get_timeline(timeline));
        }
    }
}
