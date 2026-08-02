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
const OWNTRACKS_RATE_STATE_TTL: Duration = Duration::from_mins(15);

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
        basic_handle: [u8; 32],
        basic_secret: [u8; 32],
        payload: pos_core::CanonicalBytes,
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
    owntracks_owner_key: Option<[u8; 32]>,
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
        let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
        let _ = thread::Builder::new()
            .name("piglor-store-executor".to_owned())
            .spawn(move || {
                let mut state = ExecutorState {
                    store,
                    owntracks_owner_key,
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

fn execute(state: &mut ExecutorState, command: Command) {
    match command {
        Command::AdmitOwnTracksIngress {
            basic_handle,
            basic_secret,
            payload,
            reply,
        } => {
            let result = execute_owntracks_ingress(state, basic_handle, basic_secret, payload);
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{execute_owntracks_ingress, ExecutorState, ExecutorStore, OwnTracksRateLimiter};
    use pos_core::{CanonicalBytes, CoreError, OwnTracksIngressRateKeyV1};
    use pos_store::memory::MemoryStore;
    use std::{collections::HashMap, time::Instant};

    #[test]
    fn owntracks_ingress_fails_closed_for_a_generic_store() {
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
        .unwrap_err();
        assert!(matches!(error, CoreError::GeographicAdmissionUnavailable));
    }

    #[test]
    fn owntracks_rate_state_expires_without_reaching_the_cardinality_limit() {
        let key = OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([1; 32]);
        let mut limiter = OwnTracksRateLimiter {
            buckets: HashMap::from([(
                key,
                super::OwnTracksTokenBucket {
                    tokens: 0,
                    last_refill: Instant::now()
                        .checked_sub(super::OWNTRACKS_RATE_STATE_TTL)
                        .expect("current instant is after the rate-state TTL"),
                },
            )]),
        };
        assert!(limiter.allow(OwnTracksIngressRateKeyV1::from_owner_keyed_bytes([2; 32],)));
        assert_eq!(limiter.buckets.len(), 1);
        assert!(!limiter.buckets.contains_key(&key));
    }
}
