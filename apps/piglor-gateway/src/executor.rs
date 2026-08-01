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
    ids::{EventId, TimelineId},
    store::{
        AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore,
        PurgeOutcome, SeqRange,
    },
    timeline::Timeline,
    CoreError,
};
use std::num::NonZeroUsize;
use std::thread;
use tokio::sync::{mpsc, oneshot};

pub(crate) const QUEUE_CAPACITY: usize = 64;

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

enum ExecutorStore {
    Generic(Box<dyn EventStore>),
    GeoLocation(Box<dyn GeoLocationGatewayStore>),
}

impl ExecutorStore {
    fn event_store(&mut self) -> &mut dyn EventStore {
        match self {
            Self::Generic(store) => store.as_mut(),
            Self::GeoLocation(store) => store.as_mut(),
        }
    }
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

    fn spawn(store: ExecutorStore) -> Self {
        let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
        let _ = thread::Builder::new()
            .name("piglor-store-executor".to_owned())
            .spawn(move || {
                let mut store = store;
                while let Some(command) = rx.blocking_recv() {
                    execute(&mut store, command);
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

fn execute(store: &mut ExecutorStore, command: Command) {
    match command {
        Command::AdmitGeoLocation { request, reply } => {
            let result = match store {
                ExecutorStore::GeoLocation(store) => store.admit_geo_location(request),
                ExecutorStore::Generic(_) => Err(CoreError::GeographicAdmissionUnavailable),
            };
            let _ = reply.send(result);
        }
        Command::Purge { limit, reply } => {
            let _ = reply.send(
                store
                    .event_store()
                    .purge_expired_append_identities_bounded(limit),
            );
        }
        Command::RootCount { maximum, reply } => {
            let _ = reply.send(store.event_store().root_timeline_count_bounded(maximum));
        }
        Command::Create { name, reply } => {
            let _ = reply.send(store.event_store().create_timeline(&name));
        }
        Command::Read {
            timeline,
            range,
            bounds,
            reply,
        } => {
            let _ = reply.send(store.event_store().read_bounded(timeline, range, bounds));
        }
        Command::ReadOne {
            timeline,
            event,
            reply,
        } => {
            let _ = reply.send(store.event_store().read_event_by_id(timeline, event));
        }
        Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        } => {
            let store = store.event_store();
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
                store
                    .event_store()
                    .append_intent_or_duplicate_bounded(timeline, identity, intent, maximum),
            );
        }
        Command::GetTimeline { timeline, reply } => {
            let _ = reply.send(store.event_store().get_timeline(timeline));
        }
    }
}
