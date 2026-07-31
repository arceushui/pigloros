//! Dedicated synchronous [`EventStore`] owner.
//!
//! The gateway never holds a synchronous store lock on an async executor
//! worker.  Commands are linearised by one bounded FIFO and executed by one
//! dedicated OS thread.

use pos_core::{
    event::{Event, EventDraft},
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

const QUEUE_CAPACITY: usize = 64;

enum Command {
    Purge {
        limit: NonZeroUsize,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    RootCount {
        maximum: usize,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    Create {
        name: String,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    Read {
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    ReadOne {
        timeline: TimelineId,
        event: EventId,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    Append {
        timeline: TimelineId,
        drafts: Vec<EventDraft>,
        maximum: Option<u64>,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    AppendIdentified {
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
    GetTimeline {
        timeline: TimelineId,
        reply: oneshot::Sender<Result<Response, CoreError>>,
    },
}

pub(crate) enum Response {
    Purge(PurgeOutcome),
    RootCount(usize),
    Timeline(Option<Timeline>),
    CreatedTimeline(Timeline),
    Events(Vec<Event>),
    Event(Option<Event>),
    Appended(Vec<Event>),
    Identified(Option<AppendOrDuplicateOutcome>),
}

#[derive(Clone)]
pub(crate) struct StoreExecutor {
    tx: mpsc::Sender<Command>,
}

impl StoreExecutor {
    pub(crate) fn new(store: Box<dyn EventStore>) -> Self {
        let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
        let _ = thread::Builder::new()
            .name("piglor-store-executor".to_owned())
            .spawn(move || {
                let mut store = store;
                while let Some(command) = rx.blocking_recv() {
                    execute(&mut *store, command);
                }
            })
            .is_ok();
        Self { tx }
    }

    async fn submit(&self, command: Command) -> Result<Response, CoreError> {
        let (tx, rx) = oneshot::channel();
        // Replace the placeholder sender with the real one by rebuilding the command.
        let command = command.with_reply(tx);
        self.tx.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                CoreError::Storage("store executor queue saturated".to_owned())
            }
            mpsc::error::TrySendError::Closed(_) => {
                CoreError::Storage("store executor closed".to_owned())
            }
        })?;
        rx.await
            .map_err(|_| CoreError::Storage("store executor closed".to_owned()))?
    }

    pub(crate) async fn purge(&self, limit: NonZeroUsize) -> Result<PurgeOutcome, CoreError> {
        match self
            .submit(Command::Purge {
                limit,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::Purge(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn root_count(&self, maximum: usize) -> Result<usize, CoreError> {
        match self
            .submit(Command::RootCount {
                maximum,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::RootCount(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn create(&self, name: String) -> Result<Timeline, CoreError> {
        match self
            .submit(Command::Create {
                name,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::CreatedTimeline(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn read(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        match self
            .submit(Command::Read {
                timeline,
                range,
                bounds,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::Events(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn read_one(
        &self,
        timeline: TimelineId,
        event: EventId,
    ) -> Result<Option<Event>, CoreError> {
        match self
            .submit(Command::ReadOne {
                timeline,
                event,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::Event(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn append(
        &self,
        timeline: TimelineId,
        drafts: Vec<EventDraft>,
        maximum: Option<u64>,
    ) -> Result<Vec<Event>, CoreError> {
        match self
            .submit(Command::Append {
                timeline,
                drafts,
                maximum,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::Appended(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn append_identified(
        &self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        match self
            .submit(Command::AppendIdentified {
                timeline,
                identity,
                intent,
                maximum,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::Identified(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
    pub(crate) async fn timeline(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<Timeline>, CoreError> {
        match self
            .submit(Command::GetTimeline {
                timeline,
                reply: oneshot::channel().0,
            })
            .await?
        {
            Response::Timeline(v) => Ok(v),
            _ => Err(type_mismatch()),
        }
    }
}

impl Command {
    fn with_reply(self, reply: oneshot::Sender<Result<Response, CoreError>>) -> Self {
        match self {
            Self::Purge { limit, .. } => Self::Purge { limit, reply },
            Self::RootCount { maximum, .. } => Self::RootCount { maximum, reply },
            Self::Create { name, .. } => Self::Create { name, reply },
            Self::Read {
                timeline,
                range,
                bounds,
                ..
            } => Self::Read {
                timeline,
                range,
                bounds,
                reply,
            },
            Self::ReadOne {
                timeline, event, ..
            } => Self::ReadOne {
                timeline,
                event,
                reply,
            },
            Self::Append {
                timeline,
                drafts,
                maximum,
                ..
            } => Self::Append {
                timeline,
                drafts,
                maximum,
                reply,
            },
            Self::AppendIdentified {
                timeline,
                identity,
                intent,
                maximum,
                ..
            } => Self::AppendIdentified {
                timeline,
                identity,
                intent,
                maximum,
                reply,
            },
            Self::GetTimeline { timeline, .. } => Self::GetTimeline { timeline, reply },
        }
    }
}

fn execute(store: &mut dyn EventStore, command: Command) {
    let (reply, result) = match command {
        Command::Purge { limit, reply } => (
            reply,
            store
                .purge_expired_append_identities_bounded(limit)
                .map(Response::Purge),
        ),
        Command::RootCount { maximum, reply } => (
            reply,
            store
                .root_timeline_count_bounded(maximum)
                .map(Response::RootCount),
        ),
        Command::Create { name, reply } => (
            reply,
            store.create_timeline(&name).map(Response::CreatedTimeline),
        ),
        Command::Read {
            timeline,
            range,
            bounds,
            reply,
        } => (
            reply,
            store
                .read_bounded(timeline, range, bounds)
                .map(Response::Events),
        ),
        Command::ReadOne {
            timeline,
            event,
            reply,
        } => (
            reply,
            store.read_event_by_id(timeline, event).map(Response::Event),
        ),
        Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        } => {
            let result = store
                .get_timeline(timeline)
                .and_then(|meta| {
                    if let (Some(maximum), Some(meta)) = (maximum, meta) {
                        if meta.head.as_u64() >= maximum {
                            return Err(CoreError::Storage("event limit reached".to_owned()));
                        }
                    }
                    store.append(timeline, &drafts)
                })
                .map(Response::Appended);
            (reply, result)
        }
        Command::AppendIdentified {
            timeline,
            identity,
            intent,
            maximum,
            reply,
        } => (
            reply,
            store
                .append_intent_or_duplicate_bounded(timeline, identity, intent, maximum)
                .map(Response::Identified),
        ),
        Command::GetTimeline { timeline, reply } => {
            (reply, store.get_timeline(timeline).map(Response::Timeline))
        }
    };
    let _ = reply.send(result);
}

fn type_mismatch() -> CoreError {
    CoreError::Storage("store executor response type mismatch".to_owned())
}
