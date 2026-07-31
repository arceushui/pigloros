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

    async fn submit<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, CoreError>>) -> Command,
    ) -> Result<T, CoreError> {
        let result = match self.enqueue(build) {
            Ok(result) => result,
            Err(error) => return Err(error),
        };
        match result.await {
            Ok(result) => result,
            Err(_) => Err(closed_error()),
        }
    }

    fn enqueue<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, CoreError>>) -> Command,
    ) -> Result<oneshot::Receiver<Result<T, CoreError>>, CoreError> {
        let (reply, result) = oneshot::channel();
        match self.tx.try_send(build(reply)) {
            Ok(()) => Ok(result),
            Err(error) => Err(match error {
                mpsc::error::TrySendError::Full(_) => saturated_error(),
                mpsc::error::TrySendError::Closed(_) => closed_error(),
            }),
        }
    }

    pub(crate) async fn purge(&self, limit: NonZeroUsize) -> Result<PurgeOutcome, CoreError> {
        self.submit(|reply| Command::Purge { limit, reply }).await
    }
    pub(crate) async fn root_count(&self, maximum: usize) -> Result<usize, CoreError> {
        self.submit(|reply| Command::RootCount { maximum, reply })
            .await
    }
    pub(crate) async fn create(&self, name: String) -> Result<Timeline, CoreError> {
        self.submit(|reply| Command::Create { name, reply }).await
    }
    pub(crate) async fn read(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.submit(|reply| Command::Read {
            timeline,
            range,
            bounds,
            reply,
        })
        .await
    }
    pub(crate) async fn read_one(
        &self,
        timeline: TimelineId,
        event: EventId,
    ) -> Result<Option<Event>, CoreError> {
        self.submit(|reply| Command::ReadOne {
            timeline,
            event,
            reply,
        })
        .await
    }
    pub(crate) async fn append(
        &self,
        timeline: TimelineId,
        drafts: Vec<EventDraft>,
        maximum: Option<u64>,
    ) -> Result<Vec<Event>, CoreError> {
        self.submit(|reply| Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        })
        .await
    }
    pub(crate) async fn append_identified(
        &self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        self.submit(|reply| Command::AppendIdentified {
            timeline,
            identity,
            intent,
            maximum,
            reply,
        })
        .await
    }
    pub(crate) async fn timeline(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<Timeline>, CoreError> {
        self.submit(|reply| Command::GetTimeline { timeline, reply })
            .await
    }
}

fn execute(store: &mut dyn EventStore, command: Command) {
    match command {
        Command::Purge { limit, reply } => {
            let _ = reply.send(store.purge_expired_append_identities_bounded(limit));
        }
        Command::RootCount { maximum, reply } => {
            let _ = reply.send(store.root_timeline_count_bounded(maximum));
        }
        Command::Create { name, reply } => {
            let _ = reply.send(store.create_timeline(&name));
        }
        Command::Read {
            timeline,
            range,
            bounds,
            reply,
        } => {
            let _ = reply.send(store.read_bounded(timeline, range, bounds));
        }
        Command::ReadOne {
            timeline,
            event,
            reply,
        } => {
            let _ = reply.send(store.read_event_by_id(timeline, event));
        }
        Command::Append {
            timeline,
            drafts,
            maximum,
            reply,
        } => {
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
                store.append_intent_or_duplicate_bounded(timeline, identity, intent, maximum),
            );
        }
        Command::GetTimeline { timeline, reply } => {
            let _ = reply.send(store.get_timeline(timeline));
        }
    }
}

fn saturated_error() -> CoreError {
    CoreError::Storage("store executor queue saturated".to_owned())
}

fn closed_error() -> CoreError {
    CoreError::Storage("store executor closed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{Command, StoreExecutor, QUEUE_CAPACITY};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn closed_executor_reports_closed_through_public_operation() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let executor = StoreExecutor { tx };

        let error = executor.root_count(1).await.unwrap_err().to_string();

        assert!(error.contains("store executor closed"));
    }

    #[tokio::test]
    async fn full_queue_reports_saturation_through_public_operation() {
        let (tx, _rx) = mpsc::channel(QUEUE_CAPACITY);
        let executor = StoreExecutor { tx };
        for _ in 0..QUEUE_CAPACITY {
            executor
                .enqueue(|reply| Command::RootCount { maximum: 1, reply })
                .unwrap();
        }

        let error = executor.root_count(1).await.unwrap_err().to_string();

        assert!(error.contains("store executor queue saturated"));
    }
}
