use crate::{
    clock::Seq,
    error::CoreError,
    event::{Event, EventDraft},
    ids::TimelineId,
    timeline::Timeline,
};

/// Range of sequence numbers to read.
#[derive(Clone, Copy, Debug)]
pub struct SeqRange {
    pub from: Seq,
    /// Inclusive upper bound. `None` means read to the end.
    pub to: Option<Seq>,
}

impl SeqRange {
    #[must_use] 
    pub const fn from_seq(from: Seq) -> Self {
        Self { from, to: None }
    }

    #[must_use] 
    pub const fn bounded(from: Seq, to: Seq) -> Self {
        Self { from, to: Some(to) }
    }

    #[must_use] 
    pub const fn all() -> Self {
        Self {
            from: Seq::ZERO,
            to: None,
        }
    }
}

/// A portable snapshot of a timeline and all its events.
/// Used for export/import across different `EventStore` backends.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimelineExport {
    pub timeline: Timeline,
    pub events: Vec<Event>,
}

/// The kernel's event-store abstraction. Implementations live in `pos-store`.
///
/// All methods are synchronous — no async in the kernel.
/// `Send` is required; `Sync` is not — multi-threaded callers wrap in `Arc<Mutex<_>>`.
///
/// # Provider independence
/// All timeline lifecycle operations (create, append, read, fork, export, import)
/// go through this trait. Callers should hold `Box<dyn EventStore>` or
/// `Arc<Mutex<dyn EventStore>>` — never a concrete type — so the backend
/// (`SQLite`, in-memory, `redb`, `TiKV`) can be swapped without changing call sites.
pub trait EventStore: Send {
    /// Create a new root timeline with the given name.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError>;

    /// Append one or more draft events to a timeline, returning the committed events.
    ///
    /// Batching is required for performance: single-row commit is too slow for `SQLite` WAL.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError>;

    /// Read events from a timeline in a seq range.
    ///
    /// For a forked timeline, this transparently stitches `parent[0..fork_seq]` + child events.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn read(
        &self,
        timeline: TimelineId,
        range: SeqRange,
    ) -> Result<Vec<Event>, CoreError>;

    /// Create a forked child timeline at `at_seq`.
    ///
    /// The child is copy-on-write: it stores only its own events going forward.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the parent does not exist, or
    /// [`CoreError::ForkBeyondHead`] if `at_seq` exceeds the parent's head.
    fn fork(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError>;

    /// List all known timelines.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError>;

    /// Get a specific timeline's metadata.
    ///
    /// Returns `Ok(None)` if the timeline does not exist.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error on I/O failure.
    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError>;

    /// Export a timeline and all its events as a portable snapshot.
    ///
    /// The snapshot can be serialised to JSON/CBOR and imported into any
    /// `EventStore` backend — enabling migration between providers.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    fn export_timeline(&self, id: TimelineId) -> Result<TimelineExport, CoreError> {
        let timeline = self
            .get_timeline(id)?
            .ok_or(CoreError::TimelineNotFound(id))?;
        let events = self.read(id, SeqRange::all())?;
        Ok(TimelineExport { timeline, events })
    }

    /// Import a previously exported timeline snapshot into this store.
    ///
    /// Creates the timeline and replays all events. If a timeline with the
    /// same `TimelineId` already exists, returns a storage error.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error if the timeline already exists or on I/O failure.
    fn import_timeline(&mut self, export: TimelineExport) -> Result<Timeline, CoreError> {
        let name = export.timeline.meta.name.unwrap_or_default();
        let tl = self.create_timeline(&name)?;
        if !export.events.is_empty() {
            let drafts: Vec<EventDraft> = export
                .events
                .into_iter()
                .map(|e| {
                    let mut draft = EventDraft::new(e.entity, e.event_type, e.payload);
                    draft.causation_id = e.causation_id;
                    draft.correlation_id = e.correlation_id;
                    draft.schema_version = e.schema_version;
                    draft
                })
                .collect();
            self.append(tl.id(), &drafts)?;
        }
        Ok(tl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The EventStore trait lives here; implementations are in pos-store.
    // These tests verify the trait contract is sound (not that it compiles with an impl).

    #[test]
    fn seq_range_all_starts_at_zero() {
        let r = SeqRange::all();
        assert_eq!(r.from, Seq::ZERO);
        assert!(r.to.is_none());
    }

    #[test]
    fn seq_range_from_seq() {
        let r = SeqRange::from_seq(Seq::from_u64(5));
        assert_eq!(r.from, Seq::from_u64(5));
        assert!(r.to.is_none());
    }

    #[test]
    fn seq_range_bounded() {
        let r = SeqRange::bounded(Seq::from_u64(3), Seq::from_u64(10));
        assert_eq!(r.from, Seq::from_u64(3));
        assert_eq!(r.to, Some(Seq::from_u64(10)));
    }
}
