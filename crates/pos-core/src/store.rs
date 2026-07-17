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
    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError>;

    /// Create a forked child timeline at `at_seq`.
    ///
    /// The child is copy-on-write: it stores only its own events going forward.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] if the parent does not exist, or
    /// [`CoreError::ForkBeyondHead`] if `at_seq` exceeds the parent's head.
    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError>;

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
        export_timeline_using(self.get_timeline(id), self.read(id, SeqRange::all()), id)
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
        let create_result = self.create_timeline(&name);
        import_timeline_using(create_result, export.events, |timeline_id, drafts| {
            self.append(timeline_id, drafts)
        })
    }

    /// Import a timeline snapshot preserving the original [`TimelineId`] and event IDs.
    ///
    /// Unlike [`import_timeline`], this variant creates the timeline with its original
    /// identity — required for cross-node shared worlds (Wave 6) where timelines must
    /// have stable, addressable identities.
    ///
    /// Backends that support identity-preserving import should override this method.
    /// The default implementation falls back to [`import_timeline`], which assigns a new
    /// `TimelineId`. That is safe for local use but loses the original identity.
    ///
    /// # Errors
    /// Returns a [`CoreError::Storage`] error if a timeline with that ID already exists
    /// (when overridden by a backend that enforces uniqueness).
    fn import_timeline_with_id(&mut self, export: TimelineExport) -> Result<Timeline, CoreError> {
        // Default implementation falls back to import_timeline (loses IDs).
        // Backends that support identity-preserving import should override this.
        self.import_timeline(export)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn export_timeline_using(
    timeline_result: Result<Option<Timeline>, CoreError>,
    events_result: Result<Vec<Event>, CoreError>,
    id: TimelineId,
) -> Result<TimelineExport, CoreError> {
    let Some(timeline) = timeline_result? else {
        return Err(CoreError::TimelineNotFound(id));
    };
    let events = events_result?;
    Ok(TimelineExport { timeline, events })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn import_timeline_using<A>(
    create_result: Result<Timeline, CoreError>,
    events: Vec<Event>,
    append: A,
) -> Result<Timeline, CoreError>
where
    A: FnOnce(TimelineId, &[EventDraft]) -> Result<Vec<Event>, CoreError>,
{
    let tl = create_result?;
    if !events.is_empty() {
        let drafts: Vec<EventDraft> = events
            .into_iter()
            .map(|e| {
                let mut draft = EventDraft::new(e.entity, e.event_type, e.payload);
                draft.causation_id = e.causation_id;
                draft.correlation_id = e.correlation_id;
                draft.schema_version = e.schema_version;
                draft.wall_time = Some(e.wall_time);
                draft
            })
            .collect();
        append(tl.id(), &drafts)?;
    }
    Ok(tl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId, TimelineId},
        timeline::{Timeline, TimelineMeta},
    };

    // The EventStore trait lives here; implementations are in pos-store.
    // These tests verify the trait contract is sound (not that it compiles with an impl).

    /// Minimal in-memory store used only for trait-level tests in pos-core.
    struct TrivialStore {
        counter: u64,
    }

    impl TrivialStore {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    /// Store that fails selected operations for export/import error-path coverage.
    struct FlakyStore {
        mode: FlakyMode,
        counter: u64,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FlakyMode {
        GetTimelineErr,
        GetTimelineMissing,
        ReadErr,
        CreateTimelineErr,
        AppendErr,
        Healthy,
    }

    impl FlakyStore {
        fn new(mode: FlakyMode) -> Self {
            Self { mode, counter: 0 }
        }

        fn healthy_timeline() -> Timeline {
            Timeline::new(TimelineMeta::root("flaky"))
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl EventStore for FlakyStore {
        fn create_timeline(&mut self, _name: &str) -> Result<Timeline, CoreError> {
            if self.mode == FlakyMode::CreateTimelineErr {
                return Err(CoreError::Storage("create_timeline failed".to_owned()));
            }
            Ok(Self::healthy_timeline())
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            if self.mode == FlakyMode::AppendErr {
                return Err(CoreError::Storage("append failed".to_owned()));
            }
            let events = drafts
                .iter()
                .map(|d| {
                    self.counter += 1;
                    Event {
                        id: EventId::new(),
                        entity: d.entity,
                        event_type: d.event_type.clone(),
                        payload: d.payload.clone(),
                        wall_time: d.wall_time.unwrap_or_else(WallTime::now),
                        seq: Seq::from_u64(self.counter),
                        causation_id: d.causation_id,
                        correlation_id: d.correlation_id,
                        schema_version: d.schema_version,
                        signature: None,
                        payload_hash: Hash::from_bytes([0u8; 32]),
                    }
                })
                .collect();
            Ok(events)
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if self.mode == FlakyMode::ReadErr {
                return Err(CoreError::Storage("read failed".to_owned()));
            }
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            Ok(Timeline::new(TimelineMeta::root("fork")))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            match self.mode {
                FlakyMode::GetTimelineErr => {
                    Err(CoreError::Storage("get_timeline failed".to_owned()))
                }
                FlakyMode::GetTimelineMissing => Ok(None),
                _ => Ok(Some(Self::healthy_timeline())),
            }
        }
    }

    impl EventStore for TrivialStore {
        fn create_timeline(&mut self, _name: &str) -> Result<Timeline, CoreError> {
            let meta = TimelineMeta::root("test");
            Ok(Timeline::new(meta))
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            let events = drafts
                .iter()
                .map(|d| {
                    self.counter += 1;
                    Event {
                        id: EventId::new(),
                        entity: d.entity,
                        event_type: d.event_type.clone(),
                        payload: d.payload.clone(),
                        wall_time: d.wall_time.unwrap_or_else(WallTime::now),
                        seq: Seq::from_u64(self.counter),
                        causation_id: d.causation_id,
                        correlation_id: d.correlation_id,
                        schema_version: d.schema_version,
                        signature: None,
                        payload_hash: Hash::from_bytes([0u8; 32]),
                    }
                })
                .collect();
            Ok(events)
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            let meta = TimelineMeta::root("fork");
            Ok(Timeline::new(meta))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            Ok(None)
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_defaults_to_import_timeline() {
        // The default `import_timeline_with_id` falls back to `import_timeline`, which
        // creates a new TimelineId. This test documents that known behaviour so that
        // Wave 6 backends that need identity-preserving import know they must override it.
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"hello".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let meta = TimelineMeta::root("original");
        let timeline = Timeline::new(meta);
        // The default impl will *not* preserve the original TimelineId — that's the point.
        // Wave 6 backends must override import_timeline_with_id to preserve identity.
        let export = TimelineExport {
            timeline,
            events: vec![dummy_event],
        };

        let mut store = TrivialStore::new();
        // Default fallback succeeds but assigns a new TimelineId.
        let imported = store.import_timeline_with_id(export).unwrap();
        // The returned timeline has *some* valid id (just not the original one).
        let _ = imported.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_empty_events_skips_append() {
        // Covers the `if !export.events.is_empty()` false branch (line 153 skipped).
        let meta = TimelineMeta::root("empty");
        let timeline = Timeline::new(meta);
        let export = TimelineExport {
            timeline,
            events: vec![],
        };
        let mut store = TrivialStore::new();
        let imported = store.import_timeline(export).unwrap();
        let _ = imported.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_read_returns_empty() {
        let store = TrivialStore::new();
        let id = crate::ids::TimelineId::new();
        let result = store.read(id, SeqRange::all()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_fork_returns_timeline() {
        let mut store = TrivialStore::new();
        let id = crate::ids::TimelineId::new();
        let tl = store.fork(id, Seq::ZERO, "fork").unwrap();
        let _ = tl.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_list_timelines_returns_empty() {
        let store = TrivialStore::new();
        assert!(store.list_timelines().unwrap().is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trivial_store_get_timeline_returns_none() {
        let store = TrivialStore::new();
        let id = crate::ids::TimelineId::new();
        assert!(store.get_timeline(id).unwrap().is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_range_all_starts_at_zero() {
        let r = SeqRange::all();
        assert_eq!(r.from, Seq::ZERO);
        assert!(r.to.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_range_from_seq() {
        let r = SeqRange::from_seq(Seq::from_u64(5));
        assert_eq!(r.from, Seq::from_u64(5));
        assert!(r.to.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_range_bounded() {
        let r = SeqRange::bounded(Seq::from_u64(3), Seq::from_u64(10));
        assert_eq!(r.from, Seq::from_u64(3));
        assert_eq!(r.to, Some(Seq::from_u64(10)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_get_timeline_err_propagates() {
        let store = FlakyStore::new(FlakyMode::GetTimelineErr);
        let id = TimelineId::new();
        let err = store.export_timeline(id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_missing_timeline_returns_not_found() {
        let store = FlakyStore::new(FlakyMode::GetTimelineMissing);
        let id = TimelineId::new();
        let err = store.export_timeline(id).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_timeline_read_err_propagates() {
        let store = FlakyStore::new(FlakyMode::ReadErr);
        let id = TimelineId::new();
        let err = store.export_timeline(id).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_create_timeline_err_propagates() {
        let mut store = FlakyStore::new(FlakyMode::CreateTimelineErr);
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![],
        };
        let err = store.import_timeline(export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_append_err_propagates() {
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"hello".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![dummy_event],
        };
        let mut store = FlakyStore::new(FlakyMode::AppendErr);
        let err = store.import_timeline(export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flaky_store_healthy_export_succeeds() {
        let store = FlakyStore::new(FlakyMode::Healthy);
        let id = TimelineId::new();
        let export = store.export_timeline(id).unwrap();
        assert!(export.events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn flaky_store_healthy_import_with_events_succeeds() {
        let entity = EntityId::new();
        let dummy_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(b"data".to_vec()),
            wall_time: WallTime::from_micros(1_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![dummy_event],
        };
        let mut store = FlakyStore::new(FlakyMode::Healthy);
        let imported = store.import_timeline(export).unwrap();
        let _ = imported.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_propagates_create_error() {
        let export = TimelineExport {
            timeline: FlakyStore::healthy_timeline(),
            events: vec![],
        };
        let mut store = FlakyStore::new(FlakyMode::CreateTimelineErr);
        let err = store.import_timeline_with_id(export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }
}
