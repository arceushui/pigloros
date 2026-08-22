use pos_core::{
    clock::Seq,
    error::CoreError,
    event::Event,
    ids::{EntityId, TimelineId},
    store::{EventStore, SeqRange},
};

/// Builder for filtering events from a timeline.
///
/// Construct via [`EventQuery::on`], chain filter methods, then call
/// [`EventQuery::execute`] to run the query against any [`EventStore`].
#[derive(Clone, Debug, Default)]
pub struct EventQuery {
    timeline: TimelineId,
    from_seq: Option<Seq>,
    to_seq: Option<Seq>,
    entity_filter: Option<EntityId>,
    event_type_filter: Option<String>,
}

impl EventQuery {
    /// Create a new query targeting the given timeline.
    #[must_use]
    pub const fn on(timeline: TimelineId) -> Self {
        Self {
            timeline,
            from_seq: None,
            to_seq: None,
            entity_filter: None,
            event_type_filter: None,
        }
    }

    /// Only return events at or after `seq`.
    #[must_use]
    pub const fn from_seq(mut self, seq: Seq) -> Self {
        self.from_seq = Some(seq);
        self
    }

    /// Only return events at or before `seq`.
    #[must_use]
    pub const fn to_seq(mut self, seq: Seq) -> Self {
        self.to_seq = Some(seq);
        self
    }

    /// Only return events whose `entity` matches `entity`.
    #[must_use]
    pub const fn for_entity(mut self, entity: EntityId) -> Self {
        self.entity_filter = Some(entity);
        self
    }

    /// Only return events whose `event_type` matches `event_type`.
    #[must_use]
    pub fn of_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type_filter = Some(event_type.into());
        self
    }

    /// Execute the query against `store`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
    pub fn execute(&self, store: &dyn EventStore) -> Result<Vec<Event>, CoreError> {
        let range = match (self.from_seq, self.to_seq) {
            (Some(from), Some(to)) => SeqRange::bounded(from, to),
            (Some(from), None) => SeqRange::from_seq(from),
            (None, Some(to)) => SeqRange::bounded(Seq::ZERO, to),
            (None, None) => SeqRange::all(),
        };

        let events = store.read(self.timeline, range)?;

        let events = if let Some(entity) = self.entity_filter {
            events.into_iter().filter(|e| e.entity == entity).collect()
        } else {
            events
        };

        let events = if let Some(ref event_type) = self.event_type_filter {
            events
                .into_iter()
                .filter(|e| e.event_type.as_str() == event_type.as_str())
                .collect()
        } else {
            events
        };

        Ok(events)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        clock::Seq,
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
    };
    use pos_store::{open_store, StoreConfig};

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected query fixture error: {error:?}"
                )))
            })
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing query fixture value"))
            })
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn make_draft(entity: EntityId, event_type: &str) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new(event_type),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn setup_store() -> (Box<dyn EventStore>, TimelineId, EntityId, EntityId) {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("test").test_ok();
        let entity_a = EntityId::new();
        let entity_b = EntityId::new();

        let drafts = vec![
            make_draft(entity_a, "type.a"),
            make_draft(entity_a, "type.b"),
            make_draft(entity_b, "type.a"),
            make_draft(entity_b, "type.c"),
        ];
        store.append(tl.id(), &drafts).test_ok();

        (store, tl.id(), entity_a, entity_b)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_returns_all_events_with_no_filters() {
        let (store, tl_id, _, _) = setup_store();
        let events = EventQuery::on(tl_id).execute(&*store).test_ok();
        assert_eq!(events.len(), 4);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_filters_by_entity() {
        let (store, tl_id, entity_a, _) = setup_store();
        let events = EventQuery::on(tl_id)
            .for_entity(entity_a)
            .execute(&*store)
            .test_ok();
        assert_eq!(events.len(), 2);
        for e in &events {
            assert_eq!(e.entity, entity_a);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_filters_by_event_type() {
        let (store, tl_id, _, _) = setup_store();
        let events = EventQuery::on(tl_id)
            .of_type("type.a")
            .execute(&*store)
            .test_ok();
        assert_eq!(events.len(), 2);
        for e in &events {
            assert_eq!(e.event_type.as_str(), "type.a");
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_filters_by_seq_range() {
        let (store, tl_id, _, _) = setup_store();
        // Seqs are 1-indexed; get seqs 2 and 3 only
        let events = EventQuery::on(tl_id)
            .from_seq(Seq::from_u64(2))
            .to_seq(Seq::from_u64(3))
            .execute(&*store)
            .test_ok();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, Seq::from_u64(2));
        assert_eq!(events[1].seq, Seq::from_u64(3));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_combined_filters() {
        let (store, tl_id, entity_a, _) = setup_store();
        let events = EventQuery::on(tl_id)
            .for_entity(entity_a)
            .of_type("type.a")
            .execute(&*store)
            .test_ok();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].entity, entity_a);
        assert_eq!(events[0].event_type.as_str(), "type.a");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_unknown_timeline_returns_error() {
        let store = open_store(StoreConfig::Memory).test_ok();
        let unknown_tl = TimelineId::new();
        let result = EventQuery::on(unknown_tl).execute(&*store);
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_builder_default() {
        let tl = TimelineId::new();
        let q = EventQuery::on(tl);
        assert!(q.from_seq.is_none());
        assert!(q.to_seq.is_none());
        assert!(q.entity_filter.is_none());
        assert!(q.event_type_filter.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_filters_by_from_seq_only() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5).map(|_| make_draft(entity, "test.event")).collect();
        let committed = store.append(tl.id(), &drafts).test_ok();
        let third_seq = committed[2].seq;
        // from_seq only: returns events from seq 3 onward (events 3, 4, 5)
        let events = EventQuery::on(tl.id())
            .from_seq(third_seq)
            .execute(store.as_ref())
            .test_ok();
        assert_eq!(events.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_query_filters_by_to_seq_only() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5).map(|_| make_draft(entity, "test.event")).collect();
        let committed = store.append(tl.id(), &drafts).test_ok();
        let third_seq = committed[2].seq;
        let events = EventQuery::on(tl.id())
            .to_seq(third_seq)
            .execute(store.as_ref())
            .test_ok();
        assert_eq!(events.len(), 3);
    }
}
