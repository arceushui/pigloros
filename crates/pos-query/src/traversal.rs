use std::collections::HashMap;

use pos_core::{
    error::CoreError,
    event::Event,
    ids::{EntityId, EventId, TimelineId},
    store::{EventStore, SeqRange},
};

/// Trace all relationship events involving `entity` (as source or target).
///
/// Reads all events on `timeline`, then returns those whose `event_type` equals
/// `relationship_event_type`. Results are sorted by event `seq` for determinism.
///
/// Note: actual relationship semantics (which fields encode source/target) are
/// plugin-defined. This function returns the raw matching events.
///
/// # Errors
///
/// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
pub fn trace_relationships(
    store: &dyn EventStore,
    timeline: TimelineId,
    entity: EntityId,
    relationship_event_type: &str,
) -> Result<Vec<Event>, CoreError> {
    let all = store.read(timeline, SeqRange::all())?;

    // Filter to events of the relationship type whose entity matches.
    // Plugin-defined payloads encode source/target; we filter on entity field only.
    let mut matching: Vec<Event> = all
        .into_iter()
        .filter(|e| e.event_type.as_str() == relationship_event_type && e.entity == entity)
        .collect();

    // Sort by seq for determinism.
    matching.sort_by_key(|e| e.seq);

    Ok(matching)
}

/// Walk the causation chain backwards from `event_id`.
///
/// Returns events in causal order: oldest root cause first, ending at the
/// event identified by `event_id`. If `event_id` does not exist in the store,
/// returns an empty `Vec`.
///
/// Stops when `causation_id` is `None`.
///
/// # Errors
///
/// Returns [`CoreError::TimelineNotFound`] if the timeline does not exist.
pub fn causal_chain(
    store: &dyn EventStore,
    timeline: TimelineId,
    event_id: EventId,
) -> Result<Vec<Event>, CoreError> {
    let all = store.read(timeline, SeqRange::all())?;

    // Build an index by EventId.
    let index: HashMap<EventId, Event> = all.into_iter().map(|e| (e.id, e)).collect();

    // If the starting event doesn't exist, return empty.
    if !index.contains_key(&event_id) {
        return Ok(Vec::new());
    }

    // Walk backwards following causation_id.
    let mut chain: Vec<Event> = Vec::new();
    let mut current_id = Some(event_id);

    while let Some(id) = current_id {
        if let Some(event) = index.get(&id) {
            let next = event.causation_id;
            chain.push(event.clone());
            current_id = next;
        } else {
            // causation_id points to an event not on this timeline; stop.
            break;
        }
    }

    // Reverse so oldest cause comes first.
    chain.reverse();
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, EventId},
    };
    use pos_store::{open_store, StoreConfig};

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected traversal fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing traversal fixture value"))
            })
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful traversal fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    fn make_draft(entity: EntityId, event_type: &str) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new(event_type),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    fn make_draft_with_cause(entity: EntityId, event_type: &str, cause: EventId) -> EventDraft {
        let mut d = make_draft(entity, event_type);
        d.causation_id = Some(cause);
        d
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn causal_chain_single_event_no_cause() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("causal").test_ok();
        let entity = EntityId::new();
        let events = store
            .append(tl.id(), &[make_draft(entity, "root.event")])
            .test_ok();
        let root = &events[0];

        let chain = causal_chain(&*store, tl.id(), root.id).test_ok();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].id, root.id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn causal_chain_follows_causation_ids() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("causal").test_ok();
        let entity = EntityId::new();

        // Append root event.
        let root_events = store
            .append(tl.id(), &[make_draft(entity, "root.event")])
            .test_ok();
        let root = root_events[0].clone();

        // Append middle event caused by root.
        let mid_events = store
            .append(
                tl.id(),
                &[make_draft_with_cause(entity, "mid.event", root.id)],
            )
            .test_ok();
        let mid = mid_events[0].clone();

        // Append leaf event caused by mid.
        let leaf_events = store
            .append(
                tl.id(),
                &[make_draft_with_cause(entity, "leaf.event", mid.id)],
            )
            .test_ok();
        let leaf = leaf_events[0].clone();

        let chain = causal_chain(&*store, tl.id(), leaf.id).test_ok();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].id, root.id, "oldest cause should be first");
        assert_eq!(chain[1].id, mid.id);
        assert_eq!(chain[2].id, leaf.id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn causal_chain_unknown_event_returns_empty() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("causal").test_ok();
        let missing_id = EventId::new();

        let chain = causal_chain(&*store, tl.id(), missing_id).test_ok();
        assert!(chain.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trace_relationships_returns_matching_events() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("rel").test_ok();
        let entity = EntityId::new();

        let drafts = vec![
            make_draft(entity, "entity.action"),
            make_draft(entity, "relationship.link"),
            make_draft(entity, "relationship.link"),
            make_draft(entity, "entity.action"),
        ];
        store.append(tl.id(), &drafts).test_ok();

        let rels = trace_relationships(&*store, tl.id(), entity, "relationship.link").test_ok();
        assert_eq!(rels.len(), 2);
        for e in &rels {
            assert_eq!(e.event_type.as_str(), "relationship.link");
            assert_eq!(e.entity, entity);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trace_relationships_empty_when_no_match() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("rel").test_ok();
        let entity = EntityId::new();

        store
            .append(tl.id(), &[make_draft(entity, "entity.action")])
            .test_ok();

        let rels = trace_relationships(&*store, tl.id(), entity, "relationship.link").test_ok();
        assert!(rels.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn causal_chain_stops_at_broken_causation_link() {
        // Covers the `else { break }` branch: causation_id points to an event
        // not present in the store (e.g. it was on a different timeline).
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();

        // First event has a causation_id that won't exist in the store.
        let phantom_cause = EventId::new();
        let mut draft = make_draft(entity, "test.event");
        draft.causation_id = Some(phantom_cause);
        let committed = store.append(tl.id(), &[draft]).test_ok();

        // causal_chain should return just the one event (can't follow the broken link).
        let chain = causal_chain(&*store, tl.id(), committed[0].id).test_ok();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].id, committed[0].id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn trace_relationships_unknown_timeline_returns_error() {
        let store = open_store(StoreConfig::Memory).test_ok();
        let unknown = TimelineId::new();
        let entity = EntityId::new();
        let err = trace_relationships(&*store, unknown, entity, "relationship.link").test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn causal_chain_unknown_timeline_returns_error() {
        let store = open_store(StoreConfig::Memory).test_ok();
        let unknown = TimelineId::new();
        let err = causal_chain(&*store, unknown, EventId::new()).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }
}
