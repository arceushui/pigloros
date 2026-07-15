//! Replay events from an `EventStore` through a `ProjectionRegistry`.

use pos_core::{CoreError, Seq, TimelineId};
use pos_core::store::{EventStore, SeqRange};
use pos_state::ProjectionRegistry;

/// Replay **all** events on `timeline` through every reducer in `registry`.
///
/// Events are read with [`SeqRange::all`] and then folded via
/// [`ProjectionRegistry::fold_events`]. An empty timeline is a no-op.
///
/// # Errors
/// Propagates [`CoreError`] from the underlying store.
pub fn replay(
    store: &dyn EventStore,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
) -> Result<(), CoreError> {
    let events = store.read(timeline, SeqRange::all())?;
    registry.fold_events(&events);
    Ok(())
}

/// Replay events up to and **including** `at_seq` on `timeline`.
///
/// Reads [`SeqRange::bounded`]`(Seq::ZERO, at_seq)` and folds through `registry`.
///
/// # Errors
/// Propagates [`CoreError`] from the underlying store.
pub fn replay_at(
    store: &dyn EventStore,
    timeline: TimelineId,
    at_seq: Seq,
    registry: &mut ProjectionRegistry,
) -> Result<(), CoreError> {
    let events = store.read(timeline, SeqRange::bounded(Seq::ZERO, at_seq))?;
    registry.fold_events(&events);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::WallTime,
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId},
        Event, Reducer, State,
    };
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};
    use proptest::prelude::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            let mut s = State::new();
            s.set("n", serde_json::json!(0u64));
            s
        }

        fn apply(&self, state: &mut State, _event: &Event) {
            let n = state.get("n").and_then(serde_json::Value::as_u64).unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(entity, Kind::new("test.tick"), CanonicalBytes::from_vec(vec![]))
    }

    fn make_event(entity: EntityId, seq: u64) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn count_for(reg: &ProjectionRegistry, entity: &EntityId) -> u64 {
        reg.state_for(entity)
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn replay_empty_timeline_is_noop() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("empty").unwrap();
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));

        replay(store.as_ref(), tl.id(), &mut reg).unwrap();

        // No entities seen — state_for returns None (count is zero).
        let entity = EntityId::new();
        assert_eq!(count_for(&reg, &entity), 0);
    }

    #[test]
    fn replay_full_timeline_folds_all_events() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("full").unwrap();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..5).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();

        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        replay(store.as_ref(), tl.id(), &mut reg).unwrap();

        assert_eq!(count_for(&reg, &entity), 5);
    }

    #[test]
    fn replay_at_seq_stops_at_boundary() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("partial").unwrap();
        let entity = EntityId::new();

        // Append 6 events; we only want to replay the first 3.
        let drafts: Vec<EventDraft> = (0..6).map(|_| draft(entity)).collect();
        let committed = store.append(tl.id(), &drafts).unwrap();
        // seq of the 3rd event (0-indexed = 2, but seqs are 1-based in MemoryStore)
        let third_seq = committed[2].seq;

        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        replay_at(store.as_ref(), tl.id(), third_seq, &mut reg).unwrap();

        assert_eq!(count_for(&reg, &entity), 3);
    }

    proptest! {
        #[test]
        fn replay_is_deterministic(event_count in 0usize..20) {
            let mut store = open_store(StoreConfig::Memory).unwrap();
            let tl = store.create_timeline("det").unwrap();
            let entity = EntityId::new();

            // Pre-populate with events built directly so we don't need mut store later.
            let events: Vec<Event> = (0..event_count)
                .map(|i| make_event(entity, (i + 1) as u64))
                .collect();

            // We build a registry using the raw events directly (avoids store borrow issues).
            let mut reg1 = ProjectionRegistry::new();
            reg1.register("count", Box::new(CountReducer));
            reg1.fold_events(&events);

            let mut reg2 = ProjectionRegistry::new();
            reg2.register("count", Box::new(CountReducer));
            reg2.fold_events(&events);

            let c1 = count_for(&reg1, &entity);
            let c2 = count_for(&reg2, &entity);
            prop_assert_eq!(c1, c2);
            prop_assert_eq!(c1, event_count as u64);

            // Also exercise the store-based replay path.
            let drafts: Vec<EventDraft> = (0..event_count).map(|_| draft(entity)).collect();
            if !drafts.is_empty() {
                store.append(tl.id(), &drafts).unwrap();
            }
            let mut reg3 = ProjectionRegistry::new();
            reg3.register("count", Box::new(CountReducer));
            replay(store.as_ref(), tl.id(), &mut reg3).unwrap();
            prop_assert_eq!(count_for(&reg3, &entity), event_count as u64);
        }
    }
}
