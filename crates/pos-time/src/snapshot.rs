//! Timeline snapshots: capture state at the current head and verify consistency.

use pos_core::{CoreError, EntityId, Reducer, Seq, StateRegistry, TimelineId};
use pos_core::store::{EventStore, SeqRange};

/// A snapshot of all entity states at a specific sequence number on a timeline.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    /// The timeline this snapshot was taken from.
    pub timeline: TimelineId,
    /// The sequence number at which the snapshot was taken (inclusive).
    pub at_seq: Seq,
    /// Per-entity state at `at_seq`.
    pub state: StateRegistry,
}

/// Take a snapshot of the current head of `timeline`.
///
/// Each `(name, reducer)` pair in `reducers` is folded over all events on the
/// timeline. The resulting `StateRegistry` is captured inside the `Snapshot`.
///
/// # Errors
/// Propagates [`CoreError`] from the underlying store.
pub fn snapshot(
    store: &dyn EventStore,
    timeline: TimelineId,
    reducers: &[(&str, Box<dyn Reducer>)],
) -> Result<Snapshot, CoreError> {
    let events = store.read(timeline, SeqRange::all())?;
    let at_seq = events
        .last()
        .map_or(Seq::ZERO, |e| e.seq);

    let mut registry = StateRegistry::new();
    for event in &events {
        for (_, reducer) in reducers {
            registry.apply(reducer.as_ref(), event);
        }
    }

    Ok(Snapshot {
        timeline,
        at_seq,
        state: registry,
    })
}

/// Error type for snapshot consistency checks.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// A store I/O error occurred.
    #[error("store error: {0}")]
    Store(#[from] CoreError),
    /// The snapshot and full-replay state disagree for an entity.
    #[error("snapshot inconsistent: entity {entity:?} differs")]
    Inconsistent { entity: EntityId },
}

/// Verify that `snapshot` + tail events produces the same state as a full replay.
///
/// Steps:
/// 1. Read events after `snapshot.at_seq` (the "tail").
/// 2. Clone `snapshot.state` and fold the tail through `reducers`.
/// 3. Do a full replay from seq 0 through `reducers`.
/// 4. Compare both `StateRegistry` instances; return `Err(Inconsistent)` on mismatch.
///
/// # Errors
/// Returns [`SnapshotError::Store`] on I/O failure or
/// [`SnapshotError::Inconsistent`] if the states differ.
pub fn verify_snapshot_consistency(
    store: &dyn EventStore,
    snap: &Snapshot,
    reducers: &[(&str, Box<dyn Reducer>)],
) -> Result<(), SnapshotError> {
    // --- 1. Build state by cloning the snapshot and folding the tail ----------
    let tail_range = SeqRange::from_seq(snap.at_seq.next());
    let tail_events = store.read(snap.timeline, tail_range)?;

    let mut incremental = snap.state.clone();
    for event in &tail_events {
        for (_, reducer) in reducers {
            incremental.apply(reducer.as_ref(), event);
        }
    }

    // --- 2. Full replay from seq 0 -------------------------------------------
    let all_events = store.read(snap.timeline, SeqRange::all())?;
    let mut full = StateRegistry::new();
    for event in &all_events {
        for (_, reducer) in reducers {
            full.apply(reducer.as_ref(), event);
        }
    }

    // --- 3. Compare ----------------------------------------------------------
    // Collect all entity IDs seen in either registry.
    let mut all_entities: std::collections::HashSet<EntityId> =
        std::collections::HashSet::new();
    // We compare by iterating through the full replay (which has all entities).
    // We access incremental's state via get_or_default.
    for event in &all_events {
        all_entities.insert(event.entity);
    }

    for entity in all_entities {
        let inc_state = incremental.get_or_default(&entity);
        let full_state = full.get_or_default(&entity);
        if inc_state != full_state {
            return Err(SnapshotError::Inconsistent { entity });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
        Event, Reducer, State,
    };
    use pos_store::{open_store, StoreConfig};

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

    fn reducers() -> Vec<(&'static str, Box<dyn Reducer>)> {
        vec![("count", Box::new(CountReducer))]
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(entity, Kind::new("test.tick"), CanonicalBytes::from_vec(vec![]))
    }

    fn count_in_registry(reg: &StateRegistry, entity: &EntityId) -> u64 {
        reg.get(entity)
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_captures_state_at_head() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("snap").unwrap();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..4).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();

        let snap = snapshot(store.as_ref(), tl.id(), &reducers()).unwrap();

        // State should show 4 events applied.
        assert_eq!(count_in_registry(&snap.state, &entity), 4);
        // at_seq should be the seq of the 4th event (non-zero).
        assert!(snap.at_seq > Seq::ZERO);
        assert_eq!(snap.timeline, tl.id());
    }

    #[test]
    fn verify_snapshot_consistency_passes_on_fresh_store() {
        // No tail events: snapshot IS the full replay.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("consistent").unwrap();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();

        let snap = snapshot(store.as_ref(), tl.id(), &reducers()).unwrap();
        verify_snapshot_consistency(store.as_ref(), &snap, &reducers()).unwrap();
    }

    #[test]
    fn verify_snapshot_consistency_with_tail_events() {
        // Take a snapshot, then append more events. Verification should still pass.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("with-tail").unwrap();
        let entity = EntityId::new();

        // Initial 3 events -> snapshot
        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();
        let snap = snapshot(store.as_ref(), tl.id(), &reducers()).unwrap();

        // Append 2 more events after the snapshot.
        let tail: Vec<EventDraft> = (0..2).map(|_| draft(entity)).collect();
        store.append(tl.id(), &tail).unwrap();

        // Consistency should hold: snapshot(3) + tail(2) == full replay(5).
        verify_snapshot_consistency(store.as_ref(), &snap, &reducers()).unwrap();
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use pos_core::{
        clock::WallTime,
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId},
        Event, Reducer, State,
    };
    use pos_store::{open_store, StoreConfig};

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State { State::new() }
        fn apply(&self, state: &mut State, _event: &Event) {
            let n = state.get("n").and_then(serde_json::Value::as_u64).unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn reducers() -> Vec<(&'static str, Box<dyn Reducer>)> {
        vec![("count", Box::new(CountReducer))]
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(entity, Kind::new("t"), CanonicalBytes::from_vec(vec![]))
    }

    #[test]
    fn verify_snapshot_consistency_detects_corrupted_snapshot() {
        // Covers the Err(Inconsistent) branch in verify_snapshot_consistency.
        // Build a valid snapshot, then manually corrupt its state before verifying.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();

        store.append(tl.id(), &[draft(entity)]).unwrap();
        let mut snap = snapshot(store.as_ref(), tl.id(), &reducers()).unwrap();

        // Corrupt the snapshot state by resetting entity count to a wrong value.
        snap.state.apply(&CountReducer, &Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("corrupt"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: pos_core::clock::Seq::from_u64(999),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        });

        // Now the snapshot state differs from full replay — should detect inconsistency.
        let result = verify_snapshot_consistency(store.as_ref(), &snap, &reducers());
        assert!(result.is_err(), "corrupted snapshot should fail consistency check");
    }
}
