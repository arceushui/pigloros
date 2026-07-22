//! Timeline snapshots: capture state at the current head and verify consistency.

use std::collections::{HashMap, HashSet};

use pos_core::store::{EventStore, SeqRange};
use pos_core::{CoreError, EntityId, Seq, StateRegistry, TimelineId};
use pos_state::ProjectionRegistry;

/// A snapshot of all per-reducer entity states at a specific sequence number
/// on a timeline.
///
/// The `registry` field is a map from reducer name → [`StateRegistry`] that
/// mirrors the full [`ProjectionRegistry`] state at capture time. It is kept
/// serialisable so snapshots can be persisted and loaded without re-running
/// every registered reducer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    /// The timeline this snapshot was taken from.
    pub timeline: TimelineId,
    /// The sequence number at which the snapshot was taken (inclusive).
    pub at_seq: Seq,
    /// Per-reducer, per-entity state at `at_seq`.
    pub registry: HashMap<String, StateRegistry>,
}

/// Take a snapshot of the current head of `timeline`.
///
/// All events on the timeline are folded through every reducer registered in
/// `registry`. The resulting per-reducer state is captured inside the returned
/// [`Snapshot`].
///
/// # Errors
/// Propagates [`CoreError`] from the underlying store.
pub fn snapshot(
    store: &dyn EventStore,
    timeline: TimelineId,
    registry: &mut ProjectionRegistry,
) -> Result<Snapshot, CoreError> {
    let events = store.read(timeline, SeqRange::all())?;
    let at_seq = events.last().map_or(Seq::ZERO, |e| e.seq);

    registry.fold_events(&events);

    Ok(Snapshot {
        timeline,
        at_seq,
        registry: registry.state_snapshot(),
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
/// 1. Read events after `snapshot.at_seq` (the "tail") and all events.
/// 2. Restore `registry` to `snap.registry` state, then fold the tail to build
///    the incremental projection.
/// 3. Reset `registry` to empty and fold all events to build the full-replay
///    reference projection.
/// 4. Compare both state maps; return `Err(Inconsistent)` on any mismatch.
///
/// `registry` must be pre-populated with the same reducers used when the
/// snapshot was originally taken. Its accumulated state is managed internally
/// and will be in the full-replay state when this function returns.
///
/// # Errors
/// Returns [`SnapshotError::Store`] on I/O failure or
/// [`SnapshotError::Inconsistent`] if the states differ.
pub fn verify_snapshot_consistency(
    store: &dyn EventStore,
    snap: &Snapshot,
    registry: &mut ProjectionRegistry,
) -> Result<(), SnapshotError> {
    // --- 1. Read events -------------------------------------------------------
    let tail_range = SeqRange::from_seq(snap.at_seq.next());
    let tail_events = store.read(snap.timeline, tail_range)?;
    let all_events = store.read(snap.timeline, SeqRange::all())?;

    // Collect all entity IDs seen across all events.
    let all_entities: Vec<EntityId> = all_events
        .iter()
        .map(|e| e.entity)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // --- 2. Incremental path: snap.registry state + tail fold -----------------
    registry.restore_from_snapshot(&snap.registry);
    registry.fold_events(&tail_events);
    let inc_state = registry.state_snapshot();

    // --- 3. Full replay path: clean slate + all events -----------------------
    registry.clear_state();
    registry.fold_events(&all_events);
    let full_state = registry.state_snapshot();

    // --- 4. Compare -----------------------------------------------------------
    for entity in &all_entities {
        for name in full_state.keys() {
            let inc_reg = inc_state.get(name).cloned().unwrap_or_default();
            let full_reg = full_state.get(name).cloned().unwrap_or_default();
            if inc_reg.get_or_default(entity) != full_reg.get_or_default(entity) {
                return Err(SnapshotError::Inconsistent { entity: *entity });
            }
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
    use pos_state::{EntityStateProjection, ProjectionRegistry};
    use pos_store::{open_store, StoreConfig};

    struct ReadFailStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl pos_core::store::EventStore for ReadFailStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("read failed".to_owned()))
        }

        fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {

            self.read(timeline, range)

        }


        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn create_timeline_with_meta(
            &mut self,
            _: pos_core::timeline::TimelineMeta,
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "create_timeline_with_meta not supported by this store".to_owned(),
            ))
        }
        fn append_committed(
            &mut self,
            _: pos_core::TimelineId,
            _: &[pos_core::Event],
        ) -> Result<(), pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "append_committed not supported by this store".to_owned(),
            ))
        }

        fn delete_timeline(
            &mut self,
            _: pos_core::TimelineId,
        ) -> Result<(), pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "delete_timeline not supported by this store".to_owned(),
            ))
        }
        fn chain_hash_at(
            &self,
            _: pos_core::TimelineId,
            _: pos_core::Seq,
        ) -> Result<pos_core::Hash, pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "chain_hash_at not supported by this store".to_owned(),
            ))
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            let mut s = State::new();
            s.set("n", serde_json::json!(0u64));
            s
        }

        fn apply(&self, state: &mut State, _event: &Event) {
            let n = state
                .get("n")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn make_registry() -> ProjectionRegistry {
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        reg
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.tick"),
            CanonicalBytes::from_vec(vec![]),
        )
    }

    fn count_in_snapshot(snap: &Snapshot, entity: &EntityId) -> u64 {
        snap.registry
            .get("count")
            .and_then(|r| r.get(entity))
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_captures_state_at_head() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("snap").unwrap();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..4).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();

        let mut reg = make_registry();
        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).unwrap();

        // State should show 4 events applied.
        assert_eq!(count_in_snapshot(&snap, &entity), 4);
        // at_seq should be the seq of the 4th event (non-zero).
        assert!(snap.at_seq > Seq::ZERO);
        assert_eq!(snap.timeline, tl.id());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_passes_on_fresh_store() {
        // No tail events: snapshot IS the full replay.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("consistent").unwrap();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();

        let mut reg = make_registry();
        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).unwrap();

        let mut verify_reg = make_registry();
        verify_snapshot_consistency(store.as_ref(), &snap, &mut verify_reg).unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_with_tail_events() {
        // Take a snapshot, then append more events. Verification should still pass.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("with-tail").unwrap();
        let entity = EntityId::new();

        // Initial 3 events -> snapshot
        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();
        let mut reg = make_registry();
        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).unwrap();

        // Append 2 more events after the snapshot.
        let tail: Vec<EventDraft> = (0..2).map(|_| draft(entity)).collect();
        store.append(tl.id(), &tail).unwrap();

        // Consistency should hold: snapshot(3) + tail(2) == full replay(5).
        let mut verify_reg = make_registry();
        verify_snapshot_consistency(store.as_ref(), &snap, &mut verify_reg).unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_isolates_multiple_reducers() {
        // Register two reducers — their states should be tracked independently.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("multi-reducer").unwrap();
        let entity = EntityId::new();

        let drafts: Vec<EventDraft> = (0..5).map(|_| draft(entity)).collect();
        store.append(tl.id(), &drafts).unwrap();

        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        reg.register("entity_state", Box::new(EntityStateProjection));

        let snap = snapshot(store.as_ref(), tl.id(), &mut reg).unwrap();

        // "count" reducer sees n=5.
        assert_eq!(count_in_snapshot(&snap, &entity), 5);
        // "entity_state" reducer also tracks independently.
        let ec = snap
            .registry
            .get("entity_state")
            .and_then(|r| r.get(&entity))
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(ec, 5, "entity_state should count 5 events independently");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_read_err_propagates() {
        let store = ReadFailStore;
        let mut reg = make_registry();
        let err = snapshot(&store, TimelineId::new(), &mut reg).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
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
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};

    struct ReadFailStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl pos_core::store::EventStore for ReadFailStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn read(&self, _: TimelineId, _: SeqRange) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("read failed".to_owned()))
        }

        fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {

            self.read(timeline, range)

        }


        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn create_timeline_with_meta(
            &mut self,
            _: pos_core::timeline::TimelineMeta,
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "create_timeline_with_meta not supported by this store".to_owned(),
            ))
        }
        fn append_committed(
            &mut self,
            _: pos_core::TimelineId,
            _: &[pos_core::Event],
        ) -> Result<(), pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "append_committed not supported by this store".to_owned(),
            ))
        }

        fn delete_timeline(
            &mut self,
            _: pos_core::TimelineId,
        ) -> Result<(), pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "delete_timeline not supported by this store".to_owned(),
            ))
        }
        fn chain_hash_at(
            &self,
            _: pos_core::TimelineId,
            _: pos_core::Seq,
        ) -> Result<pos_core::Hash, pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "chain_hash_at not supported by this store".to_owned(),
            ))
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }

    /// Fails only on `SeqRange::all()` reads (second read in verify).
    struct ReadFailOnAllEventsStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl pos_core::store::EventStore for ReadFailOnAllEventsStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn read(&self, _: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if range.from == Seq::ZERO && range.to.is_none() {
                return Err(CoreError::Storage("all-events read failed".to_owned()));
            }
            Ok(vec![])
        }

        fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {

            self.read(timeline, range)

        }


        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Err(CoreError::Storage("unused".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn create_timeline_with_meta(
            &mut self,
            _: pos_core::timeline::TimelineMeta,
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "create_timeline_with_meta not supported by this store".to_owned(),
            ))
        }
        fn append_committed(
            &mut self,
            _: pos_core::TimelineId,
            _: &[pos_core::Event],
        ) -> Result<(), pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "append_committed not supported by this store".to_owned(),
            ))
        }

        fn delete_timeline(
            &mut self,
            _: pos_core::TimelineId,
        ) -> Result<(), pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "delete_timeline not supported by this store".to_owned(),
            ))
        }
        fn chain_hash_at(
            &self,
            _: pos_core::TimelineId,
            _: pos_core::Seq,
        ) -> Result<pos_core::Hash, pos_core::CoreError> {
            Err(pos_core::CoreError::Storage(
                "chain_hash_at not supported by this store".to_owned(),
            ))
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, pos_core::CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            State::new()
        }
        fn apply(&self, state: &mut State, _event: &Event) {
            let n = state
                .get("n")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn make_registry() -> ProjectionRegistry {
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        reg
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(entity, Kind::new("t"), CanonicalBytes::from_vec(vec![]))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_detects_corrupted_snapshot() {
        // Covers the case where snapshot.registry has been tampered with.
        // Build a valid snapshot via normal snapshot(), then manually corrupt
        // the registry map before verifying.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();

        store.append(tl.id(), &[draft(entity)]).unwrap();
        let mut reg = make_registry();
        let mut snap = snapshot(store.as_ref(), tl.id(), &mut reg).unwrap();

        // Corrupt the snapshot by injecting a bogus extra count for the entity.
        if let Some(count_reg) = snap.registry.get_mut("count") {
            count_reg.apply(
                &CountReducer,
                &Event {
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
                },
            );
        }

        // Now the snapshot registry state (2 events) differs from a full replay (1 event).
        // verify_snapshot_consistency must detect the inconsistency.
        let mut verify_reg = make_registry();
        let result = verify_snapshot_consistency(store.as_ref(), &snap, &mut verify_reg);
        assert!(
            result.is_err(),
            "corrupted snapshot should fail consistency check"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_read_err_propagates() {
        let store = ReadFailStore;
        let snap = Snapshot {
            timeline: TimelineId::new(),
            at_seq: Seq::ZERO,
            registry: HashMap::new(),
        };
        let mut reg = make_registry();
        let err = verify_snapshot_consistency(&store, &snap, &mut reg).unwrap_err();
        assert!(matches!(err, SnapshotError::Store(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_snapshot_consistency_all_events_read_err_propagates() {
        let store = ReadFailOnAllEventsStore;
        let snap = Snapshot {
            timeline: TimelineId::new(),
            at_seq: Seq::ZERO,
            registry: HashMap::new(),
        };
        let mut reg = make_registry();
        let err = verify_snapshot_consistency(&store, &snap, &mut reg).unwrap_err();
        assert!(matches!(err, SnapshotError::Store(_)));
    }
}
