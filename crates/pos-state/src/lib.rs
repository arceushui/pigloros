#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-state` — projection layer over the `pos-core` primitives.
//!
//! Provides:
//! - [`ProjectionRegistry`]: a named registry of [`Reducer`] implementations.
//! - [`EntityStateProjection`]: a built-in `Reducer` that folds event metadata per entity.
//! - [`RelationshipIndex`]: an adjacency index for directed [`Relationship`] values.
//!
//! No I/O, no async.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use std::collections::HashMap;

use pos_core::{
    ConsentRevocationFoldListener, ConsentRevoked, EntityId, Event, Reducer, Relationship, State,
    StateRegistry, EVENT_TYPE_CONSENT_REVOKED_V1,
};

// ---------------------------------------------------------------------------
// EntityStateProjection
// ---------------------------------------------------------------------------

/// A [`Reducer`] that folds each event into minimal per-entity state.
///
/// After each event the state contains:
/// - `"last_event_type"`: the event-type string of the most-recent event.
/// - `"event_count"`: the running count of events applied to this entity.
#[derive(Clone, Debug, Default)]
pub struct EntityStateProjection;

impl Reducer for EntityStateProjection {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        // Increment event counter.
        let count = state
            .get("event_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("event_count", serde_json::Value::Number((count + 1).into()));
        // Record the event type.
        state.set(
            "last_event_type",
            serde_json::Value::String(event.event_type.as_str().to_owned()),
        );
    }
}

// ---------------------------------------------------------------------------
// ProjectionRegistry
// ---------------------------------------------------------------------------

/// One named slot inside the registry.
struct Slot {
    reducer: Box<dyn Reducer>,
    registry: StateRegistry,
}

/// A named registry of [`Reducer`] implementations backed by per-name [`StateRegistry`]s.
///
/// Plugins register reducers during Wave 3 initialisation; the registry then
/// applies every incoming event to every registered reducer in insertion order.
#[derive(Default)]
pub struct ProjectionRegistry {
    /// Ordered list so iteration is deterministic.
    slots: Vec<(String, Slot)>,
}

impl std::fmt::Debug for ProjectionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = Vec::with_capacity(self.slots.len());
        for (name, _) in &self.slots {
            names.push(name.as_str());
        }
        f.debug_struct("ProjectionRegistry")
            .field("reducers", &names)
            .finish()
    }
}

impl ProjectionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named reducer.
    ///
    /// If a reducer with the same name was already registered it is replaced and
    /// its accumulated state is cleared.
    pub fn register(&mut self, name: &str, reducer: Box<dyn Reducer>) {
        // Remove any previous entry with the same name.
        self.slots.retain(|(n, _)| n != name);
        self.slots.push((
            name.to_owned(),
            Slot {
                reducer,
                registry: StateRegistry::new(),
            },
        ));
    }

    /// Apply a single event to every registered reducer.
    pub fn apply_event(&mut self, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_CONSENT_REVOKED_V1 {
            if let Ok(revocation) = ConsentRevoked::decode(&event.payload) {
                self.on_consent_revoked(revocation.subject_id, revocation.fence_seq);
            }
            return;
        }
        // Consent is host control-plane state.  It is never reducer input and
        // therefore cannot become a Plugin-visible projection or snapshot.
        if pos_core::is_consent_event_type(&event.event_type) {
            return;
        }
        if pos_core::is_geographic_event_type(&event.event_type) {
            return;
        }
        for (_, slot) in &mut self.slots {
            slot.registry.apply(slot.reducer.as_ref(), event);
        }
    }

    /// Batch-fold a slice of events into every registered reducer.
    pub fn fold_events(&mut self, events: &[Event]) {
        for event in events {
            self.apply_event(event);
        }
    }

    /// Return the state for a given entity from the **first** registered reducer.
    ///
    /// Returns `None` if no reducers have been registered or the entity is unknown.
    /// To query a specific reducer use [`Self::state_for_reducer`].
    #[must_use]
    pub fn state_for(&self, entity: &EntityId) -> Option<&State> {
        self.slots
            .first()
            .and_then(|(_, slot)| slot.registry.get(entity))
    }

    /// Return the state for a given entity from the reducer identified by `name`.
    #[must_use]
    pub fn state_for_reducer(&self, name: &str, entity: &EntityId) -> Option<&State> {
        self.slots
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, slot)| slot.registry.get(entity))
    }

    /// Return the names of all registered reducers in insertion order.
    #[must_use]
    pub fn reducer_names(&self) -> Vec<&str> {
        let mut names = Vec::with_capacity(self.slots.len());
        for (name, _) in &self.slots {
            names.push(name.as_str());
        }
        names
    }

    /// Reset all accumulated state back to empty.
    ///
    /// Registered reducers are kept; only the per-entity state accumulation is
    /// cleared. This is equivalent to calling [`Self::register`] for every
    /// reducer again but preserving insertion order.
    pub fn clear_state(&mut self) {
        for (_, slot) in &mut self.slots {
            slot.registry = StateRegistry::new();
        }
    }

    /// Restore accumulated state from a previously captured snapshot map.
    ///
    /// Resets all accumulated state first (via [`Self::clear_state`]), then
    /// loads the corresponding [`StateRegistry`] for each reducer name found in
    /// `snapshot`. Reducer names present in `snapshot` but not registered are
    /// ignored; registered reducers with no entry in `snapshot` remain empty.
    ///
    /// This is the counterpart of [`Self::state_snapshot`] and is used by
    /// `pos-time` snapshot consistency verification to seed the incremental path.
    pub fn restore_from_snapshot(
        &mut self,
        snapshot: &std::collections::HashMap<String, StateRegistry>,
    ) {
        self.clear_state();
        for (name, slot) in &mut self.slots {
            // Missing snapshot entries stay empty after `clear_state`.
            if let Some(restored) = snapshot.get(name) {
                slot.registry = restored.clone();
            }
        }
    }

    /// Extract a snapshot of all per-reducer state as a serialisable map.
    ///
    /// The returned map is keyed by reducer name and contains each reducer's
    /// accumulated [`StateRegistry`]. This is used by `pos-time` snapshot
    /// capture and consistency verification.
    #[must_use]
    pub fn state_snapshot(&self) -> std::collections::HashMap<String, StateRegistry> {
        let mut snapshot = std::collections::HashMap::new();
        for (name, slot) in &self.slots {
            snapshot.insert(name.clone(), slot.registry.clone());
        }
        snapshot
    }

    /// Compare this registry's accumulated state against a previously captured
    /// snapshot map (as returned by [`Self::state_snapshot`]).
    ///
    /// Returns the first differing `(reducer_name, entity_id)` pair, or `None`
    /// when the states are identical.
    #[must_use]
    pub fn diff_against_snapshot(
        &self,
        snapshot: &std::collections::HashMap<String, StateRegistry>,
        all_entities: &[EntityId],
    ) -> Option<(String, EntityId)> {
        for (name, slot) in &self.slots {
            let snap_reg = snapshot.get(name).cloned().unwrap_or_default();
            for entity in all_entities {
                if slot.registry.get_or_default(entity) != snap_reg.get_or_default(entity) {
                    return Some((name.clone(), *entity));
                }
            }
        }
        None
    }
}

impl ConsentRevocationFoldListener for ProjectionRegistry {
    fn on_consent_revoked(&mut self, subject_id: EntityId, _fence_seq: u64) {
        for (_, slot) in &mut self.slots {
            slot.registry.remove(&subject_id);
        }
    }
}

// ---------------------------------------------------------------------------
// RelationshipIndex
// ---------------------------------------------------------------------------

/// Adjacency index for directed [`Relationship`] values.
///
/// NOT a [`Reducer`] — relationships are not per-entity event state; they are
/// recorded explicitly by callers that know when a relationship is established.
#[derive(Clone, Debug, Default)]
pub struct RelationshipIndex {
    outgoing: HashMap<EntityId, Vec<Relationship>>,
    incoming: HashMap<EntityId, Vec<Relationship>>,
}

impl RelationshipIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a relationship in both the outgoing and incoming indices.
    pub fn record(&mut self, rel: Relationship) {
        self.outgoing
            .entry(rel.source)
            .or_default()
            .push(rel.clone());
        self.incoming.entry(rel.target).or_default().push(rel);
    }

    /// All relationships whose source is `id`.
    #[must_use]
    pub fn outgoing_from(&self, id: &EntityId) -> &[Relationship] {
        self.outgoing.get(id).map_or(&[], Vec::as_slice)
    }

    /// All relationships whose target is `id`.
    #[must_use]
    pub fn incoming_to(&self, id: &EntityId) -> &[Relationship] {
        self.incoming.get(id).map_or(&[], Vec::as_slice)
    }

    /// Union of outgoing targets and incoming sources — the direct neighbours of `id`.
    ///
    /// Each neighbour appears at most once even if it is both a source and a target.
    #[must_use]
    pub fn neighbours(&self, id: &EntityId) -> Vec<EntityId> {
        let mut seen: std::collections::HashSet<EntityId> = std::collections::HashSet::new();
        let mut result = Vec::new();

        for rel in self.outgoing_from(id) {
            if seen.contains(&rel.target) {
                continue;
            }
            seen.insert(rel.target);
            result.push(rel.target);
        }
        for rel in self.incoming_to(id) {
            if seen.contains(&rel.source) {
                continue;
            }
            seen.insert(rel.source);
            result.push(rel.source);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        entity::RelationshipKind,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::EventId,
    };
    use proptest::prelude::*;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn make_event(entity: EntityId) -> Event {
        make_event_typed(entity, "test.tick")
    }

    fn make_event_typed(entity: EntityId, kind: &str) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(kind),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    // ------------------------------------------------------------------
    // ProjectionRegistry tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_applies_to_all_reducers() {
        let mut registry = ProjectionRegistry::new();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));

        let count_a = registry
            .state_for_reducer("a", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let count_b = registry
            .state_for_reducer("b", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count_a, 1, "reducer 'a' should have seen 1 event");
        assert_eq!(count_b, 1, "reducer 'b' should have seen 1 event");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_fold_events() {
        let mut registry = ProjectionRegistry::new();
        registry.register("main", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        let events: Vec<Event> = (0..5).map(|_| make_event(entity)).collect();
        registry.fold_events(&events);

        let count = registry
            .state_for_reducer("main", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("event_count should be present"))
            });
        assert_eq!(count, 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn valid_consent_revocation_evicts_each_subject_projection_cache() {
        let mut registry = ProjectionRegistry::new();
        registry.register("a", Box::new(EntityStateProjection));
        registry.register("b", Box::new(EntityStateProjection));
        let subject = EntityId::new();
        let other = EntityId::new();
        registry.apply_event(&make_event(subject));
        registry.apply_event(&make_event(other));

        let revocation = ConsentRevoked {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 2,
        };
        let mut event = make_event_typed(subject, EVENT_TYPE_CONSENT_REVOKED_V1);
        event.payload = revocation.encode().unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("invalid revocation fixture: {error:?}")))
        });
        registry.apply_event(&event);

        assert!(registry.state_for(&subject).is_none());
        assert!(registry.state_for_reducer("b", &subject).is_none());
        assert!(registry.state_for(&other).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_state_for_returns_first_reducers_view() {
        let mut registry = ProjectionRegistry::new();
        registry.register("first", Box::new(EntityStateProjection));
        registry.register("second", Box::new(EntityStateProjection));

        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));

        let state = registry
            .state_for(&entity)
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("state should exist")));
        let count = state
            .get("event_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_state_for_returns_none_when_empty() {
        let registry = ProjectionRegistry::new();
        let entity = EntityId::new();
        assert!(registry.state_for(&entity).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_restore_from_snapshot_skips_unknown_reducers() {
        let mut registry = ProjectionRegistry::new();
        registry.register("registered", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));

        let mut snapshot = std::collections::HashMap::new();
        snapshot.insert("other".to_owned(), StateRegistry::new());
        registry.restore_from_snapshot(&snapshot);

        let count = registry
            .state_for_reducer("registered", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_restore_from_snapshot_loads_matching_reducer() {
        let mut registry = ProjectionRegistry::new();
        registry.register("registered", Box::new(EntityStateProjection));
        let entity = EntityId::new();
        registry.apply_event(&make_event(entity));
        let snapshot = registry.state_snapshot();

        let mut restored = ProjectionRegistry::new();
        restored.register("registered", Box::new(EntityStateProjection));
        restored.restore_from_snapshot(&snapshot);

        let count = restored
            .state_for_reducer("registered", &entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours_dedupes_duplicate_outgoing_targets() {
        let mut index = RelationshipIndex::new();
        let hub = EntityId::new();
        let target = EntityId::new();
        index.record(Relationship::new(hub, target, RelationshipKind::new("a")));
        index.record(Relationship::new(hub, target, RelationshipKind::new("b")));
        let neighbours = index.neighbours(&hub);
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0], target);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours_dedupes_duplicate_incoming_sources() {
        let mut index = RelationshipIndex::new();
        let hub = EntityId::new();
        let source = EntityId::new();
        index.record(Relationship::new(source, hub, RelationshipKind::new("a")));
        index.record(Relationship::new(source, hub, RelationshipKind::new("b")));
        let neighbours = index.neighbours(&hub);
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0], source);
    }

    // ------------------------------------------------------------------
    // EntityStateProjection tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_state_projection_counts_events() {
        let proj = EntityStateProjection;
        let entity = EntityId::new();
        let mut state_reg = StateRegistry::new();

        for _ in 0..3 {
            state_reg.apply(&proj, &make_event(entity));
        }

        let count = state_reg
            .get(&entity)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("event_count should be present"))
            });
        assert_eq!(count, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_state_projection_different_entities_tracked_separately() {
        let proj = EntityStateProjection;
        let a = EntityId::new();
        let b = EntityId::new();
        let mut state_reg = StateRegistry::new();

        state_reg.apply(&proj, &make_event(a));
        state_reg.apply(&proj, &make_event(a));
        state_reg.apply(&proj, &make_event(b));

        let count_a = state_reg
            .get(&a)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let count_b = state_reg
            .get(&b)
            .and_then(|s| s.get("event_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(count_a, 2);
        assert_eq!(count_b, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn entity_state_projection_records_last_event_type() {
        let proj = EntityStateProjection;
        let entity = EntityId::new();
        let mut state_reg = StateRegistry::new();

        state_reg.apply(&proj, &make_event_typed(entity, "first.type"));
        state_reg.apply(&proj, &make_event_typed(entity, "second.type"));

        let last = state_reg
            .get(&entity)
            .and_then(|s| s.get("last_event_type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("last_event_type should be present"))
            });
        assert_eq!(last, "second.type");
    }

    // ------------------------------------------------------------------
    // RelationshipIndex tests
    // ------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_records_and_queries() {
        let mut index = RelationshipIndex::new();
        let a = EntityId::new();
        let b = EntityId::new();
        let c = EntityId::new();

        index.record(Relationship::new(a, b, RelationshipKind::new("trusts")));
        index.record(Relationship::new(a, c, RelationshipKind::new("employs")));
        index.record(Relationship::new(c, b, RelationshipKind::new("trusts")));

        assert_eq!(index.outgoing_from(&a).len(), 2);
        assert_eq!(index.incoming_to(&b).len(), 2);
        assert_eq!(index.outgoing_from(&c).len(), 1);
        assert_eq!(index.incoming_to(&c).len(), 1);

        let lone = EntityId::new();
        assert!(index.outgoing_from(&lone).is_empty());
        assert!(index.incoming_to(&lone).is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours() {
        let mut index = RelationshipIndex::new();
        let hub = EntityId::new();
        let x = EntityId::new();
        let y = EntityId::new();
        let z = EntityId::new();

        // hub → x  (outgoing target = x)
        index.record(Relationship::new(hub, x, RelationshipKind::new("link")));
        // y → hub  (incoming source = y)
        index.record(Relationship::new(y, hub, RelationshipKind::new("link")));
        // z → hub  (incoming source = z)
        index.record(Relationship::new(z, hub, RelationshipKind::new("link")));

        let mut neighbours = index.neighbours(&hub);
        neighbours.sort();
        let mut expected = vec![x, y, z];
        expected.sort();
        assert_eq!(neighbours, expected);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn relationship_index_neighbours_no_duplicates() {
        let mut index = RelationshipIndex::new();
        let a = EntityId::new();
        let b = EntityId::new();

        // a → b and b → a: from a's perspective b appears in both lists.
        index.record(Relationship::new(a, b, RelationshipKind::new("link")));
        index.record(Relationship::new(b, a, RelationshipKind::new("link")));

        let neighbours = index.neighbours(&a);
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0], b);
    }

    // ------------------------------------------------------------------
    // proptest: fold determinism
    // ------------------------------------------------------------------

    proptest! {
        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn fold_deterministic(n_events in 1usize..=20) {
            let entity = EntityId::new();
            let events: Vec<Event> = (0..n_events).map(|_| make_event(entity)).collect();

            let mut reg1 = ProjectionRegistry::new();
            reg1.register("p", Box::new(EntityStateProjection));
            reg1.fold_events(&events);

            let mut reg2 = ProjectionRegistry::new();
            reg2.register("p", Box::new(EntityStateProjection));
            reg2.fold_events(&events);

            let count1 = reg1
                .state_for_reducer("p", &entity)
                .and_then(|s| s.get("event_count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let count2 = reg2
                .state_for_reducer("p", &entity)
                .and_then(|s| s.get("event_count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);

            prop_assert_eq!(count1, count2);
            prop_assert_eq!(count1, n_events as u64);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod extra_tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_registry_debug_shows_reducer_names() {
        let mut reg = ProjectionRegistry::new();
        reg.register("alpha", Box::new(EntityStateProjection));
        reg.register("beta", Box::new(EntityStateProjection));
        let debug_str = format!("{reg:?}");
        assert!(debug_str.contains("alpha"));
        assert!(debug_str.contains("beta"));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod wave3_tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::{EntityId, EventId},
        Event, Reducer, State,
    };

    struct TR;
    impl Reducer for TR {
        fn initial(&self) -> State {
            State::new()
        }
        fn apply(&self, state: &mut State, _: &Event) {
            let n = state
                .get("n")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn ev(entity: EntityId) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_names_returns_registered_names() {
        let mut reg = ProjectionRegistry::new();
        reg.register("alpha", Box::new(TR));
        reg.register("beta", Box::new(TR));
        let names = reg.reducer_names();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_snapshot_identical_returns_none() {
        let entity = EntityId::new();
        let mut reg = ProjectionRegistry::new();
        reg.register("r", Box::new(TR));
        reg.apply_event(&ev(entity));

        let snap = reg.state_snapshot();
        let diff = reg.diff_against_snapshot(&snap, &[entity]);
        assert!(diff.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_snapshot_diverged_returns_some() {
        let entity = EntityId::new();
        let mut reg = ProjectionRegistry::new();
        reg.register("r", Box::new(TR));
        reg.apply_event(&ev(entity));

        let snap = reg.state_snapshot();
        // Apply another event — now reg diverges from the snapshot
        reg.apply_event(&ev(entity));
        let diff = reg.diff_against_snapshot(&snap, &[entity]);
        assert!(diff.is_some());
        let (name, eid) =
            diff.unwrap_or_else(|| std::panic::resume_unwind(Box::new("diff should be present")));
        assert_eq!(name, "r");
        assert_eq!(eid, entity);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn diff_against_empty_snapshot_returns_some_when_reg_has_state() {
        let entity = EntityId::new();
        let mut reg = ProjectionRegistry::new();
        reg.register("r", Box::new(TR));
        reg.apply_event(&ev(entity));

        let empty_snap = std::collections::HashMap::new();
        let diff = reg.diff_against_snapshot(&empty_snap, &[entity]);
        assert!(diff.is_some());
    }
}
