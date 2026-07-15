//! Projection registry: applies reducers to events and tracks per-entity state.

use std::collections::HashMap;

use pos_core::{EntityId, Event, Reducer, State, StateRegistry};

/// A named reducer registration. Holds a boxed `Reducer` and the last accumulated
/// `StateRegistry` after folding events through it.
struct NamedProjection {
    reducer: Box<dyn Reducer>,
    registry: StateRegistry,
}

/// Registry of named projections. Each projection is a (`name`, `Reducer`) pair
/// whose `StateRegistry` is updated by calling `apply_event` or `fold_events`.
///
/// Wave 2: basic fold functionality.
/// Wave 3 will add query integration and relationship indexing.
pub struct ProjectionRegistry {
    projections: HashMap<String, NamedProjection>,
}

impl ProjectionRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            projections: HashMap::new(),
        }
    }

    /// Register a named reducer. Replaces any existing projection with the same name.
    pub fn register(&mut self, name: impl Into<String>, reducer: Box<dyn Reducer>) {
        self.projections.insert(
            name.into(),
            NamedProjection {
                reducer,
                registry: StateRegistry::new(),
            },
        );
    }

    /// Apply a single event through all registered reducers.
    pub fn apply_event(&mut self, event: &Event) {
        for proj in self.projections.values_mut() {
            proj.registry.apply(proj.reducer.as_ref(), event);
        }
    }

    /// Fold a slice of events through all registered reducers (batch apply).
    pub fn fold_events(&mut self, events: &[Event]) {
        for event in events {
            self.apply_event(event);
        }
    }

    /// Return the current state for an entity in a named projection.
    /// Returns `None` if the projection or entity has not been seen.
    #[must_use]
    pub fn state_for(&self, projection: &str, entity_id: &EntityId) -> Option<&State> {
        self.projections
            .get(projection)?
            .registry
            .get(entity_id)
    }

    /// Return the full `StateRegistry` for a named projection, if it exists.
    #[must_use]
    pub fn registry_for(&self, projection: &str) -> Option<&StateRegistry> {
        self.projections.get(projection).map(|p| &p.registry)
    }
}

impl Default for ProjectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A `Reducer` that applies events as a fold over entity state.
/// Plugins should wrap their domain-specific logic in this type.
///
/// Wave 2: identity reducer (stores raw event count per entity).
/// Plugins subclass their own reducer logic by implementing `Reducer` directly.
pub struct EntityStateProjection {
    /// Wrapped user-supplied reducer.
    inner: Box<dyn Reducer>,
}

impl EntityStateProjection {
    /// Wrap a `Reducer` in an `EntityStateProjection`.
    #[must_use]
    pub fn new(inner: Box<dyn Reducer>) -> Self {
        Self { inner }
    }
}

impl Reducer for EntityStateProjection {
    fn initial(&self) -> State {
        self.inner.initial()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        self.inner.apply(state, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::{EntityId, EventId},
    };

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

    fn make_event(entity: EntityId) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("test.tick"),
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

    #[test]
    fn fold_events_accumulates_state() {
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        let entity = EntityId::new();
        let events: Vec<Event> = (0..3).map(|_| make_event(entity)).collect();
        reg.fold_events(&events);
        let n = reg
            .state_for("count", &entity)
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn entity_state_projection_delegates_to_inner() {
        let entity_proj = EntityStateProjection::new(Box::new(CountReducer));
        let mut state = entity_proj.initial();
        let ev = make_event(EntityId::new());
        entity_proj.apply(&mut state, &ev);
        assert_eq!(state.get("n").and_then(serde_json::Value::as_u64), Some(1));
    }
}
