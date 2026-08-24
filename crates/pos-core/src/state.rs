use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ids::EntityId;
use crate::{event::Event, is_geographic_event_type};

/// Opaque state value stored as a JSON-serializable map.
/// Plugins manage their own state shape inside this map.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub fields: HashMap<String, serde_json::Value>,
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.fields.insert(key.into(), value);
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields.get(key)
    }
}

/// A reducer applies events to produce new state. Plugins implement this.
/// State is always a fold — never authoritative storage.
pub trait Reducer: Send + Sync {
    fn initial(&self) -> State;
    fn apply(&self, state: &mut State, event: &Event);
}

/// Registry of per-entity state, produced by folding events through a Reducer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateRegistry {
    states: HashMap<EntityId, State>,
}

impl StateRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, id: &EntityId) -> Option<&State> {
        self.states.get(id)
    }

    #[must_use]
    pub fn get_or_default(&self, id: &EntityId) -> State {
        self.states.get(id).cloned().unwrap_or_default()
    }

    pub fn apply(&mut self, reducer: &dyn Reducer, event: &Event) {
        // Geographic evidence is owned by the Core visibility boundary.  A
        // generic StateRegistry must never hand it to a plugin reducer, even
        // when a caller bypasses ProjectionRegistry and uses this low-level
        // seam directly.
        if is_geographic_event_type(&event.event_type)
            || crate::is_consent_event_type(&event.event_type)
        {
            return;
        }
        let state = self
            .states
            .entry(event.entity)
            .or_insert_with(|| reducer.initial());
        reducer.apply(state, event);
    }

    /// Forget cached projection state for one subject without touching Timeline history.
    pub fn remove(&mut self, id: &EntityId) {
        self.states.remove(id);
    }

    /// Retain only the state for one subject.
    pub fn retain_only(&mut self, id: &EntityId) {
        self.states.retain(|entity, _| entity == id);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::{EntityId, EventId},
    };

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            let mut s = State::new();
            s.set("count", serde_json::Value::Number(0.into()));
            s
        }

        fn apply(&self, state: &mut State, _event: &Event) {
            let count = state
                .fields
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("count", serde_json::Value::Number((count + 1).into()));
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn state_is_a_fold() -> Result<(), Box<dyn std::error::Error>> {
        let reducer = CountReducer;
        let entity = EntityId::new();
        let mut registry = StateRegistry::new();

        for _ in 0..5 {
            registry.apply(&reducer, &make_event(entity));
        }

        let state = registry.get(&entity).ok_or("entity state missing")?;
        assert_eq!(
            state.get("count").and_then(serde_json::Value::as_u64),
            Some(5)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn initial_state_for_unknown_entity() {
        let reducer = CountReducer;
        let entity = EntityId::new();
        let registry = StateRegistry::new();
        let _ = reducer.initial(); // initial is deterministic
        assert!(registry.get(&entity).is_none());
        let default = registry.get_or_default(&entity);
        assert!(default.fields.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn state_registry_ignores_geographic_events() {
        let reducer = CountReducer;
        let entity = EntityId::new();
        let mut registry = StateRegistry::new();
        let mut event = make_event(entity);
        event.event_type = crate::Kind::new(crate::GEOGRAPHIC_EVENT_TYPE);
        registry.apply(&reducer, &event);
        assert!(registry.get(&entity).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn state_registry_remove_forgets_existing_subject_state() {
        let reducer = CountReducer;
        let entity = EntityId::new();
        let mut registry = StateRegistry::new();
        registry.apply(&reducer, &make_event(entity));

        registry.remove(&entity);

        assert!(registry.get(&entity).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn state_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let mut s = State::new();
        s.set("name", serde_json::Value::String("alice".into()));
        s.set("score", serde_json::Value::Number(42.into()));
        let back: State = serde_json::from_str(&serde_json::to_string(&s)?)?;
        assert_eq!(s, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn state_cbor_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let mut s = State::new();
        s.set("x", serde_json::json!(true));
        let mut buf = Vec::new();
        ciborium::into_writer(&s, &mut buf)?;
        let back: State = ciborium::from_reader(buf.as_slice())?;
        assert_eq!(s, back);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn state_registry_tracks_multiple_entities() -> Result<(), Box<dyn std::error::Error>> {
        let reducer = CountReducer;
        let a = EntityId::new();
        let b = EntityId::new();
        let mut registry = StateRegistry::new();

        registry.apply(&reducer, &make_event(a));
        registry.apply(&reducer, &make_event(a));
        registry.apply(&reducer, &make_event(b));

        assert_eq!(
            registry
                .get(&a)
                .ok_or("first entity state missing")?
                .get("count")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            registry
                .get(&b)
                .ok_or("second entity state missing")?
                .get("count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_gives_same_result_as_original() {
        let reducer = CountReducer;
        let entity = EntityId::new();
        let events: Vec<Event> = (0..10).map(|_| make_event(entity)).collect();

        let mut reg1 = StateRegistry::new();
        let mut reg2 = StateRegistry::new();

        for e in &events {
            reg1.apply(&reducer, e);
        }
        for e in &events {
            reg2.apply(&reducer, e);
        }

        assert_eq!(reg1.get(&entity), reg2.get(&entity));
    }
}
