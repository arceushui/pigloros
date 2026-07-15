//! Plugin registry — the single registration point for all plugins.
//!
//! A plugin registers its `Capability` here. The registry wires:
//! - event type schemas into `SchemaRegistry`
//! - reducers into `ProjectionRegistry`
//! - drivers into the runtime's step loop

use indexmap::IndexMap;

use pos_core::{ids::PluginId, Plugin, Reducer};
use pos_state::ProjectionRegistry;

use crate::{
    driver::Driver,
    error::RuntimeError,
    recorder::RECORDER_EVENT_TYPE,
    schema::{EventTypeSchema, SchemaRegistry},
};

/// A registered plugin entry.
struct PluginEntry {
    name: String,
    driver: Option<Box<dyn Driver>>,
}

/// The central plugin registry.
///
/// Plugins register here; the registry wires their components into the
/// appropriate sub-registries. Iteration order (`step_all`, `plugin_names`) is
/// guaranteed to match registration order.
pub struct PluginRegistry {
    /// `IndexMap` preserves insertion order — `step_all` / `plugin_names` are stable.
    plugins: IndexMap<PluginId, PluginEntry>,
    pub schemas: SchemaRegistry,
    pub projections: ProjectionRegistry,
}

impl PluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut schemas = SchemaRegistry::new();
        // Auto-register the Recorder's internal event type so that
        // Recorder::to_draft() output passes SchemaRegistry::validate().
        schemas.register(EventTypeSchema {
            event_type: pos_core::event::Kind::new(RECORDER_EVENT_TYPE),
            description: "Internal: nondeterministic output recorded by the Recorder".to_owned(),
            json_schema: None,
        });
        Self {
            plugins: IndexMap::new(),
            schemas,
            projections: ProjectionRegistry::new(),
        }
    }

    /// Register a plugin.
    ///
    /// Wires event-type schemas and (optionally) a reducer and driver.
    ///
    /// # Errors
    /// Returns [`RuntimeError::DuplicatePlugin`] if a plugin with the same `PluginId`
    /// is already registered.
    pub fn register(
        &mut self,
        plugin: &dyn Plugin,
        reducer: Option<Box<dyn Reducer>>,
        driver: Option<Box<dyn Driver>>,
    ) -> Result<(), RuntimeError> {
        let id = plugin.id();
        let name = plugin.name().to_owned();

        if self.plugins.contains_key(&id) {
            return Err(RuntimeError::DuplicatePlugin { id, name });
        }

        let cap = plugin.capability();

        // Register event type schemas
        for kind in &cap.owned_event_types {
            self.schemas.register(EventTypeSchema {
                event_type: kind.clone(),
                description: format!("owned by plugin '{name}'"),
                json_schema: None,
            });
        }

        // Wire reducer into projection registry
        if let Some(r) = reducer {
            self.projections.register(&name, r);
        }

        self.plugins.insert(id, PluginEntry { name, driver });
        Ok(())
    }

    /// Returns `true` if a plugin with this id is registered.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.plugins.contains_key(id)
    }

    /// Number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Returns `true` if no plugins are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Iterate over plugin names in registration order.
    pub fn plugin_names(&self) -> impl Iterator<Item = &str> {
        self.plugins.values().map(|e| e.name.as_str())
    }

    /// Step all plugins that have a driver, collecting their event drafts.
    ///
    /// Calls `driver.step(store, timeline)` on each plugin that registered a driver.
    /// Returns all drafts from all drivers in registration order.
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers.
    pub fn step_all(
        &mut self,
        store: &dyn pos_core::store::EventStore,
        timeline: pos_core::ids::TimelineId,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        let mut all_drafts = Vec::new();
        for entry in self.plugins.values_mut() {
            if let Some(driver) = entry.driver.as_mut() {
                let output = driver.step(store, timeline)?;
                all_drafts.extend(output.drafts);
            }
        }
        Ok(all_drafts)
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::WallTime,
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, PluginId},
        Capability, Event, Plugin, Reducer, State,
    };

    // ── Test helpers ──────────────────────────────────────────────────────────

    struct TestPlugin {
        id: PluginId,
        name: &'static str,
        cap: Capability,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId { self.id }
        fn name(&self) -> &str { self.name }
        fn capability(&self) -> Capability { self.cap.clone() }
    }

    fn simple_plugin(name: &'static str, event_types: &[&str]) -> TestPlugin {
        TestPlugin {
            id: PluginId::new(),
            name,
            cap: Capability {
                owned_event_types: event_types.iter().map(|s| Kind::new(*s)).collect(),
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: false,
            },
        }
    }

    struct CountReducer;
    impl Reducer for CountReducer {
        fn initial(&self) -> State { State::new() }
        fn apply(&self, state: &mut State, _: &Event) {
            let n = state.get("n").and_then(serde_json::Value::as_u64).unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn register_plugin_wires_schemas() {
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("world", &["world.observation", "world.action"]);
        reg.register(&p, None, None).unwrap();
        assert!(reg.schemas.contains("world.observation"));
        assert!(reg.schemas.contains("world.action"));
        assert!(!reg.schemas.contains("agent.decision"));
    }

    #[test]
    fn register_plugin_with_reducer_wires_projections() {
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("counter", &["counter.tick"]);
        reg.register(&p, Some(Box::new(CountReducer)), None).unwrap();
        // Apply an event and verify the reducer ran
        use pos_core::{crypto::Hash, event::SchemaVersion, ids::EventId, clock::Seq};
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("counter.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reg.projections.apply_event(&event);
        let state = reg.projections.state_for(&event.entity).unwrap();
        assert_eq!(state.get("n").and_then(serde_json::Value::as_u64), Some(1));
    }

    #[test]
    fn duplicate_plugin_returns_error() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new();
        let p1 = TestPlugin { id, name: "dup", cap: Capability::default() };
        let p2 = TestPlugin { id, name: "dup", cap: Capability::default() };
        reg.register(&p1, None, None).unwrap();
        let err = reg.register(&p2, None, None).unwrap_err();
        assert!(matches!(err, RuntimeError::DuplicatePlugin { .. }));
    }

    #[test]
    fn contains_len_is_empty() {
        let mut reg = PluginRegistry::new();
        assert!(reg.is_empty());
        let p = simple_plugin("p", &[]);
        reg.register(&p, None, None).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.contains(&p.id));
        assert!(!reg.is_empty());
    }

    #[test]
    fn plugin_names_iterator() {
        let mut reg = PluginRegistry::new();
        let p1 = simple_plugin("alpha", &[]);
        let p2 = simple_plugin("beta", &[]);
        reg.register(&p1, None, None).unwrap();
        reg.register(&p2, None, None).unwrap();
        let names: Vec<&str> = reg.plugin_names().collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    #[test]
    fn step_all_calls_drivers_and_collects_drafts() {
        use pos_store::{open_store, StoreConfig};
        use crate::driver::{Driver, StepOutput};

        struct SimpleDriver { entity: EntityId, calls: u32 }
        impl Driver for SimpleDriver {
            fn name(&self) -> &str { "simple" }
            fn step(&mut self, _: &dyn pos_core::store::EventStore, _: pos_core::ids::TimelineId) -> Result<StepOutput, RuntimeError> {
                self.calls += 1;
                let draft = EventDraft::new(self.entity, Kind::new("driver.tick"), CanonicalBytes::from_vec(vec![]));
                Ok(StepOutput::new(vec![draft]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();

        let entity = EntityId::new();
        let p = simple_plugin("driven", &["driver.tick"]);
        let driver = SimpleDriver { entity, calls: 0 };

        let mut reg = PluginRegistry::new();
        reg.register(&p, None, Some(Box::new(driver))).unwrap();

        let drafts = reg.step_all(store.as_ref(), tl.id()).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.tick");
    }

    #[test]
    fn step_all_no_drivers_returns_empty() {
        use pos_store::{open_store, StoreConfig};
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let p = simple_plugin("nodrive", &[]);
        let mut reg = PluginRegistry::new();
        reg.register(&p, None, None).unwrap();
        let drafts = reg.step_all(store.as_ref(), tl.id()).unwrap();
        assert!(drafts.is_empty());
    }

    #[test]
    fn plugin_registry_default() {
        let reg = PluginRegistry::default();
        assert!(reg.is_empty());
    }

    #[test]
    fn schema_validation_after_registration() {
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("agent", &["agent.decision"]);
        reg.register(&p, None, None).unwrap();
        let valid = EventDraft::new(
            EntityId::new(),
            Kind::new("agent.decision"),
            CanonicalBytes::from_vec(vec![]),
        );
        let invalid = EventDraft::new(
            EntityId::new(),
            Kind::new("unknown.type"),
            CanonicalBytes::from_vec(vec![]),
        );
        reg.schemas.validate(&valid).unwrap();
        assert!(reg.schemas.validate(&invalid).is_err());
    }
}
