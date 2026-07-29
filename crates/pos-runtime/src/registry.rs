//! Plugin registry — the single registration point for all plugins.
//!
//! A plugin registers its `Capability` here. The registry wires:
//! - event type schemas into `SchemaRegistry`
//! - reducers into `ProjectionRegistry`
//! - drivers into the runtime's step loop

use indexmap::IndexMap;

use pos_core::{ids::PluginId, Plugin, Reducer, SchemaVersionMap, Upcaster, UpcasterRegistry};
use pos_state::ProjectionRegistry;

use crate::{
    driver::{Driver, ObservationView},
    error::RuntimeError,
    recorder::RECORDER_EVENT_TYPE,
    schema::{EventTypeSchema, SchemaRegistry},
};

/// A registered plugin entry.
struct PluginEntry {
    name: String,
    version: String,
    driver: Option<Box<dyn Driver>>,
    last_tick: Option<u128>,
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
    pub upcasters: UpcasterRegistry,
    pub schema_versions: SchemaVersionMap,
}

impl PluginRegistry {
    fn observations_for<'a>(
        driver: &dyn Driver,
        projections: &'a ProjectionRegistry,
    ) -> ObservationView<'a> {
        ObservationView::from_subscriptions(driver.subscriptions(), |key| {
            projections.state_for(key.entity_id())
        })
    }

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
            upcasters: UpcasterRegistry::new(),
            schema_versions: SchemaVersionMap::new(),
        }
    }

    /// Register an upcaster for schema evolution of event payloads.
    pub fn register_upcaster(&mut self, upcaster: Box<dyn Upcaster>) {
        self.upcasters.register(upcaster);
    }

    /// Record the current schema version for an event type.
    pub fn set_schema_version(&mut self, event_type: impl Into<String>, version: u32) {
        self.schema_versions.set(event_type, version);
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

        if cap.has_driver != driver.is_some() {
            return Err(RuntimeError::CapabilityMismatch {
                name: name.clone(),
                reason: if cap.has_driver {
                    "has_driver=true but no driver provided".to_owned()
                } else {
                    "has_driver=false but a driver was provided".to_owned()
                },
            });
        }
        if cap.has_reducer != reducer.is_some() {
            return Err(RuntimeError::CapabilityMismatch {
                name: name.clone(),
                reason: if cap.has_reducer {
                    "has_reducer=true but no reducer provided".to_owned()
                } else {
                    "has_reducer=false but a reducer was provided".to_owned()
                },
            });
        }

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

        self.plugins.insert(
            id,
            PluginEntry {
                name,
                version: plugin.version().to_owned(),
                driver,
                last_tick: None,
            },
        );
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

    /// Iterate over registered plugin (name, version) pairs in registration order.
    pub fn plugin_versions(&self) -> impl Iterator<Item = (&str, &str)> {
        self.plugins
            .values()
            .map(|e| (e.name.as_str(), e.version.as_str()))
    }

    /// Register a driver directly (for tests and late-bound agent registration).
    pub fn register_driver(&mut self, driver: Box<dyn Driver>) {
        let name = driver.name().to_owned();
        self.plugins.insert(
            pos_core::ids::PluginId::new(),
            PluginEntry {
                name,
                version: "0.1.0".to_owned(),
                driver: Some(driver),
                last_tick: None,
            },
        );
    }

    /// Step ready drivers on cadence, returning all drafts from eligible plugins.
    ///
    /// Only drivers whose `tick_interval()` has elapsed since their last tick
    /// will fire. First-tick drivers always fire.
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn tick_cadenced(
        &mut self,
        store: &dyn pos_core::store::EventStore,
        timeline: pos_core::ids::TimelineId,
        now_ns: u128,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        let mut all_drafts = Vec::new();
        let projections = &self.projections;
        for entry in self.plugins.values_mut() {
            if let Some(driver) = entry.driver.as_mut() {
                let interval_ns = driver.tick_interval().as_nanos();
                let ready = match entry.last_tick {
                    Some(prev) => now_ns >= prev + interval_ns,
                    None => true,
                };
                if ready {
                    let observations = Self::observations_for(driver.as_ref(), projections);
                    let output = driver.step(store, timeline, observations)?;
                    entry.last_tick = Some(now_ns);
                    all_drafts.extend(output.drafts);
                }
            }
        }
        Ok(all_drafts)
    }

    /// Number of plugins that have a driver registered.
    #[must_use]
    pub fn driver_count(&self) -> usize {
        self.plugins.values().filter(|e| e.driver.is_some()).count()
    }

    /// Step all plugins that have a driver, collecting their event drafts.
    ///
    /// Calls `driver.step(store, timeline, observations)` on each plugin that registered a driver.
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
        let projections = &self.projections;
        for entry in self.plugins.values_mut() {
            if let Some(driver) = entry.driver.as_mut() {
                let observations = Self::observations_for(driver.as_ref(), projections);
                let output = driver.step(store, timeline, observations)?;
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
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId, PluginId, TimelineId},
        Capability, Event, Plugin, Reducer, State,
    };
    use pos_store::{open_store, StoreConfig};

    // ── Test helpers ──────────────────────────────────────────────────────────

    struct TestPlugin {
        id: PluginId,
        name: &'static str,
        cap: Capability,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn capability(&self) -> Capability {
            self.cap.clone()
        }
    }

    fn simple_plugin(name: &'static str, event_types: &[&str]) -> TestPlugin {
        plugin_with_caps(name, event_types, false, false)
    }

    fn plugin_with_caps(
        name: &'static str,
        event_types: &[&str],
        has_driver: bool,
        has_reducer: bool,
    ) -> TestPlugin {
        TestPlugin {
            id: PluginId::new(),
            name,
            cap: Capability {
                owned_event_types: event_types.iter().map(|s| Kind::new(*s)).collect(),
                owned_entity_kinds: vec![],
                has_driver,
                has_reducer,
            },
        }
    }

    struct CountReducer;
    impl Reducer for CountReducer {
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

    struct NoopDriver;
    impl crate::driver::Driver for NoopDriver {
        fn name(&self) -> &'static str {
            "noop"
        }
        fn step(
            &mut self,
            _: &dyn pos_core::store::EventStore,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<crate::driver::StepOutput, RuntimeError> {
            Ok(crate::driver::StepOutput::empty())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_plugin_wires_schemas() {
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("world", &["world.observation", "world.action"]);
        reg.register(&p, None, None).unwrap();
        assert!(reg.schemas.contains("world.observation"));
        assert!(reg.schemas.contains("world.action"));
        assert!(!reg.schemas.contains("agent.decision"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_plugin_with_reducer_wires_projections() {
        let mut reg = PluginRegistry::new();
        let p = plugin_with_caps("counter", &["counter.tick"], false, true);
        reg.register(&p, Some(Box::new(CountReducer)), None)
            .unwrap();
        // Apply an event and verify the reducer ran
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn duplicate_plugin_returns_error() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new();
        let p1 = TestPlugin {
            id,
            name: "dup",
            cap: Capability::default(),
        };
        let p2 = TestPlugin {
            id,
            name: "dup",
            cap: Capability::default(),
        };
        reg.register(&p1, None, None).unwrap();
        let err = reg.register(&p2, None, None).unwrap_err();
        assert!(matches!(err, RuntimeError::DuplicatePlugin { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn contains_len_is_empty() {
        let mut reg = PluginRegistry::new();
        assert!(reg.is_empty());
        let p = simple_plugin("p", &[]);
        reg.register(&p, None, None).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.driver_count(), 0);
        assert!(reg.contains(&p.id));
        assert!(!reg.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_skips_driverless_plugins() {
        let mut store = pos_store::open_store(pos_store::StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("p", &[]);
        reg.register(&p, None, None).unwrap();
        let drafts = reg.tick_cadenced(store.as_ref(), tl.id(), 0).unwrap();
        assert!(drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_calls_drivers_and_collects_drafts() {
        use crate::driver::{Driver, StepOutput};
        use pos_store::{open_store, StoreConfig};

        struct SimpleDriver {
            entity: EntityId,
            calls: u32,
        }
        impl Driver for SimpleDriver {
            fn name(&self) -> &'static str {
                "simple"
            }
            fn step(
                &mut self,
                _: &dyn pos_core::store::EventStore,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.calls += 1;
                let draft = EventDraft::new(
                    self.entity,
                    Kind::new("driver.tick"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![draft]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();

        let entity = EntityId::new();
        let p = plugin_with_caps("driven", &["driver.tick"], true, false);
        let driver = SimpleDriver { entity, calls: 0 };
        assert_eq!(driver.name(), "simple"); // force coverage of name()

        let mut reg = PluginRegistry::new();
        reg.register(&p, None, Some(Box::new(driver))).unwrap();
        assert_eq!(reg.driver_count(), 1);

        let drafts = reg.step_all(store.as_ref(), tl.id()).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.tick");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_materializes_only_subscribed_projection_state() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};

        struct ObservingDriver {
            key: ProjectionKey,
            entity: EntityId,
        }

        impl Driver for ObservingDriver {
            fn name(&self) -> &'static str {
                "observing"
            }

            fn subscriptions(&self) -> Vec<ProjectionKey> {
                vec![self.key.clone()]
            }

            fn step(
                &mut self,
                _: &dyn pos_core::store::EventStore,
                _: pos_core::ids::TimelineId,
                observations: ObservationView<'_>,
            ) -> Result<crate::driver::StepOutput, RuntimeError> {
                let observed = observations
                    .state_for(&self.key)
                    .and_then(|state| state.get("n"))
                    .and_then(serde_json::Value::as_u64);
                let drafts = (observed == Some(1))
                    .then(|| {
                        EventDraft::new(
                            self.entity,
                            Kind::new("driver.observed"),
                            CanonicalBytes::from_vec(vec![]),
                        )
                    })
                    .into_iter()
                    .collect();
                Ok(crate::driver::StepOutput::new(drafts))
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let timeline = store.create_timeline("t").unwrap();
        let observed_entity = EntityId::new();
        let event = Event {
            id: EventId::new(),
            entity: observed_entity,
            event_type: Kind::new("counter.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };

        let mut reg = PluginRegistry::new();
        reg.projections.register("counter", Box::new(CountReducer));
        reg.projections.apply_event(&event);
        reg.register_driver(Box::new(ObservingDriver {
            key: ProjectionKey::new(observed_entity),
            entity: EntityId::new(),
        }));

        let drafts = reg.tick_cadenced(store.as_ref(), timeline.id(), 0).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.observed");

        let drafts = reg.step_all(store.as_ref(), timeline.id()).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.observed");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_registry_default() {
        let reg = PluginRegistry::default();
        assert!(reg.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_rejects_capability_mismatch() {
        let mut reg = PluginRegistry::new();
        let p = plugin_with_caps("mismatch", &["x.y"], true, false);
        let err = reg.register(&p, None, None).unwrap_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));

        let p2 = plugin_with_caps("mismatch2", &["x.y"], false, false);
        let err = reg
            .register(&p2, Some(Box::new(CountReducer)), None)
            .unwrap_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));

        let p3 = plugin_with_caps("mismatch3", &["x.y"], false, true);
        let err = reg.register(&p3, None, None).unwrap_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));

        let p4 = plugin_with_caps("mismatch4", &["x.y"], false, false);
        let mut noop = NoopDriver;
        assert_eq!(crate::driver::Driver::name(&noop), "noop");
        let _ = crate::driver::Driver::step(
            &mut noop,
            open_store(StoreConfig::Memory).unwrap().as_ref(),
            TimelineId::new(),
            ObservationView::empty(),
        );
        let err = reg.register(&p4, None, Some(Box::new(noop))).unwrap_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_upcaster_and_set_schema_version() {
        use pos_core::event::{CanonicalBytes, Kind, SchemaVersion};

        struct TestUpcaster(Kind);
        impl pos_core::Upcaster for TestUpcaster {
            fn event_type(&self) -> &Kind {
                &self.0
            }
            fn source_version(&self) -> SchemaVersion {
                SchemaVersion::V1
            }
            fn target_version(&self) -> SchemaVersion {
                SchemaVersion::new(2)
            }
            fn upcast(&self, payload: CanonicalBytes) -> CanonicalBytes {
                payload
            }
        }

        let mut reg = PluginRegistry::new();
        assert!(reg.schema_versions.versions.is_empty());

        let kind = Kind::new("test.upcast");
        reg.register_upcaster(Box::new(TestUpcaster(kind)));

        reg.set_schema_version("test.upcast", 2);
        assert!(!reg.schema_versions.versions.is_empty());
    }
}
