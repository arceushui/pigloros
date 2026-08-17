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
    composition::{PluginComposition, RegisteredEventSchema, RegisteredPlugin},
    driver::{Driver, ObservationSnapshot, ProjectionKey, StepOutput},
    error::RuntimeError,
    recorder::RECORDER_EVENT_TYPE,
    schema::{EventTypeSchema, SchemaRegistry},
};
use std::collections::HashSet;

fn extend_unique_subscriptions(
    subscriptions: &mut Vec<ProjectionKey>,
    seen: &mut HashSet<ProjectionKey>,
    keys: &[ProjectionKey],
) {
    for key in keys {
        if seen.insert(key.clone()) {
            subscriptions.push(key.clone());
        }
    }
}

fn reject_geographic_drafts(output: &StepOutput) -> Result<(), RuntimeError> {
    match output
        .drafts
        .iter()
        .find(|draft| pos_core::is_geographic_event_type(&draft.event_type))
    {
        Some(draft) => Err(RuntimeError::GeographicDraft {
            event_type: draft.event_type.as_str().to_owned(),
        }),
        None => Ok(()),
    }
}

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
}

impl PluginRegistry {
    /// Return an immutable, deterministic description of the effective
    /// registration topology.
    ///
    /// Plugin order is preserved and schemas are sorted so equality is
    /// independent of registration-map iteration order. The result compares
    /// metadata only, never opaque plugin code.
    #[must_use]
    pub fn composition(&self) -> PluginComposition {
        let plugins = self
            .plugins
            .iter()
            .map(|(id, entry)| RegisteredPlugin {
                id: *id,
                name: entry.name.clone(),
                version: entry.version.clone(),
            })
            .collect();

        let mut schemas: Vec<_> = self
            .schemas
            .iter()
            .map(|schema| RegisteredEventSchema {
                event_type: schema.event_type.as_str().to_owned(),
                json_schema: schema.json_schema.clone(),
            })
            .collect();
        schemas.sort_unstable_by(|left, right| left.event_type.cmp(&right.event_type));

        PluginComposition { plugins, schemas }
    }

    fn snapshot_for_subscriptions<'a>(
        &self,
        subscriptions: impl IntoIterator<Item = &'a ProjectionKey>,
    ) -> ObservationSnapshot {
        ObservationSnapshot::from_subscriptions(subscriptions, |key| {
            self.projections.state_for(key.entity_id()).cloned()
        })
    }

    fn snapshot_for_tick(&self) -> ObservationSnapshot {
        let mut seen = HashSet::new();
        let mut subscriptions = Vec::new();

        for entry in self
            .plugins
            .values()
            .filter_map(|entry| entry.driver.as_deref())
        {
            extend_unique_subscriptions(&mut subscriptions, &mut seen, entry.subscriptions());
        }

        self.snapshot_for_subscriptions(subscriptions.iter())
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

        if let Some(kind) = cap
            .owned_event_types
            .iter()
            .find(|kind| pos_core::is_geographic_event_type(kind))
        {
            return Err(RuntimeError::ReservedGeographicEventType {
                name,
                event_type: kind.as_str().to_owned(),
            });
        }

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
    /// Propagates any [`RuntimeError`] from drivers. Returns
    /// [`RuntimeError::CadenceOverflow`] before snapshot creation or driver mutation
    /// when a prior tick plus the configured interval cannot fit in `u128` nanoseconds.
    pub fn tick_cadenced(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        now_ns: u128,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        let mut all_drafts = Vec::new();
        let mut due_driver_ids = Vec::new();
        let mut seen_subscriptions = HashSet::new();
        let mut due_subscriptions = Vec::new();

        for (id, entry) in &self.plugins {
            if let Some(driver) = entry.driver.as_deref() {
                let interval_ns = driver.tick_interval().as_nanos();
                let ready = match entry.last_tick {
                    Some(previous_ns) => {
                        let due_at = previous_ns.checked_add(interval_ns).ok_or_else(|| {
                            RuntimeError::CadenceOverflow {
                                driver: entry.name.clone(),
                                previous_ns,
                                interval_ns,
                            }
                        })?;
                        now_ns >= due_at
                    }
                    None => true,
                };
                if ready {
                    due_driver_ids.push(*id);
                    extend_unique_subscriptions(
                        &mut due_subscriptions,
                        &mut seen_subscriptions,
                        driver.subscriptions(),
                    );
                }
            }
        }

        let snapshot = self.snapshot_for_subscriptions(due_subscriptions.iter());
        for id in due_driver_ids {
            if let Some(entry) = self.plugins.get_mut(&id) {
                if let Some(driver) = entry.driver.as_mut() {
                    let observations = snapshot.view_for(driver.subscriptions());
                    let output = driver.step(timeline, observations)?;
                    reject_geographic_drafts(&output)?;
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
    /// Calls `driver.step(timeline, observations)` on each plugin that registered a driver.
    /// Returns all drafts from all drivers in registration order.
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers.
    pub fn step_all(
        &mut self,
        timeline: pos_core::ids::TimelineId,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        let mut all_drafts = Vec::new();
        let snapshot = self.snapshot_for_tick();
        for entry in self.plugins.values_mut() {
            if let Some(driver) = entry.driver.as_mut() {
                let observations = snapshot.view_for(driver.subscriptions());
                let output = driver.step(timeline, observations)?;
                reject_geographic_drafts(&output)?;
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
    use crate::driver::{ObservationView, StepOutput};
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
    fn plugins_cannot_claim_core_owned_geographic_event_types() {
        let plugin = simple_plugin("malicious-geo", &[pos_core::GEOGRAPHIC_EVENT_TYPE]);
        let error = PluginRegistry::new()
            .register(&plugin, None, None)
            .unwrap_err();
        assert!(error.to_string().contains(pos_core::GEOGRAPHIC_EVENT_TYPE));

        let cell = simple_plugin("future-geo", &[pos_core::GEOGRAPHIC_CELL_EVENT_TYPE]);
        let error = PluginRegistry::new()
            .register(&cell, None, None)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE));
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
        let mut protected = event;
        protected.event_type = Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE);
        reg.projections.apply_event(&protected);
        assert_eq!(
            reg.projections
                .state_for(&protected.entity)
                .and_then(|state| state.get("n"))
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
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
        let drafts = reg.tick_cadenced(tl.id(), 0).unwrap();
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
        let versions: Vec<(&str, &str)> = reg.plugin_versions().collect();
        assert!(versions.contains(&("alpha", "0.1.0")));
        assert!(versions.contains(&("beta", "0.1.0")));
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

        let drafts = reg.step_all(tl.id()).unwrap();
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
        let drafts = reg.step_all(tl.id()).unwrap();
        assert!(drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_propagates_driver_error() {
        struct FailingDriver;

        impl Driver for FailingDriver {
            fn name(&self) -> &'static str {
                "failing"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Err(RuntimeError::NoDriver {
                    name: "failing".to_owned(),
                })
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let timeline = store.create_timeline("t").unwrap();
        let mut reg = PluginRegistry::new();
        reg.register_driver(Box::new(FailingDriver));

        let error = reg.step_all(timeline.id()).unwrap_err();
        assert!(error.to_string().contains("failing"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn generic_driver_boundaries_reject_geographic_drafts() {
        struct GeographicDriver;
        impl Driver for GeographicDriver {
            fn name(&self) -> &'static str {
                "geographic"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new("geo.location"),
                    CanonicalBytes::from_vec(Vec::new()),
                )]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let timeline = store.create_timeline("driver-geo").unwrap();
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(GeographicDriver));
        assert!(matches!(
            registry.step_all(timeline.id()),
            Err(RuntimeError::GeographicDraft { .. })
        ));
        assert!(matches!(
            registry.tick_cadenced(timeline.id(), 0),
            Err(RuntimeError::GeographicDraft { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_materializes_only_subscribed_projection_state() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};

        struct ObservingDriver {
            target: ProjectionKey,
            entity: EntityId,
        }

        impl Driver for ObservingDriver {
            fn name(&self) -> &'static str {
                "observing"
            }

            fn subscriptions(&self) -> &[ProjectionKey] {
                std::slice::from_ref(&self.target)
            }

            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                observations: ObservationView<'_>,
            ) -> Result<crate::driver::StepOutput, RuntimeError> {
                let observed = observations
                    .state_for(&self.target)
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
            target: ProjectionKey::new(observed_entity),
            entity: EntityId::new(),
        }));

        let drafts = reg.tick_cadenced(timeline.id(), 0).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.observed");

        let drafts = reg.step_all(timeline.id()).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.observed");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_deduplicates_snapshot_subscriptions() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};

        struct DuplicateKeyDriver {
            keys: Vec<ProjectionKey>,
        }

        impl Driver for DuplicateKeyDriver {
            fn name(&self) -> &'static str {
                "dup-key-driver"
            }

            fn subscriptions(&self) -> &[ProjectionKey] {
                &self.keys
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let timeline = store.create_timeline("t").unwrap();
        let key = ProjectionKey::new(EntityId::new());
        let driver = DuplicateKeyDriver {
            keys: vec![key.clone(), key],
        };
        let plugin = plugin_with_caps("dup-key-plugin", &[], true, false);
        let mut reg = PluginRegistry::new();
        reg.register(&plugin, None, Some(Box::new(driver))).unwrap();

        let drafts = reg.tick_cadenced(timeline.id(), 0).unwrap();
        assert!(drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_for_subscriptions_handles_duplicate_and_missing_projection_keys() {
        use crate::driver::ProjectionKey;

        let mut reg = PluginRegistry::new();
        reg.projections.register("counter", Box::new(CountReducer));
        let observed_entity = EntityId::new();
        let missing_entity = EntityId::new();

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
        reg.projections.apply_event(&event);

        let observed = ProjectionKey::new(observed_entity);
        let missing = ProjectionKey::new(missing_entity);
        let subscriptions = vec![observed.clone(), observed.clone(), missing.clone()];
        let snapshot = reg.snapshot_for_subscriptions(subscriptions.iter());
        let view = snapshot.view_for(&subscriptions);

        assert_eq!(view.len(), 2);
        assert_eq!(
            view.state_for(&observed)
                .and_then(|state| state.get("n").and_then(serde_json::Value::as_u64)),
            Some(1)
        );
        assert_eq!(view.state_for(&missing), None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cadence_overflow_is_named_and_precedes_every_driver_step() {
        use std::{
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            time::Duration,
        };

        struct CadenceDriver {
            name: &'static str,
            interval: Duration,
            steps: Arc<AtomicUsize>,
        }

        impl Driver for CadenceDriver {
            fn name(&self) -> &'static str {
                self.name
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.steps.fetch_add(1, Ordering::SeqCst);
                Ok(StepOutput::empty())
            }

            fn tick_interval(&self) -> Duration {
                self.interval
            }
        }

        let overflow_steps = Arc::new(AtomicUsize::new(0));
        let untouched_steps = Arc::new(AtomicUsize::new(0));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(CadenceDriver {
            name: "overflow-driver",
            interval: Duration::from_nanos(2),
            steps: Arc::clone(&overflow_steps),
        }));
        registry.register_driver(Box::new(CadenceDriver {
            name: "must-not-step",
            interval: Duration::from_nanos(1),
            steps: Arc::clone(&untouched_steps),
        }));

        let timeline = TimelineId::new();
        registry.tick_cadenced(timeline, u128::MAX - 1).unwrap();
        let error = registry.tick_cadenced(timeline, u128::MAX).unwrap_err();

        assert!(matches!(
            error,
            RuntimeError::CadenceOverflow {
                driver,
                previous_ns,
                interval_ns: 2,
            } if driver == "overflow-driver" && previous_ns == u128::MAX - 1
        ));
        assert_eq!(overflow_steps.load(Ordering::SeqCst), 1);
        assert_eq!(untouched_steps.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cadence_keeps_registration_order_when_a_middle_driver_is_skipped() {
        use std::time::Duration;

        struct OrderedDriver {
            name: &'static str,
            interval: Duration,
        }

        impl Driver for OrderedDriver {
            fn name(&self) -> &'static str {
                self.name
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new(self.name),
                    CanonicalBytes::from_static(b"ordered"),
                )]))
            }

            fn tick_interval(&self) -> Duration {
                self.interval
            }
        }

        let mut registry = PluginRegistry::new();
        for (name, interval) in [
            ("cadence.first", Duration::from_nanos(1)),
            ("cadence.middle", Duration::from_nanos(2)),
            ("cadence.third", Duration::from_nanos(1)),
        ] {
            registry.register_driver(Box::new(OrderedDriver { name, interval }));
        }

        let timeline = TimelineId::new();
        assert_eq!(registry.tick_cadenced(timeline, 0).unwrap().len(), 3);
        let drafts = registry.tick_cadenced(timeline, 1).unwrap();
        assert_eq!(
            drafts
                .iter()
                .map(|draft| draft.event_type.as_str())
                .collect::<Vec<_>>(),
            vec!["cadence.first", "cadence.third"]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_respects_driver_interval() {
        use pos_store::{open_store, StoreConfig};

        struct IntervalDriver;
        impl Driver for IntervalDriver {
            fn name(&self) -> &'static str {
                "interval-driver"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                let event = EventDraft::new(
                    EntityId::new(),
                    Kind::new("interval.tick"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![event]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let timeline = store.create_timeline("t").unwrap();
        let plugin = plugin_with_caps("interval-plugin", &[], true, false);
        let mut reg = PluginRegistry::new();
        reg.register(&plugin, None, Some(Box::new(IntervalDriver)))
            .unwrap();

        let first = reg.tick_cadenced(timeline.id(), 0).unwrap();
        assert_eq!(first.len(), 1);

        let too_early = reg.tick_cadenced(timeline.id(), 50_000_000).unwrap();
        assert!(
            too_early.is_empty(),
            "interval gate should suppress a second tick"
        );

        let ready = reg.tick_cadenced(timeline.id(), 100_000_000).unwrap();
        assert_eq!(
            ready.len(),
            1,
            "interval gate should allow next eligible tick"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_deduplicates_snapshot_subscriptions_across_drivers() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};
        use std::sync::{Arc, Mutex};

        struct SnapshotDriver {
            key: ProjectionKey,
            observed: Arc<Mutex<Vec<usize>>>,
        }

        impl Driver for SnapshotDriver {
            fn name(&self) -> &'static str {
                "snapshot-driver"
            }

            fn subscriptions(&self) -> &[ProjectionKey] {
                std::slice::from_ref(&self.key)
            }

            fn step(
                &mut self,
                _: TimelineId,
                observations: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.observed.lock().unwrap().push(observations.len());
                Ok(StepOutput::empty())
            }
        }

        let mut store = open_store(StoreConfig::Memory).unwrap();
        let timeline = store.create_timeline("t").unwrap();
        let shared_key = ProjectionKey::new(EntityId::new());
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut reg = PluginRegistry::new();

        reg.register_driver(Box::new(SnapshotDriver {
            key: shared_key.clone(),
            observed: observed.clone(),
        }));
        reg.register_driver(Box::new(SnapshotDriver {
            key: shared_key,
            observed: observed.clone(),
        }));

        let drafts = reg.step_all(timeline.id()).unwrap();
        assert_eq!(drafts.len(), 0);

        assert_eq!(observed.lock().unwrap().as_slice(), [1, 1]);
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
        let _ = crate::driver::Driver::step(&mut noop, TimelineId::new(), ObservationView::empty());
        let err = reg.register(&p4, None, Some(Box::new(noop))).unwrap_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn composition_preserves_plugin_order_and_canonicalizes_unordered_registrations() {
        let first = TestPlugin {
            id: PluginId::new(),
            name: "first",
            cap: Capability {
                owned_event_types: vec![Kind::new("z.event")],
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: false,
            },
        };
        let second = TestPlugin {
            id: PluginId::new(),
            name: "second",
            cap: Capability {
                owned_event_types: vec![Kind::new("a.event")],
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: false,
            },
        };
        let mut registry = PluginRegistry::new();
        registry.register(&first, None, None).unwrap();
        registry.register(&second, None, None).unwrap();
        let composition = registry.composition();
        assert_eq!(
            composition
                .plugins
                .iter()
                .map(|plugin| plugin.name.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            composition
                .schemas
                .iter()
                .map(|schema| schema.event_type.as_str())
                .collect::<Vec<_>>(),
            vec!["a.event", "runtime.recorded_output", "z.event"]
        );
    }
}
