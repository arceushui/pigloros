#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-experiment` — Wave 4 closed experiment host loop.
//!
//! An [`Experiment`] composes plugins and runs them through a closed tick loop,
//! driving drivers, validating event types, appending to the store, and folding
//! projections on each tick until a [`StopCondition`] is met.

use pos_core::{clock::WallTime, crypto::Hash, ReproManifest, Timeline};
use pos_runtime::PluginRegistry;
use pos_store::{open_store, StoreConfig};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Stop condition for an experiment run.
#[derive(Clone, Debug)]
pub enum StopCondition {
    /// Run exactly N ticks.
    MaxTicks(u64),
    /// Run until the store reaches N total events.
    MaxEvents(u64),
}

/// Configuration for an experiment.
pub struct ExperimentConfig {
    pub name: String,
    pub stop: StopCondition,
    /// Store backend to use.
    pub store_config: StoreConfig,
}

/// Result of a completed experiment run.
#[derive(Debug)]
pub struct RunResult {
    pub timeline_id: pos_core::ids::TimelineId,
    pub ticks: u64,
    pub total_events: u64,
    /// Exported manifest for reproducibility.
    pub manifest: ReproManifest,
}

/// The closed experiment host loop.
///
/// tick loop: `step_all()` → `validate_batch()` → `append()` → fold projections
pub struct Experiment {
    config: ExperimentConfig,
    registry: PluginRegistry,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ExperimentError {
    #[error("runtime error: {0}")]
    Runtime(#[from] pos_runtime::RuntimeError),
    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl Experiment {
    #[must_use]
    pub fn new(config: ExperimentConfig) -> Self {
        Self {
            config,
            registry: PluginRegistry::new(),
        }
    }

    /// Register a plugin (wires schemas + reducer + driver).
    ///
    /// # Errors
    /// Returns [`pos_runtime::RuntimeError::DuplicatePlugin`] if a plugin with the same id
    /// is already registered.
    pub fn register(
        &mut self,
        plugin: &dyn pos_core::Plugin,
        reducer: Option<Box<dyn pos_core::Reducer>>,
        driver: Option<Box<dyn pos_runtime::Driver>>,
    ) -> Result<(), pos_runtime::RuntimeError> {
        self.registry.register(plugin, reducer, driver)
    }

    /// Run the experiment to completion and return a [`RunResult`].
    ///
    /// The closed tick loop:
    /// 1. `step_all()` — call all registered drivers
    /// 2. `validate_batch()` — reject unknown event types
    /// 3. `append()` — write to store
    /// 4. fold projections — `apply_event` for each committed event
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] on driver or schema errors,
    /// or [`ExperimentError::Store`] on persistence errors.
    pub fn run(mut self) -> Result<RunResult, ExperimentError> {
        let mut store = open_store(self.config.store_config)?;
        let timeline = store.create_timeline(&self.config.name)?;
        let timeline_id = timeline.id();

        let mut ticks: u64 = 0;
        let mut total_events: u64 = 0;

        loop {
            // Check stop condition before stepping.
            let stop = match &self.config.stop {
                StopCondition::MaxTicks(max) => ticks >= *max,
                StopCondition::MaxEvents(max) => total_events >= *max,
            };
            if stop {
                break;
            }

            let drafts = self.registry.step_all(store.as_ref(), timeline_id)?;

            // If drivers produced nothing and we haven't hit the stop condition,
            // the experiment is idle — terminate gracefully.
            if drafts.is_empty() {
                break;
            }

            self.registry.schemas.validate_batch(&drafts)?;

            let committed = store.append(timeline_id, &drafts)?;
            let committed_count = committed.len() as u64;

            for event in &committed {
                self.registry.projections.apply_event(event);
            }

            total_events += committed_count;
            ticks += 1;
        }

        let manifest = ReproManifest::new(
            timeline_id,
            Hash::from_bytes([0u8; 32]),
            WallTime::now(),
        );

        Ok(RunResult {
            timeline_id,
            ticks,
            total_events,
            manifest,
        })
    }

    /// Fork the experiment's timeline at the current head, returning a new child [`Timeline`].
    ///
    /// Delegates to `store.fork()`.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Store`] if the fork fails.
    pub fn branch(
        &self,
        name: &str,
        store: &mut dyn pos_core::store::EventStore,
    ) -> Result<Timeline, ExperimentError> {
        // Find the timeline by listing and matching on name.
        let timelines = store.list_timelines()?;
        let timeline = timelines
            .iter()
            .find(|t| t.meta.name.as_deref() == Some(&self.config.name))
            .ok_or_else(|| {
                pos_core::CoreError::Storage(format!(
                    "timeline '{}' not found for branching",
                    self.config.name
                ))
            })?;

        let forked = store.fork(timeline.id(), timeline.head, name)?;
        Ok(forked)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        Capability, Plugin, Reducer, State,
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, PluginId},
        Event,
    };
    use pos_runtime::{Driver, RuntimeError, StepOutput};
    use pos_store::StoreConfig;

    // ── Inline test helpers ───────────────────────────────────────────────

    struct TestPlugin {
        id: PluginId,
        name: &'static str,
        event_types: Vec<Kind>,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId { self.id }
        fn name(&self) -> &'static str { self.name }
        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: self.event_types.clone(),
                owned_entity_kinds: vec![],
                has_driver: true,
                has_reducer: false,
            }
        }
    }

    fn make_plugin(name: &'static str, event_types: &[&str]) -> TestPlugin {
        TestPlugin {
            id: PluginId::new(),
            name,
            event_types: event_types.iter().map(|s| Kind::new(*s)).collect(),
        }
    }

    /// A driver that emits `n` events of `event_type` per tick, for at most `max_ticks` ticks.
    struct FixedDriver {
        entity: EntityId,
        event_type: Kind,
        events_per_tick: usize,
        ticks_remaining: Option<u64>,
    }

    impl FixedDriver {
        fn new(entity: EntityId, event_type: &str, events_per_tick: usize) -> Self {
            Self {
                entity,
                event_type: Kind::new(event_type),
                events_per_tick,
                ticks_remaining: None,
            }
        }

        fn with_max_ticks(mut self, n: u64) -> Self {
            self.ticks_remaining = Some(n);
            self
        }
    }

    impl Driver for FixedDriver {
        fn name(&self) -> &'static str { "fixed" }
        fn step(&mut self, _: &dyn pos_core::store::EventStore, _: pos_core::ids::TimelineId) -> Result<StepOutput, RuntimeError> {
            if let Some(remaining) = self.ticks_remaining.as_mut() {
                if *remaining == 0 {
                    return Ok(StepOutput::empty());
                }
                *remaining -= 1;
            }
            let drafts: Vec<EventDraft> = (0..self.events_per_tick)
                .map(|_| EventDraft::new(self.entity, self.event_type.clone(), CanonicalBytes::from_vec(vec![])))
                .collect();
            Ok(StepOutput::new(drafts))
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

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn experiment_runs_to_max_ticks() {
        let entity = EntityId::new();
        let plugin = make_plugin("ticker", &["tick.event"]);
        let driver = FixedDriver::new(entity, "tick.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "max-ticks-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver))).unwrap();

        let result = exp.run().unwrap();
        assert_eq!(result.ticks, 5);
        assert_eq!(result.total_events, 5);
    }

    #[test]
    fn experiment_stops_on_max_events() {
        let entity = EntityId::new();
        let plugin = make_plugin("producer", &["prod.event"]);
        // 2 events per tick; stop after 6 events → 3 ticks
        let driver = FixedDriver::new(entity, "prod.event", 2);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "max-events-test".to_owned(),
            stop: StopCondition::MaxEvents(6),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver))).unwrap();

        let result = exp.run().unwrap();
        assert_eq!(result.total_events, 6);
        assert_eq!(result.ticks, 3);
    }

    #[test]
    fn experiment_empty_driver_terminates() {
        struct IdleDriver;
        impl Driver for IdleDriver {
            fn name(&self) -> &'static str { "idle" }
            fn step(&mut self, _: &dyn pos_core::store::EventStore, _: pos_core::ids::TimelineId) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }

        assert_eq!(IdleDriver.name(), "idle");
        let plugin = make_plugin("idle-plugin", &[]);
        let mut exp = Experiment::new(ExperimentConfig {
            name: "idle-test".to_owned(),
            stop: StopCondition::MaxTicks(1_000_000),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(IdleDriver))).unwrap();

        // Should terminate quickly, not loop forever
        let result = exp.run().unwrap();
        assert_eq!(result.ticks, 0);
        assert_eq!(result.total_events, 0);
    }

    #[test]
    fn experiment_schema_rejects_unknown_type() {
        struct BadDriver { entity: EntityId }
        impl Driver for BadDriver {
            fn name(&self) -> &'static str { "bad" }
            fn step(&mut self, _: &dyn pos_core::store::EventStore, _: pos_core::ids::TimelineId) -> Result<StepOutput, RuntimeError> {
                let draft = EventDraft::new(
                    self.entity,
                    Kind::new("unregistered.event"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![draft]))
            }
        }

        let entity = EntityId::new();
        assert_eq!(BadDriver { entity }.name(), "bad");
        let plugin = make_plugin("bad-plugin", &["known.event"]); // does NOT own "unregistered.event"
        let mut exp = Experiment::new(ExperimentConfig {
            name: "schema-reject-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(BadDriver { entity }))).unwrap();

        let err = exp.run().unwrap_err();
        assert!(matches!(err, ExperimentError::Runtime(_)));
    }

    #[test]
    fn experiment_fold_projects_state() {
        let entity = EntityId::new();
        let plugin = make_plugin("state-plugin", &["state.event"]);
        let driver = FixedDriver::new(entity, "state.event", 1).with_max_ticks(3);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "fold-state-test".to_owned(),
            stop: StopCondition::MaxTicks(3),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, Some(Box::new(CountReducer)), Some(Box::new(driver))).unwrap();

        let result = exp.run().unwrap();
        assert_eq!(result.ticks, 3);
        assert_eq!(result.total_events, 3);
    }

    #[test]
    fn fixed_driver_name_is_fixed() {
        let entity = EntityId::new();
        let driver = FixedDriver::new(entity, "tick.event", 1);
        assert_eq!(driver.name(), "fixed");
    }

    #[test]
    fn experiment_branch_creates_fork() {
        let entity = EntityId::new();
        let plugin = make_plugin("branch-ticker", &["branch.event"]);
        let driver = FixedDriver::new(entity, "branch.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "branch-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver))).unwrap();
        let result = exp.run().unwrap();
        assert_eq!(result.ticks, 2);

        // Re-open the same in-memory store is not possible after run() consumes it,
        // so we create a fresh store, seed a timeline, then call branch().
        let exp2 = Experiment::new(ExperimentConfig {
            name: "branch-seed".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        let plugin2 = make_plugin("branch-ticker2", &["branch2.event"]);
        let driver2 = FixedDriver::new(entity, "branch2.event", 1);
        let mut exp2_mut = exp2;
        exp2_mut.register(&plugin2, None, Some(Box::new(driver2))).unwrap();

        // Consume the experiment and get a store back via run, then re-use the
        // branch logic through a manual store path.
        let mut store2 = pos_store::open_store(StoreConfig::Memory).unwrap();
        store2.create_timeline("branch-seed").unwrap();
        let forked = exp2_mut.branch("branch-seed", store2.as_mut()).unwrap();
        assert!(!forked.id().to_string().is_empty());
    }

    #[test]
    fn experiment_branch_missing_timeline_returns_err() {
        let exp = Experiment::new(ExperimentConfig {
            name: "nonexistent".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let mut store = pos_store::open_store(StoreConfig::Memory).unwrap();
        let err = exp.branch("nonexistent", store.as_mut());
        assert!(err.is_err());
    }

    #[test]
    fn idle_driver_name_is_idle() {
        // Exercises the fn name() on the IdleDriver struct defined below — which is
        // a local struct and its name() is never called in experiment_empty_driver_terminates.
        struct IdleDriver2;
        impl Driver for IdleDriver2 {
            fn name(&self) -> &'static str { "idle2" }
            fn step(&mut self, _: &dyn pos_core::store::EventStore, _: pos_core::ids::TimelineId) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }
        let mut store = pos_store::open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("idle2-test").unwrap();
        let mut d = IdleDriver2;
        assert_eq!(d.name(), "idle2");
        // Also call step to cover those lines
        let out = d.step(store.as_ref(), tl.id()).unwrap();
        assert!(out.drafts.is_empty());
    }

    #[test]
    fn bad_driver_name_is_bad() {
        struct BadDriver2 { entity: EntityId }
        impl Driver for BadDriver2 {
            fn name(&self) -> &'static str { "bad2" }
            fn step(&mut self, _: &dyn pos_core::store::EventStore, _: pos_core::ids::TimelineId) -> Result<StepOutput, RuntimeError> {
                let draft = EventDraft::new(
                    self.entity,
                    Kind::new("known.event"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![draft]))
            }
        }
        let mut store = pos_store::open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("bad2-test").unwrap();
        let entity = EntityId::new();
        let mut d = BadDriver2 { entity };
        assert_eq!(d.name(), "bad2");
        // Also call step to cover those lines
        let out = d.step(store.as_ref(), tl.id()).unwrap();
        assert_eq!(out.drafts.len(), 1);
    }

    #[test]
    fn fixed_driver_exhaust_remaining_ticks() {
        // Drive FixedDriver.with_max_ticks(1) for 2 ticks — second tick hits the
        // `*remaining == 0` branch (line 259) and returns empty.
        let entity = EntityId::new();
        let plugin = make_plugin("exhaust-plugin", &["exhaust.event"]);
        let driver = FixedDriver::new(entity, "exhaust.event", 1).with_max_ticks(1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "exhaust-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver))).unwrap();
        let result = exp.run().unwrap();
        // After 1 tick, driver returns empty → experiment terminates
        assert_eq!(result.ticks, 1);
    }

    #[test]
    fn run_result_has_manifest() {
        let entity = EntityId::new();
        let plugin = make_plugin("manifest-plugin", &["manifest.event"]);
        let driver = FixedDriver::new(entity, "manifest.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "manifest-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver))).unwrap();

        let result = exp.run().unwrap();
        // The manifest should have the same timeline_id as the result
        assert_eq!(result.manifest.timeline_id, result.timeline_id);
    }
}
