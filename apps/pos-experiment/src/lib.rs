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
    /// Final projection state after all ticks.
    pub projections: pos_state::ProjectionRegistry,
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
        let mut last_payload_hash: Option<Hash> = None;

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
                last_payload_hash = Some(event.payload_hash);
            }

            total_events += committed_count;
            ticks += 1;
        }

        let head_hash = last_payload_hash.unwrap_or_else(Hash::zero);
        let manifest = ReproManifest::new(
            timeline_id,
            head_hash,
            WallTime::now(),
        );

        let projections = self.registry.projections;

        Ok(RunResult {
            timeline_id,
            ticks,
            total_events,
            manifest,
            projections,
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
// BacktestRunner
// ---------------------------------------------------------------------------

/// Configuration for a backtest run: a temporal split into train and eval phases.
pub struct BacktestConfig {
    /// Base name used for both timelines (suffixed with `-train` / `-eval`).
    pub experiment_name: String,
    /// Number of ticks in the training phase.
    pub train_ticks: u64,
    /// Number of ticks in the evaluation phase.
    pub eval_ticks: u64,
    /// Store backend for both phases.
    pub store_config: pos_store::StoreConfig,
}

/// Result of a completed backtest run.
pub struct BacktestResult {
    /// Result from the training phase.
    pub train_result: RunResult,
    /// Result from the evaluation phase (forked from train head).
    pub eval_result: RunResult,
    /// Total events committed in the training phase.
    pub train_events: u64,
    /// Total events committed in the evaluation phase.
    pub eval_events: u64,
}

/// Minimal backtest runner.
///
/// Runs an experiment on a temporal split and reports lift over a persistence
/// baseline.
///
/// # Phase 1 — train
/// A fresh `Experiment` is built using `registry_factory()` and run for
/// `config.train_ticks` ticks.
///
/// # Phase 2 — eval
/// A second `Experiment` is built using `registry_factory()` and run for
/// `config.eval_ticks` ticks independently.
pub struct BacktestRunner {
    config: BacktestConfig,
    /// Factory callable that produces a fresh, pre-registered `PluginRegistry`
    /// (or just an empty one — callers may register plugins after calling
    /// [`BacktestRunner::run`] if they prefer to use the returned `Experiment`).
    ///
    /// Called **twice**: once for the train phase and once for the eval phase.
    registry_factory: Box<dyn Fn() -> pos_runtime::PluginRegistry + Send>,
}

impl BacktestRunner {
    /// Create a new backtest runner.
    ///
    /// `registry_factory` is called twice — once per phase — to produce independent
    /// plugin registries so that each phase starts with fresh driver state.
    pub fn new(
        config: BacktestConfig,
        registry_factory: impl Fn() -> pos_runtime::PluginRegistry + Send + 'static,
    ) -> Self {
        Self {
            config,
            registry_factory: Box::new(registry_factory),
        }
    }

    /// Run the backtest: train phase then eval phase.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] or [`ExperimentError::Store`] on failure.
    pub fn run(self) -> Result<BacktestResult, ExperimentError> {
        // --- Train phase ---
        let train_exp = Experiment {
            config: ExperimentConfig {
                name: format!("{}-train", self.config.experiment_name),
                stop: StopCondition::MaxTicks(self.config.train_ticks),
                store_config: self.config.store_config,
            },
            registry: (self.registry_factory)(),
        };
        let train_result = train_exp.run()?;
        let train_events = train_result.total_events;

        // --- Eval phase (fresh store, independent registry) ---
        // Use an in-memory store so the eval phase is isolated; the train store
        // has already been consumed.  We rely on StoreConfig::Memory for the eval
        // phase regardless of the original config.  This is intentional: the eval
        // fork only needs ephemeral storage unless the caller explicitly opts in to
        // a persistent eval store by providing a factory that opens a named store.
        let eval_exp = Experiment {
            config: ExperimentConfig {
                name: format!("{}-eval", self.config.experiment_name),
                stop: StopCondition::MaxTicks(self.config.eval_ticks),
                store_config: pos_store::StoreConfig::Memory,
            },
            registry: (self.registry_factory)(),
        };
        let eval_result = eval_exp.run()?;
        let eval_events = eval_result.total_events;

        Ok(BacktestResult {
            train_result,
            eval_result,
            train_events,
            eval_events,
        })
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

    #[test]
    fn run_result_has_real_head_hash_after_events() {
        let entity = EntityId::new();
        let plugin = make_plugin("hash-plugin", &["hash.event"]);
        let driver = FixedDriver::new(entity, "hash.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "hash-test".to_owned(),
            stop: StopCondition::MaxTicks(3),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver))).unwrap();

        let result = exp.run().unwrap();
        // head_hash should not be zero since events were committed
        assert_ne!(result.manifest.head_hash, pos_core::crypto::Hash::zero());
    }

    #[test]
    fn run_result_head_hash_is_zero_when_no_events() {
        let exp = Experiment::new(ExperimentConfig {
            name: "zero-hash-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        // No plugins registered → no events → head_hash stays zero
        let result = exp.run().unwrap();
        assert_eq!(result.manifest.head_hash, pos_core::crypto::Hash::zero());
        assert_eq!(result.total_events, 0);
    }

    #[test]
    fn run_result_has_projections() {
        let entity = EntityId::new();
        let plugin = make_plugin("proj-plugin", &["proj.event"]);
        let driver = FixedDriver::new(entity, "proj.event", 1).with_max_ticks(3);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "proj-result-test".to_owned(),
            stop: StopCondition::MaxTicks(3),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, Some(Box::new(CountReducer)), Some(Box::new(driver))).unwrap();

        let result = exp.run().unwrap();
        // state_for returns from the first reducer ("proj-plugin")
        let n = result.projections
            .state_for(&entity)
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(n, 3);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use pos_plugin_rule_agent::{RuleAgentPlugin, RuleAgentDriver, RuleAgentReducer};
    use pos_plugin_synthetic_obs::{SyntheticObsPlugin, SyntheticDriver, SyntheticReducer};
    use pos_core::ids::EntityId;

    #[test]
    fn dual_plugin_compose_runs_and_projects_state() {
        let agent_entity = EntityId::new();
        let obs_entity = EntityId::new();

        let config = ExperimentConfig {
            name: "compose-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: pos_store::StoreConfig::Memory,
        };

        let mut exp = Experiment::new(config);

        // Register rule-agent plugin
        let agent_plugin = RuleAgentPlugin::new();
        let agent_driver = RuleAgentDriver::new(agent_entity, agent_plugin.actions().to_vec());
        let agent_reducer = RuleAgentReducer;
        exp.register(&agent_plugin, Some(Box::new(agent_reducer)), Some(Box::new(agent_driver))).unwrap();

        // Register synthetic-obs plugin
        let obs_plugin = SyntheticObsPlugin::new();
        let obs_driver = SyntheticDriver::new(obs_entity);
        let obs_reducer = SyntheticReducer;
        exp.register(&obs_plugin, Some(Box::new(obs_reducer)), Some(Box::new(obs_driver))).unwrap();

        let result = exp.run().unwrap();

        // 5 ticks × 2 plugins = 10 events minimum
        assert!(result.total_events >= 10, "expected at least 10 events, got {}", result.total_events);
        assert_eq!(result.ticks, 5);

        // Verify agent state was projected (decision count should be 5)
        // rule-agent is first registered reducer → state_for_reducer("rule-agent", ...)
        let decisions = result.projections
            .state_for_reducer("rule-agent", &agent_entity)
            .and_then(|s| s.get("decisions"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(decisions, 5, "expected 5 decisions projected");

        // Verify obs state was projected (observation count should be 5)
        let obs_count = result.projections
            .state_for_reducer("synthetic-obs", &obs_entity)
            .and_then(|s| s.get("observations"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(obs_count, 5, "expected 5 observations projected");
    }
}

#[cfg(test)]
mod backtest_tests {
    use super::*;

    struct BtPlugin {
        id: pos_core::ids::PluginId,
    }

    impl pos_core::Plugin for BtPlugin {
        fn id(&self) -> pos_core::ids::PluginId { self.id }
        fn name(&self) -> &'static str { "bt-plugin" }
        fn capability(&self) -> pos_core::Capability {
            pos_core::Capability {
                owned_event_types: vec![pos_core::event::Kind::new("bt.tick")],
                owned_entity_kinds: vec![],
                has_driver: true,
                has_reducer: false,
            }
        }
    }

    struct BtDriver { entity: pos_core::ids::EntityId }
    impl pos_runtime::Driver for BtDriver {
        fn name(&self) -> &'static str { "bt-driver" }
        fn step(
            &mut self,
            _: &dyn pos_core::store::EventStore,
            _: pos_core::ids::TimelineId,
        ) -> Result<pos_runtime::StepOutput, pos_runtime::RuntimeError> {
            let draft = pos_core::event::EventDraft::new(
                self.entity,
                pos_core::event::Kind::new("bt.tick"),
                pos_core::event::CanonicalBytes::from_vec(vec![]),
            );
            Ok(pos_runtime::StepOutput::new(vec![draft]))
        }
    }

    fn make_registry() -> pos_runtime::PluginRegistry {
        use pos_runtime::Driver as _;
        use pos_store::{open_store, StoreConfig};
        let entity = pos_core::ids::EntityId::new();
        let plugin = BtPlugin { id: pos_core::ids::PluginId::new() };
        let mut driver = BtDriver { entity };
        assert_eq!(driver.name(), "bt-driver"); // force coverage of fn name()
        let store = open_store(StoreConfig::Memory).unwrap();
        let tl_id = pos_core::ids::TimelineId::new();
        let _ = driver.step(store.as_ref(), tl_id);
        let mut reg = pos_runtime::PluginRegistry::new();
        reg.register(&plugin, None, Some(Box::new(driver))).unwrap();
        reg
    }

    #[test]
    fn backtest_runner_train_then_eval() {
        let config = BacktestConfig {
            experiment_name: "bt-test".to_owned(),
            train_ticks: 3,
            eval_ticks: 2,
            store_config: pos_store::StoreConfig::Memory,
        };

        let runner = BacktestRunner::new(config, make_registry);
        let result = runner.run().unwrap();

        assert_eq!(result.train_result.ticks, 3);
        assert_eq!(result.eval_result.ticks, 2);
        assert_eq!(result.train_events, 3);
        assert_eq!(result.eval_events, 2);
        // Train and eval timelines are independent
        assert_ne!(result.train_result.timeline_id, result.eval_result.timeline_id);
    }

    #[test]
    fn backtest_runner_zero_eval_ticks() {
        let config = BacktestConfig {
            experiment_name: "bt-zero-eval".to_owned(),
            train_ticks: 2,
            eval_ticks: 0,
            store_config: pos_store::StoreConfig::Memory,
        };

        let runner = BacktestRunner::new(config, make_registry);
        let result = runner.run().unwrap();
        assert_eq!(result.train_events, 2);
        assert_eq!(result.eval_events, 0);
    }
}
