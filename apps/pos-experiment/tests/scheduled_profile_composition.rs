//! ADR-021 Revision 3 Decision 2 (#504): an experiment host has no
//! Participants, so it composes every Driver it runs as non-participant and
//! rejects a participant-bound Driver at composition, on `MemoryStore` and
//! `SQLite`.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
};
use pos_experiment::{
    BacktestConfig, BacktestRunner, Experiment, ExperimentConfig, ExperimentError, StopCondition,
};
use pos_runtime::{
    Driver, ObservationView, PluginRegistry, RuntimeError, ScheduledDriverBindingV1, StepOutput,
};
use pos_store::StoreConfig;

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }
}

const EVENT: &str = "composition.world.v1";
const REFUSAL: &str = "scheduled Driver 'world' is not composed for the NonParticipant profile";

/// A Plugin that owns one Event type and has a Driver.
struct WorldPlugin {
    id: PluginId,
}

impl Plugin for WorldPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "world"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// A Driver that emits one draft of its Plugin's Event type on every step.
struct WorldDriver;

impl Driver for WorldDriver {
    fn name(&self) -> &'static str {
        "world"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            EntityId::new(),
            Kind::new(EVENT),
            CanonicalBytes::from_static(b"tick"),
        )]))
    }
}

/// A fresh registry holding the world Driver, bound to an ADR-059
/// Participant when `participant` is set and left unassigned otherwise.
fn world_registry(plugin_id: PluginId, participant: bool) -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    registry
        .register_generated(
            &WorldPlugin { id: plugin_id },
            None,
            Some(Box::new(WorldDriver)),
        )
        .test_ok();
    if participant {
        let binding = ScheduledDriverBindingV1::Participant(EntityId::new());
        registry
            .compose_scheduled_profiles(&[(plugin_id, binding)])
            .test_ok();
    }
    registry
}

fn store_configs(directory: &tempfile::TempDir, file: &str) -> [(&'static str, StoreConfig); 2] {
    let path = directory.path().join(file).to_string_lossy().into_owned();
    [
        ("memory", StoreConfig::Memory),
        ("sqlite", StoreConfig::Sqlite { path }),
    ]
}

/// Run a one-tick backtest whose registry factory hands out a
/// participant-bound registry from call `participant_from` onwards.
fn backtest(store_config: StoreConfig, participant_from: usize) -> ExperimentError {
    let calls = Arc::new(AtomicUsize::new(0));
    let plugin_id = PluginId::new();
    let factory = move || {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        world_registry(plugin_id, call >= participant_from)
    };
    let config = BacktestConfig {
        experiment_name: format!("composition-backtest-{participant_from}"),
        train_ticks: 1,
        eval_ticks: 1,
        store_config,
    };
    match BacktestRunner::new(config, factory).run() {
        Ok(_) => std::panic::resume_unwind(Box::new("expected a composition refusal")),
        Err(error) => error,
    }
}

#[test]
fn backtest_composes_each_phase_and_rejects_a_participant_bound_driver() {
    let directory = tempfile::tempdir().test_ok();
    for participant_from in [0, 1] {
        let file = format!("backtest-{participant_from}.db");
        for (name, store_config) in store_configs(&directory, &file) {
            let refused = backtest(store_config, participant_from);
            assert_eq!(
                refused.to_string(),
                format!("runtime error: {REFUSAL}"),
                "{name} phase {participant_from}"
            );
        }
    }
}

#[test]
fn session_composes_its_drivers_and_rejects_a_participant_bound_fork_registry() {
    let directory = tempfile::tempdir().test_ok();
    for (name, store_config) in store_configs(&directory, "session.db") {
        let plugin_id = PluginId::new();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: format!("composition-session-{name}"),
            stop: StopCondition::MaxTicks(1),
            store_config,
        })
        .with_fork_registry_factory(move || Ok(world_registry(plugin_id, true)));
        experiment
            .register_generated(
                &WorldPlugin { id: plugin_id },
                None,
                Some(Box::new(WorldDriver)),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        session.step_tick().test_ok();
        assert_eq!(session.source_events().test_ok().len(), 1, "{name}");
        let refused = session
            .fork("participant-child")
            .err()
            .map(|error| error.to_string());
        assert_eq!(refused, Some(format!("runtime error: {REFUSAL}")), "{name}");
    }
}
