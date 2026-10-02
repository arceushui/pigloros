//! ADR-021 Revision 3 Decision 4 (#484): an `ExperimentSession` scheduled
//! pass applies the same Plugin draft-ownership rule as the
//! participant-authorized path, on `MemoryStore` and `SQLite`.

use std::sync::Arc;

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    store::EventStore,
    AuthorityErrorV1, ErasureContainmentGateV1,
};
use pos_experiment::{Experiment, ExperimentConfig, ExperimentError, StopCondition};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use pos_store::{sqlite::SqliteStore, SeqRange, StoreConfig};

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

const OWNER_EVENT: &str = "ownership.owner.v1";
const INTRUDER_EVENT: &str = "ownership.intruder.v1";

/// A Plugin that owns exactly one Event type.
struct OwningPlugin {
    id: PluginId,
    name: &'static str,
    owned: &'static str,
}

impl Plugin for OwningPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.owned)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// A Driver that emits one draft of `emits` on every step.
struct EmittingDriver {
    name: &'static str,
    emits: &'static str,
}

impl Driver for EmittingDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            EntityId::new(),
            Kind::new(self.emits),
            CanonicalBytes::from_static(b"draft"),
        )]))
    }
}

/// An experiment whose second Driver emits the first Plugin's Event type.
fn experiment(store_config: StoreConfig) -> Experiment {
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "scheduled-draft-ownership".to_owned(),
        stop: StopCondition::MaxTicks(4),
        store_config,
    });
    for (name, owned) in [("owner", OWNER_EVENT), ("intruder", INTRUDER_EVENT)] {
        experiment
            .register_generated(
                &OwningPlugin {
                    id: PluginId::new(),
                    name,
                    owned,
                },
                None,
                Some(Box::new(EmittingDriver {
                    name,
                    emits: OWNER_EVENT,
                })),
            )
            .test_ok();
    }
    experiment
}

/// Step the session once, expect the ownership rejection, and return the
/// session's Timeline after confirming the session faulted closed.
fn reject_foreign_draft(store_config: StoreConfig) -> TimelineId {
    let mut session = experiment(store_config).start().test_ok();
    assert!(matches!(
        session.step_tick(),
        Err(ExperimentError::Runtime(RuntimeError::Authority(
            AuthorityErrorV1::UnauthorizedSource
        )))
    ));
    assert!(matches!(
        session.step_tick(),
        Err(ExperimentError::SessionFaulted)
    ));
    assert!(session.source_events().test_ok().is_empty());
    session.timeline().id()
}

#[test]
fn memory_session_rejects_another_plugins_event_type_and_commits_nothing() {
    reject_foreign_draft(StoreConfig::Memory);
}

#[test]
fn sqlite_session_rejects_another_plugins_event_type_and_commits_nothing() {
    let directory = tempfile::tempdir().test_ok();
    let path = directory
        .path()
        .join("ownership.db")
        .to_string_lossy()
        .into_owned();
    let timeline = reject_foreign_draft(StoreConfig::Sqlite { path: path.clone() });

    // Reopen the durable store: the rejected pass left no Event behind.
    let mut store = SqliteStore::open(&path).test_ok();
    store
        .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
        .test_ok();
    assert!(store.read(timeline, SeqRange::all()).test_ok().is_empty());
}
