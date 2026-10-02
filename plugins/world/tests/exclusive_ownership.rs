//! ADR-024 Revision 1 Decision 2 (user answer 2): the latent
//! `world.action.v1` overlap fails closed when a composition installs
//! `WorldPlugin` together with another declarer, whichever registers first.

use pos_core::{Capability, Kind, Plugin, PluginId};
use pos_plugin_world::{WorldDriver, WorldPlugin, WorldReducer, EVENT_TYPE_ACTION_V1};
use pos_runtime::{PluginCompositionErrorV1, PluginRegistry, RuntimeError};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected ownership fixture error: {error:?}"
            )))
        })
    }
}

/// A second, independent declarer of one Event type.
struct Declarer {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
}

impl Plugin for Declarer {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            ..Capability::default()
        }
    }
}

fn owner_error(event_type: &str) -> Option<String> {
    Some(
        RuntimeError::Composition(PluginCompositionErrorV1::DuplicateEventTypeOwner {
            event_type: event_type.to_owned(),
        })
        .to_string(),
    )
}

fn register_world(registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
    registry.register_generated(
        &WorldPlugin::new(),
        Some(Box::new(WorldReducer)),
        Some(Box::new(WorldDriver::default())),
    )
}

fn human_action() -> Declarer {
    Declarer {
        id: PluginId::new(),
        name: "human-action",
        event_type: EVENT_TYPE_ACTION_V1,
    }
}

#[test]
fn world_and_another_world_action_declarer_fail_closed_in_either_order() {
    let mut world_first = PluginRegistry::new();
    register_world(&mut world_first).test_ok();
    let error = world_first
        .register_generated(&human_action(), None, None)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, owner_error(EVENT_TYPE_ACTION_V1));
    assert_eq!(world_first.len(), 1);

    let mut declarer_first = PluginRegistry::new();
    declarer_first
        .register_generated(&human_action(), None, None)
        .test_ok();
    let error = register_world(&mut declarer_first)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, owner_error(EVENT_TYPE_ACTION_V1));
    assert_eq!(declarer_first.len(), 1);
}
