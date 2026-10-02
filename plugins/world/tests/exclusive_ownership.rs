//! ADR-024 Revision 1 Decision 2 (user answer 2): the latent
//! `world.action.v1` overlap fails closed when a composition installs
//! `WorldPlugin` together with another declarer (the Gateway action Plugin or
//! the human-action fixture). Order independence of the shared check is
//! proven in `pos-runtime`'s `event_type_ownership` tests.

use pos_core::{Capability, Kind, Plugin, PluginId};
use pos_plugin_world::{WorldPlugin, EVENT_TYPE_ACTION_V1};
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

fn owner_error(event_type: &str) -> String {
    RuntimeError::Composition(PluginCompositionErrorV1::DuplicateEventTypeOwner {
        event_type: event_type.to_owned(),
    })
    .to_string()
}

fn human_action() -> Declarer {
    Declarer {
        id: PluginId::new(),
        name: "human-action",
        event_type: EVENT_TYPE_ACTION_V1,
    }
}

#[test]
fn world_after_another_world_action_declarer_fails_closed() {
    let mut registry = PluginRegistry::new();
    registry
        .register_generated(&human_action(), None, None)
        .test_ok();
    // The shared ownership check runs before every capability check, so the
    // second claimant is rejected for its Event type alone.
    let error = registry
        .register_generated(&WorldPlugin::new(), None, None)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, Some(owner_error(EVENT_TYPE_ACTION_V1)));
    assert_eq!(registry.len(), 1);
}
