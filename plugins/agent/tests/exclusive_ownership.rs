//! ADR-024 Revision 1 Decisions 3 and 7: one `AgentPlugin` registration per
//! registry. Many simulated entities are entities of that one registration;
//! a second `AgentPlugin` registration, or any second claimant of the
//! Recorder type, is rejected.

use pos_core::{Capability, EntityId, Kind, Plugin, PluginId};
use pos_plugin_agent::{
    AgentDriver, AgentPlugin, AgentReducer, RoundRobinPolicy, EVENT_TYPE_ACTION,
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, PluginCompositionErrorV1, PluginRegistry, RuntimeError,
};

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

fn register_agent(registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
    registry.register_generated(
        &AgentPlugin::new(),
        Some(Box::new(AgentReducer)),
        Some(Box::new(AgentDriver::new(
            EntityId::new(),
            Box::new(RoundRobinPolicy::new(vec!["wait".to_owned()])),
            vec!["wait".to_owned()],
        ))),
    )
}

#[test]
fn a_second_agent_plugin_registration_is_rejected() {
    let mut registry = PluginRegistry::new();
    register_agent(&mut registry).test_ok();
    let error = register_agent(&mut registry)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, owner_error(EVENT_TYPE_ACTION));
    assert_eq!(registry.len(), 1);
}

#[test]
fn a_second_recorder_claimant_is_rejected_beside_the_agent() {
    let mut registry = PluginRegistry::new();
    register_agent(&mut registry).test_ok();
    let recorder = Declarer {
        id: PluginId::new(),
        name: "second-recorder",
        event_type: RECORDER_EVENT_TYPE,
    };
    let error = registry
        .register_generated(&recorder, None, None)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, owner_error(RECORDER_EVENT_TYPE));
    assert_eq!(registry.len(), 1);
}
