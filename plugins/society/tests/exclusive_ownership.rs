//! ADR-024 Revision 1 Decision 2 (user answer 2): the latent
//! `society.signal` overlap (for example the moat proof's own Society Plugin)
//! fails closed when composed with `SocietyPlugin`, whichever registers first.

use pos_core::{Capability, Kind, Plugin, PluginId};
use pos_plugin_society::{SocietyPlugin, SocietyReducer, EVENT_TYPE_SIGNAL};
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

fn proof_society() -> Declarer {
    Declarer {
        id: PluginId::new(),
        name: "society",
        event_type: EVENT_TYPE_SIGNAL,
    }
}

fn register_society(registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
    registry.register_generated(&SocietyPlugin::new(), Some(Box::new(SocietyReducer)), None)
}

#[test]
fn two_society_signal_declarers_fail_closed_in_either_order() {
    let mut society_first = PluginRegistry::new();
    register_society(&mut society_first).test_ok();
    let error = society_first
        .register_generated(&proof_society(), None, None)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, Some(owner_error(EVENT_TYPE_SIGNAL)));
    assert_eq!(society_first.len(), 1);

    let mut proof_first = PluginRegistry::new();
    proof_first
        .register_generated(&proof_society(), None, None)
        .test_ok();
    let error = register_society(&mut proof_first)
        .err()
        .map(|error| error.to_string());
    assert_eq!(error, Some(owner_error(EVENT_TYPE_SIGNAL)));
    assert_eq!(proof_first.len(), 1);
}
