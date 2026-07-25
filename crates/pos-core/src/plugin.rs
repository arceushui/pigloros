use serde::{Deserialize, Serialize};

use crate::event::Kind;
use crate::ids::PluginId;

/// What a plugin can do — the capabilities it registers with the runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Event types this plugin declares and owns.
    pub owned_event_types: Vec<Kind>,
    /// Entity kind names this plugin introduces.
    pub owned_entity_kinds: Vec<String>,
    /// Whether this plugin provides a Driver/Stepper.
    pub has_driver: bool,
    /// Whether this plugin provides a Reducer.
    pub has_reducer: bool,
}

/// Minimal plugin descriptor. The runtime (piglor-runtime) implements full registration.
/// The kernel only carries this as a type — no I/O, no execution here.
pub trait Plugin: Send + Sync {
    fn id(&self) -> PluginId;
    fn name(&self) -> &'static str;
    fn capability(&self) -> Capability;
    /// Crate version string (e.g. "0.1.0"). Defaults to "0.1.0".
    fn version(&self) -> &'static str {
        "0.1.0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        id: PluginId,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            "test-plugin"
        }
        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![Kind::new("test.event")],
                owned_entity_kinds: vec!["test.entity".to_owned()],
                has_driver: true,
                has_reducer: true,
            }
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_json_round_trip() {
        let cap = Capability {
            owned_event_types: vec![Kind::new("world.observation"), Kind::new("agent.decision")],
            owned_entity_kinds: vec!["agent".to_owned()],
            has_driver: true,
            has_reducer: false,
        };
        let back: Capability = serde_json::from_str(&serde_json::to_string(&cap).unwrap()).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_cbor_round_trip() {
        let cap = Capability {
            owned_event_types: vec![Kind::new("sensor.reading")],
            owned_entity_kinds: vec![],
            has_driver: false,
            has_reducer: true,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&cap, &mut buf).unwrap();
        let back: Capability = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_trait_is_implemented() {
        let p = TestPlugin {
            id: PluginId::new(),
        };
        assert_eq!(p.name(), "test-plugin");
        assert_eq!(p.capability().owned_event_types.len(), 1);
        assert_eq!(p.capability().owned_entity_kinds[0], "test.entity");
        assert!(p.capability().has_driver);
        assert_eq!(p.version(), "0.1.0");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn default_capability_is_empty() {
        let cap = Capability::default();
        assert!(cap.owned_event_types.is_empty());
        assert!(cap.owned_entity_kinds.is_empty());
        assert!(!cap.has_driver);
        assert!(!cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_returned_by_id_method() {
        let expected_id = PluginId::new();
        let p = TestPlugin { id: expected_id };
        assert_eq!(p.id(), expected_id);
    }
}
