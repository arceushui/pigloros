use std::error::Error;
use std::time::Duration;

use pos_core::{Capability, EntityId};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

struct DriverlessPlugin {
    id: PluginId,
}

impl Plugin for DriverlessPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "driverless"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("acme.zeta.v1"), Kind::new("acme.alpha.v1")],
            ..Capability::default()
        }
    }
}

fn settings() -> FallbackDriverSettingsV1 {
    FallbackDriverSettingsV1 {
        tick_interval: Duration::from_millis(250),
        subscriptions: vec![ProjectionKey::new(EntityId::new())],
    }
}

#[test]
fn a_driverless_unpinned_entry_has_no_driver_facts() -> TestResult {
    let plugin = DriverlessPlugin { id: PluginId::new() };
    let mut registry = PluginRegistry::new();
    registry.register_generated(&plugin, None, None)?;
    let facts = registry.fallback_registry_facts_v1(plugin.id)?;
    assert_eq!(facts.owned_event_types, ["acme.alpha.v1", "acme.zeta.v1"]);
    assert_eq!(facts.schemas, vec![None::<String>, None]);
    assert_eq!(facts.outputs.len(), 2);
    assert_eq!(facts.cpu_reservations_us, Some([10; 3]));
    assert_eq!(facts.pin, None);
    assert!(facts.subscriptions.is_empty());
    assert_eq!(facts.driver_interval, None);
    assert_eq!(facts.binding, None);
    Ok(())
}

#[test]
fn an_entry_without_an_output_admission_has_no_reservation() -> TestResult {
    let mut registry = PluginRegistry::new();
    let shell = FallbackDriverShellV1::new("undeclared", settings());
    registry.register_driver(Box::new(shell))?;
    let ids: Vec<PluginId> = registry.plugins.keys().copied().collect();
    let facts = registry.fallback_registry_facts_v1(ids[0])?;
    assert_eq!(facts.cpu_reservations_us, None);
    assert!(facts.outputs.is_empty());
    assert_eq!(facts.driver_interval, Some(Duration::from_millis(250)));
    assert_eq!(facts.subscriptions.len(), 1);
    Ok(())
}

#[test]
fn an_unregistered_plugin_has_no_facts() {
    let missing = PluginId::new();
    let facts = PluginRegistry::new().fallback_registry_facts_v1(missing);
    let refused = matches!(facts, Err(RuntimeError::NoDriver { .. }));
    assert!(refused, "{facts:?}");
}

#[test]
fn a_reserved_type_is_refused_on_the_facts_only_path() -> TestResult {
    struct Reserved;
    impl Plugin for Reserved {
        fn id(&self) -> PluginId {
            PluginId::from_ulid(ulid::Ulid::from_parts(1, 1))
        }

        fn name(&self) -> &'static str {
            "reserved"
        }

        fn capability(&self) -> Capability {
            let reserved = pos_core::COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1;
            Capability {
                owned_event_types: vec![Kind::new(reserved)],
                has_driver: true,
                ..Capability::default()
            }
        }
    }
    let key = pos_core::ImplementationKeyV1::new(
        "acme.reserved".to_owned(),
        "0.1.0".to_owned(),
        pos_core::Hash::from_bytes([1; 32]),
    )?;
    let pin = CompositionPinV1::new(key, vec!["weather".to_owned()])?;
    let facts = PluginRegistry::fallback_scratch_facts_v1(&Reserved, &pin, settings());
    let refused = matches!(facts, Err(RuntimeError::ReservedHostEventType { .. }));
    assert!(refused, "{facts:?}");
    Ok(())
}
