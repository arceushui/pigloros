#![cfg(target_os = "linux")]

use std::error::Error;

use pos_core::Plugin;
use pos_plugin_society::{SocietyReducer, SocietySignalProjectionPlugin};
use pos_runtime::{
    installed_plugin_role_v1, DomainImplementationKindV1, InstalledOutputPolicySourceV1,
    OutputPolicyBindingV1, PluginAvailabilityV1, PluginIsolationV1, PluginPinV1,
    PluginRegistrationV1, PluginRegistry,
};

#[test]
fn installed_society_projection_has_no_output_declarations() -> Result<(), Box<dyn Error>> {
    let plugin = Box::new(SocietySignalProjectionPlugin::new());
    let other = SocietySignalProjectionPlugin::default();
    assert_ne!(plugin.id(), other.id());
    assert_eq!(plugin.name(), "society-signal-projection");
    let capability = plugin.capability();
    assert!(capability.owned_event_types.is_empty());
    assert!(capability.owned_entity_kinds.is_empty());
    assert!(!capability.has_driver);
    assert!(capability.has_reducer);

    let binding = OutputPolicyBindingV1::from_installed_source(
        plugin.as_ref(),
        InstalledOutputPolicySourceV1::Society,
        b"society-read-only-projection",
        "deterministic-local-v1",
    )?;
    assert!(binding.policy().fields().output_declarations.is_empty());
    let pin = PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        binding.policy().digest(),
        vec![installed_plugin_role_v1(plugin.as_ref())],
    )?;
    let mut registry = PluginRegistry::new();
    registry.register_installed_output(
        plugin.as_ref(),
        binding,
        PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available),
        Some(Box::new(SocietyReducer)),
    )?;
    assert_eq!(registry.len(), 1);
    Ok(())
}
