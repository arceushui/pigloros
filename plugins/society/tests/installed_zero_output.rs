#![cfg(target_os = "linux")]

use std::error::Error;

use pos_core::Plugin;
use pos_plugin_society::{SocietyReducer, SocietySignalProjectionPlugin};
use pos_runtime::{
    installed_plugin_role_v1, DomainImplementationKindV1, OutputPolicySourceV1,
    OutputAdmissionErrorV1, OutputPolicyBindingV1, PluginAvailabilityV1, PluginIsolationV1,
    PluginPinV1, PluginRegistrationV1, PluginRegistry, RuntimeError,
};

#[test]
fn society_projection_is_zero_output_but_uninstalled_without_epf1() -> Result<(), Box<dyn Error>> {
    let plugin = Box::new(SocietySignalProjectionPlugin::new());
    let other = SocietySignalProjectionPlugin::default();
    assert_ne!(plugin.id(), other.id());
    assert_eq!(plugin.name(), "society-signal-projection");
    let capability = plugin.capability();
    assert!(capability.owned_event_types.is_empty());
    assert!(capability.owned_entity_kinds.is_empty());
    assert!(!capability.has_driver);
    assert!(capability.has_reducer);

    assert!(matches!(
        OutputPolicyBindingV1::from_source(
            plugin.as_ref(),
            OutputPolicySourceV1::Society,
            b"society-read-only-projection",
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    ));

    // Generated can check the empty declaration structurally, not install it.
    let binding = OutputPolicyBindingV1::from_source(
        plugin.as_ref(),
        OutputPolicySourceV1::Generated,
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
    assert!(matches!(
        registry.register_installed_output(
            plugin.as_ref(),
            binding,
            PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available),
            Some(Box::new(SocietyReducer)),
        ),
        Err(RuntimeError::OutputAdmission(
            OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" }
        ))
    ));
    assert!(registry.is_empty());
    Ok(())
}
