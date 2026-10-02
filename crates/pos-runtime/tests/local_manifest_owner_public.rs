use std::error::Error;

use pos_core::{ids::PluginId, Kind, OwnerIdV1, Plugin};
use pos_runtime::{
    ManifestRegistrationErrorV1, PluginCompositionErrorV1, PluginRegistry, RuntimeError,
};

type TestResult = Result<(), Box<dyn Error>>;

struct LocalPlugin {
    id: PluginId,
    name: &'static str,
}

impl Plugin for LocalPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> pos_core::Capability {
        pos_core::Capability::default()
    }
}

#[test]
fn local_registration_admits_the_actual_complete_registry_without_epf1() -> TestResult {
    let plugins = [
        LocalPlugin {
            id: PluginId::new(),
            name: "local-world",
        },
        LocalPlugin {
            id: PluginId::new(),
            name: "local-world",
        },
    ];
    let owner = OwnerIdV1::from_static("open-source-app");
    let mut registry = PluginRegistry::new();
    for (plugin, role) in plugins.iter().zip(["world", "agent"]) {
        registry.register_local(plugin, vec![role.to_owned()], None, None)?;
    }

    let admitted = registry.admit_local_manifest_registration(owner, 3)?;
    let catalog = admitted.catalog();
    assert_eq!(catalog.as_input().rows.len(), plugins.len());
    assert_eq!(catalog.as_input().configuration_generation, 3);
    assert_eq!(
        catalog.as_input().owner_id,
        *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes()
    );
    for plugin in &plugins {
        assert!(catalog
            .as_input()
            .rows
            .iter()
            .any(|row| row.plugin_id == plugin.id()));
    }
    let policy_sources = registry.admitted_manifest_policy_sources(&admitted)?;
    assert_eq!(policy_sources.len(), plugins.len());
    assert!(policy_sources
        .iter()
        .all(|source| source.plugin_name() == "local-world"));
    assert!(policy_sources
        .iter()
        .all(|source| source.eop1_bytes().starts_with(b"\x8a\x44EOP1")));
    assert!(policy_sources
        .iter()
        .all(|source| source.opc1_bytes().starts_with(b"OPC1")));
    for source in &policy_sources {
        assert!(catalog
            .as_input()
            .rows
            .iter()
            .any(|row| row.plugin_id == source.plugin_id()));
    }
    assert!(registry.is_admitted_composition_current_for_generation(&admitted, 3));
    assert!(!PluginRegistry::new().is_admitted_composition_current_for_generation(&admitted, 3));

    assert!(matches!(
        registry.register_local(
            &LocalPlugin {
                id: PluginId::new(),
                name: "late-plugin",
            },
            vec!["late".to_owned()],
            None,
            None,
        ),
        Err(RuntimeError::ManifestRegistration(
            ManifestRegistrationErrorV1::BatchState
        ))
    ));
    Ok(())
}

#[test]
fn local_admission_rejects_empty_or_unpinned_registries() -> TestResult {
    let owner = OwnerIdV1::from_static("open-source-app");
    assert!(matches!(
        PluginRegistry::new().admit_local_manifest_registration(owner, 1),
        Err(ManifestRegistrationErrorV1::EmptyBatch)
    ));

    let plugin = LocalPlugin {
        id: PluginId::new(),
        name: "unpinned-local-plugin",
    };
    let mut registry = PluginRegistry::new();
    registry.register_generated(&plugin, None, None)?;
    assert!(matches!(
        registry.admit_local_manifest_registration(owner, 1),
        Err(ManifestRegistrationErrorV1::UnverifiedRegistration)
    ));
    Ok(())
}

#[test]
fn local_admission_rejects_nonlocal_resealed_and_zero_generation_registries() -> TestResult {
    let owner = OwnerIdV1::from_static("open-source-app");
    assert!(matches!(
        PluginRegistry::new_air_gapped().admit_local_manifest_registration(owner, 1),
        Err(ManifestRegistrationErrorV1::RegistryState)
    ));

    let plugin = LocalPlugin {
        id: PluginId::new(),
        name: "zero-generation-local-plugin",
    };
    let mut registry = PluginRegistry::new();
    registry.register_local(&plugin, vec!["world".to_owned()], None, None)?;
    assert!(matches!(
        registry.admit_local_manifest_registration(owner, 0),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    registry.admit_local_manifest_registration(owner, 1)?;
    assert!(matches!(
        registry.admit_local_manifest_registration(owner, 2),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    Ok(())
}

struct InvalidDeclarationPlugin;

impl Plugin for InvalidDeclarationPlugin {
    fn id(&self) -> PluginId {
        PluginId::new()
    }

    fn name(&self) -> &'static str {
        "invalid-declaration-local-plugin"
    }

    fn capability(&self) -> pos_core::Capability {
        pos_core::Capability {
            owned_event_types: vec![Kind::new("")],
            ..pos_core::Capability::default()
        }
    }
}

#[test]
fn local_registration_rejects_missing_roles_and_invalid_output_declarations() {
    let plugin = LocalPlugin {
        id: PluginId::new(),
        name: "roleless-local-plugin",
    };
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.register_local(&plugin, Vec::new(), None, None),
        Err(RuntimeError::Composition(
            PluginCompositionErrorV1::InvalidMetadata
        ))
    ));
    assert!(matches!(
        registry.register_local(
            &InvalidDeclarationPlugin,
            vec!["world".to_owned()],
            None,
            None,
        ),
        Err(RuntimeError::CapabilityMismatch { .. })
    ));
    assert!(registry.is_empty());
}
