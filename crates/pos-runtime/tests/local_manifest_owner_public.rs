use pos_core::{ids::PluginId, OwnerIdV1, Plugin};
use pos_runtime::{ManifestRegistrationErrorV1, PluginRegistry, RuntimeError};

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
fn local_registration_admits_the_actual_complete_registry_without_epf1() {
    let plugins = [
        LocalPlugin {
            id: PluginId::new(),
            name: "local-world",
        },
        LocalPlugin {
            id: PluginId::new(),
            name: "local-agent",
        },
    ];
    let owner = OwnerIdV1::from_static("open-source-app");
    let mut registry = PluginRegistry::new();
    for (plugin, role) in plugins.iter().zip(["world", "agent"]) {
        registry
            .register_local(plugin, vec![role.to_owned()], None, None)
            .expect("local native registration should need no installed EPF1");
    }

    let admitted = registry
        .admit_local_manifest_registration(owner, 3)
        .expect("the actual local registry should produce a complete admission");
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
}

#[test]
fn local_admission_rejects_empty_or_unpinned_registries() {
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
    registry
        .register_generated(&plugin, None, None)
        .expect("local output admission should remain available without a pin");
    assert!(matches!(
        registry.admit_local_manifest_registration(owner, 1),
        Err(ManifestRegistrationErrorV1::UnverifiedRegistration)
    ));
}
