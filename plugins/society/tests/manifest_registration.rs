#![cfg(target_os = "linux")]

use std::error::Error;

use pos_core::{
    ids::TimelineId,
    manifest_owner_link::{
        ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
        ManifestOwnerLinkErrorV1,
    },
    Hash, Plugin,
};
use pos_plugin_society::{SocietyPlugin, SocietyReducer};
use pos_runtime::{
    installed_plugin_role_v1, DomainImplementationKindV1, Driver, InstalledOutputPolicySourceV1,
    ManifestRegistrationErrorV1, ObservationView, OutputPolicyBindingV1, PluginAvailabilityV1,
    PluginCompositionErrorV1, PluginIsolationV1, PluginPinFieldV1, PluginPinV1,
    PluginRegistrationV1, PluginRegistry, RuntimeError, StepOutput,
};

struct InstalledFixture {
    plugin: SocietyPlugin,
    binding: OutputPolicyBindingV1,
    registration: PluginRegistrationV1,
    row: ManifestAdmissionCatalogRowV1,
}

fn fixture(slot: &str, configuration: &[u8]) -> Result<InstalledFixture, Box<dyn Error>> {
    let plugin = SocietyPlugin::new();
    let binding = OutputPolicyBindingV1::from_installed_source(
        &plugin,
        InstalledOutputPolicySourceV1::Society,
        configuration,
        "deterministic-local-v1",
    )?;
    let pin = PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        binding.policy().digest(),
        vec![installed_plugin_role_v1(&plugin)],
    )?;
    let registration = PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available);
    let closure_hash = binding.manifest_closure_hash()?;
    let row = ManifestAdmissionCatalogRowV1 {
        stable_slot: slot.to_owned(),
        plugin_id: plugin.id(),
        plugin_name: plugin.name().to_owned(),
        plugin_version: plugin.version().to_owned(),
        implementation_hash: binding.policy().fields().implementation_hash,
        eop1_native_digest: binding.policy().digest(),
        closure_hash,
    };
    Ok(InstalledFixture {
        plugin,
        binding,
        registration,
        row,
    })
}

fn catalog(
    rows: Vec<ManifestAdmissionCatalogRowV1>,
) -> Result<ManifestAdmissionCatalogV1, ManifestOwnerLinkErrorV1> {
    ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: [0x41; 32],
        configuration_generation: 1,
        rows,
    })
}

fn register(registry: &mut PluginRegistry, fixture: InstalledFixture) -> Result<(), RuntimeError> {
    let InstalledFixture {
        plugin,
        binding,
        registration,
        row,
    } = fixture;
    registry.register_installed_output_in_manifest_slot(
        &plugin,
        binding,
        registration,
        Some(Box::new(SocietyReducer)),
        &row.stable_slot,
    )
}

struct MutationProbe;

impl Driver for MutationProbe {
    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn name(&self) -> &'static str {
        "manifest-mutation-probe"
    }
}

#[test]
fn same_name_plugin_ids_need_both_preassigned_slots() -> Result<(), Box<dyn Error>> {
    let first = fixture("alpha", b"alpha-policy")?;
    let second = fixture("beta", b"beta-policy")?;
    assert_eq!(first.plugin.name(), second.plugin.name());
    assert_ne!(first.plugin.id(), second.plugin.id());
    assert_ne!(first.row.eop1_native_digest, second.row.eop1_native_digest);
    let batch = catalog(vec![first.row.clone(), second.row.clone()])?;
    let mut registry = PluginRegistry::new();
    registry.prepare_manifest_registration(batch.clone())?;
    register(&mut registry, first)?;
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    register(&mut registry, second)?;
    let admitted = registry.admit_complete_manifest_registration()?;
    assert_eq!(admitted.catalog(), &batch);
    assert!(registry.is_admitted_composition_current(&admitted));

    let mut next = batch.as_input().clone();
    next.configuration_generation = 2;
    let renewed =
        registry.revalidate_manifest_registration(ManifestAdmissionCatalogV1::new(next)?)?;
    assert!(registry.is_admitted_composition_current(&renewed));
    assert_eq!(renewed.catalog().as_input().configuration_generation, 2);
    Ok(())
}

#[test]
fn malformed_or_changed_batches_fail_without_partial_admission() -> Result<(), Box<dyn Error>> {
    let first = fixture("alpha", b"first")?;
    let second = fixture("beta", b"second")?;
    let rows = vec![first.row.clone(), second.row.clone()];
    let duplicate_slot = vec![
        first.row.clone(),
        ManifestAdmissionCatalogRowV1 {
            stable_slot: "alpha".to_owned(),
            ..second.row.clone()
        },
    ];
    assert!(matches!(
        ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            owner_id: [0x41; 32],
            configuration_generation: 1,
            rows: duplicate_slot,
        }),
        Err(ManifestOwnerLinkErrorV1::InvalidRowOrder)
    ));
    let mut duplicate_id = second.row.clone();
    duplicate_id.plugin_id = first.row.plugin_id;
    assert!(matches!(
        ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            owner_id: [0x41; 32],
            configuration_generation: 1,
            rows: vec![first.row.clone(), duplicate_id],
        }),
        Err(ManifestOwnerLinkErrorV1::DuplicatePluginId)
    ));

    let mut registry = PluginRegistry::new();
    registry.prepare_manifest_registration(catalog(rows)?)?;
    register(&mut registry, first)?;
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    let extra = fixture("gamma", b"extra")?;
    assert!(matches!(
        register(&mut registry, extra),
        Err(RuntimeError::ManifestRegistration(
            ManifestRegistrationErrorV1::PluginMismatch
        ))
    ));
    assert_eq!(registry.len(), 1);
    register(&mut registry, second)?;
    let admitted = registry.admit_complete_manifest_registration()?;

    let mut changed = admitted.catalog().as_input().clone();
    changed.configuration_generation = 2;
    changed.rows[1].closure_hash = Hash::from_bytes([0x77; 32]);
    assert!(matches!(
        registry.revalidate_manifest_registration(ManifestAdmissionCatalogV1::new(changed)?),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    assert!(registry.is_admitted_composition_current(&admitted));
    Ok(())
}

#[test]
fn absent_batch_and_wrong_policy_reject_before_mutation() -> Result<(), Box<dyn Error>> {
    let first = fixture("alpha", b"first")?;
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        register(&mut registry, first),
        Err(RuntimeError::ManifestRegistration(
            ManifestRegistrationErrorV1::BatchState
        ))
    ));
    assert!(registry.is_empty());

    let bad = fixture("alpha", b"actual")?;
    let mut wrong_row = bad.row.clone();
    wrong_row.eop1_native_digest = Hash::from_bytes([0x72; 32]);
    registry.prepare_manifest_registration(catalog(vec![wrong_row])?)?;
    assert!(matches!(
        register(&mut registry, bad),
        Err(RuntimeError::ManifestRegistration(
            ManifestRegistrationErrorV1::PluginMismatch
        ))
    ));
    assert!(registry.is_empty());
    Ok(())
}

#[test]
fn wrong_pin_and_unavailable_plugin_reject_before_mutation() -> Result<(), Box<dyn Error>> {
    for unavailable in [false, true] {
        let actual = fixture("alpha", b"pinned")?;
        let registration = if unavailable {
            PluginRegistrationV1::new(
                actual.registration.pin().clone(),
                PluginAvailabilityV1::Disabled,
            )
        } else {
            PluginRegistrationV1::new(
                PluginPinV1::try_new(
                    DomainImplementationKindV1::Plugin,
                    PluginIsolationV1::OperatorTrustedNative,
                    Hash::from_bytes([0x74; 32]),
                    vec![installed_plugin_role_v1(&actual.plugin)],
                )?,
                PluginAvailabilityV1::Available,
            )
        };
        let mut registry = PluginRegistry::new();
        registry.prepare_manifest_registration(catalog(vec![actual.row.clone()])?)?;
        let result = registry.register_installed_output_in_manifest_slot(
            &actual.plugin,
            actual.binding,
            registration,
            Some(Box::new(SocietyReducer)),
            "alpha",
        );
        assert!(matches!(
            (unavailable, result),
            (
                true,
                Err(RuntimeError::Composition(
                    PluginCompositionErrorV1::ImplementationUnavailable { .. }
                ))
            ) | (
                false,
                Err(RuntimeError::Composition(
                    PluginCompositionErrorV1::IncompatibleImplementation {
                        field: PluginPinFieldV1::ConfigurationDigest,
                        ..
                    }
                ))
            )
        ));
        assert!(registry.is_empty());
    }
    Ok(())
}

#[test]
fn every_static_catalog_field_is_checked_before_registration() -> Result<(), Box<dyn Error>> {
    for field in 0..7 {
        let actual = fixture("alpha", b"field-check")?;
        let mut wrong = actual.row.clone();
        match field {
            0 => wrong.stable_slot = "other".to_owned(),
            1 => wrong.plugin_id = pos_core::PluginId::new(),
            2 => wrong.plugin_name = "foreign-name".to_owned(),
            3 => wrong.plugin_version = "foreign-version".to_owned(),
            4 => wrong.implementation_hash = Hash::from_bytes([0x71; 32]),
            5 => wrong.eop1_native_digest = Hash::from_bytes([0x72; 32]),
            _ => wrong.closure_hash = Hash::from_bytes([0x73; 32]),
        }
        let mut registry = PluginRegistry::new();
        registry.prepare_manifest_registration(catalog(vec![wrong])?)?;
        let result = register(&mut registry, actual);
        assert!(matches!(
            result,
            Err(RuntimeError::ManifestRegistration(
                ManifestRegistrationErrorV1::SlotMismatch
                    | ManifestRegistrationErrorV1::PluginMismatch
            ))
        ));
        assert!(registry.is_empty());
    }
    Ok(())
}

#[test]
fn preparation_and_capability_invalidation_are_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    assert!(matches!(
        registry.prepare_manifest_registration(catalog(Vec::new())?),
        Err(ManifestRegistrationErrorV1::EmptyBatch)
    ));
    let fixture = fixture("alpha", b"current")?;
    let batch = catalog(vec![fixture.row.clone()])?;
    registry.prepare_manifest_registration(batch.clone())?;
    assert!(matches!(
        registry.prepare_manifest_registration(batch.clone()),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    register(&mut registry, fixture)?;
    let admitted = registry.admit_complete_manifest_registration()?;
    assert!(registry.is_admitted_composition_current(&admitted));

    let mut other_owner = batch.as_input().clone();
    other_owner.owner_id = [0x42; 32];
    assert!(matches!(
        registry.revalidate_manifest_registration(ManifestAdmissionCatalogV1::new(other_owner)?),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    assert!(!PluginRegistry::new().is_admitted_composition_current(&admitted));
    registry.register_driver(Box::new(MutationProbe));
    assert!(!registry.is_admitted_composition_current(&admitted));
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    assert!(matches!(
        registry.prepare_manifest_registration(batch),
        Err(ManifestRegistrationErrorV1::RegistryState)
    ));
    Ok(())
}
