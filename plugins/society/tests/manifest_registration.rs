#![cfg(target_os = "linux")]

use std::error::Error;

use pos_core::{
    ids::TimelineId,
    manifest_owner_link::{
        ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
        ManifestOwnerLinkErrorV1,
    },
    world_consumer_set::{
        WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1, WorldProducerV1,
    },
    Hash, Plugin,
};
use pos_plugin_society::{SocietyPlugin, SocietyReducer, SocietySignalProjectionPlugin};
use pos_runtime::{
    installed_plugin_role_v1, DomainImplementationKindV1, Driver, InstalledOutputPolicySourceV1,
    ManifestRegistrationErrorV1, ObservationView, OutputPolicyBindingV1, PluginAvailabilityV1,
    PluginCompositionErrorV1, PluginIsolationV1, PluginPinFieldV1, PluginPinV1,
    PluginRegistrationV1, PluginRegistry, RuntimeError, StepOutput,
};

struct InstalledFixture {
    plugin: Box<SocietyPlugin>,
    binding: OutputPolicyBindingV1,
    registration: PluginRegistrationV1,
    row: ManifestAdmissionCatalogRowV1,
}

fn fixture(slot: &str, configuration: &[u8]) -> Result<InstalledFixture, Box<dyn Error>> {
    let plugin = Box::new(SocietyPlugin::new());
    let binding = OutputPolicyBindingV1::from_installed_source(
        plugin.as_ref(),
        InstalledOutputPolicySourceV1::Society,
        configuration,
        "deterministic-local-v1",
    )?;
    let pin = PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        binding.policy().digest(),
        vec![installed_plugin_role_v1(plugin.as_ref())],
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

struct InstalledProjectionFixture {
    plugin: Box<SocietySignalProjectionPlugin>,
    binding: OutputPolicyBindingV1,
    registration: PluginRegistrationV1,
    row: ManifestAdmissionCatalogRowV1,
}

fn projection_fixture(slot: &str) -> Result<InstalledProjectionFixture, Box<dyn Error>> {
    let plugin = Box::new(SocietySignalProjectionPlugin::new());
    let binding = OutputPolicyBindingV1::from_installed_source(
        plugin.as_ref(),
        InstalledOutputPolicySourceV1::Society,
        b"read-only-projection",
        "deterministic-local-v1",
    )?;
    assert!(plugin.capability().owned_event_types.is_empty());
    assert!(plugin.capability().has_reducer);
    assert!(binding.policy().fields().output_declarations.is_empty());
    let pin = PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        binding.policy().digest(),
        vec![installed_plugin_role_v1(plugin.as_ref())],
    )?;
    let registration = PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available);
    let row = ManifestAdmissionCatalogRowV1 {
        stable_slot: slot.to_owned(),
        plugin_id: plugin.id(),
        plugin_name: plugin.name().to_owned(),
        plugin_version: plugin.version().to_owned(),
        implementation_hash: binding.policy().fields().implementation_hash,
        eop1_native_digest: binding.policy().digest(),
        closure_hash: binding.manifest_closure_hash()?,
    };
    Ok(InstalledProjectionFixture {
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

fn independent_opc1_hash(binding: &OutputPolicyBindingV1) -> Hash {
    let policy = binding.policy().to_canonical_cbor();
    let budget = binding.budget().to_canonical_cbor();
    let members = [
        policy.as_slice(),
        budget.as_slice(),
        binding.implementation_artifact(),
        binding.configuration_artifact(),
        binding.execution_profile_artifact(),
        binding.retention_policy_artifact(),
    ];
    let mut bytes = b"OPC1".to_vec();
    for member in members {
        bytes.extend_from_slice(&(member.len() as u64).to_be_bytes());
        bytes.extend_from_slice(member);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(&bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

#[test]
fn opc1_hash_matches_independent_six_member_oracle() -> Result<(), Box<dyn Error>> {
    // Generated supplies bytes for this oracle only; it cannot admit a Plugin.
    let plugin = SocietySignalProjectionPlugin::new();
    let binding = OutputPolicyBindingV1::from_installed_source(
        &plugin,
        InstalledOutputPolicySourceV1::Generated,
        b"read-only-projection",
        "deterministic-local-v1",
    )?;
    assert_eq!(
        binding.manifest_closure_hash()?,
        independent_opc1_hash(&binding)
    );
    Ok(())
}

fn register(registry: &mut PluginRegistry, fixture: InstalledFixture) -> Result<(), RuntimeError> {
    let InstalledFixture {
        plugin,
        binding,
        registration,
        row,
    } = fixture;
    registry.register_installed_output_in_manifest_slot(
        plugin.as_ref(),
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
    assert!(registry.is_admitted_composition_current_for_generation(&admitted, 1));

    let mut next = batch.as_input().clone();
    next.configuration_generation = 2;
    let renewed =
        registry.revalidate_manifest_registration(ManifestAdmissionCatalogV1::new(next)?)?;
    assert!(registry.is_admitted_composition_current_for_generation(&renewed, 2));
    assert!(!registry.is_admitted_composition_current_for_generation(&admitted, 2));
    assert!(!registry.is_admitted_composition_current_for_generation(&renewed, 1));
    assert_eq!(renewed.catalog().as_input().configuration_generation, 2);
    Ok(())
}

#[test]
fn zero_output_reducer_is_in_complete_batch_but_not_wcs1_producers() -> Result<(), Box<dyn Error>> {
    let producer = fixture("producer", b"producer-policy")?;
    let projection = projection_fixture("projection")?;
    let producer_id = producer.plugin.id();
    let projection_id = projection.plugin.id();
    let batch = catalog(vec![producer.row.clone(), projection.row.clone()])?;

    // This WCS1 is structural only. The native owner checks its scoped leaf
    // addresses and the full MCA1/MSB1 link in later tickets.
    let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: Hash::from_bytes([0x51; 32]),
        consumers: vec![WorldConsumerV1::new(
            "society-projection".to_owned(),
            Hash::from_bytes([0x52; 32]),
            Hash::from_bytes([0x53; 32]),
            Hash::from_bytes([0x54; 32]),
        )?],
        producers: vec![WorldProducerV1::new(
            producer_id,
            Hash::from_bytes([0x55; 32]),
        )?],
        optional_view_roots: Vec::new(),
    })?;
    assert_eq!(wcs1.producers().len(), 1);
    assert_eq!(wcs1.producers()[0].plugin_id(), producer_id);
    assert!(!wcs1
        .producers()
        .iter()
        .any(|row| row.plugin_id() == projection_id));

    let mut registry = PluginRegistry::new();
    registry.prepare_manifest_registration(batch.clone())?;
    register(&mut registry, producer)?;
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    registry.register_installed_output_in_manifest_slot(
        projection.plugin.as_ref(),
        projection.binding,
        projection.registration,
        Some(Box::new(SocietyReducer)),
        &projection.row.stable_slot,
    )?;
    let admitted = registry.admit_complete_manifest_registration()?;
    assert_eq!(admitted.catalog(), &batch);
    assert_eq!(admitted.catalog().as_input().rows.len(), 2);
    assert!(admitted
        .catalog()
        .as_input()
        .rows
        .iter()
        .any(|row| row.plugin_id == projection_id));
    assert!(registry.is_admitted_composition_current_for_generation(&admitted, 1));
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
    assert!(registry.is_admitted_composition_current_for_generation(&admitted, 1));
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
                    vec![installed_plugin_role_v1(actual.plugin.as_ref())],
                )?,
                PluginAvailabilityV1::Available,
            )
        };
        let mut registry = PluginRegistry::new();
        registry.prepare_manifest_registration(catalog(vec![actual.row.clone()])?)?;
        let result = registry.register_installed_output_in_manifest_slot(
            actual.plugin.as_ref(),
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
    assert!(matches!(
        registry.revalidate_manifest_registration(batch.clone()),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    registry.prepare_manifest_registration(batch.clone())?;
    assert!(matches!(
        registry.revalidate_manifest_registration(batch.clone()),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    assert!(matches!(
        registry.prepare_manifest_registration(batch.clone()),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    register(&mut registry, fixture)?;
    let admitted = registry.admit_complete_manifest_registration()?;
    assert!(registry.is_admitted_composition_current_for_generation(&admitted, 1));

    let mut other_owner = batch.as_input().clone();
    other_owner.owner_id = [0x42; 32];
    assert!(matches!(
        registry.revalidate_manifest_registration(ManifestAdmissionCatalogV1::new(other_owner)?),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    assert!(!PluginRegistry::new().is_admitted_composition_current_for_generation(&admitted, 1));
    registry.register_driver(Box::new(MutationProbe));
    assert!(!registry.is_admitted_composition_current_for_generation(&admitted, 1));
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
