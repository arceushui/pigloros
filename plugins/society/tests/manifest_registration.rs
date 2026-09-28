#![cfg(target_os = "linux")]

use std::error::Error;

use pos_core::{
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
    installed_plugin_role_v1, DomainImplementationKindV1, InstalledOutputPolicySourceV1,
    ManifestRegistrationErrorV1, OutputAdmissionErrorV1, OutputPolicyBindingV1,
    PluginAvailabilityV1, PluginIsolationV1, PluginPinV1, PluginRegistrationV1, PluginRegistry,
    RuntimeError,
};

fn generated_binding<P: Plugin>(
    plugin: &P,
    configuration: &[u8],
) -> Result<OutputPolicyBindingV1, OutputAdmissionErrorV1> {
    OutputPolicyBindingV1::from_installed_source(
        plugin,
        InstalledOutputPolicySourceV1::Generated,
        configuration,
        "deterministic-local-v1",
    )
}

fn structural_row<P: Plugin>(
    plugin: &P,
    binding: &OutputPolicyBindingV1,
    slot: &str,
) -> Result<ManifestAdmissionCatalogRowV1, Box<dyn Error>> {
    Ok(ManifestAdmissionCatalogRowV1 {
        stable_slot: slot.to_owned(),
        plugin_id: plugin.id(),
        plugin_name: plugin.name().to_owned(),
        plugin_version: plugin.version().to_owned(),
        implementation_hash: binding.policy().fields().implementation_hash,
        eop1_native_digest: binding.policy().digest(),
        closure_hash: binding.manifest_closure_hash()?,
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

fn reject_generated_registration<P: Plugin>(
    registry: &mut PluginRegistry,
    plugin: &P,
    binding: OutputPolicyBindingV1,
    slot: &str,
) -> Result<(), Box<dyn Error>> {
    let pin = PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        binding.policy().digest(),
        vec![installed_plugin_role_v1(plugin)],
    )?;
    assert!(matches!(
        registry.register_installed_output_in_manifest_slot(
            plugin,
            binding,
            PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available),
            Some(Box::new(SocietyReducer)),
            slot,
        ),
        Err(RuntimeError::ManifestRegistration(
            ManifestRegistrationErrorV1::UnverifiedRegistration
        ))
    ));
    assert!(registry.is_empty());
    Ok(())
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
fn generated_opc1_matches_independent_oracle() -> Result<(), Box<dyn Error>> {
    let projection = SocietySignalProjectionPlugin::new();
    let binding = generated_binding(&projection, b"read-only-projection")?;
    assert_eq!(
        binding.manifest_closure_hash()?,
        independent_opc1_hash(&binding)
    );
    Ok(())
}

#[test]
fn generated_same_name_batch_cannot_admit() -> Result<(), Box<dyn Error>> {
    let first = SocietyPlugin::new();
    let second = SocietyPlugin::new();
    assert_eq!(first.name(), second.name());
    assert_ne!(first.id(), second.id());

    let first_binding = generated_binding(&first, b"first-policy")?;
    let second_binding = generated_binding(&second, b"second-policy")?;
    assert_ne!(
        first_binding.policy().digest(),
        second_binding.policy().digest()
    );
    let batch = catalog(vec![
        structural_row(&first, &first_binding, "alpha")?,
        structural_row(&second, &second_binding, "beta")?,
    ])?;
    let mut registry = PluginRegistry::new();
    registry.prepare_manifest_registration(batch)?;
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));

    reject_generated_registration(&mut registry, &first, first_binding, "alpha")?;
    reject_generated_registration(&mut registry, &second, second_binding, "beta")?;
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    Ok(())
}

#[test]
fn reducer_only_zero_output_row_is_structural_not_installed() -> Result<(), Box<dyn Error>> {
    let producer = SocietyPlugin::new();
    let projection = SocietySignalProjectionPlugin::new();
    let producer_binding = generated_binding(&producer, b"producer-policy")?;
    let projection_binding = generated_binding(&projection, b"read-only-projection")?;
    assert!(projection.capability().owned_event_types.is_empty());
    assert!(projection.capability().has_reducer);
    assert!(projection_binding
        .policy()
        .fields()
        .output_declarations
        .is_empty());

    let batch = catalog(vec![
        structural_row(&producer, &producer_binding, "producer")?,
        structural_row(&projection, &projection_binding, "projection")?,
    ])?;
    let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: Hash::from_bytes([0x51; 32]),
        consumers: vec![WorldConsumerV1::new(
            "society-projection".to_owned(),
            Hash::from_bytes([0x52; 32]),
            Hash::from_bytes([0x53; 32]),
            Hash::from_bytes([0x54; 32]),
        )?],
        producers: vec![WorldProducerV1::new(
            producer.id(),
            Hash::from_bytes([0x55; 32]),
        )?],
        optional_view_roots: Vec::new(),
    })?;
    assert_eq!(wcs1.producers().len(), 1);
    assert_eq!(wcs1.producers()[0].plugin_id(), producer.id());
    assert!(!wcs1
        .producers()
        .iter()
        .any(|row| row.plugin_id() == projection.id()));
    assert_eq!(batch.as_input().rows.len(), 2);

    let mut registry = PluginRegistry::new();
    registry.prepare_manifest_registration(batch)?;
    reject_generated_registration(&mut registry, &producer, producer_binding, "producer")?;
    reject_generated_registration(&mut registry, &projection, projection_binding, "projection")?;
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    Ok(())
}

#[test]
fn malformed_catalog_and_draft_installed_source_fail_closed() -> Result<(), Box<dyn Error>> {
    let first = SocietyPlugin::new();
    let second = SocietyPlugin::new();
    let first_binding = generated_binding(&first, b"first-policy")?;
    let second_binding = generated_binding(&second, b"second-policy")?;
    let first_row = structural_row(&first, &first_binding, "alpha")?;
    let mut duplicate_slot = structural_row(&second, &second_binding, "beta")?;
    duplicate_slot.stable_slot = "alpha".to_owned();
    assert!(matches!(
        catalog(vec![first_row.clone(), duplicate_slot]),
        Err(ManifestOwnerLinkErrorV1::InvalidRowOrder)
    ));
    let mut duplicate_id = structural_row(&second, &second_binding, "beta")?;
    duplicate_id.plugin_id = first.id();
    assert!(matches!(
        catalog(vec![first_row.clone(), duplicate_id]),
        Err(ManifestOwnerLinkErrorV1::DuplicatePluginId)
    ));

    let mut registry = PluginRegistry::new();
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    assert!(matches!(
        registry.prepare_manifest_registration(catalog(Vec::new())?),
        Err(ManifestRegistrationErrorV1::EmptyBatch)
    ));
    registry.prepare_manifest_registration(catalog(vec![first_row])?)?;
    assert!(matches!(
        OutputPolicyBindingV1::from_installed_source(
            &first,
            InstalledOutputPolicySourceV1::Society,
            b"first-policy",
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    ));
    assert!(registry.is_empty());
    assert!(matches!(
        registry.admit_complete_manifest_registration(),
        Err(ManifestRegistrationErrorV1::IncompleteBatch)
    ));
    Ok(())
}
