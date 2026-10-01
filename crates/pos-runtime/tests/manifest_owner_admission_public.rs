use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use pos_core::{
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, Hash,
    ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogV1,
    ManifestOwnerAdmissionCommitKindV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionVerifierV1, ManifestOwnerPolicyCopiesV1,
    ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
    ManifestSlotAdmissionReceiptV1, OwnerIdV1, Plugin, PluginId, TimelineId, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldConsumerSetInputV1, WorldConsumerSetV1,
    WorldProducerV1,
};
use pos_runtime::{
    recover_manifest_owner_admission_retry_v1, AdmittedCompositionV1, PluginRegistry,
};
use pos_store::{memory::MemoryStore, ManifestOwnerAdmissionPersistencePortV1};

type TestResult = Result<(), Box<dyn Error>>;
type FixtureSetup = (
    PluginRegistry,
    [LocalPlugin; 2],
    OwnerIdV1,
    AdmittedCompositionV1,
);

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

struct LocalPlugin {
    id: PluginId,
}

impl Plugin for LocalPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "same-name"
    }

    fn capability(&self) -> pos_core::Capability {
        pos_core::Capability::default()
    }
}

fn setup(owner_verifier: FixtureOwner) -> Result<FixtureSetup, Box<dyn Error>> {
    let plugins = [
        LocalPlugin {
            id: PluginId::new(),
        },
        LocalPlugin {
            id: PluginId::new(),
        },
    ];
    let owner_id = OwnerIdV1::from_static("open-source-app");
    let mut registry = PluginRegistry::new_with_manifest_owner_admission_verifier(owner_verifier);
    for (plugin, role) in plugins.iter().zip(["world", "agent"]) {
        registry.register_local(plugin, vec![role.to_owned()], None, None)?;
    }
    let admitted = registry.admit_local_manifest_registration(owner_id, 1)?;
    Ok((registry, plugins, owner_id, admitted))
}

fn request(
    admitted: &AdmittedCompositionV1,
    sources: &[pos_runtime::AdmittedManifestPolicySourceV1],
    timeline_id: TimelineId,
    operation_id: Hash,
) -> Result<ManifestOwnerAdmissionRequestV1, Box<dyn Error>> {
    let catalog = admitted.catalog().clone();
    let owner_id = catalog.as_input().owner_id;
    let scope = hash(70);
    let policy_copies = sources
        .iter()
        .map(|source| {
            let eop1_bytes = source.eop1_bytes().to_vec();
            let opc1_bytes = source.opc1_bytes().to_vec();
            let eop1_leaf = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
                scope,
                kind: WorldArtifactKindV1::OutputPolicy,
                native_digest: source.eop1_native_digest(),
                native_byte_length: u64::try_from(eop1_bytes.len()).unwrap_or(u64::MAX),
                owner: owner_id,
                data_class: ArtifactDataClassV1::StructuralAuditMetadata,
                optionality: ArtifactOptionalityV1::Required,
                transition: ArtifactTransitionRuleV1::PreserveExact,
                source_lease_hash: hash(71),
                key_dependencies: Vec::new(),
                child_node_hashes: Vec::new(),
            })?;
            let opc1_leaf = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
                scope,
                kind: WorldArtifactKindV1::OutputPolicyClosure,
                native_digest: source.closure_hash(),
                native_byte_length: u64::try_from(opc1_bytes.len()).unwrap_or(u64::MAX),
                owner: owner_id,
                data_class: ArtifactDataClassV1::StructuralAuditMetadata,
                optionality: ArtifactOptionalityV1::Required,
                transition: ArtifactTransitionRuleV1::PreserveExact,
                source_lease_hash: hash(71),
                key_dependencies: Vec::new(),
                child_node_hashes: Vec::new(),
            })?;
            Ok(ManifestOwnerPolicyCopiesV1 {
                plugin_id: source.plugin_id(),
                eop1_bytes,
                eop1_leaf,
                opc1_bytes,
                opc1_leaf,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let producer = sources.first().ok_or("empty admitted Plugin set")?;
    let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope,
        consumers: Vec::new(),
        producers: vec![WorldProducerV1::new(
            producer.plugin_id(),
            producer.eop1_native_digest(),
        )?],
        optional_view_roots: Vec::new(),
    })?;
    Ok(ManifestOwnerAdmissionRequestV1 {
        operation_id,
        catalog,
        expected_configuration_generation: None,
        previous_visible_lcq1_hash: None,
        expected_inventory_generation: None,
        resulting_inventory_generation: hash(72),
        timelines: vec![ManifestOwnerTimelineAdmissionRequestV1 {
            timeline_id,
            scope,
            wcs1,
            policy_copies,
        }],
    })
}

struct FixtureOwner {
    timeline_id: TimelineId,
    operation_id: Hash,
    rejected: Arc<AtomicBool>,
    signed: Arc<AtomicUsize>,
}

impl ManifestOwnerAdmissionVerifierV1 for FixtureOwner {
    fn verify_complete_composition(
        &self,
        catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if catalog.as_input().rows.len() == 2
            && catalog.as_input().rows[0].plugin_name == catalog.as_input().rows[1].plugin_name
        {
            Ok(())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }
    }

    fn verify_complete_owned_scope_set(
        &self,
        _owner_id: [u8; 32],
        timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if timelines.len() == 1 && timelines[0].timeline_id == self.timeline_id {
            Ok(())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }
    }

    fn verify_coordinator_receipt(
        &self,
        receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if receipt.as_input().coordinator_key_evidence_hash == hash(90)
            && receipt.as_input().signature == [90; 64]
        {
            Ok(())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }
    }

    fn verify_owner_prestate_and_allocation(
        &self,
        request: &ManifestOwnerAdmissionRequestV1,
        current_state: Option<&pos_core::ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if !self.rejected.load(Ordering::Relaxed)
            && request.operation_id == self.operation_id
            && request.expected_configuration_generation.is_none()
            && request.expected_inventory_generation.is_none()
            && request.previous_visible_lcq1_hash.is_none()
            && current_state.is_none()
        {
            Ok(())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }
    }

    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        self.signed.fetch_add(1, Ordering::Relaxed);
        draft
            .with_evidence_and_signature(hash(90), [90; 64])
            .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
    }

    fn verify_native_policy_copies(
        &self,
        _timeline_id: TimelineId,
        scope: Hash,
        copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if copies.eop1_bytes.starts_with(b"\x8a\x44EOP1")
            && copies.opc1_bytes.starts_with(b"OPC1")
            && copies.eop1_leaf.as_input().scope == scope
            && copies.opc1_leaf.as_input().scope == scope
        {
            Ok(())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }
    }
}

fn verifier(timeline_id: TimelineId, operation_id: Hash) -> FixtureOwner {
    FixtureOwner {
        timeline_id,
        operation_id,
        rejected: Arc::new(AtomicBool::new(false)),
        signed: Arc::new(AtomicUsize::new(0)),
    }
}

#[test]
fn current_private_composition_is_committed_with_exact_policy_bytes() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(73);
    let owner_verifier = verifier(timeline_id, operation_id);
    let signed_count = Arc::clone(&owner_verifier.signed);
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let input = request(&admitted, &sources, timeline_id, operation_id)?;
    let mut store = MemoryStore::new();

    let first = registry.commit_admitted_manifest_owner_admission_v1(
        &admitted,
        input.clone(),
        &mut store,
    )?;
    assert_eq!(first.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    let signed_after_apply = signed_count.load(Ordering::Relaxed);
    let recovered = recover_manifest_owner_admission_retry_v1(&input, &store)?
        .ok_or("durable owner operation was not recovered")?;
    assert_eq!(
        recovered.kind,
        ManifestOwnerAdmissionCommitKindV1::ExactRetry
    );
    assert_eq!(recovered.receipt_hashes, first.receipt_hashes);
    let retry = registry.commit_admitted_manifest_owner_admission_v1(
        &admitted,
        input.clone(),
        &mut store,
    )?;
    assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(signed_count.load(Ordering::Relaxed), signed_after_apply);

    let mut conflicting_retry = input;
    conflicting_retry.resulting_inventory_generation = hash(76);
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            conflicting_retry,
            &mut store,
        ),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    assert_eq!(signed_count.load(Ordering::Relaxed), signed_after_apply);

    let competing_operation = hash(75);
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            request(&admitted, &sources, timeline_id, competing_operation)?,
            &mut store,
        ),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    let stored = store.read_manifest_owner_admission_v1(
        *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes(),
        1,
        timeline_id,
    )?;
    assert_eq!(
        stored
            .ok_or("committed native admission is missing")?
            .timeline
            .policy_copies
            .len(),
        2
    );
    Ok(())
}

#[test]
fn sqlite_owner_retry_recovers_without_registry_or_signer_after_reopen() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(77);
    let owner_verifier = verifier(timeline_id, operation_id);
    let signed_count = Arc::clone(&owner_verifier.signed);
    let (registry, _plugins, _owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let input = request(&admitted, &sources, timeline_id, operation_id)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime-owner-admission.sqlite");
    let path = path.to_str().ok_or("non-UTF8 test path")?;

    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let applied = registry.commit_admitted_manifest_owner_admission_v1(
        &admitted,
        input.clone(),
        &mut store,
    )?;
    assert_eq!(applied.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    let signatures_before_reopen = signed_count.load(Ordering::Relaxed);
    drop(store);

    let mut reopened = pos_store::sqlite::SqliteStore::open(path)?;
    let retry = recover_manifest_owner_admission_retry_v1(&input, &reopened)?
        .ok_or("SQLite owner operation was not recovered")?;
    assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(retry.receipt_hashes, applied.receipt_hashes);
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_reopen
    );
    let mut conflicting = input.clone();
    conflicting.resulting_inventory_generation = hash(78);
    assert_eq!(
        recover_manifest_owner_admission_retry_v1(&conflicting, &reopened),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );

    let without_authority = PluginRegistry::new().commit_admitted_manifest_owner_admission_v1(
        &admitted,
        input,
        &mut reopened,
    )?;
    assert_eq!(
        without_authority.kind,
        ManifestOwnerAdmissionCommitKindV1::ExactRetry
    );
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_reopen
    );
    Ok(())
}

#[test]
fn current_private_composition_rejects_stale_catalog_and_policy_bytes() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(74);
    let owner_verifier = verifier(timeline_id, operation_id);
    let rejected_flag = Arc::clone(&owner_verifier.rejected);
    let signed_count = Arc::clone(&owner_verifier.signed);
    let (registry, _plugins, _owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let mut store = MemoryStore::new();

    let stale_admission = PluginRegistry::new().commit_admitted_manifest_owner_admission_v1(
        &admitted,
        request(&admitted, &sources, timeline_id, operation_id)?,
        &mut store,
    );
    assert_eq!(
        stale_admission,
        Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
    );

    let mut mismatched_catalog = request(&admitted, &sources, timeline_id, operation_id)?;
    let catalog = mismatched_catalog.catalog.as_input().clone();
    mismatched_catalog.catalog =
        ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            owner_id: catalog.owner_id,
            configuration_generation: 2,
            rows: catalog.rows,
        })?;
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            mismatched_catalog,
            &mut store,
        ),
        Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
    );

    let mut mismatched_policy = request(&admitted, &sources, timeline_id, operation_id)?;
    mismatched_policy.timelines[0].policy_copies[0].opc1_bytes[0] ^= 1;
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            mismatched_policy,
            &mut store,
        ),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );

    let mut missing_source = request(&admitted, &sources, timeline_id, operation_id)?;
    let mut unknown_plugin_id = PluginId::new();
    while sources
        .iter()
        .any(|source| source.plugin_id() == unknown_plugin_id)
    {
        unknown_plugin_id = PluginId::new();
    }
    missing_source.timelines[0].policy_copies[0].plugin_id = unknown_plugin_id;
    assert_eq!(
        registry
            .commit_admitted_manifest_owner_admission_v1(&admitted, missing_source, &mut store,),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );

    let mut owner_rejects = request(&admitted, &sources, timeline_id, operation_id)?;
    owner_rejects.timelines.clear();
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(&admitted, owner_rejects, &mut store,),
        Err(ManifestOwnerAdmissionErrorV1::BoundExceeded)
    );

    rejected_flag.store(true, Ordering::Relaxed);
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            request(&admitted, &sources, timeline_id, operation_id)?,
            &mut store,
        ),
        Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
    );
    assert_eq!(signed_count.load(Ordering::Relaxed), 0);
    Ok(())
}
