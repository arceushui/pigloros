use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use pos_core::{
    manifest_owner_admission_intent_digest_v1, prepare_manifest_owner_admission_v1,
    validate_manifest_owner_admission_snapshot_v1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactTransitionRuleV1, Hash, ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogV1,
    ManifestOwnerAdmissionCommitKindV1, ManifestOwnerAdmissionCommitV1,
    ManifestOwnerAdmissionErrorV1, ManifestOwnerAdmissionOwnerStateV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionSnapshotV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerPolicyCopiesV1,
    ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
    ManifestSlotAdmissionReceiptInputV1, ManifestSlotAdmissionReceiptV1, ManifestSlotBindingInputV1,
    ManifestSlotBindingRowV1, ManifestSlotBindingV1, OwnerIdV1, Plugin, PluginId,
    PreparedManifestOwnerAdmissionV1, TimelineId, WorldArtifactKindV1, WorldArtifactLeafInputV1,
    WorldArtifactLeafV1, WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1,
    WorldProducerV1, MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1,
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
    let wcs1 = consumer_set(scope, producer.plugin_id(), producer.eop1_native_digest())?;
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

fn consumer_set(
    scope: Hash,
    producer_id: PluginId,
    output_policy_hash: Hash,
) -> Result<WorldConsumerSetV1, Box<dyn Error>> {
    Ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope,
        consumers: vec![WorldConsumerV1::new(
            "local-observer".to_owned(),
            hash(79),
            hash(80),
            hash(81),
        )?],
        producers: vec![WorldProducerV1::new(producer_id, output_policy_hash)?],
        optional_view_roots: Vec::new(),
    })?)
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

    let catalog = admitted.catalog().as_input().clone();
    let current_configuration_generation = catalog.configuration_generation;
    let mismatched_configuration_generation = current_configuration_generation
        .checked_add(1)
        .ok_or("fixture configuration generation overflow")?;
    let mismatched_catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: catalog.owner_id,
        configuration_generation: mismatched_configuration_generation,
        rows: catalog.rows,
    })?;
    let mismatched_admitted = registry.revalidate_manifest_registration(mismatched_catalog)?;
    let mismatched_sources = registry.admitted_manifest_policy_sources(&mismatched_admitted)?;
    let mut mismatched_request = request(
        &mismatched_admitted,
        &mismatched_sources,
        timeline_id,
        operation_id,
    )?;
    mismatched_request.expected_configuration_generation = Some(current_configuration_generation);
    mismatched_request.expected_inventory_generation = Some(hash(82));
    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            mismatched_request,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerFault {
    Composition,
    ScopeSet,
    NativeCopies,
    Signature,
    ReceiptDraft,
    Receipt,
}

/// Fixture owner that rejects, or signs a different draft, at one step.
struct FaultyOwner {
    inner: FixtureOwner,
    fault: OwnerFault,
}

impl FaultyOwner {
    fn reject_at(&self, fault: OwnerFault) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if self.fault == fault {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        } else {
            Ok(())
        }
    }
}

impl ManifestOwnerAdmissionVerifierV1 for FaultyOwner {
    fn verify_complete_composition(
        &self,
        catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        self.reject_at(OwnerFault::Composition)?;
        self.inner.verify_complete_composition(catalog)
    }

    fn verify_complete_owned_scope_set(
        &self,
        owner_id: [u8; 32],
        timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        self.reject_at(OwnerFault::ScopeSet)?;
        self.inner
            .verify_complete_owned_scope_set(owner_id, timelines)
    }

    fn verify_coordinator_receipt(
        &self,
        receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        self.reject_at(OwnerFault::Receipt)?;
        self.inner.verify_coordinator_receipt(receipt)
    }

    fn verify_owner_prestate_and_allocation(
        &self,
        request: &ManifestOwnerAdmissionRequestV1,
        current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        self.inner
            .verify_owner_prestate_and_allocation(request, current_state)
    }

    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        self.reject_at(OwnerFault::Signature)?;
        if self.fault == OwnerFault::ReceiptDraft {
            let altered = ManifestSlotAdmissionReceiptDraftV1 {
                mca1_hash: hash(91),
                ..draft
            };
            return self.inner.sign_coordinator_receipt(altered);
        }
        self.inner.sign_coordinator_receipt(draft)
    }

    fn verify_native_policy_copies(
        &self,
        timeline_id: TimelineId,
        scope: Hash,
        copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        self.reject_at(OwnerFault::NativeCopies)?;
        self.inner
            .verify_native_policy_copies(timeline_id, scope, copies)
    }
}

/// Store whose owner-state read fails after a missing retry lookup.
struct UnavailableOwnerState;

impl ManifestOwnerAdmissionPersistencePortV1 for UnavailableOwnerState {
    fn read_manifest_owner_state_v1(
        &self,
        _owner_id: [u8; 32],
    ) -> Result<Option<ManifestOwnerAdmissionOwnerStateV1>, ManifestOwnerAdmissionErrorV1> {
        Err(ManifestOwnerAdmissionErrorV1::StorageFailure)
    }

    fn resolve_manifest_owner_admission_retry_v1(
        &self,
        _owner_id: [u8; 32],
        _operation_id: Hash,
        _intent_digest: Hash,
    ) -> Result<Option<ManifestOwnerAdmissionCommitV1>, ManifestOwnerAdmissionErrorV1> {
        Ok(None)
    }

    fn commit_manifest_owner_admission_v1(
        &mut self,
        _batch: PreparedManifestOwnerAdmissionV1,
    ) -> Result<ManifestOwnerAdmissionCommitV1, ManifestOwnerAdmissionErrorV1> {
        Err(ManifestOwnerAdmissionErrorV1::StorageFailure)
    }

    fn read_manifest_owner_admission_v1(
        &self,
        _owner_id: [u8; 32],
        _configuration_generation: u64,
        _timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerAdmissionSnapshotV1>, ManifestOwnerAdmissionErrorV1> {
        Ok(None)
    }
}

fn unknown_plugin_id(sources: &[pos_runtime::AdmittedManifestPolicySourceV1]) -> PluginId {
    let mut unknown = PluginId::new();
    while sources.iter().any(|source| source.plugin_id() == unknown) {
        unknown = PluginId::new();
    }
    unknown
}

fn prepared_snapshot(
    timeline_id: TimelineId,
    operation_id: Hash,
) -> Result<ManifestOwnerAdmissionSnapshotV1, Box<dyn Error>> {
    let (registry, _plugins, _owner, admitted) = setup(verifier(timeline_id, operation_id))?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let prepared = prepare_manifest_owner_admission_v1(
        request(&admitted, &sources, timeline_id, operation_id)?,
        &verifier(timeline_id, operation_id),
        None,
    )?;
    let input = prepared.input();
    Ok(ManifestOwnerAdmissionSnapshotV1 {
        catalog: input.catalog.clone(),
        timeline: input
            .timelines
            .first()
            .ok_or("prepared admission has no Timeline")?
            .clone(),
        operation_id: input.operation_id,
        expected_inventory_generation: input.expected_inventory_generation,
        resulting_inventory_generation: input.resulting_inventory_generation,
    })
}

/// Replace the MSB1 rows and re-issue the MSR1 so only the row content differs.
fn rebound(
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
    rows: Vec<ManifestSlotBindingRowV1>,
) -> Result<ManifestOwnerAdmissionSnapshotV1, Box<dyn Error>> {
    let binding = ManifestSlotBindingV1::new(ManifestSlotBindingInputV1 {
        scope: snapshot.timeline.scope,
        wcs1_hash: snapshot.timeline.wcs1.digest(),
        rows,
    })?;
    let receipt = ManifestSlotAdmissionReceiptV1::new(ManifestSlotAdmissionReceiptInputV1 {
        msb1_hash: binding.digest(),
        ..snapshot.timeline.receipt.as_input().clone()
    })?;
    let mut changed = snapshot.clone();
    changed.timeline.binding = binding;
    changed.timeline.receipt = receipt;
    Ok(changed)
}

#[test]
fn owner_verifier_rejections_stop_preparation_at_each_step() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(83);
    let (registry, _plugins, _owner, admitted) = setup(verifier(timeline_id, operation_id))?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    for fault in [
        OwnerFault::Composition,
        OwnerFault::ScopeSet,
        OwnerFault::NativeCopies,
        OwnerFault::Signature,
        OwnerFault::ReceiptDraft,
        OwnerFault::Receipt,
    ] {
        let owner = FaultyOwner {
            inner: verifier(timeline_id, operation_id),
            fault,
        };
        assert_eq!(
            prepare_manifest_owner_admission_v1(
                request(&admitted, &sources, timeline_id, operation_id)?,
                &owner,
                None,
            ),
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected),
            "{fault:?}"
        );
    }
    let prepared = prepare_manifest_owner_admission_v1(
        request(&admitted, &sources, timeline_id, operation_id)?,
        &verifier(timeline_id, operation_id),
        None,
    )?;
    assert_eq!(prepared.input().timelines.len(), 1);
    Ok(())
}

#[test]
fn request_shape_rejects_zero_cas_values_null_state_drift_and_oversized_copies() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(84);
    let (registry, _plugins, _owner, admitted) = setup(verifier(timeline_id, operation_id))?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let base = request(&admitted, &sources, timeline_id, operation_id)?;
    assert_ne!(manifest_owner_admission_intent_digest_v1(&base)?, Hash::zero());

    let mut zero_inventory = base.clone();
    zero_inventory.expected_inventory_generation = Some(Hash::zero());
    let mut genesis_with_inventory = base.clone();
    genesis_with_inventory.expected_inventory_generation = Some(hash(85));
    let mut successor_from_zero = base.clone();
    successor_from_zero.expected_configuration_generation = Some(0);
    let mut zero_scope = base.clone();
    zero_scope.timelines[0].scope = Hash::zero();
    for invalid in [
        zero_inventory,
        genesis_with_inventory,
        successor_from_zero,
        zero_scope,
    ] {
        assert_eq!(
            manifest_owner_admission_intent_digest_v1(&invalid),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
    }

    let mut oversized = base;
    oversized.timelines[0].policy_copies[0].eop1_bytes =
        vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1 + 1];
    assert_eq!(
        manifest_owner_admission_intent_digest_v1(&oversized),
        Err(ManifestOwnerAdmissionErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn preparation_rejects_unknown_copies_unparseable_eop1_and_foreign_producers() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(86);
    let (registry, _plugins, _owner, admitted) = setup(verifier(timeline_id, operation_id))?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let owner = verifier(timeline_id, operation_id);
    let unknown = unknown_plugin_id(&sources);
    let producer = sources.first().ok_or("empty admitted Plugin set")?;

    let mut unknown_copy = request(&admitted, &sources, timeline_id, operation_id)?;
    unknown_copy.timelines[0].policy_copies[0].plugin_id = unknown;
    unknown_copy.timelines[0]
        .policy_copies
        .sort_unstable_by_key(|copy| copy.plugin_id);

    let mut unparseable = request(&admitted, &sources, timeline_id, operation_id)?;
    unparseable.timelines[0].policy_copies[0].eop1_bytes = b"not-an-eop1".to_vec();

    let mut foreign_producer = request(&admitted, &sources, timeline_id, operation_id)?;
    let scope = foreign_producer.timelines[0].scope;
    foreign_producer.timelines[0].wcs1 =
        consumer_set(scope, unknown, producer.eop1_native_digest())?;

    let mut drifted_producer = request(&admitted, &sources, timeline_id, operation_id)?;
    drifted_producer.timelines[0].wcs1 = consumer_set(scope, producer.plugin_id(), hash(87))?;

    for invalid in [
        unknown_copy,
        unparseable,
        foreign_producer,
        drifted_producer,
    ] {
        assert_eq!(
            prepare_manifest_owner_admission_v1(invalid, &owner, None),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
    }
    Ok(())
}

#[test]
fn snapshot_validation_rejects_bound_cas_scope_owner_and_receipt_drift() -> TestResult {
    let snapshot = prepared_snapshot(TimelineId::new(), hash(88))?;
    validate_manifest_owner_admission_snapshot_v1(&snapshot)?;
    let catalog = snapshot.catalog.as_input().clone();

    let mut zero_operation = snapshot.clone();
    zero_operation.operation_id = Hash::zero();
    let mut oversized_copy = snapshot.clone();
    oversized_copy.timeline.policy_copies[0].opc1_bytes =
        vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1 + 1];
    for bounded in [zero_operation, oversized_copy] {
        assert_eq!(
            validate_manifest_owner_admission_snapshot_v1(&bounded),
            Err(ManifestOwnerAdmissionErrorV1::BoundExceeded)
        );
    }

    let mut zero_inventory = snapshot.clone();
    zero_inventory.expected_inventory_generation = Some(Hash::zero());
    let mut genesis_with_inventory = snapshot.clone();
    genesis_with_inventory.expected_inventory_generation = Some(hash(89));
    let mut successor_without_inventory = snapshot.clone();
    successor_without_inventory.catalog =
        ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            configuration_generation: 2,
            ..catalog.clone()
        })?;
    let mut zero_scope = snapshot.clone();
    zero_scope.timeline.scope = Hash::zero();
    let mut foreign_scope = snapshot.clone();
    foreign_scope.timeline.scope = hash(94);
    let mut zero_owner = snapshot.clone();
    zero_owner.catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: [0; 32],
        ..catalog
    })?;
    let mut other_operation = snapshot;
    other_operation.operation_id = hash(95);
    for invalid in [
        zero_inventory,
        genesis_with_inventory,
        successor_without_inventory,
        zero_scope,
        foreign_scope,
        zero_owner,
        other_operation,
    ] {
        assert_eq!(
            validate_manifest_owner_admission_snapshot_v1(&invalid),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
    }
    Ok(())
}

#[test]
fn snapshot_validation_rejects_reissued_bindings_with_foreign_rows() -> TestResult {
    let snapshot = prepared_snapshot(TimelineId::new(), hash(92))?;
    let rows = snapshot.timeline.binding.as_input().rows.clone();
    validate_manifest_owner_admission_snapshot_v1(&rebound(&snapshot, rows.clone())?)?;

    let foreign_ids: Vec<_> = rows
        .iter()
        .map(|row| ManifestSlotBindingRowV1 {
            plugin_id: PluginId::new(),
            ..row.clone()
        })
        .collect();
    let foreign_closures: Vec<_> = rows
        .iter()
        .map(|row| ManifestSlotBindingRowV1 {
            closure_hash: hash(96),
            ..row.clone()
        })
        .collect();
    for invalid_rows in [foreign_ids, foreign_closures] {
        assert_eq!(
            validate_manifest_owner_admission_snapshot_v1(&rebound(&snapshot, invalid_rows)?),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
    }
    Ok(())
}

#[test]
fn commit_rejects_a_foreign_capability_and_forwards_owner_state_failures() -> TestResult {
    let timeline_id = TimelineId::new();
    let operation_id = hash(97);
    let (registry, _plugins, _owner, admitted) = setup(verifier(timeline_id, operation_id))?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;

    let foreign_owner = verifier(timeline_id, operation_id);
    let foreign_registry =
        PluginRegistry::new_with_manifest_owner_admission_verifier(foreign_owner);
    assert_eq!(
        foreign_registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            request(&admitted, &sources, timeline_id, operation_id)?,
            &mut MemoryStore::new(),
        ),
        Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
    );

    assert_eq!(
        registry.commit_admitted_manifest_owner_admission_v1(
            &admitted,
            request(&admitted, &sources, timeline_id, operation_id)?,
            &mut UnavailableOwnerState,
        ),
        Err(ManifestOwnerAdmissionErrorV1::StorageFailure)
    );
    Ok(())
}
