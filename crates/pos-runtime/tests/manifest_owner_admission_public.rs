use std::{
    collections::BTreeMap,
    error::Error,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use pos_core::{
    manifest_owner_admission_intent_digest_v1, prepare_manifest_owner_admission_v1,
    validate_manifest_owner_admission_snapshot_v1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactTransitionRuleV1, Hash, LocalCutOwnerCommitKindV1, LocalCutOwnerErrorV1,
    LocalCutOwnerPersistencePortV1, ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogV1,
    ManifestOwnerAdmissionCommitKindV1, ManifestOwnerAdmissionCommitV1,
    ManifestOwnerAdmissionErrorV1, ManifestOwnerAdmissionOwnerStateV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionSnapshotV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerPolicyCopiesV1,
    ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
    ManifestSlotAdmissionReceiptInputV1, ManifestSlotAdmissionReceiptV1,
    ManifestSlotBindingInputV1, ManifestSlotBindingRowV1, ManifestSlotBindingV1, OwnerIdV1, Plugin,
    PluginId, PreparedManifestOwnerAdmissionV1, TimelineId, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldConsumerSetInputV1, WorldConsumerSetV1,
    WorldConsumerV1, WorldProducerV1, MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1,
};
use pos_runtime::{
    recover_local_cut_owner_retry_v1, recover_manifest_owner_admission_retry_v1,
    AdmittedCompositionV1, PluginRegistry,
};
use pos_store::{memory::MemoryStore, ManifestOwnerAdmissionPersistencePortV1};

type TestResult = Result<(), Box<dyn Error>>;
type FixtureSetup = (
    PluginRegistry,
    [LocalPlugin; 2],
    OwnerIdV1,
    AdmittedCompositionV1,
);
type LocalCutPair = (
    pos_core::LocalCutOwnerCommitV1,
    pos_core::LocalCutOwnerCommitV1,
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
    let registry = fixture_registry(owner_verifier, CutVerifierBinding::Installed);
    register_fixture_plugins(registry)
}

#[derive(Clone, Copy)]
enum CutVerifierBinding {
    Installed,
    Absent,
    InstalledThenSubstituted,
}

fn fixture_registry(owner_verifier: FixtureOwner, binding: CutVerifierBinding) -> PluginRegistry {
    let registry =
        PluginRegistry::new_with_manifest_owner_admission_verifier(owner_verifier.clone());
    match binding {
        CutVerifierBinding::Installed => registry.with_local_cut_owner_verifier(owner_verifier),
        CutVerifierBinding::Absent => registry,
        CutVerifierBinding::InstalledThenSubstituted => registry
            .with_local_cut_owner_verifier(owner_verifier.clone())
            .with_local_cut_owner_verifier(FaultingCutVerifier {
                inner: owner_verifier,
                fault: CutVerifierFault::SignRejected,
            }),
    }
}

fn register_fixture_plugins(mut registry: PluginRegistry) -> Result<FixtureSetup, Box<dyn Error>> {
    let plugins = [
        LocalPlugin {
            id: PluginId::new(),
        },
        LocalPlugin {
            id: PluginId::new(),
        },
    ];
    let owner_id = OwnerIdV1::from_static("open-source-app");
    for (plugin, role) in plugins.iter().zip(["world", "agent"]) {
        registry.register_local(plugin, vec![role.to_owned()], None, None)?;
    }
    let admitted = registry.admit_local_manifest_registration(owner_id, 1)?;
    Ok((registry, plugins, owner_id, admitted))
}

fn revalidated_admitted_composition(
    registry: &PluginRegistry,
    admitted: &AdmittedCompositionV1,
    configuration_generation: u64,
) -> Result<AdmittedCompositionV1, Box<dyn Error>> {
    let catalog = admitted.catalog().as_input();
    let later_catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: catalog.owner_id,
        configuration_generation,
        rows: catalog.rows.clone(),
    })?;
    Ok(registry.revalidate_manifest_registration(later_catalog)?)
}

struct AdmissionTransition {
    operation_id: Hash,
    expected_configuration_generation: Option<u64>,
    previous_visible_lcq1_hash: Option<Hash>,
    expected_inventory_generation: Option<Hash>,
    resulting_inventory_generation: Hash,
}

fn request(
    admitted: &AdmittedCompositionV1,
    sources: &[pos_runtime::AdmittedManifestPolicySourceV1],
    timeline_id: TimelineId,
    operation_id: Hash,
) -> Result<ManifestOwnerAdmissionRequestV1, Box<dyn Error>> {
    request_for_timelines(
        admitted,
        sources,
        &[timeline_id],
        &AdmissionTransition {
            operation_id,
            expected_configuration_generation: None,
            previous_visible_lcq1_hash: None,
            expected_inventory_generation: None,
            resulting_inventory_generation: hash(72),
        },
    )
}

fn request_for_timelines(
    admitted: &AdmittedCompositionV1,
    sources: &[pos_runtime::AdmittedManifestPolicySourceV1],
    timeline_ids: &[TimelineId],
    transition: &AdmissionTransition,
) -> Result<ManifestOwnerAdmissionRequestV1, Box<dyn Error>> {
    let catalog = admitted.catalog().clone();
    let owner_id = catalog.as_input().owner_id;
    let producer = sources.first().ok_or("empty admitted Plugin set")?;
    let mut timeline_ids = timeline_ids.to_vec();
    timeline_ids.sort_unstable();
    if timeline_ids.is_empty() || timeline_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("invalid fixture Timeline set".into());
    }

    let mut timelines = Vec::with_capacity(timeline_ids.len());
    for (index, timeline_id) in timeline_ids.iter().enumerate() {
        let scope_byte = 70u8
            .checked_add(u8::try_from(index)?)
            .ok_or("too many fixture Timelines")?;
        let scope = hash(scope_byte);
        let mut policy_copies = Vec::with_capacity(sources.len());
        for source in sources {
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
            policy_copies.push(ManifestOwnerPolicyCopiesV1 {
                plugin_id: source.plugin_id(),
                eop1_bytes,
                eop1_leaf,
                opc1_bytes,
                opc1_leaf,
            });
        }
        let wcs1 = consumer_set(scope, producer.plugin_id(), producer.eop1_native_digest())?;
        timelines.push(ManifestOwnerTimelineAdmissionRequestV1 {
            timeline_id: *timeline_id,
            scope,
            wcs1,
            policy_copies,
        });
    }

    Ok(ManifestOwnerAdmissionRequestV1 {
        operation_id: transition.operation_id,
        catalog,
        expected_configuration_generation: transition.expected_configuration_generation,
        previous_visible_lcq1_hash: transition.previous_visible_lcq1_hash,
        expected_inventory_generation: transition.expected_inventory_generation,
        resulting_inventory_generation: transition.resulting_inventory_generation,
        timelines,
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

#[derive(Clone)]
struct FixtureOwner {
    allowed_timeline_ids: Vec<TimelineId>,
    allowed_operations: Vec<Hash>,
    expected_timeline_sets: BTreeMap<Hash, Vec<TimelineId>>,
    rejected: Arc<AtomicBool>,
    signer_substituted: Arc<AtomicBool>,
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
        let actual = timelines
            .iter()
            .map(|timeline| timeline.timeline_id)
            .collect::<Vec<_>>();
        if actual.is_empty()
            || actual.windows(2).any(|pair| pair[0] >= pair[1])
            || actual.iter().any(|timeline_id| {
                self.allowed_timeline_ids
                    .binary_search(timeline_id)
                    .is_err()
            })
            || timelines
                .iter()
                .any(|timeline| timeline.wcs1.scope() != timeline.scope)
        {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        } else {
            Ok(())
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
        let current_state_matches = match (request.expected_configuration_generation, current_state)
        {
            (None, None) => {
                request.previous_visible_lcq1_hash.is_none()
                    && request.expected_inventory_generation.is_none()
            }
            (Some(expected_generation), Some(state)) => {
                state.configuration_generation == expected_generation
                    && state.previous_visible_lcq1_hash == request.previous_visible_lcq1_hash
                    && Some(state.inventory_generation) == request.expected_inventory_generation
            }
            _ => false,
        };
        let requested_timeline_ids = request
            .timelines
            .iter()
            .map(|timeline| timeline.timeline_id)
            .collect::<Vec<_>>();
        let expected_timeline_ids = self.expected_timeline_sets.get(&request.operation_id);
        if !self.rejected.load(Ordering::Relaxed)
            && self.allowed_operations.contains(&request.operation_id)
            && expected_timeline_ids == Some(&requested_timeline_ids)
            && current_state_matches
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

impl pos_core::LocalCutOwnerVerifierV1 for FixtureOwner {
    fn verify_authenticated_cut(
        &self,
        request: &pos_core::LocalCutOwnerRequestV1,
        _current_state: Option<&pos_core::LocalCutOwnerStateV1>,
        _admission_state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
        _admissions: &[pos_core::ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), pos_core::LocalCutOwnerErrorV1> {
        let composition_is_current = request.composition_rows.iter().all(|row| {
            row.driver_interval_ns == Some(0)
                && row.last_due_ns.is_none()
                && row.event_cursor == 0
                && row.participant_native_state_hash == hash(91)
        });
        let recording_contexts_are_current = request
            .recording_context_rows
            .iter()
            .all(|row| row.retention_lease_hash == hash(104) && row.predecessor_wcb_hash.is_none());
        (!self.rejected.load(Ordering::Relaxed)
            && composition_is_current
            && recording_contexts_are_current)
            .then_some(())
            .ok_or(pos_core::LocalCutOwnerErrorV1::OwnerRejected)
    }

    fn sign_local_cut_receipt(
        &self,
        commit: &pos_core::LocalCutCommitV1,
    ) -> Result<pos_core::LocalCutReceiptV1, pos_core::LocalCutOwnerErrorV1> {
        self.signed.fetch_add(1, Ordering::Relaxed);
        let (coordinator_key_evidence_hash, signature) =
            if self.signer_substituted.load(Ordering::Relaxed) {
                (hash(119), [119; 64])
            } else {
                (hash(90), [90; 64])
            };
        pos_core::LocalCutReceiptV1::new(pos_core::LocalCutReceiptInputV1 {
            commit_record_hash: commit.digest(),
            coordinator_key_evidence_hash,
            signature,
        })
        .map_err(|_| pos_core::LocalCutOwnerErrorV1::OwnerRejected)
    }

    fn verify_local_cut_receipt(
        &self,
        receipt: &pos_core::LocalCutReceiptV1,
        commit: &pos_core::LocalCutCommitV1,
        _admissions: &[pos_core::ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), pos_core::LocalCutOwnerErrorV1> {
        let fields = receipt.as_input();
        if fields.commit_record_hash == commit.digest()
            && fields.coordinator_key_evidence_hash == hash(90)
            && fields.signature == [90; 64]
            && receipt.signature_preimage()
                == pos_core::local_cut_receipt_signature_preimage_v1(commit.digest(), hash(90))
                    .map_err(|_| pos_core::LocalCutOwnerErrorV1::OwnerRejected)?
        {
            Ok(())
        } else {
            Err(pos_core::LocalCutOwnerErrorV1::OwnerRejected)
        }
    }
}

fn verifier(timeline_id: TimelineId, operation_id: Hash) -> FixtureOwner {
    verifier_for_scopes(vec![(operation_id, vec![timeline_id])])
}

fn verifier_for_timelines(
    allowed_timeline_ids: &[TimelineId],
    allowed_operations: Vec<Hash>,
) -> FixtureOwner {
    verifier_for_scopes(
        allowed_operations
            .into_iter()
            .map(|operation_id| (operation_id, allowed_timeline_ids.to_vec()))
            .collect(),
    )
}

fn verifier_for_scopes(expected_timeline_sets: Vec<(Hash, Vec<TimelineId>)>) -> FixtureOwner {
    let mut allowed_timeline_ids = Vec::new();
    let mut expected_timeline_sets_by_operation = BTreeMap::new();
    for (operation_id, mut timeline_ids) in expected_timeline_sets {
        timeline_ids.sort_unstable();
        timeline_ids.dedup();
        allowed_timeline_ids.extend_from_slice(&timeline_ids);
        expected_timeline_sets_by_operation.insert(operation_id, timeline_ids);
    }
    allowed_timeline_ids.sort_unstable();
    allowed_timeline_ids.dedup();
    let allowed_operations = expected_timeline_sets_by_operation
        .keys()
        .copied()
        .collect();
    FixtureOwner {
        allowed_timeline_ids,
        allowed_operations,
        expected_timeline_sets: expected_timeline_sets_by_operation,
        rejected: Arc::new(AtomicBool::new(false)),
        signer_substituted: Arc::new(AtomicBool::new(false)),
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

fn local_cut_table(
    row_count: u64,
    byte: u8,
) -> Result<pos_core::LocalCutTableRefV1, pos_core::LocalCutSealErrorV2> {
    pos_core::LocalCutTableRefV1::new(row_count, (row_count != 0).then(|| hash(byte)))
}

struct LocalCutTransition {
    cut_id: u64,
    tick: u64,
    membership_epoch: u32,
    operation_id: Hash,
    result_inventory_generation: Hash,
    result_heads_table: pos_core::LocalCutTableRefV1,
}

fn local_cut_request(
    owner_id: [u8; 32],
    state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
    snapshot: &pos_core::ManifestOwnerAdmissionSnapshotV1,
) -> Result<pos_core::LocalCutOwnerRequestV1, Box<dyn Error>> {
    local_cut_request_for_admissions(
        owner_id,
        state,
        std::slice::from_ref(snapshot),
        &LocalCutTransition {
            cut_id: 1,
            tick: 1,
            membership_epoch: 0,
            operation_id: hash(102),
            result_inventory_generation: hash(111),
            result_heads_table: local_cut_table(1, 105)?,
        },
    )
}

fn local_cut_request_for_admissions(
    owner_id: [u8; 32],
    state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
    snapshots: &[pos_core::ManifestOwnerAdmissionSnapshotV1],
    transition: &LocalCutTransition,
) -> Result<pos_core::LocalCutOwnerRequestV1, Box<dyn Error>> {
    let mut snapshots = snapshots.to_vec();
    snapshots.sort_unstable_by_key(|snapshot| snapshot.timeline.timeline_id);
    if snapshots.is_empty() {
        return Err("empty admitted Timeline set".into());
    }

    let manifest_binding_table = pos_core::LocalCutManifestBindingTableV1::new(
        owner_id,
        transition.cut_id,
        snapshots
            .iter()
            .map(|snapshot| pos_core::LocalCutManifestBindingRowV1 {
                timeline_id: snapshot.timeline.timeline_id,
                scope: snapshot.timeline.scope,
                wcs_hash: snapshot.timeline.wcs1.digest(),
                msr_hash: snapshot.timeline.receipt.digest(),
                msb_hash: snapshot.timeline.binding.digest(),
            })
            .collect(),
    )?;
    let mut composition_rows = Vec::new();
    for snapshot in &snapshots {
        composition_rows.extend(snapshot.catalog.as_input().rows.iter().map(|row| {
            pos_core::LocalCutCompositionBindingRowV1 {
                plugin_id: row.plugin_id,
                timeline_id: snapshot.timeline.timeline_id,
                plugin_version: row.plugin_version.clone(),
                implementation_hash: row.implementation_hash,
                eop1_native_digest: row.eop1_native_digest,
                driver_interval_ns: Some(0),
                last_due_ns: None,
                event_cursor: 0,
                participant_native_state_hash: hash(91),
            }
        }));
    }
    composition_rows.sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
    let mut recording_context_rows = snapshots
        .iter()
        .map(|snapshot| pos_core::LocalCutRecordingContextRowV1 {
            timeline_id: snapshot.timeline.timeline_id,
            wcs_hash: snapshot.timeline.wcs1.digest(),
            retention_lease_hash: hash(104),
            predecessor_wcb_hash: None,
        })
        .collect::<Vec<_>>();
    recording_context_rows.sort_unstable_by_key(|row| row.timeline_id);
    let composition_table = local_cut_table(u64::try_from(composition_rows.len())?, 92)?;
    let recording_context_table =
        local_cut_table(u64::try_from(recording_context_rows.len())?, 93)?;
    let seal = pos_core::LocalCutSealV2::new(pos_core::LocalCutSealInputV2 {
        owner_id,
        cut_id: transition.cut_id,
        tick: transition.tick,
        membership_epoch: transition.membership_epoch,
        configuration_generation: state.configuration_generation,
        schedule_ns: 0,
        previous_visible_receipt_hash: state.previous_visible_lcq1_hash,
        expected_inventory_generation: state.inventory_generation,
        membership_table: local_cut_table(u64::try_from(snapshots.len())?, 94)?,
        composition_table,
        inbox_table: local_cut_table(0, 95)?,
        invocation_table: local_cut_table(0, 96)?,
        expected_heads_table: transition.result_heads_table,
        ebp_native_hash: hash(98),
        execution_profile_native_hash: hash(99),
        recording_context_table,
        owner_operational_policy_hash: hash(100),
        explicit_attempt_hash: None,
        ingress_preallocation_native_hash: hash(101),
        manifest_binding_table: manifest_binding_table.table_ref(),
    })?;
    Ok(pos_core::LocalCutOwnerRequestV1 {
        operation_id: transition.operation_id,
        seal,
        manifest_hash: hash(103),
        manifest_binding_table,
        composition_rows,
        recording_context_rows,
        partition_ledger_seq: transition.cut_id,
        result_heads_table: transition.result_heads_table,
        participant_successor_table: local_cut_table(1, 106)?,
        cpu_completion_table: local_cut_table(0, 107)?,
        action_disposition_table: local_cut_table(1, 108)?,
        candidate_bases_table: local_cut_table(0, 109)?,
        invocation_bridges_table: local_cut_table(0, 110)?,
        result_inventory_generation: transition.result_inventory_generation,
        release_fence_proof_digest: hash(112),
    })
}

fn admitted_snapshot<S: ManifestOwnerAdmissionPersistencePortV1>(
    store: &S,
    owner_id: [u8; 32],
    configuration_generation: u64,
    timeline_id: TimelineId,
    missing: &'static str,
) -> Result<pos_core::ManifestOwnerAdmissionSnapshotV1, Box<dyn Error>> {
    Ok(store
        .read_manifest_owner_admission_v1(owner_id, configuration_generation, timeline_id)?
        .ok_or_else(|| std::io::Error::other(missing))?)
}

fn admitted_snapshots<S: ManifestOwnerAdmissionPersistencePortV1>(
    store: &S,
    owner_id: [u8; 32],
    state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
    missing: &'static str,
) -> Result<Vec<pos_core::ManifestOwnerAdmissionSnapshotV1>, Box<dyn Error>> {
    state
        .timelines
        .iter()
        .map(|timeline_id| {
            admitted_snapshot(
                store,
                owner_id,
                state.configuration_generation,
                *timeline_id,
                missing,
            )
        })
        .collect()
}

#[test]
fn registry_commits_local_cut_owner_and_recovers_without_authority() -> TestResult {
    let timeline_id = TimelineId::new();
    let admission_operation = hash(117);
    let owner_verifier = verifier(timeline_id, admission_operation);
    let signed_count = Arc::clone(&owner_verifier.signed);
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let admission = request(&admitted, &sources, timeline_id, admission_operation)?;
    let mut store = MemoryStore::new();
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, admission, &mut store)?;

    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let admission_state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing current admitted owner state")?;
    let snapshot = store
        .read_manifest_owner_admission_v1(
            owner_id,
            admission_state.configuration_generation,
            timeline_id,
        )?
        .ok_or("missing current admitted owner snapshot")?;
    let local_cut = local_cut_request(owner_id, &admission_state, &snapshot)?;
    let signatures_before_cut = signed_count.load(Ordering::Relaxed);

    let applied =
        registry.commit_admitted_local_cut_owner_v1(&admitted, local_cut.clone(), &mut store)?;
    assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_cut + 1
    );
    let local_state = store
        .read_local_cut_owner_state_v1(owner_id)?
        .ok_or("missing current local-cut owner state")?;
    assert_eq!(local_state.last_visible_cut_id, 1);
    assert_eq!(local_state.last_visible_tick, 1);
    assert_eq!(
        local_state.previous_visible_lcq1_hash,
        Some(applied.receipt.digest())
    );
    assert_eq!(
        local_state.inventory_generation,
        local_cut.result_inventory_generation
    );
    let current_admission = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing synchronized admitted owner state")?;
    assert_eq!(
        current_admission.previous_visible_lcq1_hash,
        Some(applied.receipt.digest())
    );
    assert_eq!(
        current_admission.inventory_generation,
        local_cut.result_inventory_generation
    );
    let persisted = store
        .read_local_cut_owner_commit_v1(owner_id, 1)?
        .ok_or("missing durable local-cut owner record")?;
    assert_eq!(persisted, applied);

    let recovered = recover_local_cut_owner_retry_v1(&local_cut, &store)?
        .ok_or("durable local-cut owner operation was not recovered")?;
    assert_eq!(recovered.kind, LocalCutOwnerCommitKindV1::ExactRetry);
    assert_eq!(recovered.commit, applied.commit);
    assert_eq!(recovered.receipt, applied.receipt);

    let without_authority = PluginRegistry::new().commit_admitted_local_cut_owner_v1(
        &admitted,
        local_cut.clone(),
        &mut store,
    )?;
    assert_eq!(
        without_authority.kind,
        LocalCutOwnerCommitKindV1::ExactRetry
    );
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_cut + 1
    );

    let mut conflicting = local_cut;
    conflicting.result_inventory_generation = hash(118);
    assert_eq!(
        recover_local_cut_owner_retry_v1(&conflicting, &store),
        Err(LocalCutOwnerErrorV1::Conflict)
    );
    Ok(())
}

#[test]
fn sqlite_local_cut_owner_retry_survives_reopen_without_registry_authority() -> TestResult {
    let timeline_id = TimelineId::new();
    let admission_operation = hash(119);
    let owner_verifier = verifier(timeline_id, admission_operation);
    let signed_count = Arc::clone(&owner_verifier.signed);
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let admission = request(&admitted, &sources, timeline_id, admission_operation)?;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("runtime-local-cut-owner.sqlite");
    let database = database.to_str().ok_or("non-UTF8 test path")?;
    let mut store = pos_store::sqlite::SqliteStore::open(database)?;
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, admission, &mut store)?;

    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let admission_state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing current admitted owner state")?;
    let snapshot = store
        .read_manifest_owner_admission_v1(
            owner_id,
            admission_state.configuration_generation,
            timeline_id,
        )?
        .ok_or("missing current admitted owner snapshot")?;
    let local_cut = local_cut_request(owner_id, &admission_state, &snapshot)?;
    let applied =
        registry.commit_admitted_local_cut_owner_v1(&admitted, local_cut.clone(), &mut store)?;
    assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
    let signatures_before_reopen = signed_count.load(Ordering::Relaxed);
    drop(store);

    let mut reopened = pos_store::sqlite::SqliteStore::open(database)?;
    let retry = recover_local_cut_owner_retry_v1(&local_cut, &reopened)?
        .ok_or("SQLite local-cut owner operation was not recovered")?;
    assert_eq!(retry.kind, LocalCutOwnerCommitKindV1::ExactRetry);
    assert_eq!(retry.commit, applied.commit);
    assert_eq!(retry.receipt, applied.receipt);
    let stored = reopened
        .read_local_cut_owner_commit_v1(owner_id, 1)?
        .ok_or("SQLite local-cut owner record was not retained")?;
    assert_eq!(stored.commit, applied.commit);
    assert_eq!(stored.receipt, applied.receipt);

    let without_authority = PluginRegistry::new().commit_admitted_local_cut_owner_v1(
        &admitted,
        local_cut.clone(),
        &mut reopened,
    )?;
    assert_eq!(
        without_authority.kind,
        LocalCutOwnerCommitKindV1::ExactRetry
    );
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_reopen
    );

    let mut conflicting = local_cut;
    conflicting.result_inventory_generation = hash(120);
    assert_eq!(
        recover_local_cut_owner_retry_v1(&conflicting, &reopened),
        Err(LocalCutOwnerErrorV1::Conflict)
    );
    Ok(())
}

fn commit_two_zero_output_cuts(
    registry: &PluginRegistry,
    admitted: &AdmittedCompositionV1,
    owner_id: [u8; 32],
    expected_timelines: &[TimelineId],
    store: &mut MemoryStore,
) -> Result<LocalCutPair, Box<dyn Error>> {
    let initial_admission_state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing initial multi-Timeline admission state")?;
    let initial_snapshots = admitted_snapshots(
        store,
        owner_id,
        &initial_admission_state,
        "missing initial multi-Timeline admission snapshot",
    )?;
    let first_request = local_cut_request_for_admissions(
        owner_id,
        &initial_admission_state,
        &initial_snapshots,
        &LocalCutTransition {
            cut_id: 1,
            tick: 1,
            membership_epoch: 0,
            operation_id: hash(124),
            result_inventory_generation: hash(125),
            result_heads_table: local_cut_table(0, 105)?,
        },
    )?;
    let first = registry.commit_admitted_local_cut_owner_v1(admitted, first_request, store)?;
    assert_eq!(first.kind, LocalCutOwnerCommitKindV1::Applied);
    assert_eq!(first.commit.as_input().result_heads_table.row_count(), 0);

    let after_first = store
        .read_local_cut_owner_state_v1(owner_id)?
        .ok_or("missing first local-cut owner state")?;
    assert_eq!(after_first.timelines.as_slice(), expected_timelines);
    let after_first_admission = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing admission state after first local cut")?;
    let second_snapshots = admitted_snapshots(
        store,
        owner_id,
        &after_first_admission,
        "missing admission snapshot after first local cut",
    )?;
    let second_request = local_cut_request_for_admissions(
        owner_id,
        &after_first_admission,
        &second_snapshots,
        &LocalCutTransition {
            cut_id: 2,
            tick: 2,
            membership_epoch: after_first.membership_epoch,
            operation_id: hash(126),
            result_inventory_generation: hash(127),
            result_heads_table: local_cut_table(0, 105)?,
        },
    )?;
    let second = registry.commit_admitted_local_cut_owner_v1(admitted, second_request, store)?;
    assert_eq!(second.kind, LocalCutOwnerCommitKindV1::Applied);
    assert_eq!(
        second.commit.as_input().result_heads_table,
        first.commit.as_input().result_heads_table
    );
    assert_ne!(second.commit.digest(), first.commit.digest());
    Ok((first, second))
}

struct MultiTimelineCutContext {
    owner_id: [u8; 32],
    admitted: AdmittedCompositionV1,
    replacement_timeline: TimelineId,
    replacement_admission_operation: Hash,
    first: pos_core::LocalCutOwnerCommitV1,
    second: pos_core::LocalCutOwnerCommitV1,
}

fn replace_scope_and_commit_third_cut(
    registry: &PluginRegistry,
    store: &mut MemoryStore,
    context: &MultiTimelineCutContext,
) -> TestResult {
    let before_replacement = store
        .read_manifest_owner_state_v1(context.owner_id)?
        .ok_or("missing admission state before replacement")?;
    let replacement_admitted = revalidated_admitted_composition(registry, &context.admitted, 2)?;
    let replacement_sources = registry.admitted_manifest_policy_sources(&replacement_admitted)?;
    let replacement_admission = request_for_timelines(
        &replacement_admitted,
        &replacement_sources,
        &[context.replacement_timeline],
        &AdmissionTransition {
            operation_id: context.replacement_admission_operation,
            expected_configuration_generation: Some(before_replacement.configuration_generation),
            previous_visible_lcq1_hash: before_replacement.previous_visible_lcq1_hash,
            expected_inventory_generation: Some(before_replacement.inventory_generation),
            resulting_inventory_generation: hash(128),
        },
    )?;
    registry.commit_admitted_manifest_owner_admission_v1(
        &replacement_admitted,
        replacement_admission,
        store,
    )?;
    let after_replacement = store
        .read_local_cut_owner_state_v1(context.owner_id)?
        .ok_or("missing local-cut owner state after replacement")?;
    assert_eq!(after_replacement.configuration_generation, 2);
    assert_eq!(after_replacement.membership_epoch, 1);
    assert_eq!(
        after_replacement.timelines,
        vec![context.replacement_timeline]
    );
    assert_eq!(after_replacement.inventory_generation, hash(128));
    assert_eq!(
        store
            .read_local_cut_owner_commit_v1(context.owner_id, 1)?
            .as_ref(),
        Some(&context.first)
    );
    assert_eq!(
        store
            .read_local_cut_owner_commit_v1(context.owner_id, 2)?
            .as_ref(),
        Some(&context.second)
    );

    let replacement_admission_state = store
        .read_manifest_owner_state_v1(context.owner_id)?
        .ok_or("missing replacement admission state")?;
    let replacement_snapshot = admitted_snapshot(
        store,
        context.owner_id,
        replacement_admission_state.configuration_generation,
        context.replacement_timeline,
        "missing replacement Timeline admission snapshot",
    )?;
    let third_request = local_cut_request_for_admissions(
        context.owner_id,
        &replacement_admission_state,
        std::slice::from_ref(&replacement_snapshot),
        &LocalCutTransition {
            cut_id: 3,
            tick: 3,
            membership_epoch: after_replacement.membership_epoch,
            operation_id: hash(129),
            result_inventory_generation: hash(130),
            result_heads_table: local_cut_table(0, 105)?,
        },
    )?;
    let third =
        registry.commit_admitted_local_cut_owner_v1(&replacement_admitted, third_request, store)?;
    assert_eq!(third.kind, LocalCutOwnerCommitKindV1::Applied);
    let final_state = store
        .read_local_cut_owner_state_v1(context.owner_id)?
        .ok_or("missing final local-cut owner state")?;
    assert_eq!(final_state.last_visible_cut_id, 3);
    assert_eq!(final_state.last_visible_tick, 3);
    assert_eq!(final_state.membership_epoch, 1);
    assert_eq!(final_state.timelines, vec![context.replacement_timeline]);
    Ok(())
}

#[test]
fn multi_timeline_zero_output_cuts_retain_history_across_scope_replacement() -> TestResult {
    let mut timelines = vec![TimelineId::new(), TimelineId::new()];
    timelines.sort_unstable();
    let first_admission_operation = hash(121);
    let replacement_admission_operation = hash(122);
    let replacement_timeline = timelines[1];
    let owner_verifier = verifier_for_scopes(vec![
        (first_admission_operation, timelines.clone()),
        (replacement_admission_operation, vec![replacement_timeline]),
    ]);
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let first_admission = request_for_timelines(
        &admitted,
        &sources,
        &timelines,
        &AdmissionTransition {
            operation_id: first_admission_operation,
            expected_configuration_generation: None,
            previous_visible_lcq1_hash: None,
            expected_inventory_generation: None,
            resulting_inventory_generation: hash(123),
        },
    )?;
    let mut store = MemoryStore::new();
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, first_admission, &mut store)?;
    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let (first, second) =
        commit_two_zero_output_cuts(&registry, &admitted, owner_id, &timelines, &mut store)?;
    let context = MultiTimelineCutContext {
        owner_id,
        admitted,
        replacement_timeline,
        replacement_admission_operation,
        first,
        second,
    };
    replace_scope_and_commit_third_cut(&registry, &mut store, &context)
}

#[derive(Clone, Copy)]
struct SqliteSuccessorInput<'a> {
    registry: &'a PluginRegistry,
    admitted: &'a AdmittedCompositionV1,
    owner_id: [u8; 32],
    timeline_id: TimelineId,
    operation_id: Hash,
    database: &'a str,
}

fn commit_sqlite_successor_and_reopen(
    input: SqliteSuccessorInput<'_>,
    first: pos_core::LocalCutOwnerCommitV1,
    mut store: pos_store::sqlite::SqliteStore,
) -> TestResult {
    let before_successor = store
        .read_manifest_owner_state_v1(input.owner_id)?
        .ok_or("missing SQLite admission state before successor")?;
    let successor_admitted = revalidated_admitted_composition(input.registry, input.admitted, 2)?;
    let successor_sources = input
        .registry
        .admitted_manifest_policy_sources(&successor_admitted)?;
    let successor_admission = request_for_timelines(
        &successor_admitted,
        &successor_sources,
        &[input.timeline_id],
        &AdmissionTransition {
            operation_id: input.operation_id,
            expected_configuration_generation: Some(before_successor.configuration_generation),
            previous_visible_lcq1_hash: before_successor.previous_visible_lcq1_hash,
            expected_inventory_generation: Some(before_successor.inventory_generation),
            resulting_inventory_generation: hash(137),
        },
    )?;
    input.registry.commit_admitted_manifest_owner_admission_v1(
        &successor_admitted,
        successor_admission,
        &mut store,
    )?;
    let successor_state = store
        .read_local_cut_owner_state_v1(input.owner_id)?
        .ok_or("missing SQLite local-cut state after successor admission")?;
    assert_eq!(successor_state.configuration_generation, 2);
    assert_eq!(successor_state.last_visible_cut_id, 1);
    assert_eq!(successor_state.last_visible_tick, 1);
    assert_eq!(successor_state.membership_epoch, 0);
    assert_eq!(successor_state.inventory_generation, hash(137));
    assert_eq!(
        store.read_local_cut_owner_commit_v1(input.owner_id, 1)?,
        Some(first.clone())
    );
    drop(store);

    let mut reopened = pos_store::sqlite::SqliteStore::open(input.database)?;
    assert_eq!(
        reopened.read_local_cut_owner_state_v1(input.owner_id)?,
        Some(successor_state.clone())
    );
    let reopened_admission = reopened
        .read_manifest_owner_state_v1(input.owner_id)?
        .ok_or("missing reopened SQLite admission state")?;
    let reopened_snapshot = admitted_snapshot(
        &reopened,
        input.owner_id,
        reopened_admission.configuration_generation,
        input.timeline_id,
        "missing reopened SQLite admission snapshot",
    )?;
    let second_request = local_cut_request_for_admissions(
        input.owner_id,
        &reopened_admission,
        std::slice::from_ref(&reopened_snapshot),
        &LocalCutTransition {
            cut_id: 2,
            tick: 2,
            membership_epoch: successor_state.membership_epoch,
            operation_id: hash(138),
            result_inventory_generation: hash(139),
            result_heads_table: local_cut_table(0, 105)?,
        },
    )?;
    let second = input.registry.commit_admitted_local_cut_owner_v1(
        &successor_admitted,
        second_request,
        &mut reopened,
    )?;
    assert_eq!(second.kind, LocalCutOwnerCommitKindV1::Applied);
    assert_eq!(
        reopened.read_local_cut_owner_commit_v1(input.owner_id, 1)?,
        Some(first)
    );
    assert_eq!(
        reopened.read_local_cut_owner_commit_v1(input.owner_id, 2)?,
        Some(second)
    );
    let final_state = reopened
        .read_local_cut_owner_state_v1(input.owner_id)?
        .ok_or("missing final reopened SQLite local-cut state")?;
    assert_eq!(final_state.configuration_generation, 2);
    assert_eq!(final_state.last_visible_cut_id, 2);
    assert_eq!(final_state.last_visible_tick, 2);
    assert_eq!(final_state.membership_epoch, 0);
    Ok(())
}

#[test]
fn sqlite_local_cut_owner_successor_admission_survives_reopen() -> TestResult {
    let timeline_id = TimelineId::new();
    let first_admission_operation = hash(135);
    let successor_admission_operation = hash(136);
    let owner_verifier = verifier_for_timelines(
        &[timeline_id],
        vec![first_admission_operation, successor_admission_operation],
    );
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let first_admission = request(&admitted, &sources, timeline_id, first_admission_operation)?;
    let directory = tempfile::tempdir()?;
    let database = directory
        .path()
        .join("runtime-local-cut-owner-successor.sqlite");
    let database = database.to_str().ok_or("non-UTF8 test path")?;
    let mut store = pos_store::sqlite::SqliteStore::open(database)?;
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, first_admission, &mut store)?;

    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let initial_state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing initial SQLite admission state")?;
    let initial_snapshot = admitted_snapshot(
        &store,
        owner_id,
        initial_state.configuration_generation,
        timeline_id,
        "missing initial SQLite admission snapshot",
    )?;
    let first_request = local_cut_request(owner_id, &initial_state, &initial_snapshot)?;
    let first =
        registry.commit_admitted_local_cut_owner_v1(&admitted, first_request, &mut store)?;
    assert_eq!(first.kind, LocalCutOwnerCommitKindV1::Applied);
    commit_sqlite_successor_and_reopen(
        SqliteSuccessorInput {
            registry: &registry,
            admitted: &admitted,
            owner_id,
            timeline_id,
            operation_id: successor_admission_operation,
            database,
        },
        first,
        store,
    )
}

#[test]
fn sqlite_local_cut_owner_rolls_back_failed_publication() -> TestResult {
    let timeline_id = TimelineId::new();
    let admission_operation = hash(131);
    let owner_verifier = verifier(timeline_id, admission_operation);
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let admission = request(&admitted, &sources, timeline_id, admission_operation)?;
    let directory = tempfile::tempdir()?;
    let database = directory
        .path()
        .join("runtime-local-cut-owner-rollback.sqlite");
    let database = database.to_str().ok_or("non-UTF8 test path")?;
    let mut store = pos_store::sqlite::SqliteStore::open(database)?;
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, admission, &mut store)?;

    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let admission_state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing current admitted owner state")?;
    let snapshot = store
        .read_manifest_owner_admission_v1(
            owner_id,
            admission_state.configuration_generation,
            timeline_id,
        )?
        .ok_or("missing current admitted owner snapshot")?;
    let local_cut = local_cut_request(owner_id, &admission_state, &snapshot)?;
    let connection = rusqlite::Connection::open(database)?;
    connection.execute_batch(
        "CREATE TRIGGER fail_local_cut_owner_cut
         BEFORE INSERT ON local_cut_owner_cuts
         BEGIN SELECT RAISE(ABORT, 'injected local-cut owner failure'); END;",
    )?;

    assert_eq!(
        registry.commit_admitted_local_cut_owner_v1(&admitted, local_cut.clone(), &mut store),
        Err(LocalCutOwnerErrorV1::StorageFailure)
    );
    assert_eq!(store.read_local_cut_owner_state_v1(owner_id)?, None);
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id)?,
        Some(admission_state)
    );
    let partial_cuts: i64 =
        connection.query_row("SELECT COUNT(*) FROM local_cut_owner_cuts", [], |row| {
            row.get(0)
        })?;
    assert_eq!(partial_cuts, 0);

    connection.execute_batch("DROP TRIGGER fail_local_cut_owner_cut")?;
    drop(connection);
    let applied = registry.commit_admitted_local_cut_owner_v1(&admitted, local_cut, &mut store)?;
    assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
    assert_eq!(
        store
            .read_local_cut_owner_commit_v1(owner_id, 1)?
            .ok_or("durable local-cut owner record is missing after retry")?,
        applied
    );
    Ok(())
}

struct LocalCutPreparationContext<'a> {
    state: &'a pos_core::ManifestOwnerAdmissionOwnerStateV1,
    snapshot: &'a pos_core::ManifestOwnerAdmissionSnapshotV1,
    verifier: &'a FixtureOwner,
}

fn assert_structural_local_cut_rejections(
    local_cut: &pos_core::LocalCutOwnerRequestV1,
    context: &LocalCutPreparationContext<'_>,
) {
    let mut missing_composition = local_cut.clone();
    missing_composition.composition_rows.pop();
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            missing_composition,
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::InvalidBatch)
    );

    let mut wrong_static_pin = local_cut.clone();
    wrong_static_pin.composition_rows[0].implementation_hash = hash(114);
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            wrong_static_pin,
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::InvalidBatch)
    );

    let mut wrong_recording_context = local_cut.clone();
    wrong_recording_context.recording_context_rows[0].wcs_hash = hash(115);
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            wrong_recording_context,
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::InvalidBatch)
    );

    let mut stale_lease_context = local_cut.clone();
    stale_lease_context.recording_context_rows[0].retention_lease_hash = hash(117);
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            stale_lease_context,
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::OwnerRejected)
    );
}

fn assert_owner_and_inventory_rejections(
    local_cut: &pos_core::LocalCutOwnerRequestV1,
    context: &LocalCutPreparationContext<'_>,
) -> TestResult {
    context
        .verifier
        .signer_substituted
        .store(true, Ordering::Relaxed);
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            local_cut.clone(),
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::OwnerRejected)
    );
    context
        .verifier
        .signer_substituted
        .store(false, Ordering::Relaxed);

    let mut stale_inventory = local_cut.clone();
    let mut stale_seal = *stale_inventory.seal.as_input();
    stale_seal.expected_inventory_generation = hash(116);
    stale_inventory.seal = pos_core::LocalCutSealV2::new(stale_seal)?;
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            stale_inventory,
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::Conflict)
    );

    context.verifier.rejected.store(true, Ordering::Relaxed);
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            local_cut.clone(),
            None,
            context.state,
            std::slice::from_ref(context.snapshot),
            context.verifier,
        ),
        Err(pos_core::LocalCutOwnerErrorV1::OwnerRejected)
    );
    Ok(())
}

#[test]
fn complete_admitted_owner_selection_is_required_before_lcq1_signing() -> TestResult {
    let timeline_id = TimelineId::new();
    let admission_operation = hash(113);
    let admission_verifier = verifier(timeline_id, admission_operation);
    let cut_verifier = admission_verifier.clone();
    let signed_count = Arc::clone(&cut_verifier.signed);
    let (registry, _plugins, owner, admitted) = setup(admission_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let admission = request(&admitted, &sources, timeline_id, admission_operation)?;
    let mut store = MemoryStore::new();
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, admission, &mut store)?;
    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing current admitted owner state")?;
    let snapshot = admitted_snapshot(
        &store,
        owner_id,
        state.configuration_generation,
        timeline_id,
        "missing current admitted owner snapshot",
    )?;
    let local_cut = local_cut_request(owner_id, &state, &snapshot)?;
    let signatures_before_cut = signed_count.load(Ordering::Relaxed);
    let context = LocalCutPreparationContext {
        state: &state,
        snapshot: &snapshot,
        verifier: &cut_verifier,
    };

    let prepared = pos_core::prepare_local_cut_owner_commit_v1(
        local_cut.clone(),
        None,
        context.state,
        std::slice::from_ref(context.snapshot),
        context.verifier,
    )?;
    assert_eq!(
        prepared.commit().as_input().seal_hash,
        local_cut.seal.digest()
    );
    assert_eq!(
        prepared.receipt().as_input().commit_record_hash,
        prepared.commit().digest()
    );
    assert_eq!(
        prepared.successor_state().previous_visible_lcq1_hash,
        Some(prepared.receipt().digest())
    );
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_cut + 1
    );

    assert_structural_local_cut_rejections(&local_cut, &context);
    assert_owner_and_inventory_rejections(&local_cut, &context)?;
    assert_eq!(
        signed_count.load(Ordering::Relaxed),
        signatures_before_cut + 2
    );
    Ok(())
}

#[test]
fn stale_local_cut_admission_is_rejected_before_signing() -> TestResult {
    let timeline_id = TimelineId::new();
    let first_admission_operation = hash(132);
    let replacement_admission_operation = hash(133);
    let owner_verifier = verifier_for_timelines(
        &[timeline_id],
        vec![first_admission_operation, replacement_admission_operation],
    );
    let signed_count = Arc::clone(&owner_verifier.signed);
    let (registry, _plugins, owner, admitted) = setup(owner_verifier)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let first_admission = request(&admitted, &sources, timeline_id, first_admission_operation)?;
    let mut store = MemoryStore::new();
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, first_admission, &mut store)?;

    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let first_state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing first owner admission state")?;
    let first_snapshot = store
        .read_manifest_owner_admission_v1(
            owner_id,
            first_state.configuration_generation,
            timeline_id,
        )?
        .ok_or("missing first owner admission snapshot")?;
    let stale_request = local_cut_request(owner_id, &first_state, &first_snapshot)?;

    let replacement_admitted = revalidated_admitted_composition(&registry, &admitted, 2)?;
    let replacement_sources = registry.admitted_manifest_policy_sources(&replacement_admitted)?;
    let replacement = request_for_timelines(
        &replacement_admitted,
        &replacement_sources,
        &[timeline_id],
        &AdmissionTransition {
            operation_id: replacement_admission_operation,
            expected_configuration_generation: Some(first_state.configuration_generation),
            previous_visible_lcq1_hash: first_state.previous_visible_lcq1_hash,
            expected_inventory_generation: Some(first_state.inventory_generation),
            resulting_inventory_generation: hash(134),
        },
    )?;
    registry.commit_admitted_manifest_owner_admission_v1(
        &replacement_admitted,
        replacement,
        &mut store,
    )?;

    let signatures_before = signed_count.load(Ordering::Relaxed);
    assert_eq!(
        registry.commit_admitted_local_cut_owner_v1(&admitted, stale_request, &mut store),
        Err(LocalCutOwnerErrorV1::OwnerRejected)
    );
    assert_eq!(signed_count.load(Ordering::Relaxed), signatures_before);
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
    assert_ne!(
        manifest_owner_admission_intent_digest_v1(&base)?,
        Hash::zero()
    );

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

type AdmissionResult<T> = Result<T, ManifestOwnerAdmissionErrorV1>;
type CutResult<T> = Result<T, LocalCutOwnerErrorV1>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CutVerifierFault {
    SignRejected,
    ReceiptRejected,
}

struct FaultingCutVerifier {
    inner: FixtureOwner,
    fault: CutVerifierFault,
}

impl pos_core::LocalCutOwnerVerifierV1 for FaultingCutVerifier {
    fn verify_authenticated_cut(
        &self,
        request: &pos_core::LocalCutOwnerRequestV1,
        current_state: Option<&pos_core::LocalCutOwnerStateV1>,
        admission_state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
        admissions: &[pos_core::ManifestOwnerAdmissionSnapshotV1],
    ) -> CutResult<()> {
        pos_core::LocalCutOwnerVerifierV1::verify_authenticated_cut(
            &self.inner,
            request,
            current_state,
            admission_state,
            admissions,
        )
    }

    fn sign_local_cut_receipt(
        &self,
        commit: &pos_core::LocalCutCommitV1,
    ) -> CutResult<pos_core::LocalCutReceiptV1> {
        if self.fault == CutVerifierFault::SignRejected {
            return Err(LocalCutOwnerErrorV1::OwnerRejected);
        }
        pos_core::LocalCutOwnerVerifierV1::sign_local_cut_receipt(&self.inner, commit)
    }

    fn verify_local_cut_receipt(
        &self,
        receipt: &pos_core::LocalCutReceiptV1,
        commit: &pos_core::LocalCutCommitV1,
        admissions: &[pos_core::ManifestOwnerAdmissionSnapshotV1],
    ) -> CutResult<()> {
        if self.fault == CutVerifierFault::ReceiptRejected {
            return Err(LocalCutOwnerErrorV1::OwnerRejected);
        }
        pos_core::LocalCutOwnerVerifierV1::verify_local_cut_receipt(
            &self.inner,
            receipt,
            commit,
            admissions,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StoreFault {
    OwnerState(ManifestOwnerAdmissionErrorV1),
    MissingOwnerState,
    Snapshot(ManifestOwnerAdmissionErrorV1),
    MissingSnapshot,
    ForeignSnapshotCatalog,
    LocalCutState,
}

struct FaultStore {
    inner: MemoryStore,
    fault: Option<StoreFault>,
}

impl FaultStore {
    fn inner_snapshot(
        &self,
        owner: [u8; 32],
        generation: u64,
        timeline: TimelineId,
    ) -> AdmissionResult<Option<pos_core::ManifestOwnerAdmissionSnapshotV1>> {
        self.inner
            .read_manifest_owner_admission_v1(owner, generation, timeline)
    }
}

fn with_foreign_catalog(
    mut snapshot: pos_core::ManifestOwnerAdmissionSnapshotV1,
) -> AdmissionResult<pos_core::ManifestOwnerAdmissionSnapshotV1> {
    let catalog = snapshot.catalog.as_input();
    let next_generation = catalog
        .configuration_generation
        .checked_add(1)
        .ok_or(ManifestOwnerAdmissionErrorV1::CorruptState)?;
    let foreign = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: catalog.owner_id,
        configuration_generation: next_generation,
        rows: catalog.rows.clone(),
    })
    .map_err(|_| ManifestOwnerAdmissionErrorV1::CorruptState)?;
    snapshot.catalog = foreign;
    Ok(snapshot)
}

impl ManifestOwnerAdmissionPersistencePortV1 for FaultStore {
    fn read_manifest_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> AdmissionResult<Option<pos_core::ManifestOwnerAdmissionOwnerStateV1>> {
        match self.fault {
            Some(StoreFault::OwnerState(error)) => Err(error),
            Some(StoreFault::MissingOwnerState) => Ok(None),
            _ => self.inner.read_manifest_owner_state_v1(owner_id),
        }
    }

    fn resolve_manifest_owner_admission_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> AdmissionResult<Option<pos_core::ManifestOwnerAdmissionCommitV1>> {
        self.inner
            .resolve_manifest_owner_admission_retry_v1(owner_id, operation_id, intent_digest)
    }

    fn commit_manifest_owner_admission_v1(
        &mut self,
        batch: pos_core::PreparedManifestOwnerAdmissionV1,
    ) -> AdmissionResult<pos_core::ManifestOwnerAdmissionCommitV1> {
        self.inner.commit_manifest_owner_admission_v1(batch)
    }

    fn read_manifest_owner_admission_v1(
        &self,
        owner: [u8; 32],
        generation: u64,
        timeline: TimelineId,
    ) -> AdmissionResult<Option<pos_core::ManifestOwnerAdmissionSnapshotV1>> {
        match self.fault {
            Some(StoreFault::Snapshot(error)) => Err(error),
            Some(StoreFault::MissingSnapshot) => Ok(None),
            Some(StoreFault::ForeignSnapshotCatalog) => {
                let snapshot = self.inner_snapshot(owner, generation, timeline)?;
                snapshot.map(with_foreign_catalog).transpose()
            }
            _ => self.inner_snapshot(owner, generation, timeline),
        }
    }
}

impl LocalCutOwnerPersistencePortV1 for FaultStore {
    fn read_local_cut_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> CutResult<Option<pos_core::LocalCutOwnerStateV1>> {
        if self.fault == Some(StoreFault::LocalCutState) {
            return Err(LocalCutOwnerErrorV1::StorageFailure);
        }
        self.inner.read_local_cut_owner_state_v1(owner_id)
    }

    fn resolve_local_cut_owner_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> CutResult<Option<pos_core::LocalCutOwnerCommitV1>> {
        self.inner
            .resolve_local_cut_owner_retry_v1(owner_id, operation_id, intent_digest)
    }

    fn commit_local_cut_owner_v1(
        &mut self,
        batch: pos_core::PreparedLocalCutOwnerCommitV1,
    ) -> CutResult<pos_core::LocalCutOwnerCommitV1> {
        self.inner.commit_local_cut_owner_v1(batch)
    }

    fn read_local_cut_owner_commit_v1(
        &self,
        owner: [u8; 32],
        cut: u64,
    ) -> CutResult<Option<pos_core::LocalCutOwnerCommitV1>> {
        self.inner.read_local_cut_owner_commit_v1(owner, cut)
    }
}

struct LocalCutFixture {
    registry: PluginRegistry,
    admitted: AdmittedCompositionV1,
    store: MemoryStore,
    state: pos_core::ManifestOwnerAdmissionOwnerStateV1,
    snapshot: pos_core::ManifestOwnerAdmissionSnapshotV1,
    request: pos_core::LocalCutOwnerRequestV1,
    verifier: FixtureOwner,
}

fn local_cut_fixture(
    admission_operation: Hash,
    binding: CutVerifierBinding,
) -> Result<LocalCutFixture, Box<dyn Error>> {
    let timeline_id = TimelineId::new();
    let owner_verifier = verifier(timeline_id, admission_operation);
    let (registry, _plugins, owner, admitted) =
        register_fixture_plugins(fixture_registry(owner_verifier.clone(), binding))?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let admission = request(&admitted, &sources, timeline_id, admission_operation)?;
    let mut store = MemoryStore::new();
    registry.commit_admitted_manifest_owner_admission_v1(&admitted, admission, &mut store)?;
    let owner_id = *pos_core::ArtifactRegistrationV1::owner_reference(&owner).as_bytes();
    let state = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing fixture admitted owner state")?;
    let snapshot = admitted_snapshot(
        &store,
        owner_id,
        state.configuration_generation,
        timeline_id,
        "missing fixture admitted owner snapshot",
    )?;
    let request = local_cut_request(owner_id, &state, &snapshot)?;
    Ok(LocalCutFixture {
        registry,
        admitted,
        store,
        state,
        snapshot,
        request,
        verifier: owner_verifier,
    })
}

fn visible_owner_state(
    admission_state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
    last_visible_tick: u64,
) -> pos_core::LocalCutOwnerStateV1 {
    pos_core::LocalCutOwnerStateV1 {
        owner_id: admission_state.owner_id,
        last_visible_cut_id: 1,
        last_visible_tick,
        membership_epoch: 0,
        configuration_generation: admission_state.configuration_generation,
        previous_visible_lcq1_hash: Some(hash(140)),
        inventory_generation: admission_state.inventory_generation,
        timelines: admission_state.timelines.clone(),
    }
}

fn prepare_with_admissions(
    fixture: &LocalCutFixture,
    admission_state: &pos_core::ManifestOwnerAdmissionOwnerStateV1,
    admissions: &[pos_core::ManifestOwnerAdmissionSnapshotV1],
) -> CutResult<pos_core::PreparedLocalCutOwnerCommitV1> {
    pos_core::prepare_local_cut_owner_commit_v1(
        fixture.request.clone(),
        None,
        admission_state,
        admissions,
        &fixture.verifier,
    )
}

fn prepare_request(
    fixture: &LocalCutFixture,
    request: pos_core::LocalCutOwnerRequestV1,
    current_state: Option<&pos_core::LocalCutOwnerStateV1>,
) -> CutResult<pos_core::PreparedLocalCutOwnerCommitV1> {
    pos_core::prepare_local_cut_owner_commit_v1(
        request,
        current_state,
        &fixture.state,
        std::slice::from_ref(&fixture.snapshot),
        &fixture.verifier,
    )
}

fn rebind_manifest_rows(
    request: &mut pos_core::LocalCutOwnerRequestV1,
    rows: Vec<pos_core::LocalCutManifestBindingRowV1>,
) -> TestResult {
    let mut seal = *request.seal.as_input();
    let table = pos_core::LocalCutManifestBindingTableV1::new(seal.owner_id, seal.cut_id, rows)?;
    seal.manifest_binding_table = table.table_ref();
    request.seal = pos_core::LocalCutSealV2::new(seal)?;
    request.manifest_binding_table = table;
    Ok(())
}

fn commit_fixture_cut(fixture: LocalCutFixture) -> CutResult<pos_core::LocalCutOwnerCommitV1> {
    let mut store = fixture.store;
    fixture.registry.commit_admitted_local_cut_owner_v1(
        &fixture.admitted,
        fixture.request,
        &mut store,
    )
}

#[test]
fn local_cut_preparation_rejects_corrupt_admission_inputs() -> TestResult {
    let fixture = local_cut_fixture(hash(150), CutVerifierBinding::Installed)?;
    let admissions = std::slice::from_ref(&fixture.snapshot);
    let zero_owner = pos_core::ManifestOwnerAdmissionOwnerStateV1 {
        owner_id: [0; 32],
        ..fixture.state.clone()
    };
    let later_generation = pos_core::ManifestOwnerAdmissionOwnerStateV1 {
        configuration_generation: fixture
            .state
            .configuration_generation
            .checked_add(1)
            .ok_or("fixture configuration generation overflow")?,
        ..fixture.state.clone()
    };
    let foreign_roster = pos_core::ManifestOwnerAdmissionOwnerStateV1 {
        timelines: vec![TimelineId::new()],
        ..fixture.state.clone()
    };
    for admission_state in [&zero_owner, &later_generation, &foreign_roster] {
        assert_eq!(
            prepare_with_admissions(&fixture, admission_state, admissions),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );
    }
    assert_eq!(
        prepare_with_admissions(&fixture, &fixture.state, &[]),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );

    let mut unsigned_snapshot = fixture.snapshot.clone();
    unsigned_snapshot.operation_id = Hash::zero();
    let unsigned_admissions = [unsigned_snapshot];
    assert_eq!(
        prepare_with_admissions(&fixture, &fixture.state, &unsigned_admissions),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );

    let corrupt = pos_core::LocalCutOwnerStateV1 {
        owner_id: [0; 32],
        ..visible_owner_state(&fixture.state, 1)
    };
    assert_eq!(
        prepare_request(&fixture, fixture.request.clone(), Some(&corrupt)),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );
    Ok(())
}

#[test]
fn local_cut_preparation_rejects_conflicting_owner_prestate() -> TestResult {
    let fixture = local_cut_fixture(hash(151), CutVerifierBinding::Installed)?;
    let exhausted = visible_owner_state(&fixture.state, u64::MAX);
    assert_eq!(
        prepare_request(&fixture, fixture.request.clone(), Some(&exhausted)),
        Err(LocalCutOwnerErrorV1::Conflict)
    );
    let stale = visible_owner_state(&fixture.state, 1);
    assert_eq!(
        prepare_request(&fixture, fixture.request.clone(), Some(&stale)),
        Err(LocalCutOwnerErrorV1::Conflict)
    );

    let mut second_tick = fixture.request.clone();
    let mut seal = *second_tick.seal.as_input();
    seal.tick = 2;
    second_tick.seal = pos_core::LocalCutSealV2::new(seal)?;
    assert_eq!(
        prepare_request(&fixture, second_tick, None),
        Err(LocalCutOwnerErrorV1::Conflict)
    );

    let receipt_without_cut_state = pos_core::ManifestOwnerAdmissionOwnerStateV1 {
        previous_visible_lcq1_hash: Some(hash(141)),
        ..fixture.state.clone()
    };
    let receipt_bound_request = local_cut_request(
        fixture.state.owner_id,
        &receipt_without_cut_state,
        &fixture.snapshot,
    )?;
    assert_eq!(
        pos_core::prepare_local_cut_owner_commit_v1(
            receipt_bound_request,
            None,
            &receipt_without_cut_state,
            std::slice::from_ref(&fixture.snapshot),
            &fixture.verifier,
        ),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );
    Ok(())
}

#[test]
fn local_cut_preparation_rejects_unbound_manifest_rows() -> TestResult {
    let fixture = local_cut_fixture(hash(152), CutVerifierBinding::Installed)?;

    let mut extra_binding = fixture.request.clone();
    let mut rows = extra_binding.manifest_binding_table.rows().to_vec();
    rows.push(pos_core::LocalCutManifestBindingRowV1 {
        timeline_id: TimelineId::new(),
        scope: hash(153),
        wcs_hash: hash(154),
        msr_hash: hash(155),
        msb_hash: hash(156),
    });
    rows.sort_unstable_by_key(|row| row.timeline_id);
    rebind_manifest_rows(&mut extra_binding, rows)?;
    assert_eq!(
        prepare_request(&fixture, extra_binding, None),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );

    let mut substituted_receipt = fixture.request.clone();
    let mut rows = substituted_receipt.manifest_binding_table.rows().to_vec();
    rows[0].msr_hash = hash(157);
    rebind_manifest_rows(&mut substituted_receipt, rows)?;
    assert_eq!(
        prepare_request(&fixture, substituted_receipt, None),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );
    Ok(())
}

fn with_composition_rows(
    request: &pos_core::LocalCutOwnerRequestV1,
    rows: Vec<pos_core::LocalCutCompositionBindingRowV1>,
) -> Result<pos_core::LocalCutOwnerRequestV1, Box<dyn Error>> {
    let mut rebound = request.clone();
    let mut seal = *rebound.seal.as_input();
    seal.composition_table = local_cut_table(u64::try_from(rows.len())?, 92)?;
    rebound.seal = pos_core::LocalCutSealV2::new(seal)?;
    rebound.composition_rows = rows;
    Ok(rebound)
}

fn reducer_only_plugin_id(
    snapshot: &pos_core::ManifestOwnerAdmissionSnapshotV1,
) -> Result<PluginId, Box<dyn Error>> {
    let producers = snapshot.timeline.wcs1.producers();
    let reducer_only = snapshot
        .catalog
        .as_input()
        .rows
        .iter()
        .map(|row| row.plugin_id)
        .find(|plugin_id| {
            producers
                .iter()
                .all(|producer| producer.plugin_id() != *plugin_id)
        })
        .ok_or("fixture has no reducer-only Plugin")?;
    Ok(reducer_only)
}

#[test]
fn local_cut_commits_without_kind_one_row_for_reducer_only_plugin() -> TestResult {
    let fixture = local_cut_fixture(hash(164), CutVerifierBinding::Installed)?;
    let reducer_only = reducer_only_plugin_id(&fixture.snapshot)?;
    assert!(fixture
        .snapshot
        .timeline
        .binding
        .as_input()
        .rows
        .iter()
        .any(|row| row.plugin_id == reducer_only));

    let mut unknown_row = fixture.request.composition_rows[0].clone();
    unknown_row.plugin_id = unknown_plugin_id(
        &fixture
            .registry
            .admitted_manifest_policy_sources(&fixture.admitted)?,
    );
    let mut unknown_rows = fixture.request.composition_rows.clone();
    unknown_rows.push(unknown_row);
    unknown_rows.sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
    let unknown_plugin = with_composition_rows(&fixture.request, unknown_rows)?;
    let mut store = fixture.store;
    assert_eq!(
        fixture.registry.commit_admitted_local_cut_owner_v1(
            &fixture.admitted,
            unknown_plugin,
            &mut store
        ),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );

    let producer_rows = fixture
        .request
        .composition_rows
        .iter()
        .filter(|row| row.plugin_id != reducer_only)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        producer_rows.len() + 1,
        fixture.request.composition_rows.len()
    );
    let reducer_omitted = with_composition_rows(&fixture.request, producer_rows)?;
    let applied = fixture.registry.commit_admitted_local_cut_owner_v1(
        &fixture.admitted,
        reducer_omitted.clone(),
        &mut store,
    )?;
    assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
    assert_eq!(
        applied.seal.as_input().composition_table.row_count(),
        u64::try_from(reducer_omitted.composition_rows.len())?
    );
    let persisted = store
        .read_local_cut_owner_commit_v1(fixture.state.owner_id, 1)?
        .ok_or("missing reducer-only local-cut record")?;
    assert_eq!(persisted, applied);
    Ok(())
}

#[test]
fn local_cut_preparation_rejects_unknown_composition_and_partial_recording_rows() -> TestResult {
    let fixture = local_cut_fixture(hash(158), CutVerifierBinding::Installed)?;

    let mut omitted_rows = fixture.request.composition_rows.clone();
    omitted_rows.pop();
    let omitted_composition = with_composition_rows(&fixture.request, omitted_rows)?;
    assert!(prepare_request(&fixture, omitted_composition, None).is_ok());

    let mut unknown_plugin = fixture.request.clone();
    unknown_plugin.composition_rows[0].plugin_id = PluginId::new();
    unknown_plugin
        .composition_rows
        .sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
    assert_eq!(
        prepare_request(&fixture, unknown_plugin, None),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );

    let mut extra_context = fixture.request.clone();
    let extra_row = pos_core::LocalCutRecordingContextRowV1 {
        timeline_id: TimelineId::new(),
        wcs_hash: hash(159),
        retention_lease_hash: hash(104),
        predecessor_wcb_hash: None,
    };
    extra_context.recording_context_rows.push(extra_row);
    extra_context
        .recording_context_rows
        .sort_unstable_by_key(|row| row.timeline_id);
    let mut seal = *extra_context.seal.as_input();
    seal.recording_context_table = local_cut_table(2, 93)?;
    extra_context.seal = pos_core::LocalCutSealV2::new(seal)?;
    assert_eq!(
        prepare_request(&fixture, extra_context, None),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );
    Ok(())
}

#[test]
fn local_cut_preparation_rejects_failed_coordinator_signing() -> TestResult {
    let fixture = local_cut_fixture(hash(160), CutVerifierBinding::Installed)?;
    for fault in [
        CutVerifierFault::SignRejected,
        CutVerifierFault::ReceiptRejected,
    ] {
        let faulting = FaultingCutVerifier {
            inner: fixture.verifier.clone(),
            fault,
        };
        assert_eq!(
            pos_core::prepare_local_cut_owner_commit_v1(
                fixture.request.clone(),
                None,
                &fixture.state,
                std::slice::from_ref(&fixture.snapshot),
                &faulting,
            ),
            Err(LocalCutOwnerErrorV1::OwnerRejected)
        );
    }
    Ok(())
}

#[test]
fn registry_local_cut_commit_maps_store_faults_before_signing() -> TestResult {
    let fixture = local_cut_fixture(hash(161), CutVerifierBinding::Installed)?;
    let signed_count = Arc::clone(&fixture.verifier.signed);
    let rejected = Arc::clone(&fixture.verifier.rejected);
    let registry = &fixture.registry;
    let admitted = &fixture.admitted;
    let local_cut = &fixture.request;
    let mut store = FaultStore {
        inner: fixture.store,
        fault: None,
    };
    let signatures_before = signed_count.load(Ordering::Relaxed);
    let faults = [
        (
            StoreFault::OwnerState(ManifestOwnerAdmissionErrorV1::Conflict),
            LocalCutOwnerErrorV1::Conflict,
        ),
        (
            StoreFault::OwnerState(ManifestOwnerAdmissionErrorV1::StorageFailure),
            LocalCutOwnerErrorV1::StorageFailure,
        ),
        (
            StoreFault::OwnerState(ManifestOwnerAdmissionErrorV1::InvalidBatch),
            LocalCutOwnerErrorV1::CorruptState,
        ),
        (
            StoreFault::MissingOwnerState,
            LocalCutOwnerErrorV1::OwnerRejected,
        ),
        (
            StoreFault::Snapshot(ManifestOwnerAdmissionErrorV1::StorageFailure),
            LocalCutOwnerErrorV1::StorageFailure,
        ),
        (
            StoreFault::MissingSnapshot,
            LocalCutOwnerErrorV1::OwnerRejected,
        ),
        (
            StoreFault::ForeignSnapshotCatalog,
            LocalCutOwnerErrorV1::OwnerRejected,
        ),
        (
            StoreFault::LocalCutState,
            LocalCutOwnerErrorV1::StorageFailure,
        ),
    ];
    for (fault, expected) in faults {
        store.fault = Some(fault);
        assert_eq!(
            registry.commit_admitted_local_cut_owner_v1(admitted, local_cut.clone(), &mut store),
            Err(expected)
        );
    }
    store.fault = None;

    let mut partial = local_cut.clone();
    partial.composition_rows.clear();
    assert_eq!(
        recover_local_cut_owner_retry_v1(&partial, &store),
        Err(LocalCutOwnerErrorV1::BoundExceeded)
    );
    assert_eq!(
        registry.commit_admitted_local_cut_owner_v1(admitted, partial, &mut store),
        Err(LocalCutOwnerErrorV1::BoundExceeded)
    );

    rejected.store(true, Ordering::Relaxed);
    assert_eq!(
        registry.commit_admitted_local_cut_owner_v1(admitted, local_cut.clone(), &mut store),
        Err(LocalCutOwnerErrorV1::OwnerRejected)
    );
    rejected.store(false, Ordering::Relaxed);
    assert_eq!(signed_count.load(Ordering::Relaxed), signatures_before);

    let applied =
        registry.commit_admitted_local_cut_owner_v1(admitted, local_cut.clone(), &mut store)?;
    assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
    Ok(())
}

#[test]
fn registry_requires_and_keeps_its_first_local_cut_owner_verifier() -> TestResult {
    let absent = local_cut_fixture(hash(162), CutVerifierBinding::Absent)?;
    let absent_signed = Arc::clone(&absent.verifier.signed);
    let signatures_before = absent_signed.load(Ordering::Relaxed);
    assert_eq!(
        commit_fixture_cut(absent),
        Err(LocalCutOwnerErrorV1::OwnerRejected)
    );
    assert_eq!(absent_signed.load(Ordering::Relaxed), signatures_before);

    let substituted = local_cut_fixture(hash(163), CutVerifierBinding::InstalledThenSubstituted)?;
    let applied = commit_fixture_cut(substituted)?;
    assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
    Ok(())
}
