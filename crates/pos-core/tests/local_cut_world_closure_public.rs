//! Public seam tests for ADR-081 Revision 2 zero-Event WCB1 local-cut recording.

use pos_core::output_policy::{OutputPolicyInputV1, OutputPolicyV1};
use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::{
    build_manifest_owner_scope_v1, derive_local_cut_world_closure_v1,
    prepare_local_cut_owner_commit_v1, prepare_manifest_owner_admission_v1,
    validate_local_cut_owner_predecessors_v1, validate_local_cut_owner_recordings_v1,
    validate_local_cut_owner_result_v1, ArtifactDataClassV1, ArtifactTransitionRuleV1,
    ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1, Hash,
    LocalCutCommitV1, LocalCutCompositionBindingRowV1, LocalCutExpectedHeadRowV1,
    LocalCutHeadsTableV1, LocalCutManifestBindingRowV1, LocalCutManifestBindingTableV1,
    LocalCutOwnerCommitV1, LocalCutOwnerErrorV1, LocalCutOwnerRequestV1, LocalCutOwnerStateV1,
    LocalCutOwnerVerifierV1, LocalCutReceiptInputV1, LocalCutReceiptV1,
    LocalCutRecordingContextRowV1, LocalCutResultHeadRowV1, LocalCutSealInputV2, LocalCutSealV2,
    LocalCutTableRefV1, LocalCutWorldClosureSourceV1, ManifestAdmissionCatalogInputV1,
    ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionRequestV1,
    ManifestOwnerAdmissionSnapshotV1, ManifestOwnerAdmissionVerifierV1,
    ManifestOwnerClassifiedLeafV1, ManifestOwnerConsumerReferenceV1,
    ManifestOwnerLeafClassificationV1, ManifestOwnerPolicyCopiesV1, ManifestOwnerPolicySourceV1,
    ManifestOwnerScopeMembersV1, ManifestOwnerScopeSourceV1,
    ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
    ManifestSlotAdmissionReceiptV1, PluginCpuReservationV1, PluginId,
    PreparedLocalCutOwnerCommitV1, TimelineId, WorkloadProfileV1, WorldArtifactKindV1,
    WorldArtifactLeafV1, WorldClosureBindingV1, WorldClosureCutCoordinateV1,
    WorldClosureReadLimitsV1, WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1,
    WorldDependencyDirectoryV1, WorldProducerV1, WorldRecordingReceiptInputV1,
    WorldRecordingReceiptV1,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;
type PolicySource = (OutputPolicyV1, Vec<u8>);
type Contexts = [LocalCutRecordingContextRowV1];
type ExpectedRows = [LocalCutExpectedHeadRowV1];
type ResultRows = [LocalCutResultHeadRowV1];
type InputEdit = fn(&mut Contexts, &mut ExpectedRows);
type ResultEdit = fn(&mut ResultRows);

const OWNER: [u8; 32] = [0x41; 32];
const DAY_MICROS: u64 = 86_400_000_000;
const EVIDENCE: Hash = hash(90);
const SIGNATURE: [u8; 64] = [0x5a; 64];
const GENESIS: Hash = hash(0x47);
const OPERATION: Hash = hash(0x61);
const RESULT_INVENTORY: Hash = hash(0x71);
const READ_LIMITS: WorldClosureReadLimitsV1 = WorldClosureReadLimitsV1 {
    max_node_visits: 4096,
    max_native_bytes: 1_048_576,
    max_combined_depth: 32,
};

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

/// Accepts every admission check so these tests isolate the local-cut owner.
struct AcceptingOwner;

impl ManifestOwnerAdmissionVerifierV1 for AcceptingOwner {
    fn verify_complete_composition(
        &self,
        _catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn verify_complete_owned_scope_set(
        &self,
        _owner_id: [u8; 32],
        _timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn verify_coordinator_receipt(
        &self,
        _receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn verify_owner_prestate_and_allocation(
        &self,
        _request: &ManifestOwnerAdmissionRequestV1,
        _current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        draft
            .with_evidence_and_signature(EVIDENCE, SIGNATURE)
            .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
    }

    fn verify_native_policy_copies(
        &self,
        _timeline_id: TimelineId,
        _scope: Hash,
        _copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn classify_scope_member_leaves(
        &self,
        _timeline_id: TimelineId,
        _scope: Hash,
        members: &ManifestOwnerScopeMembersV1,
    ) -> Result<Vec<ManifestOwnerClassifiedLeafV1>, ManifestOwnerAdmissionErrorV1> {
        Ok(members
            .leaves
            .iter()
            .map(|member| ManifestOwnerClassifiedLeafV1::of_leaf(&member.leaf))
            .collect())
    }
}

/// Installed local-cut owner whose source owner attests `genesis`.
struct CutOwner {
    genesis: Result<Hash, LocalCutOwnerErrorV1>,
}

impl LocalCutOwnerVerifierV1 for CutOwner {
    fn verify_authenticated_cut(
        &self,
        _request: &LocalCutOwnerRequestV1,
        _current_state: Option<&LocalCutOwnerStateV1>,
        _admission_state: &ManifestOwnerAdmissionOwnerStateV1,
        _admissions: &[ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), LocalCutOwnerErrorV1> {
        Ok(())
    }

    fn source_genesis_hash(&self, _timeline_id: TimelineId) -> Result<Hash, LocalCutOwnerErrorV1> {
        self.genesis
    }

    fn sign_local_cut_receipt(
        &self,
        commit: &LocalCutCommitV1,
    ) -> Result<LocalCutReceiptV1, LocalCutOwnerErrorV1> {
        LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
            commit_record_hash: commit.digest(),
            coordinator_key_evidence_hash: EVIDENCE,
            signature: SIGNATURE,
        })
        .map_err(|_| LocalCutOwnerErrorV1::OwnerRejected)
    }

    fn verify_local_cut_receipt(
        &self,
        _receipt: &LocalCutReceiptV1,
        _commit: &LocalCutCommitV1,
        _admissions: &[ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), LocalCutOwnerErrorV1> {
        Ok(())
    }
}

const ATTESTED: CutOwner = CutOwner {
    genesis: Ok(GENESIS),
};

fn retention_policy() -> Fallible<WorldRetentionPolicyV1> {
    let policy = WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world-replay-v1".to_owned(),
        audience_policy_hash: hash(0xa6),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    })?;
    Ok(policy)
}

fn retention_lease(timeline_id: TimelineId) -> Fallible<WorldRetentionLeaseV1> {
    let policy = retention_policy()?;
    let input = WorldRetentionLeaseInputV1 {
        timeline_id,
        policy_hash: policy.digest(),
        started_at_micros: DAY_MICROS,
        admission_closes_at_micros: 11 * DAY_MICROS,
        retention_deadline_micros: 111 * DAY_MICROS,
    };
    let lease = WorldRetentionLeaseV1::new(&policy, input)?;
    Ok(lease)
}

fn host_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

const fn fidelity(level: u8, max_cpu_us: u32) -> FidelityBudgetV1 {
    FidelityBudgetV1 {
        level,
        max_events: 100,
        max_bytes: 100_000,
        max_cpu_us,
        shared_host_cpu_reservation_us: 100,
    }
}

fn budget(plugin_id: PluginId, profile: &[u8]) -> Fallible<ExecutableBudgetPolicyV1> {
    let input = ExecutableBudgetPolicyInputV1 {
        revision: 1,
        workload_profile: WorkloadProfileV1::Interactive,
        cut_budget_family: 0,
        max_event_bytes: 4096,
        fidelity_budgets: [
            fidelity(0, 500_000),
            fidelity(1, 250_000),
            fidelity(2, 50_000),
        ],
        plugin_cpu_reservations: vec![PluginCpuReservationV1 {
            plugin_id,
            cpu_reservations_us: [100, 100, 100],
        }],
        accounting_semantics: 0,
        execution_profile_hash: Hash::from_bytes(*blake3::hash(profile).as_bytes()),
        max_pass_wall_duration_us: 1_000,
    };
    let budget = ExecutableBudgetPolicyV1::new(input)?;
    Ok(budget)
}

/// Self-consistent EOP1/OPC1 pair; even seeds carry a non-empty EPF1.
fn policy_and_closure(plugin_id: PluginId, seed: u8) -> Fallible<PolicySource> {
    let retention = retention_policy()?;
    let implementation = format!("implementation-{seed}").into_bytes();
    let configuration = format!("CFG1-{seed}").into_bytes();
    let profile = if seed.is_multiple_of(2) {
        format!("EPF1-{seed}").into_bytes()
    } else {
        Vec::new()
    };
    let budget = budget(plugin_id, &profile)?;
    let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: host_digest(b"pigloros.implementation-artifact.v1", &implementation),
        base_configuration_digest: host_digest(b"pigloros.base-configuration.v1", &configuration),
        executable_profile_hash: budget.digest(),
        retention_policy_hash: retention.digest(),
        policy_revision: 1,
        output_declarations: Vec::new(),
    })?;
    let members = [
        policy.to_canonical_cbor(),
        budget.to_canonical_cbor(),
        implementation,
        configuration,
        profile,
        retention.to_canonical_cbor(),
    ];
    let mut closure = b"OPC1".to_vec();
    for member in members {
        closure.extend_from_slice(&u64::try_from(member.len())?.to_be_bytes());
        closure.extend_from_slice(&member);
    }
    Ok((policy, closure))
}

fn opc1_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn catalog() -> Fallible<(ManifestAdmissionCatalogV1, Vec<PolicySource>)> {
    let sources = vec![
        policy_and_closure(plugin(1), 1)?,
        policy_and_closure(plugin(2), 2)?,
    ];
    let rows = sources
        .iter()
        .enumerate()
        .map(|(index, (policy, closure))| ManifestAdmissionCatalogRowV1 {
            stable_slot: format!("slot-{index}"),
            plugin_id: policy.fields().plugin_id,
            plugin_name: "same-name".to_owned(),
            plugin_version: policy.fields().plugin_version.clone(),
            implementation_hash: policy.fields().implementation_hash,
            eop1_native_digest: policy.digest(),
            closure_hash: opc1_digest(closure),
        })
        .collect();
    let catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: OWNER,
        configuration_generation: 1,
        rows,
    })?;
    Ok((catalog, sources))
}

const fn structural_classification() -> ManifestOwnerLeafClassificationV1 {
    ManifestOwnerLeafClassificationV1 {
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        key_dependencies: Vec::new(),
    }
}

fn timeline_request(
    timeline_id: TimelineId,
    sources: &[PolicySource],
) -> Fallible<ManifestOwnerTimelineAdmissionRequestV1> {
    let source = ManifestOwnerScopeSourceV1 {
        owner_id: OWNER,
        timeline_id,
        rtp1_bytes: retention_policy()?.to_canonical_cbor(),
        rls1_bytes: retention_lease(timeline_id)?.to_canonical_cbor(),
        consumer_references: vec![ManifestOwnerConsumerReferenceV1 {
            schema: hash(131),
            reducer: hash(130),
            runtime: hash(132),
        }],
        policy_sources: sources
            .iter()
            .map(|(policy, closure)| ManifestOwnerPolicySourceV1 {
                plugin_id: policy.fields().plugin_id,
                eop1_bytes: policy.to_canonical_cbor(),
                opc1_bytes: closure.clone(),
            })
            .collect(),
    };
    let scope = build_manifest_owner_scope_v1(&source, &|_, _| Some(structural_classification()))?;
    let reference = |kind| {
        scope
            .members
            .leaves
            .iter()
            .find(|member| member.leaf.as_input().kind == kind)
            .map(|member| member.leaf.digest())
            .ok_or("missing fixture reference leaf")
    };
    let consumer = WorldConsumerV1::new(
        "local-observer".to_owned(),
        reference(WorldArtifactKindV1::ReducerImplementation)?,
        reference(WorldArtifactKindV1::Schema)?,
        reference(WorldArtifactKindV1::RuntimeIdentity)?,
    )?;
    let producer = sources.first().ok_or("missing fixture policy")?;
    let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope.scope,
        consumers: vec![consumer],
        producers: vec![WorldProducerV1::new(plugin(1), producer.0.digest())?],
        optional_view_roots: Vec::new(),
    })?;
    Ok(ManifestOwnerTimelineAdmissionRequestV1 {
        timeline_id,
        scope: scope.scope,
        wcs1,
        policy_copies: scope.policy_copies,
        members: scope.members,
    })
}

/// One admitted generation, as a store would return it to the local-cut owner.
struct Admitted {
    state: ManifestOwnerAdmissionOwnerStateV1,
    snapshots: Vec<ManifestOwnerAdmissionSnapshotV1>,
}

fn admit(timelines: &[TimelineId], read_limits: WorldClosureReadLimitsV1) -> Fallible<Admitted> {
    let (catalog, sources) = catalog()?;
    let timeline_requests = timelines
        .iter()
        .map(|timeline_id| timeline_request(*timeline_id, &sources))
        .collect::<Fallible<Vec<_>>>()?;
    let request = ManifestOwnerAdmissionRequestV1 {
        operation_id: hash(0x51),
        catalog,
        expected_configuration_generation: None,
        previous_visible_lcq1_hash: None,
        expected_inventory_generation: None,
        resulting_inventory_generation: hash(0x52),
        read_limits,
        timelines: timeline_requests,
    };
    let prepared = prepare_manifest_owner_admission_v1(request, &AcceptingOwner, None)?;
    let input = prepared.input();
    let snapshots = input
        .timelines
        .iter()
        .map(|timeline| ManifestOwnerAdmissionSnapshotV1 {
            catalog: input.catalog.clone(),
            timeline: timeline.clone(),
            operation_id: input.operation_id,
            expected_inventory_generation: input.expected_inventory_generation,
            resulting_inventory_generation: input.resulting_inventory_generation,
            read_limits: input.read_limits,
        })
        .collect();
    let state = ManifestOwnerAdmissionOwnerStateV1 {
        owner_id: OWNER,
        configuration_generation: 1,
        previous_visible_lcq1_hash: None,
        inventory_generation: input.resulting_inventory_generation,
        timelines: input
            .timelines
            .iter()
            .map(|timeline| timeline.timeline_id)
            .collect(),
    };
    Ok(Admitted { state, snapshots })
}

fn two_timelines() -> Fallible<Admitted> {
    admit(&[timeline(1), timeline(2)], READ_LIMITS)
}

fn recorded_lease(snapshot: &ManifestOwnerAdmissionSnapshotV1) -> Fallible<Hash> {
    let lease = snapshot
        .timeline
        .members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == WorldArtifactKindV1::RetentionLease)
        .ok_or("missing recorded lease leaf")?;
    Ok(lease.leaf.as_input().native_digest)
}

fn table(row_count: usize, byte: u8) -> Fallible<LocalCutTableRefV1> {
    let rows = u64::try_from(row_count)?;
    let table = LocalCutTableRefV1::new(rows, (rows != 0).then_some(hash(byte)))?;
    Ok(table)
}

const fn zero_event_expected(timeline_id: TimelineId) -> LocalCutExpectedHeadRowV1 {
    LocalCutExpectedHeadRowV1 {
        timeline_id,
        logical_head: 0,
        stitched_chain_hash: GENESIS,
        source_timeline_id: timeline_id,
        source_segment_head: 0,
        source_chain_hash: GENESIS,
        logical_prefix: 0,
        lineage_proof_hash: None,
        predecessor_wcb_hash: None,
    }
}

const KEEP_INPUTS: InputEdit = |_, _| {};
const KEEP_RESULTS: ResultEdit = |_| {};

fn seal_for(
    admitted: &Admitted,
    composition_rows: usize,
    expected_rows: &[LocalCutExpectedHeadRowV1],
    binding_table: &LocalCutManifestBindingTableV1,
) -> Fallible<LocalCutSealV2> {
    let expected_table = LocalCutHeadsTableV1::expected_heads(OWNER, 1, expected_rows)?;
    let seal = LocalCutSealV2::new(LocalCutSealInputV2 {
        owner_id: OWNER,
        cut_id: 1,
        tick: 1,
        membership_epoch: 0,
        configuration_generation: admitted.state.configuration_generation,
        schedule_ns: 0,
        previous_visible_receipt_hash: None,
        expected_inventory_generation: admitted.state.inventory_generation,
        membership_table: table(admitted.snapshots.len(), 94)?,
        composition_table: table(composition_rows, 92)?,
        inbox_table: table(0, 95)?,
        invocation_table: table(0, 96)?,
        expected_heads_table: expected_table.table_ref(),
        ebp_native_hash: hash(98),
        execution_profile_native_hash: hash(99),
        recording_context_table: table(admitted.snapshots.len(), 93)?,
        owner_operational_policy_hash: hash(100),
        explicit_attempt_hash: None,
        ingress_preallocation_native_hash: hash(101),
        manifest_binding_table: binding_table.table_ref(),
    })?;
    Ok(seal)
}

/// Build a complete zero-Event cut request whose kind-5 rows name the WCB1
/// that the owner derives, after `edit_inputs` and before `edit_results`.
fn cut_request(
    admitted: &Admitted,
    edit_inputs: InputEdit,
    edit_results: ResultEdit,
) -> Fallible<LocalCutOwnerRequestV1> {
    let mut binding_rows = Vec::new();
    let mut composition_rows = Vec::new();
    let mut contexts = Vec::new();
    let mut expected_rows = Vec::new();
    for snapshot in &admitted.snapshots {
        let timeline = &snapshot.timeline;
        binding_rows.push(LocalCutManifestBindingRowV1 {
            timeline_id: timeline.timeline_id,
            scope: timeline.scope,
            wcs_hash: timeline.wcs1.digest(),
            msr_hash: timeline.receipt.digest(),
            msb_hash: timeline.binding.digest(),
        });
        for row in &snapshot.catalog.as_input().rows {
            composition_rows.push(LocalCutCompositionBindingRowV1 {
                plugin_id: row.plugin_id,
                timeline_id: timeline.timeline_id,
                plugin_version: row.plugin_version.clone(),
                implementation_hash: row.implementation_hash,
                eop1_native_digest: row.eop1_native_digest,
                driver_interval_ns: Some(0),
                last_due_ns: None,
                event_cursor: 0,
                participant_native_state_hash: hash(91),
            });
        }
        contexts.push(LocalCutRecordingContextRowV1 {
            timeline_id: timeline.timeline_id,
            wcs_hash: timeline.wcs1.digest(),
            retention_lease_hash: recorded_lease(snapshot)?,
            predecessor_wcb_hash: None,
        });
        expected_rows.push(zero_event_expected(timeline.timeline_id));
    }
    composition_rows.sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
    edit_inputs(&mut contexts, &mut expected_rows);
    let binding_table = LocalCutManifestBindingTableV1::new(OWNER, 1, binding_rows)?;
    let seal = seal_for(
        admitted,
        composition_rows.len(),
        &expected_rows,
        &binding_table,
    )?;
    let mut result_rows = admitted
        .snapshots
        .iter()
        .zip(&contexts)
        .map(|(snapshot, context)| {
            let source = LocalCutWorldClosureSourceV1 {
                operation_id: OPERATION,
                seal: &seal,
                admission: snapshot,
                retention_lease_hash: context.retention_lease_hash,
                predecessor_binding_hash: context.predecessor_wcb_hash,
                genesis_hash: GENESIS,
            };
            let successor_wcb_hash = derive_local_cut_world_closure_v1(&source)
                .map_or(hash(0x99), |closure| closure.binding().digest());
            LocalCutResultHeadRowV1 {
                timeline_id: context.timeline_id,
                result_logical_head: 0,
                result_stitched_hash: GENESIS,
                result_source_segment_head: 0,
                result_source_chain_hash: GENESIS,
                successor_wcb_hash,
                event_count: 0,
            }
        })
        .collect::<Vec<_>>();
    edit_results(&mut result_rows);
    let result_table = LocalCutHeadsTableV1::result_heads(OWNER, 1, &result_rows)?;
    Ok(LocalCutOwnerRequestV1 {
        operation_id: OPERATION,
        seal,
        manifest_hash: hash(103),
        manifest_binding_table: binding_table,
        composition_rows,
        recording_context_rows: contexts,
        expected_head_rows: expected_rows,
        result_head_rows: result_rows,
        partition_ledger_seq: 1,
        result_heads_table: result_table.table_ref(),
        participant_successor_table: table(1, 106)?,
        cpu_completion_table: table(0, 107)?,
        action_disposition_table: table(1, 108)?,
        candidate_bases_table: table(0, 109)?,
        invocation_bridges_table: table(0, 110)?,
        result_inventory_generation: RESULT_INVENTORY,
        release_fence_proof_digest: hash(112),
    })
}

fn prepare(
    admitted: &Admitted,
    request: LocalCutOwnerRequestV1,
    owner: &CutOwner,
) -> Result<PreparedLocalCutOwnerCommitV1, LocalCutOwnerErrorV1> {
    prepare_local_cut_owner_commit_v1(request, None, &admitted.state, &admitted.snapshots, owner)
}

fn prepare_edited(
    admitted: &Admitted,
    edit_inputs: InputEdit,
    edit_results: ResultEdit,
) -> Fallible<Result<PreparedLocalCutOwnerCommitV1, LocalCutOwnerErrorV1>> {
    let request = cut_request(admitted, edit_inputs, edit_results)?;
    Ok(prepare(admitted, request, &ATTESTED))
}

fn applied() -> Fallible<(LocalCutOwnerRequestV1, LocalCutOwnerCommitV1)> {
    let admitted = two_timelines()?;
    let request = cut_request(&admitted, KEEP_INPUTS, KEEP_RESULTS)?;
    let batch = prepare(&admitted, request.clone(), &ATTESTED)?;
    Ok((request, batch.applied_result()))
}

#[test]
fn zero_event_cut_records_one_exact_wcb1_and_wcr1_per_owned_timeline() -> TestResult {
    let admitted = two_timelines()?;
    let request = cut_request(&admitted, KEEP_INPUTS, KEEP_RESULTS)?;
    let batch = prepare(&admitted, request.clone(), &ATTESTED)?;
    let coordinate = WorldClosureCutCoordinateV1 {
        cut_id: 1,
        partition_id: 0,
        reservation_identity: *request.seal.digest().as_bytes(),
    };
    assert_eq!(batch.recordings().len(), 2);
    assert_eq!(batch.dependency_directories().len(), 2);
    for (index, snapshot) in admitted.snapshots.iter().enumerate() {
        let timeline = &snapshot.timeline;
        let recording = batch.recordings()[index];
        let directory = &batch.dependency_directories()[index];
        let mut leaves = timeline
            .members
            .leaves
            .iter()
            .map(|member| member.leaf.clone())
            .collect::<Vec<_>>();
        for copy in &timeline.policy_copies {
            leaves.push(copy.eop1_leaf.clone());
            leaves.push(copy.opc1_leaf.clone());
        }
        let packed = WorldDependencyDirectoryV1::pack(timeline.scope, leaves.clone(), READ_LIMITS)?;
        assert_eq!(directory, &packed);
        assert_eq!(directory.leaves().len(), leaves.len());
        let lease_leaf = timeline
            .members
            .leaves
            .iter()
            .find(|member| member.leaf.as_input().kind == WorldArtifactKindV1::RetentionLease)
            .ok_or("missing lease leaf")?;
        let binding = recording.binding.as_input();
        assert_eq!(recording.scope, timeline.scope);
        assert_eq!(binding.timeline_id, timeline.timeline_id);
        assert_eq!(binding.operation_id, OPERATION);
        assert_eq!(binding.cut_coordinate, coordinate);
        assert_eq!(binding.logical_head, 0);
        assert_eq!(binding.stitched_head_hash, GENESIS);
        assert_eq!(binding.retention_lease_leaf_hash, lease_leaf.leaf.digest());
        assert_eq!(binding.consumer_set_hash, timeline.wcs1.digest());
        assert_eq!(binding.dependency_root_hash, packed.root_hash());
        assert_eq!(binding.history_root_hash, None);
        assert_eq!(binding.predecessor_binding_hash, None);
        assert_eq!(binding.parent_lineage_reference, None);
        assert_eq!(binding.read_limits, READ_LIMITS);
        assert_eq!(
            recording.binding.digest(),
            request.result_head_rows[index].successor_wcb_hash
        );
        assert_eq!(
            *recording.receipt.as_input(),
            WorldRecordingReceiptInputV1 {
                binding_hash: recording.binding.digest(),
                operation_id: OPERATION,
                actual_commit_receipt_digest: batch.receipt().digest(),
                installed_inventory_generation: RESULT_INVENTORY,
            }
        );
    }
    let applied = batch.applied_result();
    assert_eq!(applied.recordings, batch.recordings());
    assert_eq!(
        validate_local_cut_owner_result_v1(OWNER, 1, &applied),
        Ok(())
    );
    assert_eq!(
        validate_local_cut_owner_recordings_v1(&request, &applied),
        Ok(())
    );
    assert_eq!(
        validate_local_cut_owner_predecessors_v1(&batch, |_| Ok(None)),
        Ok(())
    );
    Ok(())
}

#[test]
fn kind_eight_lease_must_be_the_recorded_rls1() -> TestResult {
    let admitted = two_timelines()?;
    let substituted: InputEdit = |contexts, _| contexts[1].retention_lease_hash = hash(0x33);
    assert_eq!(
        prepare_edited(&admitted, substituted, KEEP_RESULTS)?,
        Err(LocalCutOwnerErrorV1::Conflict)
    );
    Ok(())
}

#[test]
fn head_rows_outside_the_zero_event_profile_are_rejected() -> TestResult {
    let admitted = two_timelines()?;
    let inputs: [InputEdit; 7] = [
        |_, rows| rows[0].logical_head = 1,
        |_, rows| rows[0].logical_prefix = 1,
        |_, rows| rows[0].lineage_proof_hash = Some(hash(0x34)),
        |_, rows| rows[0].source_timeline_id = timeline(9),
        |_, rows| rows[0].source_segment_head = 1,
        |_, rows| rows[0].source_chain_hash = hash(0x35),
        |_, rows| rows[0].stitched_chain_hash = hash(0x36),
    ];
    for edit in inputs {
        assert_eq!(
            prepare_edited(&admitted, edit, KEEP_RESULTS)?,
            Err(LocalCutOwnerErrorV1::OwnerRejected)
        );
    }
    let results: [ResultEdit; 5] = [
        |rows| rows[0].result_logical_head = 1,
        |rows| rows[0].event_count = 1,
        |rows| rows[0].result_source_segment_head = 1,
        |rows| rows[0].result_source_chain_hash = hash(0x37),
        |rows| rows[0].result_stitched_hash = hash(0x38),
    ];
    for edit in results {
        assert_eq!(
            prepare_edited(&admitted, KEEP_INPUTS, edit)?,
            Err(LocalCutOwnerErrorV1::OwnerRejected)
        );
    }
    Ok(())
}

#[test]
fn head_rows_must_name_the_admitted_timelines_and_derived_successor() -> TestResult {
    let admitted = two_timelines()?;
    let foreign_expected: InputEdit = |_, rows| rows[1].timeline_id = timeline(9);
    let foreign_result: ResultEdit = |rows| rows[1].timeline_id = timeline(9);
    let wrong_successor: ResultEdit = |rows| rows[1].successor_wcb_hash = hash(0x39);
    let unmatched_predecessor: InputEdit = |contexts, _| {
        contexts[0].predecessor_wcb_hash = Some(hash(0x3a));
    };
    for result in [
        prepare_edited(&admitted, foreign_expected, KEEP_RESULTS)?,
        prepare_edited(&admitted, KEEP_INPUTS, foreign_result)?,
        prepare_edited(&admitted, KEEP_INPUTS, wrong_successor)?,
        prepare_edited(&admitted, unmatched_predecessor, KEEP_RESULTS)?,
    ] {
        assert_eq!(result, Err(LocalCutOwnerErrorV1::InvalidBatch));
    }
    Ok(())
}

#[test]
fn recorded_predecessor_must_be_the_latest_stored_binding() -> TestResult {
    let admitted = two_timelines()?;
    let chained: InputEdit = |contexts, rows| {
        contexts[0].predecessor_wcb_hash = Some(hash(0x3b));
        rows[0].predecessor_wcb_hash = Some(hash(0x3b));
    };
    let batch = prepare_edited(&admitted, chained, KEEP_RESULTS)??;
    let first = batch.recordings()[0].binding.as_input();
    assert_eq!(first.predecessor_binding_hash, Some(hash(0x3b)));
    let second = batch.recordings()[1].binding.as_input();
    assert_eq!(second.predecessor_binding_hash, None);
    let first_id = first.timeline_id;
    let latest = |timeline_id: TimelineId| Ok((timeline_id == first_id).then_some(hash(0x3b)));
    assert_eq!(
        validate_local_cut_owner_predecessors_v1(&batch, latest),
        Ok(())
    );
    for stale in [None, Some(hash(0x3c))] {
        assert_eq!(
            validate_local_cut_owner_predecessors_v1(&batch, |_| Ok(stale)),
            Err(LocalCutOwnerErrorV1::Conflict)
        );
    }
    let failing = |_: TimelineId| Err(LocalCutOwnerErrorV1::StorageFailure);
    assert_eq!(
        validate_local_cut_owner_predecessors_v1(&batch, failing),
        Err(LocalCutOwnerErrorV1::StorageFailure)
    );
    Ok(())
}

#[test]
fn source_genesis_failures_and_closure_limits_stop_preparation() -> TestResult {
    let admitted = two_timelines()?;
    let request = cut_request(&admitted, KEEP_INPUTS, KEEP_RESULTS)?;
    let unattested = CutOwner {
        genesis: Err(LocalCutOwnerErrorV1::StorageFailure),
    };
    assert_eq!(
        prepare(&admitted, request, &unattested),
        Err(LocalCutOwnerErrorV1::StorageFailure)
    );

    let narrow = WorldClosureReadLimitsV1 {
        max_node_visits: 2,
        ..READ_LIMITS
    };
    let limited = admit(&[timeline(1)], narrow)?;
    assert_eq!(
        prepare_edited(&limited, KEEP_INPUTS, KEEP_RESULTS)?,
        Err(LocalCutOwnerErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn derivation_rejects_a_zero_predecessor_binding() -> TestResult {
    let admitted = admit(&[timeline(1)], READ_LIMITS)?;
    let request = cut_request(&admitted, KEEP_INPUTS, KEEP_RESULTS)?;
    let snapshot = admitted.snapshots.first().ok_or("missing snapshot")?;
    let source = LocalCutWorldClosureSourceV1 {
        operation_id: OPERATION,
        seal: &request.seal,
        admission: snapshot,
        retention_lease_hash: recorded_lease(snapshot)?,
        predecessor_binding_hash: Some(Hash::zero()),
        genesis_hash: GENESIS,
    };
    assert_eq!(
        derive_local_cut_world_closure_v1(&source),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );
    Ok(())
}

#[test]
fn derivation_rejects_a_leaf_outside_the_scope() -> TestResult {
    let admitted = admit(&[timeline(1)], READ_LIMITS)?;
    let request = cut_request(&admitted, KEEP_INPUTS, KEEP_RESULTS)?;
    let snapshot = admitted.snapshots.first().ok_or("missing snapshot")?;
    let mut rescoped = snapshot.clone();
    let copy = rescoped
        .timeline
        .policy_copies
        .first_mut()
        .ok_or("missing policy copy")?;
    let mut input = copy.eop1_leaf.as_input().clone();
    input.scope = hash(0x46);
    copy.eop1_leaf = WorldArtifactLeafV1::new(input)?;
    let source = LocalCutWorldClosureSourceV1 {
        operation_id: OPERATION,
        seal: &request.seal,
        admission: &rescoped,
        retention_lease_hash: recorded_lease(snapshot)?,
        predecessor_binding_hash: None,
        genesis_hash: GENESIS,
    };
    assert_eq!(
        derive_local_cut_world_closure_v1(&source),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );
    Ok(())
}

fn rebound(binding: &WorldClosureBindingV1, cut_id: u64) -> Fallible<WorldClosureBindingV1> {
    let mut input = *binding.as_input();
    input.cut_coordinate.cut_id = cut_id;
    let binding = WorldClosureBindingV1::new(input)?;
    Ok(binding)
}

fn receipt(input: WorldRecordingReceiptInputV1) -> Fallible<WorldRecordingReceiptV1> {
    let receipt = WorldRecordingReceiptV1::new(input)?;
    Ok(receipt)
}

#[test]
fn retained_results_reject_each_unlinked_recording_field() -> TestResult {
    let (_, applied) = applied()?;
    let original = applied.recordings[0];
    let fields = *original.receipt.as_input();

    let mut missing = applied.clone();
    missing.recordings.pop();
    let mut moved = applied.clone();
    moved.recordings[0].binding = rebound(&original.binding, 2)?;
    moved.recordings[0].receipt = receipt(WorldRecordingReceiptInputV1 {
        binding_hash: moved.recordings[0].binding.digest(),
        ..fields
    })?;
    let mut unbound = applied.clone();
    unbound.recordings[0].receipt = receipt(WorldRecordingReceiptInputV1 {
        binding_hash: hash(0x40),
        ..fields
    })?;
    let mut foreign_operation = applied.clone();
    foreign_operation.recordings[0].receipt = receipt(WorldRecordingReceiptInputV1 {
        operation_id: hash(0x42),
        ..fields
    })?;
    let mut foreign_commit = applied.clone();
    foreign_commit.recordings[0].receipt = receipt(WorldRecordingReceiptInputV1 {
        actual_commit_receipt_digest: hash(0x43),
        ..fields
    })?;
    let mut foreign_inventory = applied;
    foreign_inventory.recordings[0].receipt = receipt(WorldRecordingReceiptInputV1 {
        installed_inventory_generation: hash(0x44),
        ..fields
    })?;
    for corrupt in [
        missing,
        moved,
        unbound,
        foreign_operation,
        foreign_commit,
        foreign_inventory,
    ] {
        assert_eq!(
            validate_local_cut_owner_result_v1(OWNER, 1, &corrupt),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );
    }
    Ok(())
}

#[test]
fn retained_recordings_must_match_their_request_rows() -> TestResult {
    let (request, applied) = applied()?;
    let mut missing = applied.clone();
    missing.recordings.pop();
    let mut substituted = applied.clone();
    substituted.recordings[0].binding = rebound(&applied.recordings[0].binding, 2)?;
    let mut rescoped = applied.clone();
    rescoped.recordings[0].scope = hash(0x45);
    for corrupt in [missing, substituted, rescoped] {
        assert_eq!(
            validate_local_cut_owner_recordings_v1(&request, &corrupt),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );
    }
    let first_binding = request.manifest_binding_table.rows()[..1].to_vec();
    let mut unbound = request;
    unbound.manifest_binding_table = LocalCutManifestBindingTableV1::new(OWNER, 1, first_binding)?;
    assert_eq!(
        validate_local_cut_owner_recordings_v1(&unbound, &applied),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );
    Ok(())
}
