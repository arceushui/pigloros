//! Cut-owner evidence for ADR-081 Revision 2 zero-Event WDB1 closures.
//!
//! Each test admits Plugin rows (MCA1/MSB1) through the public admission seam,
//! records one zero-Event local cut through the public local-cut owner seam
//! and a real store, and compares what the store published with an
//! independent preferred-CBOR/BLAKE3 WDB1 oracle. The oracle reuses only the
//! production WAL1 leaf encoding (`WorldArtifactLeafV1::to_canonical_cbor`) to
//! hash each leaf; the key order, deduplication, 256-way packing, WDB1 branch
//! encoding, domains, node addresses and root are computed independently. The
//! rejection tests show that every substituted admission fact or inconsistent
//! closure row stops the cut before any owner record becomes visible.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::output_policy::{OutputPolicyInputV1, OutputPolicyV1};
use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::{
    build_manifest_owner_scope_v1, local_cut_owner_intent_digest_v1,
    prepare_local_cut_owner_commit_v1, prepare_manifest_owner_admission_v1,
    validate_manifest_owner_admission_snapshot_v1, ArtifactDataClassV1, ArtifactTransitionRuleV1,
    EventStore, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1, Hash,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, LocalCutCommitV1,
    LocalCutCompositionBindingRowV1, LocalCutExpectedHeadRowV1, LocalCutHeadsTableV1,
    LocalCutManifestBindingRowV1, LocalCutManifestBindingTableV1, LocalCutOwnerCommitV1,
    LocalCutOwnerErrorV1, LocalCutOwnerPersistencePortV1, LocalCutOwnerRequestV1,
    LocalCutOwnerStateV1, LocalCutOwnerVerifierV1, LocalCutReceiptInputV1, LocalCutReceiptV1,
    LocalCutRecordingContextRowV1, LocalCutResultHeadRowV1, LocalCutSealInputV2, LocalCutSealV2,
    LocalCutTableRefV1, LocalCutWorldRecordingV1, ManifestAdmissionCatalogInputV1,
    ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionPersistencePortV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionSnapshotV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerClassifiedLeafV1,
    ManifestOwnerConsumerReferenceV1, ManifestOwnerLeafClassificationV1,
    ManifestOwnerLinkCutIdentityV1, ManifestOwnerLinkReadPortV1, ManifestOwnerMemberLeafV1,
    ManifestOwnerPolicyCopiesV1, ManifestOwnerPolicySourceV1, ManifestOwnerScopeMembersV1,
    ManifestOwnerScopeSourceV1, ManifestOwnerScopeV1, ManifestOwnerTimelineAdmissionRequestV1,
    ManifestSlotAdmissionReceiptDraftV1, ManifestSlotAdmissionReceiptV1, PluginCpuReservationV1,
    PluginId, PreparedLocalCutOwnerCommitV1, PublicKey, TimelineId, WorkloadProfileV1,
    WorldArtifactKindV1, WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldClosureBindingInputV1,
    WorldClosureBindingV1, WorldClosureCutCoordinateV1, WorldClosureReadLimitsV1,
    WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1, WorldDependencyDirectoryV1,
    WorldKeyEvidenceInputV1, WorldKeyEvidenceV1, WorldProducerV1, MAX_MANIFEST_OWNER_PLUGINS_V1,
};
use pos_store::memory::MemoryStore;

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;
type PolicySource = (OutputPolicyV1, Vec<u8>);
type SnapshotEdit = fn(&mut ManifestOwnerAdmissionSnapshotV1) -> TestResult;
type LeafEdit = fn(&mut WorldArtifactLeafInputV1);
/// One stored WDB1 node: its content address and its exact WDB1 bytes.
#[cfg(feature = "sqlite")]
type StoredNode = (Vec<u8>, Vec<u8>);
#[cfg(feature = "sqlite")]
const NODE_COLUMNS: &str = "node_hash, node_cbor";
#[cfg(feature = "sqlite")]
const NODE_TABLE: &str = "world_dependency_branches";

const OWNER: [u8; 32] = [0x41; 32];
const TIMELINE: TimelineId = timeline(1);
const DAY_MICROS: u64 = 86_400_000_000;
const SIGNATURE: [u8; 64] = [0x5a; 64];
const GENESIS: Hash = hash(0x47);
const ADMISSION_OPERATION: Hash = hash(0x51);
const ADMITTED_INVENTORY: Hash = hash(0x52);
const CUT_OPERATION: Hash = hash(0x61);
const RESULT_INVENTORY: Hash = hash(0x71);
const READ_LIMITS: WorldClosureReadLimitsV1 = WorldClosureReadLimitsV1 {
    max_node_visits: 4096,
    max_native_bytes: 4_194_304,
    max_combined_depth: 32,
};
/// Plugins 0 and 1 share one display name and are the only WCS1 producers.
const PRODUCERS: usize = 2;
/// The two same-name producers and one zero-output, reducer-only Plugin.
const SMALL_ROSTER: u16 = 3;
/// WDB1 branch fanout, restated for the oracle rather than imported.
const FANOUT: usize = 256;
const LEAF_DOMAIN: &[u8] = b"pigloros.world-evidence.artifact-leaf.v1\0";
const BRANCH_DOMAIN: &[u8] = b"pigloros.world-evidence.dependency-branch.v1\0";
const BINDING_DOMAIN: &[u8] = b"pigloros.world-evidence.binding.v1\0";
const SEAL_DOMAIN: &[u8] = b"pigloros.local-cut.seal.v2\0";
const EOP1_KIND: WorldArtifactKindV1 = WorldArtifactKindV1::OutputPolicy;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

/// Plugin identities ascend with their index, as MCA1 slots do.
const fn plugin(index: u16) -> PluginId {
    let [high, low] = index.to_be_bytes();
    let mut bytes = [7; 16];
    bytes[14] = high;
    bytes[15] = low;
    PluginId::from_ulid(ulid::Ulid::from_bytes(bytes))
}

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

/// Accepts every owner check so these tests isolate the closure evidence.
///
/// Every receipt names the coordinator's epoch-1 WKE1; a substituting owner
/// returns the epoch-2 WKE1 bytes with it instead.
struct FixtureOwner {
    substitute: bool,
}

impl FixtureOwner {
    const INSTALLED: Self = Self { substitute: false };
    const SUBSTITUTING: Self = Self { substitute: true };

    /// The signed evidence address and the WKE1 bytes returned with it.
    fn signed_evidence(&self) -> Option<(Hash, Vec<u8>)> {
        let signed = coordinator_evidence(1).ok()?;
        let returned = if self.substitute {
            coordinator_evidence(2).ok()?
        } else {
            signed
        };
        Some((signed.digest(), returned.to_canonical_cbor()))
    }
}

/// The verify-only WKE1 of one epoch of the fixture coordinator's signing key.
fn coordinator_evidence(epoch: u64) -> Fallible<WorldKeyEvidenceV1> {
    let evidence = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::new("coordinator", KeyRoleV1::TimelineIntegritySigning, epoch),
        private_material_digest: hash(0xc0),
        private_material_required: false,
        public_verification_key: Some(PublicKey::from_bytes([0xc1; 32])),
    })?;
    Ok(evidence)
}

/// Install a registry holding the coordinator's epoch-1 signing key.
fn keyed<S: EventStore>(mut store: S) -> Fallible<S> {
    let evidence = *coordinator_evidence(1)?.as_input();
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        evidence.identity,
        evidence.private_material_digest,
        evidence.public_verification_key,
    ))?;
    store.save_key_registry(&registry)?;
    Ok(store)
}

impl ManifestOwnerAdmissionVerifierV1 for FixtureOwner {
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
    ) -> Result<(ManifestSlotAdmissionReceiptV1, Vec<u8>), ManifestOwnerAdmissionErrorV1> {
        let rejected = ManifestOwnerAdmissionErrorV1::OwnerRejected;
        let (evidence_hash, bytes) = self.signed_evidence().ok_or(rejected)?;
        draft
            .with_evidence_and_signature(evidence_hash, SIGNATURE)
            .map(|receipt| (receipt, bytes))
            .or(Err(rejected))
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

impl LocalCutOwnerVerifierV1 for FixtureOwner {
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
        Ok(GENESIS)
    }

    fn sign_local_cut_receipt(
        &self,
        commit: &LocalCutCommitV1,
    ) -> Result<(LocalCutReceiptV1, Vec<u8>), LocalCutOwnerErrorV1> {
        let rejected = LocalCutOwnerErrorV1::OwnerRejected;
        let (evidence_hash, bytes) = self.signed_evidence().ok_or(rejected)?;
        LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
            commit_record_hash: commit.digest(),
            coordinator_key_evidence_hash: evidence_hash,
            signature: SIGNATURE,
        })
        .map(|receipt| (receipt, bytes))
        .or(Err(rejected))
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

fn retention_lease() -> Fallible<WorldRetentionLeaseV1> {
    let policy = retention_policy()?;
    let input = WorldRetentionLeaseInputV1 {
        timeline_id: TIMELINE,
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

/// Self-consistent zero-output EOP1/OPC1 pair; even seeds carry a non-empty EPF1.
fn policy_and_closure(plugin_id: PluginId, seed: u16) -> Fallible<PolicySource> {
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

/// Plugins 0 and 1 share one display name; it is part of no identity.
fn plugin_name(index: u16) -> String {
    if usize::from(index) < PRODUCERS {
        "same-name".to_owned()
    } else {
        format!("plugin-{index:03}")
    }
}

fn catalog(plugins: u16) -> Fallible<(ManifestAdmissionCatalogV1, Vec<PolicySource>)> {
    let sources = (0..plugins)
        .map(|index| policy_and_closure(plugin(index), index))
        .collect::<Fallible<Vec<_>>>()?;
    let rows = sources
        .iter()
        .zip(0_u16..)
        .map(|((policy, closure), index)| ManifestAdmissionCatalogRowV1 {
            stable_slot: format!("slot-{index:03}"),
            plugin_id: policy.fields().plugin_id,
            plugin_name: plugin_name(index),
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

/// Native records behind the fixture scope: a real lease and every Plugin.
fn scope_source(sources: &[PolicySource]) -> Fallible<ManifestOwnerScopeSourceV1> {
    Ok(ManifestOwnerScopeSourceV1 {
        owner_id: OWNER,
        timeline_id: TIMELINE,
        rtp1_bytes: retention_policy()?.to_canonical_cbor(),
        rls1_bytes: retention_lease()?.to_canonical_cbor(),
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
    })
}

/// WAL1 address of the scope's reference leaf of one kind.
fn reference_leaf(scope: &ManifestOwnerScopeV1, kind: WorldArtifactKindV1) -> Fallible<Hash> {
    let member = scope
        .members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == kind)
        .ok_or("missing fixture reference leaf")?;
    Ok(member.leaf.digest())
}

/// WCS1 naming the two same-name producers; every later Plugin is reducer-only.
fn fixture_wcs1(
    scope: &ManifestOwnerScopeV1,
    sources: &[PolicySource],
) -> Fallible<WorldConsumerSetV1> {
    let consumer = WorldConsumerV1::new(
        "local-observer".to_owned(),
        reference_leaf(scope, WorldArtifactKindV1::ReducerImplementation)?,
        reference_leaf(scope, WorldArtifactKindV1::Schema)?,
        reference_leaf(scope, WorldArtifactKindV1::RuntimeIdentity)?,
    )?;
    let producers = sources
        .iter()
        .take(PRODUCERS)
        .map(|(policy, _)| WorldProducerV1::new(policy.fields().plugin_id, policy.digest()))
        .collect::<Result<Vec<_>, _>>()?;
    let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope.scope,
        consumers: vec![consumer],
        producers,
        optional_view_roots: Vec::new(),
    })?;
    Ok(wcs1)
}

fn scope_request(sources: &[PolicySource]) -> Fallible<ManifestOwnerTimelineAdmissionRequestV1> {
    let source = scope_source(sources)?;
    let scope = build_manifest_owner_scope_v1(&source, &|_, _| Some(structural_classification()))?;
    let wcs1 = fixture_wcs1(&scope, sources)?;
    Ok(ManifestOwnerTimelineAdmissionRequestV1 {
        timeline_id: TIMELINE,
        scope: scope.scope,
        wcs1,
        policy_copies: scope.policy_copies,
        members: scope.members,
    })
}

fn admission_request(plugins: u16) -> Fallible<ManifestOwnerAdmissionRequestV1> {
    let (catalog, sources) = catalog(plugins)?;
    Ok(ManifestOwnerAdmissionRequestV1 {
        operation_id: ADMISSION_OPERATION,
        catalog,
        expected_configuration_generation: None,
        previous_visible_lcq1_hash: None,
        expected_inventory_generation: None,
        resulting_inventory_generation: ADMITTED_INVENTORY,
        read_limits: READ_LIMITS,
        timelines: vec![scope_request(&sources)?],
    })
}

fn full_roster() -> Fallible<u16> {
    let plugins = u16::try_from(MAX_MANIFEST_OWNER_PLUGINS_V1)?;
    Ok(plugins)
}

/// Both stores implement the admission and local-cut owner persistence ports.
trait CutStore: ManifestOwnerAdmissionPersistencePortV1 + LocalCutOwnerPersistencePortV1 {}

impl<S: ManifestOwnerAdmissionPersistencePortV1 + LocalCutOwnerPersistencePortV1> CutStore for S {}

/// One committed admission, read back as the store returns it to the cut owner.
struct Admitted {
    state: ManifestOwnerAdmissionOwnerStateV1,
    snapshot: ManifestOwnerAdmissionSnapshotV1,
}

fn admit<S: CutStore>(store: &mut S, plugins: u16) -> Fallible<Admitted> {
    let request = admission_request(plugins)?;
    let batch = prepare_manifest_owner_admission_v1(request, &FixtureOwner::INSTALLED, None)?;
    store.commit_manifest_owner_admission_v1(batch)?;
    let state = store.read_manifest_owner_state_v1(OWNER)?;
    let state = state.ok_or("missing admitted owner state")?;
    let snapshot = store.read_manifest_owner_admission_v1(OWNER, 1, TIMELINE)?;
    let snapshot = snapshot.ok_or("missing admitted snapshot")?;
    Ok(Admitted { state, snapshot })
}

/// The first recorded scope member leaf of one kind.
fn member_leaf(
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
    kind: WorldArtifactKindV1,
) -> Fallible<&WorldArtifactLeafV1> {
    let member = snapshot
        .timeline
        .members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == kind)
        .ok_or("missing recorded member leaf")?;
    Ok(&member.leaf)
}

fn lease_leaf(snapshot: &ManifestOwnerAdmissionSnapshotV1) -> Fallible<&WorldArtifactLeafV1> {
    member_leaf(snapshot, WorldArtifactKindV1::RetentionLease)
}

fn table(row_count: usize, byte: u8) -> Fallible<LocalCutTableRefV1> {
    let rows = u64::try_from(row_count)?;
    let table = LocalCutTableRefV1::new(rows, (rows != 0).then_some(hash(byte)))?;
    Ok(table)
}

const fn zero_event_expected() -> LocalCutExpectedHeadRowV1 {
    LocalCutExpectedHeadRowV1 {
        timeline_id: TIMELINE,
        logical_head: 0,
        stitched_chain_hash: GENESIS,
        source_timeline_id: TIMELINE,
        source_segment_head: 0,
        source_chain_hash: GENESIS,
        logical_prefix: 0,
        lineage_proof_hash: None,
        predecessor_wcb_hash: None,
    }
}

fn binding_table(
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
) -> Fallible<LocalCutManifestBindingTableV1> {
    let timeline = &snapshot.timeline;
    let row = LocalCutManifestBindingRowV1 {
        timeline_id: timeline.timeline_id,
        scope: timeline.scope,
        wcs_hash: timeline.wcs1.digest(),
        msr_hash: timeline.receipt.digest(),
        msb_hash: timeline.binding.digest(),
    };
    let table = LocalCutManifestBindingTableV1::new(OWNER, 1, vec![row])?;
    Ok(table)
}

/// One kind-1 row per admitted Plugin; MCA1 slot order is `PluginId` order.
fn composition_rows(
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
) -> Vec<LocalCutCompositionBindingRowV1> {
    snapshot
        .catalog
        .as_input()
        .rows
        .iter()
        .map(|row| LocalCutCompositionBindingRowV1 {
            plugin_id: row.plugin_id,
            timeline_id: TIMELINE,
            plugin_version: row.plugin_version.clone(),
            implementation_hash: row.implementation_hash,
            eop1_native_digest: row.eop1_native_digest,
            driver_interval_ns: Some(0),
            last_due_ns: None,
            event_cursor: 0,
            participant_native_state_hash: hash(91),
        })
        .collect()
}

fn seal_for(
    admitted: &Admitted,
    composition_rows: usize,
    expected_rows: &[LocalCutExpectedHeadRowV1],
    manifest_table: &LocalCutManifestBindingTableV1,
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
        membership_table: table(1, 94)?,
        composition_table: table(composition_rows, 92)?,
        inbox_table: table(0, 95)?,
        invocation_table: table(0, 96)?,
        expected_heads_table: expected_table.table_ref(),
        ebp_native_hash: hash(98),
        execution_profile_native_hash: hash(99),
        recording_context_table: table(1, 93)?,
        owner_operational_policy_hash: hash(100),
        explicit_attempt_hash: None,
        ingress_preallocation_native_hash: hash(101),
        manifest_binding_table: manifest_table.table_ref(),
    })?;
    Ok(seal)
}

/// The WCB1 the owner must derive: the oracle root at the sealed cut identity.
fn expected_binding(
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
    seal: &LocalCutSealV2,
) -> Fallible<WorldClosureBindingV1> {
    let cut_digest = domain_hash(SEAL_DOMAIN, &seal.to_canonical_cbor());
    let binding = WorldClosureBindingV1::new(WorldClosureBindingInputV1 {
        timeline_id: TIMELINE,
        operation_id: CUT_OPERATION,
        cut_coordinate: WorldClosureCutCoordinateV1 {
            cut_id: seal.as_input().cut_id,
            partition_id: 0,
            reservation_identity: *cut_digest.as_bytes(),
        },
        logical_head: 0,
        stitched_head_hash: GENESIS,
        retention_lease_leaf_hash: leaf_hash(lease_leaf(snapshot)?),
        consumer_set_hash: snapshot.timeline.wcs1.digest(),
        dependency_root_hash: oracle_directory(snapshot)?.root,
        history_root_hash: None,
        predecessor_binding_hash: None,
        parent_lineage_reference: None,
        read_limits: READ_LIMITS,
    })?;
    Ok(binding)
}

/// Build the zero-Event cut request whose kind-5 row names the oracle's WCB1.
fn cut_request(admitted: &Admitted) -> Fallible<LocalCutOwnerRequestV1> {
    let snapshot = &admitted.snapshot;
    let manifest_binding_table = binding_table(snapshot)?;
    let composition_rows = composition_rows(snapshot);
    let recording_context_rows = vec![LocalCutRecordingContextRowV1 {
        timeline_id: TIMELINE,
        wcs_hash: snapshot.timeline.wcs1.digest(),
        retention_lease_hash: lease_leaf(snapshot)?.as_input().native_digest,
        predecessor_wcb_hash: None,
    }];
    let expected_head_rows = vec![zero_event_expected()];
    let seal = seal_for(
        admitted,
        composition_rows.len(),
        &expected_head_rows,
        &manifest_binding_table,
    )?;
    let result_head_rows = vec![LocalCutResultHeadRowV1 {
        timeline_id: TIMELINE,
        result_logical_head: 0,
        result_stitched_hash: GENESIS,
        result_source_segment_head: 0,
        result_source_chain_hash: GENESIS,
        successor_wcb_hash: expected_binding(snapshot, &seal)?.digest(),
        event_count: 0,
    }];
    let result_heads_table = LocalCutHeadsTableV1::result_heads(OWNER, 1, &result_head_rows)?;
    Ok(LocalCutOwnerRequestV1 {
        operation_id: CUT_OPERATION,
        seal,
        manifest_hash: hash(103),
        manifest_binding_table,
        composition_rows,
        recording_context_rows,
        expected_head_rows,
        result_head_rows,
        partition_ledger_seq: 1,
        result_heads_table: result_heads_table.table_ref(),
        participant_successor_table: table(1, 106)?,
        cpu_completion_table: table(0, 107)?,
        action_disposition_table: table(1, 108)?,
        candidate_bases_table: table(0, 109)?,
        invocation_bridges_table: table(0, 110)?,
        result_inventory_generation: RESULT_INVENTORY,
        release_fence_proof_digest: hash(112),
    })
}

/// Prepare a cut against `snapshot` as the store's admission readback.
fn prepare_against(
    admitted: &Admitted,
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
    request: LocalCutOwnerRequestV1,
) -> Result<PreparedLocalCutOwnerCommitV1, LocalCutOwnerErrorV1> {
    let admissions = std::slice::from_ref(snapshot);
    let owner = &FixtureOwner::INSTALLED;
    prepare_local_cut_owner_commit_v1(request, None, &admitted.state, admissions, owner)
}

// Independent preferred-CBOR WDB1 oracle; it shares no production encoder or packer.
#[derive(Clone, Copy)]
struct ExpectedChild {
    first: (u8, Hash),
    last: (u8, Hash),
    count: u64,
    node_hash: Hash,
}

/// Oracle WDB1 nodes level by level, their heights, the root and the leaf count.
struct OracleDirectory {
    branches: Vec<Vec<u8>>,
    heights: Vec<u8>,
    root: Hash,
    leaf_count: usize,
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=255 => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        // Every value these fixtures encode is below 65,536.
        _ => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
    }
}

fn bytes32(out: &mut Vec<u8>, value: Hash) {
    head(out, 2, 32);
    out.extend_from_slice(value.as_bytes());
}

fn key(out: &mut Vec<u8>, (kind, digest): (u8, Hash)) {
    head(out, 4, 2);
    head(out, 0, u64::from(kind));
    bytes32(out, digest);
}

fn encode_branch(scope: Hash, height: u8, children: &[ExpectedChild]) -> Fallible<Vec<u8>> {
    let mut out = vec![0x88, 0x44];
    out.extend_from_slice(b"WDB1");
    out.push(0x01);
    bytes32(&mut out, scope);
    head(&mut out, 0, u64::from(height));
    key(&mut out, children[0].first);
    key(&mut out, children[children.len() - 1].last);
    head(&mut out, 0, children.iter().map(|child| child.count).sum());
    head(&mut out, 4, u64::try_from(children.len())?);
    for child in children {
        out.push(0x84);
        key(&mut out, child.first);
        key(&mut out, child.last);
        head(&mut out, 0, child.count);
        bytes32(&mut out, child.node_hash);
    }
    Ok(out)
}

fn leaf_hash(leaf: &WorldArtifactLeafV1) -> Hash {
    domain_hash(LEAF_DOMAIN, &leaf.to_canonical_cbor())
}

fn leaf_child(leaf: &WorldArtifactLeafV1) -> ExpectedChild {
    let input = leaf.as_input();
    let endpoint = (input.kind.code(), input.native_digest);
    ExpectedChild {
        first: endpoint,
        last: endpoint,
        count: 1,
        node_hash: leaf_hash(leaf),
    }
}

fn branch_child(bytes: &[u8], children: &[ExpectedChild]) -> ExpectedChild {
    ExpectedChild {
        first: children[0].first,
        last: children[children.len() - 1].last,
        count: children.iter().map(|child| child.count).sum(),
        node_hash: domain_hash(BRANCH_DOMAIN, bytes),
    }
}

/// WDB1 key order: artifact kind code, then raw native digest bytes.
const fn oracle_key(leaf: &WorldArtifactLeafV1) -> (u8, [u8; 32]) {
    let input = leaf.as_input();
    (input.kind.code(), *input.native_digest.as_bytes())
}

/// Every member, reference and EOP1/OPC1 leaf the admission recorded, in key order.
fn admitted_leaves(snapshot: &ManifestOwnerAdmissionSnapshotV1) -> Vec<&WorldArtifactLeafV1> {
    let timeline = &snapshot.timeline;
    let members = timeline.members.leaves.iter().map(|member| &member.leaf);
    let copies = timeline
        .policy_copies
        .iter()
        .flat_map(|copy| [&copy.eop1_leaf, &copy.opc1_leaf]);
    let mut leaves: Vec<_> = members.chain(copies).collect();
    leaves.sort_by_key(|leaf| oracle_key(leaf));
    leaves.dedup();
    leaves
}

/// Pack the admitted leaves 256 to a branch, level by level, up to one root.
fn oracle_directory(snapshot: &ManifestOwnerAdmissionSnapshotV1) -> Fallible<OracleDirectory> {
    let scope = snapshot.timeline.scope;
    let leaves = admitted_leaves(snapshot);
    let leaf_count = leaves.len();
    let mut level: Vec<ExpectedChild> = leaves.into_iter().map(leaf_child).collect();
    let mut branches = Vec::new();
    let mut heights = Vec::new();
    let mut level_height = 0_u8;
    while level.len() > 1 {
        level_height += 1;
        let mut next = Vec::with_capacity(level.len().div_ceil(FANOUT));
        for children in level.chunks(FANOUT) {
            let bytes = encode_branch(scope, level_height, children)?;
            next.push(branch_child(&bytes, children));
            branches.push(bytes);
            heights.push(level_height);
        }
        level = next;
    }
    let root = level.first().ok_or("no admitted leaves")?.node_hash;
    Ok(OracleDirectory {
        branches,
        heights,
        root,
        leaf_count,
    })
}

/// What one committed cut published, beside the admission it was cut from.
struct RecordedCut {
    admitted: Admitted,
    request: LocalCutOwnerRequestV1,
    directory: WorldDependencyDirectoryV1,
    committed: LocalCutOwnerCommitV1,
}

/// Admit `plugins` Plugin rows, then record and read back one zero-Event cut.
fn record_cut<S: CutStore>(store: &mut S, plugins: u16) -> Fallible<RecordedCut> {
    let admitted = admit(store, plugins)?;
    let request = cut_request(&admitted)?;
    let batch = prepare_against(&admitted, &admitted.snapshot, request.clone())?;
    let directories = batch.dependency_directories();
    let directory = directories.first().ok_or("missing directory")?.clone();
    let committed = store.commit_local_cut_owner_v1(batch)?;
    let readback = store.read_local_cut_owner_commit_v1(OWNER, 1)?;
    assert_eq!(readback.as_ref(), Some(&committed));
    Ok(RecordedCut {
        admitted,
        request,
        directory,
        committed,
    })
}

/// Compare every published WDB1 node, the root and the WCB1 with the oracle.
fn assert_exact_closure(cut: &RecordedCut) -> Fallible<OracleDirectory> {
    let oracle = oracle_directory(&cut.admitted.snapshot)?;
    let branches = cut.directory.branches();
    assert_eq!(branches.len(), oracle.branches.len());
    for ((branch, bytes), height) in branches.iter().zip(&oracle.branches).zip(&oracle.heights) {
        assert_eq!(branch.encode().as_slice(), bytes.as_slice());
        assert_eq!(branch.digest(), domain_hash(BRANCH_DOMAIN, bytes));
        assert_eq!(branch.height(), *height);
    }
    assert_eq!(cut.directory.root_hash(), oracle.root);
    assert_eq!(cut.directory.leaves().len(), oracle.leaf_count);
    let [recording] = cut.committed.recordings.as_slice() else {
        return Err("expected one WCB1 recording".into());
    };
    assert_eq!(recording.scope, cut.admitted.snapshot.timeline.scope);
    let binding = recording.binding.as_input();
    assert_eq!(binding.dependency_root_hash, oracle.root);
    assert_cut_identity(cut, recording)?;
    Ok(oracle)
}

/// Bind the recording to the historical cut through LCS2, LCC1, LCQ1 and WCR1.
fn assert_cut_identity(cut: &RecordedCut, recording: &LocalCutWorldRecordingV1) -> TestResult {
    let committed = &cut.committed;
    let cut_digest = domain_hash(SEAL_DOMAIN, &committed.seal.to_canonical_cbor());
    assert_eq!(committed.seal, cut.request.seal);
    assert_eq!(committed.commit.as_input().seal_hash, cut_digest);
    let lcq1 = committed.receipt.as_input();
    assert_eq!(lcq1.commit_record_hash, committed.commit.digest());
    let coordinate = WorldClosureCutCoordinateV1 {
        cut_id: 1,
        partition_id: 0,
        reservation_identity: *cut_digest.as_bytes(),
    };
    assert_eq!(recording.binding.as_input().cut_coordinate, coordinate);
    let expected = expected_binding(&cut.admitted.snapshot, &committed.seal)?;
    assert_eq!(recording.binding, expected);
    let wcb1_digest = domain_hash(BINDING_DOMAIN, &recording.binding.to_canonical_cbor());
    assert_eq!(recording.binding.digest(), wcb1_digest);
    let successor = cut.request.result_head_rows[0].successor_wcb_hash;
    assert_eq!(successor, wcb1_digest);
    let lcq1_digest = committed.receipt.digest();
    let wcr1 = recording.receipt.as_input();
    assert_eq!(wcr1.binding_hash, wcb1_digest);
    assert_eq!(wcr1.operation_id, CUT_OPERATION);
    assert_eq!(wcr1.actual_commit_receipt_digest, lcq1_digest);
    assert_eq!(wcr1.installed_inventory_generation, RESULT_INVENTORY);
    Ok(())
}

/// Each of the 256 Plugins adds EOP1, OPC1, budget, configuration and
/// implementation leaves, and every even one an execution profile; the scope
/// adds its lease, retention and audience policies and three consumer
/// references. The 1,414 leaves fill five height-one branches and part of a
/// sixth under one height-two root.
fn assert_full_roster_shape(cut: &RecordedCut, oracle: &OracleDirectory) {
    let timeline = &cut.admitted.snapshot.timeline;
    assert_eq!(cut.admitted.snapshot.catalog.as_input().rows.len(), 256);
    assert_eq!(timeline.binding.as_input().rows.len(), 256);
    assert_eq!(timeline.policy_copies.len(), 256);
    assert_eq!(oracle.leaf_count, 1414);
    assert_eq!(oracle.heights, [1, 1, 1, 1, 1, 1, 2]);
    assert_eq!(cut.directory.height(), 2);
}

/// Same-name Plugins differ only by `PluginId`; the reducer-only Plugin is
/// absent from WCS1, yet its Required EOP1/OPC1 pair is in MSB1, the copies
/// and the recorded WDB1 closure.
fn assert_small_roster(cut: &RecordedCut, oracle: &OracleDirectory) -> TestResult {
    let snapshot = &cut.admitted.snapshot;
    let [first, second, reducer_only] = snapshot.catalog.as_input().rows.as_slice() else {
        return Err("expected three admitted Plugins".into());
    };
    assert_eq!(first.plugin_name, second.plugin_name);
    assert_ne!(first.plugin_id, second.plugin_id);
    let admitted_ids = [first.plugin_id, second.plugin_id, reducer_only.plugin_id];
    let producers = snapshot.timeline.wcs1.producers();
    let producer_ids: Vec<PluginId> = producers.iter().map(WorldProducerV1::plugin_id).collect();
    assert_eq!(producer_ids, [first.plugin_id, second.plugin_id]);
    let binding_rows = &snapshot.timeline.binding.as_input().rows;
    let msb1_ids: Vec<PluginId> = binding_rows.iter().map(|row| row.plugin_id).collect();
    assert_eq!(msb1_ids, admitted_ids);
    let copies = &snapshot.timeline.policy_copies;
    let copy_ids: Vec<PluginId> = copies.iter().map(|copy| copy.plugin_id).collect();
    assert_eq!(copy_ids, admitted_ids);
    let reducer_copy = copies.last().ok_or("missing reducer-only copy")?;
    let reducer_policy = OutputPolicyV1::from_canonical_cbor(&reducer_copy.eop1_bytes)?;
    assert!(reducer_policy.fields().output_declarations.is_empty());
    let leaves = cut.directory.leaves();
    for copy in copies {
        assert!(leaves.contains(&copy.eop1_leaf));
        assert!(leaves.contains(&copy.opc1_leaf));
    }
    let mut without_reducer = snapshot.clone();
    without_reducer.timeline.policy_copies.pop();
    assert_ne!(oracle_directory(&without_reducer)?.root, oracle.root);
    Ok(())
}

/// Every recorded leaf of one kind.
fn kind_leaves(
    leaves: &[WorldArtifactLeafV1],
    kind: WorldArtifactKindV1,
) -> Vec<&WorldArtifactLeafV1> {
    leaves
        .iter()
        .filter(|leaf| leaf.as_input().kind == kind)
        .collect()
}

/// The sorted WAL1 addresses of every recorded leaf of one kind.
fn kind_hashes(leaves: &[WorldArtifactLeafV1], kind: WorldArtifactKindV1) -> Vec<Hash> {
    let mut hashes: Vec<Hash> = kind_leaves(leaves, kind)
        .into_iter()
        .map(leaf_hash)
        .collect();
    hashes.sort();
    hashes
}

fn names(leaf: &WorldArtifactLeafV1, child: Hash) -> bool {
    leaf.as_input().child_node_hashes.contains(&child)
}

/// One row's references: its OPC1 leaf and every direct OPC1 child, EOP1 included.
const fn row_references(copy: &ManifestOwnerPolicyCopiesV1) -> usize {
    1 + copy.opc1_leaf.as_input().child_node_hashes.len()
}

/// Each MSB1 row's own Required EOP1 (kind 0) and OPC1 (kind 14) leaves, all
/// recorded; returns the number of distinct explicit seed memberships.
fn assert_row_seeds(cut: &RecordedCut) -> Fallible<usize> {
    let timeline = &cut.admitted.snapshot.timeline;
    let leaves = cut.directory.leaves();
    let copies = &timeline.policy_copies;
    let mut seeds = BTreeSet::new();
    for row in &timeline.binding.as_input().rows {
        let copy = copies.iter().find(|copy| copy.plugin_id == row.plugin_id);
        let copy = copy.ok_or("MSB1 row without a copy")?;
        let eop1 = copy.eop1_leaf.as_input();
        let opc1 = copy.opc1_leaf.as_input();
        assert_eq!(eop1.kind, WorldArtifactKindV1::OutputPolicy);
        assert_eq!(opc1.kind, WorldArtifactKindV1::OutputPolicyClosure);
        assert_eq!(row.eop1_wal1_hash, leaf_hash(&copy.eop1_leaf));
        assert_eq!(row.closure_hash, opc1.native_digest);
        assert!(leaves.contains(&copy.eop1_leaf));
        assert!(leaves.contains(&copy.opc1_leaf));
        seeds.insert(leaf_hash(&copy.eop1_leaf));
        seeds.insert(leaf_hash(&copy.opc1_leaf));
    }
    Ok(seeds.len())
}

/// Row membership is proved per row before deduplication: the 256 rows carry
/// 512 explicit seed memberships, every OPC1 names the one scope RTP1 leaf,
/// which the WDB1 records once, and the WDB1 holds fewer leaves than the rows
/// reference.
fn assert_full_roster_deduplication(cut: &RecordedCut) -> TestResult {
    assert_eq!(assert_row_seeds(cut)?, 512);
    let snapshot = &cut.admitted.snapshot;
    let leaves = cut.directory.leaves();
    let rtp1 = member_leaf(snapshot, WorldArtifactKindV1::RetentionPolicy)?;
    let rtp1_hash = leaf_hash(rtp1);
    let copies = &snapshot.timeline.policy_copies;
    let naming = copies
        .iter()
        .filter(|copy| names(&copy.opc1_leaf, rtp1_hash))
        .count();
    assert_eq!(naming, 256);
    let recorded = leaves
        .iter()
        .filter(|leaf| leaf_hash(leaf) == rtp1_hash)
        .count();
    assert_eq!(recorded, 1);
    let references: usize = copies.iter().map(row_references).sum();
    assert!(leaves.len() < references);
    Ok(())
}

/// The WDB1 holds the exact transitive closure: every recorded leaf's native
/// children are recorded, each even-seed EBP1 names its own EPF1, RTP1 names
/// the audience reference leaf and RLS1 names RTP1.
fn assert_transitive_closure(cut: &RecordedCut) -> TestResult {
    let snapshot = &cut.admitted.snapshot;
    let leaves = cut.directory.leaves();
    let recorded: BTreeSet<Hash> = leaves.iter().map(leaf_hash).collect();
    for leaf in leaves {
        let children = &leaf.as_input().child_node_hashes;
        assert!(children.iter().all(|child| recorded.contains(child)));
    }
    let profiles = kind_hashes(leaves, WorldArtifactKindV1::ExecutionProfile);
    let rows = snapshot.catalog.as_input().rows.len();
    assert_eq!(profiles.len(), rows.div_ceil(2));
    let budgets = kind_leaves(leaves, WorldArtifactKindV1::ExecutableBudgetPolicy);
    let mut budget_children: Vec<Hash> = budgets
        .into_iter()
        .flat_map(|budget| budget.as_input().child_node_hashes.iter().copied())
        .collect();
    budget_children.sort();
    assert_eq!(budget_children, profiles);
    let audience = member_leaf(snapshot, WorldArtifactKindV1::AudiencePolicy)?;
    let rtp1 = member_leaf(snapshot, WorldArtifactKindV1::RetentionPolicy)?;
    let rls1 = member_leaf(snapshot, WorldArtifactKindV1::RetentionLease)?;
    assert_eq!(rtp1.as_input().child_node_hashes, [leaf_hash(audience)]);
    assert_eq!(rls1.as_input().child_node_hashes, [leaf_hash(rtp1)]);
    for leaf in [audience, rtp1, rls1] {
        assert!(leaves.contains(leaf));
    }
    Ok(())
}

/// Substituted admission facts; each one invalidates the admission snapshot.
const SNAPSHOT_FAULTS: [SnapshotEdit; 8] = [
    opc1_names_another_lease,
    opc1_in_another_scope,
    opc1_with_the_eop1_kind,
    opc1_for_another_copy_owner,
    altered_opc1_bytes,
    omitted_member_leaf,
    extra_member_leaf,
    missing_reducer_only_copy,
];

/// The reducer-only Plugin sorts last, so its copy is the last one.
fn reducer_only_copy(
    snapshot: &mut ManifestOwnerAdmissionSnapshotV1,
) -> Fallible<&mut ManifestOwnerPolicyCopiesV1> {
    let copies = &mut snapshot.timeline.policy_copies;
    copies
        .last_mut()
        .ok_or_else(|| "missing reducer-only copy".into())
}

/// Rebuild the reducer-only Plugin's OPC1 leaf with one changed registration.
fn edit_reducer_only_opc1(
    snapshot: &mut ManifestOwnerAdmissionSnapshotV1,
    edit: LeafEdit,
) -> TestResult {
    let copy = reducer_only_copy(snapshot)?;
    let mut input = copy.opc1_leaf.as_input().clone();
    edit(&mut input);
    copy.opc1_leaf = WorldArtifactLeafV1::new(input)?;
    Ok(())
}

fn opc1_names_another_lease(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    edit_reducer_only_opc1(snapshot, |leaf| leaf.source_lease_hash = hash(0x33))
}

fn opc1_in_another_scope(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    edit_reducer_only_opc1(snapshot, |leaf| leaf.scope = hash(0x34))
}

fn opc1_with_the_eop1_kind(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    edit_reducer_only_opc1(snapshot, |leaf| leaf.kind = EOP1_KIND)
}

fn opc1_for_another_copy_owner(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    edit_reducer_only_opc1(snapshot, |leaf| leaf.owner = [0x35; 32])
}

fn altered_opc1_bytes(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    let copy = reducer_only_copy(snapshot)?;
    let last = copy.opc1_bytes.last_mut().ok_or("empty OPC1 bytes")?;
    *last ^= 0x01;
    Ok(())
}

fn omitted_member_leaf(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    let leaves = &mut snapshot.timeline.members.leaves;
    leaves.pop().ok_or("no member leaves")?;
    Ok(())
}

const fn member_key(member: &ManifestOwnerMemberLeafV1) -> (WorldArtifactKindV1, Hash) {
    let input = member.leaf.as_input();
    (input.kind, input.native_digest)
}

fn extra_member_leaf(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    let leaves = &mut snapshot.timeline.members.leaves;
    let mut extra = leaves.first().ok_or("no member leaves")?.clone();
    let mut input = extra.leaf.as_input().clone();
    input.native_digest = hash(0x36);
    extra.leaf = WorldArtifactLeafV1::new(input)?;
    leaves.push(extra);
    leaves.sort_by_key(member_key);
    Ok(())
}

fn missing_reducer_only_copy(snapshot: &mut ManifestOwnerAdmissionSnapshotV1) -> TestResult {
    let copies = &mut snapshot.timeline.policy_copies;
    let copy = copies.pop().ok_or("missing reducer-only copy")?;
    assert_eq!(copy.plugin_id, plugin(2));
    Ok(())
}

/// Every owner record a rejected cut could have published or changed.
#[derive(Debug, Eq, PartialEq)]
struct OwnerView {
    admission: Option<ManifestOwnerAdmissionOwnerStateV1>,
    snapshot: Option<ManifestOwnerAdmissionSnapshotV1>,
    local_cut: Option<LocalCutOwnerStateV1>,
    history: Option<LocalCutOwnerStateV1>,
    cut: Option<LocalCutOwnerCommitV1>,
    retry: Option<LocalCutOwnerCommitV1>,
}

fn owner_view<S: CutStore>(store: &S, intent: Hash) -> Fallible<OwnerView> {
    Ok(OwnerView {
        admission: store.read_manifest_owner_state_v1(OWNER)?,
        snapshot: store.read_manifest_owner_admission_v1(OWNER, 1, TIMELINE)?,
        local_cut: store.read_local_cut_owner_state_v1(OWNER)?,
        history: store.verify_local_cut_owner_history_v1(OWNER)?,
        cut: store.read_local_cut_owner_commit_v1(OWNER, 1)?,
        retry: store.resolve_local_cut_owner_retry_v1(OWNER, CUT_OPERATION, intent)?,
    })
}

/// Reject every substituted admission fact and each closure-inconsistent row
/// through the public cut seam, before any publication.
///
/// Two layers reject them. The cut seam re-runs the admission snapshot
/// validation on the snapshots it is given, so every substituted fact returns
/// `CorruptState`. The snapshot-valid but closure-inconsistent rows reach the
/// WCB1 derivation: a kind-8 lease other than the recorded RLS1 returns
/// `Conflict`, and a kind-5 successor other than the derived WCB1 returns
/// `InvalidBatch`.
fn reject_each_fault<S: CutStore>(
    store: &S,
    admitted: &Admitted,
    request: &LocalCutOwnerRequestV1,
) -> TestResult {
    let intent = local_cut_owner_intent_digest_v1(request)?;
    let before = owner_view(store, intent)?;
    assert_eq!(before.local_cut, None);
    assert_eq!(before.cut, None);
    for (fault, tamper) in SNAPSHOT_FAULTS.into_iter().enumerate() {
        let mut snapshot = admitted.snapshot.clone();
        tamper(&mut snapshot)?;
        assert_eq!(
            validate_manifest_owner_admission_snapshot_v1(&snapshot),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch),
            "fault {fault}"
        );
        let prepared = prepare_against(admitted, &snapshot, request.clone());
        assert_eq!(
            prepared.err(),
            Some(LocalCutOwnerErrorV1::CorruptState),
            "fault {fault}"
        );
        assert_eq!(owner_view(store, intent)?, before, "fault {fault}");
    }
    let mut substituted = request.clone();
    substituted.recording_context_rows[0].retention_lease_hash = hash(0x33);
    let prepared = prepare_against(admitted, &admitted.snapshot, substituted);
    assert_eq!(prepared.err(), Some(LocalCutOwnerErrorV1::Conflict));
    assert_eq!(owner_view(store, intent)?, before);
    let mut mismatched = request.clone();
    mismatched.result_head_rows[0].successor_wcb_hash = hash(0x37);
    let table = LocalCutHeadsTableV1::result_heads(OWNER, 1, &mismatched.result_head_rows)?;
    mismatched.result_heads_table = table.table_ref();
    let prepared = prepare_against(admitted, &admitted.snapshot, mismatched);
    assert_eq!(prepared.err(), Some(LocalCutOwnerErrorV1::InvalidBatch));
    assert_eq!(owner_view(store, intent)?, before);
    Ok(())
}

/// The untampered admission still publishes the cut the rejected attempts named.
fn publish_after_rejections<S: CutStore>(
    store: &mut S,
    admitted: &Admitted,
    request: LocalCutOwnerRequestV1,
) -> TestResult {
    let intent = local_cut_owner_intent_digest_v1(&request)?;
    let batch = prepare_against(admitted, &admitted.snapshot, request)?;
    let committed = store.commit_local_cut_owner_v1(batch)?;
    assert_eq!(owner_view(store, intent)?.cut, Some(committed));
    Ok(())
}

#[cfg(feature = "sqlite")]
fn open_sqlite(directory: &tempfile::TempDir) -> Fallible<(SqliteStore, String)> {
    let path = directory.path().join("owner.db");
    let path = path.to_str().ok_or("non-UTF-8 database path")?.to_owned();
    let store = keyed(SqliteStore::open(&path)?)?;
    Ok((store, path))
}

#[cfg(feature = "sqlite")]
fn stored_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredNode> {
    Ok((row.get(0)?, row.get(1)?))
}

/// Read every WDB1 node `SQLite` persisted for `scope`, sorted.
#[cfg(feature = "sqlite")]
fn sqlite_nodes(path: &str, scope: Hash) -> Fallible<Vec<StoredNode>> {
    let connection = rusqlite::Connection::open(path)?;
    let sql = format!("SELECT {NODE_COLUMNS} FROM {NODE_TABLE} WHERE scope = ?1");
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([scope.as_bytes().as_slice()], stored_node)?;
    let mut nodes = rows.collect::<Result<Vec<_>, _>>()?;
    nodes.sort();
    Ok(nodes)
}

/// One oracle node keyed by its own content address.
#[cfg(feature = "sqlite")]
fn oracle_node(bytes: Vec<u8>) -> StoredNode {
    let address = domain_hash(BRANCH_DOMAIN, &bytes);
    (address.as_bytes().to_vec(), bytes)
}

/// The oracle nodes keyed by their own content addresses, sorted.
#[cfg(feature = "sqlite")]
fn oracle_nodes(branches: Vec<Vec<u8>>) -> Vec<StoredNode> {
    let mut nodes: Vec<StoredNode> = branches.into_iter().map(oracle_node).collect();
    nodes.sort();
    nodes
}

#[test]
fn full_roster_cut_records_the_exact_oracle_closure_in_memory() -> TestResult {
    let cut = record_cut(&mut keyed(MemoryStore::new())?, full_roster()?)?;
    let oracle = assert_exact_closure(&cut)?;
    assert_full_roster_shape(&cut, &oracle);
    assert_full_roster_deduplication(&cut)?;
    assert_transitive_closure(&cut)
}

#[cfg(feature = "sqlite")]
#[test]
fn full_roster_cut_persists_the_exact_oracle_nodes_in_sqlite() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (mut store, path) = open_sqlite(&directory)?;
    let cut = record_cut(&mut store, full_roster()?)?;
    let oracle = assert_exact_closure(&cut)?;
    assert_full_roster_shape(&cut, &oracle);
    assert_full_roster_deduplication(&cut)?;
    assert_transitive_closure(&cut)?;
    let scope = cut.admitted.snapshot.timeline.scope;
    assert_eq!(sqlite_nodes(&path, scope)?, oracle_nodes(oracle.branches));
    Ok(())
}

#[test]
fn same_name_and_reducer_only_plugins_are_recorded_in_memory() -> TestResult {
    let cut = record_cut(&mut keyed(MemoryStore::new())?, SMALL_ROSTER)?;
    let oracle = assert_exact_closure(&cut)?;
    assert_small_roster(&cut, &oracle)?;
    assert_eq!(assert_row_seeds(&cut)?, 6);
    assert_transitive_closure(&cut)
}

#[cfg(feature = "sqlite")]
#[test]
fn same_name_and_reducer_only_plugins_are_recorded_in_sqlite() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (mut store, path) = open_sqlite(&directory)?;
    let cut = record_cut(&mut store, SMALL_ROSTER)?;
    let oracle = assert_exact_closure(&cut)?;
    assert_small_roster(&cut, &oracle)?;
    let scope = cut.admitted.snapshot.timeline.scope;
    assert_eq!(sqlite_nodes(&path, scope)?, oracle_nodes(oracle.branches));
    Ok(())
}

#[test]
fn owner_seam_faults_reject_before_memory_publication() -> TestResult {
    let mut store = keyed(MemoryStore::new())?;
    let admitted = admit(&mut store, SMALL_ROSTER)?;
    let request = cut_request(&admitted)?;
    reject_each_fault(&store, &admitted, &request)?;
    publish_after_rejections(&mut store, &admitted, request)
}

#[cfg(feature = "sqlite")]
#[test]
fn owner_seam_faults_reject_before_sqlite_publication() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (mut store, path) = open_sqlite(&directory)?;
    let admitted = admit(&mut store, SMALL_ROSTER)?;
    let request = cut_request(&admitted)?;
    reject_each_fault(&store, &admitted, &request)?;
    let scope = admitted.snapshot.timeline.scope;
    assert!(sqlite_nodes(&path, scope)?.is_empty());
    publish_after_rejections(&mut store, &admitted, request)?;
    assert!(!sqlite_nodes(&path, scope)?.is_empty());
    Ok(())
}

/// The coordinator WKE1 bytes a store retained for `cut`, keyed by digest.
fn retained_evidence<S: ManifestOwnerLinkReadPortV1>(
    store: &S,
    cut: &LocalCutOwnerCommitV1,
) -> Fallible<BTreeMap<Hash, Vec<u8>>> {
    let identity = ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(cut.receipt.digest());
    let snapshot = store.read_manifest_owner_link_snapshot_v1(OWNER, identity, TIMELINE)?;
    Ok(snapshot.ok_or("missing owner-link snapshot")?.key_evidence)
}

/// The one deduplicated WKE1 record that the cut's LCQ1 and MSR1 both name.
fn expected_evidence() -> Fallible<BTreeMap<Hash, Vec<u8>>> {
    let evidence = coordinator_evidence(1)?;
    let entry = (evidence.digest(), evidence.to_canonical_cbor());
    Ok(BTreeMap::from([entry]))
}

/// Reject substituted WKE1 bytes and an absent registry before publication.
fn assert_evidence_rejections<S: CutStore>(mut keyed_store: S, mut unkeyed: S) -> TestResult {
    let request = admission_request(SMALL_ROSTER)?;
    let installed = &FixtureOwner::INSTALLED;
    let batch = prepare_manifest_owner_admission_v1(request.clone(), installed, None)?;
    assert_eq!(
        unkeyed.commit_manifest_owner_admission_v1(batch),
        Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
    );
    assert_eq!(unkeyed.read_manifest_owner_state_v1(OWNER)?, None);
    let substituting = &FixtureOwner::SUBSTITUTING;
    let substituted = prepare_manifest_owner_admission_v1(request, substituting, None)?;
    assert_eq!(
        keyed_store.commit_manifest_owner_admission_v1(substituted),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );
    assert_eq!(keyed_store.read_manifest_owner_state_v1(OWNER)?, None);
    let admitted = admit(&mut keyed_store, SMALL_ROSTER)?;
    let cut = cut_request(&admitted)?;
    let intent = local_cut_owner_intent_digest_v1(&cut)?;
    let before = owner_view(&keyed_store, intent)?;
    let admissions = std::slice::from_ref(&admitted.snapshot);
    let state = &admitted.state;
    let batch = prepare_local_cut_owner_commit_v1(cut, None, state, admissions, substituting)?;
    assert_eq!(
        keyed_store.commit_local_cut_owner_v1(batch),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );
    assert_eq!(owner_view(&keyed_store, intent)?, before);
    Ok(())
}

#[test]
fn memory_cut_retains_the_exact_coordinator_evidence() -> TestResult {
    let mut store = keyed(MemoryStore::new())?;
    let cut = record_cut(&mut store, SMALL_ROSTER)?;
    assert_eq!(retained_evidence(&store, &cut.committed)?, expected_evidence()?);
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_cut_retains_the_same_coordinator_evidence_across_reopen() -> TestResult {
    let mut memory = keyed(MemoryStore::new())?;
    let memory_cut = record_cut(&mut memory, SMALL_ROSTER)?;
    let memory_evidence = retained_evidence(&memory, &memory_cut.committed)?;
    let directory = tempfile::tempdir()?;
    let (mut store, path) = open_sqlite(&directory)?;
    let cut = record_cut(&mut store, SMALL_ROSTER)?;
    assert_eq!(retained_evidence(&store, &cut.committed)?, memory_evidence);
    drop(store);
    let reopened = SqliteStore::open(&path)?;
    assert_eq!(retained_evidence(&reopened, &cut.committed)?, memory_evidence);
    assert_eq!(memory_evidence, expected_evidence()?);
    let connection = rusqlite::Connection::open(&path)?;
    let count = "SELECT COUNT(*) FROM world_key_evidence";
    let rows: i64 = connection.query_row(count, [], |row| row.get(0))?;
    assert_eq!(rows, 1);
    Ok(())
}

#[test]
fn memory_commits_reject_substituted_evidence_and_an_absent_registry() -> TestResult {
    assert_evidence_rejections(keyed(MemoryStore::new())?, MemoryStore::new())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_commits_reject_substituted_evidence_and_an_absent_registry() -> TestResult {
    let unkeyed = SqliteStore::open_in_memory()?;
    assert_evidence_rejections(keyed(SqliteStore::open_in_memory()?)?, unkeyed)
}
