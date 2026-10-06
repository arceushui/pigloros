//! Public acceptance for the ADR-089 Revision 4 installed historical
//! owner-link verifier on Memory and `SQLite` owner stores.

use std::{error::Error, sync::Arc};

use pos_core::manifest_owner_link_verifier::test_verified_manifest_owner_link;
use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyV1,
};
use pos_core::trusted_clock::{
    open_release_guard, reserve_trusted_clock, ApplicableExpiriesV1, ExpiryPremisesV1,
    ReleaseGuardV1, ScriptedTrustedWallSourceV1, SystemGuardMonotonicSourceV1,
    SystemTrustedWallSourceV1, TrustedWallSourceV1, WaitBudgetV1,
};
use pos_core::{
    build_manifest_owner_scope_v1, collect_manifest_owner_link_ancestors_v1,
    collect_manifest_owner_link_branches_v1, deletion_receipt, derive_local_cut_world_closure_v1,
    ArtifactDataClassV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1, AssuranceLevelV1,
    AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1, ErasureContainmentGateV1,
    ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureVerifiedEmptyInventoryQueryV1, ErasureVerifiedInventoryQueryV1, EventStore, Hash,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationOutcomeV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, LocalCutCommitV1, LocalCutCompositionBindingRowV1,
    LocalCutExpectedHeadRowV1, LocalCutHeadsTableV1, LocalCutManifestBindingRowV1,
    LocalCutManifestBindingTableV1, LocalCutOwnerCommitKindV1, LocalCutOwnerCommitV1,
    LocalCutOwnerErrorV1, LocalCutOwnerPersistencePortV1, LocalCutOwnerRequestV1,
    LocalCutOwnerStateV1, LocalCutOwnerVerifierV1, LocalCutReceiptInputV1, LocalCutReceiptV1,
    LocalCutRecordingContextRowV1, LocalCutResultHeadRowV1, LocalCutSealInputV2, LocalCutSealV2,
    LocalCutTableRefV1, LocalCutWorldClosureSourceV1, LocalCutWorldRecordingV1,
    ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionPersistencePortV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionSnapshotV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerClassifiedLeafV1,
    ManifestOwnerConsumerReferenceV1, ManifestOwnerLeafClassificationV1,
    ManifestOwnerLinkAncestorV1, ManifestOwnerLinkCutIdentityV1, ManifestOwnerLinkDigestsV1,
    ManifestOwnerLinkHeadV1, ManifestOwnerLinkReadPortV1, ManifestOwnerLinkRequestV1,
    ManifestOwnerLinkSnapshotV1, ManifestOwnerLinkUseFenceV1, ManifestOwnerLinkVerificationErrorV1,
    ManifestOwnerPolicyCopiesV1, ManifestOwnerPolicySourceV1, ManifestOwnerScopeMembersV1,
    ManifestOwnerScopeSourceV1, ManifestOwnerScopeV1, ManifestOwnerTimelineAdmissionRequestV1,
    ManifestSlotAdmissionReceiptDraftV1, ManifestSlotAdmissionReceiptV1, ManifestSlotBindingV1,
    OutputPolicyClosureEnvelopeV1, OwnerIdV1, Plugin, PluginId, PrincipalRefV1, PublicKey,
    TimelineId, VerifiedManifestOwnerLinkV1, WallTime, WorldArtifactKeyDependencyV1,
    WorldArtifactKindV1, WorldClosureReadLimitsV1, WorldConsumerSetInputV1, WorldConsumerSetV1,
    WorldConsumerV1, WorldKeyEvidenceInputV1, WorldKeyEvidenceV1, WorldProducerV1,
};
use pos_runtime::{AdmittedCompositionV1, AdmittedManifestPolicySourceV1, PluginRegistry};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, trusted_clock::MemoryTrustedClockAuthorityV1,
};

type TestResult = Result<(), Box<dyn Error>>;
type Fallible<T> = Result<T, Box<dyn Error>>;
type LinkError = ManifestOwnerLinkVerificationErrorV1;
type LinkResult = Result<VerifiedManifestOwnerLinkV1, LinkError>;
type Edit = Box<dyn Fn(&mut ManifestOwnerLinkSnapshotV1)>;

const DAY_MICROS: u64 = 86_400_000_000;
const READ_LIMITS: WorldClosureReadLimitsV1 = WorldClosureReadLimitsV1 {
    max_node_visits: 4096,
    max_native_bytes: 1_048_576,
    max_combined_depth: 32,
};
/// Genesis chain hash attested by the fixture local-cut source owner.
const SOURCE_GENESIS: Hash = hash(0x47);
const FORGED_EVIDENCE: Hash = hash(119);
const SIGNATURE: [u8; 64] = [90; 64];
/// Owner of the installed coordinator's Timeline-integrity signing key.
const COORDINATOR: &str = "local-coordinator";

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn hooks(local_cut: Hash, admission: Hash) -> OwnerHooks {
    OwnerHooks {
        local_cut,
        admission,
    }
}

/// The verify-only WKE1 of the installed coordinator's epoch-1 signing key.
fn coordinator_evidence() -> Fallible<WorldKeyEvidenceV1> {
    Ok(WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        identity: KeyIdentityV1::new(COORDINATOR, KeyRoleV1::TimelineIntegritySigning, 1),
        private_material_digest: hash(0xc1),
        private_material_required: false,
        public_verification_key: Some(PublicKey::from_bytes([0xc2; 32])),
    })?)
}

/// Hooks that accept only the installed coordinator's evidence.
fn installed() -> Fallible<OwnerHooks> {
    let evidence = coordinator_evidence()?.digest();
    Ok(hooks(evidence, evidence))
}

/// The registry row that the installed coordinator's WKE1 names.
fn coordinator_registration(public_key: PublicKey) -> Fallible<KeyRegistrationV1> {
    let evidence = *coordinator_evidence()?.as_input();
    Ok(KeyRegistrationV1::new(
        evidence.identity,
        evidence.private_material_digest,
        Some(public_key),
    ))
}

/// A key registry holding the installed coordinator's live signing key.
fn coordinator_keys() -> Fallible<KeyRegistryStateV1> {
    let registration = coordinator_registration(PublicKey::from_bytes([0xc2; 32]))?;
    let mut keys = KeyRegistryStateV1::new();
    keys.register_key(registration)?;
    Ok(keys)
}

/// A Memory owner store whose key registry holds the coordinator key.
fn memory_owner() -> Fallible<MemoryStore> {
    let mut store = MemoryStore::new();
    store.save_key_registry(&coordinator_keys()?)?;
    Ok(store)
}

/// A `SQLite` owner store whose key registry holds the coordinator key.
fn sqlite_owner(path: &str) -> Fallible<SqliteStore> {
    let mut store = SqliteStore::open(path)?;
    store.save_key_registry(&coordinator_keys()?)?;
    Ok(store)
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

/// Installed owner hooks; each receipt check accepts only its key evidence.
#[derive(Clone, Copy)]
struct OwnerHooks {
    local_cut: Hash,
    admission: Hash,
}

impl ManifestOwnerAdmissionVerifierV1 for OwnerHooks {
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
        receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let fields = receipt.as_input();
        if (fields.coordinator_key_evidence_hash, fields.signature) == (self.admission, SIGNATURE) {
            Ok(())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }
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
        let evidence = coordinator_evidence().or(Err(rejected))?;
        draft
            .with_evidence_and_signature(evidence.digest(), SIGNATURE)
            .map(|receipt| (receipt, evidence.to_canonical_cbor()))
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

impl LocalCutOwnerVerifierV1 for OwnerHooks {
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
        Ok(SOURCE_GENESIS)
    }

    fn sign_local_cut_receipt(
        &self,
        commit: &LocalCutCommitV1,
    ) -> Result<(LocalCutReceiptV1, Vec<u8>), LocalCutOwnerErrorV1> {
        let rejected = LocalCutOwnerErrorV1::OwnerRejected;
        let evidence = coordinator_evidence().or(Err(rejected))?;
        let receipt = LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
            commit_record_hash: commit.digest(),
            coordinator_key_evidence_hash: evidence.digest(),
            signature: SIGNATURE,
        });
        receipt
            .map(|receipt| (receipt, evidence.to_canonical_cbor()))
            .or(Err(rejected))
    }

    fn verify_local_cut_receipt(
        &self,
        receipt: &LocalCutReceiptV1,
        commit: &LocalCutCommitV1,
        _admissions: &[ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), LocalCutOwnerErrorV1> {
        let fields = receipt.as_input();
        let signed = (
            fields.commit_record_hash,
            fields.coordinator_key_evidence_hash,
            fields.signature,
        );
        if signed == (commit.digest(), self.local_cut, SIGNATURE) {
            Ok(())
        } else {
            Err(LocalCutOwnerErrorV1::OwnerRejected)
        }
    }
}

/// A registry whose installed owner hooks are fixed at construction.
fn owner_registry(hooks: OwnerHooks) -> PluginRegistry {
    PluginRegistry::new_with_manifest_owner_admission_verifier(hooks)
        .with_local_cut_owner_verifier(hooks)
}

/// The complete installed owner world shared by every store in one test.
struct World {
    registry: PluginRegistry,
    admitted: AdmittedCompositionV1,
    owner: OwnerIdV1,
    sources: Vec<AdmittedManifestPolicySourceV1>,
    rtp1_bytes: Vec<u8>,
    policy: WorldRetentionPolicyV1,
    lease_start: u64,
    premise: WorldRetentionLeaseV1,
    events: MemoryStore,
    gate: ErasureContainmentGateV1,
    generation: ErasureReferenceV1,
    timelines: Vec<TimelineId>,
    keys: KeyRegistryStateV1,
}

/// Two same-name Plugins with distinct IDs; only the first produces.
fn world(timeline_count: usize) -> Fallible<World> {
    let mut registry = owner_registry(installed()?);
    for role in ["world", "agent"] {
        let plugin = LocalPlugin {
            id: PluginId::new(),
        };
        registry.register_local(&plugin, vec![role.to_owned()], None, None)?;
    }
    let owner = OwnerIdV1::from_static("open-source-app");
    let admitted = registry.admit_local_manifest_registration(owner, 1)?;
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    let first = sources.first().ok_or("empty admitted Plugin set")?;
    let (opc1, eop1) = (first.opc1_bytes(), first.eop1_bytes());
    let envelope = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(opc1, eop1)?;
    let rtp1_bytes = envelope.retention_policy_artifact().to_vec();
    let policy = WorldRetentionPolicyV1::from_canonical_cbor(&rtp1_bytes)?;
    let mut events = MemoryStore::new();
    let mut timelines = Vec::with_capacity(timeline_count);
    for index in 0..timeline_count {
        timelines.push(events.create_timeline(&format!("owner-link-{index}"))?.id());
    }
    timelines.sort_unstable();
    let (gate, generation) = installed_gate(&mut events)?;
    let lease_start = SystemTrustedWallSourceV1.sample()?.as_micros() - DAY_MICROS;
    let first_timeline = *timelines.first().ok_or("empty owned Timeline set")?;
    let premise = lease(&policy, first_timeline, lease_start)?;
    Ok(World {
        registry,
        admitted,
        owner,
        sources,
        rtp1_bytes,
        policy,
        lease_start,
        premise,
        events,
        gate,
        generation,
        timelines,
        keys: coordinator_keys()?,
    })
}

/// A fail-closed gate holding the verified inventory of every world Timeline.
fn installed_gate(
    events: &mut MemoryStore,
) -> Fallible<(ErasureContainmentGateV1, ErasureReferenceV1)> {
    let limits = ErasureRecoveryLimitsV1::compiled_maximum();
    let snapshot = events.complete_erasure_inventory_snapshot_with_limits(limits)?;
    let mut query = ErasureVerifiedEmptyInventoryQueryV1::new(snapshot);
    let inventory = query.verified_inventory_with_limits(limits)?;
    let gate = ErasureContainmentGateV1::new_fail_closed();
    let generation = gate.install_verified_inventory(Arc::new(inventory), limits)?;
    Ok((gate, generation))
}

/// A ten-day admission window and a hundred-day retention tail.
fn lease(
    policy: &WorldRetentionPolicyV1,
    timeline_id: TimelineId,
    started_at_micros: u64,
) -> Fallible<WorldRetentionLeaseV1> {
    Ok(WorldRetentionLeaseV1::new(
        policy,
        WorldRetentionLeaseInputV1 {
            timeline_id,
            policy_hash: policy.digest(),
            started_at_micros,
            admission_closes_at_micros: started_at_micros + 10 * DAY_MICROS,
            retention_deadline_micros: started_at_micros + 110 * DAY_MICROS,
        },
    )?)
}

fn owner_id(world: &World) -> [u8; 32] {
    *ArtifactRegistrationV1::owner_reference(&world.owner).as_bytes()
}

/// The owner inventory generation that equals the erasure gate's.
const fn fenced_inventory(world: &World) -> Hash {
    Hash::from_bytes(world.generation.digest())
}

fn revalidated(world: &World, configuration_generation: u64) -> Fallible<AdmittedCompositionV1> {
    let catalog = world.admitted.catalog().as_input();
    let later = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: catalog.owner_id,
        configuration_generation,
        rows: catalog.rows.clone(),
    })?;
    Ok(world.registry.revalidate_manifest_registration(later)?)
}

/// Owner-policy classification recorded in every scope leaf.
#[derive(Clone, Copy)]
enum LeafPolicy {
    Structural,
    KeyedSchema(WorldArtifactKeyDependencyV1),
    PublicClosure,
}

fn classification(
    kind: WorldArtifactKindV1,
    policy: LeafPolicy,
) -> ManifestOwnerLeafClassificationV1 {
    let (data_class, key_dependencies) = match policy {
        LeafPolicy::KeyedSchema(key) if kind == WorldArtifactKindV1::Schema => {
            (ArtifactDataClassV1::StructuralAuditMetadata, vec![key])
        }
        LeafPolicy::PublicClosure if kind == WorldArtifactKindV1::OutputPolicyClosure => {
            (ArtifactDataClassV1::PublicRecord, Vec::new())
        }
        _ => (ArtifactDataClassV1::StructuralAuditMetadata, Vec::new()),
    };
    ManifestOwnerLeafClassificationV1 {
        data_class,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        key_dependencies,
    }
}

/// One complete admission of every world Timeline.
struct AdmissionPlan<'a> {
    admitted: &'a AdmittedCompositionV1,
    operation_id: Hash,
    lease_start: u64,
    leaves: LeafPolicy,
    resulting_inventory: Hash,
}

fn scope(
    world: &World,
    timeline_id: TimelineId,
    plan: &AdmissionPlan<'_>,
) -> Fallible<ManifestOwnerScopeV1> {
    let lease = lease(&world.policy, timeline_id, plan.lease_start)?;
    let source = ManifestOwnerScopeSourceV1 {
        owner_id: owner_id(world),
        timeline_id,
        rtp1_bytes: world.rtp1_bytes.clone(),
        rls1_bytes: lease.to_canonical_cbor(),
        consumer_references: vec![ManifestOwnerConsumerReferenceV1 {
            schema: hash(80),
            reducer: hash(79),
            runtime: hash(81),
        }],
        policy_sources: world
            .sources
            .iter()
            .map(|source| ManifestOwnerPolicySourceV1 {
                plugin_id: source.plugin_id(),
                eop1_bytes: source.eop1_bytes().to_vec(),
                opc1_bytes: source.opc1_bytes().to_vec(),
            })
            .collect(),
    };
    let leaves = plan.leaves;
    let classify = move |kind: WorldArtifactKindV1, _: Hash| Some(classification(kind, leaves));
    Ok(build_manifest_owner_scope_v1(&source, &classify)?)
}

fn reference_leaf(
    members: &ManifestOwnerScopeMembersV1,
    kind: WorldArtifactKindV1,
) -> Fallible<Hash> {
    let member = members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == kind);
    Ok(member.ok_or("missing reference leaf")?.leaf.digest())
}

/// WCS1 naming only the first Plugin; the second stays reducer-only.
fn consumer_set(world: &World, scope: &ManifestOwnerScopeV1) -> Fallible<WorldConsumerSetV1> {
    let producer = world.sources.first().ok_or("empty admitted Plugin set")?;
    let members = &scope.members;
    let consumer = WorldConsumerV1::new(
        "local-observer".to_owned(),
        reference_leaf(members, WorldArtifactKindV1::ReducerImplementation)?,
        reference_leaf(members, WorldArtifactKindV1::Schema)?,
        reference_leaf(members, WorldArtifactKindV1::RuntimeIdentity)?,
    )?;
    Ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope.scope,
        consumers: vec![consumer],
        producers: vec![WorldProducerV1::new(
            producer.plugin_id(),
            producer.eop1_native_digest(),
        )?],
        optional_view_roots: Vec::new(),
    })?)
}

/// Owner, admission, local-cut and owner-link ports of one same-store owner.
trait OwnerStore:
    ManifestOwnerAdmissionPersistencePortV1
    + LocalCutOwnerPersistencePortV1
    + ManifestOwnerLinkReadPortV1
{
}

impl<T> OwnerStore for T where
    T: ManifestOwnerAdmissionPersistencePortV1
        + LocalCutOwnerPersistencePortV1
        + ManifestOwnerLinkReadPortV1
{
}

fn admit<S: OwnerStore>(world: &World, store: &mut S, plan: &AdmissionPlan<'_>) -> TestResult {
    let prior = store.read_manifest_owner_state_v1(owner_id(world))?;
    let prior = prior.as_ref();
    let mut timelines = Vec::with_capacity(world.timelines.len());
    for timeline_id in &world.timelines {
        let scope = scope(world, *timeline_id, plan)?;
        timelines.push(ManifestOwnerTimelineAdmissionRequestV1 {
            timeline_id: *timeline_id,
            scope: scope.scope,
            wcs1: consumer_set(world, &scope)?,
            policy_copies: scope.policy_copies,
            members: scope.members,
        });
    }
    let request = ManifestOwnerAdmissionRequestV1 {
        operation_id: plan.operation_id,
        catalog: plan.admitted.catalog().clone(),
        expected_configuration_generation: prior.map(|state| state.configuration_generation),
        previous_visible_lcq1_hash: prior.and_then(|state| state.previous_visible_lcq1_hash),
        expected_inventory_generation: prior.map(|state| state.inventory_generation),
        resulting_inventory_generation: plan.resulting_inventory,
        read_limits: READ_LIMITS,
        timelines,
    };
    world
        .registry
        .commit_admitted_manifest_owner_admission_v1(plan.admitted, request, store)?;
    Ok(())
}

const fn genesis_plan(world: &World, operation_byte: u8, leaves: LeafPolicy) -> AdmissionPlan<'_> {
    AdmissionPlan {
        admitted: &world.admitted,
        operation_id: hash(operation_byte),
        lease_start: world.lease_start,
        leaves,
        resulting_inventory: hash(operation_byte.wrapping_add(1)),
    }
}

/// One visible cut of the owner's current admitted Timeline set.
struct CutPlan {
    cut_id: u64,
    operation_id: Hash,
    result_inventory: Hash,
}

/// The owner rows and previous recordings a cut request is built from.
struct CutInputs<'a> {
    owner_id: [u8; 32],
    state: &'a ManifestOwnerAdmissionOwnerStateV1,
    snapshots: &'a [ManifestOwnerAdmissionSnapshotV1],
    previous: &'a [LocalCutWorldRecordingV1],
    tick: u64,
    membership_epoch: u32,
}

fn table(row_count: usize, byte: u8) -> Fallible<LocalCutTableRefV1> {
    let rows = u64::try_from(row_count)?;
    Ok(LocalCutTableRefV1::new(
        rows,
        (rows != 0).then(|| hash(byte)),
    )?)
}

fn recorded_lease(snapshot: &ManifestOwnerAdmissionSnapshotV1) -> Fallible<Hash> {
    let lease = snapshot
        .timeline
        .members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == WorldArtifactKindV1::RetentionLease);
    Ok(lease
        .ok_or("missing recorded lease")?
        .leaf
        .as_input()
        .native_digest)
}

fn composition_rows(
    snapshots: &[ManifestOwnerAdmissionSnapshotV1],
) -> Vec<LocalCutCompositionBindingRowV1> {
    let mut rows = Vec::new();
    for snapshot in snapshots {
        rows.extend(snapshot.catalog.as_input().rows.iter().map(|row| {
            LocalCutCompositionBindingRowV1 {
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
    rows.sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
    rows
}

type ContextAndHeadRows = (
    Vec<LocalCutRecordingContextRowV1>,
    Vec<LocalCutExpectedHeadRowV1>,
);

fn context_and_head_rows(inputs: &CutInputs<'_>) -> Fallible<ContextAndHeadRows> {
    let mut contexts = Vec::with_capacity(inputs.snapshots.len());
    let mut heads = Vec::with_capacity(inputs.snapshots.len());
    for snapshot in inputs.snapshots {
        let timeline_id = snapshot.timeline.timeline_id;
        let predecessor_wcb_hash = inputs
            .previous
            .iter()
            .find(|recording| recording.binding.as_input().timeline_id == timeline_id)
            .map(|recording| recording.binding.digest());
        contexts.push(LocalCutRecordingContextRowV1 {
            timeline_id,
            wcs_hash: snapshot.timeline.wcs1.digest(),
            retention_lease_hash: recorded_lease(snapshot)?,
            predecessor_wcb_hash,
        });
        heads.push(LocalCutExpectedHeadRowV1 {
            timeline_id,
            logical_head: 0,
            stitched_chain_hash: SOURCE_GENESIS,
            source_timeline_id: timeline_id,
            source_segment_head: 0,
            source_chain_hash: SOURCE_GENESIS,
            logical_prefix: 0,
            lineage_proof_hash: None,
            predecessor_wcb_hash,
        });
    }
    Ok((contexts, heads))
}

/// Kind-5 rows naming the WCB1 that the owner derives for each Timeline.
fn result_heads(
    request: &LocalCutOwnerRequestV1,
    snapshots: &[ManifestOwnerAdmissionSnapshotV1],
) -> Fallible<Vec<LocalCutResultHeadRowV1>> {
    let mut rows = Vec::with_capacity(snapshots.len());
    for (snapshot, context) in snapshots.iter().zip(&request.recording_context_rows) {
        let closure = derive_local_cut_world_closure_v1(&LocalCutWorldClosureSourceV1 {
            operation_id: request.operation_id,
            seal: &request.seal,
            admission: snapshot,
            retention_lease_hash: context.retention_lease_hash,
            predecessor_binding_hash: context.predecessor_wcb_hash,
            genesis_hash: SOURCE_GENESIS,
        })?;
        rows.push(LocalCutResultHeadRowV1 {
            timeline_id: context.timeline_id,
            result_logical_head: 0,
            result_stitched_hash: SOURCE_GENESIS,
            result_source_segment_head: 0,
            result_source_chain_hash: SOURCE_GENESIS,
            successor_wcb_hash: closure.binding().digest(),
            event_count: 0,
        });
    }
    Ok(rows)
}

/// The kind-1, kind-8, kind-4 and kind-14 table references a seal names.
struct SealTables {
    composition: LocalCutTableRefV1,
    recording_context: LocalCutTableRefV1,
    expected_heads: LocalCutTableRefV1,
    manifest_binding: LocalCutTableRefV1,
}

fn cut_seal(
    inputs: &CutInputs<'_>,
    plan: &CutPlan,
    tables: &SealTables,
) -> Fallible<LocalCutSealV2> {
    Ok(LocalCutSealV2::new(LocalCutSealInputV2 {
        owner_id: inputs.owner_id,
        cut_id: plan.cut_id,
        tick: inputs.tick,
        membership_epoch: inputs.membership_epoch,
        configuration_generation: inputs.state.configuration_generation,
        schedule_ns: 0,
        previous_visible_receipt_hash: inputs.state.previous_visible_lcq1_hash,
        expected_inventory_generation: inputs.state.inventory_generation,
        membership_table: table(inputs.snapshots.len(), 94)?,
        composition_table: tables.composition,
        inbox_table: table(0, 95)?,
        invocation_table: table(0, 96)?,
        expected_heads_table: tables.expected_heads,
        ebp_native_hash: hash(98),
        execution_profile_native_hash: hash(99),
        recording_context_table: tables.recording_context,
        owner_operational_policy_hash: hash(100),
        explicit_attempt_hash: None,
        ingress_preallocation_native_hash: hash(101),
        manifest_binding_table: tables.manifest_binding,
    })?)
}

fn cut_request(inputs: &CutInputs<'_>, plan: &CutPlan) -> Fallible<LocalCutOwnerRequestV1> {
    let binding_rows = inputs
        .snapshots
        .iter()
        .map(|snapshot| LocalCutManifestBindingRowV1 {
            timeline_id: snapshot.timeline.timeline_id,
            scope: snapshot.timeline.scope,
            wcs_hash: snapshot.timeline.wcs1.digest(),
            msr_hash: snapshot.timeline.receipt.digest(),
            msb_hash: snapshot.timeline.binding.digest(),
        })
        .collect();
    let manifest_binding_table =
        LocalCutManifestBindingTableV1::new(inputs.owner_id, plan.cut_id, binding_rows)?;
    let composition_rows = composition_rows(inputs.snapshots);
    let (recording_context_rows, expected_head_rows) = context_and_head_rows(inputs)?;
    let expected_heads =
        LocalCutHeadsTableV1::expected_heads(inputs.owner_id, plan.cut_id, &expected_head_rows)?;
    let tables = SealTables {
        composition: table(composition_rows.len(), 92)?,
        recording_context: table(recording_context_rows.len(), 93)?,
        expected_heads: expected_heads.table_ref(),
        manifest_binding: manifest_binding_table.table_ref(),
    };
    let mut request = LocalCutOwnerRequestV1 {
        operation_id: plan.operation_id,
        seal: cut_seal(inputs, plan, &tables)?,
        manifest_hash: hash(103),
        manifest_binding_table,
        composition_rows,
        recording_context_rows,
        expected_head_rows,
        result_head_rows: Vec::new(),
        partition_ledger_seq: plan.cut_id,
        result_heads_table: table(0, 105)?,
        participant_successor_table: table(1, 106)?,
        cpu_completion_table: table(0, 107)?,
        action_disposition_table: table(1, 108)?,
        candidate_bases_table: table(0, 109)?,
        invocation_bridges_table: table(0, 110)?,
        result_inventory_generation: plan.result_inventory,
        release_fence_proof_digest: hash(112),
    };
    request.result_head_rows = result_heads(&request, inputs.snapshots)?;
    let rows = &request.result_head_rows;
    let result_table = LocalCutHeadsTableV1::result_heads(inputs.owner_id, plan.cut_id, rows)?;
    request.result_heads_table = result_table.table_ref();
    Ok(request)
}

fn admitted_snapshot<S: OwnerStore>(
    store: &S,
    owner_id: [u8; 32],
    configuration_generation: u64,
    timeline_id: TimelineId,
) -> Fallible<ManifestOwnerAdmissionSnapshotV1> {
    let snapshot =
        store.read_manifest_owner_admission_v1(owner_id, configuration_generation, timeline_id)?;
    Ok(snapshot.ok_or("missing admitted owner snapshot")?)
}

fn commit_cut<S: OwnerStore>(
    world: &World,
    admitted: &AdmittedCompositionV1,
    store: &mut S,
    plan: &CutPlan,
) -> Fallible<LocalCutOwnerCommitV1> {
    let owner_id = owner_id(world);
    let state = store.read_manifest_owner_state_v1(owner_id)?;
    let state = state.ok_or("missing admitted owner state")?;
    let generation = state.configuration_generation;
    let reader: &S = store;
    let snapshots = state
        .timelines
        .iter()
        .map(|timeline_id| admitted_snapshot(reader, owner_id, generation, *timeline_id))
        .collect::<Fallible<Vec<_>>>()?;
    let local = store.read_local_cut_owner_state_v1(owner_id)?;
    let local = local.as_ref();
    let last_cut = local.map_or(0, |local| local.last_visible_cut_id);
    let previous = store.read_local_cut_owner_commit_v1(owner_id, last_cut)?;
    let previous = previous.map(|cut| cut.recordings).unwrap_or_default();
    let inputs = CutInputs {
        owner_id,
        state: &state,
        snapshots: &snapshots,
        previous: &previous,
        tick: local.map_or(1, |local| local.last_visible_tick + 1),
        membership_epoch: local.map_or(0, |local| local.membership_epoch),
    };
    let request = cut_request(&inputs, plan)?;
    let committed = world
        .registry
        .commit_admitted_local_cut_owner_v1(admitted, request, store)?;
    assert_eq!(committed.kind, LocalCutOwnerCommitKindV1::Applied);
    Ok(committed)
}

const fn cut_plan(cut_id: u64, operation_byte: u8, result_inventory: Hash) -> CutPlan {
    CutPlan {
        cut_id,
        operation_id: hash(operation_byte),
        result_inventory,
    }
}

fn first_recording(cut: &LocalCutOwnerCommitV1) -> Fallible<&LocalCutWorldRecordingV1> {
    Ok(cut.recordings.first().ok_or("missing cut recording")?)
}

const fn link_request(
    world: &World,
    recording: &LocalCutWorldRecordingV1,
    identity: ManifestOwnerLinkCutIdentityV1,
) -> ManifestOwnerLinkRequestV1 {
    let binding = recording.binding.as_input();
    ManifestOwnerLinkRequestV1 {
        owner: world.owner,
        identity,
        timeline_id: binding.timeline_id,
        expected_head: ManifestOwnerLinkHeadV1 {
            logical_head: binding.logical_head,
            stitched_head_hash: binding.stitched_head_hash,
        },
        expected_scope: recording.scope,
    }
}

fn by_recording(world: &World, recording: &LocalCutWorldRecordingV1) -> ManifestOwnerLinkRequestV1 {
    let identity =
        ManifestOwnerLinkCutIdentityV1::WorldRecordingReceipt(recording.receipt.digest());
    link_request(world, recording, identity)
}

fn by_cut(
    world: &World,
    cut: &LocalCutOwnerCommitV1,
    recording: &LocalCutWorldRecordingV1,
) -> ManifestOwnerLinkRequestV1 {
    let identity = ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(cut.receipt.digest());
    link_request(world, recording, identity)
}

/// How the trusted-clock release of one verification is presented.
#[derive(Clone, Copy)]
enum Release {
    Current,
    ForeignExpiries,
    LateFinalSample,
}

/// Every fresh-use fence of one verification.
#[derive(Clone, Copy)]
struct Fences<'a> {
    gate: &'a ErasureContainmentGateV1,
    keys: &'a KeyRegistryStateV1,
    premise: &'a WorldRetentionLeaseV1,
    release: Release,
}

/// The current fences, whose premise lease is the lease of every scope.
///
/// The earliest applicable expiry therefore equals the premise deadline, so
/// every verification under these fences exercises the inclusive
/// `E_min <= deadline` boundary of the fresh-use fence.
const fn current(world: &World) -> Fences<'_> {
    Fences {
        gate: &world.gate,
        keys: &world.keys,
        premise: &world.premise,
        release: Release::Current,
    }
}

fn principal() -> Fallible<AuthenticatedPrincipalResultV1> {
    let far = SystemTrustedWallSourceV1.sample()?.as_micros() + 1_000 * DAY_MICROS;
    let draft = AuthenticatedPrincipalDraftV1 {
        principal: PrincipalRefV1::try_new([1; 16], "operators")?,
        adapter_id: "test-passkey".to_owned(),
        assurance: AssuranceLevelV1::try_new(2)?,
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(far),
        binding_digest: hash(7),
    };
    Ok(AuthenticatedPrincipalResultV1::try_from_draft(draft)?)
}

/// Hold a release guard whose expiries cover `premise` and an access grant.
fn guarded<'p>(
    port: &'p mut MemoryTrustedClockAuthorityV1,
    premise: &WorldRetentionLeaseV1,
) -> Fallible<(ReleaseGuardV1<'p>, ApplicableExpiriesV1)> {
    let mut store = port.handle();
    let mut wall = SystemTrustedWallSourceV1;
    let mut mono = SystemGuardMonotonicSourceV1;
    let mut wait = WaitBudgetV1::new();
    let reservation = reserve_trusted_clock(&mut store, &mut wall, &mut mono, &mut wait, None)?;
    let guard = open_release_guard(port, reservation, &mut wait, &mut mono)?;
    let access = principal()?;
    let premises = ExpiryPremisesV1 {
        retention_leases: std::slice::from_ref(premise),
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let expiries = guard.applicable_expiries(&premises)?;
    Ok((guard, expiries))
}

/// Verify one request through the installed registry seam.
fn verify<S: ManifestOwnerLinkReadPortV1>(
    registry: &PluginRegistry,
    store: &S,
    request: &ManifestOwnerLinkRequestV1,
    fences: Fences<'_>,
) -> Fallible<LinkResult> {
    let mut clock = MemoryTrustedClockAuthorityV1::new();
    let mut foreign = MemoryTrustedClockAuthorityV1::new();
    let (guard, held_expiries) = guarded(&mut clock, fences.premise)?;
    let (foreign_guard, foreign_expiries) = guarded(&mut foreign, fences.premise)?;
    drop(foreign_guard);
    let late = guard.reservation().decision_bound().as_micros() + DAY_MICROS;
    let mut late_wall = ScriptedTrustedWallSourceV1::from_micros([late]);
    let mut system_wall = SystemTrustedWallSourceV1;
    let mut mono = SystemGuardMonotonicSourceV1;
    let expiries = match fences.release {
        Release::ForeignExpiries => &foreign_expiries,
        Release::Current | Release::LateFinalSample => &held_expiries,
    };
    let wall: &mut dyn TrustedWallSourceV1 = match fences.release {
        Release::LateFinalSample => &mut late_wall,
        Release::Current | Release::ForeignExpiries => &mut system_wall,
    };
    let fence = ManifestOwnerLinkUseFenceV1 {
        guard,
        expiries,
        erasure_gate: fences.gate,
        keys: fences.keys,
        wall,
        mono: &mut mono,
    };
    let released = registry.verify_manifest_owner_link_v1(store, request, fence);
    Ok(released.map(|released| {
        assert_eq!(released.overrun_signal(), None);
        released.value().clone()
    }))
}

/// Serves one owner's real snapshot after a test edit, whatever owner is asked.
struct CraftedStore<'a, S> {
    inner: &'a S,
    owner_id: [u8; 32],
    edit: &'a dyn Fn(&mut ManifestOwnerLinkSnapshotV1),
}

impl<S: ManifestOwnerLinkReadPortV1> ManifestOwnerLinkReadPortV1 for CraftedStore<'_, S> {
    fn read_manifest_owner_link_snapshot_v1(
        &self,
        _owner_id: [u8; 32],
        identity: ManifestOwnerLinkCutIdentityV1,
        timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerLinkSnapshotV1>, LocalCutOwnerErrorV1> {
        let found =
            self.inner
                .read_manifest_owner_link_snapshot_v1(self.owner_id, identity, timeline_id);
        found.map(|snapshot| {
            snapshot.map(|mut snapshot| {
                (self.edit)(&mut snapshot);
                snapshot
            })
        })
    }
}

/// An owner store whose snapshot read fails.
struct UnavailableStore;

impl ManifestOwnerLinkReadPortV1 for UnavailableStore {
    fn read_manifest_owner_link_snapshot_v1(
        &self,
        _owner_id: [u8; 32],
        _identity: ManifestOwnerLinkCutIdentityV1,
        _timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerLinkSnapshotV1>, LocalCutOwnerErrorV1> {
        Err(LocalCutOwnerErrorV1::StorageFailure)
    }
}

fn read_snapshot<S: ManifestOwnerLinkReadPortV1>(
    world: &World,
    store: &S,
    request: &ManifestOwnerLinkRequestV1,
) -> Fallible<ManifestOwnerLinkSnapshotV1> {
    let owner = owner_id(world);
    let (identity, timeline_id) = (request.identity, request.timeline_id);
    let snapshot = store.read_manifest_owner_link_snapshot_v1(owner, identity, timeline_id)?;
    Ok(snapshot.ok_or("missing owner-link snapshot")?)
}

/// Verify `request` against the store's snapshot after each edit.
fn assert_edits<S: ManifestOwnerLinkReadPortV1>(
    world: &World,
    store: &S,
    request: &ManifestOwnerLinkRequestV1,
    cases: Vec<(Edit, LinkError)>,
) -> TestResult {
    for (edit, expected) in cases {
        let crafted = CraftedStore {
            inner: store,
            owner_id: owner_id(world),
            edit: edit.as_ref(),
        };
        let verified = verify(&world.registry, &crafted, request, current(world))?;
        assert_eq!(verified.err(), Some(expected));
    }
    Ok(())
}

/// A two-Timeline owner with three visible zero-output cuts in generation 1.
fn three_cut_world() -> Fallible<(World, MemoryStore, Vec<LocalCutOwnerCommitV1>)> {
    let world = world(2)?;
    let mut store = memory_owner()?;
    let genesis = genesis_plan(&world, 0x11, LeafPolicy::Structural);
    admit(&world, &mut store, &genesis)?;
    let mut cuts = Vec::with_capacity(3);
    for (cut_id, operation, inventory) in [(1, 0x13, hash(0x14)), (2, 0x15, hash(0x16))] {
        let plan = cut_plan(cut_id, operation, inventory);
        cuts.push(commit_cut(&world, &world.admitted, &mut store, &plan)?);
    }
    let last = cut_plan(3, 0x17, fenced_inventory(&world));
    cuts.push(commit_cut(&world, &world.admitted, &mut store, &last)?);
    Ok((world, store, cuts))
}

#[test]
fn zero_output_reducer_and_same_name_plugins_verify_by_either_identity() -> TestResult {
    let world = world(1)?;
    let mut store = memory_owner()?;
    let genesis = genesis_plan(&world, 0x11, LeafPolicy::Structural);
    admit(&world, &mut store, &genesis)?;
    let plan = cut_plan(1, 0x13, fenced_inventory(&world));
    let cut = commit_cut(&world, &world.admitted, &mut store, &plan)?;
    let recording = first_recording(&cut)?;
    let request = by_recording(&world, recording);
    let link = verify(&world.registry, &store, &request, current(&world))??;

    let snapshot = read_snapshot(&world, &store, &request)?;
    let admission = snapshot.admissions.first().ok_or("missing admission")?;
    let catalog = &admission.catalog.as_input().rows;
    assert_eq!(catalog.len(), 2);
    assert_eq!(catalog[0].plugin_name, catalog[1].plugin_name);
    assert_ne!(catalog[0].plugin_id, catalog[1].plugin_id);
    assert_eq!(admission.timeline.binding.as_input().rows.len(), 2);
    assert_eq!(admission.timeline.wcs1.producers().len(), 1);
    assert_eq!(admission.timeline.policy_copies.len(), 2);

    let digests = ManifestOwnerLinkDigestsV1 {
        lcs2: cut.seal.digest(),
        lcc1: cut.commit.digest(),
        lcq1: cut.receipt.digest(),
        wcb1: recording.binding.digest(),
        wcr1: recording.receipt.digest(),
        mca1: world.admitted.catalog().digest(),
        msr1: admission.timeline.receipt.digest(),
        msb1: admission.timeline.binding.digest(),
        wcs1: admission.timeline.wcs1.digest(),
    };
    let expected = test_verified_manifest_owner_link(&request, 1, 1, &digests, world.generation);
    assert_eq!(link, expected);
    assert_eq!(link.owner_id(), owner_id(&world));
    assert_eq!(link.cut_id(), 1);
    assert_eq!(link.timeline_id(), request.timeline_id);
    assert_eq!(link.configuration_generation(), 1);
    assert_eq!(link.scope(), recording.scope);
    assert_eq!(link.digests(), digests);
    assert_eq!(link.head().stitched_head_hash, SOURCE_GENESIS);
    assert_eq!(link.inventory_generation(), world.generation);
    assert_eq!(
        link.require_exact_claim(),
        Err(LinkError::ClosureUnavailable)
    );
    let by_lcq1 = verify(
        &world.registry,
        &store,
        &by_cut(&world, &cut, recording),
        current(&world),
    )??;
    assert_eq!(by_lcq1, link);
    Ok(())
}

#[test]
fn separate_same_head_cuts_stay_distinct_and_pairings_must_match() -> TestResult {
    let (world, store, cuts) = three_cut_world()?;
    let mut links = Vec::new();
    for cut in &cuts {
        let request = by_recording(&world, first_recording(cut)?);
        let link = verify(&world.registry, &store, &request, current(&world))??;
        assert_eq!(link.cut_id(), cut.seal.as_input().cut_id);
        assert_eq!(link.digests().lcq1, cut.receipt.digest());
        links.push(link);
    }
    assert_eq!(links[0].head(), links[1].head());
    assert_eq!(links[0].scope(), links[1].scope());
    assert_ne!(links[0].digests().wcb1, links[1].digests().wcb1);

    let first = first_recording(&cuts[0])?;
    let other = cuts[0].recordings.get(1);
    let other = other.ok_or("missing second recording")?;
    let by_lcq1 = by_cut(&world, &cuts[0], other);
    let second_link = verify(&world.registry, &store, &by_lcq1, current(&world))??;
    let second_timeline = other.binding.as_input().timeline_id;
    assert_eq!(second_link.timeline_id(), second_timeline);
    let by_wcr1 = by_recording(&world, other);
    let second_by_wcr1 = verify(&world.registry, &store, &by_wcr1, current(&world))??;
    assert_eq!(second_by_wcr1, second_link);
    let wrong_cut = Some(LinkError::WrongCut);
    let paired = |request: &ManifestOwnerLinkRequestV1| {
        verify(&world.registry, &store, request, current(&world)).map(Result::err)
    };
    let foreign_timeline = ManifestOwnerLinkRequestV1 {
        timeline_id: other.binding.as_input().timeline_id,
        ..by_recording(&world, first)
    };
    assert_eq!(paired(&foreign_timeline)?, wrong_cut);
    let owner = owner_id(&world);
    let (identity, timeline_id) = (foreign_timeline.identity, foreign_timeline.timeline_id);
    let unpaired = store.read_manifest_owner_link_snapshot_v1(owner, identity, timeline_id)?;
    assert_eq!(unpaired, None);
    let unknown_cut = ManifestOwnerLinkRequestV1 {
        identity: ManifestOwnerLinkCutIdentityV1::LocalCutReceipt(hash(0x55)),
        ..by_recording(&world, first)
    };
    assert_eq!(paired(&unknown_cut)?, wrong_cut);
    let later_head = ManifestOwnerLinkRequestV1 {
        expected_head: ManifestOwnerLinkHeadV1 {
            logical_head: 1,
            stitched_head_hash: SOURCE_GENESIS,
        },
        ..by_recording(&world, first)
    };
    assert_eq!(paired(&later_head)?, wrong_cut);
    let mut restitched = by_recording(&world, first);
    restitched.expected_head.stitched_head_hash = hash(0x56);
    assert_eq!(paired(&restitched)?, wrong_cut);
    let other_scope = ManifestOwnerLinkRequestV1 {
        expected_scope: other.scope,
        ..by_recording(&world, first)
    };
    assert_eq!(paired(&other_scope)?, wrong_cut);
    let other_owner = ManifestOwnerLinkRequestV1 {
        owner: OwnerIdV1::from_static("another-owner"),
        ..by_recording(&world, first)
    };
    assert_eq!(paired(&other_owner)?, wrong_cut);
    Ok(())
}

/// Two cuts in generation 1, then a generation-2 scope replacement with an
/// earlier lease and one more cut; `premise` is the replacement lease.
struct History {
    cuts: Vec<LocalCutOwnerCommitV1>,
    premise: WorldRetentionLeaseV1,
}

fn replaced_history<S: OwnerStore>(world: &World, store: &mut S) -> Fallible<History> {
    let genesis = genesis_plan(world, 0x21, LeafPolicy::Structural);
    admit(world, store, &genesis)?;
    let mut cuts = Vec::with_capacity(3);
    for (cut_id, operation, inventory) in [(1, 0x23, hash(0x24)), (2, 0x25, hash(0x26))] {
        let plan = cut_plan(cut_id, operation, inventory);
        cuts.push(commit_cut(world, &world.admitted, store, &plan)?);
    }
    let replacement = revalidated(world, 2)?;
    let lease_start = world.lease_start - DAY_MICROS;
    let plan = AdmissionPlan {
        admitted: &replacement,
        operation_id: hash(0x27),
        lease_start,
        leaves: LeafPolicy::Structural,
        resulting_inventory: hash(0x28),
    };
    admit(world, store, &plan)?;
    let last = cut_plan(3, 0x29, fenced_inventory(world));
    cuts.push(commit_cut(world, &replacement, store, &last)?);
    let timeline_id = *world.timelines.first().ok_or("missing Timeline")?;
    let premise = lease(&world.policy, timeline_id, lease_start)?;
    Ok(History { cuts, premise })
}

/// Verify every historical cut, then require the old cut to keep its scope.
fn verify_history<S: ManifestOwnerLinkReadPortV1>(
    world: &World,
    store: &S,
    history: &History,
) -> Fallible<Vec<VerifiedManifestOwnerLinkV1>> {
    let fences = Fences {
        premise: &history.premise,
        ..current(world)
    };
    let mut links = Vec::with_capacity(history.cuts.len());
    for (cut, generation) in history.cuts.iter().zip([1, 1, 2]) {
        let request = by_recording(world, first_recording(cut)?);
        let link = verify(&world.registry, store, &request, fences)??;
        assert_eq!(link.cut_id(), cut.seal.as_input().cut_id);
        assert_eq!(link.configuration_generation(), generation);
        links.push(link);
    }
    let first = links.first().ok_or("missing first link")?;
    let last = links.last().ok_or("missing last link")?;
    assert_ne!(first.scope(), last.scope());
    assert_ne!(first.digests().mca1, last.digests().mca1);
    assert_ne!(first.digests().msr1, last.digests().msr1);
    let old_cut = history.cuts.first().ok_or("missing first cut")?;
    let reinterpreted = ManifestOwnerLinkRequestV1 {
        expected_scope: last.scope(),
        ..by_recording(world, first_recording(old_cut)?)
    };
    assert_eq!(
        verify(&world.registry, store, &reinterpreted, fences)?.err(),
        Some(LinkError::WrongCut)
    );
    Ok(links)
}

#[test]
fn historical_cuts_survive_generation_and_scope_replacement_on_both_stores() -> TestResult {
    let world = world(1)?;
    let mut memory = memory_owner()?;
    let history = replaced_history(&world, &mut memory)?;
    let memory_links = verify_history(&world, &memory, &history)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-link.sqlite");
    let path = path.to_str().ok_or("non-UTF8 test path")?;
    let mut sqlite = sqlite_owner(path)?;
    let sqlite_history = replaced_history(&world, &mut sqlite)?;
    assert_eq!(sqlite_history.cuts, history.cuts);
    drop(sqlite);
    let reopened = SqliteStore::open(path)?;
    let reopened_links = verify_history(&world, &reopened, &sqlite_history)?;
    assert_eq!(reopened_links, memory_links);
    for cut in &history.cuts {
        let request = by_recording(&world, first_recording(cut)?);
        let stored = read_snapshot(&world, &reopened, &request)?;
        assert_eq!(stored, read_snapshot(&world, &memory, &request)?);
    }
    Ok(())
}

#[test]
fn a_later_generation_admission_cannot_stand_for_a_historical_cut() -> TestResult {
    let world = world(1)?;
    let mut store = memory_owner()?;
    let history = replaced_history(&world, &mut store)?;
    let first = first_recording(history.cuts.first().ok_or("missing first cut")?)?;
    let last = first_recording(history.cuts.last().ok_or("missing last cut")?)?;
    let late = read_snapshot(&world, &store, &by_recording(&world, last))?.admissions;
    let late = late.first().ok_or("missing late admission")?.clone();
    let substituted = (
        edit(move |snapshot| snapshot.admissions = vec![late.clone()]),
        LinkError::CompositionUnavailable,
    );
    let request = by_recording(&world, first);
    assert_edits(&world, &store, &request, vec![substituted])
}

#[test]
fn ancestor_walks_stop_at_the_admission_or_another_generation() -> TestResult {
    let world = world(1)?;
    let mut store = memory_owner()?;
    let history = replaced_history(&world, &mut store)?;
    let [first, second, last] = history.cuts.as_slice() else {
        return Err("expected three cuts".into());
    };
    let ancestor = ManifestOwnerLinkAncestorV1::of_result;
    let request = by_recording(&world, first_recording(second)?);
    let snapshot = read_snapshot(&world, &store, &request)?;
    let admission = snapshot.admissions.first().ok_or("missing admission")?;
    let walked = collect_manifest_owner_link_ancestors_v1(
        second.seal.as_input(),
        admission,
        [Ok(ancestor(first)), Err("an unread cut")],
    )?;
    assert_eq!(walked, vec![ancestor(first)]);
    assert_eq!(walked, snapshot.ancestors);
    let crossed = collect_manifest_owner_link_ancestors_v1(
        last.seal.as_input(),
        admission,
        [Ok::<_, &str>(ancestor(second)), Ok(ancestor(first))],
    )?;
    assert!(crossed.is_empty());
    let unlinked = collect_manifest_owner_link_ancestors_v1(
        second.seal.as_input(),
        admission,
        [Ok::<_, &str>(ancestor(second)), Ok(ancestor(first))],
    )?;
    assert!(unlinked.is_empty());
    let failed = collect_manifest_owner_link_ancestors_v1(
        second.seal.as_input(),
        admission,
        [Err::<ManifestOwnerLinkAncestorV1, _>("an unreadable cut")],
    );
    assert_eq!(failed, Err("an unreadable cut"));
    Ok(())
}

#[test]
fn branch_walks_stop_at_the_admitted_node_limit() -> TestResult {
    let (world, store, request) = crafted_base()?;
    let snapshot = read_snapshot(&world, &store, &request)?;
    let recording = first_recording(&snapshot.result)?;
    let root = recording.binding.as_input().dependency_root_hash;
    let retained = |digest: Hash| {
        let node = snapshot.dependency_branches.get(&digest);
        Ok::<_, LocalCutOwnerErrorV1>(node.cloned())
    };
    let limit = READ_LIMITS.max_node_visits;
    let nodes = collect_manifest_owner_link_branches_v1(root, limit, retained)?;
    assert_eq!(nodes, snapshot.dependency_branches);
    // The walk accepts exactly as many nodes as the limit and rejects one more.
    let exact = u64::try_from(nodes.len())?;
    let at_limit = collect_manifest_owner_link_branches_v1(root, exact, retained)?;
    assert_eq!(at_limit, nodes);
    let bounded = collect_manifest_owner_link_branches_v1(root, exact - 1, retained);
    assert_eq!(bounded, Err(LocalCutOwnerErrorV1::BoundExceeded));
    Ok(())
}

#[test]
fn fresh_use_fences_deny_stale_closed_or_uncovered_protected_use() -> TestResult {
    let mut world = world(1)?;
    let (frozen, _) = installed_gate(&mut world.events)?;
    let (closing, _) = installed_gate(&mut world.events)?;
    let mut store = memory_owner()?;
    let genesis = genesis_plan(&world, 0x31, LeafPolicy::Structural);
    admit(&world, &mut store, &genesis)?;
    let first_cut = cut_plan(1, 0x33, hash(0x34));
    let stale = commit_cut(&world, &world.admitted, &mut store, &first_cut)?;
    let request = by_recording(&world, first_recording(&stale)?);
    frozen.freeze_timeline_for_test(request.timeline_id);
    let denied = Some(LinkError::ProtectedUseDenied);
    let stale_link = verify(&world.registry, &store, &request, current(&world))?;
    assert_eq!(stale_link.err(), denied);
    let plan = cut_plan(2, 0x35, fenced_inventory(&world));
    commit_cut(&world, &world.admitted, &mut store, &plan)?;
    assert!(verify(&world.registry, &store, &request, current(&world))?.is_ok());

    let later_start = world.lease_start + DAY_MICROS;
    let later = lease(&world.policy, request.timeline_id, later_start)?;
    let open = ErasureContainmentGateV1::new_test_open();
    let refused = [
        Fences {
            premise: &later,
            ..current(&world)
        },
        Fences {
            release: Release::ForeignExpiries,
            ..current(&world)
        },
        Fences {
            release: Release::LateFinalSample,
            ..current(&world)
        },
        Fences {
            gate: &open,
            ..current(&world)
        },
        Fences {
            gate: &frozen,
            ..current(&world)
        },
    ];
    for fences in refused {
        let refused_link = verify(&world.registry, &store, &request, fences)?;
        assert_eq!(refused_link.err(), denied);
    }
    let poison = |_: &mut ManifestOwnerLinkSnapshotV1| closing.poison();
    let closing_store = CraftedStore {
        inner: &store,
        owner_id: owner_id(&world),
        edit: &poison,
    };
    let fences = Fences {
        gate: &closing,
        ..current(&world)
    };
    let closed_link = verify(&world.registry, &closing_store, &request, fences)?;
    assert_eq!(closed_link.err(), denied);
    Ok(())
}

fn keyed_store(
    world: &World,
    dependency: WorldArtifactKeyDependencyV1,
) -> Fallible<(MemoryStore, ManifestOwnerLinkRequestV1)> {
    let mut store = memory_owner()?;
    let plan = genesis_plan(world, 0x41, LeafPolicy::KeyedSchema(dependency));
    admit(world, &mut store, &plan)?;
    let first_cut = cut_plan(1, 0x43, fenced_inventory(world));
    let cut = commit_cut(world, &world.admitted, &mut store, &first_cut)?;
    let request = by_recording(world, first_recording(&cut)?);
    Ok((store, request))
}

fn key_identity_digest(identity: KeyIdentityV1) -> Fallible<Hash> {
    let evidence = WorldKeyEvidenceV1::new(WorldKeyEvidenceInputV1 {
        identity,
        private_material_digest: hash(0x40),
        private_material_required: true,
        public_verification_key: None,
    })?;
    Ok(evidence.identity_digest())
}

// Leaf key dependencies keep the active-epoch rule; coordinator receipts
// instead resolve their retained WKE1 (see the rotation test below).
#[test]
fn key_dependencies_must_name_the_owners_active_live_key() -> TestResult {
    let mut world = world(1)?;
    let role = KeyRoleV1::SubjectDataEncryption;
    let first_key = KeyIdentityV1::new(world.owner, role, 1);
    let dependency = WorldArtifactKeyDependencyV1 {
        role,
        identity_digest: key_identity_digest(first_key)?,
        owner: owner_id(&world),
    };
    let (store, request) = keyed_store(&world, dependency)?;
    let denied = Some(LinkError::ProtectedUseDenied);
    let unregistered = verify(&world.registry, &store, &request, current(&world))?;
    assert_eq!(unregistered.err(), denied);
    let registration = KeyRegistrationV1::new(first_key, hash(0x44), None);
    let registered = world.keys.register_key(registration)?;
    assert_eq!(registered, KeyRegistrationOutcomeV1::Registered);
    let link = verify(&world.registry, &store, &request, current(&world))??;
    assert_eq!(link.cut_id(), 1);

    let second_key = KeyIdentityV1::new(world.owner, role, 2);
    let rotation = KeyRegistrationV1::new(second_key, hash(0x45), None);
    let rotated = world.keys.register_key(rotation)?;
    assert_eq!(rotated, KeyRegistrationOutcomeV1::Registered);
    let retired = verify(&world.registry, &store, &request, current(&world))?;
    assert_eq!(retired.err(), denied);
    let foreign = WorldArtifactKeyDependencyV1 {
        identity_digest: key_identity_digest(second_key)?,
        owner: [0x46; 32],
        ..dependency
    };
    let (foreign_store, foreign_request) = keyed_store(&world, foreign)?;
    let fences = current(&world);
    let foreign_link = verify(&world.registry, &foreign_store, &foreign_request, fences)?;
    assert_eq!(foreign_link.err(), denied);
    let owned = WorldArtifactKeyDependencyV1 {
        owner: owner_id(&world),
        ..foreign
    };
    let (owned_store, owned_request) = keyed_store(&world, owned)?;
    let owned_link = verify(&world.registry, &owned_store, &owned_request, fences)?;
    assert!(owned_link.is_ok());
    Ok(())
}

#[test]
fn installed_hooks_reject_forged_receipts_and_missing_authority() -> TestResult {
    let world = world(1)?;
    let mut store = memory_owner()?;
    let genesis = genesis_plan(&world, 0x51, LeafPolicy::Structural);
    admit(&world, &mut store, &genesis)?;
    let plan = cut_plan(1, 0x53, fenced_inventory(&world));
    let cut = commit_cut(&world, &world.admitted, &mut store, &plan)?;
    let request = by_recording(&world, first_recording(&cut)?);
    let installed = installed()?;
    let forged_cut = owner_registry(hooks(FORGED_EVIDENCE, installed.admission));
    let forged_role = owner_registry(hooks(installed.local_cut, FORGED_EVIDENCE));
    let unbound = PluginRegistry::new_with_manifest_owner_admission_verifier(installed);
    let rejected = [
        (&forged_cut, LinkError::WrongCut),
        (&forged_role, LinkError::CompositionUnavailable),
        (&unbound, LinkError::CompositionUnavailable),
    ];
    for (registry, expected) in rejected {
        let rejected_link = verify(registry, &store, &request, current(&world))?;
        assert_eq!(rejected_link.err(), Some(expected));
    }
    let fences = current(&world);
    let unavailable = verify(&world.registry, &UnavailableStore, &request, fences)?;
    assert_eq!(unavailable.err(), Some(LinkError::CompositionUnavailable));
    Ok(())
}

/// One owner with one visible cut, and the WCR1 request that selects it.
fn signed_cut<S: OwnerStore>(world: &World, store: &mut S) -> Fallible<ManifestOwnerLinkRequestV1> {
    let genesis = genesis_plan(world, 0x71, LeafPolicy::Structural);
    admit(world, store, &genesis)?;
    let plan = cut_plan(1, 0x73, fenced_inventory(world));
    let cut = commit_cut(world, &world.admitted, store, &plan)?;
    Ok(by_recording(world, first_recording(&cut)?))
}

#[test]
fn coordinator_receipts_verify_after_their_key_is_rotated_or_tombstoned() -> TestResult {
    let mut world = world(1)?;
    let mut store = memory_owner()?;
    let request = signed_cut(&world, &mut store)?;
    let signed = verify(&world.registry, &store, &request, current(&world))??;
    let evidence = *coordinator_evidence()?.as_input();
    let identity = evidence.identity;
    let next_epoch = KeyIdentityV1::new(COORDINATOR, identity.role, 2);
    let next_key = Some(PublicKey::from_bytes([0xc4; 32]));
    let rotation = KeyRegistrationV1::new(next_epoch, hash(0xc3), next_key);
    assert_eq!(
        world.keys.register_key(rotation)?,
        KeyRegistrationOutcomeV1::Registered
    );
    let rotated = verify(&world.registry, &store, &request, current(&world))??;
    assert_eq!(rotated, signed);
    let material = evidence.private_material_digest;
    let destruction = KeyDestructionRequestV1::new(identity, material, hash(0xc5));
    world.keys.begin_key_destruction(destruction)?;
    let receipt = deletion_receipt(&destruction);
    world.keys.complete_key_destruction(destruction, receipt)?;
    assert!(world.keys.tombstone(identity).is_some());
    let tombstoned = verify(&world.registry, &store, &request, current(&world))??;
    assert_eq!(tombstoned, signed);
    Ok(())
}

#[test]
fn coordinator_evidence_must_be_retained_and_match_the_installed_registry() -> TestResult {
    let world = world(1)?;
    let mut store = memory_owner()?;
    let request = signed_cut(&world, &mut store)?;
    let denied = Some(LinkError::ProtectedUseDenied);
    let empty = KeyRegistryStateV1::new();
    let unregistered = Fences {
        keys: &empty,
        ..current(&world)
    };
    let missing = verify(&world.registry, &store, &request, unregistered)?;
    assert_eq!(missing.err(), denied);
    let other_key = coordinator_registration(PublicKey::from_bytes([0xc6; 32]))?;
    let mut substituted = KeyRegistryStateV1::new();
    substituted.register_key(other_key)?;
    let rekeyed = Fences {
        keys: &substituted,
        ..current(&world)
    };
    let mismatched = verify(&world.registry, &store, &request, rekeyed)?;
    assert_eq!(mismatched.err(), denied);
    let cases = vec![
        (
            edit(|snapshot| snapshot.key_evidence.clear()),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(|snapshot| {
                for bytes in snapshot.key_evidence.values_mut() {
                    *bytes = vec![0xff];
                }
            }),
            LinkError::CompositionUnavailable,
        ),
    ];
    assert_edits(&world, &store, &request, cases)
}

#[test]
fn a_lost_sqlite_evidence_row_leaves_the_admission_unavailable() -> TestResult {
    let world = world(1)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-evidence.sqlite");
    let path = path.to_str().ok_or("non-UTF8 test path")?;
    let mut store = sqlite_owner(path)?;
    let request = signed_cut(&world, &mut store)?;
    let snapshot = read_snapshot(&world, &store, &request)?;
    let evidence = coordinator_evidence()?;
    let retained = snapshot.key_evidence.get(&evidence.digest());
    assert_eq!(retained, Some(&evidence.to_canonical_cbor()));
    assert_eq!(snapshot.key_evidence.len(), 1);
    assert!(verify(&world.registry, &store, &request, current(&world))?.is_ok());
    let raw = rusqlite::Connection::open(path)?;
    raw.execute("DELETE FROM world_key_evidence", [])?;
    drop(raw);
    let lost = verify(&world.registry, &store, &request, current(&world))?;
    assert_eq!(lost.err(), Some(LinkError::CompositionUnavailable));
    Ok(())
}

fn edit(change: impl Fn(&mut ManifestOwnerLinkSnapshotV1) + 'static) -> Edit {
    Box::new(change)
}

/// The requested Timeline's admission in a crafted snapshot.
fn selected(snapshot: &mut ManifestOwnerLinkSnapshotV1) -> &mut ManifestOwnerAdmissionSnapshotV1 {
    &mut snapshot.admissions[0]
}

/// The requested Timeline's EOP1/OPC1 copies in a crafted snapshot.
fn copies(snapshot: &mut ManifestOwnerLinkSnapshotV1) -> &mut Vec<ManifestOwnerPolicyCopiesV1> {
    &mut selected(snapshot).timeline.policy_copies
}

/// The newest of three same-generation cuts and its owner snapshot.
fn crafted_base() -> Fallible<(World, MemoryStore, ManifestOwnerLinkRequestV1)> {
    let (world, store, cuts) = three_cut_world()?;
    let last = cuts.last().ok_or("missing last cut")?;
    let request = by_recording(&world, first_recording(last)?);
    Ok((world, store, request))
}

#[test]
fn crafted_cut_chains_select_no_other_cut() -> TestResult {
    let (world, store, request) = crafted_base()?;
    let snapshot = read_snapshot(&world, &store, &request)?;
    let mut retimed = *snapshot.result.seal.as_input();
    retimed.schedule_ns = 1;
    let retimed = LocalCutSealV2::new(retimed)?;
    let mut reheaded = snapshot.request.result_head_rows;
    let reheaded_row = reheaded.first_mut().ok_or("missing kind-5 row")?;
    reheaded_row.event_count = 1;
    let reheaded_table = LocalCutHeadsTableV1::result_heads(owner_id(&world), 3, &reheaded)?;
    let reheaded_table = reheaded_table.table_ref();
    let cases = vec![
        (
            edit(|snapshot| snapshot.owner_state.last_visible_cut_id = 2),
            LinkError::WrongCut,
        ),
        (
            edit(move |snapshot| snapshot.result.seal = retimed),
            LinkError::UnsupportedSealVersion,
        ),
        (
            edit(|snapshot| snapshot.result.kind = LocalCutOwnerCommitKindV1::ExactRetry),
            LinkError::WrongCut,
        ),
        (
            edit(|snapshot| snapshot.request.operation_id = Hash::zero()),
            LinkError::WrongCut,
        ),
        (
            edit(|snapshot| snapshot.result.recordings[1].scope = hash(0x61)),
            LinkError::WrongCut,
        ),
        (
            edit(move |snapshot| snapshot.request.seal = retimed),
            LinkError::WrongCut,
        ),
        (
            edit(move |snapshot| {
                snapshot.request.result_head_rows.clone_from(&reheaded);
                snapshot.request.result_heads_table = reheaded_table;
            }),
            LinkError::WrongCut,
        ),
    ];
    assert_edits(&world, &store, &request, cases)?;
    let other_owner = ManifestOwnerLinkRequestV1 {
        owner: OwnerIdV1::from_static("another-owner"),
        ..request
    };
    let unchanged = vec![(edit(|_| {}), LinkError::WrongCut)];
    assert_edits(&world, &store, &other_owner, unchanged)
}

#[test]
fn crafted_admissions_must_match_the_sealed_policy_selection() -> TestResult {
    let (world, store, request) = crafted_base()?;
    let snapshot = read_snapshot(&world, &store, &request)?;
    let admission = snapshot.admissions.first().ok_or("missing admission")?;
    let catalog = admission.catalog.as_input();
    let mut rows = catalog.rows.clone();
    rows.first_mut().ok_or("missing row")?.stable_slot = String::from("a-slot");
    let renamed = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        rows,
        ..catalog.clone()
    })?;
    let wcs1 = &admission.timeline.wcs1;
    let producer = wcs1.producers().first().ok_or("missing producer")?;
    let repriced = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: wcs1.scope(),
        consumers: wcs1.consumers().to_vec(),
        producers: vec![WorldProducerV1::new(producer.plugin_id(), hash(0x62))?],
        optional_view_roots: Vec::new(),
    })?;
    let mut receipt = admission.timeline.receipt.as_input().clone();
    receipt.coordinator_key_evidence_hash = hash(0x63);
    let resigned = ManifestSlotAdmissionReceiptV1::new(receipt)?;
    let cases = vec![
        (
            edit(|snapshot| snapshot.admissions.clear()),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| selected(snapshot).catalog.clone_from(&renamed)),
            LinkError::SlotBindingMismatch,
        ),
        (
            edit(|snapshot| copies(snapshot).truncate(1)),
            LinkError::ClosureUnavailable,
        ),
        (
            edit(|snapshot| {
                let held = copies(snapshot);
                let first = held[0].clone();
                held[1] = first;
            }),
            LinkError::ClosureUnavailable,
        ),
        (
            edit(|snapshot| copies(snapshot)[0].eop1_bytes.clear()),
            LinkError::PolicyMismatch,
        ),
        (
            edit(|snapshot| copies(snapshot)[0].opc1_bytes.push(0)),
            LinkError::ClosureUnavailable,
        ),
        (
            edit(move |snapshot| selected(snapshot).timeline.wcs1.clone_from(&repriced)),
            LinkError::PolicyMismatch,
        ),
        (
            edit(|snapshot| snapshot.admissions.truncate(1)),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(|snapshot| selected(snapshot).read_limits.max_native_bytes = 0),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| selected(snapshot).timeline.receipt.clone_from(&resigned)),
            LinkError::SlotBindingMismatch,
        ),
        (
            edit(|snapshot| snapshot.request.recording_context_rows[0].wcs_hash = hash(0x64)),
            LinkError::SlotBindingMismatch,
        ),
    ];
    assert_edits(&world, &store, &request, cases)
}

/// A copy of `catalog` with another owner or configuration generation.
fn recatalogued(
    catalog: &ManifestAdmissionCatalogV1,
    owner_id: [u8; 32],
    configuration_generation: u64,
) -> Fallible<ManifestAdmissionCatalogV1> {
    let catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id,
        configuration_generation,
        ..catalog.as_input().clone()
    })?;
    Ok(catalog)
}

/// A copy of `binding` whose `plugin_id` row names another EOP1 WAL1.
fn rebound(
    binding: &ManifestSlotBindingV1,
    plugin_id: PluginId,
) -> Fallible<ManifestSlotBindingV1> {
    let mut input = binding.as_input().clone();
    let rows = &mut input.rows;
    let row = rows.iter_mut().find(|row| row.plugin_id == plugin_id);
    row.ok_or("missing bound row")?.eop1_wal1_hash = hash(0x69);
    Ok(ManifestSlotBindingV1::new(input)?)
}

#[test]
fn crafted_admission_rows_and_producers_must_match_the_seal() -> TestResult {
    let (world, store, request) = crafted_base()?;
    let snapshot = read_snapshot(&world, &store, &request)?;
    let admission = snapshot.admissions.first().ok_or("missing admission")?;
    let catalog = &admission.catalog;
    let owner = catalog.as_input().owner_id;
    let rehomed = recatalogued(catalog, [0x52; 32], 1)?;
    let regenerated = recatalogued(catalog, owner, 2)?;
    let wcs1 = &admission.timeline.wcs1;
    let producer = wcs1.producers().first().ok_or("missing producer")?;
    let unknown = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: wcs1.scope(),
        consumers: wcs1.consumers().to_vec(),
        producers: vec![WorldProducerV1::new(PluginId::new(), hash(0x6a))?],
        optional_view_roots: Vec::new(),
    })?;
    let unretained = rebound(&admission.timeline.binding, producer.plugin_id())?;
    let unowned = TimelineId::from_ulid(ulid::Ulid::from(1_u128));
    let cases = vec![
        (
            edit(move |snapshot| selected(snapshot).catalog.clone_from(&rehomed)),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| selected(snapshot).catalog.clone_from(&regenerated)),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| snapshot.admissions[1].timeline.timeline_id = unowned),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| selected(snapshot).timeline.wcs1.clone_from(&unknown)),
            LinkError::PolicyMismatch,
        ),
        (
            edit(move |snapshot| selected(snapshot).timeline.binding.clone_from(&unretained)),
            LinkError::PolicyMismatch,
        ),
    ];
    assert_edits(&world, &store, &request, cases)
}

#[test]
fn crafted_ancestry_closures_and_static_pins_must_hold() -> TestResult {
    let (world, store, request) = crafted_base()?;
    let snapshot = read_snapshot(&world, &store, &request)?;
    let earliest = snapshot.ancestors.get(1..).ok_or("missing ancestors")?;
    let earliest = earliest.to_vec();
    let public_plan = genesis_plan(&world, 0x11, LeafPolicy::PublicClosure);
    let public = scope(&world, request.timeline_id, &public_plan)?.policy_copies;
    let unowned = TimelineId::from_ulid(ulid::Ulid::from(1_u128));
    let cases = vec![
        (
            edit(|snapshot| selected(snapshot).resulting_inventory_generation = hash(0x65)),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(|snapshot| snapshot.ancestors.clear()),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| snapshot.ancestors.clone_from(&earliest)),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(|snapshot| snapshot.ancestors[0].commit = snapshot.ancestors[1].commit),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(|snapshot| snapshot.ancestors[0].seal = snapshot.ancestors[1].seal),
            LinkError::CompositionUnavailable,
        ),
        (
            edit(move |snapshot| copies(snapshot).clone_from(&public)),
            LinkError::ClosureUnavailable,
        ),
        (
            edit(|snapshot| snapshot.dependency_branches.clear()),
            LinkError::ClosureUnavailable,
        ),
        (
            edit(|snapshot| selected(snapshot).read_limits.max_node_visits = 1),
            LinkError::ClosureUnavailable,
        ),
        (
            edit(|snapshot| snapshot.request.composition_rows[0].plugin_version = "9.9.9".into()),
            LinkError::PolicyMismatch,
        ),
        (
            edit(move |snapshot| snapshot.request.composition_rows[0].timeline_id = unowned),
            LinkError::PolicyMismatch,
        ),
    ];
    assert_edits(&world, &store, &request, cases)
}
