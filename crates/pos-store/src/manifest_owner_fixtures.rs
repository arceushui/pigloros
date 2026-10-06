//! Manifest owner-admission fixtures shared by the in-crate store tests.
//!
//! The memory and `SQLite` coverage modules build the same two-Plugin catalog
//! with self-consistent EOP1/OPC1 members, a real RTP1/RLS1 lease per
//! Timeline, the derived scope members, and an always-accepting owner
//! verifier; each caller passes its own owner id so the stores keep distinct
//! fixture owners.

use pos_core::output_policy::{OutputPolicyInputV1, OutputPolicyV1};
use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::{
    build_manifest_owner_scope_v1, derive_local_cut_world_closure_v1,
    test_coordinator_key_evidence, ArtifactDataClassV1, ArtifactTransitionRuleV1,
    CoordinatorSignedReceiptV1, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1,
    FidelityBudgetV1, Hash, LocalCutExpectedHeadRowV1, LocalCutRecordingContextRowV1,
    LocalCutResultHeadRowV1, LocalCutSealV2, LocalCutWorldClosureSourceV1,
    ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
    ManifestOwnerAdmissionErrorV1, ManifestOwnerAdmissionOwnerStateV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionSnapshotV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerClassifiedLeafV1,
    ManifestOwnerConsumerReferenceV1, ManifestOwnerLeafClassificationV1,
    ManifestOwnerPolicyCopiesV1, ManifestOwnerPolicySourceV1, ManifestOwnerScopeMembersV1,
    ManifestOwnerScopeSourceV1, ManifestOwnerScopeV1, ManifestOwnerTimelineAdmissionRequestV1,
    ManifestSlotAdmissionReceiptDraftV1, ManifestSlotAdmissionReceiptV1, PluginCpuReservationV1,
    PluginId, SignedManifestSlotAdmissionReceiptV1, TimelineId, WorkloadProfileV1,
    WorldArtifactKindV1, WorldClosureReadLimitsV1, WorldConsumerSetInputV1, WorldConsumerSetV1,
    WorldConsumerV1, WorldProducerV1,
};

pub(crate) type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
pub(crate) type PolicySource = (OutputPolicyV1, Vec<u8>);

/// Read limits recorded by every fixture admission.
pub(crate) const READ_LIMITS: WorldClosureReadLimitsV1 = WorldClosureReadLimitsV1 {
    max_node_visits: 4096,
    max_native_bytes: 1_048_576,
    max_combined_depth: 32,
};

const DAY_MICROS: u64 = 86_400_000_000;

pub(crate) const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

pub(crate) const fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

/// Accepts every owner check so store tests isolate the persistence port.
pub(crate) struct AcceptingOwner;

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
    ) -> Result<SignedManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        let evidence = test_coordinator_key_evidence(1);
        draft
            .with_evidence_and_signature(evidence.digest(), [0x5a; 64])
            .map(|receipt| CoordinatorSignedReceiptV1 {
                receipt,
                key_evidence: evidence.to_canonical_cbor(),
            })
            .or(Err(ManifestOwnerAdmissionErrorV1::OwnerRejected))
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
        Ok(member_classes(members))
    }
}

/// Echo the classification recorded in each member leaf, in leaf order.
pub(crate) fn member_classes(
    members: &ManifestOwnerScopeMembersV1,
) -> Vec<ManifestOwnerClassifiedLeafV1> {
    members
        .leaves
        .iter()
        .map(|member| ManifestOwnerClassifiedLeafV1::of_leaf(&member.leaf))
        .collect()
}

const fn structural_classification() -> ManifestOwnerLeafClassificationV1 {
    ManifestOwnerLeafClassificationV1 {
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        key_dependencies: Vec::new(),
    }
}

pub(crate) fn retention_policy() -> Fallible<WorldRetentionPolicyV1> {
    Ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world-replay-v1".to_owned(),
        audience_policy_hash: hash(0xa6),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    })?)
}

/// A 10-day admission window and a 100-day retention tail for `timeline_id`.
pub(crate) fn retention_lease(timeline_id: TimelineId) -> Fallible<WorldRetentionLeaseV1> {
    let policy = retention_policy()?;
    Ok(WorldRetentionLeaseV1::new(
        &policy,
        WorldRetentionLeaseInputV1 {
            timeline_id,
            policy_hash: policy.digest(),
            started_at_micros: DAY_MICROS,
            admission_closes_at_micros: 11 * DAY_MICROS,
            retention_deadline_micros: 111 * DAY_MICROS,
        },
    )?)
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
    Ok(ExecutableBudgetPolicyV1::new(
        ExecutableBudgetPolicyInputV1 {
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
        },
    )?)
}

/// Self-consistent EOP1/OPC1 pair; even seeds carry a non-empty EPF1.
pub(crate) fn policy_and_closure(plugin_id: PluginId, seed: u8) -> Fallible<PolicySource> {
    let (policy, members) = policy_members(plugin_id, seed)?;
    Ok((policy, closure_bytes(members)))
}

/// Even seeds carry a non-empty EPF1; odd seeds use the Generated profile.
fn fixture_profile(seed: u8) -> Vec<u8> {
    if seed.is_multiple_of(2) {
        format!("EPF1-{seed}").into_bytes()
    } else {
        Vec::new()
    }
}

/// The EOP1 and its six OPC1 members in closure order.
fn policy_members(plugin_id: PluginId, seed: u8) -> Fallible<(OutputPolicyV1, [Vec<u8>; 6])> {
    let retention = retention_policy()?;
    let implementation = format!("implementation-{seed}").into_bytes();
    let configuration = format!("CFG1-{seed}").into_bytes();
    let profile = fixture_profile(seed);
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
    Ok((policy, members))
}

/// Frame OPC1 members with their big-endian lengths.
fn closure_bytes(members: [Vec<u8>; 6]) -> Vec<u8> {
    let mut closure = b"OPC1".to_vec();
    for member in members {
        let length = u64::try_from(member.len()).unwrap_or(u64::MAX);
        closure.extend_from_slice(&length.to_be_bytes());
        closure.extend_from_slice(&member);
    }
    closure
}

pub(crate) fn opc1_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Two-Plugin catalog for `owner` at `generation`, with its policy sources.
pub(crate) fn catalog(
    owner: [u8; 32],
    generation: u64,
) -> Fallible<(ManifestAdmissionCatalogV1, Vec<PolicySource>)> {
    let sources = vec![
        policy_and_closure(plugin(1), 1)?,
        policy_and_closure(plugin(2), 2)?,
    ];
    let rows = sources
        .iter()
        .enumerate()
        .map(|(index, (policy, closure))| ManifestAdmissionCatalogRowV1 {
            stable_slot: if index == 0 { "slot-a" } else { "slot-b" }.to_owned(),
            plugin_id: policy.fields().plugin_id,
            plugin_name: "same-name".to_owned(),
            plugin_version: policy.fields().plugin_version.clone(),
            implementation_hash: policy.fields().implementation_hash,
            eop1_native_digest: policy.digest(),
            closure_hash: opc1_digest(closure),
        })
        .collect();
    let catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: owner,
        configuration_generation: generation,
        rows,
    })?;
    Ok((catalog, sources))
}

/// One owned Timeline scope with its derived lease, members and WCS1.
///
/// Plugin 1 produces; the second same-name Plugin is reducer-only and stays
/// absent from WCS1 while remaining in MCA1/MSB1 and the copies.
pub(crate) fn timeline_request(
    owner: [u8; 32],
    timeline_id: TimelineId,
    sources: &[PolicySource],
) -> Fallible<ManifestOwnerTimelineAdmissionRequestV1> {
    let source = scope_source(owner, timeline_id, sources)?;
    let scope = build_manifest_owner_scope_v1(&source, &|_, _| Some(structural_classification()))?;
    let wcs1 = fixture_wcs1(&scope, sources)?;
    Ok(ManifestOwnerTimelineAdmissionRequestV1 {
        timeline_id,
        scope: scope.scope,
        wcs1,
        policy_copies: scope.policy_copies,
        members: scope.members,
    })
}

/// Native records behind one fixture scope: a real lease and both Plugins.
fn scope_source(
    owner: [u8; 32],
    timeline_id: TimelineId,
    sources: &[PolicySource],
) -> Fallible<ManifestOwnerScopeSourceV1> {
    Ok(ManifestOwnerScopeSourceV1 {
        owner_id: owner,
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
    })
}

/// WCS1 naming the producer and the scope's derived reference leaves.
fn fixture_wcs1(
    scope: &ManifestOwnerScopeV1,
    sources: &[PolicySource],
) -> Fallible<WorldConsumerSetV1> {
    let producer = sources.first().ok_or("missing fixture policy")?;
    let consumer = fixture_consumer(scope)?;
    let producer = WorldProducerV1::new(plugin(1), producer.0.digest())?;
    WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope.scope,
        consumers: vec![consumer],
        producers: vec![producer],
        optional_view_roots: Vec::new(),
    })
    .map_err(Into::into)
}

/// The one WCS1 consumer naming the scope's kind7/8/9 reference leaves.
fn fixture_consumer(scope: &ManifestOwnerScopeV1) -> Fallible<WorldConsumerV1> {
    let reducer = reference_leaf(scope, WorldArtifactKindV1::ReducerImplementation)?;
    let schema = reference_leaf(scope, WorldArtifactKindV1::Schema)?;
    let runtime = reference_leaf(scope, WorldArtifactKindV1::RuntimeIdentity)?;
    WorldConsumerV1::new("local-observer".to_owned(), reducer, schema, runtime).map_err(Into::into)
}

/// WAL1 address of the scope's reference leaf of one kind.
fn reference_leaf(scope: &ManifestOwnerScopeV1, kind: WorldArtifactKindV1) -> Fallible<Hash> {
    scope
        .members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == kind)
        .map(|member| member.leaf.digest())
        .ok_or_else(|| "missing fixture reference leaf".into())
}

/// Genesis chain hash attested by every fixture local-cut source owner.
pub(crate) const SOURCE_GENESIS: Hash = hash(0x47);

/// Zero-Event kind-8 and kind-4 rows for `snapshots`, in snapshot order.
///
/// Each row names the scope's recorded RLS1 and chains to `predecessor`.
pub(crate) fn zero_event_inputs(
    snapshots: &[ManifestOwnerAdmissionSnapshotV1],
    predecessor: &dyn Fn(TimelineId) -> Option<Hash>,
) -> Fallible<(
    Vec<LocalCutRecordingContextRowV1>,
    Vec<LocalCutExpectedHeadRowV1>,
)> {
    let mut contexts = Vec::with_capacity(snapshots.len());
    let mut heads = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let timeline = &snapshot.timeline;
        let lease = timeline
            .members
            .leaves
            .iter()
            .find(|member| member.leaf.as_input().kind == WorldArtifactKindV1::RetentionLease)
            .ok_or("missing recorded lease leaf")?;
        let predecessor_wcb_hash = predecessor(timeline.timeline_id);
        contexts.push(LocalCutRecordingContextRowV1 {
            timeline_id: timeline.timeline_id,
            wcs_hash: timeline.wcs1.digest(),
            retention_lease_hash: lease.leaf.as_input().native_digest,
            predecessor_wcb_hash,
        });
        heads.push(LocalCutExpectedHeadRowV1 {
            timeline_id: timeline.timeline_id,
            logical_head: 0,
            stitched_chain_hash: SOURCE_GENESIS,
            source_timeline_id: timeline.timeline_id,
            source_segment_head: 0,
            source_chain_hash: SOURCE_GENESIS,
            logical_prefix: 0,
            lineage_proof_hash: None,
            predecessor_wcb_hash,
        });
    }
    Ok((contexts, heads))
}

/// Kind-5 rows naming the WCB1 the owner derives for each Timeline.
pub(crate) fn zero_event_results(
    operation_id: Hash,
    seal: &LocalCutSealV2,
    snapshots: &[ManifestOwnerAdmissionSnapshotV1],
    contexts: &[LocalCutRecordingContextRowV1],
) -> Fallible<Vec<LocalCutResultHeadRowV1>> {
    let mut rows = Vec::with_capacity(snapshots.len());
    for (snapshot, context) in snapshots.iter().zip(contexts) {
        let source = LocalCutWorldClosureSourceV1 {
            operation_id,
            seal,
            admission: snapshot,
            retention_lease_hash: context.retention_lease_hash,
            predecessor_binding_hash: context.predecessor_wcb_hash,
            genesis_hash: SOURCE_GENESIS,
        };
        let closure = derive_local_cut_world_closure_v1(&source)?;
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
