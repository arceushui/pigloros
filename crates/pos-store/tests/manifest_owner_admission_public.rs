use std::sync::atomic::{AtomicUsize, Ordering};

use pos_core::output_policy::{OutputPolicyInputV1, OutputPolicyV1};
use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::{
    build_manifest_owner_scope_v1, manifest_owner_admission_intent_digest_v1,
    prepare_manifest_owner_admission_v1, validate_manifest_owner_lease_replacement_v1,
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1,
    ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1, FidelityBudgetV1, Hash,
    ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
    ManifestOwnerAdmissionCommitKindV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionRequestV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerConsumerReferenceV1,
    ManifestOwnerLeafClassificationV1, ManifestOwnerMemberLeafClassV1, ManifestOwnerMemberLeafV1,
    ManifestOwnerPolicyCopiesV1, ManifestOwnerPolicySourceV1, ManifestOwnerScopeMembersV1,
    ManifestOwnerScopeSourceV1, ManifestOwnerScopeV1, ManifestOwnerTimelineAdmissionRequestV1,
    ManifestSlotAdmissionReceiptDraftV1, ManifestSlotAdmissionReceiptV1, PluginCpuReservationV1,
    PluginId, TimelineId, WorkloadProfileV1, WorldArtifactKeyDependencyV1, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldClosureReadLimitsV1,
    WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1, WorldProducerV1,
    WorldReplayClosureV1, MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1,
};
use pos_store::{memory::MemoryStore, ManifestOwnerAdmissionPersistencePortV1};

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = FixtureResult<()>;
type PolicySource = (OutputPolicyV1, Vec<u8>);
type CatalogFixture = (ManifestAdmissionCatalogV1, Vec<PolicySource>);
type Classifier = dyn Fn(WorldArtifactKindV1, Hash) -> Option<ManifestOwnerLeafClassificationV1>;

const DAY_MICROS: u64 = 86_400_000_000;
const READ_LIMITS: WorldClosureReadLimitsV1 = WorldClosureReadLimitsV1 {
    max_node_visits: 4096,
    max_native_bytes: 1_048_576,
    max_combined_depth: 32,
};
const BASE_CONFIGURATION_DOMAIN: &[u8] = b"pigloros.base-configuration.v1";
const IMPLEMENTATION_DOMAIN: &[u8] = b"pigloros.implementation-artifact.v1";

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MemberFault {
    Accept,
    Reject,
    Misclassify,
}

struct FixtureOwner {
    expected_timelines: Vec<TimelineId>,
    expected_operation: Hash,
    signatures_issued: AtomicUsize,
    coordinator_evidence: Hash,
    signature_byte: u8,
    member_fault: MemberFault,
}

impl FixtureOwner {
    const fn new(expected_timelines: Vec<TimelineId>, expected_operation: Hash) -> Self {
        Self {
            expected_timelines,
            expected_operation,
            signatures_issued: AtomicUsize::new(0),
            coordinator_evidence: hash(90),
            signature_byte: 0x5a,
            member_fault: MemberFault::Accept,
        }
    }

    const fn with_signing_identity(mut self, evidence: Hash, signature_byte: u8) -> Self {
        self.coordinator_evidence = evidence;
        self.signature_byte = signature_byte;
        self
    }

    const fn with_member_fault(mut self, member_fault: MemberFault) -> Self {
        self.member_fault = member_fault;
        self
    }
}

impl ManifestOwnerAdmissionVerifierV1 for FixtureOwner {
    fn verify_complete_composition(
        &self,
        catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let rows = &catalog.as_input().rows;
        if rows.len() != 2
            || rows[0].plugin_name != rows[1].plugin_name
            || rows[0].plugin_id == rows[1].plugin_id
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn verify_complete_owned_scope_set(
        &self,
        _owner_id: [u8; 32],
        timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let actual: Vec<_> = timelines.iter().map(|row| row.timeline_id).collect();
        if actual != self.expected_timelines
            || timelines.iter().any(|row| row.wcs1.scope() != row.scope)
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn verify_owner_prestate_and_allocation(
        &self,
        request: &ManifestOwnerAdmissionRequestV1,
        current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let current_state_matches = match (request.expected_configuration_generation, current_state)
        {
            (None, None) => true,
            (Some(expected), Some(state)) => {
                state.configuration_generation == expected
                    && state.previous_visible_lcq1_hash == request.previous_visible_lcq1_hash
                    && Some(state.inventory_generation) == request.expected_inventory_generation
            }
            _ => false,
        };
        if request.operation_id != self.expected_operation
            || request.resulting_inventory_generation == Hash::zero()
            || !current_state_matches
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        self.signatures_issued.fetch_add(1, Ordering::SeqCst);
        draft
            .with_evidence_and_signature(self.coordinator_evidence, [self.signature_byte; 64])
            .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
    }

    fn verify_coordinator_receipt(
        &self,
        receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if receipt.as_input().coordinator_key_evidence_hash != self.coordinator_evidence
            || receipt.as_input().signature != [self.signature_byte; 64]
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn verify_native_policy_copies(
        &self,
        _timeline_id: TimelineId,
        scope: Hash,
        copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if !copies.eop1_bytes.starts_with(b"\x8a\x44EOP1")
            || !copies.opc1_bytes.starts_with(b"OPC1")
            || copies.eop1_leaf.as_input().scope != scope
            || copies.opc1_leaf.as_input().scope != scope
            || copies.eop1_leaf.as_input().optionality != ArtifactOptionalityV1::Required
            || copies.opc1_leaf.as_input().optionality != ArtifactOptionalityV1::Required
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn classify_scope_member_leaves(
        &self,
        _timeline_id: TimelineId,
        _scope: Hash,
        members: &ManifestOwnerScopeMembersV1,
    ) -> Result<Vec<ManifestOwnerMemberLeafClassV1>, ManifestOwnerAdmissionErrorV1> {
        let mut classes = members
            .leaves
            .iter()
            .map(|member| ManifestOwnerMemberLeafClassV1::of_leaf(&member.leaf))
            .collect::<Vec<_>>();
        match self.member_fault {
            MemberFault::Accept => Ok(classes),
            MemberFault::Reject => Err(ManifestOwnerAdmissionErrorV1::OwnerRejected),
            MemberFault::Misclassify => {
                classes.pop();
                Ok(classes)
            }
        }
    }
}

const fn classification(data_class: ArtifactDataClassV1) -> ManifestOwnerLeafClassificationV1 {
    ManifestOwnerLeafClassificationV1 {
        data_class,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        key_dependencies: Vec::new(),
    }
}

fn structural() -> Box<Classifier> {
    Box::new(|_: WorldArtifactKindV1, _: Hash| {
        Some(classification(ArtifactDataClassV1::StructuralAuditMetadata))
    })
}

fn host_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn plain_digest(bytes: &[u8]) -> Hash {
    Hash::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn retention_policy() -> FixtureResult<WorldRetentionPolicyV1> {
    Ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world-replay-v1".to_owned(),
        audience_policy_hash: hash(0xa6),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    })?)
}

/// Lease from day 1 that closes and expires on the given days.
fn retention_lease(
    timeline_id: TimelineId,
    closes_day: u64,
    deadline_day: u64,
) -> FixtureResult<WorldRetentionLeaseV1> {
    let policy = retention_policy()?;
    Ok(WorldRetentionLeaseV1::new(
        &policy,
        WorldRetentionLeaseInputV1 {
            timeline_id,
            policy_hash: policy.digest(),
            started_at_micros: DAY_MICROS,
            admission_closes_at_micros: closes_day * DAY_MICROS,
            retention_deadline_micros: deadline_day * DAY_MICROS,
        },
    )?)
}

fn default_lease(timeline_id: TimelineId) -> FixtureResult<WorldRetentionLeaseV1> {
    retention_lease(timeline_id, 11, 111)
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

fn budget(plugin_id: PluginId, profile_hash: Hash) -> FixtureResult<ExecutableBudgetPolicyV1> {
    Ok(ExecutableBudgetPolicyV1::new(ExecutableBudgetPolicyInputV1 {
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
        execution_profile_hash: profile_hash,
        max_pass_wall_duration_us: 1_000,
    })?)
}

/// Native OPC1 members one to five; member zero is the EOP1 built over them.
#[derive(Clone)]
struct NativeMembers {
    budget: Vec<u8>,
    implementation: Vec<u8>,
    configuration: Vec<u8>,
    profile: Vec<u8>,
    retention: Vec<u8>,
}

/// Self-consistent members; even seeds carry a non-empty EPF1.
fn native_members(plugin_id: PluginId, seed: u8) -> FixtureResult<NativeMembers> {
    let profile = if seed % 2 == 0 {
        format!("EPF1-{seed}").into_bytes()
    } else {
        Vec::new()
    };
    Ok(NativeMembers {
        budget: budget(plugin_id, plain_digest(&profile))?.to_canonical_cbor(),
        implementation: format!("implementation-{seed}").into_bytes(),
        configuration: format!("CFG1-{seed}").into_bytes(),
        profile,
        retention: retention_policy()?.to_canonical_cbor(),
    })
}

/// EOP1 fields that name exactly the given members.
fn policy_input(
    plugin_id: PluginId,
    members: &NativeMembers,
) -> FixtureResult<OutputPolicyInputV1> {
    Ok(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: host_digest(IMPLEMENTATION_DOMAIN, &members.implementation),
        base_configuration_digest: host_digest(BASE_CONFIGURATION_DOMAIN, &members.configuration),
        executable_profile_hash: ExecutableBudgetPolicyV1::from_canonical_cbor(&members.budget)?
            .digest(),
        retention_policy_hash: retention_policy()?.digest(),
        policy_revision: 1,
        output_declarations: Vec::new(),
    })
}

fn assemble(input: OutputPolicyInputV1, members: &NativeMembers) -> FixtureResult<PolicySource> {
    let policy = OutputPolicyV1::new(input)?;
    let framed = [
        policy.to_canonical_cbor(),
        members.budget.clone(),
        members.implementation.clone(),
        members.configuration.clone(),
        members.profile.clone(),
        members.retention.clone(),
    ];
    let mut closure = b"OPC1".to_vec();
    for member in framed {
        closure.extend_from_slice(&u64::try_from(member.len())?.to_be_bytes());
        closure.extend_from_slice(&member);
    }
    Ok((policy, closure))
}

fn policy_and_closure(plugin_id: PluginId, seed: u8) -> FixtureResult<PolicySource> {
    let members = native_members(plugin_id, seed)?;
    assemble(policy_input(plugin_id, &members)?, &members)
}

fn opc1_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn sources() -> FixtureResult<Vec<PolicySource>> {
    Ok(vec![
        policy_and_closure(plugin(1), 1)?,
        policy_and_closure(plugin(2), 2)?,
    ])
}

fn catalog(owner_id: [u8; 32], generation: u64) -> FixtureResult<CatalogFixture> {
    let source = sources()?;
    let rows = source
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
    Ok((
        ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            owner_id,
            configuration_generation: generation,
            rows,
        })?,
        source,
    ))
}

fn scope_source(
    owner_id: [u8; 32],
    lease: &WorldRetentionLeaseV1,
    source: &[PolicySource],
) -> FixtureResult<ManifestOwnerScopeSourceV1> {
    Ok(ManifestOwnerScopeSourceV1 {
        owner_id,
        timeline_id: lease.as_input().timeline_id,
        rtp1_bytes: retention_policy()?.to_canonical_cbor(),
        rls1_bytes: lease.to_canonical_cbor(),
        consumer_references: vec![ManifestOwnerConsumerReferenceV1 {
            schema: hash(131),
            reducer: hash(130),
            runtime: hash(132),
        }],
        policy_sources: source
            .iter()
            .map(|(policy, closure)| ManifestOwnerPolicySourceV1 {
                plugin_id: policy.fields().plugin_id,
                eop1_bytes: policy.to_canonical_cbor(),
                opc1_bytes: closure.clone(),
            })
            .collect(),
    })
}

fn member_of(
    members: &ManifestOwnerScopeMembersV1,
    kind: WorldArtifactKindV1,
) -> FixtureResult<&ManifestOwnerMemberLeafV1> {
    members
        .leaves
        .iter()
        .find(|member| member.leaf.as_input().kind == kind)
        .ok_or_else(|| "missing member leaf".into())
}

fn consumer_set(
    scope: &ManifestOwnerScopeV1,
    producer: &PolicySource,
    schema_hash: Option<Hash>,
    optional_view_roots: Vec<Hash>,
) -> FixtureResult<WorldConsumerSetV1> {
    let schema = member_of(&scope.members, WorldArtifactKindV1::Schema)?
        .leaf
        .digest();
    Ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope.scope,
        consumers: vec![WorldConsumerV1::new(
            "local-observer".to_owned(),
            member_of(&scope.members, WorldArtifactKindV1::ReducerImplementation)?
                .leaf
                .digest(),
            schema_hash.unwrap_or(schema),
            member_of(&scope.members, WorldArtifactKindV1::RuntimeIdentity)?
                .leaf
                .digest(),
        )?],
        producers: vec![WorldProducerV1::new(producer.0.fields().plugin_id, producer.0.digest())?],
        optional_view_roots,
    })?)
}

fn timeline_request(
    owner_id: [u8; 32],
    lease: &WorldRetentionLeaseV1,
    source: &[PolicySource],
    classify: &Classifier,
) -> FixtureResult<ManifestOwnerTimelineAdmissionRequestV1> {
    let scope = build_manifest_owner_scope_v1(&scope_source(owner_id, lease, source)?, classify)?;
    let producer = source.first().ok_or("missing fixture policy")?;
    let wcs1 = consumer_set(&scope, producer, None, Vec::new())?;
    Ok(ManifestOwnerTimelineAdmissionRequestV1 {
        timeline_id: lease.as_input().timeline_id,
        scope: scope.scope,
        wcs1,
        policy_copies: scope.policy_copies,
        members: scope.members,
    })
}

#[derive(Clone, Copy)]
struct AdmissionTransition {
    owner_id: [u8; 32],
    generation: u64,
    expected_generation: Option<u64>,
    previous_receipt: Option<Hash>,
    expected_inventory: Option<Hash>,
    resulting_inventory: Hash,
    operation_id: Hash,
}

const fn genesis(owner_id: [u8; 32], operation_id: Hash) -> AdmissionTransition {
    AdmissionTransition {
        owner_id,
        generation: 1,
        expected_generation: None,
        previous_receipt: None,
        expected_inventory: None,
        resulting_inventory: hash(44),
        operation_id,
    }
}

fn leased_request(
    transition: AdmissionTransition,
    leases: &[WorldRetentionLeaseV1],
    classify: &Classifier,
) -> FixtureResult<ManifestOwnerAdmissionRequestV1> {
    let (catalog, sources) = catalog(transition.owner_id, transition.generation)?;
    let timelines = leases
        .iter()
        .map(|lease| timeline_request(transition.owner_id, lease, &sources, classify))
        .collect::<FixtureResult<Vec<_>>>()?;
    Ok(ManifestOwnerAdmissionRequestV1 {
        operation_id: transition.operation_id,
        catalog,
        expected_configuration_generation: transition.expected_generation,
        previous_visible_lcq1_hash: transition.previous_receipt,
        expected_inventory_generation: transition.expected_inventory,
        resulting_inventory_generation: transition.resulting_inventory,
        read_limits: READ_LIMITS,
        timelines,
    })
}

fn request(
    transition: AdmissionTransition,
    timeline_ids: &[TimelineId],
) -> FixtureResult<ManifestOwnerAdmissionRequestV1> {
    let leases = timeline_ids
        .iter()
        .map(|timeline_id| default_lease(*timeline_id))
        .collect::<FixtureResult<Vec<_>>>()?;
    leased_request(transition, &leases, &*structural())
}

#[test]
fn preparation_rejects_duplicate_timelines_and_missing_zero_output_copy() -> TestResult {
    let owner_id = [9; 32];
    let scope_timelines = vec![timeline(1), timeline(2)];
    let operation_id = hash(45);
    let duplicate = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(44),
            operation_id,
        },
        &[timeline(1), timeline(1)],
    )?;
    assert_eq!(
        prepare_manifest_owner_admission_v1(
            duplicate,
            &FixtureOwner::new(vec![timeline(1), timeline(1)], operation_id),
            None,
        ),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );

    let mut missing_copy = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(44),
            operation_id,
        },
        &scope_timelines,
    )?;
    missing_copy.timelines[0].policy_copies.pop();
    let owner = FixtureOwner::new(scope_timelines, operation_id);
    assert_eq!(
        prepare_manifest_owner_admission_v1(missing_copy, &owner, None),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );
    assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn preparation_bounds_total_native_copies() -> TestResult {
    let owner_id = [29; 32];
    let timeline_id = timeline(21);
    let operation_id = hash(121);
    let mut oversized = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(120),
            operation_id,
        },
        &[timeline_id],
    )?;
    oversized.timelines[0].policy_copies[0].eop1_bytes =
        vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1];
    oversized.timelines[0].policy_copies[0].opc1_bytes =
        vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1];
    let owner = FixtureOwner::new(vec![timeline_id], operation_id);
    assert_eq!(
        prepare_manifest_owner_admission_v1(oversized, &owner, None),
        Err(ManifestOwnerAdmissionErrorV1::BoundExceeded)
    );
    assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn preparation_rejects_malformed_opc1_envelopes_before_signing() -> TestResult {
    let owner_id = [29; 32];
    let timeline_id = timeline(21);
    let operation_id = hash(121);
    let input = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(120),
            operation_id,
        },
        &[timeline_id],
    )?;
    let valid = input.timelines[0].policy_copies[0].opc1_bytes.clone();
    let mut truncated_header = valid.clone();
    truncated_header.truncate(4);
    let mut mismatched_eop1 = valid.clone();
    mismatched_eop1[12] ^= 1;
    let mut oversized_member_length = valid.clone();
    oversized_member_length[4..12].fill(u8::MAX);
    let mut trailing_bytes = valid;
    trailing_bytes.push(0);

    for malformed in [
        truncated_header,
        mismatched_eop1,
        oversized_member_length,
        trailing_bytes,
    ] {
        let mut malformed_input = input.clone();
        malformed_input.timelines[0].policy_copies[0].opc1_bytes = malformed;
        let owner = FixtureOwner::new(vec![timeline_id], operation_id);
        assert_eq!(
            prepare_manifest_owner_admission_v1(malformed_input, &owner, None),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
        assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn memory_owner_admission_resolves_retries_conflicts_and_historical_rows() -> TestResult {
    let owner_id = [9; 32];
    let first_timelines = vec![timeline(1), timeline(2)];
    let genesis_request = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(40),
            operation_id: hash(41),
        },
        &first_timelines,
    )?;
    let genesis_owner = FixtureOwner::new(first_timelines.clone(), hash(41));
    let prepared =
        prepare_manifest_owner_admission_v1(genesis_request.clone(), &genesis_owner, None)?;
    assert_eq!(genesis_owner.signatures_issued.load(Ordering::SeqCst), 2);
    let mut store = MemoryStore::new();
    let applied = store.commit_manifest_owner_admission_v1(prepared)?;
    assert_eq!(applied.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    assert_eq!(applied.receipt_hashes.len(), 2);

    let retry_owner =
        FixtureOwner::new(first_timelines.clone(), hash(41)).with_signing_identity(hash(91), 0xa5);
    let retry_prepared =
        prepare_manifest_owner_admission_v1(genesis_request.clone(), &retry_owner, None)?;
    assert_ne!(
        retry_prepared.input().timelines[0].receipt.digest(),
        applied.receipt_hashes[0]
    );
    let exact = store.commit_manifest_owner_admission_v1(retry_prepared)?;
    assert_eq!(exact.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(exact.receipt_hashes, applied.receipt_hashes);

    let mut conflicting_operation = genesis_request;
    conflicting_operation.resulting_inventory_generation = hash(42);
    let conflicting =
        prepare_manifest_owner_admission_v1(conflicting_operation, &genesis_owner, None)?;
    assert_eq!(
        store.commit_manifest_owner_admission_v1(conflicting),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );

    let signatures_before_conflict = genesis_owner.signatures_issued.load(Ordering::SeqCst);
    let competing_genesis = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(43),
            operation_id: hash(44),
        },
        &first_timelines,
    )?;
    let competing_owner = FixtureOwner::new(first_timelines.clone(), hash(44));
    assert_eq!(
        store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
            competing_genesis,
            &competing_owner,
            None,
        )?),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    assert_eq!(
        genesis_owner.signatures_issued.load(Ordering::SeqCst),
        signatures_before_conflict
    );

    let current = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing genesis state")?;
    assert_eq!(current.configuration_generation, 1);
    assert_eq!(current.previous_visible_lcq1_hash, None);
    assert_eq!(current.inventory_generation, hash(40));
    assert_eq!(current.timelines, first_timelines);
    let historical = store
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(1))?
        .ok_or("missing genesis admission row")?;
    assert_eq!(historical.timeline.policy_copies.len(), 2);
    assert_eq!(historical.timeline.wcs1.producers().len(), 1);
    assert_eq!(
        historical
            .timeline
            .receipt
            .as_input()
            .previous_visible_lcq1_hash,
        None
    );
    assert_eq!(
        historical
            .timeline
            .receipt
            .as_input()
            .expected_inventory_generation,
        None
    );

    Ok(())
}

#[test]
fn memory_owner_admission_replaces_the_complete_timeline_set() -> TestResult {
    let owner_id = [10; 32];
    let first_timelines = vec![timeline(1), timeline(2)];
    let genesis_request = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(60),
            operation_id: hash(61),
        },
        &first_timelines,
    )?;
    let genesis_owner = FixtureOwner::new(first_timelines, hash(61));
    let mut store = MemoryStore::new();
    let genesis = prepare_manifest_owner_admission_v1(genesis_request, &genesis_owner, None)?;
    store.commit_manifest_owner_admission_v1(genesis)?;
    let previous = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing pre-replacement owner state")?;

    let replacement_timelines = vec![timeline(3), timeline(4)];
    let replacement_request = request(
        AdmissionTransition {
            owner_id,
            generation: 2,
            expected_generation: Some(1),
            previous_receipt: None,
            expected_inventory: Some(hash(60)),
            resulting_inventory: hash(50),
            operation_id: hash(51),
        },
        &replacement_timelines,
    )?;
    let replacement_owner = FixtureOwner::new(replacement_timelines.clone(), hash(51));
    let replacement =
        store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
            replacement_request,
            &replacement_owner,
            Some(&previous),
        )?)?;
    assert_eq!(replacement.configuration_generation, 2);
    let current = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing replacement state")?;
    assert_eq!(current.timelines, replacement_timelines);
    assert_eq!(current.previous_visible_lcq1_hash, None);
    assert_eq!(current.inventory_generation, hash(50));
    let replacement_row = store
        .read_manifest_owner_admission_v1(owner_id, 2, timeline(3))?
        .ok_or("missing replacement scope row")?;
    assert_eq!(
        replacement_row
            .timeline
            .receipt
            .as_input()
            .expected_inventory_generation,
        Some(hash(60))
    );
    assert!(store
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(1))?
        .is_some());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_owner_admission_rolls_back_failed_transaction_and_recovers_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-admission.sqlite");
    let owner_id = [19; 32];
    let timelines = vec![timeline(11), timeline(12)];
    let operation_id = hash(111);
    let input = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(110),
            operation_id,
        },
        &timelines,
    )?;
    let owner = FixtureOwner::new(timelines.clone(), operation_id);
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF8 test path")?)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER fail_manifest_policy_copy
         BEFORE INSERT ON manifest_owner_policy_copies
         BEGIN SELECT RAISE(ABORT, 'injected policy-copy failure'); END;",
    )?;
    assert_eq!(
        store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
            input.clone(),
            &owner,
            None,
        )?),
        Err(ManifestOwnerAdmissionErrorV1::StorageFailure)
    );
    let partial_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM manifest_owner_admissions WHERE owner_id = ?1",
        rusqlite::params![owner_id.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(partial_rows, 0);
    let partial_operations: i64 = connection.query_row(
        "SELECT COUNT(*) FROM manifest_owner_admission_operations WHERE owner_id = ?1",
        rusqlite::params![owner_id.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(partial_operations, 0);
    assert_eq!(store.read_manifest_owner_state_v1(owner_id)?, None);
    connection.execute_batch("DROP TRIGGER fail_manifest_policy_copy")?;
    drop(connection);

    let applied = store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
        input.clone(),
        &owner,
        None,
    )?)?;
    assert_eq!(applied.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    drop(store);

    let reopened = SqliteStore::open(path.to_str().ok_or("non-UTF8 test path")?)?;
    let current = reopened
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("SQLite owner state is missing after reopen")?;
    assert_eq!(current.configuration_generation, 1);
    assert_eq!(current.timelines, timelines);
    let snapshot = reopened
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(11))?
        .ok_or("SQLite native admission is missing after reopen")?;
    assert_eq!(snapshot.timeline.policy_copies.len(), 2);
    assert_eq!(snapshot.timeline.wcs1.producers().len(), 1);
    let signatures_before_retry = owner.signatures_issued.load(Ordering::SeqCst);
    let retry = reopened
        .resolve_manifest_owner_admission_retry_v1(
            owner_id,
            operation_id,
            manifest_owner_admission_intent_digest_v1(&input)?,
        )?
        .ok_or("SQLite should resolve the persisted operation before signing")?;
    assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(retry.receipt_hashes, applied.receipt_hashes);
    assert_eq!(
        owner.signatures_issued.load(Ordering::SeqCst),
        signatures_before_retry
    );
    let mut conflicting_input = input;
    conflicting_input.resulting_inventory_generation = hash(112);
    assert_eq!(
        reopened.resolve_manifest_owner_admission_retry_v1(
            owner_id,
            operation_id,
            manifest_owner_admission_intent_digest_v1(&conflicting_input)?,
        ),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    let connection = rusqlite::Connection::open(&path)?;
    assert_sqlite_owner_receipt_corruption_is_rejected(
        &reopened,
        &connection,
        owner_id,
        operation_id,
    )?;
    Ok(())
}

#[cfg(feature = "sqlite")]
fn assert_competing_sqlite_owner_admission_conflicts(
    store: &mut SqliteStore,
    owner_id: [u8; 32],
    pre_replacement: &ManifestOwnerAdmissionOwnerStateV1,
) -> TestResult {
    let competing_timelines = vec![timeline(25), timeline(26)];
    let competing_operation = hash(155);
    let competing_request = request(
        AdmissionTransition {
            owner_id,
            generation: 2,
            expected_generation: Some(1),
            previous_receipt: None,
            expected_inventory: Some(hash(150)),
            resulting_inventory: hash(154),
            operation_id: competing_operation,
        },
        &competing_timelines,
    )?;
    let competing_owner = FixtureOwner::new(competing_timelines, competing_operation);
    let competing = prepare_manifest_owner_admission_v1(
        competing_request,
        &competing_owner,
        Some(pre_replacement),
    )?;
    assert_eq!(
        store.commit_manifest_owner_admission_v1(competing),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_owner_admission_replaces_complete_generation_and_recovers_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-admission-replacement.sqlite");
    let path = path.to_str().ok_or("non-UTF8 test path")?;
    let owner_id = [29; 32];
    let original_timelines = vec![timeline(21), timeline(22)];
    let genesis_operation = hash(151);
    let genesis_request = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(150),
            operation_id: genesis_operation,
        },
        &original_timelines,
    )?;
    let genesis_owner = FixtureOwner::new(original_timelines, genesis_operation);
    let mut store = SqliteStore::open(path)?;
    let genesis = prepare_manifest_owner_admission_v1(genesis_request, &genesis_owner, None)?;
    let genesis_result = store.commit_manifest_owner_admission_v1(genesis)?;
    assert_eq!(
        genesis_result.kind,
        ManifestOwnerAdmissionCommitKindV1::Applied
    );
    let pre_replacement = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("SQLite owner state is missing before replacement")?;

    let replacement_timelines = vec![timeline(23), timeline(24)];
    let replacement_operation = hash(153);
    let replacement_request = request(
        AdmissionTransition {
            owner_id,
            generation: 2,
            expected_generation: Some(1),
            previous_receipt: None,
            expected_inventory: Some(hash(150)),
            resulting_inventory: hash(152),
            operation_id: replacement_operation,
        },
        &replacement_timelines,
    )?;
    let replacement_owner = FixtureOwner::new(replacement_timelines.clone(), replacement_operation);
    let replacement = prepare_manifest_owner_admission_v1(
        replacement_request.clone(),
        &replacement_owner,
        Some(&pre_replacement),
    )?;
    let replaced = store.commit_manifest_owner_admission_v1(replacement)?;
    assert_eq!(replaced.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    assert_eq!(replaced.configuration_generation, 2);
    assert_eq!(replaced.receipt_hashes.len(), replacement_timelines.len());

    assert_competing_sqlite_owner_admission_conflicts(&mut store, owner_id, &pre_replacement)?;
    drop(store);

    let reopened = SqliteStore::open(path)?;
    let current = reopened
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("SQLite owner state is missing after replacement")?;
    assert_eq!(current.configuration_generation, 2);
    assert_eq!(current.timelines, replacement_timelines);
    assert_eq!(current.inventory_generation, hash(152));
    assert_eq!(current.previous_visible_lcq1_hash, None);
    assert!(reopened
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(21))?
        .is_some());
    for timeline_id in [timeline(23), timeline(24)] {
        let historical = reopened
            .read_manifest_owner_admission_v1(owner_id, 2, timeline_id)?
            .ok_or("replacement generation scope row was lost after reopen")?;
        assert_eq!(historical.timeline.policy_copies.len(), 2);
        assert_eq!(
            historical
                .timeline
                .receipt
                .as_input()
                .expected_inventory_generation,
            Some(hash(150))
        );
    }
    let retry = reopened
        .resolve_manifest_owner_admission_retry_v1(
            owner_id,
            replacement_operation,
            manifest_owner_admission_intent_digest_v1(&replacement_request)?,
        )?
        .ok_or("SQLite did not recover the replacement operation")?;
    assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(retry.receipt_hashes, replaced.receipt_hashes);
    let mut conflicting_retry = replacement_request;
    conflicting_retry.resulting_inventory_generation = hash(156);
    assert_eq!(
        reopened.resolve_manifest_owner_admission_retry_v1(
            owner_id,
            replacement_operation,
            manifest_owner_admission_intent_digest_v1(&conflicting_retry)?,
        ),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    Ok(())
}

fn assert_sqlite_owner_receipt_corruption_is_rejected(
    store: &SqliteStore,
    connection: &rusqlite::Connection,
    owner_id: [u8; 32],
    operation_id: Hash,
) -> TestResult {
    connection.execute(
        "UPDATE manifest_owner_admission_operations
         SET receipt_count = 1 WHERE owner_id = ?1 AND operation_id = ?2",
        rusqlite::params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    assert_eq!(
        store.read_manifest_owner_admission_v1(owner_id, 1, timeline(11)),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE manifest_owner_admission_operations
         SET receipt_count = 0 WHERE owner_id = ?1 AND operation_id = ?2",
        rusqlite::params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    connection.execute(
        "UPDATE manifest_owner_admission_operations
         SET receipt_count = 2, receipt_set_digest = zeroblob(32)
         WHERE owner_id = ?1 AND operation_id = ?2",
        rusqlite::params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    Ok(())
}

fn owner_scope(
    classify: &Classifier,
) -> FixtureResult<(WorldRetentionLeaseV1, ManifestOwnerScopeV1)> {
    let lease = default_lease(timeline(1))?;
    let source = scope_source([7; 32], &lease, &sources()?)?;
    Ok((lease, build_manifest_owner_scope_v1(&source, classify)?))
}

fn leaf_address(
    members: &ManifestOwnerScopeMembersV1,
    kind: WorldArtifactKindV1,
    native_digest: Hash,
) -> FixtureResult<Hash> {
    members
        .leaves
        .iter()
        .map(|member| &member.leaf)
        .find(|leaf| leaf.as_input().kind == kind && leaf.as_input().native_digest == native_digest)
        .map(WorldArtifactLeafV1::digest)
        .ok_or_else(|| "missing member leaf".into())
}

fn sorted(mut addresses: Vec<Hash>) -> Vec<Hash> {
    addresses.sort_unstable();
    addresses
}

fn public_configuration() -> Box<Classifier> {
    Box::new(|kind: WorldArtifactKindV1, _: Hash| {
        Some(classification(
            if kind == WorldArtifactKindV1::BaseConfiguration {
                ArtifactDataClassV1::PublicRecord
            } else {
                ArtifactDataClassV1::StructuralAuditMetadata
            },
        ))
    })
}

const fn reference_state(kind: WorldArtifactKindV1) -> ArtifactStateV1 {
    match kind {
        WorldArtifactKindV1::AudiencePolicy => ArtifactStateV1::MissingFrozenInput,
        WorldArtifactKindV1::Schema => ArtifactStateV1::MissingSchema,
        WorldArtifactKindV1::ReducerImplementation => ArtifactStateV1::MissingPlugin,
        WorldArtifactKindV1::RuntimeIdentity => ArtifactStateV1::MissingRuntime,
        _ => ArtifactStateV1::Retained,
    }
}

fn assert_policy_edges(scope: &ManifestOwnerScopeV1) -> TestResult {
    let members = &scope.members;
    let retention = member_of(members, WorldArtifactKindV1::RetentionPolicy)?
        .leaf
        .digest();
    for copy in &scope.policy_copies {
        let policy = OutputPolicyV1::from_canonical_cbor(&copy.eop1_bytes)?;
        let fields = policy.fields();
        let envelope = pos_core::OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(
            &copy.opc1_bytes,
            &copy.eop1_bytes,
        )?;
        let budget = leaf_address(
            members,
            WorldArtifactKindV1::ExecutableBudgetPolicy,
            fields.executable_profile_hash,
        )?;
        let mut children = vec![
            budget,
            retention,
            leaf_address(
                members,
                WorldArtifactKindV1::BaseConfiguration,
                fields.base_configuration_digest,
            )?,
            leaf_address(
                members,
                WorldArtifactKindV1::PluginImplementationIdentity,
                fields.implementation_hash,
            )?,
        ];
        assert_eq!(
            copy.eop1_leaf.as_input().child_node_hashes,
            sorted(children.clone())
        );
        let profile = envelope.execution_profile_artifact();
        let budget_children = if profile.is_empty() {
            Vec::new()
        } else {
            let kind = WorldArtifactKindV1::ExecutionProfile;
            vec![leaf_address(members, kind, plain_digest(profile))?]
        };
        let budget_leaf = members
            .leaves
            .iter()
            .find(|member| member.leaf.digest() == budget)
            .ok_or("missing budget leaf")?;
        assert_eq!(
            budget_leaf.leaf.as_input().child_node_hashes,
            budget_children
        );
        children.push(copy.eop1_leaf.digest());
        children.extend(budget_children);
        assert_eq!(
            copy.opc1_leaf.as_input().child_node_hashes,
            sorted(children)
        );
    }
    Ok(())
}

#[test]
fn scope_builder_records_lease_members_edges_and_reference_states() -> TestResult {
    let (lease, scope) = owner_scope(&*public_configuration())?;
    let members = &scope.members;
    assert_eq!(
        scope.scope,
        WorldReplayClosureV1::artifact_scope(timeline(1), lease.digest())
    );
    assert_eq!(members.rls1_bytes, lease.to_canonical_cbor());
    assert_eq!(members.rtp1_bytes, retention_policy()?.to_canonical_cbor());
    let kinds = members
        .leaves
        .iter()
        .map(|member| member.leaf.as_input().kind.code())
        .collect::<Vec<_>>();
    assert_eq!(kinds, [1, 1, 2, 3, 4, 4, 5, 6, 7, 8, 9, 10, 10]);
    for member in &members.leaves {
        let leaf = member.leaf.as_input();
        let state = reference_state(leaf.kind);
        assert_eq!(member.state(), state);
        assert_eq!(
            member.native_bytes.is_empty(),
            state != ArtifactStateV1::Retained
        );
        assert_eq!(
            leaf.native_byte_length,
            u64::try_from(member.native_bytes.len())?
        );
        assert_eq!(
            leaf.data_class == ArtifactDataClassV1::PublicRecord,
            leaf.kind == WorldArtifactKindV1::BaseConfiguration
        );
    }
    let audience = member_of(members, WorldArtifactKindV1::AudiencePolicy)?;
    assert_eq!(audience.leaf.as_input().native_digest, hash(0xa6));
    let retention = member_of(members, WorldArtifactKindV1::RetentionPolicy)?;
    assert_eq!(
        retention.leaf.as_input().child_node_hashes,
        [audience.leaf.digest()]
    );
    let recorded_lease = member_of(members, WorldArtifactKindV1::RetentionLease)?;
    assert_eq!(recorded_lease.leaf.as_input().native_digest, lease.digest());
    assert_eq!(
        recorded_lease.leaf.as_input().child_node_hashes,
        [retention.leaf.digest()]
    );
    assert_policy_edges(&scope)?;
    let leaves = members.leaves.iter().map(|member| &member.leaf).chain(
        scope
            .policy_copies
            .iter()
            .flat_map(|copy| [&copy.eop1_leaf, &copy.opc1_leaf]),
    );
    for leaf in leaves {
        let fields = leaf.as_input();
        assert_eq!(fields.scope, scope.scope);
        assert_eq!(fields.owner, [7; 32]);
        assert_eq!(fields.optionality, ArtifactOptionalityV1::Required);
        assert_eq!(fields.source_lease_hash, lease.digest());
    }
    Ok(())
}

fn with_plugin_source(
    valid: &ManifestOwnerScopeSourceV1,
    (policy, closure): PolicySource,
) -> ManifestOwnerScopeSourceV1 {
    let mut source = valid.clone();
    source.policy_sources[1] = ManifestOwnerPolicySourceV1 {
        plugin_id: policy.fields().plugin_id,
        eop1_bytes: policy.to_canonical_cbor(),
        opc1_bytes: closure,
    };
    source
}

/// Plugin 2 sources whose members disagree with their EOP1 or the scope RTP1.
fn inconsistent_plugin_sources() -> FixtureResult<Vec<PolicySource>> {
    let members = native_members(plugin(2), 2)?;
    let input = policy_input(plugin(2), &members)?;
    let mut other_terms = retention_policy()?.as_input().clone();
    other_terms.policy_revision = 2;
    let other_retention = WorldRetentionPolicyV1::new(other_terms)?;
    let mut foreign_retention_hash = input.clone();
    foreign_retention_hash.retention_policy_hash = other_retention.digest();
    let mut foreign_retention_bytes = members.clone();
    foreign_retention_bytes.retention = other_retention.to_canonical_cbor();
    let mut foreign_configuration = input.clone();
    foreign_configuration.base_configuration_digest = hash(1);
    let mut foreign_implementation = input.clone();
    foreign_implementation.implementation_hash = hash(2);
    let mut foreign_budget = input.clone();
    foreign_budget.executable_profile_hash = hash(3);
    let mut foreign_profile = members.clone();
    foreign_profile.budget = budget(plugin(2), hash(4))?.to_canonical_cbor();
    let mut undecodable_budget = members.clone();
    undecodable_budget.budget = b"EBP1".to_vec();
    Ok(vec![
        assemble(foreign_retention_hash, &members)?,
        assemble(input.clone(), &foreign_retention_bytes)?,
        assemble(foreign_configuration, &members)?,
        assemble(foreign_implementation, &members)?,
        assemble(foreign_budget, &members)?,
        assemble(policy_input(plugin(2), &foreign_profile)?, &foreign_profile)?,
        assemble(input, &undecodable_budget)?,
    ])
}

#[test]
fn scope_builder_rejects_inconsistent_native_members() -> TestResult {
    let lease = default_lease(timeline(1))?;
    let valid = scope_source([7; 32], &lease, &sources()?)?;
    let mut candidates = vec![
        ManifestOwnerScopeSourceV1 {
            rtp1_bytes: b"RTP1".to_vec(),
            ..valid.clone()
        },
        ManifestOwnerScopeSourceV1 {
            rls1_bytes: b"RLS1".to_vec(),
            ..valid.clone()
        },
        ManifestOwnerScopeSourceV1 {
            rls1_bytes: default_lease(timeline(2))?.to_canonical_cbor(),
            ..valid.clone()
        },
    ];
    for source in inconsistent_plugin_sources()? {
        candidates.push(with_plugin_source(&valid, source));
    }
    let mut undecodable_eop1 = valid.clone();
    undecodable_eop1.policy_sources[1].eop1_bytes = b"EOP1".to_vec();
    let mut undecodable_opc1 = valid.clone();
    undecodable_opc1.policy_sources[1].opc1_bytes = b"OPC1".to_vec();
    candidates.extend([undecodable_eop1, undecodable_opc1]);
    for candidate in candidates {
        assert_eq!(
            build_manifest_owner_scope_v1(&candidate, &*structural()),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
    }

    let duplicate_key = WorldArtifactKeyDependencyV1 {
        role: pos_core::KeyRoleV1::SubjectDataEncryption,
        identity_digest: hash(5),
        owner: [5; 32],
    };
    let unordered_keys: Box<Classifier> = Box::new(move |_: WorldArtifactKindV1, _: Hash| {
        let mut keyed = classification(ArtifactDataClassV1::PrivateSubjectData);
        keyed.key_dependencies = vec![duplicate_key, duplicate_key];
        Some(keyed)
    });
    let unclassified: Box<Classifier> = Box::new(|_: WorldArtifactKindV1, _: Hash| None);
    for classify in [unordered_keys, unclassified] {
        assert_eq!(
            build_manifest_owner_scope_v1(&valid, &*classify),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
    }
    Ok(())
}

fn recorded_members(lease: &WorldRetentionLeaseV1) -> FixtureResult<ManifestOwnerScopeMembersV1> {
    Ok(ManifestOwnerScopeMembersV1 {
        rtp1_bytes: retention_policy()?.to_canonical_cbor(),
        rls1_bytes: lease.to_canonical_cbor(),
        leaves: Vec::new(),
    })
}

#[test]
fn lease_replacement_never_extends_the_recorded_lease() -> TestResult {
    let recorded = recorded_members(&retention_lease(timeline(1), 11, 111)?)?;
    let extension = Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
    for (closes_day, deadline_day, expected) in [
        (11, 111, Ok(())),
        (10, 110, Ok(())),
        (12, 111, extension),
        (11, 112, extension),
    ] {
        let next = recorded_members(&retention_lease(timeline(1), closes_day, deadline_day)?)?;
        assert_eq!(
            validate_manifest_owner_lease_replacement_v1(&recorded, &next),
            expected
        );
    }
    let undecodable = ManifestOwnerScopeMembersV1 {
        rls1_bytes: b"RLS1".to_vec(),
        ..recorded.clone()
    };
    assert_eq!(
        validate_manifest_owner_lease_replacement_v1(&undecodable, &recorded),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    assert_eq!(
        validate_manifest_owner_lease_replacement_v1(&recorded, &undecodable),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );
    Ok(())
}

const fn read_limits(
    max_node_visits: u64,
    max_native_bytes: u64,
    max_combined_depth: u8,
) -> WorldClosureReadLimitsV1 {
    WorldClosureReadLimitsV1 {
        max_node_visits,
        max_native_bytes,
        max_combined_depth,
    }
}

#[test]
fn preparation_checks_read_limits_and_the_retained_byte_budget() -> TestResult {
    let timeline_id = timeline(31);
    let operation_id = hash(131);
    let valid = request(genesis([31; 32], operation_id), &[timeline_id])?;
    let scope = &valid.timelines[0];
    let retained = scope
        .members
        .leaves
        .iter()
        .map(|member| member.native_bytes.len())
        .chain(
            scope
                .policy_copies
                .iter()
                .flat_map(|copy| [copy.eop1_bytes.len(), copy.opc1_bytes.len()]),
        )
        .sum::<usize>();
    let retained = u64::try_from(retained)?;
    let invalid = Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    for (limits, expected) in [
        (read_limits(0, retained, 32), invalid),
        (read_limits(1, retained, 0), invalid),
        (read_limits(1, retained, 33), invalid),
        (
            read_limits(1, retained - 1, 1),
            Err(ManifestOwnerAdmissionErrorV1::BoundExceeded),
        ),
        (read_limits(1, retained, 1), Ok(())),
    ] {
        let mut candidate = valid.clone();
        candidate.read_limits = limits;
        assert_eq!(
            manifest_owner_admission_intent_digest_v1(&candidate).map(drop),
            expected
        );
        let owner = FixtureOwner::new(vec![timeline_id], operation_id);
        assert_eq!(
            prepare_manifest_owner_admission_v1(candidate, &owner, None).map(drop),
            expected
        );
    }
    Ok(())
}

#[test]
fn intent_digest_binds_read_limits_lease_and_member_bytes() -> TestResult {
    let valid = request(genesis([32; 32], hash(132)), &[timeline(32)])?;
    let digest = manifest_owner_admission_intent_digest_v1(&valid)?;
    let mut limits = valid.clone();
    limits.read_limits.max_node_visits += 1;
    let mut lease = valid.clone();
    lease.timelines[0].members.rls1_bytes.push(0);
    let mut bytes = valid.clone();
    bytes.timelines[0].members.leaves[0].native_bytes.push(0);
    let mut leaves = valid;
    leaves.timelines[0].members.leaves.pop();
    for changed in [limits, lease, bytes, leaves] {
        assert_ne!(manifest_owner_admission_intent_digest_v1(&changed)?, digest);
    }
    Ok(())
}

fn with_children(
    leaf: &WorldArtifactLeafV1,
    child_node_hashes: Vec<Hash>,
) -> FixtureResult<WorldArtifactLeafV1> {
    Ok(WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
        child_node_hashes,
        ..leaf.as_input().clone()
    })?)
}

fn assert_rejected_before_signing(
    candidate: ManifestOwnerAdmissionRequestV1,
    owner: &FixtureOwner,
    expected: ManifestOwnerAdmissionErrorV1,
) {
    assert_eq!(
        prepare_manifest_owner_admission_v1(candidate, owner, None).map(drop),
        Err(expected)
    );
    assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
}

/// Requests that differ from the exact derivation in one checked part each.
fn underived_requests(
    valid: &ManifestOwnerAdmissionRequestV1,
) -> FixtureResult<Vec<ManifestOwnerAdmissionRequestV1>> {
    let timeline = &valid.timelines[0];
    let scope = ManifestOwnerScopeV1 {
        scope: timeline.scope,
        policy_copies: timeline.policy_copies.clone(),
        members: timeline.members.clone(),
    };
    let producer = sources()?.swap_remove(0);
    let mut unlinked_policy = valid.clone();
    let eop1_leaf = &mut unlinked_policy.timelines[0].policy_copies[0].eop1_leaf;
    let unlinked = with_children(eop1_leaf, Vec::new())?;
    *eop1_leaf = unlinked;
    let mut missing_member = valid.clone();
    missing_member.timelines[0].members.leaves.pop();
    let mut retained_reference = valid.clone();
    let references = &mut retained_reference.timelines[0].members.leaves;
    let audience = references
        .iter_mut()
        .find(|member| member.state() == ArtifactStateV1::MissingFrozenInput)
        .ok_or("missing audience reference leaf")?;
    audience.native_bytes = vec![1];
    let mut optional_view = valid.clone();
    optional_view.timelines[0].wcs1 = consumer_set(&scope, &producer, None, vec![hash(201)])?;
    let mut foreign_schema = valid.clone();
    foreign_schema.timelines[0].wcs1 =
        consumer_set(&scope, &producer, Some(hash(202)), Vec::new())?;
    Ok(vec![
        unlinked_policy,
        missing_member,
        retained_reference,
        optional_view,
        foreign_schema,
    ])
}

#[test]
fn preparation_requires_the_exact_derived_scope_members() -> TestResult {
    let timeline_id = timeline(33);
    let operation_id = hash(133);
    let valid = request(genesis([33; 32], operation_id), &[timeline_id])?;
    let owner = || FixtureOwner::new(vec![timeline_id], operation_id);
    for candidate in underived_requests(&valid)? {
        assert_rejected_before_signing(
            candidate,
            &owner(),
            ManifestOwnerAdmissionErrorV1::InvalidBatch,
        );
    }
    assert_rejected_before_signing(
        valid.clone(),
        &owner().with_member_fault(MemberFault::Misclassify),
        ManifestOwnerAdmissionErrorV1::InvalidBatch,
    );
    assert_rejected_before_signing(
        valid.clone(),
        &owner().with_member_fault(MemberFault::Reject),
        ManifestOwnerAdmissionErrorV1::OwnerRejected,
    );
    let prepared = prepare_manifest_owner_admission_v1(valid.clone(), &owner(), None)?;
    assert_eq!(prepared.input().read_limits, READ_LIMITS);
    assert_eq!(
        prepared.input().timelines[0].members,
        valid.timelines[0].members
    );
    Ok(())
}

type AdmissionOutcome = Result<ManifestOwnerAdmissionCommitKindV1, ManifestOwnerAdmissionErrorV1>;

fn commit<S: ManifestOwnerAdmissionPersistencePortV1>(
    store: &mut S,
    request: ManifestOwnerAdmissionRequestV1,
) -> FixtureResult<AdmissionOutcome> {
    let owner_id = request.catalog.as_input().owner_id;
    let current = store.read_manifest_owner_state_v1(owner_id)?;
    let timelines = request
        .timelines
        .iter()
        .map(|timeline| timeline.timeline_id)
        .collect();
    let owner = FixtureOwner::new(timelines, request.operation_id);
    let prepared = prepare_manifest_owner_admission_v1(request, &owner, current.as_ref())?;
    Ok(store
        .commit_manifest_owner_admission_v1(prepared)
        .map(|result| result.kind))
}

fn owner_state<S: ManifestOwnerAdmissionPersistencePortV1>(
    store: &S,
    owner_id: [u8; 32],
) -> FixtureResult<ManifestOwnerAdmissionOwnerStateV1> {
    store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or_else(|| "missing owner state".into())
}

fn successor(state: &ManifestOwnerAdmissionOwnerStateV1, operation: u8) -> AdmissionTransition {
    AdmissionTransition {
        owner_id: state.owner_id,
        generation: state.configuration_generation + 1,
        expected_generation: Some(state.configuration_generation),
        previous_receipt: state.previous_visible_lcq1_hash,
        expected_inventory: Some(state.inventory_generation),
        resulting_inventory: hash(operation + 1),
        operation_id: hash(operation),
    }
}

fn assert_recorded_scopes<S: ManifestOwnerAdmissionPersistencePortV1>(
    store: &S,
    request: &ManifestOwnerAdmissionRequestV1,
) -> TestResult {
    let owner_id = request.catalog.as_input().owner_id;
    let generation = request.catalog.as_input().configuration_generation;
    for timeline in &request.timelines {
        let snapshot = store
            .read_manifest_owner_admission_v1(owner_id, generation, timeline.timeline_id)?
            .ok_or("missing recorded scope")?;
        assert_eq!(snapshot.timeline.members, timeline.members);
        assert_eq!(snapshot.timeline.policy_copies, timeline.policy_copies);
        assert_eq!(snapshot.read_limits, request.read_limits);
    }
    Ok(())
}

/// Lease, deduplication and conflict rules that both stores apply identically.
fn assert_lease_and_member_rules<S: ManifestOwnerAdmissionPersistencePortV1>(
    mut store: S,
) -> TestResult {
    let owner_id = [34; 32];
    let applied = Ok(ManifestOwnerAdmissionCommitKindV1::Applied);
    let first = retention_lease(timeline(1), 11, 111)?;
    let second = retention_lease(timeline(2), 10, 100)?;
    let extended = retention_lease(timeline(1), 11, 112)?;
    let genesis_request = leased_request(
        genesis(owner_id, hash(140)),
        &[first, second],
        &*structural(),
    )?;
    assert_eq!(commit(&mut store, genesis_request.clone())?, applied);
    assert_recorded_scopes(&store, &genesis_request)?;

    let current = owner_state(&store, owner_id)?;
    let renewal = leased_request(
        successor(&current, 150),
        &[extended, second],
        &*structural(),
    )?;
    let reclassified = leased_request(
        successor(&current, 152),
        &[first, second],
        &*public_configuration(),
    )?;
    for (candidate, expected) in [
        (renewal, ManifestOwnerAdmissionErrorV1::OwnerRejected),
        (reclassified, ManifestOwnerAdmissionErrorV1::Conflict),
    ] {
        assert_eq!(commit(&mut store, candidate)?, Err(expected));
        assert_eq!(owner_state(&store, owner_id)?, current);
    }
    let unchanged = leased_request(successor(&current, 154), &[first, second], &*structural())?;
    assert_eq!(commit(&mut store, unchanged.clone())?, applied);
    assert_recorded_scopes(&store, &unchanged)?;

    // A Timeline that leaves the roster keeps its latest recorded lease.
    let current = owner_state(&store, owner_id)?;
    let removal = leased_request(successor(&current, 156), &[second], &*structural())?;
    assert_eq!(commit(&mut store, removal)?, applied);
    let current = owner_state(&store, owner_id)?;
    let readded = leased_request(
        successor(&current, 158),
        &[extended, second],
        &*structural(),
    )?;
    assert_eq!(
        commit(&mut store, readded)?,
        Err(ManifestOwnerAdmissionErrorV1::OwnerRejected)
    );
    let shortened = retention_lease(timeline(1), 11, 110)?;
    let readded = leased_request(
        successor(&current, 160),
        &[shortened, second],
        &*structural(),
    )?;
    assert_eq!(commit(&mut store, readded.clone())?, applied);
    assert_recorded_scopes(&store, &readded)
}

#[test]
fn memory_owner_admission_records_leases_and_member_leaves() -> TestResult {
    assert_lease_and_member_rules(MemoryStore::new())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_owner_admission_records_leases_and_member_leaves() -> TestResult {
    assert_lease_and_member_rules(SqliteStore::open_in_memory()?)
}
