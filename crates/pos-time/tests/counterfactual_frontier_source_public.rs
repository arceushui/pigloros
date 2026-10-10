//! Public-interface tests for the ADR-064 production frontier source over the
//! recorded dependency graph: differential against the hand-built `Source`
//! fixture through a scripted read port, and end to end through the
//! coordinator against both `MemoryStore` and `SqliteStore`.
#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyV1,
};
use pos_conformance::counterfactual::frontier_artifacts::UnknownEdgeCoordinateV1;
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanV1, FrozenArtifactDescriptorV1, PlanExecutionProfileRefV1,
    PlanTrustPolicyRefV1,
};
use pos_conformance::counterfactual::{InterventionOperationV1, InterventionV1};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1, DependencyClassV1,
    DependencyNodeV1, ExecutionProfileV1, ReplayClaimV1, TrustPolicySnapshotV1,
    UnknownEdgePolicyV1,
};
use pos_core::counterfactual_store::test_fixtures::SeededFactualTickV1;
use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, CoreError, CounterfactualBasisV1,
    CounterfactualDependencyReadPortV1, CounterfactualDependencyRecordingPortV1,
    CounterfactualFactsV1, CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1 as StoreError,
    CounterfactualStorePortV1, CounterfactualTickOutcomeV1, DependencyEdgeRecordV1,
    DependencyNodeCoordinateV1, DependencyNodeRecordV1, DependencyPageRequestV1, DependencyPageV1,
    DependencyPagedRowV1, DependencyReadScopeV1, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, EventDraft,
    EventReadBounds, EventStore, ForkGenerationV1, Hash, Kind, PipelineDraftBatchV1,
    RecordedDependencyClassV1, RecordedNodeOriginV1, RegisteredArtifactV1, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, Seq, SeqRange, TickDependencyRecordV1, Timeline, TimelineId,
    TimelineMeta, MAX_DEPENDENCY_PAGE_ROWS_V1,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1 as AdmissionError, CounterfactualAdmissionRequestV1,
    CounterfactualCoordinatorV1, CounterfactualDeclaringTickStagerV1,
    CounterfactualForkAppendAuthorityV1, CounterfactualFrontierDerivationV1,
    CounterfactualFrontierSourceV1, CounterfactualFrozenArtifactsV1, CounterfactualHostPreflightV1,
    CounterfactualInterventionAuthorityV1, CounterfactualProvisionalOutputV1,
    CounterfactualStagedTickV1, CounterfactualTickFailureV1, CounterfactualTickInputsV1,
    FrozenArtifactAvailabilityV1, InterventionDecisionV1,
};
use pos_runtime::counterfactual::suffix::CounterfactualSuffixRequestV1;
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use pos_time::counterfactual::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1 as Bounds, DependencyGraphErrorV1,
    DependencyGraphNodeOriginV1 as Origin, DependencyGraphNodeV1 as Node,
    ValidatedDependencyGraphV1, MAX_DEPENDENCY_GRAPH_NODES_V1,
};
use pos_time::counterfactual::frontier::{
    dependency_graph_digest_v1, derive_recomputation_frontier_v1,
};
use pos_time::counterfactual::frontier_source::RecordedFrontierSourceV1;
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type EdgeKey = (u64, u32, String, u32, [u8; 32]);
/// The recorded node and edge rows of one scope, in canonical order.
type Rows = (Vec<DependencyNodeRecordV1>, Vec<DependencyEdgeRecordV1>);
/// The declared nodes and edges of one Tick record.
type Declaration = Rows;
/// One page request the scripted port saw: its scope, row kind, and limit.
type Request = (DependencyReadScopeV1, RowKind, usize);

const EXOGENOUS: usize = 0;
const PARENT: usize = 1;
const FIXED: usize = 2;
const EARLY_WORLD: usize = 3;
const INTERVENTION_A: usize = 4;
const WORLD_A: usize = 5;
const AGENT_C: usize = 6;
const INTERVENTION_B: usize = 7;
const AGENT_B: usize = 8;
const WORLD_D: usize = 9;
const VIEW: usize = 10;
const WEATHER: usize = 11;
/// `(consumer, source)` node positions of every edge in the base graph.
const EDGE_SPECS: [(usize, usize); 14] = [
    (PARENT, EXOGENOUS),
    (EARLY_WORLD, PARENT),
    (EARLY_WORLD, FIXED),
    (WORLD_A, EARLY_WORLD),
    (WORLD_A, INTERVENTION_A),
    (WORLD_A, FIXED),
    (AGENT_C, WORLD_A),
    (AGENT_C, INTERVENTION_A),
    (AGENT_B, EARLY_WORLD),
    (AGENT_B, INTERVENTION_B),
    (WORLD_D, WORLD_A),
    (WORLD_D, AGENT_B),
    (VIEW, WORLD_D),
    (WEATHER, EXOGENOUS),
];
/// The base-graph positions a Fork alone records: the committed `PARENT` and
/// the unrecomputed `EARLY_WORLD` are left out and `EXOGENOUS` moves to the
/// first Tick, so every node is provisional and lies at or after it.
const FORK_ONLY: [usize; 10] = [
    EXOGENOUS,
    FIXED,
    INTERVENTION_A,
    WORLD_A,
    AGENT_C,
    INTERVENTION_B,
    AGENT_B,
    WORLD_D,
    VIEW,
    WEATHER,
];
const BOUNDS: Bounds = Bounds {
    max_nodes: 5_000,
    max_edges: 5_000,
};
const DESCRIPTOR_AUTHORIZATION: [u8; 32] = [0x61; 32];
const DESCRIPTOR_PROVENANCE: [u8; 32] = [0x62; 32];
const CONSENT_DECISION: [u8; 32] = [4; 32];
const INTERVENTION_PROVENANCE: [u8; 32] = [6; 32];
const ENDOGENOUS_AUTHORIZATION: [u8; 32] = [0x72; 32];
const NODE_PROVENANCE: [u8; 32] = [0x71; 32];
const ROOM_ID: &str = "room.alpha";
const ROOM_DIGEST: [u8; 32] = [2; 32];
const COMPOSITION_DIGEST: [u8; 32] = [6; 32];
const PARENT_CUT_TICK: u64 = 9;
const FIRST_TICK: u64 = 10;
const HORIZON_TICK: u64 = 20;
/// The global frontier of the base graph, the first recomputation Tick.
const FRONTIER_TICK: u64 = 11;
const CUT_SEQ: u64 = 2;
const FRONTIER_ID: [u8; 16] = [0x81; 16];
const INVALIDATION_ID: [u8; 16] = [0x91; 16];
const PROVENANCE: [u8; 32] = [0x82; 32];
const REVOCATION_EPOCH: u64 = 7;
const ERASURE_EPOCH: u64 = 8;
const RESULT_ID: [u8; 16] = [0xa1; 16];
const EVALUATOR: [u8; 32] = [0xa2; 32];
/// An `IDP1` class code outside the closed set.
const UNKNOWN_CLASS_CODE: u8 = 0x05;

fn root_id() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x5100_u128))
}

fn fork_id() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x5200_u128))
}

fn other_fork_id() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x5300_u128))
}

fn generation(number: u64) -> ForkGenerationV1 {
    ForkGenerationV1 {
        fork: fork_id(),
        generation: number,
    }
}

fn event_draft(kind: &str, payload: Vec<u8>) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(kind),
        CanonicalBytes::from_vec(payload),
    )
}

/// The two deterministic Events every recomputation Tick stages.
fn tick_drafts(tick: u64) -> Vec<EventDraft> {
    (0..2_u64)
        .map(|ordinal| {
            let mut payload = tick.to_be_bytes().to_vec();
            payload.extend_from_slice(&ordinal.to_be_bytes());
            event_draft("counterfactual.world", payload)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plan and host records
// ---------------------------------------------------------------------------

fn intervention(effective_tick: u64, id_seed: u8) -> InterventionV1 {
    InterventionV1 {
        intervention_id: [id_seed; 16],
        target_schema_id: 7,
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: [2; 32],
        effective_tick,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        consent_decision_digest: CONSENT_DECISION,
        rationale: "what if".to_owned(),
        provenance_digest: INTERVENTION_PROVENANCE,
    }
}

const fn descriptor(schema_id: u32, seed: u8) -> FrozenArtifactDescriptorV1 {
    FrozenArtifactDescriptorV1 {
        schema_id,
        artifact_digest: [seed; 32],
        authorization_digest: DESCRIPTOR_AUTHORIZATION,
        provenance_digest: DESCRIPTOR_PROVENANCE,
    }
}

/// The plan and the host records it binds.
struct Host {
    plan: CounterfactualPlanV1,
    profile: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
    claim: ReplayClaimEvaluationV1,
}

/// The host's evaluation of one retained `Exact` Export artifact.
fn exact_evaluation() -> TestResult<ReplayClaimEvaluationV1> {
    let claim = ErasureReplayClaimV1::Exact;
    Ok(ReplayClaimEvaluatorV1::evaluate(
        claim,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                ErasureReferenceV1::from_digest([201; 32]),
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([202; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: claim,
            state: ArtifactStateV1::Retained,
        }],
    )?)
}

/// The sealed plan after `edit`, with the host records it binds.
fn host(edit: fn(&mut CounterfactualPlanV1)) -> TestResult<Host> {
    let profile = ExecutionProfileV1::from_canonical_cbor(&draft_execution_profile_bytes_v1(
        "deterministic-local-v1",
    )?)?;
    let snapshot =
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
    let mut plan = CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: ROOM_ID.to_owned(),
        room_digest: ROOM_DIGEST,
        parent_timeline_id: root_id().inner().to_bytes(),
        parent_cut_seq: CUT_SEQ,
        parent_cut_tick: PARENT_CUT_TICK,
        parent_cut_digest: [4; 32],
        first_tick: FIRST_TICK,
        horizon_tick: HORIZON_TICK,
        interventions: vec![intervention(11, 1), intervention(13, 2)],
        exogenous_descriptors: vec![descriptor(1, 0x50)],
        fixed_policy_descriptors: vec![descriptor(3, 0x30)],
        classification_bundle_digest: [5; 32],
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
        execution_profile: PlanExecutionProfileRefV1::from_execution_profile_v1(&profile)?,
        trust_policy: PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(&snapshot)?,
        plugin_composition_digest: COMPOSITION_DIGEST,
        scheduler_digest: [7; 32],
        numeric_profile_digest: [8; 32],
        budget_digest: [9; 32],
        failure_policy_digest: [10; 32],
        replay_claim: ReplayClaimV1::Exact,
        previous_plan_digest: None,
        plan_digest: [0; 32],
    };
    edit(&mut plan);
    plan.plan_digest = plan.digest()?;
    Ok(Host {
        plan,
        profile,
        snapshot,
        claim: exact_evaluation()?,
    })
}

fn plan(edit: fn(&mut CounterfactualPlanV1)) -> TestResult<CounterfactualPlanV1> {
    Ok(host(edit)?.plan)
}

// ---------------------------------------------------------------------------
// The hand-built graph and the test `Source` over it
// ---------------------------------------------------------------------------

const fn endogenous_digest(seed: u8) -> [u8; 32] {
    [0xd0 + seed; 32]
}

/// One node whose schema, origin, and provenance follow from its class and Tick.
fn node(
    tick: u64,
    scheduler_position: u32,
    owner_id: &str,
    artifact_digest: [u8; 32],
    class: DependencyClassV1,
) -> Node {
    let (schema_id, provenance_digest) = match class {
        DependencyClassV1::ExogenousFrozen => (1, DESCRIPTOR_PROVENANCE),
        DependencyClassV1::FixedPolicy => (3, DESCRIPTOR_PROVENANCE),
        DependencyClassV1::InterventionAssigned => (7, INTERVENTION_PROVENANCE),
        DependencyClassV1::EndogenousRecomputed => (40, NODE_PROVENANCE),
        DependencyClassV1::PresentationOnly => (50, NODE_PROVENANCE),
    };
    Node {
        node: DependencyNodeV1 {
            tick,
            scheduler_position,
            owner_id: owner_id.to_owned(),
            output_ordinal: 0,
            schema_id,
            artifact_digest,
        },
        class,
        origin: if tick <= PARENT_CUT_TICK {
            Origin::Committed
        } else {
            Origin::Provisional
        },
        input_digests: Vec::new(),
        provenance_digest,
    }
}

fn endogenous(tick: u64, scheduler_position: u32, owner_id: &str, seed: u8) -> Node {
    node(
        tick,
        scheduler_position,
        owner_id,
        endogenous_digest(seed),
        DependencyClassV1::EndogenousRecomputed,
    )
}

fn intervention_node(plan: &CounterfactualPlanV1, position: usize) -> TestResult<Node> {
    let intervention = &plan.interventions[position];
    Ok(node(
        intervention.effective_tick,
        0,
        "intervention",
        intervention.digest()?,
        DependencyClassV1::InterventionAssigned,
    ))
}

fn base_nodes(plan: &CounterfactualPlanV1) -> TestResult<Vec<Node>> {
    Ok(vec![
        node(5, 0, "env", [0x50; 32], DependencyClassV1::ExogenousFrozen),
        endogenous(9, 1, "world", 1),
        node(10, 0, "policy", [0x30; 32], DependencyClassV1::FixedPolicy),
        endogenous(10, 1, "world", 2),
        intervention_node(plan, 0)?,
        endogenous(12, 0, "world", 3),
        endogenous(12, 1, "agent", 4),
        intervention_node(plan, 1)?,
        endogenous(14, 0, "agent", 5),
        endogenous(14, 1, "world", 6),
        node(
            15,
            0,
            "ui",
            endogenous_digest(7),
            DependencyClassV1::PresentationOnly,
        ),
        endogenous(16, 0, "weather", 8),
    ])
}

const fn authorization_for(class: DependencyClassV1) -> [u8; 32] {
    match class {
        DependencyClassV1::ExogenousFrozen | DependencyClassV1::FixedPolicy => {
            DESCRIPTOR_AUTHORIZATION
        }
        DependencyClassV1::InterventionAssigned => CONSENT_DECISION,
        DependencyClassV1::EndogenousRecomputed | DependencyClassV1::PresentationOnly => {
            ENDOGENOUS_AUTHORIZATION
        }
    }
}

fn edge(consumer: &Node, source: &Node) -> InputDependencyV1 {
    InputDependencyV1 {
        consumer: consumer.node.clone(),
        source: source.node.clone(),
        dependency_class: source.class,
        tick_range: DependencyTickRangeV1 {
            first_tick: source.node.tick,
            last_tick: consumer.node.tick,
        },
        authorization_digest: authorization_for(source.class),
        classification_rule: DependencyClassificationRuleV1 {
            rule_id: "classify.v1".to_owned(),
            rule_version: 1,
        },
        provenance_digest: [0x73; 32],
    }
}

fn edge_key(edge: &InputDependencyV1) -> EdgeKey {
    (
        edge.consumer.tick,
        edge.consumer.scheduler_position,
        edge.consumer.owner_id.clone(),
        edge.consumer.output_ordinal,
        edge.source.artifact_digest,
    )
}

/// The hand-built graph: the `pos-time` validation and derivation behind
/// the port, exactly as the coordinator tests build it.
struct Graph {
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
}

/// Declare every input of `specs`, and build an edge for every spec except
/// those in `omitted`, which stay declared but missing.
fn connect(mut nodes: Vec<Node>, specs: &[(usize, usize)], omitted: &[(usize, usize)]) -> Graph {
    for &(consumer, source) in specs {
        let digest = nodes[source].node.artifact_digest;
        nodes[consumer].input_digests.push(digest);
    }
    for node in &mut nodes {
        node.input_digests.sort_unstable();
    }
    let mut edges: Vec<_> = specs
        .iter()
        .filter(|spec| !omitted.contains(spec))
        .map(|&(consumer, source)| edge(&nodes[consumer], &nodes[source]))
        .collect();
    edges.sort_by_key(edge_key);
    Graph { nodes, edges }
}

/// The base graph of `plan`, omitting the `omitted` edges.
fn graph_with(plan: &CounterfactualPlanV1, omitted: &[(usize, usize)]) -> TestResult<Graph> {
    Ok(connect(base_nodes(plan)?, &EDGE_SPECS, omitted))
}

/// The graph a Fork alone records: the [`FORK_ONLY`] nodes, all provisional,
/// with every base edge between them and the frozen input of `WORLD_A`.
fn fork_graph(plan: &CounterfactualPlanV1) -> TestResult<Graph> {
    let base = base_nodes(plan)?;
    let mut nodes: Vec<Node> = FORK_ONLY
        .iter()
        .map(|&position| base[position].clone())
        .collect();
    nodes[0].node.tick = FIRST_TICK;
    nodes[0].origin = Origin::Provisional;
    let position = |wanted: usize| FORK_ONLY.iter().position(|&kept| kept == wanted);
    let specs: Vec<(usize, usize)> = EDGE_SPECS
        .iter()
        .chain(&[(WORLD_A, EXOGENOUS)])
        .filter_map(|&(consumer, source)| position(consumer).zip(position(source)))
        .collect();
    Ok(connect(nodes, &specs, &[]))
}

// `graph_error` and `Graph::derive_frontier` below are a deliberate,
// independent oracle for the differential test: they re-derive the expected
// outcome straight from the validator and must not share code with the source.
fn graph_error(error: DependencyGraphErrorV1) -> AdmissionError {
    match error {
        DependencyGraphErrorV1::DependencyGraphIncomplete(coordinate) => {
            AdmissionError::DependencyGraphIncomplete(*coordinate)
        }
        DependencyGraphErrorV1::UnknownDependencyEdge(coordinate) => {
            AdmissionError::UnknownDependencyEdge(*coordinate)
        }
        _ => AdmissionError::DependencyGraphInvalid,
    }
}

impl Graph {
    fn graph(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<ValidatedDependencyGraphV1, DependencyGraphErrorV1> {
        validate_dependency_graph_v1(plan, BOUNDS, self.nodes.clone(), self.edges.clone())
    }

    fn graph_digest(&self, plan: &CounterfactualPlanV1) -> TestResult<[u8; 32]> {
        Ok(dependency_graph_digest_v1(&self.graph(plan)?))
    }
}

impl CounterfactualFrontierSourceV1 for Graph {
    fn derive_frontier(
        &mut self,
        plan: &CounterfactualPlanV1,
        frontier_id: [u8; 16],
        provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, AdmissionError> {
        let graph = self.graph(plan).map_err(graph_error)?;
        let frontier =
            derive_recomputation_frontier_v1(plan, &graph, frontier_id, provenance_digest)
                .or(Err(AdmissionError::DependencyGraphInvalid))?;
        let provisional_outputs = graph
            .nodes()
            .iter()
            .filter(|node| node.origin == Origin::Provisional)
            .map(|node| CounterfactualProvisionalOutputV1 {
                node: node.node.clone(),
                class: node.class,
            })
            .collect();
        Ok(CounterfactualFrontierDerivationV1 {
            frontier,
            provisional_outputs,
        })
    }
}

/// The derivation of `source` for `plan`, as the coordinator requests it.
///
/// A macro, not a function: the admission error is too large to return from
/// a helper (`result_large_err`).
macro_rules! derivation {
    ($source:expr_2021, $plan:expr_2021) => {
        $source.derive_frontier($plan, FRONTIER_ID, PROVENANCE)
    };
}

// ---------------------------------------------------------------------------
// Recorded rows
// ---------------------------------------------------------------------------

const fn recorded_class(class: DependencyClassV1) -> RecordedDependencyClassV1 {
    match class {
        DependencyClassV1::ExogenousFrozen => RecordedDependencyClassV1::ExogenousFrozen,
        DependencyClassV1::InterventionAssigned => RecordedDependencyClassV1::InterventionAssigned,
        DependencyClassV1::EndogenousRecomputed => RecordedDependencyClassV1::EndogenousRecomputed,
        DependencyClassV1::FixedPolicy => RecordedDependencyClassV1::FixedPolicy,
        DependencyClassV1::PresentationOnly => RecordedDependencyClassV1::PresentationOnly,
    }
}

const fn recorded_origin(origin: Origin) -> RecordedNodeOriginV1 {
    match origin {
        Origin::Committed => RecordedNodeOriginV1::Committed,
        Origin::Provisional => RecordedNodeOriginV1::Provisional,
    }
}

fn coordinate(node: &DependencyNodeV1) -> TestResult<DependencyNodeCoordinateV1> {
    Ok(DependencyNodeCoordinateV1::try_new(
        node.tick,
        node.scheduler_position,
        node.owner_id.clone(),
        node.output_ordinal,
        node.schema_id,
        Hash::from_bytes(node.artifact_digest),
    )?)
}

/// The record of one graph node, under the node's own origin.
fn node_record(node: &Node) -> TestResult<DependencyNodeRecordV1> {
    Ok(DependencyNodeRecordV1::try_new(
        coordinate(&node.node)?,
        recorded_class(node.class),
        recorded_origin(node.origin),
        node.input_digests
            .iter()
            .copied()
            .map(Hash::from_bytes)
            .collect(),
        Hash::from_bytes(node.provenance_digest),
    )?)
}

/// The record of one graph edge: its exact `IDP1` bytes bound to its
/// consumer and source.
fn edge_record(edge: &InputDependencyV1) -> TestResult<DependencyEdgeRecordV1> {
    Ok(DependencyEdgeRecordV1::try_from_canonical(
        edge.to_canonical_cbor()?,
        coordinate(&edge.consumer)?,
        Hash::from_bytes(edge.source.artifact_digest),
    )?)
}

/// The record of `edge` with its class code outside the closed set: the
/// record contract accepts the well-formed item, the `IDP1` codec does not.
fn corrupted_edge_record(edge: &InputDependencyV1) -> TestResult<DependencyEdgeRecordV1> {
    let mut bytes = edge.to_canonical_cbor()?;
    let digest = edge.source.artifact_digest;
    let class_at = bytes
        .windows(32)
        .position(|window| window == digest.as_slice())
        .ok_or("source digest not found")?
        + 32;
    assert_eq!(bytes[class_at], edge.dependency_class.wire_code());
    bytes[class_at] = UNKNOWN_CLASS_CODE;
    Ok(DependencyEdgeRecordV1::try_from_canonical(
        bytes,
        coordinate(&edge.consumer)?,
        Hash::from_bytes(digest),
    )?)
}

/// The rows of `graph` as the store records them: the committed nodes and
/// the edges consumed at or before the cut in the parent prefix, the rest in
/// the Fork generation.
fn split_rows(graph: &Graph) -> TestResult<(Rows, Rows)> {
    let mut prefix: Rows = (Vec::new(), Vec::new());
    let mut fork: Rows = (Vec::new(), Vec::new());
    for node in &graph.nodes {
        let record = node_record(node)?;
        if node.origin == Origin::Committed {
            prefix.0.push(record);
        } else {
            fork.0.push(record);
        }
    }
    for edge in &graph.edges {
        let record = edge_record(edge)?;
        if edge.consumer.tick <= PARENT_CUT_TICK {
            prefix.1.push(record);
        } else {
            fork.1.push(record);
        }
    }
    Ok((prefix, fork))
}

// ---------------------------------------------------------------------------
// The scripted read port
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowKind {
    Nodes,
    Edges,
}

static NO_ROWS: Rows = (Vec::new(), Vec::new());

/// A read port over scripted rows. It serves the prefix rows it holds as they
/// are, so a test can make it dishonest, and qualifies Fork reads by the
/// committed generation like an adapter.
#[derive(Default)]
struct FakePort {
    prefixes: BTreeMap<TimelineId, Rows>,
    /// Per Fork: the committed generation and the rows of every generation.
    forks: BTreeMap<TimelineId, (u64, BTreeMap<u64, Rows>)>,
    fault: Option<StoreError>,
    requests: RefCell<Vec<Request>>,
}

impl FakePort {
    /// A port whose parent prefix holds `prefix` and whose Fork committed
    /// `current` with the rows of `generations`.
    fn recorded(prefix: Rows, current: u64, generations: Vec<(u64, Rows)>) -> Self {
        let mut port = Self::default();
        port.prefixes.insert(root_id(), prefix);
        port.forks
            .insert(fork_id(), (current, generations.into_iter().collect()));
        port
    }

    fn rows(&self, scope: DependencyReadScopeV1) -> Result<&Rows, StoreError> {
        match scope {
            DependencyReadScopeV1::ParentPrefix { timeline, .. } => {
                self.prefixes.get(&timeline).ok_or(StoreError::ForkNotFound)
            }
            DependencyReadScopeV1::ForkGeneration(at) => {
                let (current, generations) =
                    self.forks.get(&at.fork).ok_or(StoreError::ForkNotFound)?;
                scope.ensure_current(*current)?;
                Ok(generations.get(&at.generation).unwrap_or(&NO_ROWS))
            }
        }
    }

    fn page<T: DependencyPagedRowV1 + Clone>(
        &self,
        kind: RowKind,
        request: &DependencyPageRequestV1,
        rows: &[T],
    ) -> Result<DependencyPageV1<T>, StoreError> {
        self.requests
            .borrow_mut()
            .push((request.scope(), kind, request.limit()));
        self.fault.map_or(Ok(()), Err)?;
        Ok(DependencyPageV1::from_ordered(request, rows)?)
    }

    /// How many pages of `kind` the Fork scope (or the prefix) was asked for.
    fn pages(&self, fork_scope: bool, kind: RowKind) -> usize {
        self.requests
            .borrow()
            .iter()
            .filter(|&&(scope, seen, _)| {
                matches!(scope, DependencyReadScopeV1::ForkGeneration(_)) == fork_scope
                    && seen == kind
            })
            .count()
    }
}

impl CounterfactualDependencyReadPortV1 for FakePort {
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, StoreError> {
        let (nodes, _) = self.rows(request.scope())?;
        self.page(RowKind::Nodes, request, nodes)
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, StoreError> {
        let (_, edges) = self.rows(request.scope())?;
        self.page(RowKind::Edges, request, edges)
    }
}

/// The production source over `port` at generation `number`.
fn production(
    port: FakePort,
    number: u64,
    page_limit: usize,
) -> RecordedFrontierSourceV1<FakePort> {
    RecordedFrontierSourceV1::new(port, generation(number), BOUNDS).with_page_limit(page_limit)
}

/// A production source at generation 1 over the recorded rows of `graph`.
fn recorded_source(
    graph: &Graph,
    page_limit: usize,
) -> TestResult<RecordedFrontierSourceV1<FakePort>> {
    let (prefix, fork) = split_rows(graph)?;
    Ok(production(
        FakePort::recorded(prefix, 1, vec![(1, fork)]),
        1,
        page_limit,
    ))
}

// ---------------------------------------------------------------------------
// Differential scenarios
// ---------------------------------------------------------------------------

#[test]
fn matches_the_hand_built_source_for_every_page_size() -> TestResult {
    let plan = plan(|_| {})?;
    let mut hand_built = graph_with(&plan, &[])?;
    let expected = derivation!(&mut hand_built, &plan)?;
    let expected_graph = hand_built.graph(&plan)?;
    let (prefix, fork) = split_rows(&hand_built)?;
    let counts = [prefix.0.len(), prefix.1.len(), fork.0.len(), fork.1.len()];
    assert_eq!(counts, [2, 1, 10, 13]);
    for limit in [1, 2, 3, 7, MAX_DEPENDENCY_PAGE_ROWS_V1] {
        let port = FakePort::recorded(prefix.clone(), 1, vec![(1, fork.clone())]);
        let mut source = production(port, 1, limit);
        assert_eq!(source.page_limit(), limit);
        assert_eq!(derivation!(&mut source, &plan)?, expected);
        assert_eq!(source.recorded_graph(&plan)?, expected_graph);
        assert_eq!(
            source.recorded_graph_digest(&plan)?,
            dependency_graph_digest_v1(&expected_graph)
        );
        assert_eq!(
            source.recorded_graph_digest(&plan)?,
            expected.frontier.dependency_graph_digest
        );
        // Each of the four reads pages every scope and row kind until the
        // continuation is exhausted: one page per `limit` rows, at least one.
        let requests = source.port().requests.borrow();
        assert!(requests.iter().all(|&(_, _, asked)| asked == limit));
        let pages: usize = counts
            .iter()
            .map(|&count| count.div_ceil(limit).max(1))
            .sum();
        assert_eq!(requests.len(), 4 * pages);
    }
    assert_eq!(production(FakePort::default(), 1, 0).page_limit(), 1);
    assert_eq!(
        production(FakePort::default(), 1, usize::MAX).page_limit(),
        MAX_DEPENDENCY_PAGE_ROWS_V1
    );
    let source = production(FakePort::default(), 3, 4);
    assert_eq!(source.generation(), generation(3));
    assert_eq!(source.bounds(), BOUNDS);
    Ok(())
}

#[test]
fn reads_only_the_committed_generation() -> TestResult {
    let plan = plan(|_| {})?;
    let mut hand_built = graph_with(&plan, &[])?;
    let expected = derivation!(&mut hand_built, &plan)?;
    let (prefix, fork) = split_rows(&hand_built)?;
    // Generation 1 is quarantined behind generation 2, which holds the same rows.
    let both = || vec![(1, fork.clone()), (2, fork.clone())];
    let mut stale = production(FakePort::recorded(prefix.clone(), 2, both()), 1, 3);
    assert_eq!(
        derivation!(&mut stale, &plan),
        Err(AdmissionError::Store(StoreError::MixedForkGeneration))
    );
    let mut current = production(FakePort::recorded(prefix.clone(), 2, both()), 2, 3);
    assert_eq!(derivation!(&mut current, &plan)?, expected);
    // Rows recorded only under the quarantined generation never contribute:
    // generation 2 is empty, so only the prefix remains and no Intervention
    // node exists.
    let quarantined = vec![(1, fork)];
    let mut source = production(FakePort::recorded(prefix, 2, quarantined), 2, 3);
    assert_eq!(
        derivation!(&mut source, &plan),
        Err(AdmissionError::DependencyGraphInvalid)
    );
    Ok(())
}

#[test]
fn reports_a_missing_edge_under_reject_and_falls_back_under_full_suffix() -> TestResult {
    let omitted = (WORLD_D, WORLD_A);
    let reject = plan(|_| {})?;
    let incomplete = graph_with(&reject, &[omitted])?;
    let mut source = recorded_source(&incomplete, 4)?;
    assert_eq!(
        derivation!(&mut source, &reject),
        Err(AdmissionError::DependencyGraphIncomplete(
            UnknownEdgeCoordinateV1 {
                consumer: incomplete.nodes[WORLD_D].node.clone(),
                missing_source_digest: Some(incomplete.nodes[WORLD_A].node.artifact_digest),
            }
        ))
    );
    // The same recorded rows under the fallback policy, which only the plan
    // carries, derive the full-suffix frontier.
    let fallback = plan(|plan| plan.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut)?;
    let mut hand_built = graph_with(&fallback, &[omitted])?;
    let expected = derivation!(&mut hand_built, &fallback)?;
    assert_eq!(
        expected.frontier.unknown_edge_policy,
        UnknownEdgePolicyV1::FullSuffixFromCut
    );
    assert_eq!(derivation!(&mut source, &fallback)?, expected);
    assert_eq!(
        source.recorded_graph_digest(&fallback)?,
        hand_built.graph_digest(&fallback)?
    );
    Ok(())
}

#[test]
fn reports_an_edge_whose_consumer_is_not_recorded() -> TestResult {
    let plan = plan(|_| {})?;
    let hand_built = graph_with(&plan, &[])?;
    let (prefix, mut fork) = split_rows(&hand_built)?;
    // The `VIEW` node is not recorded, but its edge from `WORLD_D` is.
    let view = coordinate(&hand_built.nodes[VIEW].node)?;
    fork.0.retain(|node| *node.coordinate() != view);
    let mut source = production(FakePort::recorded(prefix, 1, vec![(1, fork)]), 1, 4);
    assert_eq!(
        derivation!(&mut source, &plan),
        Err(AdmissionError::UnknownDependencyEdge(
            UnknownEdgeCoordinateV1 {
                consumer: hand_built.nodes[VIEW].node.clone(),
                missing_source_digest: Some(hand_built.nodes[WORLD_D].node.artifact_digest),
            }
        ))
    );
    Ok(())
}

#[test]
fn other_rejections_are_invalid_graphs() -> TestResult {
    let plan = plan(|_| {})?;
    // An empty store: the prefix has no write path yet and the generation has
    // no record, so no Intervention node exists.
    let empty = FakePort::recorded((Vec::new(), Vec::new()), 1, Vec::new());
    assert_eq!(
        derivation!(&mut production(empty, 1, 4), &plan),
        Err(AdmissionError::DependencyGraphInvalid)
    );
    // Bounds above the hard maximum are the validator's `FieldOutOfBounds`.
    let hand_built = graph_with(&plan, &[])?;
    let (prefix, fork) = split_rows(&hand_built)?;
    let bounds = Bounds {
        max_nodes: MAX_DEPENDENCY_GRAPH_NODES_V1 + 1,
        max_edges: 5_000,
    };
    let port = FakePort::recorded(prefix, 1, vec![(1, fork)]);
    let mut oversized = RecordedFrontierSourceV1::new(port, generation(1), bounds);
    assert_eq!(oversized.bounds(), bounds);
    assert_eq!(
        derivation!(&mut oversized, &plan),
        Err(AdmissionError::DependencyGraphInvalid)
    );
    // A derivation failure over a valid graph: zero provenance.
    let mut source = recorded_source(&hand_built, 4)?;
    assert_eq!(
        source.derive_frontier(&plan, FRONTIER_ID, [0; 32]),
        Err(AdmissionError::DependencyGraphInvalid)
    );
    assert_eq!(source.recorded_graph(&plan)?, hand_built.graph(&plan)?);
    Ok(())
}

#[test]
fn port_failures_are_store_errors() -> TestResult {
    let plan = plan(|_| {})?;
    let hand_built = graph_with(&plan, &[])?;
    let (prefix, fork) = split_rows(&hand_built)?;
    let recorded = || FakePort::recorded(prefix.clone(), 1, vec![(1, fork.clone())]);
    // An unknown or erased parent Timeline is never an empty prefix.
    let mut port = recorded();
    port.prefixes.clear();
    assert_eq!(
        derivation!(&mut production(port, 1, 4), &plan),
        Err(AdmissionError::Store(StoreError::ForkNotFound))
    );
    let mut port = recorded();
    port.forks.clear();
    assert_eq!(
        derivation!(&mut production(port, 1, 4), &plan),
        Err(AdmissionError::Store(StoreError::ForkNotFound))
    );
    let mut port = recorded();
    port.fault = Some(StoreError::StorageFailure);
    assert_eq!(
        derivation!(&mut production(port, 1, 4), &plan),
        Err(AdmissionError::Store(StoreError::StorageFailure))
    );
    Ok(())
}

#[test]
fn corrupt_stored_rows_are_corrupt_state() -> TestResult {
    let plan = plan(|_| {})?;
    let hand_built = graph_with(&plan, &[])?;
    let (prefix, fork) = split_rows(&hand_built)?;
    // A recorded edge the `IDP1` codec rejects.
    let mut corrupt = prefix.clone();
    corrupt.1[0] = corrupted_edge_record(&hand_built.edges[0])?;
    let mut source = production(
        FakePort::recorded(corrupt, 1, vec![(1, fork.clone())]),
        1,
        4,
    );
    assert_eq!(
        derivation!(&mut source, &plan),
        Err(AdmissionError::Store(StoreError::CorruptState))
    );
    // A prefix that serves the Fork's nodes too continues behind a cursor past
    // the cut, which no honest page can carry.
    let mut beyond = prefix;
    beyond.0.extend(fork.0.clone());
    let mut source = production(FakePort::recorded(beyond, 1, vec![(1, fork)]), 1, 1);
    assert_eq!(
        derivation!(&mut source, &plan),
        Err(AdmissionError::Store(StoreError::CorruptState))
    );
    Ok(())
}

#[test]
fn stops_reading_one_row_past_the_bounds() -> TestResult {
    let plan = plan(|_| {})?;
    let hand_built = graph_with(&plan, &[])?;
    let (prefix, fork) = split_rows(&hand_built)?;
    let recorded = || FakePort::recorded(prefix.clone(), 1, vec![(1, fork.clone())]);
    // Three nodes allowed, pages of two: the prefix's two nodes and one edge
    // fit, the first Fork node page is one row too many, and no Fork edge is
    // read.
    let node_bound = Bounds {
        max_nodes: 3,
        max_edges: 5_000,
    };
    let source =
        RecordedFrontierSourceV1::new(recorded(), generation(1), node_bound).with_page_limit(2);
    assert_eq!(
        source.recorded_graph_digest(&plan),
        Err(Box::new(AdmissionError::DependencyGraphInvalid))
    );
    let port = source.port();
    assert_eq!(port.requests.borrow().len(), 3);
    assert_eq!(port.pages(true, RowKind::Nodes), 1);
    assert_eq!(port.pages(true, RowKind::Edges), 0);
    // Two edges allowed: the prefix's one edge and five Fork node pages are
    // read, and the first Fork edge page is one row too many.
    let edge_bound = Bounds {
        max_nodes: 5_000,
        max_edges: 2,
    };
    let source =
        RecordedFrontierSourceV1::new(recorded(), generation(1), edge_bound).with_page_limit(2);
    assert_eq!(
        source.recorded_graph_digest(&plan),
        Err(Box::new(AdmissionError::DependencyGraphInvalid))
    );
    let port = source.port();
    assert_eq!(port.requests.borrow().len(), 8);
    assert_eq!(port.pages(true, RowKind::Nodes), 5);
    assert_eq!(port.pages(true, RowKind::Edges), 1);
    // Exactly the bounds are allowed: twelve nodes, fourteen edges and
    // declared inputs.
    let exact = Bounds {
        max_nodes: 12,
        max_edges: 14,
    };
    let tight = RecordedFrontierSourceV1::new(recorded(), generation(1), exact).with_page_limit(2);
    assert_eq!(tight.recorded_graph(&plan)?, hand_built.graph(&plan)?);
    Ok(())
}

#[test]
fn bounds_the_generation_at_the_plan_horizon() -> TestResult {
    let short = plan(|plan| plan.horizon_tick = 15)?;
    // The generation recorded the full graph through Tick 16 and two more
    // outputs after it; the plan's horizon stops at 15.
    let full = graph_with(&plan(|_| {})?, &[])?;
    let (prefix, mut fork) = split_rows(&full)?;
    for (tick, seed) in [(17, 9), (18, 10)] {
        fork.0
            .push(node_record(&endogenous(tick, 0, "late", seed))?);
    }
    assert_eq!(fork.0.len(), 12);
    let mut nodes = base_nodes(&short)?;
    nodes.truncate(WEATHER);
    let specs: Vec<(usize, usize)> = EDGE_SPECS
        .iter()
        .copied()
        .filter(|&(consumer, _)| consumer != WEATHER)
        .collect();
    let mut hand_built = connect(nodes, &specs, &[]);
    let expected = derivation!(&mut hand_built, &short)?;
    let mut source = production(FakePort::recorded(prefix, 1, vec![(1, fork)]), 1, 1);
    assert_eq!(derivation!(&mut source, &short)?, expected);
    assert_eq!(
        source.recorded_graph_digest(&short)?,
        hand_built.graph_digest(&short)?
    );
    // Reading stops at the page that holds the first row past the horizon:
    // nine Fork nodes through Tick 15 plus the page of Tick 16, per read.
    assert_eq!(source.port().pages(true, RowKind::Nodes), 2 * 10);
    assert_eq!(source.port().pages(true, RowKind::Edges), 2 * 13);
    Ok(())
}

// ---------------------------------------------------------------------------
// End to end through the coordinator, against both adapters
// ---------------------------------------------------------------------------

/// One store shared by the coordinator, which owns one handle, and the
/// production source, which reads through another.
struct Shared<B>(Arc<Mutex<B>>);

impl<B> Clone for Shared<B> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<B> Shared<B> {
    fn new(store: B) -> Self {
        Self(Arc::new(Mutex::new(store)))
    }

    fn lock(&self) -> MutexGuard<'_, B> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<B: EventStore> EventStore for Shared<B> {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.lock().create_timeline(name)
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        let mut store = self.lock();
        store.create_timeline_with_meta(meta)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.lock().append(timeline, drafts)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.lock().read(timeline, range)
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.lock().read_bounded(timeline, range, bounds)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.lock().fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.lock().list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.lock().get_timeline(id)
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.lock().logical_head(id)
    }
}

impl<B: CounterfactualStorePortV1> CounterfactualStorePortV1 for Shared<B> {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, StoreError> {
        self.lock().publish_counterfactual_facts(fork, facts)
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        self.lock().commit_counterfactual_invalidation(command)
    }

    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        self.lock()
            .append_counterfactual_tick(fork, expected, drafts)
    }

    fn current_fork_generation(&self, fork: TimelineId) -> Result<ForkGenerationV1, StoreError> {
        self.lock().current_fork_generation(fork)
    }

    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, StoreError> {
        self.lock().current_counterfactual_basis(fork)
    }

    fn committed_generation_receipt(
        &self,
        at: ForkGenerationV1,
    ) -> Result<Option<CounterfactualGenerationReceiptV1>, StoreError> {
        self.lock().committed_generation_receipt(at)
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.lock().read_generation_artifact(at, artifact_digest)
    }
}

impl<B: CounterfactualDependencyRecordingPortV1> CounterfactualDependencyRecordingPortV1
    for Shared<B>
{
    fn commit_counterfactual_invalidation_with_dependencies(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        self.lock()
            .commit_counterfactual_invalidation_with_dependencies(command, record)
    }

    fn append_counterfactual_tick_with_dependencies(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        self.lock()
            .append_counterfactual_tick_with_dependencies(fork, expected, drafts, record)
    }
}

impl<B: CounterfactualDependencyReadPortV1> CounterfactualDependencyReadPortV1 for Shared<B> {
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, StoreError> {
        self.lock().read_dependency_nodes(request)
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, StoreError> {
        self.lock().read_dependency_edges(request)
    }
}

/// A store adapter that records and reads dependency records.
trait Backend:
    EventStore
    + CounterfactualStorePortV1
    + CounterfactualDependencyRecordingPortV1
    + CounterfactualDependencyReadPortV1
    + Sized
{
    fn open() -> TestResult<Self>;

    /// Seed committed factual Ticks into the prefix of `timeline`.
    fn seed_prefix(&mut self, timeline: TimelineId, ticks: &[SeededFactualTickV1]) -> TestResult;
}

fn open_gate() -> Arc<ErasureContainmentGateV1> {
    Arc::new(ErasureContainmentGateV1::new_test_open())
}

impl Backend for MemoryStore {
    fn open() -> TestResult<Self> {
        let mut store = Self::new();
        store.bind_erasure_gate(open_gate())?;
        Ok(store)
    }

    fn seed_prefix(&mut self, timeline: TimelineId, ticks: &[SeededFactualTickV1]) -> TestResult {
        Ok(self.seed_factual_prefix(timeline, ticks)?)
    }
}

impl Backend for SqliteStore {
    fn open() -> TestResult<Self> {
        let mut store = Self::open_in_memory()?;
        store.bind_erasure_gate(open_gate())?;
        Ok(store)
    }

    fn seed_prefix(&mut self, timeline: TimelineId, ticks: &[SeededFactualTickV1]) -> TestResult {
        Ok(self.seed_factual_prefix(timeline, ticks)?)
    }
}

/// The host reports every frozen artifact as available.
struct AllPresent;

impl CounterfactualFrozenArtifactsV1 for AllPresent {
    fn availability(&self, _: &FrozenArtifactDescriptorV1) -> FrozenArtifactAvailabilityV1 {
        FrozenArtifactAvailabilityV1::Present
    }
}

/// Authorizes every Intervention.
struct Authority;

impl CounterfactualInterventionAuthorityV1 for Authority {
    fn decide(&self, _intervention: &InterventionV1) -> InterventionDecisionV1 {
        InterventionDecisionV1::Authorized
    }
}

/// Put `declaration` in canonical row order.
fn sort_declaration(declaration: &mut Declaration) {
    declaration.0.sort_by(|left, right| {
        left.coordinate()
            .position_key()
            .cmp(&right.coordinate().position_key())
    });
    declaration.1.sort_by(DependencyEdgeRecordV1::order_cmp);
}

/// The declaration of every record Tick of `graph` from `first`, the first
/// recomputation Tick: each provisional node rides the record of its own
/// Tick, except a root before `first`, which rides the first record; every
/// edge rides its consumer's record.
fn declarations(graph: &Graph, first: u64) -> TestResult<BTreeMap<u64, Declaration>> {
    let mut by_tick: BTreeMap<u64, Declaration> = BTreeMap::new();
    let mut record_ticks: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for node in &graph.nodes {
        let tick = if recorded_class(node.class).is_root() {
            node.node.tick.max(first)
        } else {
            node.node.tick
        };
        assert!(node.origin == Origin::Provisional && tick >= first);
        by_tick.entry(tick).or_default().0.push(node_record(node)?);
        record_ticks.insert(node.node.artifact_digest, tick);
    }
    for edge in &graph.edges {
        let tick = record_ticks
            .get(&edge.consumer.artifact_digest)
            .ok_or("edge consumer is not a node")?;
        by_tick.entry(*tick).or_default().1.push(edge_record(edge)?);
    }
    for declaration in by_tick.values_mut() {
        sort_declaration(declaration);
    }
    Ok(by_tick)
}

/// Stages [`tick_drafts`] and declares each Tick's dependencies from
/// [`declarations`].
struct DeclaringStager {
    declarations: BTreeMap<u64, Declaration>,
}

impl DeclaringStager {
    fn new(graph: &Graph) -> TestResult<Self> {
        Ok(Self {
            declarations: declarations(graph, FRONTIER_TICK)?,
        })
    }
}

impl CounterfactualDeclaringTickStagerV1 for DeclaringStager {
    fn stage_tick_with_dependencies(
        &mut self,
        inputs: &CounterfactualTickInputsV1<'_>,
    ) -> Result<CounterfactualStagedTickV1, CounterfactualTickFailureV1> {
        let tick = inputs.tick();
        let (nodes, edges) = self.declarations.get(&tick).cloned().unwrap_or_default();
        Ok(CounterfactualStagedTickV1 {
            drafts: tick_drafts(tick),
            nodes,
            edges,
        })
    }
}

/// The plan, the hand-built Fork graph, and the published facts of one
/// seeded store.
struct Seeded {
    host: Host,
    graph: Graph,
    facts: CounterfactualFactsV1,
}

/// Seed `store` with a factual root of two Events, a Fork at `Seq` 2, and the
/// published facts of the plan, whose graph digest is the hand-built one.
fn seed<B: Backend>(store: &mut Shared<B>) -> TestResult<Seeded> {
    store.create_timeline_with_meta(TimelineMeta {
        id: root_id(),
        ..TimelineMeta::root("factual")
    })?;
    store.append(
        root_id(),
        &[
            event_draft("factual.tick", vec![1]),
            event_draft("factual.tick", vec![2]),
        ],
    )?;
    store.create_timeline_with_meta(TimelineMeta {
        id: fork_id(),
        ..TimelineMeta::forked_from(root_id(), Seq::from_u64(CUT_SEQ), "counterfactual")
    })?;
    let host = host(|_| {})?;
    let graph = fork_graph(&host.plan)?;
    let facts = CounterfactualFactsV1 {
        plan_digest: Hash::from_bytes(host.plan.plan_digest),
        dependency_graph_digest: Hash::from_bytes(graph.graph_digest(&host.plan)?),
        trust_epoch: host.snapshot.epoch,
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
    };
    store.publish_counterfactual_facts(fork_id(), facts)?;
    Ok(Seeded { host, graph, facts })
}

fn admission_request(host: &Host) -> CounterfactualAdmissionRequestV1<'_> {
    CounterfactualAdmissionRequestV1 {
        plan: &host.plan,
        fork: fork_id(),
        fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
        execution_profile: &host.profile,
        trust_policy: &host.snapshot,
        preflight: CounterfactualHostPreflightV1 {
            room_id: ROOM_ID,
            room_digest: ROOM_DIGEST,
            plugin_composition_digest: COMPOSITION_DIGEST,
            frozen_artifacts: &AllPresent,
            replay_claim: &host.claim,
        },
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
        frontier_id: FRONTIER_ID,
        invalidation_id: INVALIDATION_ID,
        provenance_digest: PROVENANCE,
        invalid_checkpoint_digests: &[],
        invalid_projection_digests: &[],
    }
}

const fn suffix_request(
    plan: &CounterfactualPlanV1,
    receipt: CounterfactualGenerationReceiptV1,
) -> CounterfactualSuffixRequestV1<'_> {
    CounterfactualSuffixRequestV1 {
        plan,
        receipt,
        result_id: RESULT_ID,
        evaluator_identity_digest: EVALUATOR,
    }
}

/// The production source over `store` at the Fork's committed generation.
fn recorded<B: Backend>(store: &Shared<B>) -> TestResult<RecordedFrontierSourceV1<Shared<B>>> {
    let at = store.current_fork_generation(fork_id())?;
    Ok(RecordedFrontierSourceV1::new(store.clone(), at, BOUNDS))
}

macro_rules! both_backends {
    ($scenario:ident) => {
        mod $scenario {
            #[test]
            fn memory() -> super::TestResult {
                super::$scenario::<pos_store::memory::MemoryStore>()
            }

            #[test]
            fn sqlite() -> super::TestResult {
                super::$scenario::<pos_store::sqlite::SqliteStore>()
            }
        }
    };
}

fn admits_the_next_generation_from_the_recorded_graph<B: Backend>() -> TestResult {
    let mut store = Shared::new(B::open()?);
    let Seeded {
        host,
        mut graph,
        facts,
    } = seed(&mut store)?;
    let plan = &host.plan;
    let expected = derivation!(&mut graph, plan)?;
    let mut coordinator = CounterfactualCoordinatorV1::new(store.clone());
    let request = admission_request(&host);
    // Generation 1 is admitted from the hand-built graph and records it.
    let mut stager = DeclaringStager::new(&graph)?;
    let first =
        coordinator.admit_with_dependencies(&request, &Authority, &mut graph, &mut stager)?;
    assert_eq!(first.generation(), generation(1));
    // A generation still being written validates as what is recorded so far:
    // the second Intervention's record is not committed yet.
    let mut early = recorded(&store)?;
    assert_eq!(
        derivation!(&mut early, plan),
        Err(AdmissionError::DependencyGraphInvalid)
    );
    let run = coordinator
        .recompute_suffix_with_dependencies(&suffix_request(plan, first), &mut stager)?;
    assert_eq!(run.failure, None);
    // The complete generation derives the published digest and the hand-built
    // derivation.
    let mut complete = recorded(&store)?;
    assert_eq!(complete.generation(), generation(1));
    assert_eq!(
        complete.recorded_graph_digest(plan)?,
        *facts.dependency_graph_digest.as_bytes()
    );
    assert_eq!(derivation!(&mut complete, plan)?, expected);
    // Generation 2 is admitted from the recorded graph alone and recomputed.
    let mut again = DeclaringStager::new(&graph)?;
    let second =
        coordinator.admit_with_dependencies(&request, &Authority, &mut complete, &mut again)?;
    assert_eq!(second.generation(), generation(2));
    assert_eq!(second.frontier_digest(), first.frontier_digest());
    let run = coordinator
        .recompute_suffix_with_dependencies(&suffix_request(plan, second), &mut again)?;
    assert_eq!(run.failure, None);
    let mut third = recorded(&store)?;
    assert_eq!(third.generation(), generation(2));
    assert_eq!(
        third.recorded_graph_digest(plan)?,
        expected.frontier.dependency_graph_digest
    );
    assert_eq!(derivation!(&mut third, plan)?, expected);
    // The quarantined generation 1 never contributes, and an unknown Fork is
    // never an empty graph.
    assert_eq!(
        derivation!(&mut complete, plan),
        Err(AdmissionError::Store(StoreError::MixedForkGeneration))
    );
    let unknown = ForkGenerationV1 {
        fork: other_fork_id(),
        generation: 0,
    };
    let mut source = RecordedFrontierSourceV1::new(store.clone(), unknown, BOUNDS);
    assert_eq!(
        derivation!(&mut source, plan),
        Err(AdmissionError::Store(StoreError::ForkNotFound))
    );
    Ok(())
}
both_backends!(admits_the_next_generation_from_the_recorded_graph);

/// Artifact digest of the committed root the plan does not bind.
const UNBOUND_ROOT_DIGEST: [u8; 32] = [0x51; 32];
/// Tick of the unbound root, inside the committed prefix.
const UNBOUND_ROOT_TICK: u64 = 6;
/// Scheduler position of the unbound root.
const UNBOUND_ROOT_POSITION: u32 = 0;
/// Node position of the unbound root in the hand-built graph.
const UNBOUND_ROOT_INDEX: usize = 1;

/// The base graph plus a committed `ExogenousFrozen` root at
/// `UNBOUND_ROOT_TICK` that the plan does not bind, consumed by `PARENT`.
fn unbound_root_graph(plan: &CounterfactualPlanV1) -> TestResult<Graph> {
    let mut nodes = base_nodes(plan)?;
    nodes.insert(
        UNBOUND_ROOT_INDEX,
        node(
            UNBOUND_ROOT_TICK,
            UNBOUND_ROOT_POSITION,
            "env",
            UNBOUND_ROOT_DIGEST,
            DependencyClassV1::ExogenousFrozen,
        ),
    );
    let shift = |position: usize| position + usize::from(position >= UNBOUND_ROOT_INDEX);
    let mut specs: Vec<(usize, usize)> = EDGE_SPECS
        .iter()
        .map(|&(consumer, source)| (shift(consumer), shift(source)))
        .collect();
    specs.push((shift(PARENT), UNBOUND_ROOT_INDEX));
    Ok(connect(nodes, &specs, &[]))
}

/// The committed Ticks of `graph`, one seeded Tick per record Tick, each
/// owning one `seq`. `event_nodes` is empty, so the seed seam checks nothing
/// about Event bindings.
fn prefix_ticks(graph: &Graph) -> TestResult<Vec<SeededFactualTickV1>> {
    let mut by_tick: BTreeMap<u64, Declaration> = BTreeMap::new();
    for node in graph
        .nodes
        .iter()
        .filter(|node| node.origin == Origin::Committed)
    {
        by_tick
            .entry(node.node.tick)
            .or_default()
            .0
            .push(node_record(node)?);
    }
    for edge in graph
        .edges
        .iter()
        .filter(|edge| edge.consumer.tick <= PARENT_CUT_TICK)
    {
        by_tick
            .entry(edge.consumer.tick)
            .or_default()
            .1
            .push(edge_record(edge)?);
    }
    let mut ticks = Vec::new();
    for (index, (tick, mut declaration)) in by_tick.into_iter().enumerate() {
        sort_declaration(&mut declaration);
        let (nodes, edges) = declaration;
        let seq = Seq::from_u64(u64::try_from(index)? + 1);
        ticks.push(SeededFactualTickV1 {
            record: TickDependencyRecordV1::try_new(
                tick,
                RecordedNodeOriginV1::Committed,
                nodes,
                edges,
            )?,
            first_seq: seq,
            last_seq: seq,
            event_nodes: Vec::new(),
        });
    }
    Ok(ticks)
}

/// Serves parent-prefix reads from an adapter and Fork reads from scripted
/// rows.
struct PrefixOverStore<B> {
    store: B,
    fork: FakePort,
}

impl<B: CounterfactualDependencyReadPortV1> CounterfactualDependencyReadPortV1
    for PrefixOverStore<B>
{
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, StoreError> {
        match request.scope() {
            DependencyReadScopeV1::ParentPrefix { .. } => self.store.read_dependency_nodes(request),
            DependencyReadScopeV1::ForkGeneration(_) => self.fork.read_dependency_nodes(request),
        }
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, StoreError> {
        match request.scope() {
            DependencyReadScopeV1::ParentPrefix { .. } => self.store.read_dependency_edges(request),
            DependencyReadScopeV1::ForkGeneration(_) => self.fork.read_dependency_edges(request),
        }
    }
}

fn derives_over_a_seeded_prefix_with_an_unbound_committed_root<B: Backend>() -> TestResult {
    let plan = plan(|_| {})?;
    let mut hand_built = unbound_root_graph(&plan)?;
    let expected = derivation!(&mut hand_built, &plan)?;
    let mut store = B::open()?;
    store.create_timeline_with_meta(TimelineMeta {
        id: root_id(),
        ..TimelineMeta::root("factual")
    })?;
    store.seed_prefix(root_id(), &prefix_ticks(&hand_built)?)?;
    let (_, fork) = split_rows(&hand_built)?;
    let port = PrefixOverStore {
        store,
        fork: FakePort::recorded((Vec::new(), Vec::new()), 1, vec![(1, fork)]),
    };
    let mut source = RecordedFrontierSourceV1::new(port, generation(1), BOUNDS);
    assert_eq!(derivation!(&mut source, &plan)?, expected);
    let recorded = source.recorded_graph(&plan)?;
    assert_eq!(recorded, hand_built.graph(&plan)?);
    assert!(
        recorded
            .nodes()
            .iter()
            .any(|node| node.node.artifact_digest == UNBOUND_ROOT_DIGEST),
        "the unbound root must survive the round trip"
    );
    Ok(())
}
both_backends!(derives_over_a_seeded_prefix_with_an_unbound_committed_root);
