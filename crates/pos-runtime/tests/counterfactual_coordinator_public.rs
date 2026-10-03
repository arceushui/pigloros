//! Public-interface tests for ADR-064 counterfactual admission through the
//! first atomic Tick Boundary, against both `MemoryStore` and `SqliteStore`.
#![cfg(target_os = "linux")]

use std::error::Error as _;
use std::sync::Arc;

use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyV1,
};
use pos_conformance::counterfactual::frontier_artifacts::{
    FrontierArtifactErrorV1, UnknownEdgeCoordinateV1,
};
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1, FrozenArtifactDescriptorV1,
    PlanExecutionProfileRefV1, PlanTrustPolicyRefV1,
};
use pos_conformance::counterfactual::{InterventionOperationV1, InterventionV1};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1, DependencyClassV1,
    DependencyNodeV1, ExecutionProfileV1, InvalidArtifactV1, RecomputationFrontierV1,
    ReplayClaimV1, SuffixInvalidationReasonV1, SuffixInvalidationV1, TrustPolicySnapshotV1,
    UnknownEdgePolicyV1,
};
use pos_core::{
    CanonicalBytes, CoreError, CounterfactualBasisV1, CounterfactualFactsV1,
    CounterfactualInvalidationCommandV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1, EntityId,
    ErasureContainmentGateV1, Event, EventDraft, EventStore, ForkGenerationV1, Hash,
    InvalidationConflictV1, Kind, PipelineContractErrorV1, PipelineDraftBatchV1, Seq, SeqRange,
    Timeline, TimelineId,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1 as AdmissionError, CounterfactualAdmissionRequestV1,
    CounterfactualCoordinatorV1, CounterfactualForkAppendAuthorityV1,
    CounterfactualFrontierDerivationV1, CounterfactualFrontierSourceV1,
    CounterfactualInterventionAuthorityV1, CounterfactualProvisionalOutputV1,
    CounterfactualTickFailureV1, CounterfactualTickInputsV1, CounterfactualTickStagerV1,
    InterventionDecisionV1, COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1, ENDOGENOUS_ARTIFACT_CLASS_V1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use pos_time::counterfactual::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1, DependencyGraphErrorV1,
    DependencyGraphNodeOriginV1 as Origin, DependencyGraphNodeV1 as Node,
};
use pos_time::counterfactual::frontier::{
    dependency_graph_digest_v1, derive_recomputation_frontier_v1,
};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Admission = Result<pos_core::CounterfactualGenerationReceiptV1, AdmissionError>;

const ENV: usize = 0;
const WORLD_9: usize = 1;
const POLICY: usize = 2;
const WORLD_10: usize = 3;
const INTERVENTION_A: usize = 4;
const WORLD_11: usize = 5;
const WORLD_12: usize = 6;
const INTERVENTION_B: usize = 7;
const AGENT_14: usize = 8;
const UI_15: usize = 9;
const WEATHER_16: usize = 10;
/// `(consumer, source)` node positions of every edge.
const EDGE_SPECS: [(usize, usize); 10] = [
    (WORLD_9, ENV),
    (WORLD_10, WORLD_9),
    (WORLD_10, POLICY),
    (WORLD_11, WORLD_10),
    (WORLD_12, INTERVENTION_A),
    (WORLD_12, WORLD_11),
    (AGENT_14, INTERVENTION_B),
    (AGENT_14, WORLD_12),
    (UI_15, AGENT_14),
    (WEATHER_16, ENV),
];
const WEATHER_EDGE: &[(usize, usize)] = &[(WEATHER_16, ENV)];
const BOUNDS: DependencyGraphBoundsV1 = DependencyGraphBoundsV1 {
    max_nodes: 1_000,
    max_edges: 1_000,
};
const DESCRIPTOR_AUTHORIZATION: [u8; 32] = [0x61; 32];
const DESCRIPTOR_PROVENANCE: [u8; 32] = [0x62; 32];
const CONSENT_DECISION: [u8; 32] = [4; 32];
const INTERVENTION_PROVENANCE: [u8; 32] = [6; 32];
const ENDOGENOUS_AUTHORIZATION: [u8; 32] = [0x72; 32];
const NODE_PROVENANCE: [u8; 32] = [0x71; 32];
const PARENT_CUT_TICK: u64 = 9;
const FIRST_TICK: u64 = 10;
const HORIZON_TICK: u64 = 20;
const CUT_SEQ: u64 = 2;
const FRONTIER_ID: [u8; 16] = [0x81; 16];
const INVALIDATION_ID: [u8; 16] = [0x91; 16];
const PROVENANCE: [u8; 32] = [0x82; 32];
const REVOCATION_EPOCH: u64 = 7;
const ERASURE_EPOCH: u64 = 8;
const CHECKPOINTS: [[u8; 32]; 2] = [[0xc1; 32], [0xc3; 32]];
const PROJECTIONS: [[u8; 32]; 2] = [[0xc2; 32], [0xc3; 32]];
const INTERVENTION_A_ID: [u8; 16] = [1; 16];
const INTERVENTION_B_ID: [u8; 16] = [2; 16];
const TICK_EVENT_TYPE: &str = "counterfactual.tick";
/// A prior-generation `PresentationOnly` output before the global frontier.
const EARLY_PRESENTATION: [u8; 32] = [0xa7; 32];

fn typed_draft(event_type: &str, value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(event_type),
        CanonicalBytes::from_vec(vec![value]),
    )
}

fn draft(value: u8) -> EventDraft {
    typed_draft(TICK_EVENT_TYPE, value)
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

trait Backend: EventStore + CounterfactualStorePortV1 + Sized {
    fn open() -> TestResult<Self>;
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
}

impl Backend for SqliteStore {
    fn open() -> TestResult<Self> {
        let mut store = Self::open_in_memory()?;
        store.bind_erasure_gate(open_gate())?;
        Ok(store)
    }
}

/// [`Rigged`] mode: the one commit call fails with a storage failure.
const COMMIT_FAILS: u8 = 0;
/// [`Rigged`] mode: the one commit call reports a Logical Head conflict.
const COMMIT_CONFLICTS: u8 = 1;
/// [`Rigged`] mode: every Timeline read fails.
const TIMELINE_FAILS: u8 = 2;
/// [`Rigged`] mode: the persisted basis reports an exhausted generation.
const GENERATION_EXHAUSTED: u8 = 3;

/// A `MemoryStore` with one rigged operation, chosen by `MODE`; every other
/// call is delegated.
struct Rigged<const MODE: u8>(MemoryStore);

impl<const MODE: u8> EventStore for Rigged<MODE> {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.0.create_timeline(name)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.0.append(timeline, drafts)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.0.read(timeline, range)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.0.fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.0.list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        if MODE == TIMELINE_FAILS {
            Err(CoreError::ArtifactUnavailable)
        } else {
            self.0.get_timeline(id)
        }
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.0.logical_head(id)
    }
}

impl<const MODE: u8> CounterfactualStorePortV1 for Rigged<MODE> {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.0.publish_counterfactual_facts(fork, facts)
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        _command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        if MODE == COMMIT_CONFLICTS {
            Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                InvalidationConflictV1::LogicalHead,
            ))
        } else {
            Err(CounterfactualStoreErrorV1::StorageFailure)
        }
    }

    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        self.0.append_counterfactual_tick(fork, expected, drafts)
    }

    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.0.current_fork_generation(fork)
    }

    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, CounterfactualStoreErrorV1> {
        self.0.current_counterfactual_basis(fork).map(|basis| {
            if MODE == GENERATION_EXHAUSTED {
                CounterfactualBasisV1 {
                    generation: u64::MAX,
                    ..basis
                }
            } else {
                basis
            }
        })
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, CounterfactualStoreErrorV1> {
        self.0.read_generation_artifact(at, artifact_digest)
    }
}

impl<const MODE: u8> Backend for Rigged<MODE> {
    fn open() -> TestResult<Self> {
        <MemoryStore as Backend>::open().map(Self)
    }
}

// ---------------------------------------------------------------------------
// Plan, graph, and host ports
// ---------------------------------------------------------------------------

fn intervention(effective_tick: u64, intervention_id: [u8; 16]) -> InterventionV1 {
    InterventionV1 {
        intervention_id,
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

fn plan(
    parent: TimelineId,
    profile: &ExecutionProfileV1,
    snapshot: &TrustPolicySnapshotV1,
    edit: fn(&mut CounterfactualPlanV1),
) -> TestResult<CounterfactualPlanV1> {
    let mut plan = CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: "room.alpha".to_owned(),
        room_digest: [2; 32],
        parent_timeline_id: parent.inner().to_bytes(),
        parent_cut_seq: CUT_SEQ,
        parent_cut_tick: PARENT_CUT_TICK,
        parent_cut_digest: [4; 32],
        first_tick: FIRST_TICK,
        horizon_tick: HORIZON_TICK,
        interventions: vec![
            intervention(11, INTERVENTION_A_ID),
            intervention(13, INTERVENTION_B_ID),
        ],
        exogenous_descriptors: vec![descriptor(1, 0x50)],
        fixed_policy_descriptors: vec![descriptor(3, 0x30)],
        classification_bundle_digest: [5; 32],
        execution_profile: PlanExecutionProfileRefV1::from_execution_profile_v1(profile)?,
        trust_policy: PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(snapshot)?,
        plugin_composition_digest: [6; 32],
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
    Ok(plan)
}

const fn endogenous_digest(seed: u8) -> [u8; 32] {
    [0xd0 + seed; 32]
}

fn node(tick: u64, owner_id: &str, artifact_digest: [u8; 32], class: DependencyClassV1) -> Node {
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
            scheduler_position: u32::from(tick == 10 && owner_id == "world"),
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

fn endogenous(tick: u64, owner_id: &str, seed: u8) -> Node {
    node(
        tick,
        owner_id,
        endogenous_digest(seed),
        DependencyClassV1::EndogenousRecomputed,
    )
}

/// Every node of the base graph. An Intervention the plan does not hold
/// gets a placeholder digest; its node lies after a shortened horizon and is
/// dropped with it.
fn nodes(plan: &CounterfactualPlanV1) -> TestResult<Vec<Node>> {
    let intervention_node = |position: usize, tick: u64| -> TestResult<Node> {
        let digest = plan
            .interventions
            .get(position)
            .map_or(Ok([0xee; 32]), InterventionV1::digest)?;
        Ok(node(
            tick,
            "intervention",
            digest,
            DependencyClassV1::InterventionAssigned,
        ))
    };
    Ok(vec![
        node(5, "env", [0x50; 32], DependencyClassV1::ExogenousFrozen),
        endogenous(9, "world", 1),
        node(10, "policy", [0x30; 32], DependencyClassV1::FixedPolicy),
        endogenous(10, "world", 2),
        intervention_node(0, 11)?,
        endogenous(11, "world", 3),
        endogenous(12, "world", 4),
        intervention_node(1, 13)?,
        endogenous(14, "agent", 5),
        node(
            15,
            "ui",
            endogenous_digest(7),
            DependencyClassV1::PresentationOnly,
        ),
        endogenous(16, "weather", 8),
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

fn reseal(frontier: &mut RecomputationFrontierV1) {
    if let Ok(digest) = frontier.digest() {
        frontier.frontier_digest = digest;
    }
}

const fn untampered(_: &mut RecomputationFrontierV1) {}

fn graph_error(error: DependencyGraphErrorV1) -> AdmissionError {
    match error {
        DependencyGraphErrorV1::DependencyGraphIncomplete(coordinate) => {
            AdmissionError::DependencyGraphIncomplete(coordinate)
        }
        DependencyGraphErrorV1::UnknownDependencyEdge(coordinate) => {
            AdmissionError::UnknownDependencyEdge(coordinate)
        }
        _ => AdmissionError::DependencyGraphInvalid,
    }
}

/// The `pos-time` graph validation and frontier derivation behind the port.
#[derive(Clone)]
struct Source {
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
    policy: UnknownEdgePolicyV1,
    tamper: fn(&mut RecomputationFrontierV1),
    /// Provisional outputs reported in addition to the graph's.
    extra_outputs: Vec<CounterfactualProvisionalOutputV1>,
    calls: usize,
}

impl Source {
    /// The base graph through the plan horizon: nodes after the horizon and
    /// their edges are dropped.
    fn new(
        plan: &CounterfactualPlanV1,
        policy: UnknownEdgePolicyV1,
        omitted: &[(usize, usize)],
    ) -> TestResult<Self> {
        let mut nodes = nodes(plan)?;
        for &(consumer, source) in &EDGE_SPECS {
            let digest = nodes[source].node.artifact_digest;
            nodes[consumer].input_digests.push(digest);
        }
        for node in &mut nodes {
            node.input_digests.sort_unstable();
        }
        let mut edges: Vec<_> = EDGE_SPECS
            .iter()
            .filter(|spec| !omitted.contains(spec) && nodes[spec.0].node.tick <= plan.horizon_tick)
            .map(|&(consumer, source)| edge(&nodes[consumer], &nodes[source]))
            .collect();
        nodes.retain(|node| node.node.tick <= plan.horizon_tick);
        edges.sort_by_key(|edge| {
            (
                edge.consumer.tick,
                edge.consumer.scheduler_position,
                edge.consumer.owner_id.clone(),
                edge.consumer.output_ordinal,
                edge.source.artifact_digest,
            )
        });
        Ok(Self {
            nodes,
            edges,
            policy,
            tamper: untampered,
            extra_outputs: Vec::new(),
            calls: 0,
        })
    }

    fn graph_digest(&self, plan: &CounterfactualPlanV1) -> TestResult<[u8; 32]> {
        let graph = validate_dependency_graph_v1(
            plan,
            self.policy,
            BOUNDS,
            self.nodes.clone(),
            self.edges.clone(),
        )?;
        Ok(dependency_graph_digest_v1(&graph))
    }
}

impl CounterfactualFrontierSourceV1 for Source {
    fn derive_frontier(
        &mut self,
        plan: &CounterfactualPlanV1,
        frontier_id: [u8; 16],
        provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, AdmissionError> {
        self.calls += 1;
        let graph = validate_dependency_graph_v1(
            plan,
            self.policy,
            BOUNDS,
            self.nodes.clone(),
            self.edges.clone(),
        )
        .map_err(graph_error)?;
        let mut frontier =
            derive_recomputation_frontier_v1(plan, &graph, frontier_id, provenance_digest)
                .or(Err(AdmissionError::DependencyGraphInvalid))?;
        (self.tamper)(&mut frontier);
        // Reverse canonical order, so the coordinator must order them itself.
        let provisional_outputs = graph
            .nodes()
            .iter()
            .rev()
            .filter(|node| node.origin == Origin::Provisional)
            .map(|node| CounterfactualProvisionalOutputV1 {
                node: node.node.clone(),
                class: node.class,
            })
            .chain(self.extra_outputs.iter().cloned())
            .collect();
        Ok(CounterfactualFrontierDerivationV1 {
            frontier,
            provisional_outputs,
        })
    }
}

/// Authorizes every Intervention except the listed denials.
#[derive(Default)]
struct Authority {
    denials: Vec<([u8; 16], InterventionDecisionV1)>,
}

impl CounterfactualInterventionAuthorityV1 for Authority {
    fn decide(&self, intervention: &InterventionV1) -> InterventionDecisionV1 {
        self.denials
            .iter()
            .find(|(id, _)| *id == intervention.intervention_id)
            .map_or(InterventionDecisionV1::Authorized, |&(_, decision)| {
                decision
            })
    }
}

/// What the stager saw: only its staged inputs.
#[derive(Debug, Eq, PartialEq)]
struct Seen {
    generation: ForkGenerationV1,
    tick: u64,
    interventions: Vec<[u8; 16]>,
    exogenous: Vec<FrozenArtifactDescriptorV1>,
    fixed_policy: Vec<FrozenArtifactDescriptorV1>,
}

/// Stages `drafts` Events of `event_type`, or fails.
struct Stager {
    drafts: Option<u8>,
    event_type: &'static str,
    seen: Vec<Seen>,
}

impl Stager {
    const fn drafting(drafts: u8) -> Self {
        Self {
            drafts: Some(drafts),
            event_type: TICK_EVENT_TYPE,
            seen: Vec::new(),
        }
    }
}

impl CounterfactualTickStagerV1 for Stager {
    fn stage_tick(
        &mut self,
        inputs: &CounterfactualTickInputsV1<'_>,
    ) -> Result<Vec<EventDraft>, CounterfactualTickFailureV1> {
        self.seen.push(Seen {
            generation: inputs.generation(),
            tick: inputs.tick(),
            interventions: inputs
                .interventions()
                .iter()
                .map(|intervention| intervention.intervention_id)
                .collect(),
            exogenous: inputs.exogenous_descriptors().to_vec(),
            fixed_policy: inputs.fixed_policy_descriptors().to_vec(),
        });
        let event_type = self.event_type;
        self.drafts
            .map(|count| {
                (0..count)
                    .map(|value| typed_draft(event_type, value))
                    .collect()
            })
            .ok_or(CounterfactualTickFailureV1)
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// How one fixture differs from the base scenario.
struct Spec {
    plan: fn(&mut CounterfactualPlanV1),
    policy: UnknownEdgePolicyV1,
    omitted: &'static [(usize, usize)],
    facts: fn(&mut CounterfactualFactsV1),
}

const BASE: Spec = Spec {
    plan: |_| {},
    policy: UnknownEdgePolicyV1::Reject,
    omitted: &[],
    facts: |_| {},
};

struct Fixture {
    root: TimelineId,
    fork: TimelineId,
    plan: CounterfactualPlanV1,
    profile: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
}

struct Setup<B> {
    coordinator: CounterfactualCoordinatorV1<B>,
    source: Source,
    fixture: Fixture,
}

/// A factual root with two Events, a Fork at `Seq` 2, and published facts.
fn setup<B: Backend>(spec: &Spec) -> TestResult<Setup<B>> {
    let mut store = B::open()?;
    let root = store.create_timeline("factual")?.id();
    store.append(root, &[draft(1), draft(2)])?;
    let fork = store
        .fork(root, Seq::from_u64(CUT_SEQ), "counterfactual")?
        .id();
    let profile = ExecutionProfileV1::from_canonical_cbor(&draft_execution_profile_bytes_v1(
        "deterministic-local-v1",
    )?)?;
    let snapshot =
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
    let plan = plan(root, &profile, &snapshot, spec.plan)?;
    let source = Source::new(&plan, spec.policy, spec.omitted)?;
    // An invalid graph has no digest; its admission never reaches the store.
    let graph_digest = source.graph_digest(&plan).unwrap_or([0xee; 32]);
    let mut facts = CounterfactualFactsV1 {
        plan_digest: Hash::from_bytes(plan.plan_digest),
        dependency_graph_digest: Hash::from_bytes(graph_digest),
        trust_epoch: snapshot.epoch,
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
    };
    (spec.facts)(&mut facts);
    store.publish_counterfactual_facts(fork, facts)?;
    Ok(Setup {
        coordinator: CounterfactualCoordinatorV1::new(store),
        source,
        fixture: Fixture {
            root,
            fork,
            plan,
            profile,
            snapshot,
        },
    })
}

fn request(fixture: &Fixture) -> CounterfactualAdmissionRequestV1<'_> {
    CounterfactualAdmissionRequestV1 {
        plan: &fixture.plan,
        fork: fixture.fork,
        fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
        execution_profile: &fixture.profile,
        trust_policy: &fixture.snapshot,
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
        frontier_id: FRONTIER_ID,
        invalidation_id: INVALIDATION_ID,
        provenance_digest: PROVENANCE,
        invalid_checkpoint_digests: &CHECKPOINTS,
        invalid_projection_digests: &PROJECTIONS,
    }
}

/// Admit the base request with a default authority and a two-draft stager.
fn admit<B: Backend>(setup: &mut Setup<B>) -> (Admission, Stager) {
    let mut stager = Stager::drafting(2);
    let result = setup.coordinator.admit(
        &request(&setup.fixture),
        &Authority::default(),
        &mut setup.source,
        &mut stager,
    );
    (result, stager)
}

/// The frontier the `pos-time` port derives for this fixture.
fn expected_frontier<B>(setup: &Setup<B>) -> TestResult<RecomputationFrontierV1> {
    Ok(setup
        .source
        .clone()
        .derive_frontier(&setup.fixture.plan, FRONTIER_ID, PROVENANCE)?
        .frontier)
}

/// Assert the Fork is still at generation 0 with its factual head.
fn assert_unchanged<B: Backend>(setup: &Setup<B>) -> TestResult {
    let store = setup.coordinator.store();
    let fork = setup.fixture.fork;
    assert_eq!(
        store.current_fork_generation(fork)?,
        ForkGenerationV1 {
            fork,
            generation: 0
        }
    );
    assert_eq!(store.logical_head(fork)?, Seq::from_u64(CUT_SEQ));
    Ok(())
}

/// Assert `result` is `expected`, nothing committed, and the stager ran
/// `staged` times.
fn assert_rejected<B: Backend>(
    setup: &Setup<B>,
    outcome: &(Admission, Stager),
    expected: &AdmissionError,
    staged: usize,
) -> TestResult {
    assert_eq!(outcome.0.as_ref().err(), Some(expected));
    assert_eq!(outcome.1.seen.len(), staged);
    assert_unchanged(setup)
}

fn invalid_artifact(
    nodes: &[Node],
    position: usize,
    prior_generation: u64,
    reason: SuffixInvalidationReasonV1,
) -> InvalidArtifactV1 {
    InvalidArtifactV1 {
        artifact_class: ENDOGENOUS_ARTIFACT_CLASS_V1.to_owned(),
        schema_id: nodes[position].node.schema_id,
        artifact_digest: nodes[position].node.artifact_digest,
        producer: nodes[position].node.clone(),
        prior_generation,
        reason,
    }
}

fn read_invalidation<B: Backend>(
    setup: &Setup<B>,
    at: ForkGenerationV1,
    digest: Hash,
) -> TestResult<SuffixInvalidationV1> {
    let bytes = setup
        .coordinator
        .store()
        .read_generation_artifact(at, digest)?
        .ok_or("missing SIV1")?;
    Ok(SuffixInvalidationV1::from_canonical_cbor(&bytes)?)
}

// ---------------------------------------------------------------------------
// Scenarios, each run against both backends
// ---------------------------------------------------------------------------

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

/// The `SIV1` the base scenario commits as generation 1.
fn expected_invalidation<B>(
    setup: &Setup<B>,
    frontier: &RecomputationFrontierV1,
    invalidation_digest: Hash,
) -> SuffixInvalidationV1 {
    let nodes = &setup.source.nodes;
    let fork_id = setup.fixture.fork.inner().to_bytes();
    let reason = SuffixInvalidationReasonV1::NewIntervention;
    SuffixInvalidationV1 {
        invalidation_id: INVALIDATION_ID,
        plan_digest: setup.fixture.plan.plan_digest,
        fork_id,
        prior_generation: 0,
        new_generation: 1,
        frontier_digest: frontier.frontier_digest,
        // The lowest affected node and the highest invalidated producer.
        invalid_start: nodes[INTERVENTION_A].node.clone(),
        invalid_end: nodes[WEATHER_16].node.clone(),
        invalid_artifacts: [WORLD_11, WORLD_12, AGENT_14, WEATHER_16]
            .into_iter()
            .map(|position| invalid_artifact(nodes, position, 0, reason))
            .collect(),
        invalid_checkpoint_digests: CHECKPOINTS.to_vec(),
        invalid_projection_digests: PROJECTIONS.to_vec(),
        retained_exogenous_digests: vec![[0x30; 32], [0x50; 32]],
        reason,
        commit_timeline_id: fork_id,
        commit_seq: CUT_SEQ,
        commit_tick: 11,
        provenance_digest: PROVENANCE,
        invalidation_digest: *invalidation_digest.as_bytes(),
    }
}

/// Assert generation-qualified reads after the first commit: the `RCF1` is
/// readable, invalidated outputs, suffix presentation outputs, and evicted
/// checkpoints are quarantined, outputs before the frontier and Intervention
/// seeds are not, and the prior generation is unreadable.
fn assert_generation_reads<B: Backend>(
    setup: &Setup<B>,
    receipt: &pos_core::CounterfactualGenerationReceiptV1,
    frontier: &RecomputationFrontierV1,
) -> TestResult {
    let store = setup.coordinator.store();
    let generation = receipt.generation();
    assert_eq!(
        store.read_generation_artifact(generation, receipt.frontier_digest())?,
        Some(frontier.to_canonical_cbor()?)
    );
    // The presentation output in the suffix is quarantined through the index.
    for digest in [
        endogenous_digest(3),
        endogenous_digest(4),
        endogenous_digest(5),
        endogenous_digest(7),
        endogenous_digest(8),
        [0xc1; 32],
        [0xc2; 32],
        [0xc3; 32],
    ] {
        assert_eq!(
            store.read_generation_artifact(generation, Hash::from_bytes(digest)),
            Err(CounterfactualStoreErrorV1::InvalidArtifactReuse)
        );
    }
    // Outputs before the frontier and Intervention seeds stay unquarantined.
    let seed = setup.fixture.plan.interventions[0].digest()?;
    for digest in [endogenous_digest(2), EARLY_PRESENTATION, seed] {
        assert_eq!(
            store.read_generation_artifact(generation, Hash::from_bytes(digest)),
            Ok(None)
        );
    }
    assert_eq!(
        store.read_generation_artifact(
            ForkGenerationV1 {
                fork: generation.fork,
                generation: 0
            },
            receipt.frontier_digest()
        ),
        Err(CounterfactualStoreErrorV1::MixedForkGeneration)
    );
    Ok(())
}

fn commits_one_generation_and_the_first_tick<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&BASE)?;
    setup.source.extra_outputs = vec![CounterfactualProvisionalOutputV1 {
        node: DependencyNodeV1 {
            artifact_digest: EARLY_PRESENTATION,
            ..setup.source.nodes[WORLD_10].node.clone()
        },
        class: DependencyClassV1::PresentationOnly,
    }];
    let frontier = expected_frontier(&setup)?;
    let fork = setup.fixture.fork;
    let (result, stager) = admit(&mut setup);
    let receipt = result?;
    let generation = ForkGenerationV1 {
        fork,
        generation: 1,
    };
    assert_eq!(receipt.generation(), generation);
    assert_eq!(receipt.first_tick(), 11);
    assert_eq!(receipt.first_tick_head(), Seq::from_u64(CUT_SEQ + 2));
    assert_eq!(
        Hash::from_bytes(frontier.frontier_digest),
        receipt.frontier_digest()
    );
    // The stager saw only the staged inputs of the new generation.
    assert_eq!(
        stager.seen,
        vec![Seen {
            generation,
            tick: 11,
            interventions: vec![INTERVENTION_A_ID],
            exogenous: setup.fixture.plan.exogenous_descriptors.clone(),
            fixed_policy: setup.fixture.plan.fixed_policy_descriptors.clone(),
        }]
    );
    let store = setup.coordinator.store();
    assert_eq!(store.current_fork_generation(fork)?, generation);
    assert_eq!(store.logical_head(fork)?, Seq::from_u64(CUT_SEQ + 2));
    let mut expected = expected_invalidation(&setup, &frontier, receipt.invalidation_digest());
    assert_eq!(
        read_invalidation(&setup, generation, receipt.invalidation_digest())?,
        expected
    );
    assert_generation_reads(&setup, &receipt, &frontier)?;

    // A second admission advances exactly one more generation on top of the
    // committed first Tick.
    let second = admit(&mut setup).0?;
    let next = ForkGenerationV1 {
        fork,
        generation: 2,
    };
    assert_eq!(second.generation(), next);
    assert_eq!(second.first_tick_head(), Seq::from_u64(CUT_SEQ + 4));
    expected.prior_generation = 1;
    expected.new_generation = 2;
    expected.commit_seq = CUT_SEQ + 2;
    for artifact in &mut expected.invalid_artifacts {
        artifact.prior_generation = 1;
    }
    expected.invalidation_digest = *second.invalidation_digest().as_bytes();
    assert_eq!(
        read_invalidation(&setup, next, second.invalidation_digest())?,
        expected
    );
    Ok(())
}
both_backends!(commits_one_generation_and_the_first_tick);

fn unknown_edge_fallback_recomputes_from_the_cut<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&Spec {
        policy: UnknownEdgePolicyV1::FullSuffixFromCut,
        omitted: WEATHER_EDGE,
        ..BASE
    })?;
    let fork = setup.fixture.fork;
    let (result, stager) = admit(&mut setup);
    let receipt = result?;
    assert_eq!(receipt.first_tick(), FIRST_TICK);
    assert_eq!(stager.seen.len(), 1);
    assert_eq!(stager.seen[0].tick, FIRST_TICK);
    assert!(stager.seen[0].interventions.is_empty());
    let invalidation =
        read_invalidation(&setup, receipt.generation(), receipt.invalidation_digest())?;
    let reason = SuffixInvalidationReasonV1::UnknownEdgeFallback;
    let nodes = &setup.source.nodes;
    assert_eq!(invalidation.reason, reason);
    assert_eq!(invalidation.commit_tick, FIRST_TICK);
    // The lowest invalidated producer and the highest one.
    assert_eq!(invalidation.invalid_start, nodes[WORLD_10].node);
    assert_eq!(invalidation.invalid_end, nodes[WEATHER_16].node);
    assert_eq!(
        invalidation.invalid_artifacts,
        [WORLD_10, WORLD_11, WORLD_12, AGENT_14, WEATHER_16]
            .into_iter()
            .map(|position| invalid_artifact(nodes, position, 0, reason))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        setup
            .coordinator
            .store()
            .current_fork_generation(fork)?
            .generation,
        1
    );
    Ok(())
}
both_backends!(unknown_edge_fallback_recomputes_from_the_cut);

fn superseding_plan_records_a_changed_intervention<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&Spec {
        plan: |plan| plan.previous_plan_digest = Some([0x99; 32]),
        ..BASE
    })?;
    let receipt = admit(&mut setup).0?;
    let invalidation =
        read_invalidation(&setup, receipt.generation(), receipt.invalidation_digest())?;
    assert_eq!(
        invalidation.reason,
        SuffixInvalidationReasonV1::ChangedIntervention
    );
    assert!(invalidation
        .invalid_artifacts
        .iter()
        .all(|artifact| artifact.reason == SuffixInvalidationReasonV1::ChangedIntervention));
    Ok(())
}
both_backends!(superseding_plan_records_a_changed_intervention);

fn invalid_plan_and_classified_fork_are_rejected_first<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&BASE)?;
    let mut stager = Stager::drafting(2);
    let mut corrupt = setup.fixture.plan.clone();
    corrupt.plan_digest = [1; 32];
    let result = setup.coordinator.admit(
        &CounterfactualAdmissionRequestV1 {
            plan: &corrupt,
            fork_append_authority: CounterfactualForkAppendAuthorityV1::ClassifiedAdmission,
            ..request(&setup.fixture)
        },
        &Authority::default(),
        &mut setup.source,
        &mut stager,
    );
    assert_rejected(
        &setup,
        &(result, stager),
        &AdmissionError::Plan(CounterfactualPlanContractErrorV1::DigestMismatch),
        0,
    )?;

    // ADR-099 FAR1-admitted Forks are a deferred integration: rejected
    // before any authority, store, graph, or stager call.
    let mut stager = Stager::drafting(2);
    let result = setup.coordinator.admit(
        &CounterfactualAdmissionRequestV1 {
            fork_append_authority: CounterfactualForkAppendAuthorityV1::ClassifiedAdmission,
            ..request(&setup.fixture)
        },
        &Authority {
            denials: vec![(INTERVENTION_A_ID, InterventionDecisionV1::Unauthorized)],
        },
        &mut setup.source,
        &mut stager,
    );
    assert_rejected(
        &setup,
        &(result, stager),
        &AdmissionError::ClassifiedForkUnsupported,
        0,
    )?;
    assert_eq!(setup.source.calls, 0);
    Ok(())
}
both_backends!(invalid_plan_and_classified_fork_are_rejected_first);

fn intervention_authority_denials_are_closed<B: Backend>() -> TestResult {
    let cases = [
        (
            vec![(INTERVENTION_B_ID, InterventionDecisionV1::Unauthorized)],
            AdmissionError::UnauthorizedIntervention,
        ),
        (
            vec![(INTERVENTION_A_ID, InterventionDecisionV1::ConsentInvalid)],
            AdmissionError::ConsentInvalid,
        ),
        (
            vec![(
                INTERVENTION_B_ID,
                InterventionDecisionV1::TargetNotIntervenable,
            )],
            AdmissionError::TargetNotIntervenable,
        ),
        // The first Intervention in plan order decides.
        (
            vec![
                (INTERVENTION_B_ID, InterventionDecisionV1::Unauthorized),
                (INTERVENTION_A_ID, InterventionDecisionV1::ConsentInvalid),
            ],
            AdmissionError::ConsentInvalid,
        ),
    ];
    for (denials, expected) in cases {
        let mut setup = setup::<B>(&BASE)?;
        let mut stager = Stager::drafting(2);
        let result = setup.coordinator.admit(
            &request(&setup.fixture),
            &Authority { denials },
            &mut setup.source,
            &mut stager,
        );
        assert_rejected(&setup, &(result, stager), &expected, 0)?;
        assert_eq!(setup.source.calls, 0);
    }
    Ok(())
}
both_backends!(intervention_authority_denials_are_closed);

fn profile_and_trust_policy_must_be_the_plans<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&BASE)?;
    let mut profile = setup.fixture.profile.clone();
    profile.profile_digest = [9; 32];
    let mut stager = Stager::drafting(2);
    let result = setup.coordinator.admit(
        &CounterfactualAdmissionRequestV1 {
            execution_profile: &profile,
            ..request(&setup.fixture)
        },
        &Authority::default(),
        &mut setup.source,
        &mut stager,
    );
    assert_rejected(
        &setup,
        &(result, stager),
        &AdmissionError::IncompatibleExecutionProfile,
        0,
    )?;

    let mut snapshot = setup.fixture.snapshot.clone();
    snapshot.epoch += 1;
    let mut stager = Stager::drafting(2);
    let result = setup.coordinator.admit(
        &CounterfactualAdmissionRequestV1 {
            trust_policy: &snapshot,
            ..request(&setup.fixture)
        },
        &Authority::default(),
        &mut setup.source,
        &mut stager,
    );
    assert_rejected(
        &setup,
        &(result, stager),
        &AdmissionError::TrustPolicyMismatch,
        0,
    )?;
    assert_eq!(setup.source.calls, 0);
    Ok(())
}
both_backends!(profile_and_trust_policy_must_be_the_plans);

fn fork_and_parent_cut_must_match<B: Backend>() -> TestResult {
    // A Timeline that is not a published Fork.
    let mut root = setup::<B>(&BASE)?;
    let mut stager = Stager::drafting(2);
    let result = root.coordinator.admit(
        &CounterfactualAdmissionRequestV1 {
            fork: root.fixture.root,
            ..request(&root.fixture)
        },
        &Authority::default(),
        &mut root.source,
        &mut stager,
    );
    assert_rejected(
        &root,
        &(result, stager),
        &AdmissionError::Store(CounterfactualStoreErrorV1::ForkNotFound),
        0,
    )?;

    let wrong_cuts: [fn(&mut CounterfactualPlanV1); 2] = [
        |plan| plan.parent_timeline_id = [3; 16],
        |plan| plan.parent_cut_seq = CUT_SEQ - 1,
    ];
    for edit in wrong_cuts {
        let mut setup = setup::<B>(&Spec { plan: edit, ..BASE })?;
        let outcome = admit(&mut setup);
        assert_rejected(&setup, &outcome, &AdmissionError::ParentCutNotFound, 0)?;
        assert_eq!(setup.source.calls, 0);
    }
    Ok(())
}
both_backends!(fork_and_parent_cut_must_match);

fn incomplete_dependency_graph_is_rejected<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&Spec {
        omitted: WEATHER_EDGE,
        ..BASE
    })?;
    let expected = AdmissionError::DependencyGraphIncomplete(UnknownEdgeCoordinateV1 {
        consumer: setup.source.nodes[WEATHER_16].node.clone(),
        missing_source_digest: Some([0x50; 32]),
    });
    let outcome = admit(&mut setup);
    assert_rejected(&setup, &outcome, &expected, 0)
}
both_backends!(incomplete_dependency_graph_is_rejected);

fn derived_frontier_is_revalidated_and_bound<B: Backend>() -> TestResult {
    let cases: [(fn(&mut RecomputationFrontierV1), AdmissionError); 9] = [
        (
            |frontier| frontier.frontier_id = [1; 16],
            AdmissionError::Frontier(FrontierArtifactErrorV1::DigestMismatch),
        ),
        (
            |frontier| {
                frontier.frontier_id = [1; 16];
                reseal(frontier);
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.plan_digest = [1; 32];
                reseal(frontier);
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.parent_cut_digest = [1; 32];
                reseal(frontier);
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.classification_bundle_digest = [1; 32];
                reseal(frontier);
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.provenance_digest = [1; 32];
                reseal(frontier);
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.endogenous_suffix_end_tick = HORIZON_TICK - 1;
                reseal(frontier);
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        // The global frontier precedes the first Tick after the cut.
        (
            |frontier| {
                frontier.global_frontier_tick = PARENT_CUT_TICK;
                reseal(frontier);
            },
            AdmissionError::FrontierOutOfRange,
        ),
        // The global frontier follows the earliest Intervention.
        (
            |frontier| {
                frontier.global_frontier_tick = 12;
                frontier
                    .owner_frontiers
                    .retain(|owner| owner.earliest_tick >= 12);
                reseal(frontier);
            },
            AdmissionError::FrontierOutOfRange,
        ),
    ];
    for (tamper, expected) in cases {
        let mut setup = setup::<B>(&BASE)?;
        setup.source.tamper = tamper;
        let outcome = admit(&mut setup);
        assert_rejected(&setup, &outcome, &expected, 0)?;
        assert_eq!(setup.source.calls, 1);
    }
    Ok(())
}
both_backends!(derived_frontier_is_revalidated_and_bound);

/// Tamperings of the `RCF1` seeds that keep the resealed record valid.
const SEED_TAMPERS: [fn(&mut RecomputationFrontierV1); 5] = [
    // A seed digest that is no Intervention's INT1 digest.
    |frontier| {
        frontier.intervention_seed_nodes[0].artifact_digest = [0xee; 32];
        reseal(frontier);
    },
    // A seed off its Intervention's effective Tick.
    |frontier| {
        frontier.intervention_seed_nodes[1].tick = 12;
        reseal(frontier);
    },
    // A seed off its Intervention's target schema.
    |frontier| {
        frontier.intervention_seed_nodes[0].schema_id = 8;
        reseal(frontier);
    },
    // A plan Intervention without a seed.
    |frontier| {
        frontier.intervention_seed_nodes.truncate(1);
        reseal(frontier);
    },
    // A seed that is not an affected node.
    |frontier| {
        let seed = frontier.intervention_seed_nodes[0].clone();
        frontier.affected_nodes.retain(|node| *node != seed);
        reseal(frontier);
    },
];

fn frontier_seeds_must_be_the_plans_interventions<B: Backend>() -> TestResult {
    for tamper in SEED_TAMPERS {
        let mut setup = setup::<B>(&BASE)?;
        // The tampered record still passes the standalone RCF1 validation.
        let mut frontier = expected_frontier(&setup)?;
        tamper(&mut frontier);
        frontier.validate()?;
        setup.source.tamper = tamper;
        let outcome = admit(&mut setup);
        assert_rejected(
            &setup,
            &outcome,
            &AdmissionError::FrontierBindingMismatch,
            0,
        )?;
        assert_eq!(setup.source.calls, 1);
    }
    Ok(())
}
both_backends!(frontier_seeds_must_be_the_plans_interventions);

fn derived_frontier_range_is_enforced<B: Backend>() -> TestResult {
    let cases: [fn(&mut RecomputationFrontierV1); 2] = [
        // An affected node before the global frontier.
        |frontier| {
            if let Some(first) = frontier.affected_nodes.first().cloned() {
                frontier.affected_nodes.insert(
                    0,
                    DependencyNodeV1 {
                        tick: FIRST_TICK,
                        ..first
                    },
                );
            }
            reseal(frontier);
        },
        // An affected node after the endogenous suffix end.
        |frontier| {
            if let Some(last) = frontier.affected_nodes.last().cloned() {
                frontier.affected_nodes.push(DependencyNodeV1 {
                    tick: HORIZON_TICK + 1,
                    ..last
                });
            }
            reseal(frontier);
        },
    ];
    for tamper in cases {
        let mut setup = setup::<B>(&BASE)?;
        setup.source.tamper = tamper;
        let outcome = admit(&mut setup);
        assert_rejected(&setup, &outcome, &AdmissionError::FrontierOutOfRange, 0)?;
    }

    // A provisional output after the endogenous suffix end: the suffix runs
    // through the horizon only.
    let mut setup = setup::<B>(&BASE)?;
    let beyond = DependencyNodeV1 {
        tick: HORIZON_TICK + 1,
        ..setup.source.nodes[WEATHER_16].node.clone()
    };
    setup.source.extra_outputs = vec![CounterfactualProvisionalOutputV1 {
        node: beyond,
        class: DependencyClassV1::EndogenousRecomputed,
    }];
    let outcome = admit(&mut setup);
    assert_rejected(&setup, &outcome, &AdmissionError::FrontierOutOfRange, 0)?;
    assert_eq!(setup.source.calls, 1);
    Ok(())
}
both_backends!(derived_frontier_range_is_enforced);

fn fallback_frontier_is_exactly_the_first_tick<B: Backend>() -> TestResult {
    let cases: [fn(&mut RecomputationFrontierV1); 2] = [
        // A later scheduler position of the first Tick.
        |frontier| {
            frontier.global_frontier_scheduler_position = 1;
            reseal(frontier);
        },
        // A later Tick, which `Reject` would admit.
        |frontier| {
            frontier.global_frontier_tick = FIRST_TICK + 1;
            reseal(frontier);
        },
    ];
    for tamper in cases {
        let mut setup = setup::<B>(&Spec {
            policy: UnknownEdgePolicyV1::FullSuffixFromCut,
            omitted: WEATHER_EDGE,
            ..BASE
        })?;
        setup.source.tamper = tamper;
        let outcome = admit(&mut setup);
        assert_rejected(&setup, &outcome, &AdmissionError::FrontierOutOfRange, 0)?;
        assert_eq!(setup.source.calls, 1);
    }
    Ok(())
}
both_backends!(fallback_frontier_is_exactly_the_first_tick);

fn suffix_ending_on_the_frontier_tick_has_a_valid_range<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&Spec {
        plan: |plan| {
            plan.horizon_tick = 11;
            plan.interventions.truncate(1);
        },
        ..BASE
    })?;
    let receipt = admit(&mut setup).0?;
    assert_eq!(receipt.first_tick(), 11);
    let invalidation =
        read_invalidation(&setup, receipt.generation(), receipt.invalidation_digest())?;
    // The graph ends at Tick 11: the Intervention seed and the endogenous
    // output after it on the same Tick bound the range.
    let nodes = &setup.source.nodes;
    let seed = nodes
        .iter()
        .find(|node| node.class == DependencyClassV1::InterventionAssigned)
        .ok_or("missing seed")?;
    let world = nodes
        .iter()
        .find(|node| node.node.tick == 11 && node.node.owner_id == "world")
        .ok_or("missing output")?;
    assert_eq!(invalidation.commit_tick, 11);
    assert_eq!(invalidation.invalid_start, seed.node);
    assert_eq!(invalidation.invalid_end, world.node);
    assert_eq!(
        invalidation.invalid_artifacts,
        vec![InvalidArtifactV1 {
            artifact_class: ENDOGENOUS_ARTIFACT_CLASS_V1.to_owned(),
            schema_id: world.node.schema_id,
            artifact_digest: world.node.artifact_digest,
            producer: world.node.clone(),
            prior_generation: 0,
            reason: SuffixInvalidationReasonV1::NewIntervention,
        }]
    );
    Ok(())
}
both_backends!(suffix_ending_on_the_frontier_tick_has_a_valid_range);

fn invalidation_contract_violations_are_rejected<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&BASE)?;
    let unordered = [[0xc3; 32], [0xc1; 32]];
    let cases = [
        (
            CounterfactualAdmissionRequestV1 {
                invalidation_id: [0; 16],
                ..request(&setup.fixture)
            },
            AdmissionError::Invalidation(FrontierArtifactErrorV1::FieldOutOfBounds),
        ),
        (
            CounterfactualAdmissionRequestV1 {
                invalid_checkpoint_digests: &unordered,
                ..request(&setup.fixture)
            },
            AdmissionError::Invalidation(FrontierArtifactErrorV1::NonCanonicalOrder),
        ),
    ];
    for (request, expected) in cases {
        let mut stager = Stager::drafting(2);
        let result = setup.coordinator.admit(
            &request,
            &Authority::default(),
            &mut setup.source,
            &mut stager,
        );
        assert_rejected(&setup, &(result, stager), &expected, 0)?;
    }

    // The store port refuses to quarantine the transaction's own RCF1.
    let own = [expected_frontier(&setup)?.frontier_digest];
    let mut stager = Stager::drafting(2);
    let result = setup.coordinator.admit(
        &CounterfactualAdmissionRequestV1 {
            invalid_checkpoint_digests: &own,
            ..request(&setup.fixture)
        },
        &Authority::default(),
        &mut setup.source,
        &mut stager,
    );
    assert_rejected(
        &setup,
        &(result, stager),
        &AdmissionError::Store(CounterfactualStoreErrorV1::BindingMismatch),
        1,
    )
}
both_backends!(invalidation_contract_violations_are_rejected);

fn failed_or_empty_staging_commits_nothing<B: Backend>() -> TestResult {
    let cases = [
        (
            Stager {
                drafts: None,
                ..Stager::drafting(0)
            },
            AdmissionError::PluginFailure,
        ),
        (
            Stager::drafting(0),
            AdmissionError::StagedTickRejected(PipelineContractErrorV1::EmptyBatch),
        ),
        // The coordinator-owned checkpoint Event type is reserved on the
        // first Tick as on every later one.
        (
            Stager {
                event_type: COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1,
                ..Stager::drafting(1)
            },
            AdmissionError::ReservedEventType,
        ),
    ];
    for (mut stager, expected) in cases {
        let mut setup = setup::<B>(&BASE)?;
        let result = setup.coordinator.admit(
            &request(&setup.fixture),
            &Authority::default(),
            &mut setup.source,
            &mut stager,
        );
        assert_rejected(&setup, &(result, stager), &expected, 1)?;
    }
    Ok(())
}
both_backends!(failed_or_empty_staging_commits_nothing);

fn changed_persisted_facts_conflict_atomically<B: Backend>() -> TestResult {
    let cases: [(fn(&mut CounterfactualFactsV1), InvalidationConflictV1); 5] = [
        (
            |facts| facts.plan_digest = Hash::from_bytes([1; 32]),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |facts| facts.dependency_graph_digest = Hash::from_bytes([1; 32]),
            InvalidationConflictV1::DependencyGraphDigest,
        ),
        (
            |facts| facts.trust_epoch += 1,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |facts| facts.revocation_epoch += 1,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |facts| facts.erasure_epoch += 1,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    // The persisted basis is read before staging, so a stale fact fails
    // fast; the store's atomic recheck is covered by the rigged store.
    for (facts, conflict) in cases {
        let mut setup = setup::<B>(&Spec { facts, ..BASE })?;
        let outcome = admit(&mut setup);
        assert_rejected(
            &setup,
            &outcome,
            &AdmissionError::InvalidationConflict(conflict),
            0,
        )?;
        assert_eq!(setup.source.calls, 1);
    }
    Ok(())
}
both_backends!(changed_persisted_facts_conflict_atomically);

#[test]
fn store_outcomes_without_a_commit_map_to_closed_errors() -> TestResult {
    let mut failing = setup::<Rigged<COMMIT_FAILS>>(&BASE)?;
    let outcome = admit(&mut failing);
    assert_rejected(
        &failing,
        &outcome,
        &AdmissionError::Store(CounterfactualStoreErrorV1::StorageFailure),
        1,
    )?;
    let mut conflicting = setup::<Rigged<COMMIT_CONFLICTS>>(&BASE)?;
    let outcome = admit(&mut conflicting);
    assert_rejected(
        &conflicting,
        &outcome,
        &AdmissionError::InvalidationConflict(InvalidationConflictV1::LogicalHead),
        1,
    )
}

#[test]
fn failed_fork_reads_map_to_a_storage_failure() -> TestResult {
    let storage_failure = AdmissionError::Store(CounterfactualStoreErrorV1::StorageFailure);
    let mut timeline = setup::<Rigged<TIMELINE_FAILS>>(&BASE)?;
    let outcome = admit(&mut timeline);
    assert_rejected(&timeline, &outcome, &storage_failure, 0)?;
    assert_eq!(timeline.source.calls, 0);
    Ok(())
}

#[test]
fn exhausted_generation_is_rejected_before_staging() -> TestResult {
    let mut exhausted = setup::<Rigged<GENERATION_EXHAUSTED>>(&BASE)?;
    let outcome = admit(&mut exhausted);
    assert_rejected(
        &exhausted,
        &outcome,
        &AdmissionError::Invalidation(FrontierArtifactErrorV1::PriorGenerationMismatch),
        0,
    )
}

#[test]
fn every_error_has_a_distinct_safe_message() {
    let coordinate = UnknownEdgeCoordinateV1 {
        consumer: DependencyNodeV1 {
            tick: 1,
            scheduler_position: 0,
            owner_id: "owner".to_owned(),
            output_ordinal: 0,
            schema_id: 1,
            artifact_digest: [1; 32],
        },
        missing_source_digest: None,
    };
    let errors = [
        AdmissionError::Plan(CounterfactualPlanContractErrorV1::DigestMismatch),
        AdmissionError::ClassifiedForkUnsupported,
        AdmissionError::UnauthorizedIntervention,
        AdmissionError::ConsentInvalid,
        AdmissionError::TargetNotIntervenable,
        AdmissionError::IncompatibleExecutionProfile,
        AdmissionError::TrustPolicyMismatch,
        AdmissionError::ParentCutNotFound,
        AdmissionError::DependencyGraphIncomplete(coordinate.clone()),
        AdmissionError::UnknownDependencyEdge(coordinate),
        AdmissionError::DependencyGraphInvalid,
        AdmissionError::Frontier(FrontierArtifactErrorV1::DigestMismatch),
        AdmissionError::FrontierBindingMismatch,
        AdmissionError::FrontierOutOfRange,
        AdmissionError::Invalidation(FrontierArtifactErrorV1::DigestMismatch),
        AdmissionError::PluginFailure,
        AdmissionError::StagedTickRejected(PipelineContractErrorV1::EmptyBatch),
        AdmissionError::ReservedEventType,
        AdmissionError::InvalidationConflict(InvalidationConflictV1::LogicalHead),
        AdmissionError::Store(CounterfactualStoreErrorV1::StorageFailure),
    ];
    let messages: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    assert!(messages.iter().all(|message| !message.is_empty()));
    let with_source = [0, 11, 14, 16, 19];
    for (position, error) in errors.iter().enumerate() {
        assert_eq!(error.source().is_some(), with_source.contains(&position));
    }
}
