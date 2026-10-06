//! Public-interface tests for ADR-064 counterfactual admission through the
//! first atomic Tick Boundary, against both `MemoryStore` and `SqliteStore`.
#![cfg(target_os = "linux")]

use std::cell::Cell;
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
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, CoreError, CounterfactualAdapterSealV1,
    CounterfactualBasisV1, CounterfactualFactsV1, CounterfactualGenerationReceiptV1,
    CounterfactualGenerationRecordV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualStorePortV1,
    CounterfactualTickOutcomeV1, EntityId, ErasureArtifactClassV1, ErasureContainmentGateV1,
    ErasureReferenceV1, ErasureReplayClaimV1, Event, EventDraft, EventStore, ForkGenerationV1,
    Hash, InvalidationConflictV1, Kind, PipelineContractErrorV1, PipelineDraftBatchV1,
    RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, Seq, SeqRange, Timeline,
    TimelineId, MAX_FORK_EVENT_TYPE_BYTES_V1,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1 as AdmissionError, CounterfactualAdmissionRequestV1,
    CounterfactualCoordinatorV1, CounterfactualForkAppendAuthorityV1,
    CounterfactualFrontierDerivationV1, CounterfactualFrontierSourceV1,
    CounterfactualFrozenArtifactsV1, CounterfactualHostPreflightV1,
    CounterfactualInterventionAuthorityV1, CounterfactualPendingCommitV1,
    CounterfactualProvisionalOutputV1, CounterfactualTickFailureV1, CounterfactualTickInputsV1,
    CounterfactualTickStagerV1, FrozenArtifactAvailabilityV1 as Avail, InterventionDecisionV1,
    COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1, ENDOGENOUS_ARTIFACT_CLASS_V1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use pos_time::counterfactual::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1, DependencyGraphErrorV1,
    DependencyGraphNodeOriginV1 as Origin, DependencyGraphNodeV1 as Node,
    ValidatedDependencyGraphV1,
};
use pos_time::counterfactual::frontier::{
    affected_presentation_outputs_v1, dependency_graph_digest_v1, derive_recomputation_frontier_v1,
};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Admission = Result<CounterfactualGenerationReceiptV1, AdmissionError>;

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
const ROOM_ID: &str = "room.alpha";
const ROOM_DIGEST: [u8; 32] = [2; 32];
const COMPOSITION_DIGEST: [u8; 32] = [6; 32];
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
const LONGEST_TYPE_BYTES: [u8; MAX_FORK_EVENT_TYPE_BYTES_V1] = [b't'; MAX_FORK_EVENT_TYPE_BYTES_V1];
const LONG_TYPE_BYTES: [u8; MAX_FORK_EVENT_TYPE_BYTES_V1 + 1] =
    [b't'; MAX_FORK_EVENT_TYPE_BYTES_V1 + 1];

/// An Event type of exactly the largest accepted length.
const LONGEST_TYPE: &str = match std::str::from_utf8(&LONGEST_TYPE_BYTES) {
    Ok(text) => text,
    Err(_) => "",
};

/// An Event type one byte longer than accepted.
const LONG_TYPE: &str = match std::str::from_utf8(&LONG_TYPE_BYTES) {
    Ok(text) => text,
    Err(_) => "",
};
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
/// [`Rigged`] mode: the commit lands but reports an unknown outcome.
const LANDED_UNKNOWN: u8 = 4;
/// [`Rigged`] mode: the commit is lost and reports an unknown outcome.
const LOST_UNKNOWN: u8 = 5;
/// [`Rigged`] mode: the commit lands and reports an unknown outcome, and the
/// first recovery read fails.
const RECOVERY_READ_FAILS: u8 = 6;
/// [`Rigged`] mode: the commit lands and reports an unknown outcome, and the
/// recovery read finds another invalidation's receipt.
const OTHER_RECEIPT: u8 = 7;
/// [`Rigged`] mode: every call is delegated.
const DELEGATES: u8 = 8;

/// A `MemoryStore` with one rigged operation, chosen by `MODE`; every other
/// call is delegated. It records every command it is asked to commit and
/// counts the recovery reads.
struct Rigged<const MODE: u8> {
    store: MemoryStore,
    commands: Vec<CounterfactualInvalidationCommandV1>,
    recovery_reads: Cell<usize>,
}

/// The receipt of another invalidation of the same generation; only a test
/// wrapper may mint one with the adapter seal.
const fn other_receipt(
    receipt: CounterfactualGenerationReceiptV1,
) -> Result<CounterfactualGenerationReceiptV1, CounterfactualStoreErrorV1> {
    CounterfactualGenerationReceiptV1::from_record(
        &CounterfactualAdapterSealV1::for_adapter(),
        CounterfactualGenerationRecordV1 {
            invalidation_digest: Hash::from_bytes([0xee; 32]),
            ..receipt.record()
        },
    )
}

impl<const MODE: u8> EventStore for Rigged<MODE> {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.store.create_timeline(name)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.store.append(timeline, drafts)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.store.read(timeline, range)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.store.fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.store.list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        if MODE == TIMELINE_FAILS {
            Err(CoreError::ArtifactUnavailable)
        } else {
            self.store.get_timeline(id)
        }
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.store.logical_head(id)
    }
}

impl<const MODE: u8> CounterfactualStorePortV1 for Rigged<MODE> {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.store.publish_counterfactual_facts(fork, facts)
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        self.commands.push(command.clone());
        match MODE {
            COMMIT_CONFLICTS => Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                InvalidationConflictV1::LogicalHead,
            )),
            COMMIT_FAILS => Err(CounterfactualStoreErrorV1::StorageFailure),
            LOST_UNKNOWN => Err(CounterfactualStoreErrorV1::OutcomeUnknown),
            LANDED_UNKNOWN | RECOVERY_READ_FAILS | OTHER_RECEIPT => self
                .store
                .commit_counterfactual_invalidation(command)
                .and(Err(CounterfactualStoreErrorV1::OutcomeUnknown)),
            _ => self.store.commit_counterfactual_invalidation(command),
        }
    }

    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        self.store
            .append_counterfactual_tick(fork, expected, drafts)
    }

    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.store.current_fork_generation(fork)
    }

    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, CounterfactualStoreErrorV1> {
        self.store.current_counterfactual_basis(fork).map(|basis| {
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

    fn committed_generation_receipt(
        &self,
        at: ForkGenerationV1,
    ) -> Result<Option<CounterfactualGenerationReceiptV1>, CounterfactualStoreErrorV1> {
        let reads = self.recovery_reads.get();
        self.recovery_reads.set(reads + 1);
        if MODE == RECOVERY_READ_FAILS && reads == 0 {
            return Err(CounterfactualStoreErrorV1::StorageFailure);
        }
        let found = self.store.committed_generation_receipt(at)?;
        if MODE == OTHER_RECEIPT {
            found.map(other_receipt).transpose()
        } else {
            Ok(found)
        }
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, CounterfactualStoreErrorV1> {
        self.store.read_generation_artifact(at, artifact_digest)
    }
}

impl<const MODE: u8> Backend for Rigged<MODE> {
    fn open() -> TestResult<Self> {
        <MemoryStore as Backend>::open().map(|store| Self {
            store,
            commands: Vec::new(),
            recovery_reads: Cell::new(0),
        })
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
    unknown_edge_policy: UnknownEdgePolicyV1,
    edit: fn(&mut CounterfactualPlanV1),
) -> TestResult<CounterfactualPlanV1> {
    let mut plan = CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: ROOM_ID.to_owned(),
        room_digest: ROOM_DIGEST,
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
        unknown_edge_policy,
        execution_profile: PlanExecutionProfileRefV1::from_execution_profile_v1(profile)?,
        trust_policy: PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(snapshot)?,
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

/// Re-seal a tampered frontier with its own digest.
fn reseal(frontier: &mut RecomputationFrontierV1) -> TamperResult {
    frontier.frontier_digest = frontier.digest()?;
    Ok(())
}

/// The outcome of one frontier tamper: the reseal digest failure, if any.
type TamperResult = Result<(), FrontierArtifactErrorV1>;
/// One frontier tamper applied after the frontier is derived.
type Tamper = fn(&mut RecomputationFrontierV1) -> TamperResult;
/// One frontier tamper and the admission error it must produce.
type FrontierCase = (Tamper, AdmissionError);
/// One published-facts change, the conflict it must produce, and how often
/// the frontier source runs before it is detected.
type FactsCase = (
    fn(&mut CounterfactualFactsV1),
    InvalidationConflictV1,
    usize,
);

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

/// The `pos-time` graph validation and frontier derivation behind the port.
#[derive(Clone)]
struct Source {
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
    tamper: Tamper,
    /// Provisional outputs reported in addition to the graph's.
    extra_outputs: Vec<CounterfactualProvisionalOutputV1>,
    calls: usize,
}

impl Source {
    /// The base graph through the plan horizon: nodes after the horizon and
    /// their edges are dropped.
    fn new(plan: &CounterfactualPlanV1, omitted: &[(usize, usize)]) -> TestResult<Self> {
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
            tamper: reseal,
            extra_outputs: Vec::new(),
            calls: 0,
        })
    }

    /// Validate the graph under the plan's unknown-edge policy.
    fn graph(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<ValidatedDependencyGraphV1, DependencyGraphErrorV1> {
        validate_dependency_graph_v1(plan, BOUNDS, self.nodes.clone(), self.edges.clone())
    }

    fn graph_digest(&self, plan: &CounterfactualPlanV1) -> TestResult<[u8; 32]> {
        Ok(dependency_graph_digest_v1(&self.graph(plan)?))
    }

    /// The `PresentationOnly` outputs `pos-time` reports stale for the graph.
    fn affected_presentation(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> TestResult<Vec<DependencyNodeV1>> {
        Ok(affected_presentation_outputs_v1(&self.graph(plan)?))
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
        let graph = self.graph(plan).map_err(graph_error)?;
        let mut frontier =
            derive_recomputation_frontier_v1(plan, &graph, frontier_id, provenance_digest)
                .or(Err(AdmissionError::DependencyGraphInvalid))?;
        (self.tamper)(&mut frontier).map_err(AdmissionError::Frontier)?;
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

/// Artifact digests the host reports as other than present.
type Overrides = &'static [([u8; 32], Avail)];

/// The host's frozen-artifact port: every artifact is present except the
/// listed digests.
#[derive(Clone, Copy)]
struct Artifacts {
    overrides: Overrides,
}

impl CounterfactualFrozenArtifactsV1 for Artifacts {
    fn availability(&self, descriptor: &FrozenArtifactDescriptorV1) -> Avail {
        self.overrides
            .iter()
            .find(|(digest, _)| *digest == descriptor.artifact_digest)
            .map_or(Avail::Present, |found| found.1)
    }
}

/// The host's evaluation of one retained Export artifact of `claim`.
fn evaluation(claim: ErasureReplayClaimV1) -> TestResult<ReplayClaimEvaluationV1> {
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

struct Fixture {
    root: TimelineId,
    fork: TimelineId,
    plan: CounterfactualPlanV1,
    profile: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
    claim: ReplayClaimEvaluationV1,
    artifacts: Artifacts,
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
    let plan = plan(root, &profile, &snapshot, spec.policy, spec.plan)?;
    let source = Source::new(&plan, spec.omitted)?;
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
            claim: evaluation(ErasureReplayClaimV1::Exact)?,
            artifacts: Artifacts { overrides: &[] },
        },
    })
}

const fn request(fixture: &Fixture) -> CounterfactualAdmissionRequestV1<'_> {
    CounterfactualAdmissionRequestV1 {
        plan: &fixture.plan,
        fork: fixture.fork,
        fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
        execution_profile: &fixture.profile,
        trust_policy: &fixture.snapshot,
        preflight: CounterfactualHostPreflightV1 {
            room_id: ROOM_ID,
            room_digest: ROOM_DIGEST,
            plugin_composition_digest: COMPOSITION_DIGEST,
            frozen_artifacts: &fixture.artifacts,
            replay_claim: &fixture.claim,
        },
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

/// Assert every `PresentationOnly` output `pos-time` reports stale for the
/// graph is `expected` and is in the committed invalid-artifact `index`.
fn assert_affected_presentation_indexed<B: Backend>(
    setup: &Setup<B>,
    index: &[Hash],
    expected: &[usize],
) -> TestResult {
    let affected = setup.source.affected_presentation(&setup.fixture.plan)?;
    let nodes = &setup.source.nodes;
    assert_eq!(
        affected,
        expected
            .iter()
            .map(|&position| nodes[position].node.clone())
            .collect::<Vec<_>>()
    );
    for node in affected {
        assert!(index.contains(&Hash::from_bytes(node.artifact_digest)));
    }
    Ok(())
}

/// Assert generation-qualified reads after the first commit: the `RCF1` is
/// readable at the new generation and the prior generation is unreadable.
fn assert_generation_reads<B: Backend>(
    setup: &Setup<B>,
    receipt: &CounterfactualGenerationReceiptV1,
    frontier: &RecomputationFrontierV1,
) -> TestResult {
    let store = setup.coordinator.store();
    let generation = receipt.generation();
    assert_eq!(
        store.read_generation_artifact(generation, receipt.frontier_digest())?,
        Some(frontier.to_canonical_cbor()?)
    );
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
    let cases: [FrontierCase; 9] = [
        (
            |frontier| {
                frontier.frontier_id = [1; 16];
                Ok(())
            },
            AdmissionError::Frontier(FrontierArtifactErrorV1::DigestMismatch),
        ),
        (
            |frontier| {
                frontier.frontier_id = [1; 16];
                reseal(frontier)
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.plan_digest = [1; 32];
                reseal(frontier)
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.parent_cut_digest = [1; 32];
                reseal(frontier)
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.classification_bundle_digest = [1; 32];
                reseal(frontier)
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.provenance_digest = [1; 32];
                reseal(frontier)
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        (
            |frontier| {
                frontier.endogenous_suffix_end_tick = HORIZON_TICK - 1;
                reseal(frontier)
            },
            AdmissionError::FrontierBindingMismatch,
        ),
        // The global frontier precedes the first Tick after the cut.
        (
            |frontier| {
                frontier.global_frontier_tick = PARENT_CUT_TICK;
                reseal(frontier)
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
                reseal(frontier)
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
const SEED_TAMPERS: [Tamper; 5] = [
    // A seed digest that is no Intervention's INT1 digest.
    |frontier| {
        frontier.intervention_seed_nodes[0].artifact_digest = [0xee; 32];
        reseal(frontier)
    },
    // A seed off its Intervention's effective Tick.
    |frontier| {
        frontier.intervention_seed_nodes[1].tick = 12;
        reseal(frontier)
    },
    // A seed off its Intervention's target schema.
    |frontier| {
        frontier.intervention_seed_nodes[0].schema_id = 8;
        reseal(frontier)
    },
    // A plan Intervention without a seed.
    |frontier| {
        frontier.intervention_seed_nodes.truncate(1);
        reseal(frontier)
    },
    // A seed that is not an affected node.
    |frontier| {
        let seed = frontier.intervention_seed_nodes[0].clone();
        frontier.affected_nodes.retain(|node| *node != seed);
        reseal(frontier)
    },
];

fn frontier_seeds_must_be_the_plans_interventions<B: Backend>() -> TestResult {
    for tamper in SEED_TAMPERS {
        let mut setup = setup::<B>(&BASE)?;
        // The tampered record still passes the standalone RCF1 validation.
        let mut frontier = expected_frontier(&setup)?;
        tamper(&mut frontier)?;
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
    let cases: [Tamper; 2] = [
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
            reseal(frontier)
        },
        // An affected node after the endogenous suffix end.
        |frontier| {
            if let Some(last) = frontier.affected_nodes.last().cloned() {
                frontier.affected_nodes.push(DependencyNodeV1 {
                    tick: HORIZON_TICK + 1,
                    ..last
                });
            }
            reseal(frontier)
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
    let cases: [Tamper; 2] = [
        // A later scheduler position of the first Tick.
        |frontier| {
            frontier.global_frontier_scheduler_position = 1;
            reseal(frontier)
        },
        // A later Tick, which `Reject` would admit.
        |frontier| {
            frontier.global_frontier_tick = FIRST_TICK + 1;
            reseal(frontier)
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

fn first_tick_event_type_is_bounded<B: Backend>() -> TestResult {
    // The longest accepted type is admitted: generation 1 holds the Tick.
    let mut accepting = setup::<B>(&BASE)?;
    let mut stager = Stager {
        event_type: LONGEST_TYPE,
        ..Stager::drafting(1)
    };
    let result = accepting.coordinator.admit(
        &request(&accepting.fixture),
        &Authority::default(),
        &mut accepting.source,
        &mut stager,
    );
    assert!(result.is_ok());
    let store = accepting.coordinator.store();
    let fork = accepting.fixture.fork;
    assert_eq!(
        store.current_fork_generation(fork)?,
        ForkGenerationV1 {
            fork,
            generation: 1
        }
    );
    assert_eq!(store.logical_head(fork)?, Seq::from_u64(CUT_SEQ + 1));

    // One byte more is rejected while staging and commits nothing.
    let mut rejecting = setup::<B>(&BASE)?;
    let mut stager = Stager {
        event_type: LONG_TYPE,
        ..Stager::drafting(1)
    };
    let result = rejecting.coordinator.admit(
        &request(&rejecting.fixture),
        &Authority::default(),
        &mut rejecting.source,
        &mut stager,
    );
    assert_rejected(
        &rejecting,
        &(result, stager),
        &AdmissionError::StagedTickRejected(PipelineContractErrorV1::FieldOutOfBounds),
        1,
    )
}
both_backends!(first_tick_event_type_is_bounded);

fn changed_persisted_facts_conflict_atomically<B: Backend>() -> TestResult {
    let cases: [FactsCase; 6] = [
        (
            |facts| facts.plan_digest = Hash::from_bytes([1; 32]),
            InvalidationConflictV1::PlanDigest,
            0,
        ),
        (
            |facts| facts.dependency_graph_digest = Hash::from_bytes([1; 32]),
            InvalidationConflictV1::DependencyGraphDigest,
            1,
        ),
        (
            |facts| facts.trust_epoch += 1,
            InvalidationConflictV1::TrustEpoch,
            0,
        ),
        (
            |facts| facts.revocation_epoch += 1,
            InvalidationConflictV1::RevocationEpoch,
            0,
        ),
        (
            |facts| facts.erasure_epoch += 1,
            InvalidationConflictV1::ErasureEpoch,
            0,
        ),
        // A stale epoch is reported before the frontier is derived, even
        // when the graph digest differs too.
        (
            |facts| {
                facts.dependency_graph_digest = Hash::from_bytes([1; 32]);
                facts.erasure_epoch += 1;
            },
            InvalidationConflictV1::ErasureEpoch,
            0,
        ),
    ];
    // The plan digest and epochs are checked before the host derives a
    // frontier, the graph digest right after; both before staging. The
    // store's atomic recheck is covered by the rigged store.
    for (facts, conflict, derivations) in cases {
        let mut setup = setup::<B>(&Spec { facts, ..BASE })?;
        let outcome = admit(&mut setup);
        assert_rejected(
            &setup,
            &outcome,
            &AdmissionError::InvalidationConflict(conflict),
            0,
        )?;
        assert_eq!(setup.source.calls, derivations);
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
fn unknown_commit_outcomes_are_resolved_by_the_recovery_read() -> TestResult {
    // The commit landed: its receipt is returned as if it had been reported.
    let mut landed = setup::<Rigged<LANDED_UNKNOWN>>(&BASE)?;
    let fork = landed.fixture.fork;
    let receipt = admit(&mut landed).0?;
    let generation = ForkGenerationV1 {
        fork,
        generation: 1,
    };
    let store = landed.coordinator.store();
    assert_eq!(receipt.generation(), generation);
    assert_eq!(
        receipt.invalidation_digest(),
        store.commands[0].invalidation().digest()
    );
    assert_eq!(store.current_fork_generation(fork)?, generation);
    assert_eq!(store.recovery_reads.get(), 1);

    // The commit was lost: nothing committed, so it is a storage failure
    // after which the admission may be retried.
    let mut lost = setup::<Rigged<LOST_UNKNOWN>>(&BASE)?;
    let outcome = admit(&mut lost);
    assert_rejected(
        &lost,
        &outcome,
        &AdmissionError::Store(CounterfactualStoreErrorV1::StorageFailure),
        1,
    )?;
    assert_eq!(lost.coordinator.store().recovery_reads.get(), 1);

    // Another invalidation committed the generation.
    let mut other = setup::<Rigged<OTHER_RECEIPT>>(&BASE)?;
    assert_eq!(
        admit(&mut other).0,
        Err(AdmissionError::InvalidationConflict(
            InvalidationConflictV1::PriorGeneration
        ))
    );
    Ok(())
}

#[test]
fn failed_recovery_read_keeps_the_commit_outcome_unknown() -> TestResult {
    let mut setup = setup::<Rigged<RECOVERY_READ_FAILS>>(&BASE)?;
    let fork = setup.fixture.fork;
    let (result, stager) = admit(&mut setup);
    let store = setup.coordinator.store();
    let pending = CounterfactualPendingCommitV1 {
        generation: ForkGenerationV1 {
            fork,
            generation: 1,
        },
        invalidation_digest: store.commands[0].invalidation().digest(),
    };
    assert_eq!(result, Err(AdmissionError::CommitOutcomeUnknown(pending)));
    assert_eq!(stager.seen.len(), 1);
    // The commit did land; repeating the read, not the commit, resolves it.
    let committed = store
        .store
        .committed_generation_receipt(pending.generation)?
        .ok_or("missing receipt")?;
    assert_eq!(
        setup.coordinator.resolve_pending_commit(pending),
        Ok(committed)
    );
    assert_eq!(store.commands.len(), 1);
    assert_eq!(store.recovery_reads.get(), 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// Admission preflight
// ---------------------------------------------------------------------------

type PlanEdit = fn(&mut CounterfactualPlanV1);

/// One preflight fault: a plan edit, the host's non-present artifacts, and
/// the closed error it must produce.
type PreflightCase = (PlanEdit, Overrides, AdmissionError);

/// One host preflight stage: the expected room digest and Plugin composition
/// digest, the non-present artifacts, the evaluated claim, and the first
/// closed error it must produce.
struct Peel {
    room_digest: [u8; 32],
    composition: [u8; 32],
    overrides: Overrides,
    claim: ErasureReplayClaimV1,
    expected: AdmissionError,
}

const EXOGENOUS_DIGEST: [u8; 32] = [0x50; 32];
const FIXED_DIGEST: [u8; 32] = [0x30; 32];
const EXOGENOUS_MISSING: Overrides = &[(EXOGENOUS_DIGEST, Avail::Missing)];
const FIXED_MISSING: Overrides = &[(FIXED_DIGEST, Avail::Missing)];
const EXOGENOUS_MISMATCH: Overrides = &[(EXOGENOUS_DIGEST, Avail::DigestMismatch)];
const FIXED_MISMATCH: Overrides = &[(FIXED_DIGEST, Avail::DigestMismatch)];
const SECOND_DIGEST: [u8; 32] = [0x51; 32];
const SECOND_MISSING: Overrides = &[(SECOND_DIGEST, Avail::Missing)];
const FIRST_MISMATCH_SECOND_MISSING: Overrides = &[
    (EXOGENOUS_DIGEST, Avail::DigestMismatch),
    (SECOND_DIGEST, Avail::Missing),
];
const FIRST_MISSING_SECOND_MISMATCH: Overrides = &[
    (EXOGENOUS_DIGEST, Avail::Missing),
    (SECOND_DIGEST, Avail::DigestMismatch),
];
const BOTH_FAULTY: Overrides = &[
    (EXOGENOUS_DIGEST, Avail::Missing),
    (FIXED_DIGEST, Avail::DigestMismatch),
];

/// Every claim a host can evaluate, strongest first.
const HOST_CLAIMS: [ErasureReplayClaimV1; 5] = [
    ErasureReplayClaimV1::Exact,
    ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
    ErasureReplayClaimV1::StructuralOnly,
    ErasureReplayClaimV1::UnverifiableArtifactsMissing,
    ErasureReplayClaimV1::IncompatibleProfile,
];

/// Plans that request each claim, in the order of [`HOST_CLAIMS`].
const CLAIM_SPECS: [Spec; 5] = [
    BASE,
    Spec {
        plan: |plan| plan.replay_claim = ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ..BASE
    },
    Spec {
        plan: |plan| plan.replay_claim = ReplayClaimV1::StructuralOnly,
        ..BASE
    },
    Spec {
        plan: |plan| plan.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing,
        ..BASE
    },
    Spec {
        plan: |plan| plan.replay_claim = ReplayClaimV1::IncompatibleProfile,
        ..BASE
    },
];

/// Adds a second `ExogenousFrozen` descriptor after the base one.
const WITH_SECOND: PlanEdit = |plan| plan.exogenous_descriptors.push(descriptor(2, 0x51));

const PREFLIGHT_CASES: [PreflightCase; 10] = [
    (
        |plan| "room.beta".clone_into(&mut plan.room_id),
        &[],
        AdmissionError::RoomMismatch,
    ),
    (
        |plan| plan.room_digest = [0xff; 32],
        &[],
        AdmissionError::RoomMismatch,
    ),
    (
        |plan| plan.plugin_composition_digest = [0xff; 32],
        &[],
        AdmissionError::PluginCompositionMismatch,
    ),
    (
        |_| {},
        EXOGENOUS_MISSING,
        AdmissionError::FrozenArtifactMissing,
    ),
    (|_| {}, FIXED_MISSING, AdmissionError::FrozenArtifactMissing),
    (
        |_| {},
        EXOGENOUS_MISMATCH,
        AdmissionError::FrozenArtifactDigestMismatch,
    ),
    (
        |_| {},
        FIXED_MISMATCH,
        AdmissionError::FrozenArtifactDigestMismatch,
    ),
    (
        WITH_SECOND,
        SECOND_MISSING,
        AdmissionError::FrozenArtifactMissing,
    ),
    (
        WITH_SECOND,
        FIRST_MISMATCH_SECOND_MISSING,
        AdmissionError::FrozenArtifactDigestMismatch,
    ),
    (
        WITH_SECOND,
        FIRST_MISSING_SECOND_MISMATCH,
        AdmissionError::FrozenArtifactMissing,
    ),
];

fn preflight_rejections_are_closed_and_touch_nothing<B: Backend>() -> TestResult {
    for (edit, overrides, expected) in PREFLIGHT_CASES {
        let mut setup = setup::<B>(&Spec { plan: edit, ..BASE })?;
        setup.fixture.artifacts.overrides = overrides;
        let outcome = admit(&mut setup);
        assert_rejected(&setup, &outcome, &expected, 0)?;
        assert_eq!(setup.source.calls, 0);
    }
    Ok(())
}
both_backends!(preflight_rejections_are_closed_and_touch_nothing);

#[test]
fn preflight_rejections_make_no_store_call() -> TestResult {
    let mut committed = setup::<Rigged<DELEGATES>>(&BASE)?;
    committed.fixture.artifacts.overrides = EXOGENOUS_MISSING;
    let outcome = admit(&mut committed);
    let missing = AdmissionError::FrozenArtifactMissing;
    assert_rejected(&committed, &outcome, &missing, 0)?;
    assert!(committed.coordinator.store().commands.is_empty());
    assert_eq!(committed.coordinator.store().recovery_reads.get(), 0);

    // The Fork Timeline read, which fails here, is never reached.
    let mut unread = setup::<Rigged<TIMELINE_FAILS>>(&Spec {
        plan: |plan| plan.plugin_composition_digest = [0xff; 32],
        ..BASE
    })?;
    let outcome = admit(&mut unread);
    let mismatch = AdmissionError::PluginCompositionMismatch;
    assert_rejected(&unread, &outcome, &mismatch, 0)?;
    assert_eq!(unread.source.calls, 0);
    Ok(())
}

fn first_preflight_error_wins<B: Backend>() -> TestResult {
    let structural = ErasureReplayClaimV1::StructuralOnly;
    let peels: [Peel; 5] = [
        Peel {
            room_digest: [9; 32],
            composition: [0xff; 32],
            overrides: BOTH_FAULTY,
            claim: structural,
            expected: AdmissionError::RoomMismatch,
        },
        Peel {
            room_digest: ROOM_DIGEST,
            composition: [0xff; 32],
            overrides: BOTH_FAULTY,
            claim: structural,
            expected: AdmissionError::PluginCompositionMismatch,
        },
        Peel {
            room_digest: ROOM_DIGEST,
            composition: COMPOSITION_DIGEST,
            overrides: BOTH_FAULTY,
            claim: structural,
            expected: AdmissionError::FrozenArtifactMissing,
        },
        Peel {
            room_digest: ROOM_DIGEST,
            composition: COMPOSITION_DIGEST,
            overrides: FIXED_MISMATCH,
            claim: structural,
            expected: AdmissionError::FrozenArtifactDigestMismatch,
        },
        Peel {
            room_digest: ROOM_DIGEST,
            composition: COMPOSITION_DIGEST,
            overrides: &[],
            claim: structural,
            expected: AdmissionError::ReplayClaimInsufficient,
        },
    ];
    let mut setup = setup::<B>(&BASE)?;
    for peel in peels {
        let evaluated = evaluation(peel.claim)?;
        let artifacts = Artifacts {
            overrides: peel.overrides,
        };
        let preflight = CounterfactualHostPreflightV1 {
            room_digest: peel.room_digest,
            plugin_composition_digest: peel.composition,
            frozen_artifacts: &artifacts,
            replay_claim: &evaluated,
            ..request(&setup.fixture).preflight
        };
        let mut stager = Stager::drafting(2);
        let result = setup.coordinator.admit(
            &CounterfactualAdmissionRequestV1 {
                preflight,
                ..request(&setup.fixture)
            },
            &Authority::default(),
            &mut setup.source,
            &mut stager,
        );
        assert_rejected(&setup, &(result, stager), &peel.expected, 0)?;
        assert_eq!(setup.source.calls, 0);
    }
    // With every host fact matching the plan, the same plan is admitted.
    admit(&mut setup).0?;
    Ok(())
}
both_backends!(first_preflight_error_wins);

fn preflight_follows_the_profile_and_precedes_the_store_reads<B: Backend>() -> TestResult {
    let mut setup = setup::<B>(&BASE)?;
    let mut profile = setup.fixture.profile.clone();
    profile.profile_digest = [9; 32];
    let faulty = CounterfactualHostPreflightV1 {
        room_digest: [9; 32],
        ..request(&setup.fixture).preflight
    };
    let cases = [
        (
            CounterfactualAdmissionRequestV1 {
                execution_profile: &profile,
                preflight: faulty,
                ..request(&setup.fixture)
            },
            AdmissionError::IncompatibleExecutionProfile,
        ),
        (
            CounterfactualAdmissionRequestV1 {
                fork: setup.fixture.root,
                preflight: faulty,
                ..request(&setup.fixture)
            },
            AdmissionError::RoomMismatch,
        ),
    ];
    for (admission, expected) in cases {
        let mut stager = Stager::drafting(2);
        let result = setup.coordinator.admit(
            &admission,
            &Authority::default(),
            &mut setup.source,
            &mut stager,
        );
        assert_rejected(&setup, &(result, stager), &expected, 0)?;
        assert_eq!(setup.source.calls, 0);
    }
    Ok(())
}
both_backends!(preflight_follows_the_profile_and_precedes_the_store_reads);

fn replay_claim_must_not_be_stronger_than_the_hosts<B: Backend>() -> TestResult {
    for (plan_rank, spec) in CLAIM_SPECS.iter().enumerate() {
        for (host_rank, host) in HOST_CLAIMS.into_iter().enumerate() {
            let mut scenario = setup::<B>(spec)?;
            scenario.fixture.claim = evaluation(host)?;
            let outcome = admit(&mut scenario);
            if host_rank <= plan_rank {
                outcome.0?;
            } else {
                let insufficient = AdmissionError::ReplayClaimInsufficient;
                assert_rejected(&scenario, &outcome, &insufficient, 0)?;
                assert_eq!(scenario.source.calls, 0);
            }
        }
    }
    Ok(())
}
both_backends!(replay_claim_must_not_be_stronger_than_the_hosts);

/// The invalid-artifact index of the base scenario: every invalidated
/// endogenous output and the suffix presentation output (`UI_15`).
const BASE_INDEX: [u8; 5] = [3, 4, 5, 7, 8];

#[test]
fn index_and_eviction_set_cover_exactly_the_suffix() -> TestResult {
    let mut exact = setup::<Rigged<DELEGATES>>(&BASE)?;
    // A prior-generation presentation output before the global frontier.
    exact.source.extra_outputs = vec![CounterfactualProvisionalOutputV1 {
        node: DependencyNodeV1 {
            artifact_digest: EARLY_PRESENTATION,
            ..exact.source.nodes[WORLD_10].node.clone()
        },
        class: DependencyClassV1::PresentationOnly,
    }];
    admit(&mut exact).0?;
    let command = &exact.coordinator.store().commands[0];
    // Outputs before the frontier, the early presentation output, and the
    // Intervention seeds stay out of the index.
    assert_eq!(
        command.invalid_artifacts(),
        BASE_INDEX
            .map(|seed| Hash::from_bytes(endogenous_digest(seed)))
            .as_slice()
    );
    assert_eq!(
        command.evictions(),
        [[0xc1; 32], [0xc2; 32], [0xc3; 32]]
            .map(Hash::from_bytes)
            .as_slice()
    );
    assert_affected_presentation_indexed(&exact, command.invalid_artifacts(), &[UI_15])?;

    // Under the fallback every provisional presentation output is stale.
    let mut fallback = setup::<Rigged<DELEGATES>>(&Spec {
        policy: UnknownEdgePolicyV1::FullSuffixFromCut,
        omitted: WEATHER_EDGE,
        ..BASE
    })?;
    admit(&mut fallback).0?;
    let index = fallback.coordinator.store().commands[0].invalid_artifacts();
    assert_affected_presentation_indexed(&fallback, index, &[UI_15])
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
        AdmissionError::RoomMismatch,
        AdmissionError::PluginCompositionMismatch,
        AdmissionError::FrozenArtifactMissing,
        AdmissionError::FrozenArtifactDigestMismatch,
        AdmissionError::ReplayClaimInsufficient,
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
        AdmissionError::CommitOutcomeUnknown(CounterfactualPendingCommitV1 {
            generation: ForkGenerationV1 {
                fork: TimelineId::new(),
                generation: 1,
            },
            invalidation_digest: Hash::from_bytes([1; 32]),
        }),
    ];
    let messages: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    assert!(messages.iter().all(|message| !message.is_empty()));
    let with_source = [0, 16, 19, 21, 24];
    for (position, error) in errors.iter().enumerate() {
        assert_eq!(error.source().is_some(), with_source.contains(&position));
    }
}
