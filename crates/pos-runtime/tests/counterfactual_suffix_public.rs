//! Public-interface tests for ADR-064 endogenous suffix recomputation after
//! the first atomic Tick, against both `MemoryStore` and `SqliteStore`.
#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::error::Error as _;
use std::sync::Arc;

use pos_conformance::counterfactual::checkpoint::{
    CheckpointDigestEntryV1, ExogenousCursorV1, RecomputeCheckpointV1,
};
use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyV1,
};
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1, FrozenArtifactDescriptorV1,
    PlanExecutionProfileRefV1, PlanTrustPolicyRefV1,
};
use pos_conformance::counterfactual::result::{
    CounterfactualCheckpointRefV1, CounterfactualResultV1, CounterfactualTerminalErrorCodeV1,
    CounterfactualTerminalErrorV1, CounterfactualTerminalStateV1,
};
use pos_conformance::counterfactual::{InterventionOperationV1, InterventionV1};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1, DependencyClassV1,
    DependencyNodeV1, ExecutionProfileV1, ReplayClaimV1, TrustPolicySnapshotV1,
    UnknownEdgePolicyV1,
};
use pos_core::{
    pipeline_draft_vector_digest_v1, CanonicalBytes, CoreError, CounterfactualGenerationReceiptV1,
    CounterfactualInvalidationCommandV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, EntityId, ErasureContainmentGateV1,
    Event, EventDraft, EventStore, ForkGenerationV1, Hash, InvalidationConflictV1, Kind,
    PipelineContractErrorV1, Seq, SeqRange, Timeline, TimelineId, TimelineMeta,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1 as AdmissionError, CounterfactualAdmissionRequestV1,
    CounterfactualCoordinatorV1, CounterfactualForkAppendAuthorityV1,
    CounterfactualFrontierDerivationV1, CounterfactualFrontierSourceV1,
    CounterfactualInterventionAuthorityV1, CounterfactualProvisionalOutputV1,
    CounterfactualTickFailureV1, CounterfactualTickInputsV1, CounterfactualTickStagerV1,
    InterventionDecisionV1,
};
use pos_runtime::counterfactual::suffix::{
    CounterfactualEpochSourceV1, CounterfactualEpochsV1,
    CounterfactualSuffixErrorV1 as SuffixError, CounterfactualSuffixFailureV1 as Failure,
    CounterfactualSuffixRequestV1, CounterfactualSuffixRunV1,
    COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1, SUFFIX_STATE_OWNER_V1,
};
use pos_store::memory::{counterfactual_store::MemoryCounterfactualFactsV1, MemoryStore};
use pos_store::sqlite::{SqliteCounterfactualFactsV1, SqliteStore};
use pos_time::counterfactual::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1, DependencyGraphNodeOriginV1 as Origin,
    DependencyGraphNodeV1 as Node,
};
use pos_time::counterfactual::frontier::{
    dependency_graph_digest_v1, derive_recomputation_frontier_v1,
};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Suffix = Result<CounterfactualSuffixRunV1, SuffixError>;

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
/// The global frontier, the first recomputation Tick.
const FRONTIER_TICK: u64 = 11;
const CUT_SEQ: u64 = 2;
/// Fork head after the first Tick's two Events.
const FIRST_TICK_HEAD: u64 = CUT_SEQ + 2;
const FRONTIER_ID: [u8; 16] = [0x81; 16];
const INVALIDATION_ID: [u8; 16] = [0x91; 16];
const PROVENANCE: [u8; 32] = [0x82; 32];
const REVOCATION_EPOCH: u64 = 7;
const ERASURE_EPOCH: u64 = 8;
const INTERVENTION_A_ID: [u8; 16] = [1; 16];
const INTERVENTION_B_ID: [u8; 16] = [2; 16];
const RESULT_ID: [u8; 16] = [0xa1; 16];
const EVALUATOR: [u8; 32] = [0xa2; 32];
/// The largest suffix Tick span one result can checkpoint.
const MAX_SPAN: u64 = 65_535;
const STATE_DOMAIN: &[u8] = b"PiglorOS.CounterfactualSuffixState.v1\0";

fn root_id() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x5100_u128))
}

fn fork_id() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x5200_u128))
}

fn event_draft(kind: &str, payload: Vec<u8>) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(kind),
        CanonicalBytes::from_vec(payload),
    )
}

/// The two deterministic Events every successful Tick stages.
fn tick_drafts(tick: u64) -> Vec<EventDraft> {
    (0..2_u8)
        .map(|ordinal| {
            let mut payload = tick.to_be_bytes().to_vec();
            payload.push(ordinal);
            event_draft("counterfactual.world", payload)
        })
        .collect()
}

/// Fork `Seq` of the last recomputed Event of `tick`: the first Tick ends at
/// [`FIRST_TICK_HEAD`], every later Tick adds two Events and one checkpoint.
const fn tick_seq(tick: u64) -> u64 {
    if tick == FRONTIER_TICK {
        FIRST_TICK_HEAD
    } else {
        FIRST_TICK_HEAD + (tick - FRONTIER_TICK) * 3 - 1
    }
}

/// Fork head once `last` committed: later Ticks end with a checkpoint Event.
const fn committed_head(last: u64) -> u64 {
    if last == FRONTIER_TICK {
        FIRST_TICK_HEAD
    } else {
        tick_seq(last) + 1
    }
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// Host-published counterfactual facts of one Fork.
#[derive(Clone, Copy)]
struct Facts {
    plan_digest: Hash,
    dependency_graph_digest: Hash,
    trust_epoch: u64,
}

trait Backend: EventStore + CounterfactualStorePortV1 + Sized {
    fn open() -> TestResult<Self>;
    fn publish(&mut self, fork: TimelineId, facts: Facts) -> TestResult;
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

    fn publish(&mut self, fork: TimelineId, facts: Facts) -> TestResult {
        self.publish_counterfactual_facts(
            fork,
            MemoryCounterfactualFactsV1 {
                plan_digest: facts.plan_digest,
                dependency_graph_digest: facts.dependency_graph_digest,
                trust_epoch: facts.trust_epoch,
                revocation_epoch: REVOCATION_EPOCH,
                erasure_epoch: ERASURE_EPOCH,
            },
        )?;
        Ok(())
    }
}

fn open_sqlite(path: &str) -> TestResult<SqliteStore> {
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(open_gate())?;
    Ok(store)
}

impl Backend for SqliteStore {
    fn open() -> TestResult<Self> {
        let mut store = Self::open_in_memory()?;
        store.bind_erasure_gate(open_gate())?;
        Ok(store)
    }

    fn publish(&mut self, fork: TimelineId, facts: Facts) -> TestResult {
        self.publish_counterfactual_facts(
            fork,
            SqliteCounterfactualFactsV1 {
                plan_digest: facts.plan_digest,
                dependency_graph_digest: facts.dependency_graph_digest,
                trust_epoch: facts.trust_epoch,
                revocation_epoch: REVOCATION_EPOCH,
                erasure_epoch: ERASURE_EPOCH,
            },
        )?;
        Ok(())
    }
}

/// Which read a [`Faulty`] store fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreFault {
    None,
    Generation,
    ArtifactError,
    ArtifactMissing,
    ArtifactGarbage,
    EventRead,
}

/// A `MemoryStore` whose reads fail as configured.
struct Faulty {
    inner: MemoryStore,
    fault: StoreFault,
}

impl EventStore for Faulty {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.inner.create_timeline(name)
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        self.inner.create_timeline_with_meta(meta)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.inner.append(timeline, drafts)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        if self.fault == StoreFault::EventRead {
            Err(CoreError::Storage("injected read failure".to_owned()))
        } else {
            self.inner.read(timeline, range)
        }
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.inner.fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.inner.list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.inner.get_timeline(id)
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.inner.logical_head(id)
    }
}

impl CounterfactualStorePortV1 for Faulty {
    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        self.inner.commit_counterfactual_invalidation(command)
    }

    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        if self.fault == StoreFault::Generation {
            Err(CounterfactualStoreErrorV1::CorruptState)
        } else {
            self.inner.current_fork_generation(fork)
        }
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, CounterfactualStoreErrorV1> {
        match self.fault {
            StoreFault::ArtifactError => Err(CounterfactualStoreErrorV1::StorageFailure),
            StoreFault::ArtifactMissing => Ok(None),
            StoreFault::ArtifactGarbage => Ok(Some(vec![0])),
            _ => self.inner.read_generation_artifact(at, artifact_digest),
        }
    }
}

impl Backend for Faulty {
    fn open() -> TestResult<Self> {
        Ok(Self {
            inner: <MemoryStore as Backend>::open()?,
            fault: StoreFault::None,
        })
    }

    fn publish(&mut self, fork: TimelineId, facts: Facts) -> TestResult {
        Backend::publish(&mut self.inner, fork, facts)
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
    profile: &ExecutionProfileV1,
    snapshot: &TrustPolicySnapshotV1,
    edit: fn(&mut CounterfactualPlanV1),
) -> TestResult<CounterfactualPlanV1> {
    let mut plan = CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: "room.alpha".to_owned(),
        room_digest: [2; 32],
        parent_timeline_id: root_id().inner().to_bytes(),
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
        [0xd0 + seed; 32],
        DependencyClassV1::EndogenousRecomputed,
    )
}

fn nodes(plan: &CounterfactualPlanV1) -> TestResult<Vec<Node>> {
    let intervention_node = |position: usize| -> TestResult<Node> {
        let intervention = &plan.interventions[position];
        Ok(node(
            intervention.effective_tick,
            "intervention",
            intervention.digest()?,
            DependencyClassV1::InterventionAssigned,
        ))
    };
    Ok(vec![
        node(5, "env", [0x50; 32], DependencyClassV1::ExogenousFrozen),
        endogenous(9, "world", 1),
        node(10, "policy", [0x30; 32], DependencyClassV1::FixedPolicy),
        endogenous(10, "world", 2),
        intervention_node(0)?,
        endogenous(11, "world", 3),
        endogenous(12, "world", 4),
        intervention_node(1)?,
        endogenous(14, "agent", 5),
        node(15, "ui", [0xd7; 32], DependencyClassV1::PresentationOnly),
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

/// The `pos-time` graph validation and frontier derivation behind the port.
struct Source {
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
}

impl Source {
    fn new(plan: &CounterfactualPlanV1) -> TestResult<Self> {
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
            .map(|&(consumer, source)| edge(&nodes[consumer], &nodes[source]))
            .collect();
        edges.sort_by_key(|edge| {
            (
                edge.consumer.tick,
                edge.consumer.scheduler_position,
                edge.consumer.owner_id.clone(),
                edge.consumer.output_ordinal,
                edge.source.artifact_digest,
            )
        });
        Ok(Self { nodes, edges })
    }

    fn graph_digest(&self, plan: &CounterfactualPlanV1) -> TestResult<[u8; 32]> {
        let graph = validate_dependency_graph_v1(
            plan,
            UnknownEdgePolicyV1::Reject,
            BOUNDS,
            self.nodes.clone(),
            self.edges.clone(),
        )?;
        Ok(dependency_graph_digest_v1(&graph)?)
    }
}

impl CounterfactualFrontierSourceV1 for Source {
    fn derive_frontier(
        &mut self,
        plan: &CounterfactualPlanV1,
        frontier_id: [u8; 16],
        provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, AdmissionError> {
        let graph = validate_dependency_graph_v1(
            plan,
            UnknownEdgePolicyV1::Reject,
            BOUNDS,
            self.nodes.clone(),
            self.edges.clone(),
        )
        .or(Err(AdmissionError::DependencyGraphInvalid))?;
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

/// Authorizes every Intervention.
struct Authority;

impl CounterfactualInterventionAuthorityV1 for Authority {
    fn decide(&self, _intervention: &InterventionV1) -> InterventionDecisionV1 {
        InterventionDecisionV1::Authorized
    }
}

/// How a [`Stager`] fails one Tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Error,
    Empty,
    Reserved,
    Consent,
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

/// Stages [`tick_drafts`], or fails one Tick with `fault`.
#[derive(Default)]
struct Stager {
    fault: Option<(u64, Fault)>,
    seen: Vec<Seen>,
}

impl Stager {
    const fn failing(tick: u64, fault: Fault) -> Self {
        Self {
            fault: Some((tick, fault)),
            seen: Vec::new(),
        }
    }

    fn ticks(&self) -> Vec<u64> {
        self.seen.iter().map(|seen| seen.tick).collect()
    }
}

impl CounterfactualTickStagerV1 for Stager {
    fn stage_tick(
        &mut self,
        inputs: &CounterfactualTickInputsV1<'_>,
    ) -> Result<Vec<EventDraft>, CounterfactualTickFailureV1> {
        let tick = inputs.tick();
        self.seen.push(Seen {
            generation: inputs.generation(),
            tick,
            interventions: inputs
                .interventions()
                .iter()
                .map(|intervention| intervention.intervention_id)
                .collect(),
            exogenous: inputs.exogenous_descriptors().to_vec(),
            fixed_policy: inputs.fixed_policy_descriptors().to_vec(),
        });
        let fault = self
            .fault
            .filter(|&(at, _)| at == tick)
            .map(|(_, fault)| fault);
        match fault {
            None => Ok(tick_drafts(tick)),
            Some(Fault::Error) => Err(CounterfactualTickFailureV1),
            Some(Fault::Empty) => Ok(Vec::new()),
            Some(Fault::Reserved) => Ok(vec![event_draft(
                COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1,
                vec![1],
            )]),
            Some(Fault::Consent) => Ok(vec![event_draft("consent.grant", vec![1])]),
        }
    }
}

/// Reports the admitted epochs for `stable_calls` calls, then `change`d ones.
struct Epochs {
    admitted: CounterfactualEpochsV1,
    stable_calls: usize,
    change: fn(&mut CounterfactualEpochsV1),
    calls: Cell<usize>,
}

impl Epochs {
    fn stable(fixture: &Fixture) -> Self {
        Self::changing(fixture, usize::MAX, |_| {})
    }

    fn changing(
        fixture: &Fixture,
        stable_calls: usize,
        change: fn(&mut CounterfactualEpochsV1),
    ) -> Self {
        Self {
            admitted: admitted_epochs(fixture),
            stable_calls,
            change,
            calls: Cell::new(0),
        }
    }
}

impl CounterfactualEpochSourceV1 for Epochs {
    fn current_epochs(&self) -> CounterfactualEpochsV1 {
        let calls = self.calls.get();
        self.calls.set(calls + 1);
        let mut epochs = self.admitted;
        if calls >= self.stable_calls {
            (self.change)(&mut epochs);
        }
        epochs
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    plan: CounterfactualPlanV1,
    profile: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
    receipt: CounterfactualGenerationReceiptV1,
}

struct Setup<B> {
    coordinator: CounterfactualCoordinatorV1<B>,
    source: Source,
    fixture: Fixture,
}

fn admitted_epochs(fixture: &Fixture) -> CounterfactualEpochsV1 {
    CounterfactualEpochsV1 {
        trust: fixture.snapshot.epoch,
        revocation: REVOCATION_EPOCH,
        erasure: ERASURE_EPOCH,
    }
}

fn admission_request<'a>(
    plan: &'a CounterfactualPlanV1,
    profile: &'a ExecutionProfileV1,
    snapshot: &'a TrustPolicySnapshotV1,
) -> CounterfactualAdmissionRequestV1<'a> {
    CounterfactualAdmissionRequestV1 {
        plan,
        fork: fork_id(),
        fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
        execution_profile: profile,
        trust_policy: snapshot,
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
        frontier_id: FRONTIER_ID,
        invalidation_id: INVALIDATION_ID,
        provenance_digest: PROVENANCE,
        invalid_checkpoint_digests: &[],
        invalid_projection_digests: &[],
    }
}

/// A factual root with two Events, a Fork at `Seq` 2 with fixed IDs, the
/// published facts, and an admitted generation 1 whose first Tick is 11.
fn setup_in<B: Backend>(mut store: B, edit: fn(&mut CounterfactualPlanV1)) -> TestResult<Setup<B>> {
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
    let profile = ExecutionProfileV1::from_canonical_cbor(&draft_execution_profile_bytes_v1(
        "deterministic-local-v1",
    )?)?;
    let snapshot =
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
    let plan = plan(&profile, &snapshot, edit)?;
    let mut source = Source::new(&plan)?;
    store.publish(
        fork_id(),
        Facts {
            plan_digest: Hash::from_bytes(plan.plan_digest),
            dependency_graph_digest: Hash::from_bytes(source.graph_digest(&plan)?),
            trust_epoch: snapshot.epoch,
        },
    )?;
    let mut coordinator = CounterfactualCoordinatorV1::new(store);
    let receipt = coordinator.admit(
        &admission_request(&plan, &profile, &snapshot),
        &Authority,
        &mut source,
        &mut Stager::default(),
    )?;
    Ok(Setup {
        coordinator,
        source,
        fixture: Fixture {
            plan,
            profile,
            snapshot,
            receipt,
        },
    })
}

fn prepare<B: Backend>() -> TestResult<Setup<B>> {
    setup_in(B::open()?, |_| {})
}

/// Release the store, change it, and hand it to a new coordinator.
fn reopen<B: Backend>(
    setup: Setup<B>,
    change: impl FnOnce(&mut B) -> TestResult,
) -> TestResult<Setup<B>> {
    let mut store = setup.coordinator.into_store();
    change(&mut store)?;
    Ok(Setup {
        coordinator: CounterfactualCoordinatorV1::new(store),
        ..setup
    })
}

fn suffix_request(fixture: &Fixture) -> CounterfactualSuffixRequestV1<'_> {
    CounterfactualSuffixRequestV1 {
        plan: &fixture.plan,
        receipt: fixture.receipt,
        admitted_epochs: admitted_epochs(fixture),
        result_id: RESULT_ID,
        evaluator_identity_digest: EVALUATOR,
    }
}

fn run_with<B: Backend>(setup: &mut Setup<B>, epochs: &Epochs, stager: &mut Stager) -> Suffix {
    setup
        .coordinator
        .recompute_suffix(&suffix_request(&setup.fixture), epochs, stager)
}

fn run<B: Backend>(setup: &mut Setup<B>, stager: &mut Stager) -> Suffix {
    let epochs = Epochs::stable(&setup.fixture);
    run_with(setup, &epochs, stager)
}

fn head<B: Backend>(setup: &Setup<B>) -> TestResult<u64> {
    Ok(setup.coordinator.store().logical_head(fork_id())?.as_u64())
}

/// The uninterrupted run every retry and recovery must reproduce.
fn reference() -> TestResult<CounterfactualSuffixRunV1> {
    let mut setup = prepare::<MemoryStore>()?;
    Ok(run(&mut setup, &mut Stager::default())?)
}

fn chain(previous: &[u8; 32], tick: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STATE_DOMAIN);
    hasher.update(previous);
    hasher.update(&tick.to_be_bytes());
    hasher.update(pipeline_draft_vector_digest_v1(&tick_drafts(tick)).as_bytes());
    *hasher.finalize().as_bytes()
}

/// The `RCP1` of every Tick from the frontier through `last`.
fn expected_checkpoints(fixture: &Fixture, last: u64) -> TestResult<Vec<RecomputeCheckpointV1>> {
    let mut state = *fixture.receipt.invalidation_digest().as_bytes();
    let mut checkpoints = Vec::new();
    for tick in FRONTIER_TICK..=last {
        state = chain(&state, tick);
        let mut checkpoint = RecomputeCheckpointV1 {
            plan_digest: fixture.plan.plan_digest,
            tick,
            seq: tick_seq(tick),
            scheduler_position: 0,
            plugin_state_digests: Vec::new(),
            projection_digests: Vec::new(),
            state_digests: vec![CheckpointDigestEntryV1 {
                owner_id: SUFFIX_STATE_OWNER_V1.to_owned(),
                digest: state,
            }],
            exogenous_cursor: ExogenousCursorV1 {
                consumed_descriptors: 1,
                last_descriptor_digest: Some([0x50; 32]),
            },
            provenance_root: PROVENANCE,
            checkpoint_digest: [0; 32],
        };
        checkpoint.checkpoint_digest = checkpoint.digest()?;
        checkpoints.push(checkpoint);
    }
    Ok(checkpoints)
}

/// The `CFR1` over `checkpoints`, failed with `terminal` when present.
fn expected_result(
    fixture: &Fixture,
    checkpoints: &[RecomputeCheckpointV1],
    terminal: Option<CounterfactualTerminalErrorV1>,
) -> TestResult<CounterfactualResultV1> {
    let last = checkpoints.last().ok_or("no checkpoint")?;
    let (terminal_state, replay_claim) = if terminal.is_some() {
        (
            CounterfactualTerminalStateV1::Failed,
            ReplayClaimV1::StructuralOnly,
        )
    } else {
        (
            CounterfactualTerminalStateV1::Completed,
            ReplayClaimV1::Exact,
        )
    };
    let mut result = CounterfactualResultV1 {
        result_id: RESULT_ID,
        plan_digest: fixture.plan.plan_digest,
        fork_id: fork_id().inner().to_bytes(),
        fork_generation: 1,
        first_tick: FRONTIER_TICK,
        horizon_tick: HORIZON_TICK,
        committed_through_tick: Some(last.tick),
        checkpoints: checkpoints
            .iter()
            .map(|checkpoint| CounterfactualCheckpointRefV1 {
                tick: checkpoint.tick,
                fork_generation: 1,
                checkpoint_digest: checkpoint.checkpoint_digest,
            })
            .collect(),
        terminal_state,
        terminal_error: terminal,
        suffix_digest: last.state_digests[0].digest,
        dependency_root: *fixture.receipt.frontier_digest().as_bytes(),
        provenance_root: PROVENANCE,
        replay_claim,
        execution_profile_digest: fixture.plan.execution_profile.profile_digest,
        trust_policy_snapshot_digest: fixture.plan.trust_policy.snapshot_digest,
        evaluator_identity_digest: EVALUATOR,
        result_digest: [0; 32],
    };
    result.result_digest = result.digest()?;
    Ok(result)
}

fn decoded_checkpoints(run: &CounterfactualSuffixRunV1) -> TestResult<Vec<RecomputeCheckpointV1>> {
    run.checkpoints
        .iter()
        .map(|bytes| Ok(RecomputeCheckpointV1::from_canonical_cbor(bytes)?))
        .collect()
}

/// Assert `run` failed with `failure` at `tick` and committed nothing of it.
fn assert_failed_at<B: Backend>(
    setup: &Setup<B>,
    run: &CounterfactualSuffixRunV1,
    failure: Failure,
    code: CounterfactualTerminalErrorCodeV1,
    tick: u64,
) -> TestResult {
    let checkpoints = expected_checkpoints(&setup.fixture, tick - 1)?;
    assert_eq!(run.failure, Some(failure));
    assert_eq!(decoded_checkpoints(run)?, checkpoints);
    let terminal = CounterfactualTerminalErrorV1 {
        code,
        tick,
        scheduler_position: 0,
        safe_digest: None,
    };
    assert_eq!(
        CounterfactualResultV1::from_canonical_cbor(&run.result)?,
        expected_result(&setup.fixture, &checkpoints, Some(terminal))?
    );
    assert_eq!(head(setup)?, committed_head(tick - 1));
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenarios
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

fn recomputes_every_tick_through_the_horizon<B: Backend>() -> TestResult {
    let mut setup = prepare::<B>()?;
    let mut stager = Stager::default();
    let run = run(&mut setup, &mut stager)?;
    assert_eq!(run.failure, None);
    let generation = setup.fixture.receipt.generation();
    // Canonical Tick order under the one admitted generation, with the exact
    // frozen descriptors and only the Interventions effective at each Tick.
    let expected_seen: Vec<Seen> = (FRONTIER_TICK + 1..=HORIZON_TICK)
        .map(|tick| Seen {
            generation,
            tick,
            interventions: if tick == 13 {
                vec![INTERVENTION_B_ID]
            } else {
                Vec::new()
            },
            exogenous: setup.fixture.plan.exogenous_descriptors.clone(),
            fixed_policy: setup.fixture.plan.fixed_policy_descriptors.clone(),
        })
        .collect();
    assert_eq!(stager.seen, expected_seen);
    let store = setup.coordinator.store();
    assert_eq!(store.current_fork_generation(fork_id())?, generation);
    assert_eq!(head(&setup)?, committed_head(HORIZON_TICK));

    let checkpoints = expected_checkpoints(&setup.fixture, HORIZON_TICK)?;
    assert_eq!(decoded_checkpoints(&run)?, checkpoints);
    let result = CounterfactualResultV1::from_canonical_cbor(&run.result)?;
    assert_eq!(result, expected_result(&setup.fixture, &checkpoints, None)?);
    assert!(result.is_complete());

    // Each later Tick committed its Events and then its exact RCP1 bytes.
    let events = store.read(fork_id(), SeqRange::from_seq(Seq::from_u64(CUT_SEQ + 1)))?;
    let mut expected_events = tick_drafts(FRONTIER_TICK);
    for (tick, bytes) in (FRONTIER_TICK + 1..).zip(&run.checkpoints[1..]) {
        expected_events.extend(tick_drafts(tick));
        expected_events.push(EventDraft::new(
            EntityId::from_ulid(fork_id().inner()),
            Kind::new(COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1),
            CanonicalBytes::from_vec(bytes.clone()),
        ));
    }
    let committed: Vec<_> = events
        .iter()
        .map(|event| {
            (
                event.entity,
                event.event_type.clone(),
                event.payload.clone(),
            )
        })
        .collect();
    let staged: Vec<_> = expected_events
        .into_iter()
        .map(|draft| (draft.entity, draft.event_type, draft.payload))
        .collect();
    assert_eq!(committed, staged);
    Ok(())
}
both_backends!(recomputes_every_tick_through_the_horizon);

#[test]
fn runs_are_repeatable_across_calls_and_backends() -> TestResult {
    let reference = reference()?;
    let mut sqlite = prepare::<SqliteStore>()?;
    assert_eq!(run(&mut sqlite, &mut Stager::default())?, reference);

    // A completed generation recovers to the same artifacts and stages nothing.
    let head_before = head(&sqlite)?;
    let mut stager = Stager::default();
    assert_eq!(run(&mut sqlite, &mut stager)?, reference);
    assert!(stager.seen.is_empty());
    assert_eq!(head(&sqlite)?, head_before);
    Ok(())
}

const TICK_FAULTS: [(Fault, Failure, CounterfactualTerminalErrorCodeV1); 4] = [
    (
        Fault::Error,
        Failure::PluginFailure,
        CounterfactualTerminalErrorCodeV1::PluginFailure,
    ),
    (
        Fault::Empty,
        Failure::StagedTickRejected(PipelineContractErrorV1::EmptyBatch),
        CounterfactualTerminalErrorCodeV1::PluginFailure,
    ),
    (
        Fault::Reserved,
        Failure::ReservedEventType,
        CounterfactualTerminalErrorCodeV1::PluginFailure,
    ),
    (
        Fault::Consent,
        Failure::AtomicCommitFailed,
        CounterfactualTerminalErrorCodeV1::AtomicCommitFailed,
    ),
];

fn failed_tick_commits_nothing_and_retries_deterministically<B: Backend>() -> TestResult {
    let reference = reference()?;
    for (fault, failure, code) in TICK_FAULTS {
        let mut setup = prepare::<B>()?;
        let mut stager = Stager::failing(13, fault);
        let failed = run(&mut setup, &mut stager)?;
        assert_eq!(stager.ticks(), vec![12, 13]);
        assert_failed_at(&setup, &failed, failure, code, 13)?;

        // The failure is explicit and repeatable until the Tick succeeds.
        let mut stager = Stager::failing(13, fault);
        assert_eq!(run(&mut setup, &mut stager)?, failed);
        assert_eq!(stager.ticks(), vec![13]);

        let mut stager = Stager::default();
        assert_eq!(run(&mut setup, &mut stager)?, reference);
        assert_eq!(stager.ticks(), (13..=HORIZON_TICK).collect::<Vec<_>>());
    }
    Ok(())
}
both_backends!(failed_tick_commits_nothing_and_retries_deterministically);

fn epoch_change_stops_before_the_next_tick<B: Backend>() -> TestResult {
    let reference = reference()?;
    let changes: [(fn(&mut CounterfactualEpochsV1), InvalidationConflictV1); 3] = [
        (
            |epochs| epochs.trust += 1,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |epochs| epochs.revocation += 1,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |epochs| epochs.erasure += 1,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    for (change, conflict) in changes {
        let mut setup = prepare::<B>()?;
        let epochs = Epochs::changing(&setup.fixture, 2, change);
        let mut stager = Stager::default();
        let failed = run_with(&mut setup, &epochs, &mut stager)?;
        assert_eq!(stager.ticks(), vec![12, 13]);
        assert_failed_at(
            &setup,
            &failed,
            Failure::EpochChanged(conflict),
            CounterfactualTerminalErrorCodeV1::InvalidationConflict,
            14,
        )?;
        assert_eq!(run(&mut setup, &mut Stager::default())?, reference);
    }
    Ok(())
}
both_backends!(epoch_change_stops_before_the_next_tick);

#[test]
fn memory_coordinator_recovers_after_a_restart() -> TestResult {
    let reference = reference()?;
    let mut setup = prepare::<MemoryStore>()?;
    run(&mut setup, &mut Stager::failing(15, Fault::Error))?;
    let mut restarted = reopen(setup, |_| Ok(()))?;
    let mut stager = Stager::default();
    assert_eq!(run(&mut restarted, &mut stager)?, reference);
    assert_eq!(stager.ticks(), (15..=HORIZON_TICK).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn sqlite_coordinator_recovers_after_reopening_the_database() -> TestResult {
    let reference = reference()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("suffix.db");
    let path = path.to_str().ok_or("non UTF-8 path")?;
    let mut setup = setup_in(open_sqlite(path)?, |_| {})?;
    run(&mut setup, &mut Stager::failing(15, Fault::Consent))?;
    let Setup {
        coordinator,
        source,
        fixture,
    } = setup;
    drop(coordinator);
    let mut reopened = Setup {
        coordinator: CounterfactualCoordinatorV1::new(open_sqlite(path)?),
        source,
        fixture,
    };
    let mut stager = Stager::default();
    assert_eq!(run(&mut reopened, &mut stager)?, reference);
    assert_eq!(stager.ticks(), (15..=HORIZON_TICK).collect::<Vec<_>>());
    Ok(())
}

fn stale_generation_and_foreign_plans_are_rejected<B: Backend>() -> TestResult {
    let mut setup = prepare::<B>()?;
    let Setup {
        coordinator,
        source,
        fixture,
    } = &mut setup;
    coordinator.admit(
        &admission_request(&fixture.plan, &fixture.profile, &fixture.snapshot),
        &Authority,
        source,
        &mut Stager::default(),
    )?;
    let mut stager = Stager::default();
    assert_eq!(
        run(&mut setup, &mut stager),
        Err(SuffixError::Store(
            CounterfactualStoreErrorV1::MixedForkGeneration
        ))
    );

    let mut setup = prepare::<B>()?;
    let mut foreign = setup.fixture.plan.clone();
    foreign.room_id = "room.beta".to_owned();
    foreign.plan_digest = foreign.digest()?;
    let mut corrupt = setup.fixture.plan.clone();
    corrupt.plan_digest = [1; 32];
    let cases = [
        (foreign, SuffixError::PlanMismatch),
        (
            corrupt,
            SuffixError::Plan(CounterfactualPlanContractErrorV1::DigestMismatch),
        ),
    ];
    let epochs = Epochs::stable(&setup.fixture);
    for (plan, expected) in cases {
        let request = CounterfactualSuffixRequestV1 {
            plan: &plan,
            ..suffix_request(&setup.fixture)
        };
        let result = setup
            .coordinator
            .recompute_suffix(&request, &epochs, &mut stager);
        assert_eq!(result, Err(expected));
    }
    assert!(stager.seen.is_empty());
    assert_eq!(head(&setup)?, FIRST_TICK_HEAD);
    Ok(())
}
both_backends!(stale_generation_and_foreign_plans_are_rejected);

fn tampered_suffix_events_are_rejected<B: Backend>() -> TestResult {
    let forged = event_draft(COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1, vec![0]);
    let tampers = [
        vec![event_draft("counterfactual.world", vec![9])],
        vec![event_draft("counterfactual.world", vec![9]), forged],
    ];
    for drafts in tampers {
        let mut setup = prepare::<B>()?;
        run(&mut setup, &mut Stager::failing(14, Fault::Error))?;
        let mut setup = reopen(setup, |store| {
            store.append(fork_id(), &drafts)?;
            Ok(())
        })?;
        let mut stager = Stager::default();
        assert_eq!(
            run(&mut setup, &mut stager),
            Err(SuffixError::RecoveryMismatch)
        );
        assert!(stager.seen.is_empty());
    }
    Ok(())
}
both_backends!(tampered_suffix_events_are_rejected);

#[test]
fn store_read_faults_are_closed() -> TestResult {
    let cases = [
        (
            StoreFault::Generation,
            SuffixError::Store(CounterfactualStoreErrorV1::CorruptState),
        ),
        (
            StoreFault::ArtifactError,
            SuffixError::Store(CounterfactualStoreErrorV1::StorageFailure),
        ),
        (StoreFault::ArtifactMissing, SuffixError::RecoveryMismatch),
        (StoreFault::ArtifactGarbage, SuffixError::RecoveryMismatch),
        (
            StoreFault::EventRead,
            SuffixError::Store(CounterfactualStoreErrorV1::StorageFailure),
        ),
    ];
    for (fault, expected) in cases {
        let setup = prepare::<Faulty>()?;
        let mut setup = reopen(setup, |store| {
            store.fault = fault;
            Ok(())
        })?;
        let mut stager = Stager::default();
        assert_eq!(run(&mut setup, &mut stager), Err(expected));
        assert!(stager.seen.is_empty());
    }
    Ok(())
}

#[test]
fn suffix_length_is_bounded_by_the_checkpoint_limit() -> TestResult {
    let mut at_limit = setup_in(<MemoryStore as Backend>::open()?, |plan| {
        plan.horizon_tick = FRONTIER_TICK + MAX_SPAN;
    })?;
    let mut stager = Stager::failing(12, Fault::Error);
    let run_at_limit = run(&mut at_limit, &mut stager)?;
    assert_eq!(run_at_limit.failure, Some(Failure::PluginFailure));
    assert_eq!(stager.ticks(), vec![12]);

    let mut beyond = setup_in(<MemoryStore as Backend>::open()?, |plan| {
        plan.horizon_tick = FRONTIER_TICK + MAX_SPAN + 1;
    })?;
    let mut stager = Stager::default();
    assert_eq!(
        run(&mut beyond, &mut stager),
        Err(SuffixError::SuffixTooLong)
    );
    assert!(stager.seen.is_empty());
    Ok(())
}

#[test]
fn every_error_has_a_distinct_safe_message() {
    let errors = [
        SuffixError::Plan(CounterfactualPlanContractErrorV1::DigestMismatch),
        SuffixError::SuffixTooLong,
        SuffixError::PlanMismatch,
        SuffixError::RecoveryMismatch,
        SuffixError::ArtifactEncoding,
        SuffixError::Store(CounterfactualStoreErrorV1::StorageFailure),
    ];
    let messages: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    assert!(messages.iter().all(|message| !message.is_empty()));
    let with_source = [0, 5];
    for (position, error) in errors.iter().enumerate() {
        assert_eq!(error.source().is_some(), with_source.contains(&position));
    }
}

#[test]
fn unchanged_epochs_report_no_change() {
    let epochs = CounterfactualEpochsV1 {
        trust: 1,
        revocation: 2,
        erasure: 3,
    };
    assert_eq!(epochs.first_change(&epochs), None);
    let all_changed = CounterfactualEpochsV1 {
        trust: 4,
        revocation: 5,
        erasure: 6,
    };
    assert_eq!(
        epochs.first_change(&all_changed),
        Some(InvalidationConflictV1::TrustEpoch)
    );
}
