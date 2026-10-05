//! Public-interface tests for ADR-064 endogenous suffix recomputation after
//! the first atomic Tick, against both `MemoryStore` and `SqliteStore`.
#![cfg(target_os = "linux")]

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
    pipeline_draft_vector_digest_v1, CanonicalBytes, CoreError, CounterfactualAdapterSealV1,
    CounterfactualBasisV1, CounterfactualFactsV1, CounterfactualGenerationReceiptV1,
    CounterfactualInvalidationCommandV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1, EntityId,
    ErasureContainmentGateV1, Event, EventDraft, EventReadBounds, EventStore, ForkGenerationV1,
    Hash, InvalidationConflictV1, Kind, PipelineContractErrorV1, PipelineDraftBatchV1, Seq,
    SeqRange, Timeline, TimelineId, TimelineMeta, MAX_FORK_EVENT_TYPE_BYTES_V1,
    MAX_PIPELINE_DRAFTS_PER_BATCH, MAX_PIPELINE_DRAFT_BATCH_BYTES,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1 as AdmissionError, CounterfactualAdmissionRequestV1,
    CounterfactualCoordinatorV1, CounterfactualForkAppendAuthorityV1,
    CounterfactualFrontierDerivationV1, CounterfactualFrontierSourceV1,
    CounterfactualInterventionAuthorityV1, CounterfactualProvisionalOutputV1,
    CounterfactualTickFailureV1, CounterfactualTickInputsV1, CounterfactualTickStagerV1,
    InterventionDecisionV1, COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1,
};
use pos_runtime::counterfactual::suffix::{
    CounterfactualSuffixErrorV1 as SuffixError, CounterfactualSuffixFailureV1 as Failure,
    CounterfactualSuffixRequestV1, CounterfactualSuffixRunV1, SUFFIX_STATE_OWNER_V1,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
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
/// One change to the published facts of the Fork.
type FactsChange = fn(&mut CounterfactualFactsV1);
/// A published-facts change with the conflict it reports.
type FactCase = (FactsChange, InvalidationConflictV1);
/// The committed `(entity, type, payload)` of one Event.
type CommittedEvent = (EntityId, Kind, Vec<u8>);

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
/// The byte cap of one recovery read: one Tick batch.
const PAGE_CAP: usize = MAX_PIPELINE_DRAFT_BATCH_BYTES;
/// A payload that leaves just room for one world Event's and the checkpoint
/// Event's other content bytes in one batch.
const HEAVY_PAYLOAD: usize = MAX_PIPELINE_DRAFT_BATCH_BYTES - 1_024;
const WORLD_TYPE: &str = "counterfactual.world";

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

/// `count` deterministic Events of `tick`.
fn world_drafts(tick: u64, count: usize) -> Vec<EventDraft> {
    (0..count)
        .map(|ordinal| {
            let mut payload = tick.to_be_bytes().to_vec();
            payload.extend_from_slice(&ordinal.to_be_bytes());
            event_draft("counterfactual.world", payload)
        })
        .collect()
}

/// The two deterministic Events every successful Tick stages.
fn tick_drafts(tick: u64) -> Vec<EventDraft> {
    world_drafts(tick, 2)
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
}

/// Which read a [`Faulty`] store falsifies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreFault {
    None,
    /// The persisted basis read fails.
    Basis,
    ArtifactError,
    ArtifactMissing,
    ArtifactGarbage,
    /// Every artifact read serves this other committed artifact.
    ArtifactSwapped(Hash),
    /// Every Event read from this `Seq` on fails.
    ReadFailsFrom(u64),
    /// Every Event read omits the Event at this `Seq`.
    Dropped(u64),
    /// Every Event read alters the payload of the Event at this `Seq`.
    Altered(u64),
}

/// What a [`Faulty`] store does right before its `n`th later Tick append.
#[derive(Clone, Copy)]
enum Interference {
    None,
    /// Republish the Fork's facts with one change.
    Republish(usize, FactsChange),
    /// Append one foreign Event to the Fork.
    ForeignAppend(usize),
    /// Commit nothing and report an unknown outcome.
    LostUnknown(usize),
    /// Commit nothing, report an unknown outcome, and fail every persisted
    /// basis read from then on.
    UnreadableUnknown(usize),
    /// Commit the Tick but report an unknown outcome.
    LandedUnknown(usize),
    /// Commit the Tick but report a head one `Seq` past the real one.
    MisreportedHead(usize),
}

/// A store whose reads and Tick appends are falsified as configured.
struct Faulty<B> {
    inner: B,
    fault: StoreFault,
    interference: Interference,
    appends: usize,
    /// Whether an [`Interference::UnreadableUnknown`] append happened.
    in_doubt: bool,
}

/// Report a committed Tick one `Seq` past its real head; only a test wrapper
/// may mint that outcome with the adapter seal.
const fn misreported(
    expected: &CounterfactualBasisV1,
    outcome: CounterfactualTickOutcomeV1,
) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
    match outcome {
        CounterfactualTickOutcomeV1::Committed { head } => expected.committed_tick(
            &CounterfactualAdapterSealV1::for_adapter(),
            Seq::from_u64(head.as_u64() + 1),
        ),
        stale @ CounterfactualTickOutcomeV1::Stale(_) => Ok(stale),
    }
}

impl<B> Faulty<B> {
    fn falsify(&self, mut event: Event) -> Option<Event> {
        let seq = event.seq.as_u64();
        if self.fault == StoreFault::Altered(seq) {
            event.payload = CanonicalBytes::from_vec(vec![0xee]);
        }
        (self.fault != StoreFault::Dropped(seq)).then_some(event)
    }
}

impl<B: Backend> EventStore for Faulty<B> {
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
        self.inner.read(timeline, range)
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        if matches!(self.fault, StoreFault::ReadFailsFrom(seq) if range.from.as_u64() >= seq) {
            return Err(CoreError::Storage("injected read failure".to_owned()));
        }
        Ok(self
            .inner
            .read_bounded(timeline, range, bounds)?
            .into_iter()
            .filter_map(|event| self.falsify(event))
            .collect())
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

impl<B: Backend> CounterfactualStorePortV1 for Faulty<B> {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.inner.publish_counterfactual_facts(fork, facts)
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        self.inner.commit_counterfactual_invalidation(command)
    }

    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        self.appends += 1;
        let now = self.appends;
        match self.interference {
            Interference::Republish(at, change) if at == now => {
                let mut facts = self.inner.current_counterfactual_basis(fork)?.facts;
                change(&mut facts);
                self.inner.publish_counterfactual_facts(fork, facts)?;
            }
            Interference::ForeignAppend(at) if at == now => {
                self.inner
                    .append(fork, &[event_draft("counterfactual.world", vec![1])])
                    .or(Err(CounterfactualStoreErrorV1::StorageFailure))?;
            }
            Interference::LostUnknown(at) if at == now => {
                return Err(CounterfactualStoreErrorV1::OutcomeUnknown);
            }
            Interference::UnreadableUnknown(at) if at == now => {
                self.in_doubt = true;
                return Err(CounterfactualStoreErrorV1::OutcomeUnknown);
            }
            Interference::LandedUnknown(at) if at == now => {
                return self
                    .inner
                    .append_counterfactual_tick(fork, expected, drafts)
                    .and(Err(CounterfactualStoreErrorV1::OutcomeUnknown));
            }
            Interference::MisreportedHead(at) if at == now => {
                return self
                    .inner
                    .append_counterfactual_tick(fork, expected, drafts)
                    .and_then(|outcome| misreported(expected, outcome));
            }
            _ => {}
        }
        self.inner
            .append_counterfactual_tick(fork, expected, drafts)
    }

    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.inner.current_fork_generation(fork)
    }

    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, CounterfactualStoreErrorV1> {
        if self.fault == StoreFault::Basis || self.in_doubt {
            Err(CounterfactualStoreErrorV1::CorruptState)
        } else {
            self.inner.current_counterfactual_basis(fork)
        }
    }

    fn committed_generation_receipt(
        &self,
        at: ForkGenerationV1,
    ) -> Result<Option<CounterfactualGenerationReceiptV1>, CounterfactualStoreErrorV1> {
        self.inner.committed_generation_receipt(at)
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
            StoreFault::ArtifactSwapped(other) => self.inner.read_generation_artifact(at, other),
            _ => self.inner.read_generation_artifact(at, artifact_digest),
        }
    }
}

impl<B: Backend> Backend for Faulty<B> {
    fn open() -> TestResult<Self> {
        Ok(Self {
            inner: B::open()?,
            fault: StoreFault::None,
            interference: Interference::None,
            appends: 0,
            in_doubt: false,
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
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
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
        let graph =
            validate_dependency_graph_v1(plan, BOUNDS, self.nodes.clone(), self.edges.clone())?;
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
        let graph =
            validate_dependency_graph_v1(plan, BOUNDS, self.nodes.clone(), self.edges.clone())
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

/// How a [`Stager`] stages one Tick differently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    Error,
    Empty,
    Reserved,
    Consent,
    /// One draft fewer than a batch holds: the checkpoint Event fills it.
    Wide,
    /// A full batch: the checkpoint Event no longer fits.
    Full,
    /// One Event of [`HEAVY_PAYLOAD`] bytes: the Tick fits one batch, but a
    /// recovery page with the Ticks after it exceeds [`PAGE_CAP`].
    Heavy,
    /// One Event whose type has exactly the largest accepted length.
    LongestType,
    /// One Event whose type is one byte longer than accepted.
    LongType,
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

/// Stages [`tick_drafts`], or stages one Tick with `fault`.
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
            Some(Fault::Wide) => Ok(world_drafts(tick, MAX_PIPELINE_DRAFTS_PER_BATCH - 1)),
            Some(Fault::Full) => Ok(world_drafts(tick, MAX_PIPELINE_DRAFTS_PER_BATCH)),
            Some(Fault::Heavy) => Ok(vec![event_draft(WORLD_TYPE, vec![0x5a; HEAVY_PAYLOAD])]),
            Some(Fault::LongestType) => Ok(vec![event_draft(
                &"t".repeat(MAX_FORK_EVENT_TYPE_BYTES_V1),
                vec![1],
            )]),
            Some(Fault::LongType) => Ok(vec![event_draft(
                &"t".repeat(MAX_FORK_EVENT_TYPE_BYTES_V1 + 1),
                vec![1],
            )]),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    plan: CounterfactualPlanV1,
    profile: ExecutionProfileV1,
    snapshot: TrustPolicySnapshotV1,
    facts: CounterfactualFactsV1,
    receipt: CounterfactualGenerationReceiptV1,
}

struct Setup<B> {
    coordinator: CounterfactualCoordinatorV1<B>,
    source: Source,
    fixture: Fixture,
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
    let facts = CounterfactualFactsV1 {
        plan_digest: Hash::from_bytes(plan.plan_digest),
        dependency_graph_digest: Hash::from_bytes(source.graph_digest(&plan)?),
        trust_epoch: snapshot.epoch,
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
    };
    store.publish_counterfactual_facts(fork_id(), facts)?;
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
            facts,
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

/// Republish the admitted facts with `change` applied.
fn republish<B: Backend>(setup: Setup<B>, change: FactsChange) -> TestResult<Setup<B>> {
    let mut facts = setup.fixture.facts;
    change(&mut facts);
    reopen(setup, |store| {
        store.publish_counterfactual_facts(fork_id(), facts)?;
        Ok(())
    })
}

/// Configure a [`Faulty`] store from now on.
fn configure<B: Backend>(
    setup: Setup<Faulty<B>>,
    fault: StoreFault,
    interference: Interference,
) -> TestResult<Setup<Faulty<B>>> {
    reopen(setup, |store| {
        store.fault = fault;
        store.interference = interference;
        store.appends = 0;
        store.in_doubt = false;
        Ok(())
    })
}

const fn suffix_request(fixture: &Fixture) -> CounterfactualSuffixRequestV1<'_> {
    CounterfactualSuffixRequestV1 {
        plan: &fixture.plan,
        receipt: fixture.receipt,
        result_id: RESULT_ID,
        evaluator_identity_digest: EVALUATOR,
    }
}

fn run<B: Backend>(setup: &mut Setup<B>, stager: &mut Stager) -> Suffix {
    setup
        .coordinator
        .recompute_suffix(&suffix_request(&setup.fixture), stager)
}

/// Run with a stager that must not be called and expect `error`.
fn assert_rejected<B: Backend>(setup: &mut Setup<B>, error: SuffixError) {
    let mut stager = Stager::default();
    assert_eq!(run(setup, &mut stager), Err(error));
    assert!(stager.seen.is_empty());
}

fn head<B: Backend>(setup: &Setup<B>) -> TestResult<u64> {
    Ok(setup.coordinator.store().logical_head(fork_id())?.as_u64())
}

/// The uninterrupted run every retry and recovery must reproduce.
fn reference() -> TestResult<CounterfactualSuffixRunV1> {
    let mut setup = prepare::<MemoryStore>()?;
    Ok(run(&mut setup, &mut Stager::default())?)
}

fn chain(previous: &[u8; 32], trust: u64, tick: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STATE_DOMAIN);
    hasher.update(previous);
    for epoch in [trust, REVOCATION_EPOCH, ERASURE_EPOCH] {
        hasher.update(&epoch.to_be_bytes());
    }
    hasher.update(&tick.to_be_bytes());
    hasher.update(pipeline_draft_vector_digest_v1(&tick_drafts(tick)).as_bytes());
    *hasher.finalize().as_bytes()
}

/// The sealed `RCP1` of `tick` with chained `state`, whose last recomputed
/// Event is `seq`.
fn checkpoint_at(
    fixture: &Fixture,
    tick: u64,
    seq: u64,
    state: [u8; 32],
) -> TestResult<RecomputeCheckpointV1> {
    let mut checkpoint = RecomputeCheckpointV1 {
        plan_digest: fixture.plan.plan_digest,
        tick,
        seq,
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
    Ok(checkpoint)
}

/// The coordinator-owned checkpoint Event carrying `checkpoint`.
fn checkpoint_event(checkpoint: &RecomputeCheckpointV1) -> TestResult<EventDraft> {
    Ok(EventDraft::new(
        EntityId::from_ulid(fork_id().inner()),
        Kind::new(COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1),
        CanonicalBytes::from_vec(checkpoint.to_canonical_cbor()?),
    ))
}

/// The `RCP1` of every Tick from the frontier through `last`.
fn expected_checkpoints(fixture: &Fixture, last: u64) -> TestResult<Vec<RecomputeCheckpointV1>> {
    let mut state = *fixture.receipt.invalidation_digest().as_bytes();
    let mut checkpoints = Vec::new();
    for tick in FRONTIER_TICK..=last {
        state = chain(&state, fixture.plan.trust_policy.epoch, tick);
        checkpoints.push(checkpoint_at(fixture, tick, tick_seq(tick), state)?);
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

/// Assert `run` failed with `failure` at `tick` after the Ticks before it.
fn assert_run_failed_at<B: Backend>(
    setup: &Setup<B>,
    run: &CounterfactualSuffixRunV1,
    failure: Failure,
    tick: u64,
) -> TestResult {
    let checkpoints = expected_checkpoints(&setup.fixture, tick - 1)?;
    assert_eq!(run.failure, Some(failure));
    assert_eq!(decoded_checkpoints(run)?, checkpoints);
    let terminal = CounterfactualTerminalErrorV1 {
        code: failure.code(),
        tick,
        scheduler_position: 0,
        safe_digest: None,
    };
    assert_eq!(
        CounterfactualResultV1::from_canonical_cbor(&run.result)?,
        expected_result(&setup.fixture, &checkpoints, Some(terminal))?
    );
    Ok(())
}

/// Assert `run` failed with `failure` and `code` at `tick` and committed
/// nothing of it.
fn assert_failed_at<B: Backend>(
    setup: &Setup<B>,
    run: &CounterfactualSuffixRunV1,
    failure: Failure,
    code: CounterfactualTerminalErrorCodeV1,
    tick: u64,
) -> TestResult {
    assert_eq!(failure.code(), code);
    assert_run_failed_at(setup, run, failure, tick)?;
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

/// The committed `(entity, type, payload)` of every Event after the cut.
fn committed_events<B: Backend>(setup: &Setup<B>) -> TestResult<Vec<CommittedEvent>> {
    Ok(setup
        .coordinator
        .store()
        .read(fork_id(), SeqRange::from_seq(Seq::from_u64(CUT_SEQ + 1)))?
        .into_iter()
        .map(|event| {
            (
                event.entity,
                event.event_type,
                event.payload.as_slice().to_vec(),
            )
        })
        .collect())
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
    let mut expected_events = tick_drafts(FRONTIER_TICK);
    for (tick, bytes) in (FRONTIER_TICK + 1..).zip(&run.checkpoints[1..]) {
        expected_events.extend(tick_drafts(tick));
        expected_events.push(EventDraft::new(
            EntityId::from_ulid(fork_id().inner()),
            Kind::new(COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1),
            CanonicalBytes::from_vec(bytes.clone()),
        ));
    }
    let committed_drafts: Vec<_> = expected_events
        .into_iter()
        .map(|draft| {
            (
                draft.entity,
                draft.event_type,
                draft.payload.as_slice().to_vec(),
            )
        })
        .collect();
    assert_eq!(committed_events(&setup)?, committed_drafts);
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

/// One stager fault with the Tick failure and `CFR1` code it causes.
type TickFault = (Fault, Failure, CounterfactualTerminalErrorCodeV1);

const TICK_FAULTS: [TickFault; 6] = [
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
        Fault::Full,
        Failure::StagedTickRejected(PipelineContractErrorV1::BatchCountExceeded),
        CounterfactualTerminalErrorCodeV1::PluginFailure,
    ),
    // An Event type recovery could not read back is rejected while staging.
    (
        Fault::LongType,
        Failure::StagedTickRejected(PipelineContractErrorV1::FieldOutOfBounds),
        CounterfactualTerminalErrorCodeV1::PluginFailure,
    ),
    (
        Fault::Consent,
        Failure::AtomicCommitFailed,
        CounterfactualTerminalErrorCodeV1::AtomicCommitFailed,
    ),
];

/// The first suffix Tick, an intermediate Tick and the final horizon Tick.
const FAULT_TICKS: [u64; 3] = [FRONTIER_TICK + 1, FRONTIER_TICK + 2, HORIZON_TICK];

fn failed_tick_commits_nothing_and_retries_deterministically<B: Backend>() -> TestResult {
    let reference = reference()?;
    for fault_tick in FAULT_TICKS {
        for (fault, failure, code) in TICK_FAULTS {
            let mut setup = prepare::<B>()?;
            let mut attempt = Stager::failing(fault_tick, fault);
            let failed = run(&mut setup, &mut attempt)?;
            assert_eq!(attempt.ticks(), (FRONTIER_TICK + 1..=fault_tick).collect::<Vec<_>>());
            assert_failed_at(&setup, &failed, failure, code, fault_tick)?;

            // The failure is explicit and repeatable until the Tick succeeds,
            // and every retry stages the Tick from the same inputs.
            let mut retry = Stager::failing(fault_tick, fault);
            assert_eq!(run(&mut setup, &mut retry)?, failed);
            assert_eq!(retry.ticks(), vec![fault_tick]);
            assert_eq!(retry.seen.last(), attempt.seen.last());

            let mut finish = Stager::default();
            assert_eq!(run(&mut setup, &mut finish)?, reference);
            assert_eq!(finish.ticks(), (fault_tick..=HORIZON_TICK).collect::<Vec<_>>());
            assert_eq!(finish.seen.first(), attempt.seen.last());
        }
    }
    Ok(())
}
both_backends!(failed_tick_commits_nothing_and_retries_deterministically);

/// Every published fact the Tick basis binds, with the conflict it reports.
fn fact_changes() -> [FactCase; 5] {
    [
        (
            |facts| facts.plan_digest = Hash::from_bytes([0xe1; 32]),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |facts| facts.dependency_graph_digest = Hash::from_bytes([0xe2; 32]),
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
    ]
}

fn changed_facts_make_the_next_tick_stale<B: Backend>() -> TestResult {
    let reference = reference()?;
    for (change, conflict) in fact_changes() {
        let setup = prepare::<Faulty<B>>()?;
        // The facts change right before Tick 14's append, after staging it.
        let mut setup = configure(setup, StoreFault::None, Interference::Republish(3, change))?;
        let mut stager = Stager::default();
        let failed = run(&mut setup, &mut stager)?;
        assert_eq!(stager.ticks(), vec![12, 13, 14]);
        assert_failed_at(
            &setup,
            &failed,
            Failure::InvalidationConflict(conflict),
            CounterfactualTerminalErrorCodeV1::InvalidationConflict,
            14,
        )?;
        // While the facts stay changed, every retry is stale too.
        let mut stager = Stager::default();
        assert_eq!(run(&mut setup, &mut stager)?, failed);
        assert_eq!(stager.ticks(), vec![14]);

        let mut setup = republish(setup, |_| {})?;
        assert_eq!(run(&mut setup, &mut Stager::default())?, reference);
    }
    Ok(())
}
both_backends!(changed_facts_make_the_next_tick_stale);

fn another_writer_is_fenced_out<B: Backend>() -> TestResult {
    let setup = prepare::<Faulty<B>>()?;
    let mut setup = configure(setup, StoreFault::None, Interference::ForeignAppend(2))?;
    let failed = run(&mut setup, &mut Stager::default())?;
    // The foreign Event moved the Fork head, so Tick 13 committed nothing.
    assert_run_failed_at(
        &setup,
        &failed,
        Failure::InvalidationConflict(InvalidationConflictV1::LogicalHead),
        13,
    )?;
    assert_eq!(head(&setup)?, committed_head(12) + 1);
    // The foreign Event closes no Tick, so the suffix no longer recovers.
    assert_rejected(&mut setup, SuffixError::RecoveryMismatch);
    Ok(())
}
both_backends!(another_writer_is_fenced_out);

fn completed_generation_rechecks_the_persisted_basis<B: Backend>() -> TestResult {
    let reference = reference()?;
    for (change, conflict) in fact_changes() {
        let mut setup = prepare::<B>()?;
        assert_eq!(run(&mut setup, &mut Stager::default())?, reference);
        let mut setup = republish(setup, change)?;
        assert_rejected(&mut setup, SuffixError::InvalidationConflict(conflict));
        assert_eq!(head(&setup)?, committed_head(HORIZON_TICK));
        let mut setup = republish(setup, |_| {})?;
        assert_eq!(run(&mut setup, &mut Stager::default())?, reference);
    }
    Ok(())
}
both_backends!(completed_generation_rechecks_the_persisted_basis);

/// A plan edit with the declared and the incomplete replay claim.
type ClaimCase = (fn(&mut CounterfactualPlanV1), ReplayClaimV1, ReplayClaimV1);

#[test]
fn incomplete_results_weaken_only_exact_claims() -> TestResult {
    let cases: [ClaimCase; 5] = [
        (|_| {}, ReplayClaimV1::Exact, ReplayClaimV1::StructuralOnly),
        (
            |plan| plan.replay_claim = ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            ReplayClaimV1::StructuralOnly,
        ),
        (
            |plan| plan.replay_claim = ReplayClaimV1::StructuralOnly,
            ReplayClaimV1::StructuralOnly,
            ReplayClaimV1::StructuralOnly,
        ),
        (
            |plan| plan.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::UnverifiableArtifactsMissing,
            ReplayClaimV1::UnverifiableArtifactsMissing,
        ),
        (
            |plan| plan.replay_claim = ReplayClaimV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
            ReplayClaimV1::IncompatibleProfile,
        ),
    ];
    for (edit, declared, incomplete) in cases {
        let mut setup = setup_in(<MemoryStore as Backend>::open()?, edit)?;
        let failed = run(&mut setup, &mut Stager::failing(13, Fault::Error))?;
        let failed = CounterfactualResultV1::from_canonical_cbor(&failed.result)?;
        assert_eq!(failed.replay_claim, incomplete);
        let completed = run(&mut setup, &mut Stager::default())?;
        let completed = CounterfactualResultV1::from_canonical_cbor(&completed.result)?;
        assert_eq!(completed.replay_claim, declared);
    }
    Ok(())
}

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

/// Every widest honest Tick, as the first later or the last Tick.
const WIDEST_TICKS: [(Fault, u64); 4] = [
    // A widest Tick fills one batch with its checkpoint Event and pushes the
    // suffix past one recovery page.
    (Fault::Wide, FRONTIER_TICK + 1),
    (Fault::Wide, HORIZON_TICK),
    // A heaviest Tick pushes the first recovery page past its byte cap, so
    // the page is halved until it fits.
    (Fault::Heavy, FRONTIER_TICK + 1),
    // The longest accepted Event type is read back.
    (Fault::LongestType, HORIZON_TICK),
];

fn recovery_pages_through_the_widest_ticks<B: Backend>() -> TestResult {
    for (fault, wide) in WIDEST_TICKS {
        let mut setup = prepare::<B>()?;
        let completed = run(&mut setup, &mut Stager::failing(wide, fault))?;
        assert_eq!(completed.failure, None);
        if fault == Fault::Wide {
            assert!(head(&setup)? > FIRST_TICK_HEAD + MAX_PIPELINE_DRAFTS_PER_BATCH as u64);
        }
        let mut stager = Stager::default();
        assert_eq!(run(&mut setup, &mut stager)?, completed);
        assert!(stager.seen.is_empty());
    }
    Ok(())
}
both_backends!(recovery_pages_through_the_widest_ticks);

/// A foreign trailing Event's type and payload length, with the error it
/// causes.
type ForeignEvent = (String, usize, SuffixError);

/// Within the recovery read bounds a foreign trailing Event is a mismatch;
/// past them, at one byte over the page cap or the Event type bound, the
/// read fails.
fn foreign_events() -> [ForeignEvent; 4] {
    let longest = "t".repeat(MAX_FORK_EVENT_TYPE_BYTES_V1);
    let at_cap = PAGE_CAP - WORLD_TYPE.len();
    [
        (WORLD_TYPE.to_owned(), at_cap, SuffixError::RecoveryMismatch),
        (WORLD_TYPE.to_owned(), at_cap + 1, STORAGE),
        (longest.clone(), 1, SuffixError::RecoveryMismatch),
        (longest + "t", 1, STORAGE),
    ]
}

fn recovery_reads_are_bounded<B: Backend>() -> TestResult {
    for (kind, payload, expected) in foreign_events() {
        let mut setup = prepare::<B>()?;
        run(&mut setup, &mut Stager::failing(14, Fault::Error))?;
        let mut setup = reopen(setup, |store| {
            store.append(fork_id(), &[event_draft(&kind, vec![0x5b; payload])])?;
            Ok(())
        })?;
        assert_rejected(&mut setup, expected);
    }
    Ok(())
}
both_backends!(recovery_reads_are_bounded);

fn recovered_tick_past_the_horizon_is_rejected<B: Backend>() -> TestResult {
    let mut setup = prepare::<B>()?;
    assert_eq!(run(&mut setup, &mut Stager::default())?.failure, None);
    // A well-formed Tick past the horizon, with its own exact checkpoint.
    let past = HORIZON_TICK + 1;
    let checkpoint = expected_checkpoints(&setup.fixture, past)?
        .pop()
        .ok_or("no checkpoint")?;
    let mut drafts = tick_drafts(past);
    drafts.push(checkpoint_event(&checkpoint)?);
    let mut setup = reopen(setup, |store| {
        store.append(fork_id(), &drafts)?;
        Ok(())
    })?;
    assert_rejected(&mut setup, SuffixError::RecoveryMismatch);
    Ok(())
}
both_backends!(recovered_tick_past_the_horizon_is_rejected);

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
    assert_rejected(
        &mut setup,
        SuffixError::Store(CounterfactualStoreErrorV1::MixedForkGeneration),
    );

    let mut setup = prepare::<B>()?;
    let mut foreign = setup.fixture.plan.clone();
    "room.beta".clone_into(&mut foreign.room_id);
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
    let mut stager = Stager::default();
    for (plan, expected) in cases {
        let request = CounterfactualSuffixRequestV1 {
            plan: &plan,
            ..suffix_request(&setup.fixture)
        };
        let result = setup.coordinator.recompute_suffix(&request, &mut stager);
        assert_eq!(result, Err(expected));
    }
    assert!(stager.seen.is_empty());
    assert_eq!(head(&setup)?, FIRST_TICK_HEAD);
    Ok(())
}
both_backends!(stale_generation_and_foreign_plans_are_rejected);

#[test]
fn another_generations_invalidation_is_rejected() -> TestResult {
    let mut setup = prepare::<Faulty<MemoryStore>>()?;
    let earlier = setup.fixture.receipt;
    let Setup {
        coordinator,
        source,
        fixture,
    } = &mut setup;
    fixture.receipt = coordinator.admit(
        &admission_request(&fixture.plan, &fixture.profile, &fixture.snapshot),
        &Authority,
        source,
        &mut Stager::default(),
    )?;
    // The store serves generation 1's retained `SIV1` for generation 2's.
    let swapped = StoreFault::ArtifactSwapped(earlier.invalidation_digest());
    let mut setup = configure(setup, swapped, Interference::None)?;
    assert_rejected(&mut setup, SuffixError::RecoveryMismatch);
    let mut setup = configure(setup, StoreFault::None, Interference::None)?;
    assert_eq!(run(&mut setup, &mut Stager::default())?.failure, None);
    Ok(())
}

fn tampered_suffix_events_are_rejected<B: Backend>() -> TestResult {
    let forged = event_draft(COUNTERFACTUAL_CHECKPOINT_EVENT_TYPE_V1, vec![0]);
    let tampers = [
        vec![event_draft("counterfactual.world", vec![9])],
        vec![event_draft("counterfactual.world", vec![9]), forged],
    ];
    // Failing Tick 12 leaves only the first Tick, committed by admission.
    for (drafts, failing) in tampers
        .iter()
        .flat_map(|drafts| [(drafts, 12), (drafts, 14)])
    {
        let mut setup = prepare::<B>()?;
        run(&mut setup, &mut Stager::failing(failing, Fault::Error))?;
        let mut setup = reopen(setup, |store| {
            store.append(fork_id(), drafts)?;
            Ok(())
        })?;
        assert_rejected(&mut setup, SuffixError::RecoveryMismatch);
    }
    Ok(())
}
both_backends!(tampered_suffix_events_are_rejected);

fn recovered_tick_without_a_recomputed_event_is_rejected<B: Backend>() -> TestResult {
    let mut setup = prepare::<B>()?;
    run(&mut setup, &mut Stager::failing(14, Fault::Error))?;
    // An intermediate Tick 14 of only an exact checkpoint Event, then a
    // last Tick 15 whose checkpoint chains on it exactly.
    let empty_state = [0x5a; 32];
    let empty_seq = committed_head(13);
    let empty = checkpoint_at(&setup.fixture, 14, empty_seq, empty_state)?;
    let last_seq = empty_seq + 3;
    let state = chain(&empty_state, setup.fixture.plan.trust_policy.epoch, 15);
    let last = checkpoint_at(&setup.fixture, 15, last_seq, state)?;
    let mut drafts = vec![checkpoint_event(&empty)?];
    drafts.extend(tick_drafts(15));
    drafts.push(checkpoint_event(&last)?);
    let mut setup = reopen(setup, |store| {
        store.append(fork_id(), &drafts)?;
        Ok(())
    })?;
    assert_eq!(head(&setup)?, last_seq + 1);
    assert_rejected(&mut setup, SuffixError::RecoveryMismatch);
    Ok(())
}
both_backends!(recovered_tick_without_a_recomputed_event_is_rejected);

fn unknown_tick_outcomes_are_resolved_from_the_basis<B: Backend>() -> TestResult {
    let reference = reference()?;
    // Tick 13 did not commit and the basis proves it: a retryable failure.
    let setup = prepare::<Faulty<B>>()?;
    let mut setup = configure(setup, StoreFault::None, Interference::LostUnknown(2))?;
    let failed = run(&mut setup, &mut Stager::default())?;
    assert_failed_at(
        &setup,
        &failed,
        Failure::AtomicCommitFailed,
        CounterfactualTerminalErrorCodeV1::AtomicCommitFailed,
        13,
    )?;
    assert_eq!(run(&mut setup, &mut Stager::default())?, reference);

    // Tick 13 committed: no result is sealed, and the next call recovers it.
    let setup = prepare::<Faulty<B>>()?;
    let mut setup = configure(setup, StoreFault::None, Interference::LandedUnknown(2))?;
    let mut stager = Stager::default();
    assert_eq!(
        run(&mut setup, &mut stager),
        Err(SuffixError::TickOutcomeUnknown)
    );
    assert_eq!(stager.ticks(), vec![12, 13]);
    assert_eq!(head(&setup)?, committed_head(13));
    let mut stager = Stager::default();
    assert_eq!(run(&mut setup, &mut stager)?, reference);
    assert_eq!(stager.ticks(), (14..=HORIZON_TICK).collect::<Vec<_>>());

    // The recovery read fails, so the outcome stays unknown.
    let setup = prepare::<Faulty<B>>()?;
    let mut setup = configure(setup, StoreFault::None, Interference::UnreadableUnknown(2))?;
    assert_eq!(
        run(&mut setup, &mut Stager::default()),
        Err(SuffixError::TickOutcomeUnknown)
    );
    assert_eq!(head(&setup)?, committed_head(12));
    let mut setup = configure(setup, StoreFault::None, Interference::None)?;
    assert_eq!(run(&mut setup, &mut Stager::default())?, reference);
    Ok(())
}
both_backends!(unknown_tick_outcomes_are_resolved_from_the_basis);

fn misreported_committed_head_is_rejected<B: Backend>() -> TestResult {
    let reference = reference()?;
    let setup = prepare::<Faulty<B>>()?;
    let mut setup = configure(setup, StoreFault::None, Interference::MisreportedHead(2))?;
    assert_eq!(
        run(&mut setup, &mut Stager::default()),
        Err(SuffixError::CommittedHeadMismatch)
    );
    // Tick 13 did commit; the next call recovers it from the Event Store.
    assert_eq!(head(&setup)?, committed_head(13));
    let mut stager = Stager::default();
    assert_eq!(run(&mut setup, &mut stager)?, reference);
    assert_eq!(stager.ticks(), (14..=HORIZON_TICK).collect::<Vec<_>>());
    Ok(())
}
both_backends!(misreported_committed_head_is_rejected);

#[test]
fn zero_result_identities_are_rejected_before_staging() -> TestResult {
    let mut setup = prepare::<MemoryStore>()?;
    let cases = [
        CounterfactualSuffixRequestV1 {
            result_id: [0; 16],
            ..suffix_request(&setup.fixture)
        },
        CounterfactualSuffixRequestV1 {
            evaluator_identity_digest: [0; 32],
            ..suffix_request(&setup.fixture)
        },
    ];
    let mut stager = Stager::default();
    for request in cases {
        assert_eq!(
            setup.coordinator.recompute_suffix(&request, &mut stager),
            Err(SuffixError::InvalidResultIdentity)
        );
    }
    assert!(stager.seen.is_empty());
    assert_eq!(head(&setup)?, FIRST_TICK_HEAD);
    Ok(())
}

/// A store fault with the error recovery reports for it.
type FaultCase = (StoreFault, SuffixError);

const STORAGE: SuffixError = SuffixError::Store(CounterfactualStoreErrorV1::StorageFailure);

/// Faults while only the first Tick is committed.
const FIRST_TICK_FAULTS: [FaultCase; 6] = [
    (
        StoreFault::Basis,
        SuffixError::Store(CounterfactualStoreErrorV1::CorruptState),
    ),
    (StoreFault::ArtifactError, STORAGE),
    (StoreFault::ArtifactMissing, SuffixError::RecoveryMismatch),
    (StoreFault::ArtifactGarbage, SuffixError::RecoveryMismatch),
    (StoreFault::ReadFailsFrom(CUT_SEQ + 1), STORAGE),
    // The first Tick's exact Event range is bound.
    (
        StoreFault::Dropped(CUT_SEQ + 1),
        SuffixError::RecoveryMismatch,
    ),
];

/// Faults once Ticks 12 through 14 are committed.
const LATER_TICK_FAULTS: [FaultCase; 6] = [
    (StoreFault::ReadFailsFrom(FIRST_TICK_HEAD + 1), STORAGE),
    (
        StoreFault::Dropped(tick_seq(13)),
        SuffixError::RecoveryMismatch,
    ),
    // Tick 13's checkpoint is decoded and must be exactly its own `RCP1`.
    (
        StoreFault::Altered(committed_head(13)),
        SuffixError::RecoveryMismatch,
    ),
    // Tick 12's re-derived `RCP1` binds the first Tick's content.
    (
        StoreFault::Altered(FIRST_TICK_HEAD),
        SuffixError::RecoveryMismatch,
    ),
    // ...and its own content.
    (
        StoreFault::Altered(tick_seq(12)),
        SuffixError::RecoveryMismatch,
    ),
    // The last Tick's re-derived `RCP1` binds its content.
    (
        StoreFault::Altered(tick_seq(14)),
        SuffixError::RecoveryMismatch,
    ),
];

#[test]
fn store_read_faults_are_closed() -> TestResult {
    for (fault, expected) in FIRST_TICK_FAULTS {
        let setup = prepare::<Faulty<MemoryStore>>()?;
        let mut setup = configure(setup, fault, Interference::None)?;
        assert_rejected(&mut setup, expected);
    }
    for (fault, expected) in LATER_TICK_FAULTS {
        let mut setup = prepare::<Faulty<MemoryStore>>()?;
        run(&mut setup, &mut Stager::failing(15, Fault::Error))?;
        let mut setup = configure(setup, fault, Interference::None)?;
        assert_rejected(&mut setup, expected);
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
    assert_rejected(&mut beyond, SuffixError::SuffixTooLong);
    Ok(())
}

#[test]
fn every_error_has_a_distinct_safe_message() {
    let errors = [
        SuffixError::Plan(CounterfactualPlanContractErrorV1::DigestMismatch),
        SuffixError::SuffixTooLong,
        SuffixError::PlanMismatch,
        SuffixError::RecoveryMismatch,
        SuffixError::InvalidationConflict(InvalidationConflictV1::TrustEpoch),
        SuffixError::ArtifactEncoding,
        STORAGE,
        SuffixError::InvalidResultIdentity,
        SuffixError::TickOutcomeUnknown,
        SuffixError::CommittedHeadMismatch,
    ];
    let messages: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    assert!(messages.iter().all(|message| !message.is_empty()));
    let with_source = [0, 6];
    for (position, error) in errors.iter().enumerate() {
        assert_eq!(error.source().is_some(), with_source.contains(&position));
    }
}
