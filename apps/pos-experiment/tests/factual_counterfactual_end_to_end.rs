#![cfg(target_os = "linux")]
//! ADR-064 Revision 3, slice 12 (Redmine #608): a factual history run through
//! the registry becomes a recorded-prefix counterfactual, end to end, on
//! `MemoryStore` and `SQLite`.
//!
//! The factual history commits real Ticks, with a verified-prefix Driver, one
//! empty pass and one resume. A Fork runtime is restored at the head and at
//! an earlier Tick Boundary, and the Fork is cut there. Generation 1 is
//! admitted through the composite `PrefixSeededFrontierSourceV1`, whose
//! provisional graph a test-only stager also declares Tick by Tick.
//! `recompute_suffix` records the rest of the suffix, and
//! generation 2 is admitted through `RecordedFrontierSourceV1`, which must
//! derive the same graph digest from the store alone. The frontier is derived
//! by `pos-time`; this file builds no `OwnerFrontierV1`.

use std::cmp::Ordering as Order;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyV1,
};
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
use pos_core::factual_dependency::BoundFactualNodeV1;
use pos_core::{
    factual_artifact_digest, factual_classification_bundle_digest, factual_event_schema_id,
    fork_ancestry, ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, CanonicalBytes, Capability, CoreError,
    CounterfactualBasisV1, CounterfactualDependencyReadPortV1,
    CounterfactualDependencyRecordingPortV1, CounterfactualFactsV1,
    CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1 as StoreError,
    CounterfactualStorePortV1, CounterfactualTickOutcomeV1, DependencyEdgeRecordV1,
    DependencyNodeCoordinateV1, DependencyNodeRecordV1, DependencyPageRequestV1, DependencyPageV1,
    EntityId, ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureReferenceV1,
    ErasureReplayClaimV1, Event, EventDraft, EventReadBounds, EventStore, FactualCutV1,
    FactualHeadV1, FactualHostOwnerV1, FactualNodeKeyV1, FactualOwnerIdV1, FactualPrefixReadPortV1,
    ForkGenerationV1, Hash, Kind, PipelineDraftBatchV1, Plugin, PluginId,
    RecordedDependencyClassV1, RecordedNodeOriginV1, RecordedSetCountsV1, RegisteredArtifactV1,
    ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, Seq, SeqRange, TickDependencyRecordV1,
    Timeline, TimelineId, TimelineMeta, FACTUAL_HISTORY_SCHEMA_ID_V1, FACTUAL_PREFIX_SCHEMA_ID_V1,
    FACTUAL_STEP_SCHEMA_ID_V1,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionRequestV1, CounterfactualCoordinatorV1,
    CounterfactualDeclaringTickStagerV1, CounterfactualForkAppendAuthorityV1,
    CounterfactualFrontierDerivationV1, CounterfactualFrontierSourceV1,
    CounterfactualFrozenArtifactsV1, CounterfactualHostPreflightV1,
    CounterfactualInterventionAuthorityV1, CounterfactualStagedTickV1, CounterfactualTickFailureV1,
    CounterfactualTickInputsV1, FrozenArtifactAvailabilityV1, InterventionDecisionV1,
};
use pos_runtime::counterfactual::suffix::CounterfactualSuffixRequestV1;
use pos_runtime::{
    Driver, LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, RuntimeError,
    ScheduledAdmissionStoreV1, StepOutput, TimelineHistorySegment,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;
use pos_time::counterfactual::dependency_graph::{
    DependencyGraphBoundsV1 as Bounds, DependencyGraphNodeOriginV1 as Origin,
    DependencyGraphNodeV1 as Node, ValidatedDependencyGraphV1,
};
use pos_time::counterfactual::frontier_source::RecordedFrontierSourceV1;
use pos_time::counterfactual::prefix_seeded_source::PrefixSeededFrontierSourceV1;
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Declaration = (Vec<DependencyNodeRecordV1>, Vec<DependencyEdgeRecordV1>);
/// Per owner: the earliest Tick, scheduler position, output ordinal, and the
/// cause digests of its owner frontier.
type OwnerFrontiers = BTreeMap<String, (u64, u32, u32, Vec<[u8; 32]>)>;

const ALPHA_EVENT: &str = "agent.e2e.alpha";
const BETA_EVENT: &str = "agent.e2e.beta";
const GAMMA_EVENT: &str = "agent.e2e.gamma";
const INPUT_EVENT: &str = "agent.e2e.input";
const INTERVENTION_OWNER: &str = "intervention";
const HISTORY_OWNER: &str = FactualHostOwnerV1::History.as_str();
const PREFIX_OWNER: &str = FactualHostOwnerV1::Prefix.as_str();
const INGRESS_OWNER: &str = FactualHostOwnerV1::Ingress.as_str();

const BOUNDS: Bounds = Bounds {
    max_nodes: 5_000,
    max_edges: 5_000,
};
const ROOM_ID: &str = "room.alpha";
const ROOM_DIGEST: [u8; 32] = [2; 32];
const COMPOSITION_DIGEST: [u8; 32] = [6; 32];
const CONSENT_DECISION: [u8; 32] = [4; 32];
const INTERVENTION_PROVENANCE: [u8; 32] = [6; 32];
const ENDOGENOUS_AUTHORIZATION: [u8; 32] = [0x72; 32];
const NODE_PROVENANCE: [u8; 32] = [0x71; 32];
const EDGE_PROVENANCE: [u8; 32] = [0x73; 32];
const NODE_CONTENT: Hash = Hash::from_bytes([0x5a; 32]);
const REVOCATION_EPOCH: u64 = 7;
const ERASURE_EPOCH: u64 = 8;
const FRONTIER_ID: [u8; 16] = [0x81; 16];
const INVALIDATION_ID: [u8; 16] = [0x91; 16];
const PROVENANCE: [u8; 32] = [0x82; 32];
const RESULT_ID: [u8; 16] = [0xa1; 16];
const EVALUATOR: [u8; 32] = [0xa2; 32];
/// Recomputation Ticks after the first one, up to the plan horizon.
const HORIZON_SPAN: u64 = 2;

// ---------------------------------------------------------------------------
// The registry and its Drivers
// ---------------------------------------------------------------------------

/// One Driver of the factual history and the Plugin that owns its Event type.
struct Spec {
    plugin: u128,
    name: &'static str,
    event_type: &'static str,
    subscriptions: &'static [&'static str],
    verified_prefix: bool,
}

/// The Drivers in schedule order: `alpha` reads the external input, `beta`
/// reads `alpha`, and `gamma` reads the verified prefix. None subscribes to a
/// Projection.
const SPECS: [Spec; 3] = [
    Spec {
        plugin: 0x6101,
        name: "alpha",
        event_type: ALPHA_EVENT,
        subscriptions: &[INPUT_EVENT],
        verified_prefix: false,
    },
    Spec {
        plugin: 0x6102,
        name: "beta",
        event_type: BETA_EVENT,
        subscriptions: &[ALPHA_EVENT],
        verified_prefix: false,
    },
    Spec {
        plugin: 0x6103,
        name: "gamma",
        event_type: GAMMA_EVENT,
        subscriptions: &[],
        verified_prefix: true,
    },
];

struct E2ePlugin {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
}

impl Plugin for E2ePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// A Driver that emits one draft of its Event type while `emit` is set.
struct E2eDriver {
    name: &'static str,
    event_type: &'static str,
    subscriptions: Vec<Kind>,
    verified_prefix: bool,
    emit: Arc<AtomicBool>,
}

impl Driver for E2eDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn event_subscriptions(&self) -> &[Kind] {
        &self.subscriptions
    }

    fn requires_verified_event_prefix(&self) -> bool {
        self.verified_prefix
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        let drafts = if self.emit.load(Ordering::SeqCst) {
            vec![EventDraft::new(
                EntityId::from_ulid(Ulid::from(7_u128)),
                Kind::new(self.event_type),
                CanonicalBytes::from_static(b"e2e"),
            )]
        } else {
            Vec::new()
        };
        Ok(StepOutput::new(drafts))
    }
}

/// The shared erasure gate and the switch that makes the Drivers emit.
struct Setup {
    gate: Arc<ErasureContainmentGateV1>,
    emit: Arc<AtomicBool>,
}

impl Setup {
    fn new() -> Self {
        Self {
            gate: Arc::new(ErasureContainmentGateV1::new_test_open()),
            emit: Arc::new(AtomicBool::new(true)),
        }
    }

    /// A registry of the same Drivers under the same Plugin IDs, so every
    /// registry derives the same owner IDs.
    fn registry(&self) -> TestResult<PluginRegistry> {
        let gate: Arc<ErasureContainmentGateV1> = Arc::clone(&self.gate);
        let mut registry = PluginRegistry::new().with_erasure_gate(gate);
        for spec in &SPECS {
            let plugin = E2ePlugin {
                id: PluginId::from_ulid(Ulid::from(spec.plugin)),
                name: spec.name,
                event_type: spec.event_type,
            };
            let driver = E2eDriver {
                name: spec.name,
                event_type: spec.event_type,
                subscriptions: spec.subscriptions.iter().copied().map(Kind::new).collect(),
                verified_prefix: spec.verified_prefix,
                emit: Arc::clone(&self.emit),
            };
            registry.register_generated(&plugin, None, Some(Box::new(driver)))?;
        }
        registry.compose_non_participant_drivers()?;
        Ok(registry)
    }
}

// ---------------------------------------------------------------------------
// The store adapters
// ---------------------------------------------------------------------------

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

impl<B: FactualPrefixReadPortV1> FactualPrefixReadPortV1 for Shared<B> {
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<FactualHeadV1, CoreError> {
        self.lock().last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(&self, timeline: TimelineId, seq: Seq) -> Result<FactualCutV1, CoreError> {
        self.lock().cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        self.lock().nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<BoundFactualNodeV1>>, CoreError> {
        self.lock().nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        self.lock().last_step_node(timeline, owner)
    }

    fn factual_set_counts(&self, timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        self.lock().factual_set_counts(timeline)
    }
}

/// A store adapter that commits scheduled passes with their factual records,
/// records and reads counterfactual generations, and serves the factual
/// prefix.
trait Backend:
    ScheduledAdmissionStoreV1
    + CounterfactualStorePortV1
    + CounterfactualDependencyRecordingPortV1
    + CounterfactualDependencyReadPortV1
    + FactualPrefixReadPortV1
    + Sized
{
    fn open(gate: &Arc<ErasureContainmentGateV1>) -> TestResult<Self>;
}

impl Backend for MemoryStore {
    fn open(gate: &Arc<ErasureContainmentGateV1>) -> TestResult<Self> {
        let mut store = Self::new();
        store.bind_erasure_gate(Arc::clone(gate))?;
        Ok(store)
    }
}

impl Backend for SqliteStore {
    fn open(gate: &Arc<ErasureContainmentGateV1>) -> TestResult<Self> {
        let mut store = Self::open_in_memory()?;
        store.bind_erasure_gate(Arc::clone(gate))?;
        Ok(store)
    }
}

// ---------------------------------------------------------------------------
// The factual history
// ---------------------------------------------------------------------------

/// Where the factual history can be cut.
#[derive(Clone, Copy)]
enum CutChoice {
    /// The last recorded Tick.
    Head,
    /// The first Tick recorded after the resume, one Tick before the head.
    Boundary,
}

/// The factual Timeline and the heads its passes left.
struct History {
    root: TimelineId,
    head: FactualHeadV1,
    boundary: FactualHeadV1,
    resumed_tick: u64,
}

impl History {
    const fn cut(&self, choice: CutChoice) -> FactualHeadV1 {
        match choice {
            CutChoice::Head => self.head,
            CutChoice::Boundary => self.boundary,
        }
    }
}

fn append_input<B: Backend>(store: &mut B, timeline: TimelineId) -> TestResult {
    let draft = EventDraft::new(
        EntityId::from_ulid(Ulid::from(20_u128)),
        Kind::new(INPUT_EVENT),
        CanonicalBytes::from_static(b"input"),
    );
    store.append(timeline, &[draft])?;
    Ok(())
}

/// Step every Driver against the committed prefix and admit the pass the way
/// the experiment session does: an empty pass commits no Tick.
fn run_pass<B: Backend>(
    store: &mut B,
    registry: &mut PluginRegistry,
    timeline: TimelineId,
) -> TestResult<FactualHeadV1> {
    let host = LocalScheduledAdmissionHostV1::shared()?;
    let revisions = host.observe(registry, store, timeline)?;
    let events = store.read(timeline, SeqRange::all())?;
    let ancestry = fork_ancestry(&*store, timeline)?;
    let through = store.logical_head(timeline)?;
    let drafts = registry.step_all_anchored_with_events(timeline, &ancestry, through, &events)?;
    if drafts.is_empty() {
        registry.commit_step_at(through, 0)?;
    } else {
        let head = store.logical_head(timeline)?;
        host.admit(registry, store, revisions, head, 0)?;
    }
    Ok(store.last_committed_factual_tick(timeline)?)
}

/// Restore `registry` over the Timeline through `through`.
fn restore<S: EventStore>(
    store: &S,
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    through: Seq,
) -> TestResult {
    let range = SeqRange::bounded(Seq::from_u64(1), through);
    let events = store.read(timeline, range)?;
    let segment = TimelineHistorySegment::new(timeline, through);
    registry.restore_driver_state(&[segment], &events)?;
    Ok(())
}

/// Run the factual history: two Ticks, one empty pass, a Tick that declares
/// what the empty pass consumed, a resume on a fresh registry, and two Ticks
/// after it. The first Tick after the resume records the history node.
fn factual_history<B: Backend>(store: &mut B, setup: &Setup) -> TestResult<History> {
    let root = store.create_timeline("factual")?.id();
    let mut registry = setup.registry()?;
    append_input(store, root)?;
    append_input(store, root)?;
    let first = run_pass(store, &mut registry, root)?;
    let second = run_pass(store, &mut registry, root)?;
    append_input(store, root)?;
    setup.emit.store(false, Ordering::SeqCst);
    let empty = run_pass(store, &mut registry, root)?;
    setup.emit.store(true, Ordering::SeqCst);
    let carried = run_pass(store, &mut registry, root)?;
    assert_eq!(empty, second);
    assert_eq!((first.tick, second.tick, carried.tick), (1, 2, 3));

    let mut resumed = setup.registry()?;
    restore(&*store, &mut resumed, root, store.logical_head(root)?)?;
    let boundary = run_pass(store, &mut resumed, root)?;
    let head = run_pass(store, &mut resumed, root)?;
    assert_eq!((boundary.tick, head.tick), (4, 5));
    Ok(History {
        root,
        head,
        boundary,
        resumed_tick: boundary.tick,
    })
}

/// The Fork runtime: a registry restored over the parent prefix through the
/// cut, handed the Fork it created at that cut.
struct ForkRuntime {
    fork: TimelineId,
    owners: Vec<FactualOwnerIdV1>,
}

fn fork_runtime<B: Backend>(
    store: &mut B,
    setup: &Setup,
    history: &History,
    cut: FactualHeadV1,
) -> TestResult<ForkRuntime> {
    let mut runtime = setup.registry()?;
    restore(&*store, &mut runtime, history.root, cut.last_seq)?;
    let fork = runtime.fork_restored_timeline(store, history.root, cut.last_seq, "fork")?;
    let cut_tick = FactualCutV1::Boundary { cut_tick: cut.tick };
    assert_eq!(store.cut_tick_at(history.root, cut.last_seq)?, cut_tick);
    let owners = runtime
        .factual_owner_ids()
        .into_iter()
        .map(|(_, owner)| owner)
        .collect();
    Ok(ForkRuntime {
        fork: fork.id(),
        owners,
    })
}

// ---------------------------------------------------------------------------
// The provisional graph
// ---------------------------------------------------------------------------

/// What the Fork reads of the recorded prefix at its cut.
struct Prefix {
    steps: Vec<DependencyNodeRecordV1>,
    forwarded: Vec<DependencyNodeRecordV1>,
}

/// The latest step node of every owner, and the nodes of the Events of the
/// cut Tick, which the Drivers of the first provisional Tick are forwarded.
fn resolve_prefix<S: FactualPrefixReadPortV1>(
    store: &S,
    runtime: &ForkRuntime,
    cut: FactualHeadV1,
) -> TestResult<Prefix> {
    let mut steps = Vec::new();
    for owner in &runtime.owners {
        let step = store.last_step_node(runtime.fork, owner)?;
        steps.push(step.ok_or("an owner has no recorded step node")?);
    }
    let last = cut.last_seq.as_u64();
    let seqs: Vec<Seq> = (last - 2..=last).map(Seq::from_u64).collect();
    let nodes = store.nodes_for_committed_events(runtime.fork, &seqs)?;
    let forwarded = nodes.into_iter().collect::<Option<Vec<_>>>();
    Ok(Prefix {
        steps,
        forwarded: forwarded.ok_or("an Event of the cut Tick has no node")?,
    })
}

/// A node a provisional node can consume.
#[derive(Clone)]
struct Source {
    node: DependencyNodeV1,
    class: DependencyClassV1,
}

impl Source {
    const fn digest(&self) -> [u8; 32] {
        self.node.artifact_digest
    }
}

const fn dependency_class(class: RecordedDependencyClassV1) -> DependencyClassV1 {
    match class {
        RecordedDependencyClassV1::ExogenousFrozen => DependencyClassV1::ExogenousFrozen,
        RecordedDependencyClassV1::InterventionAssigned => DependencyClassV1::InterventionAssigned,
        RecordedDependencyClassV1::EndogenousRecomputed => DependencyClassV1::EndogenousRecomputed,
        RecordedDependencyClassV1::FixedPolicy => DependencyClassV1::FixedPolicy,
        RecordedDependencyClassV1::PresentationOnly => DependencyClassV1::PresentationOnly,
    }
}

const fn recorded_class(class: DependencyClassV1) -> RecordedDependencyClassV1 {
    match class {
        DependencyClassV1::ExogenousFrozen => RecordedDependencyClassV1::ExogenousFrozen,
        DependencyClassV1::InterventionAssigned => RecordedDependencyClassV1::InterventionAssigned,
        DependencyClassV1::EndogenousRecomputed => RecordedDependencyClassV1::EndogenousRecomputed,
        DependencyClassV1::FixedPolicy => RecordedDependencyClassV1::FixedPolicy,
        DependencyClassV1::PresentationOnly => RecordedDependencyClassV1::PresentationOnly,
    }
}

/// The source a recorded node row stands for.
fn committed_source(record: &DependencyNodeRecordV1) -> Source {
    let coordinate = record.coordinate();
    Source {
        node: DependencyNodeV1 {
            tick: coordinate.tick(),
            scheduler_position: coordinate.scheduler_position(),
            owner_id: coordinate.owner_id().to_owned(),
            output_ordinal: coordinate.output_ordinal(),
            schema_id: coordinate.schema_id(),
            artifact_digest: *coordinate.artifact_digest().as_bytes(),
        },
        class: dependency_class(record.class()),
    }
}

const fn authorization_for(class: DependencyClassV1) -> [u8; 32] {
    match class {
        DependencyClassV1::InterventionAssigned => CONSENT_DECISION,
        _ => ENDOGENOUS_AUTHORIZATION,
    }
}

fn edge(consumer: &DependencyNodeV1, source: &Source) -> InputDependencyV1 {
    InputDependencyV1 {
        consumer: consumer.clone(),
        source: source.node.clone(),
        dependency_class: source.class,
        tick_range: DependencyTickRangeV1 {
            first_tick: source.node.tick,
            last_tick: consumer.tick,
        },
        authorization_digest: authorization_for(source.class),
        classification_rule: DependencyClassificationRuleV1 {
            rule_id: "classify.v1".to_owned(),
            rule_version: 1,
        },
        provenance_digest: EDGE_PROVENANCE,
    }
}

fn node_order(left: &Node, right: &Node) -> Order {
    let (left, right) = (left.node.coordinate_key(), right.node.coordinate_key());
    left.cmp(&right)
}

/// The nodes and edges of the provisional generation.
#[derive(Default)]
struct Graph {
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
}

impl Graph {
    /// Declare an `EndogenousRecomputed` node of `fork` consuming `inputs`.
    fn endogenous(
        &mut self,
        fork: TimelineId,
        key: FactualNodeKeyV1<'_>,
        inputs: &[Source],
    ) -> Source {
        let node = DependencyNodeV1 {
            tick: key.tick,
            scheduler_position: key.scheduler_position,
            owner_id: key.owner.to_owned(),
            output_ordinal: key.output_ordinal,
            schema_id: key.schema_id,
            artifact_digest: *factual_artifact_digest(fork, key, NODE_CONTENT).as_bytes(),
        };
        let unique: BTreeMap<[u8; 32], &Source> = inputs
            .iter()
            .map(|source| (source.digest(), source))
            .collect();
        self.edges
            .extend(unique.values().map(|source| edge(&node, source)));
        self.nodes.push(Node {
            node: node.clone(),
            class: DependencyClassV1::EndogenousRecomputed,
            origin: Origin::Provisional,
            input_digests: unique.keys().copied().collect(),
            provenance_digest: NODE_PROVENANCE,
        });
        Source {
            node,
            class: DependencyClassV1::EndogenousRecomputed,
        }
    }

    /// Declare the `InterventionAssigned` root of `intervention`.
    fn intervention(&mut self, intervention: &InterventionV1) -> TestResult<Source> {
        let node = DependencyNodeV1 {
            tick: intervention.effective_tick,
            scheduler_position: 0,
            owner_id: INTERVENTION_OWNER.to_owned(),
            output_ordinal: 0,
            schema_id: intervention.target_schema_id,
            artifact_digest: intervention.digest()?,
        };
        self.nodes.push(Node {
            node: node.clone(),
            class: DependencyClassV1::InterventionAssigned,
            origin: Origin::Provisional,
            input_digests: Vec::new(),
            provenance_digest: intervention.provenance_digest,
        });
        Ok(Source {
            node,
            class: DependencyClassV1::InterventionAssigned,
        })
    }

    /// Put the nodes and edges in the canonical order of the contract.
    fn canonical(mut self) -> Self {
        self.nodes.sort_by(node_order);
        self.edges.sort_by(InputDependencyV1::order_cmp);
        self
    }

    fn digest_at(&self, tick: u64, position: u32, ordinal: u32) -> TestResult<[u8; 32]> {
        let found = self.nodes.iter().find(|candidate| {
            let node = &candidate.node;
            (node.tick, node.scheduler_position, node.output_ordinal) == (tick, position, ordinal)
        });
        found
            .map(|candidate| candidate.node.artifact_digest)
            .ok_or_else(|| "no node at the coordinate".into())
    }
}

/// One Driver of the provisional generation.
struct Lane {
    owner: String,
    position: u32,
    event_type: &'static str,
}

fn build_lanes(runtime: &ForkRuntime, prefix: &Prefix) -> Vec<Lane> {
    let pairs = runtime.owners.iter().zip(&prefix.steps);
    pairs
        .zip(&SPECS)
        .map(|((owner, step), spec)| Lane {
            owner: owner.as_str().to_owned(),
            position: step.coordinate().scheduler_position(),
            event_type: spec.event_type,
        })
        .collect()
}

/// The nodes one provisional Tick declares, and what the next Tick consumes.
struct Carry {
    steps: Vec<Source>,
    outputs: Vec<Source>,
}

/// What the Drivers of one provisional Tick are given.
struct TickInputs<'a> {
    tick: u64,
    forwarded: &'a [Source],
    seed: &'a [Source],
}

/// Declare a step node per Driver at `(t, p, owner, 0)` and one output node
/// per draft at `(t, p, owner, 1)`. A step node consumes the owner's previous
/// step node, the forwarded Events, and every previous provisional output; an
/// output node consumes its step node and, for the first Driver, the seed.
fn provisional_tick(
    graph: &mut Graph,
    fork: TimelineId,
    lanes: &[Lane],
    carry: &Carry,
    given: &TickInputs<'_>,
) -> Carry {
    let mut next = Carry {
        steps: Vec::new(),
        outputs: Vec::new(),
    };
    for (index, lane) in lanes.iter().enumerate() {
        let key = FactualNodeKeyV1 {
            tick: given.tick,
            scheduler_position: lane.position,
            owner: &lane.owner,
            output_ordinal: 0,
            schema_id: FACTUAL_STEP_SCHEMA_ID_V1,
        };
        let mut consumed = vec![carry.steps[index].clone()];
        consumed.extend_from_slice(given.forwarded);
        consumed.extend_from_slice(&carry.outputs);
        let step = graph.endogenous(fork, key, &consumed);
        let mut consumed = vec![step.clone()];
        if index == 0 {
            consumed.extend_from_slice(given.seed);
        }
        let key = FactualNodeKeyV1 {
            output_ordinal: 1,
            schema_id: factual_event_schema_id(lane.event_type),
            ..key
        };
        next.outputs.push(graph.endogenous(fork, key, &consumed));
        next.steps.push(step);
    }
    next
}

/// The provisional graph of every Tick from the first through the horizon.
fn provisional_graph(
    fork: TimelineId,
    lanes: &[Lane],
    prefix: &Prefix,
    plan: &CounterfactualPlanV1,
) -> TestResult<Graph> {
    let mut graph = Graph::default();
    let seed = vec![graph.intervention(&plan.interventions[0])?];
    let forwarded: Vec<Source> = prefix.forwarded.iter().map(committed_source).collect();
    let mut carry = Carry {
        steps: prefix.steps.iter().map(committed_source).collect(),
        outputs: Vec::new(),
    };
    for tick in plan.first_tick..=plan.horizon_tick {
        let first = tick == plan.first_tick;
        let given = TickInputs {
            tick,
            forwarded: if first { forwarded.as_slice() } else { &[] },
            seed: if first { seed.as_slice() } else { &[] },
        };
        carry = provisional_tick(&mut graph, fork, lanes, &carry, &given);
    }
    Ok(graph.canonical())
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

fn node_record(node: &Node) -> TestResult<DependencyNodeRecordV1> {
    Ok(DependencyNodeRecordV1::try_new(
        coordinate(&node.node)?,
        recorded_class(node.class),
        RecordedNodeOriginV1::Provisional,
        node.input_digests
            .iter()
            .copied()
            .map(Hash::from_bytes)
            .collect(),
        Hash::from_bytes(node.provenance_digest),
    )?)
}

fn edge_record(edge: &InputDependencyV1) -> TestResult<DependencyEdgeRecordV1> {
    Ok(DependencyEdgeRecordV1::try_from_canonical(
        edge.to_canonical_cbor()?,
        coordinate(&edge.consumer)?,
        Hash::from_bytes(edge.source.artifact_digest),
    )?)
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

/// The declaration of every record Tick: each node rides the record of its
/// own Tick, the Intervention root included because it is effective at the
/// first Tick, and every edge rides its consumer's record.
fn declarations(graph: &Graph) -> TestResult<BTreeMap<u64, Declaration>> {
    let mut by_tick: BTreeMap<u64, Declaration> = BTreeMap::new();
    let mut record_ticks: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for node in &graph.nodes {
        let tick = node.node.tick;
        by_tick.entry(tick).or_default().0.push(node_record(node)?);
        record_ticks.insert(node.node.artifact_digest, tick);
    }
    for edge in &graph.edges {
        let consumer = &edge.consumer.artifact_digest;
        let tick = record_ticks
            .get(consumer)
            .ok_or("edge consumer is not a node")?;
        by_tick.entry(*tick).or_default().1.push(edge_record(edge)?);
    }
    for declaration in by_tick.values_mut() {
        sort_declaration(declaration);
    }
    Ok(by_tick)
}

/// The test-only stager: it stages one draft per Driver for every Tick and
/// declares the nodes and edges the provisional graph assigns to the Tick.
struct ProvisionalTickStager {
    declarations: BTreeMap<u64, Declaration>,
    event_types: Vec<&'static str>,
}

impl CounterfactualDeclaringTickStagerV1 for ProvisionalTickStager {
    fn stage_tick_with_dependencies(
        &mut self,
        inputs: &CounterfactualTickInputsV1<'_>,
    ) -> Result<CounterfactualStagedTickV1, CounterfactualTickFailureV1> {
        let tick = inputs.tick();
        let (nodes, edges) = self.declarations.get(&tick).cloned().unwrap_or_default();
        let drafts = self
            .event_types
            .iter()
            .copied()
            .map(|event_type| {
                let payload = tick.to_be_bytes().to_vec();
                let entity = EntityId::from_ulid(Ulid::from(9_u128));
                EventDraft::new(
                    entity,
                    Kind::new(event_type),
                    CanonicalBytes::from_vec(payload),
                )
            })
            .collect();
        Ok(CounterfactualStagedTickV1 {
            drafts,
            nodes,
            edges,
        })
    }
}

// ---------------------------------------------------------------------------
// Plan and host records
// ---------------------------------------------------------------------------

/// The Intervention that assigns the output of the first Driver at `tick`.
fn intervention(tick: u64) -> InterventionV1 {
    InterventionV1 {
        intervention_id: [1; 16],
        target_schema_id: factual_event_schema_id(ALPHA_EVENT),
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: [2; 32],
        effective_tick: tick,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        consent_decision_digest: CONSENT_DECISION,
        rationale: "what if".to_owned(),
        provenance_digest: INTERVENTION_PROVENANCE,
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

/// The sealed plan that cuts `root` at `cut`.
fn plan_for_cut(root: TimelineId, cut: FactualHeadV1) -> TestResult<Host> {
    let profile = ExecutionProfileV1::from_canonical_cbor(&draft_execution_profile_bytes_v1(
        "deterministic-local-v1",
    )?)?;
    let snapshot =
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
    let first_tick = cut.tick + 1;
    let mut plan = CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: ROOM_ID.to_owned(),
        room_digest: ROOM_DIGEST,
        parent_timeline_id: root.inner().to_bytes(),
        parent_cut_seq: cut.last_seq.as_u64(),
        parent_cut_tick: cut.tick,
        parent_cut_digest: [4; 32],
        first_tick,
        horizon_tick: first_tick + HORIZON_SPAN,
        interventions: vec![intervention(first_tick)],
        exogenous_descriptors: Vec::new(),
        fixed_policy_descriptors: Vec::new(),
        classification_bundle_digest: *factual_classification_bundle_digest().as_bytes(),
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
    plan.plan_digest = plan.digest()?;
    Ok(Host {
        plan,
        profile,
        snapshot,
        claim: exact_evaluation()?,
    })
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

fn admission_request(host: &Host, fork: TimelineId) -> CounterfactualAdmissionRequestV1<'_> {
    CounterfactualAdmissionRequestV1 {
        plan: &host.plan,
        fork,
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

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Everything the counterfactual half needs, read after the Fork exists.
struct Prepared<B> {
    store: Shared<B>,
    fork: TimelineId,
    host: Host,
    graph: Graph,
    lanes: Vec<Lane>,
    history: History,
    cut: FactualHeadV1,
}

/// Run the factual history, cut it, restore the Fork runtime, and build the
/// plan and the provisional graph from what the Fork reads of the prefix.
fn prepare<B: Backend>(choice: CutChoice) -> TestResult<Prepared<B>> {
    let setup = Setup::new();
    let mut store = B::open(&setup.gate)?;
    let history = factual_history(&mut store, &setup)?;
    let cut = history.cut(choice);
    let runtime = fork_runtime(&mut store, &setup, &history, cut)?;
    let store = Shared::new(store);
    let prefix = resolve_prefix(&store, &runtime, cut)?;
    let host = plan_for_cut(history.root, cut)?;
    let lanes = build_lanes(&runtime, &prefix);
    let graph = provisional_graph(runtime.fork, &lanes, &prefix, &host.plan)?;
    Ok(Prepared {
        store,
        fork: runtime.fork,
        host,
        graph,
        lanes,
        history,
        cut,
    })
}

impl<B: Backend> Prepared<B> {
    /// The composite source over the recorded prefix and the host-built
    /// provisional graph.
    fn composite(&self) -> PrefixSeededFrontierSourceV1<Shared<B>> {
        PrefixSeededFrontierSourceV1::new(
            self.store.clone(),
            self.graph.nodes.clone(),
            self.graph.edges.clone(),
            BOUNDS,
        )
    }

    /// The production source over the Fork's committed generation.
    fn recorded(&self) -> TestResult<RecordedFrontierSourceV1<Shared<B>>> {
        let at = self.store.current_fork_generation(self.fork)?;
        let source = RecordedFrontierSourceV1::new(self.store.clone(), at, BOUNDS);
        Ok(source)
    }

    fn stager(&self) -> TestResult<ProvisionalTickStager> {
        Ok(ProvisionalTickStager {
            declarations: declarations(&self.graph)?,
            event_types: self.lanes.iter().map(|lane| lane.event_type).collect(),
        })
    }
}

const fn generation(fork: TimelineId, number: u64) -> ForkGenerationV1 {
    ForkGenerationV1 {
        fork,
        generation: number,
    }
}

/// The owner frontiers `pos-time` must derive: the Intervention root, the
/// first Driver at its output of the first Tick, and every other Driver at
/// its step of the next Tick, which consumes the first Driver's output.
fn expected_owner_frontiers<B>(prepared: &Prepared<B>) -> TestResult<OwnerFrontiers> {
    let first = prepared.host.plan.first_tick;
    let graph = &prepared.graph;
    let seed = graph.digest_at(first, 0, 0)?;
    let mut expected = BTreeMap::new();
    expected.insert(INTERVENTION_OWNER.to_owned(), (first, 0, 0, vec![seed]));
    for (index, lane) in prepared.lanes.iter().enumerate() {
        let (tick, ordinal, cause) = if index == 0 {
            (first, 1, seed)
        } else {
            let lead = prepared.lanes[0].position;
            (first + 1, 0, graph.digest_at(first, lead, 1)?)
        };
        expected.insert(
            lane.owner.clone(),
            (tick, lane.position, ordinal, vec![cause]),
        );
    }
    Ok(expected)
}

/// The frontier `pos-time` derived is the one the Intervention implies.
fn check_frontier<B>(
    prepared: &Prepared<B>,
    derivation: &CounterfactualFrontierDerivationV1,
) -> TestResult {
    let frontier = &derivation.frontier;
    let first = prepared.host.plan.first_tick;
    let position = frontier.global_frontier_scheduler_position;
    assert_eq!((frontier.global_frontier_tick, position), (first, 0));
    let seeds = &frontier.intervention_seed_nodes;
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].schema_id, factual_event_schema_id(ALPHA_EVENT));
    let derived: OwnerFrontiers = frontier
        .owner_frontiers
        .iter()
        .map(|owner| {
            let at = (
                owner.earliest_tick,
                owner.earliest_scheduler_position,
                owner.earliest_output_ordinal,
                owner.cause_node_digests.clone(),
            );
            (owner.owner_id.clone(), at)
        })
        .collect();
    assert_eq!(derived, expected_owner_frontiers(prepared)?);
    Ok(())
}

/// The nodes of `graph` owned by `owner`, in canonical order.
fn owned_by<'g>(graph: &'g ValidatedDependencyGraphV1, owner: &str) -> Vec<&'g Node> {
    graph
        .nodes()
        .iter()
        .filter(|node| node.node.owner_id == owner)
        .collect()
}

/// The step node `node` chains to: an input of the same owner that is a step.
fn previous_step<'g>(graph: &'g ValidatedDependencyGraphV1, node: &Node) -> Option<&'g Node> {
    node.input_digests
        .iter()
        .filter_map(|digest| graph.node(digest))
        .find(|input| is_step_of(input, node))
}

/// Whether `node` is a step node at `tick`.
const fn is_step_at(node: &Node, tick: u64) -> bool {
    node.node.tick == tick && node.node.output_ordinal == 0
}

/// Whether `input` is a step node of the owner of `node`.
fn is_step_of(input: &Node, node: &Node) -> bool {
    input.node.owner_id == node.node.owner_id
        && input.node.output_ordinal == 0
        && input.node.schema_id == FACTUAL_STEP_SCHEMA_ID_V1
}

/// The Ticks of the step chain that starts at `start`, newest first.
fn step_chain(graph: &ValidatedDependencyGraphV1, start: [u8; 32]) -> Vec<u64> {
    let mut ticks = Vec::new();
    let mut current = graph.node(&start);
    while let Some(node) = current {
        ticks.push(node.node.tick);
        current = previous_step(graph, node);
    }
    ticks
}

/// The step chain of every owner runs from the first provisional Tick through
/// every recorded factual Tick, across the resume.
fn check_step_chains<B>(prepared: &Prepared<B>, graph: &ValidatedDependencyGraphV1) -> TestResult {
    let first = prepared.host.plan.first_tick;
    let recorded = (1..=prepared.cut.tick).rev();
    let expected: Vec<u64> = std::iter::once(first).chain(recorded).collect();
    for lane in &prepared.lanes {
        let start = prepared.graph.digest_at(first, lane.position, 0)?;
        assert_eq!(step_chain(graph, start), expected, "{}", lane.owner);
    }
    Ok(())
}

/// The first step after the resume declares the one history node, which has
/// no input, and the Driver that reads the verified prefix declares its
/// prefix node; the ingress nodes are recorded with no input.
fn check_recorded_nodes<B>(
    prepared: &Prepared<B>,
    graph: &ValidatedDependencyGraphV1,
) -> TestResult {
    let resumed_tick = prepared.history.resumed_tick;
    let recorded = owned_by(graph, HISTORY_OWNER);
    assert_eq!(recorded.len(), 1);
    let history = recorded[0];
    assert!(history.input_digests.is_empty());
    assert_eq!(history.node.schema_id, FACTUAL_HISTORY_SCHEMA_ID_V1);
    assert_eq!(history.node.tick, resumed_tick);
    let lead_nodes = owned_by(graph, &prepared.lanes[0].owner);
    let resumed_step = lead_nodes
        .iter()
        .find(|node| is_step_at(node, resumed_tick))
        .ok_or("no step after the resume")?;
    let history_digest = history.node.artifact_digest;
    assert!(resumed_step.input_digests.contains(&history_digest));
    let prefix_nodes = owned_by(graph, PREFIX_OWNER);
    assert!(!prefix_nodes.is_empty());
    for node in prefix_nodes {
        assert_eq!(node.node.schema_id, FACTUAL_PREFIX_SCHEMA_ID_V1);
    }
    let ingress_nodes = owned_by(graph, INGRESS_OWNER);
    assert!(!ingress_nodes.is_empty());
    for node in ingress_nodes {
        assert!(node.input_digests.is_empty());
    }
    Ok(())
}

/// Admit generation 1 through the composite source, record its suffix, and
/// admit generation 2 through the recorded source; both graphs digest alike.
fn admit_generations<B: Backend>(
    prepared: &Prepared<B>,
    expected: &CounterfactualFrontierDerivationV1,
) -> TestResult {
    let plan = &prepared.host.plan;
    let fork = prepared.fork;
    let digest = prepared.composite().recorded_graph_digest(plan)?;
    let facts = CounterfactualFactsV1 {
        plan_digest: Hash::from_bytes(plan.plan_digest),
        dependency_graph_digest: Hash::from_bytes(digest),
        trust_epoch: prepared.host.snapshot.epoch,
        revocation_epoch: REVOCATION_EPOCH,
        erasure_epoch: ERASURE_EPOCH,
    };
    let mut publisher = prepared.store.clone();
    publisher.publish_counterfactual_facts(fork, facts)?;
    let request = admission_request(&prepared.host, fork);
    let mut coordinator = CounterfactualCoordinatorV1::new(prepared.store.clone());
    let mut stager = prepared.stager()?;
    let mut composite = prepared.composite();
    let first = coordinator.admit(&request, &Authority, &mut composite, &mut stager)?;
    assert_eq!(first.generation(), generation(fork, 1));
    let run = coordinator.recompute_suffix(&suffix_request(plan, first), &mut stager)?;
    assert_eq!(run.failure, None);
    let mut complete = prepared.recorded()?;
    assert_eq!(complete.generation(), generation(fork, 1));
    assert_eq!(complete.recorded_graph_digest(plan)?, digest);
    let derived = complete.derive_frontier(plan, FRONTIER_ID, PROVENANCE)?;
    assert_eq!(&derived, expected);
    let second = coordinator.admit(&request, &Authority, &mut complete, &mut stager)?;
    assert_eq!(second.generation(), generation(fork, 2));
    assert_eq!(second.frontier_digest(), first.frontier_digest());
    let run = coordinator.recompute_suffix(&suffix_request(plan, second), &mut stager)?;
    assert_eq!(run.failure, None);
    let mut third = prepared.recorded()?;
    assert_eq!(third.generation(), generation(fork, 2));
    assert_eq!(third.recorded_graph_digest(plan)?, digest);
    let last = third.derive_frontier(plan, FRONTIER_ID, PROVENANCE)?;
    assert_eq!(&last, expected);
    Ok(())
}

fn end_to_end<B: Backend>(choice: CutChoice) -> TestResult {
    let prepared = prepare::<B>(choice)?;
    let plan = &prepared.host.plan;
    let mut composite = prepared.composite();
    let expected = composite.derive_frontier(plan, FRONTIER_ID, PROVENANCE)?;
    check_frontier(&prepared, &expected)?;
    let graph = composite.recorded_graph(plan)?;
    check_step_chains(&prepared, &graph)?;
    check_recorded_nodes(&prepared, &graph)?;
    admit_generations(&prepared, &expected)
}

#[test]
fn memory_runs_a_history_cut_at_the_head_into_a_counterfactual() -> TestResult {
    end_to_end::<MemoryStore>(CutChoice::Head)
}

#[test]
fn memory_runs_a_history_cut_at_a_tick_boundary_into_a_counterfactual() -> TestResult {
    end_to_end::<MemoryStore>(CutChoice::Boundary)
}

#[test]
fn sqlite_runs_a_history_cut_at_the_head_into_a_counterfactual() -> TestResult {
    end_to_end::<SqliteStore>(CutChoice::Head)
}

#[test]
fn sqlite_runs_a_history_cut_at_a_tick_boundary_into_a_counterfactual() -> TestResult {
    end_to_end::<SqliteStore>(CutChoice::Boundary)
}
