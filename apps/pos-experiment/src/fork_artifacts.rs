//! ADR-064 Fork artifact export and comparison (ADR-062 Revision 8 slice R6,
//! #1225).
//!
//! [`run_fork_v1`] executes one ADR-064 counterfactual Fork from a
//! [`ForkFixtureV1`] and exports its artifacts through their public
//! encodings: every `INT1` Intervention and the `CFP1` counterfactual plan
//! the run admits, the `RCF1` recomputation frontier and `SIV1` suffix
//! invalidation the Event Store committed for the generation (read back through
//! `read_generation_artifact`), every `RCP1` checkpoint and the `CFR1`
//! result of the suffix recomputation. [`compare_fork_artifacts_v1`] compares
//! two exports with the R1 comparator
//! ([`first_divergence_v1`]), so the first mismatching artifact is one `DVR1`
//! at that artifact's `WorldCut` coordinate.
//!
//! # The run
//!
//! 1. The Execution Mode: Local, or Air-Gapped (the run uses the fixture's
//!    bundled TPS1 and refuses an EPF1 that allows network; the run is
//!    in-process and opens no network in either mode, and no isolation is
//!    claimed); a Replay or Fork mode is
//!    [`ForkRunErrorV1::ModeUnsupported`]. An Air-Gapped run whose EPF1
//!    allows network is [`ForkRunErrorV1::NetworkDenied`] before anything
//!    runs (as slice R5 decided for the replay adapter). Nothing else depends
//!    on the mode, so a Local and an Air-Gapped run of one fixture export the
//!    same bytes.
//! 2. The factual history (the `history` module): `cut_tick` factual Ticks on
//!    the factual Timeline [`FACTUAL_TIMELINE_ID_V1`], then one Tick per
//!    `factual_suffix` input. The Fork [`FORK_TIMELINE_ID_V1`] is cut at the
//!    last Tick before the suffix.
//! 3. The `CFP1` plan: it cuts the factual Timeline at that Tick, recomputes
//!    from the next Tick through `horizon_span` more Ticks and binds the
//!    fixture's Intervention, EPF1, TPS1 and pinned digests.
//! 4. The provisional Ticks come from the records form (the `records_form`
//!    module, owner answer Q7). Per Q7 such a run is a genuine ADR-064 Fork
//!    execution; it is re-run when the ADR-064 R7 steps form (#1204) lands.
//! 5. The frontier: `pos-time`'s `PrefixSeededFrontierSourceV1` reads the
//!    recorded prefix through the cut, stitches the provisional graph and
//!    derives the `RCF1`. It runs before the coordinator takes exclusive
//!    ownership of the store, because it reads that store; the coordinator
//!    re-validates the derived frontier and binds it to the published
//!    dependency-graph digest.
//! 6. The core `CounterfactualCoordinatorV1` admits the generation and
//!    recomputes the suffix through the horizon.
//!
//! A host failure in steps 2 to 4 or in the export is
//! [`ForkRunErrorV1::Host`]; an admission or recomputation refusal is
//! [`ForkRunErrorV1::Admission`] or [`ForkRunErrorV1::Suffix`].
//!
//! # Replay of a recorded run
//!
//! [`record_fork_v1`] also returns the run's recorded Event Store as a
//! [`RecordedForkV1`]. [`replay_recorded_fork_v1`] rebuilds the export from
//! that store alone: it reads the committed generation's receipt, reads the
//! `RCF1` and `SIV1` back with `read_generation_artifact`, and has the
//! coordinator recover every `RCP1` and the `CFR1` from the committed Fork
//! Events. A complete generation stages nothing, so no Driver runs and no
//! Event is appended; its stager declares no provisional Tick, so a Tick it
//! were asked to stage would be an empty batch, which the coordinator
//! refuses. The `INT1` and `CFP1` are the recorded run's plan.
//!
//! # No factual-suffix splicing
//!
//! The Fork sees the factual Timeline only through its cut: the frontier
//! source pages the recorded prefix through the plan's parent-cut Tick, and
//! every recomputed Tick is staged from the plan and the records form alone.
//! The factual suffix therefore never reaches an exported artifact: two
//! fixtures that differ only in their factual suffix, or in the hidden
//! participant field their factual Events carry after the cut, export the
//! same bytes.
//!
//! # Coordinates
//!
//! Every artifact of a run is exported at the run's `WorldCut`, the parent
//! cut of its plan: the `WorldCut` id is the plan's parent Timeline id, the
//! cut ordinal its parent cut `Seq`, and the tick its parent cut Tick. The
//! artifact ordinal is the artifact's position in the export order: the
//! Interventions in plan order, the plan, the frontier, the invalidation, the
//! checkpoints in Tick order, then the result.
//!
//! # Determinism
//!
//! The factual and Fork Timeline ids are fixed and every factual pass derives
//! its attempt identities from its Timeline and Tick, so the exported bytes
//! are a function of the fixture alone. Event ids and wall times stay
//! store-assigned and are covered by no artifact.
//!
//! The run uses the open fixture erasure gate and the generated Plugin
//! registration, so the module is compiled only with the `test-support`
//! feature, and only on Linux, where `pos-time` has its counterfactual
//! module. Its results are Local-relaxation engineering evidence, not hosted
//! conformance.

use pos_conformance::counterfactual::dependency::InputDependencyV1;
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanV1, FrozenArtifactDescriptorV1, PlanExecutionProfileRefV1,
    PlanTrustPolicyRefV1,
};
use pos_conformance::counterfactual::InterventionV1;
use pos_conformance::{
    DivergenceReportV1, ExecutionModeV1, ExecutionProfileV1, ReplayClaimV1, TrustPolicySnapshotV1,
    UnknownEdgePolicyV1,
};
use pos_core::{
    factual_classification_bundle_digest, CoreError, CounterfactualDependencyReadPortV1,
    CounterfactualFactsV1, CounterfactualGenerationReceiptV1, CounterfactualStoreErrorV1,
    CounterfactualStorePortV1, DependencyEdgeRecordV1, DependencyNodeRecordV1,
    DependencyPageRequestV1, DependencyPageV1, FactualHeadV1, Hash, ReplayClaimEvaluationV1,
    TimelineId,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1, CounterfactualAdmissionRequestV1, CounterfactualCoordinatorV1,
    CounterfactualForkAppendAuthorityV1, CounterfactualFrontierDerivationV1,
    CounterfactualFrontierSourceV1, CounterfactualFrozenArtifactsV1, CounterfactualHostPreflightV1,
    CounterfactualInterventionAuthorityV1, FrozenArtifactAvailabilityV1, GenericForksOnlyV1,
    InterventionDecisionV1,
};
use pos_runtime::counterfactual::suffix::{
    CounterfactualSuffixErrorV1, CounterfactualSuffixRequestV1, CounterfactualSuffixRunV1,
};
use pos_runtime::LocalScheduledAdmissionHostV1;
use pos_store::memory::MemoryStore;
use pos_time::counterfactual::dependency_graph::DependencyGraphBoundsV1;
use pos_time::counterfactual::prefix_seeded_source::PrefixSeededFrontierSourceV1;
use ulid::Ulid;

use crate::authoritative_comparison::{
    first_divergence_v1, AuthoritativeStreamV1, DivergenceContextV1, WorldCutArtifactCoordinateV1,
};

mod history;
mod records_form;

use history::FactualV1;
use records_form::{BindingsV1, ProvisionalGraphV1, RecordsFormStagerV1};

/// The id of the factual Timeline of every run.
pub const FACTUAL_TIMELINE_ID_V1: [u8; 16] = *b"pigloros.factual";
/// The id of the Fork of every run.
pub const FORK_TIMELINE_ID_V1: [u8; 16] = *b"pigloros.fork.v1";
/// The Event type the lead Driver emits; an Intervention of the run assigns
/// the output of this type at the first recomputation Tick.
pub const LEAD_EVENT_TYPE_V1: &str = history::LEAD_EVENT_TYPE;

/// The bounds the dependency graph is validated under.
const BOUNDS: DependencyGraphBoundsV1 = DependencyGraphBoundsV1 {
    max_nodes: 5_000,
    max_edges: 5_000,
};

/// The kind of one exported artifact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ForkArtifactKindV1 {
    /// An `INT1` Intervention of the plan.
    Intervention,
    /// The `CFP1` counterfactual plan.
    CounterfactualPlan,
    /// The `RCF1` recomputation frontier of the generation.
    RecomputationFrontier,
    /// The `SIV1` suffix invalidation of the generation.
    SuffixInvalidation,
    /// One `RCP1` checkpoint of a recomputed Tick.
    Checkpoint,
    /// The `CFR1` result of the suffix recomputation.
    Result,
}

/// One exported artifact: its kind, its `WorldCut` coordinate and its exact
/// canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkArtifactV1 {
    /// The kind of the artifact.
    pub kind: ForkArtifactKindV1,
    /// The coordinate the comparator reports it at.
    pub coordinate: WorldCutArtifactCoordinateV1,
    /// The canonical bytes.
    pub bytes: Vec<u8>,
}

/// One Driver of the run, as its registration recorded it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkDriverV1 {
    /// The name its Plugin reports.
    pub plugin_name: String,
    /// The name the Driver reports.
    pub driver_name: String,
    /// Its factual owner ID, the owner of its nodes in the artifacts.
    pub owner_id: String,
    /// Its scheduler position.
    pub scheduler_position: u32,
}

/// The artifacts of one run, in export order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkArtifactExportV1 {
    /// The last Tick of the factual Timeline, after its suffix. It is no
    /// artifact and is never compared; it shows how far the factual history
    /// ran past the cut.
    pub factual_head: FactualHeadV1,
    /// The Drivers of the run in schedule order. They are no artifact and
    /// are never compared.
    pub drivers: Vec<ForkDriverV1>,
    /// Every provisional edge the records form declared, in canonical order.
    /// They are no artifact and are never compared.
    pub provisional_edges: Vec<InputDependencyV1>,
    /// The artifacts, in the export order of the module documentation.
    pub artifacts: Vec<ForkArtifactV1>,
}

impl ForkArtifactExportV1 {
    /// The authoritative stream of the export: every artifact at its
    /// `WorldCut` coordinate and nothing else.
    #[must_use]
    pub fn stream(&self) -> AuthoritativeStreamV1 {
        AuthoritativeStreamV1 {
            world_cut_artifacts: self
                .artifacts
                .iter()
                .map(|artifact| (artifact.coordinate, artifact.bytes.clone()))
                .collect(),
            ..AuthoritativeStreamV1::default()
        }
    }
}

/// Compare two exports with the R1 comparator.
///
/// Returns `Ok(None)` when every artifact agrees, otherwise one sealed `DVR1`
/// at the coordinate of the first mismatching artifact.
///
/// # Errors
/// Returns the `DVR1` codec error of [`first_divergence_v1`].
pub fn compare_fork_artifacts_v1(
    context: &DivergenceContextV1,
    expected: &ForkArtifactExportV1,
    actual: &ForkArtifactExportV1,
) -> Result<Option<DivergenceReportV1>, CoreError> {
    first_divergence_v1(context, &expected.stream(), &actual.stream())
}

/// Everything one Fork run is executed from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkFixtureV1 {
    /// Factual Ticks committed before the cut.
    pub cut_tick: u64,
    /// The input of each factual Tick after the cut; it never reaches an
    /// exported artifact.
    pub factual_suffix: Vec<Vec<u8>>,
    /// The hidden participant field: the participant Driver `beta` appends
    /// it to the payload of each of its factual Events after the cut. It
    /// never reaches an exported artifact.
    pub hidden_participant_field: Vec<u8>,
    /// Recomputation Ticks after the first one, through the plan horizon.
    pub horizon_span: u64,
    /// `CFP1` plan id.
    pub plan_id: [u8; 16],
    /// Scenario Room id, also the host's expected room.
    pub room_id: String,
    /// Scenario Room digest, also the host's expected room digest.
    pub room_digest: [u8; 32],
    /// `CFP1` parent cut digest.
    pub parent_cut_digest: [u8; 32],
    /// The plan's one Intervention, effective at the first recomputation Tick.
    pub intervention: InterventionV1,
    /// The plan's `ExogenousFrozen` descriptors. The run's frozen closure
    /// holds no artifact, so a plan with a descriptor is refused at
    /// admission.
    pub exogenous_descriptors: Vec<FrozenArtifactDescriptorV1>,
    /// Pinned Plugin composition digest, also the host's expected one.
    pub plugin_composition_digest: [u8; 32],
    /// Pinned scheduler and Driver order digest.
    pub scheduler_digest: [u8; 32],
    /// Pinned numeric profile digest.
    pub numeric_profile_digest: [u8; 32],
    /// Deterministic budget digest.
    pub budget_digest: [u8; 32],
    /// Failure policy digest.
    pub failure_policy_digest: [u8; 32],
    /// The `ReplayClaim` the plan requests.
    pub replay_claim: ReplayClaimV1,
    /// The EPF1 the plan binds and the host admits.
    pub execution_profile: ExecutionProfileV1,
    /// The bundled TPS1 the plan binds and the host admits.
    pub trust_policy: TrustPolicySnapshotV1,
    /// The host's evaluated `ReplayClaim` of the frozen closure.
    pub evaluated_claim: ReplayClaimEvaluationV1,
    /// Revocation epoch the generation is admitted under.
    pub revocation_epoch: u64,
    /// Erasure epoch the generation is admitted under.
    pub erasure_epoch: u64,
    /// `RCF1` frontier id.
    pub frontier_id: [u8; 16],
    /// `SIV1` invalidation id.
    pub invalidation_id: [u8; 16],
    /// Provenance of the frontier, the invalidation and every provisional
    /// record.
    pub provenance_digest: [u8; 32],
    /// `CFR1` result id.
    pub result_id: [u8; 16],
    /// `CFR1` evaluator identity digest.
    pub evaluator_identity_digest: [u8; 32],
}

/// Why a run exported nothing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkRunErrorV1 {
    /// The Execution Mode is not Local or Air-Gapped.
    #[error("the execution mode is not Local or Air-Gapped")]
    ModeUnsupported,
    /// An Air-Gapped run's EPF1 allows network.
    #[error("an Air-Gapped run cannot use network")]
    NetworkDenied,
    /// The host could not record the factual history, cut the Fork, build
    /// the plan or the records form, or read back an artifact.
    #[error("the Fork host failed")]
    Host,
    /// The frontier source or the coordinator refused the admission.
    #[error("the counterfactual admission was refused: {0}")]
    Admission(Box<CounterfactualAdmissionErrorV1>),
    /// The coordinator refused the suffix recomputation.
    #[error("the suffix recomputation was refused: {0}")]
    Suffix(CounterfactualSuffixErrorV1),
}

/// One executed run's recorded Event Store, which
/// [`replay_recorded_fork_v1`] rebuilds the export from.
pub struct RecordedForkV1 {
    coordinator: CounterfactualCoordinatorV1<MemoryStore>,
    plan: CounterfactualPlanV1,
    fork: TimelineId,
    result_id: [u8; 16],
    evaluator_identity_digest: [u8; 32],
    factual_head: FactualHeadV1,
    drivers: Vec<ForkDriverV1>,
    provisional_edges: Vec<InputDependencyV1>,
}

impl RecordedForkV1 {
    /// The recorded Event Store: the factual Timeline
    /// ([`FACTUAL_TIMELINE_ID_V1`]) and the Fork ([`FORK_TIMELINE_ID_V1`]).
    #[must_use]
    pub const fn store(&self) -> &MemoryStore {
        self.coordinator.store()
    }
}

/// Execute `fixture` in `mode` and export its artifacts.
///
/// # Errors
/// Returns the [`ForkRunErrorV1`] of the first refused step, in the order of
/// the module documentation.
pub fn run_fork_v1(
    fixture: &ForkFixtureV1,
    mode: ExecutionModeV1,
) -> Result<ForkArtifactExportV1, ForkRunErrorV1> {
    record_fork_v1(fixture, mode).map(|(export, _)| export)
}

/// Rebuild the export of a recorded run from its Event Store alone (see the
/// module documentation): no Driver runs and no Event is appended.
///
/// # Errors
/// Returns [`ForkRunErrorV1::Host`] when the store holds no committed
/// generation or one of its artifacts cannot be read back, and the
/// coordinator's [`ForkRunErrorV1::Suffix`] refusal of the recovery.
pub fn replay_recorded_fork_v1(
    recorded: &mut RecordedForkV1,
) -> Result<ForkArtifactExportV1, ForkRunErrorV1> {
    let store = recorded.coordinator.store();
    let receipt = store
        .current_fork_generation(recorded.fork)
        .ok()
        .and_then(|at| store.committed_generation_receipt(at).ok().flatten());
    let no_provisional_tick = ProvisionalGraphV1 {
        nodes: Vec::new(),
        edges: Vec::new(),
    };
    receipt
        .zip(RecordsFormStagerV1::new(&no_provisional_tick, Vec::new()))
        .ok_or(ForkRunErrorV1::Host)
        .and_then(|(receipt, mut stager)| {
            let suffix = CounterfactualSuffixRequestV1 {
                plan: &recorded.plan,
                receipt,
                fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
                result_id: recorded.result_id,
                evaluator_identity_digest: recorded.evaluator_identity_digest,
            };
            recorded
                .coordinator
                .recompute_suffix(&suffix, &mut stager, &mut GenericForksOnlyV1)
                .map_err(ForkRunErrorV1::Suffix)
                .and_then(|run| export(recorded.coordinator.store(), &recorded.plan, receipt, run))
        })
        .map(|artifacts| ForkArtifactExportV1 {
            factual_head: recorded.factual_head,
            drivers: recorded.drivers.clone(),
            provisional_edges: recorded.provisional_edges.clone(),
            artifacts,
        })
}

/// Execute `fixture` in `mode`, export its artifacts and keep its recorded
/// Event Store for [`replay_recorded_fork_v1`].
///
/// # Errors
/// Returns the [`ForkRunErrorV1`] of the first refused step, in the order of
/// the module documentation.
pub fn record_fork_v1(
    fixture: &ForkFixtureV1,
    mode: ExecutionModeV1,
) -> Result<(ForkArtifactExportV1, RecordedForkV1), ForkRunErrorV1> {
    let network = fixture
        .execution_profile
        .capabilities_and_network
        .network_allowed;
    let admitted = match mode {
        ExecutionModeV1::AirGapped if network => Err(ForkRunErrorV1::NetworkDenied),
        ExecutionModeV1::Local | ExecutionModeV1::AirGapped => Ok(()),
        ExecutionModeV1::Replay | ExecutionModeV1::Fork => Err(ForkRunErrorV1::ModeUnsupported),
    };
    admitted
        .and_then(|()| {
            let root = TimelineId::from_ulid(Ulid::from_bytes(FACTUAL_TIMELINE_ID_V1));
            let fork = TimelineId::from_ulid(Ulid::from_bytes(FORK_TIMELINE_ID_V1));
            let suffix = (
                fixture.factual_suffix.as_slice(),
                fixture.hidden_participant_field.as_slice(),
            );
            history::record(root, fork, fixture.cut_tick, suffix).ok_or(ForkRunErrorV1::Host)
        })
        .and_then(|factual| execute(fixture, factual))
}

/// The `CFP1` plan that cuts `root` at `cut`.
fn plan(
    fixture: &ForkFixtureV1,
    root: TimelineId,
    cut: FactualHeadV1,
) -> Option<CounterfactualPlanV1> {
    let profile = PlanExecutionProfileRefV1::from_execution_profile_v1(&fixture.execution_profile);
    let trust = PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(&fixture.trust_policy);
    profile
        .ok()
        .zip(trust.ok())
        .and_then(|(execution_profile, trust_policy)| {
            let first_tick = cut.tick + 1;
            let mut plan = CounterfactualPlanV1 {
                plan_id: fixture.plan_id,
                room_id: fixture.room_id.clone(),
                room_digest: fixture.room_digest,
                parent_timeline_id: root.inner().to_bytes(),
                parent_cut_seq: cut.last_seq.as_u64(),
                parent_cut_tick: cut.tick,
                parent_cut_digest: fixture.parent_cut_digest,
                first_tick,
                horizon_tick: first_tick.saturating_add(fixture.horizon_span),
                interventions: vec![fixture.intervention.clone()],
                exogenous_descriptors: fixture.exogenous_descriptors.clone(),
                fixed_policy_descriptors: Vec::new(),
                classification_bundle_digest: *factual_classification_bundle_digest().as_bytes(),
                unknown_edge_policy: UnknownEdgePolicyV1::Reject,
                execution_profile,
                trust_policy,
                plugin_composition_digest: fixture.plugin_composition_digest,
                scheduler_digest: fixture.scheduler_digest,
                numeric_profile_digest: fixture.numeric_profile_digest,
                budget_digest: fixture.budget_digest,
                failure_policy_digest: fixture.failure_policy_digest,
                replay_claim: fixture.replay_claim,
                previous_plan_digest: None,
                plan_digest: [0; 32],
            };
            plan.digest().ok().map(|digest| {
                plan.plan_digest = digest;
                plan
            })
        })
}

/// The plan, the records form and the frontier of the run, then its
/// admission.
fn execute(
    fixture: &ForkFixtureV1,
    factual: FactualV1,
) -> Result<(ForkArtifactExportV1, RecordedForkV1), ForkRunErrorV1> {
    let FactualV1 {
        store,
        root,
        fork,
        cut,
        head,
        lanes,
        prefix,
    } = factual;
    let drivers: Vec<ForkDriverV1> = lanes
        .iter()
        .map(|lane| ForkDriverV1 {
            plugin_name: lane.plugin_name.to_owned(),
            driver_name: lane.driver_name.to_owned(),
            owner_id: lane.owner.clone(),
            scheduler_position: lane.position,
        })
        .collect();
    let grant = LocalScheduledAdmissionHostV1::shared()
        .ok()
        .map(LocalScheduledAdmissionHostV1::authority_grant);
    plan(fixture, root, cut)
        .zip(grant)
        .and_then(|(plan, grant)| {
            let bindings = BindingsV1 {
                authorization: *grant.as_bytes(),
                provenance: fixture.provenance_digest,
            };
            records_form::provisional_graph(fork, &lanes, &prefix, &plan, bindings).and_then(
                |graph| RecordsFormStagerV1::new(&graph, lanes).map(|stager| (plan, graph, stager)),
            )
        })
        .ok_or(ForkRunErrorV1::Host)
        .and_then(|(plan, graph, mut stager)| {
            let provisional_edges = graph.edges.clone();
            let derived = {
                let mut source = PrefixSeededFrontierSourceV1::new(
                    PrefixReadsV1(&store),
                    graph.nodes,
                    graph.edges,
                    BOUNDS,
                );
                source
                    .recorded_graph_digest(&plan)
                    .map_err(ForkRunErrorV1::Admission)
                    .and_then(|digest| {
                        source
                            .derive_frontier(&plan, fixture.frontier_id, fixture.provenance_digest)
                            .map_err(Box::new)
                            .map_err(ForkRunErrorV1::Admission)
                            .map(|derivation| (digest, derivation))
                    })
            };
            derived.and_then(|(digest, derivation)| {
                admit(
                    fixture,
                    store,
                    fork,
                    &plan,
                    (digest, derivation),
                    &mut stager,
                )
                .map(|(artifacts, coordinator)| {
                    let recorded = RecordedForkV1 {
                        coordinator,
                        plan,
                        fork,
                        result_id: fixture.result_id,
                        evaluator_identity_digest: fixture.evaluator_identity_digest,
                        factual_head: head,
                        drivers: drivers.clone(),
                        provisional_edges: provisional_edges.clone(),
                    };
                    let export = ForkArtifactExportV1 {
                        factual_head: head,
                        drivers,
                        provisional_edges,
                        artifacts,
                    };
                    (export, recorded)
                })
            })
        })
}

/// Publish the generation's facts, admit it, recompute its suffix and export
/// its artifacts; the coordinator keeps the recorded store.
fn admit(
    fixture: &ForkFixtureV1,
    mut store: MemoryStore,
    fork: TimelineId,
    plan: &CounterfactualPlanV1,
    (digest, derivation): ([u8; 32], CounterfactualFrontierDerivationV1),
    stager: &mut RecordsFormStagerV1,
) -> Result<
    (
        Vec<ForkArtifactV1>,
        CounterfactualCoordinatorV1<MemoryStore>,
    ),
    ForkRunErrorV1,
> {
    let facts = CounterfactualFactsV1 {
        plan_digest: Hash::from_bytes(plan.plan_digest),
        dependency_graph_digest: Hash::from_bytes(digest),
        trust_epoch: fixture.trust_policy.epoch,
        revocation_epoch: fixture.revocation_epoch,
        erasure_epoch: fixture.erasure_epoch,
    };
    let published = store.publish_counterfactual_facts(fork, facts);
    let mut coordinator = CounterfactualCoordinatorV1::new(store);
    let request = CounterfactualAdmissionRequestV1 {
        plan,
        fork,
        fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
        execution_profile: &fixture.execution_profile,
        trust_policy: &fixture.trust_policy,
        preflight: CounterfactualHostPreflightV1 {
            room_id: &fixture.room_id,
            room_digest: fixture.room_digest,
            plugin_composition_digest: fixture.plugin_composition_digest,
            frozen_artifacts: &FrozenClosureV1,
            replay_claim: &fixture.evaluated_claim,
        },
        revocation_epoch: fixture.revocation_epoch,
        erasure_epoch: fixture.erasure_epoch,
        frontier_id: fixture.frontier_id,
        invalidation_id: fixture.invalidation_id,
        provenance_digest: fixture.provenance_digest,
        invalid_checkpoint_digests: &[],
        invalid_projection_digests: &[],
    };
    published
        .or(Err(ForkRunErrorV1::Host))
        .and_then(|_| {
            coordinator
                .admit(
                    &request,
                    &HostAuthorityV1,
                    &mut AdmittedFrontierV1(derivation),
                    stager,
                    &mut GenericForksOnlyV1,
                )
                .map_err(Box::new)
                .map_err(ForkRunErrorV1::Admission)
        })
        .and_then(|receipt| {
            let suffix = CounterfactualSuffixRequestV1 {
                plan,
                receipt,
                fork_append_authority: CounterfactualForkAppendAuthorityV1::Generic,
                result_id: fixture.result_id,
                evaluator_identity_digest: fixture.evaluator_identity_digest,
            };
            coordinator
                .recompute_suffix(&suffix, stager, &mut GenericForksOnlyV1)
                .map_err(ForkRunErrorV1::Suffix)
                .and_then(|run| export(coordinator.store(), plan, receipt, run))
        })
        .map(|artifacts| (artifacts, coordinator))
}

/// Export the run's artifacts in export order. The frontier and the
/// invalidation are read back from the generation the store committed.
fn export(
    store: &MemoryStore,
    plan: &CounterfactualPlanV1,
    receipt: CounterfactualGenerationReceiptV1,
    run: CounterfactualSuffixRunV1,
) -> Result<Vec<ForkArtifactV1>, ForkRunErrorV1> {
    let at = receipt.generation();
    let read = |digest: Hash| store.read_generation_artifact(at, digest).ok().flatten();
    let committed = read(receipt.frontier_digest()).zip(read(receipt.invalidation_digest()));
    let interventions: Option<Vec<Vec<u8>>> = plan
        .interventions
        .iter()
        .map(|intervention| intervention.to_canonical_cbor().ok())
        .collect();
    let admitted = interventions.zip(plan.to_canonical_cbor().ok());
    admitted
        .zip(committed)
        .map(|((interventions, plan_bytes), (frontier, invalidation))| {
            interventions
                .into_iter()
                .map(|bytes| (ForkArtifactKindV1::Intervention, bytes))
                .chain([
                    (ForkArtifactKindV1::CounterfactualPlan, plan_bytes),
                    (ForkArtifactKindV1::RecomputationFrontier, frontier),
                    (ForkArtifactKindV1::SuffixInvalidation, invalidation),
                ])
                .chain(
                    run.checkpoints
                        .into_iter()
                        .map(|bytes| (ForkArtifactKindV1::Checkpoint, bytes)),
                )
                .chain([(ForkArtifactKindV1::Result, run.result)])
                .zip(0_u32..)
                .map(|((kind, bytes), artifact_ordinal)| ForkArtifactV1 {
                    kind,
                    coordinate: WorldCutArtifactCoordinateV1 {
                        world_cut_id: plan.parent_timeline_id,
                        cut_ordinal: plan.parent_cut_seq,
                        tick: plan.parent_cut_tick,
                        artifact_ordinal,
                    },
                    bytes,
                })
                .collect()
        })
        .ok_or(ForkRunErrorV1::Host)
}

/// The prefix read port over the store the coordinator takes afterwards.
struct PrefixReadsV1<'a>(&'a MemoryStore);

impl CounterfactualDependencyReadPortV1 for PrefixReadsV1<'_> {
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, CounterfactualStoreErrorV1> {
        self.0.read_dependency_nodes(request)
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, CounterfactualStoreErrorV1> {
        self.0.read_dependency_edges(request)
    }
}

/// The frontier `PrefixSeededFrontierSourceV1` derived before admission,
/// handed to the coordinator, which re-validates it.
///
/// Invariant: it was derived for the same plan, frontier id and provenance
/// digest the admission request carries; `execute` and `admit` take all
/// three from one plan and one fixture, so the arguments are not compared
/// again here.
struct AdmittedFrontierV1(CounterfactualFrontierDerivationV1);

impl CounterfactualFrontierSourceV1 for AdmittedFrontierV1 {
    fn derive_frontier(
        &mut self,
        _plan: &CounterfactualPlanV1,
        _frontier_id: [u8; 16],
        _provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, CounterfactualAdmissionErrorV1> {
        Ok(self.0.clone())
    }
}

/// The run's frozen closure holds no `ExogenousFrozen` or `FixedPolicy`
/// artifact (the records form stages no exogenous input), so every
/// descriptor is missing and the admission is refused with
/// `FrozenArtifactMissing`.
struct FrozenClosureV1;

impl CounterfactualFrozenArtifactsV1 for FrozenClosureV1 {
    fn availability(&self, _: &FrozenArtifactDescriptorV1) -> FrozenArtifactAvailabilityV1 {
        FrozenArtifactAvailabilityV1::Missing
    }
}

/// The host authorizes the fixture's Intervention, whose consent decision
/// the fixture carries.
struct HostAuthorityV1;

impl CounterfactualInterventionAuthorityV1 for HostAuthorityV1 {
    fn decide(&self, _: &InterventionV1) -> InterventionDecisionV1 {
        InterventionDecisionV1::Authorized
    }
}
