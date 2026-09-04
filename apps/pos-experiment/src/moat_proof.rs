//! Wave 8 parameterized proof kernel.
//!
//! The kernel composes the existing Tick Boundary host with the versioned
//! World plugin and two deliberately small, swappable proof Plugins. It is an
//! engineering evaluator for the user-parameterized Wave 8 fixture contract;
//! the public Gateway/client Scenario Room contract remains a Wave 9 concern.

use crate::{Experiment, ExperimentConfig, ExperimentError, ExperimentSession, StopCondition};
use pos_conformance::{
    compare, compare_authoritative_outputs, schema_id_for_event_type, verify_counterfactual_fork,
    verify_evidence, wave8_non_interference_matrix, wave8_plugin_boundary, AuthoritativeEventV1,
    CaseOutcomeStatusV1, CaseOutcomeV1, CausalTraceEntryV1, ClaimLayerV1, ComparisonV1,
    ConformanceReportV1, CounterfactualContractV1, DependencyClassV1, DependencyNodeV1,
    DivergenceClassV1, ExecutionModeV1, FixtureAuthorizationDecisionV1, FixtureCapabilityGrantV1,
    FixturePrincipalRefV1, HostClosureAuditV1, ImplementationIdentityV1, IndependenceEvidenceV1,
    InputDependencyV1, InterventionV1, InvalidArtifactV1, KnowledgeSnapshotV1, MoatProofEvidenceV1,
    MoatProofInputV1, ParticipantEventV1, ParticipantViewV1, PluginFailureClassV1, PluginFailureV1,
    ProjectionEvidenceV1, RecomputationFrontierV1, RedactionStateV1, ReplayClaimV1,
    ReproManifestV1, ReproducibilityClassV1, ScenarioRoomFixtureV1, SuffixInvalidationReasonV1,
    SuffixInvalidationV1, TickAtomicityV1, UncertaintyV1, UnknownEdgePolicyV1,
    Wave8ProofContractV1, EVIDENCE_FORMAT_V1,
};
use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, EventId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
};
use pos_plugin_society::{draft_signal, SocietyDimension, SocietyReducer, SocietySignal};
use pos_plugin_world::{
    ActionKindV1, Body, SimpleKinematicBackend, WorldActionV1, WorldConfigV1, WorldDriver,
    WorldPlugin, WorldReducer, ACTION_SCOPE_SINGLE_BODY, COORD_CONVENTION_RIGHT_HANDED_Y_UP,
    EVENT_TYPE_ACTION_V1, EVENT_TYPE_OBSERVATION_V1, SENSOR_MIN_RESOLUTION_MM,
};
use pos_runtime::{
    Driver, DriverRecoveryEvidence, ObservationView, RecoveryEventHeader, RuntimeError, StepOutput,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{atomic::AtomicU64, Arc};

// Keep fallible proof orchestration linear without the compiler-generated
// unmapped coverage regions introduced by repeated `?` propagation.
macro_rules! result_pipeline {
    (let mut $binding:ident = $value:expr_2021; $($remaining:tt)+) => {{
        let mut $binding = $value;
        result_pipeline!($($remaining)+)
    }};
    (let $binding:ident = $value:expr_2021; $($remaining:tt)+) => {{
        let $binding = $value;
        result_pipeline!($($remaining)+)
    }};
    ($result:expr_2021 => |$binding:pat_param|; $($remaining:tt)+) => {
        $result.and_then(|$binding| result_pipeline!($($remaining)+))
    };
    ($result:expr_2021 $(;)?) => {
        $result
    };
}

const AGENT_EVENT_TYPE: &str = "proof.agent.reaction.v1";
const AGENT_ENTITY_KIND: &str = "proof-agent";
const SOCIETY_ENTITY_KIND: &str = "proof-society";
const WORLD_BACKEND_CONTENT: &[u8] = b"PiglorOS.WorldBackend.simple-kinematic.v1";
const EXECUTION_PROFILE_CONTENT: &[u8] = b"PiglorOS.ExecutionProfile.deterministic-v1";
const TRUST_POLICY_CONTENT: &[u8] = b"PiglorOS.TrustPolicySnapshot.wave8-v1";
const HOST_SOURCE_CONTENT: &[u8] = include_bytes!("moat_proof.rs");
const EVALUATOR_CONTENT: &[u8] = include_bytes!("../../../crates/pos-reference/src/lib.rs");

/// Result of one Local or Air-Gapped proof execution.
#[derive(Debug)]
pub struct MoatProofReport {
    pub baseline: MoatProofEvidenceV1,
    pub counterfactual: MoatProofEvidenceV1,
    pub baseline_cbor: Vec<u8>,
    pub counterfactual_cbor: Vec<u8>,
    pub divergence: ComparisonV1,
    pub physical_reaction: GateStatus,
    pub agent_reaction: GateStatus,
    pub society_signal_changed: GateStatus,
    pub prefix_identical_through_fork: GateStatus,
    pub suffix_recomputed: GateStatus,
    pub failure_probes: Vec<PluginFailureV1>,
    pub host_closure: HostClosureAuditV1,
}

impl MoatProofReport {
    /// Whether the three observable reactions and causal evidence are present.
    #[must_use]
    pub fn passes_reaction_gates(&self) -> bool {
        self.physical_reaction == GateStatus::Passed
            && self.agent_reaction == GateStatus::Passed
            && self.society_signal_changed == GateStatus::Passed
            && self.prefix_identical_through_fork == GateStatus::Passed
            && self.suffix_recomputed == GateStatus::Passed
            && !self.baseline.causal_trace.is_empty()
            && !self.counterfactual.causal_trace.is_empty()
            && self.failure_probes.iter().all(|failure| !failure.committed)
            && self.failure_probes.len() == 2
            && self.host_closure.halted_at_tick_boundary
            && self.host_closure.effective_after_seq > self.host_closure.requested_after_seq
            && self.host_closure.closure_event_seq == self.host_closure.effective_after_seq
    }
}

/// One closed conformance-gate outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateStatus {
    /// The required behavior was observed.
    Passed,
    /// The required behavior was not observed.
    Failed,
}

impl From<bool> for GateStatus {
    fn from(value: bool) -> Self {
        if value {
            Self::Passed
        } else {
            Self::Failed
        }
    }
}

/// Run the parameterized proof kernel in one execution profile.
#[derive(Clone, Debug)]
pub struct MoatProofRun {
    input: MoatProofInputV1,
    mode: ExecutionModeV1,
}

impl MoatProofRun {
    /// Validate input and prepare a proof run.
    ///
    /// # Errors
    /// Returns the dependency-light input validation error.
    pub fn new(
        input: MoatProofInputV1,
        mode: ExecutionModeV1,
    ) -> Result<Self, pos_conformance::InputError> {
        input.validate()?;
        if input.network_enabled {
            return Err(if matches!(mode, ExecutionModeV1::AirGapped) {
                pos_conformance::InputError::NetworkNotAllowedInAirGapped
            } else {
                pos_conformance::InputError::NetworkNotAllowedInDeterministicProfile
            });
        }
        Ok(Self { input, mode })
    }

    /// Execute a baseline and one deterministic counterfactual Fork.
    ///
    /// # Errors
    /// Returns host, codec, or evidence construction failures.
    pub fn run(self) -> Result<MoatProofReport, MoatProofError> {
        let input = self.input;
        let mode = self.mode;
        result_pipeline! {
            failure_probes(input.resource_limit) => |failure_probes|;
            ProofTopology::new(input.clone()).map_err(MoatProofError::from) => |topology|;
            plugin_versions(&topology).map_err(MoatProofError::from) => |plugin_versions|;
            let factory_topology = topology.clone();
            let registry_factory = move || build_registry(&factory_topology);
            let mut experiment = Experiment::new(ExperimentConfig {
                name: format!("wave8-{}", input.scenario_id),
                stop: StopCondition::MaxTicks(input.ticks.saturating_add(1)),
                store_config: pos_store::StoreConfig::Memory,
            })
            .with_fork_registry_factory(registry_factory)
            .with_resource_limit(input.resource_limit);
            register_plugins(&mut experiment, &topology).map_err(MoatProofError::from) => |()|;
            experiment.start().map_err(MoatProofError::from) => |mut parent|;
            parent.step_tick().map_err(MoatProofError::from) => |_|;
            parent.source_events_with_control().map_err(MoatProofError::from) => |events|;
            events.last().map(|event| event.seq.as_u64()).ok_or(MoatProofError::MissingForkCut) => |fork_cut_seq|;
            parent.fork("counterfactual").map_err(MoatProofError::from) => |mut child|;
            intervention(topology.body, topology.agent, &input, 1) => |proposal|;
            child.submit_action(&proposal).map_err(MoatProofError::from) => |_seq|;
            finish(&mut parent).map_err(MoatProofError::from) => |()|;
            finish(&mut child).map_err(MoatProofError::from) => |()|;
            commit_host_closure(&mut parent, "proof-subject") => |host_closure|;
            commit_host_closure(&mut child, "proof-subject") => |counterfactual_host_closure|;
            parent.source_events_with_control().map_err(MoatProofError::from) => |baseline_events|;
            child.source_events_with_control().map_err(MoatProofError::from) => |counterfactual_events|;
            parent.run_to_completion().map_err(MoatProofError::from) => |parent_result|;
            child.run_to_completion().map_err(MoatProofError::from) => |child_result|;
            let suffix_audit_result =
                suffix_audit(&baseline_events, &counterfactual_events, fork_cut_seq);
            let prefix_identical_through_fork = suffix_audit_result.0;
            let suffix_recomputed = suffix_audit_result.1;
            evidence(&EvidenceContext {
                input: &input,
                mode,
                timeline_id: parent_result.timeline_id,
                fork_cut_seq: Some(fork_cut_seq),
                events: baseline_events.as_slice(),
                factual_events: baseline_events.as_slice(),
                projections: &parent_result.projections,
                topology: &topology,
                plugin_versions: &plugin_versions,
                failure_probes: &failure_probes,
                host_closure: &host_closure,
            }) => |baseline|;
            evidence(&EvidenceContext {
                input: &input,
                mode,
                timeline_id: child_result.timeline_id,
                fork_cut_seq: Some(fork_cut_seq),
                events: counterfactual_events.as_slice(),
                factual_events: baseline_events.as_slice(),
                projections: &child_result.projections,
                topology: &topology,
                plugin_versions: &plugin_versions,
                failure_probes: &failure_probes,
                host_closure: &counterfactual_host_closure,
            }) => |counterfactual|;
            verify_evidence(&baseline).map_err(MoatProofError::from) => |()|;
            verify_evidence(&counterfactual).map_err(MoatProofError::from) => |()|;
            verify_counterfactual_fork(&baseline, &counterfactual, EVENT_TYPE_ACTION_V1)
                .map_err(MoatProofError::from) => |()|;
            baseline.to_canonical_cbor().map_err(MoatProofError::from) => |baseline_cbor|;
            counterfactual.to_canonical_cbor().map_err(MoatProofError::from) => |counterfactual_cbor|;
            baseline.to_json().map_err(MoatProofError::from) => |baseline_json|;
            counterfactual.to_json().map_err(MoatProofError::from) => |counterfactual_json|;
            pos_reference::verify_fork_json(
                &baseline_json,
                &counterfactual_json,
                EVENT_TYPE_ACTION_V1,
            ).map_err(MoatProofError::from) => |()|;
            compare(&baseline, &counterfactual).map_err(MoatProofError::from) => |divergence|;
            verify_independent_fixture_reproduction(&baseline, &counterfactual, &divergence) => |()|;
            compare_with_reference(&baseline, &counterfactual, &divergence) => |()|;
            let physical_reaction = projection_changed(&baseline, &counterfactual, "world");
            let agent_reaction = projection_changed(&baseline, &counterfactual, "proof-agent");
            let society_signal_changed = projection_changed(&baseline, &counterfactual, "society");
            let report = MoatProofReport {
                baseline,
                counterfactual,
                baseline_cbor,
                counterfactual_cbor,
                divergence,
                physical_reaction: physical_reaction.into(),
                agent_reaction: agent_reaction.into(),
                society_signal_changed: society_signal_changed.into(),
                prefix_identical_through_fork: prefix_identical_through_fork.into(),
                suffix_recomputed: suffix_recomputed.into(),
                failure_probes,
                host_closure,
            };
            report
                .passes_reaction_gates()
                .then_some(report)
                .ok_or(MoatProofError::ReactionGatesFailed)
        }
    }
}

/// Run the same input through Local and Air-Gapped profiles.
///
/// The profiles share only the declarative input; the returned comparison is
/// made by the independent conformance crate and ignores the profile label
/// while requiring equal authoritative and projection evidence.
///
/// # Errors
/// Returns input validation, host execution, codec, or proof-probe errors.
pub fn run_local_and_air_gapped(
    input: MoatProofInputV1,
) -> Result<(MoatProofReport, MoatProofReport, ComparisonV1), MoatProofError> {
    result_pipeline! {
        MoatProofRun::new(input.clone(), ExecutionModeV1::Local)
            .map_err(MoatProofError::from) => |local_run|;
        local_run.run() => |local|;
        MoatProofRun::new(input, ExecutionModeV1::AirGapped)
            .map_err(MoatProofError::from) => |air_gapped_run|;
        air_gapped_run.run() => |air_gapped|;
        compare_authoritative_outputs(&local.baseline, &air_gapped.baseline)
            .map_err(MoatProofError::from) => |comparison|;
        let left_digest = comparison.left_digest;
        let right_digest = comparison.right_digest;
        comparison.equal.then_some(())
            .ok_or(MoatProofError::ExecutionModesDiverged(comparison)) => |()|;
        compare_authoritative_outputs(&local.counterfactual, &air_gapped.counterfactual)
            .map_err(MoatProofError::from) => |counterfactual_comparison|;
        counterfactual_comparison.equal.then_some(())
            .ok_or(MoatProofError::ExecutionModesDiverged(counterfactual_comparison)) => |()|;
        Ok((
            local,
            air_gapped,
            pos_conformance::ComparisonV1 {
                equal: true,
                divergence: DivergenceClassV1::None,
                left_digest,
                right_digest,
            },
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MoatProofError {
    #[error("invalid proof input: {0}")]
    Input(#[from] pos_conformance::InputError),
    #[error("experiment failed: {0}")]
    Experiment(#[from] ExperimentError),
    #[error("runtime failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("world action encoding failed: {0}")]
    WorldCodec(#[from] pos_plugin_world::WorldCodecError),
    #[error("world action parameter encoding failed: {0}")]
    ActionParams(String),
    #[error("fork cut has no committed events")]
    MissingForkCut,
    #[error("proof evidence failed independent verification: {0}")]
    Evidence(#[from] pos_conformance::EvidenceError),
    #[error("proof evidence JSON export failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("proof evidence canonical-CBOR export failed: {0}")]
    CanonicalCbor(#[from] pos_core::CoreError),
    #[error("independent reference evaluator failed: {0}")]
    Reference(#[from] pos_reference::ReferenceError),
    #[error("independent reference evaluator classified a different divergence")]
    ReferenceDivergenceMismatch,
    #[error("Local and Air-Gapped proof artifacts diverged: {0:?}")]
    ExecutionModesDiverged(ComparisonV1),
    #[error("Wave 8 reaction and atomicity conformance gates failed")]
    ReactionGatesFailed,
    #[error("consent-revoked session accepted a post-revocation append")]
    ConsentAppendAccepted,
    #[error("consent probe did not commit its host-owned closure marker")]
    ConsentMarkerMissing,
}

fn compare_with_reference(
    baseline: &MoatProofEvidenceV1,
    counterfactual: &MoatProofEvidenceV1,
    expected: &ComparisonV1,
) -> Result<(), MoatProofError> {
    result_pipeline! {
        baseline.to_json().map_err(MoatProofError::from) => |baseline_json|;
        counterfactual.to_json().map_err(MoatProofError::from) => |counterfactual_json|;
        pos_reference::compare_json(&baseline_json, &counterfactual_json)
            .map_err(MoatProofError::from) => |reference|;
        let divergence = match reference.divergence {
            pos_reference::ReferenceDivergenceV1::Equal => DivergenceClassV1::None,
            pos_reference::ReferenceDivergenceV1::Metadata => DivergenceClassV1::Metadata,
            pos_reference::ReferenceDivergenceV1::AuthoritativeEvents => {
                DivergenceClassV1::AuthoritativeEvents
            }
            pos_reference::ReferenceDivergenceV1::Projections => DivergenceClassV1::Projections,
            pos_reference::ReferenceDivergenceV1::CausalTrace => DivergenceClassV1::CausalTrace,
            pos_reference::ReferenceDivergenceV1::Observability => DivergenceClassV1::Observability,
        };
        (divergence == expected.divergence)
            .then_some(())
            .ok_or(MoatProofError::ReferenceDivergenceMismatch)
    }
}

fn verify_independent_fixture_reproduction(
    baseline: &MoatProofEvidenceV1,
    counterfactual: &MoatProofEvidenceV1,
    expected: &ComparisonV1,
) -> Result<(), MoatProofError> {
    result_pipeline! {
        baseline.to_json().map_err(MoatProofError::from) => |baseline_json|;
        pos_reference::reproduce_fixture_json(&baseline_json)
            .map_err(MoatProofError::from) => |independent_baseline|;
        counterfactual.to_json().map_err(MoatProofError::from) => |counterfactual_json|;
        pos_reference::reproduce_fixture_json(&counterfactual_json)
            .map_err(MoatProofError::from) => |independent_counterfactual|;
        ((independent_baseline == independent_counterfactual) == expected.equal)
            .then_some(())
            .ok_or(MoatProofError::ReferenceDivergenceMismatch)
    }
}

fn fixed_id(value: u128) -> EntityId {
    EntityId::from_ulid(ulid::Ulid::from(value))
}

fn room_entity(input_digest: &[u8; 32], slot: u8) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.wave8.fixture.entity.v1");
    hasher.update(input_digest);
    hasher.update(&[slot]);
    let digest = hasher.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(bytes)))
}

fn finish(session: &mut ExperimentSession) -> Result<(), ExperimentError> {
    loop {
        if matches!(session.step_tick()?, crate::TickOutcome::Stopped) {
            return Ok(());
        }
    }
}

fn intervention(
    body: EntityId,
    actor: EntityId,
    input: &MoatProofInputV1,
    tick: u64,
) -> Result<pos_core::ProposedAction, MoatProofError> {
    let mut params = Vec::new();
    result_pipeline! {
        ciborium::into_writer(&input.fork_velocity.to_vec(), &mut params)
            .map_err(|error| MoatProofError::ActionParams(error.to_string())) => |()|;
        let action = WorldActionV1 {
            actor_entity_id: actor,
            body_entity_id: body,
            action_kind: ActionKindV1::TargetVelocity,
            params_cbor: params,
            action_scope: ACTION_SCOPE_SINGLE_BODY,
            catalogue_version: 1,
            tick,
        };
        action.encode().map_err(MoatProofError::from) => |payload|;
        Ok(pos_core::ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION_V1),
            actor,
            payload,
            Kind::new("world.action.v1.submit"),
        ))
    }
}

#[derive(Clone)]
struct ProofTopology {
    input: MoatProofInputV1,
    input_digest: [u8; 32],
    body: EntityId,
    agent: EntityId,
    society: EntityId,
    config_entity: EntityId,
    world_plugin: WorldPlugin,
    agent_plugin: ProofAgentPlugin,
    society_plugin: ProofSocietyPlugin,
}

impl ProofTopology {
    fn new(input: MoatProofInputV1) -> Result<Self, pos_core::CoreError> {
        input.digest().map(|input_digest| {
            let body = room_entity(&input_digest, 1);
            let agent = room_entity(&input_digest, 2);
            let society = room_entity(&input_digest, 3);
            let config_entity = room_entity(&input_digest, 4);
            Self {
                input,
                input_digest,
                body,
                agent,
                society,
                config_entity,
                world_plugin: WorldPlugin::new().with_bodies([body]),
                agent_plugin: ProofAgentPlugin::new(),
                society_plugin: ProofSocietyPlugin::new(),
            }
        })
    }
}

fn register_plugins(
    experiment: &mut Experiment,
    topology: &ProofTopology,
) -> Result<(), RuntimeError> {
    result_pipeline! {
        experiment.register_with_approver(
            &topology.world_plugin,
            Some(Box::new(WorldReducer)),
            Some(Box::new(world_driver(
                &topology.input,
                topology.body,
                topology.config_entity,
            ))),
            Some(Box::new(topology.world_plugin.clone())),
            [Kind::new(EVENT_TYPE_ACTION_V1)],
        ) => |()|;
        experiment.register(
            &topology.agent_plugin,
            Some(Box::new(ProofAgentReducer)),
            Some(Box::new(ProofAgentDriver::new(
                topology.agent,
                topology.input.agent_response_threshold,
            ))),
        ) => |()|;
        experiment.register(
            &topology.society_plugin,
            Some(Box::new(SocietyReducer)),
            Some(Box::new(ProofSocietyDriver::new(topology.society))),
        )
    }
}

fn build_registry(topology: &ProofTopology) -> Result<pos_runtime::PluginRegistry, RuntimeError> {
    let mut registry =
        pos_runtime::PluginRegistry::new().with_resource_limit(topology.input.resource_limit);
    result_pipeline! {
        registry.register_with_approver(
            &topology.world_plugin,
            Some(Box::new(WorldReducer)),
            Some(Box::new(world_driver(
                &topology.input,
                topology.body,
                topology.config_entity,
            ))),
            Some(Box::new(topology.world_plugin.clone())),
            [Kind::new(EVENT_TYPE_ACTION_V1)],
        ) => |()|;
        registry.register(
            &topology.agent_plugin,
            Some(Box::new(ProofAgentReducer)),
            Some(Box::new(ProofAgentDriver::new(
                topology.agent,
                topology.input.agent_response_threshold,
            ))),
        ) => |()|;
        registry.register(
            &topology.society_plugin,
            Some(Box::new(SocietyReducer)),
            Some(Box::new(ProofSocietyDriver::new(topology.society))),
        ) => |()|;
        Ok(registry)
    }
}

fn world_driver(input: &MoatProofInputV1, body: EntityId, config_entity: EntityId) -> WorldDriver {
    WorldDriver::new(
        vec![Body {
            entity_id: body,
            x: input.initial_position[0],
            y: input.initial_position[1],
            vx: input.initial_velocity[0],
            vy: input.initial_velocity[1],
        }],
        Box::new(SimpleKinematicBackend::new()),
        WorldConfigV1 {
            timestep_micros: 16_667,
            coord_convention: COORD_CONVENTION_RIGHT_HANDED_Y_UP,
            gravity_x: 0.0,
            gravity_y: 0.0,
            gravity_z: 0.0,
            backend_id: "simple-kinematic".to_owned(),
            backend_version: "1.0.0".to_owned(),
            backend_content_hash: *blake3::hash(WORLD_BACKEND_CONTENT).as_bytes(),
            action_schema_version: 1,
            observation_schema_version: 1,
            sensor_min_resolution_mm: SENSOR_MIN_RESOLUTION_MM,
            actuator_catalogue_version: 1,
        },
    )
    .with_config_entity(config_entity)
}

fn payload_digest(event: &Event) -> [u8; 32] {
    *blake3::hash(event.payload.as_slice()).as_bytes()
}

fn authoritative_events(events: &[Event]) -> Vec<AuthoritativeEventV1> {
    let ids = events
        .iter()
        .map(|event| (event.id, event.seq.as_u64()))
        .collect::<HashMap<_, _>>();
    events
        .iter()
        .map(|event| AuthoritativeEventV1 {
            seq: event.seq.as_u64(),
            tick: event_tick(event, events),
            entity: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            payload_digest: payload_digest(event),
            causation_seq: event.causation_id.and_then(|id| ids.get(&id).copied()),
        })
        .collect()
}

struct EvidenceContext<'a> {
    input: &'a MoatProofInputV1,
    mode: ExecutionModeV1,
    timeline_id: TimelineId,
    fork_cut_seq: Option<u64>,
    events: &'a [Event],
    factual_events: &'a [Event],
    projections: &'a pos_state::ProjectionRegistry,
    topology: &'a ProofTopology,
    plugin_versions: &'a BTreeMap<String, String>,
    failure_probes: &'a [PluginFailureV1],
    host_closure: &'a HostClosureAuditV1,
}

fn evidence(context: &EvidenceContext<'_>) -> Result<MoatProofEvidenceV1, MoatProofError> {
    let input = context.input;
    let mode = context.mode;
    let fork_cut_seq = context.fork_cut_seq;
    let events = context.events;
    let factual_events = context.factual_events;
    let projections = context.projections;
    let topology = context.topology;
    let plugin_versions = context.plugin_versions;
    let failure_probes = context.failure_probes;
    let host_closure = context.host_closure;
    let ids = events
        .iter()
        .map(|event| (event.id, event.seq.as_u64()))
        .collect::<HashMap<_, _>>();
    let event_summaries = authoritative_events(events);
    let factual_authoritative_events = authoritative_events(factual_events);
    let mut projection_evidence = Vec::new();
    for (name, entity) in [
        ("world", topology.body),
        (AGENT_ENTITY_KIND, topology.agent),
        (SOCIETY_NAME, topology.society),
    ] {
        if let Some(state) = projections.state_for_reducer(name, &entity) {
            projection_evidence.push(ProjectionEvidenceV1 {
                reducer: name.to_owned(),
                entity: entity.to_string(),
                state: serde_json::to_value(state)?,
            });
        }
    }
    let causal_trace = causal_trace(events, &ids);
    let uncertainty = uncertainty_from_events(events);
    let participant_views = participant_views(events);
    let contract = build_wave8_contract(
        context,
        &event_summaries,
        &factual_authoritative_events,
        &participant_views,
    );
    Ok(MoatProofEvidenceV1 {
        format_version: EVIDENCE_FORMAT_V1,
        manifest: ReproManifestV1 {
            format_version: EVIDENCE_FORMAT_V1,
            input_digest: topology.input_digest,
            execution_mode: mode,
            fork_cut_seq,
            seed: input.random_seed,
            resource_limit: input.resource_limit,
            network_enabled: input.network_enabled,
            reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
            execution_profile: "deterministic-v1".to_owned(),
            execution_profile_digest: profile_digest(),
            trust_policy_snapshot_digest: digest_domain(
                b"PiglorOS.TrustPolicySnapshot.v1",
                TRUST_POLICY_CONTENT,
            ),
            artifact_closure_digest: artifact_closure_digest(topology),
            evaluator_digest: digest_domain(b"PiglorOS.Evaluator.v1", EVALUATOR_CONTENT),
            replay_claim: ReplayClaimV1::Exact,
            plugin_versions: plugin_versions.clone(),
            scenario_room_digest: contract.scenario_room.room_digest,
            scheduler_digest: scheduler_digest(),
            budget_digest: budget_digest(input.resource_limit),
        },
        authoritative_events: event_summaries,
        projections: projection_evidence,
        causal_trace,
        uncertainty,
        participant_views,
        plugin_failures: failure_probes.to_vec(),
        host_closure: host_closure.clone(),
        contract,
    })
}

fn causal_trace(events: &[Event], ids: &HashMap<EventId, u64>) -> Vec<CausalTraceEntryV1> {
    events
        .iter()
        .filter_map(|event| {
            event.causation_id.and_then(|cause| {
                ids.get(&cause).map(|cause_seq| {
                    let cause_type = events
                        .iter()
                        .find(|candidate| candidate.seq.as_u64() == *cause_seq)
                        .map_or("", |candidate| candidate.event_type.as_str());
                    CausalTraceEntryV1 {
                        cause_seq: *cause_seq,
                        effect_seq: event.seq.as_u64(),
                        relation: causal_relation(cause_type, event.event_type.as_str()),
                        visibility: causal_visibility(event.event_type.as_str()),
                        dependency_class: dependency_class(event.event_type.as_str()),
                    }
                })
            })
        })
        .collect()
}

fn causal_visibility(event_type: &str) -> String {
    match event_type {
        AGENT_EVENT_TYPE => "participant",
        pos_plugin_society::EVENT_TYPE_SIGNAL => "public",
        _ => "operator",
    }
    .to_owned()
}

const SOCIETY_NAME: &str = "society";

fn participant_views(events: &[Event]) -> Vec<ParticipantViewV1> {
    [
        ("proof-agent", &[EVENT_TYPE_OBSERVATION_V1][..]),
        (
            "society",
            &[AGENT_EVENT_TYPE, pos_plugin_society::EVENT_TYPE_SIGNAL][..],
        ),
    ]
    .into_iter()
    .map(|(participant, visible)| {
        let all_types = events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<BTreeSet<_>>();
        let visible_types = visible
            .iter()
            .filter(|event_type| all_types.contains(**event_type))
            .map(|event_type| (*event_type).to_owned())
            .collect::<Vec<_>>();
        let hidden_types = all_types
            .iter()
            .filter(|event_type| !visible.contains(event_type))
            .map(|event_type| (*event_type).to_owned())
            .collect::<Vec<_>>();
        ParticipantViewV1 {
            participant: participant.to_owned(),
            visible_event_types: visible_types.clone(),
            hidden_event_types: hidden_types,
            visible_events: events
                .iter()
                .filter(|event| {
                    visible_types
                        .iter()
                        .any(|kind| kind == event.event_type.as_str())
                })
                .map(|event| ParticipantEventV1 {
                    seq: event.seq.as_u64(),
                    event_type: event.event_type.as_str().to_owned(),
                    payload_digest: payload_digest(event),
                })
                .collect(),
        }
    })
    .collect()
}

fn causal_relation(cause_type: &str, effect_type: &str) -> String {
    match (cause_type, effect_type) {
        (EVENT_TYPE_ACTION_V1, EVENT_TYPE_OBSERVATION_V1) => "intervention_to_physics",
        (EVENT_TYPE_OBSERVATION_V1, AGENT_EVENT_TYPE) => "physical_to_agent",
        (AGENT_EVENT_TYPE, pos_plugin_society::EVENT_TYPE_SIGNAL) => "agent_to_society",
        _ => "derived",
    }
    .to_owned()
}

fn dependency_class(event_type: &str) -> DependencyClassV1 {
    if event_type == EVENT_TYPE_ACTION_V1 {
        DependencyClassV1::InterventionAssigned
    } else {
        DependencyClassV1::EndogenousRecomputed
    }
}

fn digest_domain(domain: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

fn profile_digest() -> [u8; 32] {
    digest_domain(EXECUTION_PROFILE_CONTENT, b"profile-v1")
}

fn artifact_closure_digest(topology: &ProofTopology) -> [u8; 32] {
    let mut bytes = Vec::new();
    for (name, version) in [
        ("world", "1.0.0"),
        ("proof-agent", "1.0.0"),
        ("society", "1.0.0"),
    ] {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(version.as_bytes());
        bytes.push(0);
    }
    bytes.extend_from_slice(&topology.input_digest);
    bytes.extend_from_slice(blake3::hash(WORLD_BACKEND_CONTENT).as_bytes());
    bytes.extend_from_slice(blake3::hash(EXECUTION_PROFILE_CONTENT).as_bytes());
    bytes.extend_from_slice(blake3::hash(TRUST_POLICY_CONTENT).as_bytes());
    bytes.extend_from_slice(blake3::hash(EVALUATOR_CONTENT).as_bytes());
    digest_domain(b"PiglorOS.ArtifactClosure.v1", &bytes)
}

fn scheduler_digest() -> [u8; 32] {
    digest_domain(
        b"PiglorOS.SchedulerComposition.v1",
        b"world:0\0proof-agent:1\0society:2\0host:3\0",
    )
}

fn budget_digest(resource_limit: u64) -> [u8; 32] {
    digest_domain(
        b"PiglorOS.DeterministicBudget.v1",
        &resource_limit.to_be_bytes(),
    )
}

fn serialized_digest<T: Serialize>(value: &T) -> [u8; 32] {
    pos_crypto::canonical::encode(value).map_or([0; 32], |bytes| {
        digest_domain(b"PiglorOS.Wave8.ContractValue.v1", bytes.as_slice())
    })
}

fn id16_digest(value: &[u8; 32]) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&value[..16]);
    id
}

fn event_tick(event: &Event, events: &[Event]) -> u64 {
    fn resolve(event: &Event, events: &[Event], seen: &mut HashSet<EventId>) -> u64 {
        if !seen.insert(event.id) {
            return event.seq.as_u64();
        }
        match event.event_type.as_str() {
            EVENT_TYPE_ACTION_V1 => WorldActionV1::decode(&event.payload)
                .map_or(event.seq.as_u64(), |action| action.tick),
            EVENT_TYPE_OBSERVATION_V1 => {
                pos_plugin_world::WorldObservationV1::decode(&event.payload)
                    .map_or(event.seq.as_u64(), |observation| observation.tick)
            }
            AGENT_EVENT_TYPE => serde_json::from_slice::<AgentReaction>(event.payload.as_slice())
                .map_or(event.seq.as_u64(), |reaction| reaction.tick),
            _ => event
                .causation_id
                .and_then(|cause| events.iter().find(|candidate| candidate.id == cause))
                .map_or(event.seq.as_u64(), |cause| resolve(cause, events, seen)),
        }
    }

    resolve(event, events, &mut HashSet::new())
}

fn event_node(event: &AuthoritativeEventV1) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick: event.tick,
        scheduler_position: match event.event_type.as_str() {
            EVENT_TYPE_ACTION_V1 => 0,
            EVENT_TYPE_OBSERVATION_V1 => 1,
            AGENT_EVENT_TYPE => 2,
            pos_plugin_society::EVENT_TYPE_SIGNAL => 3,
            _ => 4,
        },
        owner_id: event.entity.clone(),
        output_ordinal: 0,
        schema_id: schema_id_for_event_type(&event.event_type),
        artifact_digest: event.payload_digest,
    }
}

fn event_nodes<F>(
    events: &[AuthoritativeEventV1],
    include: F,
    cut: Option<u64>,
) -> BTreeMap<u64, DependencyNodeV1>
where
    F: Fn(&str) -> bool,
{
    let mut ordinals = BTreeMap::<(u64, u32, String, u32), u32>::new();
    let mut nodes = BTreeMap::new();
    for event in events.iter().filter(|event| {
        include(event.event_type.as_str()) && cut.is_none_or(|value| event.seq > value)
    }) {
        let mut node = event_node(event);
        let key = (
            node.tick,
            node.scheduler_position,
            node.owner_id.clone(),
            node.schema_id,
        );
        node.output_ordinal = *ordinals
            .entry(key)
            .and_modify(|value| *value += 1)
            .or_default();
        nodes.insert(event.seq, node);
    }
    nodes
}

fn zero_node() -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick: 0,
        scheduler_position: 0,
        owner_id: "scenario-room".to_owned(),
        output_ordinal: 0,
        schema_id: schema_id_for_event_type("scenario.input.v1"),
        artifact_digest: [0; 32],
    }
}

struct ContractRoomParts {
    room: ScenarioRoomFixtureV1,
    principals: Vec<FixturePrincipalRefV1>,
    grants: Vec<FixtureCapabilityGrantV1>,
    exogenous_digest: [u8; 32],
}

fn build_room_parts(
    input: &MoatProofInputV1,
    input_digest: [u8; 32],
    participant_views: &[ParticipantViewV1],
    host_closure: &HostClosureAuditV1,
    policy_digest: [u8; 32],
) -> ContractRoomParts {
    let consent_epoch =
        u64::from(host_closure.closure_event_seq > host_closure.requested_after_seq);
    let exogenous_digest = digest_domain(
        b"PiglorOS.ScenarioRoom.Exogenous.v1",
        &input
            .initial_position
            .iter()
            .chain(input.initial_velocity.iter())
            .flat_map(|value| value.to_bits().to_be_bytes())
            .collect::<Vec<_>>(),
    );
    let principals = participant_views
        .iter()
        .map(|view| FixturePrincipalRefV1 {
            principal_id: format!("principal:{}", view.participant),
            participant_id: view.participant.clone(),
            subject_id: (view.participant == "proof-agent").then(|| "proof-subject".to_owned()),
            trust_domain: "pigloros.local".to_owned(),
        })
        .collect::<Vec<_>>();
    let grants = principals
        .iter()
        .map(|principal| FixtureCapabilityGrantV1 {
            grant_id: format!("grant:{}", principal.participant_id),
            principal_id: principal.principal_id.clone(),
            capability: "observe:authorized-snapshot".to_owned(),
            resource: "scenario-room".to_owned(),
            consent_epoch: if principal.subject_id.as_deref() == Some(host_closure.subject.as_str())
            {
                consent_epoch
            } else {
                0
            },
            policy_digest,
        })
        .collect::<Vec<_>>();
    let mut room = ScenarioRoomFixtureV1 {
        room_id: input.scenario_id.clone(),
        input_digest,
        horizon_ticks: input.ticks,
        random_seed: input.random_seed,
        network_enabled: input.network_enabled,
        exogenous_digests: vec![exogenous_digest],
        fixed_policy_digests: vec![policy_digest, scheduler_digest()],
        principals: principals.clone(),
        grants: grants.clone(),
        room_digest: [0; 32],
    };
    room.room_digest = serialized_digest(&room);
    ContractRoomParts {
        room,
        principals,
        grants,
        exogenous_digest,
    }
}

fn build_knowledge_snapshots(
    input: &MoatProofInputV1,
    participant_views: &[ParticipantViewV1],
    principals: &[FixturePrincipalRefV1],
    grants: &[FixtureCapabilityGrantV1],
) -> (
    Vec<KnowledgeSnapshotV1>,
    Vec<FixtureAuthorizationDecisionV1>,
) {
    let knowledge_snapshots = participant_views
        .iter()
        .zip(principals.iter().zip(grants.iter()))
        .map(|(view, (principal, grant))| {
            let visible_event_seqs = view.visible_events.iter().map(|event| event.seq).collect();
            let visible_event_digests = view
                .visible_events
                .iter()
                .map(|event| event.payload_digest)
                .collect::<Vec<_>>();
            let revoked = grant.consent_epoch > 0;
            let mut decision = FixtureAuthorizationDecisionV1 {
                principal_id: principal.principal_id.clone(),
                resource: "scenario-room".to_owned(),
                operation: "observe".to_owned(),
                allowed: !revoked,
                reason: if revoked {
                    "consent-revoked-at-tick-boundary".to_owned()
                } else {
                    "capability-consent-policy-match".to_owned()
                },
                consent_epoch: grant.consent_epoch,
                grant_digest: serialized_digest(grant),
                decision_digest: [0; 32],
            };
            decision.decision_digest = serialized_digest(&decision);
            let mut snapshot = KnowledgeSnapshotV1 {
                participant_id: view.participant.clone(),
                principal: principal.clone(),
                grant: grant.clone(),
                authorization: decision,
                tick: input.ticks,
                visible_event_seqs,
                visible_event_digests,
                hidden_event_types: view.hidden_event_types.clone(),
                consent_epoch: grant.consent_epoch,
                snapshot_digest: [0; 32],
            };
            snapshot.snapshot_digest = serialized_digest(&snapshot);
            snapshot
        })
        .collect::<Vec<_>>();
    let authorization_decisions = knowledge_snapshots
        .iter()
        .map(|snapshot| snapshot.authorization.clone())
        .collect::<Vec<_>>();
    (knowledge_snapshots, authorization_decisions)
}

fn build_dependencies(
    events: &[AuthoritativeEventV1],
    policy_digest: [u8; 32],
) -> (BTreeMap<u64, DependencyNodeV1>, Vec<InputDependencyV1>) {
    let event_by_seq = events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    let current_nodes = event_nodes(events, is_contract_event, None);
    let source_node = zero_node();
    let mut dependencies = events
        .iter()
        .filter(|event| is_contract_event(event.event_type.as_str()))
        .map(|event| {
            let consumer = current_nodes[&event.seq].clone();
            let source = event
                .causation_seq
                .and_then(|seq| event_by_seq.get(&seq).copied())
                .filter(|event| is_contract_event(event.event_type.as_str()))
                .and_then(|event| current_nodes.get(&event.seq).cloned())
                .unwrap_or_else(|| source_node.clone());
            InputDependencyV1 {
                consumer,
                source,
                dependency_class: dependency_class(event.event_type.as_str()),
                authorization_digest: policy_digest,
                provenance_digest: serialized_digest(event),
            }
        })
        .collect::<Vec<_>>();
    dependencies.sort_by(|left, right| {
        (&left.consumer, &left.source.artifact_digest)
            .cmp(&(&right.consumer, &right.source.artifact_digest))
    });
    (current_nodes, dependencies)
}

struct CounterfactualParts {
    dependencies: Vec<InputDependencyV1>,
    intervention_event: Option<AuthoritativeEventV1>,
    intervention: Option<InterventionV1>,
    affected_nodes: Vec<DependencyNodeV1>,
    frontier: RecomputationFrontierV1,
}

fn build_counterfactual_parts(
    input: &MoatProofInputV1,
    fork_cut_seq: Option<u64>,
    events: &[AuthoritativeEventV1],
    factual_events: &[AuthoritativeEventV1],
    policy_digest: [u8; 32],
) -> CounterfactualParts {
    let (current_nodes, dependencies) = build_dependencies(events, policy_digest);
    let factual_nodes = event_nodes(factual_events, is_endogenous_event, fork_cut_seq)
        .into_values()
        .collect::<Vec<_>>();
    let intervention_event = events
        .iter()
        .find(|event| {
            event.event_type == EVENT_TYPE_ACTION_V1
                && fork_cut_seq.is_some_and(|cut| event.seq > cut)
        })
        .cloned();
    let intervention = intervention_event.as_ref().map(|event| {
        let identity = digest_domain(b"PiglorOS.Intervention.v1", &event.payload_digest);
        InterventionV1 {
            intervention_id: id16_digest(&identity),
            target: event.entity.clone(),
            operation: "world.target_velocity".to_owned(),
            value_digest: event.payload_digest,
            effective_tick: event.tick,
            ordinal: 0,
            principal_id: "principal:operator".to_owned(),
            capability: "intervene:world-body".to_owned(),
            consent_epoch: 0,
            provenance_digest: serialized_digest(event),
        }
    });
    let mut affected_nodes = intervention_event.as_ref().map_or_else(Vec::new, |event| {
        factual_nodes
            .iter()
            .filter(|node| node.tick >= event.tick)
            .cloned()
            .collect::<Vec<_>>()
    });
    affected_nodes.sort_unstable();
    let parent_cut_digest = serialized_digest(
        &factual_events
            .iter()
            .filter(|event| fork_cut_seq.is_some_and(|cut| event.seq <= cut))
            .collect::<Vec<_>>(),
    );
    let plan_digest = digest_domain(
        b"PiglorOS.CounterfactualPlan.v1",
        &[
            input.digest().unwrap_or([0; 32]).as_slice(),
            parent_cut_digest.as_slice(),
            intervention
                .as_ref()
                .map_or(&[0; 32], |value| &value.value_digest)
                .as_slice(),
        ]
        .concat(),
    );
    let global_frontier_tick = affected_nodes.first().map_or(0, |node| node.tick);
    let global_frontier_scheduler_position = affected_nodes
        .first()
        .map_or(0, |node| node.scheduler_position);
    let mut frontier = RecomputationFrontierV1 {
        frontier_id: id16_digest(&plan_digest),
        plan_digest,
        parent_cut_digest,
        dependency_graph_digest: serialized_digest(&dependencies),
        intervention_seed_nodes: intervention_event
            .as_ref()
            .and_then(|event| current_nodes.get(&event.seq).cloned())
            .map(|node| vec![node])
            .unwrap_or_default(),
        affected_nodes: affected_nodes.clone(),
        owner_frontiers: owner_frontiers(&affected_nodes),
        global_frontier_tick,
        global_frontier_scheduler_position,
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
        unknown_edge_coordinates: Vec::new(),
        endogenous_suffix_end_tick: affected_nodes
            .last()
            .map_or(global_frontier_tick, |node| node.tick),
        classification_bundle_digest: policy_digest,
        provenance_digest: serialized_digest(&dependencies),
        frontier_digest: [0; 32],
    };
    frontier.frontier_digest = serialized_digest(&frontier);
    CounterfactualParts {
        dependencies,
        intervention_event,
        intervention,
        affected_nodes,
        frontier,
    }
}

fn build_counterfactual_contract(
    input: &MoatProofInputV1,
    timeline_id: TimelineId,
    fork_cut_seq: Option<u64>,
    events: &[AuthoritativeEventV1],
    factual_events: &[AuthoritativeEventV1],
    policy_digest: [u8; 32],
    exogenous_digest: [u8; 32],
) -> CounterfactualContractV1 {
    let parts =
        build_counterfactual_parts(input, fork_cut_seq, events, factual_events, policy_digest);
    let fork_id = id16_digest(&digest_domain(
        b"PiglorOS.Fork.v1",
        &input.digest().unwrap_or([0; 32]),
    ));
    let invalid_start = parts
        .affected_nodes
        .first()
        .cloned()
        .unwrap_or_else(zero_node);
    let invalid_end = parts
        .affected_nodes
        .last()
        .cloned()
        .unwrap_or_else(|| invalid_start.clone());
    let invalid_artifacts = parts
        .intervention
        .as_ref()
        .map(|_| {
            parts
                .affected_nodes
                .iter()
                .map(|node| InvalidArtifactV1 {
                    artifact_class: "endogenous-event".to_owned(),
                    schema_id: node.schema_id,
                    artifact_digest: node.artifact_digest,
                    producer: node.clone(),
                    prior_generation: 0,
                    reason: SuffixInvalidationReasonV1::NewIntervention,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut invalidation = SuffixInvalidationV1 {
        invalidation_id: id16_digest(&digest_domain(
            b"PiglorOS.SuffixInvalidation.v1",
            &parts.frontier.frontier_digest,
        )),
        plan_digest: parts.frontier.plan_digest,
        fork_id,
        prior_generation: 0,
        new_generation: u64::from(parts.intervention.is_some()),
        frontier_digest: parts.frontier.frontier_digest,
        invalid_start,
        invalid_end,
        invalid_artifacts,
        invalid_checkpoint_digests: Vec::new(),
        invalid_projection_digests: Vec::new(),
        retained_exogenous_digests: vec![exogenous_digest],
        reason: if parts.intervention.is_some() {
            SuffixInvalidationReasonV1::NewIntervention
        } else {
            SuffixInvalidationReasonV1::TrustOrErasureChange
        },
        commit_timeline_id: timeline_id.inner().to_bytes(),
        commit_tick: parts.frontier.global_frontier_tick,
        commit_seq: parts
            .intervention_event
            .as_ref()
            .map_or_else(|| fork_cut_seq.unwrap_or(0), |event| event.seq),
        provenance_digest: serialized_digest(&parts.frontier),
        invalidation_digest: [0; 32],
    };
    invalidation.invalidation_digest = serialized_digest(&invalidation);
    let mut recomputed_event_seqs =
        parts
            .intervention_event
            .as_ref()
            .map_or_else(Vec::new, |event| {
                events
                    .iter()
                    .filter(|candidate| {
                        candidate.seq > event.seq
                            && is_endogenous_event(candidate.event_type.as_str())
                    })
                    .map(|event| event.seq)
                    .collect()
            });
    recomputed_event_seqs.sort_unstable();
    let mut counterfactual = CounterfactualContractV1 {
        fork_id,
        prior_generation: 0,
        generation: u64::from(parts.intervention.is_some()),
        intervention: parts.intervention,
        dependencies: parts.dependencies,
        frontier: parts.frontier,
        invalidation,
        recomputed_event_seqs,
        retained_exogenous_digests: vec![exogenous_digest],
        replay_claim: ReplayClaimV1::Exact,
        contract_digest: [0; 32],
    };
    counterfactual.contract_digest = serialized_digest(&counterfactual);
    counterfactual
}

fn build_conformance_report(
    mode: ExecutionModeV1,
    events: &[AuthoritativeEventV1],
    plugin_versions: &BTreeMap<String, String>,
    policy_digest: [u8; 32],
) -> (ConformanceReportV1, [u8; 32]) {
    let subject_artifact_digest = serialized_digest(&events.to_vec());
    let cases = vec![CaseOutcomeV1 {
        case_id: format!("scenario-{mode:?}").to_lowercase(),
        fixture_digest: subject_artifact_digest,
        execution_profile_digest: policy_digest,
        mode,
        claim_layer: ClaimLayerV1::ReplayConformance,
        outcome: CaseOutcomeStatusV1::Pass,
        first_coordinate: None,
        expected_digest: Some(subject_artifact_digest),
        actual_digest: Some(subject_artifact_digest),
        expected_error: None,
        actual_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        provenance_digest: policy_digest,
    }];
    let mut report = ConformanceReportV1 {
        report_id: id16_digest(&subject_artifact_digest),
        subject_artifact_digest,
        profile_digest: policy_digest,
        normative_spec_digest: digest_domain(b"PiglorOS.NormativeSpec.v1", b"ADR-058-064"),
        execution_profile_digest: policy_digest,
        fixture_bundle_digest: serialized_digest(plugin_versions),
        evaluator_source_digest: digest_domain(b"PiglorOS.Evaluator.Source.v1", EVALUATOR_CONTENT),
        evaluator_binary_digest: digest_domain(
            b"PiglorOS.Evaluator.Binary.v1",
            &[EVALUATOR_CONTENT, EXECUTION_PROFILE_CONTENT].concat(),
        ),
        evaluator_protocol_digest: digest_domain(b"PiglorOS.Evaluator.Protocol.v1", b"VRR1/DVR1"),
        implementation: ImplementationIdentityV1 {
            implementation_id: "pos-experiment-wave8".to_owned(),
            source_digest: digest_domain(b"PiglorOS.Host.Source.v1", HOST_SOURCE_CONTENT),
            build_digest: digest_domain(
                b"PiglorOS.Host.Build.v1",
                concat!(env!("CARGO_PKG_NAME"), "\0", env!("CARGO_PKG_VERSION")).as_bytes(),
            ),
            binary_digest: digest_domain(
                b"PiglorOS.Host.Binary.v1",
                &[HOST_SOURCE_CONTENT, EXECUTION_PROFILE_CONTENT].concat(),
            ),
            public_contract_digest: serialized_digest(&wave8_plugin_boundary()),
            organization_id: None,
        },
        independence: IndependenceEvidenceV1 {
            technical_independent: true,
            authorship_independent: false,
            organizational_independent: false,
            declaration_digest: digest_domain(
                b"PiglorOS.Independence.Declaration.v1",
                b"candidate",
            ),
            shared_code_audit_digest: digest_domain(
                b"PiglorOS.Independence.Audit.v1",
                EVALUATOR_CONTENT,
            ),
            reviewer_ids: vec!["pos-reference".to_owned()],
        },
        passed: u32::try_from(cases.len()).unwrap_or(u32::MAX),
        failed: 0,
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        cases,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        limitations_digest: digest_domain(
            b"PiglorOS.Conformance.Limitations.v1",
            b"external-authorship-and-organization-attestation-not-claimed",
        ),
        provenance_digest: policy_digest,
        report_digest: [0; 32],
    };
    report.report_digest = report.digest().unwrap_or([0; 32]);
    (report, subject_artifact_digest)
}

fn build_atomicity(
    input: &MoatProofInputV1,
    events: &[AuthoritativeEventV1],
    failure_probes: &[PluginFailureV1],
    generation: u64,
    subject_artifact_digest: [u8; 32],
) -> Vec<TickAtomicityV1> {
    failure_probes
        .iter()
        .map(|failure| TickAtomicityV1 {
            tick: failure.tick,
            fork_generation: generation,
            staged_event_count: failure.staged_event_count,
            committed_event_count: failure.committed_event_count,
            state_digest_before: failure.state_digest_before,
            state_digest_after: failure.state_digest_after,
            committed: failure.committed,
            failure_class: Some(failure.class),
        })
        .chain(std::iter::once(TickAtomicityV1 {
            tick: input.ticks,
            fork_generation: generation,
            staged_event_count: u64::try_from(events.len()).unwrap_or(u64::MAX),
            committed_event_count: u64::try_from(events.len()).unwrap_or(u64::MAX),
            state_digest_before: input.digest().unwrap_or([0; 32]),
            state_digest_after: subject_artifact_digest,
            committed: true,
            failure_class: None,
        }))
        .collect()
}

fn build_wave8_contract(
    context: &EvidenceContext<'_>,
    events: &[AuthoritativeEventV1],
    factual_events: &[AuthoritativeEventV1],
    participant_views: &[ParticipantViewV1],
) -> Wave8ProofContractV1 {
    let policy_digest = profile_digest();
    let room_parts = build_room_parts(
        context.input,
        context.topology.input_digest,
        participant_views,
        context.host_closure,
        policy_digest,
    );
    let (knowledge_snapshots, authorization_decisions) = build_knowledge_snapshots(
        context.input,
        participant_views,
        &room_parts.principals,
        &room_parts.grants,
    );
    let counterfactual = build_counterfactual_contract(
        context.input,
        context.timeline_id,
        context.fork_cut_seq,
        events,
        factual_events,
        policy_digest,
        room_parts.exogenous_digest,
    );
    let (conformance_report, subject_artifact_digest) =
        build_conformance_report(context.mode, events, context.plugin_versions, policy_digest);
    let atomicity = build_atomicity(
        context.input,
        events,
        context.failure_probes,
        counterfactual.generation,
        subject_artifact_digest,
    );
    Wave8ProofContractV1 {
        scenario_room: room_parts.room,
        plugin_boundary: wave8_plugin_boundary(),
        knowledge_snapshots,
        authorization_decisions,
        counterfactual,
        atomicity,
        conformance_report,
        non_interference: wave8_non_interference_matrix(context.input.digest().unwrap_or([0; 32])),
    }
}

fn owner_frontiers(nodes: &[DependencyNodeV1]) -> Vec<pos_conformance::OwnerFrontierV1> {
    let mut by_owner = BTreeMap::<String, pos_conformance::OwnerFrontierV1>::new();
    for node in nodes {
        let entry = by_owner.entry(node.owner_id.clone()).or_insert_with(|| {
            pos_conformance::OwnerFrontierV1 {
                owner_id: node.owner_id.clone(),
                earliest_tick: node.tick,
                earliest_scheduler_position: node.scheduler_position,
                earliest_output_ordinal: node.output_ordinal,
                cause_node_digests: Vec::new(),
            }
        });
        let candidate = (
            node.tick,
            node.scheduler_position,
            node.owner_id.as_str(),
            node.output_ordinal,
        );
        let current = (
            entry.earliest_tick,
            entry.earliest_scheduler_position,
            entry.owner_id.as_str(),
            entry.earliest_output_ordinal,
        );
        if candidate < current {
            entry.earliest_tick = node.tick;
            entry.earliest_scheduler_position = node.scheduler_position;
            entry.earliest_output_ordinal = node.output_ordinal;
        }
        entry.cause_node_digests.push(node.artifact_digest);
    }
    let mut frontiers = by_owner.into_values().collect::<Vec<_>>();
    for frontier in &mut frontiers {
        frontier.cause_node_digests.sort_unstable();
        frontier.cause_node_digests.dedup();
    }
    frontiers.sort_by(|left, right| {
        (
            left.earliest_tick,
            left.earliest_scheduler_position,
            left.owner_id.as_str(),
            left.earliest_output_ordinal,
        )
            .cmp(&(
                right.earliest_tick,
                right.earliest_scheduler_position,
                right.owner_id.as_str(),
                right.earliest_output_ordinal,
            ))
    });
    frontiers
}

fn is_contract_event(event_type: &str) -> bool {
    event_type == EVENT_TYPE_ACTION_V1 || is_endogenous_event(event_type)
}

fn is_endogenous_event(event_type: &str) -> bool {
    matches!(
        event_type,
        EVENT_TYPE_OBSERVATION_V1 | AGENT_EVENT_TYPE | pos_plugin_society::EVENT_TYPE_SIGNAL
    )
}

fn plugin_versions(topology: &ProofTopology) -> Result<BTreeMap<String, String>, RuntimeError> {
    build_registry(topology).map(|registry| {
        registry
            .plugin_versions()
            .map(|(name, version)| (name.to_owned(), version.to_owned()))
            .collect()
    })
}

fn uncertainty_from_events(events: &[Event]) -> Vec<UncertaintyV1> {
    events
        .iter()
        .filter(|event| event.event_type.as_str() == AGENT_EVENT_TYPE)
        .filter_map(|event| serde_json::from_slice::<AgentReaction>(event.payload.as_slice()).ok())
        .last()
        .map(|reaction| {
            vec![UncertaintyV1 {
                label: "agent_confidence".to_owned(),
                lower: (reaction.confidence - 0.1).max(0.0),
                upper: (reaction.confidence + 0.1).min(1.0),
                confidence: reaction.confidence,
            }]
        })
        .unwrap_or_default()
}

fn projection_changed(
    left: &MoatProofEvidenceV1,
    right: &MoatProofEvidenceV1,
    reducer: &str,
) -> bool {
    let left_state = left.projections.iter().find(|item| item.reducer == reducer);
    let right_state = right
        .projections
        .iter()
        .find(|item| item.reducer == reducer);
    left_state != right_state
}

fn suffix_audit(baseline: &[Event], counterfactual: &[Event], fork_cut_seq: u64) -> (bool, bool) {
    let prefix = |events: &[Event]| {
        events
            .iter()
            .filter(|event| event.seq.as_u64() <= fork_cut_seq)
            .map(|event| {
                (
                    event.seq,
                    event.entity,
                    event.event_type.clone(),
                    payload_digest(event),
                    event.causation_id,
                )
            })
            .collect::<Vec<_>>()
    };
    let suffix = |events: &[Event]| {
        events
            .iter()
            .filter(|event| event.seq.as_u64() > fork_cut_seq)
            .map(|event| {
                (
                    event.event_type.clone(),
                    payload_digest(event),
                    event.causation_id,
                )
            })
            .collect::<Vec<_>>()
    };
    let baseline_suffix = suffix(baseline);
    let child_suffix = suffix(counterfactual);
    (
        prefix(baseline) == prefix(counterfactual),
        baseline_suffix != child_suffix && !child_suffix.is_empty(),
    )
}

fn failure_probes(resource_limit: u64) -> Result<Vec<PluginFailureV1>, MoatProofError> {
    ["plugin_crash", "resource_exhaustion"]
        .into_iter()
        .map(|class| failure_probe(class, resource_limit))
        .collect()
}

fn failure_probe(
    class: &'static str,
    resource_limit: u64,
) -> Result<PluginFailureV1, MoatProofError> {
    let sibling_steps = Arc::new(AtomicU64::new(0));
    let sibling_plugin = SiblingProbePlugin {
        id: PluginId::new(),
    };
    let plugin = FailureProbePlugin {
        id: PluginId::new(),
    };
    let mut experiment = Experiment::new(ExperimentConfig {
        name: format!("wave8-failure-{class}"),
        stop: StopCondition::MaxTicks(1),
        store_config: pos_store::StoreConfig::Memory,
    })
    .with_resource_limit(resource_limit);
    result_pipeline! {
        experiment.register(
            &sibling_plugin,
            None,
            Some(Box::new(SiblingProbeDriver {
                steps: Arc::clone(&sibling_steps),
            })),
        ).map_err(MoatProofError::from) => |()|;
        experiment.register(
            &plugin,
            None,
            Some(Box::new(FailureProbeDriver {
                class,
                resource_limit,
            })),
        ).map_err(MoatProofError::from) => |()|;
        experiment.start().map_err(MoatProofError::from) => |mut session|;
        session.source_events_with_control().map_err(MoatProofError::from) => |before|;
        let step_failed = session.step_tick().is_err();
        session.source_events_with_control().map_err(MoatProofError::from) => |after|;
        let failure_class = match class {
            "resource_exhaustion" => PluginFailureClassV1::ResourceExhaustion,
            _ => PluginFailureClassV1::PluginCrash,
        };
        Ok(PluginFailureV1 {
            plugin: "failure-probe".to_owned(),
            class: failure_class,
            tick: 0,
            committed: !step_failed || before != after,
            staged_event_count: 0,
            committed_event_count: u64::try_from(after.len()).unwrap_or(u64::MAX),
            state_digest_before: serialized_digest(&before),
            state_digest_after: serialized_digest(&after),
            sibling_step_count: sibling_steps.load(std::sync::atomic::Ordering::SeqCst),
        })
    }
}

fn commit_host_closure(
    session: &mut ExperimentSession,
    subject: &str,
) -> Result<HostClosureAuditV1, MoatProofError> {
    result_pipeline! {
        session.source_events_with_control().map_err(MoatProofError::from) => |events|;
        let boundary_seq = events.last().map_or(0, |event| event.seq.as_u64());
        let closure_request = {
            session.close_session_at_boundary();
            session.append_events(&[EventDraft::new(
                fixed_id(5),
                Kind::new("proof.consent.tick"),
                CanonicalBytes::from_static(b"post-revocation"),
            )])
        };
        closure_request.is_err().then_some(())
            .ok_or(MoatProofError::ConsentAppendAccepted) => |()|;
        session.step_tick().map_err(MoatProofError::from) => |marker_outcome|;
        let marker_committed = matches!(
            marker_outcome,
            crate::TickOutcome::Advanced {
                emitted_events: 1,
                ..
            }
        );
        session.source_events_with_control().map_err(MoatProofError::from) => |marker_events|;
        marker_events.last()
            .filter(|event| event.event_type.as_str() == crate::EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE)
            .map(|marker| (
                marker.event_type.as_str().to_owned(),
                *blake3::hash(marker.payload.as_slice()).as_bytes(),
            ))
            .ok_or(MoatProofError::ConsentMarkerMissing) => |marker|;
        marker_committed
            .then(|| session.step_tick().map_err(MoatProofError::from))
            .transpose() => |halt_outcome|;
        let halted = halt_outcome
            .is_some_and(|outcome| matches!(outcome, crate::TickOutcome::Stopped));
        session.source_events_with_control().map_err(MoatProofError::from) => |events|;
        let after_seq = events.last().map_or(0, |event| event.seq.as_u64());
        Ok(HostClosureAuditV1 {
            subject: subject.to_owned(),
            requested_after_seq: boundary_seq,
            effective_after_seq: after_seq,
            closure_event_seq: after_seq,
            closure_event_type: marker.0,
            closure_payload_digest: marker.1,
            halted_at_tick_boundary: halted,
        })
    }
}

struct FailureProbePlugin {
    id: PluginId,
}

struct SiblingProbePlugin {
    id: PluginId,
}

impl Plugin for SiblingProbePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "successful-sibling"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("proof.failure.sibling")],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

struct SiblingProbeDriver {
    steps: Arc<AtomicU64>,
}

impl Driver for SiblingProbeDriver {
    fn name(&self) -> &'static str {
        "successful-sibling-driver"
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        self.steps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(StepOutput::empty())
    }
}

impl Plugin for FailureProbePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "failure-probe"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("proof.failure.probe")],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

struct FailureProbeDriver {
    class: &'static str,
    resource_limit: u64,
}

impl Driver for FailureProbeDriver {
    fn name(&self) -> &'static str {
        "failure-probe-driver"
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        if self.class == "plugin_crash" {
            std::panic::resume_unwind(Box::new("proof crash probe"));
        }
        if self.class == "resource_exhaustion" {
            return Err(RuntimeError::ResourceExhausted {
                driver: "failure-probe-driver".to_owned(),
                requested: self.resource_limit.saturating_add(1),
                limit: self.resource_limit,
            });
        }
        Err(RuntimeError::InvalidPayload {
            event_type: "proof.failure.probe".to_owned(),
            reason: self.class.to_owned(),
        })
    }
}

#[derive(Clone)]
struct ProofAgentPlugin {
    id: PluginId,
}

impl ProofAgentPlugin {
    fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for ProofAgentPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        AGENT_ENTITY_KIND
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(AGENT_EVENT_TYPE)],
            owned_entity_kinds: vec![AGENT_ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

#[derive(Clone)]
struct ProofSocietyPlugin {
    id: PluginId,
}

impl ProofSocietyPlugin {
    fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for ProofSocietyPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        SOCIETY_NAME
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(pos_plugin_society::EVENT_TYPE_SIGNAL)],
            owned_entity_kinds: vec![SOCIETY_ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AgentReaction {
    tick: u64,
    action: String,
    confidence: f64,
    observed_x: f64,
}

struct ProofAgentDriver {
    entity: EntityId,
    threshold: f64,
    tick: u64,
    staged_tick: Option<u64>,
}

impl ProofAgentDriver {
    const fn new(entity: EntityId, threshold: f64) -> Self {
        Self {
            entity,
            threshold,
            tick: 0,
            staged_tick: None,
        }
    }
}

impl Driver for ProofAgentDriver {
    fn name(&self) -> &'static str {
        "proof-agent-driver"
    }

    fn event_subscriptions(&self) -> &[Kind] {
        static EVENTS: std::sync::OnceLock<Vec<Kind>> = std::sync::OnceLock::new();
        EVENTS.get_or_init(|| vec![Kind::new(EVENT_TYPE_OBSERVATION_V1)])
    }

    fn needs_recovery_payload(&self, header: &RecoveryEventHeader) -> bool {
        header.event_type().as_str() == AGENT_EVENT_TYPE
    }

    fn stage_restore_from_history(
        &mut self,
        evidence: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        let mut next_tick: u64 = 0;
        for event in evidence.events() {
            if event.header().event_type().as_str() != AGENT_EVENT_TYPE {
                continue;
            }
            let payload = event
                .payload()
                .ok_or(RuntimeError::InvalidRecoveryEvidence {
                    reason: "proof agent recovery payload missing",
                })?;
            let reaction =
                serde_json::from_slice::<AgentReaction>(payload.as_slice()).map_err(|_| {
                    RuntimeError::InvalidRecoveryEvidence {
                        reason: "proof agent recovery payload malformed",
                    }
                })?;
            next_tick = next_tick.max(reaction.tick.saturating_add(1));
        }
        self.staged_tick = Some(next_tick);
        Ok(())
    }

    fn commit_restore_from_history(&mut self) {
        if let Some(tick) = self.staged_tick.take() {
            self.tick = tick;
        }
    }

    fn abort_restore_from_history(&mut self) {
        self.staged_tick = None;
    }

    fn commit_step(&mut self) {
        self.staged_tick = None;
    }

    fn abort_step(&mut self) {
        if let Some(tick) = self.staged_tick.take() {
            self.tick = tick;
        }
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        self.staged_tick = Some(self.tick);
        let latest = observations
            .events()
            .iter()
            .filter(|event| event.event_type.as_str() == EVENT_TYPE_OBSERVATION_V1)
            .last();
        let (observed_x, causation_id, observed_tick) = latest
            .and_then(|event| {
                pos_plugin_world::WorldObservationV1::decode(&event.payload)
                    .ok()
                    .map(|observation| {
                        (
                            f64::from(observation.pos_x),
                            Some(event.id),
                            Some(observation.tick),
                        )
                    })
            })
            .unwrap_or((0.0, None, None));
        let distance = (observed_x - self.threshold).abs();
        let confidence = (0.5 + distance).min(1.0);
        let reaction_tick = observed_tick.unwrap_or(self.tick);
        let reaction = AgentReaction {
            tick: reaction_tick,
            action: if observed_x >= self.threshold {
                "accelerate".to_owned()
            } else {
                "wait".to_owned()
            },
            confidence,
            observed_x,
        };
        let mut payload = Vec::new();
        // `AgentReaction` contains only JSON primitives and `Vec<u8>` is an
        // infallible sink at this host-owned boundary.
        let _result = serde_json::to_writer(&mut payload, &reaction);
        self.tick = reaction_tick.saturating_add(1);
        let mut draft = EventDraft::new(
            self.entity,
            Kind::new(AGENT_EVENT_TYPE),
            CanonicalBytes::from_vec(payload),
        );
        draft.causation_id = causation_id;
        Ok(StepOutput::new(vec![draft]))
    }
}

struct ProofAgentReducer;

impl Reducer for ProofAgentReducer {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("action_count", serde_json::json!(0));
        state
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() != AGENT_EVENT_TYPE {
            return;
        }
        let Ok(reaction) = serde_json::from_slice::<AgentReaction>(event.payload.as_slice()) else {
            return;
        };
        let count = state
            .get("action_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .saturating_add(1);
        state.set("action_count", serde_json::json!(count));
        state.set("last_action", serde_json::json!(reaction.action));
        state.set("last_observed_x", serde_json::json!(reaction.observed_x));
    }
}

struct ProofSocietyDriver {
    entity: EntityId,
    staged: bool,
}

impl ProofSocietyDriver {
    const fn new(entity: EntityId) -> Self {
        Self {
            entity,
            staged: false,
        }
    }
}

impl Driver for ProofSocietyDriver {
    fn name(&self) -> &'static str {
        "proof-society-driver"
    }

    fn event_subscriptions(&self) -> &[Kind] {
        static EVENTS: std::sync::OnceLock<Vec<Kind>> = std::sync::OnceLock::new();
        EVENTS.get_or_init(|| vec![Kind::new(AGENT_EVENT_TYPE)])
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        self.staged = true;
        let latest = observations
            .events()
            .iter()
            .filter(|event| event.event_type.as_str() == AGENT_EVENT_TYPE)
            .last();
        let (value, causation_id) = latest
            .and_then(|event| {
                serde_json::from_slice::<AgentReaction>(event.payload.as_slice())
                    .ok()
                    .map(|reaction| {
                        (
                            if reaction.action == "accelerate" {
                                0.8
                            } else {
                                0.2
                            },
                            Some(event.id),
                        )
                    })
            })
            .unwrap_or((0.5, None));
        let signal = SocietySignal {
            dimension: SocietyDimension::Opinion,
            value,
            subject: Some(self.entity.to_string()),
            object: None,
        };
        let mut draft = draft_signal(self.entity, &signal);
        draft.causation_id = causation_id;
        Ok(StepOutput::new(vec![draft]))
    }

    fn commit_step(&mut self) {
        self.staged = false;
    }

    fn abort_step(&mut self) {
        self.staged = false;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::EventId,
    };

    fn input() -> MoatProofInputV1 {
        MoatProofInputV1 {
            scenario_id: "proof-test".to_owned(),
            ticks: 4,
            initial_position: [0.0, 0.0],
            initial_velocity: [0.0, 0.0],
            agent_response_threshold: 0.5,
            fork_velocity: [1.0, 0.0],
            random_seed: 7,
            resource_limit: 100,
            network_enabled: false,
        }
    }

    #[test]
    fn proof_run_exhibits_the_three_reactions_and_fork_divergence() {
        let report = MoatProofRun::new(input(), ExecutionModeV1::Local)
            .test_ok()
            .run()
            .test_ok();
        assert!(report.passes_reaction_gates());
        assert_eq!(report.prefix_identical_through_fork, GateStatus::Passed);
        assert_eq!(report.suffix_recomputed, GateStatus::Passed);
        assert!(!report.divergence.equal);
        assert_eq!(
            report.divergence.divergence,
            DivergenceClassV1::AuthoritativeEvents
        );
        assert!(!report.baseline.causal_trace.is_empty());
    }

    #[test]
    fn local_and_air_gapped_have_equivalent_baseline_evidence() {
        let (local, air_gapped, comparison) = run_local_and_air_gapped(input()).test_ok();
        assert!(comparison.equal);
        assert!(local.passes_reaction_gates());
        assert!(air_gapped.passes_reaction_gates());
    }

    #[test]
    fn independent_reference_agrees_for_every_divergence_class() {
        let report = MoatProofRun::new(input(), ExecutionModeV1::Local)
            .test_ok()
            .run()
            .test_ok();
        let baseline = report.baseline;
        let mut variants = Vec::new();

        variants.push(baseline.clone());
        let mut metadata = baseline.clone();
        metadata.manifest.seed += 1;
        variants.push(metadata);
        let mut events = baseline.clone();
        events.authoritative_events[0].payload_digest = [9; 32];
        variants.push(events);
        let mut projections = baseline.clone();
        projections.projections[0].state = serde_json::json!({"changed": true});
        variants.push(projections);
        let mut trace = baseline.clone();
        trace.causal_trace[0].relation.push_str("-changed");
        variants.push(trace);
        let mut observability = baseline.clone();
        observability.uncertainty[0].confidence = 0.5;
        variants.push(observability);

        for variant in &variants {
            let expected = compare(&baseline, variant).test_ok();
            compare_with_reference(&baseline, variant, &expected).test_ok();
        }

        let mut wrong = compare(&baseline, &variants[2]).test_ok();
        wrong.divergence = DivergenceClassV1::None;
        assert!(matches!(
            compare_with_reference(&baseline, &variants[2], &wrong),
            Err(MoatProofError::ReferenceDivergenceMismatch)
        ));
    }

    #[test]
    fn invalid_input_is_rejected_before_host_creation() {
        let mut value = input();
        value.ticks = 0;
        assert!(MoatProofRun::new(value, ExecutionModeV1::Local).is_err());
        let mut value = input();
        value.network_enabled = true;
        assert!(matches!(
            MoatProofRun::new(value, ExecutionModeV1::AirGapped),
            Err(pos_conformance::InputError::NetworkNotAllowedInAirGapped)
        ));
        let mut value = input();
        value.network_enabled = true;
        assert!(matches!(
            MoatProofRun::new(value, ExecutionModeV1::Local),
            Err(pos_conformance::InputError::NetworkNotAllowedInDeterministicProfile)
        ));
    }

    #[test]
    fn failed_gate_status_and_causal_classification_are_explicit() {
        assert_eq!(GateStatus::from(false), GateStatus::Failed);
        assert_eq!(causal_relation("unrecognized", "unrecognized"), "derived");
        assert_eq!(
            dependency_class(EVENT_TYPE_ACTION_V1),
            DependencyClassV1::InterventionAssigned
        );
        assert_eq!(
            dependency_class("other.event"),
            DependencyClassV1::EndogenousRecomputed
        );
    }

    #[test]
    fn causal_trace_records_a_matching_cause_and_effect() {
        let cause_id = EventId::new();
        let effect_id = EventId::new();
        let cause = Event {
            id: cause_id,
            entity: fixed_id(1),
            event_type: Kind::new(EVENT_TYPE_ACTION_V1),
            payload: CanonicalBytes::from_static(b"cause"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let effect = Event {
            id: effect_id,
            entity: fixed_id(2),
            event_type: Kind::new(AGENT_EVENT_TYPE),
            payload: CanonicalBytes::from_static(b"effect"),
            wall_time: WallTime::from_micros(2),
            seq: Seq::from_u64(2),
            causation_id: Some(cause.id),
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let ids = [(cause.id, 1), (effect.id, 2)].into_iter().collect();
        let trace = causal_trace(&[cause, effect], &ids);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].cause_seq, 1);
        assert_eq!(trace[0].effect_seq, 2);
    }

    #[test]
    fn causal_tick_resolution_stops_on_a_cycle() {
        let id = EventId::new();
        let event = Event {
            id,
            entity: fixed_id(1),
            event_type: Kind::new("custom.event"),
            payload: CanonicalBytes::from_static(b"cycle"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(7),
            causation_id: Some(id),
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        assert_eq!(authoritative_events(&[event])[0].tick, 7);
    }

    #[test]
    fn failure_probe_driver_reports_both_failure_classes() {
        let mut resource = FailureProbeDriver {
            class: "resource_exhaustion",
            resource_limit: 3,
        };
        assert!(matches!(
            resource.step(TimelineId::new(), ObservationView::empty()),
            Err(RuntimeError::ResourceExhausted { .. })
        ));
        let mut invalid = FailureProbeDriver {
            class: "invalid_payload",
            resource_limit: 3,
        };
        assert!(matches!(
            invalid.step(TimelineId::new(), ObservationView::empty()),
            Err(RuntimeError::InvalidPayload { .. })
        ));
    }

    #[test]
    fn proof_agent_reacts_when_observation_crosses_threshold() {
        let entity = fixed_id(2);
        let observation = pos_plugin_world::WorldObservationV1 {
            body_entity_id: fixed_id(1),
            tick: 1,
            step_index: 1,
            pos_x: 1.0,
            pos_y: 0.0,
            pos_z: 0.0,
            orient_w: 1.0,
            orient_x: 0.0,
            orient_y: 0.0,
            orient_z: 0.0,
            vel_lin_x: 0.0,
            vel_lin_y: 0.0,
            vel_lin_z: 0.0,
            vel_ang_x: 0.0,
            vel_ang_y: 0.0,
            vel_ang_z: 0.0,
            sensor_kind: 0,
            sensor_value: Vec::new(),
        };
        let event = Event {
            id: EventId::new(),
            entity: fixed_id(1),
            event_type: Kind::new(EVENT_TYPE_OBSERVATION_V1),
            payload: observation.encode().test_ok(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let mut driver = ProofAgentDriver::new(entity, 0.5);
        let output = driver
            .step(TimelineId::new(), ObservationView::from_events(&[event]))
            .test_ok();
        let reaction: AgentReaction =
            serde_json::from_slice(output.drafts[0].payload.as_slice()).test_ok();
        assert_eq!(reaction.action, "accelerate");
    }

    #[test]
    fn scenario_room_entities_are_deterministic_and_input_derived() {
        let first = ProofTopology::new(input()).test_ok();
        let same = ProofTopology::new(input()).test_ok();
        let mut changed_input = input();
        changed_input.scenario_id = "different-room".to_owned();
        let changed = ProofTopology::new(changed_input).test_ok();
        assert_eq!(first.body, same.body);
        assert_eq!(first.agent, same.agent);
        assert_ne!(first.body, changed.body);
        assert_ne!(first.config_entity, changed.config_entity);
    }

    #[test]
    fn proof_drivers_rollback_and_reducers_fail_closed_on_bad_payloads() {
        let mut agent = ProofAgentDriver::new(fixed_id(2), 0.5);
        agent
            .step(TimelineId::new(), ObservationView::empty())
            .test_ok();
        agent.abort_step();
        agent.abort_restore_from_history();
        agent.commit_restore_from_history();
        agent.abort_step();
        agent.staged_tick = Some(7);
        agent.commit_restore_from_history();
        assert_eq!(agent.tick, 7);
        agent.abort_step();

        let mut society = ProofSocietyDriver::new(fixed_id(3));
        society
            .step(TimelineId::new(), ObservationView::empty())
            .test_ok();
        society.abort_step();

        let bad_event = Event {
            id: EventId::new(),
            entity: fixed_id(2),
            event_type: Kind::new(AGENT_EVENT_TYPE),
            payload: CanonicalBytes::from_static(b"bad"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let reducer = ProofAgentReducer;
        let mut state = reducer.initial();
        reducer.apply(&mut state, &bad_event);
        assert_eq!(state.get("action_count"), Some(&serde_json::json!(0)));
    }

    #[test]
    fn fork_rejects_malformed_agent_recovery_payload() {
        let topology = ProofTopology::new(input()).test_ok();
        let factory_topology = topology.clone();
        let registry_factory = move || build_registry(&factory_topology);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "malformed-agent-recovery".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        })
        .with_fork_registry_factory(registry_factory);
        register_plugins(&mut experiment, &topology).test_ok();
        let mut session = experiment.start().test_ok();
        session
            .append_events(&[EventDraft::new(
                topology.agent,
                Kind::new(AGENT_EVENT_TYPE),
                CanonicalBytes::from_static(b"malformed"),
            )])
            .test_ok();
        assert!(session.fork("malformed").is_err());
    }

    #[test]
    fn plugin_registration_rejects_duplicate_topology_ids() {
        let mut agent_duplicate = ProofTopology::new(input()).test_ok();
        agent_duplicate.agent_plugin.id = agent_duplicate.world_plugin.id();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "duplicate-agent".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        });
        experiment
            .register(
                &agent_duplicate.world_plugin,
                Some(Box::new(WorldReducer)),
                Some(Box::new(world_driver(
                    &agent_duplicate.input,
                    agent_duplicate.body,
                    agent_duplicate.config_entity,
                ))),
            )
            .test_ok();
        assert!(register_plugins(&mut experiment, &agent_duplicate).is_err());
        assert!(build_registry(&agent_duplicate).is_err());

        let mut society_duplicate = ProofTopology::new(input()).test_ok();
        society_duplicate.society_plugin.id = society_duplicate.world_plugin.id();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "duplicate-society".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        });
        assert!(register_plugins(&mut experiment, &society_duplicate).is_err());
        assert!(build_registry(&society_duplicate).is_err());
    }

    #[test]
    fn proof_helpers_cover_empty_views_custom_nodes_and_unknown_failures() {
        struct BrokenSerialize;

        impl Serialize for BrokenSerialize {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("broken"))
            }
        }

        let input = input();
        let topology = ProofTopology::new(input.clone()).test_ok();
        let projections = pos_state::ProjectionRegistry::new();
        let versions = BTreeMap::new();
        let host_closure = HostClosureAuditV1 {
            subject: "subject".to_owned(),
            requested_after_seq: 0,
            effective_after_seq: 1,
            closure_event_seq: 1,
            closure_event_type: "proof.consent.tick".to_owned(),
            closure_payload_digest: [0; 32],
            halted_at_tick_boundary: true,
        };
        let evidence = evidence(&EvidenceContext {
            input: &input,
            mode: ExecutionModeV1::Local,
            timeline_id: TimelineId::new(),
            fork_cut_seq: None,
            events: &[],
            factual_events: &[],
            projections: &projections,
            topology: &topology,
            plugin_versions: &versions,
            failure_probes: &[],
            host_closure: &host_closure,
        })
        .test_ok();
        assert!(evidence.projections.is_empty());

        assert_eq!(serialized_digest(&BrokenSerialize), [0; 32]);
        let custom = AuthoritativeEventV1 {
            seq: 2,
            tick: 1,
            entity: "custom".to_owned(),
            event_type: "custom.event".to_owned(),
            payload_digest: [7; 32],
            causation_seq: None,
        };
        assert_eq!(event_node(&custom).scheduler_position, 4);

        let mut earlier = event_node(&custom);
        earlier.tick = 1;
        let mut later = earlier.clone();
        later.tick = 2;
        let frontiers = owner_frontiers(&[later, earlier.clone(), earlier]);
        assert_eq!(frontiers.len(), 1);
        assert_eq!(frontiers[0].earliest_tick, 1);
        assert_eq!(frontiers[0].cause_node_digests.len(), 1);

        let failure = failure_probe("unknown", 3).test_ok();
        assert_eq!(failure.class, PluginFailureClassV1::PluginCrash);
        assert!(!failure.committed);
    }

    #[test]
    fn independent_fixture_reproduction_rejects_a_wrong_equality_claim() {
        let report = MoatProofRun::new(input(), ExecutionModeV1::Local)
            .test_ok()
            .run()
            .test_ok();
        let expected = ComparisonV1 {
            equal: true,
            divergence: DivergenceClassV1::None,
            left_digest: [0; 32],
            right_digest: [0; 32],
        };
        assert!(matches!(
            verify_independent_fixture_reproduction(
                &report.baseline,
                &report.counterfactual,
                &expected,
            ),
            Err(MoatProofError::ReferenceDivergenceMismatch)
        ));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
        })
    }

    fn input() -> MoatProofInputV1 {
        MoatProofInputV1 {
            scenario_id: "coverage-room".to_owned(),
            ticks: 4,
            initial_position: [0.0, 0.0],
            initial_velocity: [0.0, 0.0],
            agent_response_threshold: 0.5,
            fork_velocity: [1.0, 0.0],
            random_seed: 7,
            resource_limit: 100,
            network_enabled: false,
        }
    }

    #[test]
    fn public_run_and_reference_paths_are_instrumented() {
        let run = test_ok(MoatProofRun::new(input(), ExecutionModeV1::Local));
        let report = test_ok(run.run());
        let baseline = report.baseline;
        let mut variants = vec![baseline.clone()];

        let mut metadata = baseline.clone();
        metadata.manifest.seed += 1;
        variants.push(metadata);
        let mut events = baseline.clone();
        events.authoritative_events[0].payload_digest = [9; 32];
        variants.push(events);
        let mut projections = baseline.clone();
        projections.projections[0].state = serde_json::json!({"changed": true});
        variants.push(projections);
        let mut trace = baseline.clone();
        trace.causal_trace[0].relation.push_str("-changed");
        variants.push(trace);
        let mut observability = baseline.clone();
        observability.uncertainty[0].confidence = 0.5;
        variants.push(observability);

        for variant in &variants {
            let expected = test_ok(compare(&baseline, variant));
            test_ok(compare_with_reference(&baseline, variant, &expected));
        }

        let mut wrong = test_ok(compare(&baseline, &variants[2]));
        wrong.divergence = DivergenceClassV1::None;
        assert!(matches!(
            compare_with_reference(&baseline, &variants[2], &wrong),
            Err(MoatProofError::ReferenceDivergenceMismatch)
        ));

        let (_, _, comparison) = test_ok(run_local_and_air_gapped(input()));
        assert!(comparison.equal);
    }

    #[test]
    fn input_and_helper_edges_are_instrumented() {
        let mut value = input();
        value.scenario_id.clear();
        assert!(matches!(
            MoatProofRun::new(value, ExecutionModeV1::Local),
            Err(pos_conformance::InputError::EmptyScenarioId)
        ));

        for value in [
            {
                let mut value = input();
                value.ticks = 0;
                value
            },
            {
                let mut value = input();
                value.resource_limit = 0;
                value
            },
            {
                let mut value = input();
                value.resource_limit = 2;
                value
            },
            {
                let mut value = input();
                value.agent_response_threshold = 2.0;
                value
            },
        ] {
            assert!(MoatProofRun::new(value, ExecutionModeV1::Local).is_err());
        }

        let mut network = input();
        network.network_enabled = true;
        assert!(matches!(
            MoatProofRun::new(network.clone(), ExecutionModeV1::AirGapped),
            Err(pos_conformance::InputError::NetworkNotAllowedInAirGapped)
        ));
        assert!(matches!(
            MoatProofRun::new(network, ExecutionModeV1::Local),
            Err(pos_conformance::InputError::NetworkNotAllowedInDeterministicProfile)
        ));

        assert_eq!(GateStatus::from(false), GateStatus::Failed);
        let failure = test_ok(failure_probe("unknown", 3));
        assert_eq!(failure.class, PluginFailureClassV1::PluginCrash);
        assert_eq!(suffix_audit(&[], &[], 0), (true, false));
        assert_eq!(suffix_audit(&[], &[], 0), (true, false));
        assert!(uncertainty_from_events(&[]).is_empty());
        assert_eq!(participant_views(&[]).len(), 2);
        assert_eq!(causal_relation("unknown", "unknown"), "derived");
        assert_eq!(
            dependency_class("unknown"),
            DependencyClassV1::EndogenousRecomputed
        );
    }

    #[test]
    fn empty_evidence_and_failed_gate_are_exercised() {
        let input = input();
        let topology = test_ok(ProofTopology::new(input.clone()));
        let projections = pos_state::ProjectionRegistry::new();
        let plugin_versions = BTreeMap::new();
        let host_closure = HostClosureAuditV1 {
            subject: "subject".to_owned(),
            requested_after_seq: 0,
            effective_after_seq: 1,
            closure_event_seq: 1,
            closure_event_type: "proof.consent.tick".to_owned(),
            closure_payload_digest: [0; 32],
            halted_at_tick_boundary: true,
        };
        let empty = test_ok(evidence(&EvidenceContext {
            input: &input,
            mode: ExecutionModeV1::Local,
            timeline_id: TimelineId::new(),
            fork_cut_seq: None,
            events: &[],
            factual_events: &[],
            projections: &projections,
            topology: &topology,
            plugin_versions: &plugin_versions,
            failure_probes: &[],
            host_closure: &host_closure,
        }));
        assert!(empty.projections.is_empty());

        let mut failed = MoatProofReport {
            baseline: empty.clone(),
            counterfactual: empty,
            baseline_cbor: Vec::new(),
            counterfactual_cbor: Vec::new(),
            divergence: ComparisonV1 {
                equal: true,
                divergence: DivergenceClassV1::None,
                left_digest: [0; 32],
                right_digest: [0; 32],
            },
            physical_reaction: GateStatus::Failed,
            agent_reaction: GateStatus::Passed,
            society_signal_changed: GateStatus::Passed,
            prefix_identical_through_fork: GateStatus::Passed,
            suffix_recomputed: GateStatus::Passed,
            failure_probes: Vec::new(),
            host_closure,
        };
        assert!(!failed.passes_reaction_gates());
        failed.failure_probes = vec![PluginFailureV1 {
            plugin: "probe".to_owned(),
            class: PluginFailureClassV1::PluginCrash,
            tick: 0,
            committed: true,
            staged_event_count: 0,
            committed_event_count: 0,
            state_digest_before: [1; 32],
            state_digest_after: [1; 32],
            sibling_step_count: 1,
        }];
        assert!(!failed.passes_reaction_gates());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod run_coverage_entrypoints {
    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected coverage fixture error: {error:?}"
            )))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn proof_input() -> MoatProofInputV1 {
        MoatProofInputV1 {
            scenario_id: "coverage-complete-run".to_owned(),
            ticks: 4,
            initial_position: [0.0, 0.0],
            initial_velocity: [0.0, 0.0],
            agent_response_threshold: 0.5,
            fork_velocity: [1.0, 0.0],
            random_seed: 7,
            resource_limit: 100,
            network_enabled: false,
        }
    }

    #[test]
    fn complete_local_and_air_gapped_runs_instrument_the_proof_kernel() {
        let (mut local, air_gapped, comparison) = test_ok(run_local_and_air_gapped(proof_input()));
        assert!(comparison.equal);
        assert!(local.passes_reaction_gates());
        assert!(air_gapped.passes_reaction_gates());
        assert!(!local.baseline_cbor.is_empty());
        assert!(!local.counterfactual_cbor.is_empty());

        local.physical_reaction = GateStatus::Failed;
        assert!(!local.passes_reaction_gates());
        local.physical_reaction = GateStatus::Passed;
        local.agent_reaction = GateStatus::Failed;
        assert!(!local.passes_reaction_gates());
        local.agent_reaction = GateStatus::Passed;
        local.society_signal_changed = GateStatus::Failed;
        assert!(!local.passes_reaction_gates());
        local.society_signal_changed = GateStatus::Passed;
        local.prefix_identical_through_fork = GateStatus::Failed;
        assert!(!local.passes_reaction_gates());
        local.prefix_identical_through_fork = GateStatus::Passed;
        local.suffix_recomputed = GateStatus::Failed;
        assert!(!local.passes_reaction_gates());
        local.suffix_recomputed = GateStatus::Passed;

        let baseline_trace = std::mem::take(&mut local.baseline.causal_trace);
        assert!(!local.passes_reaction_gates());
        local.baseline.causal_trace = baseline_trace;
        let counterfactual_trace = std::mem::take(&mut local.counterfactual.causal_trace);
        assert!(!local.passes_reaction_gates());
        local.counterfactual.causal_trace = counterfactual_trace;
        local.failure_probes[0].committed = true;
        assert!(!local.passes_reaction_gates());
        local.failure_probes[0].committed = false;
        let failure_probes = std::mem::take(&mut local.failure_probes);
        assert!(!local.passes_reaction_gates());
        local.failure_probes = failure_probes;
        local.host_closure.halted_at_tick_boundary = false;
        assert!(!local.passes_reaction_gates());
        local.host_closure.halted_at_tick_boundary = true;
        local.host_closure.effective_after_seq = local.host_closure.requested_after_seq;
        local.host_closure.closure_event_seq = local.host_closure.effective_after_seq;
        assert!(!local.passes_reaction_gates());
        local.host_closure.effective_after_seq = local.host_closure.requested_after_seq + 1;
        local.host_closure.closure_event_seq = local.host_closure.effective_after_seq - 1;
        assert!(!local.passes_reaction_gates());

        let mut network = proof_input();
        network.network_enabled = true;
        assert!(MoatProofRun::new(network, ExecutionModeV1::Local).is_err());

        let mut invalid_ticks = proof_input();
        invalid_ticks.ticks = 0;
        assert!(MoatProofRun::new(invalid_ticks, ExecutionModeV1::Local).is_err());
    }

    #[test]
    fn consent_epoch_boundary_and_subject_binding_are_observable() {
        let participant_views = [
            ParticipantViewV1 {
                participant: "proof-agent".to_owned(),
                visible_event_types: Vec::new(),
                hidden_event_types: Vec::new(),
                visible_events: Vec::new(),
            },
            ParticipantViewV1 {
                participant: "other-agent".to_owned(),
                visible_event_types: Vec::new(),
                hidden_event_types: Vec::new(),
                visible_events: Vec::new(),
            },
        ];
        let mut closure = HostClosureAuditV1 {
            subject: "proof-subject".to_owned(),
            requested_after_seq: 5,
            effective_after_seq: 5,
            closure_event_seq: 5,
            closure_event_type: "proof.consent.tick".to_owned(),
            closure_payload_digest: [0; 32],
            halted_at_tick_boundary: true,
        };
        let no_revocation = build_room_parts(
            &proof_input(),
            [0; 32],
            &participant_views,
            &closure,
            [1; 32],
        );
        assert_eq!(no_revocation.grants[0].consent_epoch, 0);
        assert_eq!(no_revocation.grants[1].consent_epoch, 0);

        closure.closure_event_seq = 6;
        let revocation = build_room_parts(
            &proof_input(),
            [0; 32],
            &participant_views,
            &closure,
            [1; 32],
        );
        assert_eq!(revocation.grants[0].consent_epoch, 1);
        assert_eq!(revocation.grants[1].consent_epoch, 0);
    }

    #[test]
    fn minimum_budget_run_reaches_host_failure_boundary() {
        let mut input = proof_input();
        input.scenario_id = "minimum-budget".to_owned();
        input.resource_limit = 3;
        drop(
            MoatProofRun {
                input,
                mode: ExecutionModeV1::Local,
            }
            .run(),
        );
    }

    #[test]
    fn minimal_resource_budget_exercises_run_failure_propagation() {
        let mut input = proof_input();
        input.scenario_id = "minimal-budget".to_owned();
        input.resource_limit = 1;
        assert!(MoatProofRun {
            input,
            mode: ExecutionModeV1::Local,
        }
        .run()
        .is_err());
    }

    #[test]
    fn malformed_coordinates_reach_topology_digest_failure() {
        let mut input = proof_input();
        input.initial_position[0] = f64::NAN;
        assert!(MoatProofRun {
            input,
            mode: ExecutionModeV1::Local,
        }
        .run()
        .is_err());
    }

    #[test]
    fn duplicate_plugin_ids_reach_both_registration_seams() {
        let topology = test_ok(ProofTopology::new(proof_input()));
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "coverage-duplicate-world".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        });
        test_ok(experiment.register(
            &topology.world_plugin,
            Some(Box::new(WorldReducer)),
            Some(Box::new(world_driver(
                &topology.input,
                topology.body,
                topology.config_entity,
            ))),
        ));
        assert!(register_plugins(&mut experiment, &topology).is_err());

        let mut duplicate_agent = topology;
        duplicate_agent.agent_plugin.id = duplicate_agent.world_plugin.id();
        assert!(build_registry(&duplicate_agent).is_err());
    }

    #[test]
    fn finish_propagates_a_driver_failure() {
        let plugin = FailureProbePlugin {
            id: PluginId::new(),
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "coverage-finish-failure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        })
        .with_resource_limit(3);
        test_ok(experiment.register(
            &plugin,
            None,
            Some(Box::new(FailureProbeDriver {
                class: "invalid_payload",
                resource_limit: 3,
            })),
        ));
        let mut session = test_ok(experiment.start());
        assert!(finish(&mut session).is_err());
    }

    #[test]
    fn unvalidated_zero_budget_reaches_host_step_boundary() {
        let mut input = proof_input();
        input.scenario_id = "zero-budget-host".to_owned();
        input.resource_limit = 0;
        assert!(MoatProofRun {
            input,
            mode: ExecutionModeV1::Local
        }
        .run()
        .is_err());
    }

    #[test]
    fn invalid_public_input_reaches_local_profile_validation() {
        let mut input = proof_input();
        input.scenario_id.clear();
        assert!(run_local_and_air_gapped(input).is_err());
    }
}
