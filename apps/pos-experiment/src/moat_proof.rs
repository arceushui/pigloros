//! Wave 8 parameterized proof kernel.
//!
//! The kernel composes the existing Tick Boundary host with the versioned
//! World plugin and two deliberately small, swappable proof Plugins. It is an
//! engineering evaluator for the user-parameterized Scenario Room proof
//! contract; the public Gateway/client contract remains a Wave 9 concern.

use crate::{Experiment, ExperimentConfig, ExperimentError, ExperimentSession, StopCondition};
use pos_conformance::{
    compare, verify_counterfactual_fork, verify_evidence, AuthoritativeEventV1, CausalTraceEntryV1,
    ComparisonV1, ConsentAuditV1, DivergenceClassV1, ExecutionModeV1, MoatProofEvidenceV1,
    MoatProofInputV1, ParticipantEventV1, ParticipantViewV1, PluginFailureV1, ProjectionEvidenceV1,
    ReplayClaimV1, ReproManifestV1, ReproducibilityClassV1, UncertaintyV1, EVIDENCE_FORMAT_V1,
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
use std::collections::{BTreeMap, BTreeSet, HashMap};

const AGENT_EVENT_TYPE: &str = "proof.agent.reaction.v1";
const AGENT_ENTITY_KIND: &str = "proof-agent";
const SOCIETY_ENTITY_KIND: &str = "proof-society";
const WORLD_BACKEND_CONTENT: &[u8] = b"PiglorOS.WorldBackend.simple-kinematic.v1";

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
    pub consent_audit: ConsentAuditV1,
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
            && self.consent_audit.halted_at_tick_boundary
            && self.consent_audit.effective_after_seq >= self.consent_audit.requested_after_seq
            && self.consent_audit.revocation_event_seq == self.consent_audit.effective_after_seq
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
        if matches!(mode, ExecutionModeV1::AirGapped) && input.network_enabled {
            return Err(pos_conformance::InputError::NetworkNotAllowedInAirGapped);
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
        let failure_probes = failure_probes(input.resource_limit)?;
        let consent_audit = consent_probe()?;
        let topology = ProofTopology::new(input.clone());
        let factory_topology = topology.clone();
        let registry_factory = move || build_registry(&factory_topology);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: format!("wave8-{}", input.scenario_id),
            stop: StopCondition::MaxTicks(input.ticks.saturating_add(1)),
            store_config: pos_store::StoreConfig::Memory,
        })
        .with_fork_registry_factory(registry_factory)
        .with_resource_limit(input.resource_limit);
        register_plugins(&mut experiment, &topology)?;
        let mut parent = experiment.start()?;
        parent.step_tick()?;
        let fork_cut_seq = parent
            .source_events()?
            .last()
            .map(|event| event.seq.as_u64())
            .ok_or(MoatProofError::MissingForkCut)?;
        let mut child = parent.fork("counterfactual")?;
        let proposal = intervention(topology.body, topology.agent, &input, 1)?;
        child.submit_action(&proposal)?;
        finish(&mut parent)?;
        finish(&mut child)?;
        let baseline_events = parent.source_events()?;
        let counterfactual_events = child.source_events()?;
        let (prefix_identical_through_fork, suffix_recomputed) =
            suffix_audit(&baseline_events, &counterfactual_events, fork_cut_seq);
        let baseline = evidence(&EvidenceContext {
            input: &input,
            mode,
            fork_cut_seq: Some(fork_cut_seq),
            events: baseline_events.as_slice(),
            projections: parent.projections()?,
            topology: &topology,
            failure_probes: &failure_probes,
            consent_audit: &consent_audit,
        });
        let counterfactual = evidence(&EvidenceContext {
            input: &input,
            mode,
            fork_cut_seq: Some(fork_cut_seq),
            events: counterfactual_events.as_slice(),
            projections: child.projections()?,
            topology: &topology,
            failure_probes: &failure_probes,
            consent_audit: &consent_audit,
        });
        verify_evidence(&baseline)?;
        verify_evidence(&counterfactual)?;
        verify_counterfactual_fork(&baseline, &counterfactual, EVENT_TYPE_ACTION_V1)?;
        let baseline_cbor = baseline.to_canonical_cbor()?;
        let counterfactual_cbor = counterfactual.to_canonical_cbor()?;
        let baseline_json = baseline.to_json()?;
        let counterfactual_json = counterfactual.to_json()?;
        pos_reference::verify_fork_json(
            &baseline_json,
            &counterfactual_json,
            EVENT_TYPE_ACTION_V1,
        )?;
        let divergence = compare(&baseline, &counterfactual);
        compare_with_reference(&baseline, &counterfactual, &divergence)?;
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
            consent_audit,
        };
        if !report.passes_reaction_gates() {
            return Err(MoatProofError::ReactionGatesFailed);
        }
        Ok(report)
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
    let local = MoatProofRun::new(input.clone(), ExecutionModeV1::Local)?.run()?;
    let air_gapped = MoatProofRun::new(input, ExecutionModeV1::AirGapped)?.run()?;
    let comparison = compare(&local.baseline, &air_gapped.baseline);
    if !comparison.equal {
        return Err(MoatProofError::ExecutionModesDiverged(comparison));
    }
    let counterfactual_comparison = compare(&local.counterfactual, &air_gapped.counterfactual);
    if !counterfactual_comparison.equal {
        return Err(MoatProofError::ExecutionModesDiverged(
            counterfactual_comparison,
        ));
    }
    Ok((local, air_gapped, comparison))
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
    #[error("consent probe did not commit its host-owned revocation marker")]
    ConsentMarkerMissing,
}

fn compare_with_reference(
    baseline: &MoatProofEvidenceV1,
    counterfactual: &MoatProofEvidenceV1,
    expected: &ComparisonV1,
) -> Result<(), MoatProofError> {
    let reference = pos_reference::compare_json(&baseline.to_json()?, &counterfactual.to_json()?)?;
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

fn fixed_id(value: u128) -> EntityId {
    EntityId::from_ulid(ulid::Ulid::from(value))
}

fn room_entity(input: &MoatProofInputV1, slot: u8) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.wave8.scenario-room.entity.v1");
    hasher.update(&input.digest());
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
) -> Result<pos_core::ProposedAction, pos_plugin_world::WorldCodecError> {
    let mut params = Vec::new();
    ciborium::into_writer(&input.fork_velocity.to_vec(), &mut params)
        .expect("CBOR writing to Vec is infallible");
    let action = WorldActionV1 {
        actor_entity_id: actor,
        body_entity_id: body,
        action_kind: ActionKindV1::TargetVelocity,
        params_cbor: params,
        action_scope: ACTION_SCOPE_SINGLE_BODY,
        catalogue_version: 1,
        tick,
    };
    Ok(pos_core::ProposedAction::new(
        Kind::new(EVENT_TYPE_ACTION_V1),
        actor,
        action.encode()?,
        Kind::new("world.action.v1.submit"),
    ))
}

#[derive(Clone)]
struct ProofTopology {
    input: MoatProofInputV1,
    body: EntityId,
    agent: EntityId,
    society: EntityId,
    config_entity: EntityId,
    world_plugin: WorldPlugin,
    agent_plugin: ProofAgentPlugin,
    society_plugin: ProofSocietyPlugin,
}

impl ProofTopology {
    fn new(input: MoatProofInputV1) -> Self {
        let body = room_entity(&input, 1);
        let agent = room_entity(&input, 2);
        let society = room_entity(&input, 3);
        let config_entity = room_entity(&input, 4);
        Self {
            input,
            body,
            agent,
            society,
            config_entity,
            world_plugin: WorldPlugin::new().with_bodies([body]),
            agent_plugin: ProofAgentPlugin::new(),
            society_plugin: ProofSocietyPlugin::new(),
        }
    }
}

fn register_plugins(
    experiment: &mut Experiment,
    topology: &ProofTopology,
) -> Result<(), RuntimeError> {
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
    )?;
    experiment.register(
        &topology.agent_plugin,
        Some(Box::new(ProofAgentReducer)),
        Some(Box::new(ProofAgentDriver::new(
            topology.agent,
            topology.input.agent_response_threshold,
        ))),
    )?;
    experiment.register(
        &topology.society_plugin,
        Some(Box::new(SocietyReducer)),
        Some(Box::new(ProofSocietyDriver::new(topology.society))),
    )?;
    Ok(())
}

fn build_registry(topology: &ProofTopology) -> Result<pos_runtime::PluginRegistry, RuntimeError> {
    let mut registry =
        pos_runtime::PluginRegistry::new().with_resource_limit(topology.input.resource_limit);
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
    )?;
    registry.register(
        &topology.agent_plugin,
        Some(Box::new(ProofAgentReducer)),
        Some(Box::new(ProofAgentDriver::new(
            topology.agent,
            topology.input.agent_response_threshold,
        ))),
    )?;
    registry.register(
        &topology.society_plugin,
        Some(Box::new(SocietyReducer)),
        Some(Box::new(ProofSocietyDriver::new(topology.society))),
    )?;
    Ok(registry)
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

struct EvidenceContext<'a> {
    input: &'a MoatProofInputV1,
    mode: ExecutionModeV1,
    fork_cut_seq: Option<u64>,
    events: &'a [Event],
    projections: &'a pos_state::ProjectionRegistry,
    topology: &'a ProofTopology,
    failure_probes: &'a [PluginFailureV1],
    consent_audit: &'a ConsentAuditV1,
}

fn evidence(context: &EvidenceContext<'_>) -> MoatProofEvidenceV1 {
    let input = context.input;
    let mode = context.mode;
    let fork_cut_seq = context.fork_cut_seq;
    let events = context.events;
    let projections = context.projections;
    let topology = context.topology;
    let failure_probes = context.failure_probes;
    let consent_audit = context.consent_audit;
    let mut ids = HashMap::<EventId, u64>::new();
    for event in events {
        ids.insert(event.id, event.seq.as_u64());
    }
    let authoritative_events = events
        .iter()
        .map(|event| AuthoritativeEventV1 {
            seq: event.seq.as_u64(),
            entity: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            payload_digest: payload_digest(event),
            causation_seq: event.causation_id.and_then(|id| ids.get(&id).copied()),
        })
        .collect::<Vec<_>>();
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
                state: serde_json::to_value(state).expect("State is serializable"),
            });
        }
    }
    let causal_trace = events
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
                        visibility: "operator".to_owned(),
                        dependency_class: dependency_class(event.event_type.as_str()),
                    }
                })
            })
        })
        .collect();
    let uncertainty = uncertainty_from_events(events);
    let participant_views = participant_views(events);
    MoatProofEvidenceV1 {
        format_version: EVIDENCE_FORMAT_V1,
        manifest: ReproManifestV1 {
            format_version: EVIDENCE_FORMAT_V1,
            input_digest: input.digest(),
            execution_mode: mode,
            fork_cut_seq,
            seed: input.random_seed,
            resource_limit: input.resource_limit,
            network_enabled: input.network_enabled,
            reproducibility_class: ReproducibilityClassV1::ProfileRecomputation,
            execution_profile: "deterministic-v1".to_owned(),
            execution_profile_digest: profile_digest(input),
            trust_policy_snapshot_digest: digest_domain(
                b"PiglorOS.TrustPolicySnapshot.v1",
                &input.digest(),
            ),
            artifact_closure_digest: artifact_closure_digest(topology),
            evaluator_digest: digest_domain(b"PiglorOS.Evaluator.v1", b"pos-reference-json-v1"),
            replay_claim: ReplayClaimV1::Exact,
            plugin_versions: BTreeMap::from([
                ("world".to_owned(), "1.0.0".to_owned()),
                ("proof-agent".to_owned(), "1.0.0".to_owned()),
                ("society".to_owned(), "1.0.0".to_owned()),
            ]),
        },
        authoritative_events,
        projections: projection_evidence,
        causal_trace,
        uncertainty,
        participant_views,
        plugin_failures: failure_probes.to_vec(),
        consent_audit: consent_audit.clone(),
    }
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

fn dependency_class(event_type: &str) -> String {
    if event_type == EVENT_TYPE_ACTION_V1 {
        "intervention_assigned".to_owned()
    } else {
        "endogenous_recomputed".to_owned()
    }
}

fn digest_domain(domain: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(input);
    *hasher.finalize().as_bytes()
}

fn profile_digest(input: &MoatProofInputV1) -> [u8; 32] {
    digest_domain(
        b"PiglorOS.ExecutionProfile.deterministic-v1",
        &input.digest(),
    )
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
    bytes.extend_from_slice(&topology.input.digest());
    bytes.extend_from_slice(blake3::hash(WORLD_BACKEND_CONTENT).as_bytes());
    digest_domain(b"PiglorOS.ArtifactClosure.v1", &bytes)
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
    let plugin = FailureProbePlugin {
        id: PluginId::new(),
    };
    let mut experiment = Experiment::new(ExperimentConfig {
        name: format!("wave8-failure-{class}"),
        stop: StopCondition::MaxTicks(1),
        store_config: pos_store::StoreConfig::Memory,
    })
    .with_resource_limit(resource_limit);
    experiment.register(
        &plugin,
        None,
        Some(Box::new(FailureProbeDriver {
            class,
            resource_limit,
        })),
    )?;
    let mut session = experiment.start()?;
    let step_failed = session.step_tick().is_err();
    let committed = !session.source_events()?.is_empty();
    Ok(PluginFailureV1 {
        plugin: "failure-probe".to_owned(),
        class: class.to_owned(),
        tick: 0,
        committed: !step_failed || committed,
    })
}

fn consent_probe() -> Result<ConsentAuditV1, MoatProofError> {
    let plugin = ConsentProbePlugin {
        id: PluginId::new(),
    };
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "wave8-consent-boundary".to_owned(),
        stop: StopCondition::MaxTicks(4),
        store_config: pos_store::StoreConfig::Memory,
    });
    experiment.register(&plugin, None, Some(Box::new(ConsentProbeDriver)))?;
    let mut session = experiment.start()?;
    session.step_tick()?;
    let boundary_seq = session
        .source_events()?
        .last()
        .map_or(0, |event| event.seq.as_u64());
    session.revoke_consent_for_subject_at_boundary("proof-subject");
    let post_revocation_append = session.append_events(&[EventDraft::new(
        fixed_id(5),
        Kind::new("proof.consent.tick"),
        CanonicalBytes::from_static(b"post-revocation"),
    )]);
    if post_revocation_append.is_ok() {
        return Err(MoatProofError::ConsentAppendAccepted);
    }
    let marker_committed = matches!(
        session.step_tick()?,
        crate::TickOutcome::Advanced {
            emitted_events: 1,
            ..
        }
    );
    let marker_events = session.source_events()?;
    let marker = marker_events
        .last()
        .filter(|event| {
            event.event_type.as_str() == pos_runtime::HOST_CONSENT_REVOCATION_EVENT_TYPE
        })
        .ok_or(MoatProofError::ConsentMarkerMissing)?;
    let halted = marker_committed && matches!(session.step_tick()?, crate::TickOutcome::Stopped);
    let after_seq = session
        .source_events()?
        .last()
        .map_or(0, |event| event.seq.as_u64());
    Ok(ConsentAuditV1 {
        subject: "proof-subject".to_owned(),
        requested_after_seq: boundary_seq,
        effective_after_seq: after_seq,
        revocation_event_seq: after_seq,
        revocation_event_type: marker.event_type.as_str().to_owned(),
        revocation_payload_digest: *blake3::hash(marker.payload.as_slice()).as_bytes(),
        halted_at_tick_boundary: halted,
    })
}

struct ConsentProbePlugin {
    id: PluginId,
}

impl Plugin for ConsentProbePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "consent-probe"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new("proof.consent.tick")],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

struct ConsentProbeDriver;

impl Driver for ConsentProbeDriver {
    fn name(&self) -> &'static str {
        "consent-probe-driver"
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            fixed_id(5),
            Kind::new("proof.consent.tick"),
            CanonicalBytes::from_static(b"tick"),
        )]))
    }
}

struct FailureProbePlugin {
    id: PluginId,
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
        assert!(self.class != "plugin_crash", "proof crash probe");
        if self.class == "resource_exhaustion" {
            let count =
                usize::try_from(self.resource_limit.saturating_add(1)).unwrap_or(usize::MAX);
            return Ok(StepOutput::new(
                (0..count)
                    .map(|_| {
                        EventDraft::new(
                            fixed_id(6),
                            Kind::new("proof.failure.probe"),
                            CanonicalBytes::from_static(b"budget"),
                        )
                    })
                    .collect(),
            ));
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
    fn new(entity: EntityId, threshold: f64) -> Self {
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
        let (observed_x, causation_id) = latest
            .and_then(|event| {
                pos_plugin_world::WorldObservationV1::decode(&event.payload)
                    .ok()
                    .map(|observation| (f64::from(observation.pos_x), Some(event.id)))
            })
            .unwrap_or((0.0, None));
        let distance = (observed_x - self.threshold).abs();
        let confidence = (0.5 + distance).min(1.0);
        let reaction = AgentReaction {
            tick: self.tick,
            action: if observed_x >= self.threshold {
                "accelerate".to_owned()
            } else {
                "wait".to_owned()
            },
            confidence,
            observed_x,
        };
        let payload = serde_json::to_vec(&reaction).expect("AgentReaction is serializable");
        self.tick = self.tick.saturating_add(1);
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
    fn new(entity: EntityId) -> Self {
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
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
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
            .unwrap()
            .run()
            .unwrap();
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
        let (local, air_gapped, comparison) = run_local_and_air_gapped(input()).unwrap();
        assert!(comparison.equal);
        assert!(local.passes_reaction_gates());
        assert!(air_gapped.passes_reaction_gates());
    }

    #[test]
    fn independent_reference_agrees_for_every_divergence_class() {
        let report = MoatProofRun::new(input(), ExecutionModeV1::Local)
            .unwrap()
            .run()
            .unwrap();
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
            let expected = compare(&baseline, variant);
            compare_with_reference(&baseline, variant, &expected).unwrap();
        }

        let mut wrong = compare(&baseline, &variants[2]);
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
    }

    #[test]
    fn scenario_room_entities_are_deterministic_and_input_derived() {
        let first = ProofTopology::new(input());
        let same = ProofTopology::new(input());
        let mut changed_input = input();
        changed_input.scenario_id = "different-room".to_owned();
        let changed = ProofTopology::new(changed_input);
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
            .unwrap();
        agent.abort_step();
        agent.abort_restore_from_history();

        let mut society = ProofSocietyDriver::new(fixed_id(3));
        society
            .step(TimelineId::new(), ObservationView::empty())
            .unwrap();
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
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let reducer = ProofAgentReducer;
        let mut state = reducer.initial();
        reducer.apply(&mut state, &bad_event);
        assert_eq!(state.get("action_count"), Some(&serde_json::json!(0)));
    }

    #[test]
    fn fork_rejects_malformed_agent_recovery_payload() {
        let topology = ProofTopology::new(input());
        let factory_topology = topology.clone();
        let registry_factory = move || build_registry(&factory_topology);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "malformed-agent-recovery".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        })
        .with_fork_registry_factory(registry_factory);
        register_plugins(&mut experiment, &topology).unwrap();
        let mut session = experiment.start().unwrap();
        session
            .append_events(&[EventDraft::new(
                topology.agent,
                Kind::new(AGENT_EVENT_TYPE),
                CanonicalBytes::from_static(b"malformed"),
            )])
            .unwrap();
        assert!(session.fork("malformed").is_err());
    }
}
