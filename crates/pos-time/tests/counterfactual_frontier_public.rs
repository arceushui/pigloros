//! Public-interface tests for ADR-064 recomputation-frontier derivation.
#![cfg(target_os = "linux")]

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
    DependencyNodeV1, ExecutionProfileV1, OwnerFrontierV1, RecomputationFrontierV1, ReplayClaimV1,
    TrustPolicySnapshotV1, UnknownEdgePolicyV1,
};
use pos_time::counterfactual::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1 as Bounds,
    DependencyGraphNodeOriginV1 as Origin, DependencyGraphNodeV1 as Node,
    ValidatedDependencyGraphV1,
};
use pos_time::counterfactual::frontier::{
    dependency_graph_digest_v1, derive_recomputation_frontier_v1,
    RecomputationFrontierErrorV1 as FrontierError,
};
use std::collections::BTreeSet;
use std::error::Error as _;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type EdgeKey = (u64, u32, String, u32, [u8; 32]);

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
const BOUNDS: Bounds = Bounds {
    max_nodes: 5_000,
    max_edges: 5_000,
};
const MAX_OWNER_FRONTIERS: usize = 4_096;
const DESCRIPTOR_AUTHORIZATION: [u8; 32] = [0x61; 32];
const DESCRIPTOR_PROVENANCE: [u8; 32] = [0x62; 32];
const CONSENT_DECISION: [u8; 32] = [4; 32];
const INTERVENTION_PROVENANCE: [u8; 32] = [6; 32];
const ENDOGENOUS_AUTHORIZATION: [u8; 32] = [0x72; 32];
const NODE_PROVENANCE: [u8; 32] = [0x71; 32];
const PARENT_CUT_TICK: u64 = 9;
const FIRST_TICK: u64 = 10;
const HORIZON_TICK: u64 = 20;
const FRONTIER_ID: [u8; 16] = [0x81; 16];
const FRONTIER_PROVENANCE: [u8; 32] = [0x82; 32];

struct Graph {
    plan: CounterfactualPlanV1,
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
}

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

fn plan() -> TestResult<CounterfactualPlanV1> {
    let profile = ExecutionProfileV1::from_canonical_cbor(&draft_execution_profile_bytes_v1(
        "deterministic-local-v1",
    )?)?;
    let snapshot =
        TrustPolicySnapshotV1::from_canonical_cbor(&draft_trust_policy_snapshot_bytes_v1()?)?;
    let mut plan = CounterfactualPlanV1 {
        plan_id: [1; 16],
        room_id: "room.alpha".to_owned(),
        room_digest: [2; 32],
        parent_timeline_id: [3; 16],
        parent_cut_seq: 41,
        parent_cut_tick: PARENT_CUT_TICK,
        parent_cut_digest: [4; 32],
        first_tick: FIRST_TICK,
        horizon_tick: HORIZON_TICK,
        interventions: vec![intervention(11, 1), intervention(13, 2)],
        exogenous_descriptors: vec![descriptor(1, 0x50)],
        fixed_policy_descriptors: vec![descriptor(3, 0x30)],
        classification_bundle_digest: [5; 32],
        execution_profile: PlanExecutionProfileRefV1::from_execution_profile_v1(&profile)?,
        trust_policy: PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(&snapshot)?,
        plugin_composition_digest: [6; 32],
        scheduler_digest: [7; 32],
        numeric_profile_digest: [8; 32],
        budget_digest: [9; 32],
        failure_policy_digest: [10; 32],
        replay_claim: ReplayClaimV1::Exact,
        previous_plan_digest: None,
        plan_digest: [0; 32],
    };
    plan.plan_digest = plan.digest()?;
    Ok(plan)
}

const fn endogenous_digest(seed: u8) -> [u8; 32] {
    [0xd0 + seed; 32]
}

fn bulk_digest(index: u32) -> [u8; 32] {
    let mut digest = [0xee; 32];
    digest[..4].copy_from_slice(&index.to_be_bytes());
    digest
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

/// Declare every input of `specs`, and build an edge for every spec except
/// those in `omitted`, which stay declared but missing.
fn connect(
    plan: CounterfactualPlanV1,
    mut nodes: Vec<Node>,
    specs: &[(usize, usize)],
    omitted: &[(usize, usize)],
) -> Graph {
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
    Graph { plan, nodes, edges }
}

/// Build the base graph after `edit` changes its nodes, omitting `omitted`.
fn graph_with(edit: impl FnOnce(&mut [Node]), omitted: &[(usize, usize)]) -> TestResult<Graph> {
    let plan = plan()?;
    let mut nodes = base_nodes(&plan)?;
    edit(&mut nodes);
    Ok(connect(plan, nodes, &EDGE_SPECS, omitted))
}

fn graph() -> TestResult<Graph> {
    graph_with(|_| (), &[])
}

fn validate(
    graph: Graph,
    policy: UnknownEdgePolicyV1,
) -> TestResult<(CounterfactualPlanV1, ValidatedDependencyGraphV1)> {
    let validated =
        validate_dependency_graph_v1(&graph.plan, policy, BOUNDS, graph.nodes, graph.edges)?;
    Ok((graph.plan, validated))
}

fn derive(
    plan: &CounterfactualPlanV1,
    graph: &ValidatedDependencyGraphV1,
) -> Result<RecomputationFrontierV1, FrontierError> {
    derive_recomputation_frontier_v1(plan, graph, FRONTIER_ID, FRONTIER_PROVENANCE)
}

fn derive_base() -> TestResult<(ValidatedDependencyGraphV1, RecomputationFrontierV1)> {
    let (plan, validated) = validate(graph()?, UnknownEdgePolicyV1::Reject)?;
    let frontier = derive(&plan, &validated)?;
    Ok((validated, frontier))
}

fn coordinates(nodes: &[Node], positions: &[usize]) -> Vec<DependencyNodeV1> {
    positions
        .iter()
        .map(|&position| nodes[position].node.clone())
        .collect()
}

fn owner_frontier(owner: &Node, mut causes: Vec<[u8; 32]>) -> OwnerFrontierV1 {
    causes.sort_unstable();
    OwnerFrontierV1 {
        owner_id: owner.node.owner_id.clone(),
        earliest_tick: owner.node.tick,
        earliest_scheduler_position: owner.node.scheduler_position,
        earliest_output_ordinal: owner.node.output_ordinal,
        cause_node_digests: causes,
    }
}

const fn class_code(class: DependencyClassV1) -> u8 {
    match class {
        DependencyClassV1::ExogenousFrozen => 0,
        DependencyClassV1::InterventionAssigned => 1,
        DependencyClassV1::EndogenousRecomputed => 2,
        DependencyClassV1::FixedPolicy => 3,
        DependencyClassV1::PresentationOnly => 4,
    }
}

const fn count(length: usize) -> [u8; 8] {
    (length as u64).to_be_bytes()
}

/// Independent reimplementation of the documented graph-digest frame.
fn documented_graph_digest(graph: &ValidatedDependencyGraphV1) -> TestResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.CounterfactualDependencyGraph.v1\0");
    hasher.update(&graph.plan_digest());
    hasher.update(&count(graph.nodes().len()));
    for node in graph.nodes() {
        let coordinate = &node.node;
        hasher.update(&coordinate.tick.to_be_bytes());
        hasher.update(&coordinate.scheduler_position.to_be_bytes());
        hasher.update(&count(coordinate.owner_id.len()));
        hasher.update(coordinate.owner_id.as_bytes());
        hasher.update(&coordinate.output_ordinal.to_be_bytes());
        hasher.update(&coordinate.schema_id.to_be_bytes());
        hasher.update(&coordinate.artifact_digest);
        hasher.update(&[class_code(node.class)]);
        hasher.update(&count(node.input_digests.len()));
        for digest in &node.input_digests {
            hasher.update(digest);
        }
        hasher.update(&node.provenance_digest);
    }
    hasher.update(&count(graph.edges().len()));
    for edge in graph.edges() {
        hasher.update(&edge.digest()?);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[test]
fn derives_canonical_frontier_from_intervention_reachability() -> TestResult {
    let nodes = graph()?.nodes;
    let (validated, frontier) = derive_base()?;
    let plan = plan()?;
    let digest = |position: usize| nodes[position].node.artifact_digest;
    let expected = RecomputationFrontierV1 {
        frontier_id: FRONTIER_ID,
        plan_digest: plan.plan_digest,
        parent_cut_digest: plan.parent_cut_digest,
        dependency_graph_digest: dependency_graph_digest_v1(&validated),
        intervention_seed_nodes: coordinates(&nodes, &[INTERVENTION_A, INTERVENTION_B]),
        affected_nodes: coordinates(
            &nodes,
            &[
                INTERVENTION_A,
                WORLD_A,
                AGENT_C,
                INTERVENTION_B,
                AGENT_B,
                WORLD_D,
            ],
        ),
        owner_frontiers: vec![
            owner_frontier(&nodes[INTERVENTION_A], vec![digest(INTERVENTION_A)]),
            owner_frontier(&nodes[WORLD_A], vec![digest(INTERVENTION_A)]),
            owner_frontier(
                &nodes[AGENT_C],
                vec![digest(WORLD_A), digest(INTERVENTION_A)],
            ),
        ],
        global_frontier_tick: 11,
        global_frontier_scheduler_position: 0,
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
        unknown_edge_coordinates: Vec::new(),
        endogenous_suffix_end_tick: HORIZON_TICK,
        classification_bundle_digest: plan.classification_bundle_digest,
        provenance_digest: FRONTIER_PROVENANCE,
        frontier_digest: frontier.frontier_digest,
    };
    assert_eq!(frontier, expected);
    assert_eq!(frontier.frontier_digest, frontier.digest()?);
    assert_ne!(frontier.frontier_digest, [0; 32]);
    frontier.validate()?;
    let bytes = frontier.to_canonical_cbor()?;
    assert_eq!(
        RecomputationFrontierV1::from_canonical_cbor(&bytes)?,
        frontier
    );
    Ok(())
}

#[test]
fn reuses_frozen_inputs_and_excludes_presentation_and_unreached_nodes() -> TestResult {
    let nodes = graph()?.nodes;
    let (_, frontier) = derive_base()?;
    for position in [EXOGENOUS, PARENT, FIXED, EARLY_WORLD, VIEW, WEATHER] {
        assert!(!frontier.affected_nodes.contains(&nodes[position].node));
    }
    assert!(frontier
        .owner_frontiers
        .iter()
        .all(|owner| !["env", "policy", "ui", "weather"].contains(&owner.owner_id.as_str())));
    Ok(())
}

#[test]
fn full_suffix_fallback_starts_at_first_tick_after_cut() -> TestResult {
    let omitted = (WORLD_D, WORLD_A);
    let nodes = graph()?.nodes;
    let (plan, validated) = validate(
        graph_with(|_| (), &[omitted])?,
        UnknownEdgePolicyV1::FullSuffixFromCut,
    )?;
    let frontier = derive(&plan, &validated)?;
    let (_, complete) = derive_base()?;
    assert_eq!(
        frontier.unknown_edge_policy,
        UnknownEdgePolicyV1::FullSuffixFromCut
    );
    assert_eq!(
        frontier.unknown_edge_coordinates,
        vec![UnknownEdgeCoordinateV1 {
            consumer: nodes[WORLD_D].node.clone(),
            missing_source_digest: Some(nodes[WORLD_A].node.artifact_digest),
        }]
    );
    assert_eq!(
        (
            frontier.global_frontier_tick,
            frontier.global_frontier_scheduler_position
        ),
        (FIRST_TICK, 0)
    );
    assert_eq!(frontier.endogenous_suffix_end_tick, HORIZON_TICK);
    assert_eq!(frontier.affected_nodes, complete.affected_nodes);
    assert_eq!(frontier.owner_frontiers, complete.owner_frontiers);
    assert_ne!(
        frontier.dependency_graph_digest,
        complete.dependency_graph_digest
    );
    assert_eq!(frontier.frontier_digest, frontier.digest()?);
    frontier.validate()?;
    Ok(())
}

#[test]
fn complete_graph_under_full_suffix_policy_keeps_fine_grained_frontier() -> TestResult {
    let (plan, validated) = validate(graph()?, UnknownEdgePolicyV1::FullSuffixFromCut)?;
    let (_, complete) = derive_base()?;
    assert_eq!(derive(&plan, &validated)?, complete);
    Ok(())
}

#[test]
fn graph_digest_matches_documented_frame() -> TestResult {
    let (plan, validated) = validate(graph()?, UnknownEdgePolicyV1::Reject)?;
    assert_eq!(
        dependency_graph_digest_v1(&validated),
        documented_graph_digest(&validated)?
    );
    let (_, incomplete) = validate(
        graph_with(|_| (), &[(WORLD_D, WORLD_A)])?,
        UnknownEdgePolicyV1::FullSuffixFromCut,
    )?;
    assert_eq!(
        dependency_graph_digest_v1(&incomplete),
        documented_graph_digest(&incomplete)?
    );
    assert_eq!(
        derive(&plan, &validated)?.dependency_graph_digest,
        documented_graph_digest(&validated)?
    );
    Ok(())
}

#[test]
fn graph_digest_is_sensitive_to_every_node_and_edge_change() -> TestResult {
    let (_, base) = validate(graph()?, UnknownEdgePolicyV1::Reject)?;
    let base_digest = dependency_graph_digest_v1(&base);
    let edits: [fn(&mut [Node]); 4] = [
        |nodes| nodes[WEATHER].provenance_digest = [0x74; 32],
        |nodes| nodes[WEATHER].class = DependencyClassV1::PresentationOnly,
        |nodes| nodes[WEATHER].node.owner_id = "weathers".to_owned(),
        |nodes| nodes[WEATHER].node.output_ordinal = 1,
    ];
    let mut digests = BTreeSet::from([base_digest]);
    for edit in edits {
        let (_, edited) = validate(graph_with(edit, &[])?, UnknownEdgePolicyV1::Reject)?;
        assert_eq!(
            dependency_graph_digest_v1(&edited),
            documented_graph_digest(&edited)?
        );
        digests.insert(dependency_graph_digest_v1(&edited));
    }
    let (_, missing) = validate(
        graph_with(|_| (), &[(WEATHER, EXOGENOUS)])?,
        UnknownEdgePolicyV1::FullSuffixFromCut,
    )?;
    digests.insert(dependency_graph_digest_v1(&missing));
    assert_eq!(digests.len(), edits.len() + 2);
    Ok(())
}

#[test]
fn frontier_digest_binds_caller_fields() -> TestResult {
    let (plan, validated) = validate(graph()?, UnknownEdgePolicyV1::Reject)?;
    let (_, base) = derive_base()?;
    let other_id =
        derive_recomputation_frontier_v1(&plan, &validated, [0x91; 16], FRONTIER_PROVENANCE)?;
    let other_provenance =
        derive_recomputation_frontier_v1(&plan, &validated, FRONTIER_ID, [0x92; 32])?;
    assert_eq!(other_id.frontier_id, [0x91; 16]);
    assert_eq!(other_provenance.provenance_digest, [0x92; 32]);
    let digests = BTreeSet::from([
        base.frontier_digest,
        other_id.frontier_digest,
        other_provenance.frontier_digest,
    ]);
    assert_eq!(digests.len(), 3);
    Ok(())
}

#[test]
fn rejects_invalid_or_foreign_plan_and_missing_provenance() -> TestResult {
    let (plan, validated) = validate(graph()?, UnknownEdgePolicyV1::Reject)?;
    let mut tampered = plan.clone();
    tampered.room_digest = [0x99; 32];
    assert_eq!(
        derive(&tampered, &validated),
        Err(FrontierError::Plan(
            CounterfactualPlanContractErrorV1::DigestMismatch
        ))
    );
    tampered.plan_digest = tampered.digest()?;
    assert_eq!(
        derive(&tampered, &validated),
        Err(FrontierError::PlanMismatch)
    );
    assert_eq!(
        derive_recomputation_frontier_v1(&plan, &validated, FRONTIER_ID, [0; 32]),
        Err(FrontierError::ProvenanceMissing)
    );
    assert_eq!(
        derive_recomputation_frontier_v1(&plan, &validated, FRONTIER_ID, [1; 32])?
            .provenance_digest,
        [1; 32]
    );
    Ok(())
}

/// A graph whose first Intervention feeds `owners` endogenous nodes of
/// distinct owners, so the frontier has `owners + 1` owner frontiers.
fn fan_out_graph(owners: u32) -> TestResult<Graph> {
    let plan = plan()?;
    let mut nodes = vec![intervention_node(&plan, 0)?];
    for index in 0..owners {
        nodes.push(node(
            12,
            index,
            &format!("owner-{index:05}"),
            bulk_digest(index),
            DependencyClassV1::EndogenousRecomputed,
        ));
    }
    nodes.push(intervention_node(&plan, 1)?);
    let specs: Vec<(usize, usize)> = (1..nodes.len() - 1).map(|consumer| (consumer, 0)).collect();
    Ok(connect(plan, nodes, &specs, &[]))
}

#[test]
fn enforces_owner_frontier_bound() -> TestResult {
    let limit = u32::try_from(MAX_OWNER_FRONTIERS)?;
    let (plan, at_limit) = validate(fan_out_graph(limit - 1)?, UnknownEdgePolicyV1::Reject)?;
    let frontier = derive(&plan, &at_limit)?;
    assert_eq!(frontier.owner_frontiers.len(), MAX_OWNER_FRONTIERS);
    assert_eq!(frontier.affected_nodes.len(), MAX_OWNER_FRONTIERS + 1);
    let (plan, over_limit) = validate(fan_out_graph(limit)?, UnknownEdgePolicyV1::Reject)?;
    assert_eq!(
        derive(&plan, &over_limit),
        Err(FrontierError::Frontier(
            FrontierArtifactErrorV1::FieldOutOfBounds
        ))
    );
    Ok(())
}

#[test]
fn errors_render_distinct_safe_messages() {
    let errors = [
        FrontierError::Plan(CounterfactualPlanContractErrorV1::InvalidEncoding),
        FrontierError::PlanMismatch,
        FrontierError::ProvenanceMissing,
        FrontierError::Frontier(FrontierArtifactErrorV1::InvalidEncoding),
    ];
    let messages: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    let with_source = errors
        .iter()
        .filter(|error| error.source().is_some())
        .count();
    assert_eq!(with_source, 2);
}
