//! Public-interface tests for ADR-064 counterfactual dependency-graph validation.
#![cfg(target_os = "linux")]

use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyContractErrorV1,
    InputDependencyV1,
};
use pos_conformance::counterfactual::frontier_artifacts::{
    UnknownEdgeCoordinateV1, MAX_CAUSE_DIGESTS_V1, MAX_UNKNOWN_EDGE_COORDINATES_V1,
};
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1, FrozenArtifactDescriptorV1,
    PlanExecutionProfileRefV1, PlanTrustPolicyRefV1,
};
use pos_conformance::counterfactual::{InterventionOperationV1, InterventionV1};
use pos_conformance::{
    draft_execution_profile_bytes_v1, draft_trust_policy_snapshot_bytes_v1, DependencyClassV1,
    DependencyNodeV1, ExecutionProfileV1, ReplayClaimV1, TrustPolicySnapshotV1,
    UnknownEdgePolicyV1,
};
use pos_time::counterfactual::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1 as Bounds,
    DependencyGraphErrorV1 as GraphError, DependencyGraphNodeOriginV1 as Origin,
    DependencyGraphNodeV1 as Node, ValidatedDependencyGraphV1, MAX_DEPENDENCY_GRAPH_EDGES_V1,
    MAX_DEPENDENCY_GRAPH_NODES_V1,
};
use std::collections::BTreeSet;
use std::error::Error as _;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type EdgeKey = (u64, u32, String, u32, [u8; 32]);
/// A graph edit and whether its missing edge sorts before its unknown edge.
type UnknownEdgeCase = (fn(&mut Graph), bool);

const EXOGENOUS: usize = 0;
const PARENT: usize = 1;
const INTERVENTION_A: usize = 2;
const FIXED: usize = 3;
const ENDOGENOUS_A: usize = 4;
const INTERVENTION_B: usize = 5;
const ENDOGENOUS_B: usize = 6;
const VIEW: usize = 7;
const VIEW_DETAIL: usize = 8;
const NODE_COUNT: usize = 9;
/// `(consumer, source)` node positions of every edge in the base graph.
const EDGE_SPECS: [(usize, usize); NODE_COUNT] = [
    (PARENT, EXOGENOUS),
    (ENDOGENOUS_A, PARENT),
    (ENDOGENOUS_A, INTERVENTION_A),
    (ENDOGENOUS_A, FIXED),
    (ENDOGENOUS_B, PARENT),
    (ENDOGENOUS_B, ENDOGENOUS_A),
    (ENDOGENOUS_B, INTERVENTION_B),
    (VIEW, ENDOGENOUS_B),
    (VIEW_DETAIL, VIEW),
];
const BOUNDS: Bounds = Bounds {
    max_nodes: 64,
    max_edges: 64,
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

struct Graph {
    plan: CounterfactualPlanV1,
    nodes: Vec<Node>,
    edges: Vec<InputDependencyV1>,
}

fn intervention(effective_tick: u64, ordinal: u32, id_seed: u8) -> InterventionV1 {
    InterventionV1 {
        intervention_id: [id_seed; 16],
        target_schema_id: 7,
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: [2; 32],
        effective_tick,
        ordinal,
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
        interventions: vec![intervention(10, 0, 1), intervention(12, 0, 2)],
        exogenous_descriptors: vec![descriptor(1, 0x50), descriptor(2, 0x40)],
        fixed_policy_descriptors: vec![descriptor(3, 0x30)],
        classification_bundle_digest: [5; 32],
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
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

fn base_nodes(plan: &CounterfactualPlanV1) -> TestResult<Vec<Node>> {
    Ok(vec![
        node(5, 0, "env", [0x50; 32], DependencyClassV1::ExogenousFrozen),
        node(
            9,
            1,
            "world",
            endogenous_digest(1),
            DependencyClassV1::EndogenousRecomputed,
        ),
        node(
            10,
            0,
            "intervention",
            plan.interventions[0].digest()?,
            DependencyClassV1::InterventionAssigned,
        ),
        node(10, 0, "policy", [0x30; 32], DependencyClassV1::FixedPolicy),
        node(
            11,
            0,
            "world",
            endogenous_digest(2),
            DependencyClassV1::EndogenousRecomputed,
        ),
        node(
            12,
            0,
            "intervention",
            plan.interventions[1].digest()?,
            DependencyClassV1::InterventionAssigned,
        ),
        node(
            13,
            0,
            "world",
            endogenous_digest(3),
            DependencyClassV1::EndogenousRecomputed,
        ),
        node(
            20,
            0,
            "ui",
            endogenous_digest(4),
            DependencyClassV1::PresentationOnly,
        ),
        node(
            20,
            1,
            "ui",
            endogenous_digest(5),
            DependencyClassV1::PresentationOnly,
        ),
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

/// Build the base graph after `edit` changes its nodes, declaring every
/// input and deriving every edge from the edited nodes.
fn graph_with(edit: impl FnOnce(&mut [Node])) -> TestResult<Graph> {
    let plan = plan()?;
    let mut nodes = base_nodes(&plan)?;
    edit(&mut nodes);
    for (consumer, source) in EDGE_SPECS {
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
    edges.sort_by_key(edge_key);
    Ok(Graph { plan, nodes, edges })
}

fn graph() -> TestResult<Graph> {
    graph_with(|_| ())
}

/// Validate `graph` under `bounds` after resealing its plan with `policy`,
/// since the plan digest binds the unknown-edge policy.
fn validate_with(
    mut graph: Graph,
    policy: UnknownEdgePolicyV1,
    bounds: Bounds,
) -> TestResult<Result<ValidatedDependencyGraphV1, GraphError>> {
    graph.plan.unknown_edge_policy = policy;
    graph.plan.plan_digest = graph.plan.digest()?;
    Ok(validate_dependency_graph_v1(
        &graph.plan,
        bounds,
        graph.nodes,
        graph.edges,
    ))
}

/// Validate `graph` under its plan as built, with the `Reject` policy.
fn validate(graph: Graph) -> Result<ValidatedDependencyGraphV1, GraphError> {
    validate_dependency_graph_v1(&graph.plan, BOUNDS, graph.nodes, graph.edges)
}

fn edited(edit: impl FnOnce(&mut [Node])) -> TestResult<Result<(), GraphError>> {
    Ok(validate(graph_with(edit)?).map(drop))
}

fn edge_position(graph: &Graph, consumer: usize, source: usize) -> TestResult<usize> {
    let consumer = &graph.nodes[consumer].node;
    let source = graph.nodes[source].node.artifact_digest;
    graph
        .edges
        .iter()
        .position(|edge| edge.consumer == *consumer && edge.source.artifact_digest == source)
        .ok_or_else(|| "edge is absent from the fixture".into())
}

fn edge_coordinate(edge: &InputDependencyV1) -> UnknownEdgeCoordinateV1 {
    UnknownEdgeCoordinateV1 {
        consumer: edge.consumer.clone(),
        missing_source_digest: Some(edge.source.artifact_digest),
    }
}

fn boxed_edge(edge: &InputDependencyV1) -> Box<UnknownEdgeCoordinateV1> {
    Box::new(edge_coordinate(edge))
}

fn consumer_digests(graph: &ValidatedDependencyGraphV1, source: [u8; 32]) -> Vec<[u8; 32]> {
    graph
        .consumers(source)
        .map(|consumer| consumer.node.artifact_digest)
        .collect()
}

#[test]
fn accepts_complete_graph_and_exposes_canonical_view() -> TestResult {
    let fixture = graph()?;
    let (plan_digest, nodes, edges) = (
        fixture.plan.plan_digest,
        fixture.nodes.clone(),
        fixture.edges.clone(),
    );
    let validated = validate(fixture)?;
    assert_eq!(validated.plan_digest(), plan_digest);
    assert_eq!(validated.parent_cut_digest(), [4; 32]);
    assert_eq!(validated.classification_bundle_digest(), [5; 32]);
    assert_eq!(validated.first_tick(), FIRST_TICK);
    assert_eq!(validated.horizon_tick(), HORIZON_TICK);
    assert_eq!(validated.unknown_edge_policy(), UnknownEdgePolicyV1::Reject);
    assert_eq!(validated.nodes(), nodes.as_slice());
    assert_eq!(validated.edges(), edges.as_slice());
    let edge_digests = edges
        .iter()
        .map(InputDependencyV1::digest)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(validated.edge_digests(), edge_digests.as_slice());
    assert!(validated.unknown_edge_coordinates().is_empty());
    assert!(validated.is_complete());
    let parent = nodes[PARENT].node.artifact_digest;
    assert_eq!(validated.node(&parent), Some(&nodes[PARENT]));
    assert!(validated.node(&[0x99; 32]).is_none());
    assert_eq!(
        consumer_digests(&validated, parent),
        vec![
            nodes[ENDOGENOUS_A].node.artifact_digest,
            nodes[ENDOGENOUS_B].node.artifact_digest,
        ]
    );
    assert_eq!(
        consumer_digests(&validated, nodes[EXOGENOUS].node.artifact_digest),
        vec![parent]
    );
    assert_eq!(
        consumer_digests(&validated, nodes[VIEW].node.artifact_digest),
        vec![nodes[VIEW_DETAIL].node.artifact_digest]
    );
    assert!(consumer_digests(&validated, nodes[VIEW_DETAIL].node.artifact_digest).is_empty());
    assert!(consumer_digests(&validated, [0x99; 32]).is_empty());
    assert!(consumer_digests(&validated, [0x01; 32]).is_empty());
    assert!(consumer_digests(&validated, [0xff; 32]).is_empty());

    let full = validate_with(graph()?, UnknownEdgePolicyV1::FullSuffixFromCut, BOUNDS)??;
    assert_eq!(
        full.unknown_edge_policy(),
        UnknownEdgePolicyV1::FullSuffixFromCut
    );
    assert!(full.is_complete());
    Ok(())
}

#[test]
fn rejects_bounds_above_hard_maximums() -> TestResult {
    let maximum = Bounds {
        max_nodes: MAX_DEPENDENCY_GRAPH_NODES_V1,
        max_edges: MAX_DEPENDENCY_GRAPH_EDGES_V1,
    };
    assert!(validate_with(graph()?, UnknownEdgePolicyV1::Reject, maximum)?.is_ok());
    for bounds in [
        Bounds {
            max_nodes: MAX_DEPENDENCY_GRAPH_NODES_V1 + 1,
            ..BOUNDS
        },
        Bounds {
            max_edges: MAX_DEPENDENCY_GRAPH_EDGES_V1 + 1,
            ..BOUNDS
        },
    ] {
        assert_eq!(
            validate_with(graph()?, UnknownEdgePolicyV1::Reject, bounds)?.map(drop),
            Err(GraphError::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn bounds_nodes_edges_and_declared_inputs_before_traversal() -> TestResult {
    let exact = Bounds {
        max_nodes: NODE_COUNT,
        max_edges: EDGE_SPECS.len(),
    };
    assert!(validate_with(graph()?, UnknownEdgePolicyV1::Reject, exact)?.is_ok());
    for bounds in [
        Bounds {
            max_nodes: NODE_COUNT - 1,
            ..exact
        },
        Bounds {
            max_edges: EDGE_SPECS.len() - 1,
            ..exact
        },
    ] {
        assert_eq!(
            validate_with(graph()?, UnknownEdgePolicyV1::Reject, bounds)?.map(drop),
            Err(GraphError::ResourceLimitExceeded)
        );
    }

    let mut extra_edge = graph()?;
    let undeclared = edge(&extra_edge.nodes[VIEW_DETAIL], &extra_edge.nodes[EXOGENOUS]);
    extra_edge.edges.push(undeclared);
    assert_eq!(
        validate_with(extra_edge, UnknownEdgePolicyV1::Reject, exact)?.map(drop),
        Err(GraphError::ResourceLimitExceeded)
    );

    let mut missing_edge = graph()?;
    missing_edge.edges.pop();
    let fewer_edges = Bounds {
        max_edges: EDGE_SPECS.len() - 1,
        ..exact
    };
    assert_eq!(
        validate_with(missing_edge, UnknownEdgePolicyV1::Reject, fewer_edges)?.map(drop),
        Err(GraphError::ResourceLimitExceeded)
    );
    Ok(())
}

#[test]
fn rejects_invalid_plan() -> TestResult {
    let mut fixture = graph()?;
    fixture.plan.plan_digest = [0x55; 32];
    let error = validate(fixture).map(drop).err();
    assert_eq!(
        error,
        Some(GraphError::Plan(
            CounterfactualPlanContractErrorV1::DigestMismatch
        ))
    );
    assert!(error.as_ref().and_then(std::error::Error::source).is_some());

    // The plan digest binds the unknown-edge policy, so it cannot be relabelled.
    let mut relabelled = graph()?;
    relabelled.plan.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut;
    assert_eq!(
        validate(relabelled).map(drop),
        Err(GraphError::Plan(
            CounterfactualPlanContractErrorV1::DigestMismatch
        ))
    );
    Ok(())
}

#[test]
fn applies_the_policy_bound_by_the_plan() -> TestResult {
    let (fixture, expected) = incomplete_graph()?;
    let validated = validate_with(fixture, UnknownEdgePolicyV1::FullSuffixFromCut, BOUNDS)??;
    assert_eq!(
        validated.unknown_edge_policy(),
        UnknownEdgePolicyV1::FullSuffixFromCut
    );
    assert_eq!(validated.unknown_edge_coordinates(), expected.as_slice());

    let (fixture, expected) = incomplete_graph()?;
    assert_eq!(
        validate_with(fixture, UnknownEdgePolicyV1::Reject, BOUNDS)?.map(drop),
        Err(GraphError::DependencyGraphIncomplete(Box::new(
            expected[0].clone()
        )))
    );
    Ok(())
}

#[test]
fn rejects_noncanonical_and_duplicate_nodes() -> TestResult {
    let mut swapped = graph()?;
    swapped.nodes.swap(INTERVENTION_A, FIXED);
    assert_eq!(
        validate(swapped).map(drop),
        Err(GraphError::NonCanonicalOrder)
    );

    let mut same_coordinate = graph()?;
    same_coordinate.nodes[FIXED].node.owner_id = "intervention".to_owned();
    assert_eq!(
        validate(same_coordinate).map(drop),
        Err(GraphError::DuplicateIdentity)
    );

    let mut same_digest = graph()?;
    same_digest.nodes[VIEW_DETAIL].node.artifact_digest =
        same_digest.nodes[VIEW].node.artifact_digest;
    assert_eq!(
        validate(same_digest).map(drop),
        Err(GraphError::DuplicateIdentity)
    );
    Ok(())
}

#[test]
fn bounds_node_coordinate_fields() -> TestResult {
    assert_eq!(
        edited(|nodes| nodes[VIEW_DETAIL].node.owner_id = "u".repeat(128))?,
        Ok(())
    );
    let edits: [fn(&mut [Node]); 4] = [
        |nodes| nodes[VIEW_DETAIL].node.owner_id = String::new(),
        |nodes| nodes[VIEW_DETAIL].node.owner_id = "u".repeat(129),
        |nodes| nodes[VIEW_DETAIL].node.schema_id = 0,
        |nodes| nodes[VIEW_DETAIL].node.artifact_digest = [0; 32],
    ];
    for edit in edits {
        assert_eq!(edited(edit)?, Err(GraphError::FieldOutOfBounds));
    }
    assert_eq!(
        edited(|nodes| nodes[VIEW_DETAIL].provenance_digest = [0; 32])?,
        Err(GraphError::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn requires_canonical_nonzero_declared_inputs() -> TestResult {
    let mut zero_input = graph()?;
    zero_input.nodes[ENDOGENOUS_A].input_digests[0] = [0; 32];
    assert_eq!(
        validate(zero_input).map(drop),
        Err(GraphError::FieldOutOfBounds)
    );

    let mut reversed = graph()?;
    reversed.nodes[ENDOGENOUS_A].input_digests.reverse();
    assert_eq!(
        validate(reversed).map(drop),
        Err(GraphError::NonCanonicalOrder)
    );

    let mut repeated = graph()?;
    let first = repeated.nodes[ENDOGENOUS_A].input_digests[0];
    repeated.nodes[ENDOGENOUS_A].input_digests[1] = first;
    assert_eq!(
        validate(repeated).map(drop),
        Err(GraphError::DuplicateIdentity)
    );
    Ok(())
}

#[test]
fn keeps_nodes_inside_their_origin_window() -> TestResult {
    let edits: [fn(&mut [Node]); 3] = [
        |nodes| nodes[FIXED].origin = Origin::Committed,
        |nodes| nodes[PARENT].origin = Origin::Provisional,
        |nodes| nodes[VIEW_DETAIL].node.tick = HORIZON_TICK + 1,
    ];
    for edit in edits {
        assert_eq!(edited(edit)?, Err(GraphError::OutOfRange));
    }

    let mut past_horizon = graph()?;
    let position = edge_position(&past_horizon, VIEW_DETAIL, VIEW)?;
    past_horizon.edges[position].tick_range.last_tick = HORIZON_TICK + 1;
    assert_eq!(
        validate(past_horizon).map(drop),
        Err(GraphError::OutOfRange)
    );
    Ok(())
}

#[test]
fn rejects_bound_roots_that_disagree_with_the_plan() -> TestResult {
    let mut consuming_root = graph()?;
    consuming_root.nodes[EXOGENOUS].input_digests = vec![[0x11; 32]];
    assert_eq!(
        validate(consuming_root).map(drop),
        Err(GraphError::UnclosedEndogenousInput)
    );

    // The `FIXED` edits make a provisional root the plan does not bind: it
    // sits above the cut, so `validate_root` has no committed exemption.
    let edits: [fn(&mut [Node]); 9] = [
        |nodes| nodes[EXOGENOUS].provenance_digest = [0x63; 32],
        |nodes| nodes[FIXED].class = DependencyClassV1::ExogenousFrozen,
        |nodes| nodes[FIXED].node.schema_id = 4,
        |nodes| {
            nodes[FIXED].class = DependencyClassV1::ExogenousFrozen;
            nodes[FIXED].node.schema_id = 4;
        },
        |nodes| nodes[FIXED].provenance_digest = [0x63; 32],
        |nodes| {
            nodes[INTERVENTION_B].node.tick = 11;
            nodes[INTERVENTION_B].node.scheduler_position = 1;
        },
        |nodes| nodes[INTERVENTION_B].node.schema_id = 8,
        |nodes| nodes[INTERVENTION_B].provenance_digest = [0x63; 32],
        |nodes| nodes[INTERVENTION_B].node.artifact_digest = [0x99; 32],
    ];
    for edit in edits {
        assert_eq!(edited(edit)?, Err(GraphError::RootNotInPlan));
    }
    assert_eq!(
        edited(|nodes| nodes[INTERVENTION_B].class = DependencyClassV1::EndogenousRecomputed)?,
        Err(GraphError::InterventionNodeMissing)
    );
    Ok(())
}

#[test]
fn accepts_committed_roots_the_plan_does_not_bind() -> TestResult {
    let edits: [fn(&mut [Node]); 2] = [
        |nodes| nodes[EXOGENOUS].node.schema_id = 2,
        |nodes| nodes[EXOGENOUS].class = DependencyClassV1::FixedPolicy,
    ];
    for edit in edits {
        assert_eq!(edited(edit)?, Ok(()));
    }
    // An unbound committed root still declares no input.
    let mut consuming = graph()?;
    consuming.nodes[EXOGENOUS].node.schema_id = 2;
    consuming.nodes[EXOGENOUS].input_digests = vec![[0x11; 32]];
    assert_eq!(
        validate(consuming).map(drop),
        Err(GraphError::UnclosedEndogenousInput)
    );
    // An unbound committed Intervention is an extra Intervention node, since
    // the plan has no Intervention for it.
    assert_eq!(
        edited(|nodes| nodes[EXOGENOUS].class = DependencyClassV1::InterventionAssigned)?,
        Err(GraphError::InterventionNodeMissing)
    );
    Ok(())
}

#[test]
fn rejects_invalid_edge_lists() -> TestResult {
    let mut swapped = graph()?;
    swapped.edges.swap(0, 1);
    let error = validate(swapped).map(drop).err();
    assert_eq!(
        error,
        Some(GraphError::Dependency(
            InputDependencyContractErrorV1::NonCanonicalOrder
        ))
    );
    assert!(error.as_ref().and_then(std::error::Error::source).is_some());

    let mut repeated = graph()?;
    let first = repeated.edges[0].clone();
    repeated.edges.insert(1, first);
    assert_eq!(
        validate(repeated).map(drop),
        Err(GraphError::Dependency(
            InputDependencyContractErrorV1::DuplicateIdentity
        ))
    );

    // An invalid record is reported before an earlier order error.
    let mut invalid = graph()?;
    invalid.edges.swap(0, 1);
    let last = invalid.edges.len() - 1;
    invalid.edges[last].provenance_digest = [0; 32];
    assert_eq!(
        validate(invalid).map(drop),
        Err(GraphError::Dependency(
            InputDependencyContractErrorV1::FieldOutOfBounds
        ))
    );
    Ok(())
}

/// The missing `PARENT <- EXOGENOUS` edge left by invalidating `edges[0]`.
fn parent_gap(fixture: &Graph) -> UnknownEdgeCoordinateV1 {
    UnknownEdgeCoordinateV1 {
        consumer: fixture.nodes[PARENT].node.clone(),
        missing_source_digest: Some(fixture.nodes[EXOGENOUS].node.artifact_digest),
    }
}

#[test]
fn rejects_unknown_edges_under_every_policy() -> TestResult {
    // Each edit makes `edges[0]` (`PARENT <- EXOGENOUS`) unknown, which also
    // leaves that declared input without a valid edge. The flag says whether
    // the missing edge's canonical key sorts before the unknown edge's key.
    let edits: [UnknownEdgeCase; 4] = [
        (
            |graph| graph.edges[0].consumer.artifact_digest = [0x98; 32],
            false,
        ),
        (
            |graph| graph.edges[0].source.artifact_digest = [0x97; 32],
            true,
        ),
        (|graph| graph.edges[0].source.scheduler_position = 1, false),
        (|graph| graph.edges[0].consumer.output_ordinal = 1, true),
    ];
    for (edit, gap_first) in edits {
        let mut fixture = graph()?;
        edit(&mut fixture);
        let unknown = GraphError::UnknownDependencyEdge(boxed_edge(&fixture.edges[0]));
        let expected = if gap_first {
            GraphError::DependencyGraphIncomplete(Box::new(parent_gap(&fixture)))
        } else {
            unknown.clone()
        };
        let full = Graph {
            plan: fixture.plan.clone(),
            nodes: fixture.nodes.clone(),
            edges: fixture.edges.clone(),
        };
        assert_eq!(validate(fixture).map(drop), Err(expected));
        assert_eq!(
            validate_with(full, UnknownEdgePolicyV1::FullSuffixFromCut, BOUNDS)?.map(drop),
            Err(unknown)
        );
    }

    let mut undeclared = graph()?;
    let source = undeclared.nodes[INTERVENTION_B].node.artifact_digest;
    undeclared.nodes[ENDOGENOUS_B]
        .input_digests
        .retain(|digest| *digest != source);
    let position = edge_position(&undeclared, ENDOGENOUS_B, INTERVENTION_B)?;
    let expected = edge_coordinate(&undeclared.edges[position]);
    assert_eq!(
        validate(undeclared).map(drop),
        Err(GraphError::UnknownDependencyEdge(Box::new(expected)))
    );
    Ok(())
}

#[test]
fn enforces_edge_class_rules() -> TestResult {
    let mut mismatched = graph()?;
    let position = edge_position(&mismatched, ENDOGENOUS_A, PARENT)?;
    mismatched.edges[position].dependency_class = DependencyClassV1::ExogenousFrozen;
    let expected = edge_coordinate(&mismatched.edges[position]);
    assert_eq!(
        validate(mismatched).map(drop),
        Err(GraphError::ClassRuleViolation(Box::new(expected)))
    );

    let presentation = graph_with(|nodes| {
        nodes[VIEW_DETAIL].class = DependencyClassV1::EndogenousRecomputed;
    })?;
    let position = edge_position(&presentation, VIEW_DETAIL, VIEW)?;
    let expected = edge_coordinate(&presentation.edges[position]);
    assert_eq!(
        validate(presentation).map(drop),
        Err(GraphError::ClassRuleViolation(Box::new(expected)))
    );
    Ok(())
}

#[test]
fn requires_plan_authorization_on_root_edges() -> TestResult {
    for (consumer, source) in [
        (PARENT, EXOGENOUS),
        (ENDOGENOUS_A, INTERVENTION_A),
        (ENDOGENOUS_A, FIXED),
    ] {
        let mut fixture = graph()?;
        let position = edge_position(&fixture, consumer, source)?;
        fixture.edges[position].authorization_digest = [0x01; 32];
        let expected = edge_coordinate(&fixture.edges[position]);
        assert_eq!(
            validate(fixture).map(drop),
            Err(GraphError::UnauthorizedDependency(Box::new(expected)))
        );
    }
    Ok(())
}

/// The base graph without the `ENDOGENOUS_B <- INTERVENTION_B` edge and with
/// an extra endogenous node at Tick 11 that declares no input.
fn incomplete_graph() -> TestResult<(Graph, Vec<UnknownEdgeCoordinateV1>)> {
    let mut fixture = graph()?;
    let position = edge_position(&fixture, ENDOGENOUS_B, INTERVENTION_B)?;
    let removed = fixture.edges.remove(position);
    let closure_unknown = node(
        11,
        1,
        "world",
        endogenous_digest(6),
        DependencyClassV1::EndogenousRecomputed,
    );
    let expected = vec![
        UnknownEdgeCoordinateV1 {
            consumer: closure_unknown.node.clone(),
            missing_source_digest: None,
        },
        edge_coordinate(&removed),
    ];
    fixture.nodes.insert(ENDOGENOUS_A + 1, closure_unknown);
    Ok((fixture, expected))
}

#[test]
fn reject_policy_returns_first_canonical_missing_edge() -> TestResult {
    let (fixture, expected) = incomplete_graph()?;
    assert_eq!(
        validate(fixture).map(drop),
        Err(GraphError::DependencyGraphIncomplete(Box::new(
            expected[0].clone()
        )))
    );

    let mut single = graph()?;
    let position = edge_position(&single, ENDOGENOUS_B, INTERVENTION_B)?;
    let removed = single.edges.remove(position);
    assert_eq!(
        validate(single).map(drop),
        Err(GraphError::DependencyGraphIncomplete(boxed_edge(&removed)))
    );
    Ok(())
}

#[test]
fn reject_policy_reports_a_missing_input_digest_that_sorts_after_every_node() -> TestResult {
    let mut fixture = graph()?;
    fixture.nodes[ENDOGENOUS_B].input_digests.push([0xff; 32]);
    let expected = UnknownEdgeCoordinateV1 {
        consumer: fixture.nodes[ENDOGENOUS_B].node.clone(),
        missing_source_digest: Some([0xff; 32]),
    };
    assert_eq!(
        validate(fixture).map(drop),
        Err(GraphError::DependencyGraphIncomplete(Box::new(expected)))
    );
    Ok(())
}

/// The base graph plus an endogenous node at Tick 10 that declares the
/// `PARENT` input without an edge, and the missing edge it leaves.
fn missing_at_tick_ten() -> TestResult<(Graph, UnknownEdgeCoordinateV1)> {
    let mut fixture = graph()?;
    let mut consumer = node(
        FIRST_TICK,
        1,
        "world",
        endogenous_digest(8),
        DependencyClassV1::EndogenousRecomputed,
    );
    let source = fixture.nodes[PARENT].node.artifact_digest;
    consumer.input_digests = vec![source];
    let gap = UnknownEdgeCoordinateV1 {
        consumer: consumer.node.clone(),
        missing_source_digest: Some(source),
    };
    fixture.nodes.insert(ENDOGENOUS_A, consumer);
    Ok((fixture, gap))
}

#[test]
fn reject_policy_merges_edge_errors_and_missing_edges_by_canonical_key() -> TestResult {
    // Missing edge at Tick 10, undeclared edge at Tick 20: the missing edge wins.
    let (mut fixture, gap) = missing_at_tick_ten()?;
    let view = fixture.nodes[VIEW + 1].node.artifact_digest;
    fixture.nodes[VIEW_DETAIL + 1].input_digests.clear();
    let position = fixture
        .edges
        .iter()
        .position(|edge| edge.source.artifact_digest == view)
        .ok_or("edge is absent from the fixture")?;
    let undeclared = edge_coordinate(&fixture.edges[position]);
    let full = Graph {
        plan: fixture.plan.clone(),
        nodes: fixture.nodes.clone(),
        edges: fixture.edges.clone(),
    };
    assert_eq!(
        validate(fixture).map(drop),
        Err(GraphError::DependencyGraphIncomplete(Box::new(gap)))
    );
    // Under `FullSuffixFromCut` the undeclared edge stays fatal.
    assert_eq!(
        validate_with(full, UnknownEdgePolicyV1::FullSuffixFromCut, BOUNDS)?.map(drop),
        Err(GraphError::UnknownDependencyEdge(Box::new(undeclared)))
    );

    // Missing edge at Tick 10, class-rule violation at Tick 20: same order.
    let (mut fixture, gap) = missing_at_tick_ten()?;
    let position = fixture
        .edges
        .iter()
        .position(|edge| edge.consumer == fixture.nodes[VIEW_DETAIL + 1].node)
        .ok_or("edge is absent from the fixture")?;
    fixture.edges[position].dependency_class = DependencyClassV1::EndogenousRecomputed;
    assert_eq!(
        validate(fixture).map(drop),
        Err(GraphError::DependencyGraphIncomplete(Box::new(gap)))
    );

    // Undeclared edge at Tick 11, missing edge at Tick 20: the edge error wins.
    let mut fixture = graph()?;
    let fixed = fixture.nodes[FIXED].node.artifact_digest;
    fixture.nodes[ENDOGENOUS_A]
        .input_digests
        .retain(|digest| *digest != fixed);
    let undeclared = edge_coordinate(&fixture.edges[edge_position(&fixture, ENDOGENOUS_A, FIXED)?]);
    let missing = edge_position(&fixture, VIEW_DETAIL, VIEW)?;
    fixture.edges.remove(missing);
    assert_eq!(
        validate(fixture).map(drop),
        Err(GraphError::UnknownDependencyEdge(Box::new(undeclared)))
    );

    // Unauthorized edge at Tick 11, missing edge at Tick 20: the edge error wins.
    let mut fixture = graph()?;
    let position = edge_position(&fixture, ENDOGENOUS_A, FIXED)?;
    fixture.edges[position].authorization_digest = [0x01; 32];
    let unauthorized = edge_coordinate(&fixture.edges[position]);
    let missing = edge_position(&fixture, VIEW_DETAIL, VIEW)?;
    fixture.edges.remove(missing);
    assert_eq!(
        validate(fixture).map(drop),
        Err(GraphError::UnauthorizedDependency(Box::new(unauthorized)))
    );
    Ok(())
}

#[test]
fn reports_the_smallest_edge_error_key_under_every_policy() -> TestResult {
    for policy in [
        UnknownEdgePolicyV1::Reject,
        UnknownEdgePolicyV1::FullSuffixFromCut,
    ] {
        let mut fixture = graph()?;
        let late = edge_position(&fixture, VIEW_DETAIL, VIEW)?;
        fixture.edges[late].dependency_class = DependencyClassV1::EndogenousRecomputed;
        let early = edge_position(&fixture, ENDOGENOUS_A, FIXED)?;
        fixture.edges[early].authorization_digest = [0x01; 32];
        let expected = edge_coordinate(&fixture.edges[early]);
        assert_eq!(
            validate_with(fixture, policy, BOUNDS)?.map(drop),
            Err(GraphError::UnauthorizedDependency(Box::new(expected)))
        );
    }
    Ok(())
}

#[test]
fn full_suffix_policy_records_missing_edges_in_canonical_order() -> TestResult {
    let (fixture, expected) = incomplete_graph()?;
    let validated = validate_with(fixture, UnknownEdgePolicyV1::FullSuffixFromCut, BOUNDS)??;
    assert_eq!(validated.unknown_edge_coordinates(), expected.as_slice());
    assert!(!validated.is_complete());
    Ok(())
}

/// One provisional endogenous node at Tick 19 that declares `inputs`.
fn bulk_node(scheduler_position: u32, inputs: std::ops::Range<u32>) -> Node {
    let mut artifact_digest = [0xd7; 32];
    artifact_digest[..4].copy_from_slice(&scheduler_position.to_be_bytes());
    let mut bulk = node(
        19,
        scheduler_position,
        "bulk",
        artifact_digest,
        DependencyClassV1::EndogenousRecomputed,
    );
    bulk.input_digests = inputs.map(bulk_digest).collect();
    bulk
}

/// The base graph plus `missing` declared inputs without edges, spread over
/// bulk nodes of at most `MAX_CAUSE_DIGESTS_V1` inputs each.
fn bulk_graph(missing: u32) -> TestResult<Graph> {
    let mut fixture = graph()?;
    let per_node = u32::try_from(MAX_CAUSE_DIGESTS_V1)?;
    let bulk: Vec<Node> = (0..missing.div_ceil(per_node))
        .map(|chunk| bulk_node(chunk, chunk * per_node..missing.min((chunk + 1) * per_node)))
        .collect();
    let tail = fixture.nodes.split_off(VIEW);
    fixture.nodes.extend(bulk);
    fixture.nodes.extend(tail);
    Ok(fixture)
}

#[test]
fn bounds_recorded_missing_edges() -> TestResult {
    let limit = u32::try_from(MAX_UNKNOWN_EDGE_COORDINATES_V1)?;
    let bounds = Bounds {
        max_nodes: 64,
        max_edges: MAX_UNKNOWN_EDGE_COORDINATES_V1 + 64,
    };
    let validated = validate_with(
        bulk_graph(limit)?,
        UnknownEdgePolicyV1::FullSuffixFromCut,
        bounds,
    )??;
    assert_eq!(
        validated.unknown_edge_coordinates().len(),
        MAX_UNKNOWN_EDGE_COORDINATES_V1
    );
    assert!(validated
        .nodes()
        .iter()
        .all(|node| node.input_digests.len() <= MAX_CAUSE_DIGESTS_V1));
    assert_eq!(
        validate_with(
            bulk_graph(limit + 1)?,
            UnknownEdgePolicyV1::FullSuffixFromCut,
            bounds,
        )?
        .map(drop),
        Err(GraphError::ResourceLimitExceeded)
    );
    Ok(())
}

#[test]
fn bounds_declared_inputs_per_node_at_the_cause_limit() -> TestResult {
    let limit = u32::try_from(MAX_CAUSE_DIGESTS_V1)?;
    let bounds = Bounds {
        max_nodes: 64,
        max_edges: MAX_CAUSE_DIGESTS_V1 + 64,
    };
    let mut at_limit = graph()?;
    at_limit.nodes.insert(VIEW, bulk_node(0, 0..limit));
    let validated = validate_with(at_limit, UnknownEdgePolicyV1::FullSuffixFromCut, bounds)??;
    assert_eq!(
        validated.unknown_edge_coordinates().len(),
        MAX_CAUSE_DIGESTS_V1
    );

    let mut over = graph()?;
    over.nodes.insert(VIEW, bulk_node(0, 0..limit + 1));
    assert_eq!(
        validate_with(over, UnknownEdgePolicyV1::FullSuffixFromCut, bounds)?.map(drop),
        Err(GraphError::ResourceLimitExceeded)
    );
    Ok(())
}

#[test]
fn committed_endogenous_nodes_without_inputs_are_prefix_roots() -> TestResult {
    // Initial (genesis) state in the parent prefix declares no input.
    let mut committed = graph()?;
    let genesis = node(
        PARENT_CUT_TICK - 1,
        0,
        "world",
        endogenous_digest(9),
        DependencyClassV1::EndogenousRecomputed,
    );
    committed.nodes.insert(PARENT, genesis);
    let full = Graph {
        plan: committed.plan.clone(),
        nodes: committed.nodes.clone(),
        edges: committed.edges.clone(),
    };
    assert!(validate(committed)?.is_complete());
    assert!(validate_with(full, UnknownEdgePolicyV1::FullSuffixFromCut, BOUNDS)??.is_complete());

    // The same no-input node in a Fork generation has an unknown closure.
    let mut provisional = graph()?;
    let fork_node = node(
        FIRST_TICK,
        1,
        "world",
        endogenous_digest(9),
        DependencyClassV1::EndogenousRecomputed,
    );
    let expected = UnknownEdgeCoordinateV1 {
        consumer: fork_node.node.clone(),
        missing_source_digest: None,
    };
    provisional.nodes.insert(ENDOGENOUS_A, fork_node);
    assert_eq!(
        validate(provisional).map(drop),
        Err(GraphError::DependencyGraphIncomplete(Box::new(expected)))
    );
    Ok(())
}

#[test]
fn errors_render_distinct_safe_messages() {
    let coordinate = UnknownEdgeCoordinateV1 {
        consumer: DependencyNodeV1 {
            tick: 1,
            scheduler_position: 0,
            owner_id: "world".to_owned(),
            output_ordinal: 0,
            schema_id: 1,
            artifact_digest: [1; 32],
        },
        missing_source_digest: None,
    };
    let errors = [
        GraphError::FieldOutOfBounds,
        GraphError::ResourceLimitExceeded,
        GraphError::Plan(CounterfactualPlanContractErrorV1::InvalidEncoding),
        GraphError::Dependency(InputDependencyContractErrorV1::InvalidEncoding),
        GraphError::NonCanonicalOrder,
        GraphError::DuplicateIdentity,
        GraphError::ProvenanceMissing,
        GraphError::OutOfRange,
        GraphError::RootNotInPlan,
        GraphError::UnclosedEndogenousInput,
        GraphError::InterventionNodeMissing,
        GraphError::UnknownDependencyEdge(Box::new(coordinate.clone())),
        GraphError::ClassRuleViolation(Box::new(coordinate.clone())),
        GraphError::UnauthorizedDependency(Box::new(coordinate.clone())),
        GraphError::DependencyGraphIncomplete(Box::new(coordinate)),
    ];
    let messages: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    assert!(messages.iter().all(|message| !message.contains("world")));
    let with_source = errors
        .iter()
        .filter(|error| error.source().is_some())
        .count();
    assert_eq!(with_source, 2);
}
