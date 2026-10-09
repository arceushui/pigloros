//! Pure bounded validation of the closed ADR-064 counterfactual dependency
//! graph.
//!
//! Frontier derivation (ADR-064 step 1) starts from "the closed dependency
//! graph from committed dependency edges for the parent prefix and every
//! provisional Fork generation through the requested horizon". This module
//! validates such a graph against its CFP1 [`CounterfactualPlanV1`] and
//! returns a [`ValidatedDependencyGraphV1`] that frontier derivation can
//! traverse without re-checking it. It computes no frontier, invalidates
//! nothing, touches no store, and calls no Plugin.
//!
//! The graph is a list of [`DependencyGraphNodeV1`] declarations and a list
//! of IDP1 [`InputDependencyV1`] edges. Validation checks, in order:
//!
//! 1. the caller's [`DependencyGraphBoundsV1`] against the hard maximums,
//!    the node, edge, and declared-input counts against those bounds, and
//!    every node's declared inputs against [`MAX_CAUSE_DIGESTS_V1`], before
//!    any allocation or traversal;
//! 2. the CFP1 plan itself, whose digest binds the [`UnknownEdgePolicyV1`]
//!    that validation applies;
//! 3. every node: coordinate fields, provenance, declared inputs, the Tick
//!    window of its origin, and, for root classes, agreement with the plan
//!    binding (a `Committed` root the plan does not bind is accepted);
//! 4. the IDP1 records and edge-list order;
//! 5. every edge: both endpoints, the consumer's declaration of the input,
//!    the horizon, the class rules, and the plan authorization of root
//!    sources, together with direct-edge completeness under the
//!    plan's [`UnknownEdgePolicyV1`], as described below.
//!
//! Contract decisions where ADR-064 is silent:
//!
//! - Nodes are listed strictly ascending by `(tick, scheduler_position,
//!   owner_id bytes, output_ordinal)`, and each artifact digest names exactly
//!   one node, because frontier traversal visits a node once by digest.
//! - A `Committed` node belongs to the inherited parent prefix and lies at or
//!   before the parent-cut Tick; a `Provisional` node belongs to a Fork
//!   generation and lies in `first_tick..=horizon_tick`. An edge's Tick range
//!   may not extend past the horizon.
//! - Every node declares the strictly ascending artifact digests of its
//!   direct inputs. Each edge must resolve both endpoints to declared nodes
//!   by exact coordinate and must be declared by its consumer; anything else
//!   is an [`UnknownDependencyEdge`]. A declared input without a valid edge
//!   from the exact declared node is a missing edge
//!   `[consumer, Some(source_digest)]`, and a `Provisional`
//!   `EndogenousRecomputed` node that declares no input has an unknown input
//!   closure `[consumer, None]`. A `Committed` `EndogenousRecomputed` node
//!   that declares no input is initial (genesis) state of the parent prefix:
//!   a valid root of the inherited prefix, not a gap, since nothing before
//!   the cut is recomputed.
//! - `ExogenousFrozen`, `FixedPolicy`, and `InterventionAssigned` nodes are
//!   roots: they declare no input, since an edge from recomputed state into
//!   a purported frozen value makes it endogenous. A bound `ExogenousFrozen`
//!   or `FixedPolicy` node must equal a descriptor of the same class in the
//!   plan by `(schema_id, artifact_digest, provenance_digest)`; a `Committed`
//!   root the plan does not bind is accepted, since the inherited prefix
//!   records the roots of factual Ticks, while every `Provisional` root must
//!   be bound. An `InterventionAssigned` node's artifact digest is its INT1
//!   record digest, so two Interventions assigning the same value stay
//!   distinct; its Tick, schema, and provenance are the Intervention's
//!   effective Tick, target schema, and provenance, and every plan
//!   Intervention has exactly one.
//! - An edge carries the class of its source node. A `PresentationOnly`
//!   output may only feed another `PresentationOnly` node, so presentation
//!   never reaches authoritative state. An edge out of a root carries the
//!   plan's authorization digest for that root: the descriptor's
//!   authorization or the Intervention's consent decision.
//! - Edge errors and missing edges share one canonical key: the RCF1
//!   unknown-edge order of [`UnknownEdgeCoordinateV1`], that is the full
//!   consumer coordinate `(tick, scheduler_position, owner_id bytes,
//!   output_ordinal, schema_id, artifact_digest)` and then the source digest,
//!   where `None` (an unknown input closure) orders before every digest. An
//!   invalid edge is keyed `[edge consumer, Some(edge source digest)]`.
//! - Under [`UnknownEdgePolicyV1::Reject`] every per-edge error (unknown
//!   edge, horizon, class rule, or authorization) is merged with the missing
//!   edges, and the one with the smallest canonical key is returned; on an
//!   equal key the edge error wins. A missing edge is returned as
//!   `DependencyGraphIncomplete`. Only IDP1 record and edge-list order errors
//!   precede this merge, since without a canonical edge list there is no
//!   canonical key order.
//! - Under [`UnknownEdgePolicyV1::FullSuffixFromCut`] every per-edge error is
//!   still fatal, and the one with the smallest canonical key is returned.
//!   ADR-064 does not say whether an undeclared or inexact edge may be
//!   absorbed into the full suffix; this contract conservatively rejects it,
//!   since such an edge contradicts the declared graph rather than leaving a
//!   gap in it. Otherwise every missing edge is recorded in canonical RCF1
//!   order, at most [`MAX_UNKNOWN_EDGE_COORDINATES_V1`] of them, and the
//!   graph is marked incomplete so
//!   that no fine-grained reachability may be claimed.
//! - Declared inputs count against the edge bound, since each one is either
//!   an edge or a recorded missing edge. A node declares at most
//!   [`MAX_CAUSE_DIGESTS_V1`] inputs, so every validated graph can be sealed
//!   into RCF1 owner causes.
//! - The policy is never a free caller argument: it is
//!   `plan.unknown_edge_policy`, bound by the CFP1 plan digest.
//!
//! [`UnknownDependencyEdge`]: DependencyGraphErrorV1::UnknownDependencyEdge

use pos_conformance::counterfactual::dependency::{
    validate_input_dependency_list_order_v1, InputDependencyContractErrorV1, InputDependencyV1,
};
use pos_conformance::counterfactual::frontier_artifacts::{
    UnknownEdgeCoordinateV1, MAX_CAUSE_DIGESTS_V1, MAX_UNKNOWN_EDGE_COORDINATES_V1,
};
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1, FrozenArtifactDescriptorV1,
};
use pos_conformance::counterfactual::InterventionV1;
use pos_conformance::{DependencyClassV1, DependencyNodeV1, UnknownEdgePolicyV1};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Hard maximum number of nodes in one dependency graph.
pub const MAX_DEPENDENCY_GRAPH_NODES_V1: usize = 1_000_000;
/// Hard maximum number of edges, and of declared inputs, in one graph.
pub const MAX_DEPENDENCY_GRAPH_EDGES_V1: usize = 4_000_000;

/// Closed safe errors exposed by dependency-graph validation.
///
/// Edge-level errors expose only the first canonical
/// `[consumer_coordinate, source_digest]`; no other subject data is carried.
/// The coordinate is boxed so that the error stays small.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DependencyGraphErrorV1 {
    /// A bound exceeds its hard maximum, or a node field is out of bounds.
    #[error("dependency-graph field is out of bounds")]
    FieldOutOfBounds,
    /// The graph exceeds its work bound or the missing-edge record bound.
    #[error("dependency graph exceeds its work bound")]
    ResourceLimitExceeded,
    /// The CFP1 plan is invalid.
    #[error("dependency-graph counterfactual plan is invalid")]
    Plan(#[source] CounterfactualPlanContractErrorV1),
    /// An IDP1 edge or the canonical edge-list order is invalid.
    #[error("dependency-graph edge is invalid")]
    Dependency(#[source] InputDependencyContractErrorV1),
    /// Nodes or declared inputs are not strictly ascending.
    #[error("dependency-graph nodes are not canonical")]
    NonCanonicalOrder,
    /// A node coordinate, node artifact digest, or declared input repeats.
    #[error("dependency-graph identity is duplicated")]
    DuplicateIdentity,
    /// A node has no provenance digest.
    #[error("dependency-graph node provenance is missing")]
    ProvenanceMissing,
    /// A node or edge Tick lies outside the window of its origin or horizon.
    #[error("dependency-graph coordinate is out of range")]
    OutOfRange,
    /// A `Provisional` frozen, fixed-policy, or Intervention node is not bound
    /// by the plan, or a bound root disagrees with the plan's provenance. A
    /// `Committed` root the plan does not bind is accepted.
    #[error("dependency-graph root node is not bound by the plan")]
    RootNotInPlan,
    /// A frozen, fixed-policy, or Intervention node declares an input.
    #[error("dependency-graph root node consumes an input")]
    UnclosedEndogenousInput,
    /// A plan Intervention has no `InterventionAssigned` node.
    #[error("dependency-graph Intervention node is missing")]
    InterventionNodeMissing,
    /// An edge endpoint is undeclared, or the consumer did not declare it.
    #[error("dependency-graph edge is unknown")]
    UnknownDependencyEdge(Box<UnknownEdgeCoordinateV1>),
    /// An edge class differs from its source, or presentation feeds authority.
    #[error("dependency-graph edge violates a class rule")]
    ClassRuleViolation(Box<UnknownEdgeCoordinateV1>),
    /// An edge out of a root lacks the plan's authorization for that root.
    #[error("dependency-graph edge is not authorized by the plan")]
    UnauthorizedDependency(Box<UnknownEdgeCoordinateV1>),
    /// A required direct edge is missing under the `Reject` policy.
    #[error("dependency graph is incomplete")]
    DependencyGraphIncomplete(Box<UnknownEdgeCoordinateV1>),
}

/// Caller-selected work bounds, checked before any allocation or traversal.
///
/// Deterministic budgets decide authoritative outcomes, so a profile may
/// select tighter bounds than the hard maximums.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyGraphBoundsV1 {
    /// Maximum node count; at most [`MAX_DEPENDENCY_GRAPH_NODES_V1`].
    pub max_nodes: usize,
    /// Maximum edge count and declared-input count; at most
    /// [`MAX_DEPENDENCY_GRAPH_EDGES_V1`].
    pub max_edges: usize,
}

/// Where a node's output was committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyGraphNodeOriginV1 {
    /// Inherited parent prefix, at or before the parent-cut Tick.
    Committed,
    /// Provisional Fork generation, inside `first_tick..=horizon_tick`.
    Provisional,
}

/// One declared node of the closed dependency graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyGraphNodeV1 {
    /// Exact node coordinate; its artifact digest identifies the node.
    pub node: DependencyNodeV1,
    /// Closed ADR-064 class of the node's output.
    pub class: DependencyClassV1,
    /// Whether the output is in the parent prefix or a Fork generation.
    pub origin: DependencyGraphNodeOriginV1,
    /// Strictly ascending artifact digests of every direct input; at most
    /// [`MAX_CAUSE_DIGESTS_V1`].
    pub input_digests: Vec<[u8; 32]>,
    /// Digest of the node's provenance record.
    pub provenance_digest: [u8; 32],
}

/// A dependency graph that passed every validation rule for one plan.
///
/// It can only be built by [`validate_dependency_graph_v1`], so frontier
/// derivation may rely on canonical node and edge order, unique digests,
/// resolved endpoints, and the recorded missing edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDependencyGraphV1 {
    plan_digest: [u8; 32],
    parent_cut_digest: [u8; 32],
    classification_bundle_digest: [u8; 32],
    first_tick: u64,
    horizon_tick: u64,
    unknown_edge_policy: UnknownEdgePolicyV1,
    nodes: Vec<DependencyGraphNodeV1>,
    edges: Vec<InputDependencyV1>,
    edge_digests: Vec<[u8; 32]>,
    unknown_edge_coordinates: Vec<UnknownEdgeCoordinateV1>,
    by_digest: BTreeMap<[u8; 32], usize>,
    outgoing: Vec<(usize, usize)>,
}

impl ValidatedDependencyGraphV1 {
    /// Digest of the CFP1 plan the graph was validated against.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Parent-cut digest of the validated plan.
    #[must_use]
    pub const fn parent_cut_digest(&self) -> [u8; 32] {
        self.parent_cut_digest
    }

    /// Dependency-classification bundle digest of the validated plan.
    #[must_use]
    pub const fn classification_bundle_digest(&self) -> [u8; 32] {
        self.classification_bundle_digest
    }

    /// First recomputed Tick of the plan, right after the parent cut.
    #[must_use]
    pub const fn first_tick(&self) -> u64 {
        self.first_tick
    }

    /// Inclusive horizon Tick of the plan.
    #[must_use]
    pub const fn horizon_tick(&self) -> u64 {
        self.horizon_tick
    }

    /// Unknown-edge policy the graph was validated under: the plan's
    /// `unknown_edge_policy`, bound by [`Self::plan_digest`].
    #[must_use]
    pub const fn unknown_edge_policy(&self) -> UnknownEdgePolicyV1 {
        self.unknown_edge_policy
    }

    /// Nodes in canonical coordinate order.
    #[must_use]
    pub fn nodes(&self) -> &[DependencyGraphNodeV1] {
        &self.nodes
    }

    /// Edges in canonical IDP1 edge-list order.
    #[must_use]
    pub fn edges(&self) -> &[InputDependencyV1] {
        &self.edges
    }

    /// Canonical IDP1 digest of every edge, in canonical edge-list order.
    #[must_use]
    pub fn edge_digests(&self) -> &[[u8; 32]] {
        &self.edge_digests
    }

    /// Missing edges recorded under `FullSuffixFromCut`, in RCF1 order.
    #[must_use]
    pub fn unknown_edge_coordinates(&self) -> &[UnknownEdgeCoordinateV1] {
        &self.unknown_edge_coordinates
    }

    /// Whether every required direct edge is present, so fine-grained
    /// causal reachability may be claimed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.unknown_edge_coordinates.is_empty()
    }

    /// The node whose artifact digest is `artifact_digest`, if declared.
    #[must_use]
    pub fn node(&self, artifact_digest: &[u8; 32]) -> Option<&DependencyGraphNodeV1> {
        self.by_digest
            .get(artifact_digest)
            .map(|&position| &self.nodes[position])
    }

    /// Direct consumers of the node with `source_digest`, in canonical
    /// coordinate order; empty for an unknown digest.
    pub fn consumers(
        &self,
        source_digest: [u8; 32],
    ) -> impl Iterator<Item = &DependencyGraphNodeV1> + '_ {
        let source = self.by_digest.get(&source_digest).copied();
        let start = self
            .outgoing
            .partition_point(|&(position, _)| Some(position) < source);
        self.outgoing[start..]
            .iter()
            .take_while(move |&&(position, _)| Some(position) == source)
            .map(move |&(_, consumer)| &self.nodes[consumer])
    }
}

/// Validate one closed counterfactual dependency graph against its plan.
///
/// `nodes` must be in canonical coordinate order and `edges` in canonical
/// IDP1 edge-list order. Missing edges are resolved under the plan's
/// `unknown_edge_policy`, which the plan digest binds. See the module
/// documentation for every rule.
///
/// # Errors
///
/// Returns the first closed safe error in validation order: bounds, plan,
/// nodes, and the edge list, then the per-edge error or missing edge chosen
/// under the plan's unknown-edge policy as the module documentation
/// describes.
pub fn validate_dependency_graph_v1(
    plan: &CounterfactualPlanV1,
    bounds: DependencyGraphBoundsV1,
    nodes: Vec<DependencyGraphNodeV1>,
    edges: Vec<InputDependencyV1>,
) -> Result<ValidatedDependencyGraphV1, DependencyGraphErrorV1> {
    check_work_bounds(bounds, &nodes, &edges)?;
    let bindings = PlanBindings::new(plan).map_err(DependencyGraphErrorV1::Plan)?;
    let by_digest = validate_nodes(&bindings, &nodes)?;
    let EdgeScan {
        edge_digests,
        outgoing,
        first_error,
    } = validate_edges(&bindings, &nodes, &by_digest, &edges)?;
    let unknown_edge_policy = plan.unknown_edge_policy;
    let unknown_edge_coordinates =
        missing_edges(unknown_edge_policy, &nodes, &outgoing, first_error)?;
    Ok(ValidatedDependencyGraphV1 {
        plan_digest: plan.plan_digest,
        parent_cut_digest: plan.parent_cut_digest,
        classification_bundle_digest: plan.classification_bundle_digest,
        first_tick: plan.first_tick,
        horizon_tick: plan.horizon_tick,
        unknown_edge_policy,
        nodes,
        edges,
        edge_digests,
        unknown_edge_coordinates,
        by_digest,
        outgoing,
    })
}

fn check_work_bounds(
    bounds: DependencyGraphBoundsV1,
    nodes: &[DependencyGraphNodeV1],
    edges: &[InputDependencyV1],
) -> Result<(), DependencyGraphErrorV1> {
    if bounds.max_nodes > MAX_DEPENDENCY_GRAPH_NODES_V1
        || bounds.max_edges > MAX_DEPENDENCY_GRAPH_EDGES_V1
    {
        Err(DependencyGraphErrorV1::FieldOutOfBounds)
    } else if nodes.len() > bounds.max_nodes
        || edges.len() > bounds.max_edges
        || nodes
            .iter()
            .any(|node| node.input_digests.len() > MAX_CAUSE_DIGESTS_V1)
        || declared_inputs(nodes) > bounds.max_edges
    {
        Err(DependencyGraphErrorV1::ResourceLimitExceeded)
    } else {
        Ok(())
    }
}

/// Total declared inputs, computed only after the node count is bounded.
fn declared_inputs(nodes: &[DependencyGraphNodeV1]) -> usize {
    nodes.iter().fold(0_usize, |total, node| {
        total.saturating_add(node.input_digests.len())
    })
}

/// Plan identity that a root node must match and its edges must carry.
struct RootBinding {
    authorization_digest: [u8; 32],
    provenance_digest: [u8; 32],
}

/// The plan plus its Interventions indexed by INT1 digest.
struct PlanBindings<'p> {
    plan: &'p CounterfactualPlanV1,
    interventions: BTreeMap<[u8; 32], &'p InterventionV1>,
}

impl<'p> PlanBindings<'p> {
    /// Validate the plan, then index its Interventions by INT1 digest.
    ///
    /// The plan is validated first so that the Intervention list is bounded
    /// before any digest is computed; a digest error is propagated, not
    /// dropped.
    fn new(plan: &'p CounterfactualPlanV1) -> Result<Self, CounterfactualPlanContractErrorV1> {
        plan.validate()?;
        plan.interventions
            .iter()
            .map(|intervention| intervention.digest().map(|id| (id, intervention)))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(CounterfactualPlanContractErrorV1::Intervention)
            .map(|interventions| Self {
                plan,
                interventions,
            })
    }

    /// The plan binding of a root node; `None` for a non-root or unbound node.
    fn root_binding(&self, node: &DependencyGraphNodeV1) -> Option<RootBinding> {
        let coordinate = &node.node;
        match node.class {
            DependencyClassV1::ExogenousFrozen => {
                descriptor_binding(&self.plan.exogenous_descriptors, coordinate)
            }
            DependencyClassV1::FixedPolicy => {
                descriptor_binding(&self.plan.fixed_policy_descriptors, coordinate)
            }
            DependencyClassV1::InterventionAssigned => self
                .interventions
                .get(&coordinate.artifact_digest)
                .filter(|intervention| {
                    intervention.effective_tick == coordinate.tick
                        && intervention.target_schema_id == coordinate.schema_id
                })
                .map(|intervention| RootBinding {
                    authorization_digest: intervention.consent_decision_digest,
                    provenance_digest: intervention.provenance_digest,
                }),
            DependencyClassV1::EndogenousRecomputed | DependencyClassV1::PresentationOnly => None,
        }
    }
}

fn descriptor_binding(
    descriptors: &[FrozenArtifactDescriptorV1],
    coordinate: &DependencyNodeV1,
) -> Option<RootBinding> {
    // CFP1 validation enforces strictly ascending `(schema_id,
    // artifact_digest)` descriptor order (`validate_descriptor_order`).
    descriptors
        .binary_search_by(|descriptor| {
            (descriptor.schema_id, &descriptor.artifact_digest)
                .cmp(&(coordinate.schema_id, &coordinate.artifact_digest))
        })
        .ok()
        .map(|position| RootBinding {
            authorization_digest: descriptors[position].authorization_digest,
            provenance_digest: descriptors[position].provenance_digest,
        })
}

fn validate_nodes(
    bindings: &PlanBindings<'_>,
    nodes: &[DependencyGraphNodeV1],
) -> Result<BTreeMap<[u8; 32], usize>, DependencyGraphErrorV1> {
    nodes.windows(2).try_for_each(|pair| {
        ordered(
            pair[0]
                .node
                .coordinate_key()
                .cmp(&pair[1].node.coordinate_key()),
        )
    })?;
    let mut by_digest = BTreeMap::new();
    for (position, node) in nodes.iter().enumerate() {
        validate_node(bindings, node)?;
        if by_digest
            .insert(node.node.artifact_digest, position)
            .is_some()
        {
            return Err(DependencyGraphErrorV1::DuplicateIdentity);
        }
    }
    let intervention_nodes = nodes
        .iter()
        .filter(|node| node.class == DependencyClassV1::InterventionAssigned)
        .count();
    if intervention_nodes == bindings.plan.interventions.len() {
        Ok(by_digest)
    } else {
        Err(DependencyGraphErrorV1::InterventionNodeMissing)
    }
}

fn validate_node(
    bindings: &PlanBindings<'_>,
    node: &DependencyGraphNodeV1,
) -> Result<(), DependencyGraphErrorV1> {
    validate_node_fields(node)
        .and_then(|()| validate_node_range(bindings.plan, node))
        .and_then(|()| validate_root(bindings, node))
}

fn validate_node_fields(node: &DependencyGraphNodeV1) -> Result<(), DependencyGraphErrorV1> {
    if !node.node.is_valid_coordinate() || node.input_digests.contains(&[0; 32]) {
        Err(DependencyGraphErrorV1::FieldOutOfBounds)
    } else if node.provenance_digest == [0; 32] {
        Err(DependencyGraphErrorV1::ProvenanceMissing)
    } else {
        node.input_digests
            .windows(2)
            .try_for_each(|pair| ordered(pair[0].cmp(&pair[1])))
    }
}

fn validate_node_range(
    plan: &CounterfactualPlanV1,
    node: &DependencyGraphNodeV1,
) -> Result<(), DependencyGraphErrorV1> {
    let tick = node.node.tick;
    let in_range = match node.origin {
        DependencyGraphNodeOriginV1::Committed => tick <= plan.parent_cut_tick,
        DependencyGraphNodeOriginV1::Provisional => {
            (plan.first_tick..=plan.horizon_tick).contains(&tick)
        }
    };
    if in_range {
        Ok(())
    } else {
        Err(DependencyGraphErrorV1::OutOfRange)
    }
}

/// A root consumes no input and matches the plan's provenance when the plan
/// binds it. A `Committed` root the plan does not bind is accepted, because
/// the prefix records the roots of factual Ticks; a `Provisional` root must
/// be bound.
fn validate_root(
    bindings: &PlanBindings<'_>,
    node: &DependencyGraphNodeV1,
) -> Result<(), DependencyGraphErrorV1> {
    if !is_root(node.class) {
        return Ok(());
    }
    if !node.input_digests.is_empty() {
        return Err(DependencyGraphErrorV1::UnclosedEndogenousInput);
    }
    let accepts_unbound = node.origin == DependencyGraphNodeOriginV1::Committed;
    let matches_plan = bindings
        .root_binding(node)
        .map_or(accepts_unbound, |binding| {
            binding.provenance_digest == node.provenance_digest
        });
    if matches_plan {
        Ok(())
    } else {
        Err(DependencyGraphErrorV1::RootNotInPlan)
    }
}

const fn is_root(class: DependencyClassV1) -> bool {
    matches!(
        class,
        DependencyClassV1::ExogenousFrozen
            | DependencyClassV1::FixedPolicy
            | DependencyClassV1::InterventionAssigned
    )
}

/// A per-edge error and its canonical key `[edge consumer, Some(source)]`.
type KeyedEdgeError = (UnknownEdgeCoordinateV1, DependencyGraphErrorV1);

/// The valid edges of a graph and its first canonical per-edge error.
struct EdgeScan {
    /// Canonical IDP1 digest of every edge, in edge-list order.
    edge_digests: Vec<[u8; 32]>,
    /// `(source, consumer)` node positions of every valid edge, sorted so
    /// that each source's consumers are contiguous and ascending.
    outgoing: Vec<(usize, usize)>,
    /// The per-edge error with the smallest canonical key, and that key.
    first_error: Option<KeyedEdgeError>,
}

/// Digest every IDP1 edge and check the edge-list order, then validate every
/// edge, keeping the per-edge error with the smallest canonical key instead of
/// the first in list order.
///
/// An IDP1 digest validates its record first, so the first invalid record is
/// reported before any order error, exactly as
/// `validate_input_dependency_order_v1` does; the order check then uses
/// `validate_input_dependency_list_order_v1`, which compares the IDP1 order
/// keys without validating every record a second time.
fn validate_edges(
    bindings: &PlanBindings<'_>,
    nodes: &[DependencyGraphNodeV1],
    by_digest: &BTreeMap<[u8; 32], usize>,
    edges: &[InputDependencyV1],
) -> Result<EdgeScan, DependencyGraphErrorV1> {
    let edge_digests = edges
        .iter()
        .map(InputDependencyV1::digest)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|digests| validate_input_dependency_list_order_v1(edges).map(|()| digests))
        .map_err(DependencyGraphErrorV1::Dependency)?;
    let mut outgoing = Vec::with_capacity(edges.len());
    let mut first_error: Option<KeyedEdgeError> = None;
    for edge in edges {
        match validate_edge(bindings, nodes, by_digest, edge) {
            Ok(positions) => outgoing.push(positions),
            Err(error) => {
                let key = edge_coordinate(edge);
                if first_error.as_ref().is_none_or(|(first, _)| key < *first) {
                    first_error = Some((key, error));
                }
            }
        }
    }
    outgoing.sort_unstable();
    Ok(EdgeScan {
        edge_digests,
        outgoing,
        first_error,
    })
}

fn validate_edge(
    bindings: &PlanBindings<'_>,
    nodes: &[DependencyGraphNodeV1],
    by_digest: &BTreeMap<[u8; 32], usize>,
    edge: &InputDependencyV1,
) -> Result<(usize, usize), DependencyGraphErrorV1> {
    match (
        declared(nodes, by_digest, &edge.consumer),
        declared(nodes, by_digest, &edge.source),
    ) {
        (Some(consumer), Some(source))
            if nodes[consumer]
                .input_digests
                .binary_search(&edge.source.artifact_digest)
                .is_ok() =>
        {
            check_edge_rules(bindings, &nodes[consumer], &nodes[source], edge)
                .map(|()| (source, consumer))
        }
        _ => Err(DependencyGraphErrorV1::UnknownDependencyEdge(Box::new(
            edge_coordinate(edge),
        ))),
    }
}

/// Position of the declared node whose exact coordinate is `coordinate`.
fn declared(
    nodes: &[DependencyGraphNodeV1],
    by_digest: &BTreeMap<[u8; 32], usize>,
    coordinate: &DependencyNodeV1,
) -> Option<usize> {
    by_digest
        .get(&coordinate.artifact_digest)
        .copied()
        .filter(|&position| nodes[position].node == *coordinate)
}

fn check_edge_rules(
    bindings: &PlanBindings<'_>,
    consumer: &DependencyGraphNodeV1,
    source: &DependencyGraphNodeV1,
    edge: &InputDependencyV1,
) -> Result<(), DependencyGraphErrorV1> {
    if edge.tick_range.last_tick > bindings.plan.horizon_tick {
        Err(DependencyGraphErrorV1::OutOfRange)
    } else if edge.dependency_class != source.class
        || (source.class == DependencyClassV1::PresentationOnly
            && consumer.class != DependencyClassV1::PresentationOnly)
    {
        Err(DependencyGraphErrorV1::ClassRuleViolation(Box::new(
            edge_coordinate(edge),
        )))
    } else if bindings
        .root_binding(source)
        .is_some_and(|binding| binding.authorization_digest != edge.authorization_digest)
    {
        Err(DependencyGraphErrorV1::UnauthorizedDependency(Box::new(
            edge_coordinate(edge),
        )))
    } else {
        Ok(())
    }
}

/// Resolve per-edge errors and missing direct edges under `policy`, and
/// return the missing edges recorded in canonical RCF1 order.
///
/// Only valid edges count as present, so an invalid edge never hides a
/// missing edge with a smaller canonical key.
fn missing_edges(
    policy: UnknownEdgePolicyV1,
    nodes: &[DependencyGraphNodeV1],
    outgoing: &[(usize, usize)],
    first_error: Option<KeyedEdgeError>,
) -> Result<Vec<UnknownEdgeCoordinateV1>, DependencyGraphErrorV1> {
    let present: BTreeSet<(&[u8; 32], &[u8; 32])> = outgoing
        .iter()
        .map(|&(source, consumer)| {
            (
                &nodes[consumer].node.artifact_digest,
                &nodes[source].node.artifact_digest,
            )
        })
        .collect();
    // Nodes are in canonical coordinate order, so gaps arrive in RCF1 order.
    let mut gaps = nodes.iter().flat_map(|node| node_gaps(node, &present));
    match (policy, first_error) {
        (UnknownEdgePolicyV1::Reject, first_error) => {
            let first_gap = gaps.next().map(|gap| {
                (
                    gap.clone(),
                    DependencyGraphErrorV1::DependencyGraphIncomplete(Box::new(gap)),
                )
            });
            // `min_by` keeps the first of equal keys, so an edge error wins a tie.
            first_error
                .into_iter()
                .chain(first_gap)
                .min_by(|left, right| left.0.cmp(&right.0))
                .map_or(Ok(Vec::new()), |(_, error)| Err(error))
        }
        (UnknownEdgePolicyV1::FullSuffixFromCut, Some((_, error))) => Err(error),
        (UnknownEdgePolicyV1::FullSuffixFromCut, None) => {
            let recorded: Vec<_> = gaps.take(MAX_UNKNOWN_EDGE_COORDINATES_V1 + 1).collect();
            if recorded.len() > MAX_UNKNOWN_EDGE_COORDINATES_V1 {
                Err(DependencyGraphErrorV1::ResourceLimitExceeded)
            } else {
                Ok(recorded)
            }
        }
    }
}

/// Missing edges of one node: an unknown input closure of a provisional
/// endogenous node first, then every declared input without a valid edge, in
/// ascending digest order.
fn node_gaps<'g>(
    node: &'g DependencyGraphNodeV1,
    present: &'g BTreeSet<(&'g [u8; 32], &'g [u8; 32])>,
) -> impl Iterator<Item = UnknownEdgeCoordinateV1> + 'g {
    // A committed no-input node is initial state of the parent prefix, not a gap.
    let unknown_closure = node.class == DependencyClassV1::EndogenousRecomputed
        && node.origin == DependencyGraphNodeOriginV1::Provisional
        && node.input_digests.is_empty();
    unknown_closure.then(|| gap(node, None)).into_iter().chain(
        node.input_digests
            .iter()
            .filter(move |&source| !present.contains(&(&node.node.artifact_digest, source)))
            .map(move |source| gap(node, Some(*source))),
    )
}

fn gap(node: &DependencyGraphNodeV1, source: Option<[u8; 32]>) -> UnknownEdgeCoordinateV1 {
    UnknownEdgeCoordinateV1 {
        consumer: node.node.clone(),
        missing_source_digest: source,
    }
}

fn edge_coordinate(edge: &InputDependencyV1) -> UnknownEdgeCoordinateV1 {
    UnknownEdgeCoordinateV1 {
        consumer: edge.consumer.clone(),
        missing_source_digest: Some(edge.source.artifact_digest),
    }
}

const fn ordered(ordering: Ordering) -> Result<(), DependencyGraphErrorV1> {
    match ordering {
        Ordering::Less => Ok(()),
        Ordering::Equal => Err(DependencyGraphErrorV1::DuplicateIdentity),
        Ordering::Greater => Err(DependencyGraphErrorV1::NonCanonicalOrder),
    }
}
