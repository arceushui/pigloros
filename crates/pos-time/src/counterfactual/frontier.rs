//! Pure deterministic derivation of the ADR-064 `RCF1` recomputation
//! frontier.
//!
//! [`derive_recomputation_frontier_v1`] takes a CFP1 [`CounterfactualPlanV1`]
//! and the [`ValidatedDependencyGraphV1`] that was validated against it and
//! returns a sealed `RCF1` [`RecomputationFrontierV1`] that passes the
//! standalone `RCF1` validation and carries its exact frontier digest. It
//! inventories no invalid artifact, persists nothing, evicts nothing,
//! executes no Tick, and calls no Plugin.
//!
//! Derivation follows ADR-064 "Frontier derivation":
//!
//! 1. the seed nodes are the `InterventionAssigned` nodes of the plan's
//!    ordered Interventions, each at its effective Tick Boundary;
//! 2. outgoing dependency edges are traversed transitively in canonical
//!    breadth-first layers, each layer in node-coordinate order, and every
//!    node is visited once;
//! 3. each owner's frontier is its lowest affected node coordinate, and the
//!    owner frontiers are sorted by the `RCF1` rule;
//! 4. the global frontier is the lowest owner frontier, which is never later
//!    than the earliest Intervention, or the first scheduler position of the
//!    first Tick after the parent cut when edges are missing;
//! 5. the endogenous suffix always ends at the plan horizon, because the
//!    complete-suffix rule recomputes every endogenous artifact from the
//!    global frontier through the horizon regardless of reachability.
//!
//! Contract decisions where ADR-064 is silent:
//!
//! - The seeds are exactly the plan's Intervention nodes. A node whose
//!   classification or canonical request digest changes because of a target
//!   is a consumer of that target in the closed graph, so traversal reaches
//!   it in the first layer.
//! - Traversal enters only `EndogenousRecomputed` consumers. Roots declare no
//!   input and are never consumers, so `ExogenousFrozen` and `FixedPolicy`
//!   nodes are never affected and their frozen bytes stay reusable;
//!   `PresentationOnly` outputs are excluded from the suffix claim. Node
//!   coordinates and artifact digests are one-to-one in a validated graph, so
//!   visiting a coordinate once visits its digest once.
//! - Owner frontiers range over every affected node, seeds included. The
//!   cause digests of an owner frontier are the ascending digests of its
//!   affected direct inputs; a seed has none, so its cause is its own
//!   artifact digest, the INT1 record digest.
//! - The `FullSuffixFromCut` fallback is applied, and recorded in `RCF1`
//!   field 11, only when the graph recorded a missing edge. A complete graph
//!   validated under `FullSuffixFromCut` yields the fine-grained frontier and
//!   records `Reject`, since `RCF1` forbids `FullSuffixFromCut` without an
//!   unknown-edge coordinate. Under the fallback the affected nodes and owner
//!   frontiers remain the explanatory reachability of the known edges.
//! - The derived frontier is checked by the standalone `RCF1` validation, so
//!   its seed, affected-node, owner-frontier, cause-digest, and encoded-size
//!   bounds surface as [`RecomputationFrontierErrorV1::Frontier`].
//!
//! ADR gap: `RCF1` field 5 names a dependency-graph digest, but no canonical
//! graph encoding exists. [`dependency_graph_digest_v1`] defines a minimal
//! deterministic one: BLAKE3 over `PiglorOS.CounterfactualDependencyGraph.v1`,
//! a zero byte, the plan digest, the big-endian `u64` node count, every node
//! frame in canonical node order, the big-endian `u64` edge count, and the
//! canonical IDP1 digest of every edge in canonical edge order. A node frame
//! is the big-endian `tick` (`u64`), `scheduler_position` (`u32`), owner byte
//! length (`u64`) and owner bytes, `output_ordinal` (`u32`), and `schema_id`
//! (`u32`); the artifact digest; the one-byte IDP1 class code, from
//! `ExogenousFrozen` = 0 through `PresentationOnly` = 4 in IDP1 order; the
//! big-endian `u64` declared-input count and the declared input digests; and
//! the provenance digest. The node origin is omitted because the plan's
//! parent-cut Tick determines it.

use super::dependency_graph::{DependencyGraphNodeV1, ValidatedDependencyGraphV1};
use pos_conformance::counterfactual::frontier_artifacts::FrontierArtifactErrorV1;
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1,
};
use pos_conformance::{
    DependencyClassV1, DependencyNodeV1, OwnerFrontierV1, RecomputationFrontierV1,
    UnknownEdgePolicyV1,
};
use std::collections::{BTreeMap, BTreeSet};

const DEPENDENCY_GRAPH_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.CounterfactualDependencyGraph.v1";

/// Closed safe errors exposed by recomputation-frontier derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecomputationFrontierErrorV1 {
    /// The CFP1 plan is invalid.
    #[error("recomputation-frontier counterfactual plan is invalid")]
    Plan(#[source] CounterfactualPlanContractErrorV1),
    /// The plan is not the plan the dependency graph was validated against.
    #[error("recomputation-frontier plan does not match the dependency graph")]
    PlanMismatch,
    /// The frontier provenance digest is all zero.
    #[error("recomputation-frontier provenance is missing")]
    ProvenanceMissing,
    /// The derived frontier violates the `RCF1` contract or its bounds.
    #[error("recomputation frontier violates the RCF1 contract")]
    Frontier(#[source] FrontierArtifactErrorV1),
}

/// Derive the sealed `RCF1` recomputation frontier of `graph` for `plan`.
///
/// `frontier_id` and `provenance_digest` fill `RCF1` fields 2 and 15; every
/// other field is derived from the plan and the graph. See the module
/// documentation for every rule.
///
/// # Errors
///
/// Returns the first closed safe error: an invalid plan, a zero provenance
/// digest, a plan other than the graph's, or a frontier that violates the
/// `RCF1` contract or its bounds.
pub fn derive_recomputation_frontier_v1(
    plan: &CounterfactualPlanV1,
    graph: &ValidatedDependencyGraphV1,
    frontier_id: [u8; 16],
    provenance_digest: [u8; 32],
) -> Result<RecomputationFrontierV1, RecomputationFrontierErrorV1> {
    check_inputs(plan, graph, provenance_digest)?;
    seal(RecomputationFrontierV1 {
        frontier_id,
        dependency_graph_digest: dependency_graph_digest_v1(graph),
        provenance_digest,
        ..unsealed_frontier(plan, graph)
    })
    .map_err(RecomputationFrontierErrorV1::Frontier)
}

/// Compute the documented digest of a validated dependency graph.
///
/// See the module documentation for the exact hashed frame. The edge digests
/// are the ones recorded when the graph was validated, so no edge is
/// re-encoded here.
#[must_use]
pub fn dependency_graph_digest_v1(graph: &ValidatedDependencyGraphV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DEPENDENCY_GRAPH_DIGEST_DOMAIN_V1);
    hasher.update(&[0]);
    hasher.update(&graph.plan_digest());
    hasher.update(&length(graph.nodes().len()));
    for node in graph.nodes() {
        hash_node(&mut hasher, node);
    }
    hasher.update(&length(graph.edge_digests().len()));
    for digest in graph.edge_digests() {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn check_inputs(
    plan: &CounterfactualPlanV1,
    graph: &ValidatedDependencyGraphV1,
    provenance_digest: [u8; 32],
) -> Result<(), RecomputationFrontierErrorV1> {
    plan.validate()
        .map_err(RecomputationFrontierErrorV1::Plan)
        .and_then(|()| {
            if provenance_digest == [0; 32] {
                Err(RecomputationFrontierErrorV1::ProvenanceMissing)
            } else if plan.plan_digest == graph.plan_digest() {
                Ok(())
            } else {
                Err(RecomputationFrontierErrorV1::PlanMismatch)
            }
        })
}

/// Every derived field; the caller supplies the ID, graph digest, and
/// provenance, and [`seal`] supplies the frontier digest.
fn unsealed_frontier(
    plan: &CounterfactualPlanV1,
    graph: &ValidatedDependencyGraphV1,
) -> RecomputationFrontierV1 {
    let affected = affected_nodes(graph);
    let fallback = !graph.is_complete();
    // The plan has at least one Intervention and the graph one node for each,
    // so `affected` is never empty; its lowest node is the lowest owner
    // frontier (ADR-064 derivation step 5).
    let earliest = &affected[0].node;
    let (global_frontier_tick, global_frontier_scheduler_position, unknown_edge_policy) =
        if fallback {
            (
                graph.first_tick(),
                0,
                UnknownEdgePolicyV1::FullSuffixFromCut,
            )
        } else {
            (
                earliest.tick,
                earliest.scheduler_position,
                UnknownEdgePolicyV1::Reject,
            )
        };
    // `frontier_id`, `dependency_graph_digest` and `provenance_digest` are
    // placeholders the caller overwrites, and `seal` computes
    // `frontier_digest`.
    RecomputationFrontierV1 {
        frontier_id: [0; 16],
        plan_digest: plan.plan_digest,
        parent_cut_digest: plan.parent_cut_digest,
        dependency_graph_digest: [0; 32],
        intervention_seed_nodes: seeds(graph).map(|node| node.node.clone()).collect(),
        affected_nodes: affected.iter().map(|node| node.node.clone()).collect(),
        owner_frontiers: owner_frontiers(&affected),
        global_frontier_tick,
        global_frontier_scheduler_position,
        unknown_edge_policy,
        unknown_edge_coordinates: graph.unknown_edge_coordinates().to_vec(),
        endogenous_suffix_end_tick: graph.horizon_tick(),
        classification_bundle_digest: plan.classification_bundle_digest,
        provenance_digest: [0; 32],
        frontier_digest: [0; 32],
    }
}

/// The Intervention nodes, in canonical node order.
fn seeds(graph: &ValidatedDependencyGraphV1) -> impl Iterator<Item = &DependencyGraphNodeV1> + '_ {
    graph
        .nodes()
        .iter()
        .filter(|node| node.class == DependencyClassV1::InterventionAssigned)
}

/// Seeds plus every endogenous node reachable from them, in canonical order.
fn affected_nodes(graph: &ValidatedDependencyGraphV1) -> Vec<&DependencyGraphNodeV1> {
    let mut affected: BTreeMap<&DependencyNodeV1, &DependencyGraphNodeV1> =
        seeds(graph).map(|node| (&node.node, node)).collect();
    let mut layer: Vec<&DependencyGraphNodeV1> = affected.values().copied().collect();
    while !layer.is_empty() {
        let next: BTreeMap<&DependencyNodeV1, &DependencyGraphNodeV1> = layer
            .iter()
            .flat_map(|node| graph.consumers(node.node.artifact_digest))
            .filter(|consumer| {
                consumer.class == DependencyClassV1::EndogenousRecomputed
                    && !affected.contains_key(&consumer.node)
            })
            .map(|consumer| (&consumer.node, consumer))
            .collect();
        layer = next.values().copied().collect();
        affected.extend(next);
    }
    affected.into_values().collect()
}

/// The first affected node of each owner, which is its lowest coordinate.
fn owner_frontiers(affected: &[&DependencyGraphNodeV1]) -> Vec<OwnerFrontierV1> {
    let digests: BTreeSet<[u8; 32]> = affected
        .iter()
        .map(|node| node.node.artifact_digest)
        .collect();
    let mut owners = BTreeSet::new();
    affected
        .iter()
        .filter(|node| owners.insert(node.node.owner_id.as_str()))
        .map(|node| owner_frontier(node, &digests))
        .collect()
}

fn owner_frontier(node: &DependencyGraphNodeV1, affected: &BTreeSet<[u8; 32]>) -> OwnerFrontierV1 {
    let causes: Vec<[u8; 32]> = node
        .input_digests
        .iter()
        .filter(|digest| affected.contains(*digest))
        .copied()
        .collect();
    OwnerFrontierV1 {
        owner_id: node.node.owner_id.clone(),
        earliest_tick: node.node.tick,
        earliest_scheduler_position: node.node.scheduler_position,
        earliest_output_ordinal: node.node.output_ordinal,
        cause_node_digests: if causes.is_empty() {
            vec![node.node.artifact_digest]
        } else {
            causes
        },
    }
}

/// Fill the frontier digest, then run the standalone `RCF1` validation.
///
/// This is the fewest encodings the public `RCF1` API allows: `digest`
/// encodes the unsigned fields once, and `validate` must run on the sealed
/// record to enforce the field and encoded-size bounds. The re-encoding that
/// `validate` does internally to verify the digest belongs to the `RCF1`
/// contract, not to this derivation.
fn seal(
    unsigned: RecomputationFrontierV1,
) -> Result<RecomputationFrontierV1, FrontierArtifactErrorV1> {
    unsigned
        .digest()
        .map(|frontier_digest| RecomputationFrontierV1 {
            frontier_digest,
            ..unsigned
        })
        .and_then(|frontier| frontier.validate().map(|()| frontier))
}

fn hash_node(hasher: &mut blake3::Hasher, node: &DependencyGraphNodeV1) {
    let coordinate = &node.node;
    hasher.update(&coordinate.tick.to_be_bytes());
    hasher.update(&coordinate.scheduler_position.to_be_bytes());
    hasher.update(&length(coordinate.owner_id.len()));
    hasher.update(coordinate.owner_id.as_bytes());
    hasher.update(&coordinate.output_ordinal.to_be_bytes());
    hasher.update(&coordinate.schema_id.to_be_bytes());
    hasher.update(&coordinate.artifact_digest);
    hasher.update(&[class_code(node.class)]);
    hasher.update(&length(node.input_digests.len()));
    for digest in &node.input_digests {
        hasher.update(digest);
    }
    hasher.update(&node.provenance_digest);
}

const fn length(count: usize) -> [u8; 8] {
    (count as u64).to_be_bytes()
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
