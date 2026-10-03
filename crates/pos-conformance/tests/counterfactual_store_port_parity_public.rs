#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Parity guard between the conformance `RCF1`/`SIV1` codecs and the
//! `pos-core` counterfactual storage port, which carries both records as
//! verified canonical bytes without a CBOR decoder.

use pos_conformance::counterfactual::frontier_artifacts::{
    MAX_RECOMPUTATION_FRONTIER_BYTES_V1, MAX_SUFFIX_INVALIDATION_BYTES_V1,
};
use pos_conformance::{
    DependencyNodeV1, InvalidArtifactV1, OwnerFrontierV1, RecomputationFrontierV1,
    SuffixInvalidationReasonV1, SuffixInvalidationV1, UnknownEdgePolicyV1,
};
use pos_core::{
    Hash, RecomputationFrontierBytesV1, SuffixInvalidationBytesV1,
    MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1, MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn node(tick: u64, scheduler_position: u32, owner_id: &str) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick,
        scheduler_position,
        owner_id: owner_id.to_owned(),
        output_ordinal: 0,
        schema_id: 7,
        artifact_digest: [9; 32],
    }
}

fn artifact(artifact_class: &str, producer: DependencyNodeV1) -> InvalidArtifactV1 {
    InvalidArtifactV1 {
        artifact_class: artifact_class.to_owned(),
        schema_id: 70_000,
        artifact_digest: [11; 32],
        producer,
        prior_generation: 300,
        reason: SuffixInvalidationReasonV1::NewIntervention,
    }
}

fn frontier() -> TestResult<RecomputationFrontierV1> {
    let mut frontier = RecomputationFrontierV1 {
        frontier_id: [1; 16],
        plan_digest: [2; 32],
        parent_cut_digest: [3; 32],
        dependency_graph_digest: [4; 32],
        intervention_seed_nodes: vec![node(5, 0, "agent-a")],
        affected_nodes: vec![node(5, 0, "agent-a"), node(6, 1, "agent-b")],
        owner_frontiers: vec![
            OwnerFrontierV1 {
                owner_id: "agent-a".to_owned(),
                earliest_tick: 5,
                earliest_scheduler_position: 0,
                earliest_output_ordinal: 0,
                cause_node_digests: vec![[1; 32]],
            },
            OwnerFrontierV1 {
                owner_id: "agent-b".to_owned(),
                earliest_tick: 6,
                earliest_scheduler_position: 1,
                earliest_output_ordinal: 0,
                cause_node_digests: vec![[2; 32], [3; 32]],
            },
        ],
        global_frontier_tick: 5,
        global_frontier_scheduler_position: 0,
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
        unknown_edge_coordinates: Vec::new(),
        endogenous_suffix_end_tick: 9,
        classification_bundle_digest: [5; 32],
        provenance_digest: [6; 32],
        frontier_digest: [0; 32],
    };
    frontier.frontier_digest = frontier.digest()?;
    Ok(frontier)
}

fn invalidation(
    frontier: &RecomputationFrontierV1,
    prior_generation: u64,
    commit_seq: u64,
    commit_tick: u64,
) -> TestResult<SuffixInvalidationV1> {
    let long_owner = "an-owner-identifier-longer-than-twenty-four-bytes";
    let mut invalidation = SuffixInvalidationV1 {
        invalidation_id: [1; 16],
        plan_digest: frontier.plan_digest,
        fork_id: [3; 16],
        prior_generation,
        new_generation: prior_generation + 1,
        frontier_digest: frontier.frontier_digest,
        invalid_start: node(5, 0, "agent-a"),
        invalid_end: node(4_294_967_296, 0, long_owner),
        invalid_artifacts: vec![
            artifact("event", node(5, 0, "agent-a")),
            artifact("projection", node(5, 0, "agent-a")),
            artifact("event", node(6, 1, long_owner)),
        ],
        invalid_checkpoint_digests: vec![[5; 32], [6; 32]],
        invalid_projection_digests: vec![[7; 32]],
        retained_exogenous_digests: vec![[8; 32]],
        reason: SuffixInvalidationReasonV1::TrustOrErasureChange,
        commit_timeline_id: [3; 16],
        commit_seq,
        commit_tick,
        provenance_digest: [13; 32],
        invalidation_digest: [0; 32],
    };
    invalidation.invalidation_digest = invalidation.digest()?;
    Ok(invalidation)
}

#[test]
fn port_size_limits_match_the_conformance_codecs() {
    assert_eq!(
        MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1,
        MAX_RECOMPUTATION_FRONTIER_BYTES_V1
    );
    assert_eq!(
        MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1,
        MAX_SUFFIX_INVALIDATION_BYTES_V1
    );
}

#[test]
fn port_reads_conformance_frontier_bytes() -> TestResult {
    let frontier = frontier()?;
    let bytes = frontier.to_canonical_cbor()?;
    let port = RecomputationFrontierBytesV1::try_from_canonical(bytes.clone())?;
    assert_eq!(port.as_bytes(), bytes.as_slice());
    assert_eq!(port.digest(), Hash::from_bytes(frontier.frontier_digest));
    assert_eq!(port.plan_digest(), Hash::from_bytes(frontier.plan_digest));
    assert_eq!(
        port.dependency_graph_digest(),
        Hash::from_bytes(frontier.dependency_graph_digest)
    );
    Ok(())
}

#[test]
fn port_reads_conformance_invalidation_bytes() -> TestResult {
    let frontier = frontier()?;
    for (prior_generation, commit_seq, commit_tick) in [
        (0, 0, 0),
        (23, 24, 255),
        (65_535, 4_294_967_296, 70_000),
        (u64::MAX - 1, u64::MAX, u64::MAX),
    ] {
        let invalidation = invalidation(&frontier, prior_generation, commit_seq, commit_tick)?;
        let bytes = invalidation.to_canonical_cbor()?;
        let port = SuffixInvalidationBytesV1::try_from_canonical(bytes.clone())?;
        assert_eq!(port.as_bytes(), bytes.as_slice());
        assert_eq!(
            port.digest(),
            Hash::from_bytes(invalidation.invalidation_digest)
        );
        assert_eq!(
            port.plan_digest(),
            Hash::from_bytes(invalidation.plan_digest)
        );
        assert_eq!(port.fork_id(), invalidation.fork_id);
        assert_eq!(port.prior_generation(), invalidation.prior_generation);
        assert_eq!(port.new_generation(), invalidation.new_generation);
        assert_eq!(
            port.frontier_digest(),
            Hash::from_bytes(invalidation.frontier_digest)
        );
        assert_eq!(port.commit_timeline_id(), invalidation.commit_timeline_id);
        assert_eq!(port.commit_seq(), invalidation.commit_seq);
        assert_eq!(port.commit_tick(), invalidation.commit_tick);
    }
    Ok(())
}
