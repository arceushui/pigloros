#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-064 `RCF1` and `SIV1` artifact codecs.

use ciborium::value::Value;
use pos_conformance::counterfactual::frontier_artifacts::{
    FrontierArtifactErrorV1, UnknownEdgeCoordinateV1, MAX_RECOMPUTATION_FRONTIER_BYTES_V1,
    MAX_SUFFIX_INVALIDATION_BYTES_V1,
};
use pos_conformance::{
    DependencyNodeV1, InvalidArtifactV1, OwnerFrontierV1, RecomputationFrontierV1,
    SuffixInvalidationReasonV1, SuffixInvalidationV1, UnknownEdgePolicyV1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type FrontierMutation = fn(&mut RecomputationFrontierV1);
type InvalidationMutation = fn(&mut SuffixInvalidationV1);

const FRONTIER_DOMAIN: &[u8] = b"PiglorOS.RecomputationFrontier.v1\0";
const INVALIDATION_DOMAIN: &[u8] = b"PiglorOS.SuffixInvalidation.v1\0";
const OUT_OF_RANGE: FrontierArtifactErrorV1 = FrontierArtifactErrorV1::FieldOutOfBounds;
const DUPLICATE: FrontierArtifactErrorV1 = FrontierArtifactErrorV1::DuplicateIdentity;
const UNORDERED: FrontierArtifactErrorV1 = FrontierArtifactErrorV1::NonCanonicalOrder;
const ENCODING: FrontierArtifactErrorV1 = FrontierArtifactErrorV1::InvalidEncoding;

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

fn owner(
    owner_id: &str,
    earliest_tick: u64,
    earliest_scheduler_position: u32,
    cause_node_digests: Vec<[u8; 32]>,
) -> OwnerFrontierV1 {
    OwnerFrontierV1 {
        owner_id: owner_id.to_owned(),
        earliest_tick,
        earliest_scheduler_position,
        earliest_output_ordinal: 0,
        cause_node_digests,
    }
}

const fn edge(
    consumer: DependencyNodeV1,
    missing_source_digest: Option<[u8; 32]>,
) -> UnknownEdgeCoordinateV1 {
    UnknownEdgeCoordinateV1 {
        consumer,
        missing_source_digest,
    }
}

fn artifact(artifact_class: &str, producer: DependencyNodeV1) -> InvalidArtifactV1 {
    InvalidArtifactV1 {
        artifact_class: artifact_class.to_owned(),
        schema_id: 7,
        artifact_digest: [11; 32],
        producer,
        prior_generation: 0,
        reason: SuffixInvalidationReasonV1::NewIntervention,
    }
}

fn nodes_at_positions(count: u32) -> Vec<DependencyNodeV1> {
    (0..count)
        .map(|position| node(5, position, "agent-a"))
        .collect()
}

fn ascending_digests(count: u32) -> Vec<[u8; 32]> {
    (0..count)
        .map(|index| {
            let mut digest = [1; 32];
            digest[..4].copy_from_slice(&index.to_be_bytes());
            digest
        })
        .collect()
}

fn unsigned_frontier() -> RecomputationFrontierV1 {
    RecomputationFrontierV1 {
        frontier_id: [1; 16],
        plan_digest: [2; 32],
        parent_cut_digest: [3; 32],
        dependency_graph_digest: [4; 32],
        intervention_seed_nodes: vec![node(5, 0, "agent-a")],
        affected_nodes: vec![node(5, 0, "agent-a"), node(6, 1, "agent-b")],
        owner_frontiers: vec![
            owner("agent-a", 5, 0, vec![[1; 32]]),
            owner("agent-b", 6, 1, vec![[2; 32], [3; 32]]),
        ],
        global_frontier_tick: 5,
        global_frontier_scheduler_position: 0,
        unknown_edge_policy: UnknownEdgePolicyV1::Reject,
        unknown_edge_coordinates: Vec::new(),
        endogenous_suffix_end_tick: 9,
        classification_bundle_digest: [5; 32],
        provenance_digest: [6; 32],
        frontier_digest: [0; 32],
    }
}

fn full_suffix(frontier: &mut RecomputationFrontierV1) {
    frontier.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut;
    frontier.unknown_edge_coordinates = vec![
        edge(node(6, 1, "agent-b"), None),
        edge(node(6, 1, "agent-b"), Some([4; 32])),
    ];
}

fn signed_frontier(mut frontier: RecomputationFrontierV1) -> TestResult<RecomputationFrontierV1> {
    frontier.frontier_digest = frontier.digest()?;
    Ok(frontier)
}

fn frontier() -> TestResult<RecomputationFrontierV1> {
    signed_frontier(unsigned_frontier())
}

fn full_suffix_frontier() -> TestResult<RecomputationFrontierV1> {
    let mut frontier = unsigned_frontier();
    full_suffix(&mut frontier);
    signed_frontier(frontier)
}

fn unsigned_invalidation() -> SuffixInvalidationV1 {
    SuffixInvalidationV1 {
        invalidation_id: [1; 16],
        plan_digest: [2; 32],
        fork_id: [3; 16],
        prior_generation: 0,
        new_generation: 1,
        frontier_digest: [4; 32],
        invalid_start: node(5, 0, "agent-a"),
        invalid_end: node(9, 0, "agent-b"),
        invalid_artifacts: vec![
            artifact("event", node(5, 0, "agent-a")),
            artifact("projection", node(5, 0, "agent-a")),
            artifact("event", node(6, 1, "agent-b")),
        ],
        invalid_checkpoint_digests: vec![[5; 32], [6; 32]],
        invalid_projection_digests: vec![[7; 32]],
        retained_exogenous_digests: vec![[8; 32]],
        reason: SuffixInvalidationReasonV1::NewIntervention,
        commit_timeline_id: [12; 16],
        commit_seq: 3,
        commit_tick: 5,
        provenance_digest: [13; 32],
        invalidation_digest: [0; 32],
    }
}

fn signed_invalidation(mut invalidation: SuffixInvalidationV1) -> TestResult<SuffixInvalidationV1> {
    invalidation.invalidation_digest = invalidation.digest()?;
    Ok(invalidation)
}

fn invalidation() -> TestResult<SuffixInvalidationV1> {
    signed_invalidation(unsigned_invalidation())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn beyond_u32() -> Value {
    uint(u64::from(u32::MAX) + 1)
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

fn decode(encoded: &[u8]) -> TestResult<Value> {
    Ok(ciborium::from_reader(encoded)?)
}

fn root_fields(encoded: &[u8]) -> TestResult<Vec<Value>> {
    match decode(encoded)? {
        Value::Array(fields) => Ok(fields),
        _ => Err("expected a CBOR array".into()),
    }
}

fn replace_at(value: &mut Value, path: &[usize], replacement: Value) -> TestResult {
    let Some((index, rest)) = path.split_first() else {
        *value = replacement;
        return Ok(());
    };
    let Value::Array(items) = value else {
        return Err("path crosses a non-array value".into());
    };
    let item = items.get_mut(*index).ok_or("path index is absent")?;
    replace_at(item, rest, replacement)
}

fn replaced(encoded: &[u8], path: &[usize], replacement: Value) -> TestResult<Vec<u8>> {
    let mut document = decode(encoded)?;
    replace_at(&mut document, path, replacement)?;
    encode(&document)
}

/// Recompute a record digest without the library: the domain, then the
/// canonical array of every field except the trailing digest.
fn independent_digest(encoded: &[u8], domain: &[u8]) -> TestResult<[u8; 32]> {
    let mut fields = root_fields(encoded)?;
    fields.pop();
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&encode(&Value::Array(fields))?);
    Ok(*hasher.finalize().as_bytes())
}

fn node_value(node: &DependencyNodeV1) -> Value {
    Value::Array(vec![
        uint(node.tick),
        uint(node.scheduler_position.into()),
        text(&node.owner_id),
        uint(node.output_ordinal.into()),
        uint(node.schema_id.into()),
        bytes(&node.artifact_digest),
    ])
}

fn digests_value(digests: &[[u8; 32]]) -> Value {
    Value::Array(
        digests
            .iter()
            .map(|digest| bytes(digest.as_slice()))
            .collect(),
    )
}

const fn policy_code(policy: UnknownEdgePolicyV1) -> u64 {
    match policy {
        UnknownEdgePolicyV1::Reject => 0,
        UnknownEdgePolicyV1::FullSuffixFromCut => 1,
    }
}

const fn reason_code(reason: SuffixInvalidationReasonV1) -> u64 {
    match reason {
        SuffixInvalidationReasonV1::NewIntervention => 0,
        SuffixInvalidationReasonV1::ChangedIntervention => 1,
        SuffixInvalidationReasonV1::UnknownEdgeFallback => 2,
        SuffixInvalidationReasonV1::RetryAfterAtomicFailure => 3,
        SuffixInvalidationReasonV1::TrustOrErasureChange => 4,
    }
}

fn expected_frontier_value(frontier: &RecomputationFrontierV1) -> Value {
    Value::Array(vec![
        text("RCF1"),
        uint(1),
        bytes(&frontier.frontier_id),
        bytes(&frontier.plan_digest),
        bytes(&frontier.parent_cut_digest),
        bytes(&frontier.dependency_graph_digest),
        Value::Array(
            frontier
                .intervention_seed_nodes
                .iter()
                .map(node_value)
                .collect(),
        ),
        Value::Array(frontier.affected_nodes.iter().map(node_value).collect()),
        Value::Array(
            frontier
                .owner_frontiers
                .iter()
                .map(|owner| {
                    Value::Array(vec![
                        text(&owner.owner_id),
                        uint(owner.earliest_tick),
                        uint(owner.earliest_scheduler_position.into()),
                        uint(owner.earliest_output_ordinal.into()),
                        digests_value(&owner.cause_node_digests),
                    ])
                })
                .collect(),
        ),
        uint(frontier.global_frontier_tick),
        uint(frontier.global_frontier_scheduler_position.into()),
        uint(policy_code(frontier.unknown_edge_policy)),
        Value::Array(
            frontier
                .unknown_edge_coordinates
                .iter()
                .map(|edge| {
                    Value::Array(vec![
                        node_value(&edge.consumer),
                        edge.missing_source_digest
                            .map_or(Value::Null, |digest| bytes(&digest)),
                    ])
                })
                .collect(),
        ),
        uint(frontier.endogenous_suffix_end_tick),
        bytes(&frontier.classification_bundle_digest),
        bytes(&frontier.provenance_digest),
        bytes(&frontier.frontier_digest),
    ])
}

fn expected_invalidation_value(invalidation: &SuffixInvalidationV1) -> Value {
    Value::Array(vec![
        text("SIV1"),
        uint(1),
        bytes(&invalidation.invalidation_id),
        bytes(&invalidation.plan_digest),
        bytes(&invalidation.fork_id),
        uint(invalidation.prior_generation),
        uint(invalidation.new_generation),
        bytes(&invalidation.frontier_digest),
        node_value(&invalidation.invalid_start),
        node_value(&invalidation.invalid_end),
        Value::Array(
            invalidation
                .invalid_artifacts
                .iter()
                .map(|artifact| {
                    Value::Array(vec![
                        text(&artifact.artifact_class),
                        uint(artifact.schema_id.into()),
                        bytes(&artifact.artifact_digest),
                        node_value(&artifact.producer),
                        uint(artifact.prior_generation),
                        uint(reason_code(artifact.reason)),
                    ])
                })
                .collect(),
        ),
        digests_value(&invalidation.invalid_checkpoint_digests),
        digests_value(&invalidation.invalid_projection_digests),
        digests_value(&invalidation.retained_exogenous_digests),
        uint(reason_code(invalidation.reason)),
        Value::Array(vec![
            bytes(&invalidation.commit_timeline_id),
            uint(invalidation.commit_seq),
            uint(invalidation.commit_tick),
        ]),
        bytes(&invalidation.provenance_digest),
        bytes(&invalidation.invalidation_digest),
    ])
}

fn assert_frontier_rejected(cases: &[(&str, FrontierMutation, FrontierArtifactErrorV1)]) {
    for (name, mutate, expected) in cases {
        let mut candidate = unsigned_frontier();
        mutate(&mut candidate);
        assert_eq!(candidate.validate(), Err(*expected), "{name}");
        assert_eq!(candidate.to_canonical_cbor(), Err(*expected), "{name}");
    }
}

fn assert_frontier_accepted(cases: &[(&str, FrontierMutation)]) -> TestResult {
    for (name, mutate) in cases {
        let mut candidate = unsigned_frontier();
        mutate(&mut candidate);
        let candidate = signed_frontier(candidate)?;
        let encoded = candidate
            .to_canonical_cbor()
            .map_err(|error| format!("{name}: {error}"))?;
        assert_eq!(
            RecomputationFrontierV1::from_canonical_cbor(&encoded)?,
            candidate,
            "{name}"
        );
    }
    Ok(())
}

fn assert_invalidation_rejected(cases: &[(&str, InvalidationMutation, FrontierArtifactErrorV1)]) {
    for (name, mutate, expected) in cases {
        let mut candidate = unsigned_invalidation();
        mutate(&mut candidate);
        assert_eq!(candidate.validate(), Err(*expected), "{name}");
        assert_eq!(candidate.to_canonical_cbor(), Err(*expected), "{name}");
    }
}

fn assert_invalidation_accepted(cases: &[(&str, InvalidationMutation)]) -> TestResult {
    for (name, mutate) in cases {
        let mut candidate = unsigned_invalidation();
        mutate(&mut candidate);
        let candidate = signed_invalidation(candidate)?;
        let encoded = candidate
            .to_canonical_cbor()
            .map_err(|error| format!("{name}: {error}"))?;
        assert_eq!(
            SuffixInvalidationV1::from_canonical_cbor(&encoded)?,
            candidate,
            "{name}"
        );
    }
    Ok(())
}

fn assert_frontier_decode(encoded: &[u8], expected: FrontierArtifactErrorV1) {
    assert_eq!(
        RecomputationFrontierV1::from_canonical_cbor(encoded).map(|_| ()),
        Err(expected)
    );
}

fn assert_invalidation_decode(encoded: &[u8], expected: FrontierArtifactErrorV1) {
    assert_eq!(
        SuffixInvalidationV1::from_canonical_cbor(encoded).map(|_| ()),
        Err(expected)
    );
}

#[test]
fn frontier_roundtrips_the_exact_seventeen_field_layout_and_digest() -> TestResult {
    for frontier in [frontier()?, full_suffix_frontier()?] {
        let encoded = frontier.to_canonical_cbor()?;
        assert_eq!(encoded, encode(&expected_frontier_value(&frontier))?);
        assert_eq!(root_fields(&encoded)?.len(), 17);
        assert_eq!(frontier.validate(), Ok(()));
        assert_eq!(
            RecomputationFrontierV1::from_canonical_cbor(&encoded)?,
            frontier
        );
        assert_eq!(
            independent_digest(&encoded, FRONTIER_DOMAIN)?,
            frontier.frontier_digest
        );
        let json = serde_json::to_string(&frontier)?;
        assert_eq!(
            serde_json::from_str::<RecomputationFrontierV1>(&json)?,
            frontier
        );
    }
    Ok(())
}

#[test]
fn invalidation_roundtrips_the_exact_eighteen_field_layout_and_every_reason() -> TestResult {
    for reason in [
        SuffixInvalidationReasonV1::NewIntervention,
        SuffixInvalidationReasonV1::ChangedIntervention,
        SuffixInvalidationReasonV1::UnknownEdgeFallback,
        SuffixInvalidationReasonV1::RetryAfterAtomicFailure,
        SuffixInvalidationReasonV1::TrustOrErasureChange,
    ] {
        let mut candidate = unsigned_invalidation();
        candidate.reason = reason;
        for artifact in &mut candidate.invalid_artifacts {
            artifact.reason = reason;
        }
        let invalidation = signed_invalidation(candidate)?;
        let encoded = invalidation.to_canonical_cbor()?;
        assert_eq!(
            encoded,
            encode(&expected_invalidation_value(&invalidation))?
        );
        assert_eq!(root_fields(&encoded)?.len(), 18);
        assert_eq!(invalidation.validate(), Ok(()));
        assert_eq!(
            SuffixInvalidationV1::from_canonical_cbor(&encoded)?,
            invalidation
        );
        assert_eq!(
            independent_digest(&encoded, INVALIDATION_DOMAIN)?,
            invalidation.invalidation_digest
        );
    }
    Ok(())
}

#[test]
fn frontier_list_bounds_are_exact() -> TestResult {
    assert_frontier_rejected(&[
        (
            "no seeds",
            |f| f.intervention_seed_nodes.clear(),
            OUT_OF_RANGE,
        ),
        (
            "seeds over limit",
            |f| f.intervention_seed_nodes = nodes_at_positions(1_025),
            OUT_OF_RANGE,
        ),
        ("no affected", |f| f.affected_nodes.clear(), OUT_OF_RANGE),
        ("no owners", |f| f.owner_frontiers.clear(), OUT_OF_RANGE),
        (
            "owners over limit",
            |f| f.owner_frontiers = vec![owner("a", 5, 0, vec![[1; 32]]); 4_097],
            OUT_OF_RANGE,
        ),
        (
            "owners at limit",
            |f| f.owner_frontiers = vec![owner("a", 5, 0, vec![[1; 32]]); 4_096],
            DUPLICATE,
        ),
        (
            "no causes",
            |f| f.owner_frontiers[0].cause_node_digests.clear(),
            OUT_OF_RANGE,
        ),
        (
            "causes over limit",
            |f| f.owner_frontiers[0].cause_node_digests = ascending_digests(4_097),
            OUT_OF_RANGE,
        ),
        (
            "unknown edges over limit",
            |f| {
                f.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut;
                f.unknown_edge_coordinates = vec![edge(node(6, 1, "b"), None); 65_537];
            },
            OUT_OF_RANGE,
        ),
        (
            "unknown edges at limit",
            |f| {
                f.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut;
                f.unknown_edge_coordinates = vec![edge(node(6, 1, "b"), None); 65_536];
            },
            DUPLICATE,
        ),
    ]);
    assert_frontier_accepted(&[
        ("seeds at limit", |f| {
            f.intervention_seed_nodes = nodes_at_positions(1_024);
        }),
        ("causes at limit", |f| {
            f.owner_frontiers[0].cause_node_digests = ascending_digests(4_096);
        }),
    ])
}

#[test]
fn frontier_identifiers_and_unknown_edge_policy_are_bounded() -> TestResult {
    assert_frontier_rejected(&[
        (
            "empty seed owner",
            |f| f.intervention_seed_nodes[0].owner_id.clear(),
            OUT_OF_RANGE,
        ),
        (
            "long seed owner",
            |f| f.intervention_seed_nodes[0].owner_id = "s".repeat(129),
            OUT_OF_RANGE,
        ),
        (
            "empty affected owner",
            |f| f.affected_nodes[1].owner_id.clear(),
            OUT_OF_RANGE,
        ),
        (
            "empty frontier owner",
            |f| f.owner_frontiers[1].owner_id.clear(),
            OUT_OF_RANGE,
        ),
        (
            "long frontier owner",
            |f| f.owner_frontiers[1].owner_id = "o".repeat(129),
            OUT_OF_RANGE,
        ),
        (
            "empty unknown consumer owner",
            |f| {
                full_suffix(f);
                f.unknown_edge_coordinates[0].consumer.owner_id.clear();
            },
            OUT_OF_RANGE,
        ),
        (
            "zero unknown source digest",
            |f| {
                full_suffix(f);
                f.unknown_edge_coordinates[1].missing_source_digest = Some([0; 32]);
            },
            OUT_OF_RANGE,
        ),
        (
            "reject with unknown edges",
            |f| {
                full_suffix(f);
                f.unknown_edge_policy = UnknownEdgePolicyV1::Reject;
            },
            OUT_OF_RANGE,
        ),
        (
            "full suffix without unknown edges",
            |f| {
                f.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut;
            },
            OUT_OF_RANGE,
        ),
    ]);
    assert_frontier_accepted(&[
        ("seed owner at limit", |f| {
            f.intervention_seed_nodes[0].owner_id = "s".repeat(128);
        }),
        ("frontier owner at limit", |f| {
            f.owner_frontiers[1].owner_id = "o".repeat(128);
        }),
        ("full suffix with unknown edges", full_suffix),
    ])
}

#[test]
fn frontier_rejects_every_all_zero_digest_like_the_nested_verifier() {
    assert_frontier_rejected(&[
        (
            "zero frontier id",
            |f| f.frontier_id = [0; 16],
            OUT_OF_RANGE,
        ),
        ("zero plan", |f| f.plan_digest = [0; 32], OUT_OF_RANGE),
        (
            "zero parent cut",
            |f| f.parent_cut_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero dependency graph",
            |f| f.dependency_graph_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero classification bundle",
            |f| f.classification_bundle_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero provenance",
            |f| f.provenance_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero seed artifact",
            |f| f.intervention_seed_nodes[0].artifact_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero affected artifact",
            |f| f.affected_nodes[1].artifact_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero cause digest",
            |f| f.owner_frontiers[1].cause_node_digests[1] = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero unknown consumer artifact",
            |f| {
                full_suffix(f);
                f.unknown_edge_coordinates[0].consumer.artifact_digest = [0; 32];
            },
            OUT_OF_RANGE,
        ),
    ]);
}

#[test]
fn frontier_lists_are_strictly_ordered_and_owners_unique() {
    assert_frontier_rejected(&[
        (
            "unsorted seeds",
            |f| f.intervention_seed_nodes = vec![node(6, 0, "a"), node(5, 0, "a")],
            UNORDERED,
        ),
        (
            "duplicate seeds",
            |f| f.intervention_seed_nodes = vec![node(5, 0, "a"); 2],
            DUPLICATE,
        ),
        (
            "unsorted affected",
            |f| f.affected_nodes.reverse(),
            UNORDERED,
        ),
        (
            "unsorted owners",
            |f| f.owner_frontiers.reverse(),
            UNORDERED,
        ),
        (
            "owner bytes unsorted",
            |f| {
                f.owner_frontiers = vec![
                    owner("b", 5, 0, vec![[1; 32]]),
                    owner("a", 5, 0, vec![[1; 32]]),
                ];
            },
            UNORDERED,
        ),
        (
            "owner repeated at later coordinate",
            |f| f.owner_frontiers[1].owner_id = "agent-a".to_owned(),
            DUPLICATE,
        ),
        (
            "unsorted causes",
            |f| f.owner_frontiers[1].cause_node_digests.reverse(),
            UNORDERED,
        ),
        (
            "duplicate causes",
            |f| f.owner_frontiers[1].cause_node_digests = vec![[2; 32]; 2],
            DUPLICATE,
        ),
        (
            "unknown source order",
            |f| {
                full_suffix(f);
                f.unknown_edge_coordinates.reverse();
            },
            UNORDERED,
        ),
        (
            "duplicate unknown edges",
            |f| {
                full_suffix(f);
                f.unknown_edge_coordinates[1].missing_source_digest = None;
            },
            DUPLICATE,
        ),
    ]);
}

#[test]
fn frontier_coordinates_stay_within_range() -> TestResult {
    let out_of_range = FrontierArtifactErrorV1::FrontierOutOfRange;
    assert_frontier_rejected(&[
        (
            "suffix ends before frontier",
            |f| f.endogenous_suffix_end_tick = 4,
            out_of_range,
        ),
        (
            "owner before global scheduler",
            |f| f.global_frontier_scheduler_position = 1,
            out_of_range,
        ),
        (
            "owner before global tick",
            |f| f.global_frontier_tick = 6,
            out_of_range,
        ),
    ]);
    assert_frontier_accepted(&[
        ("suffix ends at frontier", |f| {
            f.endogenous_suffix_end_tick = 5;
        }),
        ("global before owners", |f| f.global_frontier_tick = 4),
    ])
}

#[test]
fn frontier_digest_covers_fields_two_through_fifteen_only() -> TestResult {
    let base = frontier()?;
    let mutations: [FrontierMutation; 14] = [
        |f| f.frontier_id[0] ^= 1,
        |f| f.plan_digest[0] ^= 1,
        |f| f.parent_cut_digest[0] ^= 1,
        |f| f.dependency_graph_digest[0] ^= 1,
        |f| f.intervention_seed_nodes[0].artifact_digest[0] ^= 1,
        |f| f.affected_nodes[1].output_ordinal = 1,
        |f| f.owner_frontiers[1].earliest_output_ordinal = 1,
        |f| f.global_frontier_tick = 4,
        |f| f.global_frontier_scheduler_position = 1,
        |f| f.unknown_edge_policy = UnknownEdgePolicyV1::FullSuffixFromCut,
        |f| f.unknown_edge_coordinates.push(edge(node(6, 1, "b"), None)),
        |f| f.endogenous_suffix_end_tick = 10,
        |f| f.classification_bundle_digest[0] ^= 1,
        |f| f.provenance_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        assert_ne!(candidate.digest()?, base.frontier_digest);
    }
    let mut redigested = base.clone();
    redigested.frontier_digest = [0xaa; 32];
    assert_eq!(redigested.digest()?, base.frontier_digest);
    assert_eq!(
        redigested.validate(),
        Err(FrontierArtifactErrorV1::DigestMismatch)
    );
    assert_eq!(
        redigested.to_canonical_cbor(),
        Err(FrontierArtifactErrorV1::DigestMismatch)
    );
    Ok(())
}

#[test]
fn invalidation_list_bounds_are_exact() {
    // The million-entry artifact and affected-node limits are checked on
    // counts alone; the crate's unit tests cover them without a million-entry
    // record.
    assert_invalidation_rejected(&[
        (
            "checkpoints over limit",
            |s| s.invalid_checkpoint_digests = vec![[1; 32]; 65_537],
            OUT_OF_RANGE,
        ),
        (
            "checkpoints at limit",
            |s| s.invalid_checkpoint_digests = vec![[1; 32]; 65_536],
            DUPLICATE,
        ),
        (
            "projections over limit",
            |s| s.invalid_projection_digests = vec![[1; 32]; 65_537],
            OUT_OF_RANGE,
        ),
        (
            "projections at limit",
            |s| s.invalid_projection_digests = vec![[1; 32]; 65_536],
            DUPLICATE,
        ),
        (
            "retained over limit",
            |s| s.retained_exogenous_digests = vec![[1; 32]; 65_537],
            OUT_OF_RANGE,
        ),
        (
            "retained at limit",
            |s| s.retained_exogenous_digests = vec![[1; 32]; 65_536],
            DUPLICATE,
        ),
    ]);
}

#[test]
fn invalidation_identifiers_generation_and_range_are_exact() -> TestResult {
    let generation = FrontierArtifactErrorV1::PriorGenerationMismatch;
    assert_invalidation_rejected(&[
        (
            "empty start owner",
            |s| s.invalid_start.owner_id.clear(),
            OUT_OF_RANGE,
        ),
        (
            "long start owner",
            |s| s.invalid_start.owner_id = "s".repeat(129),
            OUT_OF_RANGE,
        ),
        (
            "empty end owner",
            |s| s.invalid_end.owner_id.clear(),
            OUT_OF_RANGE,
        ),
        (
            "empty artifact class",
            |s| s.invalid_artifacts[2].artifact_class.clear(),
            OUT_OF_RANGE,
        ),
        (
            "long artifact class",
            |s| s.invalid_artifacts[2].artifact_class = "c".repeat(129),
            OUT_OF_RANGE,
        ),
        (
            "empty producer owner",
            |s| s.invalid_artifacts[2].producer.owner_id.clear(),
            OUT_OF_RANGE,
        ),
        ("generation unchanged", |s| s.new_generation = 0, generation),
        ("generation skipped", |s| s.new_generation = 2, generation),
        (
            "generation overflow",
            |s| {
                s.prior_generation = u64::MAX;
                s.new_generation = 0;
            },
            generation,
        ),
        (
            "end before start",
            |s| s.invalid_end = node(4, 0, "agent-a"),
            FrontierArtifactErrorV1::FrontierOutOfRange,
        ),
    ]);
    assert_invalidation_accepted(&[
        ("later generation", |s| {
            s.prior_generation = 7;
            s.new_generation = 8;
        }),
        ("single coordinate", |s| {
            s.invalid_end = s.invalid_start.clone();
        }),
        ("artifact class at limit", |s| {
            s.invalid_artifacts[2].artifact_class = "c".repeat(128);
        }),
        ("empty lists", |s| {
            s.invalid_artifacts.clear();
            s.invalid_checkpoint_digests.clear();
            s.invalid_projection_digests.clear();
            s.retained_exogenous_digests.clear();
        }),
    ])
}

#[test]
fn invalidation_rejects_every_all_zero_digest_like_the_nested_verifier() -> TestResult {
    assert_invalidation_rejected(&[
        (
            "zero invalidation id",
            |s| s.invalidation_id = [0; 16],
            OUT_OF_RANGE,
        ),
        ("zero plan", |s| s.plan_digest = [0; 32], OUT_OF_RANGE),
        (
            "zero frontier digest",
            |s| s.frontier_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero commit timeline",
            |s| s.commit_timeline_id = [0; 16],
            OUT_OF_RANGE,
        ),
        (
            "zero provenance",
            |s| s.provenance_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero artifact digest",
            |s| s.invalid_artifacts[2].artifact_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero producer artifact",
            |s| s.invalid_artifacts[2].producer.artifact_digest = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero checkpoint",
            |s| s.invalid_checkpoint_digests[1] = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero projection",
            |s| s.invalid_projection_digests[0] = [0; 32],
            OUT_OF_RANGE,
        ),
        (
            "zero retained",
            |s| s.retained_exogenous_digests[0] = [0; 32],
            OUT_OF_RANGE,
        ),
    ]);
    // Range endpoints are bare coordinates, as in the nested verifier.
    assert_invalidation_accepted(&[("zero endpoint artifacts", |s| {
        s.invalid_start.artifact_digest = [0; 32];
        s.invalid_end.artifact_digest = [0; 32];
    })])
}

#[test]
fn invalidation_lists_are_strictly_ordered() {
    assert_invalidation_rejected(&[
        (
            "unsorted artifacts",
            |s| s.invalid_artifacts.reverse(),
            UNORDERED,
        ),
        (
            "artifact class order",
            |s| s.invalid_artifacts.swap(0, 1),
            UNORDERED,
        ),
        (
            "duplicate artifacts",
            |s| s.invalid_artifacts[1].artifact_class = "event".to_owned(),
            DUPLICATE,
        ),
        (
            "unsorted checkpoints",
            |s| s.invalid_checkpoint_digests.reverse(),
            UNORDERED,
        ),
        (
            "unsorted projections",
            |s| s.invalid_projection_digests = vec![[8; 32], [7; 32]],
            UNORDERED,
        ),
        (
            "unsorted retained",
            |s| s.retained_exogenous_digests = vec![[9; 32], [8; 32]],
            UNORDERED,
        ),
    ]);
}

#[test]
fn invalidation_digest_covers_fields_two_through_sixteen_only() -> TestResult {
    let base = invalidation()?;
    let mutations: [InvalidationMutation; 17] = [
        |s| s.invalidation_id[0] ^= 1,
        |s| s.plan_digest[0] ^= 1,
        |s| s.fork_id[0] ^= 1,
        |s| s.prior_generation = 1,
        |s| s.new_generation = 2,
        |s| s.frontier_digest[0] ^= 1,
        |s| s.invalid_start.tick = 4,
        |s| s.invalid_end.tick = 10,
        |s| s.invalid_artifacts[0].prior_generation = 1,
        |s| s.invalid_checkpoint_digests.clear(),
        |s| s.invalid_projection_digests.clear(),
        |s| s.retained_exogenous_digests.clear(),
        |s| s.reason = SuffixInvalidationReasonV1::ChangedIntervention,
        |s| s.commit_timeline_id[0] ^= 1,
        |s| s.commit_seq = 4,
        |s| s.commit_tick = 6,
        |s| s.provenance_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        assert_ne!(candidate.digest()?, base.invalidation_digest);
    }
    let mut redigested = base.clone();
    redigested.invalidation_digest = [0xaa; 32];
    assert_eq!(redigested.digest()?, base.invalidation_digest);
    assert_eq!(
        redigested.validate(),
        Err(FrontierArtifactErrorV1::DigestMismatch)
    );
    assert_eq!(
        redigested.to_canonical_cbor(),
        Err(FrontierArtifactErrorV1::DigestMismatch)
    );
    Ok(())
}

#[test]
fn decoders_bound_input_size_before_parsing() {
    assert_eq!(MAX_RECOMPUTATION_FRONTIER_BYTES_V1, 64 * 1024 * 1024);
    assert_eq!(MAX_SUFFIX_INVALIDATION_BYTES_V1, 128 * 1024 * 1024);
    // One zeroed (lazily committed) buffer serves every case. A leading zero
    // byte is a lone unsigned integer, so the bytes that pass the size bound
    // fail at once on trailing input without being read further.
    let buffer = vec![0; MAX_SUFFIX_INVALIDATION_BYTES_V1 + 1];
    let frontier_limit = MAX_RECOMPUTATION_FRONTIER_BYTES_V1;
    assert_frontier_decode(&buffer[..frontier_limit], ENCODING);
    assert_frontier_decode(&buffer[..=frontier_limit], OUT_OF_RANGE);
    assert_invalidation_decode(&buffer[..MAX_SUFFIX_INVALIDATION_BYTES_V1], ENCODING);
    assert_invalidation_decode(&buffer, OUT_OF_RANGE);
}

#[test]
fn frontier_decoder_rejects_noncanonical_and_forbidden_cbor() -> TestResult {
    let encoded = frontier()?.to_canonical_cbor()?;
    assert_eq!(&encoded[..7], &[0x91, 0x64, b'R', b'C', b'F', b'1', 0x01]);

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_frontier_decode(&trailing, ENCODING);

    let mut wide_version = encoded[..6].to_vec();
    wide_version.extend_from_slice(&[0x18, 0x01]);
    wide_version.extend_from_slice(&encoded[7..]);
    assert_frontier_decode(&wide_version, ENCODING);

    let mut invalid_utf8 = encoded.clone();
    invalid_utf8[4] = 0xff;
    assert_frontier_decode(&invalid_utf8, ENCODING);

    for forbidden in [
        Value::Map(Vec::new()),
        Value::Tag(1, Box::new(uint(1))),
        Value::Float(1.5),
        Value::Bool(true),
    ] {
        assert_frontier_decode(&replaced(&encoded, &[2], forbidden)?, ENCODING);
    }
    let too_deep = Value::Array(vec![Value::Array(vec![uint(1)])]);
    assert_frontier_decode(&replaced(&encoded, &[6, 0, 0], too_deep)?, OUT_OF_RANGE);
    // Array headers are bounded before any item is read: one item over the
    // limit is out of bounds, while the limit itself passes the header check
    // and then fails on the absent items.
    let too_many = [0x9a, 0x00, 0x0f, 0x42, 0x41];
    assert_eq!(u32::from_be_bytes([0x00, 0x0f, 0x42, 0x41]), 1_000_001);
    assert_frontier_decode(&too_many, OUT_OF_RANGE);
    assert_frontier_decode(&[0x9a, 0x00, 0x0f, 0x42, 0x40], ENCODING);

    assert_frontier_decode(&encode(&uint(1))?, ENCODING);
    let mut short = root_fields(&encoded)?;
    short.pop();
    assert_frontier_decode(&encode(&Value::Array(short))?, ENCODING);
    Ok(())
}

#[test]
fn frontier_decoder_rejects_each_malformed_header_and_scalar() -> TestResult {
    let unsupported = FrontierArtifactErrorV1::UnsupportedVersion;
    let encoded = frontier()?.to_canonical_cbor()?;
    let cases: Vec<(Vec<usize>, Value, FrontierArtifactErrorV1)> = vec![
        (vec![0], uint(1), ENCODING),
        (vec![0], text("RCF2"), unsupported),
        (vec![1], uint(2), unsupported),
        (vec![1], text("1"), ENCODING),
        (vec![2], bytes(&[1; 15]), ENCODING),
        (vec![3], text("digest"), ENCODING),
        (vec![10], beyond_u32(), OUT_OF_RANGE),
        (vec![11], uint(2), FrontierArtifactErrorV1::UnknownEnum),
        (vec![11], text("reject"), ENCODING),
        (
            vec![13],
            uint(4),
            FrontierArtifactErrorV1::FrontierOutOfRange,
        ),
        (vec![9], uint(4), FrontierArtifactErrorV1::DigestMismatch),
    ];
    for (path, replacement, expected) in cases {
        assert_frontier_decode(&replaced(&encoded, &path, replacement)?, expected);
    }
    Ok(())
}

#[test]
fn frontier_decoder_rejects_each_malformed_nested_record() -> TestResult {
    let encoded = frontier()?.to_canonical_cbor()?;
    let cases: Vec<(Vec<usize>, Value, FrontierArtifactErrorV1)> = vec![
        (vec![6], uint(1), ENCODING),
        (vec![6, 0], Value::Array(vec![uint(1); 5]), ENCODING),
        (vec![6, 0, 0], Value::Integer((-1).into()), ENCODING),
        (vec![6, 0, 1], beyond_u32(), OUT_OF_RANGE),
        (vec![6, 0, 2], uint(1), ENCODING),
        (vec![6, 0, 3], beyond_u32(), OUT_OF_RANGE),
        (vec![6, 0, 4], beyond_u32(), OUT_OF_RANGE),
        (vec![8, 0], Value::Array(vec![uint(1); 4]), ENCODING),
        (vec![8, 0, 2], beyond_u32(), OUT_OF_RANGE),
        (vec![8, 0, 4], uint(1), ENCODING),
        (vec![8, 0, 4, 0], bytes(&[1; 31]), ENCODING),
    ];
    for (path, replacement, expected) in cases {
        assert_frontier_decode(&replaced(&encoded, &path, replacement)?, expected);
    }
    let full = full_suffix_frontier()?.to_canonical_cbor()?;
    let cases: Vec<(Vec<usize>, Value)> = vec![
        (vec![12, 0], Value::Array(vec![uint(1); 3])),
        (vec![12, 0, 0], uint(1)),
        (vec![12, 1, 1], bytes(&[4; 31])),
    ];
    for (path, replacement) in cases {
        assert_frontier_decode(&replaced(&full, &path, replacement)?, ENCODING);
    }
    Ok(())
}

#[test]
fn invalidation_decoder_rejects_each_malformed_field() -> TestResult {
    let unsupported = FrontierArtifactErrorV1::UnsupportedVersion;
    let unknown = FrontierArtifactErrorV1::UnknownEnum;
    let encoded = invalidation()?.to_canonical_cbor()?;
    let cases: Vec<(Vec<usize>, Value, FrontierArtifactErrorV1)> = vec![
        (vec![0], text("SIV2"), unsupported),
        (vec![1], uint(2), unsupported),
        (vec![4], bytes(&[3; 17]), ENCODING),
        (vec![5], text("0"), ENCODING),
        (
            vec![6],
            uint(2),
            FrontierArtifactErrorV1::PriorGenerationMismatch,
        ),
        (vec![8], uint(1), ENCODING),
        (vec![10], uint(1), ENCODING),
        (vec![10, 0], Value::Array(vec![uint(1); 5]), ENCODING),
        (vec![10, 0, 1], uint(u64::from(u32::MAX) + 1), OUT_OF_RANGE),
        (
            vec![10, 0, 3, 0],
            Value::Array(vec![Value::Array(vec![uint(1)])]),
            OUT_OF_RANGE,
        ),
        (vec![10, 0, 5], uint(5), unknown),
        (vec![11], uint(1), ENCODING),
        (vec![11, 0], bytes(&[5; 31]), ENCODING),
        (vec![14], uint(5), unknown),
        (
            vec![15],
            Value::Array(vec![bytes(&[12; 16]), uint(3)]),
            ENCODING,
        ),
        (vec![15, 0], bytes(&[12; 15]), ENCODING),
        (vec![15, 1], text("3"), ENCODING),
        (
            vec![17],
            bytes(&[0; 32]),
            FrontierArtifactErrorV1::DigestMismatch,
        ),
    ];
    for (path, replacement, expected) in cases {
        assert_invalidation_decode(&replaced(&encoded, &path, replacement)?, expected);
    }
    let mut long = root_fields(&encoded)?;
    long.push(uint(0));
    assert_invalidation_decode(&encode(&Value::Array(long))?, ENCODING);
    assert_invalidation_decode(&encode(&text("SIV1"))?, ENCODING);
    Ok(())
}

#[test]
fn errors_have_distinct_safe_messages() {
    let errors = [
        FrontierArtifactErrorV1::InvalidEncoding,
        FrontierArtifactErrorV1::UnsupportedVersion,
        FrontierArtifactErrorV1::UnknownEnum,
        FrontierArtifactErrorV1::FieldOutOfBounds,
        FrontierArtifactErrorV1::NonCanonicalOrder,
        FrontierArtifactErrorV1::DuplicateIdentity,
        FrontierArtifactErrorV1::FrontierOutOfRange,
        FrontierArtifactErrorV1::PriorGenerationMismatch,
        FrontierArtifactErrorV1::DigestMismatch,
    ];
    let messages = errors
        .iter()
        .map(|error| {
            let boxed: Box<dyn std::error::Error> = Box::new(*error);
            boxed.to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(messages.len(), errors.len());
    assert!(messages
        .iter()
        .all(|message| message.contains("RCF1") || message.contains("SIV1")));
}

#[test]
fn seal_computes_the_digest_once_the_fields_are_valid() -> TestResult {
    let sealed = unsigned_frontier().seal()?;
    assert_eq!(sealed, frontier()?);
    assert_eq!(sealed.validate(), Ok(()));
    let mut stale = sealed.clone();
    stale.frontier_digest = [0xaa; 32];
    assert_eq!(stale.seal()?, sealed);
    let mut invalid = unsigned_frontier();
    invalid.affected_nodes.clear();
    assert_eq!(invalid.seal(), Err(OUT_OF_RANGE));

    let sealed = unsigned_invalidation().seal()?;
    assert_eq!(sealed, invalidation()?);
    assert_eq!(sealed.validate(), Ok(()));
    let mut stale = sealed.clone();
    stale.invalidation_digest = [0xaa; 32];
    assert_eq!(stale.seal()?, sealed);
    let mut invalid = unsigned_invalidation();
    invalid.new_generation = 3;
    assert_eq!(
        invalid.seal(),
        Err(FrontierArtifactErrorV1::PriorGenerationMismatch)
    );
    Ok(())
}

#[test]
fn artifact_nodes_need_a_schema_like_the_nested_verifier() {
    assert_frontier_rejected(&[
        (
            "zero seed schema",
            |s| s.intervention_seed_nodes[0].schema_id = 0,
            OUT_OF_RANGE,
        ),
        (
            "zero affected schema",
            |s| s.affected_nodes[1].schema_id = 0,
            OUT_OF_RANGE,
        ),
        (
            "zero unknown-edge consumer schema",
            |s| {
                full_suffix(s);
                s.unknown_edge_coordinates[1].consumer.schema_id = 0;
            },
            OUT_OF_RANGE,
        ),
    ]);
    assert_invalidation_rejected(&[
        (
            "zero producer schema",
            |s| {
                s.invalid_artifacts[2].schema_id = 0;
                s.invalid_artifacts[2].producer.schema_id = 0;
            },
            OUT_OF_RANGE,
        ),
        (
            "artifact schema differs from producer",
            |s| s.invalid_artifacts[2].schema_id = 8,
            OUT_OF_RANGE,
        ),
        (
            "artifact reason differs from record",
            |s| s.invalid_artifacts[1].reason = SuffixInvalidationReasonV1::ChangedIntervention,
            OUT_OF_RANGE,
        ),
    ]);
}

#[test]
fn invalid_artifacts_order_by_the_full_producer_node() -> TestResult {
    fn with_schema(schema_id: u32) -> InvalidArtifactV1 {
        let mut producer = node(5, 0, "agent-a");
        producer.schema_id = schema_id;
        let mut artifact = artifact("projection", producer);
        artifact.schema_id = schema_id;
        artifact
    }
    fn with_producer_digest(fill: u8) -> InvalidArtifactV1 {
        let mut producer = node(5, 0, "agent-a");
        producer.artifact_digest = [fill; 32];
        artifact("projection", producer)
    }
    assert_invalidation_accepted(&[
        ("producer schema ascending", |s| {
            s.invalid_artifacts = vec![with_schema(7), with_schema(8)];
        }),
        ("producer digest ascending", |s| {
            s.invalid_artifacts = vec![with_producer_digest(9), with_producer_digest(10)];
        }),
    ])?;
    assert_invalidation_rejected(&[
        (
            "producer schema descending",
            |s| s.invalid_artifacts = vec![with_schema(8), with_schema(7)],
            UNORDERED,
        ),
        (
            "producer before class",
            |s| {
                let mut later = with_schema(8);
                later.artifact_class = "event".to_owned();
                s.invalid_artifacts = vec![later, with_schema(7)];
            },
            UNORDERED,
        ),
        (
            "producer digest descending",
            |s| s.invalid_artifacts = vec![with_producer_digest(10), with_producer_digest(9)],
            UNORDERED,
        ),
    ]);
    Ok(())
}
