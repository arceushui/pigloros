#![cfg(all(feature = "test-support", feature = "counterfactual-adapter"))]

//! Public-interface contract tests for the ADR-064 counterfactual dependency
//! record contract and read port.

use std::collections::BTreeSet;

use pos_core::counterfactual_store::test_fixtures::{
    frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, text_field, uint,
};
use pos_core::{
    CanonicalBytes, CounterfactualAdapterSealV1, CounterfactualBasisV1,
    CounterfactualDependencyErrorV1, CounterfactualDependencyReadPortV1,
    CounterfactualDependencyRecordingPortV1, CounterfactualFactsV1,
    CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1,
    DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    DependencyPageCursorV1, DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1,
    DependencyReadScopeV1, EntityId, EventDraft, ForkGenerationV1, Hash, InvalidationConflictV1,
    Kind, PipelineDraftBatchV1, RecomputationFrontierBytesV1, RecordedDependencyClassV1,
    RecordedNodeOriginV1, RecordedSetCountsV1, Seq, SuffixInvalidationBytesV1,
    TickDependencyRecordV1, TimelineId, MAX_DEPENDENCY_EDGE_BYTES_V1,
    MAX_DEPENDENCY_NODE_INPUTS_V1, MAX_DEPENDENCY_OWNER_ID_BYTES_V1, MAX_DEPENDENCY_PAGE_ROWS_V1,
    MAX_RECORDED_DEPENDENCY_EDGES_V1, MAX_RECORDED_DEPENDENCY_NODES_V1,
    MAX_TICK_DEPENDENCY_EDGES_V1, MAX_TICK_DEPENDENCY_EDGE_BYTES_V1, MAX_TICK_DEPENDENCY_NODES_V1,
};
use ulid::Ulid;

type DepError = CounterfactualDependencyErrorV1;
type StoreError = CounterfactualStoreErrorV1;
type Coordinate = DependencyNodeCoordinateV1;
type NodeRow = DependencyNodeRecordV1;
type EdgeRow = DependencyEdgeRecordV1;
type TickRecord = TickDependencyRecordV1;
type NodePage = DependencyPageV1<NodeRow>;
type EdgePage = DependencyPageV1<EdgeRow>;

/// The adapter seal; these tests stand in for an adapter.
const SEAL: CounterfactualAdapterSealV1 = CounterfactualAdapterSealV1::for_adapter();
const PROVISIONAL: RecordedNodeOriginV1 = RecordedNodeOriginV1::Provisional;
const EDGE_HEAD: [u8; 7] = [0x89, 0x64, b'I', b'D', b'P', b'1', 0x01];

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn unexpected_success<T: std::fmt::Debug, E>(value: &T) -> E {
    std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}")))
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    result.map_or_else(|error| error, |value| unexpected_success(&value))
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn indexed_hash(index: usize) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&ok(u64::try_from(index)).to_be_bytes());
    Hash::from_bytes(bytes)
}

/// The nonzero digests `1..=count` in ascending order.
fn ascending_hashes(count: usize) -> Vec<Hash> {
    (1..=count).map(indexed_hash).collect()
}

fn fork() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128))
}

fn parent() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x00ff_u128))
}

fn coord_at(tick: u64, owner: &str, ordinal: u32, digest: Hash) -> Coordinate {
    ok(Coordinate::try_new(
        tick,
        0,
        owner.to_owned(),
        ordinal,
        7,
        digest,
    ))
}

fn coord(tick: u64, owner: &str, digest: u8) -> Coordinate {
    coord_at(tick, owner, 0, hash(digest))
}

fn class_row(
    coordinate: Coordinate,
    class: RecordedDependencyClassV1,
    origin: RecordedNodeOriginV1,
    inputs: Vec<Hash>,
) -> NodeRow {
    ok(NodeRow::try_new(
        coordinate,
        class,
        origin,
        inputs,
        hash(99),
    ))
}

fn node_row(coordinate: Coordinate, origin: RecordedNodeOriginV1, inputs: Vec<Hash>) -> NodeRow {
    let class = RecordedDependencyClassV1::EndogenousRecomputed;
    class_row(coordinate, class, origin, inputs)
}

/// The encoded six-field node array, written independently of the contract.
fn node_bytes(node: &Coordinate) -> Vec<u8> {
    [
        vec![0x86],
        uint(node.tick()),
        uint(u64::from(node.scheduler_position())),
        text_field(node.owner_id()),
        uint(u64::from(node.output_ordinal())),
        uint(u64::from(node.schema_id())),
        hash_field(node.artifact_digest()),
    ]
    .concat()
}

/// The five `IDP1` fields after the source node, with `rule` as the rule ID.
fn edge_tail_with_rule(rule: &str) -> Vec<u8> {
    [
        uint(2),
        vec![0x82],
        uint(3),
        uint(5),
        hash_field(hash(0x33)),
        vec![0x82],
        text_field(rule),
        uint(1),
        hash_field(hash(0x44)),
    ]
    .concat()
}

fn edge_tail() -> Vec<u8> {
    edge_tail_with_rule("adr064.classification")
}

/// One `IDP1` edge split into the parts a test corrupts.
struct EdgeParts {
    head: Vec<u8>,
    consumer: Vec<u8>,
    source: Vec<u8>,
    tail: Vec<u8>,
}

impl EdgeParts {
    fn new(consumer: &Coordinate, source: &Coordinate) -> Self {
        Self {
            head: EDGE_HEAD.to_vec(),
            consumer: node_bytes(consumer),
            source: node_bytes(source),
            tail: edge_tail(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        [
            self.head.as_slice(),
            self.consumer.as_slice(),
            self.source.as_slice(),
            self.tail.as_slice(),
        ]
        .concat()
    }
}

/// The edge of `consumer` and `source`, padded through its classification
/// rule text to exactly `size` bytes.
fn sized_parts(consumer: &Coordinate, source: &Coordinate, size: usize) -> EdgeParts {
    let bare = EdgeParts {
        tail: edge_tail_with_rule(""),
        ..EdgeParts::new(consumer, source)
    };
    // Each rule text byte adds one byte, and its head grows from 1 to 3.
    let rule = "r".repeat(size - bare.bytes().len() - 2);
    EdgeParts {
        tail: edge_tail_with_rule(&rule),
        ..bare
    }
}

fn edge_row(consumer: &Coordinate, source: &Coordinate) -> EdgeRow {
    ok(EdgeRow::try_from_canonical(
        EdgeParts::new(consumer, source).bytes(),
        consumer.clone(),
        source.artifact_digest(),
    ))
}

/// Verify `parts` against the consumer and the source of `edge_row(a, b)`.
fn verify(parts: &EdgeParts) -> Result<EdgeRow, DepError> {
    EdgeRow::try_from_canonical(parts.bytes(), coord(17, "a", 1), hash(50))
}

fn valid_parts() -> EdgeParts {
    EdgeParts::new(&coord(17, "a", 1), &coord(10, "w", 50))
}

/// Tick 17: node `a` declares the prefix input 50, node `b` declares the
/// provisional input 1 (node `a`) and the unrecorded input 60.
fn sample_nodes() -> Vec<NodeRow> {
    vec![
        node_row(coord(17, "a", 1), PROVISIONAL, vec![hash(50)]),
        node_row(coord(17, "b", 2), PROVISIONAL, vec![hash(1), hash(60)]),
    ]
}

fn sample_edges() -> Vec<EdgeRow> {
    vec![
        edge_row(&coord(17, "a", 1), &coord(10, "w", 50)),
        edge_row(&coord(17, "b", 2), &coord(17, "a", 1)),
    ]
}

fn sample_record() -> TickRecord {
    ok(TickRecord::try_new(
        17,
        PROVISIONAL,
        sample_nodes(),
        sample_edges(),
    ))
}

#[test]
fn class_and_origin_codes_are_closed() {
    for (index, class) in RecordedDependencyClassV1::ALL.into_iter().enumerate() {
        assert_eq!(usize::from(class.code()), index);
        assert_eq!(
            RecordedDependencyClassV1::from_code(u64::from(class.code())),
            Ok(class)
        );
    }
    for origin in [RecordedNodeOriginV1::Committed, PROVISIONAL] {
        assert_eq!(
            RecordedNodeOriginV1::from_code(u64::from(origin.code())),
            Ok(origin)
        );
    }
    assert_eq!(PROVISIONAL.code(), 1);
    assert_eq!(RecordedDependencyClassV1::PresentationOnly.code(), 4);
    for code in [5, u64::MAX] {
        assert_eq!(
            RecordedDependencyClassV1::from_code(code),
            Err(DepError::UnknownEnum)
        );
    }
    for code in [2, u64::MAX] {
        assert_eq!(
            RecordedNodeOriginV1::from_code(code),
            Err(DepError::UnknownEnum)
        );
    }
}

#[test]
fn coordinates_are_bounded_and_expose_their_fields() {
    let longest = "o".repeat(MAX_DEPENDENCY_OWNER_ID_BYTES_V1);
    let valid = ok(Coordinate::try_new(5, 2, longest.clone(), 3, 7, hash(9)));
    assert_eq!(valid.tick(), 5);
    assert_eq!(valid.scheduler_position(), 2);
    assert_eq!(valid.owner_id(), longest);
    assert_eq!(valid.output_ordinal(), 3);
    assert_eq!(valid.schema_id(), 7);
    assert_eq!(valid.artifact_digest(), hash(9));
    assert_eq!(valid.position_key(), (5, 2, longest.as_str(), 3));
    let cases = [
        (String::new(), 7, hash(9)),
        ("o".repeat(MAX_DEPENDENCY_OWNER_ID_BYTES_V1 + 1), 7, hash(9)),
        ("a".to_owned(), 0, hash(9)),
        ("a".to_owned(), 7, Hash::zero()),
    ];
    for (owner, schema, digest) in cases {
        assert_eq!(
            Coordinate::try_new(5, 2, owner, 3, schema, digest),
            Err(DepError::FieldOutOfBounds)
        );
    }
}

#[test]
fn coordinate_order_is_the_canonical_field_order() {
    let base = ok(Coordinate::try_new(5, 5, "m".to_owned(), 5, 5, hash(5)));
    let later = [
        ok(Coordinate::try_new(6, 0, "a".to_owned(), 0, 1, hash(1))),
        ok(Coordinate::try_new(5, 6, "a".to_owned(), 0, 1, hash(1))),
        ok(Coordinate::try_new(5, 5, "n".to_owned(), 0, 1, hash(1))),
        ok(Coordinate::try_new(5, 5, "m".to_owned(), 6, 1, hash(1))),
        ok(Coordinate::try_new(5, 5, "m".to_owned(), 5, 6, hash(1))),
        ok(Coordinate::try_new(5, 5, "m".to_owned(), 5, 5, hash(6))),
    ];
    for coordinate in later {
        assert!(base < coordinate);
    }
    let prefix = ok(Coordinate::try_new(5, 5, "m".to_owned(), 5, 5, hash(5)));
    let longer = ok(Coordinate::try_new(5, 5, "ma".to_owned(), 0, 1, hash(1)));
    assert!(prefix < longer);
    assert_eq!(base.cmp(&prefix), std::cmp::Ordering::Equal);
}

#[test]
fn node_records_bound_and_order_their_inputs() {
    let row = node_row(coord(17, "a", 1), PROVISIONAL, vec![hash(1), hash(2)]);
    assert_eq!(row.coordinate(), &coord(17, "a", 1));
    assert_eq!(row.class(), RecordedDependencyClassV1::EndogenousRecomputed);
    assert_eq!(row.origin(), PROVISIONAL);
    assert_eq!(row.input_digests(), &[hash(1), hash(2)]);
    assert_eq!(row.provenance_digest(), hash(99));
    let at_limit = ascending_hashes(MAX_DEPENDENCY_NODE_INPUTS_V1);
    let over = ascending_hashes(MAX_DEPENDENCY_NODE_INPUTS_V1 + 1);
    let class = RecordedDependencyClassV1::FixedPolicy;
    let make = |inputs: Vec<Hash>, provenance: Hash| {
        NodeRow::try_new(coord(17, "a", 1), class, PROVISIONAL, inputs, provenance)
    };
    assert!(make(at_limit, hash(99)).is_ok());
    let cases = [
        (over, hash(99), DepError::FieldOutOfBounds),
        (vec![Hash::zero()], hash(99), DepError::FieldOutOfBounds),
        (vec![hash(1)], Hash::zero(), DepError::ProvenanceMissing),
        (
            vec![hash(2), hash(1)],
            hash(99),
            DepError::NonCanonicalOrder,
        ),
        (
            vec![hash(1), hash(1)],
            hash(99),
            DepError::DuplicateIdentity,
        ),
    ];
    for (inputs, provenance, expected) in cases {
        assert_eq!(err(make(inputs, provenance)), expected);
    }
}

#[test]
fn edge_records_expose_the_verified_bytes() {
    let consumer = coord(17, "a", 1);
    let edge = edge_row(&consumer, &coord(10, "w", 50));
    let expected_bytes = valid_parts().bytes();
    assert_eq!(edge.as_bytes(), expected_bytes.as_slice());
    assert_eq!(edge.consumer(), &consumer);
    assert_eq!(edge.source_digest(), hash(50));
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.InputDependency.v1");
    hasher.update(&[0]);
    hasher.update(&expected_bytes);
    let expected_digest = Hash::from_bytes(*hasher.finalize().as_bytes());
    assert_eq!(edge.digest(), expected_digest);
}

#[test]
fn edge_size_bound_is_checked_first() {
    let mut padded = valid_parts().bytes();
    padded.resize(MAX_DEPENDENCY_EDGE_BYTES_V1, 0);
    assert_eq!(
        EdgeRow::try_from_canonical(padded, coord(17, "a", 1), hash(50)),
        Err(DepError::InvalidEncoding)
    );
    let oversize = vec![0x89; MAX_DEPENDENCY_EDGE_BYTES_V1 + 1];
    assert_eq!(
        EdgeRow::try_from_canonical(oversize, coord(17, "a", 1), hash(50)),
        Err(DepError::FieldOutOfBounds)
    );
}

#[test]
fn edges_may_fill_the_size_bound_exactly() {
    let consumer = coord(17, "a", 1);
    let source = coord(10, "w", 50);
    let at_limit = sized_parts(&consumer, &source, MAX_DEPENDENCY_EDGE_BYTES_V1).bytes();
    assert_eq!(at_limit.len(), MAX_DEPENDENCY_EDGE_BYTES_V1);
    let edge = ok(EdgeRow::try_from_canonical(
        at_limit,
        consumer.clone(),
        hash(50),
    ));
    assert_eq!(edge.as_bytes().len(), MAX_DEPENDENCY_EDGE_BYTES_V1);
    let over = sized_parts(&consumer, &source, MAX_DEPENDENCY_EDGE_BYTES_V1 + 1).bytes();
    assert_eq!(
        err(EdgeRow::try_from_canonical(over, consumer, hash(50))),
        DepError::FieldOutOfBounds
    );
}

#[test]
fn zero_source_digests_are_rejected_up_front() {
    let consumer = coord(17, "a", 1);
    let zero = Hash::zero();
    assert_eq!(
        EdgeRow::try_from_canonical(valid_parts().bytes(), consumer.clone(), zero),
        Err(DepError::FieldOutOfBounds)
    );
    assert_eq!(
        EdgeRow::try_from_canonical(Vec::new(), consumer, zero),
        Err(DepError::FieldOutOfBounds)
    );
}

#[test]
fn edge_framing_failures_are_closed() {
    let wrong_head = EdgeParts {
        head: vec![0x88, 0x64, b'I', b'D', b'P', b'1', 0x01],
        ..valid_parts()
    };
    let other_magic = EdgeParts {
        head: vec![0x89, 0x64, b'I', b'D', b'P', b'2', 0x01],
        ..valid_parts()
    };
    let other_version = EdgeParts {
        head: vec![0x89, 0x64, b'I', b'D', b'P', b'1', 0x02],
        ..valid_parts()
    };
    assert_eq!(err(verify(&wrong_head)), DepError::InvalidEncoding);
    assert_eq!(err(verify(&other_magic)), DepError::UnsupportedVersion);
    assert_eq!(err(verify(&other_version)), DepError::UnsupportedVersion);
    assert_eq!(
        EdgeRow::try_from_canonical(Vec::new(), coord(17, "a", 1), hash(50)),
        Err(DepError::InvalidEncoding)
    );
}

#[test]
fn edge_fields_must_match_the_supplied_coordinates() {
    let other_consumer = EdgeParts {
        consumer: node_bytes(&coord(17, "a", 2)),
        ..valid_parts()
    };
    assert_eq!(err(verify(&other_consumer)), DepError::BindingMismatch);
    let other_source = EdgeParts {
        source: node_bytes(&coord(10, "w", 51)),
        ..valid_parts()
    };
    assert_eq!(err(verify(&other_source)), DepError::BindingMismatch);
    let long_form_tick = EdgeParts {
        consumer: [
            vec![0x86, 0x18, 17],
            node_bytes(&coord(17, "a", 1))[2..].to_vec(),
        ]
        .concat(),
        ..valid_parts()
    };
    assert_eq!(err(verify(&long_form_tick)), DepError::BindingMismatch);
}

/// A source node array with the given owner and artifact digest fields.
fn source_with(owner_field: Vec<u8>, digest_field: Vec<u8>) -> Vec<u8> {
    [
        vec![0x86],
        uint(10),
        uint(0),
        owner_field,
        uint(0),
        uint(7),
        digest_field,
    ]
    .concat()
}

#[test]
fn edge_source_and_tail_must_be_well_formed_items() {
    let not_an_array = EdgeParts {
        source: hash_field(hash(50)),
        ..valid_parts()
    };
    let truncated_source = EdgeParts {
        source: vec![0x86],
        tail: Vec::new(),
        ..valid_parts()
    };
    let truncated_owner = EdgeParts {
        source: [vec![0x86], uint(10), uint(0), vec![0x65, b'w']].concat(),
        tail: Vec::new(),
        ..valid_parts()
    };
    let owner_not_text = EdgeParts {
        source: source_with(uint(0), hash_field(hash(50))),
        ..valid_parts()
    };
    let digest_not_bytes = EdgeParts {
        source: source_with(text_field("w"), uint(0)),
        ..valid_parts()
    };
    let missing_tail = EdgeParts {
        tail: Vec::new(),
        ..valid_parts()
    };
    let negative_tail = EdgeParts {
        tail: vec![0x20],
        ..valid_parts()
    };
    let trailing = EdgeParts {
        tail: [edge_tail(), vec![0]].concat(),
        ..valid_parts()
    };
    for parts in [
        not_an_array,
        truncated_source,
        truncated_owner,
        owner_not_text,
        digest_not_bytes,
        missing_tail,
        negative_tail,
        trailing,
    ] {
        assert_eq!(err(verify(&parts)), DepError::InvalidEncoding);
    }
}

#[test]
fn edge_source_owner_is_bounded() {
    let longest = "o".repeat(MAX_DEPENDENCY_OWNER_ID_BYTES_V1);
    let at_limit = EdgeParts {
        source: source_with(text_field(&longest), hash_field(hash(50))),
        ..valid_parts()
    };
    assert!(verify(&at_limit).is_ok());
    let over = "o".repeat(MAX_DEPENDENCY_OWNER_ID_BYTES_V1 + 1);
    let huge = [vec![0x7b], vec![0xff; 8]].concat();
    for owner_field in [text_field(""), text_field(&over), huge] {
        let parts = EdgeParts {
            source: source_with(owner_field, hash_field(hash(50))),
            ..valid_parts()
        };
        assert_eq!(err(verify(&parts)), DepError::FieldOutOfBounds);
    }
}

#[test]
fn tick_records_expose_their_rows_and_uncovered_inputs() {
    let record = sample_record();
    assert_eq!(record.tick(), 17);
    assert_eq!(record.origin(), PROVISIONAL);
    assert_eq!(record.nodes(), sample_nodes().as_slice());
    assert_eq!(record.edges(), sample_edges().as_slice());
    assert_eq!(record.declared_input_count(), 3);
    assert_eq!(record.uncovered_input_count(), 1);
    assert_eq!(record.ensure_provisional(), Ok(()));
    let empty = ok(TickRecord::try_new(
        4,
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(empty.uncovered_input_count(), 0);
    assert_eq!(empty.ensure_provisional(), Err(StoreError::BindingMismatch));
}

/// Build `count` node rows at tick 17 with ascending ordinals.
fn numbered_nodes(count: usize, inputs: &[Hash]) -> Vec<NodeRow> {
    (0..count)
        .map(|index| {
            let ordinal = ok(u32::try_from(index));
            let digest = indexed_hash(100_000 + index);
            node_row(
                coord_at(17, "c", ordinal, digest),
                PROVISIONAL,
                inputs.to_vec(),
            )
        })
        .collect()
}

#[test]
fn node_count_is_bounded_at_the_limit() {
    let at_limit = numbered_nodes(MAX_TICK_DEPENDENCY_NODES_V1, &[]);
    let over = vec![at_limit[0].clone(); MAX_TICK_DEPENDENCY_NODES_V1 + 1];
    let record = ok(TickRecord::try_new(17, PROVISIONAL, at_limit, Vec::new()));
    assert_eq!(record.nodes().len(), MAX_TICK_DEPENDENCY_NODES_V1);
    assert_eq!(
        err(TickRecord::try_new(17, PROVISIONAL, over, Vec::new())),
        DepError::FieldOutOfBounds
    );
}

#[test]
fn edge_count_is_bounded_at_the_limit() {
    let inputs = ascending_hashes(MAX_DEPENDENCY_NODE_INPUTS_V1);
    let consumers = MAX_TICK_DEPENDENCY_EDGES_V1 / MAX_DEPENDENCY_NODE_INPUTS_V1;
    let nodes = numbered_nodes(consumers, &inputs);
    let sources: Vec<Coordinate> = inputs
        .iter()
        .enumerate()
        .map(|(index, digest)| {
            let ordinal = ok(u32::try_from(index));
            coord_at(3, "w", ordinal, *digest)
        })
        .collect();
    let edges: Vec<EdgeRow> = nodes
        .iter()
        .flat_map(|row| {
            sources
                .iter()
                .map(move |origin| edge_row(row.coordinate(), origin))
        })
        .collect();
    assert_eq!(edges.len(), MAX_TICK_DEPENDENCY_EDGES_V1);
    let kept = edges[0].clone();
    let record = ok(TickRecord::try_new(17, PROVISIONAL, nodes.clone(), edges));
    assert_eq!(record.uncovered_input_count(), 0);
    drop(record);
    let over = vec![kept; MAX_TICK_DEPENDENCY_EDGES_V1 + 1];
    assert_eq!(
        err(TickRecord::try_new(17, PROVISIONAL, nodes, over)),
        DepError::FieldOutOfBounds
    );
}

#[test]
fn declared_inputs_are_bounded_per_record() {
    let inputs = ascending_hashes(MAX_DEPENDENCY_NODE_INPUTS_V1);
    let consumers = MAX_TICK_DEPENDENCY_EDGES_V1 / MAX_DEPENDENCY_NODE_INPUTS_V1;
    let nodes = numbered_nodes(consumers, &inputs);
    let ordinal = ok(u32::try_from(consumers));
    let extra = node_row(
        coord_at(17, "c", ordinal, indexed_hash(200_000)),
        PROVISIONAL,
        vec![hash(1)],
    );
    let mut over = nodes.clone();
    over.push(extra);
    let record = ok(build(nodes, Vec::new()));
    assert_eq!(record.declared_input_count(), MAX_TICK_DEPENDENCY_EDGES_V1);
    assert_eq!(err(build(over, Vec::new())), DepError::FieldOutOfBounds);
}

/// An edge of exactly the per-edge size bound from `consumer`.
fn full_edge(consumer: &Coordinate, source_digest: Hash) -> EdgeRow {
    let source = coord_at(3, "w", 0, source_digest);
    let parts = sized_parts(consumer, &source, MAX_DEPENDENCY_EDGE_BYTES_V1);
    ok(EdgeRow::try_from_canonical(
        parts.bytes(),
        consumer.clone(),
        source_digest,
    ))
}

/// Full-size edges from `consumer`, one per source digest.
fn full_edges(consumer: &Coordinate, sources: &[Hash]) -> Vec<EdgeRow> {
    sources
        .iter()
        .map(|digest| full_edge(consumer, *digest))
        .collect()
}

#[test]
fn edge_bytes_are_bounded_per_record() {
    let count = MAX_TICK_DEPENDENCY_EDGE_BYTES_V1 / MAX_DEPENDENCY_EDGE_BYTES_V1;
    assert_eq!(
        count * MAX_DEPENDENCY_EDGE_BYTES_V1,
        MAX_TICK_DEPENDENCY_EDGE_BYTES_V1
    );
    // A node declares at most 4,096 inputs, so the full count needs two.
    let inputs = ascending_hashes(MAX_DEPENDENCY_NODE_INPUTS_V1);
    assert_eq!(count, 2 * inputs.len());
    let pair = [
        coord_at(17, "c", 0, indexed_hash(100_000)),
        coord_at(17, "c", 1, indexed_hash(100_001)),
    ];
    let nodes: Vec<NodeRow> = pair
        .iter()
        .map(|consumer| node_row(consumer.clone(), PROVISIONAL, inputs.clone()))
        .collect();
    // The over-limit vector is built first and dropped before the at-limit
    // one exists, so only one of them is ever in memory.
    let over = vec![full_edge(&pair[0], inputs[0]); count + 1];
    let outcome = err(build(nodes.clone(), over));
    assert_eq!(outcome, DepError::FieldOutOfBounds);
    let edges: Vec<EdgeRow> = pair
        .iter()
        .flat_map(|consumer| full_edges(consumer, &inputs))
        .collect();
    let record = ok(build(nodes, edges));
    assert_eq!(record.edges().len(), count);
}

#[test]
fn recorded_sets_are_bounded_at_the_graph_limits() {
    let record = sample_record();
    let room = RecordedSetCountsV1 {
        nodes: MAX_RECORDED_DEPENDENCY_NODES_V1 - record.nodes().len(),
        edges: MAX_RECORDED_DEPENDENCY_EDGES_V1 - record.edges().len(),
        inputs: MAX_RECORDED_DEPENDENCY_EDGES_V1 - record.declared_input_count(),
    };
    assert_eq!(record.ensure_set_capacity(room), Ok(()));
    assert_eq!(
        record.ensure_set_capacity(RecordedSetCountsV1::default()),
        Ok(())
    );
    let mut over = [room; 6];
    over[0].nodes += 1;
    over[1].edges += 1;
    over[2].inputs += 1;
    over[3].nodes = usize::MAX;
    over[4].edges = usize::MAX;
    over[5].inputs = usize::MAX;
    for counts in over {
        assert_eq!(
            record.ensure_set_capacity(counts),
            Err(DepError::FieldOutOfBounds)
        );
    }
}

fn build(nodes: Vec<NodeRow>, edges: Vec<EdgeRow>) -> Result<TickRecord, DepError> {
    TickRecord::try_new(17, PROVISIONAL, nodes, edges)
}

#[test]
fn nodes_must_share_the_record_tick_and_origin() {
    let other_tick = vec![node_row(coord(18, "a", 1), PROVISIONAL, Vec::new())];
    let outcome = err(build(other_tick, Vec::new()));
    assert_eq!(outcome, DepError::BindingMismatch);
    let committed = RecordedNodeOriginV1::Committed;
    let other_origin = vec![node_row(coord(17, "a", 1), committed, Vec::new())];
    assert_eq!(
        err(build(other_origin, Vec::new())),
        DepError::BindingMismatch
    );
}

#[test]
fn root_nodes_may_precede_the_record_tick() {
    let expected = [true, true, false, true, false];
    for (class, expect_root) in RecordedDependencyClassV1::ALL.into_iter().zip(expected) {
        assert_eq!(class.is_root(), expect_root);
        let row_at = |tick: u64| class_row(coord(tick, "r", 9), class, PROVISIONAL, Vec::new());
        let early = build(vec![row_at(12)], Vec::new()).err();
        assert_eq!(early, (!expect_root).then_some(DepError::BindingMismatch));
        let late = build(vec![row_at(18)], Vec::new()).err();
        assert_eq!(late, Some(DepError::BindingMismatch));
        assert_eq!(build(vec![row_at(17)], Vec::new()).err(), None);
    }
    let early_root = class_row(
        coord(12, "r", 9),
        RecordedDependencyClassV1::InterventionAssigned,
        PROVISIONAL,
        Vec::new(),
    );
    let mut nodes = vec![early_root];
    nodes.extend(sample_nodes());
    assert_eq!(ok(build(nodes, Vec::new())).nodes().len(), 3);
}

#[test]
fn nodes_must_be_strictly_ascending_with_unique_digests() {
    let mut reordered = sample_nodes();
    reordered.reverse();
    let outcome = err(build(reordered, Vec::new()));
    assert_eq!(outcome, DepError::NonCanonicalOrder);
    let first = sample_nodes().remove(0);
    let same_position = vec![first.clone(), first];
    assert_eq!(
        err(build(same_position, Vec::new())),
        DepError::DuplicateIdentity
    );
    let digest_repeat = vec![
        node_row(coord(17, "a", 1), PROVISIONAL, Vec::new()),
        node_row(coord(17, "b", 1), PROVISIONAL, Vec::new()),
    ];
    assert_eq!(
        err(build(digest_repeat, Vec::new())),
        DepError::DuplicateIdentity
    );
}

#[test]
fn edges_must_be_in_canonical_order_without_repeats() {
    let mut reordered = sample_edges();
    reordered.reverse();
    let outcome = err(build(sample_nodes(), reordered));
    assert_eq!(outcome, DepError::NonCanonicalOrder);
    let repeated = vec![sample_edges().remove(0), sample_edges().remove(0)];
    assert_eq!(
        err(build(sample_nodes(), repeated)),
        DepError::DuplicateIdentity
    );
    let consumer = coord(17, "b", 2);
    let by_source = vec![
        edge_row(&consumer, &coord(10, "w", 70)),
        edge_row(&consumer, &coord(10, "w", 60)),
    ];
    assert_eq!(
        err(build(sample_nodes(), by_source)),
        DepError::NonCanonicalOrder
    );
}

#[test]
fn edge_order_ignores_the_consumer_schema_and_digest() {
    let first = coord(17, "a", 1);
    let twin = coord(17, "a", 9);
    let source = coord(10, "w", 50);
    let left = edge_row(&first, &source);
    let right = edge_row(&twin, &source);
    assert_eq!(left.order_cmp(&right), std::cmp::Ordering::Equal);
    let later = edge_row(&coord(17, "b", 2), &source);
    assert_eq!(left.order_cmp(&later), std::cmp::Ordering::Less);
}

#[test]
fn edge_consumers_must_be_nodes_of_the_record() {
    let outside = vec![edge_row(&coord(17, "c", 3), &coord(10, "w", 50))];
    assert_eq!(
        err(build(sample_nodes(), outside)),
        DepError::UnknownConsumer
    );
    let other_digest = vec![edge_row(&coord(17, "a", 9), &coord(10, "w", 50))];
    assert_eq!(
        err(build(sample_nodes(), other_digest)),
        DepError::UnknownConsumer
    );
}

#[test]
fn edge_sources_must_be_declared_by_the_consumer() {
    let undeclared = vec![edge_row(&coord(17, "a", 1), &coord(10, "w", 51))];
    assert_eq!(
        err(build(sample_nodes(), undeclared)),
        DepError::UndeclaredInput
    );
    let declared_only = ok(build(sample_nodes(), Vec::new()));
    assert_eq!(declared_only.uncovered_input_count(), 3);
}

#[test]
fn errors_have_distinct_safe_messages() {
    let errors = [
        DepError::InvalidEncoding,
        DepError::UnsupportedVersion,
        DepError::FieldOutOfBounds,
        DepError::UnknownEnum,
        DepError::NonCanonicalOrder,
        DepError::DuplicateIdentity,
        DepError::ProvenanceMissing,
        DepError::BindingMismatch,
        DepError::UnknownConsumer,
        DepError::UndeclaredInput,
        DepError::InvalidCursor,
        DepError::InvalidPageLimit,
    ];
    let messages: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
}

#[test]
fn dependency_errors_map_to_the_nearest_store_error() {
    let table = [
        (DepError::InvalidEncoding, StoreError::InvalidEncoding),
        (DepError::UnsupportedVersion, StoreError::UnsupportedVersion),
        (DepError::FieldOutOfBounds, StoreError::FieldOutOfBounds),
        (DepError::UnknownEnum, StoreError::InvalidEncoding),
        (DepError::NonCanonicalOrder, StoreError::NonCanonicalOrder),
        (DepError::DuplicateIdentity, StoreError::DuplicateIdentity),
        (DepError::ProvenanceMissing, StoreError::FieldOutOfBounds),
        (DepError::BindingMismatch, StoreError::BindingMismatch),
        (DepError::UnknownConsumer, StoreError::BindingMismatch),
        (DepError::UndeclaredInput, StoreError::BindingMismatch),
        (DepError::InvalidCursor, StoreError::BindingMismatch),
        (DepError::InvalidPageLimit, StoreError::FieldOutOfBounds),
    ];
    for (error, expected) in table {
        assert_eq!(StoreError::from(error), expected);
    }
    assert_eq!(DepError::READ_BACK_FAULT, StoreError::CorruptState);
}

fn fork_scope(generation: u64) -> DependencyReadScopeV1 {
    DependencyReadScopeV1::ForkGeneration(ForkGenerationV1 {
        fork: fork(),
        generation,
    })
}

fn prefix_scope(through_tick: u64) -> DependencyReadScopeV1 {
    DependencyReadScopeV1::ParentPrefix {
        timeline: parent(),
        through_tick,
    }
}

fn request(
    scope: DependencyReadScopeV1,
    after: Option<DependencyPageCursorV1>,
    limit: usize,
) -> DependencyPageRequestV1 {
    ok(DependencyPageRequestV1::try_new(scope, after, limit))
}

fn numbered_rows(count: u32) -> Vec<NodeRow> {
    (0..count)
        .map(|ordinal| {
            let digest = indexed_hash(1 + ok(usize::try_from(ordinal)));
            node_row(coord_at(17, "a", ordinal, digest), PROVISIONAL, Vec::new())
        })
        .collect()
}

#[test]
fn cursors_are_validated_and_expose_their_key() {
    let owner = "a".to_owned();
    let node_cursor = ok(DependencyPageCursorV1::try_new(5, 2, owner, 3, None));
    assert_eq!(node_cursor.tick(), 5);
    assert_eq!(node_cursor.scheduler_position(), 2);
    assert_eq!(node_cursor.owner_id(), "a");
    assert_eq!(node_cursor.output_ordinal(), 3);
    assert_eq!(node_cursor.source_digest(), None);
    let edge_cursor = ok(DependencyPageCursorV1::try_new(
        5,
        2,
        "a".to_owned(),
        3,
        Some(hash(4)),
    ));
    assert_eq!(edge_cursor.source_digest(), Some(hash(4)));
    assert!(node_cursor < edge_cursor);
    let bad_owner = "o".repeat(MAX_DEPENDENCY_OWNER_ID_BYTES_V1 + 1);
    let cases = [
        (String::new(), None),
        (bad_owner, None),
        ("a".to_owned(), Some(Hash::zero())),
    ];
    for (owner, digest) in cases {
        assert_eq!(
            DependencyPageCursorV1::try_new(5, 2, owner, 3, digest),
            Err(DepError::InvalidCursor)
        );
    }
    let row = numbered_rows(1).remove(0);
    assert_eq!(row.cursor().output_ordinal(), 0);
    assert_eq!(row.cursor().source_digest(), None);
    let edge = sample_edges().remove(1);
    assert_eq!(edge.cursor().owner_id(), "b");
    assert_eq!(edge.cursor().source_digest(), Some(hash(1)));
}

#[test]
fn page_requests_cap_the_limit_and_scope_the_cursor() {
    let scope = fork_scope(3);
    for limit in [1, MAX_DEPENDENCY_PAGE_ROWS_V1] {
        assert_eq!(request(scope, None, limit).limit(), limit);
    }
    for limit in [0, MAX_DEPENDENCY_PAGE_ROWS_V1 + 1] {
        assert_eq!(
            DependencyPageRequestV1::try_new(scope, None, limit),
            Err(DepError::InvalidPageLimit)
        );
    }
    let owner = "a".to_owned();
    let cursor = ok(DependencyPageCursorV1::try_new(9, 0, owner, 0, None));
    let at_end = request(prefix_scope(9), Some(cursor.clone()), 2);
    assert_eq!(at_end.after(), Some(&cursor));
    assert_eq!(at_end.scope(), prefix_scope(9));
    assert_eq!(
        DependencyPageRequestV1::try_new(prefix_scope(8), Some(cursor.clone()), 2),
        Err(DepError::InvalidCursor)
    );
    let resumed = DependencyPageRequestV1::try_new(scope, Some(cursor), 2);
    assert!(resumed.is_ok());
}

fn node_page_of(scope: DependencyReadScopeV1, row: &NodeRow) -> Result<NodePage, DepError> {
    NodePage::try_new(&request(scope, None, 2), vec![row.clone()], None)
}

fn edge_page_of(scope: DependencyReadScopeV1, row: &EdgeRow) -> Result<EdgePage, DepError> {
    EdgePage::try_new(&request(scope, None, 2), vec![row.clone()], None)
}

#[test]
fn pages_reject_rows_outside_the_request_scope() {
    let committed = RecordedNodeOriginV1::Committed;
    let prefix_row = node_row(coord(10, "w", 50), committed, Vec::new());
    let fork_row = node_row(coord(17, "a", 1), PROVISIONAL, Vec::new());
    assert!(node_page_of(prefix_scope(10), &prefix_row).is_ok());
    assert!(node_page_of(fork_scope(3), &fork_row).is_ok());
    let outside = [
        (prefix_scope(9), &prefix_row),
        (prefix_scope(20), &fork_row),
        (fork_scope(3), &prefix_row),
    ];
    for (scope, row) in outside {
        assert_eq!(err(node_page_of(scope, row)), DepError::BindingMismatch);
    }
    let edge = sample_edges().remove(0);
    assert!(edge_page_of(prefix_scope(17), &edge).is_ok());
    assert!(edge_page_of(fork_scope(3), &edge).is_ok());
    let beyond = edge_page_of(prefix_scope(16), &edge);
    assert_eq!(err(beyond), DepError::BindingMismatch);
}

#[test]
fn ordered_rows_page_with_continuation_cursors() {
    let rows = numbered_rows(5);
    let first_request = request(fork_scope(3), None, 2);
    let first = ok(NodePage::from_ordered(&first_request, &rows));
    assert_eq!(first.items(), &rows[..2]);
    assert_eq!(first.next(), Some(&rows[1].cursor()));
    let second_request = request(fork_scope(3), first.next().cloned(), 2);
    let second = ok(NodePage::from_ordered(&second_request, &rows));
    assert_eq!(second.items(), &rows[2..4]);
    let third_request = request(fork_scope(3), second.next().cloned(), 2);
    let third = ok(NodePage::from_ordered(&third_request, &rows));
    assert_eq!(third.items(), &rows[4..]);
    assert_eq!(third.next(), None);
    let wide_request = request(fork_scope(3), None, 5);
    let exact = ok(NodePage::from_ordered(&wide_request, &rows));
    assert_eq!((exact.items().len(), exact.next()), (5, None));
    let empty = ok(NodePage::from_ordered(&wide_request, &[]));
    assert_eq!((empty.items().len(), empty.next()), (0, None));
    let rebuilt = NodePage::try_new(&second_request, rows[2..4].to_vec(), second.next().cloned());
    assert_eq!(ok(rebuilt), second);
}

#[test]
fn pages_reject_cursors_of_the_other_row_kind() {
    let rows = numbered_rows(2);
    let edges = sample_edges();
    let node_after = request(fork_scope(3), Some(rows[0].cursor()), 2);
    let edge_after = request(fork_scope(3), Some(edges[0].cursor()), 2);
    assert_eq!(
        err(EdgePage::from_ordered(&node_after, &edges)),
        DepError::InvalidCursor
    );
    assert_eq!(
        err(NodePage::from_ordered(&edge_after, &rows)),
        DepError::InvalidCursor
    );
    assert_eq!(
        err(EdgePage::try_new(&node_after, Vec::new(), None)),
        DepError::InvalidCursor
    );
    let resumed = request(fork_scope(3), Some(edges[0].cursor()), 2);
    let page = ok(EdgePage::from_ordered(&resumed, &edges));
    assert_eq!(page.items(), &edges[1..]);
}

#[test]
fn adapter_built_pages_are_validated_against_the_request() {
    let rows = numbered_rows(4);
    let first_request = request(fork_scope(3), None, 2);
    let too_many = rows[..3].to_vec();
    assert_eq!(
        err(NodePage::try_new(&first_request, too_many, None)),
        DepError::FieldOutOfBounds
    );
    let mut swapped = rows[..2].to_vec();
    swapped.reverse();
    assert_eq!(
        err(NodePage::try_new(&first_request, swapped, None)),
        DepError::NonCanonicalOrder
    );
    let repeated = vec![rows[0].clone(), rows[0].clone()];
    assert_eq!(
        err(NodePage::try_new(&first_request, repeated, None)),
        DepError::DuplicateIdentity
    );
    let after_first = request(fork_scope(3), Some(rows[1].cursor()), 2);
    assert_eq!(
        err(NodePage::try_new(&after_first, rows[1..2].to_vec(), None)),
        DepError::DuplicateIdentity
    );
    let before_cursor = request(fork_scope(3), Some(rows[2].cursor()), 2);
    assert_eq!(
        err(NodePage::try_new(&before_cursor, rows[..2].to_vec(), None)),
        DepError::NonCanonicalOrder
    );
}

#[test]
fn page_continuations_must_resume_after_a_full_page() {
    let rows = numbered_rows(4);
    let two = request(fork_scope(3), None, 2);
    let full = rows[..2].to_vec();
    let last = Some(rows[1].cursor());
    assert!(NodePage::try_new(&two, full.clone(), last.clone()).is_ok());
    assert!(NodePage::try_new(&two, full.clone(), None).is_ok());
    let wrong = Some(rows[0].cursor());
    assert_eq!(
        err(NodePage::try_new(&two, full, wrong)),
        DepError::InvalidCursor
    );
    let short = rows[..1].to_vec();
    assert_eq!(
        err(NodePage::try_new(&two, short, Some(rows[0].cursor()))),
        DepError::InvalidCursor
    );
    assert_eq!(
        err(NodePage::try_new(&two, Vec::new(), last)),
        DepError::InvalidCursor
    );
}

#[test]
fn read_scopes_require_the_committed_generation() {
    assert_eq!(fork_scope(3).ensure_current(3), Ok(()));
    for current in [2, 4] {
        assert_eq!(
            fork_scope(3).ensure_current(current),
            Err(StoreError::MixedForkGeneration)
        );
    }
    assert_eq!(prefix_scope(9).ensure_current(0), Ok(()));
}

#[test]
fn only_parent_prefix_scopes_are_bounded_by_a_tick() {
    assert_eq!(prefix_scope(9).through_tick(), Some(9));
    assert_eq!(fork_scope(3).through_tick(), None);
}

// The frontier, invalidation, drafts, facts, and command helpers below mirror
// those of `counterfactual_store_public.rs`: integration tests are separate
// crates, so they are copied rather than shared.
fn frontier() -> RecomputationFrontierBytesV1 {
    let fields = [
        id_field([1; 16]),
        hash_field(hash(5)),
        hash_field(hash(2)),
        hash_field(hash(3)),
        vec![0x01],
    ]
    .concat();
    ok(RecomputationFrontierBytesV1::try_from_canonical(
        frontier_frame(&fields, 0),
    ))
}

fn invalidation(frontier: &RecomputationFrontierBytesV1) -> SuffixInvalidationBytesV1 {
    let fork_id = fork().inner().to_bytes();
    let fields = [
        id_field([4; 16]),
        hash_field(frontier.plan_digest()),
        id_field(fork_id),
        uint(3),
        uint(4),
        hash_field(frontier.digest()),
        invalidation_middle(),
        vec![0x83],
        id_field(fork_id),
        uint(41),
        uint(17),
    ]
    .concat();
    ok(SuffixInvalidationBytesV1::try_from_canonical(
        invalidation_frame(&fields, 0),
    ))
}

fn drafts() -> PipelineDraftBatchV1 {
    ok(PipelineDraftBatchV1::try_new(vec![EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new("counterfactual.tick"),
        CanonicalBytes::from_vec(vec![7]),
    )]))
}

const fn facts() -> CounterfactualFactsV1 {
    CounterfactualFactsV1 {
        plan_digest: hash(5),
        dependency_graph_digest: hash(3),
        trust_epoch: 6,
        revocation_epoch: 7,
        erasure_epoch: 8,
    }
}

fn command() -> CounterfactualInvalidationCommandV1 {
    let frontier = frontier();
    let invalidation = invalidation(&frontier);
    ok(CounterfactualInvalidationCommandV1::try_new(
        CounterfactualInvalidationInputV1 {
            fork: fork(),
            fork_logical_head: Seq::from_u64(41),
            trust_epoch: 6,
            revocation_epoch: 7,
            erasure_epoch: 8,
            frontier,
            invalidation,
            invalid_artifacts: vec![hash(10)],
            evictions: vec![hash(12)],
            first_tick: 17,
            first_tick_drafts: drafts(),
        },
    ))
}

/// Minimal fake showing both contracts are implementable without backend
/// types. Fork rows carry the generation that wrote them.
struct FakeStore {
    head: Seq,
    generation: u64,
    facts: CounterfactualFactsV1,
    fork_nodes: Vec<(u64, NodeRow)>,
    fork_edges: Vec<(u64, EdgeRow)>,
    /// The Tick of every record, with its generation: persisted apart from
    /// the node Ticks, which under-report it for a record of early roots.
    record_ticks: Vec<(u64, u64)>,
    /// The first Tick of the current generation, known from its invalidation.
    first_tick: u64,
    /// Whether the generation has a persisted first Tick: not at generation
    /// 0, nor for a Fork never invalidated, nor one re-created at its floor.
    has_first_tick: bool,
    /// Test-poked: the committed prefix has no write path here (#554).
    parent_nodes: Vec<NodeRow>,
    /// Test-poked: the committed prefix has no write path here (#554).
    parent_edges: Vec<EdgeRow>,
}

impl FakeStore {
    const fn new() -> Self {
        Self {
            head: Seq::from_u64(41),
            generation: 3,
            facts: facts(),
            fork_nodes: Vec::new(),
            fork_edges: Vec::new(),
            record_ticks: Vec::new(),
            first_tick: 17,
            has_first_tick: true,
            parent_nodes: Vec::new(),
            parent_edges: Vec::new(),
        }
    }

    const fn basis(&self) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head: self.head,
            generation: self.generation,
            facts: self.facts,
        }
    }

    fn head_after(&self, drafts: &PipelineDraftBatchV1) -> Seq {
        Seq::from_u64(self.head.as_u64() + ok(u64::try_from(drafts.drafts().len())))
    }

    /// The nodes recorded under the current generation.
    fn recorded_nodes(&self) -> impl Iterator<Item = &NodeRow> {
        self.fork_nodes
            .iter()
            .filter(|(generation, _)| *generation == self.generation)
            .map(|(_, row)| row)
    }

    /// The row counts of the current generation's recorded set.
    fn recorded_counts(&self) -> RecordedSetCountsV1 {
        let edges = self
            .fork_edges
            .iter()
            .filter(|(generation, _)| *generation == self.generation);
        RecordedSetCountsV1 {
            nodes: self.recorded_nodes().count(),
            edges: edges.count(),
            inputs: self
                .recorded_nodes()
                .map(|row| row.input_digests().len())
                .sum(),
        }
    }

    /// Validate `record` for an invalidation at `first_tick`, which writes
    /// the empty set of the new generation.
    fn admit_first(record: &TickRecord, first_tick: u64) -> Result<(), StoreError> {
        record.ensure_provisional()?;
        if record.tick() != first_tick {
            return Err(StoreError::BindingMismatch);
        }
        let capacity = record.ensure_set_capacity(RecordedSetCountsV1::default());
        capacity.map_err(StoreError::from)
    }

    /// Validate `record` for a later Tick: refused outright when the
    /// generation has no persisted first Tick; otherwise strictly after the
    /// last persisted record Tick, or not below the generation's first Tick
    /// while the set is empty, with no node position key or digest already in
    /// the set.
    fn admit_later(&self, record: &TickRecord) -> Result<(), StoreError> {
        record.ensure_provisional()?;
        if !self.has_first_tick {
            return Err(StoreError::BindingMismatch);
        }
        let last_tick = self
            .record_ticks
            .iter()
            .filter(|(generation, _)| *generation == self.generation)
            .map(|(_, tick)| *tick)
            .max();
        let first_tick = self.first_tick;
        let rejected =
            last_tick.map_or_else(|| record.tick() < first_tick, |last| record.tick() <= last);
        if rejected {
            return Err(StoreError::BindingMismatch);
        }
        let repeats = record.nodes().iter().any(|row| {
            self.recorded_nodes().any(|old| {
                old.coordinate().artifact_digest() == row.coordinate().artifact_digest()
                    || old.coordinate().position_key() == row.coordinate().position_key()
            })
        });
        if repeats {
            return Err(StoreError::DuplicateIdentity);
        }
        let capacity = record.ensure_set_capacity(self.recorded_counts());
        capacity.map_err(StoreError::from)
    }

    fn record(&mut self, record: &TickRecord, generation: u64) {
        self.record_ticks.push((generation, record.tick()));
        self.fork_nodes
            .extend(record.nodes().iter().map(|row| (generation, row.clone())));
        self.fork_edges
            .extend(record.edges().iter().map(|row| (generation, row.clone())));
    }

    fn commit(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: Option<&TickRecord>,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        if let Some(record) = record {
            Self::admit_first(record, command.first_tick())?;
        }
        if let Some(conflict) = command.expected_basis().first_conflict(&self.basis()) {
            return Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                conflict,
            ));
        }
        let receipt =
            command.committed_receipt(&SEAL, self.head_after(command.first_tick_drafts()))?;
        self.head = receipt.first_tick_head();
        self.generation = receipt.generation().generation;
        self.first_tick = command.first_tick();
        self.has_first_tick = true;
        if let Some(record) = record {
            self.record(record, self.generation);
        }
        Ok(CounterfactualInvalidationOutcomeV1::Committed(Box::new(
            receipt,
        )))
    }

    fn append(
        &mut self,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: Option<&TickRecord>,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        if let Some(conflict) = expected.first_conflict(&self.basis()) {
            return Ok(CounterfactualTickOutcomeV1::Stale(conflict));
        }
        if let Some(record) = record {
            self.admit_later(record)?;
        }
        let outcome = self
            .basis()
            .committed_tick(&SEAL, self.head_after(drafts))?;
        self.head = self.head_after(drafts);
        if let Some(record) = record {
            self.record(record, self.generation);
        }
        Ok(outcome)
    }

    fn page<T: DependencyPagedRowV1 + Clone>(
        &self,
        request: &DependencyPageRequestV1,
        fork_rows: &[(u64, T)],
        parent_rows: &[T],
    ) -> Result<DependencyPageV1<T>, StoreError> {
        request.scope().ensure_current(self.generation)?;
        let mut rows: Vec<T> = match request.scope() {
            DependencyReadScopeV1::ParentPrefix {
                timeline,
                through_tick,
            } if timeline == parent() => parent_rows
                .iter()
                .filter(|row| row.cursor().tick() <= through_tick)
                .cloned()
                .collect(),
            DependencyReadScopeV1::ForkGeneration(at) if at.fork == fork() => fork_rows
                .iter()
                .filter(|(generation, _)| *generation == at.generation)
                .map(|(_, row)| row.clone())
                .collect(),
            _ => return Err(StoreError::ForkNotFound),
        };
        rows.sort_by_key(T::cursor);
        // A request cursor of the other row kind is the caller's fault.
        let page = DependencyPageV1::from_ordered(request, &rows)?;
        // A stored row that fails re-validation is corrupt state.
        let checked =
            DependencyPageV1::try_new(request, page.items().to_vec(), page.next().cloned());
        checked.or(Err(DepError::READ_BACK_FAULT))
    }
}

impl CounterfactualStorePortV1 for FakeStore {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, StoreError> {
        self.facts = facts;
        Ok(ForkGenerationV1 {
            fork,
            generation: self.generation,
        })
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        self.commit(command, None)
    }

    fn append_counterfactual_tick(
        &mut self,
        _fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        self.append(expected, drafts, None)
    }

    fn current_fork_generation(&self, fork: TimelineId) -> Result<ForkGenerationV1, StoreError> {
        Ok(ForkGenerationV1 {
            fork,
            generation: self.generation,
        })
    }

    fn current_counterfactual_basis(
        &self,
        _fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, StoreError> {
        Ok(self.basis())
    }

    fn committed_generation_receipt(
        &self,
        _at: ForkGenerationV1,
    ) -> Result<Option<CounterfactualGenerationReceiptV1>, StoreError> {
        Ok(None)
    }

    fn read_generation_artifact(
        &self,
        _at: ForkGenerationV1,
        _artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(None)
    }
}

impl CounterfactualDependencyRecordingPortV1 for FakeStore {
    fn commit_counterfactual_invalidation_with_dependencies(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        self.commit(command, Some(record))
    }

    fn append_counterfactual_tick_with_dependencies(
        &mut self,
        _fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        self.append(expected, drafts, Some(record))
    }
}

impl CounterfactualDependencyReadPortV1 for FakeStore {
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<NodePage, StoreError> {
        self.page(request, &self.fork_nodes, &self.parent_nodes)
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<EdgePage, StoreError> {
        self.page(request, &self.fork_edges, &self.parent_edges)
    }
}

/// Read every page of `scope` through `read`.
fn collect_rows<T: DependencyPagedRowV1 + Clone>(
    scope: DependencyReadScopeV1,
    limit: usize,
    read: impl Fn(&DependencyPageRequestV1) -> Result<DependencyPageV1<T>, StoreError>,
) -> Result<Vec<T>, StoreError> {
    let mut rows = Vec::new();
    let mut after = None;
    loop {
        let page = read(&request(scope, after, limit))?;
        rows.extend_from_slice(page.items());
        after = page.next().cloned();
        if after.is_none() {
            return Ok(rows);
        }
    }
}

fn collect_nodes(
    store: &FakeStore,
    scope: DependencyReadScopeV1,
    limit: usize,
) -> Result<Vec<NodeRow>, StoreError> {
    collect_rows(scope, limit, |page| store.read_dependency_nodes(page))
}

fn collect_edges(
    store: &FakeStore,
    scope: DependencyReadScopeV1,
    limit: usize,
) -> Result<Vec<EdgeRow>, StoreError> {
    collect_rows(scope, limit, |page| store.read_dependency_edges(page))
}

/// Tick 18: node `a` consumes the provisional node `a` of tick 17.
fn tick_18_record() -> TickRecord {
    let consumer = coord(18, "a", 21);
    let nodes = vec![node_row(consumer.clone(), PROVISIONAL, vec![hash(1)])];
    let edges = vec![edge_row(&consumer, &coord(17, "a", 1))];
    ok(TickRecord::try_new(18, PROVISIONAL, nodes, edges))
}

fn committed_store() -> FakeStore {
    let mut store = FakeStore::new();
    let outcome =
        ok(store
            .commit_counterfactual_invalidation_with_dependencies(&command(), &sample_record()));
    assert!(matches!(
        outcome,
        CounterfactualInvalidationOutcomeV1::Committed(_)
    ));
    store
}

#[test]
fn invalidation_records_its_dependencies_under_the_new_generation() {
    let store = committed_store();
    for limit in [1, 2, 5] {
        let nodes = ok(collect_nodes(&store, fork_scope(4), limit));
        assert_eq!(nodes, sample_nodes());
        let edges = ok(collect_edges(&store, fork_scope(4), limit));
        assert_eq!(edges, sample_edges());
    }
    for stale in [3, 5] {
        assert_eq!(
            err(collect_nodes(&store, fork_scope(stale), 2)),
            StoreError::MixedForkGeneration
        );
        assert_eq!(
            err(collect_edges(&store, fork_scope(stale), 2)),
            StoreError::MixedForkGeneration
        );
    }
}

#[test]
fn conflicting_or_misplaced_invalidations_record_nothing() {
    let mut store = FakeStore::new();
    store.facts.trust_epoch = 99;
    let outcome =
        ok(store
            .commit_counterfactual_invalidation_with_dependencies(&command(), &sample_record()));
    assert_eq!(
        outcome,
        CounterfactualInvalidationOutcomeV1::InvalidationConflict(
            InvalidationConflictV1::TrustEpoch
        )
    );
    store.facts = facts();
    let committed_record = ok(TickRecord::try_new(
        17,
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        Vec::new(),
    ));
    let wrong_tick = ok(TickRecord::try_new(18, PROVISIONAL, Vec::new(), Vec::new()));
    for record in [committed_record, wrong_tick] {
        let outcome =
            store.commit_counterfactual_invalidation_with_dependencies(&command(), &record);
        assert_eq!(err(outcome), StoreError::BindingMismatch);
    }
    assert_eq!(ok(collect_nodes(&store, fork_scope(3), 2)), Vec::new());
    assert_eq!(ok(collect_edges(&store, fork_scope(3), 2)), Vec::new());
    assert_eq!(store.basis().generation, 3);
    assert_eq!(store.basis().fork_logical_head, Seq::from_u64(41));
}

#[test]
fn later_ticks_record_only_on_the_expected_basis() {
    let mut store = committed_store();
    let expected = store.basis();
    let outcome = ok(store.append_counterfactual_tick_with_dependencies(
        fork(),
        &expected,
        &drafts(),
        &tick_18_record(),
    ));
    assert_eq!(
        outcome,
        CounterfactualTickOutcomeV1::Committed {
            head: Seq::from_u64(43)
        }
    );
    let nodes = ok(collect_nodes(&store, fork_scope(4), 2));
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[2], tick_18_record().nodes()[0]);
    assert_eq!(ok(collect_edges(&store, fork_scope(4), 2)).len(), 3);
    let stale = ok(store.append_counterfactual_tick_with_dependencies(
        fork(),
        &expected,
        &drafts(),
        &tick_18_record(),
    ));
    assert_eq!(
        stale,
        CounterfactualTickOutcomeV1::Stale(InvalidationConflictV1::LogicalHead)
    );
    assert_eq!(ok(collect_nodes(&store, fork_scope(4), 2)).len(), 3);
}

#[test]
fn later_tick_records_must_be_provisional_and_advance() {
    let mut store = committed_store();
    let expected = store.basis();
    let committed_record = ok(TickRecord::try_new(
        18,
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        Vec::new(),
    ));
    let repeated_tick = sample_record();
    for record in [committed_record, repeated_tick] {
        assert_eq!(
            err(store.append_counterfactual_tick_with_dependencies(
                fork(),
                &expected,
                &drafts(),
                &record
            )),
            StoreError::BindingMismatch
        );
    }
    assert_eq!(store.basis(), expected);
    assert_eq!(ok(collect_nodes(&store, fork_scope(4), 5)).len(), 2);
}

fn append_record(
    store: &mut FakeStore,
    record: &TickRecord,
) -> Result<CounterfactualTickOutcomeV1, StoreError> {
    let expected = store.basis();
    store.append_counterfactual_tick_with_dependencies(fork(), &expected, &drafts(), record)
}

#[test]
fn later_records_may_not_reuse_a_recorded_position_key_or_digest() {
    let mut store = committed_store();
    let expected = store.basis();
    let root = RecordedDependencyClassV1::InterventionAssigned;
    // The position key of node `a` at tick 17 with another digest.
    let same_position = class_row(coord(17, "a", 77), root, PROVISIONAL, Vec::new());
    // The digest of node `a` at another position.
    let same_digest = node_row(coord(18, "z", 1), PROVISIONAL, Vec::new());
    for row in [same_position, same_digest] {
        let record = ok(TickRecord::try_new(18, PROVISIONAL, vec![row], Vec::new()));
        let outcome = append_record(&mut store, &record);
        assert_eq!(err(outcome), StoreError::DuplicateIdentity);
    }
    assert_eq!(store.basis(), expected);
    assert_eq!(ok(collect_nodes(&store, fork_scope(4), 5)).len(), 2);
}

#[test]
fn the_record_tick_is_persisted_apart_from_node_ticks() {
    let mut store = FakeStore::new();
    store.first_tick = 5;
    let root_class = RecordedDependencyClassV1::InterventionAssigned;
    let root = class_row(coord(2, "r", 9), root_class, PROVISIONAL, Vec::new());
    let early = ok(TickRecord::try_new(5, PROVISIONAL, vec![root], Vec::new()));
    let empty_at = |tick: u64| {
        ok(TickRecord::try_new(
            tick,
            PROVISIONAL,
            Vec::new(),
            Vec::new(),
        ))
    };
    let first = append_record(&mut store, &early);
    assert!(first.is_ok());
    let before = append_record(&mut store, &empty_at(4));
    assert_eq!(err(before), StoreError::BindingMismatch);
    let after = append_record(&mut store, &empty_at(6));
    assert!(after.is_ok());
}

#[test]
fn parent_prefix_rows_stitch_to_fork_rows_by_concatenation() {
    let mut store = committed_store();
    let committed = RecordedNodeOriginV1::Committed;
    store.parent_nodes = vec![
        node_row(coord(8, "w", 31), committed, Vec::new()),
        node_row(coord(9, "w", 32), committed, Vec::new()),
        node_row(coord(10, "w", 50), committed, Vec::new()),
    ];
    let prefix = ok(collect_nodes(&store, prefix_scope(9), 1));
    assert_eq!(prefix, store.parent_nodes[..2].to_vec());
    let stitched = [prefix, ok(collect_nodes(&store, fork_scope(4), 5))].concat();
    assert_eq!(stitched.len(), 4);
    assert!(stitched
        .windows(2)
        .all(|pair| pair[0].cursor() < pair[1].cursor()));
    assert_eq!(ok(collect_edges(&store, prefix_scope(9), 2)), Vec::new());
    let other = DependencyReadScopeV1::ParentPrefix {
        timeline: fork(),
        through_tick: 9,
    };
    let outcome = err(collect_nodes(&store, other, 2));
    assert_eq!(outcome, StoreError::ForkNotFound);
}

#[test]
fn reads_reject_cursors_of_the_wrong_row_kind() {
    let store = committed_store();
    let edge_cursor = sample_edges()[0].cursor();
    let wrong = request(fork_scope(4), Some(edge_cursor), 2);
    assert_eq!(
        err(store.read_dependency_nodes(&wrong)),
        StoreError::BindingMismatch
    );
}

#[test]
fn stored_rows_that_fail_revalidation_read_back_as_corrupt_state() {
    let mut store = committed_store();
    let committed = RecordedNodeOriginV1::Committed;
    // A committed node stored under the Fork generation is out of scope.
    let stray = node_row(coord(30, "q", 1), committed, Vec::new());
    store.fork_nodes.push((4, stray));
    assert_eq!(
        err(collect_nodes(&store, fork_scope(4), 5)),
        StoreError::CorruptState
    );
    // A provisional node stored in the parent prefix is out of scope.
    let mut prefix_store = FakeStore::new();
    prefix_store.parent_nodes = vec![node_row(coord(8, "w", 31), PROVISIONAL, Vec::new())];
    assert_eq!(
        err(collect_nodes(&prefix_store, prefix_scope(9), 2)),
        StoreError::CorruptState
    );
}

#[test]
fn the_first_record_tick_may_not_precede_the_generation_first_tick() {
    let mut store = FakeStore::new();
    let plain = ok(store.commit_counterfactual_invalidation(&command()));
    assert!(matches!(
        plain,
        CounterfactualInvalidationOutcomeV1::Committed(_)
    ));
    let below = ok(TickRecord::try_new(16, PROVISIONAL, Vec::new(), Vec::new()));
    assert_eq!(
        err(append_record(&mut store, &below)),
        StoreError::BindingMismatch
    );
    assert_eq!(ok(collect_nodes(&store, fork_scope(4), 5)), Vec::new());
    assert!(append_record(&mut store, &sample_record()).is_ok());
    assert_eq!(ok(collect_nodes(&store, fork_scope(4), 5)).len(), 2);
}

#[test]
fn a_generation_without_a_first_tick_takes_no_record() {
    let mut store = FakeStore::new();
    store.has_first_tick = false;
    let expected = store.basis();
    assert_eq!(
        err(append_record(&mut store, &sample_record())),
        StoreError::BindingMismatch
    );
    assert_eq!(store.basis(), expected);
    assert_eq!(ok(collect_nodes(&store, fork_scope(3), 5)), Vec::new());
    assert!(store.record_ticks.is_empty());
}
