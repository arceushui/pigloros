//! Public-interface tests for the `MemoryStore` ADR-064 dependency record
//! adapter.
//!
//! Every test name starts with the id of the shared conformance checklist item
//! it proves (C1 to C13), so the `SQLite` adapter's tests correspond one to one.
//! State-private cases (injected failures, lowered set counts, the seeded
//! committed prefix, corrupt stored rows) are in-module tests of the adapter.
//!
//! Checklist id C3 is split: provisional-only is proved here, and set capacity
//! is proved in the in-module tests.

use std::sync::Arc;

use pos_core::counterfactual_store::test_fixtures::{
    frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, text_field, uint,
};
use pos_core::{
    CanonicalBytes, CounterfactualBasisV1, CounterfactualDependencyErrorV1,
    CounterfactualDependencyReadPortV1, CounterfactualDependencyRecordingPortV1,
    CounterfactualFactsV1, CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1,
    DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    DependencyPageCursorV1, DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1,
    DependencyReadScopeV1, EntityId, ErasureContainmentGateV1, EventDraft, ForkGenerationV1, Hash,
    InvalidationConflictV1, Kind, PipelineDraftBatchV1, RecomputationFrontierBytesV1,
    RecordedDependencyClassV1, RecordedNodeOriginV1, Seq, SeqRange, SuffixInvalidationBytesV1,
    TickDependencyRecordV1, TimelineId, TimelineMeta, MAX_DEPENDENCY_PAGE_ROWS_V1,
};
use pos_store::{memory::MemoryStore, EventStore};

type DepError = CounterfactualDependencyErrorV1;
type StoreError = CounterfactualStoreErrorV1;
type Coordinate = DependencyNodeCoordinateV1;
type NodeRow = DependencyNodeRecordV1;
type EdgeRow = DependencyEdgeRecordV1;
type TickRecord = TickDependencyRecordV1;
type Scope = DependencyReadScopeV1;

const PROVISIONAL: RecordedNodeOriginV1 = RecordedNodeOriginV1::Provisional;
const COMMITTED: RecordedNodeOriginV1 = RecordedNodeOriginV1::Committed;
const ROOT_CLASS: RecordedDependencyClassV1 = RecordedDependencyClassV1::InterventionAssigned;
const EDGE_HEAD: [u8; 7] = [0x89, 0x64, b'I', b'D', b'P', b'1', 0x01];

/// Tick number of every test command's first recomputation Tick.
const FIRST_TICK: u64 = 17;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    result.map_or_else(
        |error| error,
        |value| std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
    )
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn indexed_hash(index: usize) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&ok(u64::try_from(index)).to_be_bytes());
    Hash::from_bytes(bytes)
}

fn draft(value: u8) -> EventDraft {
    typed_draft("counterfactual.tick", value)
}

fn typed_draft(kind: &str, value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new(kind),
        CanonicalBytes::from_vec(vec![value]),
    )
}

fn tick_drafts(count: u8) -> PipelineDraftBatchV1 {
    let drafts = (0..count).map(draft).collect();
    ok(PipelineDraftBatchV1::try_new(drafts))
}

/// A Tick whose last draft the generic append guard conceals as a missing Fork.
fn guarded_drafts() -> PipelineDraftBatchV1 {
    let guarded = typed_draft("geo.location", 0);
    ok(PipelineDraftBatchV1::try_new(vec![draft(0), guarded]))
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

/// An invalidation of `fork` at its logical `head` over generation `prior`,
/// expecting `trust_epoch`, whose first Tick appends two Events at
/// [`FIRST_TICK`].
fn command_expecting(
    fork: TimelineId,
    head: u64,
    prior: u64,
    trust_epoch: u64,
) -> CounterfactualInvalidationCommandV1 {
    let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(
        frontier_frame(
            &[
                id_field([1; 16]),
                hash_field(hash(5)),
                hash_field(hash(2)),
                hash_field(hash(3)),
                vec![0x01],
            ]
            .concat(),
            0,
        ),
    ));
    let fork_id = fork.inner().to_bytes();
    let invalidation = ok(SuffixInvalidationBytesV1::try_from_canonical(
        invalidation_frame(
            &[
                id_field([1; 16]),
                hash_field(hash(5)),
                id_field(fork_id),
                uint(prior),
                uint(prior + 1),
                hash_field(frontier.digest()),
                invalidation_middle(),
                // Commit coordinate: the Fork, its expected head, the first Tick.
                vec![0x83],
                id_field(fork_id),
                uint(head),
                uint(FIRST_TICK),
            ]
            .concat(),
            0,
        ),
    ));
    ok(CounterfactualInvalidationCommandV1::try_new(
        CounterfactualInvalidationInputV1 {
            fork,
            fork_logical_head: Seq::from_u64(head),
            trust_epoch,
            revocation_epoch: 7,
            erasure_epoch: 8,
            frontier,
            invalidation,
            invalid_artifacts: vec![hash(10)],
            evictions: Vec::new(),
            first_tick: FIRST_TICK,
            first_tick_drafts: tick_drafts(2),
        },
    ))
}

fn command(fork: TimelineId, head: u64, prior: u64) -> CounterfactualInvalidationCommandV1 {
    command_expecting(fork, head, prior, 6)
}

struct Fixture {
    store: MemoryStore,
    gate: Arc<ErasureContainmentGateV1>,
    root: TimelineId,
    fork: TimelineId,
}

/// A root Timeline with two Events and a Fork of it at logical Seq 1.
fn fixture() -> Fixture {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut store = MemoryStore::new();
    ok(store.bind_erasure_gate(Arc::clone(&gate)));
    let root = ok(store.create_timeline("dependency-root")).id();
    ok(store.append(root, &[draft(100), draft(101)]));
    let fork = ok(store.fork(root, Seq::from_u64(1), "dependency-fork")).id();
    Fixture {
        store,
        gate,
        root,
        fork,
    }
}

/// A fixture whose Fork has the default facts published.
fn published() -> Fixture {
    let mut fixture = fixture();
    ok(fixture
        .store
        .publish_counterfactual_facts(fixture.fork, facts()));
    fixture
}

/// Logical sequence numbers visible on one Timeline.
fn seqs(store: &MemoryStore, timeline: TimelineId) -> Vec<u64> {
    ok(store.read(timeline, SeqRange::all()))
        .iter()
        .map(|event| event.seq.as_u64())
        .collect()
}

// The coordinate, node, edge, and record builders below mirror the contract's
// own tests, the in-module tests of this adapter, and the `SQLite` adapter's
// tests. Consolidating them into the shared `test_fixtures` touches the
// contract crate, so it is not done here (follow-up: Redmine #559).
fn coord_at(tick: u64, owner: &str, digest: Hash) -> Coordinate {
    ok(Coordinate::try_new(tick, 0, owner.to_owned(), 0, 7, digest))
}

fn coord(tick: u64, owner: &str, digest: u8) -> Coordinate {
    coord_at(tick, owner, hash(digest))
}

fn node_of(
    coordinate: &Coordinate,
    class: RecordedDependencyClassV1,
    origin: RecordedNodeOriginV1,
    inputs: Vec<Hash>,
) -> NodeRow {
    ok(NodeRow::try_new(
        coordinate.clone(),
        class,
        origin,
        inputs,
        hash(99),
    ))
}

fn endogenous(coordinate: &Coordinate, inputs: Vec<Hash>) -> NodeRow {
    let class = RecordedDependencyClassV1::EndogenousRecomputed;
    node_of(coordinate, class, PROVISIONAL, inputs)
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

/// The five `IDP1` fields after the source node.
fn edge_tail() -> Vec<u8> {
    [
        uint(2),
        vec![0x82],
        uint(3),
        uint(5),
        hash_field(hash(0x33)),
        vec![0x82],
        text_field("adr064.classification"),
        uint(1),
        hash_field(hash(0x44)),
    ]
    .concat()
}

fn edge(consumer: &Coordinate, source: &Coordinate) -> EdgeRow {
    let bytes = [
        EDGE_HEAD.to_vec(),
        node_bytes(consumer),
        node_bytes(source),
        edge_tail(),
    ]
    .concat();
    ok(EdgeRow::try_from_canonical(
        bytes,
        consumer.clone(),
        source.artifact_digest(),
    ))
}

fn record(tick: u64, nodes: Vec<NodeRow>, edges: Vec<EdgeRow>) -> TickRecord {
    ok(TickRecord::try_new(tick, PROVISIONAL, nodes, edges))
}

fn empty_at(tick: u64) -> TickRecord {
    record(tick, Vec::new(), Vec::new())
}

/// Tick 17: node `a` declares the prefix input 50 and node `b` declares `a`.
fn tick_17() -> TickRecord {
    let node_a = coord(17, "a", 1);
    let node_b = coord(17, "b", 2);
    let nodes = vec![
        endogenous(&node_a, vec![hash(50)]),
        endogenous(&node_b, vec![hash(1)]),
    ];
    let edges = vec![edge(&node_a, &coord(10, "w", 50)), edge(&node_b, &node_a)];
    record(FIRST_TICK, nodes, edges)
}

/// Tick 18: node `c` consumes node `b` of tick 17.
fn tick_18() -> TickRecord {
    let node_c = coord(18, "c", 3);
    let nodes = vec![endogenous(&node_c, vec![hash(2)])];
    record(18, nodes, vec![edge(&node_c, &coord(17, "b", 2))])
}

const fn at(fork: TimelineId, generation: u64) -> ForkGenerationV1 {
    ForkGenerationV1 { fork, generation }
}

const fn fork_scope(fork: TimelineId, generation: u64) -> Scope {
    Scope::ForkGeneration(at(fork, generation))
}

const fn prefix_scope(timeline: TimelineId, through_tick: u64) -> Scope {
    Scope::ParentPrefix {
        timeline,
        through_tick,
    }
}

fn request(
    scope: Scope,
    after: Option<DependencyPageCursorV1>,
    limit: usize,
) -> DependencyPageRequestV1 {
    ok(DependencyPageRequestV1::try_new(scope, after, limit))
}

/// Read every page of `scope` through `read`.
fn collect_rows<T: DependencyPagedRowV1 + Clone>(
    scope: Scope,
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
    store: &MemoryStore,
    scope: Scope,
    limit: usize,
) -> Result<Vec<NodeRow>, StoreError> {
    collect_rows(scope, limit, |page| store.read_dependency_nodes(page))
}

fn collect_edges(
    store: &MemoryStore,
    scope: Scope,
    limit: usize,
) -> Result<Vec<EdgeRow>, StoreError> {
    collect_rows(scope, limit, |page| store.read_dependency_edges(page))
}

fn sorted<T: DependencyPagedRowV1>(mut rows: Vec<T>) -> Vec<T> {
    rows.sort_by_key(T::cursor);
    rows
}

/// The nodes of `records`, in canonical order.
fn nodes_of(records: &[TickRecord]) -> Vec<NodeRow> {
    let rows = records.iter().flat_map(|row| row.nodes().to_vec());
    sorted(rows.collect())
}

/// The edges of `records`, in canonical order.
fn edges_of(records: &[TickRecord]) -> Vec<EdgeRow> {
    let rows = records.iter().flat_map(|row| row.edges().to_vec());
    sorted(rows.collect())
}

/// Assert that the Fork's generation holds exactly the rows of `records`.
fn assert_recorded(store: &MemoryStore, scope: Scope, records: &[TickRecord]) {
    assert_eq!(ok(collect_nodes(store, scope, 3)), nodes_of(records));
    assert_eq!(ok(collect_edges(store, scope, 3)), edges_of(records));
}

fn committed(
    store: &mut MemoryStore,
    command: &CounterfactualInvalidationCommandV1,
    record: &TickRecord,
) -> CounterfactualGenerationReceiptV1 {
    let outcome = store.commit_counterfactual_invalidation_with_dependencies(command, record);
    match ok(outcome) {
        CounterfactualInvalidationOutcomeV1::Committed(receipt) => *receipt,
        other @ CounterfactualInvalidationOutcomeV1::InvalidationConflict(_) => {
            std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}")))
        }
    }
}

/// Append one Event Tick with `record` on the Fork's current basis.
fn append(
    store: &mut MemoryStore,
    fork: TimelineId,
    record: &TickRecord,
) -> Result<CounterfactualTickOutcomeV1, StoreError> {
    let expected = ok(store.current_counterfactual_basis(fork));
    store.append_counterfactual_tick_with_dependencies(fork, &expected, &tick_drafts(1), record)
}

/// Commit an invalidation without dependencies.
fn invalidate(store: &mut MemoryStore, fork: TimelineId, head: u64, prior: u64) {
    let plain = command(fork, head, prior);
    ok(store.commit_counterfactual_invalidation(&plain));
}

/// A published Fork with the tick 17 record committed at generation 1, whose
/// logical head is 3.
fn recorded() -> Fixture {
    let mut fixture = published();
    let first = command(fixture.fork, 1, 0);
    committed(&mut fixture.store, &first, &tick_17());
    fixture
}

#[test]
fn c1_a_record_commits_with_the_tick_and_reads_return_it() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let receipt = committed(store, &command(fork, 1, 0), &tick_17());

    assert_eq!(receipt.generation(), at(fork, 1));
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    for limit in [1, 2, 5] {
        let nodes = ok(collect_nodes(store, fork_scope(fork, 1), limit));
        assert_eq!(nodes, nodes_of(&[tick_17()]));
        let edges = ok(collect_edges(store, fork_scope(fork, 1), limit));
        assert_eq!(edges, edges_of(&[tick_17()]));
    }

    let later = append(store, fork, &tick_18());
    let head = Seq::from_u64(4);
    assert_eq!(later, Ok(CounterfactualTickOutcomeV1::Committed { head }));
    assert_eq!(seqs(store, fork), vec![1, 2, 3, 4]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17(), tick_18()]);
}

#[test]
fn c1_repeated_reads_return_identical_bytes() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    ok(append(store, fork, &tick_18()));
    let bytes_of = |edges: Vec<EdgeRow>| -> Vec<Vec<u8>> {
        edges.iter().map(|row| row.as_bytes().to_vec()).collect()
    };

    let first = bytes_of(ok(collect_edges(store, fork_scope(fork, 1), 2)));
    let second = bytes_of(ok(collect_edges(store, fork_scope(fork, 1), 1)));

    assert_eq!(first.len(), 3);
    assert_eq!(first, second);
    let page = request(fork_scope(fork, 1), None, 2);
    assert_eq!(
        ok(store.read_dependency_nodes(&page)),
        ok(store.read_dependency_nodes(&page))
    );
}

#[test]
fn c2_a_conflicting_invalidation_records_nothing() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let stale = command_expecting(fork, 1, 0, 60);

    let outcome = store.commit_counterfactual_invalidation_with_dependencies(&stale, &tick_17());

    assert_eq!(
        outcome,
        Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
            InvalidationConflictV1::TrustEpoch
        ))
    );
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 0)));
    assert_eq!(seqs(store, fork), vec![1]);
    assert_recorded(store, fork_scope(fork, 0), &[]);
    // The record was not kept: a good commit records exactly its own.
    committed(store, &command(fork, 1, 0), &tick_17());
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
}

#[test]
fn c2_a_stale_tick_basis_records_nothing() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let mut expected = ok(store.current_counterfactual_basis(fork));
    expected.generation = 0;

    let stale = store.append_counterfactual_tick_with_dependencies(
        fork,
        &expected,
        &tick_drafts(1),
        &tick_18(),
    );

    assert_eq!(
        stale,
        Ok(CounterfactualTickOutcomeV1::Stale(
            InvalidationConflictV1::PriorGeneration
        ))
    );
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
    // Neither the rows nor the record Tick 18 were kept.
    assert!(append(store, fork, &tick_18()).is_ok());
    assert_recorded(store, fork_scope(fork, 1), &[tick_17(), tick_18()]);
}

#[test]
fn c2_a_misplaced_record_beats_a_conflicting_invalidation_basis() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let conflicting = command_expecting(fork, 1, 0, 60);
    let misplaced = empty_at(FIRST_TICK + 1);

    let outcome =
        store.commit_counterfactual_invalidation_with_dependencies(&conflicting, &misplaced);

    // The record is checked before the basis, so no conflict is reported.
    assert_eq!(outcome, Err(StoreError::BindingMismatch));
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 0)));
    assert_eq!(seqs(store, fork), vec![1]);
    assert_recorded(store, fork_scope(fork, 0), &[]);
}

#[test]
fn c2_a_stale_tick_basis_beats_a_misplaced_record() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let mut expected = ok(store.current_counterfactual_basis(fork));
    expected.generation = 0;
    // Not after the last record Tick 17, so the record alone is rejected.
    let misplaced = empty_at(FIRST_TICK);

    let outcome = store.append_counterfactual_tick_with_dependencies(
        fork,
        &expected,
        &tick_drafts(1),
        &misplaced,
    );

    // The basis is rechecked first, so the Stale outcome is reported.
    assert_eq!(
        outcome,
        Ok(CounterfactualTickOutcomeV1::Stale(
            InvalidationConflictV1::PriorGeneration
        ))
    );
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
    assert!(append(store, fork, &tick_18()).is_ok());
}

#[test]
fn c2_a_failed_tick_records_nothing() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let expected = ok(store.current_counterfactual_basis(fork));

    let guarded = store.append_counterfactual_tick_with_dependencies(
        fork,
        &expected,
        &guarded_drafts(),
        &tick_18(),
    );

    assert_eq!(guarded, Err(StoreError::ForkNotFound));
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
    assert_eq!(ok(store.current_counterfactual_basis(fork)), expected);
    assert!(append(store, fork, &tick_18()).is_ok());
}

#[test]
fn c2_a_rejected_record_commits_no_events() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let first = command(fork, 1, 0);
    let wrong_tick = empty_at(FIRST_TICK + 1);

    let outcome = store.commit_counterfactual_invalidation_with_dependencies(&first, &wrong_tick);

    assert_eq!(outcome, Err(StoreError::BindingMismatch));
    assert_eq!(store.current_fork_generation(fork), Ok(at(fork, 0)));
    assert_eq!(seqs(store, fork), vec![1]);
    assert_recorded(store, fork_scope(fork, 0), &[]);

    committed(store, &first, &tick_17());
    let rejected = append(store, fork, &empty_at(FIRST_TICK));
    assert_eq!(rejected, Err(StoreError::BindingMismatch));
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    let basis = ok(store.current_counterfactual_basis(fork));
    assert_eq!(basis.fork_logical_head, Seq::from_u64(3));
}

#[test]
fn c3_a_record_must_be_provisional() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let prefix_record = |tick| ok(TickRecord::try_new(tick, COMMITTED, Vec::new(), Vec::new()));

    let first = store.commit_counterfactual_invalidation_with_dependencies(
        &command(fork, 1, 0),
        &prefix_record(FIRST_TICK),
    );
    assert_eq!(first, Err(StoreError::BindingMismatch));
    assert_eq!(seqs(store, fork), vec![1]);

    committed(store, &command(fork, 1, 0), &tick_17());
    let later = append(store, fork, &prefix_record(18));
    assert_eq!(later, Err(StoreError::BindingMismatch));
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
}

#[test]
fn c4_position_key_and_digest_collisions_are_rejected_across_records() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    // The position key of node `a` at tick 17 with another digest.
    let same_position = node_of(&coord(17, "a", 77), ROOT_CLASS, PROVISIONAL, Vec::new());
    // The digest of node `a` at another position.
    let same_digest = endogenous(&coord(18, "z", 1), Vec::new());

    for row in [same_position, same_digest] {
        let outcome = append(store, fork, &record(18, vec![row], Vec::new()));
        assert_eq!(outcome, Err(StoreError::DuplicateIdentity));
        assert_eq!(seqs(store, fork), vec![1, 2, 3]);
        assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
    }
    // Nothing was kept, not even the record Tick.
    assert!(append(store, fork, &tick_18()).is_ok());
}

#[test]
fn c4_a_new_generation_may_reuse_identities_of_an_older_one() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    let receipt = committed(store, &command(fork, 3, 1), &tick_17());

    assert_eq!(receipt.generation(), at(fork, 2));
    assert_recorded(store, fork_scope(fork, 2), &[tick_17()]);
}

#[test]
fn c5_the_first_record_of_an_invalidation_is_at_its_first_tick() {
    for tick in [FIRST_TICK - 1, FIRST_TICK + 1] {
        let mut fixture = published();
        let fork = fixture.fork;
        let store = &mut fixture.store;
        let first = command(fork, 1, 0);

        let outcome =
            store.commit_counterfactual_invalidation_with_dependencies(&first, &empty_at(tick));

        assert_eq!(outcome, Err(StoreError::BindingMismatch));
        assert_eq!(seqs(store, fork), vec![1]);
    }
}

#[test]
fn c5_a_record_tick_must_be_strictly_after_the_last_and_gaps_are_allowed() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    for tick in [FIRST_TICK, FIRST_TICK - 1] {
        let outcome = append(store, fork, &empty_at(tick));
        assert_eq!(outcome, Err(StoreError::BindingMismatch));
    }
    assert!(append(store, fork, &empty_at(19)).is_ok());
    assert_eq!(
        append(store, fork, &empty_at(19)),
        Err(StoreError::BindingMismatch)
    );
    assert_eq!(
        append(store, fork, &empty_at(18)),
        Err(StoreError::BindingMismatch)
    );
    assert!(append(store, fork, &empty_at(20)).is_ok());
    assert_eq!(seqs(store, fork), vec![1, 2, 3, 4, 5]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
}

#[test]
fn c5_an_empty_set_requires_the_generation_first_tick() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    // A plain invalidation persists the first Tick and no dependency rows.
    invalidate(store, fork, 1, 0);

    assert_eq!(
        append(store, fork, &empty_at(FIRST_TICK - 1)),
        Err(StoreError::BindingMismatch)
    );
    assert_eq!(seqs(store, fork), vec![1, 2, 3]);
    assert!(append(store, fork, &tick_17()).is_ok());
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
}

#[test]
fn c5_the_record_tick_is_persisted_apart_from_node_ticks() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    invalidate(store, fork, 1, 0);
    let early_root = node_of(&coord(3, "r", 9), ROOT_CLASS, PROVISIONAL, Vec::new());
    let riding = record(20, vec![early_root], Vec::new());

    assert!(append(store, fork, &riding).is_ok());

    // The root's own Tick is 3, but the record Tick 20 is what is compared.
    assert_eq!(
        append(store, fork, &empty_at(19)),
        Err(StoreError::BindingMismatch)
    );
    assert_eq!(
        append(store, fork, &empty_at(20)),
        Err(StoreError::BindingMismatch)
    );
    assert!(append(store, fork, &empty_at(21)).is_ok());
    assert_recorded(store, fork_scope(fork, 1), &[riding]);
}

#[test]
fn c5_a_fork_that_was_never_invalidated_takes_no_record() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    let outcome = append(store, fork, &empty_at(FIRST_TICK));

    assert_eq!(outcome, Err(StoreError::BindingMismatch));
    assert_eq!(seqs(store, fork), vec![1]);
    assert_recorded(store, fork_scope(fork, 0), &[]);
}

#[test]
fn c6_roots_ride_later_records_and_rows_are_ordered_by_position_key() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let root = node_of(&coord(3, "r", 9), ROOT_CLASS, PROVISIONAL, Vec::new());
    let node_c = coord(18, "c", 3);
    let nodes = vec![root, endogenous(&node_c, vec![hash(2)])];
    let edges = vec![edge(&node_c, &coord(17, "b", 2))];
    let riding = record(18, nodes, edges);

    assert!(append(store, fork, &riding).is_ok());

    let read = ok(collect_nodes(store, fork_scope(fork, 1), 2));
    let ticks: Vec<u64> = read.iter().map(|row| row.coordinate().tick()).collect();
    // The root was recorded last but is served first, at its own Tick.
    assert_eq!(ticks, vec![3, 17, 17, 18]);
    assert_recorded(store, fork_scope(fork, 1), &[tick_17(), riding]);
}

#[test]
fn c6_roots_after_the_record_tick_and_other_nodes_off_it_are_not_records() {
    let late_root = node_of(&coord(18, "r", 9), ROOT_CLASS, PROVISIONAL, Vec::new());
    let early_node = endogenous(&coord(16, "e", 8), Vec::new());

    for row in [late_root, early_node] {
        let built = TickRecord::try_new(17, PROVISIONAL, vec![row], Vec::new());
        assert_eq!(err(built), DepError::BindingMismatch);
    }
    assert_eq!(
        StoreError::from(DepError::BindingMismatch),
        StoreError::BindingMismatch
    );
}

#[test]
fn c7_only_the_current_generation_is_readable() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    for stale in [0, 2] {
        let scope = fork_scope(fork, stale);
        assert_eq!(
            err(collect_nodes(store, scope, 2)),
            StoreError::MixedForkGeneration
        );
        assert_eq!(
            err(collect_edges(store, scope, 2)),
            StoreError::MixedForkGeneration
        );
    }
    // Generation 1 is quarantined once generation 2 commits.
    invalidate(store, fork, 3, 1);
    assert_eq!(
        err(collect_nodes(store, fork_scope(fork, 1), 2)),
        StoreError::MixedForkGeneration
    );
    assert_eq!(
        err(collect_edges(store, fork_scope(fork, 1), 2)),
        StoreError::MixedForkGeneration
    );
}

#[test]
fn c7_a_new_generation_starts_with_an_empty_set() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;

    invalidate(store, fork, 3, 1);

    assert_recorded(store, fork_scope(fork, 2), &[]);
    // Its first record is still bounded by the new first Tick.
    assert_eq!(
        append(store, fork, &empty_at(FIRST_TICK - 1)),
        Err(StoreError::BindingMismatch)
    );
    assert!(append(store, fork, &tick_17()).is_ok());
    assert_recorded(store, fork_scope(fork, 2), &[tick_17()]);
}

#[test]
fn c7_a_new_generation_records_its_own_first_tick_record() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let other = record(
        FIRST_TICK,
        vec![endogenous(&coord(17, "q", 40), Vec::new())],
        Vec::new(),
    );

    committed(store, &command(fork, 3, 1), &other);

    assert_recorded(store, fork_scope(fork, 2), &[other]);
    assert_eq!(
        err(collect_nodes(store, fork_scope(fork, 1), 2)),
        StoreError::MixedForkGeneration
    );
}

#[test]
fn c8_fork_scope_serves_only_provisional_rows() {
    let fixture = recorded();
    let (store, fork, root) = (&fixture.store, fixture.fork, fixture.root);

    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
    for timeline in [root, fork] {
        let scope = prefix_scope(timeline, u64::MAX);
        assert_eq!(ok(collect_nodes(store, scope, 5)), Vec::new());
        assert_eq!(ok(collect_edges(store, scope, 5)), Vec::new());
    }
}

#[test]
fn c9_unknown_and_unpublished_timelines_are_not_found() {
    let fixture = fixture();
    let (store, fork, root) = (&fixture.store, fixture.fork, fixture.root);
    let unknown = TimelineId::new();
    let scopes = [
        fork_scope(fork, 0),
        fork_scope(root, 0),
        fork_scope(unknown, 0),
        prefix_scope(unknown, 5),
    ];

    for scope in scopes {
        assert_eq!(
            err(collect_nodes(store, scope, 2)),
            StoreError::ForkNotFound
        );
        assert_eq!(
            err(collect_edges(store, scope, 2)),
            StoreError::ForkNotFound
        );
    }
}

#[test]
fn c9_existing_timelines_without_rows_read_as_empty_pages() {
    let fixture = published();
    let (store, fork, root) = (&fixture.store, fixture.fork, fixture.root);

    assert_recorded(store, fork_scope(fork, 0), &[]);
    for timeline in [root, fork] {
        assert_recorded(store, prefix_scope(timeline, 100), &[]);
    }
    let first = request(fork_scope(fork, 0), None, 1);
    let page = ok(store.read_dependency_nodes(&first));
    assert!(page.items().is_empty());
    assert!(page.next().is_none());
}

#[test]
fn c9_reads_run_under_their_erasure_read_fence() {
    let fixture = recorded();
    let (fork, root) = (fixture.fork, fixture.root);
    fixture.gate.block_timeline(fork);

    // The Fork's fence guards its own rows, and not the parent prefix of
    // another Timeline.
    assert_eq!(
        err(collect_nodes(&fixture.store, fork_scope(fork, 1), 2)),
        StoreError::StorageFailure
    );
    assert_eq!(
        err(collect_edges(&fixture.store, prefix_scope(fork, 5), 2)),
        StoreError::StorageFailure
    );
    assert_eq!(
        ok(collect_nodes(&fixture.store, prefix_scope(root, 5), 2)),
        Vec::new()
    );

    let blocked_root = recorded();
    blocked_root.gate.block_timeline(blocked_root.root);
    for timeline in [blocked_root.root, blocked_root.fork] {
        let scope = prefix_scope(timeline, 5);
        assert_eq!(
            err(collect_nodes(&blocked_root.store, scope, 2)),
            StoreError::StorageFailure
        );
    }
}

#[test]
fn c9_a_blocked_grandparent_fails_a_grandchild_prefix_read_closed() {
    let mut fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let name = "dependency-grandchild";
    let grandchild = ok(fixture.store.fork(fork, Seq::from_u64(1), name)).id();
    let scope = prefix_scope(grandchild, 5);
    assert_eq!(ok(collect_nodes(&fixture.store, scope, 2)), Vec::new());

    // Only the grandparent is blocked: the fence of the grandchild's own
    // read stays open, and its inherited scopes decide.
    fixture.gate.block_timeline(root);

    assert_eq!(
        err(collect_nodes(&fixture.store, scope, 2)),
        StoreError::StorageFailure
    );
    assert_eq!(
        err(collect_edges(&fixture.store, scope, 2)),
        StoreError::StorageFailure
    );
}

#[test]
fn c9_an_ungated_store_fails_closed() {
    let fixture = recorded();
    let (fork, root) = (fixture.fork, fixture.root);
    let ungated = fixture.store.without_erasure_gate();

    for scope in [fork_scope(fork, 1), prefix_scope(root, 5)] {
        assert_eq!(
            err(collect_nodes(&ungated, scope, 2)),
            StoreError::StorageFailure
        );
        assert_eq!(
            err(collect_edges(&ungated, scope, 2)),
            StoreError::StorageFailure
        );
    }
}

#[test]
fn c9_writes_run_under_the_erasure_write_fence() {
    // The basis is read before the fence closes: reading it afterwards would
    // fail closed on its own and never reach the write.
    let mut fixture = recorded();
    let fork = fixture.fork;
    let basis = ok(fixture.store.current_counterfactual_basis(fork));
    fixture.gate.block_timeline(fork);
    let first = command(fork, 3, 1);

    let commit = fixture
        .store
        .commit_counterfactual_invalidation_with_dependencies(&first, &tick_17());
    assert_eq!(commit, Err(StoreError::StorageFailure));
    let blocked = fixture.store.append_counterfactual_tick_with_dependencies(
        fork,
        &basis,
        &tick_drafts(1),
        &tick_18(),
    );
    assert_eq!(blocked.map(drop), Err(StoreError::StorageFailure));

    let fresh = recorded();
    let fork = fresh.fork;
    let basis = ok(fresh.store.current_counterfactual_basis(fork));
    let first = command(fork, 3, 1);
    let mut ungated = fresh.store.without_erasure_gate();
    assert_eq!(
        ungated.commit_counterfactual_invalidation_with_dependencies(&first, &tick_17()),
        Err(StoreError::StorageFailure)
    );
    let ungated_append = ungated.append_counterfactual_tick_with_dependencies(
        fork,
        &basis,
        &tick_drafts(1),
        &tick_18(),
    );
    assert_eq!(ungated_append.map(drop), Err(StoreError::StorageFailure));
}

#[test]
fn c9_writes_require_a_visible_published_fork() {
    let mut fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let store = &mut fixture.store;
    let basis = CounterfactualBasisV1 {
        fork_logical_head: Seq::from_u64(1),
        generation: 0,
        facts: facts(),
    };

    for target in [fork, root, TimelineId::new()] {
        let first = command(target, 1, 0);
        let commit = store.commit_counterfactual_invalidation_with_dependencies(&first, &tick_17());
        assert_eq!(commit, Err(StoreError::ForkNotFound));
        let drafts = tick_drafts(1);
        let later =
            store.append_counterfactual_tick_with_dependencies(target, &basis, &drafts, &tick_18());
        assert_eq!(later, Err(StoreError::ForkNotFound));
    }
    // The commit resolves the Fork before it checks the record, and the
    // append resolves it through the basis read: a misplaced record (its Tick
    // before the first Tick) is still a missing Fork on both paths.
    let misplaced = empty_at(1);
    let first = command(fork, 1, 0);
    let commit = store.commit_counterfactual_invalidation_with_dependencies(&first, &misplaced);
    assert_eq!(commit, Err(StoreError::ForkNotFound));
    let drafts = tick_drafts(1);
    let later =
        store.append_counterfactual_tick_with_dependencies(fork, &basis, &drafts, &misplaced);
    assert_eq!(later, Err(StoreError::ForkNotFound));
    assert_eq!(seqs(store, fork), vec![1]);
}

#[test]
fn c9_deleted_timelines_are_not_found() {
    let mut fixture = recorded();
    let (fork, root) = (fixture.fork, fixture.root);
    let store = &mut fixture.store;
    ok(store.delete_timeline(fork));

    for scope in [fork_scope(fork, 1), prefix_scope(fork, 5)] {
        assert_eq!(
            err(collect_nodes(store, scope, 2)),
            StoreError::ForkNotFound
        );
    }
    ok(store.delete_timeline(root));
    assert_eq!(
        err(collect_edges(store, prefix_scope(root, 5), 2)),
        StoreError::ForkNotFound
    );
}

/// The coordinate of node `index` of [`numbered`].
fn numbered_coord(index: usize) -> Coordinate {
    let owner = format!("n{index:05}");
    coord_at(FIRST_TICK, &owner, indexed_hash(index + 100))
}

/// `count` provisional nodes at tick 17, each consuming the prefix node `w`.
fn numbered(count: usize) -> TickRecord {
    let source = coord(10, "w", 50);
    let consumers: Vec<Coordinate> = (0..count).map(numbered_coord).collect();
    let nodes = consumers
        .iter()
        .map(|consumer| endogenous(consumer, vec![hash(50)]))
        .collect();
    let edges = consumers
        .iter()
        .map(|consumer| edge(consumer, &source))
        .collect();
    record(FIRST_TICK, nodes, edges)
}

const WIDE: usize = MAX_DEPENDENCY_PAGE_ROWS_V1 + 76;

fn wide() -> Fixture {
    let mut fixture = published();
    let first = command(fixture.fork, 1, 0);
    committed(&mut fixture.store, &first, &numbered(WIDE));
    fixture
}

#[test]
fn c10_pages_are_capped_and_continue_after_the_last_row() {
    let fixture = wide();
    let (store, fork) = (&fixture.store, fixture.fork);
    let scope = fork_scope(fork, 1);
    let expected = nodes_of(&[numbered(WIDE)]);
    let cap = MAX_DEPENDENCY_PAGE_ROWS_V1;

    let first = ok(store.read_dependency_nodes(&request(scope, None, cap)));
    assert_eq!(first.items().len(), cap);
    assert_eq!(first.items(), &expected[..cap]);
    let next = first.next().cloned();
    assert_eq!(next, first.items().last().map(DependencyPagedRowV1::cursor));
    let second = ok(store.read_dependency_nodes(&request(scope, next, cap)));
    assert_eq!(second.items(), &expected[cap..]);
    assert!(second.next().is_none());

    for limit in [0, cap + 1] {
        let invalid = DependencyPageRequestV1::try_new(scope, None, limit);
        assert_eq!(err(invalid), DepError::InvalidPageLimit);
    }
    assert_eq!(ok(collect_nodes(store, scope, 100)), expected);
    let edges = ok(collect_edges(store, scope, 100));
    assert_eq!(edges, edges_of(&[numbered(WIDE)]));
}

#[test]
fn c10_a_cursor_between_rows_resumes_at_the_next_row() {
    let fixture = wide();
    let (store, fork) = (&fixture.store, fixture.fork);
    let expected = nodes_of(&[numbered(WIDE)]);
    // After `n00499` and before `n00500`.
    let between = ok(DependencyPageCursorV1::try_new(
        FIRST_TICK,
        0,
        "n00499x".to_owned(),
        0,
        None,
    ));

    let page = request(fork_scope(fork, 1), Some(between), 3);
    let read = ok(store.read_dependency_nodes(&page));

    assert_eq!(read.items(), &expected[500..503]);
    assert_eq!(read.next(), Some(&expected[502].cursor()));
}

#[test]
fn c10_keyset_paging_is_stable_while_later_records_arrive() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let scope = fork_scope(fork, 1);
    let first = ok(store.read_dependency_nodes(&request(scope, None, 1)));
    assert_eq!(first.items(), &nodes_of(&[tick_17()])[..1]);

    ok(append(store, fork, &tick_18()));

    let resumed = request(scope, first.next().cloned(), 5);
    let rest = ok(store.read_dependency_nodes(&resumed));
    assert_eq!(rest.items(), &nodes_of(&[tick_17(), tick_18()])[1..]);
    let again = ok(store.read_dependency_nodes(&request(scope, None, 1)));
    assert_eq!(again, first);
}

#[test]
fn c10_cursors_of_the_other_row_kind_are_rejected() {
    let fixture = recorded();
    let (store, fork) = (&fixture.store, fixture.fork);
    let scope = fork_scope(fork, 1);
    let edge_cursor = tick_17().edges()[0].cursor();
    let node_cursor = tick_17().nodes()[0].cursor();

    let nodes = store.read_dependency_nodes(&request(scope, Some(edge_cursor), 2));
    assert_eq!(err(nodes), StoreError::BindingMismatch);
    let edges = store.read_dependency_edges(&request(scope, Some(node_cursor), 2));
    assert_eq!(err(edges), StoreError::BindingMismatch);
    let beyond = prefix_scope(fixture.root, 4);
    let owner = "a".to_owned();
    let cursor = ok(DependencyPageCursorV1::try_new(5, 0, owner, 0, None));
    assert_eq!(
        err(DependencyPageRequestV1::try_new(beyond, Some(cursor), 2)),
        DepError::InvalidCursor
    );
}

#[test]
fn c11_contract_errors_surface_through_the_storage_error_mapping() {
    let mut fixture = recorded();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    let duplicate = endogenous(&coord(18, "z", 1), Vec::new());

    let binding = append(store, fork, &empty_at(FIRST_TICK));
    let repeated = append(store, fork, &record(18, vec![duplicate], Vec::new()));
    let kind = store.read_dependency_nodes(&request(
        fork_scope(fork, 1),
        Some(tick_17().edges()[0].cursor()),
        2,
    ));

    assert_eq!(err(binding), StoreError::from(DepError::BindingMismatch));
    assert_eq!(err(repeated), StoreError::from(DepError::DuplicateIdentity));
    assert_eq!(err(kind), StoreError::from(DepError::InvalidCursor));
}

#[test]
fn c12_deleting_a_fork_purges_its_rows_and_a_recreated_fork_starts_empty() {
    let mut fixture = recorded();
    let (fork, root) = (fixture.fork, fixture.root);
    let store = &mut fixture.store;
    ok(store.delete_timeline(fork));

    assert_eq!(
        err(collect_nodes(store, fork_scope(fork, 1), 2)),
        StoreError::ForkNotFound
    );
    let mut meta = TimelineMeta::forked_from(root, Seq::from_u64(1), "recreated");
    meta.id = fork;
    ok(store.create_timeline_with_meta(meta));
    // Unpublished again, so the re-created Fork reads as not found.
    assert_eq!(
        err(collect_nodes(store, fork_scope(fork, 1), 2)),
        StoreError::ForkNotFound
    );
    // Publication resumes at the generation floor and holds none of the rows.
    ok(store.publish_counterfactual_facts(fork, facts()));
    assert_recorded(store, fork_scope(fork, 1), &[]);
    let events = seqs(store, fork);
    assert_eq!(
        append(store, fork, &empty_at(FIRST_TICK)),
        Err(StoreError::BindingMismatch)
    );
    assert_eq!(seqs(store, fork), events);
    let again = committed(store, &command(fork, 1, 1), &tick_17());
    assert_eq!(again.generation(), at(fork, 2));
    assert_recorded(store, fork_scope(fork, 2), &[tick_17()]);
}

#[test]
fn c12_deleting_a_parent_timeline_makes_its_prefix_unreadable() {
    let mut fixture = published();
    let (fork, root) = (fixture.fork, fixture.root);
    let store = &mut fixture.store;
    assert_recorded(store, prefix_scope(root, 9), &[]);

    assert!(store.delete_timeline(root).is_err());
    assert_recorded(store, prefix_scope(root, 9), &[]);
    ok(store.delete_timeline(fork));
    ok(store.delete_timeline(root));

    assert_eq!(
        err(collect_nodes(store, prefix_scope(root, 9), 2)),
        StoreError::ForkNotFound
    );
}

#[test]
fn c13_plain_methods_keep_working_and_record_nothing() {
    let mut fixture = published();
    let fork = fixture.fork;
    let store = &mut fixture.store;
    invalidate(store, fork, 1, 0);
    let expected = ok(store.current_counterfactual_basis(fork));

    let plain = store.append_counterfactual_tick(fork, &expected, &tick_drafts(1));

    let head = Seq::from_u64(4);
    assert_eq!(plain, Ok(CounterfactualTickOutcomeV1::Committed { head }));
    assert_eq!(seqs(store, fork), vec![1, 2, 3, 4]);
    assert_recorded(store, fork_scope(fork, 1), &[]);
    // A record may still start the set at the first Tick.
    assert!(append(store, fork, &tick_17()).is_ok());
    let expected = ok(store.current_counterfactual_basis(fork));
    let plain = store.append_counterfactual_tick(fork, &expected, &tick_drafts(1));
    assert!(plain.is_ok());
    assert_recorded(store, fork_scope(fork, 1), &[tick_17()]);
    // The plain Tick did not move the persisted record Tick.
    assert!(append(store, fork, &tick_18()).is_ok());
}
