//! Public-interface tests for the `SQLite` dependency record adapter (ADR-064,
//! Redmine #551).
//!
//! Every test is named after the id of the shared conformance checklist item
//! (`c1` to `c14`) it proves, so the Memory adapter's tests correspond to
//! these. The in-doubt (`OutcomeUnknown`) cases of C2 need the connection's
//! commit hook and live in the adapter's unit tests.
#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pos_core::counterfactual_store::test_fixtures::{
    frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, text_field, uint,
};
use pos_core::{
    CanonicalBytes, CounterfactualAdapterSealV1, CounterfactualDependencyErrorV1,
    CounterfactualDependencyReadPortV1, CounterfactualDependencyRecordingPortV1,
    CounterfactualFactsV1, CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, CounterfactualTickOutcomeV1,
    DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    DependencyPageCursorV1, DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1,
    DependencyReadScopeV1, EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
    ErasureProtectedEffectDispositionV1, EventDraft, EventStore, ForkGenerationV1, Hash,
    InvalidationConflictV1, Kind, PipelineDraftBatchV1, RecomputationFrontierBytesV1,
    RecordedDependencyClassV1, RecordedNodeOriginV1, Seq, SuffixInvalidationBytesV1,
    TickDependencyRecordV1, TimelineId, TimelineMeta, MAX_DEPENDENCY_PAGE_ROWS_V1,
    MAX_RECORDED_DEPENDENCY_EDGES_V1, MAX_RECORDED_DEPENDENCY_NODES_V1,
};
use pos_store::sqlite::SqliteStore;
use tempfile::{tempdir, TempDir};
use ulid::Ulid;

type StoreError = CounterfactualStoreErrorV1;
type DepError = CounterfactualDependencyErrorV1;
type Outcome = CounterfactualInvalidationOutcomeV1;
type TickOutcome = CounterfactualTickOutcomeV1;
type Coordinate = DependencyNodeCoordinateV1;
type NodeRow = DependencyNodeRecordV1;
type EdgeRow = DependencyEdgeRecordV1;
type TickRecord = TickDependencyRecordV1;
type NodePage = DependencyPageV1<NodeRow>;

/// Counts of the recorded rows: Tick records, nodes, then edges.
type RecordedCounts = [i64; 3];

/// The adapter seal, minted here only to build expected receipts.
const SEAL: CounterfactualAdapterSealV1 = CounterfactualAdapterSealV1::for_adapter();
/// The largest integer `SQLite` stores.
const SQL_MAX: u64 = 9_223_372_036_854_775_807;
const PROVISIONAL: RecordedNodeOriginV1 = RecordedNodeOriginV1::Provisional;
const COMMITTED: RecordedNodeOriginV1 = RecordedNodeOriginV1::Committed;
const ENDOGENOUS: RecordedDependencyClassV1 = RecordedDependencyClassV1::EndogenousRecomputed;
const ROOT: RecordedDependencyClassV1 = RecordedDependencyClassV1::InterventionAssigned;
const EDGE_HEAD: [u8; 7] = [0x89, 0x64, b'I', b'D', b'P', b'1', 0x01];
/// The Tick of the invalidation every fixture commits.
const FIRST_TICK: u64 = 17;
/// Every column of a node row, in table order.
const NODE_COLUMNS: &str = "timeline_id, generation, tick, scheduler_position, owner_id,
    output_ordinal, schema_id, artifact_digest, class, origin, input_digests, provenance_digest";
/// Faults that fail one insert of a record.
const RECORD_FAULTS: [&str; 3] = [
    "BEFORE INSERT ON counterfactual_dependency_records",
    "BEFORE INSERT ON counterfactual_dependency_nodes",
    "BEFORE INSERT ON counterfactual_dependency_edges",
];

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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn hash_hex(value: u8) -> String {
    hex(hash(value).as_bytes())
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

fn draft(value: u8, kind: &str) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(kind),
        CanonicalBytes::from_vec(vec![value]),
    )
}

/// Ordinary drafts `values`, optionally ending with a `guarded` one.
fn tick_drafts(values: &[u8], guarded: Option<&str>) -> PipelineDraftBatchV1 {
    ok(PipelineDraftBatchV1::try_new(
        values
            .iter()
            .map(|value| draft(*value, "counterfactual.tick"))
            .chain(guarded.map(|kind| draft(0, kind)))
            .collect(),
    ))
}

/// One invalidation request; every field defaults to the fixture's basis.
struct Spec {
    fork: TimelineId,
    facts: CounterfactualFactsV1,
    head: u64,
    prior: u64,
    frontier_id: u8,
    first_tick: u64,
    guarded: Option<&'static str>,
}

impl Spec {
    const fn new(fork: TimelineId) -> Self {
        Self {
            fork,
            facts: facts(),
            head: 2,
            prior: 0,
            frontier_id: 1,
            first_tick: FIRST_TICK,
            guarded: None,
        }
    }

    fn frontier(&self) -> RecomputationFrontierBytesV1 {
        let fields = [
            id_field([self.frontier_id; 16]),
            hash_field(self.facts.plan_digest),
            hash_field(hash(2)),
            hash_field(self.facts.dependency_graph_digest),
            vec![0x01],
        ]
        .concat();
        ok(RecomputationFrontierBytesV1::try_from_canonical(
            frontier_frame(&fields, 0),
        ))
    }

    fn invalidation(&self, frontier: &RecomputationFrontierBytesV1) -> SuffixInvalidationBytesV1 {
        let fields = [
            id_field([self.frontier_id; 16]),
            hash_field(frontier.plan_digest()),
            id_field(self.fork.inner().to_bytes()),
            uint(self.prior),
            uint(self.prior + 1),
            hash_field(frontier.digest()),
            invalidation_middle(),
            // Commit coordinate: the Fork, its expected head, the first Tick.
            vec![0x83],
            id_field(self.fork.inner().to_bytes()),
            uint(self.head),
            uint(self.first_tick),
        ]
        .concat();
        ok(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(&fields, 0),
        ))
    }

    fn command(&self) -> CounterfactualInvalidationCommandV1 {
        let frontier = self.frontier();
        let invalidation = self.invalidation(&frontier);
        ok(CounterfactualInvalidationCommandV1::try_new(
            CounterfactualInvalidationInputV1 {
                fork: self.fork,
                fork_logical_head: Seq::from_u64(self.head),
                trust_epoch: self.facts.trust_epoch,
                revocation_epoch: self.facts.revocation_epoch,
                erasure_epoch: self.facts.erasure_epoch,
                frontier,
                invalidation,
                invalid_artifacts: vec![hash(10), hash(11)],
                evictions: vec![hash(12)],
                first_tick: self.first_tick,
                first_tick_drafts: tick_drafts(&[7, 8], self.guarded),
            },
        ))
    }
}

/// A file-backed store with a factual root (two Events) and a Fork at Seq 2
/// whose counterfactual facts are published.
struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    root: TimelineId,
    fork: TimelineId,
}

fn fixture_path_str(fixture: &Fixture) -> &str {
    fixture.path.to_str().unwrap_or_default()
}

fn open(path: &Path) -> SqliteStore {
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    store
}

fn open_with_gate(path: &Path, gate: &Arc<ErasureContainmentGateV1>) -> SqliteStore {
    let mut store = ok(SqliteStore::open(path.to_str().unwrap_or_default()));
    ok(store.bind_erasure_gate(Arc::clone(gate)));
    store
}

fn fixture() -> Fixture {
    let directory = ok(tempdir());
    let path = directory.path().join("dependency.db");
    let mut store = open(&path);
    let root = ok(store.create_timeline("factual")).id();
    ok(store.append(root, &[draft(1, "factual"), draft(2, "factual")]));
    let fork = ok(store.fork(root, Seq::from_u64(2), "counterfactual")).id();
    ok(store.publish_counterfactual_facts(fork, facts()));
    Fixture {
        _directory: directory,
        path,
        root,
        fork,
    }
}

fn execute(path: &Path, sql: &str) -> rusqlite::Result<()> {
    rusqlite::Connection::open(path).and_then(|connection| connection.execute_batch(sql))
}

fn scalar(path: &Path, sql: &str, timeline: TimelineId) -> i64 {
    ok(rusqlite::Connection::open(path).and_then(|connection| {
        connection.query_row(sql, rusqlite::params![timeline.to_string()], |row| {
            row.get(0)
        })
    }))
}

fn text_scalar(path: &Path, sql: &str) -> String {
    ok(rusqlite::Connection::open(path)
        .and_then(|connection| connection.query_row(sql, [], |row| row.get::<_, String>(0))))
}

/// Rows written by commits on `fork`: own Events, generations, quarantine,
/// and readable artifacts.
fn written_rows(path: &Path, fork: TimelineId) -> [i64; 4] {
    [
        "SELECT count(*) FROM events WHERE timeline_id = ?1",
        "SELECT count(*) FROM counterfactual_generations WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_quarantine WHERE fork_id = ?1",
        "SELECT count(*) FROM counterfactual_artifacts WHERE fork_id = ?1",
    ]
    .map(|sql| scalar(path, sql, fork))
}

/// Dependency rows of one Timeline: Tick records, nodes, then edges.
fn recorded_rows(path: &Path, timeline: TimelineId) -> RecordedCounts {
    [
        "SELECT count(*) FROM counterfactual_dependency_records WHERE timeline_id = ?1",
        "SELECT count(*) FROM counterfactual_dependency_nodes WHERE timeline_id = ?1",
        "SELECT count(*) FROM counterfactual_dependency_edges WHERE timeline_id = ?1",
    ]
    .map(|sql| scalar(path, sql, timeline))
}

/// Everything a commit on `fork` writes: [`written_rows`] then
/// [`recorded_rows`].
fn snapshot(path: &Path, fork: TimelineId) -> Vec<i64> {
    let mut rows = written_rows(path, fork).to_vec();
    rows.extend(recorded_rows(path, fork));
    rows
}

const fn at(fork: TimelineId, generation: u64) -> ForkGenerationV1 {
    ForkGenerationV1 { fork, generation }
}

fn generation(store: &SqliteStore, fork: TimelineId) -> u64 {
    ok(store.current_fork_generation(fork)).generation
}

/// Whether both a writable and a read-only open fail naming `object`.
fn refuses(path: &str, object: &str) -> bool {
    open_error(SqliteStore::open(path)).contains(object)
        && open_error(SqliteStore::open_read_only(path)).contains(object)
}

fn opens_cleanly(fixture: &Fixture) -> String {
    open_error(SqliteStore::open(fixture_path_str(fixture)))
}

fn open_error(result: Result<SqliteStore, pos_core::CoreError>) -> String {
    result
        .err()
        .map_or_else(String::new, |error| format!("{error}"))
}

// Coordinates, nodes, edges, and records. Node `a` has digest 1 and `b` has
// digest 2; the digest byte of the other nodes is named at each use.

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

fn row(
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

fn provisional(coordinate: Coordinate, inputs: Vec<Hash>) -> NodeRow {
    row(coordinate, ENDOGENOUS, PROVISIONAL, inputs)
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

fn edge_bytes(consumer: &Coordinate, source: &Coordinate) -> Vec<u8> {
    [
        EDGE_HEAD.to_vec(),
        node_bytes(consumer),
        node_bytes(source),
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
    ok(EdgeRow::try_from_canonical(
        edge_bytes(consumer, source),
        consumer.clone(),
        source.artifact_digest(),
    ))
}

fn record_of(tick: u64, nodes: Vec<NodeRow>, edges: Vec<EdgeRow>) -> TickRecord {
    ok(TickRecord::try_new(tick, PROVISIONAL, nodes, edges))
}

/// An empty provisional record at `tick`.
fn empty_record(tick: u64) -> TickRecord {
    record_of(tick, Vec::new(), Vec::new())
}

/// Tick 17: node `b` consumes node `a`.
fn sample_record() -> TickRecord {
    let consumer = coord(FIRST_TICK, "b", 2);
    let nodes = vec![
        provisional(coord(FIRST_TICK, "a", 1), Vec::new()),
        provisional(consumer.clone(), vec![hash(1)]),
    ];
    let edges = vec![edge(&consumer, &coord(FIRST_TICK, "a", 1))];
    record_of(FIRST_TICK, nodes, edges)
}

/// Tick 18: node `a` consumes the node `a` of tick 17.
fn tick_18_record() -> TickRecord {
    let consumer = coord(18, "a", 21);
    let nodes = vec![provisional(consumer.clone(), vec![hash(1)])];
    let edges = vec![edge(&consumer, &coord(FIRST_TICK, "a", 1))];
    record_of(18, nodes, edges)
}

/// Tick 19: one node, one declared input, and one edge.
fn tick_19_record() -> TickRecord {
    let consumer = coord(19, "c", 31);
    let nodes = vec![provisional(consumer.clone(), vec![hash(1)])];
    let edges = vec![edge(&consumer, &coord(FIRST_TICK, "a", 1))];
    record_of(19, nodes, edges)
}

// Scopes, requests, and paged reads.

const fn fork_scope(fork: TimelineId, generation: u64) -> DependencyReadScopeV1 {
    DependencyReadScopeV1::ForkGeneration(at(fork, generation))
}

const fn prefix_scope(timeline: TimelineId, through_tick: u64) -> DependencyReadScopeV1 {
    DependencyReadScopeV1::ParentPrefix {
        timeline,
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

/// Read every page of `scope` through `read`.
fn collect_rows<T: DependencyPagedRowV1 + Clone>(
    scope: DependencyReadScopeV1,
    limit: usize,
    read: impl Fn(&DependencyPageRequestV1) -> Result<DependencyPageV1<T>, StoreError>,
) -> Result<Vec<T>, StoreError> {
    let mut collected = Vec::new();
    let mut after = None;
    loop {
        let page = read(&request(scope, after, limit))?;
        collected.extend_from_slice(page.items());
        after = page.next().cloned();
        if after.is_none() {
            return Ok(collected);
        }
    }
}

fn nodes(
    store: &SqliteStore,
    scope: DependencyReadScopeV1,
    limit: usize,
) -> Result<Vec<NodeRow>, StoreError> {
    collect_rows(scope, limit, |page| store.read_dependency_nodes(page))
}

fn edges(
    store: &SqliteStore,
    scope: DependencyReadScopeV1,
    limit: usize,
) -> Result<Vec<EdgeRow>, StoreError> {
    collect_rows(scope, limit, |page| store.read_dependency_edges(page))
}

/// The owner IDs of `listed` nodes, in the order they were served.
fn owners(listed: &[NodeRow]) -> Vec<String> {
    listed
        .iter()
        .map(|entry| entry.coordinate().owner_id().to_owned())
        .collect()
}

// Writes.

fn commit_with(
    store: &mut SqliteStore,
    command: &CounterfactualInvalidationCommandV1,
    record: &TickRecord,
) -> Result<Outcome, StoreError> {
    store.commit_counterfactual_invalidation_with_dependencies(command, record)
}

fn commit_spec(
    store: &mut SqliteStore,
    spec: &Spec,
    record: &TickRecord,
) -> Result<Outcome, StoreError> {
    commit_with(store, &spec.command(), record)
}

/// Commit the default invalidation with `record` and return its receipt.
fn commit_recorded(
    store: &mut SqliteStore,
    fork: TimelineId,
    record: &TickRecord,
) -> CounterfactualGenerationReceiptV1 {
    match ok(commit_spec(store, &Spec::new(fork), record)) {
        Outcome::Committed(receipt) => *receipt,
        other @ Outcome::InvalidationConflict(_) => {
            std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}")))
        }
    }
}

/// Append one later Tick with `record` on the persisted basis.
fn append_record(
    store: &mut SqliteStore,
    fork: TimelineId,
    record: &TickRecord,
) -> Result<TickOutcome, StoreError> {
    let expected = ok(store.current_counterfactual_basis(fork));
    store.append_counterfactual_tick_with_dependencies(
        fork,
        &expected,
        &tick_drafts(&[20], None),
        record,
    )
}

/// A fixture whose Fork committed the default invalidation with the sample
/// record.
fn recorded_fixture() -> Fixture {
    let fixture = fixture();
    let mut store = open(&fixture.path);
    commit_recorded(&mut store, fixture.fork, &sample_record());
    drop(store);
    fixture
}

/// The snapshot of a fixture that committed the sample record: two Events,
/// one generation with three quarantine rows and two artifacts, one record
/// with two nodes and one edge.
const RECORDED: [i64; 7] = [2, 1, 3, 2, 1, 2, 1];

/// Make the Fork's own head fall back to `reset` once it reaches `reached`,
/// so the staged Logical Head does not advance.
fn stall_head(path: &Path, fork: TimelineId, reached: u64, reset: u64) {
    ok(execute(
        path,
        &format!(
            "CREATE TRIGGER stalled_head AFTER UPDATE OF head_seq ON timelines
             WHEN NEW.id = '{fork}' AND NEW.head_seq = {reached}
             BEGIN UPDATE timelines SET head_seq = {reset} WHERE id = NEW.id; END;"
        ),
    ));
}

/// Insert one committed-prefix node of `timeline` through raw SQL: the prefix
/// has no write path yet (#554).
fn insert_prefix_node(path: &Path, timeline: TimelineId, node: &Coordinate) {
    ok(execute(
        path,
        &format!(
            "INSERT INTO counterfactual_dependency_nodes ({NODE_COLUMNS})
             VALUES ('{timeline}', -1, {tick}, 0, '{owner}', 0, 7, X'{digest}', 2, 0, X'',
                     X'{provenance}');",
            tick = node.tick(),
            owner = node.owner_id(),
            digest = hex(node.artifact_digest().as_bytes()),
            provenance = hash_hex(99),
        ),
    ));
}

/// Insert one committed-prefix edge of `timeline` through raw SQL.
fn insert_prefix_edge(
    path: &Path,
    timeline: TimelineId,
    consumer: &Coordinate,
    source: &Coordinate,
) {
    ok(execute(
        path,
        &format!(
            "INSERT INTO counterfactual_dependency_edges
             (timeline_id, generation, tick, scheduler_position, owner_id, output_ordinal,
              source_digest, consumer_schema_id, consumer_digest, edge_bytes)
             VALUES ('{timeline}', -1, {tick}, 0, '{owner}', 0, X'{source_digest}', 7,
                     X'{consumer_digest}', X'{bytes}');",
            tick = consumer.tick(),
            owner = consumer.owner_id(),
            source_digest = hex(source.artifact_digest().as_bytes()),
            consumer_digest = hex(consumer.artifact_digest().as_bytes()),
            bytes = hex(&edge_bytes(consumer, source)),
        ),
    ));
}

/// Event types the generic append guard conceals as an absent Fork.
const GUARDED_KINDS: [&str; 3] = ["geo.location", "geo.cell", "consent.granted.v1"];

/// An empty record of committed origin at `tick`.
fn committed_record(tick: u64) -> TickRecord {
    ok(TickRecord::try_new(tick, COMMITTED, Vec::new(), Vec::new()))
}

#[test]
fn c1_a_record_commits_with_the_events_and_reads_return_it() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let command = Spec::new(fork).command();
    assert_eq!(
        store.commit_counterfactual_invalidation_with_dependencies(&command, &sample_record()),
        Ok(Outcome::Committed(Box::new(ok(
            command.committed_receipt(&SEAL, Seq::from_u64(4))
        ))))
    );
    // The Tick's Events, the generation, and the record are all committed.
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
    assert_eq!(ok(store.logical_head(fork)), Seq::from_u64(4));
    let sample = sample_record();
    let (sample_nodes, sample_edges) = (sample.nodes().to_vec(), sample.edges().to_vec());
    for limit in [1, 2, 5] {
        let current = fork_scope(fork, 1);
        assert_eq!(ok(nodes(&store, current, limit)), sample_nodes);
        assert_eq!(ok(edges(&store, current, limit)), sample_edges);
    }

    // A later Tick adds its rows behind the first record's.
    assert_eq!(
        append_record(&mut store, fork, &tick_18_record()),
        Ok(TickOutcome::Committed {
            head: Seq::from_u64(5)
        })
    );
    assert_eq!(snapshot(&fixture.path, fork), [3, 1, 3, 2, 2, 3, 2]);
    let later = tick_18_record();
    let both_nodes = [sample_nodes, later.nodes().to_vec()].concat();
    let both_edges = [sample_edges, later.edges().to_vec()].concat();
    assert_eq!(ok(nodes(&store, fork_scope(fork, 1), 2)), both_nodes);
    assert_eq!(ok(edges(&store, fork_scope(fork, 1), 2)), both_edges);
    // Repeated reads and a reopened file serve identical rows and bytes.
    assert_eq!(ok(nodes(&store, fork_scope(fork, 1), 2)), both_nodes);
    drop(store);
    let reopened = open(&fixture.path);
    assert_eq!(ok(nodes(&reopened, fork_scope(fork, 1), 3)), both_nodes);
    let served = ok(edges(&reopened, fork_scope(fork, 1), 1));
    assert_eq!(served, both_edges);
    for (entry, sent) in served.iter().zip(&both_edges) {
        assert_eq!(entry.as_bytes(), sent.as_bytes());
        assert_eq!(entry.digest(), sent.digest());
    }
}

#[test]
fn c2_injected_faults_record_nothing_and_the_commit_recovers() {
    let fixture = fixture();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    for fault in RECORD_FAULTS {
        ok(execute(
            &fixture.path,
            &format!(
                "CREATE TRIGGER injected_fault {fault}
                 BEGIN SELECT RAISE(ABORT, 'injected dependency fault'); END;"
            ),
        ));
        let mut faulted = open(&fixture.path);
        assert_eq!(
            commit_with(&mut faulted, &command, &sample_record()),
            Err(StoreError::StorageFailure),
            "{fault}"
        );
        assert_eq!(generation(&faulted, fork), 0, "{fault}");
        assert_eq!(ok(faulted.logical_head(fork)), Seq::from_u64(2), "{fault}");
        assert_eq!(snapshot(&fixture.path, fork), [0; 7], "{fault}");
        drop(faulted);
        ok(execute(&fixture.path, "DROP TRIGGER injected_fault;"));
    }
    let mut recovered = open(&fixture.path);
    commit_recorded(&mut recovered, fork, &sample_record());
    drop(recovered);
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);

    // The same faults fail a later Tick and leave the committed state alone.
    for fault in RECORD_FAULTS {
        ok(execute(
            &fixture.path,
            &format!(
                "CREATE TRIGGER injected_fault {fault}
                 BEGIN SELECT RAISE(ABORT, 'injected dependency fault'); END;"
            ),
        ));
        let mut faulted = open(&fixture.path);
        let before = ok(faulted.current_counterfactual_basis(fork));
        assert_eq!(
            err(append_record(&mut faulted, fork, &tick_18_record())),
            StoreError::StorageFailure,
            "{fault}"
        );
        assert_eq!(faulted.current_counterfactual_basis(fork), Ok(before));
        assert_eq!(snapshot(&fixture.path, fork), RECORDED, "{fault}");
        drop(faulted);
        ok(execute(&fixture.path, "DROP TRIGGER injected_fault;"));
    }
    let mut reopened = open(&fixture.path);
    assert!(append_record(&mut reopened, fork, &tick_18_record()).is_ok());
    assert_eq!(snapshot(&fixture.path, fork), [3, 1, 3, 2, 2, 3, 2]);
}

#[test]
fn c2_stale_and_conflicting_commits_record_nothing() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let mut stale_head = Spec::new(fork);
    stale_head.head = 3;
    let mut stale_epoch = Spec::new(fork);
    stale_epoch.facts.trust_epoch = 16;
    for (spec, conflict) in [
        (stale_head, InvalidationConflictV1::LogicalHead),
        (stale_epoch, InvalidationConflictV1::TrustEpoch),
    ] {
        assert_eq!(
            commit_spec(&mut store, &spec, &sample_record()),
            Ok(Outcome::InvalidationConflict(conflict))
        );
        assert_eq!(snapshot(&fixture.path, fork), [0; 7]);
    }
    assert_eq!(generation(&store, fork), 0);

    commit_recorded(&mut store, fork, &sample_record());
    let expected = ok(store.current_counterfactual_basis(fork));
    let mut old_head = expected;
    old_head.fork_logical_head = Seq::from_u64(3);
    let mut old_generation = expected;
    old_generation.generation = 0;
    for (stale, conflict) in [
        (old_head, InvalidationConflictV1::LogicalHead),
        (old_generation, InvalidationConflictV1::PriorGeneration),
    ] {
        assert_eq!(
            store.append_counterfactual_tick_with_dependencies(
                fork,
                &stale,
                &tick_drafts(&[20], None),
                &tick_18_record()
            ),
            Ok(TickOutcome::Stale(conflict))
        );
        assert_eq!(snapshot(&fixture.path, fork), RECORDED);
    }
    assert_eq!(store.current_counterfactual_basis(fork), Ok(expected));

    // Replaying a committed Tick on its old basis is stale and records nothing.
    assert!(append_record(&mut store, fork, &tick_18_record()).is_ok());
    assert_eq!(
        store.append_counterfactual_tick_with_dependencies(
            fork,
            &expected,
            &tick_drafts(&[20], None),
            &tick_19_record()
        ),
        Ok(TickOutcome::Stale(InvalidationConflictV1::LogicalHead))
    );
    assert_eq!(snapshot(&fixture.path, fork), [3, 1, 3, 2, 2, 3, 2]);
    drop(store);
    let reopened = open(&fixture.path);
    assert_eq!(ok(nodes(&reopened, fork_scope(fork, 1), 5)).len(), 3);
}

#[test]
fn c2_rejected_records_commit_no_events_and_no_rows() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    // A record fault precedes the basis recheck, so it wins over a stale one.
    let stale = Spec {
        head: 3,
        ..Spec::new(fork)
    };
    let bases = [Spec::new(fork), stale];
    for record in [committed_record(FIRST_TICK), empty_record(18)] {
        for spec in &bases {
            assert_eq!(
                err(commit_spec(&mut store, spec, &record)),
                StoreError::BindingMismatch
            );
        }
    }
    // Integers beyond SQLite storage fail before any transaction.
    let beyond_tick = Spec {
        first_tick: SQL_MAX + 1,
        ..Spec::new(fork)
    };
    let beyond_generation = Spec {
        prior: SQL_MAX,
        ..Spec::new(fork)
    };
    for spec in [beyond_tick, beyond_generation] {
        let record = empty_record(spec.first_tick);
        assert_eq!(
            err(commit_spec(&mut store, &spec, &record)),
            StoreError::FieldOutOfBounds
        );
    }
    for kind in GUARDED_KINDS {
        let spec = Spec {
            guarded: Some(kind),
            ..Spec::new(fork)
        };
        assert_eq!(
            err(commit_spec(&mut store, &spec, &sample_record())),
            StoreError::ForkNotFound,
            "{kind}"
        );
    }
    assert_eq!(snapshot(&fixture.path, fork), [0; 7]);
    assert_eq!(ok(store.logical_head(fork)), Seq::from_u64(2));
    assert_eq!(generation(&store, fork), 0);

    // Later Ticks: the draft guard and a Tick beyond SQLite record nothing.
    commit_recorded(&mut store, fork, &sample_record());
    let expected = ok(store.current_counterfactual_basis(fork));
    for kind in GUARDED_KINDS {
        assert_eq!(
            err(store.append_counterfactual_tick_with_dependencies(
                fork,
                &expected,
                &tick_drafts(&[20], Some(kind)),
                &tick_18_record()
            )),
            StoreError::ForkNotFound,
            "{kind}"
        );
    }
    let root = row(coord(5, "r", 51), ROOT, PROVISIONAL, Vec::new());
    let beyond = record_of(SQL_MAX + 1, vec![root], Vec::new());
    assert_eq!(
        err(append_record(&mut store, fork, &beyond)),
        StoreError::FieldOutOfBounds
    );
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
    assert_eq!(store.current_counterfactual_basis(fork), Ok(expected));
}

#[test]
fn c2_a_head_that_does_not_advance_records_nothing() {
    let fixture = fixture();
    let fork = fixture.fork;
    let command = Spec::new(fork).command();
    // The first Tick's two Events reach own head 2; it falls back to 0.
    stall_head(&fixture.path, fork, 2, 0);
    let mut store = open(&fixture.path);
    assert_eq!(
        err(commit_with(&mut store, &command, &sample_record())),
        StoreError::CorruptState
    );
    assert_eq!(snapshot(&fixture.path, fork), [0; 7]);
    drop(store);
    ok(execute(&fixture.path, "DROP TRIGGER stalled_head;"));

    let mut store = open(&fixture.path);
    commit_recorded(&mut store, fork, &sample_record());
    drop(store);
    // A later Tick's Event reaches own head 3; it falls back to 2.
    stall_head(&fixture.path, fork, 3, 2);
    let mut store = open(&fixture.path);
    assert_eq!(
        err(append_record(&mut store, fork, &tick_18_record())),
        StoreError::CorruptState
    );
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
}

#[test]
fn c3_only_provisional_records_are_accepted() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let command = Spec::new(fork).command();
    assert_eq!(
        err(commit_with(&mut store, &command, &committed_record(17))),
        StoreError::BindingMismatch
    );
    commit_recorded(&mut store, fork, &sample_record());
    assert_eq!(
        err(append_record(&mut store, fork, &committed_record(18))),
        StoreError::BindingMismatch
    );
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
}

/// Extra counts above the room left for the Tick 19 record, and whether the
/// record fits.
const CAPACITY_CASES: [([usize; 3], bool); 4] = [
    ([0, 0, 0], true),
    ([1, 0, 0], false),
    ([0, 1, 0], false),
    ([0, 0, 1], false),
];

/// The capacity check sums the stored counts of the set's records, so a raw
/// record row stands for the rest of a set the size of the recorded bounds
/// without writing a million rows. The sample record stored two nodes, one
/// edge, and one declared input; the Tick 19 record adds one of each.
#[test]
fn c3_a_record_must_fit_the_stored_set_counts() {
    let room = [
        MAX_RECORDED_DEPENDENCY_NODES_V1 - 3,
        MAX_RECORDED_DEPENDENCY_EDGES_V1 - 2,
        MAX_RECORDED_DEPENDENCY_EDGES_V1 - 2,
    ];
    for (over, fits) in CAPACITY_CASES {
        let fixture = recorded_fixture();
        let fork = fixture.fork;
        ok(execute(
            &fixture.path,
            &format!(
                "INSERT INTO counterfactual_dependency_records
                 (timeline_id, generation, record_tick, node_count, edge_count, input_count)
                 VALUES ('{fork}', 1, 18, {}, {}, {});",
                room[0] + over[0],
                room[1] + over[1],
                room[2] + over[2]
            ),
        ));
        let mut store = open(&fixture.path);
        let outcome = append_record(&mut store, fork, &tick_19_record());
        if fits {
            assert_eq!(
                outcome,
                Ok(TickOutcome::Committed {
                    head: Seq::from_u64(5)
                })
            );
            assert_eq!(recorded_rows(&fixture.path, fork), [3, 3, 2]);
        } else {
            assert_eq!(err(outcome), StoreError::FieldOutOfBounds, "{over:?}");
            assert_eq!(recorded_rows(&fixture.path, fork), [2, 2, 1], "{over:?}");
            assert_eq!(written_rows(&fixture.path, fork)[0], 2, "{over:?}");
        }
    }
}

#[test]
fn c3_corrupt_stored_counts_and_ticks_are_corrupt_state() {
    for assignment in ["node_count = -1", "input_count = -1", "record_tick = -1"] {
        let fixture = recorded_fixture();
        let fork = fixture.fork;
        ok(execute(
            &fixture.path,
            &format!(
                "PRAGMA ignore_check_constraints = ON;
                 DROP TRIGGER counterfactual_dependency_records_immutable;
                 UPDATE counterfactual_dependency_records SET {assignment};"
            ),
        ));
        let mut store = open(&fixture.path);
        assert_eq!(
            err(append_record(&mut store, fork, &tick_18_record())),
            StoreError::CorruptState,
            "{assignment}"
        );
        assert_eq!(snapshot(&fixture.path, fork), RECORDED, "{assignment}");
    }
}

/// The capacity check trusts the stored counts: this adapter alone writes
/// them, in the transaction of the rows they describe, behind the immutability
/// guard. So a count that drifted low, which takes a file edited with the
/// guard dropped, lets in a record that the real rows would exceed.
#[test]
fn c3_capacity_trusts_drifted_stored_counts() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    ok(execute(
        &fixture.path,
        &format!(
            "DROP TRIGGER counterfactual_dependency_records_immutable;
             UPDATE counterfactual_dependency_records
             SET node_count = 0, edge_count = 0, input_count = 0;
             INSERT INTO counterfactual_dependency_records
             (timeline_id, generation, record_tick, node_count, edge_count, input_count)
             VALUES ('{fork}', 1, 18, {}, {}, {});",
            MAX_RECORDED_DEPENDENCY_NODES_V1 - 1,
            MAX_RECORDED_DEPENDENCY_EDGES_V1 - 1,
            MAX_RECORDED_DEPENDENCY_EDGES_V1 - 1
        ),
    ));
    let mut store = open(&fixture.path);
    // Counting the two real node rows, the Tick 19 record would exceed the
    // node bound, but the zeroed stored counts say it fits.
    assert_eq!(
        append_record(&mut store, fork, &tick_19_record()),
        Ok(TickOutcome::Committed {
            head: Seq::from_u64(5)
        })
    );
    assert_eq!(recorded_rows(&fixture.path, fork), [3, 3, 2]);
}

#[test]
fn c4_repeated_position_keys_and_digests_are_rejected_across_records() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    // The position key of node `a` at tick 17 with another digest, then the
    // digest of node `a` at another position.
    let same_position = row(coord(FIRST_TICK, "a", 77), ROOT, PROVISIONAL, Vec::new());
    let same_digest = provisional(coord(18, "z", 1), Vec::new());
    // Only the second node of the record collides.
    let fresh = provisional(coord(18, "m", 41), Vec::new());
    let colliding = provisional(coord(18, "n", 2), Vec::new());
    // Only the first node of the record collides; the lookup stops there.
    let first_hit = provisional(coord(18, "n", 2), Vec::new());
    let after_hit = provisional(coord(18, "p", 43), Vec::new());
    for candidates in [
        vec![same_position],
        vec![same_digest],
        vec![fresh, colliding],
        vec![first_hit, after_hit],
    ] {
        let record = record_of(18, candidates, Vec::new());
        assert_eq!(
            err(append_record(&mut store, fork, &record)),
            StoreError::DuplicateIdentity
        );
        assert_eq!(snapshot(&fixture.path, fork), RECORDED);
    }
    // The rejected records left the set usable.
    assert!(append_record(&mut store, fork, &tick_18_record()).is_ok());
}

/// A node insert copying the first stored node with its Tick and artifact
/// digest replaced by the given SQL expressions.
fn node_copy(verb: &str, tick: &str, digest: &str) -> String {
    format!(
        "{verb} INTO counterfactual_dependency_nodes ({NODE_COLUMNS})
         SELECT timeline_id, generation, {tick}, scheduler_position, owner_id, output_ordinal,
                schema_id, {digest}, class, origin, input_digests, provenance_digest
         FROM counterfactual_dependency_nodes LIMIT 1"
    )
}

#[test]
fn c4_the_database_refuses_repeated_keys_and_replacements() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let same_position = node_copy("INSERT", "tick", "randomblob(32)");
    let same_digest = node_copy("INSERT", "tick + 100", "artifact_digest");
    let replacing = node_copy("INSERT OR REPLACE", "tick", "randomblob(32)");
    let replace_digest = node_copy("INSERT OR REPLACE", "tick + 100", "artifact_digest");
    let same_edge = "INSERT INTO counterfactual_dependency_edges
                     SELECT * FROM counterfactual_dependency_edges";
    let same_record = "INSERT INTO counterfactual_dependency_records
                       SELECT * FROM counterfactual_dependency_records";
    let refused_inserts = [
        same_position.as_str(),
        same_digest.as_str(),
        replacing.as_str(),
        replace_digest.as_str(),
        same_edge,
        same_record,
    ];
    for sql in refused_inserts {
        assert!(execute(&fixture.path, sql).is_err(), "{sql}");
    }
    // Without the insert guards the unique keys refuse the same rows.
    for (guard, sql) in [
        ("nodes_key_not_replaced", same_position.as_str()),
        ("nodes_digest_not_replaced", same_digest.as_str()),
        ("edges_not_replaced", same_edge),
        ("records_monotonic", same_record),
    ] {
        let drop_guard = format!("DROP TRIGGER IF EXISTS counterfactual_dependency_{guard};");
        ok(execute(&fixture.path, &drop_guard));
        let refused = err(execute(&fixture.path, sql)).to_string();
        assert!(refused.contains("UNIQUE constraint failed"), "{refused}");
    }
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
}

#[test]
fn c5_a_record_tick_must_exceed_every_recorded_tick() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    for tick in [FIRST_TICK, 5] {
        assert_eq!(
            err(append_record(&mut store, fork, &empty_record(tick))),
            StoreError::BindingMismatch,
            "{tick}"
        );
    }
    // Gaps are allowed.
    assert!(append_record(&mut store, fork, &empty_record(20)).is_ok());
    assert!(append_record(&mut store, fork, &empty_record(25)).is_ok());
    for tick in [24, 25] {
        assert_eq!(
            err(append_record(&mut store, fork, &empty_record(tick))),
            StoreError::BindingMismatch,
            "{tick}"
        );
    }
    assert_eq!(
        text_scalar(
            &fixture.path,
            "SELECT group_concat(record_tick) FROM (
                 SELECT record_tick FROM counterfactual_dependency_records
                 ORDER BY record_tick
             )"
        ),
        "17,20,25"
    );
    // The database refuses a record Tick that is not above the set's own.
    for tick in [25, 3] {
        let raw = format!(
            "INSERT INTO counterfactual_dependency_records VALUES ('{fork}', 1, {tick}, 0, 0, 0);"
        );
        assert!(execute(&fixture.path, &raw).is_err(), "{tick}");
    }
    assert_eq!(recorded_rows(&fixture.path, fork), [3, 2, 1]);
}

#[test]
fn c5_an_empty_set_starts_at_the_generation_first_tick() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    // A plain invalidation records no dependencies; its first Tick is 17.
    assert!(matches!(
        ok(store.commit_counterfactual_invalidation(&Spec::new(fork).command())),
        Outcome::Committed(_)
    ));
    assert_eq!(
        err(append_record(
            &mut store,
            fork,
            &empty_record(FIRST_TICK - 1)
        )),
        StoreError::BindingMismatch
    );
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
    assert!(append_record(&mut store, fork, &empty_record(FIRST_TICK)).is_ok());
    assert_eq!(recorded_rows(&fixture.path, fork), [1, 0, 0]);
}

#[test]
fn c5_the_record_tick_is_persisted_apart_from_node_ticks() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    // A record made only of an early root: its node Tick is 3, its own is 17.
    let early = row(coord(3, "r", 51), ROOT, PROVISIONAL, Vec::new());
    let first = record_of(FIRST_TICK, vec![early.clone()], Vec::new());
    commit_recorded(&mut store, fork, &first);
    assert_eq!(
        text_scalar(
            &fixture.path,
            "SELECT CAST(record_tick AS TEXT) FROM counterfactual_dependency_records"
        ),
        "17"
    );
    assert_eq!(ok(nodes(&store, fork_scope(fork, 1), 5)), [early]);
    // Comparing with the node Tick would admit 16.
    assert_eq!(
        err(append_record(&mut store, fork, &empty_record(16))),
        StoreError::BindingMismatch
    );
    assert!(append_record(&mut store, fork, &empty_record(18)).is_ok());
}

#[test]
fn c5_a_generation_without_an_invalidation_has_no_first_tick() {
    let fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    // Generation 0 has no invalidation, so it has no first Tick to compare.
    assert_eq!(
        err(append_record(&mut store, fork, &empty_record(FIRST_TICK))),
        StoreError::BindingMismatch
    );
    // A re-created Fork resumes at its generation floor without a receipt row.
    commit_recorded(&mut store, fork, &sample_record());
    ok(store.delete_timeline(fork));
    let mut meta = TimelineMeta::forked_from(root, Seq::from_u64(2), "recreated");
    meta.id = fork;
    ok(store.create_timeline_with_meta(meta));
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 1))
    );
    assert_eq!(
        err(append_record(&mut store, fork, &empty_record(FIRST_TICK))),
        StoreError::BindingMismatch
    );
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
}

#[test]
fn c6_roots_ride_later_records_and_rows_are_served_by_position_key() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let source = coord(3, "s", 60);
    let early_root = row(coord(16, "r", 51), ROOT, PROVISIONAL, vec![hash(60)]);
    let second = record_of(
        20,
        vec![early_root, provisional(coord(20, "e", 52), Vec::new())],
        vec![edge(&coord(16, "r", 51), &source)],
    );
    assert!(append_record(&mut store, fork, &second).is_ok());
    let earlier_root = row(coord(9, "q", 53), ROOT, PROVISIONAL, Vec::new());
    let third = record_of(
        21,
        vec![earlier_root, provisional(coord(21, "f", 54), Vec::new())],
        Vec::new(),
    );
    assert!(append_record(&mut store, fork, &third).is_ok());

    // Rows are ordered by position key across records, not by insertion.
    let listed = ok(nodes(&store, fork_scope(fork, 1), 2));
    assert_eq!(owners(&listed), ["q", "r", "a", "b", "e", "f"]);
    let edge_owners: Vec<String> = ok(edges(&store, fork_scope(fork, 1), 1))
        .iter()
        .map(|entry| entry.consumer().owner_id().to_owned())
        .collect();
    assert_eq!(edge_owners, ["r", "b"]);
    drop(store);
    let reopened = open(&fixture.path);
    assert_eq!(ok(nodes(&reopened, fork_scope(fork, 1), 4)), listed);
}

#[test]
fn c6_roots_may_not_repeat_a_position_key_and_follow_the_record_tick_rule() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let root = row(coord(9, "q", 53), ROOT, PROVISIONAL, Vec::new());
    assert!(append_record(&mut store, fork, &record_of(20, vec![root], Vec::new())).is_ok());
    // Another root at the same position key with another digest, in a later
    // record, is a collision.
    let twin = row(coord(9, "q", 77), ROOT, PROVISIONAL, Vec::new());
    assert_eq!(
        err(append_record(
            &mut store,
            fork,
            &record_of(21, vec![twin], Vec::new())
        )),
        StoreError::DuplicateIdentity
    );
    assert_eq!(recorded_rows(&fixture.path, fork), [2, 3, 1]);

    // The record contract itself refuses a root after the record's Tick and
    // any other node at another Tick, before an adapter sees the record.
    let late_root = row(coord(18, "r", 51), ROOT, PROVISIONAL, Vec::new());
    let early_plain = provisional(coord(16, "p", 52), Vec::new());
    for misplaced in [late_root, early_plain] {
        let rejected = TickRecord::try_new(FIRST_TICK, PROVISIONAL, vec![misplaced], Vec::new());
        assert_eq!(err(rejected), DepError::BindingMismatch);
    }
}

#[test]
fn c7_reads_are_qualified_by_the_current_generation() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    commit_recorded(&mut store, fork, &sample_record());
    for stale in [0, 2] {
        let scope = fork_scope(fork, stale);
        let mixed = StoreError::MixedForkGeneration;
        assert_eq!(err(nodes(&store, scope, 2)), mixed);
        assert_eq!(err(edges(&store, scope, 2)), mixed);
    }

    // The second invalidation records its first Tick record at its own first
    // Tick, and starts from an empty set.
    let second = Spec {
        prior: 1,
        head: 4,
        frontier_id: 2,
        first_tick: 40,
        ..Spec::new(fork)
    };
    let second_node = provisional(coord(40, "a", 61), Vec::new());
    let second_record = record_of(40, vec![second_node], Vec::new());
    assert!(matches!(
        ok(commit_spec(&mut store, &second, &second_record)),
        Outcome::Committed(_)
    ));
    let current = fork_scope(fork, 2);
    assert_eq!(ok(nodes(&store, current, 5)), second_record.nodes());
    assert_eq!(ok(edges(&store, current, 5)), Vec::new());
    // The quarantined generation is retained for audit but never served.
    assert_eq!(
        err(nodes(&store, fork_scope(fork, 1), 5)),
        StoreError::MixedForkGeneration
    );
    assert_eq!(
        text_scalar(
            &fixture.path,
            "SELECT group_concat(generation || ':' || record_tick) FROM (
                 SELECT generation, record_tick FROM counterfactual_dependency_records
                 ORDER BY generation
             )"
        ),
        "1:17,2:40"
    );
    assert_eq!(recorded_rows(&fixture.path, fork), [2, 3, 1]);

    // An invalidation without dependencies opens an empty set too.
    let third = Spec {
        prior: 2,
        head: 6,
        frontier_id: 3,
        first_tick: 60,
        ..Spec::new(fork)
    };
    assert!(matches!(
        ok(store.commit_counterfactual_invalidation(&third.command())),
        Outcome::Committed(_)
    ));
    assert_eq!(ok(nodes(&store, fork_scope(fork, 3), 5)), Vec::new());
    assert_eq!(
        err(nodes(&store, fork_scope(fork, 4), 5)),
        StoreError::MixedForkGeneration
    );
}

/// Insert the committed prefix of `root` used by the scope tests: nodes at
/// Ticks 3, 5, and 9, and edges of the Tick 5 and Tick 9 nodes.
fn insert_prefix(path: &Path, root: TimelineId) {
    let (first, second, third) = (coord(3, "p", 71), coord(5, "q", 72), coord(9, "s", 73));
    for node in [&first, &second, &third] {
        insert_prefix_node(path, root, node);
    }
    insert_prefix_edge(path, root, &second, &first);
    insert_prefix_edge(path, root, &third, &second);
}

#[test]
fn c8_parent_prefix_reads_only_committed_rows_through_the_tick() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    insert_prefix(&fixture.path, root);
    let store = open(&fixture.path);
    for limit in [1, 2, 5] {
        for (through, expected_nodes, expected_edges) in [
            (9, ["p", "q", "s"].as_slice(), 2),
            (5, ["p", "q"].as_slice(), 1),
            (4, ["p"].as_slice(), 0),
            (2, [].as_slice(), 0),
            (u64::MAX, ["p", "q", "s"].as_slice(), 2),
        ] {
            let scope = prefix_scope(root, through);
            let listed = ok(nodes(&store, scope, limit));
            assert_eq!(owners(&listed), expected_nodes, "{through} {limit}");
            assert!(listed.iter().all(|entry| entry.origin() == COMMITTED));
            assert_eq!(ok(edges(&store, scope, limit)).len(), expected_edges);
        }
    }

    // The Fork's own rows are provisional and live in its generation; a
    // prefix recorded under the Fork's id is a different set.
    insert_prefix_node(&fixture.path, fork, &coord(4, "k", 74));
    let reopened = open(&fixture.path);
    let sample = sample_record();
    assert_eq!(ok(nodes(&reopened, fork_scope(fork, 1), 5)), sample.nodes());
    assert_eq!(
        owners(&ok(nodes(&reopened, prefix_scope(fork, 9), 5))),
        ["k"]
    );
    // A reader stitches the prefix and the Fork generation by concatenation.
    let stitched = [
        ok(nodes(&reopened, prefix_scope(root, 9), 2)),
        ok(nodes(&reopened, fork_scope(fork, 1), 2)),
    ]
    .concat();
    assert_eq!(stitched.len(), 5);
    assert!(stitched
        .windows(2)
        .all(|pair| pair[0].coordinate().position_key() < pair[1].coordinate().position_key()));
}

/// One corrupted column of the sample node `a` and one of the sample edge.
const NODE_CORRUPTIONS: [&str; 14] = [
    "origin = 0",
    "origin = 7",
    "class = 9",
    "class = -1",
    "tick = -1",
    "scheduler_position = 4294967296",
    "output_ordinal = -1",
    "owner_id = ''",
    "schema_id = 0",
    "artifact_digest = X'00'",
    "provenance_digest = zeroblob(32)",
    "provenance_digest = X'00'",
    "input_digests = X'00'",
    "input_digests = zeroblob(32)",
];

const EDGE_CORRUPTIONS: [&str; 9] = [
    "edge_bytes = X'00'",
    "tick = -1",
    "owner_id = ''",
    "scheduler_position = 4294967296",
    "consumer_schema_id = 0",
    "consumer_schema_id = 8",
    "consumer_digest = X'00'",
    "consumer_digest = zeroblob(32)",
    "source_digest = zeroblob(32)",
];

/// Corrupt `assignment` of `table` through raw SQL, with the table's update
/// guard dropped and its checks ignored, as the schema-drift tests do.
fn corrupt(path: &Path, table: &str, assignment: &str, filter: &str) {
    ok(execute(
        path,
        &format!(
            "PRAGMA ignore_check_constraints = ON;
             DROP TRIGGER counterfactual_dependency_{table}_immutable;
             UPDATE counterfactual_dependency_{table} SET {assignment} {filter};"
        ),
    ));
}

#[test]
fn c8_corrupted_stored_rows_read_back_as_corrupt_state() {
    for assignment in NODE_CORRUPTIONS {
        let fixture = recorded_fixture();
        let fork = fixture.fork;
        corrupt(&fixture.path, "nodes", assignment, "WHERE owner_id = 'a'");
        let store = open(&fixture.path);
        assert_eq!(
            err(nodes(&store, fork_scope(fork, 1), 5)),
            StoreError::CorruptState,
            "{assignment}"
        );
        // The edges are intact, so only the node page fails.
        assert_eq!(ok(edges(&store, fork_scope(fork, 1), 5)).len(), 1);
    }
    for assignment in EDGE_CORRUPTIONS {
        let fixture = recorded_fixture();
        let fork = fixture.fork;
        corrupt(&fixture.path, "edges", assignment, "");
        let store = open(&fixture.path);
        assert_eq!(
            err(edges(&store, fork_scope(fork, 1), 5)),
            StoreError::CorruptState,
            "{assignment}"
        );
        assert_eq!(ok(nodes(&store, fork_scope(fork, 1), 5)).len(), 2);
    }
}

#[test]
fn c8_stored_input_digests_must_be_one_ascending_run_of_digests() {
    // Node `b` declares digest 1; two digests in descending order are not
    // canonical, and a trailing partial digest is not a digest at all.
    let descending = format!("X'{}{}'", hash_hex(2), hash_hex(1));
    let partial = format!("X'{}00'", hash_hex(1));
    for digests in [descending, partial] {
        let fixture = recorded_fixture();
        let assignment = format!("input_digests = {digests}");
        corrupt(&fixture.path, "nodes", &assignment, "WHERE owner_id = 'b'");
        let store = open(&fixture.path);
        assert_eq!(
            err(nodes(&store, fork_scope(fixture.fork, 1), 5)),
            StoreError::CorruptState,
            "{digests}"
        );
    }
}

#[test]
fn c8_rows_outside_the_requested_scope_read_back_as_corrupt_state() {
    let fixture = fixture();
    let root = fixture.root;
    insert_prefix_node(&fixture.path, root, &coord(3, "p", 71));
    // A provisional node stored in the committed prefix is out of scope.
    corrupt(&fixture.path, "nodes", "origin = 1", "");
    let store = open(&fixture.path);
    assert_eq!(
        err(nodes(&store, prefix_scope(root, 9), 2)),
        StoreError::CorruptState
    );
}

/// The number of nodes and of edges a scope serves, or the first error.
fn counts(store: &SqliteStore, scope: DependencyReadScopeV1) -> [Result<usize, StoreError>; 2] {
    [
        nodes(store, scope, 2).map(|listed| listed.len()),
        edges(store, scope, 2).map(|listed| listed.len()),
    ]
}

const NOT_FOUND: [Result<usize, StoreError>; 2] =
    [Err(StoreError::ForkNotFound), Err(StoreError::ForkNotFound)];
const FAILED: [Result<usize, StoreError>; 2] = [
    Err(StoreError::StorageFailure),
    Err(StoreError::StorageFailure),
];
const EMPTY: [Result<usize, StoreError>; 2] = [Ok(0), Ok(0)];

#[test]
fn c9_unknown_deleted_and_unpublished_timelines_are_not_found() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    let unpublished = ok(store.fork(root, Seq::from_u64(1), "unpublished")).id();
    let missing = TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128));
    // Never an empty page: an unknown Timeline, the root as a Fork, and a Fork
    // whose facts are unpublished.
    for scope in [
        prefix_scope(missing, 9),
        fork_scope(missing, 0),
        fork_scope(root, 0),
        fork_scope(unpublished, 0),
    ] {
        assert_eq!(counts(&store, scope), NOT_FOUND, "{scope:?}");
    }
    // An existing Timeline without recorded rows serves an empty page.
    for scope in [prefix_scope(root, 9), prefix_scope(unpublished, 9)] {
        assert_eq!(counts(&store, scope), EMPTY, "{scope:?}");
    }
    assert_eq!(
        store.publish_counterfactual_facts(unpublished, facts()),
        Ok(at(unpublished, 0))
    );
    assert_eq!(counts(&store, fork_scope(unpublished, 0)), EMPTY);
    assert_eq!(counts(&store, fork_scope(fork, 1)), [Ok(2), Ok(1)]);

    // A deleted Fork is erased from both of its scopes.
    ok(store.delete_timeline(fork));
    for scope in [fork_scope(fork, 1), prefix_scope(fork, 9)] {
        assert_eq!(counts(&store, scope), NOT_FOUND, "{scope:?}");
    }
}

#[test]
fn c9_a_protected_lineage_is_not_found() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    ok(execute(
        &fixture.path,
        &format!(
            "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES ('{root}', 1);"
        ),
    ));
    let store = open(&fixture.path);
    for scope in [
        fork_scope(fork, 1),
        prefix_scope(fork, 9),
        prefix_scope(root, 9),
    ] {
        assert_eq!(counts(&store, scope), NOT_FOUND, "{scope:?}");
    }
}

#[test]
fn c9_a_misplaced_record_reports_the_fork_error_first() {
    let fixture = fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let missing = TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128));
    let mut store = open(&fixture.path);
    let expected = ok(store.current_counterfactual_basis(fork));
    // The Fork is looked up before the record is checked, so a record that
    // is not provisional, or not at the first Tick, never wins over it.
    for record in [committed_record(FIRST_TICK), empty_record(18)] {
        assert_eq!(
            err(commit_spec(&mut store, &Spec::new(missing), &record)),
            StoreError::ForkNotFound
        );
    }
    assert_eq!(
        err(store.append_counterfactual_tick_with_dependencies(
            missing,
            &expected,
            &tick_drafts(&[20], None),
            &committed_record(18)
        )),
        StoreError::ForkNotFound
    );
    // A frozen Fork is closed by its fence before any record check.
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut frozen = open_with_gate(&fixture.path, &gate);
    gate.freeze_timeline_for_test(fork);
    assert_eq!(
        err(commit_spec(
            &mut frozen,
            &Spec::new(fork),
            &committed_record(FIRST_TICK)
        )),
        StoreError::StorageFailure
    );
    drop(frozen);
    // A geographic-protected lineage is not found.
    ok(execute(
        &fixture.path,
        &format!(
            "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES ('{root}', 1);"
        ),
    ));
    let mut protected = open(&fixture.path);
    assert_eq!(
        err(commit_spec(
            &mut protected,
            &Spec::new(fork),
            &committed_record(FIRST_TICK)
        )),
        StoreError::ForkNotFound
    );
    assert_eq!(snapshot(&fixture.path, fork), [0; 7]);
}

#[test]
fn c9_reads_and_writes_fail_closed_without_a_gate() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut ungated = ok(SqliteStore::open(fixture_path_str(&fixture)));
    for scope in [
        fork_scope(fork, 1),
        prefix_scope(root, 9),
        prefix_scope(fork, 9),
    ] {
        assert_eq!(counts(&ungated, scope), FAILED, "{scope:?}");
    }
    let spec = Spec::new(fork);
    assert_eq!(
        err(commit_spec(&mut ungated, &spec, &sample_record())),
        StoreError::StorageFailure
    );
    assert_eq!(
        err(ungated.append_counterfactual_tick_with_dependencies(
            fork,
            &spec.command().expected_basis(),
            &tick_drafts(&[20], None),
            &tick_18_record()
        )),
        StoreError::StorageFailure
    );
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
}

#[test]
fn c9_the_erasure_fence_of_each_scope_applies() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let spec = Spec::new(fork);
    let basis = spec.command().expected_basis();
    // A frozen Fork refuses its own reads and writes; a parent-prefix read of
    // the root names no Fork, so the Fork's fence does not apply to it.
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut store = open_with_gate(&fixture.path, &gate);
    gate.freeze_timeline_for_test(fork);
    assert_eq!(counts(&store, fork_scope(fork, 1)), FAILED);
    assert_eq!(counts(&store, prefix_scope(root, 9)), EMPTY);
    assert_eq!(
        err(commit_spec(&mut store, &spec, &sample_record())),
        StoreError::StorageFailure
    );
    assert_eq!(
        err(store.append_counterfactual_tick_with_dependencies(
            fork,
            &basis,
            &tick_drafts(&[20], None),
            &tick_18_record()
        )),
        StoreError::StorageFailure
    );
    drop(store);

    // A frozen parent refuses its own prefix and, through the inherited
    // scopes, the prefix recorded under its Fork.
    let parent_gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let store = open_with_gate(&fixture.path, &parent_gate);
    parent_gate.freeze_timeline_for_test(root);
    assert_eq!(counts(&store, prefix_scope(root, 9)), FAILED);
    assert_eq!(counts(&store, prefix_scope(fork, 9)), FAILED);
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
}

#[test]
fn c9_a_file_changed_by_another_connection_fails_closed() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    ok(execute(
        &fixture.path,
        "CREATE TABLE unrelated (id INTEGER);",
    ));
    assert_eq!(counts(&store, fork_scope(fork, 1)), FAILED);
    assert_eq!(
        err(commit_spec(&mut store, &Spec::new(fork), &sample_record())),
        StoreError::StorageFailure
    );
    let basis = Spec::new(fork).command().expected_basis();
    assert_eq!(
        err(store.append_counterfactual_tick_with_dependencies(
            fork,
            &basis,
            &tick_drafts(&[20], None),
            &tick_18_record()
        )),
        StoreError::StorageFailure
    );
    assert_eq!(snapshot(&fixture.path, fork), RECORDED);
}

#[test]
fn c9_reads_inside_a_protected_effect_interval_see_its_writes() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let interval = ok(store.begin_protected_effect_interval());
    commit_recorded(&mut store, fork, &sample_record());
    let sample = sample_record();
    // The interval's own uncommitted write is visible at one read point.
    assert_eq!(ok(nodes(&store, fork_scope(fork, 1), 1)), sample.nodes());
    assert_eq!(ok(edges(&store, fork_scope(fork, 1), 1)), sample.edges());
    assert!(append_record(&mut store, fork, &tick_18_record()).is_ok());
    assert_eq!(ok(nodes(&store, fork_scope(fork, 1), 2)).len(), 3);
    ok(store
        .finish_protected_effect_interval(interval, ErasureProtectedEffectDispositionV1::Rollback));
    assert_eq!(generation(&store, fork), 0);
    assert_eq!(snapshot(&fixture.path, fork), [0; 7]);
    assert_eq!(counts(&store, fork_scope(fork, 0)), EMPTY);
}

/// Insert `count` committed-prefix nodes of `root`, at Ticks `1..=count`.
fn insert_prefix_run(path: &Path, root: TimelineId, count: u64) {
    ok(execute(
        path,
        &format!(
            "WITH RECURSIVE sequence(value) AS (
                 SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < {count}
             )
             INSERT INTO counterfactual_dependency_nodes ({NODE_COLUMNS})
             SELECT '{root}', -1, value, 0, 'o', 0, 7, randomblob(32), 2, 0, X'',
                    X'{provenance}'
             FROM sequence;",
            provenance = hash_hex(99)
        ),
    ));
}

#[test]
fn c10_a_page_is_capped_and_keyset_paging_is_stable_across_reopen() {
    let fixture = fixture();
    let root = fixture.root;
    let page_cap = u64::try_from(MAX_DEPENDENCY_PAGE_ROWS_V1).unwrap_or(u64::MAX);
    insert_prefix_run(&fixture.path, root, page_cap + 1);
    let scope = prefix_scope(root, u64::MAX);
    let store = open(&fixture.path);
    let first: NodePage =
        ok(store.read_dependency_nodes(&request(scope, None, MAX_DEPENDENCY_PAGE_ROWS_V1)));
    assert_eq!(first.items().len(), MAX_DEPENDENCY_PAGE_ROWS_V1);
    assert_eq!(first.items()[0].coordinate().tick(), 1);
    let last = first.items()[MAX_DEPENDENCY_PAGE_ROWS_V1 - 1]
        .coordinate()
        .tick();
    assert_eq!(last, page_cap);
    let cursor = first.next().cloned();
    let cursor_tick = cursor.as_ref().map(DependencyPageCursorV1::tick);
    assert_eq!(cursor_tick, Some(last));
    let second = ok(store.read_dependency_nodes(&request(
        scope,
        cursor.clone(),
        MAX_DEPENDENCY_PAGE_ROWS_V1,
    )));
    assert_eq!(second.items().len(), 1);
    assert_eq!(second.items()[0].coordinate().tick(), page_cap + 1);
    assert_eq!(second.next(), None);
    drop(store);

    // The same cursor continues identically after a reopen.
    let reopened = open(&fixture.path);
    let again =
        ok(reopened.read_dependency_nodes(&request(scope, cursor, MAX_DEPENDENCY_PAGE_ROWS_V1)));
    assert_eq!(again, second);
    let all = ok(nodes(&reopened, scope, 100));
    assert_eq!(all.len(), MAX_DEPENDENCY_PAGE_ROWS_V1 + 1);
    assert!(all
        .windows(2)
        .all(|pair| pair[0].coordinate().tick() < pair[1].coordinate().tick()));
}

#[test]
fn c10_cursors_continue_after_their_key_and_wrong_ones_are_refused() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let store = open(&fixture.path);
    let scope = fork_scope(fork, 1);
    let cursor = |owner: &str, ordinal: u32, source: Option<Hash>| {
        ok(DependencyPageCursorV1::try_new(
            FIRST_TICK,
            0,
            owner.to_owned(),
            ordinal,
            source,
        ))
    };
    // Rows strictly after the cursor key are served, in both row kinds.
    let after_first = request(scope, Some(cursor("a", 0, None)), 5);
    let served = ok(store.read_dependency_nodes(&after_first));
    assert_eq!(owners(served.items()), ["b"]);
    let after_last = request(scope, Some(cursor("b", 0, None)), 5);
    assert!(ok(store.read_dependency_nodes(&after_last))
        .items()
        .is_empty());
    let before_edge = request(scope, Some(cursor("a", 5, Some(hash(9)))), 5);
    let served = ok(store.read_dependency_edges(&before_edge));
    assert_eq!(served.items().len(), 1);
    let at_edge = request(scope, Some(cursor("b", 0, Some(hash(1)))), 5);
    assert!(ok(store.read_dependency_edges(&at_edge)).items().is_empty());

    // A cursor of the other row kind is the caller's fault.
    let edge_cursor = request(scope, Some(cursor("a", 0, Some(hash(1)))), 5);
    assert_eq!(
        err(store.read_dependency_nodes(&edge_cursor)),
        StoreError::BindingMismatch
    );
    assert_eq!(
        err(store.read_dependency_edges(&after_first)),
        StoreError::BindingMismatch
    );
    // A cursor Tick SQLite cannot store is no cursor this adapter issued.
    let beyond = ok(DependencyPageCursorV1::try_new(
        SQL_MAX + 1,
        0,
        "a".to_owned(),
        0,
        None,
    ));
    assert_eq!(
        err(store.read_dependency_nodes(&request(scope, Some(beyond), 5))),
        StoreError::BindingMismatch
    );
}

#[test]
fn c11_dependency_faults_map_to_the_storage_errors() {
    for (fault, mapped) in [
        (DepError::InvalidEncoding, StoreError::InvalidEncoding),
        (DepError::UnknownEnum, StoreError::InvalidEncoding),
        (DepError::UnsupportedVersion, StoreError::UnsupportedVersion),
        (DepError::FieldOutOfBounds, StoreError::FieldOutOfBounds),
        (DepError::ProvenanceMissing, StoreError::FieldOutOfBounds),
        (DepError::InvalidPageLimit, StoreError::FieldOutOfBounds),
        (DepError::NonCanonicalOrder, StoreError::NonCanonicalOrder),
        (DepError::DuplicateIdentity, StoreError::DuplicateIdentity),
        (DepError::BindingMismatch, StoreError::BindingMismatch),
        (DepError::UnknownConsumer, StoreError::BindingMismatch),
        (DepError::UndeclaredInput, StoreError::BindingMismatch),
        (DepError::InvalidCursor, StoreError::BindingMismatch),
    ] {
        assert_eq!(StoreError::from(fault), mapped, "{fault:?}");
    }
    assert_eq!(DepError::READ_BACK_FAULT, StoreError::CorruptState);
    // The page limit and a cursor beyond a parent prefix fail the request, and
    // the adapter reports them with the same mapping.
    let scope = prefix_scope(TimelineId::from_ulid(Ulid::from(1_u128)), 5);
    for limit in [0, MAX_DEPENDENCY_PAGE_ROWS_V1 + 1] {
        let rejected = err(DependencyPageRequestV1::try_new(scope, None, limit));
        assert_eq!(StoreError::from(rejected), StoreError::FieldOutOfBounds);
    }
    let beyond = ok(DependencyPageCursorV1::try_new(
        6,
        0,
        "a".to_owned(),
        0,
        None,
    ));
    let rejected = err(DependencyPageRequestV1::try_new(scope, Some(beyond), 1));
    assert_eq!(StoreError::from(rejected), StoreError::BindingMismatch);
    assert!(DependencyPageRequestV1::try_new(scope, None, MAX_DEPENDENCY_PAGE_ROWS_V1).is_ok());
}

/// A second Fork of the root at Seq 1 that committed the sample record.
fn recorded_other_fork(store: &mut SqliteStore, root: TimelineId) -> TimelineId {
    let other = ok(store.fork(root, Seq::from_u64(1), "other")).id();
    ok(store.publish_counterfactual_facts(other, facts()));
    let spec = Spec {
        head: 1,
        ..Spec::new(other)
    };
    assert!(matches!(
        ok(commit_spec(store, &spec, &sample_record())),
        Outcome::Committed(_)
    ));
    other
}

#[test]
fn c12_deleting_a_fork_purges_its_dependency_rows_and_reads_are_not_found() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    let other = recorded_other_fork(&mut store, root);
    drop(store);
    // A prefix recorded under the Fork's own id, and one under the root.
    insert_prefix_node(&fixture.path, fork, &coord(4, "k", 74));
    insert_prefix_node(&fixture.path, root, &coord(3, "p", 71));
    assert_eq!(recorded_rows(&fixture.path, fork), [1, 3, 1]);

    let mut store = open(&fixture.path);
    ok(store.delete_timeline(fork));
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
    assert_eq!(recorded_rows(&fixture.path, other), [1, 2, 1]);
    assert_eq!(recorded_rows(&fixture.path, root), [0, 1, 0]);
    for scope in [fork_scope(fork, 1), prefix_scope(fork, 9)] {
        assert_eq!(counts(&store, scope), NOT_FOUND, "{scope:?}");
    }
    assert_eq!(counts(&store, fork_scope(other, 1)), [Ok(2), Ok(1)]);
    assert_eq!(counts(&store, prefix_scope(root, 9)), [Ok(1), Ok(0)]);

    // A Fork re-created under the same ID starts with empty sets.
    let mut meta = TimelineMeta::forked_from(root, Seq::from_u64(2), "recreated");
    meta.id = fork;
    ok(store.create_timeline_with_meta(meta));
    assert_eq!(
        store.publish_counterfactual_facts(fork, facts()),
        Ok(at(fork, 1))
    );
    assert_eq!(counts(&store, fork_scope(fork, 1)), EMPTY);
    assert_eq!(counts(&store, prefix_scope(fork, 9)), EMPTY);
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
}

#[test]
fn c12_deleting_a_parent_timeline_purges_its_prefix_rows() {
    let fixture = fixture();
    let mut store = open(&fixture.path);
    let lonely = ok(store.create_timeline("lonely")).id();
    ok(store.append(lonely, &[draft(1, "factual")]));
    drop(store);
    insert_prefix(&fixture.path, lonely);
    assert_eq!(recorded_rows(&fixture.path, lonely), [0, 3, 2]);

    let mut store = open(&fixture.path);
    assert_eq!(counts(&store, prefix_scope(lonely, 9)), [Ok(3), Ok(2)]);
    ok(store.delete_timeline(lonely));
    assert_eq!(recorded_rows(&fixture.path, lonely), [0; 3]);
    assert_eq!(counts(&store, prefix_scope(lonely, 9)), NOT_FOUND);
}

/// Direct deletes and updates that no purge marker authorizes.
const DEPENDENCY_DELETES: [&str; 3] = [
    "DELETE FROM counterfactual_dependency_edges",
    "DELETE FROM counterfactual_dependency_nodes",
    "DELETE FROM counterfactual_dependency_records",
];
const DEPENDENCY_UPDATES: [&str; 4] = [
    "UPDATE counterfactual_dependency_records SET node_count = 0",
    "UPDATE counterfactual_dependency_nodes SET schema_id = 8",
    "UPDATE counterfactual_dependency_nodes SET timeline_id = 'moved'",
    "UPDATE counterfactual_dependency_edges SET consumer_schema_id = 8",
];

#[test]
fn c12_only_a_marked_purge_passes_the_dependency_guards() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    let mut store = open(&fixture.path);
    let other = recorded_other_fork(&mut store, root);
    drop(store);
    for delete in DEPENDENCY_DELETES {
        assert!(execute(&fixture.path, delete).is_err(), "{delete}");
        // A marker for another Timeline authorizes nothing here.
        let marked = format!(
            "BEGIN;
             INSERT INTO counterfactual_purge_fence (fork_id) VALUES ('another');
             {delete};
             COMMIT;"
        );
        assert!(execute(&fixture.path, &marked).is_err(), "{marked}");
    }
    for update in DEPENDENCY_UPDATES {
        assert!(execute(&fixture.path, update).is_err(), "{update}");
    }
    // A marker authorizes only its own Timeline's rows, so an unqualified
    // delete aborts and removes nothing.
    let mark = format!("INSERT INTO counterfactual_purge_fence (fork_id) VALUES ('{fork}');");
    for delete in DEPENDENCY_DELETES {
        let unqualified = format!("BEGIN; {mark} {delete}; COMMIT;");
        let refused = execute(&fixture.path, &unqualified);
        assert!(refused.is_err(), "{unqualified}");
    }
    assert_eq!(recorded_rows(&fixture.path, fork), [1, 2, 1]);
    assert_eq!(recorded_rows(&fixture.path, other), [1, 2, 1]);

    let scoped = format!(
        "BEGIN; {mark}
         DELETE FROM counterfactual_dependency_edges WHERE timeline_id = '{fork}';
         DELETE FROM counterfactual_dependency_nodes WHERE timeline_id = '{fork}';
         DELETE FROM counterfactual_dependency_records WHERE timeline_id = '{fork}';
         DELETE FROM counterfactual_purge_fence;
         COMMIT;"
    );
    ok(execute(&fixture.path, &scoped));
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
    assert_eq!(recorded_rows(&fixture.path, other), [1, 2, 1]);
    assert_eq!(opens_cleanly(&fixture), "");
}

/// Faults that fail one dependency statement of the delete transaction.
const DEPENDENCY_DELETE_FAULTS: [&str; 3] = [
    "BEFORE DELETE ON counterfactual_dependency_edges",
    "BEFORE DELETE ON counterfactual_dependency_nodes",
    "BEFORE DELETE ON counterfactual_dependency_records",
];

#[test]
fn c12_a_failed_purge_statement_leaves_every_row_and_no_marker() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    for fault in DEPENDENCY_DELETE_FAULTS {
        ok(execute(
            &fixture.path,
            &format!(
                "CREATE TRIGGER injected_fault {fault}
                 BEGIN SELECT RAISE(ABORT, 'injected delete fault'); END;"
            ),
        ));
        let mut faulted = open(&fixture.path);
        assert!(faulted.delete_timeline(fork).is_err(), "{fault}");
        assert_eq!(generation(&faulted, fork), 1, "{fault}");
        assert_eq!(snapshot(&fixture.path, fork), RECORDED, "{fault}");
        assert_eq!(
            scalar(
                &fixture.path,
                "SELECT count(*) FROM counterfactual_purge_fence WHERE fork_id = ?1",
                fork
            ),
            0,
            "{fault}"
        );
        drop(faulted);
        ok(execute(&fixture.path, "DROP TRIGGER injected_fault;"));
        assert_eq!(opens_cleanly(&fixture), "");
    }
    let mut recovered = open(&fixture.path);
    ok(recovered.delete_timeline(fork));
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
}

#[test]
fn c13_the_existing_methods_keep_working_and_plain_ticks_record_nothing() {
    let fixture = fixture();
    let fork = fixture.fork;
    let mut store = open(&fixture.path);
    let command = Spec::new(fork).command();
    let receipt = ok(command.committed_receipt(&SEAL, Seq::from_u64(4)));
    assert_eq!(
        store.commit_counterfactual_invalidation(&command),
        Ok(Outcome::Committed(Box::new(receipt)))
    );
    assert_eq!(
        store.append_counterfactual_tick(
            fork,
            &receipt.tick_basis(receipt.first_tick_head()),
            &tick_drafts(&[20, 21], None)
        ),
        Ok(TickOutcome::Committed {
            head: Seq::from_u64(6)
        })
    );
    assert_eq!(recorded_rows(&fixture.path, fork), [0; 3]);
    assert_eq!(counts(&store, fork_scope(fork, 1)), EMPTY);
    let recovered = store.committed_generation_receipt(at(fork, 1));
    assert_eq!(recovered, Ok(Some(receipt)));
    assert_eq!(
        store.read_generation_artifact(at(fork, 1), command.frontier().digest()),
        Ok(Some(command.frontier().as_bytes().to_vec()))
    );

    // A record may still start the set after plain Ticks of the generation.
    assert!(append_record(&mut store, fork, &sample_record()).is_ok());
    assert_eq!(recorded_rows(&fixture.path, fork), [1, 2, 1]);
    assert_eq!(counts(&store, fork_scope(fork, 1)), [Ok(2), Ok(1)]);
    let recovered = store.committed_generation_receipt(at(fork, 1));
    assert_eq!(recovered, Ok(Some(receipt)));
}

#[test]
fn c14_drifted_dependency_tables_are_rejected_on_every_open() {
    for (table, fragment) in [
        (
            "nodes",
            "UNIQUE (timeline_id, generation, artifact_digest), ",
        ),
        ("nodes", "CHECK (class BETWEEN 0 AND 4), "),
        ("nodes", "CHECK ((generation = -1) = (origin = 0)), "),
        ("edges", "CHECK (length(edge_bytes) <= 16384), "),
        ("records", "CHECK (node_count >= 0), "),
    ] {
        let fixture = fixture();
        let name = format!("counterfactual_dependency_{table}");
        let stored = text_scalar(
            &fixture.path,
            &format!("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '{name}'"),
        );
        let drifted = stored.replace(fragment, "");
        assert_ne!(drifted, stored, "{fragment}");
        ok(execute(
            &fixture.path,
            &format!("DROP TABLE {name}; {drifted};"),
        ));
        let text = fixture_path_str(&fixture);
        assert!(refuses(text, &name), "{fragment}");
    }
    for table in ["records", "nodes", "edges"] {
        let fixture = fixture();
        let name = format!("counterfactual_dependency_{table}");
        ok(execute(
            &fixture.path,
            &format!("DROP TABLE {name}; CREATE TABLE {name} (timeline_id TEXT PRIMARY KEY);"),
        ));
        let text = fixture_path_str(&fixture);
        assert!(refuses(text, &name), "{name}");
    }
}

#[test]
fn c14_a_file_without_the_dependency_tables_fails_closed_read_only() {
    let fixture = recorded_fixture();
    let fork = fixture.fork;
    let text = fixture_path_str(&fixture);
    ok(execute(
        &fixture.path,
        "DROP TABLE counterfactual_dependency_records;
         DROP TABLE counterfactual_dependency_nodes;
         DROP TABLE counterfactual_dependency_edges;",
    ));
    // A read-only open cannot create them, and the storage schema alone is
    // not enough: the file fails the exact validation.
    let refused = open_error(SqliteStore::open_read_only(text));
    let missing = "counterfactual_dependency_records";
    assert!(refused.contains(missing), "{refused}");
    // A writable open creates the additive tables empty; nothing is migrated.
    assert_eq!(open_error(SqliteStore::open(text)), "");
    assert_eq!(open_error(SqliteStore::open_read_only(text)), "");
    let mut store = open(&fixture.path);
    assert_eq!(counts(&store, fork_scope(fork, 1)), EMPTY);
    assert!(append_record(&mut store, fork, &tick_18_record()).is_ok());
    assert_eq!(recorded_rows(&fixture.path, fork), [1, 1, 1]);
}

#[test]
fn c14_a_pre_schema_file_reads_dependencies_as_not_found() {
    let fixture = recorded_fixture();
    let (fork, root) = (fixture.fork, fixture.root);
    ok(execute(
        &fixture.path,
        "DROP TABLE counterfactual_forks;
         DROP TABLE counterfactual_generations;
         DROP TABLE counterfactual_quarantine;
         DROP TABLE counterfactual_artifacts;
         DROP TABLE counterfactual_fork_tombstones;
         DROP TABLE counterfactual_purge_fence;
         DROP TABLE counterfactual_dependency_records;
         DROP TABLE counterfactual_dependency_nodes;
         DROP TABLE counterfactual_dependency_edges;",
    ));
    let mut read_only = ok(SqliteStore::open_read_only(fixture_path_str(&fixture)));
    ok(read_only.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    for scope in [
        fork_scope(fork, 1),
        prefix_scope(root, 9),
        prefix_scope(fork, 9),
    ] {
        assert_eq!(counts(&read_only, scope), NOT_FOUND, "{scope:?}");
    }
}
