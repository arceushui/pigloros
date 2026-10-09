//! Public-interface tests for the `MemoryStore` ADR-064 Revision 3 factual
//! prefix reads (Redmine #596).
//!
//! The tests run over rows seeded through the public `test-support` seeding
//! function, so this file is feature-gated by design (`required-features` in
//! `Cargo.toml`); the conformance tests C1 to C13 stay in
//! `counterfactual_dependency_memory_public.rs`, which seeding does not gate.

use std::sync::Arc;

use pos_core::counterfactual_store::test_fixtures::SeededFactualTickV1;
use pos_core::{
    CanonicalBytes, CoreError, CounterfactualDependencyReadPortV1, CounterfactualStoreErrorV1,
    DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    DependencyPageCursorV1, DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1,
    DependencyReadScopeV1, EntityId, ErasureContainmentGateV1, EventDraft, FactualCutV1,
    FactualHeadV1, FactualOwnerIdV1, FactualPrefixReadPortV1, Hash, Kind,
    RecordedDependencyClassV1, RecordedNodeOriginV1, RecordedSetCountsV1, Seq,
    TickDependencyRecordV1, TimelineId,
};
use pos_store::{memory::MemoryStore, EventStore};

type StoreError = CounterfactualStoreErrorV1;
type Coordinate = DependencyNodeCoordinateV1;
type NodeRow = DependencyNodeRecordV1;
type EdgeRow = DependencyEdgeRecordV1;
type TickRecord = TickDependencyRecordV1;
type Scope = DependencyReadScopeV1;

const COMMITTED: RecordedNodeOriginV1 = RecordedNodeOriginV1::Committed;

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


const OWNER_A: &str = "plugin:a";
const OWNER_B: &str = "plugin:b";
const OWNER_C: &str = "plugin:c";
/// Digest salt of the root Timeline's nodes, and of the Fork's.
const ROOT_SALT: u8 = 0;
const FORK_SALT: u8 = 100;

/// The artifact digest of a seeded node, apart per Timeline by `salt`.
const fn seeded_digest(salt: u8, tick: u8, ordinal: u8) -> Hash {
    hash(salt + tick * 16 + ordinal)
}

/// A committed node of `owner` at `tick`: the step node at ordinal zero, then
/// the Event-backed nodes.
fn seeded_node(salt: u8, tick: u8, owner: &str, ordinal: u8) -> NodeRow {
    let digest = seeded_digest(salt, tick, ordinal);
    let at = u64::from(tick);
    let owner_id = owner.to_owned();
    let position = u32::from(ordinal);
    let made = Coordinate::try_new(at, 1, owner_id, position, 7, digest);
    let coordinate = ok(made);
    let class = RecordedDependencyClassV1::EndogenousRecomputed;
    node_of(&coordinate, class, COMMITTED, Vec::new())
}

/// A committed factual Tick owning the `seq` range `first..=last`: a step node
/// of `owner` and one Event-backed node per `seq`.
fn seeded_tick(salt: u8, tick: u8, owner: &str, first: u64, last: u64) -> SeededFactualTickV1 {
    let mut nodes = vec![seeded_node(salt, tick, owner, 0)];
    let mut event_nodes = Vec::new();
    for (ordinal, seq) in (1_u8..).zip(first..=last) {
        nodes.push(seeded_node(salt, tick, owner, ordinal));
        event_nodes.push((Seq::from_u64(seq), seeded_digest(salt, tick, ordinal)));
    }
    let at = u64::from(tick);
    let record = ok(TickRecord::try_new(at, COMMITTED, nodes, Vec::new()));
    SeededFactualTickV1 {
        record,
        first_seq: Seq::from_u64(first),
        last_seq: Seq::from_u64(last),
        event_nodes,
    }
}

/// The root Timeline's Ticks: 1 owns `seq` 2 to 4, 2 owns 5, 3 owns 6 to 8.
fn root_ticks() -> [SeededFactualTickV1; 3] {
    [
        seeded_tick(ROOT_SALT, 1, OWNER_A, 2, 4),
        seeded_tick(ROOT_SALT, 2, OWNER_B, 5, 5),
        seeded_tick(ROOT_SALT, 3, OWNER_C, 6, 8),
    ]
}

/// The Fork's own Tick: 3 owns `seq` 9.
fn fork_tick() -> SeededFactualTickV1 {
    seeded_tick(FORK_SALT, 3, OWNER_A, 9, 9)
}

/// A root Timeline with 14 Events and three seeded Ticks, a Fork of it at
/// `seq` 6 that is mid-Tick at the first `seq` of Tick 3 (cut Tick 2) and owns
/// Tick 3 at `seq` 9, and a Fork of that Fork at `seq` 7.
struct Lineage {
    store: MemoryStore,
    gate: Arc<ErasureContainmentGateV1>,
    root: TimelineId,
    mid: TimelineId,
    deep: TimelineId,
}

fn lineage() -> Lineage {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut store = MemoryStore::new();
    ok(store.bind_erasure_gate(Arc::clone(&gate)));
    let root = ok(store.create_timeline("factual-root")).id();
    let events: Vec<EventDraft> = (0..14).map(draft).collect();
    ok(store.append(root, &events));
    ok(store.seed_factual_prefix(root, &root_ticks()));
    let mid = fork_at(&mut store, root, 6);
    let own: Vec<EventDraft> = (0..3).map(draft).collect();
    ok(store.append(mid, &own));
    ok(store.seed_factual_prefix(mid, &[fork_tick()]));
    let deep = fork_at(&mut store, mid, 7);
    Lineage {
        store,
        gate,
        root,
        mid,
        deep,
    }
}

fn fork_at(store: &mut MemoryStore, parent: TimelineId, seq: u64) -> TimelineId {
    let name = format!("factual-fork-{parent}-{seq}");
    ok(store.fork(parent, Seq::from_u64(seq), &name)).id()
}

fn head_of(store: &MemoryStore, timeline: TimelineId) -> FactualHeadV1 {
    ok(store.last_committed_factual_tick(timeline))
}

const fn head(tick: u64, last_seq: u64) -> FactualHeadV1 {
    FactualHeadV1 {
        tick,
        last_seq: Seq::from_u64(last_seq),
    }
}

const fn boundary(cut_tick: u64) -> FactualCutV1 {
    FactualCutV1::Boundary { cut_tick }
}

const fn mid_tick(cut_tick: u64, split_tick: u64) -> FactualCutV1 {
    FactualCutV1::MidTick {
        cut_tick,
        split_tick,
    }
}

fn owner(name: &str) -> FactualOwnerIdV1 {
    FactualOwnerIdV1::new(name.to_owned())
}

fn seq_list(values: &[u64]) -> Vec<Seq> {
    values.iter().copied().map(Seq::from_u64).collect()
}

#[test]
fn f1_the_head_is_total_and_inherits_the_cut_tick() {
    let mut lineage = lineage();
    let (root, mid, deep) = (lineage.root, lineage.mid, lineage.deep);

    assert_eq!(head_of(&lineage.store, root), head(3, 8));
    assert_eq!(head_of(&lineage.store, mid), head(3, 9));
    // The Fork at 7 sees Tick 2 of the root, which ends at 5, and nothing of
    // the Fork's own Tick 3, which ends above the cut.
    assert_eq!(head_of(&lineage.store, deep), head(2, 5));

    let cases = [
        (8, head(3, 8)),
        (6, head(2, 5)),
        (5, head(2, 5)),
        (4, head(1, 4)),
        // Inside Tick 1, and in the legacy range before the first Tick.
        (3, head(0, 0)),
        (1, head(0, 0)),
    ];
    for (index, (seq, expected)) in cases.into_iter().enumerate() {
        let name = format!("factual-head-{index}-{seq}");
        let child = ok(lineage.store.fork(root, Seq::from_u64(seq), &name)).id();
        assert_eq!(head_of(&lineage.store, child), expected);
    }
    let bare = ok(lineage.store.create_timeline("factual-bare")).id();
    assert_eq!(head_of(&lineage.store, bare), head(0, 0));
}

#[test]
fn f2_cut_tick_at_locates_legacy_boundary_tail_and_mid_tick_cuts() {
    let lineage = lineage();
    let cases = [
        // The legacy range before the first Tick.
        (1, boundary(0)),
        // The first `seq` of a multi-Event Tick, and strictly inside it.
        (2, mid_tick(0, 1)),
        (3, mid_tick(0, 1)),
        (4, boundary(1)),
        // The single Event of a one-Event Tick is a boundary.
        (5, boundary(2)),
        (6, mid_tick(2, 3)),
        (7, mid_tick(2, 3)),
        (8, boundary(3)),
        // The unrecorded tail after the last Tick.
        (12, boundary(3)),
    ];
    for (seq, expected) in cases {
        let cut = lineage.store.cut_tick_at(lineage.root, Seq::from_u64(seq));
        assert_eq!(ok(cut), expected);
    }
}

#[test]
fn f3_a_straddling_grandparent_tick_is_invisible_to_the_nested_cut() {
    let lineage = lineage();
    // The Fork at 6 keeps the root's Ticks through 2. The root's Tick 3 spans
    // 6 to 8, so a cut at 6 or 7 is mid-Tick for the root and a boundary here.
    let cases = [
        (3, mid_tick(0, 1)),
        (4, boundary(1)),
        (5, boundary(2)),
        (6, boundary(2)),
        (7, boundary(2)),
        (9, boundary(3)),
        (10, boundary(3)),
    ];
    for (seq, expected) in cases {
        let cut = lineage.store.cut_tick_at(lineage.mid, Seq::from_u64(seq));
        assert_eq!(ok(cut), expected);
    }
    let root_cut = lineage.store.cut_tick_at(lineage.root, Seq::from_u64(7));
    assert_eq!(ok(root_cut), mid_tick(2, 3));
}

#[test]
fn f4_event_nodes_resolve_through_ancestry_and_stop_at_each_cut() {
    let lineage = lineage();
    let store = &lineage.store;

    let seqs = seq_list(&[1, 2, 5, 6, 8, 9, 10]);
    let resolved = ok(store.nodes_for_committed_events(lineage.mid, &seqs));
    // The root's Tick 3 binds 6 and 8 above the Fork's cut.
    let expected = vec![
        None,
        Some(seeded_node(ROOT_SALT, 1, OWNER_A, 1)),
        Some(seeded_node(ROOT_SALT, 2, OWNER_B, 1)),
        None,
        None,
        Some(seeded_node(FORK_SALT, 3, OWNER_A, 1)),
        None,
    ];
    assert_eq!(resolved, expected);

    let own = seq_list(&[6, 8]);
    let resolved = ok(store.nodes_for_committed_events(lineage.root, &own));
    let expected = vec![
        Some(seeded_node(ROOT_SALT, 3, OWNER_C, 1)),
        Some(seeded_node(ROOT_SALT, 3, OWNER_C, 3)),
    ];
    assert_eq!(resolved, expected);

    // The deepest Fork cuts the Fork's own Tick away too.
    let both = seq_list(&[2, 9]);
    let resolved = ok(store.nodes_for_committed_events(lineage.deep, &both));
    let expected = vec![Some(seeded_node(ROOT_SALT, 1, OWNER_A, 1)), None];
    assert_eq!(resolved, expected);
}

#[test]
fn f4_a_binding_to_an_unrecorded_node_resolves_to_nothing() {
    let mut store = MemoryStore::new();
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    ok(store.bind_erasure_gate(gate));
    let root = ok(store.create_timeline("factual-dangling")).id();
    let mut tick = seeded_tick(ROOT_SALT, 1, OWNER_A, 1, 1);
    tick.event_nodes = vec![(Seq::from_u64(1), hash(250))];
    ok(store.seed_factual_prefix(root, &[tick]));

    let resolved = ok(store.nodes_for_committed_events(root, &seq_list(&[1])));

    assert_eq!(resolved, vec![None]);
}

#[test]
fn f5_nodes_resolve_by_digest_with_their_bound_seq() {
    let lineage = lineage();
    let store = &lineage.store;
    let digests = [
        seeded_digest(ROOT_SALT, 1, 0),
        seeded_digest(ROOT_SALT, 1, 1),
        // The root's Tick 3 is above the Fork's cut.
        seeded_digest(ROOT_SALT, 3, 0),
        seeded_digest(FORK_SALT, 3, 0),
        seeded_digest(FORK_SALT, 3, 1),
        hash(250),
    ];

    let resolved = ok(store.nodes_by_digest(lineage.mid, &digests));

    let expected = vec![
        Some((seeded_node(ROOT_SALT, 1, OWNER_A, 0), None)),
        Some((
            seeded_node(ROOT_SALT, 1, OWNER_A, 1),
            Some(Seq::from_u64(2)),
        )),
        None,
        Some((seeded_node(FORK_SALT, 3, OWNER_A, 0), None)),
        Some((
            seeded_node(FORK_SALT, 3, OWNER_A, 1),
            Some(Seq::from_u64(9)),
        )),
        None,
    ];
    assert_eq!(resolved, expected);
    let own = ok(store.nodes_by_digest(lineage.root, &digests[2..3]));
    let step = seeded_node(ROOT_SALT, 3, OWNER_C, 0);
    assert_eq!(own, vec![Some((step, None))]);
}

#[test]
fn f6_the_latest_step_node_of_an_owner_stops_at_each_cut() {
    let lineage = lineage();
    let store = &lineage.store;
    let step = |salt, tick, name| Some(seeded_node(salt, tick, name, 0));
    let latest = |timeline, name: &str| ok(store.last_step_node(timeline, &owner(name)));

    assert_eq!(latest(lineage.root, OWNER_A), step(ROOT_SALT, 1, OWNER_A));
    assert_eq!(latest(lineage.root, OWNER_B), step(ROOT_SALT, 2, OWNER_B));
    assert_eq!(latest(lineage.root, OWNER_C), step(ROOT_SALT, 3, OWNER_C));
    assert_eq!(latest(lineage.root, "plugin:none"), None);
    // The Fork's own Tick wins over the inherited one; the root's Tick 3 is
    // above its cut.
    assert_eq!(latest(lineage.mid, OWNER_A), step(FORK_SALT, 3, OWNER_A));
    assert_eq!(latest(lineage.mid, OWNER_B), step(ROOT_SALT, 2, OWNER_B));
    assert_eq!(latest(lineage.mid, OWNER_C), None);
    // The deepest Fork cuts the Fork's own Tick away too.
    assert_eq!(latest(lineage.deep, OWNER_A), step(ROOT_SALT, 1, OWNER_A));
    assert_eq!(latest(lineage.deep, OWNER_B), step(ROOT_SALT, 2, OWNER_B));
}

#[test]
fn f7_set_counts_cover_only_the_timelines_own_set() {
    let lineage = lineage();
    let store = &lineage.store;
    let counts = |nodes| RecordedSetCountsV1 {
        nodes,
        edges: 0,
        inputs: 0,
    };

    assert_eq!(ok(store.factual_set_counts(lineage.root)), counts(10));
    assert_eq!(ok(store.factual_set_counts(lineage.mid)), counts(2));
    assert_eq!(ok(store.factual_set_counts(lineage.deep)), counts(0));
}

#[test]
fn f8_parent_prefix_reads_stitch_ancestors_through_their_cuts() {
    let lineage = lineage();
    let store = &lineage.store;
    let [first, second, third] = root_ticks();
    let rows = |ticks: &[&SeededFactualTickV1]| -> Vec<NodeRow> {
        let nodes = ticks
            .iter()
            .flat_map(|seeded| seeded.record.nodes().to_vec());
        sorted(nodes.collect())
    };
    let inherited = rows(&[&first, &second]);
    let own = fork_tick();
    let stitched = rows(&[&first, &second, &own]);

    for limit in [2, 3, 50] {
        let mid_scope = prefix_scope(lineage.mid, 9);
        assert_eq!(ok(collect_nodes(store, mid_scope, limit)), stitched);
        let deep_scope = prefix_scope(lineage.deep, 9);
        assert_eq!(ok(collect_nodes(store, deep_scope, limit)), inherited);
        let root_scope = prefix_scope(lineage.root, 9);
        let all = rows(&[&first, &second, &third]);
        assert_eq!(ok(collect_nodes(store, root_scope, limit)), all);
    }
    // The request bound applies on top of each cut.
    let bounded = collect_nodes(store, prefix_scope(lineage.mid, 1), 3);
    assert_eq!(ok(bounded), rows(&[&first]));
    let edges = collect_edges(store, prefix_scope(lineage.mid, 9), 3);
    assert_eq!(ok(edges), Vec::<EdgeRow>::new());
}

/// The case of a deleted ancestor under a live Fork is unreachable on Memory,
/// which refuses to delete a Timeline while Forks of it exist, so Timelines are
/// deleted leaf first here.
#[test]
fn f9_missing_and_deleted_timelines_are_not_found() {
    let mut lineage = lineage();
    let (root, mid, deep) = (lineage.root, lineage.mid, lineage.deep);
    let unknown = TimelineId::new();
    let store = &mut lineage.store;

    assert!(matches!(
        err(store.last_committed_factual_tick(unknown)),
        CoreError::TimelineNotFound(_)
    ));
    assert!(matches!(
        err(store.seed_factual_prefix(unknown, &[])),
        CoreError::TimelineNotFound(_)
    ));
    assert_eq!(
        err(collect_nodes(store, prefix_scope(unknown, 5), 2)),
        StoreError::ForkNotFound
    );

    // Deleting a Timeline purges its set; the others stay readable.
    ok(store.delete_timeline(deep));
    ok(store.delete_timeline(mid));
    assert!(matches!(
        err(store.factual_set_counts(mid)),
        CoreError::TimelineNotFound(_)
    ));
    assert_eq!(head_of(store, root), head(3, 8));
    ok(store.delete_timeline(root));
    assert!(matches!(
        err(store.last_committed_factual_tick(root)),
        CoreError::TimelineNotFound(_)
    ));
    assert_eq!(
        err(collect_nodes(store, prefix_scope(root, 5), 2)),
        StoreError::ForkNotFound
    );
}

#[test]
fn f9_factual_reads_fail_closed_without_a_gate_or_past_a_blocked_ancestor() {
    let blocked = lineage();
    let (root, deep) = (blocked.root, blocked.deep);
    blocked.gate.block_timeline(root);
    let seqs = seq_list(&[2]);
    let step = owner(OWNER_A);

    for timeline in [root, deep] {
        let store = &blocked.store;
        assert!(store.last_committed_factual_tick(timeline).is_err());
        assert!(store.nodes_for_committed_events(timeline, &seqs).is_err());
        assert!(store.last_step_node(timeline, &step).is_err());
        assert!(store.factual_set_counts(timeline).is_err());
    }

    let open = lineage();
    let root = open.root;
    let ungated = open.store.without_erasure_gate();
    assert!(matches!(
        err(ungated.last_committed_factual_tick(root)),
        CoreError::ErasureContainmentUnavailable
    ));
    assert!(matches!(
        err(ungated.factual_set_counts(root)),
        CoreError::ErasureContainmentUnavailable
    ));
}

#[test]
fn f2_cut_tick_at_is_a_boundary_on_a_timeline_without_ticks_and_at_seq_zero() {
    let mut lineage = lineage();
    let bare = ok(lineage.store.create_timeline("factual-bare-cut")).id();
    let events: Vec<EventDraft> = (0..3).map(draft).collect();
    ok(lineage.store.append(bare, &events));
    let store = &lineage.store;

    // No Tick is recorded, so every `seq`, beyond the head too, is a boundary.
    for seq in [0, 1, 3, 50] {
        let cut = store.cut_tick_at(bare, Seq::from_u64(seq));
        assert_eq!(ok(cut), boundary(0));
    }
    let zero = store.cut_tick_at(bare, Seq::ZERO);
    assert_eq!(ok(zero), boundary(0));
    // `Seq::ZERO` precedes the first Tick of a recorded Timeline too.
    let root_zero = store.cut_tick_at(lineage.root, Seq::ZERO);
    assert_eq!(ok(root_zero), boundary(0));
}

#[test]
fn f3_a_split_tick_clipped_at_two_levels_is_a_boundary_for_the_deepest_fork() {
    let lineage = lineage();
    // The Fork at 7 sees the root through 6 and the middle Fork through 7. The
    // root's Tick 3 (6 to 8) and the middle Fork's Tick 3 (9) both end above
    // those limits, so neither splits a cut here; only Tick 1 (2 to 4) does.
    let cases = [
        (3, mid_tick(0, 1)),
        (4, boundary(1)),
        (5, boundary(2)),
        (6, boundary(2)),
        (7, boundary(2)),
        (8, boundary(2)),
        (9, boundary(2)),
        (12, boundary(2)),
    ];
    for (seq, expected) in cases {
        let cut = lineage.store.cut_tick_at(lineage.deep, Seq::from_u64(seq));
        assert_eq!(ok(cut), expected);
    }
}

#[test]
fn f8_paging_resumes_after_a_cursor_inside_an_ancestor_segment() {
    let lineage = lineage();
    let store = &lineage.store;
    let scope = prefix_scope(lineage.mid, 9);
    let all = ok(collect_nodes(store, scope, 50));
    assert_eq!(all.len(), 8);

    // Rows 0 to 5 are the root's segment, rows 6 and 7 the Fork's own.
    for (index, limit) in [(1_usize, 50_usize), (1, 3), (5, 50), (5, 1)] {
        let after = Some(all[index].cursor());
        let page = ok(store.read_dependency_nodes(&request(scope, after, limit)));
        let rest = &all[index + 1..];
        assert_eq!(page.items(), &rest[..rest.len().min(limit)]);
        assert_eq!(page.next().is_some(), rest.len() > limit);
    }
}
