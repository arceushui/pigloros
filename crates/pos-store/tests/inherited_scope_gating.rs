//! ADR-021 Revision 4 Decision 3: stitched Fork reads apply every inherited
//! ancestor segment's own erasure decision (#499).

use std::sync::Arc;

use pos_core::{
    fork_ancestry,
    store::{EventReadBounds, EventStore, SeqRange},
    CanonicalBytes, CoreError, EntityId, ErasureContainmentGateV1, ErasureLifecycleV1, EventDraft,
    Kind, SchemaVersion, Seq, TimelineId,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

/// Root (two Events), a Fork of the root at Seq 2, and a Fork of that Fork,
/// plus an unrelated root with its own Fork, all behind one open gate.
struct Topology {
    store: Box<dyn EventStore>,
    gate: Arc<ErasureContainmentGateV1>,
    root: TimelineId,
    child: TimelineId,
    grandchild: TimelineId,
    unrelated: TimelineId,
    unrelated_fork: TimelineId,
    inherited_event: pos_core::EventId,
}

fn draft() -> EventDraft {
    EventDraft {
        entity: EntityId::new(),
        event_type: Kind::new("world.test"),
        payload: CanonicalBytes::from_vec(vec![7]),
        wall_time: None,
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
    }
}

fn topology(mut store: Box<dyn EventStore>) -> Topology {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate)).test_ok();
    let root = store.create_timeline("root").test_ok().id();
    let appended = store.append(root, &[draft(), draft()]).test_ok();
    let child = store.fork(root, Seq::from_u64(2), "child").test_ok().id();
    let grandchild = store
        .fork(child, Seq::from_u64(2), "grandchild")
        .test_ok()
        .id();
    let unrelated = store.create_timeline("unrelated").test_ok().id();
    store.append(unrelated, &[draft()]).test_ok();
    let unrelated_fork = store
        .fork(unrelated, Seq::from_u64(1), "unrelated-fork")
        .test_ok()
        .id();
    Topology {
        store,
        gate,
        root,
        child,
        grandchild,
        unrelated,
        unrelated_fork,
        inherited_event: appended[0].id,
    }
}

fn stores() -> Vec<(&'static str, Box<dyn EventStore>)> {
    vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ]
}

fn bounds() -> EventReadBounds {
    EventReadBounds::new(1_024, 64, 8, 64)
}

const fn is_frozen<T>(result: &Result<T, CoreError>) -> bool {
    matches!(result, Err(CoreError::ErasureAccessFrozen))
}

/// Every stitched read of `timeline` is refused with the closed error.
fn assert_stitched_reads_frozen(topology: &Topology, timeline: TimelineId, label: &str) {
    let store = topology.store.as_ref();
    assert!(
        is_frozen(&store.read(timeline, SeqRange::all())),
        "{label}: read"
    );
    assert!(
        is_frozen(&store.read_bounded(timeline, SeqRange::all(), bounds())),
        "{label}: read_bounded"
    );
    assert!(
        is_frozen(&store.read_event_by_id(timeline, topology.inherited_event)),
        "{label}: read_event_by_id"
    );
    assert!(
        is_frozen(&store.chain_hash_at(timeline, Seq::from_u64(1))),
        "{label}: chain_hash_at"
    );
}

fn assert_unrelated_reads_normally(topology: &Topology, label: &str) {
    let store = topology.store.as_ref();
    for timeline in [topology.unrelated, topology.unrelated_fork] {
        assert_eq!(
            store.read(timeline, SeqRange::all()).test_ok().len(),
            1,
            "{label}"
        );
        assert_eq!(
            store
                .read_bounded(timeline, SeqRange::all(), bounds())
                .test_ok()
                .len(),
            1,
            "{label}"
        );
        assert!(store.chain_hash_at(timeline, Seq::from_u64(1)).is_ok());
    }
}

#[test]
fn stitched_reads_include_inherited_segments_while_every_scope_is_open() {
    for (name, store) in stores() {
        let topology = topology(store);
        let store = topology.store.as_ref();
        for timeline in [topology.child, topology.grandchild] {
            assert_eq!(store.read(timeline, SeqRange::all()).test_ok().len(), 2);
            assert_eq!(
                store
                    .read_bounded(timeline, SeqRange::all(), bounds())
                    .test_ok()
                    .len(),
                2,
                "{name}"
            );
            let inherited = store
                .read_event_by_id(timeline, topology.inherited_event)
                .test_ok();
            assert_eq!(
                inherited.map(|event| event.seq),
                Some(Seq::from_u64(1)),
                "{name}"
            );
            assert_eq!(
                store.chain_hash_at(timeline, Seq::from_u64(2)).test_ok(),
                store
                    .chain_hash_at(topology.root, Seq::from_u64(2))
                    .test_ok(),
                "{name}"
            );
        }
        assert_eq!(
            fork_ancestry(store, topology.grandchild)
                .test_ok()
                .iter()
                .map(|meta| meta.id)
                .collect::<Vec<_>>(),
            [topology.grandchild, topology.child, topology.root],
            "{name}"
        );
    }
}

#[test]
fn a_frozen_ancestor_fails_every_stitched_read_of_its_descendants_closed() {
    for (name, store) in stores() {
        let mut topology = topology(store);
        let own = topology.store.append(topology.child, &[draft()]).test_ok();
        topology.gate.freeze_timeline_for_test(topology.root);
        assert_stitched_reads_frozen(&topology, topology.root, name);
        assert_stitched_reads_frozen(&topology, topology.child, name);
        assert_stitched_reads_frozen(&topology, topology.grandchild, name);
        // A Fork's own segment is not stitched and keeps its own decision.
        let own_segment = topology
            .store
            .read_own(topology.child, SeqRange::all())
            .test_ok();
        assert_eq!(
            own_segment.iter().map(|event| event.id).collect::<Vec<_>>(),
            [own[0].id],
            "{name}"
        );
        assert_unrelated_reads_normally(&topology, name);
    }
}

#[test]
fn a_frozen_intermediate_fork_fails_only_its_own_lineage_closed() {
    for (name, store) in stores() {
        let topology = topology(store);
        topology.gate.freeze_timeline_for_test(topology.child);
        assert_stitched_reads_frozen(&topology, topology.grandchild, name);
        assert_eq!(
            topology
                .store
                .read(topology.root, SeqRange::all())
                .test_ok()
                .len(),
            2,
            "{name}"
        );
        assert_unrelated_reads_normally(&topology, name);
    }
}

#[test]
fn a_completed_ancestor_erasure_keeps_inherited_reads_denied() {
    for (name, store) in stores() {
        let topology = topology(store);
        assert_eq!(
            topology
                .gate
                .complete_timeline_erasure_for_test(topology.root),
            Ok(ErasureLifecycleV1::Complete)
        );
        // Inherited reads follow exactly what a direct ancestor read gets.
        assert_stitched_reads_frozen(&topology, topology.root, name);
        assert_stitched_reads_frozen(&topology, topology.child, name);
        assert_stitched_reads_frozen(&topology, topology.grandchild, name);
        assert_unrelated_reads_normally(&topology, name);
    }
}
