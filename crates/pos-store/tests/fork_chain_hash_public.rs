//! Exact logical-cut hashes across inherited, empty, and local Fork segments.

use pos_core::{
    CanonicalBytes, CoreError, EntityId, ErasureContainmentGateV1, Event, EventDraft, EventStore,
    Hash, Kind, Seq, TimelineId,
};
use pos_store::memory::MemoryStore;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn draft(value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new("test.fork-cut"),
        CanonicalBytes::from_vec(vec![value]),
    )
}

fn check_cuts(store: &dyn EventStore, timeline: TimelineId, expected: &[Event]) -> TestResult {
    let mut hash = Hash::zero();
    assert_eq!(store.chain_hash_at(timeline, Seq::ZERO)?, hash);
    for (index, event) in expected.iter().enumerate() {
        // Fold the independently selected append results, never a Store read
        // or another call to the implementation's segment-selection logic.
        hash =
            pos_crypto::chain::hash_event(&hash, event.id.to_string().as_bytes(), &event.payload);
        let cut = Seq::from_u64(u64::try_from(index)? + 1);
        for _ in 0..2 {
            assert_eq!(store.chain_hash_at(timeline, cut)?, hash);
        }
    }
    let expected_head = u64::try_from(expected.len())?;
    assert!(matches!(
        store.chain_hash_at(timeline, Seq::from_u64(expected_head + 1)),
        Err(CoreError::ForkBeyondHead { fork_seq, head })
            if fork_seq == expected_head + 1 && head == expected_head
    ));
    Ok(())
}

fn nested_cuts(store: &mut dyn EventStore) -> TestResult {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let root = store.create_timeline("root")?.id();
    let root_events = store.append(root, &[draft(1), draft(2), draft(99)])?;
    let child = store.fork(root, Seq::from_u64(2), "child")?.id();
    let child_events = store.append(child, &[draft(3), draft(98)])?;
    let empty = store.fork(child, Seq::from_u64(3), "empty")?.id();
    let leaf = store.fork(empty, Seq::from_u64(3), "leaf")?.id();
    let leaf_events = store.append(leaf, &[draft(4), draft(5)])?;
    check_cuts(store, root, &root_events)?;
    let mut expected = root_events[..2].to_vec();
    expected.extend_from_slice(&child_events);
    check_cuts(store, child, &expected)?;
    expected.truncate(3);
    check_cuts(store, empty, &expected)?;
    expected.extend_from_slice(&leaf_events);
    check_cuts(store, leaf, &expected)?;
    // Later ancestor appends cannot move the already-selected boundaries.
    store.append(root, &[draft(97)])?;
    store.append(child, &[draft(96)])?;
    check_cuts(store, leaf, &expected)?;
    let zero = store.fork(root, Seq::ZERO, "zero-prefix")?.id();
    check_cuts(store, zero, &[])?;
    let local = store.append(zero, &[draft(6)])?;
    check_cuts(store, zero, &local)
}

#[test]
fn memory_hashes_every_nested_cut_without_reincluding_parent_suffixes() -> TestResult {
    nested_cuts(&mut MemoryStore::new())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_has_the_same_public_logical_cut_contract() -> TestResult {
    nested_cuts(&mut pos_store::sqlite::SqliteStore::open(":memory:")?)
}
