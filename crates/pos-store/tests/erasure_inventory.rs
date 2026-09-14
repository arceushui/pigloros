//! Public parity tests for complete erasure inventory snapshots.

use std::sync::Arc;

use pos_core::{
    store::EventStore, ErasureContainmentGateV1, ErasureErrorV1, ErasureInventoryPersistencePortV1,
    TimelineId, TimelineMeta, TimelineMode,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

fn open_memory() -> Result<MemoryStore, Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()))?;
    Ok(store)
}

fn assert_verified_empty_snapshot<S>(mut store: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: EventStore + ErasureInventoryPersistencePortV1,
{
    let second = store.create_timeline("second")?.meta.id;
    let first = store.create_timeline("first")?.meta.id;
    let snapshot = store.complete_erasure_inventory_snapshot(4)?;
    let mut expected = vec![first, second];
    expected.sort_unstable();
    assert!(snapshot.request_heads().is_empty());
    assert_eq!(snapshot.topology(), expected);
    assert_eq!(
        store.complete_erasure_inventory_snapshot(0),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}

#[test]
fn memory_proves_complete_empty_inventory() -> Result<(), Box<dyn std::error::Error>> {
    assert_verified_empty_snapshot(open_memory()?)
}

#[cfg(feature = "sqlite")]
#[test]
fn memory_and_sqlite_share_the_complete_inventory_generation(
) -> Result<(), Box<dyn std::error::Error>> {
    let first = TimelineMeta {
        id: TimelineId::from_ulid(Ulid::from(1_u128)),
        mode: TimelineMode::Live,
        name: Some("first".to_owned()),
        owner: None,
        fork_point: None,
    };
    let second = TimelineMeta {
        id: TimelineId::from_ulid(Ulid::from(2_u128)),
        mode: TimelineMode::Live,
        name: Some("second".to_owned()),
        owner: None,
        fork_point: None,
    };
    let mut memory = open_memory()?;
    let mut sqlite = SqliteStore::open_in_memory()?;
    sqlite.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()))?;

    for store in [
        &mut memory as &mut dyn EventStore,
        &mut sqlite as &mut dyn EventStore,
    ] {
        store.create_timeline_with_meta(first.clone())?;
        store.create_timeline_with_meta(second.clone())?;
    }

    assert_eq!(
        memory.complete_erasure_inventory_snapshot(4)?.generation(),
        sqlite.complete_erasure_inventory_snapshot(4)?.generation(),
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_proves_complete_empty_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open_in_memory()?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()))?;
    assert_verified_empty_snapshot(store)
}
