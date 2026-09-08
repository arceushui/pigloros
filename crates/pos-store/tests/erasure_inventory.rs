//! Public parity tests for complete erasure inventory snapshots.

use std::sync::Arc;

use pos_core::{
    store::EventStore, ErasureContainmentGateV1, ErasureErrorV1, ErasureInventoryPersistencePortV1,
};
use pos_store::memory::MemoryStore;
use pos_store::{open_erasure_host_store, StoreConfig};

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

#[test]
fn host_factory_preserves_the_complete_inventory_capability(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = open_erasure_host_store(StoreConfig::Memory)?;
    let snapshot = store.complete_erasure_inventory_snapshot(4)?;
    assert!(snapshot.request_heads().is_empty());
    assert!(snapshot.topology().is_empty());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_proves_complete_empty_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open_in_memory()?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()))?;
    assert_verified_empty_snapshot(store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_host_factory_preserves_the_complete_inventory_capability(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = open_erasure_host_store(StoreConfig::SqliteInMemory)?;
    let snapshot = store.complete_erasure_inventory_snapshot(4)?;
    assert!(snapshot.request_heads().is_empty());
    assert!(snapshot.topology().is_empty());
    Ok(())
}
