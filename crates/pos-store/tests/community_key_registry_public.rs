//! Registry persistence only; these fixtures do not qualify a key vault/owner.

use pos_core::{
    deletion_receipt, ErasureContainmentGateV1, EventStore, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryErrorV1, KeyRegistryHistoricalDecryptionPortV1,
    KeyRegistryStateV1, KeyRoleV1,
};
use pos_store::memory::MemoryStore;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity() -> KeyIdentityV1 {
    KeyIdentityV1::new(
        "community-registry-test",
        KeyRoleV1::CommunityArtifactEncryption,
        1,
    )
}

fn seed(store: &mut impl EventStore) -> TestResult {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity(),
        Hash::from_bytes([1; 32]),
        None,
    ))?;
    store.save_key_registry(&registry)?;
    assert_eq!(store.load_key_registry()?, Some(registry));
    Ok(())
}

fn destroy(store: &mut (impl EventStore + KeyRegistryHistoricalDecryptionPortV1)) -> TestResult {
    assert_eq!(
        store.with_decryption_authorization(identity(), Hash::from_bytes([1; 32]), || 42)?,
        42
    );
    let request = KeyDestructionRequestV1::new(
        identity(),
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
    );
    store.begin_key_registry_destruction(request)?;
    assert_eq!(
        store.with_decryption_authorization(identity(), Hash::from_bytes([1; 32]), || ()),
        Err(KeyRegistryErrorV1::DestructionPending)
    );
    store.complete_key_registry_destruction(request, deletion_receipt(&request))?;
    assert_destroyed(store)
}

fn assert_destroyed(
    store: &mut (impl EventStore + KeyRegistryHistoricalDecryptionPortV1),
) -> TestResult {
    assert_eq!(
        store.with_decryption_authorization(identity(), Hash::from_bytes([1; 32]), || ()),
        Err(KeyRegistryErrorV1::Destroyed)
    );
    let registry = store.load_key_registry()?.ok_or("missing registry")?;
    let tombstone = registry
        .tombstone(identity())
        .ok_or("missing community tombstone")?;
    assert_eq!(tombstone.identity, identity());
    assert_eq!(
        registry.highest_epoch(&identity().owner_id, identity().role),
        Some(1)
    );
    Ok(())
}

#[test]
fn retained_memory_registry_preserves_community_role_and_irreversible_destruction() -> TestResult {
    let mut store = MemoryStore::new();
    seed(&mut store)?;
    destroy(&mut store)
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_registry_reopen_preserves_community_role_and_tombstone() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("registry.sqlite3");
    let path = database
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    {
        let mut store = pos_store::sqlite::SqliteStore::open(path)?;
        seed(&mut store)?;
    }
    {
        let mut store = pos_store::sqlite::SqliteStore::open(path)?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        destroy(&mut store)?;
    }
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    assert_destroyed(&mut store)
}
