//! The erasure authority read view (ADR-136 companion §2.6) is a read-only
//! window onto one adapter snapshot, and only the execution host builds it.

use pos_core::{
    EntityId, ErasureAuthorityTimelineRowV1, ErasureContainmentGateV1,
    ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1, EventStore, Hash, TimelineId,
    TimelineMeta, TimelineMode,
};
use pos_runtime::{
    ErasureAuthorityReadViewV1, ErasureCoordinatorCompositionV1, ErasureExecutionHostV1,
};
use pos_store::memory::MemoryStore;
use std::sync::Arc;
use ulid::Ulid;

#[test]
fn the_view_reports_exactly_its_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let owned_timeline = TimelineId::from_ulid(Ulid::from_bytes([2; 16]));
    let owner = EntityId::from_ulid(Ulid::from_bytes([9; 16]));
    store.create_timeline_with_meta(TimelineMeta {
        id: owned_timeline,
        mode: TimelineMode::Live,
        name: Some("owned".to_owned()),
        owner: Some(owner),
        fork_point: None,
    })?;
    let identity = Hash::from_bytes([5; 32]);
    store.init_erasure_store_identity(identity)?;
    let limits = ErasureRecoveryLimitsV1::from_maximum_requests(4)?;
    let snapshot = store.erasure_authority_snapshot_with_limits(limits)?;
    let generation = snapshot.inventory().generation();

    let mut host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
        store,
        &ErasureCoordinatorCompositionV1::closed(),
        limits,
    )?;
    let view = host.authority_view()?;
    let read: &dyn ErasureAuthorityReadViewV1 = &view;
    assert_eq!(read.snapshot_generation(), generation);
    assert_eq!(read.topology(), [owned_timeline].as_slice());
    assert_eq!(
        read.timeline_meta(owned_timeline),
        Some(&ErasureAuthorityTimelineRowV1 {
            id: owned_timeline,
            owner: Some(owner),
            fork_point: None,
        })
    );
    assert_eq!(
        read.timeline_meta(TimelineId::from_ulid(Ulid::from_bytes([3; 16]))),
        None
    );
    assert_eq!(read.request_count(), 0);
    assert_eq!(read.store_identity(), Some(identity));

    // A second view of the unchanged store reports the same snapshot. The
    // non-mutation check over a committed request lives in
    // `erasure_coordinator_host_public.rs`.
    let again = host.authority_view()?;
    assert_eq!(again.snapshot_generation(), generation);
    assert_eq!(again.topology(), read.topology());
    Ok(())
}
