//! The erasure authority read view (ADR-136 companion §2.6) is a read-only
//! window onto one adapter snapshot.

use pos_core::{
    EntityId, ErasureAuthorityTimelineRowV1, ErasureContainmentGateV1,
    ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1, EventStore, Hash, TimelineId,
    TimelineMeta, TimelineMode,
};
use pos_runtime::{ErasureAuthorityReadViewV1, ErasureAuthoritySnapshotViewV1};
use pos_store::memory::MemoryStore;
use std::sync::Arc;
use ulid::Ulid;

#[test]
fn the_view_reports_exactly_its_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let owned = TimelineId::from_ulid(Ulid::from_bytes([2; 16]));
    let owner = EntityId::from_ulid(Ulid::from_bytes([9; 16]));
    store.create_timeline_with_meta(TimelineMeta {
        id: owned,
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

    let view = ErasureAuthoritySnapshotViewV1::new(snapshot.clone());
    let read: &dyn ErasureAuthorityReadViewV1 = &view;
    assert_eq!(read.snapshot_generation(), generation);
    assert_eq!(read.topology(), [owned].as_slice());
    assert_eq!(
        read.timeline_meta(owned),
        Some(&ErasureAuthorityTimelineRowV1 {
            id: owned,
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

    // The view is a value over its snapshot. The non-mutation check over a
    // committed request lives in `erasure_coordinator_host_public.rs`.
    assert_eq!(
        store.erasure_authority_snapshot_with_limits(limits)?,
        snapshot
    );
    assert_eq!(view, ErasureAuthoritySnapshotViewV1::new(snapshot));
    Ok(())
}
