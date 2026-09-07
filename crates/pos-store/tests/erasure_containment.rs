use std::sync::Arc;

use pos_core::{
    store::{export_timeline_raw, EventStore, SeqRange},
    CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureGate, ErasureProtectedOperationV1,
    EventDraft, Kind, SchemaVersion,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

fn draft() -> EventDraft {
    EventDraft {
        entity: EntityId::new(),
        event_type: Kind::new("world.test"),
        payload: CanonicalBytes::from_vec(vec![1]),
        wall_time: None,
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
    }
}

fn assert_blocked<S: EventStore>(mut store: S) -> Result<(), Box<dyn std::error::Error>> {
    let timeline = store.create_timeline("erasure-containment")?;
    let gate = Arc::new(ErasureContainmentGateV1::new());
    gate.block_timeline(timeline.id());
    let gate_for_store: Arc<dyn ErasureGate> = gate.clone();
    store.bind_erasure_gate(gate_for_store)?;
    assert!(matches!(
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new())),
        Err(pos_core::CoreError::Storage(_))
    ));

    assert!(matches!(
        store.append(timeline.id(), &[draft()]),
        Err(pos_core::CoreError::ErasureContainmentUnavailable)
    ));
    assert!(matches!(
        store.read(timeline.id(), SeqRange::all()),
        Err(pos_core::CoreError::ErasureContainmentUnavailable)
    ));
    assert!(matches!(
        export_timeline_raw(&store, timeline.id()),
        Err(pos_core::CoreError::ErasureContainmentUnavailable)
    ));
    assert_eq!(
        gate.authorize(timeline.id(), ErasureProtectedOperationV1::Export),
        Err(pos_core::ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

#[test]
fn memory_store_fails_closed_for_unavailable_erasure_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_blocked(MemoryStore::new())
}

#[test]
fn sqlite_store_fails_closed_for_unavailable_erasure_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_blocked(SqliteStore::open_in_memory()?)
}
