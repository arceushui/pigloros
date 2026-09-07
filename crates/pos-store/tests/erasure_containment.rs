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
    let second_binding = store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()));
    assert!(second_binding.is_err());

    let append_error = store.append(timeline.id(), &[draft()]).err();
    assert_eq!(
        append_error.map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    let read_error = store.read(timeline.id(), SeqRange::all()).err();
    assert_eq!(
        read_error.map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    let export_error = export_timeline_raw(&store, timeline.id()).err();
    assert_eq!(
        export_error.map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
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
