use pos_core::{
    CanonicalBytes, EntityId, ErasureHostStoreV1, EventDraft, EventReadBounds, Kind, SeqRange,
    ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use std::error::Error;

fn assert_hosted_store_parity(
    store: Box<dyn ErasureHostStoreV1>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut host =
        ErasureExecutionHostV1::recover_verified_empty(store, ERASURE_MAX_INVENTORY_REQUESTS)?;
    let (timeline, event) = {
        let mut commands = host.command_sender()?;
        let timeline = commands.create_timeline("public-host-parity")?;
        let mut events = commands.append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("public.host.parity"),
                CanonicalBytes::from_static(b"payload"),
            )],
        )?;
        let event = events
            .pop()
            .ok_or_else(|| std::io::Error::other("host append returned no committed event"))?;
        (timeline, event)
    };
    let mut reads = host.read_sender()?;
    assert_eq!(
        reads.read_bounded(
            timeline.id(),
            SeqRange::all(),
            EventReadBounds::new(8, 32, 4, 4),
        )?,
        vec![event.clone()]
    );
    assert_eq!(reads.event_by_id(timeline.id(), event.id)?, Some(event));
    Ok(())
}

#[test]
fn memory_store_is_contained_by_the_public_host_api() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_hosted_store_parity(Box::new(MemoryStore::new().without_erasure_gate()))
}

#[test]
fn sqlite_store_is_contained_by_the_public_host_api() -> Result<(), Box<dyn Error + Send + Sync>> {
    let store = SqliteStore::open_in_memory()?.without_erasure_gate();
    assert_hosted_store_parity(Box::new(store))
}
