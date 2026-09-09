use pos_core::{
    CanonicalBytes, EntityId, ErasureErrorV1, ErasurePersistenceInventorySnapshotV1,
    ErasureVerifiedInventoryQueryV1, ErasureVerifiedInventoryV1, EventDraft, EventReadBounds, Kind,
    SeqRange, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;
use std::error::Error;

struct OneInventory(Option<ErasureVerifiedInventoryV1>);

impl ErasureVerifiedInventoryQueryV1 for OneInventory {
    fn verified_inventory(
        &mut self,
        _maximum_requests: usize,
    ) -> Result<ErasureVerifiedInventoryV1, ErasureErrorV1> {
        self.0.take().ok_or(ErasureErrorV1::ProvenanceMissing)
    }
}

fn empty_inventory() -> Result<ErasureVerifiedInventoryV1, ErasureErrorV1> {
    ErasurePersistenceInventorySnapshotV1::new(
        Vec::new(),
        Vec::new(),
        ERASURE_MAX_INVENTORY_REQUESTS,
    )
    .and_then(|snapshot| {
        ErasureVerifiedInventoryV1::from_verified_empty_snapshot(
            snapshot,
            ERASURE_MAX_INVENTORY_REQUESTS,
        )
    })
}

fn assert_hosted_store_parity(config: StoreConfig) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut host =
        ErasureExecutionHostV1::open_verified_empty(config, ERASURE_MAX_INVENTORY_REQUESTS)?;
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
    assert_hosted_store_parity(StoreConfig::Memory)
}

#[test]
fn sqlite_store_is_contained_by_the_public_host_api() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_hosted_store_parity(StoreConfig::SqliteInMemory)
}

fn assert_stale_inventory_closes_host(
    config: StoreConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut host =
        ErasureExecutionHostV1::open_verified_empty(config, ERASURE_MAX_INVENTORY_REQUESTS)?;
    host.command_sender()?.create_timeline("newer-topology")?;
    let mut stale = OneInventory(Some(empty_inventory()?));
    assert!(host
        .install_inventory(&mut stale, ERASURE_MAX_INVENTORY_REQUESTS)
        .is_err());
    assert!(host.read_sender().is_err());
    Ok(())
}

#[test]
fn stale_inventory_cannot_reopen_memory_host() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_stale_inventory_closes_host(StoreConfig::Memory)
}

#[test]
fn stale_inventory_cannot_reopen_sqlite_host() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_stale_inventory_closes_host(StoreConfig::SqliteInMemory)
}

#[test]
fn unavailable_or_invalid_inventory_keeps_public_host_closed(
) -> Result<(), Box<dyn Error + Send + Sync>> {
    assert!(ErasureExecutionHostV1::open_from_verified_query(
        StoreConfig::Memory,
        &mut OneInventory(None),
        ERASURE_MAX_INVENTORY_REQUESTS,
    )
    .is_err());
    assert!(ErasureExecutionHostV1::open_from_verified_query(
        StoreConfig::Memory,
        &mut OneInventory(Some(empty_inventory()?)),
        0,
    )
    .is_err());
    Ok(())
}

#[test]
fn verified_query_constructors_accept_public_trait_objects(
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut generic_inventory = OneInventory(Some(empty_inventory()?));
    let generic_query: &mut dyn ErasureVerifiedInventoryQueryV1 = &mut generic_inventory;
    let mut generic = ErasureExecutionHostV1::open_from_verified_query(
        StoreConfig::Memory,
        generic_query,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    assert!(generic.read_sender().is_ok());

    let mut gateway_inventory = OneInventory(Some(empty_inventory()?));
    let gateway_query: &mut dyn ErasureVerifiedInventoryQueryV1 = &mut gateway_inventory;
    let mut gateway = ErasureExecutionHostV1::open_gateway_from_verified_query(
        StoreConfig::Memory,
        gateway_query,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    assert!(gateway.command_sender().is_ok());

    let mut unavailable_generic = OneInventory(None);
    assert!(ErasureExecutionHostV1::open_from_verified_query(
        StoreConfig::Memory,
        &mut unavailable_generic,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )
    .is_err());

    let mut unavailable_gateway = OneInventory(None);
    assert!(ErasureExecutionHostV1::open_gateway_from_verified_query(
        StoreConfig::Memory,
        &mut unavailable_gateway,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )
    .is_err());
    Ok(())
}
