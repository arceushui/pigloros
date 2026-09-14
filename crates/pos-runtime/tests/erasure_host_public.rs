use pos_core::{
    CanonicalBytes, EntityId, ErasureHostErrorV1, ErasureProtectedOperationV1, EventDraft,
    EventReadBounds, Kind, SeqRange, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;
use std::error::Error;

fn assert_hosted_store_parity(config: StoreConfig) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut host =
        ErasureExecutionHostV1::open_verified_empty(config, ERASURE_MAX_INVENTORY_REQUESTS)?;
    let (timeline, event) = {
        let mut commands = host.command_sender()?;
        let timeline = commands.create_timeline("public-host-parity")?;
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("public.host.parity"),
            CanonicalBytes::from_static(b"payload"),
        );
        let mut fenced_append = Err(ErasureHostErrorV1::RecoveryUnavailable);
        let mut effect = |commands: &mut pos_runtime::ErasureCommandSenderV1<'_>| {
            fenced_append = commands.timeline(timeline.id()).and_then(|metadata| {
                metadata
                    .ok_or(ErasureHostErrorV1::AdapterFailure)
                    .and_then(|_| commands.append(timeline.id(), std::slice::from_ref(&draft)))
            });
        };
        commands.with_protected_effect_fence(
            timeline.id(),
            ErasureProtectedOperationV1::ProposedAction,
            &mut effect,
        )?;
        let mut events = fenced_append?;
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
