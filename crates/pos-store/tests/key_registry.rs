#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

use pos_core::{
    CoreError, EntityId, Event, EventDraft, EventId, EventStore, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Seq, TimelineId,
};
use pos_store::sqlite::SqliteStore;

fn registry() -> Result<(KeyRegistryStateV1, KeyIdentityV1, Hash), Box<dyn std::error::Error>> {
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let material_digest = Hash::from_bytes([3; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material_digest,
        Some(pos_core::PublicKey::from_bytes([4; 32])),
    ))?;
    Ok((registry, identity, material_digest))
}

fn seed_event(store: &mut SqliteStore, timeline: TimelineId) -> Result<Event, CoreError> {
    store
        .append(
            timeline,
            &[EventDraft::new(
                EntityId::new(),
                pos_core::Kind::new("registry.seed"),
                pos_core::CanonicalBytes::from_static(b"seed"),
            )],
        )?
        .into_iter()
        .next()
        .ok_or_else(|| CoreError::Storage("seed append returned no event".to_owned()))
}

#[test]
fn sqlite_key_registry_public_contract_covers_persistence_and_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, identity, material_digest) = registry()?;
    let mut store = SqliteStore::open_in_memory()?;
    assert!(store.load_key_registry()?.is_none());
    store.save_key_registry(&registry)?;
    assert_eq!(store.load_key_registry()?, Some(registry.clone()));

    let timeline = store.create_timeline("registry-contract")?;
    let mut event = seed_event(&mut store, timeline.id())?;
    event.id = EventId::new();
    let mut callback = move |_registry: &KeyRegistryStateV1, seq: Seq| {
        event.seq = seq;
        Ok::<Event, CoreError>(event.clone())
    };
    store.append_signed_authorized(timeline.id(), &registry, &mut callback)?;
    assert_eq!(
        store.read(timeline.id(), pos_core::SeqRange::all())?.len(),
        2
    );

    let mut mismatch_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(
            timeline.id(),
            &KeyRegistryStateV1::new(),
            &mut mismatch_callback,
        ),
        Err(CoreError::Storage(_))
    ));

    let mut missing_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(TimelineId::new(), &registry, &mut missing_callback,),
        Err(CoreError::TimelineNotFound(_))
    ));

    let mut callback_failure = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback failed".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(timeline.id(), &registry, &mut callback_failure),
        Err(CoreError::Storage(_))
    ));

    let invalid_request = KeyDestructionRequestV1::new(
        identity,
        Hash::from_bytes([9; 32]),
        Hash::from_bytes([2; 32]),
    );
    assert!(matches!(
        store.destroy_key_registry(invalid_request),
        Err(CoreError::Storage(_))
    ));

    let valid_request =
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([2; 32]));
    let (_, destroyed) = store.destroy_key_registry(valid_request)?;
    assert!(destroyed.key_record(identity).is_some());
    assert!(store.save_key_registry(&KeyRegistryStateV1::new()).is_err());
    assert_eq!(store.load_key_registry()?, Some(destroyed));
    Ok(())
}
