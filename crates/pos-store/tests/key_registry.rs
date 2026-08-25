#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

use pos_core::{
    CoreError, EntityId, Event, EventDraft, EventId, EventStore, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Seq, TimelineId,
};
use pos_store::sqlite::SqliteStore;

fn replace_first_bytes(value: &mut ciborium::value::Value, from: &[u8; 32], to: [u8; 32]) -> bool {
    match value {
        ciborium::value::Value::Bytes(bytes) if bytes.as_slice() == from => {
            *value = ciborium::value::Value::Bytes(to.to_vec());
            true
        }
        ciborium::value::Value::Array(values) => values
            .iter_mut()
            .any(|value| replace_first_bytes(value, from, to)),
        ciborium::value::Value::Map(entries) => entries.iter_mut().any(|(key, value)| {
            replace_first_bytes(key, from, to) || replace_first_bytes(value, from, to)
        }),
        ciborium::value::Value::Tag(_, value) => replace_first_bytes(value, from, to),
        _ => false,
    }
}

fn changed_tombstone_digest(
    registry: &KeyRegistryStateV1,
) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(registry, &mut bytes)?;
    let mut value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice())?;
    assert!(replace_first_bytes(&mut value, &[3; 32], [9; 32]));
    let mut changed_bytes = Vec::new();
    ciborium::into_writer(&value, &mut changed_bytes)?;
    Ok(ciborium::from_reader(changed_bytes.as_slice())?)
}

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
    let changed_tombstone = changed_tombstone_digest(&destroyed)?;
    assert!(store.save_key_registry(&changed_tombstone).is_err());
    assert_eq!(store.load_key_registry()?, Some(destroyed));
    Ok(())
}

#[test]
fn sqlite_key_registry_signing_and_destruction_are_ordered_across_handles(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let (registry, identity, material_digest) = registry()?;
    let mut setup = SqliteStore::open(path)?;
    setup.save_key_registry(&registry)?;
    let timeline = setup.create_timeline("registry-ordering")?;
    let timeline_id = timeline.id();
    let mut event = seed_event(&mut setup, timeline_id)?;
    event.id = EventId::new();
    drop(setup);

    let mut signing_store = SqliteStore::open(path)?;
    let mut destruction_store = SqliteStore::open(path)?;
    let destruction_request =
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([7; 32]));
    let (callback_entered_tx, callback_entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (destruction_done_tx, destruction_done_rx) = std::sync::mpsc::channel();
    let live_registry = registry.clone();

    let (sign_result, destroy_result, destruction_waited) = std::thread::scope(|scope| {
        let sign_handle = scope.spawn(move || {
            let mut callback_event = event;
            let mut callback = move |_registry: &KeyRegistryStateV1, seq: Seq| {
                callback_entered_tx
                    .send(())
                    .map_err(|_| CoreError::Storage("signing callback signal failed".to_owned()))?;
                release_rx.recv().map_err(|_| {
                    CoreError::Storage("signing callback release failed".to_owned())
                })?;
                callback_event.seq = seq;
                Ok::<Event, CoreError>(callback_event.clone())
            };
            signing_store.append_signed_authorized(timeline_id, &live_registry, &mut callback)
        });
        callback_entered_rx.recv()?;

        let destroy_handle = scope.spawn(move || {
            let result = destruction_store.destroy_key_registry(destruction_request);
            let _ = destruction_done_tx.send(());
            result
        });
        let destruction_waited = matches!(
            destruction_done_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        release_tx.send(())?;
        let sign_result = sign_handle
            .join()
            .map_err(|_| std::io::Error::other("signing thread panicked"))?;
        let destroy_result = destroy_handle
            .join()
            .map_err(|_| std::io::Error::other("destruction thread panicked"))?;
        Ok::<_, Box<dyn std::error::Error>>((sign_result, destroy_result, destruction_waited))
    })?;

    assert!(destruction_waited);
    assert!(sign_result.is_ok());
    assert!(destroy_result.is_ok());

    let mut late_signing_store = SqliteStore::open(path)?;
    let mut callback_called = false;
    let mut late_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        callback_called = true;
        Err::<Event, _>(CoreError::Storage(
            "destroyed signing key callback must not run".to_owned(),
        ))
    };
    assert!(late_signing_store
        .append_signed_authorized(timeline_id, &registry, &mut late_callback)
        .is_err());
    assert!(!callback_called);
    assert_eq!(
        late_signing_store
            .read(timeline_id, pos_core::SeqRange::all())?
            .len(),
        2
    );
    assert!(late_signing_store
        .load_key_registry()?
        .and_then(|value| value.tombstone(identity))
        .is_some());
    Ok(())
}
