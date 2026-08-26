#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

use pos_core::{
    CoreError, EntityId, Event, EventDraft, EventId, EventStore, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Seq, TimelineId,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use rusqlite::params;
use std::cell::Cell;

#[cfg_attr(coverage_nightly, coverage(off))]
fn replace_first_integer(value: &mut ciborium::value::Value) -> bool {
    match value {
        ciborium::value::Value::Integer(integer) => {
            if u64::try_from(*integer).ok() == Some(1) {
                *integer = 0.into();
                true
            } else {
                false
            }
        }
        ciborium::value::Value::Array(values) => values.iter_mut().any(replace_first_integer),
        ciborium::value::Value::Map(entries) => entries
            .iter_mut()
            .any(|(key, value)| replace_first_integer(key) || replace_first_integer(value)),
        ciborium::value::Value::Tag(_, value) => replace_first_integer(value),
        _ => false,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
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

    let mismatch_callback_called = Cell::new(false);
    let mut mismatch_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        mismatch_callback_called.set(true);
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(
            timeline.id(),
            &KeyRegistryStateV1::new(),
            &mut mismatch_callback,
        ),
        Err(CoreError::Storage(message)) if message.contains("changed during signing")
    ));
    assert!(!mismatch_callback_called.get());

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
    let (already_destroyed, same_state) = store.destroy_key_registry(valid_request)?;
    assert!(matches!(
        already_destroyed,
        pos_core::KeyDestructionOutcomeV1::AlreadyDestroyed(_)
    ));
    assert_eq!(same_state, destroyed);

    let mut restored = KeyRegistryStateV1::new();
    restored.register_key(KeyRegistrationV1::new(
        identity,
        material_digest,
        Some(pos_core::PublicKey::from_bytes([4; 32])),
    ))?;
    assert!(matches!(
        store.save_key_registry(&restored),
        Err(CoreError::Serialization(_))
    ));

    let mut encoded = Vec::new();
    ciborium::into_writer(&destroyed, &mut encoded)?;
    let mut value: ciborium::value::Value = ciborium::from_reader(encoded.as_slice())?;
    assert!(replace_first_bytes(&mut value, &[3; 32], [9; 32]));
    let mut changed_encoded = Vec::new();
    ciborium::into_writer(&value, &mut changed_encoded)?;
    let changed_tombstone: KeyRegistryStateV1 = ciborium::from_reader(changed_encoded.as_slice())?;
    assert!(matches!(
        store.save_key_registry(&changed_tombstone),
        Err(CoreError::Serialization(_))
    ));
    assert!(matches!(
        store.save_key_registry(&KeyRegistryStateV1::new()),
        Err(CoreError::Serialization(_))
    ));
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
    let live_registry = registry.clone();

    let (sign_result, destroy_result) = std::thread::scope(|scope| {
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
        if let Err(error) = callback_entered_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            let release_failed = release_tx.send(()).is_err();
            return Err(format!(
                "signing callback was not entered: {error}; release failed: {release_failed}"
            )
            .into());
        }

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
        Ok::<_, Box<dyn std::error::Error>>((sign_result, destroy_result))
    })?;

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

#[test]
fn sqlite_key_registry_load_rejects_malformed_persisted_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let (registry, _, _) = registry()?;
    let mut store = SqliteStore::open(path)?;
    store.save_key_registry(&registry)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE key_registry SET state_cbor = X'01' WHERE singleton = 1",
        [],
    )?;
    drop(connection);

    let store = SqliteStore::open(path)?;
    assert!(matches!(
        store.load_key_registry(),
        Err(CoreError::Serialization(_))
    ));
    Ok(())
}

#[test]
fn sqlite_key_registry_rejects_a_decodable_invalid_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let (registry, _, _) = registry()?;
    let mut encoded = Vec::new();
    ciborium::into_writer(&registry, &mut encoded)?;
    let mut value: ciborium::value::Value = ciborium::from_reader(encoded.as_slice())?;
    assert!(replace_first_integer(&mut value));
    let mut invalid_encoded = Vec::new();
    ciborium::into_writer(&value, &mut invalid_encoded)?;
    let invalid: KeyRegistryStateV1 = ciborium::from_reader(invalid_encoded.as_slice())?;
    assert!(invalid.validate().is_err());

    let mut store = SqliteStore::open(path)?;
    store.save_key_registry(&registry)?;
    assert!(matches!(
        store.save_key_registry(&invalid),
        Err(CoreError::Serialization(_))
    ));
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    let updated = connection.execute(
        "UPDATE key_registry SET state_cbor = ?1 WHERE singleton = 1",
        params![invalid_encoded],
    )?;
    assert_eq!(updated, 1);
    drop(connection);

    let store = SqliteStore::open(path)?;
    assert!(matches!(
        store.load_key_registry(),
        Err(CoreError::Serialization(_))
    ));
    Ok(())
}

#[test]
fn sqlite_public_read_rejects_invalid_signature_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    let mut store = SqliteStore::open(path)?;
    let timeline = store.create_timeline("invalid-signature-identity")?;
    seed_event(&mut store, timeline.id())?;
    drop(store);

    for (role, epoch) in [(-1_i64, 1_i64), (99, 1), (1, -1)] {
        let connection = rusqlite::Connection::open(path)?;
        connection.execute(
            "UPDATE events SET signature_role = ?1, signature_epoch = ?2
             WHERE timeline_id = ?3",
            params![role, epoch, timeline.id().to_string()],
        )?;
        drop(connection);

        let store = SqliteStore::open(path)?;
        assert!(matches!(
            store.read(timeline.id(), pos_core::SeqRange::all()),
            Err(CoreError::Serialization(_))
        ));
    }

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE events SET signature_role = NULL, signature_epoch = 1
         WHERE timeline_id = ?1",
        params![timeline.id().to_string()],
    )?;
    drop(connection);
    let store = SqliteStore::open(path)?;
    assert!(matches!(
        store.read(timeline.id(), pos_core::SeqRange::all()),
        Err(CoreError::Serialization(_))
    ));
    Ok(())
}

#[test]
fn sqlite_key_registry_requires_a_persisted_snapshot_for_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open_in_memory()?;
    let timeline = store.create_timeline("missing-registry")?;
    let mut callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };

    assert!(matches!(
        store.append_signed_authorized(timeline.id(), &KeyRegistryStateV1::new(), &mut callback),
        Err(CoreError::Storage(message)) if message.contains("durable key registry")
    ));
    assert!(matches!(
        store.destroy_key_registry(KeyDestructionRequestV1::new(
            KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        )),
        Err(CoreError::Storage(message)) if message.contains("durable key registry")
    ));
    Ok(())
}

#[test]
fn memory_key_registry_public_contract_covers_persistence_and_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let (registry, identity, material_digest) = registry()?;
    let mut store = MemoryStore::new();
    assert_eq!(store.load_key_registry()?, None);
    store.save_key_registry(&registry)?;
    assert_eq!(store.load_key_registry()?, Some(registry.clone()));

    let timeline = store.create_timeline("memory-registry")?;
    let mut event = store
        .append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                pos_core::Kind::new("registry.memory-seed"),
                pos_core::CanonicalBytes::from_static(b"seed"),
            )],
        )?
        .into_iter()
        .next()
        .ok_or("memory seed append returned no event")?;
    event.id = EventId::new();
    let mut callback = move |_registry: &KeyRegistryStateV1, seq: Seq| {
        event.seq = seq;
        Ok::<Event, CoreError>(event.clone())
    };
    store.append_signed_authorized(timeline.id(), &registry, &mut callback)?;

    let mut mismatch_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(
            timeline.id(),
            &KeyRegistryStateV1::new(),
            &mut mismatch_callback,
        ),
        Err(CoreError::Storage(message)) if message.contains("changed during signing")
    ));

    let mut missing_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
        Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
    };
    assert!(matches!(
        store.append_signed_authorized(TimelineId::new(), &registry, &mut missing_callback),
        Err(CoreError::TimelineNotFound(_))
    ));

    let (_, destroyed) = store.destroy_key_registry(KeyDestructionRequestV1::new(
        identity,
        material_digest,
        Hash::from_bytes([8; 32]),
    ))?;
    let request =
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([8; 32]));
    let (already_destroyed, same_state) = store.destroy_key_registry(request)?;
    assert!(matches!(
        already_destroyed,
        pos_core::KeyDestructionOutcomeV1::AlreadyDestroyed(_)
    ));
    assert_eq!(same_state, destroyed);
    assert_eq!(
        destroyed
            .key_record(identity)
            .and_then(|record| record.private_material_digest),
        None
    );
    let mut restored = KeyRegistryStateV1::new();
    restored.register_key(KeyRegistrationV1::new(
        identity,
        material_digest,
        Some(pos_core::PublicKey::from_bytes([4; 32])),
    ))?;
    assert!(matches!(
        store.save_key_registry(&restored),
        Err(CoreError::Serialization(_))
    ));
    assert_eq!(store.load_key_registry()?, Some(destroyed));
    Ok(())
}
