#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg(feature = "sqlite")]

use pos_core::{
    AppendDedupKey, AppendDedupScope, AppendIdentity, AppendOrDuplicateOutcome, CanonicalBytes,
    CoreError, EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1, EventDraft,
    EventId, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, SeqRange, WallTime,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg_attr(coverage_nightly, coverage(off))]
fn draft(entity: EntityId, event_type: &str) -> EventDraft {
    EventDraft::new(
        entity,
        Kind::new(event_type),
        CanonicalBytes::from_static(b"private"),
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn bind(store: &mut impl EventStore) -> Result<(), CoreError> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn assert_refused<T>(result: Result<T, CoreError>) {
    assert!(result.is_err_and(|error| {
        assert_eq!(
            error.to_string(),
            "plaintext Persona Preferences are unavailable for this subject"
        );
        matches!(error, CoreError::SubjectPlaintextPreferenceRefused)
    }));
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn identity(subject: EntityId, epoch: u64) -> Result<KeyIdentityV1, Box<dyn std::error::Error>> {
    let owner = pos_crypto::subject_key::subject_owner_id(subject)?;
    Ok(KeyIdentityV1::new(
        owner.as_str(),
        KeyRoleV1::SubjectDataEncryption,
        epoch,
    ))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn register(registry: &mut KeyRegistryStateV1, key: KeyIdentityV1, material: u8) -> TestResult {
    registry.register_key(KeyRegistrationV1::new(
        key,
        Hash::from_bytes([material; 32]),
        None,
    ))?;
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn contract(store: &mut impl EventStore) -> TestResult {
    bind(store)?;
    let timeline = store.create_timeline("subject-preferences")?.id();
    let subject = EntityId::new();
    let plaintext = draft(subject, "persona.preference");
    let historical = store
        .append(timeline, std::slice::from_ref(&plaintext))?
        .remove(0);
    let dedup = AppendIdentity::new(
        AppendDedupKey::from_keyed_hash([1; 32]),
        AppendDedupScope::from_keyed_hash([2; 32]),
    );
    let admitted = WallTime::from_micros(1);
    store.append_or_duplicate(timeline, dedup, admitted, plaintext.clone())?;

    // Neither a different role for this exact owner nor a subject record for
    // another entity makes this entity a subject.
    let mut registry = KeyRegistryStateV1::new();
    let key = identity(subject, 1)?;
    register(
        &mut registry,
        KeyIdentityV1::from_parts(key.owner_id, KeyRoleV1::ExportRecipientEncryption, 1),
        11,
    )?;
    register(&mut registry, identity(EntityId::new(), 1)?, 12)?;
    store.save_key_registry(&registry)?;
    store.append(timeline, std::slice::from_ref(&plaintext))?;

    register(&mut registry, key, 13)?;
    store.save_key_registry(&registry)?;
    let before = store.read(timeline, SeqRange::all())?;
    let head = store
        .get_timeline(timeline)?
        .ok_or("missing Timeline")?
        .head;
    assert_refused(store.append(timeline, std::slice::from_ref(&plaintext)));
    let mixed = [draft(EntityId::new(), "other"), plaintext.clone()];
    assert_refused(store.append(timeline, &mixed));
    assert_refused(store.append_bounded(timeline, &mixed, u64::MAX));

    let fresh_dedup = AppendIdentity::new(
        AppendDedupKey::from_keyed_hash([3; 32]),
        AppendDedupScope::from_keyed_hash([4; 32]),
    );
    assert_refused(store.append_or_duplicate(timeline, fresh_dedup, admitted, plaintext.clone()));
    // Retrying an existing admission adds no Event and preserves history.
    assert!(matches!(
        store.append_or_duplicate(timeline, dedup, admitted, plaintext.clone())?,
        AppendOrDuplicateOutcome::Duplicate { .. }
    ));

    let mut committed = historical.clone();
    committed.id = EventId::new();
    committed.seq = head.next();
    committed.origin = None;
    assert_refused(store.append_committed(timeline, &[committed]));
    assert_eq!(
        store
            .get_timeline(timeline)?
            .ok_or("missing Timeline")?
            .head,
        head
    );
    assert_eq!(store.read(timeline, SeqRange::all())?, before);
    assert_eq!(before[0], historical);

    // Rotation, pending destruction and a committed tombstone never restore
    // plaintext authority; another entity and another Event type still work.
    let rotated = identity(subject, 2)?;
    register(&mut registry, rotated, 14)?;
    store.save_key_registry(&registry)?;
    assert_refused(store.append(timeline, std::slice::from_ref(&plaintext)));
    let request = KeyDestructionRequestV1::new(
        rotated,
        Hash::from_bytes([14; 32]),
        Hash::from_bytes([15; 32]),
    );
    store.begin_key_registry_destruction(request)?;
    assert_refused(store.append(timeline, std::slice::from_ref(&plaintext)));
    store.complete_key_registry_destruction(request, pos_core::deletion_receipt(&request))?;
    assert_refused(store.append(timeline, std::slice::from_ref(&plaintext)));
    let first_request =
        KeyDestructionRequestV1::new(key, Hash::from_bytes([13; 32]), Hash::from_bytes([16; 32]));
    store.begin_key_registry_destruction(first_request)?;
    store.complete_key_registry_destruction(
        first_request,
        pos_core::deletion_receipt(&first_request),
    )?;
    assert_refused(store.append(timeline, std::slice::from_ref(&plaintext)));
    store.append(timeline, &[draft(subject, "persona.preference.v2")])?;
    store.append(timeline, &[draft(EntityId::new(), "persona.preference")])?;
    Ok(())
}

#[test]
fn memory_refuses_new_subject_preferences_through_public_append_seams() -> TestResult {
    contract(&mut MemoryStore::new())
}

#[test]
fn sqlite_refuses_new_subject_preferences_through_public_append_seams() -> TestResult {
    contract(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_observes_registration_from_another_handle_before_appending() -> TestResult {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("database path is not UTF-8")?;
    let mut first = SqliteStore::open(path)?;
    bind(&mut first)?;
    let timeline = first.create_timeline("two-writers")?.id();
    let subject = EntityId::new();
    first.append(timeline, &[draft(subject, "persona.preference")])?;
    assert!(first.load_key_registry()?.is_none());

    let mut second = SqliteStore::open(path)?;
    bind(&mut second)?;
    let mut registry = KeyRegistryStateV1::new();
    register(&mut registry, identity(subject, 1)?, 31)?;
    second.save_key_registry(&registry)?;
    // The existing erasure inventory refuses any external write until its
    // recovery snapshot is refreshed. Preserve that prerequisite, then prove
    // the append observes the new durable registry instead of the old None.
    assert!(matches!(
        first.append(timeline, &[draft(subject, "persona.preference")]),
        Err(CoreError::ErasureContainmentUnavailable)
    ));
    first.complete_erasure_inventory_snapshot(64)?;
    assert_refused(first.append(timeline, &[draft(subject, "persona.preference")]));
    assert_eq!(first.read(timeline, SeqRange::all())?.len(), 1);
    Ok(())
}

#[test]
fn sqlite_refuses_plaintext_when_registry_bytes_are_unreadable() -> TestResult {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or("database path is not UTF-8")?;
    let mut setup = SqliteStore::open(path)?;
    bind(&mut setup)?;
    let timeline = setup.create_timeline("bad-registry")?.id();
    drop(setup);
    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "INSERT INTO key_registry (singleton, state_cbor) VALUES (1, X'ff')",
        [],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(path)?;
    bind(&mut store)?;
    assert_refused(store.append(timeline, &[draft(EntityId::new(), "persona.preference")]));
    assert!(store.read(timeline, SeqRange::all())?.is_empty());
    store.append(timeline, &[draft(EntityId::new(), "other")])?;
    Ok(())
}
