    let alternate_source: Vec<_> = batch
        .records()
        .iter()
        .map(|record| ArtifactRegistrationInputV1 {
            owner_id: *record.owner_id(),
            artifact_bytes: record.artifact_bytes().to_vec(),
            registration_cbor: record.registration().canonical_cbor().to_vec(),
        })
        .collect();
    let mut store = MemoryStore::new();
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );

    let (alternate_root, alternate_inputs) = alternate_root_with_same_operation(alternate_source)?;
    let alternate = prepare_artifact_registration_batch_v1(
        owner_id,
        alternate_root,
        alternate_inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    assert_eq!(
        store.commit_artifact_registration_batch(alternate),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::Conflict)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    assert!(store
        .read_artifact_registration(&owner_id, alternate_root)?
        .is_none());
    Ok(())
}

#[test]
fn persisted_graph_rejects_structurally_valid_but_wrong_mrm1_registration_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut rows: Vec<_> = batch
        .records()
        .iter()
        .map(|record| {
            ArtifactRegistrationCatalogRowV1::from_persisted(
                *record.owner_id(),
                record.artifact_class(),
                record.artifact_digest(),
                record.registration_address(),
                record.artifact_bytes().to_vec(),
                record.registration().canonical_cbor(),
            )
        })
        .collect::<Result<_, _>>()?;
    let root_index = rows
        .iter()
        .position(|row| row.registration_address() == root_address)
        .ok_or_else(|| std::io::Error::other("MRM1 root row was not present"))?;
    let root = rows[root_index].clone();
    let mut fields = (*root.registration().fields()).clone();
    fields.data_class = ArtifactDataClassV1::PublicRecord;
    let tampered_registration = ArtifactRegistrationV1::new(fields)?;
    let tampered_address = tampered_registration.address();
    rows[root_index] = ArtifactRegistrationCatalogRowV1::from_persisted(
        owner_id,
        ErasureArtifactClassV1::ReproManifest,
        root.artifact_digest(),
        tampered_address,
        root.artifact_bytes().to_vec(),
        tampered_registration.canonical_cbor(),
    )?;

    assert_eq!(
        validate_artifact_registration_catalog_graph_v1(tampered_address, &rows),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_is_visible_across_handles_and_after_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut writer = pos_store::sqlite::SqliteStore::open(path)?;
    let reader = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut writer, &batch)?;
    assert_eq!(
        writer.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );
    assert!(reader
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    drop(reader);
    drop(writer);

    let reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert!(reopened
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_rejects_a_second_root_for_the_same_operation_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let alternate_source: Vec<_> = batch
        .records()
        .iter()
        .map(|record| ArtifactRegistrationInputV1 {
            owner_id: *record.owner_id(),
            artifact_bytes: record.artifact_bytes().to_vec(),
            registration_cbor: record.registration().canonical_cbor().to_vec(),
        })
        .collect();
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );

    let (alternate_root, alternate_inputs) = alternate_root_with_same_operation(alternate_source)?;
    let alternate = prepare_artifact_registration_batch_v1(
        owner_id,
        alternate_root,
        alternate_inputs,
        &TestOnlyStructuralOwnerVerifier,
    )?;
    assert_eq!(
        store.commit_artifact_registration_batch(alternate),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::Conflict)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_some());
    assert!(store
        .read_artifact_registration(&owner_id, alternate_root)?
        .is_none());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_reports_a_missing_operation_index_as_corruption(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "DELETE FROM artifact_registration_operations WHERE owner_id = ?1",
        [owner_id.as_str()],
    )?;
    drop(connection);

    let mut reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    let (_, _, retry) = prepared_repro_manifest()?;
    assert_eq!(
        reopened.commit_artifact_registration_batch(retry),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_reports_modified_artifact_bytes_as_corruption(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE artifact_registrations SET artifact_bytes = ?1
         WHERE registration_address = ?2",
        rusqlite::params![
            b"corrupt MRM1 bytes".as_slice(),
            root_address.as_bytes().as_slice()
        ],
    )?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_rejects_changed_closed_recorder_bytes_on_read(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE adapter_recording_sessions SET transcript_cbor = ?1
         WHERE owner_reference = ?2 AND run_operation_id = ?3",
        rusqlite::params![
            b"changed closed MAT1".as_slice(),
            ArtifactRegistrationV1::owner_reference(&owner_id)
                .as_bytes()
                .as_slice(),
            [0x51_u8; 32].as_slice(),
        ],
    )?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_rolls_back_the_entire_closure_when_root_commit_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    drop(pos_store::sqlite::SqliteStore::open(path)?);
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let connection = rusqlite::Connection::open(path)?;
    let mut root_hex = String::with_capacity(64);
    for byte in root_address.as_bytes() {
        write!(&mut root_hex, "{byte:02x}")?;
    }
    connection.execute_batch(&format!(
        "CREATE TRIGGER fail_root_registration BEFORE INSERT ON artifact_registrations
         WHEN NEW.registration_address = X'{root_hex}'
         BEGIN SELECT RAISE(ABORT, 'injected root commit failure'); END;"
    ))?;
    drop(connection);

    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    close_repro_manifest_recording(&mut store, &batch)?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::StorageFailure)
    );
    assert!(store
        .read_artifact_registration(&owner_id, root_address)?
        .is_none());
    let connection = rusqlite::Connection::open(path)?;
    let row_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM artifact_registrations", [], |row| {
            row.get(0)
        })?;
    assert_eq!(row_count, 0);
    Ok(())
}

#[test]
fn memory_event_store_adapter_recording_port_covers_the_public_state_machine(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    exercise_event_store_adapter_recording(&mut store, Hash::from_bytes([0x7e; 32]))
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_event_store_adapter_recording_port_covers_the_public_state_machine(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    exercise_event_store_adapter_recording(&mut store, Hash::from_bytes([0x7f; 32]))
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_event_store_exposes_the_artifact_registration_port(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    close_repro_manifest_recording(&mut store, &batch)?;
    let retry = batch.clone();
    assert_eq!(
        pos_core::store::EventStore::commit_artifact_registration_batch(&mut store, batch)?,
        ArtifactRegistrationCommitOutcomeV1::Applied
    );
    assert_eq!(
        pos_core::store::EventStore::commit_artifact_registration_batch(&mut store, retry)?,
        ArtifactRegistrationCommitOutcomeV1::ExactRetry
    );
    assert!(pos_core::store::EventStore::read_artifact_registration(
        &store,
        &owner_id,
        root_address,
    )?
    .is_some());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_commit_requires_the_complete_schema() -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?;
    let mut store = pos_store::sqlite::SqliteStore::open(path)?;
    let (_, _, batch) = prepared_repro_manifest()?;
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch("DROP TABLE artifact_registration_operations")?;
    assert_eq!(
        store.commit_artifact_registration_batch(batch),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::StorageFailure)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_reads_fail_closed_for_missing_and_malformed_durable_rows(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?
        .to_owned();
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut store = pos_store::sqlite::SqliteStore::open(&path)?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM artifact_registrations WHERE registration_address = ?1",
        [root_address.as_bytes().as_slice()],
    )?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(&path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );

    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?
        .to_owned();
    let (owner_id, root_address, batch) = prepared_repro_manifest()?;
    let mut store = pos_store::sqlite::SqliteStore::open(&path)?;
    close_repro_manifest_recording(&mut store, &batch)?;
    store.commit_artifact_registration_batch(batch)?;
    assert_eq!(
        store.read_artifact_registration(&OwnerIdV1::from_static("another-owner"), root_address)?,
        None
    );
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
    connection.execute(
        "UPDATE artifact_registrations SET artifact_class = 99
         WHERE registration_address = ?1",
        [root_address.as_bytes().as_slice()],
    )?;
    connection.execute_batch("PRAGMA ignore_check_constraints = OFF;")?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(&path)?;
    assert_eq!(
        reopened.read_artifact_registration(&owner_id, root_address),
        Err(pos_core::ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_catalog_read_treats_an_absent_schema_as_an_empty_catalog(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?
        .to_owned();
    let store = pos_store::sqlite::SqliteStore::open(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "DROP TABLE artifact_registration_operations;
         DROP TABLE artifact_registrations",
    )?;
    assert_eq!(
        store.read_artifact_registration(
            &OwnerIdV1::from_static("missing-schema-owner"),
            Hash::from_bytes([0x92; 32]),
        )?,
        None
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_adapter_recording_rejects_malformed_durable_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?
        .to_owned();
    let (session, reservation) = adapter_recording_fixture(Hash::from_bytes([0x93; 32]))?;
    let owner_reference = session.owner_reference();
    let run_operation_id = session.run_operation_id();
    let mut store = pos_store::sqlite::SqliteStore::open(&path)?;
    store.open_adapter_recording_session(session)?;
    store.reserve_adapter_call(owner_reference, run_operation_id, reservation)?;
    store.complete_adapter_call(
        owner_reference,
        run_operation_id,
        0,
        b"exact response".to_vec(),
    )?;
    store.close_adapter_recording_session(owner_reference, run_operation_id)?;
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
    connection.execute(
        "UPDATE adapter_recording_sessions SET transcript_cbor = NULL
         WHERE owner_reference = ?1 AND run_operation_id = ?2",
        rusqlite::params![
            owner_reference.as_bytes().as_slice(),
            run_operation_id.as_bytes().as_slice(),
        ],
    )?;
    connection.execute_batch("PRAGMA ignore_check_constraints = OFF;")?;
    drop(connection);

    let reopened = pos_store::sqlite::SqliteStore::open(&path)?;
    assert_eq!(
        reopened.read_closed_adapter_recording_session(owner_reference, run_operation_id),
        Err(AdapterRecordingStoreErrorV1::CorruptState)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_adapter_recording_requires_its_complete_schema() -> Result<(), Box<dyn std::error::Error>>
{
    let database = tempfile::NamedTempFile::new()?;
    let path = database
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary path is not UTF-8"))?
        .to_owned();
    let (session, _) = adapter_recording_fixture(Hash::from_bytes([0x94; 32]))?;
    let mut store = pos_store::sqlite::SqliteStore::open(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("DROP TABLE adapter_recording_calls")?;
    assert_eq!(
        store.open_adapter_recording_session(session),
        Err(AdapterRecordingStoreErrorV1::StorageFailure)
    );
    Ok(())
}