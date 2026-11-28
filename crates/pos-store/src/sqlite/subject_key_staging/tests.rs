//! ADR-137 P1, P3, P3a, P5 and D4: the staging table, the P3 store steps, the
//! P5 store recovery and the registry reads.

use std::sync::Arc;

use pos_core::{
    deletion_receipt, error::CoreError, ids::TimelineId, ErasureContainmentGateV1, EventStore,
    Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1,
    OwnerIdV1, PublicKey,
};
use rusqlite::{params, types::Value, Connection};

use super::{
    sealed, PendingKeyDestructionsV1, SubjectKeyLifecycleV1 as Lifecycle,
    SubjectKeyStagingRecordV1, MAX_STAGING_RECORDS, OUTCOME_UNKNOWN, OWNER_SIGNING_OWNER_ID,
    OWNER_SIGNING_ROLE, REFUSED,
};
use crate::sqlite::{SqliteStore, FAIL_BEGIN_IMMEDIATE};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STORE: [u8; 20] = [7; 20];
const OTHER_STORE: [u8; 20] = [8; 20];

fn owner(number: u128) -> String {
    format!("subject:{number:032x}")
}

fn digest(seed: u8) -> Hash {
    Hash::from_bytes([seed; 32])
}

/// An in-memory store that holds an empty registry, as every owner store does
/// once its first identity is registered.
fn registry_store() -> Result<SqliteStore, Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open_in_memory()?;
    store.save_key_registry(&KeyRegistryStateV1::new())?;
    Ok(store)
}

fn load_registry(store: &SqliteStore) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>> {
    Ok(store.load_key_registry()?.ok_or("no registry")?)
}

fn identity(owner_id: &str, epoch: u64) -> Result<KeyIdentityV1, Box<dyn std::error::Error>> {
    Ok(KeyIdentityV1::new(
        OwnerIdV1::new(owner_id)?,
        KeyRoleV1::SubjectDataEncryption,
        epoch,
    ))
}

/// Register the identity in the registry, bypassing the staging flow.
fn register_directly(store: &mut SqliteStore, owner_id: &str, epoch: u64, seed: u8) -> TestResult {
    let mut registry = load_registry(store)?;
    registry.register_key(KeyRegistrationV1::new(
        identity(owner_id, epoch)?,
        digest(seed),
        None,
    ))?;
    store.save_key_registry(&registry)?;
    Ok(())
}

fn destruction_request(
    owner_id: &str,
    epoch: u64,
    seed: u8,
) -> Result<KeyDestructionRequestV1, Box<dyn std::error::Error>> {
    Ok(KeyDestructionRequestV1::new(
        identity(owner_id, epoch)?,
        digest(seed),
        digest(200),
    ))
}

fn begin_destruction(
    store: &mut SqliteStore,
    owner_id: &str,
    epoch: u64,
    seed: u8,
) -> Result<KeyDestructionRequestV1, Box<dyn std::error::Error>> {
    let request = destruction_request(owner_id, epoch, seed)?;
    store.begin_key_registry_destruction(request)?;
    Ok(request)
}

fn rows(conn: &Connection) -> rusqlite::Result<Vec<(String, i64, Vec<u8>)>> {
    let mut statement = conn
        .prepare("SELECT owner_id, epoch, store_file_id FROM subject_key_staging ORDER BY 1, 2")?;
    let collected = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect();
    collected
}

fn row_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM subject_key_staging", [], |row| {
        row.get(0)
    })
}

fn row_of(owner_id: &str, epoch: i64, store: &[u8]) -> (String, i64, Vec<u8>) {
    (owner_id.to_owned(), epoch, store.to_vec())
}

fn table_exists(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'subject_key_staging'",
        [],
        |row| row.get(0),
    )
}

fn fence(conn: &Connection, timeline: TimelineId, lifecycle: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO erasure_fence_rows (timeline_id, erasure_request_id, lifecycle_code)
         VALUES (?1, ?2, ?3)",
        params![timeline.to_string(), [3_u8; 32].as_slice(), lifecycle],
    )
}

#[track_caller]
fn assert_refused<T: std::fmt::Debug>(result: &Result<T, CoreError>) {
    assert!(
        matches!(result, Err(CoreError::Storage(text)) if text == REFUSED),
        "{result:?}"
    );
}

fn raw_insert(conn: &Connection, values: &[Value; 3]) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO subject_key_staging (owner_id, epoch, store_file_id) VALUES (?1, ?2, ?3)",
        params![values[0], values[1], values[2]],
    )
}

fn good_row() -> [Value; 3] {
    [
        Value::Text(owner(1)),
        Value::Integer(1),
        Value::Blob(STORE.to_vec()),
    ]
}

fn with(index: usize, value: Value) -> [Value; 3] {
    let mut values = good_row();
    values[index] = value;
    values
}

#[test]
fn a_writable_open_creates_the_table_and_a_reopen_keeps_its_rows() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("staging.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    {
        let store = SqliteStore::open(path)?;
        assert!(table_exists(&store.conn)?);
        raw_insert(&store.conn, &good_row())?;
    }
    let store = SqliteStore::open(path)?;
    assert_eq!(rows(&store.conn)?, vec![row_of(&owner(1), 1, &STORE)]);
    Ok(())
}

#[test]
fn a_read_only_open_creates_nothing_and_a_writable_open_adds_the_table() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("staging.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch("DROP TABLE subject_key_staging")?;

    let store = SqliteStore::open_read_only(path)?;
    assert!(!table_exists(&store.conn)?);
    drop(store);

    let store = SqliteStore::open(path)?;
    assert!(table_exists(&store.conn)?);
    Ok(())
}

#[test]
fn a_table_without_the_checks_is_an_incompatible_schema() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("staging.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch(
        "DROP TABLE subject_key_staging;
         CREATE TABLE subject_key_staging (
             owner_id TEXT NOT NULL, epoch INTEGER NOT NULL, store_file_id BLOB NOT NULL,
             PRIMARY KEY (owner_id, epoch));",
    )?;
    let error = SqliteStore::open(path)
        .err()
        .map(|error| error.to_string())
        .ok_or("the weak table was accepted")?;
    assert!(error.contains("incompatible schema"), "{error}");
    Ok(())
}

#[test]
fn the_table_accepts_a_good_row_and_refuses_each_malformed_one() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let refused = [
        (
            "owner as a blob",
            with(0, Value::Blob(owner(1).into_bytes())),
        ),
        (
            "owner too short",
            with(0, Value::Text("subject:ab".to_owned())),
        ),
        (
            "owner prefix",
            with(0, Value::Text(format!("subjecT:{:032x}", 2))),
        ),
        (
            "owner upper-case digits",
            with(0, Value::Text(format!("subject:{:032X}", 0xabc_u128))),
        ),
        (
            "owner non-hex digit",
            with(0, Value::Text(format!("subject:{}g", "1".repeat(31)))),
        ),
        ("epoch zero", with(1, Value::Integer(0))),
        ("epoch negative", with(1, Value::Integer(-1))),
        ("epoch as text", with(1, Value::Text("one".to_owned()))),
        ("epoch as a real", with(1, Value::Real(1.5))),
        ("store id as text", with(2, Value::Text("abc".to_owned()))),
        ("store id empty", with(2, Value::Blob(Vec::new()))),
        ("store id too long", with(2, Value::Blob(vec![1; 33]))),
        ("store id null", with(2, Value::Null)),
        ("owner null", with(0, Value::Null)),
        ("epoch null", with(1, Value::Null)),
    ];
    for (name, values) in refused {
        assert!(
            raw_insert(&store.conn, &values).is_err(),
            "{name} was accepted"
        );
    }
    raw_insert(&store.conn, &good_row())?;
    raw_insert(&store.conn, &with(2, Value::Blob(vec![1; 32])))
        .err()
        .ok_or("the duplicate key was accepted")?;
    raw_insert(
        &store.conn,
        &[
            Value::Text(owner(1)),
            Value::Integer(2),
            Value::Blob(vec![1; 32]),
        ],
    )?;
    assert_eq!(rows(&store.conn)?.len(), 2);
    Ok(())
}

#[test]
fn the_epoch_ceiling_is_the_highest_epoch_in_any_lifecycle_state() -> TestResult {
    let mut store = registry_store()?;
    let timeline = TimelineId::new();
    let subject = owner(1);
    assert_eq!(store.subject_registry_epoch_ceiling(&subject, timeline)?, 0);

    register_directly(&mut store, &subject, 1, 1)?;
    register_directly(&mut store, &subject, 3, 2)?;
    register_directly(&mut store, &owner(2), 9, 3)?;
    assert_eq!(store.subject_registry_epoch_ceiling(&subject, timeline)?, 3);
    assert_eq!(
        store.subject_registry_epoch_ceiling(&owner(2), timeline)?,
        9
    );
    assert_eq!(
        store.subject_registry_epoch_ceiling(&owner(3), timeline)?,
        0
    );

    begin_destruction(&mut store, &subject, 3, 2)?;
    assert_eq!(
        store.subject_registry_epoch_ceiling(&subject, timeline)?,
        3,
        "a pending identity keeps the ceiling"
    );
    let request = destruction_request(&subject, 3, 2)?;
    store.complete_key_registry_destruction(request, deletion_receipt(&request))?;
    assert_eq!(
        store.subject_registry_epoch_ceiling(&subject, timeline)?,
        3,
        "a tombstone keeps the ceiling"
    );
    assert!(store.conn.is_autocommit(), "the read left no transaction");
    Ok(())
}

#[test]
fn the_epoch_ceiling_refuses_a_bad_owner_a_fence_and_an_unreadable_registry() -> TestResult {
    let store = registry_store()?;
    let timeline = TimelineId::new();
    for bad in [
        String::new(),
        "owner-a".to_owned(),
        owner(1).to_uppercase(),
        format!("subject:{}", "a".repeat(31)),
        format!("subject:{}", "a".repeat(33)),
        format!("subject:{}g", "a".repeat(31)),
        format!("subject:{:032x}", 0),
        format!("subjec_:{:032x}", 1),
    ] {
        assert_refused(&store.subject_registry_epoch_ceiling(&bad, timeline));
    }

    fence(&store.conn, timeline, 2)?;
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), timeline));
    assert_eq!(
        store.subject_registry_epoch_ceiling(&owner(1), TimelineId::new())?,
        0,
        "a fence of another Timeline does not refuse"
    );
    let malformed = TimelineId::new();
    store
        .conn
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    fence(&store.conn, malformed, 9)?;
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), malformed));
    store.conn.execute_batch("DROP TABLE erasure_fence_rows")?;
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), timeline));
    Ok(())
}

#[test]
fn p1_is_never_treated_as_empty() -> TestResult {
    let timeline = TimelineId::new();
    let store = SqliteStore::open_in_memory()?;
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), timeline));
    assert_refused(&store.recover_subject_key_staging(&STORE));
    assert_refused(&store.subject_key_lifecycle(&owner(1), 1));
    assert_refused(&store.pending_subject_key_destructions());

    let store = registry_store()?;
    store
        .conn
        .execute_batch("UPDATE key_registry SET state_cbor = X'00'")?;
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), timeline));
    assert_refused(&store.subject_key_lifecycle(&owner(1), 1));
    assert_refused(&store.registered_subject_root_material_digest(&owner(1), 1));
    assert_refused(&store.pending_subject_key_destructions());
    store.conn.execute_batch("DROP TABLE key_registry")?;
    assert_refused(&store.recover_subject_key_staging(&STORE));
    Ok(())
}

#[test]
fn a_staging_record_commits_once_and_is_never_replaced() -> TestResult {
    let store = registry_store()?;
    store.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    store.commit_subject_key_staging_record(&owner(1), 2, &STORE)?;
    store.commit_subject_key_staging_record(&owner(2), 1, &OTHER_STORE)?;
    assert_eq!(
        rows(&store.conn)?,
        vec![
            row_of(&owner(1), 1, &STORE),
            row_of(&owner(1), 2, &STORE),
            row_of(&owner(2), 1, &OTHER_STORE),
        ]
    );
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 1, &STORE));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 1, &OTHER_STORE));
    assert_eq!(
        rows(&store.conn)?[0],
        row_of(&owner(1), 1, &STORE),
        "a later claim never replaces the first"
    );
    assert!(store.conn.is_autocommit());
    Ok(())
}

#[test]
fn a_staging_record_refuses_invalid_input_and_stages_nothing() -> TestResult {
    let store = registry_store()?;
    assert_refused(&store.commit_subject_key_staging_record("owner-a", 1, &STORE));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 0, &STORE));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), u64::MAX, &STORE));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 1, &[]));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 1, &[1; 33]));
    store.commit_subject_key_staging_record(&owner(1), 1, &[1; 32])?;
    store.commit_subject_key_staging_record(&owner(1), 2, &[1])?;
    assert_eq!(rows(&store.conn)?.len(), 2);
    Ok(())
}

#[test]
fn a_registration_registers_activates_and_unstages_in_one_commit() -> TestResult {
    let store = registry_store()?;
    let timeline = TimelineId::new();
    let subject = owner(1);
    store.commit_subject_key_staging_record(&subject, 1, &STORE)?;
    assert_eq!(
        store.subject_key_lifecycle(&subject, 1)?,
        Lifecycle::Absent,
        "staging registers nothing"
    );
    store.register_subject_key(&subject, timeline, 1, &STORE, digest(11))?;
    assert!(rows(&store.conn)?.is_empty());
    assert_eq!(
        store.subject_key_lifecycle(&subject, 1)?,
        Lifecycle::Live(digest(11))
    );
    assert_eq!(store.subject_registry_epoch_ceiling(&subject, timeline)?, 1);

    // A rotation retains the previous epoch for decryption only.
    store.commit_subject_key_staging_record(&subject, 2, &STORE)?;
    store.register_subject_key(&subject, timeline, 2, &STORE, digest(12))?;
    let registry = load_registry(&store)?;
    let owner_id = OwnerIdV1::new(&subject)?;
    assert_eq!(
        registry
            .active_key(&owner_id, KeyRoleV1::SubjectDataEncryption)
            .map(|record| record.identity.epoch),
        Some(2)
    );
    assert_eq!(
        store.registered_subject_root_material_digest(&subject, 1)?,
        digest(11)
    );
    assert_eq!(
        store.registered_subject_root_material_digest(&subject, 2)?,
        digest(12)
    );
    assert!(rows(&store.conn)?.is_empty());
    Ok(())
}

#[test]
fn a_registration_at_or_below_the_high_water_mark_is_refused() -> TestResult {
    let mut store = registry_store()?;
    let timeline = TimelineId::new();
    let subject = owner(1);
    register_directly(&mut store, &subject, 3, 1)?;
    for epoch in [1, 2, 3] {
        store.commit_subject_key_staging_record(&subject, epoch, &STORE)?;
        assert_refused(&store.register_subject_key(&subject, timeline, epoch, &STORE, digest(9)));
    }
    // The very same material at the ceiling would be an idempotent
    // re-registration; the strict comparison still refuses it.
    assert_refused(&store.register_subject_key(&subject, timeline, 3, &STORE, digest(1)));
    assert_eq!(rows(&store.conn)?.len(), 3, "the records stay for P5");
    assert_eq!(
        store.subject_key_lifecycle(&subject, 1)?,
        Lifecycle::Absent,
        "nothing was registered"
    );
    store.commit_subject_key_staging_record(&subject, 4, &STORE)?;
    store.register_subject_key(&subject, timeline, 4, &STORE, digest(9))?;
    Ok(())
}

#[test]
fn a_registration_needs_its_own_stores_record() -> TestResult {
    let store = registry_store()?;
    let timeline = TimelineId::new();
    let subject = owner(1);
    assert_refused(&store.register_subject_key(&subject, timeline, 1, &STORE, digest(1)));
    store.commit_subject_key_staging_record(&subject, 1, &OTHER_STORE)?;
    assert_refused(&store.register_subject_key(&subject, timeline, 1, &STORE, digest(1)));
    assert_eq!(rows(&store.conn)?, vec![row_of(&subject, 1, &OTHER_STORE)]);
    assert_eq!(store.subject_key_lifecycle(&subject, 1)?, Lifecycle::Absent);
    assert_eq!(
        load_registry(&store)?
            .highest_epoch(&OwnerIdV1::new(&subject)?, KeyRoleV1::SubjectDataEncryption),
        None,
        "the refused registration rolled back"
    );
    Ok(())
}

#[test]
fn a_registration_refuses_a_fence_reused_material_and_invalid_input() -> TestResult {
    let mut store = registry_store()?;
    let timeline = TimelineId::new();
    register_directly(&mut store, &owner(2), 1, 5)?;
    store.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;

    assert_refused(&store.register_subject_key(&owner(1), timeline, 1, &STORE, digest(5)));
    assert_refused(&store.register_subject_key("owner-a", timeline, 1, &STORE, digest(6)));
    assert_refused(&store.register_subject_key(&owner(1), timeline, 0, &STORE, digest(6)));
    assert_refused(&store.register_subject_key(&owner(1), timeline, 1, &[], digest(6)));
    fence(&store.conn, timeline, 3)?;
    assert_refused(&store.register_subject_key(&owner(1), timeline, 1, &STORE, digest(6)));
    assert_eq!(rows(&store.conn)?, vec![row_of(&owner(1), 1, &STORE)]);
    assert_eq!(
        store.subject_key_lifecycle(&owner(1), 1)?,
        Lifecycle::Absent
    );

    store.register_subject_key(&owner(1), TimelineId::new(), 1, &STORE, digest(6))?;
    assert_eq!(
        store.subject_key_lifecycle(&owner(1), 1)?,
        Lifecycle::Live(digest(6))
    );
    Ok(())
}

#[test]
fn deleting_a_record_is_idempotent_and_never_releases_another_stores_claim() -> TestResult {
    let store = registry_store()?;
    store.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    store.commit_subject_key_staging_record(&owner(1), 2, &OTHER_STORE)?;

    store.delete_subject_key_staging_record(&owner(1), 2, &STORE)?;
    store.delete_subject_key_staging_record(&owner(2), 1, &STORE)?;
    assert_eq!(rows(&store.conn)?.len(), 2, "no claim was released");

    store.delete_subject_key_staging_record(&owner(1), 1, &STORE)?;
    store.delete_subject_key_staging_record(&owner(1), 1, &STORE)?;
    assert_eq!(rows(&store.conn)?, vec![row_of(&owner(1), 2, &OTHER_STORE)]);

    assert_refused(&store.delete_subject_key_staging_record("owner-a", 1, &STORE));
    assert_refused(&store.delete_subject_key_staging_record(&owner(1), 0, &STORE));
    assert_refused(&store.delete_subject_key_staging_record(&owner(1), 1, &[]));
    assert_eq!(rows(&store.conn)?.len(), 1);
    Ok(())
}

#[test]
fn recovery_deletes_foreign_and_registered_records_and_returns_the_orphans() -> TestResult {
    let mut store = registry_store()?;
    let foreign = owner(1);
    let orphan = owner(2);
    let registered = owner(3);
    let below_mark = owner(4);
    let pending = owner(5);
    let destroyed = owner(6);
    register_directly(&mut store, &registered, 1, 31)?;
    register_directly(&mut store, &below_mark, 5, 32)?;
    register_directly(&mut store, &pending, 1, 33)?;
    register_directly(&mut store, &destroyed, 1, 34)?;
    begin_destruction(&mut store, &pending, 1, 33)?;
    let request = begin_destruction(&mut store, &destroyed, 1, 34)?;
    store.complete_key_registry_destruction(request, deletion_receipt(&request))?;

    for (subject, epoch, bound) in [
        (&foreign, 1, OTHER_STORE),
        (&orphan, 1, STORE),
        (&registered, 1, STORE),
        (&below_mark, 2, STORE),
        (&pending, 1, STORE),
        (&destroyed, 1, STORE),
    ] {
        store.commit_subject_key_staging_record(subject, epoch, &bound)?;
    }
    let before = load_registry(&store)?;

    let orphans = store.recover_subject_key_staging(&STORE)?;
    assert_eq!(
        orphans,
        vec![
            SubjectKeyStagingRecordV1 {
                owner_id: orphan.clone(),
                epoch: 1,
                store_file_id: STORE.to_vec(),
            },
            SubjectKeyStagingRecordV1 {
                owner_id: below_mark.clone(),
                epoch: 2,
                store_file_id: STORE.to_vec(),
            },
        ]
    );
    assert_eq!(
        rows(&store.conn)?,
        vec![row_of(&orphan, 1, &STORE), row_of(&below_mark, 2, &STORE)],
        "only the orphans keep their records"
    );
    assert!(load_registry(&store)? == before, "P5 never edits P1");

    assert_eq!(
        store.recover_subject_key_staging(&STORE)?.len(),
        2,
        "recovery is repeatable until the owner finishes the orphans"
    );
    for record in store.recover_subject_key_staging(&STORE)? {
        store.delete_subject_key_staging_record(
            &record.owner_id,
            record.epoch,
            &record.store_file_id,
        )?;
    }
    assert!(store.recover_subject_key_staging(&STORE)?.is_empty());
    assert!(rows(&store.conn)?.is_empty());
    Ok(())
}

#[test]
fn a_copied_store_deletes_only_its_foreign_record() -> TestResult {
    let original = registry_store()?;
    original.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    original.register_subject_key(&owner(1), TimelineId::new(), 1, &STORE, digest(1))?;

    // The copy was taken between steps 3 and 6, so it still holds the record,
    // but it is a different file with another identity.
    let copy = registry_store()?;
    copy.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    assert!(copy.recover_subject_key_staging(&OTHER_STORE)?.is_empty());
    assert!(rows(&copy.conn)?.is_empty());
    assert_eq!(
        original.subject_key_lifecycle(&owner(1), 1)?,
        Lifecycle::Live(digest(1))
    );
    Ok(())
}

#[test]
fn an_unparseable_staging_table_fails_recovery_closed_and_deletes_nothing() -> TestResult {
    let bad_rows = [
        ("owner", with(0, Value::Text("owner-a".to_owned()))),
        ("epoch zero", with(1, Value::Integer(0))),
        ("epoch text", with(1, Value::Text("one".to_owned()))),
        ("store id empty", with(2, Value::Blob(Vec::new()))),
        ("store id long", with(2, Value::Blob(vec![1; 33]))),
        ("store id text", with(2, Value::Text("abc".to_owned()))),
    ];
    for (name, values) in bad_rows {
        let store = registry_store()?;
        store.commit_subject_key_staging_record(&owner(2), 1, &OTHER_STORE)?;
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = ON")?;
        raw_insert(&store.conn, &values)?;
        assert_refused(&store.recover_subject_key_staging(&STORE));
        assert_eq!(row_count(&store.conn)?, 2, "{name}: nothing was deleted");
    }
    Ok(())
}

#[test]
fn a_staging_table_over_the_bound_fails_recovery_closed() -> TestResult {
    let store = registry_store()?;
    store.conn.execute_batch("BEGIN")?;
    for number in 1..=MAX_STAGING_RECORDS + 1 {
        store.conn.execute(
            "INSERT INTO subject_key_staging (owner_id, epoch, store_file_id) VALUES (?1, 1, ?2)",
            params![owner(u128::try_from(number)?), OTHER_STORE.as_slice()],
        )?;
    }
    store.conn.execute_batch("COMMIT")?;
    assert_refused(&store.recover_subject_key_staging(&STORE));
    assert_eq!(rows(&store.conn)?.len(), MAX_STAGING_RECORDS + 1);

    store.conn.execute(
        "DELETE FROM subject_key_staging WHERE owner_id = ?1",
        [owner(1)],
    )?;
    assert!(store.recover_subject_key_staging(&STORE)?.is_empty());
    assert!(rows(&store.conn)?.is_empty());
    Ok(())
}

#[test]
fn recovery_refuses_a_bad_bound_identity_and_a_missing_table_and_deletes_nothing() -> TestResult {
    let store = registry_store()?;
    store.commit_subject_key_staging_record(&owner(1), 1, &OTHER_STORE)?;
    assert_refused(&store.recover_subject_key_staging(&[]));
    assert_refused(&store.recover_subject_key_staging(&[1; 33]));
    assert_eq!(rows(&store.conn)?.len(), 1, "an empty id matches no store");
    store.conn.execute_batch("DROP TABLE subject_key_staging")?;
    assert_refused(&store.recover_subject_key_staging(&STORE));
    Ok(())
}

#[test]
fn the_lifecycle_distinguishes_every_p1_state_and_unlock_accepts_only_live() -> TestResult {
    let mut store = registry_store()?;
    let subject = owner(1);
    assert_eq!(store.subject_key_lifecycle(&subject, 1)?, Lifecycle::Absent);
    assert_refused(&store.registered_subject_root_material_digest(&subject, 1));

    register_directly(&mut store, &subject, 1, 21)?;
    register_directly(&mut store, &subject, 2, 22)?;
    assert_eq!(
        store.subject_key_lifecycle(&subject, 1)?,
        Lifecycle::Live(digest(21)),
        "a retained epoch is live"
    );
    assert_eq!(
        store.registered_subject_root_material_digest(&subject, 2)?,
        digest(22)
    );
    assert_eq!(store.subject_key_lifecycle(&subject, 3)?, Lifecycle::Absent);
    assert_eq!(
        store.subject_key_lifecycle(&owner(2), 1)?,
        Lifecycle::Absent
    );

    let request = begin_destruction(&mut store, &subject, 2, 22)?;
    assert_eq!(
        store.subject_key_lifecycle(&subject, 2)?,
        Lifecycle::DestructionPending
    );
    assert_refused(&store.registered_subject_root_material_digest(&subject, 2));
    assert_eq!(
        store.registered_subject_root_material_digest(&subject, 1)?,
        digest(21),
        "another epoch is unaffected"
    );

    store.complete_key_registry_destruction(request, deletion_receipt(&request))?;
    assert_eq!(
        store.subject_key_lifecycle(&subject, 2)?,
        Lifecycle::Destroyed
    );
    assert_refused(&store.registered_subject_root_material_digest(&subject, 2));

    assert_refused(&store.subject_key_lifecycle("owner-a", 1));
    assert_refused(&store.subject_key_lifecycle(&subject, 0));
    assert_refused(&store.subject_key_lifecycle(&subject, u64::MAX));
    Ok(())
}

fn none_pending() -> PendingKeyDestructionsV1 {
    PendingKeyDestructionsV1 {
        subject_keys: Vec::new(),
        signing_keys: Vec::new(),
    }
}

/// The verification key a registration of `identity` carries.
fn public_of(identity: KeyIdentityV1, seed: u8) -> Option<PublicKey> {
    identity
        .role
        .is_signing()
        .then_some(PublicKey::from_bytes([seed; 32]))
}

/// Register `identity` in the stored registry.
fn register_identity(store: &mut SqliteStore, identity: KeyIdentityV1, seed: u8) -> TestResult {
    let mut registry = load_registry(store)?;
    registry.register_key(KeyRegistrationV1::new(
        identity,
        digest(seed),
        public_of(identity, seed),
    ))?;
    Ok(store.save_key_registry(&registry)?)
}

/// Register `identity` and make its destruction pending.
fn pend(store: &mut SqliteStore, identity: KeyIdentityV1, seed: u8) -> TestResult {
    register_identity(store, identity, seed)?;
    store.begin_key_registry_destruction(KeyDestructionRequestV1::new(
        identity,
        digest(seed),
        digest(200),
    ))?;
    Ok(())
}

type IdentityResult = Result<KeyIdentityV1, Box<dyn std::error::Error>>;

fn key_identity(owner_id: &str, role: KeyRoleV1, epoch: u64) -> IdentityResult {
    Ok(KeyIdentityV1::new(OwnerIdV1::new(owner_id)?, role, epoch))
}

#[test]
fn startup_destruction_recovery_lists_every_pending_subject_key() -> TestResult {
    let mut store = registry_store()?;
    assert_eq!(store.pending_subject_key_destructions()?, none_pending());
    register_directly(&mut store, &owner(1), 1, 41)?;
    register_directly(&mut store, &owner(1), 2, 42)?;
    register_directly(&mut store, &owner(2), 1, 43)?;
    assert_eq!(store.pending_subject_key_destructions()?, none_pending());

    // A pending request of another owner and role is neither kind.
    pend(
        &mut store,
        key_identity("recipient-a", KeyRoleV1::ExportRecipientEncryption, 1)?,
        44,
    )?;
    assert_eq!(store.pending_subject_key_destructions()?, none_pending());

    let first = begin_destruction(&mut store, &owner(1), 2, 42)?;
    let second = begin_destruction(&mut store, &owner(2), 1, 43)?;
    let mut pending = store.pending_subject_key_destructions()?;
    pending
        .subject_keys
        .sort_by_key(|request| request.identity.owner_id.as_str().to_owned());
    assert_eq!(
        pending,
        PendingKeyDestructionsV1 {
            subject_keys: vec![first, second],
            signing_keys: Vec::new(),
        }
    );
    Ok(())
}

fn owner_signing(epoch: u64) -> IdentityResult {
    key_identity(OWNER_SIGNING_OWNER_ID, OWNER_SIGNING_ROLE, epoch)
}

fn request_of(identity: KeyIdentityV1, seed: u8) -> KeyDestructionRequestV1 {
    KeyDestructionRequestV1::new(identity, digest(seed), digest(200))
}

fn sorted_signing(store: &SqliteStore) -> Result<Vec<KeyDestructionRequestV1>, CoreError> {
    let mut keys = store.pending_subject_key_destructions()?.signing_keys;
    keys.sort_by_key(|request| request.identity.epoch);
    Ok(keys)
}

#[test]
fn the_owner_signing_identity_is_the_fixed_adr_137_pair() {
    assert_eq!(OWNER_SIGNING_OWNER_ID, "piglor-owner");
    assert_eq!(OWNER_SIGNING_ROLE, KeyRoleV1::TimelineIntegritySigning);
}

#[test]
fn no_pending_owner_signing_request_lists_nothing() -> TestResult {
    let mut store = registry_store()?;
    assert!(sorted_signing(&store)?.is_empty());
    register_identity(&mut store, owner_signing(1)?, 50)?;
    assert!(sorted_signing(&store)?.is_empty());
    Ok(())
}

#[test]
fn every_epoch_of_the_owner_signing_identity_is_listed() -> TestResult {
    let mut store = registry_store()?;
    pend(&mut store, owner_signing(1)?, 51)?;
    pend(&mut store, owner_signing(2)?, 52)?;
    pend(&mut store, owner_signing(3)?, 53)?;
    assert_eq!(
        sorted_signing(&store)?,
        vec![
            request_of(owner_signing(1)?, 51),
            request_of(owner_signing(2)?, 52),
            request_of(owner_signing(3)?, 53),
        ]
    );
    Ok(())
}

#[test]
fn another_owner_id_with_the_signing_role_is_excluded() -> TestResult {
    let mut store = registry_store()?;
    pend(&mut store, owner_signing(1)?, 51)?;
    pend(
        &mut store,
        key_identity("bundle-signer", OWNER_SIGNING_ROLE, 2)?,
        52,
    )?;
    assert_eq!(
        sorted_signing(&store)?,
        vec![request_of(owner_signing(1)?, 51)]
    );
    Ok(())
}

#[test]
fn the_owner_id_with_another_role_is_excluded() -> TestResult {
    let mut store = registry_store()?;
    pend(&mut store, owner_signing(1)?, 51)?;
    pend(
        &mut store,
        key_identity(OWNER_SIGNING_OWNER_ID, KeyRoleV1::PluginReleaseSigning, 2)?,
        52,
    )?;
    pend(
        &mut store,
        key_identity(
            OWNER_SIGNING_OWNER_ID,
            KeyRoleV1::ExportRecipientEncryption,
            3,
        )?,
        53,
    )?;
    assert_eq!(
        sorted_signing(&store)?,
        vec![request_of(owner_signing(1)?, 51)]
    );
    Ok(())
}

#[test]
fn both_groups_are_listed_together_and_independently() -> TestResult {
    let mut store = registry_store()?;
    pend(&mut store, owner_signing(1)?, 51)?;
    pend(
        &mut store,
        key_identity("bundle-signer", OWNER_SIGNING_ROLE, 2)?,
        52,
    )?;
    register_directly(&mut store, &owner(3), 1, 61)?;
    let subject = begin_destruction(&mut store, &owner(3), 1, 61)?;
    let both = store.pending_subject_key_destructions()?;
    assert_eq!(both.subject_keys, vec![subject]);
    assert_eq!(both.signing_keys, vec![request_of(owner_signing(1)?, 51)]);
    Ok(())
}

#[test]
fn a_caller_that_holds_a_transaction_is_refused_every_write() -> TestResult {
    let store = registry_store()?;
    store.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    store.conn.execute_batch("BEGIN IMMEDIATE")?;
    let timeline = TimelineId::new();
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), timeline));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 2, &STORE));
    assert_refused(&store.register_subject_key(&owner(1), timeline, 1, &STORE, digest(1)));
    assert_refused(&store.delete_subject_key_staging_record(&owner(1), 1, &STORE));
    assert_refused(&store.recover_subject_key_staging(&OTHER_STORE));
    assert!(
        !store.conn.is_autocommit(),
        "the caller's transaction is untouched"
    );
    store.conn.execute_batch("ROLLBACK")?;
    assert_eq!(rows(&store.conn)?, vec![row_of(&owner(1), 1, &STORE)]);
    assert_eq!(
        store.subject_key_lifecycle(&owner(1), 1)?,
        Lifecycle::Absent
    );
    Ok(())
}

#[test]
fn a_failed_transaction_start_refuses_every_write_with_a_fixed_message() -> TestResult {
    let store = registry_store()?;
    store.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    let timeline = TimelineId::new();
    FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
    let results = [
        store
            .subject_registry_epoch_ceiling(&owner(1), timeline)
            .map(|_| ()),
        store.commit_subject_key_staging_record(&owner(1), 2, &STORE),
        store.register_subject_key(&owner(1), timeline, 1, &STORE, digest(1)),
        store.delete_subject_key_staging_record(&owner(1), 1, &STORE),
        store.recover_subject_key_staging(&OTHER_STORE).map(|_| ()),
    ];
    FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));
    for result in results {
        assert_refused(&result);
    }
    assert_eq!(rows(&store.conn)?, vec![row_of(&owner(1), 1, &STORE)]);
    Ok(())
}

#[test]
fn a_stale_inventory_data_version_refuses_every_write_first() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("staging.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    let mut store = SqliteStore::open(path)?;
    store.save_key_registry(&KeyRegistryStateV1::new())?;
    store.commit_subject_key_staging_record(&owner(1), 1, &STORE)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let timeline = TimelineId::new();
    store.subject_registry_epoch_ceiling(&owner(1), timeline)?;

    Connection::open(path)?.execute_batch("CREATE TABLE other_writer (value INTEGER)")?;
    assert_refused(&store.subject_registry_epoch_ceiling(&owner(1), timeline));
    assert_refused(&store.commit_subject_key_staging_record(&owner(1), 2, &STORE));
    assert_refused(&store.register_subject_key(&owner(1), timeline, 1, &STORE, digest(1)));
    assert_refused(&store.delete_subject_key_staging_record(&owner(1), 1, &STORE));
    assert_refused(&store.recover_subject_key_staging(&OTHER_STORE));
    assert_eq!(rows(&store.conn)?, vec![row_of(&owner(1), 1, &STORE)]);
    assert_eq!(
        store.subject_key_lifecycle(&owner(1), 1)?,
        Lifecycle::Absent
    );
    Ok(())
}

#[test]
fn errors_carry_only_fixed_text_and_an_unknown_outcome_stays_unknown() {
    let secret = "SQLITE_FULL at /secret/path";
    let unknown = sealed(&CoreError::StorageOutcomeUnknown(secret.to_owned()));
    assert!(
        matches!(&unknown, CoreError::StorageOutcomeUnknown(text) if text == OUTCOME_UNKNOWN),
        "{unknown:?}"
    );
    for error in [
        CoreError::Storage(secret.to_owned()),
        CoreError::ErasureContainmentUnavailable,
    ] {
        assert_refused::<()>(&Err(sealed(&error)));
    }
}
