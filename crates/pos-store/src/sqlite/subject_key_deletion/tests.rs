//! ADR-137 D1-D4: the receipt table, the digests, the `Started` and
//! `Confirmed` writes, and the finalization with the registry tombstone.

use std::sync::Arc;

use pos_core::{
    deletion_receipt, error::CoreError, ErasureContainmentGateV1, EventStore, Hash,
    KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1,
};
use rusqlite::{params, types::Value, Connection};

use super::{
    finish_scope, read_request_rows, sealed, subject_key_deletion_receipt_digest,
    subject_key_destruction_request_digest, SubjectKeyDeletionArtifactV1 as Artifact,
    SubjectKeyDeletionRowV1, SubjectKeyDeletionStateV1 as State, ABSENT_AT_START_IDENTITY,
};
use crate::sqlite::{begin_immediate_scope, SqliteStore, FAIL_BEGIN_IMMEDIATE};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn encryption_identity(epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::new("owner-a", KeyRoleV1::SubjectDataEncryption, epoch)
}

fn request_of(identity: KeyIdentityV1, seed: u8) -> KeyDestructionRequestV1 {
    KeyDestructionRequestV1::new(
        identity,
        Hash::from_bytes([seed; 32]),
        Hash::from_bytes([seed.wrapping_add(1); 32]),
    )
}

/// Register the identity's key in the store's registry.
fn registered(store: &mut SqliteStore, request: &KeyDestructionRequestV1) -> TestResult {
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        request.identity,
        request.expected_material_digest,
        None,
    ))?;
    store.save_key_registry(&registry)?;
    Ok(())
}

/// A store whose registry holds the request as `DestructionPending`.
fn pending_in(
    mut store: SqliteStore,
    seed: u8,
) -> Result<(SqliteStore, KeyDestructionRequestV1), Box<dyn std::error::Error>> {
    let request = request_of(encryption_identity(1), seed);
    registered(&mut store, &request)?;
    store.begin_key_registry_destruction(request)?;
    Ok((store, request))
}

fn pending() -> Result<(SqliteStore, KeyDestructionRequestV1), Box<dyn std::error::Error>> {
    pending_in(SqliteStore::open_in_memory()?, 7)
}

fn refused<T: std::fmt::Debug>(result: Result<T, CoreError>, needle: &str) {
    let outcome = result.map(|value| format!("{value:?}"));
    assert!(
        outcome
            .as_ref()
            .is_err_and(|error| error.to_string().contains(needle)),
        "{outcome:?}"
    );
}

fn error_text<T>(result: Result<T, CoreError>) -> Result<String, Box<dyn std::error::Error>> {
    result
        .err()
        .map(|error| error.to_string())
        .ok_or_else(|| "expected a refusal".into())
}

fn rows(
    store: &SqliteStore,
    request: &KeyDestructionRequestV1,
) -> Result<Vec<SubjectKeyDeletionRowV1>, CoreError> {
    store.subject_key_deletion_receipts(request)
}

fn pending_count(store: &SqliteStore) -> Result<usize, CoreError> {
    Ok(store
        .load_key_registry()?
        .ok_or_else(|| CoreError::Storage("no registry".to_owned()))?
        .pending_destruction_requests()
        .count())
}

fn table_exists(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'subject_key_deletion_receipts'",
        [],
        |row| row.get(0),
    )
}

fn raw_insert(conn: &Connection, values: [&Value; 7]) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO subject_key_deletion_receipts
             (request_digest, owner_id, epoch, artifact, artifact_identity, state, receipt_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![values[0], values[1], values[2], values[3], values[4], values[5], values[6]],
    )
}

fn good() -> [Value; 7] {
    [
        Value::Blob(vec![1; 32]),
        Value::Text("owner-a".to_owned()),
        Value::Integer(1),
        Value::Integer(1),
        Value::Blob(vec![9]),
        Value::Integer(1),
        Value::Null,
    ]
}

fn with(index: usize, value: Value) -> [Value; 7] {
    let mut values = good();
    values[index] = value;
    values
}

fn insert_values(conn: &Connection, values: &[Value; 7]) -> rusqlite::Result<usize> {
    raw_insert(
        conn,
        [
            &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
        ],
    )
}

/// Record and confirm one artifact, returning the receipt digest.
fn destroyed(
    store: &SqliteStore,
    request: &KeyDestructionRequestV1,
    artifact: Artifact,
    identity: &[u8],
) -> Result<Hash, CoreError> {
    store.record_subject_key_deletion_started(request, artifact, identity)?;
    store.confirm_subject_key_deletion(request, artifact, identity, b"enoent")
}

fn destroy_all_kinds(
    store: &SqliteStore,
    request: &KeyDestructionRequestV1,
) -> Result<(), CoreError> {
    Artifact::ALL
        .iter()
        .try_for_each(|kind| destroyed(store, request, *kind, &[9]).map(|_| ()))
}

#[test]
fn a_writable_open_creates_the_table_and_a_reopen_keeps_its_rows() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("deletion.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    let request = {
        let (store, request) = pending_in(SqliteStore::open(path)?, 7)?;
        assert!(table_exists(&store.conn)?);
        store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[5])?;
        request
    };
    let store = SqliteStore::open(path)?;
    assert_eq!(
        rows(&store, &request)?,
        vec![SubjectKeyDeletionRowV1 {
            artifact: Artifact::Wrap,
            artifact_identity: vec![5],
            state: State::Started,
        }]
    );
    Ok(())
}

#[test]
fn a_read_only_open_creates_nothing_and_a_missing_table_fails_closed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("deletion.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch("DROP TABLE subject_key_deletion_receipts")?;

    let store = SqliteStore::open_read_only(path)?;
    assert!(!table_exists(&store.conn)?);
    refused(
        rows(&store, &request_of(encryption_identity(1), 7)),
        "receipt store failed",
    );
    let writer = Connection::open(path)?;
    refused(
        read_request_rows(&writer, &request_of(encryption_identity(1), 7)),
        "receipt store failed",
    );
    Ok(())
}

#[test]
fn a_writable_open_adds_the_table_to_a_store_without_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("deletion.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch("DROP TABLE subject_key_deletion_receipts")?;

    let store = SqliteStore::open(path)?;
    assert!(table_exists(&store.conn)?);
    assert_eq!(
        rows(&store, &request_of(encryption_identity(1), 7))?,
        vec![]
    );
    Ok(())
}

#[test]
fn an_incompatible_table_refuses_a_writable_open() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("deletion.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch(
        "DROP TABLE subject_key_deletion_receipts;
         CREATE TABLE subject_key_deletion_receipts (request_digest BLOB NOT NULL);",
    )?;
    let refusal = SqliteStore::open(path)
        .err()
        .ok_or("open accepted the table")?;
    assert!(refusal
        .to_string()
        .contains("subject_key_deletion_receipts"));
    Ok(())
}

#[test]
fn the_table_refuses_rows_d1_never_writes() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let conn = &store.conn;
    let text32 = Value::Text("r".repeat(32));
    let bad_rows = [
        ("short digest", with(0, Value::Blob(vec![1; 31]))),
        ("text digest", with(0, text32.clone())),
        ("blob owner", with(1, Value::Blob(vec![1]))),
        ("epoch zero", with(2, Value::Integer(0))),
        ("real epoch", with(2, Value::Real(1.5))),
        ("artifact zero", with(3, Value::Integer(0))),
        ("artifact four", with(3, Value::Integer(4))),
        ("real artifact", with(3, Value::Real(1.5))),
        ("long identity", with(4, Value::Blob(vec![1; 65]))),
        ("text identity", with(4, Value::Text("x".to_owned()))),
        ("state zero", with(5, Value::Integer(0))),
        ("state three", with(5, Value::Integer(3))),
        ("started with receipt", with(6, Value::Blob(vec![2; 32]))),
        ("confirmed without receipt", with(5, Value::Integer(2))),
        ("short receipt", {
            let mut values = with(5, Value::Integer(2));
            values[6] = Value::Blob(vec![2; 31]);
            values
        }),
        ("text receipt", {
            let mut values = with(5, Value::Integer(2));
            values[6] = text32;
            values
        }),
    ];
    for (label, values) in &bad_rows {
        assert!(insert_values(conn, values).is_err(), "{label}");
    }

    let mut confirmed = with(5, Value::Integer(2));
    confirmed[6] = Value::Blob(vec![2; 32]);
    let mut longest = with(4, Value::Blob(vec![1; 64]));
    longest[3] = Value::Integer(3);
    assert_eq!(insert_values(conn, &good())?, 1);
    assert!(
        insert_values(conn, &confirmed).is_err(),
        "the key is (request_digest, artifact, artifact_identity)"
    );
    assert_eq!(insert_values(conn, &longest)?, 1, "64 bytes fit");
    let mut next_artifact = confirmed;
    next_artifact[3] = Value::Integer(2);
    assert_eq!(insert_values(conn, &next_artifact)?, 1);
    Ok(())
}

#[test]
fn the_digests_follow_the_adr_encoding_and_depend_on_every_input() {
    let request = request_of(encryption_identity(3), 9);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/subject-key-destruction-request/v1\0");
    hasher.update(deletion_receipt(&request).as_bytes());
    let request_digest = subject_key_destruction_request_digest(&request);
    assert_eq!(request_digest.as_bytes(), hasher.finalize().as_bytes());
    assert_ne!(
        request_digest,
        subject_key_destruction_request_digest(&request_of(encryption_identity(4), 9))
    );
    assert_ne!(
        request_digest,
        subject_key_destruction_request_digest(&request_of(encryption_identity(3), 10))
    );

    let digest =
        subject_key_deletion_receipt_digest(&request_digest, Artifact::Binding, b"id", b"ev");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/subject-key-deletion-receipt/v1\0");
    hasher.update(request_digest.as_bytes());
    hasher.update(&[2]);
    hasher.update(b"id");
    hasher.update(b"ev");
    assert_eq!(digest.as_bytes(), hasher.finalize().as_bytes());

    let other_request = Hash::from_bytes([1; 32]);
    for other in [
        subject_key_deletion_receipt_digest(&other_request, Artifact::Binding, b"id", b"ev"),
        subject_key_deletion_receipt_digest(&request_digest, Artifact::Wrap, b"id", b"ev"),
        subject_key_deletion_receipt_digest(&request_digest, Artifact::Snl1Row, b"id", b"ev"),
        subject_key_deletion_receipt_digest(&request_digest, Artifact::Binding, b"ix", b"ev"),
        subject_key_deletion_receipt_digest(&request_digest, Artifact::Binding, b"id", b"ex"),
    ] {
        assert_ne!(other, digest);
    }
}

#[test]
fn started_needs_the_exact_request_pending_in_the_registry() -> TestResult {
    let mut store = SqliteStore::open_in_memory()?;
    let request = request_of(encryption_identity(1), 7);
    refused(
        store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[1]),
        "registry is unavailable",
    );

    registered(&mut store, &request)?;
    refused(
        store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[1]),
        "is not pending",
    );
    store.begin_key_registry_destruction(request)?;
    let other_authorization = KeyDestructionRequestV1::new(
        request.identity,
        request.expected_material_digest,
        Hash::from_bytes([99; 32]),
    );
    refused(
        store.record_subject_key_deletion_started(&other_authorization, Artifact::Wrap, &[1]),
        "is not pending",
    );
    assert_eq!(rows(&store, &request)?, vec![]);
    store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[1])?;
    assert_eq!(rows(&store, &request)?.len(), 1);

    store
        .conn
        .execute_batch("UPDATE key_registry SET state_cbor = X'00'")?;
    refused(
        store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[2]),
        "",
    );
    Ok(())
}

#[test]
fn only_subject_data_encryption_and_representable_epochs_are_accepted() -> TestResult {
    let (mut store, request) = pending()?;
    let signing = KeyDestructionRequestV1::new(
        KeyIdentityV1::new("owner-a", KeyRoleV1::SubjectAttributionSigning, 1),
        request.expected_material_digest,
        request.authorization_digest,
    );
    refused(
        store.record_subject_key_deletion_started(&signing, Artifact::Wrap, &[1]),
        "SubjectDataEncryption only",
    );
    refused(
        store.confirm_subject_key_deletion(&signing, Artifact::Wrap, &[1], b"e"),
        "SubjectDataEncryption only",
    );
    refused(
        store.complete_subject_key_destruction_with_receipts(signing),
        "SubjectDataEncryption only",
    );
    assert_eq!(rows(&store, &signing)?, vec![]);

    let huge = request_of(encryption_identity(1 << 63), 7);
    refused(
        store.record_subject_key_deletion_started(&huge, Artifact::Wrap, &[1]),
        "out of range",
    );
    let largest = request_of(encryption_identity(i64::MAX.unsigned_abs()), 8);
    refused(
        store.record_subject_key_deletion_started(&largest, Artifact::Wrap, &[1]),
        "is not pending",
    );
    Ok(())
}

#[test]
fn started_is_idempotent_and_never_downgrades_a_confirmed_row() -> TestResult {
    let (store, request) = pending()?;
    store.record_subject_key_deletion_started(&request, Artifact::Snl1Row, &[4, 5])?;
    store.record_subject_key_deletion_started(&request, Artifact::Snl1Row, &[4, 5])?;
    assert_eq!(rows(&store, &request)?.len(), 1);
    let (owner, epoch): (String, i64) = store.conn.query_row(
        "SELECT owner_id, epoch FROM subject_key_deletion_receipts",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((owner.as_str(), epoch), ("owner-a", 1));

    let receipt = store.confirm_subject_key_deletion(&request, Artifact::Snl1Row, &[4, 5], b"e")?;
    store.record_subject_key_deletion_started(&request, Artifact::Snl1Row, &[4, 5])?;
    assert_eq!(
        rows(&store, &request)?,
        vec![SubjectKeyDeletionRowV1 {
            artifact: Artifact::Snl1Row,
            artifact_identity: vec![4, 5],
            state: State::Confirmed(receipt),
        }]
    );
    Ok(())
}

#[test]
fn started_identities_are_bounded_and_the_absent_marker_is_one_zero_byte() -> TestResult {
    let (store, request) = pending()?;
    assert_eq!(ABSENT_AT_START_IDENTITY, [0]);
    store.record_subject_key_deletion_started(
        &request,
        Artifact::Binding,
        &ABSENT_AT_START_IDENTITY,
    )?;
    store.record_subject_key_deletion_started(&request, Artifact::Binding, &[7; 64])?;
    refused(
        store.record_subject_key_deletion_started(&request, Artifact::Binding, &[7; 65]),
        "receipt store failed",
    );
    assert_eq!(rows(&store, &request)?.len(), 2);
    Ok(())
}

#[test]
fn confirm_binds_the_receipt_digest_to_the_started_row_only() -> TestResult {
    let (store, request) = pending()?;
    refused(
        store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[1], b"enoent"),
        "was not started",
    );
    for (artifact, identity) in [
        (Artifact::Wrap, [1u8]),
        (Artifact::Wrap, [2]),
        (Artifact::Binding, [1]),
    ] {
        store.record_subject_key_deletion_started(&request, artifact, &identity)?;
    }
    let receipt = store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[1], b"enoent")?;
    let expected = subject_key_deletion_receipt_digest(
        &subject_key_destruction_request_digest(&request),
        Artifact::Wrap,
        &[1],
        b"enoent",
    );
    assert_eq!(receipt, expected);
    let states = rows(&store, &request)?
        .into_iter()
        .map(|row| (row.artifact, row.artifact_identity, row.state))
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        vec![
            (Artifact::Wrap, vec![1], State::Confirmed(expected)),
            (Artifact::Wrap, vec![2], State::Started),
            (Artifact::Binding, vec![1], State::Started),
        ]
    );

    assert_eq!(
        store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[1], b"enoent")?,
        expected,
        "the same evidence is idempotent"
    );
    refused(
        store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[1], b"other"),
        "other evidence",
    );
    assert_eq!(rows(&store, &request)?[0].state, State::Confirmed(expected));
    Ok(())
}

#[test]
fn rows_are_listed_in_kind_then_identity_order_and_per_request() -> TestResult {
    let (store, request) = pending()?;
    for (artifact, identity) in [
        (Artifact::Snl1Row, vec![1]),
        (Artifact::Binding, vec![2]),
        (Artifact::Wrap, vec![3]),
        (Artifact::Wrap, vec![1]),
    ] {
        store.record_subject_key_deletion_started(&request, artifact, &identity)?;
    }
    let order = rows(&store, &request)?
        .into_iter()
        .map(|row| (row.artifact, row.artifact_identity))
        .collect::<Vec<_>>();
    assert_eq!(
        order,
        vec![
            (Artifact::Wrap, vec![1]),
            (Artifact::Wrap, vec![3]),
            (Artifact::Binding, vec![2]),
            (Artifact::Snl1Row, vec![1]),
        ]
    );
    let other = request_of(encryption_identity(1), 50);
    assert_eq!(rows(&store, &other)?, vec![]);
    Ok(())
}

#[test]
fn a_malformed_row_fails_closed_for_reads_and_confirmation() -> TestResult {
    let (store, request) = pending()?;
    let request_digest = subject_key_destruction_request_digest(&request);
    store
        .conn
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    let digest = Value::Blob(request_digest.as_bytes().to_vec());
    let malformed = [
        ("unknown artifact", with(3, Value::Integer(9))),
        ("unknown state", with(5, Value::Integer(3))),
        ("started with receipt", with(6, Value::Blob(vec![2; 32]))),
        ("confirmed without receipt", with(5, Value::Integer(2))),
        ("short receipt", {
            let mut values = with(5, Value::Integer(2));
            values[6] = Value::Blob(vec![2; 5]);
            values
        }),
        ("text artifact", with(3, Value::Text("wrap".to_owned()))),
    ];
    for (label, mut values) in malformed {
        values[0] = digest.clone();
        store
            .conn
            .execute_batch("DELETE FROM subject_key_deletion_receipts")?;
        insert_values(&store.conn, &values)?;
        assert!(rows(&store, &request).is_err(), "{label}");
    }

    store
        .conn
        .execute_batch("DELETE FROM subject_key_deletion_receipts")?;
    let mut values = with(5, Value::Integer(3));
    values[0] = digest;
    insert_values(&store.conn, &values)?;
    refused(
        store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[9], b"e"),
        "malformed",
    );
    Ok(())
}

fn insert_many(store: &SqliteStore, request: &KeyDestructionRequestV1, count: i64) -> TestResult {
    store.conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?2)
         INSERT INTO subject_key_deletion_receipts
             (request_digest, owner_id, epoch, artifact, artifact_identity, state, receipt_digest)
         SELECT ?1, 'owner-a', 1, 1, CAST(printf('%d', i) AS BLOB), 1, NULL FROM n",
        params![
            subject_key_destruction_request_digest(request)
                .as_bytes()
                .as_slice(),
            count
        ],
    )?;
    Ok(())
}

#[test]
fn a_request_holds_at_most_the_inventory_bound_of_rows() -> TestResult {
    let (store, request) = pending()?;
    insert_many(&store, &request, 4_098)?;
    assert_eq!(rows(&store, &request)?.len(), 4_098);

    let (store, request) = pending()?;
    insert_many(&store, &request, 4_099)?;
    refused(rows(&store, &request), "exceed the bound");
    Ok(())
}

#[test]
fn finalization_needs_every_kind_confirmed() -> TestResult {
    let (mut store, request) = pending()?;
    refused(
        store.complete_subject_key_destruction_with_receipts(request),
        "miss an artifact kind",
    );
    for missing in Artifact::ALL {
        let (mut store, request) = pending()?;
        for kind in Artifact::ALL.into_iter().filter(|kind| *kind != missing) {
            destroyed(&store, &request, kind, &[9])?;
        }
        refused(
            store.complete_subject_key_destruction_with_receipts(request),
            "miss an artifact kind",
        );
        assert_eq!(pending_count(&store)?, 1, "{missing:?}");
    }

    destroy_all_kinds(&store, &request)?;
    store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[10])?;
    refused(
        store.complete_subject_key_destruction_with_receipts(request),
        "not all confirmed",
    );
    assert_eq!(pending_count(&store)?, 1);
    Ok(())
}

#[test]
fn finalization_applies_the_registry_tombstone_with_the_rows_retained() -> TestResult {
    let (mut store, request) = pending()?;
    destroy_all_kinds(&store, &request)?;
    let (outcome, registry) = store.complete_subject_key_destruction_with_receipts(request)?;
    let KeyDestructionOutcomeV1::Destroyed(tombstone) = outcome else {
        return Err("expected a fresh tombstone".into());
    };
    assert_eq!(tombstone.identity, request.identity);
    assert_eq!(tombstone.deletion_receipt, deletion_receipt(&request));
    assert_eq!(registry.tombstone(request.identity), Some(tombstone));
    assert_eq!(registry.pending_destruction_requests().count(), 0);
    assert_eq!(store.load_key_registry()?, Some(registry));
    assert_eq!(rows(&store, &request)?.len(), 3, "rows are never deleted");

    let (again, _) = store.complete_subject_key_destruction_with_receipts(request)?;
    assert_eq!(again, KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone));
    refused(
        store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[11]),
        "is not pending",
    );
    Ok(())
}

#[test]
fn finalizing_a_different_request_after_destruction_is_not_pending() -> TestResult {
    let (mut store, request) = pending()?;
    destroy_all_kinds(&store, &request)?;
    store.complete_subject_key_destruction_with_receipts(request)?;
    let other = KeyDestructionRequestV1::new(
        request.identity,
        request.expected_material_digest,
        Hash::from_bytes([99; 32]),
    );
    refused(
        store.complete_subject_key_destruction_with_receipts(other),
        "is not pending",
    );
    Ok(())
}

#[test]
fn finalization_refuses_an_unreadable_registry_and_commits_nothing() -> TestResult {
    let (mut store, request) = pending()?;
    destroy_all_kinds(&store, &request)?;
    store
        .conn
        .execute_batch("UPDATE key_registry SET state_cbor = X'00'")?;
    assert!(store
        .complete_subject_key_destruction_with_receipts(request)
        .is_err());
    assert_eq!(rows(&store, &request)?.len(), 3);
    assert!(
        store.conn.is_autocommit(),
        "the failed finalization rolled back"
    );
    Ok(())
}

#[test]
fn a_failed_transaction_start_refuses_every_write() -> TestResult {
    let (mut store, request) = pending()?;
    destroy_all_kinds(&store, &request)?;
    FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
    let started = store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[12]);
    let finalized = store.complete_subject_key_destruction_with_receipts(request);
    FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));
    for result in [started, finalized.map(|_| ())] {
        let text = error_text(result)?;
        assert!(text.contains("receipt store failed"), "{text}");
        assert!(!text.contains("begin fault"), "{text}");
    }
    assert_eq!(pending_count(&store)?, 1);
    assert_eq!(rows(&store, &request)?.len(), 3);
    Ok(())
}

/// Make the next commit that touches `table` fail with `SQLite` text, through a
/// deferred foreign key that the table's triggers violate.
fn arm_commit_failure(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE fk_parent (id INTEGER PRIMARY KEY);
         CREATE TABLE fk_child (
             parent INTEGER REFERENCES fk_parent (id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER fk_insert AFTER INSERT ON {table}
             BEGIN INSERT INTO fk_child VALUES (1); END;
         CREATE TRIGGER fk_update AFTER UPDATE ON {table}
             BEGIN INSERT INTO fk_child VALUES (1); END;"
    ))
}

fn assert_sealed(result: Result<impl Sized, CoreError>, leaked: &[&str]) -> TestResult {
    let text = error_text(result)?;
    assert!(text.contains("receipt store failed"), "{text}");
    assert!(leaked.iter().all(|word| !text.contains(word)), "{text}");
    Ok(())
}

#[test]
fn a_failed_commit_never_leaks_sqlite_text() -> TestResult {
    let leaked = ["FOREIGN KEY", "commit failed", "constraint"];

    let (store, request) = pending()?;
    arm_commit_failure(&store.conn, "subject_key_deletion_receipts")?;
    assert_sealed(
        store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[1]),
        &leaked,
    )?;
    assert_eq!(rows(&store, &request)?, vec![]);
    assert!(store.conn.is_autocommit());

    let (store, request) = pending()?;
    store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[1])?;
    arm_commit_failure(&store.conn, "subject_key_deletion_receipts")?;
    assert_sealed(
        store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[1], b"e"),
        &leaked,
    )?;
    assert_eq!(rows(&store, &request)?[0].state, State::Started);

    let (mut store, request) = pending()?;
    destroy_all_kinds(&store, &request)?;
    arm_commit_failure(&store.conn, "key_registry")?;
    assert_sealed(
        store.complete_subject_key_destruction_with_receipts(request),
        &leaked,
    )?;
    assert_eq!(pending_count(&store)?, 1);
    Ok(())
}

#[test]
fn finalization_of_a_request_the_registry_does_not_hold_pending_says_so() -> TestResult {
    let mut store = SqliteStore::open_in_memory()?;
    let request = request_of(encryption_identity(1), 7);
    registered(&mut store, &request)?;
    let digest = Value::Blob(
        subject_key_destruction_request_digest(&request)
            .as_bytes()
            .to_vec(),
    );
    for artifact in 1..=3 {
        let mut values = with(5, Value::Integer(2));
        values[0] = digest.clone();
        values[3] = Value::Integer(artifact);
        values[6] = Value::Blob(vec![2; 32]);
        insert_values(&store.conn, &values)?;
    }
    refused(
        store.complete_subject_key_destruction_with_receipts(request),
        "is not pending",
    );
    Ok(())
}

#[test]
fn unknown_outcomes_stay_unknown_with_fixed_text() -> TestResult {
    let secret = "SQLITE_FULL at /secret/path";
    let sealed_unknown = sealed(CoreError::StorageOutcomeUnknown(secret.to_owned()));
    assert!(matches!(
        &sealed_unknown,
        CoreError::StorageOutcomeUnknown(text) if !text.contains("secret") && !text.is_empty()
    ));
    let sealed_storage = sealed(CoreError::Storage(secret.to_owned())).to_string();
    assert!(sealed_storage.contains("receipt store failed"));
    assert!(!sealed_storage.contains("secret"));
    assert_eq!(
        sealed(CoreError::ErasureContainmentUnavailable).to_string(),
        CoreError::ErasureContainmentUnavailable.to_string()
    );

    for operation in [
        Ok(()),
        Err(CoreError::Storage("operation failed".to_owned())),
    ] {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("BEGIN")?;
        let scope = begin_immediate_scope(&conn)?;
        conn.execute_batch("RELEASE SAVEPOINT pigloros_protected_effect")?;
        let outcome = finish_scope(&conn, scope, operation).err();
        assert!(matches!(
            &outcome,
            Some(CoreError::StorageOutcomeUnknown(text))
                if !text.contains("savepoint") && !text.contains("no such")
        ));
    }
    Ok(())
}

#[test]
fn a_stale_inventory_data_version_refuses_every_write_first() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("deletion.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    let (mut store, request) = pending_in(SqliteStore::open(path)?, 7)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[1])?;

    Connection::open(path)?.execute_batch("CREATE TABLE other_writer (value INTEGER)")?;
    let other = KeyDestructionRequestV1::new(
        request.identity,
        request.expected_material_digest,
        Hash::from_bytes([99; 32]),
    );
    let unavailable = CoreError::ErasureContainmentUnavailable.to_string();
    // The unpending request and the missing rows would refuse with another
    // message if the version check did not come first.
    let refusals = [
        store
            .record_subject_key_deletion_started(&other, Artifact::Wrap, &[1])
            .err(),
        store
            .confirm_subject_key_deletion(&other, Artifact::Wrap, &[1], b"e")
            .err(),
        store
            .complete_subject_key_destruction_with_receipts(request)
            .err(),
    ];
    for refusal in refusals {
        assert_eq!(
            refusal.map(|error| error.to_string()),
            Some(unavailable.clone())
        );
    }
    assert_eq!(rows(&store, &request)?.len(), 1);
    assert_eq!(pending_count(&store)?, 1);
    Ok(())
}

#[test]
fn finalization_refuses_a_kind_mixing_absent_and_present_artifacts() -> TestResult {
    for mixed in Artifact::ALL {
        let (mut store, request) = pending()?;
        destroy_all_kinds(&store, &request)?;
        destroyed(&store, &request, mixed, &ABSENT_AT_START_IDENTITY)?;
        refused(
            store.complete_subject_key_destruction_with_receipts(request),
            "mix an absent and a present artifact",
        );
        assert_eq!(pending_count(&store)?, 1, "{mixed:?}");
    }

    let (mut store, request) = pending()?;
    destroyed(&store, &request, Artifact::Wrap, &[9])?;
    destroyed(
        &store,
        &request,
        Artifact::Binding,
        &ABSENT_AT_START_IDENTITY,
    )?;
    destroyed(&store, &request, Artifact::Snl1Row, &[9])?;
    let (outcome, _) = store.complete_subject_key_destruction_with_receipts(request)?;
    assert!(matches!(outcome, KeyDestructionOutcomeV1::Destroyed(_)));
    Ok(())
}

fn foreign_row(
    store: &SqliteStore,
    request: &KeyDestructionRequestV1,
    index: usize,
    value: Value,
) -> TestResult {
    let mut values = with(index, value);
    values[0] = Value::Blob(
        subject_key_destruction_request_digest(request)
            .as_bytes()
            .to_vec(),
    );
    store
        .conn
        .execute_batch("DELETE FROM subject_key_deletion_receipts")?;
    insert_values(&store.conn, &values)?;
    Ok(())
}

#[test]
fn rows_of_another_owner_or_epoch_are_refused() -> TestResult {
    let (store, request) = pending()?;
    for (index, value) in [
        (1, Value::Text("owner-b".to_owned())),
        (2, Value::Integer(2)),
    ] {
        foreign_row(&store, &request, index, value)?;
        refused(rows(&store, &request), "another owner or epoch");
        refused(
            store.confirm_subject_key_deletion(&request, Artifact::Wrap, &[9], b"e"),
            "another owner or epoch",
        );
        refused(
            store.record_subject_key_deletion_started(&request, Artifact::Wrap, &[9]),
            "another owner or epoch",
        );
    }

    foreign_row(&store, &request, 1, Value::Text("owner-a".to_owned()))?;
    assert_eq!(rows(&store, &request)?.len(), 1);
    refused(
        rows(&store, &request_of(encryption_identity(1 << 63), 7)),
        "out of range",
    );
    Ok(())
}
