//! ADR-137 A1-A2 receipts: the table shape, the lookup table of outcomes, the
//! request digest and MAC, and the append-MAC key file custody.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use pos_core::{
    ids::{EntityId, EventId, TimelineId},
    WallTime, APPEND_IDENTITY_RETENTION_MICROS,
};
use rusqlite::{params, types::Value, Connection};
use ulid::Ulid;

use super::{
    insert_subject_append_receipt, lookup_subject_append_receipt,
    purge_expired_subject_append_receipts, subject_append_request_digest, SubjectAppendMacKeyV1,
    SubjectAppendReceiptLookupV1, SubjectAppendReceiptRefusalV1, SubjectAppendReceiptV1,
    APPEND_MAC_KEY_FILE_NAME,
};
use crate::sqlite::SqliteStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];
const DIGEST_A: [u8; 32] = [0x33; 32];
const DIGEST_B: [u8; 32] = [0x44; 32];

fn open_store(directory: &Path) -> Result<SqliteStore, Box<dyn std::error::Error>> {
    let path = directory.join("receipts.sqlite3");
    Ok(SqliteStore::open(path.to_str().ok_or("non-UTF-8 path")?)?)
}

fn receipt(operation_key: [u8; 32], request_digest: [u8; 32]) -> SubjectAppendReceiptV1 {
    SubjectAppendReceiptV1 {
        operation_key,
        subject: EntityId::new(),
        request_digest,
        event_id: EventId::new(),
    }
}

fn raw_insert(conn: &Connection, values: [Value; 5]) -> rusqlite::Result<usize> {
    let [key, owner, digest, event, expires] = values;
    conn.execute(
        "INSERT INTO subject_data_append_receipts
         (operation_key, subject_owner_id, request_digest, event_id, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![key, owner, digest, event, expires],
    )
}

fn good_row(key: u8) -> [Value; 5] {
    [
        Value::Blob(vec![key; 32]),
        Value::Text(format!("subject:{}", "ab".repeat(16))),
        Value::Blob(vec![9; 32]),
        Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        Value::Integer(7),
    ]
}

fn table_exists(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'subject_data_append_receipts'",
        [],
        |row| row.get(0),
    )
}

fn row_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM subject_data_append_receipts",
        [],
        |row| row.get(0),
    )
}

#[test]
fn a_writable_open_creates_the_table_and_a_reopen_keeps_its_rows() -> TestResult {
    let directory = tempfile::tempdir()?;
    {
        let store = open_store(directory.path())?;
        assert!(table_exists(&store.conn)?);
        raw_insert(&store.conn, good_row(1))?;
    }
    let store = open_store(directory.path())?;
    assert_eq!(row_count(&store.conn)?, 1);
    Ok(())
}

#[test]
fn a_read_only_open_creates_nothing_and_a_missing_table_is_unreadable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipts.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch("DROP TABLE subject_data_append_receipts")?;

    let store = SqliteStore::open_read_only(path)?;
    assert!(!table_exists(&store.conn)?);
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &KEY_A, &DIGEST_A),
        Err(SubjectAppendReceiptRefusalV1::Unreadable)
    );
    assert_eq!(
        insert_subject_append_receipt(
            &store.conn,
            &receipt(KEY_A, DIGEST_A),
            WallTime::from_micros(1)
        ),
        Err(SubjectAppendReceiptRefusalV1::NotStored)
    );
    assert_eq!(
        purge_expired_subject_append_receipts(&store.conn, WallTime::from_micros(1)),
        Err(SubjectAppendReceiptRefusalV1::Unreadable)
    );
    Ok(())
}

#[test]
fn a_writable_open_adds_the_table_to_a_store_without_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipts.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch("DROP TABLE subject_data_append_receipts")?;

    let store = SqliteStore::open(path)?;
    assert!(table_exists(&store.conn)?);
    assert_eq!(row_count(&store.conn)?, 0);
    Ok(())
}

#[test]
fn an_incompatible_table_refuses_a_writable_open() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipts.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch(
        "DROP TABLE subject_data_append_receipts;
         CREATE TABLE subject_data_append_receipts (
             operation_key BLOB NOT NULL PRIMARY KEY,
             subject_owner_id TEXT NOT NULL,
             request_digest BLOB NOT NULL,
             event_id TEXT NOT NULL,
             expires_at INTEGER NOT NULL
         );",
    )?;
    let refusal = SqliteStore::open(path)
        .err()
        .ok_or("open accepted the table")?;
    assert!(refusal.to_string().contains("subject_data_append_receipts"));
    Ok(())
}

#[test]
fn the_table_accepts_one_good_row_and_refuses_each_malformed_column() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open_store(directory.path())?;
    assert_eq!(raw_insert(&store.conn, good_row(1))?, 1);
    assert!(
        raw_insert(&store.conn, good_row(1)).is_err(),
        "operation_key is the primary key"
    );

    let owner_hex = "ab".repeat(16);
    let bad: Vec<(usize, Value, &str)> = vec![
        (0, Value::Blob(vec![2; 31]), "31-byte key"),
        (0, Value::Blob(vec![2; 33]), "33-byte key"),
        (0, Value::Text("2".repeat(32)), "text key"),
        (
            1,
            Value::Text(format!("subject:{}", &owner_hex[1..])),
            "39-byte owner",
        ),
        (
            1,
            Value::Text(format!("subject:{owner_hex}0")),
            "41-byte owner",
        ),
        (
            1,
            Value::Text(format!("xubject:{owner_hex}")),
            "wrong prefix",
        ),
        (
            1,
            Value::Text(format!("subject:{}", owner_hex.to_uppercase())),
            "upper-case digits",
        ),
        (
            1,
            Value::Text(format!("subject:{}g", &owner_hex[1..])),
            "non-hex digit",
        ),
        (
            1,
            Value::Blob(format!("subject:{owner_hex}").into_bytes()),
            "blob owner",
        ),
        (2, Value::Blob(vec![9; 31]), "31-byte digest"),
        (2, Value::Blob(vec![9; 33]), "33-byte digest"),
        (2, Value::Text("9".repeat(32)), "text digest"),
        (
            3,
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FA".to_owned()),
            "25-byte event id",
        ),
        (
            3,
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAVV".to_owned()),
            "27-byte event id",
        ),
        (
            3,
            Value::Text("01arz3ndektsv4rrffq69g5fav".to_owned()),
            "lower-case event id",
        ),
        (3, Value::Blob(vec![b'A'; 26]), "blob event id"),
        (4, Value::Text("7".to_owned()), "text expiry"),
        (4, Value::Real(7.5), "real expiry"),
    ];
    for (column, value, label) in bad {
        let mut values = good_row(3);
        values[column] = value;
        assert!(raw_insert(&store.conn, values).is_err(), "{label}");
    }
    assert_eq!(row_count(&store.conn)?, 1, "no malformed row was stored");
    Ok(())
}

#[test]
fn a_lookup_is_absent_duplicate_or_a_conflict() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open_store(directory.path())?;
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &KEY_A, &DIGEST_A),
        Ok(SubjectAppendReceiptLookupV1::Absent)
    );
    let stored = receipt(KEY_A, DIGEST_A);
    insert_subject_append_receipt(&store.conn, &stored, WallTime::from_micros(5))?;
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &KEY_A, &DIGEST_A),
        Ok(SubjectAppendReceiptLookupV1::Duplicate(stored.event_id))
    );
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &KEY_A, &DIGEST_B),
        Ok(SubjectAppendReceiptLookupV1::OperationConflict)
    );
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &KEY_B, &DIGEST_A),
        Ok(SubjectAppendReceiptLookupV1::Absent),
        "another operation key never sees the receipt"
    );
    Ok(())
}

#[test]
fn a_matching_row_that_does_not_parse_is_malformed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open_store(directory.path())?;
    store
        .conn
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    let cases: Vec<(u8, Value, Value)> = vec![
        (
            1,
            Value::Blob(vec![3; 31]),
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        ),
        (
            2,
            Value::Integer(5),
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        ),
        (
            3,
            Value::Blob(DIGEST_A.to_vec()),
            Value::Text("not-a-ulid".to_owned()),
        ),
        (4, Value::Blob(DIGEST_A.to_vec()), Value::Integer(9)),
    ];
    for (key, digest, event) in cases {
        let mut values = good_row(key);
        values[2] = digest;
        values[3] = event;
        raw_insert(&store.conn, values)?;
        assert_eq!(
            lookup_subject_append_receipt(&store.conn, &[key; 32], &DIGEST_A),
            Err(SubjectAppendReceiptRefusalV1::Malformed),
            "row {key}"
        );
    }
    let mut values = good_row(5);
    values[2] = Value::Blob(DIGEST_B.to_vec());
    values[3] = Value::Text("not-a-ulid".to_owned());
    raw_insert(&store.conn, values)?;
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &[5; 32], &DIGEST_A),
        Ok(SubjectAppendReceiptLookupV1::OperationConflict),
        "a different digest conflicts without reading the Event id"
    );
    Ok(())
}

#[test]
fn an_insert_stores_the_owner_event_and_retention_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open_store(directory.path())?;
    let stored = receipt(KEY_A, DIGEST_A);
    insert_subject_append_receipt(&store.conn, &stored, WallTime::from_micros(1_000))?;
    let (owner, digest, event, expires): (String, Vec<u8>, String, i64) = store.conn.query_row(
        "SELECT subject_owner_id, request_digest, event_id, expires_at
         FROM subject_data_append_receipts WHERE operation_key = ?1",
        params![KEY_A.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        owner,
        format!(
            "subject:{:032x}",
            u128::from_be_bytes(stored.subject.inner().to_bytes())
        )
    );
    assert_eq!(digest, DIGEST_A);
    assert_eq!(event, stored.event_id.to_string());
    assert_eq!(
        u64::try_from(expires)?,
        1_000 + APPEND_IDENTITY_RETENTION_MICROS
    );
    Ok(())
}

#[test]
fn an_insert_never_replaces_a_receipt_and_refuses_unbindable_requests() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open_store(directory.path())?;
    let first = receipt(KEY_A, DIGEST_A);
    insert_subject_append_receipt(&store.conn, &first, WallTime::from_micros(1))?;
    assert_eq!(
        insert_subject_append_receipt(
            &store.conn,
            &receipt(KEY_A, DIGEST_B),
            WallTime::from_micros(1)
        ),
        Err(SubjectAppendReceiptRefusalV1::NotStored)
    );
    assert_eq!(
        lookup_subject_append_receipt(&store.conn, &KEY_A, &DIGEST_A),
        Ok(SubjectAppendReceiptLookupV1::Duplicate(first.event_id)),
        "the first receipt is untouched"
    );

    let nil = SubjectAppendReceiptV1 {
        subject: EntityId::from_ulid(Ulid::nil()),
        ..receipt(KEY_B, DIGEST_A)
    };
    assert_eq!(
        insert_subject_append_receipt(&store.conn, &nil, WallTime::from_micros(1)),
        Err(SubjectAppendReceiptRefusalV1::InvalidRequest)
    );
    let past_unsigned_range = WallTime::from_micros(u64::MAX);
    assert_eq!(
        insert_subject_append_receipt(&store.conn, &receipt(KEY_B, DIGEST_A), past_unsigned_range),
        Err(SubjectAppendReceiptRefusalV1::InvalidRequest)
    );
    let past_signed_range = WallTime::from_micros(u64::try_from(i64::MAX)?);
    assert_eq!(
        insert_subject_append_receipt(&store.conn, &receipt(KEY_B, DIGEST_A), past_signed_range),
        Err(SubjectAppendReceiptRefusalV1::InvalidRequest)
    );
    assert_eq!(
        row_count(&store.conn)?,
        1,
        "no refused request stored a row"
    );
    Ok(())
}

#[test]
fn a_purge_removes_only_receipts_whose_retention_has_ended() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = open_store(directory.path())?;
    let horizon = APPEND_IDENTITY_RETENTION_MICROS;
    for (key, admitted) in [(1_u8, 10_u64), (2, 11), (3, 12)] {
        insert_subject_append_receipt(
            &store.conn,
            &receipt([key; 32], DIGEST_A),
            WallTime::from_micros(admitted),
        )?;
    }
    assert_eq!(
        purge_expired_subject_append_receipts(&store.conn, WallTime::from_micros(horizon + 9))?,
        0,
        "nothing expires before its horizon"
    );
    assert_eq!(
        purge_expired_subject_append_receipts(&store.conn, WallTime::from_micros(horizon + 11))?,
        2,
        "a receipt expires at its horizon, inclusive"
    );
    assert_eq!(row_count(&store.conn)?, 1);
    assert_eq!(
        purge_expired_subject_append_receipts(&store.conn, WallTime::from_micros(u64::MAX))?,
        1,
        "an unrepresentable clock reading purges everything expirable"
    );
    assert_eq!(row_count(&store.conn)?, 0);
    Ok(())
}

fn digest_of(
    subject: EntityId,
    timeline: TimelineId,
    field_tag: &str,
    predecessor: Option<EventId>,
    mac: &[u8; 32],
) -> Result<[u8; 32], SubjectAppendReceiptRefusalV1> {
    subject_append_request_digest(subject, timeline, field_tag, predecessor, mac)
}

#[test]
fn the_request_digest_is_the_documented_blake3_preimage() -> TestResult {
    let subject = EntityId::new();
    let timeline = TimelineId::new();
    let predecessor = EventId::new();
    let mac = [0x5a; 32];
    let mut preimage = b"pigloros/subject-data-append-request/v1\0".to_vec();
    preimage.extend(
        format!(
            "subject:{:032x}",
            u128::from_be_bytes(subject.inner().to_bytes())
        )
        .bytes(),
    );
    preimage.push(0);
    preimage.extend(timeline.inner().to_bytes());
    preimage.extend(b"weights");
    preimage.push(0);
    preimage.extend(predecessor.inner().to_bytes());
    preimage.extend(mac);
    assert_eq!(
        digest_of(subject, timeline, "weights", Some(predecessor), &mac)?,
        *blake3::hash(&preimage).as_bytes()
    );

    let mut zero_preimage = preimage.clone();
    let tail = zero_preimage.len() - 32 - 16;
    zero_preimage[tail..tail + 16].fill(0);
    assert_eq!(
        digest_of(subject, timeline, "weights", None, &mac)?,
        *blake3::hash(&zero_preimage).as_bytes(),
        "no predecessor binds sixteen zero bytes"
    );
    assert_eq!(
        digest_of(
            subject,
            timeline,
            "weights",
            Some(EventId::from_ulid(Ulid::nil())),
            &mac
        )?,
        digest_of(subject, timeline, "weights", None, &mac)?
    );
    Ok(())
}

#[test]
fn every_request_component_changes_the_digest() -> TestResult {
    let subject = EntityId::new();
    let timeline = TimelineId::new();
    let predecessor = EventId::new();
    let mac = [0x5a; 32];
    let base = digest_of(subject, timeline, "weights", Some(predecessor), &mac)?;
    let variants = [
        digest_of(
            EntityId::new(),
            timeline,
            "weights",
            Some(predecessor),
            &mac,
        )?,
        digest_of(
            subject,
            TimelineId::new(),
            "weights",
            Some(predecessor),
            &mac,
        )?,
        digest_of(subject, timeline, "weight", Some(predecessor), &mac)?,
        digest_of(subject, timeline, "weights", Some(EventId::new()), &mac)?,
        digest_of(subject, timeline, "weights", None, &mac)?,
        digest_of(subject, timeline, "weights", Some(predecessor), &[0x5b; 32])?,
    ];
    for (index, variant) in variants.iter().enumerate() {
        assert_ne!(*variant, base, "variant {index}");
    }
    assert_eq!(
        digest_of(subject, timeline, "weights", Some(predecessor), &mac)?,
        base,
        "the digest is deterministic"
    );
    Ok(())
}

#[test]
fn the_request_digest_refuses_a_nil_subject_and_a_bad_field_tag() {
    let timeline = TimelineId::new();
    let mac = [0; 32];
    let refused = Err(SubjectAppendReceiptRefusalV1::InvalidRequest);
    assert_eq!(
        digest_of(
            EntityId::from_ulid(Ulid::nil()),
            timeline,
            "weights",
            None,
            &mac
        ),
        refused
    );
    assert_eq!(
        digest_of(EntityId::new(), timeline, "", None, &mac),
        refused
    );
    assert_eq!(
        digest_of(EntityId::new(), timeline, "poids\u{e9}", None, &mac),
        refused
    );
    assert_eq!(
        digest_of(EntityId::new(), timeline, &"a".repeat(129), None, &mac),
        refused
    );
    assert!(digest_of(EntityId::new(), timeline, &"a".repeat(128), None, &mac).is_ok());
}

fn key_path(directory: &Path) -> std::path::PathBuf {
    directory.join(APPEND_MAC_KEY_FILE_NAME)
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn fixed_entropy(bytes: &mut [u8]) -> Result<(), ()> {
    if bytes.is_empty() {
        return Err(());
    }
    bytes.fill(7);
    Ok(())
}

fn failing_entropy(_: &mut [u8]) -> Result<(), ()> {
    Err(())
}

fn write_key(path: &Path, bytes: &[u8], mode: u32) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn assert_regenerated(directory: &Path) -> TestResult {
    let path = key_path(directory);
    let key = SubjectAppendMacKeyV1::load_or_create_with(directory, euid(), fixed_entropy)?;
    assert_eq!(fs::read(&path)?, [7; 32]);
    let metadata = fs::metadata(&path)?;
    assert_eq!(metadata.mode(), 0o100_600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(key.request_mac("f", b"p"), blake3_mac([7; 32], "f", b"p"));
    Ok(())
}

fn blake3_mac(key: [u8; 32], field_tag: &str, plaintext: &[u8]) -> [u8; 32] {
    let mut input = b"pigloros/subject-data-append-mac/v1\0".to_vec();
    input.extend(field_tag.as_bytes());
    input.push(0);
    input.extend(plaintext);
    *blake3::keyed_hash(&key, &input).as_bytes()
}

#[test]
fn a_missing_key_is_created_once_and_then_reloaded() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert_regenerated(directory.path())?;
    let reloaded =
        SubjectAppendMacKeyV1::load_or_create_with(directory.path(), euid(), failing_entropy)?;
    assert_eq!(
        reloaded.request_mac("f", b"p"),
        blake3_mac([7; 32], "f", b"p"),
        "a valid key is loaded without drawing entropy"
    );
    Ok(())
}

#[test]
fn the_public_loader_uses_system_entropy_and_the_current_user() -> TestResult {
    let directory = tempfile::tempdir()?;
    let first = SubjectAppendMacKeyV1::load_or_create(directory.path())?;
    let stored = fs::read(key_path(directory.path()))?;
    assert_eq!(stored.len(), 32);
    assert_ne!(stored, [0; 32]);
    let second = SubjectAppendMacKeyV1::load_or_create(directory.path())?;
    assert_eq!(first.request_mac("f", b"p"), second.request_mac("f", b"p"));
    Ok(())
}

#[test]
fn each_corrupt_key_file_is_replaced() -> TestResult {
    let corrupt: [(&str, &[u8], u32); 5] = [
        ("short", &[1; 31], 0o600),
        ("long", &[1; 33], 0o600),
        ("group readable", &[1; 32], 0o644),
        ("owner executable", &[1; 32], 0o700),
        ("setuid", &[1; 32], 0o4600),
    ];
    for (label, bytes, mode) in corrupt {
        let directory = tempfile::tempdir()?;
        write_key(&key_path(directory.path()), bytes, mode)?;
        assert_regenerated(directory.path()).map_err(|error| format!("{label}: {error}"))?;
    }
    Ok(())
}

#[test]
fn a_key_owned_by_another_user_is_replaced() -> TestResult {
    let directory = tempfile::tempdir()?;
    write_key(&key_path(directory.path()), &[1; 32], 0o600)?;
    let key = SubjectAppendMacKeyV1::load_or_create_with(
        directory.path(),
        euid().wrapping_add(1),
        fixed_entropy,
    )?;
    assert_eq!(key.request_mac("f", b"p"), blake3_mac([7; 32], "f", b"p"));
    Ok(())
}

#[test]
fn a_linked_key_file_is_replaced_without_touching_the_other_link() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = key_path(directory.path());
    write_key(&path, &[1; 32], 0o600)?;
    let other = directory.path().join("other-link");
    fs::hard_link(&path, &other)?;
    assert_regenerated(directory.path())?;
    assert_eq!(fs::read(&other)?, [1; 32]);
    Ok(())
}

#[test]
fn a_symlinked_key_file_is_replaced_without_following_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let target = directory.path().join("target");
    write_key(&target, &[1; 32], 0o600)?;
    std::os::unix::fs::symlink(&target, key_path(directory.path()))?;
    assert_regenerated(directory.path())?;
    assert_eq!(fs::read(&target)?, [1; 32], "the target is untouched");
    Ok(())
}

#[test]
fn a_directory_in_place_of_the_key_is_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::create_dir(key_path(directory.path()))?;
    assert!(matches!(
        SubjectAppendMacKeyV1::load_or_create_with(directory.path(), euid(), fixed_entropy),
        Err(SubjectAppendReceiptRefusalV1::KeyUnavailable)
    ));
    Ok(())
}

#[test]
fn a_missing_state_directory_is_unavailable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("absent");
    assert!(matches!(
        SubjectAppendMacKeyV1::load_or_create_with(&missing, euid(), fixed_entropy),
        Err(SubjectAppendReceiptRefusalV1::KeyUnavailable)
    ));
    Ok(())
}

#[test]
fn a_failed_entropy_source_creates_no_key_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert!(matches!(
        SubjectAppendMacKeyV1::load_or_create_with(directory.path(), euid(), failing_entropy),
        Err(SubjectAppendReceiptRefusalV1::KeyUnavailable)
    ));
    assert!(!key_path(directory.path()).exists());
    Ok(())
}

#[test]
fn the_request_mac_is_keyed_and_binds_the_field_tag_and_plaintext() -> TestResult {
    let directory = tempfile::tempdir()?;
    let key = SubjectAppendMacKeyV1::load_or_create_with(directory.path(), euid(), fixed_entropy)?;
    let mac = key.request_mac("weights", b"plaintext");
    assert_eq!(mac, blake3_mac([7; 32], "weights", b"plaintext"));
    assert_ne!(mac, key.request_mac("weight", b"plaintext"));
    assert_ne!(mac, key.request_mac("weights", b"plaintex"));
    assert_ne!(
        key.request_mac("a", b"bc"),
        key.request_mac("ab", b"c"),
        "the field tag and plaintext are separated"
    );
    let other = tempfile::tempdir()?;
    write_key(&key_path(other.path()), &[8; 32], 0o600)?;
    let other_key =
        SubjectAppendMacKeyV1::load_or_create_with(other.path(), euid(), failing_entropy)?;
    assert_ne!(mac, other_key.request_mac("weights", b"plaintext"));
    assert_eq!(format!("{key:?}"), "SubjectAppendMacKeyV1(..)");
    Ok(())
}

#[test]
fn refusals_display_fixed_text() {
    let texts = [
        (
            SubjectAppendReceiptRefusalV1::InvalidRequest,
            "subject append receipt request is invalid",
        ),
        (
            SubjectAppendReceiptRefusalV1::Unreadable,
            "subject append receipts are unreadable",
        ),
        (
            SubjectAppendReceiptRefusalV1::Malformed,
            "subject append receipt is malformed",
        ),
        (
            SubjectAppendReceiptRefusalV1::NotStored,
            "subject append receipt was not stored",
        ),
        (
            SubjectAppendReceiptRefusalV1::KeyUnavailable,
            "subject append MAC key is unavailable",
        ),
    ];
    for (refusal, text) in texts {
        assert_eq!(refusal.to_string(), text);
    }
}
