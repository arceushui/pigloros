#![cfg(unix)]

use std::path::Path;

use piglor_ledger::{open_store, run, Source};
use pos_core::{
    ErasureContainmentGateV1, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRoleV1,
};
use pos_store::sqlite::SqliteStore;

fn make_key(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    run(&[
        "piglor-ledger".into(),
        "keygen".into(),
        "--out".into(),
        path.display().to_string(),
    ])?;
    Ok(())
}

fn destroy_args(database: &Path, key: &Path) -> Vec<String> {
    vec![
        "piglor-ledger".into(),
        "destroy-key".into(),
        "--source".into(),
        format!("store:{}", database.display()),
        "--key".into(),
        key.display().to_string(),
        "--epoch".into(),
        "1".into(),
        "--authorization-digest".into(),
        "07".repeat(32),
    ]
}

fn registry(database: &Path) -> Result<pos_core::KeyRegistryStateV1, Box<dyn std::error::Error>> {
    let store = SqliteStore::open(
        database
            .to_str()
            .ok_or("temporary database path is not UTF-8")?,
    )?;
    Ok(store.load_key_registry()?.ok_or("key registry missing")?)
}

fn authorized_store(database: &Path) -> Result<SqliteStore, Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open(
        database
            .to_str()
            .ok_or("temporary database path is not UTF-8")?,
    )?;
    store.bind_erasure_gate(std::sync::Arc::new(
        ErasureContainmentGateV1::new_test_open(),
    ))?;
    Ok(store)
}

#[test]
fn destroyed_secret_file_is_absent_after_reopen_and_retry() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    make_key(&key)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    let args = destroy_args(&database, &key);
    run(&args)?;
    assert!(!key.exists());
    run(&args)?;

    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let state = registry(&database)?;
    assert!(state.tombstone(identity).is_some());
    assert!(state
        .key_record(identity)
        .is_some_and(|record| record.private_material_digest.is_none()));
    assert!(open_store(&Source::Store(database), Some(&key)).is_err());
    Ok(())
}

#[test]
fn wrong_owned_file_leaves_pending_and_startup_recovers_with_the_correct_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    let wrong = directory.path().join("other.key");
    make_key(&key)?;
    make_key(&wrong)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    assert!(run(&destroy_args(&database, &wrong)).is_err());
    assert!(key.exists());
    assert!(wrong.exists());
    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    assert_eq!(
        registry(&database)?.pending_destruction_requests().count(),
        1
    );

    assert!(open_store(&Source::Store(database.clone()), Some(&key)).is_err());
    assert!(!key.exists());
    assert!(wrong.exists());
    let state = registry(&database)?;
    assert!(state.tombstone(identity).is_some());
    assert_eq!(state.pending_destruction_requests().count(), 0);
    Ok(())
}

#[test]
fn failed_tombstone_commit_keeps_pending_until_absent_file_is_recovered(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    make_key(&key)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let mut store = authorized_store(&database)?;
    let state = store.load_key_registry()?.ok_or("key registry missing")?;
    let digest = state
        .key_record(identity)
        .and_then(|record| record.private_material_digest)
        .ok_or("signing material digest missing")?;
    let request = KeyDestructionRequestV1::new(identity, digest, Hash::from_bytes([7; 32]));
    store.begin_key_registry_destruction(request)?;
    let receipt = piglor_ledger::key_output::delete_owned_secret_key(&key, request)?;
    assert_eq!(receipt, pos_core::deletion_receipt(&request));
    assert!(!key.exists());

    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_final_destruction BEFORE UPDATE ON key_registry
         BEGIN SELECT RAISE(ABORT, 'final destruction commit denied'); END",
    )?;
    assert!(store
        .complete_key_registry_destruction(request, receipt)
        .is_err());
    assert_eq!(
        store
            .load_key_registry()?
            .ok_or("key registry missing")?
            .pending_destruction_requests()
            .count(),
        1
    );

    connection.execute_batch("DROP TRIGGER reject_final_destruction")?;
    drop(connection);
    piglor_ledger::key_output::destroy_owned_secret_key(&mut store, &key, request)?;
    drop(store);
    let state = registry(&database)?;
    assert!(state.tombstone(identity).is_some());
    assert_eq!(state.pending_destruction_requests().count(), 0);
    assert!(!key.exists());
    Ok(())
}
