#![cfg(unix)]

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use piglor_ledger::{open_store, run, Source};
use pos_core::{
    ErasureContainmentGateV1, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRoleV1, PublicKey,
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

fn deletion_request(seed: &[u8; 32]) -> KeyDestructionRequestV1 {
    KeyDestructionRequestV1::new(
        KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1),
        pos_crypto::key_roles::key_material_digest(seed),
        Hash::from_bytes([7; 32]),
    )
}

fn owned_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[test]
fn deletion_rejects_unsafe_paths_and_file_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let request = deletion_request(&[9; 32]);
    let key = directory.path().join("secret.key");

    assert!(piglor_ledger::key_output::delete_owned_secret_key(Path::new("/"), request).is_err());
    assert!(piglor_ledger::key_output::delete_owned_secret_key(directory.path(), request).is_err());

    let missing_parent = directory.path().join("missing").join("secret.key");
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&missing_parent, request).is_err());

    let ancestor = directory.path().join("ancestor");
    std::os::unix::fs::symlink(directory.path(), &ancestor)?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(
        &ancestor.join("secret.key"),
        request
    )
    .is_err());
    std::fs::remove_file(&ancestor)?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777))?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;

    let link = directory.path().join("link.key");
    std::os::unix::fs::symlink(&key, &link)?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&link, request).is_err());
    std::fs::remove_file(&link)?;

    owned_file(&key, b"00")?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    std::fs::hard_link(&key, &link)?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::remove_file(&link)?;

    std::fs::write(&key, vec![b'0'; 129])?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::write(&key, [0xff; 2])?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::write(&key, b"not-hex")?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::write(&key, b"00")?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    std::fs::write(&key, "08".repeat(32))?;
    assert!(piglor_ledger::key_output::delete_owned_secret_key(&key, request).is_err());
    assert!(key.exists());

    std::fs::write(&key, "09".repeat(32))?;
    assert_eq!(
        piglor_ledger::key_output::delete_owned_secret_key(&key, request)?,
        pos_core::deletion_receipt(&request)
    );
    assert!(!key.exists());
    Ok(())
}

#[test]
fn destroy_key_rejects_invalid_flags_and_unknown_registry() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    let valid = destroy_args(&database, &key);
    for flag in ["--source", "--key", "--epoch", "--authorization-digest"] {
        let position = valid
            .iter()
            .position(|argument| argument == flag)
            .ok_or("flag missing")?;
        let mut args = valid.clone();
        args.drain(position..=position + 1);
        assert!(run(&args).is_err(), "{flag}");
    }
    for (flag, value) in [
        ("--source", "toml:unused"),
        ("--source", "invalid"),
        ("--epoch", "invalid"),
        ("--authorization-digest", "not-hex"),
        ("--authorization-digest", "00"),
    ] {
        let mut args = valid.clone();
        let position = args
            .iter()
            .position(|argument| argument == flag)
            .ok_or("flag missing")?;
        args[position + 1] = value.to_owned();
        assert!(run(&args).is_err(), "{flag}={value}");
    }
    assert!(run(&valid).is_err());
    make_key(&key)?;
    drop(open_store(&Source::Store(database), Some(&key))?);
    let mut unknown_epoch = valid;
    let position = unknown_epoch
        .iter()
        .position(|argument| argument == "--epoch")
        .ok_or("epoch flag missing")?;
    unknown_epoch[position + 1] = "2".to_owned();
    assert!(run(&unknown_epoch).is_err());
    Ok(())
}

#[test]
fn startup_rejects_non_utf8_signing_key() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    std::fs::write(&key, [0xff])?;

    assert!(open_store(&Source::Store(database), Some(&key)).is_err());
    Ok(())
}

#[test]
fn destroy_key_reports_store_open_and_registry_load_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    let missing_parent = directory.path().join("missing").join("ledger.db");
    assert!(run(&destroy_args(&missing_parent, &key)).is_err());

    drop(SqliteStore::open(
        database
            .to_str()
            .ok_or("temporary database path is not UTF-8")?,
    )?);
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch(
        "DROP TABLE key_registry;
         CREATE TABLE key_registry (singleton INTEGER PRIMARY KEY, wrong_column BLOB);",
    )?;
    drop(connection);
    assert!(run(&destroy_args(&database, &key)).is_err());
    Ok(())
}

#[test]
fn startup_requires_explicit_recovery_for_multiple_pending_ledger_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    let mut state = pos_core::KeyRegistryStateV1::new();
    for (epoch, byte) in [(1, 1_u8), (2, 2_u8)] {
        let identity =
            KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, epoch);
        state.register_key(KeyRegistrationV1::new(
            identity,
            Hash::from_bytes([byte; 32]),
            Some(PublicKey::from_bytes([byte; 32])),
        ))?;
    }
    let mut store = authorized_store(&database)?;
    store.save_key_registry(&state)?;
    for (epoch, byte) in [(1, 1_u8), (2, 2_u8)] {
        store.begin_key_registry_destruction(KeyDestructionRequestV1::new(
            KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, epoch),
            Hash::from_bytes([byte; 32]),
            Hash::from_bytes([7; 32]),
        ))?;
    }
    drop(store);
    assert_eq!(
        registry(&database)?.pending_destruction_requests().count(),
        2
    );
    assert!(open_store(&Source::Store(database), Some(&key)).is_err());
    Ok(())
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
fn destroy_key_rejects_unbound_absent_path_and_matching_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    let absent = directory.path().join("absent.key");
    let copy = directory.path().join("copy.key");
    make_key(&key)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    assert!(run(&destroy_args(&database, &absent)).is_err());
    owned_file(&copy, &std::fs::read(&key)?)?;
    assert!(run(&destroy_args(&database, &copy)).is_err());

    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let state = registry(&database)?;
    assert!(state
        .active_key(&identity.owner_id, identity.role)
        .is_some());
    assert!(state.tombstone(identity).is_none());
    assert_eq!(state.pending_destruction_requests().count(), 0);
    assert!(key.exists());
    assert!(copy.exists());
    run(&destroy_args(&database, &key))?;
    assert!(!key.exists());
    assert!(copy.exists());
    Ok(())
}

#[test]
fn destroy_key_rejects_replacement_at_the_bound_path() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    let moved = directory.path().join("moved.key");
    make_key(&key)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    std::fs::rename(&key, &moved)?;
    owned_file(&key, &std::fs::read(&moved)?)?;
    assert!(run(&destroy_args(&database, &key)).is_err());
    assert!(moved.exists());
    assert!(key.exists());
    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let state = registry(&database)?;
    assert!(state.tombstone(identity).is_none());
    assert_eq!(state.pending_destruction_requests().count(), 1);
    Ok(())
}

#[test]
fn destroy_key_requires_durable_owner_path_binding() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    make_key(&key)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("DROP TABLE ledger_owned_key_binding_v1")?;
    drop(connection);

    assert!(run(&destroy_args(&database, &key)).is_err());
    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let state = registry(&database)?;
    assert!(state
        .active_key(&identity.owner_id, identity.role)
        .is_some());
    assert_eq!(state.pending_destruction_requests().count(), 0);
    assert!(state.tombstone(identity).is_none());
    assert!(key.exists());
    Ok(())
}

#[test]
fn bound_deletion_failures_keep_the_identity_pending() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let database = directory.path().join("ledger.db");
    let key = directory.path().join("secret.key");
    make_key(&key)?;
    drop(open_store(&Source::Store(database.clone()), Some(&key))?);

    let mut store = authorized_store(&database)?;
    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let digest = store
        .load_key_registry()?
        .ok_or("key registry missing")?
        .key_record(identity)
        .and_then(|record| record.private_material_digest)
        .ok_or("signing material digest missing")?;
    let request = KeyDestructionRequestV1::new(identity, digest, Hash::from_bytes([7; 32]));
    store.begin_key_registry_destruction(request)?;
    let wrong_authorization =
        KeyDestructionRequestV1::new(identity, digest, Hash::from_bytes([8; 32]));
    assert!(piglor_ledger::key_output::destroy_owned_secret_key(
        &mut store,
        &database,
        &key,
        wrong_authorization,
    )
    .is_err());
    assert!(key.exists());
    assert_eq!(
        store
            .load_key_registry()?
            .ok_or("key registry missing")?
            .pending_destruction_requests()
            .count(),
        1
    );

    std::fs::write(&key, b"wrong material")?;
    assert!(piglor_ledger::key_output::destroy_owned_secret_key(
        &mut store, &database, &key, request,
    )
    .is_err());
    assert!(key.exists());
    assert_eq!(
        store
            .load_key_registry()?
            .ok_or("key registry missing")?
            .pending_destruction_requests()
            .count(),
        1
    );
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

    let mut store = authorized_store(&database)?;
    assert!(piglor_ledger::key_output::destroy_owned_secret_key(
        &mut store,
        &database,
        &key,
        deletion_request(&[0; 32]),
    )
    .is_err());
    assert!(key.exists());
    let state = store.load_key_registry()?.ok_or("key registry missing")?;
    let identity = KeyIdentityV1::new("piglor-ledger", KeyRoleV1::TimelineIntegritySigning, 1);
    let digest = state
        .key_record(identity)
        .and_then(|record| record.private_material_digest)
        .ok_or("signing material digest missing")?;
    store.begin_key_registry_destruction(KeyDestructionRequestV1::new(
        identity,
        digest,
        Hash::from_bytes([7; 32]),
    ))?;
    drop(store);

    assert!(run(&destroy_args(&database, &wrong)).is_err());
    assert!(key.exists());
    assert!(wrong.exists());
    assert_eq!(
        registry(&database)?.pending_destruction_requests().count(),
        1
    );

    assert!(open_store(&Source::Store(database.clone()), Some(&wrong)).is_err());
    assert!(wrong.exists());
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
    piglor_ledger::key_output::destroy_owned_secret_key(&mut store, &database, &key, request)?;
    drop(store);
    let state = registry(&database)?;
    assert!(state.tombstone(identity).is_some());
    assert_eq!(state.pending_destruction_requests().count(), 0);
    assert!(!key.exists());
    Ok(())
}
