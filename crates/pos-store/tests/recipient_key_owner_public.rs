#![cfg(all(feature = "sqlite", unix))]

//! Public black-box contracts for role-4 recipient private-file custody.

use std::{os::unix::fs::PermissionsExt, sync::mpsc, thread};

use pos_core::{EntityId, EventStore, Hash, KeyDestructionRequestV1, KeyRoleV1};
use pos_store::sqlite::{RecipientKeyOwnerV1, SqliteStore};

fn private_directory(
    root: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let directory = root.join("recipient-private");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn enrolled_owner() -> Result<
    (
        tempfile::TempDir,
        SqliteStore,
        RecipientKeyOwnerV1,
        pos_core::RecipientKeyDescriptorV1,
    ),
    Box<dyn std::error::Error>,
> {
    let temporary = tempfile::tempdir()?;
    let private_directory = private_directory(temporary.path())?;
    let mut store = SqliteStore::open(
        temporary
            .path()
            .join("recipient.sqlite")
            .to_str()
            .ok_or("database path is not UTF-8")?,
    )?;
    let owner = RecipientKeyOwnerV1::open(private_directory, EntityId::new())?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    Ok((temporary, store, owner, descriptor))
}

fn only_private_file(
    directory: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let mut entries = std::fs::read_dir(directory)?;
    let path = entries.next().ok_or("private key file is absent")??.path();
    if entries.next().is_some() {
        return Err("private directory has more than one entry".into());
    }
    Ok(path)
}

fn recipient_private_path(
    directory: &std::path::Path,
    descriptor: pos_core::RecipientKeyDescriptorV1,
) -> std::path::PathBuf {
    let mut name = format!("recipient-{}-", descriptor.identity().epoch);
    for byte in descriptor.fingerprint().as_bytes() {
        name.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        name.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    name.push_str(".key");
    directory.join(name)
}

fn begin_pending_destruction(
    store: &mut SqliteStore,
    descriptor: pos_core::RecipientKeyDescriptorV1,
    authorization_digest: Hash,
) -> Result<(), Box<dyn std::error::Error>> {
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    let digest = registry
        .key_record(descriptor.identity())
        .and_then(|record| record.private_material_digest)
        .ok_or("recipient material digest is absent")?;
    store.begin_key_registry_destruction(KeyDestructionRequestV1::new(
        descriptor.identity(),
        digest,
        authorization_digest,
    ))?;
    Ok(())
}

#[test]
fn recipient_owner_public_contract_recovers_and_destroys_the_bound_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    assert_eq!(store.recover_recipient_keys(&owner)?, vec![descriptor]);

    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    let metadata = std::fs::metadata(&path)?;
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::os::unix::fs::MetadataExt::nlink(&metadata), 1);

    store.destroy_recipient_key(
        &owner,
        descriptor.identity().epoch,
        Hash::from_bytes([8; 32]),
    )?;
    assert!(!path.exists());
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry
        .active_key(
            &descriptor.identity().owner_id,
            KeyRoleV1::ExportRecipientEncryption
        )
        .is_none());
    assert!(registry.tombstone(descriptor.identity()).is_some());
    let receipt_count = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?
        .query_row(
            "SELECT COUNT(*) FROM recipient_key_destruction_receipts_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    assert_eq!(receipt_count, 1);
    assert!(store.recover_recipient_keys(&owner)?.is_empty());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_replaced_file_and_keeps_key_active(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    std::fs::rename(&path, path.with_extension("original"))?;
    std::fs::write(&path, [9_u8; 32])?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    assert!(store.recover_recipient_keys(&owner).is_err());
    assert!(store
        .destroy_recipient_key(
            &owner,
            descriptor.identity().epoch,
            Hash::from_bytes([9; 32])
        )
        .is_err());
    drop(store);
    let mut resumed = SqliteStore::open(
        temporary
            .path()
            .join("recipient.sqlite")
            .to_str()
            .ok_or("database path is not UTF-8")?,
    )?;
    assert!(resumed
        .destroy_recipient_key(
            &owner,
            descriptor.identity().epoch,
            Hash::from_bytes([9; 32])
        )
        .is_err());
    let registry = resumed
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry
        .active_key(
            &descriptor.identity().owner_id,
            KeyRoleV1::ExportRecipientEncryption
        )
        .is_some());
    assert!(registry.tombstone(descriptor.identity()).is_none());
    let receipt_count = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?
        .query_row(
            "SELECT COUNT(*) FROM recipient_key_destruction_receipts_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    assert_eq!(receipt_count, 0);
    Ok(())
}

#[test]
fn recipient_owner_public_contract_keeps_using_the_retained_directory_descriptor(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, descriptor) = enrolled_owner()?;
    let original = temporary.path().join("recipient-private");
    let moved = temporary.path().join("recipient-private-moved");
    std::fs::rename(&original, &moved)?;
    std::fs::create_dir(&original)?;
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(original.join("untrusted.key"), [9_u8; 32])?;
    std::fs::set_permissions(
        original.join("untrusted.key"),
        std::fs::Permissions::from_mode(0o600),
    )?;

    assert_eq!(store.recover_recipient_keys(&owner)?, vec![descriptor]);
    Ok(())
}

#[test]
fn recipient_owner_public_contract_claims_directory_for_one_grantee_across_path_aliases(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = private_directory(temporary.path())?;
    let database = temporary.path().join("recipient.sqlite");
    let grantee = EntityId::new();
    let mut store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    let owner = RecipientKeyOwnerV1::open(directory.clone(), grantee)?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let same_grantee_alias = RecipientKeyOwnerV1::open(directory.join("."), grantee)?;
    let other_grantee = RecipientKeyOwnerV1::open(directory.clone(), EntityId::new())?;
    let path = only_private_file(&directory)?;

    assert_eq!(
        store.recover_recipient_keys(&same_grantee_alias)?,
        vec![descriptor]
    );
    assert!(store.recover_recipient_keys(&other_grantee).is_err());
    assert!(store.enroll_recipient_key(&other_grantee).is_err());
    assert!(store
        .destroy_recipient_key(
            &other_grantee,
            descriptor.identity().epoch,
            Hash::from_bytes([83; 32]),
        )
        .is_err());
    assert!(path.exists());
    assert_eq!(store.recover_recipient_keys(&owner)?, vec![descriptor]);
    Ok(())
}

#[test]
fn recipient_owner_public_contract_ignores_foreign_directory_inventory_with_shared_key_coordinates(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = private_directory(temporary.path())?;
    let foreign_directory = temporary.path().join("recipient-private-foreign");
    std::fs::create_dir(&foreign_directory)?;
    std::fs::set_permissions(&foreign_directory, std::fs::Permissions::from_mode(0o700))?;
    let database = temporary.path().join("recipient.sqlite");
    let grantee = EntityId::new();
    let foreign_grantee = EntityId::new();
    let mut store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    let owner = RecipientKeyOwnerV1::open(directory.clone(), grantee)?;
    let descriptor = store.enroll_recipient_key(&owner)?;
    let foreign_descriptor = pos_core::RecipientKeyDescriptorV1::for_grantee(
        foreign_grantee,
        descriptor.identity().epoch,
        descriptor.public_key(),
    )?;
    let local_path = only_private_file(&directory)?;
    let foreign_path = recipient_private_path(&foreign_directory, foreign_descriptor);
    std::fs::copy(&local_path, &foreign_path)?;
    std::fs::set_permissions(&foreign_path, std::fs::Permissions::from_mode(0o600))?;
    let foreign_metadata = std::fs::metadata(&foreign_path)?;
    let connection = rusqlite::Connection::open(&database)?;
    let material_digest = connection.query_row(
        "SELECT material_digest FROM recipient_key_inventory_v1 WHERE owner_id = ?1 AND epoch = ?2",
        rusqlite::params![
            descriptor.identity().owner_id.as_str(),
            i64::try_from(descriptor.identity().epoch)?,
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    connection.execute(
        "INSERT INTO recipient_key_inventory_v1
         (owner_id, epoch, descriptor, material_digest, private_path, file_device, file_inode, file_uid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            foreign_descriptor.identity().owner_id.as_str(),
            i64::try_from(foreign_descriptor.identity().epoch)?,
            foreign_descriptor.encode(),
            material_digest,
            foreign_path.as_os_str().as_encoded_bytes(),
            std::os::unix::fs::MetadataExt::dev(&foreign_metadata).to_be_bytes(),
            std::os::unix::fs::MetadataExt::ino(&foreign_metadata).to_be_bytes(),
            std::os::unix::fs::MetadataExt::uid(&foreign_metadata).to_be_bytes(),
        ],
    )?;

    assert_eq!(store.recover_recipient_keys(&owner)?, vec![descriptor]);
    Ok(())
}

#[test]
fn recipient_owner_public_contract_quarantines_unregistered_staged_material(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute_batch(
        "CREATE TRIGGER reject_recipient_inventory
         BEFORE INSERT ON recipient_key_inventory_v1
         BEGIN SELECT RAISE(ABORT, 'injected inventory failure'); END;",
    )?;

    assert!(store.enroll_recipient_key(&owner).is_err());
    assert_eq!(store.recover_recipient_keys(&owner)?, vec![descriptor]);
    let names = std::fs::read_dir(temporary.path().join("recipient-private"))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(names.iter().any(|name| name.ends_with(".orphan")));
    Ok(())
}

#[test]
fn recipient_owner_public_contract_serializes_recovery_with_enrollment_staging(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let database = temporary.path().join("recipient.sqlite");
    let staged = temporary
        .path()
        .join("recipient-private")
        .join("recipient-staged.key");
    std::fs::write(&staged, [1_u8; 32])?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
    let writer = rusqlite::Connection::open(&database)?;
    writer.execute_batch("BEGIN IMMEDIATE")?;
    let (started_sender, started_receiver) = mpsc::channel();
    let recovery = thread::spawn(move || {
        if started_sender.send(()).is_err() {
            return Err(pos_core::CoreError::Storage(
                "recovery start signal did not reach test coordinator".to_owned(),
            ));
        }
        store.recover_recipient_keys(&owner)
    });
    started_receiver.recv()?;
    assert!(staged.exists());
    writer.execute_batch("COMMIT")?;
    assert!(recovery
        .join()
        .map_err(|_| "recovery thread panicked")?
        .is_ok());
    assert!(!staged.exists());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_recovers_retained_epoch_after_rotation_and_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = private_directory(temporary.path())?;
    let grantee = EntityId::new();
    let database = temporary.path().join("recipient.sqlite");
    let mut store = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    let owner = RecipientKeyOwnerV1::open(directory.clone(), grantee)?;
    let first = store.enroll_recipient_key(&owner)?;
    let second = store.enroll_recipient_key(&owner)?;
    drop(store);
    drop(owner);

    let reopened = SqliteStore::open(database.to_str().ok_or("database path is not UTF-8")?)?;
    let reopened_owner = RecipientKeyOwnerV1::open(directory, grantee)?;
    assert_eq!(
        reopened.recover_recipient_keys(&reopened_owner)?,
        vec![first, second]
    );
    Ok(())
}

#[test]
fn recipient_owner_public_contract_recovers_live_epoch_after_old_epoch_destruction(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = private_directory(temporary.path())?;
    let grantee = EntityId::new();
    let database = temporary.path().join("recipient.sqlite");
    let database_path = database.to_str().ok_or("database path is not UTF-8")?;
    let mut store = SqliteStore::open(database_path)?;
    let owner = RecipientKeyOwnerV1::open(directory.clone(), grantee)?;
    let first = store.enroll_recipient_key(&owner)?;
    let first_path = only_private_file(&directory)?;
    let second = store.enroll_recipient_key(&owner)?;

    store.destroy_recipient_key(&owner, first.identity().epoch, Hash::from_bytes([71; 32]))?;
    assert!(!first_path.exists());
    assert_eq!(store.recover_recipient_keys(&owner)?, vec![second]);
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry.tombstone(first.identity()).is_some());
    drop(store);
    drop(owner);

    let connection = rusqlite::Connection::open(&database)?;
    let inventory_count = connection.query_row(
        "SELECT COUNT(*) FROM recipient_key_inventory_v1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let receipt_count = connection.query_row(
        "SELECT COUNT(*) FROM recipient_key_destruction_receipts_v1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!((inventory_count, receipt_count), (1, 1));

    let reopened = SqliteStore::open(database_path)?;
    let reopened_owner = RecipientKeyOwnerV1::open(directory, grantee)?;
    assert_eq!(
        reopened.recover_recipient_keys(&reopened_owner)?,
        vec![second]
    );
    Ok(())
}

#[test]
fn recipient_owner_public_contract_keeps_destruction_pending_if_inventory_removal_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    for trigger_action in ["RAISE(IGNORE)", "RAISE(ABORT, 'delete refused')"] {
        let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
        let path = only_private_file(&temporary.path().join("recipient-private"))?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
        connection.execute_batch(&format!(
            "CREATE TRIGGER refuse_recipient_inventory_delete
             BEFORE DELETE ON recipient_key_inventory_v1
             BEGIN SELECT {trigger_action}; END;"
        ))?;

        assert!(store
            .destroy_recipient_key(
                &owner,
                descriptor.identity().epoch,
                Hash::from_bytes([72; 32])
            )
            .is_err());
        assert!(!path.exists());
        let registry = store
            .load_key_registry()?
            .ok_or("recipient registry is absent")?;
        assert!(registry.tombstone(descriptor.identity()).is_none());
        assert!(registry
            .pending_destruction_requests()
            .any(|pending| pending.identity == descriptor.identity()));
        let inventory_count = connection.query_row(
            "SELECT COUNT(*) FROM recipient_key_inventory_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let receipt_count = connection.query_row(
            "SELECT COUNT(*) FROM recipient_key_destruction_receipts_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!((inventory_count, receipt_count), (1, 0));
        assert!(store.recover_recipient_keys(&owner).is_err());
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_never_finalizes_a_pending_missing_file_without_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    let digest = registry
        .key_record(descriptor.identity())
        .and_then(|record| record.private_material_digest)
        .ok_or("recipient material digest is absent")?;
    let request =
        KeyDestructionRequestV1::new(descriptor.identity(), digest, Hash::from_bytes([11; 32]));
    store.begin_key_registry_destruction(request)?;
    std::fs::remove_file(only_private_file(
        &temporary.path().join("recipient-private"),
    )?)?;
    drop(store);

    let mut resumed = SqliteStore::open(
        temporary
            .path()
            .join("recipient.sqlite")
            .to_str()
            .ok_or("database path is not UTF-8")?,
    )?;
    assert!(resumed
        .destroy_recipient_key(
            &owner,
            descriptor.identity().epoch,
            Hash::from_bytes([11; 32])
        )
        .is_err());
    let resumed_registry = resumed
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(resumed_registry.tombstone(descriptor.identity()).is_none());
    let receipt_count = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?
        .query_row(
            "SELECT COUNT(*) FROM recipient_key_destruction_receipts_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    assert_eq!(receipt_count, 0);
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_insecure_mode_and_multiple_links(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
    assert!(store.recover_recipient_keys(&owner).is_err());

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::hard_link(&path, path.with_extension("extra-link"))?;
    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_refuses_a_symlinked_private_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    let target = path.with_extension("target");
    std::fs::rename(&path, &target)?;
    std::os::unix::fs::symlink(target, &path)?;
    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_a_tampered_file_owner_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute(
        "UPDATE recipient_key_inventory_v1 SET file_uid = ?1",
        rusqlite::params![vec![255_u8; 4]],
    )?;
    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_unsafe_owner_directories(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("unsafe");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    assert!(RecipientKeyOwnerV1::open(&directory, EntityId::new()).is_err());
    std::fs::remove_dir(&directory)?;
    assert!(RecipientKeyOwnerV1::open(&directory, EntityId::new()).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_unknown_destruction_epoch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, mut store, owner, descriptor) = enrolled_owner()?;
    assert!(store
        .destroy_recipient_key(
            &owner,
            descriptor
                .identity()
                .epoch
                .checked_add(1)
                .ok_or("epoch overflow")?,
            Hash::from_bytes([46; 32]),
        )
        .is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_a_descriptor_with_changed_public_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, descriptor) = enrolled_owner()?;
    let mut changed = descriptor.encode();
    *changed.last_mut().ok_or("recipient descriptor is empty")? ^= 1;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute(
        "UPDATE recipient_key_inventory_v1 SET descriptor = ?1",
        [changed],
    )?;

    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_duplicate_inventory_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute_batch(
        "CREATE TABLE recipient_key_inventory_duplicate AS
             SELECT * FROM recipient_key_inventory_v1;
         DROP TABLE recipient_key_inventory_v1;
         ALTER TABLE recipient_key_inventory_duplicate RENAME TO recipient_key_inventory_v1;
         INSERT INTO recipient_key_inventory_v1
             SELECT * FROM recipient_key_inventory_v1;",
    )?;

    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_a_missing_live_inventory_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, descriptor) = enrolled_owner()?;
    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute(
        "DELETE FROM recipient_key_inventory_v1 WHERE owner_id = ?1 AND epoch = ?2",
        rusqlite::params![
            descriptor.identity().owner_id.as_str(),
            i64::try_from(descriptor.identity().epoch)?,
        ],
    )?;

    assert!(store.recover_recipient_keys(&owner).is_err());
    assert!(path.exists());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_fails_closed_without_registry_or_entry_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = private_directory(temporary.path())?;
    let store = SqliteStore::open(
        temporary
            .path()
            .join("recipient.sqlite")
            .to_str()
            .ok_or("database path is not UTF-8")?,
    )?;
    let owner = RecipientKeyOwnerV1::open(directory, EntityId::new())?;
    assert!(store.recover_recipient_keys(&owner).is_err());

    for path in [b"/".as_slice(), b"a/b", b"foreign.key"] {
        let (temporary, store, owner, _) = enrolled_owner()?;
        let private = only_private_file(&temporary.path().join("recipient-private"))?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
        connection.execute(
            "UPDATE recipient_key_inventory_v1 SET private_path = ?1",
            [path],
        )?;

        assert!(store.recover_recipient_keys(&owner).is_err());
        assert!(private.exists());
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_keeps_missing_and_pending_material_unavailable(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    std::fs::remove_file(&path)?;
    assert!(store.recover_recipient_keys(&owner).is_err());

    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    begin_pending_destruction(&mut store, descriptor, Hash::from_bytes([96; 32]))?;
    assert!(store.recover_recipient_keys(&owner).is_err());
    assert!(
        recipient_private_path(&temporary.path().join("recipient-private"), descriptor).exists()
    );
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_foreign_inventory_bound_in_claimed_directory(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, descriptor) = enrolled_owner()?;
    let foreign_descriptor = pos_core::RecipientKeyDescriptorV1::for_grantee(
        EntityId::new(),
        descriptor.identity().epoch,
        descriptor.public_key(),
    )?;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute(
        "UPDATE recipient_key_inventory_v1 SET descriptor = ?1",
        [foreign_descriptor.encode()],
    )?;

    assert!(store.recover_recipient_keys(&owner).is_err());
    assert!(only_private_file(&temporary.path().join("recipient-private"))?.exists());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_fails_closed_for_corrupt_durable_inventory(
) -> Result<(), Box<dyn std::error::Error>> {
    for (column, value) in [
        ("descriptor", rusqlite::types::Value::Blob(vec![0])),
        ("material_digest", rusqlite::types::Value::Blob(vec![0; 31])),
        (
            "private_path",
            rusqlite::types::Value::Blob(b"foreign.key".to_vec()),
        ),
        ("file_device", rusqlite::types::Value::Blob(vec![0; 8])),
        ("file_inode", rusqlite::types::Value::Blob(vec![0; 8])),
    ] {
        let (temporary, store, owner, _) = enrolled_owner()?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
        connection.execute(
            &format!("UPDATE recipient_key_inventory_v1 SET {column} = ?1"),
            [value],
        )?;
        assert!(store.recover_recipient_keys(&owner).is_err(), "{column}");
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_fails_closed_for_malformed_file_identity_widths(
) -> Result<(), Box<dyn std::error::Error>> {
    for (column, value) in [
        ("file_device", vec![0_u8; 7]),
        ("file_inode", vec![0_u8; 7]),
        ("file_uid", vec![0_u8; 3]),
    ] {
        let (temporary, store, owner, _) = enrolled_owner()?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON;")?;
        connection.execute(
            &format!("UPDATE recipient_key_inventory_v1 SET {column} = ?1"),
            [value],
        )?;
        assert!(store.recover_recipient_keys(&owner).is_err(), "{column}");
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_file_and_symlink_owner_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let file = temporary.path().join("file");
    std::fs::write(&file, b"not a directory")?;
    assert!(RecipientKeyOwnerV1::open(&file, EntityId::new()).is_err());
    let directory = private_directory(temporary.path())?;
    let link = temporary.path().join("link");
    std::os::unix::fs::symlink(&directory, &link)?;
    assert!(RecipientKeyOwnerV1::open(&link, EntityId::new()).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_fails_closed_for_registry_and_inventory_schema_loss(
) -> Result<(), Box<dyn std::error::Error>> {
    for statement in [
        "DROP TABLE key_registry",
        "UPDATE key_registry SET state_cbor = X'01'",
        "DROP TABLE recipient_key_inventory_v1",
    ] {
        let (temporary, store, owner, _) = enrolled_owner()?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
        connection.execute_batch(statement)?;
        assert!(store.recover_recipient_keys(&owner).is_err(), "{statement}");
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_private_material_size_and_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    for material in [vec![0; 31], vec![0; 33], vec![0; 32]] {
        let (temporary, store, owner, _) = enrolled_owner()?;
        let path = only_private_file(&temporary.path().join("recipient-private"))?;
        std::fs::write(&path, material)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(store.recover_recipient_keys(&owner).is_err());
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_directory_that_becomes_unsafe(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, store, owner, _) = enrolled_owner()?;
    let directory = temporary.path().join("recipient-private");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_keeps_pending_for_tampered_destruction_inventory(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let authorization = Hash::from_bytes([43; 32]);
    begin_pending_destruction(&mut store, descriptor, authorization)?;
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute(
        "UPDATE recipient_key_inventory_v1 SET material_digest = ?1",
        [vec![0_u8; 32]],
    )?;

    assert!(store
        .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
        .is_err());
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry.tombstone(descriptor.identity()).is_none());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_invalid_pending_inventory_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong_descriptor =
        pos_core::RecipientKeyDescriptorV1::for_grantee(EntityId::new(), 1, [0_u8; 32])?.encode();
    for (column, value) in [
        ("descriptor", rusqlite::types::Value::Blob(wrong_descriptor)),
        (
            "private_path",
            rusqlite::types::Value::Blob(b"foreign.key".to_vec()),
        ),
        (
            "material_digest",
            rusqlite::types::Value::Blob(vec![0_u8; 31]),
        ),
    ] {
        let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
        let authorization = Hash::from_bytes([44; 32]);
        begin_pending_destruction(&mut store, descriptor, authorization)?;
        let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
        connection.execute(
            &format!("UPDATE recipient_key_inventory_v1 SET {column} = ?1"),
            [value],
        )?;

        assert!(store
            .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
            .is_err());
        let registry = store
            .load_key_registry()?
            .ok_or("recipient registry is absent")?;
        assert!(
            registry.tombstone(descriptor.identity()).is_none(),
            "{column}"
        );
    }
    Ok(())
}

#[test]
fn recipient_owner_public_contract_keeps_pending_when_private_material_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let authorization = Hash::from_bytes([45; 32]);
    begin_pending_destruction(&mut store, descriptor, authorization)?;
    let path = only_private_file(&temporary.path().join("recipient-private"))?;
    std::fs::write(&path, [7_u8; 32])?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    assert!(store
        .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
        .is_err());
    assert!(path.exists());
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry.tombstone(descriptor.identity()).is_none());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_keeps_pending_when_receipt_insert_rolls_back(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let authorization = Hash::from_bytes([49; 32]);
    let connection = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?;
    connection.execute_batch(
        "CREATE TRIGGER reject_recipient_receipt
         BEFORE INSERT ON recipient_key_destruction_receipts_v1
         BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;",
    )?;

    assert!(store
        .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
        .is_err());
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry.tombstone(descriptor.identity()).is_none());
    assert!(registry
        .pending_destruction_requests()
        .any(|request| request.identity == descriptor.identity()));
    let receipt_count = rusqlite::Connection::open(temporary.path().join("recipient.sqlite"))?
        .query_row(
            "SELECT COUNT(*) FROM recipient_key_destruction_receipts_v1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    assert_eq!(receipt_count, 0);
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_destruction_after_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let authorization = Hash::from_bytes([42; 32]);
    store.destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)?;
    assert!(store
        .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
        .is_err());
    assert!(store.recover_recipient_keys(&owner)?.is_empty());
    Ok(())
}
