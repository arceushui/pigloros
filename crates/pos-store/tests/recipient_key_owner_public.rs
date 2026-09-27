#![cfg(all(feature = "sqlite", unix))]

//! Public black-box contracts for role-4 recipient private-file custody.

use std::os::unix::fs::PermissionsExt;

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
    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}

#[test]
fn recipient_owner_public_contract_rejects_replaced_file_and_keeps_pending(
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
        .is_none());
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
fn recipient_owner_public_contract_rejects_destruction_after_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temporary, mut store, owner, descriptor) = enrolled_owner()?;
    let authorization = Hash::from_bytes([42; 32]);
    store.destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)?;
    assert!(store
        .destroy_recipient_key(&owner, descriptor.identity().epoch, authorization)
        .is_err());
    assert!(store.recover_recipient_keys(&owner).is_err());
    Ok(())
}
