#![cfg(all(feature = "sqlite", unix))]

//! Public black-box contracts for role-4 recipient private-file custody.

use std::os::unix::fs::PermissionsExt;

use pos_core::{EntityId, EventStore, Hash, KeyRoleV1};
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
    let registry = store
        .load_key_registry()?
        .ok_or("recipient registry is absent")?;
    assert!(registry
        .active_key(
            &descriptor.identity().owner_id,
            KeyRoleV1::ExportRecipientEncryption
        )
        .is_none());
    assert!(registry.tombstone(descriptor.identity()).is_none());
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
