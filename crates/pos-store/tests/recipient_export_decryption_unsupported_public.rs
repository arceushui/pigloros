#![cfg(all(feature = "sqlite", not(target_os = "linux")))]

//! Public non-Linux contract for recipient export decryption.

use pos_core::{EntityId, RecipientKeyDescriptorV1};
use pos_store::sqlite::{RecipientExportDecryptionErrorV1, RecipientKeyOwnerV1, SqliteStore};

#[test]
fn recipient_export_decryption_public_contract_is_unavailable_without_linux_custody(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open_in_memory()?;
    let owner = RecipientKeyOwnerV1;
    let descriptor = RecipientKeyDescriptorV1::for_grantee(EntityId::new(), 1, [0; 32])?;
    assert_eq!(
        store.decrypt_recipient_export(&owner, &[], [0; 16], descriptor),
        Err(RecipientExportDecryptionErrorV1::MaterialUnavailable)
    );
    Ok(())
}
