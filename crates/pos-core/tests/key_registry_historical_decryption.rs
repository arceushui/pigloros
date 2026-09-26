use std::cell::Cell;

use pos_core::{
    deletion_receipt, Hash, KeyDestructionBeginOutcomeV1, KeyDestructionOutcomeV1,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryHistoricalDecryptionPortV1, KeyRegistryStateV1, KeyRoleV1,
};

const fn digest(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn denied(
    registry: &mut impl KeyRegistryHistoricalDecryptionPortV1,
    identity: KeyIdentityV1,
    material: Hash,
    expected: pos_core::KeyRegistryErrorV1,
) {
    let called = Cell::new(false);
    assert_eq!(
        registry.with_decryption_authorization(identity, material, || {
            called.set(true);
        }),
        Err(expected)
    );
    assert!(!called.get());
}

#[test]
fn retained_subject_epoch_decrypts_without_restoring_encryption_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let old = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let current = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 2);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(old, digest(1), None))?;
    registry.register_key(KeyRegistrationV1::new(current, digest(2), None))?;

    assert_eq!(
        KeyRegistryHistoricalDecryptionPortV1::with_decryption_authorization(
            &mut registry,
            old,
            digest(1),
            || "old ciphertext",
        )?,
        "old ciphertext"
    );
    assert_eq!(
        registry.with_decryption_authorization(current, digest(2), || "current ciphertext")?,
        "current ciphertext"
    );
    denied(
        &mut registry,
        old,
        digest(9),
        pos_core::KeyRegistryErrorV1::EncryptionKeyMismatch,
    );
    assert_eq!(
        registry.with_encryption_authorization(old, digest(1), || "new encryption"),
        Err(pos_core::KeyRegistryErrorV1::InactiveKey)
    );
    assert_eq!(
        registry.with_encryption_authorization(current, digest(2), || "new encryption")?,
        "new encryption"
    );

    Ok(())
}

#[test]
fn historical_decryption_checks_exact_identity_and_never_calls_on_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let subject = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let recipient = KeyIdentityV1::new("subject-owner", KeyRoleV1::ExportRecipientEncryption, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(subject, digest(1), None))?;
    registry.register_key(KeyRegistrationV1::new(recipient, digest(2), None))?;

    denied(
        &mut registry,
        KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 0),
        digest(1),
        pos_core::KeyRegistryErrorV1::InvalidEpoch,
    );
    denied(
        &mut registry,
        recipient,
        digest(2),
        pos_core::KeyRegistryErrorV1::HistoricalDecryptionRoleRequired,
    );
    denied(
        &mut registry,
        KeyIdentityV1::new("other-owner", KeyRoleV1::SubjectDataEncryption, 1),
        digest(1),
        pos_core::KeyRegistryErrorV1::NotFound,
    );
    denied(
        &mut registry,
        KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 2),
        digest(1),
        pos_core::KeyRegistryErrorV1::NotFound,
    );
    denied(
        &mut registry,
        subject,
        digest(2),
        pos_core::KeyRegistryErrorV1::EncryptionKeyMismatch,
    );

    Ok(())
}

#[test]
fn pending_and_destroyed_old_epoch_cannot_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let old = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let current = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 2);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(old, digest(1), None))?;
    registry.register_key(KeyRegistrationV1::new(current, digest(2), None))?;
    let request = KeyDestructionRequestV1::new(old, digest(1), digest(3));

    assert_eq!(
        registry.begin_key_destruction(request)?,
        KeyDestructionBeginOutcomeV1::Started
    );
    denied(
        &mut registry,
        old,
        digest(1),
        pos_core::KeyRegistryErrorV1::DestructionPending,
    );
    denied(
        &mut registry,
        old,
        digest(9),
        pos_core::KeyRegistryErrorV1::DestructionPending,
    );
    let outcome = registry.complete_key_destruction(request, deletion_receipt(&request))?;
    assert_eq!(
        outcome,
        KeyDestructionOutcomeV1::Destroyed(outcome.tombstone())
    );
    denied(
        &mut registry,
        old,
        digest(1),
        pos_core::KeyRegistryErrorV1::Destroyed,
    );
    assert_eq!(
        registry.with_decryption_authorization(current, digest(2), || "still live")?,
        "still live"
    );

    Ok(())
}
