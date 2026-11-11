//! Role7 registry policy, independently of the not-yet-qualified artifact owner.

use pos_core::{
    deletion_receipt, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryErrorV1 as Error, KeyRegistryStateV1, KeyRoleV1, PublicKey,
};
use std::cell::Cell;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn identity() -> KeyIdentityV1 {
    KeyIdentityV1::new(
        "community-registry-test",
        KeyRoleV1::CommunityArtifactEncryption,
        1,
    )
}

#[test]
fn role_seven_preserves_existing_codes_and_keeps_unknown_codes_closed() -> TestResult {
    for (code, role, signing) in [
        (0, KeyRoleV1::SubjectDataEncryption, false),
        (1, KeyRoleV1::SubjectAttributionSigning, true),
        (2, KeyRoleV1::TimelineIntegritySigning, true),
        (3, KeyRoleV1::PluginReleaseSigning, true),
        (4, KeyRoleV1::ExportRecipientEncryption, false),
        (5, KeyRoleV1::ConformanceEvaluatorSigning, true),
        (6, KeyRoleV1::ConformanceReportSigning, true),
        (7, KeyRoleV1::CommunityArtifactEncryption, false),
    ] {
        assert_eq!(role.code(), code);
        assert_eq!(KeyRoleV1::from_code(code)?, role);
        assert_eq!(role.is_signing(), signing);
        assert_eq!(role.is_encryption(), !signing);
    }
    for code in [8, 255] {
        assert_eq!(KeyRoleV1::from_code(code), Err(Error::InvalidRoleCode));
    }
    Ok(())
}

#[test]
fn community_material_cannot_sign_or_be_reused_for_subject_or_export_keys() -> TestResult {
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(identity(), hash(1), None))?;
    for role in [
        KeyRoleV1::SubjectDataEncryption,
        KeyRoleV1::ExportRecipientEncryption,
    ] {
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("community-registry-test", role, 1),
                hash(1),
                None,
            )),
            Err(Error::MaterialReuse)
        );
    }
    let called = Cell::new(false);
    assert_eq!(
        registry.with_signing_authorization(
            identity(),
            hash(1),
            PublicKey::from_bytes([2; 32]),
            || called.set(true)
        ),
        Err(Error::SigningRoleRequired)
    );
    assert!(!called.get());
    let mut invalid = KeyRegistryStateV1::new();
    assert_eq!(
        invalid.register_key(KeyRegistrationV1::new(
            identity(),
            hash(1),
            Some(PublicKey::from_bytes([2; 32]))
        )),
        Err(Error::UnexpectedPublicVerificationKey)
    );
    Ok(())
}

#[test]
fn community_registry_checks_exact_identity_and_material_before_a_callback() -> TestResult {
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(identity(), hash(1), None))?;
    assert_eq!(
        registry.with_encryption_authorization(identity(), hash(1), || 42)?,
        42
    );
    assert_eq!(
        registry.with_decryption_authorization(identity(), hash(1), || 43)?,
        43
    );
    for digest in [hash(2), Hash::zero()] {
        let called = Cell::new(false);
        assert_eq!(
            registry.with_encryption_authorization(identity(), digest, || called.set(true)),
            Err(Error::EncryptionKeyMismatch)
        );
        assert_eq!(
            registry.with_decryption_authorization(identity(), digest, || called.set(true)),
            Err(Error::EncryptionKeyMismatch)
        );
        assert!(!called.get());
    }
    let other = KeyIdentityV1::new(
        "other-community-test",
        KeyRoleV1::CommunityArtifactEncryption,
        1,
    );
    assert_eq!(
        registry.with_decryption_authorization(other, hash(1), || ()),
        Err(Error::NotFound)
    );
    let zero_epoch = KeyIdentityV1::new(
        "community-registry-test",
        KeyRoleV1::CommunityArtifactEncryption,
        0,
    );
    assert_eq!(
        zero_epoch.validate_historical_decryption(),
        Err(Error::InvalidEpoch)
    );
    Ok(())
}

#[test]
fn pending_and_confirmed_community_destruction_never_restore_private_use() -> TestResult {
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(identity(), hash(1), None))?;
    let request = KeyDestructionRequestV1::new(identity(), hash(1), hash(2));
    registry.begin_key_destruction(request)?;
    let called = Cell::new(false);
    assert_eq!(
        registry.with_decryption_authorization(identity(), hash(1), || called.set(true)),
        Err(Error::DestructionPending)
    );
    assert_eq!(
        registry.with_encryption_authorization(identity(), hash(1), || called.set(true)),
        Err(Error::DestructionPending)
    );
    registry.complete_key_destruction(request, deletion_receipt(&request))?;
    assert_eq!(
        registry.with_decryption_authorization(identity(), hash(1), || called.set(true)),
        Err(Error::Destroyed)
    );
    assert_eq!(
        registry.with_encryption_authorization(identity(), hash(1), || called.set(true)),
        Err(Error::Destroyed)
    );
    assert_eq!(
        registry.register_key(KeyRegistrationV1::new(identity(), hash(3), None)),
        Err(Error::Destroyed)
    );
    assert!(!called.get());
    assert_eq!(
        registry.highest_epoch(&identity().owner_id, identity().role),
        Some(1)
    );
    Ok(())
}
