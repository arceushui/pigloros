#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
use pos_core::{CanonicalBytes, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1};
use pos_crypto::key_roles::{
    key_material_digest, sign_for_registered_role, verify_for_role,
    with_registered_encryption_authorization,
};
use pos_crypto::signing::public_key_from_verifying_key;

#[test]
fn public_role_bound_signing_and_encryption_cover_authorization_edges(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_public_key = public_key_from_verifying_key(&signing_key.verifying_key());
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material = [32; 32];
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(signing_public_key),
    ))?;
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        key_material_digest(&encryption_material),
        None,
    ))?;

    let payload = CanonicalBytes::from_static(b"role-bound payload");
    let signature =
        sign_for_registered_role(&mut registry, &signing_key, signing_identity, &payload)?;
    verify_for_role(
        &signing_key.verifying_key(),
        signing_identity.role,
        signing_identity.epoch,
        &payload,
        &signature,
    )?;
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        signing_identity.role,
        signing_identity.epoch,
        &CanonicalBytes::from_static(b"different payload"),
        &signature,
    )
    .is_err());
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        KeyRoleV1::SubjectDataEncryption,
        signing_identity.epoch,
        &payload,
        &signature,
    )
    .is_err());
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        signing_identity.role,
        0,
        &payload,
        &signature,
    )
    .is_err());

    assert_eq!(
        sign_for_registered_role(
            &mut registry,
            &signing_key,
            KeyIdentityV1::new(signing_identity.role, 0),
            &payload,
        ),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    assert_eq!(
        sign_for_registered_role(&mut registry, &signing_key, encryption_identity, &payload,),
        Err(pos_core::KeyRegistryErrorV1::SigningRoleRequired)
    );
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            encryption_identity,
            || "authorized",
        )?,
        "authorized"
    );
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            KeyIdentityV1::new(encryption_identity.role, 0),
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            signing_identity,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionRoleRequired)
    );
    Ok(())
}

#[test]
fn public_role_bound_key_mismatch_errors_are_closed() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(public_key_from_verifying_key(&signing_key.verifying_key())),
    ))?;
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        key_material_digest(&[32; 32]),
        None,
    ))?;

    let wrong_signing_key = SigningKey::from_bytes(&[34; 32]);
    assert_eq!(
        sign_for_registered_role(
            &mut registry,
            &wrong_signing_key,
            signing_identity,
            &CanonicalBytes::from_static(b"mismatch"),
        ),
        Err(pos_core::KeyRegistryErrorV1::SigningKeyMismatch)
    );
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &[35; 32],
            encryption_identity,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionKeyMismatch)
    );
    Ok(())
}
