#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
use pos_core::{CanonicalBytes, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1};
use pos_crypto::key_roles::{
    destroy_registered_encryption_key, destroy_registered_signing_key, key_material_digest,
    sign_for_registered_role, verify_for_role, with_registered_encryption_authorization,
    EncryptionKeyMaterial, KeyMaterialDestructionError, SigningKeyMaterial,
};
use pos_crypto::signing::public_key_from_verifying_key;

#[test]
fn public_role_bound_signing_covers_authorization_edges() -> Result<(), Box<dyn std::error::Error>>
{
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_public_key = public_key_from_verifying_key(&signing_key.verifying_key());
    let signing_material = SigningKeyMaterial::new(signing_key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(signing_public_key),
    ))?;
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        key_material_digest(&[32; 32]),
        None,
    ))?;

    let payload = CanonicalBytes::from_static(b"role-bound payload");
    let signature =
        sign_for_registered_role(&mut registry, &signing_material, signing_identity, &payload)?;
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
            &signing_material,
            KeyIdentityV1::new(signing_identity.role, 0),
            &payload,
        ),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    assert_eq!(
        sign_for_registered_role(
            &mut registry,
            &signing_material,
            encryption_identity,
            &payload,
        ),
        Err(pos_core::KeyRegistryErrorV1::SigningRoleRequired)
    );

    Ok(())
}

#[test]
fn public_role_bound_encryption_covers_destruction_edges() -> Result<(), Box<dyn std::error::Error>>
{
    let encryption_identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    let mut encryption_material = EncryptionKeyMaterial::new([32; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material.material_digest()?,
        None,
    ))?;
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
    let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            signing_identity,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionRoleRequired)
    );

    let material_digest = encryption_material.material_digest()?;
    assert_eq!(
        destroy_registered_encryption_key::<&str, _>(
            &mut encryption_material,
            pos_core::KeyDestructionRequestV1::new(
                encryption_identity,
                pos_core::Hash::from_bytes([33; 32]),
                pos_core::Hash::from_bytes([9; 32]),
            ),
            |_| Err("the material digest must be checked first"),
        ),
        Err(KeyMaterialDestructionError::MaterialDigestMismatch)
    );
    assert_eq!(
        destroy_registered_encryption_key(
            &mut encryption_material,
            pos_core::KeyDestructionRequestV1::new(
                encryption_identity,
                material_digest,
                pos_core::Hash::from_bytes([9; 32]),
            ),
            |_| Err("registry unavailable"),
        ),
        Err(KeyMaterialDestructionError::Commit("registry unavailable"))
    );
    assert!(!encryption_material.is_destroyed());
    destroy_registered_encryption_key(
        &mut encryption_material,
        pos_core::KeyDestructionRequestV1::new(
            encryption_identity,
            material_digest,
            pos_core::Hash::from_bytes([9; 32]),
        ),
        |request| registry.destroy_key(request),
    )?;
    assert!(encryption_material.is_destroyed());
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            encryption_identity,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );

    Ok(())
}

#[test]
fn public_signing_material_destruction_is_commit_gated() -> Result<(), Box<dyn std::error::Error>> {
    let (signing_key, verifying_key) = pos_crypto::signing::generate_keypair();
    let mut material = SigningKeyMaterial::new(signing_key);
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let digest = material.material_digest()?;
    let wrong_request = pos_core::KeyDestructionRequestV1::new(
        identity,
        pos_core::Hash::from_bytes([35; 32]),
        pos_core::Hash::from_bytes([9; 32]),
    );
    assert_eq!(
        destroy_registered_signing_key::<&str, _>(&mut material, wrong_request, |_| {
            Err("the material digest must be checked first")
        }),
        Err(KeyMaterialDestructionError::MaterialDigestMismatch)
    );

    let request = pos_core::KeyDestructionRequestV1::new(
        identity,
        digest,
        pos_core::Hash::from_bytes([9; 32]),
    );
    assert_eq!(
        destroy_registered_signing_key(&mut material, request, |_| Err("registry unavailable")),
        Err(KeyMaterialDestructionError::Commit("registry unavailable"))
    );
    assert!(!material.is_destroyed());

    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        digest,
        Some(public_key_from_verifying_key(&verifying_key)),
    ))?;
    destroy_registered_signing_key(&mut material, request, |request| {
        registry.destroy_key(request)
    })?;
    assert!(material.is_destroyed());
    assert_eq!(
        destroy_registered_signing_key::<&str, _>(&mut material, request, |_| {
            Err("destroyed material cannot be committed again")
        }),
        Err(KeyMaterialDestructionError::AlreadyDestroyed)
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
    let wrong_signing_material = SigningKeyMaterial::new(wrong_signing_key);
    assert_eq!(
        sign_for_registered_role(
            &mut registry,
            &wrong_signing_material,
            signing_identity,
            &CanonicalBytes::from_static(b"mismatch"),
        ),
        Err(pos_core::KeyRegistryErrorV1::SigningKeyMismatch)
    );
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &EncryptionKeyMaterial::new([35; 32]),
            encryption_identity,
            || "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionKeyMismatch)
    );
    Ok(())
}
