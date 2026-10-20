#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ed25519_dalek::{Signer, SigningKey};
use pos_core::{
    CanonicalBytes, KeyDestructionOutcomeV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1,
    KeyRoleV1, OwnerIdV1, Signature,
};
use pos_crypto::key_roles::{
    destroy_registered_encryption_key, destroy_registered_signing_key, key_material_digest,
    sign_for_registered_role, verify_for_role, with_registered_encryption_authorization,
    EncryptionKeyMaterial, KeyDestructionPersistence, KeyMaterialDestructionError,
    SigningKeyMaterial,
};
use pos_crypto::signing::public_key_from_verifying_key;

struct FailingDestruction(&'static str);

#[test]
fn public_role_verification_preserves_independent_contiguous_framing(
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[71; 32]);
    let verifying_key = signing_key.verifying_key();
    let public_key = public_key_from_verifying_key(&verifying_key);
    let material = SigningKeyMaterial::new(signing_key.clone());
    let owners = ["o".to_owned(), "π".to_owned(), "界".repeat(42) + "ab"];
    let payloads = [
        Vec::new(),
        b"FRM1-shaped payload".to_vec(),
        vec![91; 65_536],
    ];
    for owner in owners {
        let owner_id = OwnerIdV1::new(owner.clone())?;
        for (role, code) in [
            (KeyRoleV1::SubjectAttributionSigning, 1),
            (KeyRoleV1::TimelineIntegritySigning, 2),
            (KeyRoleV1::PluginReleaseSigning, 3),
        ] {
            for epoch in [1, 256, u64::from(u32::MAX) + 1, u64::MAX] {
                let identity = KeyIdentityV1::from_parts(owner_id, role, epoch);
                let mut registry = KeyRegistryStateV1::new();
                registry.register_key(KeyRegistrationV1::new(
                    identity,
                    material.material_digest(),
                    Some(public_key),
                ))?;
                for bytes in &payloads {
                    // Independent ADR-065 framing, not the production helper.
                    let mut message = b"pigloros/role-signature/v1".to_vec();
                    message.extend_from_slice(&u32::try_from(owner.len())?.to_be_bytes());
                    message.extend_from_slice(owner.as_bytes());
                    message.push(code);
                    message.extend_from_slice(&epoch.to_be_bytes());
                    message.extend_from_slice(bytes);
                    let signature = Signature::from_bytes(signing_key.sign(&message).to_bytes());
                    let payload = CanonicalBytes::from_vec(bytes.clone());
                    verify_for_role(&verifying_key, identity, &payload, &signature)?;
                    assert_eq!(
                        sign_for_registered_role(&mut registry, &material, identity, &payload)?,
                        signature
                    );
                    let other_owner = KeyIdentityV1::new("other-owner", role, epoch);
                    assert!(
                        verify_for_role(&verifying_key, other_owner, &payload, &signature).is_err()
                    );
                    let other_epoch = KeyIdentityV1::from_parts(owner_id, role, epoch ^ 1);
                    assert!(
                        verify_for_role(&verifying_key, other_epoch, &payload, &signature).is_err()
                    );
                    let mut altered = bytes.clone();
                    altered.push(0);
                    assert!(verify_for_role(
                        &verifying_key,
                        identity,
                        &CanonicalBytes::from_vec(altered),
                        &signature,
                    )
                    .is_err());
                    let mut altered_signature = *signature.as_bytes();
                    altered_signature[0] ^= 1;
                    assert!(verify_for_role(
                        &verifying_key,
                        identity,
                        &payload,
                        &Signature::from_bytes(altered_signature),
                    )
                    .is_err());
                }
            }
        }
    }
    Ok(())
}

impl KeyDestructionPersistence for FailingDestruction {
    type Error = &'static str;

    fn begin(
        &mut self,
        _request: pos_core::KeyDestructionRequestV1,
    ) -> Result<pos_core::KeyDestructionBeginOutcomeV1, Self::Error> {
        Err(self.0)
    }

    fn complete(
        &mut self,
        _request: pos_core::KeyDestructionRequestV1,
        _deletion_receipt: pos_core::Hash,
    ) -> Result<KeyDestructionOutcomeV1, Self::Error> {
        Err(self.0)
    }
}

#[test]
fn public_role_bound_signing_covers_authorization_edges() -> Result<(), Box<dyn std::error::Error>>
{
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let signing_identity =
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_public_key = public_key_from_verifying_key(&signing_key.verifying_key());
    let signing_material = SigningKeyMaterial::new(signing_key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(signing_public_key),
    ))?;
    let encryption_identity =
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::SubjectDataEncryption, 1);
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
        signing_identity,
        &payload,
        &signature,
    )?;
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        signing_identity,
        &CanonicalBytes::from_static(b"different payload"),
        &signature,
    )
    .is_err());
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::SubjectDataEncryption, 1),
        &payload,
        &signature,
    )
    .is_err());
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        KeyIdentityV1::new("ledger-owner", signing_identity.role, 0),
        &payload,
        &signature,
    )
    .is_err());
    assert!(verify_for_role(
        &signing_key.verifying_key(),
        KeyIdentityV1::new("other-owner", signing_identity.role, signing_identity.epoch),
        &payload,
        &signature,
    )
    .is_err());

    assert_eq!(
        sign_for_registered_role(
            &mut registry,
            &signing_material,
            KeyIdentityV1::new("ledger-owner", signing_identity.role, 0),
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
    let encryption_identity =
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let mut encryption_material = EncryptionKeyMaterial::new([32; 32]);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material.material_digest(),
        None,
    ))?;
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            encryption_identity,
            |material| {
                assert_eq!(material, &[32; 32]);
                "authorized"
            },
        )?,
        "authorized"
    );
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            KeyIdentityV1::new("ledger-owner", encryption_identity.role, 0),
            |_| "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::InvalidEpoch)
    );
    let signing_identity =
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            signing_identity,
            |_| "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionRoleRequired)
    );

    let material_digest = encryption_material.material_digest();
    assert_eq!(
        destroy_registered_encryption_key(
            &mut encryption_material,
            pos_core::KeyDestructionRequestV1::new(
                encryption_identity,
                pos_core::Hash::from_bytes([33; 32]),
                pos_core::Hash::from_bytes([9; 32]),
            ),
            &mut FailingDestruction("the material digest must be checked first"),
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
            &mut FailingDestruction("registry unavailable"),
        ),
        Err(KeyMaterialDestructionError::Commit("registry unavailable"))
    );
    assert!(!encryption_material.is_destroyed());
    let request = pos_core::KeyDestructionRequestV1::new(
        encryption_identity,
        material_digest,
        pos_core::Hash::from_bytes([9; 32]),
    );
    destroy_registered_encryption_key(&mut encryption_material, request, &mut registry)?;
    assert!(encryption_material.is_destroyed());
    assert_eq!(encryption_material.material_digest(), material_digest);
    assert_eq!(
        with_registered_encryption_authorization(
            &mut registry,
            &encryption_material,
            encryption_identity,
            |_| "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );
    let tombstone = registry
        .tombstone(encryption_identity)
        .ok_or("destroyed encryption key must retain its tombstone")?;
    assert_eq!(
        destroy_registered_encryption_key(&mut encryption_material, request, &mut registry)?,
        KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone)
    );

    Ok(())
}

#[test]
fn public_signing_material_destruction_is_commit_gated() -> Result<(), Box<dyn std::error::Error>> {
    let (signing_key, verifying_key) = pos_crypto::signing::generate_keypair();
    let mut material = SigningKeyMaterial::new(signing_key);
    let identity = KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let digest = material.material_digest();
    let wrong_request = pos_core::KeyDestructionRequestV1::new(
        identity,
        pos_core::Hash::from_bytes([35; 32]),
        pos_core::Hash::from_bytes([9; 32]),
    );
    assert_eq!(
        destroy_registered_signing_key(
            &mut material,
            wrong_request,
            &mut FailingDestruction("the material digest must be checked first"),
        ),
        Err(KeyMaterialDestructionError::MaterialDigestMismatch)
    );

    let request = pos_core::KeyDestructionRequestV1::new(
        identity,
        digest,
        pos_core::Hash::from_bytes([9; 32]),
    );
    assert_eq!(
        destroy_registered_signing_key(
            &mut material,
            request,
            &mut FailingDestruction("registry unavailable"),
        ),
        Err(KeyMaterialDestructionError::Commit("registry unavailable"))
    );
    assert!(!material.is_destroyed());

    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        digest,
        Some(public_key_from_verifying_key(&verifying_key)),
    ))?;
    let historical_payload = CanonicalBytes::from_static(b"historical signature");
    let historical_signature =
        sign_for_registered_role(&mut registry, &material, identity, &historical_payload)?;
    destroy_registered_signing_key(&mut material, request, &mut registry)?;
    assert!(material.is_destroyed());
    assert_eq!(material.material_digest(), digest);
    assert_eq!(
        material.public_verification_key(),
        public_key_from_verifying_key(&verifying_key)
    );
    verify_for_role(
        &verifying_key,
        identity,
        &historical_payload,
        &historical_signature,
    )?;
    let tombstone = registry
        .tombstone(identity)
        .ok_or("destroyed signing key must retain its tombstone")?;
    assert_eq!(
        destroy_registered_signing_key(&mut material, request, &mut registry)?,
        KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone)
    );
    assert_eq!(
        sign_for_registered_role(
            &mut registry,
            &material,
            identity,
            &CanonicalBytes::from_static(b"destroyed material"),
        ),
        Err(pos_core::KeyRegistryErrorV1::Destroyed)
    );
    Ok(())
}

#[test]
fn public_role_bound_key_mismatch_errors_are_closed() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let signing_identity =
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        signing_identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(public_key_from_verifying_key(&signing_key.verifying_key())),
    ))?;
    let encryption_identity =
        KeyIdentityV1::new("ledger-owner", KeyRoleV1::SubjectDataEncryption, 1);
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
            |_| "not called",
        ),
        Err(pos_core::KeyRegistryErrorV1::EncryptionKeyMismatch)
    );
    Ok(())
}

#[test]
fn public_destruction_error_messages_identify_each_failure() {
    assert_eq!(
        KeyMaterialDestructionError::<&str>::MaterialDigestMismatch.to_string(),
        "key material digest does not match the request"
    );
    assert_eq!(
        KeyMaterialDestructionError::Commit("registry unavailable").to_string(),
        "key registry commit failed: registry unavailable"
    );
}
