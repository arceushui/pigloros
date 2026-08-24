//! Role/epoch-bound cryptographic operations for the key-registry boundary.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pos_core::{
    CanonicalBytes, Hash, KeyIdentityV1, KeyRegistryErrorV1, KeyRegistrySigningPortV1, KeyRoleV1,
    Signature,
};

const KEY_MATERIAL_DOMAIN: &[u8] = b"pigloros/key-material/v1";
const ROLE_SIGNATURE_DOMAIN: &[u8] = b"pigloros/role-signature/v1";

/// Fingerprint private key material without retaining the material in core.
///
/// The fingerprint intentionally does not include role or epoch.  That makes
/// the core registry able to detect one private key being registered for two
/// roles or two epochs.  Role and epoch are bound separately by the registry
/// identity and by [`sign_for_registered_role`].
#[must_use]
pub fn key_material_digest(private_material: &[u8; 32]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_MATERIAL_DOMAIN);
    hasher.update(private_material);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Sign a payload with an explicit role and epoch domain.
///
/// # Errors
///
/// Returns [`KeyRegistryErrorV1::SigningRoleRequired`] when an encryption role
/// is supplied.  Legacy subject-data-key signatures must remain on the
/// verify-only compatibility path and cannot be reissued here.
#[cfg(test)]
fn sign_for_role(
    signing_key: &SigningKey,
    role: KeyRoleV1,
    epoch: u64,
    payload: &CanonicalBytes,
) -> Result<Signature, KeyRegistryErrorV1> {
    if epoch == 0 {
        return Err(KeyRegistryErrorV1::InvalidEpoch);
    }
    if !role.is_signing() {
        return Err(KeyRegistryErrorV1::SigningRoleRequired);
    }
    Ok(sign_for_role_unchecked(signing_key, role, epoch, payload))
}

fn sign_for_role_unchecked(
    signing_key: &SigningKey,
    role: KeyRoleV1,
    epoch: u64,
    payload: &CanonicalBytes,
) -> Signature {
    let message = role_bound_message(role, epoch, payload);
    Signature::from_bytes(signing_key.sign(&message).to_bytes())
}

/// Sign a role/epoch-bound payload under the registry's atomic authorization.
///
/// The registry adapter validates that the identity is active and that the
/// supplied signing key matches its registered public key and private-material
/// digest.  It must hold its transaction or lock through the signing callback,
/// so destruction and signing have a defined ordering.  A copied
/// [`SigningKey`] used outside this function is intentionally outside the
/// revocation boundary.
///
/// # Errors
///
/// Returns a closed [`KeyRegistryErrorV1`] when the identity is invalid,
/// inactive, destroyed, absent, or does not match the supplied signing key.
pub fn sign_for_registered_role<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKey,
    identity: KeyIdentityV1,
    payload: &CanonicalBytes,
) -> Result<Signature, KeyRegistryErrorV1> {
    if identity.epoch == 0 {
        return Err(KeyRegistryErrorV1::InvalidEpoch);
    }
    if !identity.role.is_signing() {
        return Err(KeyRegistryErrorV1::SigningRoleRequired);
    }
    let material_digest = key_material_digest(&signing_key.to_bytes());
    let public_verification_key =
        crate::signing::public_key_from_verifying_key(&signing_key.verifying_key());
    registry.with_signing_authorization(identity, material_digest, public_verification_key, || {
        sign_for_role_unchecked(signing_key, identity.role, identity.epoch, payload)
    })
}

/// Verify a role/epoch-bound signature.
///
/// # Errors
///
/// Returns [`pos_core::CoreError::SignatureVerificationFailed`] if the role,
/// epoch, payload, or signature does not match.
pub fn verify_for_role(
    verifying_key: &VerifyingKey,
    role: KeyRoleV1,
    epoch: u64,
    payload: &CanonicalBytes,
    signature: &Signature,
) -> Result<(), pos_core::CoreError> {
    if epoch == 0 || !role.is_signing() {
        return Err(pos_core::CoreError::SignatureVerificationFailed);
    }
    let message = role_bound_message(role, epoch, payload);
    let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| pos_core::CoreError::SignatureVerificationFailed)
}

fn role_bound_message(role: KeyRoleV1, epoch: u64, payload: &CanonicalBytes) -> Vec<u8> {
    let mut message = Vec::with_capacity(ROLE_SIGNATURE_DOMAIN.len() + 1 + 8 + payload.len());
    message.extend_from_slice(ROLE_SIGNATURE_DOMAIN);
    message.push(role.code());
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(payload.as_slice());
    message
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::signing::{generate_keypair, public_key_from_verifying_key};
    use ed25519_dalek::Signer;
    use pos_core::{KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1};

    fn payload(bytes: &[u8]) -> CanonicalBytes {
        CanonicalBytes::from_vec(bytes.to_vec())
    }

    #[test]
    fn material_digest_is_stable_across_roles_and_epochs() {
        let material = [7; 32];
        let first = key_material_digest(&material);
        let same_material = key_material_digest(&material);
        assert_eq!(first, same_material);
    }

    #[test]
    fn role_signature_rejects_role_and_epoch_confusion() -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, verifying_key) = generate_keypair();
        let value = payload(b"attribution");
        assert!(KeyRoleV1::SubjectAttributionSigning.is_signing());
        assert!(KeyRoleV1::TimelineIntegritySigning.is_signing());
        assert!(KeyRoleV1::PluginReleaseSigning.is_signing());
        assert!(!KeyRoleV1::SubjectDataEncryption.is_signing());
        assert!(!KeyRoleV1::ExportRecipientEncryption.is_signing());
        let signature = sign_for_role(
            &signing_key,
            KeyRoleV1::SubjectAttributionSigning,
            3,
            &value,
        )?;
        assert!(verify_for_role(
            &verifying_key,
            KeyRoleV1::SubjectAttributionSigning,
            3,
            &value,
            &signature
        )
        .is_ok());
        assert!(verify_for_role(
            &verifying_key,
            KeyRoleV1::TimelineIntegritySigning,
            3,
            &value,
            &signature
        )
        .is_err());
        assert!(verify_for_role(
            &verifying_key,
            KeyRoleV1::SubjectAttributionSigning,
            0,
            &value,
            &signature
        )
        .is_err());
        assert_eq!(
            sign_for_role(&signing_key, KeyRoleV1::SubjectDataEncryption, 1, &value),
            Err(KeyRegistryErrorV1::SigningRoleRequired)
        );
        assert_eq!(
            sign_for_role(
                &signing_key,
                KeyRoleV1::SubjectAttributionSigning,
                0,
                &value,
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        let mut registry = KeyRegistryStateV1::new();
        assert_eq!(
            sign_for_registered_role(
                &mut registry,
                &signing_key,
                KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 0),
                &value,
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        assert_eq!(
            sign_for_registered_role(
                &mut registry,
                &signing_key,
                KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1),
                &value,
            ),
            Err(KeyRegistryErrorV1::SigningRoleRequired)
        );
        assert!(verify_for_role(
            &verifying_key,
            KeyRoleV1::SubjectAttributionSigning,
            4,
            &value,
            &signature
        )
        .is_err());

        let invalid_identity_signature = Signature::from_bytes(
            signing_key
                .sign(&role_bound_message(
                    KeyRoleV1::SubjectAttributionSigning,
                    0,
                    &value,
                ))
                .to_bytes(),
        );
        assert!(verify_for_role(
            &verifying_key,
            KeyRoleV1::SubjectAttributionSigning,
            0,
            &value,
            &invalid_identity_signature,
        )
        .is_err());
        assert_eq!(
            public_key_from_verifying_key(&verifying_key).as_bytes(),
            verifying_key.as_bytes()
        );
        Ok(())
    }

    #[test]
    fn historical_role_signature_verifies_after_registry_destruction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, verifying_key) = generate_keypair();
        let identity = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 1);
        let material_digest = key_material_digest(&signing_key.to_bytes());
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            identity,
            material_digest,
            Some(public_key_from_verifying_key(&verifying_key)),
        ))?;

        let value = payload(b"historical attribution");
        let signature = sign_for_registered_role(&mut registry, &signing_key, identity, &value)?;
        registry.destroy_key(KeyDestructionRequestV1::new(
            identity,
            material_digest,
            Hash::from_bytes([7; 32]),
        ))?;

        assert_eq!(
            sign_for_registered_role(&mut registry, &signing_key, identity, &value),
            Err(KeyRegistryErrorV1::Destroyed)
        );

        assert!(verify_for_role(
            &verifying_key,
            identity.role,
            identity.epoch,
            &value,
            &signature,
        )
        .is_ok());
        assert_eq!(
            registry
                .key_record(identity)
                .and_then(|record| record.public_verification_key),
            Some(public_key_from_verifying_key(&verifying_key))
        );
        Ok(())
    }
}
