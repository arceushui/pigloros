//! Role/epoch-bound cryptographic operations for the key-registry boundary.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pos_core::{
    CanonicalBytes, Hash, KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistryEncryptionPortV1, KeyRegistryErrorV1, KeyRegistrySigningPortV1, KeyRoleV1,
    Signature,
};
use zeroize::Zeroize;

const KEY_MATERIAL_DOMAIN: &[u8] = b"pigloros/key-material/v1";
const ROLE_SIGNATURE_DOMAIN: &[u8] = b"pigloros/role-signature/v1";

/// An application-owned Ed25519 signing key and its immutable registry facts.
///
/// The wrapper deliberately does not implement `Clone` or expose the private
/// seed. `ed25519-dalek` zeroizes the seed when the wrapped key is dropped.
/// The cached digest and public key avoid creating another private-byte copy
/// for every authorization check.
pub struct SigningKeyMaterial {
    signing_key: Option<SigningKey>,
    material_digest: Hash,
    public_verification_key: pos_core::PublicKey,
}

impl SigningKeyMaterial {
    /// Take ownership of a signing key at an application boundary.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        let mut private_bytes = signing_key.to_bytes();
        let material_digest = key_material_digest(&private_bytes);
        private_bytes.zeroize();
        let public_verification_key =
            crate::signing::public_key_from_verifying_key(&signing_key.verifying_key());
        Self {
            signing_key: Some(signing_key),
            material_digest,
            public_verification_key,
        }
    }

    /// Return whether this material has been destroyed.
    #[must_use]
    pub const fn is_destroyed(&self) -> bool {
        self.signing_key.is_none()
    }

    /// Return the material fingerprint used by the registry contract.
    ///
    /// # Errors
    /// Returns [`KeyRegistryErrorV1::Destroyed`] after the material has been
    /// destroyed.
    pub fn material_digest(&self) -> Result<Hash, KeyRegistryErrorV1> {
        self.signing_key
            .as_ref()
            .map(|_| self.material_digest)
            .ok_or(KeyRegistryErrorV1::Destroyed)
    }

    /// Return the public verification key corresponding to the private key.
    ///
    /// # Errors
    /// Returns [`KeyRegistryErrorV1::Destroyed`] after the material has been
    /// destroyed.
    pub fn public_verification_key(&self) -> Result<pos_core::PublicKey, KeyRegistryErrorV1> {
        self.signing_key
            .as_ref()
            .map(|_| self.public_verification_key)
            .ok_or(KeyRegistryErrorV1::Destroyed)
    }

    fn as_key(&self) -> Result<&SigningKey, KeyRegistryErrorV1> {
        self.signing_key
            .as_ref()
            .ok_or(KeyRegistryErrorV1::Destroyed)
    }

    fn destroy(&mut self) {
        let _ = self.signing_key.take();
    }
}

/// An application-owned key for one encryption role/epoch.
///
/// The key bytes are not cloneable or observable. The wrapper is intentionally
/// limited to registry authorization in this ticket; encryption algorithms and
/// ciphertext formats belong to the consuming storage boundary.
pub struct EncryptionKeyMaterial {
    private_material: Option<[u8; 32]>,
    material_digest: Hash,
}

impl EncryptionKeyMaterial {
    /// Take ownership of encryption key material.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        let material_digest = key_material_digest(&key);
        Self {
            private_material: Some(key),
            material_digest,
        }
    }

    /// Return whether this material has been destroyed.
    #[must_use]
    pub const fn is_destroyed(&self) -> bool {
        self.private_material.is_none()
    }

    /// Return the material fingerprint used by the registry contract.
    ///
    /// # Errors
    /// Returns [`KeyRegistryErrorV1::Destroyed`] after the material has been
    /// destroyed.
    pub fn material_digest(&self) -> Result<Hash, KeyRegistryErrorV1> {
        self.private_material
            .as_ref()
            .map(|_| self.material_digest)
            .ok_or(KeyRegistryErrorV1::Destroyed)
    }

    fn destroy(&mut self) {
        if let Some(mut key) = self.private_material.take() {
            key.zeroize();
        }
    }
}

impl Drop for EncryptionKeyMaterial {
    fn drop(&mut self) {
        if let Some(mut key) = self.private_material.take() {
            key.zeroize();
        }
    }
}

/// Failure while atomically committing a key tombstone and destroying its
/// owned private material.
#[derive(Debug, Eq, PartialEq)]
pub enum KeyMaterialDestructionError<E> {
    /// The owned material had already been destroyed.
    AlreadyDestroyed,
    /// The request did not identify this owned material.
    MaterialDigestMismatch,
    /// The registry commit failed; the material remains available.
    Commit(E),
}

impl<E: fmt::Display> fmt::Display for KeyMaterialDestructionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyDestroyed => formatter.write_str("key material is already destroyed"),
            Self::MaterialDigestMismatch => {
                formatter.write_str("key material digest does not match the request")
            }
            Self::Commit(error) => write!(formatter, "key registry commit failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for KeyMaterialDestructionError<E> {}

/// Commit a registry tombstone and then destroy the corresponding owned
/// signing key.
///
/// The commit callback is the only boundary that can cause the private key to
/// be destroyed. It must durably commit the supplied request before returning;
/// if it fails, the key remains available for retry. This keeps logical
/// revocation and physical destruction in one caller-visible operation.
///
/// # Errors
/// Returns [`KeyMaterialDestructionError::AlreadyDestroyed`] when the key has
/// already been destroyed, [`KeyMaterialDestructionError::MaterialDigestMismatch`]
/// when the request does not identify this key, or
/// [`KeyMaterialDestructionError::Commit`] when the registry rejects the
/// destruction request.
pub fn destroy_registered_signing_key<E, F>(
    signing_key: &mut SigningKeyMaterial,
    request: KeyDestructionRequestV1,
    commit: F,
) -> Result<KeyDestructionOutcomeV1, KeyMaterialDestructionError<E>>
where
    F: FnOnce(KeyDestructionRequestV1) -> Result<KeyDestructionOutcomeV1, E>,
{
    let material_digest = signing_key
        .material_digest()
        .map_err(|_| KeyMaterialDestructionError::AlreadyDestroyed)?;
    if request.expected_material_digest != material_digest {
        return Err(KeyMaterialDestructionError::MaterialDigestMismatch);
    }
    let outcome = commit(request).map_err(KeyMaterialDestructionError::Commit)?;
    signing_key.destroy();
    Ok(outcome)
}

/// Commit a registry tombstone and then destroy the corresponding owned
/// encryption key.
///
/// # Errors
/// Returns [`KeyMaterialDestructionError::AlreadyDestroyed`] when the key has
/// already been destroyed, [`KeyMaterialDestructionError::MaterialDigestMismatch`]
/// when the request does not identify this key, or
/// [`KeyMaterialDestructionError::Commit`] when the registry rejects the
/// destruction request.
pub fn destroy_registered_encryption_key<E, F>(
    encryption_key: &mut EncryptionKeyMaterial,
    request: KeyDestructionRequestV1,
    commit: F,
) -> Result<KeyDestructionOutcomeV1, KeyMaterialDestructionError<E>>
where
    F: FnOnce(KeyDestructionRequestV1) -> Result<KeyDestructionOutcomeV1, E>,
{
    let material_digest = encryption_key
        .material_digest()
        .map_err(|_| KeyMaterialDestructionError::AlreadyDestroyed)?;
    if request.expected_material_digest != material_digest {
        return Err(KeyMaterialDestructionError::MaterialDigestMismatch);
    }
    let outcome = commit(request).map_err(KeyMaterialDestructionError::Commit)?;
    encryption_key.destroy();
    Ok(outcome)
}

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
/// digest. It must hold its transaction or lock through the signing callback,
/// so destruction and signing have a defined ordering.
///
/// # Errors
///
/// Returns a closed [`KeyRegistryErrorV1`] when the identity is invalid,
/// inactive, destroyed, absent, or does not match the supplied signing key.
pub fn sign_for_registered_role<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKeyMaterial,
    identity: KeyIdentityV1,
    payload: &CanonicalBytes,
) -> Result<Signature, KeyRegistryErrorV1> {
    if identity.epoch == 0 {
        return Err(KeyRegistryErrorV1::InvalidEpoch);
    }
    if !identity.role.is_signing() {
        return Err(KeyRegistryErrorV1::SigningRoleRequired);
    }
    let material_digest = signing_key.material_digest()?;
    let public_verification_key = signing_key.public_verification_key()?;
    let signing_key = signing_key.as_key()?;
    registry.with_signing_authorization(identity, material_digest, public_verification_key, || {
        sign_for_role_unchecked(signing_key, identity.role, identity.epoch, payload)
    })
}

/// Authorize one encryption operation under an active registry identity.
///
/// The callback is the adapter-owned encryption operation and receives no
/// private bytes. Destruction and the callback are ordered by the registry
/// adapter's serialization boundary.
///
/// # Errors
///
/// Returns a closed [`KeyRegistryErrorV1`] when the identity is invalid,
/// inactive, destroyed, absent, or is a signing role.
pub fn with_registered_encryption_authorization<R, T, F>(
    registry: &mut R,
    private_material: &EncryptionKeyMaterial,
    identity: KeyIdentityV1,
    operation: F,
) -> Result<T, KeyRegistryErrorV1>
where
    R: KeyRegistryEncryptionPortV1,
    F: FnOnce() -> T,
{
    if identity.epoch == 0 {
        return Err(KeyRegistryErrorV1::InvalidEpoch);
    }
    if !identity.role.is_encryption() {
        return Err(KeyRegistryErrorV1::EncryptionRoleRequired);
    }
    let digest = private_material.material_digest()?;
    registry.with_encryption_authorization(identity, digest, operation)
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
    if epoch == 0 {
        return Err(pos_core::CoreError::SignatureVerificationFailed);
    }
    if !role.is_signing() {
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
        let signing_key = SigningKeyMaterial::new(signing_key);
        let value = payload(b"attribution");
        assert!(KeyRoleV1::SubjectAttributionSigning.is_signing());
        assert!(KeyRoleV1::TimelineIntegritySigning.is_signing());
        assert!(KeyRoleV1::PluginReleaseSigning.is_signing());
        assert!(!KeyRoleV1::SubjectDataEncryption.is_signing());
        assert!(!KeyRoleV1::ExportRecipientEncryption.is_signing());
        let identity = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 3);
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            identity,
            signing_key.material_digest()?,
            Some(public_key_from_verifying_key(&verifying_key)),
        ))?;
        let signature = sign_for_registered_role(&mut registry, &signing_key, identity, &value)?;
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
            KeyRoleV1::SubjectDataEncryption,
            3,
            &value,
            &signature,
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

        assert!(verify_for_role(
            &verifying_key,
            KeyRoleV1::SubjectAttributionSigning,
            0,
            &value,
            &signature,
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
        let mut signing_key = SigningKeyMaterial::new(signing_key);
        let identity = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 1);
        let material_digest = signing_key.material_digest()?;
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            identity,
            material_digest,
            Some(public_key_from_verifying_key(&verifying_key)),
        ))?;

        let value = payload(b"historical attribution");
        let signature = sign_for_registered_role(&mut registry, &signing_key, identity, &value)?;
        destroy_registered_signing_key(
            &mut signing_key,
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([7; 32])),
            |request| registry.destroy_key(request),
        )?;

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

    #[test]
    fn encryption_authorization_is_role_separated_and_destroyable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut material = EncryptionKeyMaterial::new([11u8; 32]);
        let identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
        let material_digest = material.material_digest()?;
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(identity, material_digest, None))?;

        let mut callbacks = 0;
        assert_eq!(
            with_registered_encryption_authorization(&mut registry, &material, identity, || {
                callbacks += 1;
                7u8
            },)?,
            7
        );
        assert_eq!(callbacks, 1);
        destroy_registered_encryption_key(
            &mut material,
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([12; 32])),
            |request| registry.destroy_key(request),
        )?;
        assert_eq!(
            with_registered_encryption_authorization(&mut registry, &material, identity, || {
                callbacks += 1;
                8u8
            },),
            Err(KeyRegistryErrorV1::Destroyed)
        );
        assert_eq!(callbacks, 1);

        let signing_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
        assert_eq!(
            with_registered_encryption_authorization(
                &mut registry,
                &material,
                signing_identity,
                || (),
            ),
            Err(KeyRegistryErrorV1::EncryptionRoleRequired)
        );
        assert_eq!(
            with_registered_encryption_authorization(
                &mut registry,
                &material,
                KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 0),
                || (),
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        Ok(())
    }
}
