//! Owner-scoped role/epoch-bound cryptographic operations for the key-registry boundary.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pos_core::{
    deletion_receipt, CanonicalBytes, Hash, KeyDestructionBeginOutcomeV1, KeyDestructionOutcomeV1,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRegistryEncryptionPortV1, KeyRegistryErrorV1,
    KeyRegistrySigningPortV1, Signature,
};
use zeroize::{Zeroize, Zeroizing};

const KEY_MATERIAL_DOMAIN: &[u8] = b"pigloros/key-material/v1";
const ROLE_SIGNATURE_DOMAIN: &[u8] = b"pigloros/role-signature/v1";

/// An application-owned Ed25519 signing key and its immutable registry facts.
///
/// The wrapper deliberately does not implement `Clone` or expose the private
/// seed. `ed25519-dalek` zeroizes the seed when the wrapped key is dropped.
/// The cached digest and public key avoid creating another private-byte copy
/// for every authorization check.
pub struct SigningKeyMaterial {
    signing_key: Option<Box<SigningKey>>,
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
            signing_key: Some(Box::new(signing_key)),
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
    /// The fingerprint is retained after destruction so an exact replay can
    /// be checked without retaining or restoring private material.
    #[must_use]
    pub const fn material_digest(&self) -> Hash {
        self.material_digest
    }

    /// Return the public verification key corresponding to the private key.
    ///
    /// The public key is retained after destruction for historical signature
    /// verification.
    #[must_use]
    pub const fn public_verification_key(&self) -> pos_core::PublicKey {
        self.public_verification_key
    }

    fn as_key(&self) -> Result<&SigningKey, KeyRegistryErrorV1> {
        self.signing_key
            .as_ref()
            .map(Box::as_ref)
            .ok_or(KeyRegistryErrorV1::Destroyed)
    }

    fn destroy(&mut self) {
        drop(self.signing_key.take());
    }
}

/// An application-owned key for one encryption role/epoch.
///
/// The key bytes are not cloneable or observable. The wrapper is intentionally
/// limited to registry authorization in this ticket; encryption algorithms and
/// ciphertext formats belong to the consuming storage boundary.
pub struct EncryptionKeyMaterial {
    private_material: Option<Zeroizing<[u8; 32]>>,
    material_digest: Hash,
}

impl EncryptionKeyMaterial {
    /// Take ownership of encryption key material.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        let material_digest = key_material_digest(&key);
        Self {
            private_material: Some(Zeroizing::new(key)),
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
    /// The fingerprint is retained after destruction so an exact replay can
    /// be checked without retaining or restoring private material.
    #[must_use]
    pub const fn material_digest(&self) -> Hash {
        self.material_digest
    }

    fn destroy(&mut self) {
        if let Some(key) = self.private_material.as_mut() {
            key.zeroize();
        }
        self.private_material = None;
    }
}

/// Failure while atomically committing a key tombstone and destroying its
/// owned private material.
#[derive(Debug, Eq, PartialEq)]
pub enum KeyMaterialDestructionError<E> {
    /// The request did not identify this owned material.
    MaterialDigestMismatch,
    /// The registry commit failed; the material remains available.
    Commit(E),
}

impl<E: fmt::Display> fmt::Display for KeyMaterialDestructionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaterialDigestMismatch => {
                formatter.write_str("key material digest does not match the request")
            }
            Self::Commit(error) => write!(formatter, "key registry commit failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for KeyMaterialDestructionError<E> {}

/// Persistence boundary used by the private-material destruction helpers.
///
/// Implementations must make `begin` durable before returning and must make
/// `complete` durable only after the caller has destroyed its private
/// material. Keeping both phases on one mutable object prevents callers from
/// accidentally constructing two callbacks that borrow the same registry.
pub trait KeyDestructionPersistence {
    /// Error returned by the persistence boundary.
    type Error;

    /// Persist the pending-destruction state.
    ///
    /// # Errors
    ///
    /// Returns the persistence boundary's error when the pending state cannot
    /// be durably recorded.
    fn begin(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionBeginOutcomeV1, Self::Error>;

    /// Persist the final tombstone after private material has been destroyed.
    ///
    /// # Errors
    ///
    /// Returns the persistence boundary's error when the final tombstone
    /// cannot be durably recorded.
    fn complete(
        &mut self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<KeyDestructionOutcomeV1, Self::Error>;
}

impl KeyDestructionPersistence for pos_core::KeyRegistryStateV1 {
    type Error = KeyRegistryErrorV1;

    fn begin(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionBeginOutcomeV1, Self::Error> {
        self.begin_key_destruction(request)
    }

    fn complete(
        &mut self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<KeyDestructionOutcomeV1, Self::Error> {
        self.complete_key_destruction(request, deletion_receipt)
    }
}

/// Record pending destruction, destroy the corresponding owned signing key,
/// and then commit the final tombstone.
///
/// The first callback must durably persist `DestructionPending` before
/// returning. The second callback must durably persist the final tombstone
/// only after the deletion receipt is available. If either callback fails, the
/// error is returned and the pending state remains the recovery boundary.
///
/// # Errors
/// Returns [`KeyMaterialDestructionError::MaterialDigestMismatch`]
/// when the request does not identify this key, or
/// [`KeyMaterialDestructionError::Commit`] when either registry phase rejects
/// the request. Replaying the same request is idempotent.
pub fn destroy_registered_signing_key<P: KeyDestructionPersistence>(
    signing_key: &mut SigningKeyMaterial,
    request: KeyDestructionRequestV1,
    persistence: &mut P,
) -> Result<KeyDestructionOutcomeV1, KeyMaterialDestructionError<P::Error>> {
    let material_digest = signing_key.material_digest;
    if request.expected_material_digest != material_digest {
        return Err(KeyMaterialDestructionError::MaterialDigestMismatch);
    }
    let begin_outcome = persistence
        .begin(request)
        .map_err(KeyMaterialDestructionError::Commit)?;
    if let KeyDestructionBeginOutcomeV1::AlreadyDestroyed(tombstone) = begin_outcome {
        signing_key.destroy();
        return Ok(KeyDestructionOutcomeV1::AlreadyDestroyed(*tombstone));
    }
    signing_key.destroy();
    persistence
        .complete(request, deletion_receipt(&request))
        .map_err(KeyMaterialDestructionError::Commit)
}

/// Record pending destruction, destroy the corresponding owned encryption key,
/// and then commit the final tombstone.
///
/// # Errors
/// Returns [`KeyMaterialDestructionError::MaterialDigestMismatch`]
/// when the request does not identify this key, or
/// [`KeyMaterialDestructionError::Commit`] when either registry phase rejects
/// the request. Replaying the same request is idempotent.
pub fn destroy_registered_encryption_key<P: KeyDestructionPersistence>(
    encryption_key: &mut EncryptionKeyMaterial,
    request: KeyDestructionRequestV1,
    persistence: &mut P,
) -> Result<KeyDestructionOutcomeV1, KeyMaterialDestructionError<P::Error>> {
    let material_digest = encryption_key.material_digest;
    if request.expected_material_digest != material_digest {
        return Err(KeyMaterialDestructionError::MaterialDigestMismatch);
    }
    let begin_outcome = persistence
        .begin(request)
        .map_err(KeyMaterialDestructionError::Commit)?;
    if let KeyDestructionBeginOutcomeV1::AlreadyDestroyed(tombstone) = begin_outcome {
        encryption_key.destroy();
        return Ok(KeyDestructionOutcomeV1::AlreadyDestroyed(*tombstone));
    }
    encryption_key.destroy();
    persistence
        .complete(request, deletion_receipt(&request))
        .map_err(KeyMaterialDestructionError::Commit)
}

/// Fingerprint private key material without retaining the material in core.
///
/// The fingerprint intentionally does not include role or epoch.  That makes
/// the core registry able to detect one private key being registered for two
/// roles or two epochs. Owner, role, and epoch are bound separately by the
/// registry identity and by [`sign_for_registered_role`].
#[must_use]
pub fn key_material_digest(private_material: &[u8; 32]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(KEY_MATERIAL_DOMAIN);
    hasher.update(private_material);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn sign_for_role_unchecked(
    signing_key: &SigningKey,
    identity: KeyIdentityV1,
    payload: &CanonicalBytes,
) -> Signature {
    let message = role_bound_message(identity, payload);
    Signature::from_bytes(signing_key.sign(&message).to_bytes())
}

/// Sign an owner-scoped role/epoch-bound payload under the registry's atomic
/// authorization.
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
    let signing_key_ref = signing_key.as_key()?;
    let material_digest = signing_key.material_digest;
    let public_verification_key = signing_key.public_verification_key;
    registry.with_signing_authorization(identity, material_digest, public_verification_key, || {
        sign_for_role_unchecked(signing_key_ref, identity, payload)
    })
}

/// Authorize one encryption operation under an active registry identity.
///
/// The callback is the adapter-owned encryption operation and receives a
/// temporary borrow of the private material. The borrow cannot escape the
/// call, and the material is never cloned. Destruction and the callback are
/// ordered by the registry adapter's serialization boundary.
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
    F: FnOnce(&[u8; 32]) -> T,
{
    if identity.epoch == 0 {
        return Err(KeyRegistryErrorV1::InvalidEpoch);
    }
    if !identity.role.is_encryption() {
        return Err(KeyRegistryErrorV1::EncryptionRoleRequired);
    }
    let Some(material) = private_material.private_material.as_ref() else {
        return Err(KeyRegistryErrorV1::Destroyed);
    };
    let digest = private_material.material_digest;
    registry.with_encryption_authorization(identity, digest, || operation(material))
}

/// Verify an owner-scoped role/epoch-bound signature.
///
/// The signed preimage is exactly ADR-065's role-signature format: the
/// domain, the owner's UTF-8 byte length as a four-byte big-endian integer,
/// the exact owner bytes, the role code, the epoch as a big-endian integer,
/// and the canonical payload bytes.
///
/// # Errors
///
/// Returns [`pos_core::CoreError::SignatureVerificationFailed`] if the owner,
/// role, epoch, payload, or signature does not match.
pub fn verify_for_role(
    verifying_key: &VerifyingKey,
    identity: KeyIdentityV1,
    payload: &CanonicalBytes,
    signature: &Signature,
) -> Result<(), pos_core::CoreError> {
    if identity.epoch == 0 {
        return Err(pos_core::CoreError::SignatureVerificationFailed);
    }
    if !identity.role.is_signing() {
        return Err(pos_core::CoreError::SignatureVerificationFailed);
    }
    let message = role_bound_message(identity, payload);
    let signature = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| pos_core::CoreError::SignatureVerificationFailed)
}

fn role_bound_message(identity: KeyIdentityV1, payload: &CanonicalBytes) -> Vec<u8> {
    let owner_bytes = identity.owner_id.as_str().as_bytes();
    let owner_length = u32::try_from(owner_bytes.len()).unwrap_or_default();
    let mut message = Vec::with_capacity(
        ROLE_SIGNATURE_DOMAIN.len() + 4 + owner_bytes.len() + 1 + 8 + payload.len(),
    );
    message.extend_from_slice(ROLE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&owner_length.to_be_bytes());
    message.extend_from_slice(owner_bytes);
    message.push(identity.role.code());
    message.extend_from_slice(&identity.epoch.to_be_bytes());
    message.extend_from_slice(payload.as_slice());
    message
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::signing::{generate_keypair, public_key_from_verifying_key};
    use pos_core::{
        KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1,
    };

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
    fn role_signature_rejects_owner_role_and_epoch_confusion(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, verifying_key) = generate_keypair();
        let signing_key = SigningKeyMaterial::new(signing_key);
        let value = payload(b"attribution");
        assert!(KeyRoleV1::SubjectAttributionSigning.is_signing());
        assert!(KeyRoleV1::TimelineIntegritySigning.is_signing());
        assert!(KeyRoleV1::PluginReleaseSigning.is_signing());
        assert!(!KeyRoleV1::SubjectDataEncryption.is_signing());
        assert!(!KeyRoleV1::ExportRecipientEncryption.is_signing());
        let identity = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectAttributionSigning, 3);
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            identity,
            signing_key.material_digest(),
            Some(public_key_from_verifying_key(&verifying_key)),
        ))?;
        let signature = sign_for_registered_role(&mut registry, &signing_key, identity, &value)?;
        assert!(verify_for_role(&verifying_key, identity, &value, &signature).is_ok());
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("subject-owner", KeyRoleV1::TimelineIntegritySigning, 3,),
            &value,
            &signature
        )
        .is_err());
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 3),
            &value,
            &signature,
        )
        .is_err());
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectAttributionSigning, 0,),
            &value,
            &signature
        )
        .is_err());
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("other-owner", KeyRoleV1::SubjectAttributionSigning, 3),
            &value,
            &signature,
        )
        .is_err());
        assert_eq!(
            sign_for_registered_role(
                &mut registry,
                &signing_key,
                KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectAttributionSigning, 0,),
                &value,
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        assert_eq!(
            sign_for_registered_role(
                &mut registry,
                &signing_key,
                KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1),
                &value,
            ),
            Err(KeyRegistryErrorV1::SigningRoleRequired)
        );
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectAttributionSigning, 4,),
            &value,
            &signature
        )
        .is_err());

        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectAttributionSigning, 0,),
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
    fn role_signature_preimage_matches_adr_065() {
        let identity = KeyIdentityV1::new("owner-a", KeyRoleV1::PluginReleaseSigning, 9);
        let payload = payload(b"canonical payload");
        let mut expected = ROLE_SIGNATURE_DOMAIN.to_vec();
        expected.extend_from_slice(&(7_u32).to_be_bytes());
        expected.extend_from_slice(b"owner-a");
        expected.push(KeyRoleV1::PluginReleaseSigning.code());
        expected.extend_from_slice(&9_u64.to_be_bytes());
        expected.extend_from_slice(payload.as_slice());

        assert_eq!(role_bound_message(identity, &payload), expected);
    }

    #[test]
    fn historical_role_signature_verifies_after_registry_destruction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, verifying_key) = generate_keypair();
        let mut signing_key = SigningKeyMaterial::new(signing_key);
        let identity = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let material_digest = signing_key.material_digest();
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
            &mut registry,
        )?;

        assert_eq!(
            sign_for_registered_role(&mut registry, &signing_key, identity, &value),
            Err(KeyRegistryErrorV1::Destroyed)
        );

        assert!(verify_for_role(&verifying_key, identity, &value, &signature,).is_ok());
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
        let identity = KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
        let material_digest = material.material_digest();
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(identity, material_digest, None))?;

        let mut callbacks = 0;
        assert_eq!(
            with_registered_encryption_authorization(&mut registry, &material, identity, |_| {
                callbacks += 1;
                7u8
            },)?,
            7
        );
        assert_eq!(callbacks, 1);
        destroy_registered_encryption_key(
            &mut material,
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([12; 32])),
            &mut registry,
        )?;
        assert_eq!(
            with_registered_encryption_authorization(&mut registry, &material, identity, |_| {
                callbacks += 1;
                8u8
            },),
            Err(KeyRegistryErrorV1::Destroyed)
        );
        assert_eq!(callbacks, 1);

        let signing_identity =
            KeyIdentityV1::new("subject-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        assert_eq!(
            with_registered_encryption_authorization(
                &mut registry,
                &material,
                signing_identity,
                |_| (),
            ),
            Err(KeyRegistryErrorV1::EncryptionRoleRequired)
        );
        assert_eq!(
            with_registered_encryption_authorization(
                &mut registry,
                &material,
                KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 0),
                |_| (),
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        Ok(())
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod key_roles_coverage {
    use super::*;
    use crate::signing::{generate_keypair, public_key_from_verifying_key};
    use pos_core::{
        KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1,
    };

    fn payload(bytes: &[u8]) -> CanonicalBytes {
        CanonicalBytes::from_vec(bytes.to_vec())
    }

    #[test]
    fn public_role_operations_cover_destroyed_material_and_invalid_inputs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, verifying_key) = generate_keypair();
        let mut signing_material = SigningKeyMaterial::new(signing_key);
        let signing_identity =
            KeyIdentityV1::new("coverage-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let mut signing_registry = KeyRegistryStateV1::new();
        signing_registry.register_key(KeyRegistrationV1::new(
            signing_identity,
            signing_material.material_digest(),
            Some(public_key_from_verifying_key(&verifying_key)),
        ))?;
        let message = payload(b"coverage");
        let signature = sign_for_registered_role(
            &mut signing_registry,
            &signing_material,
            signing_identity,
            &message,
        )?;
        assert!(verify_for_role(&verifying_key, signing_identity, &message, &signature,).is_ok());
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("coverage-owner", KeyRoleV1::SubjectAttributionSigning, 0,),
            &message,
            &signature,
        )
        .is_err());
        assert!(verify_for_role(
            &verifying_key,
            KeyIdentityV1::new("coverage-owner", KeyRoleV1::SubjectDataEncryption, 1,),
            &message,
            &signature,
        )
        .is_err());
        assert!(verify_for_role(
            &verifying_key,
            signing_identity,
            &payload(b"different"),
            &signature,
        )
        .is_err());

        let signing_request = KeyDestructionRequestV1::new(
            signing_identity,
            signing_material.material_digest(),
            Hash::from_bytes([1; 32]),
        );
        assert!(matches!(
            destroy_registered_signing_key(
                &mut signing_material,
                KeyDestructionRequestV1::new(
                    signing_identity,
                    Hash::from_bytes([2; 32]),
                    Hash::from_bytes([1; 32]),
                ),
                &mut signing_registry,
            ),
            Err(KeyMaterialDestructionError::MaterialDigestMismatch)
        ));
        assert!(matches!(
            destroy_registered_signing_key(
                &mut signing_material,
                signing_request,
                &mut signing_registry,
            )?,
            KeyDestructionOutcomeV1::Destroyed(_)
        ));
        assert!(signing_material.is_destroyed());
        assert!(matches!(
            sign_for_registered_role(
                &mut signing_registry,
                &signing_material,
                signing_identity,
                &message,
            ),
            Err(KeyRegistryErrorV1::Destroyed)
        ));
        assert!(matches!(
            destroy_registered_signing_key(
                &mut signing_material,
                signing_request,
                &mut signing_registry,
            )?,
            KeyDestructionOutcomeV1::AlreadyDestroyed(_)
        ));

        Ok(())
    }

    #[test]
    fn encryption_operations_cover_destroyed_material() -> Result<(), Box<dyn std::error::Error>> {
        let mut encryption_material = EncryptionKeyMaterial::new([9; 32]);
        let encryption_identity =
            KeyIdentityV1::new("coverage-owner", KeyRoleV1::SubjectDataEncryption, 1);
        let mut encryption_registry = KeyRegistryStateV1::new();
        encryption_registry.register_key(KeyRegistrationV1::new(
            encryption_identity,
            encryption_material.material_digest(),
            None,
        ))?;
        assert_eq!(
            with_registered_encryption_authorization(
                &mut encryption_registry,
                &encryption_material,
                encryption_identity,
                |key| key[0],
            )?,
            9
        );
        let encryption_request = KeyDestructionRequestV1::new(
            encryption_identity,
            encryption_material.material_digest(),
            Hash::from_bytes([3; 32]),
        );
        assert!(matches!(
            destroy_registered_encryption_key(
                &mut encryption_material,
                encryption_request,
                &mut encryption_registry,
            )?,
            KeyDestructionOutcomeV1::Destroyed(_)
        ));
        assert!(matches!(
            with_registered_encryption_authorization(
                &mut encryption_registry,
                &encryption_material,
                encryption_identity,
                |_| (),
            ),
            Err(KeyRegistryErrorV1::Destroyed)
        ));
        Ok(())
    }
}
