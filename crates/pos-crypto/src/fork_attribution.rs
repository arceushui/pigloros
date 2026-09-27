//! Mathematical signing helpers for the portable ADR-099 `FSM1` seam.
//!
//! These helpers deliberately do not publish a sidecar or authorize Replay.
//! The later local publication authority must hold registry authorization
//! through its own transaction and must not use this standalone helper.

use ed25519_dalek::VerifyingKey;
use pos_core::{
    CanonicalBytes, CoreError, KeyIdentityV1, KeyRegistryErrorV1, KeyRegistrySigningPortV1,
    KeyRoleV1, PublicKey, SignedForkReproManifestV1,
};

use crate::{
    key_roles::{sign_for_registered_role, verify_for_role, SigningKeyMaterial},
    signing::verifying_key_from_public_key,
};

/// Produce a mathematical `FSM1` signature through the current role registry.
///
/// This standalone operation is intentionally unsuitable for trusted Fork
/// publication: its authorization ends when the callback returns. It exists
/// for portable vectors and diagnostics only.
///
/// # Errors
///
/// Returns the closed registry error when the exact attribution identity is
/// inactive, absent, destroyed, or does not match the supplied private key.
pub fn sign_local_fork_manifest_signature_only<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKeyMaterial,
    identity: KeyIdentityV1,
    manifest: pos_core::ForkReproManifestV1,
) -> Result<SignedForkReproManifestV1, KeyRegistryErrorV1> {
    if identity.role != KeyRoleV1::SubjectAttributionSigning {
        return Err(KeyRegistryErrorV1::SigningRoleRequired);
    }
    let payload = CanonicalBytes::from_vec(manifest.to_canonical_cbor());
    let signature = sign_for_registered_role(registry, signing_key, identity, &payload)?;
    SignedForkReproManifestV1::new(identity, manifest, signature)
        .map_err(|_| KeyRegistryErrorV1::SigningRoleRequired)
}

/// Verify only the mathematical ADR-065 role signature in `FSM1`.
///
/// Successful output does not prove that a Fork was admitted or that a sidecar
/// was atomically published; consumers must use the later trusted read seam.
///
/// # Errors
///
/// Returns [`CoreError::SignatureVerificationFailed`] for invalid public key,
/// identity, inner bytes, or signature.
pub fn verify_local_fork_manifest_signature_only(
    manifest: &SignedForkReproManifestV1,
    public_key: PublicKey,
) -> Result<(), CoreError> {
    let verifying_key: VerifyingKey = verifying_key_from_public_key(&public_key)
        .map_err(|_| CoreError::SignatureVerificationFailed)?;
    let payload = CanonicalBytes::from_vec(manifest.manifest_bytes());
    verify_for_role(&verifying_key, manifest.identity(), &payload, &manifest.signature())
}
