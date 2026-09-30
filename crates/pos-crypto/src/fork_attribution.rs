//! Mathematical signing helpers for the portable ADR-099 `FSM1` seam.
//!
//! These helpers deliberately do not publish a sidecar or authorize Replay.
//! The later local publication authority must hold registry authorization
//! through its own transaction and must not use this standalone helper.

use ed25519_dalek::VerifyingKey;
use pos_core::{
    CanonicalBytes, CoreError, ForkAdmissionRecordV1, ForkAttributionCodecErrorV1,
    ForkReproManifestV1, KeyIdentityV1, KeyRegistryErrorV1, KeyRegistrySigningPortV1, KeyRoleV1,
    PublicKey, Signature, SignedForkReproManifestV1,
};

use crate::{
    key_roles::{sign_for_registered_role, verify_for_role, SigningKeyMaterial},
    signing::verifying_key_from_public_key,
};

/// Closed errors for admission-bound signature-only construction.
#[derive(Debug, thiserror::Error)]
pub enum ForkAttributionSigningErrorV1 {
    /// The supplied local attribution records do not form a valid construction input.
    #[error(transparent)]
    Codec(#[from] ForkAttributionCodecErrorV1),
    /// The current key registry rejected the derived attribution identity.
    #[error(transparent)]
    Registry(#[from] KeyRegistryErrorV1),
}

/// Sign an `FSM1` whose creator and duplicate `FRM1` coordinates match local `FAR1`.
///
/// The supplied admission record is structural input only. This helper does
/// not assert that it is a committed host authority or publish the resulting
/// record; #452 owns that durable authority boundary.
///
/// # Errors
///
/// Returns the precise codec error for invalid construction input, or the
/// closed registry error from the signing operation.
pub fn sign_local_fork_manifest_from_admission_signature_only<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKeyMaterial,
    admission: &ForkAdmissionRecordV1,
    epoch: u64,
    manifest: ForkReproManifestV1,
) -> Result<SignedForkReproManifestV1, ForkAttributionSigningErrorV1> {
    let identity = KeyIdentityV1::from_parts(
        admission.input().creator,
        KeyRoleV1::SubjectAttributionSigning,
        epoch,
    );
    sign_local_fork_manifest_for_identity_signature_only(
        registry,
        signing_key,
        identity,
        admission,
        manifest,
    )
}

/// Sign an admission-bound `FSM1` for an already held registry identity.
///
/// The identity is checked by the same `FSM1` constructor as decoded records,
/// then bound to the supplied local `FAR1`, before the registry can sign. It
/// does not grant admission or publication authority.
///
/// # Errors
///
/// Returns [`ForkAttributionCodecErrorV1::FieldOutOfBounds`] for a zero epoch
/// or a role other than `SubjectAttributionSigning`,
/// [`ForkAttributionCodecErrorV1::FieldMismatch`] for a creator or manifest
/// that disagrees with `FAR1`, or the closed registry error from signing.
pub fn sign_local_fork_manifest_for_identity_signature_only<R: KeyRegistrySigningPortV1>(
    registry: &mut R,
    signing_key: &SigningKeyMaterial,
    identity: KeyIdentityV1,
    admission: &ForkAdmissionRecordV1,
    manifest: ForkReproManifestV1,
) -> Result<SignedForkReproManifestV1, ForkAttributionSigningErrorV1> {
    let placeholder = Signature::from_bytes([0; 64]);
    let unsigned =
        SignedForkReproManifestV1::new(identity, manifest, placeholder).and_then(|record| {
            record
                .validate_against_admission(admission)
                .map(|()| record)
        })?;
    let payload = CanonicalBytes::from_vec(unsigned.manifest_bytes());
    let signature = sign_for_registered_role(registry, signing_key, identity, &payload)?;
    Ok(unsigned.with_signature(signature))
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
    verify_for_role(
        &verifying_key,
        manifest.identity(),
        &payload,
        &manifest.signature(),
    )
}
