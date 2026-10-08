//! PMF1 V1 release-signature verification (ADR-061 revision 2).
//!
//! Verification re-decodes one verified OCI release closure, so the signed
//! release digest, owner, and epoch come from the closure's own PMF1 bytes and
//! never from a caller-supplied projection. The ADR-103 trust authorization
//! supplies the one public key and the complete-PMF1 digest it was resolved
//! for. Success is mathematical validity only: it does not prove that the
//! registry authorized the signing, that the release is admitted, or that any
//! policy accepts it.

use ed25519_dalek::VerifyingKey;
use pos_core::{CanonicalBytes, KeyIdentityV1, KeyRoleV1, OwnerIdV1, Signature};
use pos_plugin_release::VerifiedReleaseBundleV1;
use thiserror::Error;

use super::{validate_bundle, Digest, PluginManifestErrorV1};
use crate::key_roles::verify_for_role;
use crate::plugin_trust::ResolvedPluginTrustAuthorizationV1;

/// A closed PMF1 release-signature verification failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginReleaseSignatureErrorV1 {
    /// The closure's PMF1 failed strict decoding, closure binding, or digest
    /// recomputation.
    #[error(transparent)]
    Manifest(#[from] PluginManifestErrorV1),
    /// The authorization was resolved for different complete PMF1 bytes than
    /// the closure carries.
    #[error("trust authorization is bound to a different PMF1")]
    AuthorizationMismatch,
    /// Field 26 is not a valid signature by the resolved key over the ADR-065
    /// message for the release digest, owner, role 3, and epoch.
    #[error("PMF1 release signature does not verify")]
    InvalidSignature,
}

/// Proof that field 26 of one PMF1 is a valid signature by the authorized key.
///
/// It is constructed only by [`verify_plugin_release_signature_v1()`]. It is a
/// mathematical fact about exact bytes, not an admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPluginReleaseSignatureV1 {
    pmf1_digest: Digest,
    release_digest: Digest,
    owner: OwnerIdV1,
    epoch: u64,
    public_key: [u8; 32],
}

impl VerifiedPluginReleaseSignatureV1 {
    /// BLAKE3-256 of the complete PMF1 bytes that were verified.
    #[must_use]
    pub const fn pmf1_digest(&self) -> Digest {
        self.pmf1_digest
    }

    /// The signed field 27 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> Digest {
        self.release_digest
    }

    /// The signing identity's owner (field 21).
    #[must_use]
    pub const fn owner(&self) -> OwnerIdV1 {
        self.owner
    }

    /// The signing identity's key epoch (field 26).
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The raw Ed25519 public key the signature verified under, as resolved by
    /// the trust authorization.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// The signature claim of one strictly decoded PMF1: what field 26 asserts,
/// before any key has judged it.
///
/// It is produced only by [`decode_plugin_release_signature_claim_v1()`] from
/// the closure's own bytes. It proves nothing: whether the signature verifies,
/// which key may verify it, and whether the release is admitted are separate
/// questions for the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginReleaseSignatureClaimV1 {
    pmf1_digest: Digest,
    release_digest: Digest,
    owner: OwnerIdV1,
    epoch: u64,
    signature: [u8; 64],
}

impl PluginReleaseSignatureClaimV1 {
    /// BLAKE3-256 of the complete PMF1 bytes that were decoded.
    #[must_use]
    pub const fn pmf1_digest(&self) -> Digest {
        self.pmf1_digest
    }

    /// The claimed field 27 release digest (the signed payload).
    #[must_use]
    pub const fn release_digest(&self) -> Digest {
        self.release_digest
    }

    /// The claimed signing identity's owner (field 21).
    #[must_use]
    pub const fn owner(&self) -> OwnerIdV1 {
        self.owner
    }

    /// The claimed signing key epoch (field 26).
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The 64 signature bytes (field 26).
    #[must_use]
    pub const fn signature(&self) -> [u8; 64] {
        self.signature
    }
}

/// Decode, bind, and digest-check `bundle`, then return its signature claim.
///
/// The same phases as [`verify_plugin_release_signature_v1()`] run, but no key
/// is consulted: the caller judges the claim under whichever key it retains.
///
/// # Errors
/// Returns the strict decode, closure, or digest failure.
pub fn decode_plugin_release_signature_claim_v1(
    bundle: &VerifiedReleaseBundleV1,
) -> Result<PluginReleaseSignatureClaimV1, PluginManifestErrorV1> {
    let validated = validate_bundle(bundle)?;
    let signed = &validated.pmf1.signed;
    Ok(PluginReleaseSignatureClaimV1 {
        pmf1_digest: validated.pmf1_digest,
        release_digest: signed.release_digest,
        owner: signed.owner,
        epoch: signed.epoch,
        signature: signed.signature,
    })
}

/// Verify field 26 of the PMF1 in `bundle` under the authorization's key.
///
/// The bundle is decoded, bound, and digest-checked again. The authorization's
/// complete-PMF1 digest must equal the BLAKE3-256 of the exact PMF1 bytes, and
/// the signature must verify, under `authorization`'s resolved key, over the
/// ADR-065 message for the identity `(owner, PluginReleaseSigning, epoch)` and
/// the raw 32-byte release digest. The caller supplies no projection, key, or
/// clock.
///
/// # Errors
/// Returns the strict decode, closure, or digest failure; or
/// `AuthorizationMismatch` when the authorization was resolved for other PMF1
/// bytes; or `InvalidSignature` when the signature does not verify under the key.
pub fn verify_plugin_release_signature_v1(
    bundle: &VerifiedReleaseBundleV1,
    authorization: &ResolvedPluginTrustAuthorizationV1,
) -> Result<VerifiedPluginReleaseSignatureV1, PluginReleaseSignatureErrorV1> {
    let validated = validate_bundle(bundle)?;
    if validated.pmf1_digest != authorization.pmf1_digest() {
        return Err(PluginReleaseSignatureErrorV1::AuthorizationMismatch);
    }
    let signed = &validated.pmf1.signed;
    let public_key = authorization.resolved_public_key();
    let identity =
        KeyIdentityV1::from_parts(signed.owner, KeyRoleV1::PluginReleaseSigning, signed.epoch);
    let payload = CanonicalBytes::from_vec(signed.release_digest.to_vec());
    let signature = Signature::from_bytes(signed.signature);
    // PTR1 decoding already proved the key is a curve point; a key that still
    // fails to parse is rejected like a signature that does not verify.
    let valid = VerifyingKey::from_bytes(&public_key)
        .is_ok_and(|key| verify_for_role(&key, identity, &payload, &signature).is_ok());
    if !valid {
        return Err(PluginReleaseSignatureErrorV1::InvalidSignature);
    }
    Ok(VerifiedPluginReleaseSignatureV1 {
        pmf1_digest: validated.pmf1_digest,
        release_digest: signed.release_digest,
        owner: signed.owner,
        epoch: signed.epoch,
        public_key,
    })
}
