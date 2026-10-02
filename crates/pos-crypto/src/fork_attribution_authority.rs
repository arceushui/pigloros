//! Ed25519 verification for the ADR-105 `FAE1` issuer signature.
//!
//! A valid signature proves only that the key named by the envelope's exact
//! `FAI1` signed the exact unsigned preimage. It does not establish that the
//! issuer is `Active` in the locally pinned `FIP1`, nor install anything.

use ed25519_dalek::VerifyingKey;
use pos_core::{
    ForkAttributionAuthorityEnvelopeV1, ForkAttributionIssuerPolicyV1, ForkAttributionIssuerV1,
};

/// Closed failures for `FAE1` issuer key and signature verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAttributionAuthoritySignatureErrorV1 {
    /// The issuer public key is not a valid, non-weak Ed25519 point.
    #[error("Fork attribution issuer key is invalid")]
    InvalidIssuerKey,
    /// The issuer signature does not verify over the exact preimage.
    #[error("Fork attribution envelope signature is invalid")]
    InvalidSignature,
}

/// Require one `FAI1` public key to be valid Ed25519 verification material.
///
/// # Errors
/// Returns [`ForkAttributionAuthoritySignatureErrorV1::InvalidIssuerKey`] for
/// bytes that are not a point encoding or that encode a small-order point.
pub fn verify_fork_attribution_issuer_key_v1(
    issuer: &ForkAttributionIssuerV1,
) -> Result<(), ForkAttributionAuthoritySignatureErrorV1> {
    issuer_key(issuer).map(|_| ())
}

/// Require every `FIP1` entry key to be valid Ed25519 verification material.
///
/// # Errors
/// Returns [`ForkAttributionAuthoritySignatureErrorV1::InvalidIssuerKey`] for
/// the first invalid entry key.
pub fn verify_fork_attribution_issuer_policy_keys_v1(
    policy: &ForkAttributionIssuerPolicyV1,
) -> Result<(), ForkAttributionAuthoritySignatureErrorV1> {
    policy
        .input()
        .entries
        .iter()
        .try_for_each(|entry| verify_fork_attribution_issuer_key_v1(&entry.issuer))
}

/// Verify `FAE1` field 22 under the key of its exact field-3 `FAI1`.
///
/// The message is the ADR-105 signature domain, the big-endian unsigned
/// length, and the exact canonical 22-element unsigned array. Verification
/// is strict Ed25519.
///
/// # Errors
/// Returns [`ForkAttributionAuthoritySignatureErrorV1::InvalidIssuerKey`] for
/// invalid or weak key material, and
/// [`ForkAttributionAuthoritySignatureErrorV1::InvalidSignature`] for any
/// signature that does not verify.
pub fn verify_fork_attribution_authority_envelope_signature_v1(
    envelope: &ForkAttributionAuthorityEnvelopeV1,
) -> Result<(), ForkAttributionAuthoritySignatureErrorV1> {
    let unsigned = envelope.unsigned();
    issuer_key(&unsigned.input().issuer).and_then(|key| {
        key.verify_strict(
            &unsigned.signature_message(),
            &ed25519_dalek::Signature::from_bytes(envelope.signature().as_bytes()),
        )
        .map_err(|_| ForkAttributionAuthoritySignatureErrorV1::InvalidSignature)
    })
}

fn issuer_key(
    issuer: &ForkAttributionIssuerV1,
) -> Result<VerifyingKey, ForkAttributionAuthoritySignatureErrorV1> {
    // A small-order key admits signatures over arbitrary messages, so it can
    // never identify an attribution-import issuer.
    VerifyingKey::from_bytes(issuer.public_key().as_bytes())
        .ok()
        .filter(|key| !key.is_weak())
        .ok_or(ForkAttributionAuthoritySignatureErrorV1::InvalidIssuerKey)
}
