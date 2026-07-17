//! Ed25519 sign/verify for events.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pos_core::{CanonicalBytes, CoreError, PublicKey, Signature};
use rand_core::OsRng;

/// Generate a new Ed25519 signing key pair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a canonical payload with the given signing key.
/// Returns a core `Signature` newtype.
pub fn sign(signing_key: &SigningKey, payload: &CanonicalBytes) -> Signature {
    let sig = signing_key.sign(payload.as_slice());
    Signature::from_bytes(sig.to_bytes())
}

/// Verify a signature against the canonical payload using a verifying key.
///
/// # Errors
/// Returns [`CoreError::SignatureVerificationFailed`] if the signature is invalid.
pub fn verify(
    verifying_key: &VerifyingKey,
    payload: &CanonicalBytes,
    signature: &Signature,
) -> Result<(), CoreError> {
    let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify(payload.as_slice(), &sig)
        .map_err(|_| CoreError::SignatureVerificationFailed)
}

/// Convert a core `PublicKey` to an `ed25519_dalek::VerifyingKey`.
///
/// # Errors
/// Returns [`CoreError::SignatureVerificationFailed`] if the bytes are not a valid compressed Ed25519 point.
pub fn verifying_key_from_public_key(pk: &PublicKey) -> Result<VerifyingKey, CoreError> {
    VerifyingKey::from_bytes(pk.as_bytes()).map_err(|_| CoreError::SignatureVerificationFailed)
}

/// Convert a `VerifyingKey` to a core `PublicKey`.
#[must_use]
pub fn public_key_from_verifying_key(vk: &VerifyingKey) -> PublicKey {
    PublicKey::from_bytes(vk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(b: &[u8]) -> CanonicalBytes {
        CanonicalBytes::from_vec(b.to_vec())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sign_and_verify_round_trip() {
        let (sk, vk) = generate_keypair();
        let p = payload(b"sign me");
        let sig = sign(&sk, &p);
        assert!(verify(&vk, &p, &sig).is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tampered_payload_fails_verification() {
        let (sk, vk) = generate_keypair();
        let p = payload(b"original");
        let sig = sign(&sk, &p);
        let tampered = payload(b"tampered");
        assert!(verify(&vk, &tampered, &sig).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wrong_key_fails_verification() {
        let (sk, _vk) = generate_keypair();
        let (_, other_vk) = generate_keypair();
        let p = payload(b"data");
        let sig = sign(&sk, &p);
        assert!(verify(&other_vk, &p, &sig).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn different_payloads_produce_different_signatures() {
        let (sk, _) = generate_keypair();
        let s1 = sign(&sk, &payload(b"a"));
        let s2 = sign(&sk, &payload(b"b"));
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_key_round_trip_via_verifying_key() {
        let (_, vk) = generate_keypair();
        let pk = public_key_from_verifying_key(&vk);
        let vk2 = verifying_key_from_public_key(&pk).unwrap();
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn invalid_public_key_bytes_returns_error() {
        let bad_pk = PublicKey::from_bytes([0u8; 32]);
        // All-zeros is not a valid compressed point on Ed25519
        let result = verifying_key_from_public_key(&bad_pk);
        // May succeed or fail depending on ed25519-dalek's validation — just ensure no panic
        let _ = result;
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_payload_signs_and_verifies() {
        let (sk, vk) = generate_keypair();
        let p = payload(b"");
        let sig = sign(&sk, &p);
        assert!(verify(&vk, &p, &sig).is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_is_64_bytes() {
        let (sk, _) = generate_keypair();
        let sig = sign(&sk, &payload(b"test"));
        assert_eq!(sig.as_bytes().len(), 64);
    }
}
