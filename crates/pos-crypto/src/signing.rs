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

/// Verify every event that carries a signature against `verifying_key` and its payload.
///
/// Events with `signature: None` are skipped. Prefer [`verify_events_all_signed`] when
/// an export is expected to be fully signed.
///
/// Note: signatures cover the **payload bytes only**, not id/seq/entity/causation metadata.
///
/// # Errors
/// Returns [`CoreError::SignatureVerificationFailed`] on the first bad signature.
pub fn verify_events(
    verifying_key: &VerifyingKey,
    events: &[pos_core::Event],
) -> Result<(), CoreError> {
    for event in events {
        if let Some(sig) = &event.signature {
            verify(verifying_key, &event.payload, sig)?;
        }
    }
    Ok(())
}

/// Like [`verify_events`], but every event must carry a signature (empty slice is ok).
///
/// # Errors
/// Returns [`CoreError::SignatureVerificationFailed`] if any event is unsigned or fails verify.
pub fn verify_events_all_signed(
    verifying_key: &VerifyingKey,
    events: &[pos_core::Event],
) -> Result<(), CoreError> {
    for event in events {
        let Some(sig) = &event.signature else {
            return Err(CoreError::SignatureVerificationFailed);
        };
        verify(verifying_key, &event.payload, sig)?;
    }
    Ok(())
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
        // Compressed Edwards-Y that fails decompression (last byte 0xff with zeros).
        let mut bytes = [0u8; 32];
        bytes[31] = 0xff;
        let bad_pk = PublicKey::from_bytes(bytes);
        let result = verifying_key_from_public_key(&bad_pk);
        assert!(matches!(
            result,
            Err(CoreError::SignatureVerificationFailed)
        ));
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_events_skips_unsigned_and_checks_signed() {
        use pos_core::{
            clock::{Seq, WallTime},
            crypto::Hash,
            event::{Event, Kind, SchemaVersion},
            ids::{EntityId, EventId},
        };

        let (sk, vk) = generate_keypair();
        let p = payload(b"body");
        let sig = sign(&sk, &p);
        let signed = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("t"),
            payload: p.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(sig),
            payload_hash: Hash::zero(),
        };
        let unsigned = Event {
            signature: None,
            ..signed.clone()
        };
        assert!(verify_events(&vk, &[unsigned, signed.clone()]).is_ok());

        let (_, other_vk) = generate_keypair();
        assert!(verify_events(&other_vk, &[signed]).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn verify_events_all_signed_rejects_unsigned() {
        use pos_core::{
            clock::{Seq, WallTime},
            crypto::Hash,
            event::{Event, Kind, SchemaVersion},
            ids::{EntityId, EventId},
        };

        let (sk, vk) = generate_keypair();
        let p = payload(b"body");
        let unsigned = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("t"),
            payload: p.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::zero(),
        };
        assert!(verify_events_all_signed(&vk, std::slice::from_ref(&unsigned)).is_err());
        let mut signed = unsigned;
        signed.signature = Some(sign(&sk, &p));
        assert!(verify_events_all_signed(&vk, &[signed]).is_ok());
        assert!(verify_events_all_signed(&vk, &[]).is_ok());
    }
}
