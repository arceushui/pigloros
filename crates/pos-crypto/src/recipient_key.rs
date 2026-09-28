//! HPKE recipient-key derivation used by durable recipient custody.

use hpke::{kem::X25519HkdfSha256, Kem, Serializable};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// Derive a DHKEM(X25519, HKDF-SHA256) key pair from CSPRNG IKM.
///
/// The caller must zeroize `ikm` after this call and retain the returned
/// private bytes only in the owner-managed durable boundary.
///
pub fn derive_recipient_keypair_v1(ikm: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (private_key, public_key) = X25519HkdfSha256::derive_keypair(ikm);
    let private_key = private_key.to_bytes();
    let public_key = public_key.to_bytes();
    let private_key = private_key.into();
    let public_key = public_key.into();
    (private_key, public_key)
}

/// Derive the X25519 public key corresponding to stored HPKE private bytes.
///
pub fn recipient_public_key_from_private_v1(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(*private_key, X25519_BASEPOINT_BYTES)
}
