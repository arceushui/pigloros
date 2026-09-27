//! HPKE recipient-key derivation used by durable recipient custody.

use hpke::{kem::X25519HkdfSha256, Deserializable, Kem, Serializable};
use thiserror::Error;

/// Closed failures while converting HPKE KEM output to the RKP1 key width.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RecipientKeyErrorV1 {
    /// The selected KEM did not produce an X25519-sized key.
    #[error("HPKE X25519 key width is invalid")]
    InvalidKeyWidth,
}

/// Derive a DHKEM(X25519, HKDF-SHA256) key pair from CSPRNG IKM.
///
/// The caller must zeroize `ikm` after this call and retain the returned
/// private bytes only in the owner-managed durable boundary.
///
/// # Errors
///
/// Returns a closed error if the selected HPKE KEM does not return
/// X25519-sized private or public key bytes.
pub fn derive_recipient_keypair_v1(
    ikm: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), RecipientKeyErrorV1> {
    let (private_key, public_key) = X25519HkdfSha256::derive_keypair(ikm);
    let private_key = private_key.to_bytes();
    let public_key = public_key.to_bytes();
    let private_key = private_key
        .as_slice()
        .try_into()
        .map_err(|_| RecipientKeyErrorV1::InvalidKeyWidth)?;
    let public_key = public_key
        .as_slice()
        .try_into()
        .map_err(|_| RecipientKeyErrorV1::InvalidKeyWidth)?;
    Ok((private_key, public_key))
}

/// Derive the X25519 public key corresponding to stored HPKE private bytes.
///
/// # Errors
///
/// Returns a closed error when the private bytes are not an X25519 private
/// key accepted by the selected HPKE KEM.
pub fn recipient_public_key_from_private_v1(
    private_key: &[u8; 32],
) -> Result<[u8; 32], RecipientKeyErrorV1> {
    let private_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(private_key)
        .map_err(|_| RecipientKeyErrorV1::InvalidKeyWidth)?;
    let public_key = X25519HkdfSha256::sk_to_pk(&private_key).to_bytes();
    public_key
        .as_slice()
        .try_into()
        .map_err(|_| RecipientKeyErrorV1::InvalidKeyWidth)
}
