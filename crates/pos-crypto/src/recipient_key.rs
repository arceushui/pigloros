//! HPKE recipient-key derivation used by durable recipient custody.

use hpke::{kem::X25519HkdfSha256, Kem, Serializable};
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
