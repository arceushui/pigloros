//! THROWAWAY (#471 prototype). Exercises exactly the non-allocating APIs that
//! ADR-110 r6 §2 lists for the codec: `Digest` into a fixed array,
//! `VerifyingKey::verify`, `Signature::from_der` on a borrowed slice,
//! `httparse::Request::parse` with caller-owned header slots and
//! `Engine::encode_slice`. No `alloc`.
#![no_std]

use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use sha2::Digest as _;

/// SHA-256 into a fixed array.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha2::Sha256::digest(data));
    out
}

/// base64url (no pad) into a caller buffer.
pub fn b64(data: &[u8], out: &mut [u8; 64]) -> Option<usize> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(data, out)
        .ok()
}

/// Parse one request with exactly 24 caller-owned header slots.
pub fn admit(buf: &[u8]) -> Option<usize> {
    let mut headers = [httparse::EMPTY_HEADER; 24];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => Some(n),
        _ => None,
    }
}

/// ES256 verification: uncompressed SEC1 point from COSE x/y, DER signature.
#[cfg(feature = "api-key-sec1")]
pub fn key_from_xy(x: &[u8; 32], y: &[u8; 32]) -> Option<p256::ecdsa::VerifyingKey> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..33].copy_from_slice(x);
    sec1[33..].copy_from_slice(y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()
}

#[cfg(feature = "api-sig-der")]
pub fn verify_der(key: &p256::ecdsa::VerifyingKey, msg: &[u8], der: &[u8]) -> bool {
    match p256::ecdsa::Signature::from_der(der) {
        Ok(sig) => key.verify(msg, &sig).is_ok(),
        Err(_) => false,
    }
}

/// Fixed-size (r||s) signature path, always available.
pub fn verify_fixed(key: &p256::ecdsa::VerifyingKey, msg: &[u8], rs: &[u8; 64]) -> bool {
    match p256::ecdsa::Signature::from_slice(rs) {
        Ok(sig) => key.verify(msg, &sig).is_ok(),
        Err(_) => false,
    }
}
