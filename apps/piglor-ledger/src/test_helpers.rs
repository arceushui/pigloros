//! Shared test-support utilities exposed as a public module so the binary
//! crate's test code can call them without duplicating the implementations.

use std::path::Path;

use crate::hex::hex_decode;

/// Derive the hex-encoded public key from a hex-encoded (32-byte) secret key.
///
/// # Panics
/// Panics if `secret_hex` is not 64 hex chars — expected only on test
/// fixtures that guarantee valid input.
#[must_use]
pub fn derive_pubkey_hex(secret_hex: &str) -> String {
    let bytes = hex_decode(secret_hex.trim()).unwrap();
    let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    let vk = sk.verifying_key();
    crate::hex_encode(&vk.to_bytes())
}

/// Return the prediction id (ULID string) of the first `.toml` file found
/// under `<dir>/predictions/`.
///
/// Used in multiple test modules; lives here to avoid the 4-way duplication
/// of the `read_dir().next().…file_stem().to_owned()` chain.
///
/// # Panics
///
/// Panics if the `predictions/` directory is empty or the entry cannot be
/// read — expected only in test fixtures that guarantee a prediction exists.
#[must_use]
pub fn first_prediction_id(dir: &Path) -> String {
    std::fs::read_dir(dir.join("predictions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}
