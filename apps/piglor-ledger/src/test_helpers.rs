//! Shared test-support utilities exposed as a public module so the binary
//! crate's test code can call them without duplicating the implementations.

use std::fmt::Debug;
use std::path::Path;

use crate::hex::hex_decode;

/// Report whether the current Unix test process has effective UID zero.
#[cfg(all(test, unix))]
#[must_use]
pub fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:\t"))
                .and_then(|uids| uids.split_whitespace().next())
                .and_then(|uid| uid.parse::<u32>().ok())
        })
        == Some(0)
}

/// Fallible assertions used by test modules that must propagate fixture errors.
pub trait TestResultExt<T, E> {
    /// Extract an expected error without panicking.
    ///
    /// # Errors
    ///
    /// Returns an error when the result is unexpectedly successful.
    fn test_err(self) -> Result<E, Box<dyn std::error::Error>>;
    /// Extract an expected success without panicking.
    ///
    /// # Errors
    ///
    /// Returns the source error when the result is unsuccessful.
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
}

impl<T, E: Debug> TestResultExt<T, E> for Result<T, E> {
    fn test_err(self) -> Result<E, Box<dyn std::error::Error>> {
        self.err().ok_or_else(|| "expected an error".into())
    }

    fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
        self.map_err(|error| format!("unexpected error: {error:?}").into())
    }
}

/// Fallible assertions for optional test fixture values.
pub trait TestOptionExt<T> {
    /// Extract an expected option value without panicking.
    ///
    /// # Errors
    ///
    /// Returns an error when the option is empty.
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
}

impl<T> TestOptionExt<T> for Option<T> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
        self.ok_or_else(|| "expected a value".into())
    }
}

/// Derive the hex-encoded public key from a hex-encoded (32-byte) secret key.
///
/// Invalid fixture input produces an empty string after a failing assertion.
///
/// # Panics
///
/// Panics when the fixture is not valid hexadecimal or is not exactly 32 bytes.
#[must_use]
pub fn derive_pubkey_hex(secret_hex: &str) -> String {
    let bytes = hex_decode(secret_hex.trim());
    assert!(bytes.is_ok(), "test fixture must contain valid hexadecimal");
    let bytes = bytes.unwrap_or_default();
    let arr = bytes.as_slice().try_into();
    assert!(
        arr.is_ok(),
        "test fixture must contain a 32-byte secret key"
    );
    let arr: [u8; 32] = arr.unwrap_or([0; 32]);
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
/// A missing or malformed fixture produces an empty string after a failing
/// assertion.
///
/// # Panics
///
/// Panics when the fixture directory has no readable prediction file.
#[must_use]
pub fn first_prediction_id(dir: &Path) -> String {
    let id = std::fs::read_dir(dir.join("predictions"))
        .ok()
        .and_then(|mut entries| entries.next())
        .and_then(Result::ok)
        .and_then(|entry| entry.path().file_stem().map(ToOwned::to_owned))
        .and_then(|stem| stem.to_str().map(ToOwned::to_owned));
    assert!(
        id.is_some(),
        "test fixture must contain a readable prediction"
    );
    id.unwrap_or_default()
}
