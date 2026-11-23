//! The `WebAuthn` client side of the native path (ADR-110 E20 LS4, LP2, LP4).
//!
//! It builds `clientDataJSON` exactly as a browser would for the owner origin, derives the
//! `WebAuthn` PRF salt, rewrites the attestation to `none`, and reads the two authenticator-data
//! facts the client needs: the new credential with its `hmac-secret` flag, and the encrypted
//! `hmac-secret` output of an assertion. Everything else is left to the shared verifier.

use sha2::{Digest, Sha256};

use crate::cbor::{decode, decode_prefix, Value, Writer};

/// The owner origin every `clientDataJSON` names (ADR-097 §5).
pub const ORIGIN: &str = "http://localhost:49291";

/// The exact length of an encrypted protocol 2 `hmac-secret` output for one salt.
pub const HMAC_SECRET_OUTPUT_BYTES: usize = 48;

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const AUTH_DATA_PREFIX: usize = 37;
const FLAG_ATTESTED: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;
const CREDENTIAL_LENGTH_AT: usize = AUTH_DATA_PREFIX + 16;

/// Encode `bytes` as unpadded base64url.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = [0; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let word = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for position in 0..=chunk.len() {
            let index = (word >> (18 - 6 * position)) & 63;
            let index = usize::try_from(index).unwrap_or(0);
            encoded.push(char::from(BASE64URL[index]));
        }
    }
    encoded
}

/// The `clientDataJSON` of a `webauthn.create` or `webauthn.get` ceremony over `challenge`.
#[must_use]
pub fn client_data_json(kind: &str, challenge: &[u8; 32]) -> Vec<u8> {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}",
        base64url(challenge)
    )
    .into_bytes()
}

/// `salt1 = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ prf_input)` (ADR-110 E20 LP2, LP4).
#[must_use]
pub fn prf_salt(prf_input: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"WebAuthn PRF")
        .chain_update([0_u8])
        .chain_update(prf_input)
        .finalize()
        .into()
}

/// The attestation object `{"fmt": "none", "attStmt": {}, "authData": auth_data}`.
#[must_use]
pub fn none_attestation(auth_data: &[u8]) -> Vec<u8> {
    Writer::default()
        .map(3)
        .text("fmt")
        .text("none")
        .text("attStmt")
        .map(0)
        .text("authData")
        .bytes(auth_data)
        .finish()
}

/// What `makeCredential` authenticator data says about the new credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Created<'a> {
    /// The attested credential ID.
    pub credential_id: &'a [u8],
    /// Whether the extension map has `"hmac-secret": true`.
    pub hmac_secret: bool,
}

fn extensions(auth_data: &[u8], flags: u8, offset: usize) -> Option<Value<'_>> {
    let rest = auth_data.get(offset..)?;
    if flags & FLAG_EXTENSIONS == 0 {
        return rest.is_empty().then_some(Value::Map(Vec::new()));
    }
    decode(rest).filter(|map| matches!(map, Value::Map(_)))
}

/// Read the credential ID and the `hmac-secret` flag of `makeCredential` authenticator data.
#[must_use]
pub fn created(auth_data: &[u8]) -> Option<Created<'_>> {
    let flags = *auth_data
        .get(32)
        .filter(|flags| *flags & FLAG_ATTESTED != 0)?;
    let length = auth_data.get(CREDENTIAL_LENGTH_AT..CREDENTIAL_LENGTH_AT + 2)?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let start = CREDENTIAL_LENGTH_AT + 2;
    let credential_id = auth_data.get(start..start + length)?;
    let (_, key_length) = decode_prefix(auth_data.get(start + length..).unwrap_or_default())?;
    let map = extensions(auth_data, flags, start + length + key_length)?;
    Some(Created {
        credential_id,
        hmac_secret: map.text_key("hmac-secret") == Some(&Value::Bool(true)),
    })
}

/// The encrypted `hmac-secret` output of `getAssertion` authenticator data: exactly 48 bytes.
#[must_use]
pub fn hmac_secret_output(auth_data: &[u8]) -> Option<&[u8]> {
    let flags = *auth_data
        .get(32)
        .filter(|flags| *flags & FLAG_ATTESTED == 0)?;
    extensions(auth_data, flags, AUTH_DATA_PREFIX)?
        .text_key("hmac-secret")
        .and_then(Value::bytes)
        .filter(|output| output.len() == HMAC_SECRET_OUTPUT_BYTES)
}

#[cfg(test)]
mod tests;
