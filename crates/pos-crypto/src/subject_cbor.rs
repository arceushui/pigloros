//! Deterministic CBOR writer and AES-256-GCM/HKDF primitives shared by the
//! ADR-091/ADR-097 subject key wrap and subject ciphertext codecs.

use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use pos_core::KeyRoleV1;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The record version of both `SubjectKeyWrapV1` and `SubjectCiphertextV1`.
pub(crate) const VERSION: u64 = 1;
/// The role code both records carry: `KeyRoleV1::SubjectDataEncryption`.
pub(crate) const ROLE: u8 = KeyRoleV1::SubjectDataEncryption.code();

/// Append a shortest-form CBOR head for `major` with argument `value`.
pub(crate) fn head(output: &mut Vec<u8>, major: u8, value: u64) {
    // The major type occupies the top three bits and the additional
    // information the low five, so adding them composes the initial byte.
    let bytes = value.to_be_bytes();
    let tag = major << 5;
    match value {
        0..=23 => output.push(tag + bytes[7]),
        24..=0xff => output.extend_from_slice(&[tag + 24, bytes[7]]),
        0x100..=0xffff => {
            output.push(tag + 25);
            output.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            output.push(tag + 26);
            output.extend_from_slice(&bytes[4..]);
        }
        _ => {
            output.push(tag + 27);
            output.extend_from_slice(&bytes);
        }
    }
}

/// Append an unsigned integer.
pub(crate) fn unsigned(output: &mut Vec<u8>, value: u64) {
    head(output, 0, value);
}

/// Append a definite byte string.
pub(crate) fn byte_string(output: &mut Vec<u8>, bytes: &[u8]) {
    head(output, 2, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

/// Append definite UTF-8 text.
pub(crate) fn text(output: &mut Vec<u8>, value: &str) {
    head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

/// `HKDF-SHA-256(IKM = ikm, salt, info = label || context, L = 32)`, or
/// `None` when HKDF refuses the output length.
///
/// HKDF-Expand refuses only an output above 255 hash lengths, so `L = 32`
/// always succeeds; the refusal still fails closed rather than yielding a
/// zero key. The output is wiped on drop. The pseudorandom key and HMAC
/// state inside `hkdf 0.13.0` are not wiped: that release has no `zeroize`
/// support, and this crate does not clear them.
pub(crate) fn hkdf_sha256(
    ikm: &[u8; 32],
    salt: &[u8; 32],
    label: &[u8],
    context: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand_multi_info(&[label, context], okm.as_mut_slice())
        .ok()
        .map(|()| okm)
}

/// Encrypt `buffer` in place under AES-256-GCM and return the full tag, or
/// `None` when AES-GCM refuses the input lengths.
///
/// AES-GCM refuses only a plaintext above 2^36 - 32 bytes or associated data
/// above 2^61 - 1 bytes. Every caller bounds both to 256 KiB first; the
/// refusal still fails closed rather than yielding a zero tag.
pub(crate) fn aes_gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
) -> Option<[u8; 16]> {
    Aes256Gcm::new(key.into())
        .encrypt_inout_detached(nonce.into(), associated_data, buffer.into())
        .ok()
        .map(Into::into)
}

/// Authenticate and decrypt `buffer` in place; `false` releases nothing.
pub(crate) fn aes_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    Aes256Gcm::new(key.into())
        .decrypt_inout_detached(nonce.into(), associated_data, buffer.into(), tag.into())
        .is_ok()
}
