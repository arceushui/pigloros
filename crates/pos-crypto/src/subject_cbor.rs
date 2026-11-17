//! Deterministic CBOR writer and AES-256-GCM/HKDF primitives shared by the
//! ADR-091/ADR-097 subject key wrap and subject ciphertext codecs, and the
//! shortest-float writer of the ADR-097 B4 preference weights plaintext.

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

/// The 52 fraction bits of an IEEE 754 binary64 value.
const DOUBLE_FRACTION: u64 = (1 << 52) - 1;

/// The bits of the binary64 value `double` in the narrower IEEE 754 format with
/// `exponent_bits` and `fraction_bits`, or `None` when that format cannot hold
/// the value bit for bit.
///
/// A normal binary64 value narrows to a normal value when its exponent fits
/// and its dropped fraction bits are zero, or to a subnormal value when the
/// shifted-out significand bits are zero. Zero keeps its sign. Infinities,
/// NaNs and binary64 subnormals never narrow.
fn narrowed(double: u64, exponent_bits: u64, fraction_bits: u64) -> Option<u64> {
    let bias = (1 << (exponent_bits - 1)) - 1;
    let exponent = (double >> 52) & 0x7ff;
    let significand = (double & DOUBLE_FRACTION) | (u64::from(exponent != 0) << 52);
    let normal = exponent + bias > 1023;
    let (target, shift) = if normal {
        (exponent + bias - 1023, 52 - fraction_bits)
    } else {
        // `exponent <= 1023 - bias` here, so the shift is at least 53 - fraction_bits.
        (0, 1076 - fraction_bits - bias - exponent)
    };
    let exact = u64::from(significand.trailing_zeros()) >= shift.min(64);
    (exact && target < (1 << exponent_bits) - 1).then(|| {
        let kept = significand
            .checked_shr(u32::try_from(shift).unwrap_or(u32::MAX))
            .unwrap_or(0);
        ((double >> 63) << (exponent_bits + fraction_bits))
            | (target << fraction_bits)
            | (kept & ((1 << fraction_bits) - 1))
    })
}

/// The initial byte, argument width and argument of the shortest of half,
/// single or double precision that holds `value` bit for bit.
pub(crate) fn shortest_float(value: f64) -> (u8, usize, u64) {
    let bits = value.to_bits();
    narrowed(bits, 5, 10)
        .map(|half| (0xf9, 2, half))
        .or_else(|| narrowed(bits, 8, 23).map(|single| (0xfa, 4, single)))
        .unwrap_or((0xfb, 8, bits))
}

/// Append `value` as the shortest float that holds it bit for bit.
pub(crate) fn float(output: &mut Vec<u8>, value: f64) {
    let (initial, width, argument) = shortest_float(value);
    output.push(initial);
    output.extend_from_slice(&argument.to_be_bytes()[8 - width..]);
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
