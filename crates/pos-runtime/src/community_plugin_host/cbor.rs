//! A small canonical CBOR encoder for host-owned records (ADR-061 revision 7).
//!
//! It emits the only items the host's digests and payloads use: unsigned
//! integers, byte strings, text, booleans and array heads. Every head is in
//! its shortest form and every length is definite; there are no maps, floats,
//! tags or negative integers, so the output is canonical by construction.
//!
//! It follows the hand-written `encode_head` precedent of `pos-core` rather
//! than `pos_crypto::canonical::encode`, which goes through `serde_json::Value`
//! and cannot emit byte strings, and it adds no dependency. Every function
//! appends to the caller's buffer.

/// Major type 0: unsigned integer.
const UNSIGNED: u8 = 0;
/// Major type 2: byte string.
const BYTES: u8 = 2;
/// Major type 3: text string.
const TEXT: u8 = 3;
/// Major type 4: array.
const ARRAY: u8 = 4;
/// The simple value `true`.
const TRUE: u8 = 0xf5;
/// The simple value `false`.
const FALSE: u8 = 0xf4;

/// Append the head of `major` for `value` in its shortest form.
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    let (code, width) = match value {
        0..=23 => {
            out.push(tag | bytes[7]);
            return;
        }
        24..=0xff => (0x18, 1),
        0x100..=0xffff => (0x19, 2),
        0x1_0000..=0xffff_ffff => (0x1a, 4),
        _ => (0x1b, 8),
    };
    out.push(tag | code);
    out.extend_from_slice(&bytes[8 - width..]);
}

/// A length as a head argument; a `usize` always fits in a `u64` here.
#[must_use]
pub fn length(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Append an unsigned integer.
pub fn unsigned(out: &mut Vec<u8>, value: u64) {
    head(out, UNSIGNED, value);
}

/// Append a boolean, a single byte with no width.
pub fn boolean(out: &mut Vec<u8>, value: bool) {
    out.push(if value { TRUE } else { FALSE });
}

/// Append a text string.
pub fn text(out: &mut Vec<u8>, value: &str) {
    head(out, TEXT, length(value.len()));
    out.extend_from_slice(value.as_bytes());
}

/// Append a byte string.
pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, BYTES, length(value.len()));
    out.extend_from_slice(value);
}

/// Append the head of an array of `count` items; the caller appends the items.
pub fn array(out: &mut Vec<u8>, count: usize) {
    head(out, ARRAY, length(count));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
