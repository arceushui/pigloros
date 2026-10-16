//! Lowercase hexadecimal text (ADR-061 revision 8 decision 2): the payload's `hexN` and `hexb`
//! values and the output record's digests. Uppercase digits are not accepted.

/// The digits of the encoder.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The value of one lowercase hexadecimal digit.
const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The byte of one pair of digits.
fn byte(pair: &[u8]) -> Option<u8> {
    let high = nibble(pair[0])?;
    let low = nibble(pair[1])?;
    Some((high << 4) | low)
}

/// The bytes of `text`, or `None` for an odd length or a character outside `0-9a-f`.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits.chunks_exact(2).map(byte).collect()
}

/// The `N` bytes of `text`, or `None` unless `text` is exactly `2 * N` lowercase digits.
#[must_use]
pub fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode(text).and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
}

/// `bytes` as lowercase hexadecimal text.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    text
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
