//! Shared hex encoding/decoding helpers.

/// Decode a hex string into bytes (lower- **and** upper-case accepted).
///
/// # Errors
/// Returns a descriptive `String` on odd-length input or an invalid hex digit.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_owned());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let byte = (nib(h)? << 4) | nib(l)?;
        out.push(byte);
    }
    Ok(out)
}

/// Convert a single hex character to its nibble value (0–15).
///
/// # Errors
/// Returns `Err` if `c` is not a valid hex digit (`0–9`, `a–f`, `A–F`).
pub fn nib(c: char) -> Result<u8, String> {
    match c {
        '0'..='9' => Ok((c as u8) - b'0'),
        'a'..='f' => Ok((c as u8) - b'a' + 10),
        'A'..='F' => Ok((c as u8) - b'A' + 10),
        _ => Err(format!("bad hex digit {c:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_lowercase() {
        let bytes = [0x00, 0xab, 0xff];
        let hex = "00abff";
        assert_eq!(hex_decode(hex).unwrap(), bytes);
    }

    #[test]
    fn round_trip_uppercase() {
        assert_eq!(hex_decode("00ABFF").unwrap(), [0x00, 0xab, 0xff]);
    }

    #[test]
    fn round_trip_mixed_case() {
        assert_eq!(hex_decode("aAbB").unwrap(), [0xaa, 0xbb]);
    }

    #[test]
    fn odd_length_rejected() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn bad_digit_rejected() {
        assert!(nib('g').is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn nib_covers_all_ranges() {
        assert_eq!(nib('0').unwrap(), 0);
        assert_eq!(nib('9').unwrap(), 9);
        assert_eq!(nib('a').unwrap(), 10);
        assert_eq!(nib('f').unwrap(), 15);
        assert_eq!(nib('A').unwrap(), 10);
        assert_eq!(nib('F').unwrap(), 15);
    }
}
