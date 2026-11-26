//! Readers for the hex test-vector files under `tests/vectors`.

/// Decode lowercase hex; an odd trailing digit is ignored.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .unwrap_or_default()
        })
        .collect()
}

/// The bytes on the line `name <hex>` of a vector file.
pub(crate) fn vector(file: &str, name: &str) -> Vec<u8> {
    file.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .map(hex)
        .unwrap_or_default()
}

/// The first 32 bytes of `bytes`, or zeros when there are fewer.
pub(crate) fn array32(bytes: &[u8]) -> [u8; 32] {
    bytes.first_chunk().copied().unwrap_or_default()
}
