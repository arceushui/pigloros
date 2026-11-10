//! Shared ADR-061 identifier grammar for complete invocation inputs.

/// Exact ADR-061/PMF1 ID grammar; no authority is derived from an ID.
#[must_use]
pub fn is_valid_community_id_v1(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 128
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}
