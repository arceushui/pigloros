//! ADR-087 Part C.3 (#440, owner decision Q7.8): the kernel command line
//! must veto systemd's userspace Verity fallback before mountfsd is called.
//!
//! systemd v260.2 reads `systemd.allow_userspace_verity=` with
//! `PROC_CMDLINE_TRUE_WHEN_MISSING`, so a missing option allows userspace
//! validation. To match systemd's parsing without ambiguity, the accepted
//! rule is closed:
//! - the command line is ASCII, with no control character other than space,
//!   tab, newline or carriage return, and no quote or backslash, because
//!   systemd unquotes words;
//! - it is split on exactly those four separators;
//! - exactly one word has the key `systemd.allow_userspace_verity` or
//!   `rd.systemd.allow_userspace_verity`, where the key is the text before
//!   the word's first `=` (or the whole word) and `-` equals `_`;
//! - that word is exactly `systemd.allow_userspace_verity=0`.

/// The only accepted word.
const VETO: &[u8] = b"systemd.allow_userspace_verity=0";
/// Every key systemd may read for this option.
const KEYS: [&[u8]; 2] = [
    b"systemd.allow_userspace_verity",
    b"rd.systemd.allow_userspace_verity",
];

/// Whether `cmdline` vetoes systemd's userspace Verity fallback.
pub(super) fn vetoes_userspace_verity(cmdline: &[u8]) -> bool {
    let mut options = cmdline
        .split(|byte| is_separator(*byte))
        .filter(|word| KEYS.iter().any(|key| same_key(key_of(word), key)));
    cmdline.iter().all(|byte| is_plain(*byte))
        && matches!((options.next(), options.next()), (Some(word), None) if word == VETO)
}

const fn is_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Printable ASCII other than a quote or backslash, or a separator.
const fn is_plain(byte: u8) -> bool {
    is_separator(byte) || (byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\'))
}

/// The text before the word's first `=`, or the whole word.
fn key_of(word: &[u8]) -> &[u8] {
    word.iter()
        .position(|byte| *byte == b'=')
        .map_or(word, |end| &word[..end])
}

/// systemd compares option keys with `-` and `_` treated as equal.
fn same_key(observed: &[u8], key: &[u8]) -> bool {
    observed.len() == key.len()
        && observed
            .iter()
            .zip(key)
            .all(|(left, right)| dash_as_underscore(*left) == dash_as_underscore(*right))
}

const fn dash_as_underscore(byte: u8) -> u8 {
    if byte == b'-' {
        b'_'
    } else {
        byte
    }
}
