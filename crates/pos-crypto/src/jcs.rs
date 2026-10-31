//! RFC 8785 canonical JSON (JCS): a writer and a canonical-only reader.
//!
//! It writes the Plugin conformance oracle record (ADR-061 revision 8 decision 2) and the
//! ADR-062 Revision 8 report attestation (#1236).
//!
//! Object members are sorted by the UTF-16 code units of their keys, strings escape `"`, `\`
//! and control characters (`\b`, `\t`, `\n`, `\f`, `\r`, otherwise lowercase `\u00xx`), numbers
//! are non-negative integers no greater than 2^53 (RFC 8785 writes numbers as IEEE-754
//! doubles, which represent every such integer exactly and in plain decimal form), the literals
//! are `true`, `false` and `null`, and there is no whitespace. The oracle record ends with one
//! LF byte, as `jq -c` writes it.
//!
//! [`JsonV1::parse_canonical`] accepts a document only when writing the parsed value again
//! yields exactly the input bytes; whitespace, escaped aliases, duplicate or unsorted keys,
//! fractions, exponents, negative numbers and integers above 2^53 are therefore refused. `serde_json` reads the
//! input and bounds its nesting; callers bound the byte length before calling it.

/// A JSON integer in the exactly representable range `0..=2^53`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct JsonIntegerV1(u64);

/// The refusal of an integer above 2^53, which an IEEE-754 double cannot hold exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("JSON integer is above 2^53")]
pub struct JsonIntegerRangeErrorV1;

impl JsonIntegerV1 {
    /// The largest integer RFC 8785 writes exactly: 2^53.
    pub const MAX: u64 = 9_007_199_254_740_992;

    /// The integer `value`.
    ///
    /// # Errors
    /// Returns [`JsonIntegerRangeErrorV1`] when `value` is above [`Self::MAX`].
    pub const fn new(value: u64) -> Result<Self, JsonIntegerRangeErrorV1> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(JsonIntegerRangeErrorV1)
        }
    }

    /// The integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One JSON value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonV1 {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A non-negative integer no greater than 2^53.
    Number(JsonIntegerV1),
    /// A string.
    Text(String),
    /// An array.
    Array(Vec<Self>),
    /// An object; the writer sorts the keys.
    Object(Vec<(String, Self)>),
}

impl JsonV1 {
    /// A string value.
    #[must_use]
    pub fn text(value: &str) -> Self {
        Self::Text(value.to_owned())
    }

    /// An object over `entries`.
    #[must_use]
    pub fn object<const N: usize>(entries: [(&str, Self); N]) -> Self {
        Self::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// The canonical bytes of the value.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// The canonical bytes of the value followed by one LF byte: the oracle record.
    #[must_use]
    pub fn line(&self) -> Vec<u8> {
        let mut out = self.canonical();
        out.push(b'\n');
        out
    }

    /// Read `bytes` as one canonical JSON document.
    ///
    /// Returns `None` unless `bytes` is valid JSON whose canonical encoding is exactly `bytes`.
    /// The caller bounds the length of `bytes` before calling this reader.
    #[must_use]
    pub fn parse_canonical(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes)
            .ok()
            .and_then(Self::from_json_value)
            .filter(|value| value.canonical() == bytes)
    }

    /// Convert a parsed `serde_json` value; `None` for a number that is not an integer in
    /// `0..=2^53`.
    #[must_use]
    pub fn from_json_value(value: serde_json::Value) -> Option<Self> {
        match value {
            serde_json::Value::Null => Some(Self::Null),
            serde_json::Value::Bool(value) => Some(Self::Bool(value)),
            serde_json::Value::Number(value) => value
                .as_u64()
                .and_then(|integer| JsonIntegerV1::new(integer).ok())
                .map(Self::Number),
            serde_json::Value::String(value) => Some(Self::Text(value)),
            serde_json::Value::Array(items) => items
                .into_iter()
                .map(Self::from_json_value)
                .collect::<Option<Vec<_>>>()
                .map(Self::Array),
            serde_json::Value::Object(members) => members
                .into_iter()
                .map(|(key, value)| Self::from_json_value(value).map(|value| (key, value)))
                .collect::<Option<Vec<_>>>()
                .map(Self::Object),
        }
    }

    /// The values of an object that has exactly the members `keys`, in the order of `keys`.
    ///
    /// Returns `None` for a value that is not an object, or for an object with a missing,
    /// extra or repeated member.
    #[must_use]
    pub fn into_members<const N: usize>(self, keys: [&str; N]) -> Option<[Self; N]> {
        match self {
            Self::Object(mut entries) if entries.len() == N => keys
                .iter()
                .map(|key| {
                    entries
                        .iter()
                        .position(|(name, _)| name == key)
                        .map(|index| entries.swap_remove(index).1)
                })
                .collect::<Option<Vec<_>>>()
                .and_then(|values| values.try_into().ok()),
            Self::Null
            | Self::Bool(_)
            | Self::Number(_)
            | Self::Text(_)
            | Self::Array(_)
            | Self::Object(_) => None,
        }
    }

    /// The items of an array.
    #[must_use]
    pub fn into_array(self) -> Option<Vec<Self>> {
        match self {
            Self::Array(items) => Some(items),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::Text(_) | Self::Object(_) => None,
        }
    }

    /// The text of a string.
    #[must_use]
    pub fn into_text(self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    /// The value of a boolean.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            Self::Null | Self::Number(_) | Self::Text(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            literal @ (Self::Null | Self::Bool(_)) => {
                out.extend_from_slice(literal_bytes(literal.as_bool()));
            }
            Self::Number(value) => write_number(*value, out),
            Self::Text(value) => write_text(value, out),
            Self::Array(items) => write_list(items.iter(), out),
            Self::Object(entries) => write_object(entries, out),
        }
    }
}

/// The literal of a boolean, or `null` for `None`.
const fn literal_bytes(value: Option<bool>) -> &'static [u8] {
    match value {
        Some(true) => b"true",
        Some(false) => b"false",
        None => b"null",
    }
}

/// An integer in plain decimal form, as RFC 8785 writes an integral double up to 2^53.
fn write_number(value: JsonIntegerV1, out: &mut Vec<u8>) {
    out.extend_from_slice(value.get().to_string().as_bytes());
}

/// The items of an array, separated by commas.
fn write_list<'a>(items: impl Iterator<Item = &'a JsonV1>, out: &mut Vec<u8>) {
    out.push(b'[');
    for (index, item) in items.enumerate() {
        if index > 0 {
            out.push(b',');
        }
        item.write(out);
    }
    out.push(b']');
}

/// The members of an object in the UTF-16 code-unit order of their keys (RFC 8785 section
/// 3.2.3).
fn write_object(entries: &[(String, JsonV1)], out: &mut Vec<u8>) {
    let mut sorted: Vec<&(String, JsonV1)> = entries.iter().collect();
    sorted.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
    out.push(b'{');
    for (index, (key, value)) in sorted.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_text(key, out);
        out.push(b':');
        value.write(out);
    }
    out.push(b'}');
}

/// A string with its escapes.
fn write_text(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            control if control < ' ' => {
                out.extend_from_slice(format!("\\u{:04x}", u32::from(control)).as_bytes());
            }
            plain => {
                let mut buffer = [0; 4];
                out.extend_from_slice(plain.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
