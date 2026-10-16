//! The canonical JSON writer of the oracle record (ADR-061 revision 8 decision 2).
//!
//! Keys are sorted bytewise, strings escape `"`, `\` and control characters, numbers are
//! non-negative integers, booleans are `true` and `false`, and there is no whitespace. The
//! record ends with one LF byte, as `jq -c` writes it. `serde_json` is used to read the payload
//! only.

/// One JSON value of the output record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonV1 {
    /// `true` or `false`.
    Bool(bool),
    /// A non-negative integer.
    Number(u64),
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

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Bool(value) => out.extend_from_slice(literal(*value).as_bytes()),
            Self::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
            Self::Text(value) => write_text(value, out),
            Self::Array(items) => write_list(items.iter(), out),
            Self::Object(entries) => write_object(entries, out),
        }
    }
}

/// The JSON literal of a boolean.
const fn literal(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
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

/// The members of an object in bytewise key order.
fn write_object(entries: &[(String, JsonV1)], out: &mut Vec<u8>) {
    let mut sorted: Vec<&(String, JsonV1)> = entries.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
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
