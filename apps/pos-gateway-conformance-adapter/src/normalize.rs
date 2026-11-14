//! The response normalization of the requirements text (section 4).
//!
//! The contract fixes neither Timeline and Event IDs, nor cursors, nor problem detail text, so
//! they are permitted nondeterministic operational fields: an `id` member that is a ULID, a
//! `next_cursor` member that is a well-formed cursor and every problem `detail` text member are
//! replaced by placeholders, and every ULID segment of a problem `instance` path becomes
//! `<ulid>`. Every other value stays as it is, so a malformed ID or cursor cannot match.

use serde_json::{json, Value};

/// The Crockford base-32 alphabet of a ULID.
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The observation of one sent exchange: `{"status", "body"}`, whose body is `{"json": <the
/// normalized value>}` when the response bytes parsed as one JSON value, else `"non-json"`.
#[must_use]
pub fn observation_v1(status: u16, parsed: Option<Value>) -> Value {
    let body = parsed.map_or_else(
        || Value::from("non-json"),
        |value| json!({"json": normalize_response_v1(value)}),
    );
    json!({"status": status, "body": body})
}

/// Normalize one parsed JSON response value.
#[must_use]
pub fn normalize_response_v1(value: Value) -> Value {
    normalize(value, None)
}

fn normalize(value: Value, key: Option<&str>) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(name, member)| {
                    let normalized = normalize(member, Some(&name));
                    (name, normalized)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalize(item, None))
                .collect(),
        ),
        Value::String(text) => Value::String(normalize_text(key, text)),
        other => other,
    }
}

fn normalize_text(key: Option<&str>, text: String) -> String {
    match key {
        Some("id" | "instance") => normalize_ulid_segments(&text),
        Some("next_cursor") if is_cursor(&text) => "<cursor>".to_owned(),
        Some("detail") => "<message>".to_owned(),
        _ => text,
    }
}

/// Every `/`-separated segment of an `id` or a problem `instance` that is a ULID becomes
/// `<ulid>`; an `id` that is one ULID becomes `<ulid>`, any other value keeps its other bytes.
fn normalize_ulid_segments(path: &str) -> String {
    path.split('/')
        .map(|segment| if is_ulid(segment) { "<ulid>" } else { segment })
        .collect::<Vec<_>>()
        .join("/")
}

/// A canonical (upper-case) ULID: 26 Crockford characters, the first at most `7`.
fn is_ulid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 26 && bytes[0] <= b'7' && bytes.iter().all(|byte| CROCKFORD.contains(byte))
}

/// `v1.<64 lowercase hex>.<ULID>.<positive integer without a leading zero>`.
fn is_cursor(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    match parts.as_slice() {
        ["v1", generation, timeline, position] => {
            is_generation(generation) && is_ulid(timeline) && is_position(position)
        }
        _ => false,
    }
}

fn is_generation(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_position(text: &str) -> bool {
    !text.is_empty() && !text.starts_with('0') && text.bytes().all(|byte| byte.is_ascii_digit())
}
