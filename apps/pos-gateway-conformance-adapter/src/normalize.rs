//! The response normalization of the requirements text (section 4).
//!
//! A text value equal to a value the sub-case captured becomes its slot literal (`{consent}`,
//! `{room}`), so an echo of a captured consent or room is pinned. The contract fixes neither
//! Timeline and Event IDs, nor cursors, nor problem detail text, nor a room's correlation ID and
//! the hashes that cover it, so they are permitted nondeterministic operational fields: a ULID
//! `id`, `consent_ref`, `timeline_id` or `event_id` member, a `next_cursor` member that is a
//! well-formed cursor, a `correlation_id` or `descriptor_hash` of lowercase hex digits that are
//! not all zero, such a provenance digest of a Scenario Room revision, and every problem
//! `detail` text member are replaced by placeholders, and every ULID segment of a problem
//! `instance` path becomes `<ulid>`. Every other value stays as it is, so a malformed ID,
//! cursor or hash, or an echo of another consent or room, cannot match.

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

/// The `schema_id` of a Scenario Room revision, whose provenance digest covers its run-local
/// descriptor hash and Event ID.
const ROOM_REVISION_SCHEMA: &str = "urn:pigloros:gateway:v1:schema:scenario-room-revision";

/// Normalize one parsed JSON response value.
#[must_use]
pub fn normalize_response_v1(value: Value) -> Value {
    normalize(value, None)
}

/// Replace every text value of `value` equal to a captured value by its slot literal:
/// `captured` holds `(slot, captured value)` pairs, such as `("{room}", <the room ID>)`.
#[must_use]
pub fn substitute_captured_v1(value: Value, captured: &[(&str, &str)]) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(name, member)| (name, substitute_captured_v1(member, captured)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| substitute_captured_v1(item, captured))
                .collect(),
        ),
        Value::String(text) => Value::String(
            captured
                .iter()
                .find(|(_, value)| *value == text)
                .map_or(text, |(slot, _)| (*slot).to_owned()),
        ),
        other => other,
    }
}

fn normalize(value: Value, key: Option<&str>) -> Value {
    match value {
        Value::Object(members) => {
            let revision =
                members.get("schema_id").and_then(Value::as_str) == Some(ROOM_REVISION_SCHEMA);
            Value::Object(
                members
                    .into_iter()
                    .map(|(name, member)| {
                        let mut normalized = normalize(member, Some(&name));
                        if revision && name == "provenance" {
                            mask_digest(&mut normalized);
                        }
                        (name, normalized)
                    })
                    .collect(),
            )
        }
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

/// The `(member, whether a value of it is masked, placeholder)` rows of the operational text
/// members that a placeholder replaces whole.
const TEXT_MASKS: [(&str, fn(&str) -> bool, &str); 4] = [
    ("next_cursor", is_cursor, "<cursor>"),
    ("correlation_id", is_correlation, "<correlation>"),
    ("descriptor_hash", is_hash, "<hash>"),
    ("detail", is_text, "<message>"),
];

fn normalize_text(key: Option<&str>, text: String) -> String {
    match key {
        Some("id" | "instance" | "consent_ref" | "timeline_id" | "event_id") => {
            normalize_ulid_segments(&text)
        }
        _ => TEXT_MASKS
            .iter()
            .find(|(member, masked, _)| key == Some(*member) && masked(&text))
            .map_or(text, |(_, _, placeholder)| (*placeholder).to_owned()),
    }
}

/// Every problem `detail` text is masked.
const fn is_text(_: &str) -> bool {
    true
}

/// A correlation ID: 32 lowercase hex digits that are not all zero.
fn is_correlation(text: &str) -> bool {
    is_nonzero_hex(text, 32)
}

/// A hash: 64 lowercase hex digits that are not all zero.
fn is_hash(text: &str) -> bool {
    is_nonzero_hex(text, 64)
}

/// Every `/`-separated segment of a ULID member or a problem `instance` that is a ULID becomes
/// `<ulid>`; a member that is one ULID becomes `<ulid>`, any other value keeps its other bytes.
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
            is_hex(generation, 64) && is_ulid(timeline) && is_position(position)
        }
        _ => false,
    }
}

/// The `digest` of a room revision's provenance becomes `<hash>` when it is a hash.
fn mask_digest(provenance: &mut Value) {
    if let Some(digest) = provenance
        .get_mut("digest")
        .filter(|digest| digest.as_str().is_some_and(is_hash))
    {
        *digest = Value::from("<hash>");
    }
}

/// `length` lowercase hex digits that are not all zero, as the contract's hash and
/// correlation ID patterns require.
fn is_nonzero_hex(text: &str, length: usize) -> bool {
    is_hex(text, length) && text.bytes().any(|byte| byte != b'0')
}

/// `length` lowercase hex digits.
fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_position(text: &str) -> bool {
    !text.is_empty() && !text.starts_with('0') && text.bytes().all(|byte| byte.is_ascii_digit())
}
