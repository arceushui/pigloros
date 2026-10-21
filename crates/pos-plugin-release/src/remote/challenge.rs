//! Strict parsing of a registry Bearer challenge and of a token-service
//! response (ADR-061 amendment revision 1). Anything ambiguous is rejected,
//! and nothing about a rejected header or body is echoed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use ureq::http::{header, HeaderMap};

/// The parameters of exactly one Bearer challenge.
pub(super) struct Challenge {
    pub(super) realm: String,
    pub(super) service: Option<String>,
    pub(super) scope: Option<String>,
}

/// The one Bearer challenge in `headers`, or `None` when there is not exactly
/// one `WWW-Authenticate` header, it is not a lone Bearer challenge, a
/// parameter is malformed or duplicated, or it has no `realm`. A Basic
/// challenge, or a Basic challenge next to a Bearer one, is never accepted.
pub(super) fn bearer_challenge(headers: &HeaderMap) -> Option<Challenge> {
    let mut values = headers.get_all(header::WWW_AUTHENTICATE).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok()?,
        _ => return None,
    };
    let (scheme, parameters) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut parameters = parameters_of(parameters.trim_start_matches(' '))?;
    Some(Challenge {
        realm: parameters.remove("realm")?,
        service: parameters.remove("service"),
        scope: parameters.remove("scope"),
    })
}

/// A comma-separated `name=value` list. Names are case-insensitive and must
/// be unique; a value is a token or a quoted string.
fn parameters_of(mut rest: &str) -> Option<BTreeMap<String, String>> {
    let mut parameters = BTreeMap::new();
    loop {
        let (name, after) = rest.split_once('=')?;
        if !is_token(name) {
            return None;
        }
        let (value, after) = after
            .strip_prefix('"')
            .map_or_else(|| unquoted_value(after), quoted_string)?;
        if parameters
            .insert(name.to_ascii_lowercase(), value)
            .is_some()
        {
            return None;
        }
        let after = after.trim_start_matches([' ', '\t']);
        if after.is_empty() {
            return Some(parameters);
        }
        rest = after.strip_prefix(',')?.trim_start_matches([' ', '\t']);
    }
}

/// A token value up to the next comma or blank, and the text after it.
fn unquoted_value(text: &str) -> Option<(String, &str)> {
    let (value, after) = text.split_at(text.find([',', ' ', '\t']).unwrap_or(text.len()));
    is_token(value).then(|| (value.to_owned(), after))
}

/// A non-empty RFC 9110 token.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// The value of a quoted string whose opening quote was consumed, and the
/// text after its closing quote.
fn quoted_string(text: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut characters = text.char_indices();
    while let Some((index, character)) = characters.next() {
        match character {
            '"' => return Some((value, &text[index + 1..])),
            '\\' => value.push(characters.next()?.1),
            other => value.push(other),
        }
    }
    None
}

/// The token of a token-service response body.
///
/// The body must be one JSON object without a duplicate key at any depth. It
/// must carry a string `token`, a string `access_token`, or both with the
/// same value.
pub(super) fn token_of(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if has_duplicate_keys(body) {
        return None;
    }
    let object = value.as_object()?;
    let token = match (object.get("token"), object.get("access_token")) {
        (Some(token), Some(access)) if token != access => return None,
        (Some(token), _) | (None, Some(token)) => token,
        (None, None) => return None,
    };
    token.as_str().map(str::to_owned)
}

/// Whether any JSON object in `json` repeats a key, after unescaping. `json`
/// must already be valid JSON.
fn has_duplicate_keys(json: &[u8]) -> bool {
    // One frame per open container: the keys of an object, or `None` for an
    // array.
    let mut frames: Vec<Option<BTreeSet<String>>> = Vec::new();
    let mut expect_key = false;
    // The bytes of the string literal being read, from its opening quote.
    let mut literal: Option<Vec<u8>> = None;
    let mut escaped = false;
    for &byte in json {
        if let Some(text) = &mut literal {
            text.push(byte);
            let closing = byte == b'"' && !escaped;
            escaped = byte == b'\\' && !escaped;
            if closing {
                let text = std::mem::take(text);
                literal = None;
                if expect_key {
                    expect_key = false;
                    let key = serde_json::from_slice::<String>(&text).unwrap_or_default();
                    if frames
                        .last_mut()
                        .and_then(Option::as_mut)
                        .is_some_and(|keys| !keys.insert(key))
                    {
                        return true;
                    }
                }
            }
            continue;
        }
        match byte {
            b'"' => literal = Some(vec![byte]),
            b'{' => {
                frames.push(Some(BTreeSet::new()));
                expect_key = true;
            }
            b'[' => frames.push(None),
            b'}' | b']' => {
                frames.pop();
            }
            b',' => expect_key = frames.last().is_some_and(Option::is_some),
            _ => {}
        }
    }
    false
}
