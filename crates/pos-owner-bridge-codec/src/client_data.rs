use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::{CeremonyKind, VerificationReason, WebAuthnChallenge};

const MAX_CLIENT_DATA_BYTES: usize = 4_096;
const OWNER_ORIGIN: &str = "http://localhost:49291";
const CREATE_TYPE: &str = "webauthn.create";
const GET_TYPE: &str = "webauthn.get";
const CLIENT_DATA_TYPE_FIELD: u8 = 1;
const CLIENT_DATA_CHALLENGE_FIELD: u8 = 2;
const CLIENT_DATA_ORIGIN_FIELD: u8 = 4;

/// Validate closed `WebAuthn` `clientDataJSON` for one ceremony and challenge.
///
/// The parser accepts a single flat JSON object whose member values are only
/// strings or booleans. It validates UTF-8 and every JSON escape while it
/// parses, compares duplicate keys after unescaping, and does not allocate.
///
/// # Errors
///
/// Returns [`VerificationReason::Malformed`] for malformed JSON, duplicate
/// keys, an unsupported value shape, or an empty or oversized input. Returns
/// [`VerificationReason::ClientDataType`], [`VerificationReason::Challenge`],
/// or [`VerificationReason::Origin`] when that member is wrong or absent, and
/// [`VerificationReason::CrossOrigin`] when `crossOrigin` is not `false` or
/// `topOrigin` or `tokenBinding` is present.
pub fn validate_client_data_json(
    input: &[u8],
    kind: CeremonyKind,
    challenge: &WebAuthnChallenge,
) -> Result<(), VerificationReason> {
    if input.is_empty() || input.len() > MAX_CLIENT_DATA_BYTES {
        return Err(VerificationReason::Malformed);
    }

    let mut parser = JsonParser::new(input)?;
    parser.skip_whitespace();
    parser.expect_byte(b'{')?;
    let members_start = parser.offset;

    let mut seen_fields = 0;
    let expected_type = match kind {
        CeremonyKind::Create => CREATE_TYPE,
        CeremonyKind::Get => GET_TYPE,
    };
    let expected_challenge = base64url_challenge(challenge.as_bytes());

    parser.skip_whitespace();
    if parser.peek_byte() == Some(b'}') {
        return Err(VerificationReason::Malformed);
    }

    loop {
        let key_start = parser.offset;
        let key = parser.parse_string()?;
        if duplicate_key_before(parser.input, members_start, key_start, key) {
            return Err(VerificationReason::Malformed);
        }
        parser.skip_whitespace();
        parser.expect_byte(b':')?;
        parser.skip_whitespace();
        let value = parser.parse_value()?;

        validate_client_data_member(
            key,
            value,
            expected_type,
            &expected_challenge,
            &mut seen_fields,
        )?;

        parser.skip_whitespace();
        match parser.take_byte() {
            Some(b',') => {
                parser.skip_whitespace();
                if parser.peek_byte() == Some(b'}') {
                    return Err(VerificationReason::Malformed);
                }
            }
            Some(b'}') => break,
            _ => return Err(VerificationReason::Malformed),
        }
    }

    parser.skip_whitespace();
    if parser.offset != input.len() {
        return Err(VerificationReason::Malformed);
    }
    require_client_data_fields(seen_fields)
}

const fn require_client_data_fields(seen_fields: u8) -> Result<(), VerificationReason> {
    if seen_fields & CLIENT_DATA_TYPE_FIELD == 0 {
        Err(VerificationReason::ClientDataType)
    } else if seen_fields & CLIENT_DATA_CHALLENGE_FIELD == 0 {
        Err(VerificationReason::Challenge)
    } else if seen_fields & CLIENT_DATA_ORIGIN_FIELD == 0 {
        Err(VerificationReason::Origin)
    } else {
        Ok(())
    }
}

fn validate_client_data_member(
    key: JsonString<'_>,
    value: JsonValue<'_>,
    expected_type: &str,
    expected_challenge: &[u8; 43],
    seen_fields: &mut u8,
) -> Result<(), VerificationReason> {
    if key.equals_text("type") {
        validate_text_client_data_member(value, expected_type, VerificationReason::ClientDataType)?;
        *seen_fields |= CLIENT_DATA_TYPE_FIELD;
    } else if key.equals_text("challenge") {
        validate_challenge_client_data_member(value, expected_challenge)?;
        *seen_fields |= CLIENT_DATA_CHALLENGE_FIELD;
    } else if key.equals_text("origin") {
        validate_text_client_data_member(value, OWNER_ORIGIN, VerificationReason::Origin)?;
        *seen_fields |= CLIENT_DATA_ORIGIN_FIELD;
    } else if key.equals_text("crossOrigin") {
        validate_cross_origin_client_data_member(value)?;
    } else if key.equals_text("topOrigin") || key.equals_text("tokenBinding") {
        return Err(VerificationReason::CrossOrigin);
    }
    Ok(())
}

fn validate_text_client_data_member(
    value: JsonValue<'_>,
    expected: &str,
    fault: VerificationReason,
) -> Result<(), VerificationReason> {
    match value {
        JsonValue::String(text) => text.equals_text(expected).then_some(()).ok_or(fault),
        JsonValue::Boolean(_) => Err(fault),
    }
}

fn validate_challenge_client_data_member(
    value: JsonValue<'_>,
    expected_challenge: &[u8; 43],
) -> Result<(), VerificationReason> {
    match value {
        JsonValue::String(text) if challenge_matches(text, expected_challenge) => Ok(()),
        _ => Err(VerificationReason::Challenge),
    }
}

fn challenge_matches(text: JsonString<'_>, expected_challenge: &[u8; 43]) -> bool {
    !text.contains_escape && text.raw.as_bytes() == &expected_challenge[..]
}

const fn validate_cross_origin_client_data_member(
    value: JsonValue<'_>,
) -> Result<(), VerificationReason> {
    if matches!(value, JsonValue::Boolean(false)) {
        Ok(())
    } else {
        Err(VerificationReason::CrossOrigin)
    }
}

fn duplicate_key_before<'a>(
    input: &'a str,
    members_start: usize,
    current_key_start: usize,
    key: JsonString<'a>,
) -> bool {
    let mut parser = JsonParser {
        input,
        offset: members_start,
    };

    loop {
        parser.skip_whitespace();
        if parser.offset == current_key_start {
            return false;
        }

        // The outer parser accepted every preceding member before replaying it
        // here, so this internal duplicate check only walks a valid prefix.
        let prior_key = parser.parse_string().unwrap_or(key);
        if prior_key.equals_string(key) {
            return true;
        }
        parser.skip_whitespace();
        parser.expect_byte(b':').unwrap_or(());
        parser.skip_whitespace();
        parser.parse_value().unwrap_or(JsonValue::Boolean(false));
        parser.skip_whitespace();
        parser.take_byte().unwrap_or_default();
    }
}

#[derive(Clone, Copy)]
enum JsonValue<'a> {
    String(JsonString<'a>),
    Boolean(bool),
}

#[derive(Clone, Copy)]
struct JsonString<'a> {
    // `JsonParser::parse_string` validates UTF-8 and every escape before this
    // value exists, so equality operates on a closed, trusted string shape.
    raw: &'a str,
    contains_escape: bool,
}

impl JsonString<'_> {
    fn equals_text(self, expected: &str) -> bool {
        let mut offset = 0;
        for character in expected.chars() {
            if self.next_scalar(&mut offset) != Some(u32::from(character)) {
                return false;
            }
        }
        self.next_scalar(&mut offset).is_none()
    }

    fn equals_string(self, other: Self) -> bool {
        let mut left_offset = 0;
        let mut right_offset = 0;
        loop {
            match (
                self.next_scalar(&mut left_offset),
                other.next_scalar(&mut right_offset),
            ) {
                (Some(left), Some(right)) if left == right => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    fn next_scalar(&self, offset: &mut usize) -> Option<u32> {
        let raw = self.raw.as_bytes();
        let &byte = raw.get(*offset)?;
        if byte != b'\\' {
            let character = self.raw[*offset..].chars().next().unwrap_or_default();
            *offset += character.len_utf8();
            return Some(u32::from(character));
        }

        *offset += 1;
        // `parse_string` validates every escape before constructing a
        // `JsonString`, so an escape byte always follows the slash.
        let escape = raw.get(*offset).copied().unwrap_or_default();
        *offset += 1;
        // `"`, `\\` and `/` unescape to themselves, so only the control
        // escapes and `\u` need their own arms.
        let scalar = match escape {
            b'b' => u32::from(8_u8),
            b'f' => u32::from(12_u8),
            b'n' => u32::from(b'\n'),
            b'r' => u32::from(b'\r'),
            b't' => u32::from(b'\t'),
            b'u' => self.decode_unicode_escape(offset).unwrap_or_default(),
            _ => u32::from(escape),
        };
        Some(scalar)
    }

    fn decode_unicode_escape(&self, offset: &mut usize) -> Result<u32, VerificationReason> {
        let first = self.decode_code_unit(offset)?;
        if (0xd800..=0xdbff).contains(&first) {
            if self.raw.as_bytes().get(*offset..*offset + 2) != Some(b"\\u") {
                return Err(VerificationReason::Malformed);
            }
            *offset += 2;
            let second = self.decode_code_unit(offset)?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(VerificationReason::Malformed);
            }
            let high = u32::from(first - 0xd800);
            let low = u32::from(second - 0xdc00);
            return Ok(0x1_0000 + (high << 10) + low);
        }
        if (0xdc00..=0xdfff).contains(&first) {
            return Err(VerificationReason::Malformed);
        }
        Ok(u32::from(first))
    }

    fn decode_code_unit(&self, offset: &mut usize) -> Result<u16, VerificationReason> {
        let end = *offset + 4;
        let digits = self
            .raw
            .as_bytes()
            .get(*offset..end)
            .ok_or(VerificationReason::Malformed)?;
        let mut value = 0_u16;
        for &digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(VerificationReason::Malformed),
            };
            value = value * 16 + u16::from(nibble);
        }
        *offset = end;
        Ok(value)
    }
}

struct JsonParser<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a [u8]) -> Result<Self, VerificationReason> {
        let input = core::str::from_utf8(input).map_err(|_| VerificationReason::Malformed)?;
        Ok(Self { input, offset: 0 })
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek_byte()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.offset += 1;
        }
    }

    fn parse_string(&mut self) -> Result<JsonString<'a>, VerificationReason> {
        self.expect_byte(b'"')?;
        let start = self.offset;
        let mut contains_escape = false;

        loop {
            let byte = self.take_byte().ok_or(VerificationReason::Malformed)?;
            match byte {
                b'"' => {
                    return Ok(JsonString {
                        raw: &self.input[start..self.offset - 1],
                        contains_escape,
                    });
                }
                b'\\' => {
                    contains_escape = true;
                    self.validate_escape()?;
                }
                0x00..=0x1f => return Err(VerificationReason::Malformed),
                _ => {}
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue<'a>, VerificationReason> {
        match self.peek_byte() {
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') => {
                self.expect_literal(b"true")?;
                Ok(JsonValue::Boolean(true))
            }
            Some(b'f') => {
                self.expect_literal(b"false")?;
                Ok(JsonValue::Boolean(false))
            }
            _ => Err(VerificationReason::Malformed),
        }
    }

    fn validate_escape(&mut self) -> Result<(), VerificationReason> {
        let escape = self.take_byte().ok_or(VerificationReason::Malformed)?;
        match escape {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Ok(()),
            b'u' => {
                let string = JsonString {
                    raw: self.input,
                    contains_escape: true,
                };
                let mut offset = self.offset;
                string.decode_unicode_escape(&mut offset)?;
                self.offset = offset;
                Ok(())
            }
            _ => Err(VerificationReason::Malformed),
        }
    }

    fn expect_literal(&mut self, expected: &[u8]) -> Result<(), VerificationReason> {
        let end = self.offset + expected.len();
        if self.input.as_bytes().get(self.offset..end) != Some(expected) {
            return Err(VerificationReason::Malformed);
        }
        self.offset = end;
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), VerificationReason> {
        if self.take_byte() == Some(expected) {
            Ok(())
        } else {
            Err(VerificationReason::Malformed)
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.offset).copied()
    }

    fn take_byte(&mut self) -> Option<u8> {
        let byte = self.peek_byte()?;
        self.offset += 1;
        Some(byte)
    }
}

fn base64url_challenge(challenge: &[u8; 32]) -> [u8; 43] {
    let mut output = [0; 43];
    // Thirty-two source bytes always produce exactly forty-three unpadded
    // base64url bytes, so the fixed output cannot be too small.
    URL_SAFE_NO_PAD
        .encode_slice(challenge, &mut output)
        .unwrap_or_default();
    output
}
