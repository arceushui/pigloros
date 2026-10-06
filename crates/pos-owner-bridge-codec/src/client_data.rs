use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::{CeremonyKind, OwnerBridgeCodecError};

const MAX_CLIENT_DATA_BYTES: usize = 4_096;
const OWNER_ORIGIN: &str = "http://localhost:49291";
const CREATE_TYPE: &str = "webauthn.create";
const GET_TYPE: &str = "webauthn.get";

/// Validate closed `WebAuthn` `clientDataJSON` for one ceremony and challenge.
///
/// The parser accepts a single flat JSON object whose member values are only
/// strings or booleans. It validates UTF-8 and every JSON escape while it
/// parses, compares duplicate keys after unescaping, and does not allocate.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::InvalidPayload`] for malformed JSON,
/// duplicate keys, an unsupported value shape, or a client-data value that
/// does not satisfy the closed ADR-110 `WebAuthn` contract. Returns
/// [`OwnerBridgeCodecError::BoundsExceeded`] when `input` is empty or exceeds
/// the fixed 4,096-byte bridge limit.
pub fn validate_client_data_json(
    input: &[u8],
    kind: CeremonyKind,
    challenge: &[u8; 32],
) -> Result<(), OwnerBridgeCodecError> {
    if input.is_empty() || input.len() > MAX_CLIENT_DATA_BYTES {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }

    let mut parser = JsonParser::new(input)?;
    parser.skip_whitespace();
    parser.expect_byte(b'{')?;
    let members_start = parser.offset;

    let mut type_seen = false;
    let mut challenge_seen = false;
    let mut origin_seen = false;
    let expected_type = match kind {
        CeremonyKind::Create => CREATE_TYPE,
        CeremonyKind::Get => GET_TYPE,
    };
    let expected_challenge = base64url_challenge(challenge);

    parser.skip_whitespace();
    if parser.peek_byte() == Some(b'}') {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }

    loop {
        let key_start = parser.offset;
        let key = parser.parse_string()?;
        if duplicate_key_before(parser.input, members_start, key_start, key) {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        parser.skip_whitespace();
        parser.expect_byte(b':')?;
        parser.skip_whitespace();
        let value = parser.parse_value()?;

        if key.equals_text("type") {
            let JsonValue::String(value) = value else {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            };
            if !value.equals_text(expected_type) {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            type_seen = true;
        } else if key.equals_text("challenge") {
            let JsonValue::String(value) = value else {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            };
            if value.contains_escape || value.raw.as_bytes() != &expected_challenge[..] {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            challenge_seen = true;
        } else if key.equals_text("origin") {
            let JsonValue::String(value) = value else {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            };
            if !value.equals_text(OWNER_ORIGIN) {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            origin_seen = true;
        } else if key.equals_text("crossOrigin") {
            let JsonValue::Boolean(value) = value else {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            };
            if value {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
        } else if key.equals_text("topOrigin") || key.equals_text("tokenBinding") {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }

        parser.skip_whitespace();
        match parser.take_byte() {
            Some(b',') => {
                parser.skip_whitespace();
                if parser.peek_byte() == Some(b'}') {
                    return Err(OwnerBridgeCodecError::InvalidPayload);
                }
            }
            Some(b'}') => break,
            _ => return Err(OwnerBridgeCodecError::InvalidPayload),
        }
    }

    parser.skip_whitespace();
    if parser.offset != input.len() || !(type_seen && challenge_seen && origin_seen) {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    Ok(())
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
        let Some(&byte) = raw.get(*offset) else {
            return None;
        };
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
        let scalar = match escape {
            b'"' => u32::from(b'"'),
            b'\\' => u32::from(b'\\'),
            b'/' => u32::from(b'/'),
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

    fn decode_unicode_escape(&self, offset: &mut usize) -> Result<u32, OwnerBridgeCodecError> {
        let first = self.decode_code_unit(offset)?;
        if (0xd800..=0xdbff).contains(&first) {
            if self.raw.as_bytes().get(*offset..*offset + 2) != Some(b"\\u") {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            *offset += 2;
            let second = self.decode_code_unit(offset)?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            let high = u32::from(first - 0xd800);
            let low = u32::from(second - 0xdc00);
            return Ok(0x1_0000 + (high << 10) + low);
        }
        if (0xdc00..=0xdfff).contains(&first) {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        Ok(u32::from(first))
    }

    fn decode_code_unit(&self, offset: &mut usize) -> Result<u16, OwnerBridgeCodecError> {
        let end = *offset + 4;
        let digits = self
            .raw
            .as_bytes()
            .get(*offset..end)
            .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
        let mut value = 0_u16;
        for &digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(OwnerBridgeCodecError::InvalidPayload),
            };
            value = (value << 4) | u16::from(nibble);
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
    fn new(input: &'a [u8]) -> Result<Self, OwnerBridgeCodecError> {
        let input =
            core::str::from_utf8(input).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
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

    fn parse_string(&mut self) -> Result<JsonString<'a>, OwnerBridgeCodecError> {
        self.expect_byte(b'"')?;
        let start = self.offset;
        let mut contains_escape = false;

        loop {
            let byte = self
                .take_byte()
                .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
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
                0x00..=0x1f => return Err(OwnerBridgeCodecError::InvalidPayload),
                _ => {}
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue<'a>, OwnerBridgeCodecError> {
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
            _ => Err(OwnerBridgeCodecError::InvalidPayload),
        }
    }

    fn validate_escape(&mut self) -> Result<(), OwnerBridgeCodecError> {
        let escape = self
            .take_byte()
            .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
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
            _ => Err(OwnerBridgeCodecError::InvalidPayload),
        }
    }

    fn expect_literal(&mut self, expected: &[u8]) -> Result<(), OwnerBridgeCodecError> {
        let end = self.offset + expected.len();
        if self.input.as_bytes().get(self.offset..end) != Some(expected) {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        self.offset = end;
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), OwnerBridgeCodecError> {
        if self.take_byte() == Some(expected) {
            Ok(())
        } else {
            Err(OwnerBridgeCodecError::InvalidPayload)
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
