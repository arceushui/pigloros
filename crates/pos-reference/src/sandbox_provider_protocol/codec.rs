use std::io::Cursor;

use ciborium::value::Value;
use ed25519_dalek::Verifier;

use super::SandboxProviderProtocolError;

pub(super) const MAX_INPUT_BYTES_U64: u64 = 128 * 1024 * 1024;
pub(super) const MAX_SAFE_DETAIL_BYTES: usize = 256;

const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
pub(super) const MAX_LIST_ENTRIES: usize = 256;
pub(super) const MAX_CBOR_COLLECTION_ENTRIES: usize = 512;
pub(super) const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_EXECUTABLE_PATH_BYTES: usize = 512;

type SignedFields<'a, const N: usize> = (&'a [Value; N], [u8; 32], [u8; 64]);

pub(super) fn signed<'a, const N: usize>(
    value: &'a Value,
    magic: &str,
) -> Result<SignedFields<'a, N>, SandboxProviderProtocolError> {
    let wrapper = array::<3>(value)?;
    let unsigned = array::<N>(&wrapper[0])?;
    validate_magic(unsigned, magic)?;
    Ok((unsigned, digest32(&wrapper[1])?, fixed_bytes(&wrapper[2])?))
}

pub(super) fn self_digested<'a, const N: usize>(
    value: &'a Value,
    magic: &str,
) -> Result<(&'a [Value; N], [u8; 32]), SandboxProviderProtocolError> {
    let wrapper = array::<2>(value)?;
    let unsigned = array::<N>(&wrapper[0])?;
    validate_magic(unsigned, magic)?;
    Ok((unsigned, digest32(&wrapper[1])?))
}

pub(super) fn verify_digest(
    magic: &str,
    unsigned: &[Value],
    expected: [u8; 32],
) -> Result<(), SandboxProviderProtocolError> {
    let actual = record_digest(magic, &Value::Array(unsigned.to_vec()))?;
    if expected == [0; 32] || expected != actual {
        Err(SandboxProviderProtocolError::DigestMismatch)
    } else {
        Ok(())
    }
}

pub(super) fn verify_digest_with_domain(
    domain: &[u8],
    unsigned: &[Value],
    expected: [u8; 32],
) -> Result<(), SandboxProviderProtocolError> {
    let actual = digest_with_domain(domain, &Value::Array(unsigned.to_vec()))?;
    if expected == [0; 32] || expected != actual {
        Err(SandboxProviderProtocolError::DigestMismatch)
    } else {
        Ok(())
    }
}

pub(super) fn record_digest(
    magic: &str,
    unsigned: &Value,
) -> Result<[u8; 32], SandboxProviderProtocolError> {
    let mut domain = Vec::with_capacity(magic.len() + 13);
    domain.extend_from_slice(b"PiglorOS.");
    domain.extend_from_slice(magic.as_bytes());
    domain.extend_from_slice(b".v1\0");
    digest_with_domain(&domain, unsigned)
}

fn digest_with_domain(
    domain: &[u8],
    unsigned: &Value,
) -> Result<[u8; 32], SandboxProviderProtocolError> {
    let encoded = encode(unsigned)?;
    let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&encoded);
    Ok(*blake3::hash(&preimage).as_bytes())
}

pub(super) fn verify_signature(
    magic: &str,
    digest: &[u8; 32],
    signature: &[u8; 64],
    key: &ed25519_dalek::VerifyingKey,
) -> Result<(), SandboxProviderProtocolError> {
    let mut message = Vec::with_capacity(magic.len() + 55);
    message.extend_from_slice(b"PiglorOS.");
    message.extend_from_slice(magic.as_bytes());
    message.extend_from_slice(b".Signature.v1\0");
    message.extend_from_slice(digest);
    key.verify(&message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| SandboxProviderProtocolError::SignatureInvalid)
}

pub(super) fn require_signature(signature: &[u8; 64]) -> Result<(), SandboxProviderProtocolError> {
    if signature == &[0; 64] {
        Err(SandboxProviderProtocolError::SignatureInvalid)
    } else {
        Ok(())
    }
}

pub(super) fn decode_document(bytes: &[u8]) -> Result<Value, SandboxProviderProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    preflight(bytes)?;
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)?;
    if encode(&value)? != bytes {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    }
    Ok(value)
}

pub(super) fn encode(value: &Value) -> Result<Vec<u8>, SandboxProviderProtocolError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)?;
    Ok(bytes)
}

pub(super) fn preflight(bytes: &[u8]) -> Result<(), SandboxProviderProtocolError> {
    fn length(
        bytes: &[u8],
        index: &mut usize,
        additional: u8,
    ) -> Result<u64, SandboxProviderProtocolError> {
        let width = match additional {
            value @ 0..=23 => return Ok(u64::from(value)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(SandboxProviderProtocolError::InvalidEncoding),
        };
        let end = index
            .checked_add(width)
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)?;
        let encoded = bytes
            .get(*index..end)
            .ok_or(SandboxProviderProtocolError::InvalidEncoding)?;
        *index = end;
        let mut value = [0_u8; 8];
        value[8 - width..].copy_from_slice(encoded);
        Ok(u64::from_be_bytes(value))
    }

    fn item(
        bytes: &[u8],
        index: &mut usize,
        depth: usize,
    ) -> Result<(), SandboxProviderProtocolError> {
        if depth > MAX_DEPTH {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        let initial = *bytes
            .get(*index)
            .ok_or(SandboxProviderProtocolError::InvalidEncoding)?;
        *index += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let count = length(bytes, index, additional)?;
        match major {
            0 => Ok(()),
            2 | 3 => {
                let count = usize::try_from(count)
                    .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?;
                let end = index
                    .checked_add(count)
                    .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)?;
                bytes
                    .get(*index..end)
                    .ok_or(SandboxProviderProtocolError::InvalidEncoding)?;
                *index = end;
                Ok(())
            }
            4 => {
                let count = usize::try_from(count)
                    .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?;
                if count > MAX_CBOR_COLLECTION_ENTRIES {
                    return Err(SandboxProviderProtocolError::FieldOutOfBounds);
                }
                (0..count).try_for_each(|_| item(bytes, index, depth + 1))
            }
            7 if matches!(additional, 20..=22) => Ok(()),
            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
        }
    }

    let mut index = 0;
    item(bytes, &mut index, 0)?;
    if index == bytes.len() {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::InvalidEncoding)
    }
}

pub(super) fn array<const N: usize>(
    value: &Value,
) -> Result<&[Value; N], SandboxProviderProtocolError> {
    let Value::Array(values) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    values
        .as_slice()
        .try_into()
        .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)
}

pub(super) fn bounded_array(
    value: &Value,
    minimum: usize,
) -> Result<&[Value], SandboxProviderProtocolError> {
    let Value::Array(values) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    if values.len() < minimum || values.len() > MAX_LIST_ENTRIES {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(values)
    }
}

pub(super) fn validate_magic(
    fields: &[Value],
    magic: &str,
) -> Result<(), SandboxProviderProtocolError> {
    if text(&fields[0])? == magic && uint(&fields[1])? == 1 {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::UnsupportedVersion)
    }
}

pub(super) fn text(value: &Value) -> Result<&str, SandboxProviderProtocolError> {
    let Value::Text(value) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    Ok(value)
}

pub(super) fn identifier(value: &Value) -> Result<String, SandboxProviderProtocolError> {
    let value = text(value)?;
    if valid_identifier(value) {
        Ok(value.to_owned())
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

pub(super) fn valid_identifier(value: &str) -> bool {
    let Some(first) = value.bytes().next() else {
        return false;
    };
    value.len() <= MAX_IDENTIFIER_BYTES
        && value.is_ascii()
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

pub(super) fn key_id(value: &Value) -> Result<String, SandboxProviderProtocolError> {
    let value = text(value)?;
    if valid_key_id(value) {
        Ok(value.to_owned())
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

pub(super) const fn valid_key_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
}

pub(super) fn uint(value: &Value) -> Result<u64, SandboxProviderProtocolError> {
    let Value::Integer(value) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    u64::try_from(*value).map_err(|_| SandboxProviderProtocolError::InvalidEncoding)
}

pub(super) const fn bool_value(value: &Value) -> Result<bool, SandboxProviderProtocolError> {
    let Value::Bool(value) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    Ok(*value)
}

pub(super) fn byte_string(value: &Value) -> Result<&[u8], SandboxProviderProtocolError> {
    let Value::Bytes(value) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    Ok(value)
}

pub(super) fn fixed_bytes<const N: usize>(
    value: &Value,
) -> Result<[u8; N], SandboxProviderProtocolError> {
    byte_string(value)?
        .try_into()
        .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)
}

pub(super) fn id16(value: &Value) -> Result<[u8; 16], SandboxProviderProtocolError> {
    let identity = fixed_bytes(value)?;
    if identity == [0; 16] {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(identity)
    }
}

pub(super) fn digest32(value: &Value) -> Result<[u8; 32], SandboxProviderProtocolError> {
    fixed_bytes(value)
}

pub(super) fn optional_id16(
    value: &Value,
) -> Result<Option<[u8; 16]>, SandboxProviderProtocolError> {
    if value == &Value::Null {
        Ok(None)
    } else {
        id16(value).map(Some)
    }
}

pub(super) fn optional_digest(
    value: &Value,
) -> Result<Option<[u8; 32]>, SandboxProviderProtocolError> {
    if value == &Value::Null {
        Ok(None)
    } else {
        digest32(value).map(Some)
    }
}

pub(super) fn optional_u8(value: &Value) -> Result<Option<u8>, SandboxProviderProtocolError> {
    if value == &Value::Null {
        Ok(None)
    } else {
        u8::try_from(uint(value)?)
            .map(Some)
            .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

pub(super) fn optional_text(
    value: &Value,
    maximum: usize,
) -> Result<Option<String>, SandboxProviderProtocolError> {
    if value == &Value::Null {
        return Ok(None);
    }
    let value = text(value)?;
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(Some(value.to_owned()))
    }
}

pub(super) fn decode_identifiers(
    value: &Value,
) -> Result<Vec<String>, SandboxProviderProtocolError> {
    bounded_array(value, 0)?.iter().map(identifier).collect()
}

pub(super) fn decode_text_list(value: &Value) -> Result<Vec<String>, SandboxProviderProtocolError> {
    bounded_array(value, 0)?
        .iter()
        .map(|value| text(value).map(ToOwned::to_owned))
        .collect()
}

pub(super) fn decode_digest_list(
    value: &Value,
) -> Result<Vec<[u8; 32]>, SandboxProviderProtocolError> {
    bounded_array(value, 0)?.iter().map(digest32).collect()
}

pub(super) fn decode_u8_list(value: &Value) -> Result<Vec<u8>, SandboxProviderProtocolError> {
    bounded_array(value, 0)?
        .iter()
        .map(|value| {
            u8::try_from(uint(value)?).map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
        })
        .collect()
}

pub(super) fn invalid_digest_list(values: &[[u8; 32]]) -> bool {
    values.len() > MAX_LIST_ENTRIES || values.contains(&[0; 32])
}

pub(super) fn usize_u64(value: usize) -> Result<u64, SandboxProviderProtocolError> {
    u64::try_from(value).map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
}

pub(super) fn validate_identifier_order(
    values: &[String],
) -> Result<(), SandboxProviderProtocolError> {
    if values
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::NonCanonicalOrder)
    }
}

pub(super) fn require_canonical_order(
    values: &[Value],
) -> Result<(), SandboxProviderProtocolError> {
    let encoded = values.iter().map(encode).collect::<Result<Vec<_>, _>>()?;
    if encoded.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::NonCanonicalOrder)
    }
}

pub(super) fn normalized_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_EXECUTABLE_PATH_BYTES
        && !value.contains('\0')
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

pub(super) fn nonzero_optional(value: Option<[u8; 32]>) -> bool {
    matches!(value, Some(digest) if digest != [0; 32])
}

pub(super) fn text_value(value: &str) -> Value {
    Value::Text(value.to_owned())
}

pub(super) fn uint_value(value: u64) -> Value {
    Value::Integer(value.into())
}

pub(super) fn bytes_value(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

pub(super) fn optional_bytes_value<const N: usize>(value: Option<&[u8; N]>) -> Value {
    value.map_or(Value::Null, |value| bytes_value(value))
}

pub(super) fn optional_digest_value(value: Option<&[u8; 32]>) -> Value {
    optional_bytes_value(value)
}

pub(super) fn digest_list_value(values: &[[u8; 32]]) -> Value {
    Value::Array(values.iter().map(|value| bytes_value(value)).collect())
}
