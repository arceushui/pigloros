use std::io::Cursor;

use ciborium::value::Value;
use ed25519_dalek::{Signer, Verifier};

use super::{
    SandboxContractErrorV1, MAX_SANDBOX_PROVIDER_CBOR_COLLECTION_ENTRIES_V1,
    MAX_SANDBOX_PROVIDER_DOCUMENT_BYTES_V1,
};

pub(super) fn decode(bytes: &[u8]) -> Result<Value, SandboxContractErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_SANDBOX_PROVIDER_DOCUMENT_BYTES_V1 {
        return Err(SandboxContractErrorV1::FieldOutOfBounds);
    }
    crate::preflight_array_cbor(
        bytes,
        32,
        MAX_SANDBOX_PROVIDER_CBOR_COLLECTION_ENTRIES_V1 as u64,
        true,
    )
    .map_err(|error| match error {
        crate::CborPreflightError::InvalidEncoding => SandboxContractErrorV1::InvalidEncoding,
        crate::CborPreflightError::FieldOutOfBounds => SandboxContractErrorV1::FieldOutOfBounds,
    })?;
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| SandboxContractErrorV1::InvalidEncoding)?;
    if encode(&value)? == bytes {
        Ok(value)
    } else {
        Err(SandboxContractErrorV1::InvalidEncoding)
    }
}

pub(super) fn encode(value: &Value) -> Result<Vec<u8>, SandboxContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| SandboxContractErrorV1::InvalidEncoding)?;
    if bytes.len() <= MAX_SANDBOX_PROVIDER_DOCUMENT_BYTES_V1 {
        Ok(bytes)
    } else {
        Err(SandboxContractErrorV1::FieldOutOfBounds)
    }
}

pub(super) fn array<const N: usize>(value: &Value) -> Result<&[Value; N], SandboxContractErrorV1> {
    let Value::Array(fields) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    fields
        .as_slice()
        .try_into()
        .map_err(|_| SandboxContractErrorV1::InvalidEncoding)
}

pub(super) fn text(value: &Value) -> Result<&str, SandboxContractErrorV1> {
    let Value::Text(value) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    Ok(value)
}

pub(super) fn uint(value: &Value) -> Result<u64, SandboxContractErrorV1> {
    let Value::Integer(value) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    u64::try_from(*value).map_err(|_| SandboxContractErrorV1::InvalidEncoding)
}

pub(super) fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], SandboxContractErrorV1> {
    let Value::Bytes(value) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| SandboxContractErrorV1::InvalidEncoding)
}

pub(super) fn bytes(value: &Value) -> Result<&[u8], SandboxContractErrorV1> {
    let Value::Bytes(value) = value else {
        return Err(SandboxContractErrorV1::InvalidEncoding);
    };
    Ok(value)
}

pub(super) fn optional_fixed<const N: usize>(
    value: &Value,
) -> Result<Option<[u8; N]>, SandboxContractErrorV1> {
    if value == &Value::Null {
        Ok(None)
    } else {
        fixed(value).map(Some)
    }
}

pub(super) fn digest(magic: &str, unsigned: &Value) -> Result<[u8; 32], SandboxContractErrorV1> {
    let mut domain = Vec::with_capacity(magic.len() + 13);
    domain.extend_from_slice(b"PiglorOS.");
    domain.extend_from_slice(magic.as_bytes());
    domain.extend_from_slice(b".v1\0");
    digest_with_domain(&domain, unsigned)
}

pub(super) fn digest_with_domain(
    domain: &[u8],
    unsigned: &Value,
) -> Result<[u8; 32], SandboxContractErrorV1> {
    let encoded = encode(unsigned)?;
    let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&encoded);
    Ok(*blake3::hash(&preimage).as_bytes())
}

pub(super) fn signature_message(magic: &str, digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(magic.len() + digest.len() + 23);
    message.extend_from_slice(b"PiglorOS.");
    message.extend_from_slice(magic.as_bytes());
    message.extend_from_slice(b".Signature.v1\0");
    message.extend_from_slice(digest);
    message
}

pub(super) fn sign(magic: &str, digest: &[u8; 32], key: &ed25519_dalek::SigningKey) -> [u8; 64] {
    key.sign(&signature_message(magic, digest)).to_bytes()
}

pub(super) fn verify(
    magic: &str,
    digest: &[u8; 32],
    signature: &[u8; 64],
    key: &ed25519_dalek::VerifyingKey,
) -> Result<(), SandboxContractErrorV1> {
    key.verify(
        &signature_message(magic, digest),
        &ed25519_dalek::Signature::from_bytes(signature),
    )
    .map_err(|_| SandboxContractErrorV1::SignatureInvalid)
}

pub(super) fn value_text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

pub(super) fn value_uint(value: u64) -> Value {
    Value::Integer(value.into())
}

pub(super) fn value_bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

pub(super) fn value_optional_bytes<const N: usize>(value: Option<&[u8; N]>) -> Value {
    value.map_or(Value::Null, |value| value_bytes(value))
}

pub(super) fn validate_magic(fields: &[Value], magic: &str) -> Result<(), SandboxContractErrorV1> {
    if text(&fields[0])? == magic && uint(&fields[1])? == 1 {
        Ok(())
    } else {
        Err(SandboxContractErrorV1::UnsupportedVersion)
    }
}

pub(super) fn canonically_ordered(values: &[Value]) -> Result<bool, SandboxContractErrorV1> {
    let encoded = values.iter().map(encode).collect::<Result<Vec<_>, _>>()?;
    Ok(encoded.windows(2).all(|pair| pair[0] < pair[1]))
}
