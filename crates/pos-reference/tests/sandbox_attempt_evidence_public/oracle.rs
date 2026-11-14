//! The independent oracle: canonical CBOR through ciborium and self-digests
//! through BLAKE3, never through the codecs under test.

use std::error::Error;

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::SandboxProviderProtocolError as ProtocolError;

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub fn unhex(text: &str) -> TestResult<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&text[index..index + 2], 16)?))
        .collect()
}

pub fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

pub fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

pub fn filled(byte: u8, length: usize) -> Value {
    Value::Bytes(vec![byte; length])
}

pub fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// `BLAKE3-256("PiglorOS." || magic || ".v1\0" || cbor(unsigned))`.
pub fn self_digest(magic: &str, unsigned: &Value) -> TestResult<[u8; 32]> {
    let mut preimage = format!("PiglorOS.{magic}.v1\0").into_bytes();
    preimage.extend(encode(unsigned)?);
    Ok(*blake3::hash(&preimage).as_bytes())
}

/// The canonical wrapper `[unsigned, self_digest]`.
pub fn seal(magic: &str, unsigned: Vec<Value>) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(unsigned);
    let digest = self_digest(magic, &unsigned)?;
    encode(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
}

/// The unsigned fields of one self-digested record.
pub fn unsigned(bytes: &[u8]) -> TestResult<Vec<Value>> {
    let wrapper: Value = ciborium::from_reader(bytes)?;
    match wrapper {
        Value::Array(mut parts) if parts.len() == 2 => match parts.swap_remove(0) {
            Value::Array(fields) => Ok(fields),
            _ => Err("unsigned prefix is not an array".into()),
        },
        _ => Err("record is not a self-digested wrapper".into()),
    }
}

/// The record's self-digest, read from its wrapper.
pub fn wrapped_digest(bytes: &[u8]) -> TestResult<[u8; 32]> {
    let fields = unsigned(bytes)?;
    let magic = match &fields[0] {
        Value::Text(magic) => magic.clone(),
        _ => return Err("record has no magic".into()),
    };
    self_digest(&magic, &Value::Array(fields))
}

/// Change a record's unsigned fields and seal it again.
pub fn edit(
    bytes: &[u8],
    change: impl FnOnce(&mut Vec<Value>) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut fields = unsigned(bytes)?;
    change(&mut fields)?;
    let magic = match &fields[0] {
        Value::Text(magic) => magic.clone(),
        _ => "XXXX".to_owned(),
    };
    seal(&magic, fields)
}

/// Replace the value at a nested array path.
pub fn set(fields: &mut [Value], path: &[usize], value: Value) -> TestResult {
    *at(fields, path)? = value;
    Ok(())
}

/// The value at a nested array path.
pub fn at<'a>(fields: &'a mut [Value], path: &[usize]) -> TestResult<&'a mut Value> {
    let (first, rest) = path.split_first().ok_or("empty path")?;
    let mut value = fields.get_mut(*first).ok_or("path out of range")?;
    for index in rest {
        value = match value {
            Value::Array(values) => values.get_mut(*index).ok_or("path out of range")?,
            _ => return Err("path enters a non-array".into()),
        };
    }
    Ok(value)
}

/// Set one field of a record and seal it again.
pub fn with(bytes: &[u8], path: &[usize], value: Value) -> TestResult<Vec<u8>> {
    edit(bytes, |fields| set(fields, path, value))
}

/// Every path of the unsigned tree, and a value of another CBOR type for it.
pub fn retyped_paths(fields: &[Value]) -> Vec<(Vec<usize>, Value)> {
    fn walk(value: &Value, path: &mut Vec<usize>, out: &mut Vec<(Vec<usize>, Value)>) {
        let replacement = match value {
            Value::Integer(_) | Value::Null => text("~"),
            _ => integer(0),
        };
        out.push((path.clone(), replacement));
        if let Value::Array(values) = value {
            for (index, value) in values.iter().enumerate() {
                path.push(index);
                walk(value, path, out);
                path.pop();
            }
        }
    }
    let mut out = Vec::new();
    for (index, value) in fields.iter().enumerate() {
        let mut path = vec![index];
        walk(value, &mut path, &mut out);
    }
    out
}

/// Every node of `bytes`, retyped and resealed, is rejected by `decode`.
pub fn rejects_every_retyped_node(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<(), ProtocolError>,
) -> TestResult {
    for (path, replacement) in retyped_paths(&unsigned(bytes)?) {
        let changed = with(bytes, &path, replacement)?;
        assert!(
            decode(&changed).is_err(),
            "retyped node {path:?} was accepted"
        );
    }
    Ok(())
}

/// A raw input of exactly `length` bytes: not CBOR, so only the size bound
/// can make it `FieldOutOfBounds`.
pub fn junk(length: usize) -> Vec<u8> {
    vec![0; length]
}

/// The raw-size bound is inclusive at `maximum`.
pub fn bounds_raw_size(maximum: usize, decode: impl Fn(&[u8]) -> Result<(), ProtocolError>) {
    assert_eq!(decode(&junk(maximum)), Err(ProtocolError::InvalidEncoding));
    assert_eq!(
        decode(&junk(maximum + 1)),
        Err(ProtocolError::FieldOutOfBounds)
    );
}

/// The shared envelope rules: magic, version, digest and canonical bytes.
pub fn checks_envelope(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<(), ProtocolError>,
) -> TestResult {
    assert_eq!(decode(bytes), Ok(()));
    let magic = match &unsigned(bytes)?[0] {
        Value::Text(magic) => magic.clone(),
        _ => return Err("record has no magic".into()),
    };
    let other_magic = format!("{}9", &magic[..3]);
    assert_eq!(
        decode(&with(bytes, &[0], text(&other_magic))?),
        Err(ProtocolError::UnsupportedVersion)
    );
    assert_eq!(
        decode(&with(bytes, &[1], integer(2))?),
        Err(ProtocolError::UnsupportedVersion)
    );
    let mut wrapper: Value = ciborium::from_reader(bytes)?;
    if let Value::Array(parts) = &mut wrapper {
        parts[1] = Value::Bytes(vec![0x5a; 32]);
    }
    assert_eq!(
        decode(&encode(&wrapper)?),
        Err(ProtocolError::DigestMismatch)
    );
    if let Value::Array(parts) = &mut wrapper {
        parts[1] = Value::Bytes(vec![0; 32]);
    }
    assert_eq!(
        decode(&encode(&wrapper)?),
        Err(ProtocolError::DigestMismatch)
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(ProtocolError::InvalidEncoding));
    Ok(())
}
