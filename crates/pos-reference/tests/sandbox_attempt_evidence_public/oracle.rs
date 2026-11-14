//! The independent oracle: canonical CBOR through ciborium and self-digests
//! through BLAKE3, never through the codecs under test.

use std::error::Error;

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::SandboxProviderProtocolError as ProtocolError;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub(super) fn unhex(text: &str) -> TestResult<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&text[index..index + 2], 16)?))
        .collect()
}

pub(super) fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

pub(super) fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

pub(super) fn filled(byte: u8, length: usize) -> Value {
    Value::Bytes(vec![byte; length])
}

pub(super) fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// `BLAKE3-256("PiglorOS." || magic || ".v1\0" || cbor(unsigned))`.
pub(super) fn self_digest(magic: &str, unsigned: &Value) -> TestResult<[u8; 32]> {
    let mut preimage = format!("PiglorOS.{magic}.v1\0").into_bytes();
    preimage.extend(encode(unsigned)?);
    Ok(*blake3::hash(&preimage).as_bytes())
}

/// The canonical wrapper `[unsigned, self_digest]`.
pub(super) fn seal(magic: &str, unsigned: Vec<Value>) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(unsigned);
    let digest = self_digest(magic, &unsigned)?;
    encode(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
}

/// The unsigned fields of one self-digested record.
pub(super) fn unsigned(bytes: &[u8]) -> TestResult<Vec<Value>> {
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
pub(super) fn wrapped_digest(bytes: &[u8]) -> TestResult<[u8; 32]> {
    let fields = unsigned(bytes)?;
    let magic = match &fields[0] {
        Value::Text(magic) => magic.clone(),
        _ => return Err("record has no magic".into()),
    };
    self_digest(&magic, &Value::Array(fields))
}

/// Change a record's unsigned fields and seal it again.
pub(super) fn edit(
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
pub(super) fn set(fields: &mut [Value], path: &[usize], value: Value) -> TestResult {
    *at(fields, path)? = value;
    Ok(())
}

/// The value at a nested array path.
pub(super) fn at<'a>(fields: &'a mut [Value], path: &[usize]) -> TestResult<&'a mut Value> {
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
pub(super) fn with(bytes: &[u8], path: &[usize], value: Value) -> TestResult<Vec<u8>> {
    edit(bytes, |fields| set(fields, path, value))
}

/// Every path of the unsigned tree, and a value of another CBOR type for it.
pub(super) fn retyped_paths(fields: &[Value]) -> Vec<(Vec<usize>, Value)> {
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
pub(super) fn rejects_every_retyped_node(
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
pub(super) fn junk(length: usize) -> Vec<u8> {
    vec![0; length]
}

/// The raw-size bound is inclusive at `maximum`.
pub(super) fn bounds_raw_size(maximum: usize, decode: impl Fn(&[u8]) -> Result<(), ProtocolError>) {
    assert_eq!(decode(&junk(maximum)), Err(ProtocolError::InvalidEncoding));
    assert_eq!(
        decode(&junk(maximum + 1)),
        Err(ProtocolError::FieldOutOfBounds)
    );
}

/// The shared envelope rules: magic, version, digest and canonical bytes.
pub(super) fn checks_envelope(
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

/// Hand-built malformed encodings of the canonical record `bytes`, each
/// rejected as `InvalidEncoding`: a non-preferred integer, a map, a tag, a
/// float, an indefinite length, invalid UTF-8, and an unsigned-array length
/// one too large and one too small.
pub(super) fn rejects_malformed_encodings(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<(), ProtocolError>,
) -> TestResult {
    // `[unsigned, digest]`: the unsigned header, then the magic, then the
    // version 1.
    let header = if bytes[1] == 0x98 { 2 } else { 1 };
    let magic = 1 + header;
    let version = magic + 5;
    assert_eq!((bytes[0], bytes[magic], bytes[version]), (0x82, 0x64, 0x01));
    let replace = |index: usize, with: &[u8]| {
        let mut changed = bytes[..index].to_vec();
        changed.extend_from_slice(with);
        changed.extend_from_slice(&bytes[index + 1..]);
        changed
    };
    let mut indefinite = replace(0, &[0x9f]);
    indefinite.push(0xff);
    let count = bytes[header];
    let cases = [
        ("non-preferred integer", replace(version, &[0x18, 0x01])),
        ("map", replace(version, &[0xa0])),
        ("tag", replace(version, &[0xc1, 0x01])),
        ("float", replace(version, &[0xf9, 0x3c, 0x00])),
        ("indefinite length", indefinite),
        ("invalid UTF-8", replace(magic + 1, &[0xff])),
        ("one field too many", replace(header, &[count + 1])),
        ("one field too few", replace(header, &[count - 1])),
    ];
    for (case, changed) in cases {
        assert_eq!(
            decode(&changed),
            Err(ProtocolError::InvalidEncoding),
            "{case}"
        );
    }
    Ok(())
}
