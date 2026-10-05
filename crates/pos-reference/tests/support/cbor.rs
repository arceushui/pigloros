// Canonical-CBOR and field-mutation helpers shared by the public tests.
//
// Every public contract test that builds or corrupts wire bytes goes through
// these helpers, so the encoding and the mutation primitives are defined once.
// This file is `include!`d into a `cbor` module so it also builds when
// `support/mod.rs` itself is included from `src/lib.rs`.

use std::error::Error;

use ciborium::value::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Encode one CBOR value exactly as the public codecs emit it.
///
/// # Errors
/// Returns an error when the value cannot be encoded.
pub fn canonical(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// Decode CBOR bytes into a value tree that a test can mutate.
///
/// # Errors
/// Returns an error when the bytes are not CBOR.
pub fn decoded_value(bytes: &[u8]) -> TestResult<Value> {
    Ok(ciborium::from_reader(bytes)?)
}

/// Replace one field of an array-shaped value.
///
/// # Errors
/// Returns an error when the value is not an array or the index is absent.
pub fn replace_field(value: &mut Value, index: usize, replacement: Value) -> TestResult {
    replace_path(value, &[index], replacement)
}

/// Replace the value at a nested array path.
///
/// # Errors
/// Returns an error when the path does not select an existing array element.
pub fn replace_path(value: &mut Value, path: &[usize], replacement: Value) -> TestResult {
    let (&index, remainder) = path.split_first().ok_or("test path is empty")?;
    let Value::Array(fields) = value else {
        return Err("test path does not select an array".into());
    };
    let field = fields
        .get_mut(index)
        .ok_or("test path index is out of bounds")?;
    if remainder.is_empty() {
        *field = replacement;
        Ok(())
    } else {
        replace_path(field, remainder, replacement)
    }
}

/// Decode array-shaped CBOR, let `update` rewrite its top-level fields, and
/// re-encode the result.
///
/// # Errors
/// Returns an error when the bytes are not an array or `update` fails.
pub fn rewrite_fields(
    bytes: &[u8],
    update: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut value = decoded_value(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err("test value is not an array".into());
    };
    update(fields)?;
    canonical(&value)
}
