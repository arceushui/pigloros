//! The `PCW2` composite of the Plugin conformance fixtures (ADR-061 revision 8 decision 7).

use std::collections::BTreeMap;

use ciborium::value::Value;

use super::TestResult;

/// The pieces of a composite, each addressed by its digest.
pub type Pieces = BTreeMap<[u8; 32], Vec<u8>>;

/// The pieces of the composite `bytes`: `["PCW2", 1, [[digest32, bytes], ...]]`, each digest
/// the BLAKE3 of its bytes.
///
/// # Errors
/// Returns an error for a composite of another shape or a piece whose digest is wrong.
pub fn pieces_of(composite: &[u8]) -> TestResult<Pieces> {
    let value: Value = ciborium::from_reader(composite)?;
    let Value::Array(items) = value else {
        return Err("the composite is not an array".into());
    };
    let [Value::Text(tag), Value::Integer(_), Value::Array(list)] = items.as_slice() else {
        return Err("the composite has the wrong shape".into());
    };
    if tag != "PCW2" || list.is_empty() {
        return Err("the composite has the wrong tag or no pieces".into());
    }
    let mut pieces = Pieces::new();
    for entry in list {
        let Value::Array(pair) = entry else {
            return Err("a piece is not a pair".into());
        };
        let [Value::Bytes(named), Value::Bytes(bytes)] = pair.as_slice() else {
            return Err("a piece is not a digest and bytes".into());
        };
        if blake3::hash(bytes).as_bytes().as_slice() != named.as_slice() {
            return Err("a piece digest is wrong".into());
        }
        pieces.insert(<[u8; 32]>::try_from(named.as_slice())?, bytes.clone());
    }
    Ok(pieces)
}
