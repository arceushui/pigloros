//! Canonical CBOR encoding: RFC 8949 §4.2.1 deterministic profile.
//!
//! `ciborium::into_writer` on serde-derived types does NOT produce canonical CBOR
//! because it preserves struct field declaration order (not sorted by key length/lex).
//! This module produces canonical CBOR by going through `ciborium::Value` and
//! sorting map keys before serialization.

use ciborium::value::Value;
use pos_core::{CanonicalBytes, CoreError};
use serde::Serialize;

/// Encode `value` as canonical (deterministic) CBOR bytes.
///
/// Canonical means: map keys are sorted by (byte-length, lexicographic) order per RFC 8949 §4.2.1.
/// This is required for the hash chain to be tamper-evident regardless of struct field order.
///
/// # Errors
/// Returns [`CoreError::Serialization`] if the value cannot be serialized to a CBOR value.
///
/// # Panics
/// Panics only if writing a `ciborium::Value` into an in-memory `Vec<u8>` fails, which
/// is not expected for well-formed values.
pub fn encode<T: Serialize>(value: &T) -> Result<CanonicalBytes, CoreError> {
    // Step 1: serialize to ciborium::Value via serde
    let cv = serde_to_cbor_value(value)?;
    // Step 2: sort all map keys recursively (RFC 8949 deterministic profile)
    let sorted = sort_map_keys(cv);
    // Step 3: encode to bytes
    let mut buf = Vec::new();
    // Encoding a `ciborium::Value` into an in-memory buffer is infallible.
    ciborium::into_writer(&sorted, &mut buf).expect("CBOR encode to Vec is infallible");
    Ok(CanonicalBytes::from_vec(buf))
}

/// Decode canonical CBOR bytes back to `T`.
///
/// # Errors
/// Returns [`CoreError::Serialization`] if the bytes cannot be decoded into `T`.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &CanonicalBytes) -> Result<T, CoreError> {
    ciborium::from_reader(bytes.as_slice()).map_err(|e| CoreError::Serialization(e.to_string()))
}

/// Serialize any serde-serializable type to a `ciborium::Value`.
fn serde_to_cbor_value<T: Serialize>(value: &T) -> Result<Value, CoreError> {
    // Serialize to JSON then parse into Value — a reliable bridge for serde types.
    let json = serde_json::to_value(value)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    json_value_to_cbor(json)
}

fn json_value_to_cbor(json: serde_json::Value) -> Result<Value, CoreError> {
    use serde_json::Value as J;
    Ok(match json {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(b),
        J::Number(n) => n.as_i64().map_or_else(
            || Value::Float(n.as_f64().unwrap_or(0.0)),
            |i| Value::Integer(i.into()),
        ),
        J::String(s) => Value::Text(s),
        J::Array(arr) => Value::Array(
            arr.into_iter()
                .map(json_value_to_cbor)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        J::Object(map) => Value::Map(
            map.into_iter()
                .map(|(k, v)| json_value_to_cbor(v).map(|v| (Value::Text(k), v)))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

/// Sort map keys recursively per RFC 8949 §4.2.1: sort by (`key_length`, `key_bytes`) ascending.
fn sort_map_keys(value: Value) -> Value {
    match value {
        Value::Map(mut pairs) => {
            // Sort keys: RFC 8949 §4.2.1 — first by byte length of key encoding, then lexicographic.
            pairs.sort_by(|(a, _), (b, _)| {
                let a_bytes = cbor_key_bytes(a);
                let b_bytes = cbor_key_bytes(b);
                a_bytes.len().cmp(&b_bytes.len()).then_with(|| a_bytes.cmp(&b_bytes))
            });
            // Recurse into values
            Value::Map(pairs.into_iter().map(|(k, v)| (k, sort_map_keys(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_map_keys).collect()),
        other => other,
    }
}

/// Get the canonical CBOR encoding of a map key for sorting purposes.
fn cbor_key_bytes(key: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = ciborium::into_writer(key, &mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct ZebraFirst {
        zebra: u32,
        apple: u32,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct AppleFirst {
        apple: u32,
        zebra: u32,
    }

    #[test]
    fn canonical_cbor_is_same_regardless_of_field_declaration_order() {
        let zebra_first = ZebraFirst { zebra: 1, apple: 2 };
        let apple_first = AppleFirst { apple: 2, zebra: 1 };
        let encoded_zebra = encode(&zebra_first).unwrap();
        let encoded_apple = encode(&apple_first).unwrap();
        assert_eq!(
            encoded_zebra.as_slice(),
            encoded_apple.as_slice(),
            "canonical CBOR must be identical regardless of struct field order"
        );
    }

    #[test]
    fn canonical_key_order_is_by_length_then_lex() {
        // "apple" (5 bytes) should come before "zebra" (5 bytes, but 'a' < 'z' lex)
        // "a" (1 byte) should come before "apple" (5 bytes)
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Multi {
            zebra: u32,
            apple: u32,
            a: u32,
        }
        let m = Multi { zebra: 1, apple: 2, a: 3 };
        let encoded = encode(&m).unwrap();
        // Decode as a ciborium::Value to inspect key ordering
        let decoded: Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        // encoding a struct always produces a map
        let Value::Map(pairs) = decoded else { unreachable!("struct encodes as CBOR map") };
        let keys: Vec<&str> = pairs
            .iter()
            .map(|(k, _)| if let Value::Text(s) = k { s.as_str() } else { "" })
            .collect();
        // "a" (1 char) < "apple" (5 chars) < "zebra" (5 chars, but 'a' < 'z')
        assert_eq!(keys, vec!["a", "apple", "zebra"]);
    }

    #[test]
    fn encode_decode_round_trip() {
        let zf = ZebraFirst { zebra: 42, apple: 99 };
        let encoded = encode(&zf).unwrap();
        let decoded: ZebraFirst = decode(&encoded).unwrap();
        assert_eq!(zf, decoded);
    }

    #[test]
    fn encode_bool() {
        let b = true;
        let enc = encode(&b).unwrap();
        let back: bool = decode(&enc).unwrap();
        assert!(back);
    }

    #[test]
    fn encode_null() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithNull {
            x: Option<u32>,
        }
        let v = WithNull { x: None };
        let enc = encode(&v).unwrap();
        let back: WithNull = decode(&enc).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn encode_nested_map() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Inner {
            z: u32,
            a: u32,
        }
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Outer {
            inner: Inner,
        }
        let v = Outer { inner: Inner { z: 1, a: 2 } };
        let enc = encode(&v).unwrap();
        let back: Outer = decode(&enc).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn encode_array() {
        let arr = vec![1u32, 2, 3];
        let enc = encode(&arr).unwrap();
        let back: Vec<u32> = decode(&enc).unwrap();
        assert_eq!(arr, back);
    }

    #[test]
    fn same_input_always_same_bytes() {
        let v = ZebraFirst { zebra: 7, apple: 8 };
        let enc1 = encode(&v).unwrap();
        let enc2 = encode(&v).unwrap();
        assert_eq!(enc1.as_slice(), enc2.as_slice());
    }

    #[test]
    fn encode_f64_number_round_trips() {
        // serde_json::Number can represent f64 values that are not i64.
        // This exercises the `if let Some(f) = n.as_f64()` branch in json_value_to_cbor.
        let v: f64 = std::f64::consts::PI;
        let enc = encode(&v).unwrap();
        let back: f64 = decode(&enc).unwrap();
        assert!((back - std::f64::consts::PI).abs() < 1e-10);
    }

    #[test]
    fn canonical_key_order_with_non_map_root_array() {
        // Exercises the Value::Array arm of sort_map_keys with nested maps.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Item {
            zebra: u32,
            a: u32,
        }
        let items = vec![Item { zebra: 1, a: 2 }, Item { zebra: 3, a: 4 }];
        let enc = encode(&items).unwrap();
        let decoded: Value = ciborium::from_reader(enc.as_slice()).unwrap();
        // The root should be an array, not a map.
        assert!(matches!(decoded, Value::Array(_)));
        let back: Vec<Item> = decode(&enc).unwrap();
        assert_eq!(back, items);
    }

    #[test]
    fn encode_string_value_round_trips() {
        // Exercises the J::String arm in json_value_to_cbor when a string appears as a value.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithString {
            label: String,
        }
        let v = WithString { label: "hello".to_owned() };
        let enc = encode(&v).unwrap();
        let back: WithString = decode(&enc).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn canonical_key_order_test_is_a_map() {
        // Verify the existing canonical_key_order_is_by_length_then_lex test path:
        // when the decoded value IS a map, the panic branch is not taken.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Multi {
            zebra: u32,
            apple: u32,
            a: u32,
        }
        let m = Multi { zebra: 1, apple: 2, a: 3 };
        let encoded = encode(&m).unwrap();
        let decoded: Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        // Must be a map — otherwise the test would panic.
        assert!(matches!(decoded, Value::Map(_)));
    }

    #[test]
    fn decode_rejects_invalid_cbor() {
        let bad = CanonicalBytes::from_vec(vec![0xFF, 0x00, 0x01]);
        let result: Result<u32, _> = decode(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn encode_propagates_serialize_errors() {
        struct Boom;
        impl Serialize for Boom {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        let err = encode(&Boom).unwrap_err();
        assert!(err.to_string().contains("boom") || matches!(err, CoreError::Serialization(_)));
    }
}
