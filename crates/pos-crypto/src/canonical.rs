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
/// Returns [`CoreError::Serialization`] if the value cannot be serialized to JSON.
///
/// # Panics
/// Panics only if writing a `ciborium::Value` into an in-memory `Vec<u8>` fails, which
/// is not expected for well-formed values.
pub fn encode<T: Serialize>(value: &T) -> Result<CanonicalBytes, CoreError> {
    // Branching lives in non-generic `encode_result` so each `T` monomorphization
    // does not leave an uncovered Ok/Err arm.
    encode_result(serde_json::to_value(value))
}

fn encode_result(
    json: Result<serde_json::Value, serde_json::Error>,
) -> Result<CanonicalBytes, CoreError> {
    match json {
        Ok(value) => Ok(encode_json(value)),
        Err(error) => Err(CoreError::Serialization(error.to_string())),
    }
}

/// Non-generic encode path so map/array helpers are not re-monomorphized per `T`.
fn encode_json(json: serde_json::Value) -> CanonicalBytes {
    let sorted = sort_map_keys(json_value_to_cbor(json));
    let mut buf = Vec::new();
    ciborium::into_writer(&sorted, &mut buf).expect("CBOR encode to Vec is infallible");
    CanonicalBytes::from_vec(buf)
}

/// Decode canonical CBOR bytes back to `T`.
///
/// # Errors
/// Returns [`CoreError::Serialization`] if the bytes cannot be decoded into `T`.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &CanonicalBytes) -> Result<T, CoreError> {
    // Prefer decoding through a single monomorphization in tests (`serde_json::Value`)
    // so Ok/Err arms are not left uncovered per struct type.
    match ciborium::from_reader(bytes.as_slice()) {
        Ok(value) => Ok(value),
        Err(error) => Err(CoreError::Serialization(error.to_string())),
    }
}

/// Total conversion: every `serde_json::Value` maps to a CBOR `Value`.
fn json_value_to_cbor(json: serde_json::Value) -> Value {
    use serde_json::Value as J;
    match json {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else {
                // serde_json::Number always has an f64 view when it is not an i64.
                Value::Float(n.as_f64().unwrap())
            }
        }
        J::String(s) => Value::Text(s),
        J::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(json_value_to_cbor(item));
            }
            Value::Array(out)
        }
        J::Object(map) => {
            let mut pairs = Vec::with_capacity(map.len());
            for (k, v) in map {
                pairs.push((Value::Text(k), json_value_to_cbor(v)));
            }
            Value::Map(pairs)
        }
    }
}

/// Sort map keys recursively per RFC 8949 §4.2.1: sort by (`key_length`, `key_bytes`) ascending.
fn sort_map_keys(value: Value) -> Value {
    match value {
        Value::Map(mut pairs) => {
            pairs.sort_by(|(a, _), (b, _)| compare_cbor_keys(a, b));
            let mut sorted = Vec::with_capacity(pairs.len());
            for (k, v) in pairs {
                sorted.push((k, sort_map_keys(v)));
            }
            Value::Map(sorted)
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(sort_map_keys(item));
            }
            Value::Array(out)
        }
        other => other,
    }
}

fn compare_cbor_keys(a: &Value, b: &Value) -> std::cmp::Ordering {
    let a_bytes = cbor_key_bytes(a);
    let b_bytes = cbor_key_bytes(b);
    match a_bytes.len().cmp(&b_bytes.len()) {
        std::cmp::Ordering::Equal => a_bytes.cmp(&b_bytes),
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
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_key_order_is_by_length_then_lex() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Multi {
            zebra: u32,
            apple: u32,
            a: u32,
        }
        let m = Multi {
            zebra: 1,
            apple: 2,
            a: 3,
        };
        let encoded = encode(&m).unwrap();
        let decoded: Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let Value::Map(pairs) = decoded else {
            unreachable!("struct encodes as CBOR map")
        };
        let keys: Vec<&str> = pairs
            .iter()
            .map(|(k, _)| {
                if let Value::Text(s) = k {
                    s.as_str()
                } else {
                    ""
                }
            })
            .collect();
        assert_eq!(keys, vec!["a", "apple", "zebra"]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_decode_round_trip() {
        let zf = ZebraFirst {
            zebra: 42,
            apple: 99,
        };
        let encoded = encode(&zf).unwrap();
        let decoded: serde_json::Value = decode(&encoded).unwrap();
        let back: ZebraFirst = serde_json::from_value(decoded).unwrap();
        assert_eq!(zf, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_bool() {
        let b = true;
        let enc = encode(&b).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        assert_eq!(back, serde_json::Value::Bool(true));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_null() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithNull {
            x: Option<u32>,
        }
        let v = WithNull { x: None };
        let enc = encode(&v).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: WithNull = serde_json::from_value(back).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
        let v = Outer {
            inner: Inner { z: 1, a: 2 },
        };
        let enc = encode(&v).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: Outer = serde_json::from_value(back).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_array() {
        let arr = vec![1u32, 2, 3];
        let enc = encode(&arr).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: Vec<u32> = serde_json::from_value(back).unwrap();
        assert_eq!(arr, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn same_input_always_same_bytes() {
        let v = ZebraFirst { zebra: 7, apple: 8 };
        let enc1 = encode(&v).unwrap();
        let enc2 = encode(&v).unwrap();
        assert_eq!(enc1.as_slice(), enc2.as_slice());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_f64_number_round_trips() {
        let v: f64 = std::f64::consts::PI;
        let enc = encode(&v).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back = back.as_f64().unwrap();
        assert!((back - std::f64::consts::PI).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_float_values_with_struct() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithFloat {
            value: f64,
            small: f32,
            fraction: f64,
        }
        let v = WithFloat {
            value: 1.5,
            small: 2.7f32,
            fraction: 0.123_456_789,
        };
        let enc = encode(&v).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: WithFloat = serde_json::from_value(back).unwrap();
        assert!((back.value - v.value).abs() < f64::EPSILON);
        assert!((back.small - v.small).abs() < f32::EPSILON);
        assert!((back.fraction - v.fraction).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_large_float_values() {
        #[derive(Serialize, Deserialize, Debug)]
        struct LargeFloats {
            very_large: f64,
            very_small: f64,
            large_negative: f64,
        }
        let v = LargeFloats {
            very_large: f64::MAX,
            very_small: f64::MIN_POSITIVE,
            large_negative: -1e100,
        };
        let enc = encode(&v).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: LargeFloats = serde_json::from_value(back).unwrap();
        assert!((back.very_large - v.very_large).abs() < f64::EPSILON);
        assert!((back.very_small - v.very_small).abs() < f64::EPSILON);
        assert!((back.large_negative - v.large_negative).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_key_order_with_non_map_root_array() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Item {
            zebra: u32,
            a: u32,
        }
        let items = vec![Item { zebra: 1, a: 2 }, Item { zebra: 3, a: 4 }];
        let enc = encode(&items).unwrap();
        let decoded: Value = ciborium::from_reader(enc.as_slice()).unwrap();
        assert!(matches!(decoded, Value::Array(_)));
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: Vec<Item> = serde_json::from_value(back).unwrap();
        assert_eq!(back, items);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_string_value_round_trips() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithString {
            label: String,
        }
        let v = WithString {
            label: "hello".to_owned(),
        };
        let enc = encode(&v).unwrap();
        let back: serde_json::Value = decode(&enc).unwrap();
        let back: WithString = serde_json::from_value(back).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_key_order_test_is_a_map() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Multi {
            zebra: u32,
            apple: u32,
            a: u32,
        }
        let m = Multi {
            zebra: 1,
            apple: 2,
            a: 3,
        };
        let encoded = encode(&m).unwrap();
        let decoded: Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert!(matches!(decoded, Value::Map(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_rejects_invalid_cbor() {
        let bad = CanonicalBytes::from_vec(vec![0xFF, 0x00, 0x01]);
        let result: Result<serde_json::Value, _> = decode(&bad);
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sort_map_keys_orders_by_length_then_lex() {
        let map = Value::Map(vec![
            (Value::Text("zebra".to_owned()), Value::Integer(1.into())),
            (Value::Text("apple".to_owned()), Value::Integer(2.into())),
            (Value::Text("a".to_owned()), Value::Integer(3.into())),
        ]);
        let sorted = sort_map_keys(map);
        let Value::Map(pairs) = sorted else {
            panic!("expected map");
        };
        let keys: Vec<&str> = pairs
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Text(s) = k {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec!["a", "apple", "zebra"]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_cbor_keys_covers_all_orderings() {
        let short = Value::Text("a".to_owned());
        let long = Value::Text("apple".to_owned());
        let later = Value::Text("zebra".to_owned());
        let earlier = Value::Text("apple".to_owned());
        assert_eq!(compare_cbor_keys(&short, &long), std::cmp::Ordering::Less);
        assert_eq!(
            compare_cbor_keys(&long, &short),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_cbor_keys(&earlier, &later),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
