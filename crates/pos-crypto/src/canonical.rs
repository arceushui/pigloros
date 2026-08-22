//! Canonical CBOR encoding: RFC 8949 §4.2.1 deterministic profile.
//!
//! `ciborium::into_writer` on serde-derived types does NOT produce canonical CBOR
//! because it preserves struct field declaration order (not sorted by key length/lex).
//! This module produces canonical CBOR by going through `ciborium::Value` and
//! sorting map keys before serialization.

use ciborium::value::Value;
use pos_core::{CanonicalBytes, CoreError};
use serde::Serialize;
use std::io::Write;

/// Encode `value` as canonical (deterministic) CBOR bytes.
///
/// Canonical means: map keys are sorted by (byte-length, lexicographic) order per RFC 8949 §4.2.1.
/// This is required for the hash chain to be tamper-evident regardless of struct field order.
///
/// # Errors
/// Returns [`CoreError::CanonicalCborSerialization`] if the value cannot be
/// converted to JSON or written as CBOR, or
/// [`CoreError::CanonicalCborNumericConversion`] if a JSON number cannot be
/// represented as CBOR.
pub fn encode<T: Serialize>(value: &T) -> Result<CanonicalBytes, CoreError> {
    // Branching lives in non-generic `encode_result` so each `T` monomorphization
    // does not leave an uncovered Ok/Err arm.
    encode_result(serde_json::to_value(value))
}

fn encode_result(
    json: Result<serde_json::Value, serde_json::Error>,
) -> Result<CanonicalBytes, CoreError> {
    match json {
        Ok(value) => encode_json(value),
        Err(error) => Err(CoreError::CanonicalCborSerialization(error.to_string())),
    }
}

/// Non-generic encode path so map/array helpers are not re-monomorphized per `T`.
fn encode_json(json: serde_json::Value) -> Result<CanonicalBytes, CoreError> {
    json_value_to_cbor(json)
        .and_then(sort_map_keys)
        .and_then(|sorted| {
            let mut buf = Vec::new();
            write_cbor(&sorted, &mut buf).map(|()| CanonicalBytes::from_vec(buf))
        })
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

/// Convert a JSON value into its CBOR representation.
fn json_value_to_cbor(json: serde_json::Value) -> Result<Value, CoreError> {
    use serde_json::Value as J;
    match json {
        J::Null => Ok(Value::Null),
        J::Bool(b) => Ok(Value::Bool(b)),
        J::Number(n) => n.as_i64().map_or_else(
            || {
                n.as_u64().map_or_else(
                    || cbor_float(n.as_f64()),
                    |value| Ok(Value::Integer(value.into())),
                )
            },
            |value| Ok(Value::Integer(value.into())),
        ),
        J::String(s) => Ok(Value::Text(s)),
        J::Array(items) => items
            .into_iter()
            .map(json_value_to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        J::Object(map) => map
            .into_iter()
            .map(|(key, value)| json_value_to_cbor(value).map(|value| (Value::Text(key), value)))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Map),
    }
}

fn cbor_float(value: Option<f64>) -> Result<Value, CoreError> {
    value.map_or_else(
        || Err(CoreError::CanonicalCborNumericConversion),
        |value| Ok(Value::Float(value)),
    )
}

/// Sort map keys recursively per RFC 8949 §4.2.1: sort by (`key_length`, `key_bytes`) ascending.
fn sort_map_keys(value: Value) -> Result<Value, CoreError> {
    match value {
        Value::Map(pairs) => pairs
            .into_iter()
            .map(|(key, value)| {
                cbor_key_bytes(&key)
                    .and_then(|key_bytes| sort_map_keys(value).map(|value| (key_bytes, key, value)))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|mut sortable| {
                sortable.sort_by(|(a_bytes, _, _), (b_bytes, _, _)| {
                    compare_cbor_key_bytes(a_bytes, b_bytes)
                });
                Value::Map(
                    sortable
                        .into_iter()
                        .map(|(_, key, value)| (key, value))
                        .collect(),
                )
            }),
        Value::Array(items) => items
            .into_iter()
            .map(sort_map_keys)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => Ok(other),
    }
}

fn compare_cbor_key_bytes(a_bytes: &[u8], b_bytes: &[u8]) -> std::cmp::Ordering {
    match a_bytes.len().cmp(&b_bytes.len()) {
        std::cmp::Ordering::Equal => a_bytes.cmp(b_bytes),
        other => other,
    }
}

/// Get the canonical CBOR encoding of a map key for sorting purposes.
fn cbor_key_bytes(key: &Value) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::new();
    write_cbor(key, &mut buf).map(|()| buf)
}

fn write_cbor<W: Write>(value: &Value, writer: W) -> Result<(), CoreError> {
    ciborium::into_writer(value, writer)
        .map_err(|error| CoreError::CanonicalCborSerialization(error.to_string()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::fmt::Debug;

    trait TestResultExt<T, E> {
        fn test_err(self) -> Result<E, Box<dyn std::error::Error>>;
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
    }

    impl<T, E: Debug> TestResultExt<T, E> for Result<T, E> {
        fn test_err(self) -> Result<E, Box<dyn std::error::Error>> {
            self.err().ok_or_else(|| "expected an error".into())
        }

        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
            self.map_err(|error| format!("unexpected error: {error:?}").into())
        }
    }

    trait TestOptionExt<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
    }

    impl<T> TestOptionExt<T> for Option<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
            self.ok_or_else(|| "expected a value".into())
        }
    }
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
    fn canonical_cbor_is_same_regardless_of_field_declaration_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let zebra_first = ZebraFirst { zebra: 1, apple: 2 };
        let apple_first = AppleFirst { apple: 2, zebra: 1 };
        let encoded_zebra = encode(&zebra_first).test_ok()?;
        let encoded_apple = encode(&apple_first).test_ok()?;
        assert_eq!(
            encoded_zebra.as_slice(),
            encoded_apple.as_slice(),
            "canonical CBOR must be identical regardless of struct field order"
        );

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_key_order_is_by_length_then_lex() -> Result<(), Box<dyn std::error::Error>> {
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
        let encoded = encode(&m).test_ok()?;
        let decoded: Value = ciborium::from_reader(encoded.as_slice()).test_ok()?;
        let Value::Map(pairs) = decoded else {
            return Err("struct encodes as CBOR map".into());
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

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_decode_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let zf = ZebraFirst {
            zebra: 42,
            apple: 99,
        };
        let encoded = encode(&zf).test_ok()?;
        let decoded: serde_json::Value = decode(&encoded).test_ok()?;
        let back: ZebraFirst = serde_json::from_value(decoded).test_ok()?;
        assert_eq!(zf, back);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_bool() -> Result<(), Box<dyn std::error::Error>> {
        let b = true;
        let enc = encode(&b).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        assert_eq!(back, serde_json::Value::Bool(true));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_null() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithNull {
            x: Option<u32>,
        }
        let v = WithNull { x: None };
        let enc = encode(&v).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: WithNull = serde_json::from_value(back).test_ok()?;
        assert_eq!(v, back);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_nested_map() -> Result<(), Box<dyn std::error::Error>> {
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
        let enc = encode(&v).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: Outer = serde_json::from_value(back).test_ok()?;
        assert_eq!(v, back);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_array() -> Result<(), Box<dyn std::error::Error>> {
        let arr = vec![1u32, 2, 3];
        let enc = encode(&arr).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: Vec<u32> = serde_json::from_value(back).test_ok()?;
        assert_eq!(arr, back);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn same_input_always_same_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let v = ZebraFirst { zebra: 7, apple: 8 };
        let enc1 = encode(&v).test_ok()?;
        let enc2 = encode(&v).test_ok()?;
        assert_eq!(enc1.as_slice(), enc2.as_slice());

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_f64_number_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let v: f64 = std::f64::consts::PI;
        let enc = encode(&v).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back = back.as_f64().test_ok()?;
        assert!((back - std::f64::consts::PI).abs() < 1e-10);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_float_values_with_struct() -> Result<(), Box<dyn std::error::Error>> {
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
        let enc = encode(&v).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: WithFloat = serde_json::from_value(back).test_ok()?;
        assert!((back.value - v.value).abs() < f64::EPSILON);
        assert!((back.small - v.small).abs() < f32::EPSILON);
        assert!((back.fraction - v.fraction).abs() < f64::EPSILON);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_large_float_values() -> Result<(), Box<dyn std::error::Error>> {
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
        let enc = encode(&v).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: LargeFloats = serde_json::from_value(back).test_ok()?;
        assert!((back.very_large - v.very_large).abs() < f64::EPSILON);
        assert!((back.very_small - v.very_small).abs() < f64::EPSILON);
        assert!((back.large_negative - v.large_negative).abs() < f64::EPSILON);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_key_order_with_non_map_root_array() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Item {
            zebra: u32,
            a: u32,
        }
        let items = vec![Item { zebra: 1, a: 2 }, Item { zebra: 3, a: 4 }];
        let enc = encode(&items).test_ok()?;
        let decoded: Value = ciborium::from_reader(enc.as_slice()).test_ok()?;
        assert!(matches!(decoded, Value::Array(_)));
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: Vec<Item> = serde_json::from_value(back).test_ok()?;
        assert_eq!(back, items);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_string_value_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct WithString {
            label: String,
        }
        let v = WithString {
            label: "hello".to_owned(),
        };
        let enc = encode(&v).test_ok()?;
        let back: serde_json::Value = decode(&enc).test_ok()?;
        let back: WithString = serde_json::from_value(back).test_ok()?;
        assert_eq!(v, back);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_key_order_test_is_a_map() -> Result<(), Box<dyn std::error::Error>> {
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
        let encoded = encode(&m).test_ok()?;
        let decoded: Value = ciborium::from_reader(encoded.as_slice()).test_ok()?;
        assert!(matches!(decoded, Value::Map(_)));

        Ok(())
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
    fn sort_map_keys_orders_by_length_then_lex() -> Result<(), Box<dyn std::error::Error>> {
        let map = Value::Map(vec![
            (Value::Text("zebra".to_owned()), Value::Integer(1.into())),
            (Value::Text("apple".to_owned()), Value::Integer(2.into())),
            (Value::Text("a".to_owned()), Value::Integer(3.into())),
        ]);
        let sorted = sort_map_keys(map).test_ok()?;
        let Value::Map(pairs) = sorted else {
            return Err("expected map".into());
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

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compare_cbor_key_bytes_covers_all_orderings() {
        assert_eq!(
            compare_cbor_key_bytes(b"a", b"apple"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_cbor_key_bytes(b"apple", b"a"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_cbor_key_bytes(b"apple", b"zebra"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn encode_propagates_serialize_errors() -> Result<(), Box<dyn std::error::Error>> {
        struct Boom;
        impl Serialize for Boom {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        let err = encode(&Boom).test_err()?;
        assert!(err.to_string().contains("boom"));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_cbor_rejects_missing_float_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let error = cbor_float(None).test_err()?;
        assert!(error.to_string().contains("numeric conversion"));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_cbor_preserves_large_unsigned_integers() -> Result<(), Box<dyn std::error::Error>>
    {
        let converted = json_value_to_cbor(serde_json::json!(u64::MAX)).test_ok()?;
        assert_eq!(converted, Value::Integer(u64::MAX.into()));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn canonical_cbor_surfaces_writer_failures() -> Result<(), Box<dyn std::error::Error>> {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("writer failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let error = write_cbor(&Value::Null, FailingWriter).test_err()?;
        assert!(error.to_string().contains("writer failed"));

        Ok(())
    }
}
