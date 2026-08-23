#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::value::Value;
use pos_conformance::{ConformanceProfileV1, EvaluatorRequestV1};

#[cfg_attr(coverage_nightly, coverage(off))]
mod fixtures {
    use super::*;

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    fn uint(value: u64) -> Value {
        Value::Integer(value.into())
    }

    fn bytes(seed: u8) -> Value {
        Value::Bytes(vec![seed; 32])
    }

    fn bytes16(seed: u8) -> Value {
        Value::Bytes(vec![seed; 16])
    }

    fn identity(seed: u8) -> Value {
        Value::Array(vec![
            text("external-implementation"),
            bytes(seed),
            bytes(seed.saturating_add(1)),
            bytes(seed.saturating_add(2)),
            bytes(7),
            Value::Null,
        ])
    }

    fn independence(seed: u8) -> Value {
        Value::Array(vec![
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            bytes(seed),
            bytes(seed.saturating_add(1)),
            Value::Array(vec![text("external-reviewer")]),
        ])
    }

    fn strict_case(seed: u8) -> Value {
        Value::Array(vec![
            text("ART-001"),
            bytes(seed),
            bytes(1),
            uint(0),
            uint(0),
            uint(0),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            uint(0),
            uint(0),
            bytes(2),
        ])
    }

    fn report(seed: u8) -> Value {
        Value::Array(vec![
            text("CNR1"),
            uint(1),
            bytes16(1),
            bytes(seed),
            bytes(seed.saturating_add(1)),
            bytes(12),
            bytes(1),
            bytes(3),
            bytes(4),
            bytes(5),
            bytes(13),
            identity(seed),
            independence(seed.saturating_add(2)),
            Value::Array(vec![strict_case(seed)]),
            uint(1),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            bytes(18),
            bytes(19),
            bytes(20),
        ])
    }

    fn case(seed: u8) -> Value {
        Value::Array(vec![
            text("ART-001"),
            bytes(seed),
            bytes(1),
            uint(0),
            uint(0),
            uint(0),
            uint(0),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            uint(0),
            uint(0),
            bytes(2),
            uint(0),
            uint(0),
        ])
    }

    fn fixture() -> Value {
        Value::Array(vec![
            text("ART-001"),
            Value::Bool(true),
            uint(0),
            bytes(1),
            bytes(2),
            Value::Array(vec![uint(0), uint(1)]),
            uint(0),
            Value::Array(vec![Value::Array(vec![
                text("fixture.json"),
                uint(1),
                bytes(3),
                bytes(4),
            ])]),
            Value::Array(vec![
                uint(0),
                Value::Bytes(vec![1]),
                bytes(5),
                Value::Null,
                Value::Null,
            ]),
            uint(0),
            Value::Null,
            uint(0),
            uint(0),
            Value::Array(vec![
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
                uint(1),
            ]),
            Value::Array(vec![
                Value::Bool(false),
                Value::Array(vec![text("read-public-bundle")]),
            ]),
            Value::Array(vec![
                text("MIT"),
                bytes(6),
                bytes(7),
                bytes(8),
                bytes(9),
                bytes(10),
                bytes(11),
            ]),
            bytes(12),
        ])
    }

    fn protocol() -> Value {
        Value::Array(vec![
            text("pigloros.evaluator.v1"),
            bytes(13),
            bytes(14),
            bytes(15),
            Value::Array(vec![
                uint(16_777_216),
                uint(65_536),
                uint(65_536),
                uint(256),
                uint(1_073_741_824),
                uint(1_073_741_824),
                uint(100),
                uint(32),
                uint(128),
                uint(1_048_576),
            ]),
        ])
    }

    fn requirements() -> Value {
        Value::Array(vec![
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            bytes(16),
            bytes(17),
        ])
    }

    fn stable_evidence() -> Value {
        Value::Array(vec![
            identity(30),
            independence(34),
            bytes(13),
            report(30),
            Value::Array(vec![case(30)]),
            Value::Array(vec![bytes(31), Value::Bytes(vec![1; 64]), bytes(32)]),
        ])
    }

    pub(super) fn encode(value: Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap_or_default();
        bytes
    }

    pub(super) fn profile(lifecycle: u64, with_stable_evidence: bool) -> Vec<u8> {
        encode(Value::Array(vec![
            text("CPF1"),
            uint(1),
            text("pigloros.w8.external"),
            text("1.0.0"),
            uint(lifecycle),
            bytes(12),
            Value::Array(vec![bytes(1)]),
            Value::Array(vec![bytes(2)]),
            Value::Array(vec![fixture()]),
            Value::Array(vec![Value::Array(vec![uint(0), bytes(99)])]),
            protocol(),
            requirements(),
            bytes(17),
            bytes(18),
            bytes(19),
            Value::Null,
            if with_stable_evidence {
                Value::Array(vec![stable_evidence()])
            } else {
                Value::Array(vec![])
            },
            bytes(20),
        ]))
    }

    pub(super) fn request() -> Vec<u8> {
        encode(Value::Array(vec![
            text("EVR1"),
            uint(1),
            bytes16(1),
            bytes(1),
            bytes(2),
            uint(0),
            bytes(3),
            identity(4),
            bytes(1),
            bytes(5),
            Value::Array(vec![bytes(6), uint(1), uint(1)]),
            bytes(13),
            bytes(14),
            bytes(15),
        ]))
    }
}

#[test]
fn exported_profile_and_request_decoders_cover_nested_public_shapes() {
    assert!(ConformanceProfileV1::from_canonical_cbor(&fixtures::profile(0, false)).is_err());
    assert!(ConformanceProfileV1::from_canonical_cbor(&fixtures::profile(2, true)).is_err());
    assert!(EvaluatorRequestV1::from_canonical_cbor(&fixtures::request()).is_err());
}
