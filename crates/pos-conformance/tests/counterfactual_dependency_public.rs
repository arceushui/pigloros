#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-064 IDP1 input-dependency contract.

use ciborium::value::Value;
use pos_conformance::counterfactual::dependency::{
    validate_input_dependency_order_v1, DependencyClassificationRuleV1, DependencyTickRangeV1,
    InputDependencyContractErrorV1, InputDependencyV1, INPUT_DEPENDENCY_MAGIC_V1,
    MAX_DEPENDENCY_OWNER_ID_BYTES_V1, MAX_INPUT_DEPENDENCY_BYTES_V1,
};
use pos_conformance::{DependencyClassV1, DependencyNodeV1};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type ErrorV1 = InputDependencyContractErrorV1;

const ABOVE_U32: u64 = 1 << 32;

fn node(
    tick: u64,
    scheduler_position: u32,
    owner_id: &str,
    output_ordinal: u32,
    digest: u8,
) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick,
        scheduler_position,
        owner_id: owner_id.to_owned(),
        output_ordinal,
        schema_id: 7,
        artifact_digest: [digest; 32],
    }
}

fn rule() -> DependencyClassificationRuleV1 {
    DependencyClassificationRuleV1 {
        rule_id: "adr064.classification".to_owned(),
        rule_version: 1,
    }
}

fn dependency() -> InputDependencyV1 {
    InputDependencyV1 {
        consumer: node(5, 2, "agent-b", 1, 0x22),
        source: node(3, 1, "world", 0, 0x11),
        dependency_class: DependencyClassV1::EndogenousRecomputed,
        tick_range: DependencyTickRangeV1 {
            first_tick: 3,
            last_tick: 5,
        },
        authorization_digest: [0x33; 32],
        classification_rule: rule(),
        provenance_digest: [0x44; 32],
    }
}

fn with(change: impl FnOnce(&mut InputDependencyV1)) -> InputDependencyV1 {
    let mut candidate = dependency();
    change(&mut candidate);
    candidate
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn digest(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode_node(node: &DependencyNodeV1) -> Value {
    Value::Array(vec![
        uint(node.tick),
        uint(u64::from(node.scheduler_position)),
        text(&node.owner_id),
        uint(u64::from(node.output_ordinal)),
        uint(u64::from(node.schema_id)),
        digest(&node.artifact_digest),
    ])
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn canonical_fields() -> TestResult<Vec<Value>> {
    let bytes = dependency().to_canonical_cbor()?;
    match ciborium::from_reader::<Value, _>(bytes.as_slice())? {
        Value::Array(fields) => Ok(fields),
        _ => Err("IDP1 must be represented by a CBOR array".into()),
    }
}

fn with_field(index: usize, replacement: Value) -> TestResult<Vec<u8>> {
    let mut fields = canonical_fields()?;
    let field = fields.get_mut(index).ok_or("IDP1 field is absent")?;
    *field = replacement;
    encode_value(&Value::Array(fields))
}

fn with_nested(index: usize, nested: usize, replacement: Value) -> TestResult<Vec<u8>> {
    let mut fields = canonical_fields()?;
    let Some(Value::Array(values)) = fields.get_mut(index) else {
        return Err("IDP1 field is not an array".into());
    };
    let value = values
        .get_mut(nested)
        .ok_or("IDP1 nested field is absent")?;
    *value = replacement;
    encode_value(&Value::Array(fields))
}

fn assert_decode_error(bytes: &[u8], expected: ErrorV1, case: &str) {
    assert_eq!(
        InputDependencyV1::from_canonical_cbor(bytes),
        Err(expected),
        "case {case}"
    );
}

#[test]
fn canonical_codec_emits_the_exact_nine_field_wire_layout() -> TestResult {
    let dependency = dependency();
    let expected = encode_value(&Value::Array(vec![
        text("IDP1"),
        uint(1),
        encode_node(&dependency.consumer),
        encode_node(&dependency.source),
        uint(2),
        Value::Array(vec![uint(3), uint(5)]),
        digest(&[0x33; 32]),
        Value::Array(vec![text("adr064.classification"), uint(1)]),
        digest(&[0x44; 32]),
    ]))?;

    assert_eq!(INPUT_DEPENDENCY_MAGIC_V1, "IDP1");
    assert_eq!(MAX_INPUT_DEPENDENCY_BYTES_V1, 16 * 1024);
    assert_eq!(dependency.validate(), Ok(()));
    assert_eq!(dependency.to_canonical_cbor()?, expected);
    assert_eq!(
        InputDependencyV1::from_canonical_cbor(&expected)?,
        dependency
    );
    Ok(())
}

#[test]
fn every_closed_dependency_class_roundtrips_with_its_code() -> TestResult {
    let classes = [
        (DependencyClassV1::ExogenousFrozen, 0),
        (DependencyClassV1::InterventionAssigned, 1),
        (DependencyClassV1::EndogenousRecomputed, 2),
        (DependencyClassV1::FixedPolicy, 3),
        (DependencyClassV1::PresentationOnly, 4),
    ];
    for (class, code) in classes {
        let candidate = with(|value| value.dependency_class = class);
        let bytes = candidate.to_canonical_cbor()?;
        assert_eq!(bytes, with_field(4, uint(code))?);
        assert_eq!(InputDependencyV1::from_canonical_cbor(&bytes)?, candidate);
    }
    for code in [5, u64::MAX] {
        assert_decode_error(&with_field(4, uint(code))?, ErrorV1::UnknownEnum, "class");
    }
    Ok(())
}

#[test]
fn public_wire_code_table_is_the_closed_class_order() {
    for (index, class) in DependencyClassV1::ALL_V1.into_iter().enumerate() {
        assert_eq!(usize::from(class.wire_code()), index);
        assert_eq!(
            DependencyClassV1::from_wire_code(u64::from(class.wire_code())),
            Some(class)
        );
    }
    assert_eq!(DependencyClassV1::PresentationOnly.wire_code(), 4);
    for code in [5, u64::MAX] {
        assert_eq!(DependencyClassV1::from_wire_code(code), None);
    }
}

#[test]
fn public_node_coordinate_helpers_match_the_idp1_rules() {
    let valid = node(5, 2, "agent-b", 1, 0x22);
    assert_eq!(valid.coordinate_key(), (5, 2, "agent-b", 1));
    assert!(valid.is_valid_coordinate());
    assert_eq!(MAX_DEPENDENCY_OWNER_ID_BYTES_V1, 128);
    let longest = node(5, 2, &"o".repeat(128), 1, 0x22);
    assert!(longest.is_valid_coordinate());
    let invalid: [fn(&mut DependencyNodeV1); 4] = [
        |value| value.owner_id = String::new(),
        |value| value.owner_id = "o".repeat(129),
        |value| value.schema_id = 0,
        |value| value.artifact_digest = [0; 32],
    ];
    for change in invalid {
        let mut candidate = valid.clone();
        change(&mut candidate);
        assert!(!candidate.is_valid_coordinate());
    }
}

#[test]
fn digest_is_domain_separated_over_the_canonical_bytes() -> TestResult {
    let dependency = dependency();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.InputDependency.v1\0");
    hasher.update(&dependency.to_canonical_cbor()?);
    assert_eq!(dependency.digest()?, *hasher.finalize().as_bytes());
    assert_eq!(
        with(|value| value.provenance_digest = [0; 32]).digest(),
        Err(ErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn digest_is_sensitive_to_every_bound_field() -> TestResult {
    let variants = [
        with(|value| {
            value.consumer.tick = 6;
            value.tick_range.last_tick = 6;
        }),
        with(|value| value.consumer.scheduler_position = 3),
        with(|value| value.consumer.owner_id = "agent-c".to_owned()),
        with(|value| value.consumer.output_ordinal = 2),
        with(|value| value.consumer.schema_id = 8),
        with(|value| value.consumer.artifact_digest = [0x23; 32]),
        with(|value| {
            value.source.tick = 2;
            value.tick_range.first_tick = 2;
        }),
        with(|value| value.source.scheduler_position = 2),
        with(|value| value.source.owner_id = "world-b".to_owned()),
        with(|value| value.source.output_ordinal = 1),
        with(|value| value.source.schema_id = 8),
        with(|value| value.source.artifact_digest = [0x12; 32]),
        with(|value| value.dependency_class = DependencyClassV1::FixedPolicy),
        with(|value| value.tick_range.first_tick = 0),
        with(|value| value.tick_range.last_tick = 9),
        with(|value| value.authorization_digest = [0x34; 32]),
        with(|value| value.classification_rule.rule_id = "adr064.other".to_owned()),
        with(|value| value.classification_rule.rule_version = 2),
        with(|value| value.provenance_digest = [0x45; 32]),
    ];
    let mut digests = BTreeSet::from([dependency().digest()?]);
    for variant in &variants {
        assert!(digests.insert(variant.digest()?), "variant {variant:?}");
        assert_eq!(
            InputDependencyV1::from_canonical_cbor(&variant.to_canonical_cbor()?)?,
            *variant
        );
    }
    assert_eq!(digests.len(), variants.len() + 1);
    Ok(())
}

#[test]
fn every_bounded_field_is_rejected_independently() {
    let owner_129 = "o".repeat(129);
    let rule_129 = "r".repeat(129);
    let cases = [
        (
            "empty consumer owner",
            with(|v| v.consumer.owner_id.clear()),
        ),
        ("empty source owner", with(|v| v.source.owner_id.clear())),
        (
            "long consumer owner",
            with(|v| v.consumer.owner_id.clone_from(&owner_129)),
        ),
        (
            "long source owner",
            with(|v| v.source.owner_id.clone_from(&owner_129)),
        ),
        ("consumer schema", with(|v| v.consumer.schema_id = 0)),
        ("source schema", with(|v| v.source.schema_id = 0)),
        (
            "consumer digest",
            with(|v| v.consumer.artifact_digest = [0; 32]),
        ),
        (
            "source digest",
            with(|v| v.source.artifact_digest = [0; 32]),
        ),
        ("range after source", with(|v| v.tick_range.first_tick = 4)),
        (
            "range before consumer",
            with(|v| v.tick_range.last_tick = 4),
        ),
        ("authorization", with(|v| v.authorization_digest = [0; 32])),
        (
            "empty rule",
            with(|v| v.classification_rule.rule_id.clear()),
        ),
        (
            "uppercase rule",
            with(|v| v.classification_rule.rule_id = "Rule".to_owned()),
        ),
        (
            "long rule",
            with(|v| v.classification_rule.rule_id.clone_from(&rule_129)),
        ),
        (
            "rule version",
            with(|v| v.classification_rule.rule_version = 0),
        ),
        ("provenance", with(|v| v.provenance_digest = [0; 32])),
    ];
    for (case, candidate) in cases {
        assert_eq!(
            candidate.validate(),
            Err(ErrorV1::FieldOutOfBounds),
            "{case}"
        );
        assert_eq!(
            candidate.to_canonical_cbor(),
            Err(ErrorV1::FieldOutOfBounds),
            "{case}"
        );
    }
}

#[test]
fn exact_limits_and_loose_ranges_are_accepted() -> TestResult {
    let owner_128 = "o".repeat(128);
    let rule_128 = "r".repeat(128);
    let accepted = [
        with(|v| v.consumer.owner_id.clone_from(&owner_128)),
        with(|v| v.source.owner_id.clone_from(&owner_128)),
        with(|v| v.classification_rule.rule_id.clone_from(&rule_128)),
        with(|v| v.classification_rule.rule_version = u32::MAX),
        with(|v| {
            v.consumer.scheduler_position = u32::MAX;
            v.consumer.output_ordinal = u32::MAX;
            v.consumer.schema_id = u32::MAX;
        }),
        with(|v| {
            v.tick_range.first_tick = 0;
            v.tick_range.last_tick = u64::MAX;
        }),
    ];
    for candidate in accepted {
        let bytes = candidate.to_canonical_cbor()?;
        assert_eq!(InputDependencyV1::from_canonical_cbor(&bytes)?, candidate);
    }
    Ok(())
}

#[test]
fn source_must_strictly_precede_consumer_coordinate() {
    let cover = |v: &mut InputDependencyV1| {
        v.tick_range.first_tick = 0;
        v.tick_range.last_tick = 9;
    };
    let rejected = [
        ("same slot", node(5, 2, "agent-b", 1, 0x55)),
        ("later tick", node(6, 0, "agent-a", 0, 0x55)),
        ("later scheduler position", node(5, 3, "agent-a", 0, 0x55)),
        ("later owner bytes", node(5, 2, "agent-c", 0, 0x55)),
        ("later output ordinal", node(5, 2, "agent-b", 2, 0x55)),
    ];
    for (case, source) in rejected {
        let candidate = with(|v| {
            cover(v);
            v.source = source;
        });
        assert_eq!(
            candidate.validate(),
            Err(ErrorV1::NonCanonicalOrder),
            "{case}"
        );
    }
    let accepted = [
        node(5, 2, "agent-b", 0, 0x55),
        node(5, 2, "agent-a", 9, 0x55),
        node(5, 1, "agent-z", 9, 0x55),
        node(4, 9, "agent-z", 9, 0x55),
    ];
    for source in accepted {
        let candidate = with(|v| {
            cover(v);
            v.source = source;
        });
        assert_eq!(candidate.validate(), Ok(()), "{candidate:?}");
    }
}

#[test]
fn decoded_records_are_validated_after_shape_checks() -> TestResult {
    assert_decode_error(
        &with_field(8, digest(&[0; 32]))?,
        ErrorV1::FieldOutOfBounds,
        "zero provenance",
    );
    assert_decode_error(
        &with_field(3, encode_node(&node(5, 2, "agent-b", 1, 0x55)))?,
        ErrorV1::NonCanonicalOrder,
        "source at consumer slot",
    );
    Ok(())
}

#[test]
fn size_and_framing_are_rejected_before_decoding() -> TestResult {
    let bytes = dependency().to_canonical_cbor()?;
    assert_decode_error(
        &vec![0; MAX_INPUT_DEPENDENCY_BYTES_V1 + 1],
        ErrorV1::FieldOutOfBounds,
        "limit plus one",
    );
    assert_decode_error(
        &vec![0; MAX_INPUT_DEPENDENCY_BYTES_V1],
        ErrorV1::InvalidEncoding,
        "exact limit",
    );
    assert_decode_error(
        &bytes[..bytes.len() - 1],
        ErrorV1::InvalidEncoding,
        "truncated",
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_decode_error(&trailing, ErrorV1::InvalidEncoding, "trailing");
    assert_decode_error(&[0x9f, 0xff], ErrorV1::InvalidEncoding, "indefinite");
    assert_decode_error(&encode_value(&uint(1))?, ErrorV1::InvalidEncoding, "scalar");

    assert_eq!(&bytes[..7], &[0x89, 0x64, b'I', b'D', b'P', b'1', 0x01]);
    let mut long_integer = bytes[..6].to_vec();
    long_integer.extend_from_slice(&[0x18, 0x01]);
    long_integer.extend_from_slice(&bytes[7..]);
    assert_decode_error(&long_integer, ErrorV1::InvalidEncoding, "long integer");
    let mut invalid_utf8 = bytes;
    invalid_utf8[2..6].copy_from_slice(&[0xff; 4]);
    assert_decode_error(&invalid_utf8, ErrorV1::InvalidEncoding, "invalid utf-8");
    Ok(())
}

#[test]
fn array_lengths_depth_and_forbidden_types_are_rejected() -> TestResult {
    let mut fields = canonical_fields()?;
    fields.pop();
    assert_decode_error(
        &encode_value(&Value::Array(fields.clone()))?,
        ErrorV1::InvalidEncoding,
        "eight fields",
    );
    fields.extend([digest(&[0x44; 32]), uint(0)]);
    assert_decode_error(
        &encode_value(&Value::Array(fields))?,
        ErrorV1::FieldOutOfBounds,
        "ten fields",
    );
    let deep = Value::Array(vec![Value::Array(vec![text("x")]), uint(1)]);
    assert_decode_error(&with_field(7, deep)?, ErrorV1::FieldOutOfBounds, "depth");
    let forbidden = [
        ("map", Value::Map(Vec::new())),
        ("tag", Value::Tag(1, Box::new(uint(0)))),
        ("bool", Value::Bool(true)),
        ("null", Value::Null),
    ];
    for (case, value) in forbidden {
        assert_decode_error(&with_field(8, value)?, ErrorV1::InvalidEncoding, case);
    }
    Ok(())
}

#[test]
fn header_is_closed_to_other_magic_and_versions() -> TestResult {
    let unsupported = [(0, text("IDP2")), (1, uint(2)), (1, uint(0))];
    for (index, value) in unsupported {
        assert_decode_error(
            &with_field(index, value)?,
            ErrorV1::UnsupportedVersion,
            "header",
        );
    }
    let mut short = canonical_fields()?;
    short.truncate(5);
    for (index, value) in [(0, text("IDP2")), (1, uint(2))] {
        let mut future = short.clone();
        future[index] = value;
        assert_decode_error(
            &encode_value(&Value::Array(future))?,
            ErrorV1::UnsupportedVersion,
            "future header with another field count",
        );
    }
    assert_decode_error(
        &encode_value(&Value::Array(short))?,
        ErrorV1::InvalidEncoding,
        "supported header with a short field count",
    );
    let malformed = [
        (0, uint(1)),
        (1, text("1")),
        (1, Value::Integer((-1).into())),
    ];
    for (index, value) in malformed {
        assert_decode_error(
            &with_field(index, value)?,
            ErrorV1::InvalidEncoding,
            "header",
        );
    }
    Ok(())
}

#[test]
fn every_top_level_field_type_is_checked() -> TestResult {
    for index in 2..=8 {
        assert_decode_error(
            &with_field(index, text("x"))?,
            ErrorV1::InvalidEncoding,
            &format!("field {index}"),
        );
    }
    assert_decode_error(
        &with_field(6, Value::Bytes(vec![0x33; 31]))?,
        ErrorV1::InvalidEncoding,
        "short digest",
    );
    assert_decode_error(
        &with_field(8, Value::Bytes(vec![0x44; 33]))?,
        ErrorV1::InvalidEncoding,
        "long digest",
    );
    Ok(())
}

#[test]
fn every_node_field_type_and_width_is_checked() -> TestResult {
    for index in [2, 3] {
        for nested in 0..6 {
            let replacement = if nested == 2 { uint(1) } else { text("x") };
            assert_decode_error(
                &with_nested(index, nested, replacement)?,
                ErrorV1::InvalidEncoding,
                &format!("node {index}.{nested}"),
            );
        }
        for nested in [1, 3, 4] {
            assert_decode_error(
                &with_nested(index, nested, uint(ABOVE_U32))?,
                ErrorV1::FieldOutOfBounds,
                &format!("node {index}.{nested} width"),
            );
        }
        assert_decode_error(
            &with_field(index, Value::Array(vec![uint(1); 5]))?,
            ErrorV1::InvalidEncoding,
            "short node",
        );
    }
    Ok(())
}

#[test]
fn tick_range_and_rule_shapes_are_checked() -> TestResult {
    for nested in [0, 1] {
        assert_decode_error(
            &with_nested(5, nested, text("x"))?,
            ErrorV1::InvalidEncoding,
            "range",
        );
    }
    assert_decode_error(
        &with_field(5, Value::Array(vec![uint(3), uint(5), uint(7)]))?,
        ErrorV1::InvalidEncoding,
        "range length",
    );
    assert_decode_error(
        &with_nested(7, 0, uint(1))?,
        ErrorV1::InvalidEncoding,
        "rule id",
    );
    assert_decode_error(
        &with_nested(7, 1, text("1"))?,
        ErrorV1::InvalidEncoding,
        "rule version",
    );
    assert_decode_error(
        &with_nested(7, 1, uint(ABOVE_U32))?,
        ErrorV1::FieldOutOfBounds,
        "rule version width",
    );
    assert_decode_error(
        &with_field(7, Value::Array(vec![text("adr064.classification")]))?,
        ErrorV1::InvalidEncoding,
        "rule length",
    );
    Ok(())
}

#[test]
fn edge_lists_follow_the_canonical_consumer_and_source_order() {
    let base = dependency();
    let later = [
        with(|v| v.source.artifact_digest = [0x12; 32]),
        with(|v| v.consumer.output_ordinal = 2),
        with(|v| v.consumer.owner_id = "agent-c".to_owned()),
        with(|v| v.consumer.scheduler_position = 3),
        with(|v| {
            v.consumer.tick = 6;
            v.tick_range.last_tick = 6;
        }),
    ];
    assert_eq!(validate_input_dependency_order_v1(&[]), Ok(()));
    assert_eq!(
        validate_input_dependency_order_v1(std::slice::from_ref(&base)),
        Ok(())
    );
    for edge in &later {
        let ordered = [base.clone(), edge.clone()];
        let reversed = [edge.clone(), base.clone()];
        assert_eq!(validate_input_dependency_order_v1(&ordered), Ok(()));
        assert_eq!(
            validate_input_dependency_order_v1(&reversed),
            Err(ErrorV1::NonCanonicalOrder),
            "{edge:?}"
        );
    }
    let same_key = with(|v| v.consumer.artifact_digest = [0x99; 32]);
    assert_eq!(
        validate_input_dependency_order_v1(&[base.clone(), same_key]),
        Err(ErrorV1::DuplicateIdentity)
    );
    assert_eq!(
        validate_input_dependency_order_v1(&[base.clone(), later[0].clone(), base.clone()]),
        Err(ErrorV1::NonCanonicalOrder)
    );
    let invalid = with(|v| v.provenance_digest = [0; 32]);
    assert_eq!(
        validate_input_dependency_order_v1(&[base, invalid]),
        Err(ErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn proof_evidence_converts_only_through_the_explicit_rule() {
    let expected = dependency();
    let evidence = pos_conformance::InputDependencyV1 {
        consumer: expected.consumer.clone(),
        source: expected.source.clone(),
        dependency_class: expected.dependency_class,
        authorization_digest: expected.authorization_digest,
        provenance_digest: expected.provenance_digest,
    };
    assert_eq!(
        InputDependencyV1::from_proof_evidence_v1(&evidence, rule()),
        Ok(expected)
    );

    let mut placeholder = evidence.clone();
    placeholder.source = DependencyNodeV1 {
        tick: 0,
        scheduler_position: 0,
        owner_id: "scenario-room".to_owned(),
        output_ordinal: 0,
        schema_id: 7,
        artifact_digest: [0; 32],
    };
    assert_eq!(
        InputDependencyV1::from_proof_evidence_v1(&placeholder, rule()),
        Err(ErrorV1::FieldOutOfBounds)
    );
    let unversioned = DependencyClassificationRuleV1 {
        rule_version: 0,
        ..rule()
    };
    assert_eq!(
        InputDependencyV1::from_proof_evidence_v1(&evidence, unversioned),
        Err(ErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn errors_have_stable_safe_messages() {
    let messages = [
        (
            ErrorV1::InvalidEncoding,
            "invalid IDP1 input-dependency encoding",
        ),
        (
            ErrorV1::UnsupportedVersion,
            "unsupported IDP1 input-dependency version",
        ),
        (
            ErrorV1::FieldOutOfBounds,
            "IDP1 input-dependency field is out of bounds",
        ),
        (
            ErrorV1::UnknownEnum,
            "IDP1 input-dependency class is unknown",
        ),
        (
            ErrorV1::NonCanonicalOrder,
            "IDP1 input-dependency coordinates are not canonical",
        ),
        (
            ErrorV1::DuplicateIdentity,
            "IDP1 input-dependency edge identity is duplicated",
        ),
    ];
    for (error, message) in messages {
        assert_eq!(error.to_string(), message);
        let source: &dyn std::error::Error = &error;
        assert!(source.source().is_none());
    }
}
