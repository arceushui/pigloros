#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-058 EPF1 execution-profile contract.

use ciborium::value::Value;
use pos_conformance::{
    draft_execution_profile_bytes_v1, ExecutionProfileContractErrorV1, ExecutionProfileV1,
    ReproducibilityClassV1, MAX_EXECUTION_PROFILE_BYTES_V1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn draft_profile_bytes() -> TestResult<Vec<u8>> {
    draft_execution_profile_bytes_v1("deterministic-local-v1").map_err(Into::into)
}

fn decode_value(bytes: &[u8]) -> TestResult<Value> {
    ciborium::from_reader(bytes).map_err(Into::into)
}

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn replace_field(bytes: &[u8], index: usize, replacement: Value) -> TestResult<Vec<u8>> {
    let mut document = decode_value(bytes)?;
    let Value::Array(fields) = &mut document else {
        return Err("EPF1 must be represented by a CBOR array".into());
    };
    let Some(field) = fields.get_mut(index) else {
        return Err(format!("EPF1 field {index} is absent").into());
    };
    *field = replacement;
    encode_value(&document)
}

fn value_array(value: &Value) -> TestResult<&[Value]> {
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err("expected a CBOR array".into()),
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn assert_decode_error(bytes: &[u8], expected: ExecutionProfileContractErrorV1) {
    assert_eq!(
        ExecutionProfileV1::from_canonical_cbor(bytes).map(|_| ()),
        Err(expected),
        "input was {bytes:?}"
    );
}

fn profile_with_architecture_rule_count(
    profile: &ExecutionProfileV1,
    count: usize,
) -> ExecutionProfileV1 {
    let mut candidate = profile.clone();
    candidate.architecture_rules = (0..count)
        .map(|index| format!("a{index:06}-{}", "x".repeat(120)))
        .collect();
    candidate.profile_digest = candidate.digest();
    candidate
}

fn unsigned_profile_size(bytes: &[u8], rules: &[String]) -> TestResult<usize> {
    let mut document = decode_value(bytes)?;
    let Value::Array(fields) = &mut document else {
        return Err("EPF1 must be represented by a CBOR array".into());
    };
    fields.pop();
    fields[5] = Value::Array(rules.iter().cloned().map(Value::Text).collect());
    Ok(encode_value(&document)?.len())
}

#[test]
fn public_codec_roundtrips_the_existing_draft_epf1_bytes() -> TestResult {
    let draft = draft_profile_bytes()?;
    let profile = ExecutionProfileV1::from_canonical_cbor(&draft)?;

    assert_eq!(profile.to_canonical_cbor()?, draft);
    assert_eq!(profile.digest(), profile.profile_digest);
    assert_eq!(
        profile.reproducibility_classes,
        vec![
            ReproducibilityClassV1::ProfileRecomputation,
            ReproducibilityClassV1::CrossProfileConformance,
        ]
    );
    Ok(())
}

#[test]
fn digest_changes_when_profile_semantics_or_predecessor_changes() -> TestResult {
    let draft = draft_profile_bytes()?;
    let original = ExecutionProfileV1::from_canonical_cbor(&draft)?;
    let original_digest = original.digest();

    let mut changed_rules = original.clone();
    changed_rules
        .architecture_rules
        .insert(0, "a-test-rule".to_owned());
    changed_rules.profile_digest = changed_rules.digest();
    assert_ne!(changed_rules.profile_digest, original_digest);
    assert_eq!(
        ExecutionProfileV1::from_canonical_cbor(&changed_rules.to_canonical_cbor()?)?,
        changed_rules
    );

    let mut changed_predecessor = original;
    changed_predecessor.previous_profile_digest = Some([9; 32]);
    changed_predecessor.capabilities_and_network.network_allowed = true;
    changed_predecessor.capabilities_and_network.capability_ids =
        vec!["capability.alpha".to_owned(), "capability.zeta".to_owned()];
    changed_predecessor.reproducibility_classes = vec![
        ReproducibilityClassV1::RecordedReplay,
        ReproducibilityClassV1::LiveUnverified,
    ];
    changed_predecessor.profile_digest = changed_predecessor.digest();
    assert_ne!(changed_predecessor.profile_digest, original_digest);
    assert_eq!(changed_predecessor.validate(), Ok(()));
    assert_eq!(
        ExecutionProfileV1::from_canonical_cbor(&changed_predecessor.to_canonical_cbor()?)?,
        changed_predecessor
    );

    let mut reordered_sequence = changed_predecessor;
    reordered_sequence.scheduler_driver_order.reverse();
    reordered_sequence.profile_digest = reordered_sequence.digest();
    let encoded = reordered_sequence.to_canonical_cbor()?;
    assert_eq!(
        ExecutionProfileV1::from_canonical_cbor(&encoded)?,
        reordered_sequence
    );
    Ok(())
}

#[test]
fn decoder_rejects_closed_schema_and_malformed_cbor_forms() -> TestResult {
    let valid = draft_profile_bytes()?;
    let document = decode_value(&valid)?;
    let fields = value_array(&document)?;

    let wrong_magic = replace_field(&valid, 0, text("EPF2"))?;
    assert_decode_error(
        &wrong_magic,
        ExecutionProfileContractErrorV1::UnsupportedVersion,
    );
    let wrong_version = replace_field(&valid, 1, uint(2))?;
    assert_decode_error(
        &wrong_version,
        ExecutionProfileContractErrorV1::UnsupportedVersion,
    );
    let wrong_class = replace_field(&valid, 4, Value::Array(vec![uint(99)]))?;
    assert_decode_error(
        &wrong_class,
        ExecutionProfileContractErrorV1::UnsupportedVersion,
    );
    let wrong_digest = replace_field(&valid, 16, Value::Bytes(vec![9; 32]))?;
    assert_decode_error(
        &wrong_digest,
        ExecutionProfileContractErrorV1::DigestMismatch,
    );

    let mut missing_field = fields.to_vec();
    missing_field.pop();
    assert_decode_error(
        &encode_value(&Value::Array(missing_field))?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    let mut unknown_field = fields.to_vec();
    unknown_field.push(Value::Null);
    assert_decode_error(
        &encode_value(&Value::Array(unknown_field))?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );

    for raw in [
        vec![0xff],                         // malformed CBOR
        vec![0xa0],                         // map
        vec![0xc0, 0x00],                   // tag
        vec![0xf9, 0x00, 0x00],             // float
        vec![0x9f, 0xff],                   // indefinite array
        vec![0x61, 0xff],                   // invalid UTF-8
        vec![0x81, 0x81, 0x81, 0x81, 0x00], // excessive nesting
        vec![0x9a, 0x00, 0x10, 0x00, 0x01], // excessive array count
    ] {
        let expected =
            if raw == [0x81, 0x81, 0x81, 0x81, 0x00] || raw == [0x9a, 0x00, 0x10, 0x00, 0x01] {
                ExecutionProfileContractErrorV1::FieldOutOfBounds
            } else {
                ExecutionProfileContractErrorV1::InvalidEncoding
            };
        assert_decode_error(&raw, expected);
    }

    let mut trailing = valid.clone();
    trailing.push(0);
    assert_decode_error(&trailing, ExecutionProfileContractErrorV1::InvalidEncoding);
    let oversized = vec![0; MAX_EXECUTION_PROFILE_BYTES_V1 + 1];
    assert_decode_error(
        &oversized,
        ExecutionProfileContractErrorV1::FieldOutOfBounds,
    );

    let marker = [0x64, b'E', b'P', b'F', b'1', 0x01];
    let marker_index = valid
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("canonical EPF1 header bytes are absent")?;
    let version_index = marker_index + marker.len() - 1;
    let mut noncanonical_integer = valid;
    noncanonical_integer.splice(version_index..=version_index, [0x18, 0x01]);
    assert_decode_error(
        &noncanonical_integer,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );

    let errors = [
        ExecutionProfileContractErrorV1::InvalidEncoding,
        ExecutionProfileContractErrorV1::UnsupportedVersion,
        ExecutionProfileContractErrorV1::FieldOutOfBounds,
        ExecutionProfileContractErrorV1::NonCanonicalOrder,
        ExecutionProfileContractErrorV1::DigestMismatch,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
    Ok(())
}

#[test]
fn decoder_rejects_malformed_field_types_and_noncanonical_lists() -> TestResult {
    let valid = draft_profile_bytes()?;
    assert_rejects_profile_field_shapes(&valid)?;
    assert_rejects_duplicate_and_noncanonical_lists(&valid)?;
    assert_rejects_malformed_nested_fields(&valid)?;
    Ok(())
}

fn assert_rejects_profile_field_shapes(valid: &[u8]) -> TestResult {
    assert_decode_error(
        &replace_field(valid, 0, Value::Null)?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(valid, 1, Value::Null)?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(valid, 1, Value::Integer((-1).into()))?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    for (index, invalid_value) in [
        (2, Value::Null),
        (3, Value::Null),
        (4, Value::Null),
        (5, Value::Null),
        (6, Value::Null),
        (7, Value::Null),
        (8, Value::Null),
        (9, Value::Null),
        (10, Value::Null),
        (11, Value::Null),
        (12, Value::Null),
        (13, Value::Null),
        (14, Value::Null),
        (15, uint(1)),
        (16, Value::Text("not-bytes".to_owned())),
    ] {
        assert_decode_error(
            &replace_field(valid, index, invalid_value)?,
            ExecutionProfileContractErrorV1::InvalidEncoding,
        );
    }

    for index in [5_usize, 6, 7, 9, 10, 13] {
        let document = decode_value(valid)?;
        let fields = value_array(&document)?;
        let Value::Array(values) = fields[index].clone() else {
            return Err(format!("EPF1 list field {index} must be an array").into());
        };
        let mut invalid_values = values;
        invalid_values[0] = uint(1);
        assert_decode_error(
            &replace_field(valid, index, Value::Array(invalid_values))?,
            ExecutionProfileContractErrorV1::InvalidEncoding,
        );
    }

    assert_decode_error(
        &replace_field(
            valid,
            11,
            Value::Array(vec![uint(1), Value::Array(Vec::new())]),
        )?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    assert_decode_error(
        &replace_field(valid, 11, Value::Array(vec![Value::Bool(false), uint(1)]))?,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    Ok(())
}

fn assert_rejects_duplicate_and_noncanonical_lists(valid: &[u8]) -> TestResult {
    for (index, duplicate_values) in [
        (5_usize, vec![text("z-rule"), text("z-rule")]),
        (6, vec![text("z-rule"), text("z-rule")]),
        (7, vec![text("driver"), text("driver")]),
        (9, vec![text("z-schema"), text("z-schema")]),
        (10, vec![text("z-artifact"), text("z-artifact")]),
        (13, vec![text("z-difference"), text("z-difference")]),
    ] {
        assert_decode_error(
            &replace_field(valid, index, Value::Array(duplicate_values))?,
            ExecutionProfileContractErrorV1::NonCanonicalOrder,
        );
    }

    let duplicate_class = replace_field(valid, 4, Value::Array(vec![uint(1), uint(1)]))?;
    assert_decode_error(
        &duplicate_class,
        ExecutionProfileContractErrorV1::NonCanonicalOrder,
    );
    let duplicate_capability = replace_field(
        valid,
        11,
        Value::Array(vec![
            Value::Bool(false),
            Value::Array(vec![text("z"), text("z")]),
        ]),
    )?;
    assert_decode_error(
        &duplicate_capability,
        ExecutionProfileContractErrorV1::NonCanonicalOrder,
    );
    let reversed_class = replace_field(valid, 4, Value::Array(vec![uint(2), uint(1)]))?;
    assert_decode_error(
        &reversed_class,
        ExecutionProfileContractErrorV1::NonCanonicalOrder,
    );
    let reversed_capability = replace_field(
        valid,
        11,
        Value::Array(vec![
            Value::Bool(false),
            Value::Array(vec![text("z"), text("a")]),
        ]),
    )?;
    assert_decode_error(
        &reversed_capability,
        ExecutionProfileContractErrorV1::NonCanonicalOrder,
    );
    let duplicate_difference = replace_field(valid, 13, Value::Array(vec![text("z"), text("z")]))?;
    assert_decode_error(
        &duplicate_difference,
        ExecutionProfileContractErrorV1::NonCanonicalOrder,
    );
    Ok(())
}

fn assert_rejects_malformed_nested_fields(valid: &[u8]) -> TestResult {
    let wrong_compatibility = replace_field(valid, 14, Value::Array(vec![text("1.0.0"), uint(1)]))?;
    assert_decode_error(
        &wrong_compatibility,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    let wrong_budget = replace_field(valid, 12, Value::Array(vec![text("not-a-number"); 8]))?;
    assert_decode_error(
        &wrong_budget,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    let short_budget = replace_field(valid, 12, Value::Array(vec![uint(1); 7]))?;
    assert_decode_error(
        &short_budget,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    let invalid_previous_digest = replace_field(valid, 15, Value::Bytes(vec![1; 31]))?;
    assert_decode_error(
        &invalid_previous_digest,
        ExecutionProfileContractErrorV1::InvalidEncoding,
    );
    Ok(())
}

fn invalid_profile(
    base: &ExecutionProfileV1,
    mutate: impl FnOnce(&mut ExecutionProfileV1),
    expected: ExecutionProfileContractErrorV1,
) -> (ExecutionProfileV1, ExecutionProfileContractErrorV1) {
    let mut profile = base.clone();
    mutate(&mut profile);
    profile.profile_digest = profile.digest();
    (profile, expected)
}

fn invalid_profile_cases(
    profile: &ExecutionProfileV1,
) -> Vec<(ExecutionProfileV1, ExecutionProfileContractErrorV1)> {
    use ExecutionProfileContractErrorV1::{FieldOutOfBounds as Bounds, NonCanonicalOrder as Order};
    vec![
        invalid_profile(
            profile,
            |value| "Uppercase-ID".clone_into(&mut value.profile_id),
            Bounds,
        ),
        invalid_profile(
            profile,
            |value| "01.0.0".clone_into(&mut value.semantic_version),
            Bounds,
        ),
        invalid_profile(
            profile,
            |value| value.reproducibility_classes.clear(),
            Bounds,
        ),
        invalid_profile(
            profile,
            |value| value.reproducibility_classes.reverse(),
            Order,
        ),
        invalid_profile(
            profile,
            |value| value.architecture_rules[1] = value.architecture_rules[0].clone(),
            Order,
        ),
        invalid_profile(
            profile,
            |value| value.scheduler_driver_order.clear(),
            Bounds,
        ),
        invalid_profile(
            profile,
            |value| "BAD-ID".clone_into(&mut value.scheduler_driver_order[0]),
            Bounds,
        ),
        invalid_profile(
            profile,
            |value| "bad policy".clone_into(&mut value.tick_policy),
            Bounds,
        ),
        invalid_profile(
            profile,
            |value| value.schemas_and_upcasters[1] = value.schemas_and_upcasters[0].clone(),
            Order,
        ),
        invalid_profile(
            profile,
            |value| value.artifact_rules[1] = value.artifact_rules[0].clone(),
            Order,
        ),
        invalid_profile(
            profile,
            |value| {
                value.capabilities_and_network.capability_ids =
                    vec!["z".to_owned(), "a".to_owned()];
            },
            Order,
        ),
        invalid_profile(profile, |value| value.deterministic_budgets[0] = 0, Bounds),
        invalid_profile(
            profile,
            |value| {
                value.allowed_operational_differences[1] =
                    value.allowed_operational_differences[0].clone();
            },
            Order,
        ),
        invalid_profile(
            profile,
            |value| {
                "not-a-version".clone_into(&mut value.compatibility.minimum_evaluator_version);
            },
            Bounds,
        ),
    ]
}

fn assert_overlarge_profile_lists(profile: &ExecutionProfileV1) {
    let mut overlarge_sequence = profile.clone();
    overlarge_sequence.scheduler_driver_order = (0..=256)
        .map(|index| format!("driver-{index:03}"))
        .collect();
    overlarge_sequence.profile_digest = overlarge_sequence.digest();
    assert_eq!(
        overlarge_sequence.validate(),
        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
    );

    let mut overlarge_schema_set = profile.clone();
    overlarge_schema_set.schemas_and_upcasters = (0..=256)
        .map(|index| format!("schema-{index:03}"))
        .collect();
    overlarge_schema_set.profile_digest = overlarge_schema_set.digest();
    assert_eq!(
        overlarge_schema_set.validate(),
        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
    );

    let mut overlarge_capability_set = profile.clone();
    overlarge_capability_set
        .capabilities_and_network
        .capability_ids = (0..=256)
        .map(|index| format!("capability-{index:03}"))
        .collect();
    overlarge_capability_set.profile_digest = overlarge_capability_set.digest();
    assert_eq!(
        overlarge_capability_set.validate(),
        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
    );

    let mut overlarge_difference_set = profile.clone();
    overlarge_difference_set.allowed_operational_differences = (0..=64)
        .map(|index| format!("difference-{index:03}"))
        .collect();
    overlarge_difference_set.profile_digest = overlarge_difference_set.digest();
    assert_eq!(
        overlarge_difference_set.validate(),
        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn public_validation_rejects_bounds_order_invalid_identifiers_and_bad_digests() -> TestResult {
    let bytes = draft_profile_bytes()?;
    let profile = ExecutionProfileV1::from_canonical_cbor(&bytes)?;
    for (invalid, expected) in invalid_profile_cases(&profile) {
        assert_eq!(invalid.validate(), Err(expected));
        assert_eq!(invalid.to_canonical_cbor(), Err(expected));
    }
    let mut wrong_digest = profile.clone();
    wrong_digest.profile_digest[0] ^= 1;
    assert_eq!(
        wrong_digest.validate(),
        Err(ExecutionProfileContractErrorV1::DigestMismatch)
    );

    assert_overlarge_profile_lists(&profile);
    Ok(())
}

#[test]
fn typed_encoder_enforces_encoded_size_limit() -> TestResult {
    let draft = draft_profile_bytes()?;
    let mut profile = ExecutionProfileV1::from_canonical_cbor(&draft)?;
    profile.architecture_rules = (0..9_000)
        .map(|index| format!("r{index:05}{}", "x".repeat(114)))
        .collect();
    profile.profile_digest = profile.digest();
    assert_eq!(
        profile.validate(),
        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        profile.to_canonical_cbor(),
        Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn typed_encoder_enforces_size_limit_including_profile_digest() -> TestResult {
    let bytes = draft_profile_bytes()?;
    let profile = ExecutionProfileV1::from_canonical_cbor(&bytes)?;
    let mut low = 0_usize;
    let mut high = 10_000_usize;
    while low < high {
        let middle = (low + high).div_ceil(2);
        let candidate = profile_with_architecture_rule_count(&profile, middle);
        if unsigned_profile_size(&bytes, &candidate.architecture_rules)?
            <= MAX_EXECUTION_PROFILE_BYTES_V1
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }

    let base = profile_with_architecture_rule_count(&profile, low);
    for length in 1..=128 {
        let mut candidate = base.clone();
        candidate
            .architecture_rules
            .push(format!("z{}", "x".repeat(length - 1)));
        let unsigned_size = unsigned_profile_size(&bytes, &candidate.architecture_rules)?;
        if unsigned_size <= MAX_EXECUTION_PROFILE_BYTES_V1
            && unsigned_size + 34 > MAX_EXECUTION_PROFILE_BYTES_V1
        {
            candidate.profile_digest = candidate.digest();
            assert_eq!(
                candidate.to_canonical_cbor(),
                Err(ExecutionProfileContractErrorV1::FieldOutOfBounds)
            );
            return Ok(());
        }
    }
    Err("could not construct a profile at the encoded-size boundary".into())
}

#[test]
fn compatibility_window_uses_semantic_version_precedence() -> TestResult {
    let bytes = draft_profile_bytes()?;
    let profile = ExecutionProfileV1::from_canonical_cbor(&bytes)?;
    for (minimum, maximum, expected) in [
        ("1.2.0", "1.10.0", Ok(())),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", Ok(())),
        ("1.0.0-alpha", "1.0.0-alpha", Ok(())),
        ("1.0.0-alpha.1", "1.0.0-beta", Ok(())),
        ("1.0.0-1", "1.0.0-alpha", Ok(())),
        ("1.0.0-alpha", "1.0.0", Ok(())),
        ("1.0.0", "1.0.0", Ok(())),
        ("1.0.0+build-a", "1.0.0+build-b", Ok(())),
        (
            "1.0.0-alpha.1",
            "1.0.0-alpha",
            Err(ExecutionProfileContractErrorV1::FieldOutOfBounds),
        ),
        (
            "1.0.0-alpha",
            "1.0.0-1",
            Err(ExecutionProfileContractErrorV1::FieldOutOfBounds),
        ),
        (
            "1.0.0",
            "1.0.0-alpha",
            Err(ExecutionProfileContractErrorV1::FieldOutOfBounds),
        ),
        (
            "1.0.0-beta",
            "1.0.0-alpha",
            Err(ExecutionProfileContractErrorV1::FieldOutOfBounds),
        ),
        (
            "2.0.0",
            "1.9.0",
            Err(ExecutionProfileContractErrorV1::FieldOutOfBounds),
        ),
    ] {
        let mut candidate = profile.clone();
        candidate.compatibility.minimum_evaluator_version = minimum.to_owned();
        candidate.compatibility.maximum_evaluator_version = maximum.to_owned();
        candidate.profile_digest = candidate.digest();
        assert_eq!(candidate.validate(), expected, "{minimum} .. {maximum}");
    }
    Ok(())
}
