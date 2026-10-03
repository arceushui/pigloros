use ciborium::value::Value;
use pos_conformance::counterfactual::{
    validate_plan_interventions_v1, InterventionContractErrorV1 as InterventionError,
    InterventionOperationV1, InterventionV1, ProofInterventionBindingV1, INTERVENTION_MAGIC_V1,
    MAX_INTERVENTIONS_PER_PLAN_V1, MAX_INTERVENTION_BYTES_V1,
};
use pos_conformance::InterventionV1 as ProofInterventionV1;
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FIELD_COUNT: usize = 16;
const FIELD_SCHEMA: usize = 3;
const FIELD_OPERATION: usize = 6;
const FIELD_TICK: usize = 8;
const FIELD_ORDINAL: usize = 9;
const FIELD_RATIONALE: usize = 14;

fn intervention() -> InterventionV1 {
    InterventionV1 {
        intervention_id: [1; 16],
        target_schema_id: 7,
        target_entity_id: "body".to_owned(),
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        value_digest: [2; 32],
        effective_tick: 5,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        consent_decision_digest: [4; 32],
        rationale: "zz-rationale".to_owned(),
        provenance_digest: [6; 32],
    }
}

fn planned(effective_tick: u64, ordinal: u32, id_seed: u32) -> InterventionV1 {
    let mut record = intervention();
    record.effective_tick = effective_tick;
    record.ordinal = ordinal;
    record.intervention_id = [0xff; 16];
    record.intervention_id[..4].copy_from_slice(&id_seed.to_be_bytes());
    record
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn fields() -> TestResult<Vec<Value>> {
    let bytes = intervention().to_canonical_cbor()?;
    let value: Value = ciborium::from_reader(Cursor::new(bytes))?;
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err("INT1 must encode as an array".into()),
    }
}

fn bytes_with_field(index: usize, value: Value) -> TestResult<Vec<u8>> {
    let mut fields = fields()?;
    fields[index] = value;
    encode(&Value::Array(fields))
}

fn decode_error(bytes: &[u8]) -> TestResult<InterventionError> {
    match InterventionV1::from_canonical_cbor(bytes) {
        Ok(_) => Err("invalid INT1 bytes must be rejected".into()),
        Err(error) => Ok(error),
    }
}

fn expected_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.Intervention.v1\0");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[test]
fn canonical_int1_round_trips_with_exact_field_layout_and_domain_digest() -> TestResult {
    let original = intervention();
    let bytes = original.to_canonical_cbor()?;
    assert_eq!(InterventionV1::from_canonical_cbor(&bytes)?, original);
    assert_eq!(original.digest()?, expected_digest(&bytes));
    assert_eq!(INTERVENTION_MAGIC_V1, "INT1");
    let fields = fields()?;
    assert_eq!(fields.len(), FIELD_COUNT);
    let expected = [
        Value::Text("INT1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(vec![1; 16]),
        Value::Integer(7_u64.into()),
        Value::Text("body".to_owned()),
        Value::Text("velocity".to_owned()),
        Value::Integer(0_u64.into()),
        Value::Bytes(vec![2; 32]),
        Value::Integer(5_u64.into()),
        Value::Integer(0_u64.into()),
        Value::Text("principal:operator".to_owned()),
        Value::Text("intervene".to_owned()),
        Value::Integer(3_u64.into()),
        Value::Bytes(vec![4; 32]),
        Value::Text("zz-rationale".to_owned()),
        Value::Bytes(vec![6; 32]),
    ];
    assert_eq!(fields, expected);
    Ok(())
}

#[test]
fn closed_operations_round_trip_and_unknown_codes_are_rejected() -> TestResult {
    let mut artifact = intervention();
    artifact.operation = InterventionOperationV1::AssignArtifact;
    let bytes = artifact.to_canonical_cbor()?;
    assert_eq!(InterventionV1::from_canonical_cbor(&bytes)?, artifact);
    assert_eq!(
        bytes,
        bytes_with_field(FIELD_OPERATION, Value::Integer(1_u64.into()))?
    );
    assert!(InterventionOperationV1::AssignValue < InterventionOperationV1::AssignArtifact);
    let unknown = bytes_with_field(FIELD_OPERATION, Value::Integer(2_u64.into()))?;
    assert_eq!(decode_error(&unknown)?, InterventionError::UnknownEnum);
    Ok(())
}

#[test]
fn every_bound_field_changes_the_canonical_bytes_and_digest() -> TestResult {
    let original = intervention();
    let original_digest = original.digest()?;
    let mutations: [fn(&mut InterventionV1); 14] = [
        |value| value.intervention_id[0] ^= 1,
        |value| value.target_schema_id += 1,
        |value| value.target_entity_id.push('x'),
        |value| value.target_field.push('x'),
        |value| value.operation = InterventionOperationV1::AssignArtifact,
        |value| value.value_digest[0] ^= 1,
        |value| value.effective_tick += 1,
        |value| value.ordinal += 1,
        |value| value.principal_id.push('x'),
        |value| value.capability.push('x'),
        |value| value.consent_epoch += 1,
        |value| value.consent_decision_digest[0] ^= 1,
        |value| value.rationale.push('x'),
        |value| value.provenance_digest[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        let bytes = changed.to_canonical_cbor()?;
        assert_ne!(bytes, original.to_canonical_cbor()?);
        assert_ne!(changed.digest()?, original_digest);
        assert_eq!(InterventionV1::from_canonical_cbor(&bytes)?, changed);
    }
    Ok(())
}

#[test]
fn text_fields_enforce_exact_byte_bounds_and_reject_control_characters() -> TestResult {
    let identifier_fields: [fn(&mut InterventionV1) -> &mut String; 4] = [
        |value| &mut value.target_entity_id,
        |value| &mut value.target_field,
        |value| &mut value.principal_id,
        |value| &mut value.capability,
    ];
    let rationale_field: fn(&mut InterventionV1) -> &mut String = |value| &mut value.rationale;
    for (field, maximum) in identifier_fields
        .into_iter()
        .map(|field| (field, 128))
        .chain([(rationale_field, 4_096)])
    {
        for (text, accepted) in [
            ("a".repeat(maximum), true),
            ("\u{e9}".repeat(maximum / 2), true),
            ("a".repeat(maximum + 1), false),
            (String::new(), false),
            ("line\nbreak".to_owned(), false),
        ] {
            let mut candidate = intervention();
            *field(&mut candidate) = text;
            if accepted {
                let bytes = candidate.to_canonical_cbor()?;
                assert_eq!(InterventionV1::from_canonical_cbor(&bytes)?, candidate);
            } else {
                assert_eq!(
                    candidate.validate(),
                    Err(InterventionError::FieldOutOfBounds)
                );
                assert_eq!(
                    candidate.to_canonical_cbor(),
                    Err(InterventionError::FieldOutOfBounds)
                );
                assert_eq!(candidate.digest(), Err(InterventionError::FieldOutOfBounds));
            }
        }
    }
    let oversized = bytes_with_field(FIELD_RATIONALE, Value::Text("a".repeat(4_097)))?;
    assert_eq!(
        decode_error(&oversized)?,
        InterventionError::FieldOutOfBounds
    );
    Ok(())
}

#[test]
fn zero_identities_and_digests_are_rejected() -> TestResult {
    let zeroed: [fn(&mut InterventionV1); 5] = [
        |value| value.intervention_id = [0; 16],
        |value| value.target_schema_id = 0,
        |value| value.value_digest = [0; 32],
        |value| value.consent_decision_digest = [0; 32],
        |value| value.provenance_digest = [0; 32],
    ];
    for zero in zeroed {
        let mut candidate = intervention();
        zero(&mut candidate);
        assert_eq!(
            candidate.validate(),
            Err(InterventionError::FieldOutOfBounds)
        );
        assert_eq!(
            candidate.to_canonical_cbor(),
            Err(InterventionError::FieldOutOfBounds)
        );
    }
    let mut minimal = intervention();
    minimal.intervention_id = [0; 16];
    minimal.intervention_id[15] = 1;
    minimal.target_schema_id = 1;
    for digest in [
        &mut minimal.value_digest,
        &mut minimal.consent_decision_digest,
        &mut minimal.provenance_digest,
    ] {
        *digest = [0; 32];
        digest[31] = 1;
    }
    minimal.validate()?;
    let bytes = minimal.to_canonical_cbor()?;
    assert_eq!(InterventionV1::from_canonical_cbor(&bytes)?, minimal);
    for (index, value) in [
        (2, Value::Bytes(vec![0; 16])),
        (FIELD_SCHEMA, Value::Integer(0_u64.into())),
        (7, Value::Bytes(vec![0; 32])),
        (13, Value::Bytes(vec![0; 32])),
        (15, Value::Bytes(vec![0; 32])),
    ] {
        assert_eq!(
            decode_error(&bytes_with_field(index, value)?)?,
            InterventionError::FieldOutOfBounds
        );
    }
    Ok(())
}

#[test]
fn encoded_size_is_bounded_before_decoding() -> TestResult {
    assert_eq!(MAX_INTERVENTION_BYTES_V1, 65_536);
    let mut at_limit = encode(&Value::Text("a".repeat(MAX_INTERVENTION_BYTES_V1 - 3)))?;
    assert_eq!(at_limit.len(), MAX_INTERVENTION_BYTES_V1);
    assert_eq!(decode_error(&at_limit)?, InterventionError::InvalidEncoding);
    at_limit.push(0);
    assert_eq!(
        decode_error(&at_limit)?,
        InterventionError::FieldOutOfBounds
    );
    Ok(())
}

#[test]
fn header_and_integer_fields_are_closed() -> TestResult {
    for (index, value, expected) in [
        (
            0,
            Value::Text("INT2".to_owned()),
            InterventionError::UnsupportedVersion,
        ),
        (
            1,
            Value::Integer(0_u64.into()),
            InterventionError::UnsupportedVersion,
        ),
        (
            1,
            Value::Integer(2_u64.into()),
            InterventionError::UnsupportedVersion,
        ),
        (
            FIELD_SCHEMA,
            Value::Integer((u64::from(u32::MAX) + 1).into()),
            InterventionError::FieldOutOfBounds,
        ),
        (
            FIELD_ORDINAL,
            Value::Integer((u64::from(u32::MAX) + 1).into()),
            InterventionError::FieldOutOfBounds,
        ),
        (
            FIELD_TICK,
            Value::Integer((-1_i64).into()),
            InterventionError::InvalidEncoding,
        ),
        (
            2,
            Value::Bytes(vec![1; 15]),
            InterventionError::InvalidEncoding,
        ),
        (
            7,
            Value::Bytes(vec![2; 31]),
            InterventionError::InvalidEncoding,
        ),
    ] {
        assert_eq!(decode_error(&bytes_with_field(index, value)?)?, expected);
    }
    let mut maximum = intervention();
    maximum.target_schema_id = u32::MAX;
    maximum.ordinal = u32::MAX;
    maximum.effective_tick = u64::MAX;
    maximum.consent_epoch = u64::MAX;
    let bytes = maximum.to_canonical_cbor()?;
    assert_eq!(InterventionV1::from_canonical_cbor(&bytes)?, maximum);
    Ok(())
}

#[test]
fn header_is_checked_before_the_field_count() -> TestResult {
    let mut fields = fields()?;
    fields.truncate(FIELD_COUNT - 3);
    for (magic, version) in [("INT1", 2_u64), ("INT2", 1)] {
        let mut future = fields.clone();
        future[0] = Value::Text(magic.to_owned());
        future[1] = Value::Integer(version.into());
        assert_eq!(
            decode_error(&encode(&Value::Array(future))?)?,
            InterventionError::UnsupportedVersion
        );
    }
    assert_eq!(
        decode_error(&encode(&Value::Array(fields))?)?,
        InterventionError::InvalidEncoding
    );
    let magic_only = encode(&Value::Array(vec![Value::Text("INT1".to_owned())]))?;
    assert_eq!(
        decode_error(&magic_only)?,
        InterventionError::InvalidEncoding
    );
    Ok(())
}

#[test]
fn every_field_rejects_a_wrong_cbor_type() -> TestResult {
    for index in 0..FIELD_COUNT {
        let bytes = bytes_with_field(index, Value::Array(Vec::new()))?;
        assert_eq!(decode_error(&bytes)?, InterventionError::InvalidEncoding);
    }
    Ok(())
}

#[test]
fn malformed_and_noncanonical_cbor_is_rejected() -> TestResult {
    let mut fields = fields()?;
    let canonical = encode(&Value::Array(fields.clone()))?;
    fields.pop();
    let short = encode(&Value::Array(fields.clone()))?;
    fields.extend([Value::Integer(0_u64.into()), Value::Integer(0_u64.into())]);
    let long = encode(&Value::Array(fields))?;
    assert_eq!(decode_error(&short)?, InterventionError::InvalidEncoding);
    assert_eq!(decode_error(&long)?, InterventionError::FieldOutOfBounds);
    let nested = bytes_with_field(2, Value::Array(vec![Value::Array(Vec::new())]))?;
    assert_eq!(decode_error(&nested)?, InterventionError::FieldOutOfBounds);
    for value in [
        Value::Null,
        Value::Bool(true),
        Value::Map(Vec::new()),
        Value::Tag(1, Box::new(Value::Integer(0_u64.into()))),
    ] {
        let bytes = bytes_with_field(FIELD_TICK, value)?;
        assert_eq!(decode_error(&bytes)?, InterventionError::InvalidEncoding);
    }
    let top_level_text = encode(&Value::Text("INT1".to_owned()))?;
    assert_eq!(
        decode_error(&top_level_text)?,
        InterventionError::InvalidEncoding
    );
    assert_eq!(decode_error(&[])?, InterventionError::InvalidEncoding);

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(decode_error(&trailing)?, InterventionError::InvalidEncoding);

    assert_eq!(canonical[6], 1);
    let mut wide_version = canonical[..6].to_vec();
    wide_version.extend([0x18, 0x01]);
    wide_version.extend_from_slice(&canonical[7..]);
    assert_eq!(
        decode_error(&wide_version)?,
        InterventionError::InvalidEncoding
    );

    let marker = b"zz-rationale";
    let offset = canonical
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("rationale must be encoded")?;
    let mut invalid_utf8 = canonical;
    invalid_utf8[offset] = 0xff;
    assert_eq!(
        decode_error(&invalid_utf8)?,
        InterventionError::InvalidEncoding
    );
    Ok(())
}

#[test]
fn proof_evidence_converts_only_with_explicit_bindings() -> TestResult {
    let evidence = ProofInterventionV1 {
        intervention_id: [1; 16],
        target: "body".to_owned(),
        operation: "set_velocity".to_owned(),
        value_digest: [2; 32],
        effective_tick: 5,
        ordinal: 0,
        principal_id: "principal:operator".to_owned(),
        capability: "intervene".to_owned(),
        consent_epoch: 3,
        provenance_digest: [6; 32],
    };
    let binding = ProofInterventionBindingV1 {
        target_schema_id: 7,
        target_field: "velocity".to_owned(),
        operation: InterventionOperationV1::AssignValue,
        consent_decision_digest: [4; 32],
        rationale: "zz-rationale".to_owned(),
    };
    assert_eq!(
        InterventionV1::from_proof_evidence_v1(&evidence, binding.clone())?,
        intervention()
    );

    let mut invalid_binding = binding.clone();
    invalid_binding.target_field = String::new();
    assert_eq!(
        InterventionV1::from_proof_evidence_v1(&evidence, invalid_binding),
        Err(InterventionError::FieldOutOfBounds)
    );
    let mut invalid_evidence = evidence;
    invalid_evidence.target = String::new();
    assert_eq!(
        InterventionV1::from_proof_evidence_v1(&invalid_evidence, binding),
        Err(InterventionError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn plan_interventions_are_bounded_canonically_ordered_contiguous_and_unique() -> TestResult {
    validate_plan_interventions_v1(&[planned(1, 0, 1), planned(1, 1, 2), planned(3, 0, 3)])?;
    validate_plan_interventions_v1(&[planned(1, 0, 9), planned(2, 0, 1)])?;

    assert_eq!(MAX_INTERVENTIONS_PER_PLAN_V1, 1_024);
    let mut full = (0..1_024_u32)
        .map(|ordinal| planned(1, ordinal, ordinal))
        .collect::<Vec<_>>();
    validate_plan_interventions_v1(&full)?;
    full.push(planned(1, 1_024, 1_024));
    assert_eq!(
        validate_plan_interventions_v1(&full),
        Err(InterventionError::FieldOutOfBounds)
    );
    assert_eq!(
        validate_plan_interventions_v1(&[]),
        Err(InterventionError::FieldOutOfBounds)
    );

    let mut invalid = planned(1, 1, 2);
    invalid.rationale = String::new();
    for (plan, expected) in [
        (
            vec![planned(1, 0, 1), invalid],
            InterventionError::FieldOutOfBounds,
        ),
        (
            vec![planned(1, 1, 2), planned(1, 0, 1)],
            InterventionError::NonCanonicalOrder,
        ),
        (
            vec![planned(2, 0, 2), planned(1, 0, 1)],
            InterventionError::NonCanonicalOrder,
        ),
        (
            vec![planned(1, 0, 1), planned(1, 0, 1)],
            InterventionError::NonCanonicalOrder,
        ),
        (
            vec![planned(1, 0, 1), planned(1, 0, 2)],
            InterventionError::NonContiguousOrdinal,
        ),
        (
            vec![planned(1, 1, 1)],
            InterventionError::NonContiguousOrdinal,
        ),
        (
            vec![planned(1, 0, 1), planned(1, 2, 2)],
            InterventionError::NonContiguousOrdinal,
        ),
        (
            vec![planned(1, 0, 1), planned(2, 1, 2)],
            InterventionError::NonContiguousOrdinal,
        ),
        (
            vec![planned(1, 0, 1), planned(2, 0, 1)],
            InterventionError::DuplicateIdentity,
        ),
    ] {
        assert_eq!(validate_plan_interventions_v1(&plan), Err(expected));
    }
    Ok(())
}

#[test]
fn contract_errors_have_distinct_safe_messages() {
    let errors = [
        (
            InterventionError::InvalidEncoding,
            "invalid INT1 intervention encoding",
        ),
        (
            InterventionError::UnsupportedVersion,
            "unsupported INT1 intervention version",
        ),
        (
            InterventionError::FieldOutOfBounds,
            "INT1 intervention field is out of bounds",
        ),
        (
            InterventionError::UnknownEnum,
            "unknown INT1 intervention operation",
        ),
        (
            InterventionError::NonCanonicalOrder,
            "INT1 plan interventions are not canonically ordered",
        ),
        (
            InterventionError::DuplicateIdentity,
            "INT1 plan intervention ID is duplicated",
        ),
        (
            InterventionError::NonContiguousOrdinal,
            "INT1 plan intervention ordinals are not contiguous",
        ),
    ];
    for (error, message) in errors {
        assert_eq!(error.to_string(), message);
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert_eq!(boxed.to_string(), message);
    }
}
