//! GCA1 guest claims are compared to actual data, never treated as authority.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityClaimArtifactV1 as Artifact, CommunityGuestClaimContextV1 as Context,
    CommunityGuestClaimKindV1 as Kind, CommunityGuestClaimV1 as Claim,
    CommunityLifecycleErrorV1 as Error, COMMUNITY_CLAIM_STATE_SCHEMA_V1 as STATE_SCHEMA,
    COMMUNITY_GUEST_CLAIM_SCHEMA_V1 as CLAIM_SCHEMA,
};
use pos_core::Hash;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn artifact(schema: u32, byte: u8) -> Artifact {
    Artifact {
        schema,
        digest: Hash::from_bytes([byte; 32]),
    }
}
const fn claim_context(drafts: &[Artifact]) -> Context<'_> {
    Context {
        inputs: [
            artifact(10, 1),
            artifact(STATE_SCHEMA, 2),
            artifact(12, 3),
            artifact(13, 4),
        ],
        next_state: artifact(STATE_SCHEMA, 5),
        event_drafts: drafts,
        execution_profile_digest: Hash::from_bytes([6; 32]),
    }
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn reference(position: u64, artifact: Artifact) -> Value {
    Value::Array(vec![
        uint(position),
        uint(u64::from(artifact.schema)),
        bytes(artifact.digest.as_bytes()),
    ])
}
fn fixture(kind: u64, used: Vec<Value>, generated: Vec<Value>) -> Value {
    Value::Array(vec![
        bytes(b"GCA1"),
        uint(1),
        uint(kind),
        Value::Array(used),
        Value::Array(generated),
        bytes(&[6; 32]),
    ])
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}

#[test]
fn valid_claims_keep_exact_kind_reference_coordinates_and_borrowed_bytes() -> TestResult {
    let drafts = [artifact(u32::MAX, 7)];
    let context = claim_context(&drafts);
    let all_used: Vec<_> = context
        .inputs
        .iter()
        .enumerate()
        .map(|(index, artifact)| reference(index as u64, *artifact))
        .collect();
    let all_generated = vec![reference(0, context.next_state), reference(1, drafts[0])];
    for (code, kind, used, generated) in [
        (0, Kind::InputAvailable, all_used.clone(), vec![]),
        (1, Kind::OutputProduced, vec![], all_generated.clone()),
        (2, Kind::DeclaredDerivation, all_used, all_generated),
    ] {
        let encoded = encode(&fixture(code, used, generated))?;
        let claim = Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context)?;
        assert!(claim.kind() == kind);
        assert_eq!(claim.as_canonical_cbor(), &encoded);
        assert!(std::ptr::eq(claim.as_canonical_cbor(), encoded.as_slice()));
        for references in [claim.used_refs(), claim.generated_refs()] {
            let rows = references.as_canonical_rows();
            let offset = rows.as_ptr() as usize - encoded.as_ptr() as usize;
            assert!(offset + rows.len() <= encoded.len());
            assert_eq!(&encoded[offset..offset + rows.len()], rows);
            let parsed = references.iter().collect::<Result<Vec<_>, _>>()?;
            assert_eq!(parsed.len(), references.len());
            assert_eq!(references.iter().len(), references.len());
            for row in parsed {
                assert_ne!(row.digest, Hash::zero());
            }
        }
    }
    Ok(())
}

#[test]
fn claim_kind_requires_its_exact_nonempty_input_output_shape() -> TestResult {
    let context = claim_context(&[]);
    for kind in 0..3 {
        for has_used in [false, true] {
            for has_generated in [false, true] {
                let used = if has_used {
                    vec![reference(0, context.inputs[0])]
                } else {
                    vec![]
                };
                let generated = if has_generated {
                    vec![reference(0, context.next_state)]
                } else {
                    vec![]
                };
                let encoded = encode(&fixture(kind, used, generated))?;
                let accepted = match kind {
                    0 => has_used && !has_generated,
                    1 => !has_used && has_generated,
                    _ => has_used && has_generated,
                };
                assert_eq!(
                    Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context).is_ok(),
                    accepted
                );
            }
        }
    }
    for kind in [3, u64::MAX] {
        let encoded = encode(&fixture(kind, vec![], vec![]))?;
        assert_eq!(
            Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn substituted_schemas_digests_or_nonexistent_positions_are_refused() -> TestResult {
    let drafts = [artifact(20, 7)];
    let context = claim_context(&drafts);
    for (kind, used, generated) in [
        (0, vec![reference(0, artifact(11, 1))], vec![]),
        (0, vec![reference(0, artifact(10, 9))], vec![]),
        (0, vec![reference(4, context.inputs[0])], vec![]),
        (0, vec![reference(u64::MAX, context.inputs[0])], vec![]),
        (1, vec![], vec![reference(0, artifact(20, 5))]),
        (1, vec![], vec![reference(1, artifact(20, 9))]),
        (1, vec![], vec![reference(2, drafts[0])]),
        (1, vec![], vec![reference(u64::MAX, drafts[0])]),
    ] {
        let encoded = encode(&fixture(kind, used, generated))?;
        assert_eq!(
            Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn claim_requires_strict_unique_reference_tuple_order_and_fixed_policy() -> TestResult {
    let context = claim_context(&[]);
    for rows in [
        vec![
            reference(1, context.inputs[1]),
            reference(0, context.inputs[0]),
        ],
        vec![
            reference(0, context.inputs[0]),
            reference(0, context.inputs[0]),
        ],
    ] {
        let encoded = encode(&fixture(0, rows, vec![]))?;
        assert_eq!(
            Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut value = fixture(0, vec![reference(0, context.inputs[0])], vec![]);
    fields(&mut value)?[5] = bytes(&[9; 32]);
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &encode(&value)?, &context).err(),
        Some(Error::InvalidBinding)
    );
    let encoded = encode(&fixture(0, vec![reference(0, context.inputs[0])], vec![]))?;
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA + 1, &encoded, &context).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn actual_comparison_context_requires_state_schemas_and_nonzero_identities() -> TestResult {
    let context = claim_context(&[]);
    let encoded = encode(&fixture(0, vec![reference(0, context.inputs[0])], vec![]))?;
    for index in 0..7 {
        let mut changed = claim_context(&[]);
        match index {
            0 => changed.inputs[1].schema = 0,
            1 => changed.next_state.schema = 0,
            2 => changed.execution_profile_digest = Hash::zero(),
            3 => changed.inputs[0].digest = Hash::zero(),
            4 => changed.inputs[1].digest = Hash::zero(),
            5 => changed.inputs[2].digest = Hash::zero(),
            _ => changed.inputs[3].digest = Hash::zero(),
        }
        assert_eq!(
            Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &changed).err(),
            Some(Error::InvalidBinding)
        );
    }
    let bad_state = Context {
        next_state: artifact(STATE_SCHEMA, 0),
        ..claim_context(&[])
    };
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &bad_state).err(),
        Some(Error::InvalidBinding)
    );
    let drafts = [artifact(20, 0)];
    let bad_draft = claim_context(&drafts);
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &bad_draft).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn reference_count_limit_is_inclusive_and_precedes_element_decoding() -> TestResult {
    let context = claim_context(&[]);
    for (count, expected) in [
        (4096, Error::InvalidEncoding),
        (4097, Error::BoundsExceeded),
    ] {
        let encoded = encode(&fixture(0, vec![Value::Null; count], vec![]))?;
        assert_eq!(
            Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context).err(),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn all_actual_drafts_fit_the_shared_claim_reference_bound() -> TestResult {
    let drafts = vec![artifact(20, 7); 1024];
    let context = claim_context(&drafts);
    let used = context
        .inputs
        .iter()
        .enumerate()
        .map(|(index, artifact)| reference(index as u64, *artifact))
        .collect();
    let generated = std::iter::once(reference(0, context.next_state))
        .chain(
            drafts
                .iter()
                .enumerate()
                .map(|(index, artifact)| reference(index as u64 + 1, *artifact)),
        )
        .collect();
    let encoded = encode(&fixture(2, used, generated))?;
    let claim = Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context)?;
    assert_eq!(claim.used_refs().len(), 4);
    assert_eq!(claim.generated_refs().len(), 1025);
    let refs = claim
        .generated_refs()
        .iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(refs[0].schema, STATE_SCHEMA);
    assert_eq!(refs[1024].position, 1024);
    assert_eq!(refs[1024].schema, 20);
    let too_many = vec![artifact(20, 7); 1025];
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &claim_context(&too_many)).err(),
        Some(Error::BoundsExceeded)
    );
    for side in [3, 4] {
        let mut value = fixture(0, vec![], vec![]);
        fields(&mut value)?[side] = Value::Array(vec![uint(0); 4097]);
        assert_eq!(
            Claim::validate_annotation(CLAIM_SCHEMA, &encode(&value)?, &context).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn malformed_reference_shapes_scalar_widths_and_payloads_are_refused() -> TestResult {
    let context = claim_context(&[]);
    let good = reference(0, context.inputs[0]);
    let mut variants = vec![
        Value::Array(vec![]),
        Value::Array(vec![uint(0), uint(10)]),
        Value::Array(vec![uint(0), uint(10), bytes(&[1; 32]), uint(0)]),
    ];
    for (index, value) in [
        (0, Value::Null),
        (1, uint(u64::from(u32::MAX) + 1)),
        (2, bytes(&[1; 31])),
    ] {
        let mut row = good.clone();
        fields(&mut row)?[index] = value;
        variants.push(row);
    }
    for row in variants {
        let encoded = encode(&fixture(0, vec![row], vec![]))?;
        assert!(Claim::validate_annotation(CLAIM_SCHEMA, &encoded, &context).is_err());
    }
    Ok(())
}

#[test]
fn claim_rejects_all_truncations_nonpreferred_trailing_versions_and_oversize() -> TestResult {
    let context = claim_context(&[]);
    let value = fixture(0, vec![reference(0, context.inputs[0])], vec![]);
    let encoded = encode(&value)?;
    for end in 0..encoded.len() {
        assert!(Claim::validate_annotation(CLAIM_SCHEMA, &encoded[..end], &context).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &trailing, &context).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = value;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &encode(&unsupported)?, &context).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &nonpreferred, &context).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Claim::validate_annotation(CLAIM_SCHEMA, &vec![0; 1_048_577], &context).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
