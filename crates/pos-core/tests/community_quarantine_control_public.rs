//! Independent CQC1/CQO1 shapes; data never installs current reset authority.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    ArtifactRefV1 as Artifact, CommunityLifecycleErrorV1 as Error,
    CommunityQuarantineControlInputV1 as Input, CommunityQuarantineControlKindV1 as Operation,
    CommunityQuarantineControlV1 as Request, CommunityQuarantineDispositionV1 as Disposition,
    CommunityQuarantineKeyV1 as Key, CommunityQuarantineOutcomeInputV1 as OutcomeInput,
    CommunityQuarantineOutcomeV1 as Outcome, CommunityQuarantineReasonEvidenceV1 as Evidence,
    CommunityQuarantineReasonV1 as Reason, CommunityQuarantineReasonsV1 as Reasons,
};
use pos_core::{Hash, ImplementationKeyV1, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
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
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}
fn implementation() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "v".into(),
        hash(3),
    )?)
}
fn key(implementation: &ImplementationKeyV1) -> Result<Key<'_>, Error> {
    Key::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        "slot",
        implementation,
    )
}
fn key_value() -> Fallible<Value> {
    let implementation = Value::Array(vec![
        bytes(b"IMK1"),
        uint(1),
        Value::Text("plugin-a".into()),
        Value::Text("v".into()),
        bytes(&[3; 32]),
    ]);
    Ok(Value::Array(vec![
        bytes(b"CQK1"),
        uint(1),
        bytes(&[1; 16]),
        Value::Text("slot".into()),
        bytes(&encode(&implementation)?),
    ]))
}
const fn artifact(schema: u32, byte: u8) -> Artifact {
    Artifact {
        schema_id: schema,
        byte_length: u64::MAX,
        digest: [byte; 32],
    }
}
const fn reasons() -> [Evidence; 4] {
    [
        Evidence {
            reason: Reason::Trapped,
            failure_evidence_digest: hash(12),
        },
        Evidence {
            reason: Reason::ResourceExhausted,
            failure_evidence_digest: hash(13),
        },
        Evidence {
            reason: Reason::Revoked,
            failure_evidence_digest: hash(14),
        },
        Evidence {
            reason: Reason::Unavailable,
            failure_evidence_digest: hash(15),
        },
    ]
}
fn input<'a>(
    implementation: &'a ImplementationKeyV1,
    reasons: &'a [Evidence],
    operation: Operation,
) -> Fallible<Input<'a>> {
    let reset = operation == Operation::AuthenticatedReset;
    Ok(Input {
        control_operation_id: [2; 16],
        key: key(implementation)?,
        expected_ledger_digest: Some(hash(4)),
        operation,
        bound_reasons: Reasons::from_reasons(reasons),
        trust_snapshot_digest: hash(5),
        expected_generation: [6; 16],
        expected_state_head_digest: hash(7),
        principal_ref: reset.then_some(artifact(u32::MAX, 8)),
        authorization_ref: reset.then_some(artifact(1, 9)),
        authorization_not_after_micros: 10,
        host_decision_provenance_digest: hash(11),
    })
}
fn reference(schema: u32, byte: u8) -> Value {
    Value::Array(vec![
        uint(u64::from(schema)),
        uint(u64::MAX),
        bytes(&[byte; 32]),
    ])
}
fn request_value(reasons: &[Evidence], reset: bool) -> Fallible<Value> {
    let reasons = Value::Array(
        reasons
            .iter()
            .map(|entry| {
                Value::Array(vec![
                    uint(u64::from(entry.reason.code())),
                    bytes(entry.failure_evidence_digest.as_bytes()),
                ])
            })
            .collect(),
    );
    Ok(Value::Array(vec![
        bytes(b"CQC1"),
        uint(1),
        bytes(&[2; 16]),
        bytes(&encode(&key_value()?)?),
        bytes(&[4; 32]),
        uint(u64::from(reset)),
        reasons,
        bytes(&[5; 32]),
        bytes(&[6; 16]),
        bytes(&[7; 32]),
        if reset {
            reference(u32::MAX, 8)
        } else {
            Value::Null
        },
        if reset { reference(1, 9) } else { Value::Null },
        uint(10),
        bytes(&[11; 32]),
    ]))
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.push(0);
    preimage.extend_from_slice(bytes);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
const fn outcome_input(prior: Option<Hash>, disposition: Disposition) -> OutcomeInput {
    OutcomeInput {
        control_operation_id: [2; 16],
        control_request_digest: hash(3),
        prior_ledger_digest: prior,
        selected_ledger_digest: hash(4),
        disposition,
        evidence_not_after_micros: 5,
    }
}
fn outcome_value(prior: Option<Hash>, code: u64) -> Value {
    Value::Array(vec![
        bytes(b"CQO1"),
        uint(1),
        bytes(&[2; 16]),
        bytes(&[3; 32]),
        prior.map_or(Value::Null, |hash| bytes(hash.as_bytes())),
        bytes(&[4; 32]),
        uint(code),
        uint(5),
    ])
}

#[test]
fn control_requests_have_exact_fourteen_fields_and_different_authority_ref_shapes() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    for (operation, rows, reset) in [
        (Operation::SetReason, &reasons[..1], false),
        (Operation::AuthenticatedReset, &reasons[..], true),
    ] {
        let input = input(&implementation, rows, operation)?;
        let request = Request::new(input)?;
        let expected = encode(&request_value(rows, reset)?)?;
        assert_eq!(&*request.to_canonical_cbor(), &expected);
        assert_eq!(
            request.digest(),
            domain_hash(b"PiglorOS.Community.CQC1.v1", &expected)
        );
        assert!(*Request::from_canonical_cbor(&expected, &implementation)?.as_input() == input);
    }
    Ok(())
}

#[test]
fn set_reason_never_borrows_guest_refs_and_reset_always_requires_both() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    for rows in [&[][..], &reasons[..2]] {
        assert_eq!(
            Request::new(input(&implementation, rows, Operation::SetReason)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    let base = input(&implementation, &reasons[..1], Operation::SetReason)?;
    for changed in [
        Input {
            principal_ref: Some(artifact(1, 8)),
            ..base
        },
        Input {
            authorization_ref: Some(artifact(1, 9)),
            ..base
        },
    ] {
        assert_eq!(Request::new(changed).err(), Some(Error::InvalidBinding));
    }
    let base = input(&implementation, &reasons, Operation::AuthenticatedReset)?;
    for changed in [
        Input {
            principal_ref: None,
            ..base
        },
        Input {
            authorization_ref: None,
            ..base
        },
    ] {
        assert_eq!(Request::new(changed).err(), Some(Error::InvalidBinding));
    }
    // An authenticated empty expected set is still data, never a reset grant.
    assert!(Request::new(input(&implementation, &[], Operation::AuthenticatedReset)?).is_ok());
    Ok(())
}

#[test]
fn control_checks_every_required_identity_and_the_fixed_command_horizon() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    let base = input(&implementation, &reasons, Operation::AuthenticatedReset)?;
    for index in 0..8 {
        let mut changed = base;
        match index {
            0 => changed.control_operation_id = [0; 16],
            1 => changed.expected_generation = [0; 16],
            2 => changed.expected_ledger_digest = Some(Hash::zero()),
            3 => changed.trust_snapshot_digest = Hash::zero(),
            4 => changed.expected_state_head_digest = Hash::zero(),
            5 => changed.host_decision_provenance_digest = Hash::zero(),
            6 => changed.principal_ref = Some(artifact(1, 0)),
            _ => changed.authorization_ref = Some(artifact(1, 0)),
        }
        assert_eq!(Request::new(changed).err(), Some(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Request::new(Input {
                authorization_not_after_micros: horizon,
                ..base
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    assert!(Request::new(Input {
        authorization_not_after_micros: u64::MAX / 2,
        expected_ledger_digest: None,
        ..base
    })
    .is_ok());
    Ok(())
}

#[test]
fn request_reason_sets_and_nested_identity_remain_exact() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    for rows in [
        vec![reasons[1], reasons[0]],
        vec![reasons[0], reasons[0]],
        vec![Evidence {
            failure_evidence_digest: Hash::zero(),
            ..reasons[0]
        }],
    ] {
        assert_eq!(
            Request::new(input(
                &implementation,
                &rows,
                Operation::AuthenticatedReset
            )?)
            .err(),
            Some(Error::InvalidBinding)
        );
    }
    let excess = [reasons[0]; 5];
    assert_eq!(
        Request::new(input(
            &implementation,
            &excess,
            Operation::AuthenticatedReset
        )?)
        .err(),
        Some(Error::BoundsExceeded)
    );
    let encoded = encode(&request_value(&reasons, true)?)?;
    let foreign = ImplementationKeyV1::new("plugin-a".into(), "v".into(), hash(20))?;
    assert_eq!(
        Request::from_canonical_cbor(&encoded, &foreign).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn request_rejects_unknown_operation_malformed_refs_and_overwide_schema() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    for (index, replacement, error) in [
        (5, uint(2), Error::InvalidEncoding),
        (2, bytes(&[2; 15]), Error::InvalidEncoding),
        (8, bytes(&[6; 17]), Error::InvalidEncoding),
        (
            10,
            Value::Array(vec![
                uint(u64::from(u32::MAX) + 1),
                uint(1),
                bytes(&[8; 32]),
            ]),
            Error::BoundsExceeded,
        ),
        (10, Value::Array(vec![]), Error::InvalidEncoding),
        (
            11,
            Value::Array(vec![uint(1), uint(1), bytes(&[9; 31])]),
            Error::InvalidEncoding,
        ),
        (3, bytes(&[]), Error::InvalidEncoding),
    ] {
        let mut value = request_value(&reasons, true)?;
        fields(&mut value)?[index] = replacement;
        assert_eq!(
            Request::from_canonical_cbor(&encode(&value)?, &implementation).err(),
            Some(error)
        );
    }
    Ok(())
}

#[test]
fn request_rejects_all_truncations_trailing_versions_nonpreferred_and_oversize() -> TestResult {
    let implementation = implementation()?;
    let value = request_value(&reasons(), true)?;
    let encoded = encode(&value)?;
    for end in 0..encoded.len() {
        assert!(Request::from_canonical_cbor(&encoded[..end], &implementation).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Request::from_canonical_cbor(&trailing, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = value;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Request::from_canonical_cbor(&encode(&unsupported)?, &implementation).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Request::from_canonical_cbor(&nonpreferred, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Request::from_canonical_cbor(&vec![0; 4097], &implementation).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn control_outcomes_have_exact_original_links_and_disposition_codes() -> TestResult {
    for (prior, disposition, code) in [
        (None, Disposition::Applied, 0),
        (Some(hash(6)), Disposition::Applied, 0),
        (Some(hash(4)), Disposition::AlreadyQuarantined, 1),
    ] {
        let input = outcome_input(prior, disposition);
        let outcome = Outcome::new(input)?;
        let expected = encode(&outcome_value(prior, code))?;
        assert_eq!(&*outcome.to_canonical_cbor(), &expected);
        assert!(*Outcome::from_canonical_cbor(&expected)?.as_input() == input);
        assert_eq!(
            outcome.digest(),
            domain_hash(b"PiglorOS.Community.CQO1.v1", &expected)
        );
    }
    Ok(())
}

#[test]
fn already_quarantined_preserves_selection_and_checks_fixed_fields() {
    for prior in [None, Some(hash(6))] {
        assert_eq!(
            Outcome::new(outcome_input(prior, Disposition::AlreadyQuarantined)).err(),
            Some(Error::InvalidBinding)
        );
    }
    let base = outcome_input(None, Disposition::Applied);
    for changed in [
        OutcomeInput {
            control_operation_id: [0; 16],
            ..base
        },
        OutcomeInput {
            control_request_digest: Hash::zero(),
            ..base
        },
        OutcomeInput {
            selected_ledger_digest: Hash::zero(),
            ..base
        },
        OutcomeInput {
            prior_ledger_digest: Some(Hash::zero()),
            ..base
        },
    ] {
        assert_eq!(Outcome::new(changed).err(), Some(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Outcome::new(OutcomeInput {
                evidence_not_after_micros: horizon,
                ..base
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    assert!(Outcome::new(OutcomeInput {
        evidence_not_after_micros: u64::MAX / 2,
        ..base
    })
    .is_ok());
}

#[test]
fn outcome_rejects_all_truncations_unknown_disposition_and_framing() -> TestResult {
    let value = outcome_value(Some(hash(4)), 1);
    let encoded = encode(&value)?;
    for end in 0..encoded.len() {
        assert!(Outcome::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Outcome::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    for (index, replacement, error) in [
        (1, uint(2), Error::UnsupportedVersion),
        (6, uint(2), Error::InvalidEncoding),
        (2, bytes(&[2; 17]), Error::InvalidEncoding),
    ] {
        let mut changed = value.clone();
        fields(&mut changed)?[index] = replacement;
        assert_eq!(
            Outcome::from_canonical_cbor(&encode(&changed)?).err(),
            Some(error)
        );
    }
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Outcome::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Outcome::from_canonical_cbor(&vec![0; 1025]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
