//! Independent CRR1 oracles and complete due-roster substitution checks.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityAnnotationOmissionV1 as Reason, CommunityAnnotationOmissionsV1 as Reasons,
    CommunityInvocationEvidenceInputV1 as InvocationInput,
    CommunityInvocationEvidenceV1 as Invocation, CommunityLifecycleErrorV1 as Error,
    CommunityOutputUsageV1 as Usage, CommunityPassKeyV1 as Pass,
    CommunityReplayMemberBindingV1 as Binding, CommunityReplayMemberV1 as Member,
    CommunityReplayRecordingInputV1 as Input, CommunityReplayRecordingV1 as Recording, MeteringV1,
};
use pos_core::{Hash, TimelineId};

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
fn pass() -> Result<Pass, Error> {
    Pass::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        [2; 16],
        3,
    )
}
fn pass_value() -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ])
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.push(0);
    preimage.extend_from_slice(bytes);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
fn invocation(member: u8, tuple: u8, annotations: u64) -> Fallible<Invocation> {
    Ok(Invocation::new(InvocationInput {
        pass_key: pass()?,
        member_binding_digest: hash(member),
        invocation_id: [member; 16],
        negotiated_tuple_digest: hash(tuple),
        prepared_invocation_digest: hash(7),
        validated_output_digest: hash(8),
        metering: MeteringV1 {
            startup_fuel: 0,
            call_fuel: 1,
            memory_bytes: 2,
            host_calls: 3,
        },
        output_usage: Usage {
            event_count: 1,
            event_payload_bytes: 2,
            state_bytes: 3,
        },
        validated_annotation_count: annotations,
        next_state_content_digest: hash(17),
        event_draft_vector_digest: hash(18),
    })?)
}
fn invocation_value(member: u8, tuple: u8, annotations: u64) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CIV1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        bytes(&[member; 32]),
        bytes(&[member; 16]),
        bytes(&[tuple; 32]),
        bytes(&[7; 32]),
        bytes(&[8; 32]),
        Value::Array((0..=3).map(uint).collect()),
        Value::Array((1..=3).map(uint).collect()),
        Value::Null,
        Value::Null,
        uint(annotations),
        bytes(&[17; 32]),
        bytes(&[18; 32]),
    ]))
}
const fn binding(member: u8, tuple: u8) -> Binding {
    Binding {
        member_binding_digest: hash(member),
        negotiated_tuple_digest: hash(tuple),
    }
}
fn input<'a>(due: &'a [Binding], members: &'a [Member<'a>]) -> Fallible<Input<'a>> {
    Ok(Input {
        pass_key: pass()?,
        due_roster: due,
        members,
        evidence_not_after_micros: 19,
    })
}
const fn all_reasons() -> Reasons {
    Reasons::none()
        .with_reason(Reason::AnnotationPolicy)
        .with_reason(Reason::InvalidClaim)
        .with_reason(Reason::AnnotationBudget)
        .with_reason(Reason::UnsupportedClaimSchema)
        .with_reason(Reason::UnresolvedAnnotationInput)
        .with_reason(Reason::InvalidClaim)
}
fn fixture() -> Fallible<Value> {
    let first = encode(&invocation_value(4, 6, 0)?)?;
    let second = encode(&invocation_value(5, 7, 5)?)?;
    Ok(Value::Array(vec![
        bytes(b"CRR1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        Value::Array(vec![
            bytes(domain_hash(b"PiglorOS.Community.CIV1.v1", &first).as_bytes()),
            bytes(domain_hash(b"PiglorOS.Community.CIV1.v1", &second).as_bytes()),
        ]),
        Value::Array(vec![bytes(&[6; 32]), bytes(&[7; 32])]),
        Value::Array(vec![
            Value::Array(vec![
                bytes(&[4; 32]),
                uint(0),
                uint(0),
                Value::Array(vec![]),
            ]),
            Value::Array(vec![
                bytes(&[5; 32]),
                uint(5),
                uint(0),
                Value::Array((0..=4).map(uint).collect()),
            ]),
        ]),
        uint(19),
    ]))
}
fn coverage_rows(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    fields(&mut fields(value)?[5])
}

#[test]
fn recording_has_exact_complete_arrays_and_canonical_reason_set() -> TestResult {
    let first = invocation(4, 6, 0)?;
    let second = invocation(5, 7, 5)?;
    let due = [binding(4, 6), binding(5, 7)];
    let members = [
        Member {
            invocation: &first,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        },
        Member {
            invocation: &second,
            retained_annotation_count: 0,
            omissions: all_reasons(),
        },
    ];
    let recording = Recording::new(input(&due, &members)?)?;
    let expected = encode(&fixture()?)?;
    assert_eq!(&*recording.to_canonical_cbor(), &expected);
    let validated = Recording::validate_canonical_cbor(&expected, input(&due, &members)?)?;
    assert_eq!(
        validated.digest(),
        domain_hash(b"PiglorOS.Community.CRR1.v1", &expected)
    );
    assert_eq!(validated.as_input().members.len(), 2);
    assert!(!all_reasons().is_empty());
    Ok(())
}

#[test]
fn recording_refuses_any_missing_or_substituted_due_binding() -> TestResult {
    let first = invocation(4, 6, 0)?;
    let second = invocation(5, 7, 0)?;
    let members = [
        Member {
            invocation: &first,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        },
        Member {
            invocation: &second,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        },
    ];
    for due in [
        vec![],
        vec![binding(4, 6)],
        vec![binding(5, 7), binding(4, 6)],
        vec![binding(4, 6), binding(4, 6)],
        vec![binding(4, 6), binding(5, 8)],
        vec![binding(4, 6), binding(6, 7)],
        vec![
            Binding {
                member_binding_digest: Hash::zero(),
                ..binding(4, 6)
            },
            binding(5, 7),
        ],
        vec![
            Binding {
                negotiated_tuple_digest: Hash::zero(),
                ..binding(4, 6)
            },
            binding(5, 7),
        ],
    ] {
        assert_eq!(
            Recording::new(input(&due, &members)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    let due = [binding(4, 6), binding(5, 7)];
    let foreign = Input {
        pass_key: Pass::new(
            TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
            [2; 16],
            4,
        )?,
        ..input(&due, &members)?
    };
    assert_eq!(Recording::new(foreign).err(), Some(Error::InvalidBinding));
    Ok(())
}

#[test]
fn annotation_coverage_requires_exact_counts_and_explained_omissions() -> TestResult {
    let evidence = invocation(4, 6, 5)?;
    let due = [binding(4, 6)];
    for (retained, omissions) in [
        (6, Reasons::none()),
        (5, all_reasons()),
        (0, Reasons::none()),
    ] {
        let members = [Member {
            invocation: &evidence,
            retained_annotation_count: retained,
            omissions,
        }];
        assert_eq!(
            Recording::new(input(&due, &members)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for (retained, omissions) in [
        (5, Reasons::none()),
        (4, Reasons::none().with_reason(Reason::AnnotationBudget)),
        (0, all_reasons()),
    ] {
        let members = [Member {
            invocation: &evidence,
            retained_annotation_count: retained,
            omissions,
        }];
        let encoded = Recording::new(input(&due, &members)?)?.to_canonical_cbor();
        assert!(Recording::validate_canonical_cbor(&encoded, input(&due, &members)?).is_ok());
    }
    Ok(())
}

#[test]
fn retained_wire_must_match_every_invocation_tuple_and_coverage_row() -> TestResult {
    let first = invocation(4, 6, 0)?;
    let second = invocation(5, 7, 5)?;
    let due = [binding(4, 6), binding(5, 7)];
    let members = [
        Member {
            invocation: &first,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        },
        Member {
            invocation: &second,
            retained_annotation_count: 0,
            omissions: all_reasons(),
        },
    ];
    for index in [3, 4] {
        for replacement in [Value::Array(vec![]), Value::Array(vec![bytes(&[9; 32]); 2])] {
            let mut value = fixture()?;
            fields(&mut value)?[index] = replacement;
            assert_eq!(
                Recording::validate_canonical_cbor(&encode(&value)?, input(&due, &members)?).err(),
                Some(Error::InvalidBinding)
            );
        }
    }
    let mut value = fixture()?;
    fields(&mut value)?[5] = Value::Array(vec![]);
    assert_eq!(
        Recording::validate_canonical_cbor(&encode(&value)?, input(&due, &members)?).err(),
        Some(Error::InvalidBinding)
    );
    for (index, replacement) in [
        (0, bytes(&[9; 32])),
        (1, uint(4)),
        (2, uint(1)),
        (3, Value::Array(vec![uint(0)])),
    ] {
        let mut value = fixture()?;
        fields(&mut coverage_rows(&mut value)?[1])?[index] = replacement;
        assert_eq!(
            Recording::validate_canonical_cbor(&encode(&value)?, input(&due, &members)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for (index, replacement) in [
        (
            2,
            bytes(&encode(&Value::Array(vec![
                bytes(b"CPK1"),
                uint(1),
                bytes(&[1; 16]),
                bytes(&[2; 16]),
                uint(4),
            ]))?),
        ),
        (6, uint(20)),
    ] {
        let mut value = fixture()?;
        fields(&mut value)?[index] = replacement;
        assert_eq!(
            Recording::validate_canonical_cbor(&encode(&value)?, input(&due, &members)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn omission_wire_rejects_unknown_duplicate_unsorted_and_overlong_sets() -> TestResult {
    let first = invocation(4, 6, 0)?;
    let second = invocation(5, 7, 5)?;
    let due = [binding(4, 6), binding(5, 7)];
    let members = [
        Member {
            invocation: &first,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        },
        Member {
            invocation: &second,
            retained_annotation_count: 0,
            omissions: all_reasons(),
        },
    ];
    for (codes, error) in [
        (vec![5], Error::InvalidEncoding),
        (vec![1, 1], Error::InvalidBinding),
        (vec![1, 0], Error::InvalidBinding),
        (vec![0; 6], Error::BoundsExceeded),
    ] {
        let mut value = fixture()?;
        fields(&mut coverage_rows(&mut value)?[1])?[3] =
            Value::Array(codes.into_iter().map(uint).collect());
        assert_eq!(
            Recording::validate_canonical_cbor(&encode(&value)?, input(&due, &members)?).err(),
            Some(error)
        );
    }
    let mut encoded = encode(&fixture()?)?;
    let start = encoded
        .windows(6)
        .position(|bytes| bytes == [0x85, 0, 1, 2, 3, 4])
        .ok_or("missing reason fixture")?;
    encoded.splice(start + 1..start + 2, [0x18, 0]);
    assert_eq!(
        Recording::validate_canonical_cbor(&encoded, input(&due, &members)?).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn recording_accepts_64_members_and_refuses_65() -> TestResult {
    let invocations: Vec<_> = (1..=65)
        .map(|member| invocation(member, 6, 0))
        .collect::<Fallible<_>>()?;
    let due: Vec<_> = (1..=65).map(|member| binding(member, 6)).collect();
    let members: Vec<_> = invocations
        .iter()
        .map(|invocation| Member {
            invocation,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        })
        .collect();
    let recording = Recording::new(input(&due[..64], &members[..64])?)?;
    let encoded = recording.to_canonical_cbor();
    assert!(encoded.len() <= 65_536);
    assert_eq!(
        Recording::validate_canonical_cbor(&encoded, input(&due[..64], &members[..64])?)?
            .as_input()
            .members
            .len(),
        64
    );
    assert_eq!(
        Recording::new(input(&due, &members)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn recording_preserves_fixed_horizon_and_structural_empty_lists() -> TestResult {
    for horizon in [1, 23, 24, 65_536, u64::MAX / 2] {
        let expected = Input {
            evidence_not_after_micros: horizon,
            ..input(&[], &[])?
        };
        let encoded = Recording::new(expected)?.to_canonical_cbor();
        let expected = Input {
            evidence_not_after_micros: horizon,
            ..input(&[], &[])?
        };
        assert_eq!(
            Recording::validate_canonical_cbor(&encoded, expected)?
                .as_input()
                .evidence_not_after_micros,
            horizon
        );
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Recording::new(Input {
                evidence_not_after_micros: horizon,
                ..input(&[], &[])?
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn recording_rejects_truncations_trailers_versions_and_oversized_records() -> TestResult {
    let first = invocation(4, 6, 0)?;
    let second = invocation(5, 7, 5)?;
    let due = [binding(4, 6), binding(5, 7)];
    let members = [
        Member {
            invocation: &first,
            retained_annotation_count: 0,
            omissions: Reasons::none(),
        },
        Member {
            invocation: &second,
            retained_annotation_count: 0,
            omissions: all_reasons(),
        },
    ];
    let encoded = encode(&fixture()?)?;
    for end in 0..encoded.len() {
        assert!(
            Recording::validate_canonical_cbor(&encoded[..end], input(&due, &members)?).is_err()
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Recording::validate_canonical_cbor(&trailing, input(&due, &members)?).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = fixture()?;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Recording::validate_canonical_cbor(&encode(&unsupported)?, input(&due, &members)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Recording::validate_canonical_cbor(&nonpreferred, input(&due, &members)?).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Recording::validate_canonical_cbor(&vec![0; 65_537], input(&due, &members)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
