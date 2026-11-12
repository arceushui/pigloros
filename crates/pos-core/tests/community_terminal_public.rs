//! Independent terminal wire fixtures, not a claim that a live store committed.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityAbortInputV1 as AbortInput, CommunityAbortReasonV1 as Reason,
    CommunityAbortV1 as Abort, CommunityCommitInputV1 as CommitInput, CommunityCommitV1 as Commit,
    CommunityFactualRangeV1 as Range, CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1,
};
use pos_core::{Hash, Seq, TimelineId};

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

fn optional(hash: Option<Hash>) -> Value {
    hash.map_or(Value::Null, |hash| bytes(hash.as_bytes()))
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn pass() -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([7; 16])),
        [8; 16],
        999,
    )
}

fn pass_bytes() -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[7; 16]),
        bytes(&[8; 16]),
        uint(999),
    ]))
}

const fn range(tick: u64, first: u64, last: u64) -> Range {
    Range {
        tick,
        first_logical_sequence: Seq::from_u64(first),
        last_logical_sequence: Seq::from_u64(last),
    }
}

fn commit_input() -> Result<CommitInput, Error> {
    Ok(CommitInput {
        pass_key: pass()?,
        reservation_digest: hash(1),
        sealed_result_digest: hash(2),
        selected_head_digest: hash(3),
        factual_range: None,
        dependency_commit_digest: hash(4),
        inventory_commit_digest: hash(5),
        evidence_not_after_micros: 1,
    })
}

fn commit_fields(input: CommitInput) -> Fallible<Vec<Value>> {
    let factual = input.factual_range.map_or(Value::Null, |range| {
        Value::Array(vec![
            uint(range.tick),
            uint(range.first_logical_sequence.as_u64()),
            uint(range.last_logical_sequence.as_u64()),
        ])
    });
    Ok(vec![
        bytes(b"CPC1"),
        uint(1),
        bytes(&pass_bytes()?),
        bytes(input.reservation_digest.as_bytes()),
        bytes(input.sealed_result_digest.as_bytes()),
        bytes(input.selected_head_digest.as_bytes()),
        factual,
        bytes(input.dependency_commit_digest.as_bytes()),
        bytes(input.inventory_commit_digest.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

fn abort_input(reason: Reason) -> Result<AbortInput, Error> {
    Ok(AbortInput {
        pass_key: pass()?,
        reservation_digest: hash(1),
        sealed_result_digest: None,
        reason,
        failure_evidence_digest: Some(hash(2)),
        quarantine_delta_digest: None,
        evidence_not_after_micros: 1,
    })
}

fn abort_fields(input: AbortInput, code: u64) -> Fallible<Vec<Value>> {
    Ok(vec![
        bytes(b"CAB1"),
        uint(1),
        bytes(&pass_bytes()?),
        bytes(input.reservation_digest.as_bytes()),
        optional(input.sealed_result_digest),
        uint(code),
        optional(input.failure_evidence_digest),
        optional(input.quarantine_delta_digest),
        uint(input.evidence_not_after_micros),
    ])
}

fn assert_framing(encoded: &[u8], decode: impl Fn(&[u8]) -> Result<(), Error>) {
    for end in 0..encoded.len() {
        assert!(decode(&encoded[..end]).is_err(), "accepted prefix {end}");
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(Error::InvalidEncoding));
    assert_eq!(decode(&vec![0; 1025]), Err(Error::BoundsExceeded));
    let mut version = encoded.to_vec();
    version[6] = 2;
    assert_eq!(decode(&version), Err(Error::UnsupportedVersion));
    let mut preferred = encoded.to_vec();
    preferred.splice(6..7, [0x18, 1]);
    assert_eq!(decode(&preferred), Err(Error::InvalidEncoding));
}

#[test]
fn committed_pass_has_exact_ten_fields_with_independent_factual_allocation() -> TestResult {
    for factual in [
        None,
        Some(range(1, 1, 1)),
        Some(range(24, 100, 102)),
        Some(range(u64::MAX, u64::MAX, u64::MAX)),
    ] {
        let input = CommitInput {
            factual_range: factual,
            evidence_not_after_micros: u64::MAX / 2,
            ..commit_input()?
        };
        let expected = encode(&Value::Array(commit_fields(input)?))?;
        let record = Commit::new(input)?;
        assert!(record.as_input() == &input);
        assert_eq!(record.to_canonical_cbor().as_slice(), expected);
        assert!(Commit::from_canonical_cbor(&expected)?.as_input() == &input);
        assert!(expected.len() <= 1024);
    }
    Ok(())
}

#[test]
fn null_factual_range_preserves_state_only_dependency_and_inventory_links() -> TestResult {
    let record = Commit::new(commit_input()?)?;
    let encoded = record.to_canonical_cbor();
    let restored = Commit::from_canonical_cbor(&encoded)?;
    assert!(restored.as_input().factual_range.is_none());
    assert_eq!(restored.as_input().dependency_commit_digest, hash(4));
    assert_eq!(restored.as_input().inventory_commit_digest, hash(5));
    assert_eq!(restored.as_input().pass_key.ordinal(), 999);
    Ok(())
}

#[test]
fn commit_refuses_zero_required_links_and_nonpositive_or_reversed_ranges() -> TestResult {
    for field in [3, 4, 5, 7, 8] {
        let mut fields = commit_fields(commit_input()?)?;
        fields[field] = bytes(&[0; 32]);
        assert_eq!(
            Commit::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for factual in [
        range(0, 1, 1),
        range(1, 0, 1),
        range(1, 2, 1),
        range(1, 1, 0),
    ] {
        let input = CommitInput {
            factual_range: Some(factual),
            ..commit_input()?
        };
        let encoded = encode(&Value::Array(commit_fields(input)?))?;
        assert_eq!(Commit::new(input).err(), Some(Error::InvalidBinding));
        assert_eq!(
            Commit::from_canonical_cbor(&encoded).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn commit_refuses_invalid_horizons_and_every_truncation() -> TestResult {
    for horizon in [0, (u64::MAX / 2) + 1, u64::MAX] {
        let input = CommitInput {
            evidence_not_after_micros: horizon,
            ..commit_input()?
        };
        let encoded = encode(&Value::Array(commit_fields(input)?))?;
        assert_eq!(
            Commit::from_canonical_cbor(&encoded).err(),
            Some(Error::BoundsExceeded)
        );
    }
    for factual in [None, Some(range(1, 1, 2))] {
        let input = CommitInput {
            factual_range: factual,
            ..commit_input()?
        };
        assert_framing(&encode(&Value::Array(commit_fields(input)?))?, |bytes| {
            Commit::from_canonical_cbor(bytes).map(|_| ())
        });
    }
    Ok(())
}

#[test]
fn factual_range_arity_type_and_integer_framing_are_closed() -> TestResult {
    for factual in [
        Value::Array(vec![uint(1), uint(1)]),
        Value::Array(vec![uint(1), uint(1), uint(1), uint(1)]),
        Value::Bool(false),
        Value::Array(vec![uint(1), Value::Null, uint(1)]),
    ] {
        let mut fields = commit_fields(commit_input()?)?;
        fields[6] = factual;
        assert_eq!(
            Commit::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut fields = commit_fields(commit_input()?)?;
    fields[6] = Value::Array(vec![uint(1), uint(1), uint(1)]);
    let mut encoded = encode(&Value::Array(fields[..6].to_vec()))?;
    encoded[0] = 0x8a;
    encoded.extend_from_slice(&[0x83, 0x18, 1, 1, 1]);
    for field in &fields[7..] {
        encoded.extend_from_slice(&encode(field)?);
    }
    assert_eq!(
        Commit::from_canonical_cbor(&encoded).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn aborted_pass_has_exact_nine_fields_and_all_five_explicit_reason_codes() -> TestResult {
    for (code, reason) in [
        (0, Reason::AuthenticatedCancellation),
        (1, Reason::ValidatedInvocationFailure),
        (2, Reason::AdmissionRefused),
        (3, Reason::ProtectedUseRefused),
        (4, Reason::RetiringGeneration),
    ] {
        for sealed in [None, Some(hash(3))] {
            for delta in [None, Some(hash(4))] {
                let input = AbortInput {
                    sealed_result_digest: sealed,
                    quarantine_delta_digest: delta,
                    evidence_not_after_micros: u64::MAX / 2,
                    ..abort_input(reason)?
                };
                let expected = encode(&Value::Array(abort_fields(input, code)?))?;
                let record = Abort::new(input)?;
                assert!(record.as_input() == &input);
                assert_eq!(record.to_canonical_cbor().as_slice(), expected);
                assert!(Abort::from_canonical_cbor(&expected)?.as_input() == &input);
                assert!(expected.len() <= 1024);
            }
        }
    }
    Ok(())
}

#[test]
fn failure_and_refusal_reasons_require_their_exact_evidence_link() -> TestResult {
    for (code, reason) in [
        (1, Reason::ValidatedInvocationFailure),
        (2, Reason::AdmissionRefused),
        (3, Reason::ProtectedUseRefused),
    ] {
        let input = AbortInput {
            failure_evidence_digest: None,
            ..abort_input(reason)?
        };
        let encoded = encode(&Value::Array(abort_fields(input, code)?))?;
        assert_eq!(Abort::new(input).err(), Some(Error::InvalidBinding));
        assert_eq!(
            Abort::from_canonical_cbor(&encoded).err(),
            Some(Error::InvalidBinding)
        );
    }
    for (code, reason) in [
        (0, Reason::AuthenticatedCancellation),
        (4, Reason::RetiringGeneration),
    ] {
        let input = AbortInput {
            failure_evidence_digest: None,
            ..abort_input(reason)?
        };
        let expected = encode(&Value::Array(abort_fields(input, code)?))?;
        assert!(Abort::from_canonical_cbor(&expected)?.as_input() == &input);
    }
    Ok(())
}

#[test]
fn abort_refuses_zero_links_horizon_errors_and_unknown_reasons() -> TestResult {
    for field in [3, 4, 6, 7] {
        let mut fields = abort_fields(abort_input(Reason::ValidatedInvocationFailure)?, 1)?;
        fields[field] = bytes(&[0; 32]);
        assert_eq!(
            Abort::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for horizon in [0, (u64::MAX / 2) + 1, u64::MAX] {
        let input = AbortInput {
            evidence_not_after_micros: horizon,
            ..abort_input(Reason::ValidatedInvocationFailure)?
        };
        assert_eq!(
            Abort::from_canonical_cbor(&encode(&Value::Array(abort_fields(input, 1)?))?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    for code in [5, 24, u64::MAX] {
        let encoded = encode(&Value::Array(abort_fields(
            abort_input(Reason::AuthenticatedCancellation)?,
            code,
        )?))?;
        assert_eq!(
            Abort::from_canonical_cbor(&encoded).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn abort_rejects_every_truncation_and_malformed_optional_fields() -> TestResult {
    for (code, reason, failure) in [
        (0, Reason::AuthenticatedCancellation, None),
        (1, Reason::ValidatedInvocationFailure, Some(hash(2))),
    ] {
        let input = AbortInput {
            failure_evidence_digest: failure,
            ..abort_input(reason)?
        };
        let encoded = encode(&Value::Array(abort_fields(input, code)?))?;
        assert_framing(&encoded, |bytes| {
            Abort::from_canonical_cbor(bytes).map(|_| ())
        });
    }
    for field in [4, 6, 7] {
        let mut fields = abort_fields(abort_input(Reason::ValidatedInvocationFailure)?, 1)?;
        fields[field] = Value::Bool(false);
        assert_eq!(
            Abort::from_canonical_cbor(&encode(&Value::Array(fields))?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let fields = abort_fields(abort_input(Reason::ValidatedInvocationFailure)?, 1)?;
    let mut encoded = encode(&Value::Array(fields[..5].to_vec()))?;
    encoded[0] = 0x89;
    encoded.extend_from_slice(&[0x18, 1]);
    for field in &fields[6..] {
        encoded.extend_from_slice(&encode(field)?);
    }
    assert_eq!(
        Abort::from_canonical_cbor(&encoded).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn terminal_identity_changes_with_the_exact_bound_request_tuple() -> TestResult {
    let original = abort_input(Reason::ValidatedInvocationFailure)?;
    let mut changes = [original; 4];
    changes[0].sealed_result_digest = Some(hash(3));
    changes[1].failure_evidence_digest = Some(hash(4));
    changes[2].quarantine_delta_digest = Some(hash(5));
    changes[3].evidence_not_after_micros = 2;
    let encoded = Abort::new(original)?.to_canonical_cbor();
    for input in changes {
        assert_ne!(
            Abort::new(input)?.to_canonical_cbor().as_slice(),
            encoded.as_slice()
        );
    }
    Ok(())
}
