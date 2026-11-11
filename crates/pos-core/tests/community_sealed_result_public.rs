//! Independent CPS1 wire oracles, not native candidate/admission evidence.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityDigestListV1 as Digests, CommunityLifecycleErrorV1 as Error,
    CommunityPassKeyV1 as Pass, CommunitySealedResultInputV1 as Input,
    CommunitySealedResultV1 as Seal,
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
fn pass_value() -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ])
}
fn input(digests: &[Hash], annotations: Option<Hash>) -> Fallible<Input<'_>> {
    Ok(Input {
        pass_key: Pass::new(
            TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
            [2; 16],
            3,
        )?,
        reservation_digest: hash(4),
        invocation_step_digests: Digests::from_digests(digests),
        event_draft_vector_digest: hash(5),
        event_draft_manifest_digest: hash(6),
        new_revision_digests: Digests::from_digests(digests),
        new_member_progress_digests: Digests::from_digests(digests),
        candidate_head_digest: hash(7),
        dependency_bundle_digest: hash(8),
        annotation_manifest_digest: annotations,
        replay_recording_digest: hash(10),
        evidence_not_after_micros: 11,
    })
}
fn fixture(digests: &[Hash], annotations: bool) -> Fallible<Value> {
    let list = Value::Array(digests.iter().map(|hash| bytes(hash.as_bytes())).collect());
    Ok(Value::Array(vec![
        bytes(b"CPS1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        bytes(&[4; 32]),
        list.clone(),
        bytes(&[5; 32]),
        bytes(&[6; 32]),
        list.clone(),
        list,
        bytes(&[7; 32]),
        bytes(&[8; 32]),
        if annotations {
            bytes(&[9; 32])
        } else {
            Value::Null
        },
        bytes(&[10; 32]),
        uint(11),
    ]))
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}

#[test]
fn sealed_candidate_has_exact_fourteen_fields_and_optional_presentation_only() -> TestResult {
    let digests = [hash(12), hash(2)];
    for annotations in [None, Some(hash(9))] {
        let input = input(&digests, annotations)?;
        let seal = Seal::new(input)?;
        let expected = encode(&fixture(&digests, annotations.is_some())?)?;
        assert_eq!(&*seal.to_canonical_cbor(), &expected);
        assert!(*Seal::from_canonical_cbor(&expected)?.as_input() == input);
        let mut preimage = b"PiglorOS.Community.CPS1.v1\0".to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(
            seal.digest(),
            Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
        );
    }
    Ok(())
}

#[test]
fn digest_lists_preserve_roster_order_and_borrow_original_ranges() -> TestResult {
    let digests = [hash(12), hash(2)];
    let input = input(&digests, None)?;
    assert!(!input.invocation_step_digests.is_empty());
    assert!(input.invocation_step_digests.as_canonical_rows().is_none());
    let encoded = Seal::new(input)?.to_canonical_cbor();
    let decoded = Seal::from_canonical_cbor(&encoded)?;
    for list in [
        decoded.as_input().invocation_step_digests,
        decoded.as_input().new_revision_digests,
        decoded.as_input().new_member_progress_digests,
    ] {
        assert_eq!(list.len(), 2);
        assert_eq!(list.iter().collect::<Vec<_>>(), digests);
        assert!(list.eq(&Digests::from_digests(&digests)));
        assert!(!list.eq(&Digests::from_digests(&[hash(12), hash(3)])));
        assert!(!list.eq(&Digests::from_digests(&[])));
        let rows = list
            .as_canonical_rows()
            .ok_or("missing borrowed digest rows")?;
        let offset = rows.as_ptr() as usize - encoded.as_ptr() as usize;
        assert!(offset + rows.len() <= encoded.len());
        assert_eq!(&encoded[offset..offset + rows.len()], rows);
    }
    Ok(())
}

#[test]
fn lists_accept_structural_empty_and_maximum_without_claiming_completeness() -> TestResult {
    let full = [hash(9); 64];
    for digests in [&[][..], &full[..]] {
        let seal = Seal::new(input(digests, None)?)?;
        let encoded = seal.to_canonical_cbor();
        assert_eq!(&*encoded, &encode(&fixture(digests, false)?)?);
        assert_eq!(
            Seal::from_canonical_cbor(&encoded)?
                .as_input()
                .invocation_step_digests
                .len(),
            digests.len()
        );
        assert_eq!(
            seal.as_input().invocation_step_digests.is_empty(),
            digests.is_empty()
        );
    }
    Ok(())
}

#[test]
fn sealed_candidate_rejects_zero_links_including_mandatory_recording() -> TestResult {
    for index in 0..7 {
        let mut input = input(&[], None)?;
        match index {
            0 => input.reservation_digest = Hash::zero(),
            1 => input.event_draft_vector_digest = Hash::zero(),
            2 => input.event_draft_manifest_digest = Hash::zero(),
            3 => input.candidate_head_digest = Hash::zero(),
            4 => input.dependency_bundle_digest = Hash::zero(),
            5 => input.annotation_manifest_digest = Some(Hash::zero()),
            _ => input.replay_recording_digest = Hash::zero(),
        }
        assert_eq!(Seal::new(input).err(), Some(Error::InvalidBinding));
    }
    let mut fixture = fixture(&[], false)?;
    fields(&mut fixture)?[12] = Value::Null;
    assert_eq!(
        Seal::from_canonical_cbor(&encode(&fixture)?).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn every_candidate_list_checks_64_entry_bound_and_nonzero_identities() -> TestResult {
    let too_many = [hash(9); 65];
    let zero = [Hash::zero()];
    for index in 0..3 {
        for (digests, error) in [
            (&too_many[..], Error::BoundsExceeded),
            (&zero[..], Error::InvalidBinding),
        ] {
            let mut input = input(&[], None)?;
            match index {
                0 => input.invocation_step_digests = Digests::from_digests(digests),
                1 => input.new_revision_digests = Digests::from_digests(digests),
                _ => input.new_member_progress_digests = Digests::from_digests(digests),
            }
            assert_eq!(Seal::new(input).err(), Some(error));
            let mut fixture = fixture(&[], false)?;
            fields(&mut fixture)?[[4, 7, 8][index]] =
                Value::Array(digests.iter().map(|hash| bytes(hash.as_bytes())).collect());
            assert_eq!(
                Seal::from_canonical_cbor(&encode(&fixture)?).err(),
                Some(error)
            );
        }
    }
    Ok(())
}

#[test]
fn candidate_horizon_preserves_original_positive_i64_range() -> TestResult {
    for horizon in [1, 23, 24, 255, 256, 65_536, u64::MAX / 2] {
        let input = Input {
            evidence_not_after_micros: horizon,
            ..input(&[], None)?
        };
        let encoded = Seal::new(input)?.to_canonical_cbor();
        assert_eq!(
            Seal::from_canonical_cbor(&encoded)?
                .as_input()
                .evidence_not_after_micros,
            horizon
        );
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Seal::new(Input {
                evidence_not_after_micros: horizon,
                ..input(&[], None)?
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn seal_rejects_truncations_trailers_versions_bounds_and_nonpreferred() -> TestResult {
    let encoded = encode(&fixture(&[hash(9)], false)?)?;
    for end in 0..encoded.len() {
        assert!(Seal::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Seal::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = fixture(&[], false)?;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Seal::from_canonical_cbor(&encode(&unsupported)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded.clone();
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Seal::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    let list_start = encoded
        .windows(5)
        .position(|value| value == [0x81, 0x58, 0x20, 9, 9])
        .ok_or("missing fixture list")?;
    let mut wide_list = encoded;
    wide_list.splice(list_start..=list_start, [0x98, 1]);
    assert_eq!(
        Seal::from_canonical_cbor(&wide_list).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Seal::from_canonical_cbor(&vec![0; 65_537]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn seal_rejects_malformed_list_rows_and_nested_pass() -> TestResult {
    for index in [4, 7, 8] {
        for value in [
            Value::Null,
            Value::Array(vec![bytes(&[9; 31])]),
            Value::Array(vec![uint(9)]),
            Value::Array(vec![bytes(&[9; 33])]),
        ] {
            let mut fixture = fixture(&[], false)?;
            fields(&mut fixture)?[index] = value;
            assert!(Seal::from_canonical_cbor(&encode(&fixture)?).is_err());
        }
    }
    let mut pass = pass_value();
    fields(&mut pass)?[4] = uint(0);
    let mut fixture = fixture(&[], false)?;
    fields(&mut fixture)?[2] = bytes(&encode(&pass)?);
    assert_eq!(
        Seal::from_canonical_cbor(&encode(&fixture)?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
