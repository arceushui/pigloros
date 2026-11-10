//! CQK1/CQR1 independent bytes. A retained ledger is not reset authority.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityQuarantineKeyV1 as Key,
    CommunityQuarantineReasonEvidenceV1 as Evidence, CommunityQuarantineReasonV1 as Reason,
    CommunityQuarantineReasonsV1 as Reasons, CommunityQuarantineRevisionInputV1 as Input,
    CommunityQuarantineRevisionV1 as Revision,
};
use pos_core::{Hash, ImplementationKeyV1, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
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
        "host-v1".into(),
        hash(3),
    )?)
}
fn implementation_value() -> Value {
    Value::Array(vec![
        bytes(b"IMK1"),
        uint(1),
        Value::Text("plugin-a".into()),
        Value::Text("host-v1".into()),
        bytes(&[3; 32]),
    ])
}
fn key_value() -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CQK1"),
        uint(1),
        bytes(&[1; 16]),
        Value::Text("Entry-A_1".into()),
        bytes(&encode(&implementation_value())?),
    ]))
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.push(0);
    preimage.extend_from_slice(bytes);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
const fn reasons() -> [Evidence; 4] {
    [
        Evidence {
            reason: Reason::Trapped,
            failure_evidence_digest: hash(7),
        },
        Evidence {
            reason: Reason::ResourceExhausted,
            failure_evidence_digest: hash(8),
        },
        Evidence {
            reason: Reason::Revoked,
            failure_evidence_digest: hash(9),
        },
        Evidence {
            reason: Reason::Unavailable,
            failure_evidence_digest: hash(10),
        },
    ]
}
fn input<'a>(
    implementation: &'a ImplementationKeyV1,
    reasons: &'a [Evidence],
    predecessor: Option<Hash>,
    ordinal: u64,
) -> Fallible<Input<'a>> {
    Ok(Input {
        key: Key::new(timeline(1), "Entry-A_1", implementation)?,
        ledger_ordinal: ordinal,
        predecessor_ledger_digest: predecessor,
        active_reasons: Reasons::from_reasons(reasons),
        control_request_digest: hash(5),
        evidence_not_after_micros: 6,
    })
}
fn revision_value(
    reasons: &[Evidence],
    predecessor: Option<Hash>,
    ordinal: u64,
) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CQR1"),
        uint(1),
        bytes(&encode(&key_value()?)?),
        uint(ordinal),
        predecessor.map_or(Value::Null, |hash| bytes(hash.as_bytes())),
        Value::Array(
            reasons
                .iter()
                .map(|entry| {
                    Value::Array(vec![
                        uint(u64::from(entry.reason.code())),
                        bytes(entry.failure_evidence_digest.as_bytes()),
                    ])
                })
                .collect(),
        ),
        bytes(&[5; 32]),
        uint(6),
    ]))
}

#[test]
fn quarantine_key_has_exact_stable_identity_without_generation_or_run_id() -> TestResult {
    let implementation = implementation()?;
    let key = Key::new(timeline(1), "Entry-A_1", &implementation)?;
    let expected = encode(&key_value()?)?;
    assert_eq!(&*key.to_canonical_cbor(), &expected);
    assert_eq!(
        key.digest(),
        domain_hash(b"PiglorOS.Community.CQK1.v1", &expected)
    );
    let decoded = Key::from_canonical_cbor(&expected, &implementation)?;
    assert_eq!(decoded.timeline(), timeline(1));
    assert_eq!(decoded.stable_entry(), "Entry-A_1");
    assert!(std::ptr::eq(
        decoded.implementation(),
        &raw const implementation
    ));
    let offset = decoded.stable_entry().as_ptr() as usize - expected.as_ptr() as usize;
    assert!(offset + decoded.stable_entry().len() <= expected.len());
    let same = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?;
    assert_eq!(
        Key::new(timeline(1), "Entry-A_1", &same)?.digest(),
        key.digest()
    );
    assert_ne!(
        Key::new(timeline(2), "Entry-A_1", &same)?.digest(),
        key.digest()
    );
    assert_ne!(
        Key::new(timeline(1), "other", &same)?.digest(),
        key.digest()
    );
    Ok(())
}

#[test]
fn key_validates_exact_slot_grammar_and_original_release_binding() -> TestResult {
    let implementation = implementation()?;
    for slot in ["A", "a.b_c-d", "01", &"s".repeat(64)] {
        assert!(Key::new(timeline(1), slot, &implementation).is_ok());
    }
    for slot in ["", "bad/entry", "bad entry", "é", &"s".repeat(65)] {
        assert_eq!(
            Key::new(timeline(1), slot, &implementation).err(),
            Some(Error::InvalidBinding)
        );
    }
    assert_eq!(
        Key::new(timeline(0), "slot", &implementation).err(),
        Some(Error::InvalidBinding)
    );
    let zero = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), Hash::zero())?;
    assert_eq!(
        Key::new(timeline(1), "slot", &zero).err(),
        Some(Error::InvalidBinding)
    );
    let expected = encode(&key_value()?)?;
    for changed in [
        ImplementationKeyV1::new("plugin-b".into(), "host-v1".into(), hash(3))?,
        ImplementationKeyV1::new("plugin-a".into(), "host-v2".into(), hash(3))?,
        ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(4))?,
    ] {
        assert_eq!(
            Key::from_canonical_cbor(&expected, &changed).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn key_rejects_all_truncations_nonpreferred_utf8_versions_and_bounds() -> TestResult {
    let implementation = implementation()?;
    let encoded = encode(&key_value()?)?;
    for end in 0..encoded.len() {
        assert!(Key::from_canonical_cbor(&encoded[..end], &implementation).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Key::from_canonical_cbor(&trailing, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = key_value()?;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Key::from_canonical_cbor(&encode(&unsupported)?, &implementation).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded.clone();
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Key::from_canonical_cbor(&nonpreferred, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    let start = encoded
        .windows(9)
        .position(|bytes| bytes == b"Entry-A_1")
        .ok_or("missing entry fixture")?;
    let mut utf8 = encoded;
    utf8[start] = 0xff;
    assert_eq!(
        Key::from_canonical_cbor(&utf8, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    let mut oversized = key_value()?;
    fields(&mut oversized)?[3] = Value::Text("s".repeat(65));
    assert_eq!(
        Key::from_canonical_cbor(&encode(&oversized)?, &implementation).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        Key::from_canonical_cbor(&vec![0; 513], &implementation).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn ledger_has_exact_eight_fields_and_all_four_closed_reason_codes() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    for predecessor in [None, Some(hash(4))] {
        let input = input(&implementation, &reasons, predecessor, u64::MAX)?;
        let revision = Revision::new(input)?;
        let expected = encode(&revision_value(&reasons, predecessor, u64::MAX)?)?;
        assert_eq!(&*revision.to_canonical_cbor(), &expected);
        assert_eq!(
            revision.digest(),
            domain_hash(b"PiglorOS.Community.CQR1.v1", &expected)
        );
        assert!(*Revision::from_canonical_cbor(&expected, &implementation)?.as_input() == input);
    }
    Ok(())
}

#[test]
fn ledger_borrows_reason_rows_and_does_not_mint_reset_from_empty_set() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    let revision = Revision::new(input(&implementation, &reasons, None, 1)?)?;
    assert!(revision
        .as_input()
        .active_reasons
        .as_canonical_rows()
        .is_none());
    let encoded = revision.to_canonical_cbor();
    let decoded = Revision::from_canonical_cbor(&encoded, &implementation)?;
    let original_reasons = revision.as_input().active_reasons;
    assert!(!original_reasons.is_empty());
    assert!(!decoded.as_input().active_reasons.is_empty());
    assert!(original_reasons.eq(&decoded.as_input().active_reasons));
    let mut changed_reasons = reasons;
    changed_reasons[0].failure_evidence_digest = hash(11);
    assert!(!original_reasons.eq(&Reasons::from_reasons(&changed_reasons)));
    assert!(!original_reasons.eq(&Reasons::from_reasons(&[])));
    let rows = decoded
        .as_input()
        .active_reasons
        .as_canonical_rows()
        .ok_or("missing borrowed rows")?;
    assert_eq!(rows.len(), 4 * 36);
    let offset = rows.as_ptr() as usize - encoded.as_ptr() as usize;
    assert!(offset + rows.len() <= encoded.len());
    assert_eq!(&encoded[offset..offset + rows.len()], rows);
    assert_eq!(
        decoded
            .as_input()
            .active_reasons
            .iter()
            .map(|entry| (entry.reason.code(), entry.failure_evidence_digest))
            .collect::<Vec<_>>(),
        vec![(0, hash(7)), (1, hash(8)), (2, hash(9)), (3, hash(10))]
    );
    let empty = Revision::new(input(&implementation, &[], Some(hash(4)), 2)?)?;
    assert!(empty.as_input().active_reasons.is_empty());
    assert_eq!(
        &*empty.to_canonical_cbor(),
        &encode(&revision_value(&[], Some(hash(4)), 2)?)?
    );
    Ok(())
}

#[test]
fn ledger_rejects_duplicate_unsorted_zero_or_excess_reason_evidence() -> TestResult {
    let implementation = implementation()?;
    let reasons = reasons();
    for invalid in [
        vec![reasons[1], reasons[0]],
        vec![reasons[0], reasons[0]],
        vec![Evidence {
            failure_evidence_digest: Hash::zero(),
            ..reasons[0]
        }],
    ] {
        assert_eq!(
            Revision::new(input(&implementation, &invalid, None, 1)?).err(),
            Some(Error::InvalidBinding)
        );
        assert_eq!(
            Revision::from_canonical_cbor(
                &encode(&revision_value(&invalid, None, 1)?)?,
                &implementation
            )
            .err(),
            Some(Error::InvalidBinding)
        );
    }
    let excess = [reasons[0]; 5];
    assert_eq!(
        Revision::new(input(&implementation, &excess, None, 1)?).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        Revision::from_canonical_cbor(
            &encode(&revision_value(&excess, None, 1)?)?,
            &implementation
        )
        .err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn ledger_checks_ordinal_required_links_and_absolute_horizon() -> TestResult {
    let implementation = implementation()?;
    let original = input(&implementation, &[], None, 1)?;
    for input in [
        Input {
            ledger_ordinal: 0,
            ..original
        },
        Input {
            control_request_digest: Hash::zero(),
            ..original
        },
        Input {
            predecessor_ledger_digest: Some(Hash::zero()),
            ..original
        },
    ] {
        assert_eq!(Revision::new(input).err(), Some(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Revision::new(Input {
                evidence_not_after_micros: horizon,
                ..original
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    assert!(Revision::new(Input {
        evidence_not_after_micros: u64::MAX / 2,
        ..original
    })
    .is_ok());
    Ok(())
}

#[test]
fn ledger_rejects_invalid_nested_key_reason_shapes_codes_and_trailers() -> TestResult {
    let implementation = implementation()?;
    let value = revision_value(&reasons(), None, 1)?;
    let encoded = encode(&value)?;
    for end in 0..encoded.len() {
        assert!(Revision::from_canonical_cbor(&encoded[..end], &implementation).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Revision::from_canonical_cbor(&trailing, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = value.clone();
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Revision::from_canonical_cbor(&encode(&unsupported)?, &implementation).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Revision::from_canonical_cbor(&nonpreferred, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    for row in [
        Value::Array(vec![uint(4), bytes(&[7; 32])]),
        Value::Array(vec![uint(0), bytes(&[7; 31])]),
        Value::Array(vec![uint(0), bytes(&[7; 33])]),
        Value::Array(vec![uint(0), bytes(&[7; 32]), uint(0)]),
    ] {
        let mut changed = value.clone();
        fields(&mut changed)?[5] = Value::Array(vec![row]);
        assert!(Revision::from_canonical_cbor(&encode(&changed)?, &implementation).is_err());
    }
    let mut changed = value;
    fields(&mut changed)?[2] = bytes(&[]);
    assert_eq!(
        Revision::from_canonical_cbor(&encode(&changed)?, &implementation).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Revision::from_canonical_cbor(&vec![0; 4097], &implementation).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
