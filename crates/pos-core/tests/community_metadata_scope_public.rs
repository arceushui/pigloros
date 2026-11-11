//! Minimal scope covers retain original source references without granting access.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataScopeInputV1 as Input,
    CommunityMetadataScopeV1 as Cover, CommunityScopeMemberV1 as Member,
    CommunityScopeMembersV1 as Members, MAX_COMMUNITY_SCOPE_MEMBERS_V1 as MAX_MEMBERS,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;
const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
const fn member() -> Member {
    Member {
        scope_reference: hash(5),
        source_timeline: timeline(6),
        owner_reference: hash(7),
        retention_lease_reference: hash(8),
        not_after_micros: 9,
    }
}
const fn input(rows: &[Member]) -> Input<'_> {
    Input {
        store_incarnation: [1; 16],
        metadata_anchor_timeline: timeline(2),
        metadata_anchor_generation: [3; 16],
        protection_operation_id: [4; 16],
        scope_members: Members::from_members(rows),
        metadata_not_after_micros: 10,
    }
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("array expected".into()),
    }
}
fn value() -> Value {
    Value::Array(vec![
        bytes(b"CSM1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        bytes(&[3; 16]),
        bytes(&[4; 16]),
        Value::Array(vec![Value::Array(vec![
            bytes(&[5; 32]),
            bytes(&[6; 16]),
            bytes(&[7; 32]),
            bytes(&[8; 32]),
            uint(9),
        ])]),
        uint(10),
    ])
}

#[test]
fn exact_scope_cover_and_exception_domain_borrow_original_rows() -> TestResult {
    let rows = [member()];
    let cover = Cover::new(input(&rows))?;
    assert!(cover.as_input().scope_members.as_canonical_rows().is_none());
    assert!(!cover.as_input().scope_members.is_empty());
    assert!(cover.as_input().scope_members.iter().next().transpose()? == Some(member()));
    let expected = encode(&value())?;
    assert_eq!(cover.to_canonical_cbor().as_slice(), expected.as_slice());
    let mut preimage = b"PiglorOS.Community.ScopeCover.v1\0".to_vec();
    preimage.extend_from_slice(&expected);
    assert_eq!(
        cover.digest(),
        Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
    );
    let decoded = Cover::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == input(&rows));
    for members in [
        &cover.as_input().scope_members,
        &decoded.as_input().scope_members,
    ] {
        let mut count = 0;
        for row in members {
            assert!(row? == member());
            count += 1;
        }
        assert_eq!(count, 1);
    }
    let encoded_rows = decoded
        .as_input()
        .scope_members
        .as_canonical_rows()
        .ok_or("rows missing")?;
    assert!(expected.as_ptr_range().contains(&encoded_rows.as_ptr()));
    assert_eq!(encoded_rows.len(), 121);
    let mut iter = decoded.as_input().scope_members.iter();
    assert_eq!(iter.size_hint(), (1, Some(1)));
    assert_eq!(iter.len(), 1);
    assert!(iter.next().transpose()? == Some(member()));
    assert_eq!(iter.len(), 0);
    assert!(iter.next().is_none());
    assert_eq!(decoded.to_canonical_cbor().as_slice(), expected.as_slice());
    Ok(())
}

#[test]
fn empty_cover_is_structurally_valid_without_claiming_a_public_source() -> TestResult {
    let cover = Cover::new(input(&[]))?;
    assert!(cover.as_input().scope_members.is_empty());
    assert_eq!(cover.as_input().scope_members.iter().len(), 0);
    assert!(cover.as_input().scope_members.iter().next().is_none());
    let encoded = cover.to_canonical_cbor();
    let decoded = Cover::from_canonical_cbor(&encoded)?;
    assert!(decoded.as_input().scope_members.is_empty());
    assert!(decoded.as_input().scope_members.iter().next().is_none());
    Ok(())
}

#[test]
fn ordering_uses_all_four_references_and_excludes_deadline() -> TestResult {
    let first = member();
    for second in [
        Member {
            scope_reference: hash(6),
            ..first
        },
        Member {
            source_timeline: timeline(7),
            ..first
        },
        Member {
            owner_reference: hash(8),
            ..first
        },
        Member {
            retention_lease_reference: hash(9),
            ..first
        },
    ] {
        let rows = [first, second];
        let cover = Cover::new(input(&rows))?;
        let encoded = cover.to_canonical_cbor();
        assert!(*Cover::from_canonical_cbor(&encoded)?.as_input() == input(&rows));
        assert_eq!(
            Cover::new(input(&[second, first])).err(),
            Some(Error::InvalidBinding)
        );
    }
    for deadline in [9, 10] {
        let rows = [
            first,
            Member {
                not_after_micros: deadline,
                ..first
            },
        ];
        assert_eq!(Cover::new(input(&rows)).err(), Some(Error::InvalidBinding));
    }
    let mut wire = value();
    let row = fields(&mut fields(&mut wire)?[6])?[0].clone();
    fields(&mut fields(&mut wire)?[6])?.push(row);
    assert_eq!(
        Cover::from_canonical_cbor(&encode(&wire)?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn identities_and_both_independent_deadlines_are_nonzero_and_finite() -> TestResult {
    let rows = [member()];
    for field in 0..4 {
        let mut candidate = input(&rows);
        match field {
            0 => candidate.store_incarnation = [0; 16],
            1 => candidate.metadata_anchor_timeline = timeline(0),
            2 => candidate.metadata_anchor_generation = [0; 16],
            _ => candidate.protection_operation_id = [0; 16],
        }
        assert_eq!(Cover::new(candidate).err(), Some(Error::InvalidBinding));
    }
    for field in 0..4 {
        let mut row = member();
        match field {
            0 => row.scope_reference = Hash::zero(),
            1 => row.source_timeline = timeline(0),
            2 => row.owner_reference = Hash::zero(),
            _ => row.retention_lease_reference = Hash::zero(),
        }
        assert_eq!(Cover::new(input(&[row])).err(), Some(Error::InvalidBinding));
    }
    for deadline in [0, i64::MAX as u64 + 1, u64::MAX] {
        assert_eq!(
            Cover::new(Input {
                metadata_not_after_micros: deadline,
                ..input(&rows)
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
        assert_eq!(
            Cover::new(input(&[Member {
                not_after_micros: deadline,
                ..member()
            }]))
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    for deadline in [
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        i64::MAX as u64,
    ] {
        let rows = [Member {
            not_after_micros: deadline,
            ..member()
        }];
        let cover = Cover::new(Input {
            metadata_not_after_micros: deadline,
            ..input(&rows)
        })?;
        let encoded = cover.to_canonical_cbor();
        assert_eq!(
            Cover::from_canonical_cbor(&encoded)?
                .as_input()
                .metadata_not_after_micros,
            deadline
        );
    }
    Ok(())
}

#[test]
fn complete_row_bound_is_checked_before_decoding_oversized_arrays() -> TestResult {
    let rows: Vec<_> = (1..=MAX_MEMBERS)
        .map(|n| {
            let mut reference = [0; 32];
            reference[24..].copy_from_slice(&(n as u64).to_be_bytes());
            Member {
                scope_reference: Hash::from_bytes(reference),
                not_after_micros: i64::MAX as u64,
                ..member()
            }
        })
        .collect();
    let cover = Cover::new(input(&rows))?;
    let encoded = cover.to_canonical_cbor();
    assert_eq!(
        Cover::from_canonical_cbor(&encoded)?
            .as_input()
            .scope_members
            .len(),
        MAX_MEMBERS
    );
    let too_many = vec![member(); MAX_MEMBERS + 1];
    assert_eq!(
        Cover::new(input(&too_many)).err(),
        Some(Error::BoundsExceeded)
    );
    let mut wire = encode(&value())?;
    // Locate the independently encoded five-field row, then replace its array header.
    let row_header = wire
        .iter()
        .position(|byte| *byte == 0x85)
        .ok_or("row absent")?
        - 1;
    wire.truncate(row_header);
    wire.extend_from_slice(&[0x99, 0x08, 0x01]);
    assert_eq!(
        Cover::from_canonical_cbor(&wire).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        Cover::from_canonical_cbor(&vec![0; 1_048_577]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn member_equality_distinguishes_retention_and_membership_changes() -> TestResult {
    let original = [member()];
    let changed_deadline = [Member {
        not_after_micros: 10,
        ..member()
    }];
    let original_cover = Cover::new(input(&original))?;
    let changed_cover = Cover::new(input(&changed_deadline))?;
    let wire = original_cover.to_canonical_cbor();
    let decoded = Cover::from_canonical_cbor(&wire)?;
    let left = original_cover.as_input().scope_members;
    assert!(left.eq(&decoded.as_input().scope_members));
    assert!(!left.eq(&changed_cover.as_input().scope_members));
    assert!(!left.eq(&Members::from_members(&[])));
    Ok(())
}

#[test]
fn scope_parser_refuses_incomplete_nonpreferred_and_wrong_grammar() -> TestResult {
    let canonical = encode(&value())?;
    for length in 0..canonical.len() {
        assert!(Cover::from_canonical_cbor(&canonical[..length]).is_err());
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(Cover::from_canonical_cbor(&trailing).is_err());
    let mut nonpreferred = canonical;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert!(Cover::from_canonical_cbor(&nonpreferred).is_err());
    for field in 0..8 {
        let mut wire = value();
        fields(&mut wire)?[field] = Value::Null;
        assert!(Cover::from_canonical_cbor(&encode(&wire)?).is_err());
    }
    let mut version = value();
    fields(&mut version)?[1] = uint(2);
    assert!(Cover::from_canonical_cbor(&encode(&version)?).is_err());
    for field in 0..5 {
        let mut wire = value();
        fields(&mut fields(&mut fields(&mut wire)?[6])?[0])?[field] = Value::Null;
        assert!(Cover::from_canonical_cbor(&encode(&wire)?).is_err());
    }
    Ok(())
}
