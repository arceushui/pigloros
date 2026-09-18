use ciborium::value::Value;
use pos_core::retention::{
    WorldRetentionErrorV1, WorldRetentionLeaseInputV1, WorldRetentionLeaseV1,
    WorldRetentionPolicyInputV1, WorldRetentionPolicyV1, MAX_WORLD_RETENTION_RECORD_BYTES_V1,
};
use pos_core::{Hash, TimelineId};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const DAY: u64 = 86_400_000_000;

fn policy_input() -> WorldRetentionPolicyInputV1 {
    WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world".to_owned(),
        audience_policy_hash: Hash::from_bytes([7; 32]),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    }
}

fn lease_input(policy: &WorldRetentionPolicyV1) -> WorldRetentionLeaseInputV1 {
    WorldRetentionLeaseInputV1 {
        timeline_id: TimelineId::from_ulid(ulid::Ulid::from(9u128)),
        policy_hash: policy.digest(),
        started_at_micros: 0,
        admission_closes_at_micros: 30 * DAY,
        retention_deadline_micros: 120 * DAY,
    }
}

fn policy_wire(input: &WorldRetentionPolicyInputV1) -> Value {
    Value::Array(vec![
        Value::Bytes(b"RTP1".to_vec()),
        Value::Integer(1.into()),
        Value::Integer(input.policy_revision.into()),
        Value::Text(input.purpose.clone()),
        Value::Bytes(input.audience_policy_hash.as_bytes().to_vec()),
        Value::Integer(input.minimum_post_admission_days.into()),
        Value::Integer(input.maximum_active_days.into()),
        Value::Integer(input.maximum_total_days.into()),
        Value::Integer(0.into()),
        Value::Integer(0.into()),
    ])
}

fn lease_wire(input: &WorldRetentionLeaseInputV1) -> Value {
    Value::Array(vec![
        Value::Bytes(b"RLS1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(input.timeline_id.inner().to_bytes().to_vec()),
        Value::Bytes(input.policy_hash.as_bytes().to_vec()),
        Value::Integer(input.started_at_micros.into()),
        Value::Integer(input.admission_closes_at_micros.into()),
        Value::Integer(input.retention_deadline_micros.into()),
    ])
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(bytes);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}

#[test]
fn policy_and_lease_match_independent_wire_and_digest_oracles() -> TestResult {
    let input = policy_input();
    let policy = WorldRetentionPolicyV1::new(input.clone())?;
    let bytes = encode(&policy_wire(&input))?;
    assert_eq!(policy.to_canonical_cbor(), bytes);
    assert_eq!(policy.as_input(), &input);
    assert_eq!(WorldRetentionPolicyV1::from_canonical_cbor(&bytes)?, policy);
    assert_eq!(
        policy.digest(),
        digest(b"pigloros.retention-policy.v1\0", &bytes)
    );
    let input = lease_input(&policy);
    let lease = WorldRetentionLeaseV1::new(&policy, input)?;
    let bytes = encode(&lease_wire(&input))?;
    assert_eq!(lease.to_canonical_cbor(), bytes);
    assert_eq!(lease.as_input(), &input);
    assert_eq!(
        WorldRetentionLeaseV1::from_canonical_cbor(&bytes, &policy)?,
        lease
    );
    assert_eq!(
        lease.digest(),
        digest(b"pigloros.retention-lease.v1\0", &bytes)
    );
    assert_ne!(policy.digest(), lease.digest());
    Ok(())
}

#[test]
fn every_policy_field_changes_identity_without_mutating_the_original() -> TestResult {
    let mut original_input = policy_input();
    original_input.maximum_total_days = 121;
    let original = WorldRetentionPolicyV1::new(original_input.clone())?;
    for field in 0..6 {
        let mut changed = original.as_input().clone();
        match field {
            0 => changed.policy_revision = 2,
            1 => changed.purpose = "other".to_owned(),
            2 => changed.audience_policy_hash = Hash::from_bytes([8; 32]),
            3 => changed.minimum_post_admission_days = 91,
            4 => changed.maximum_active_days = 29,
            _ => changed.maximum_total_days = 122,
        }
        let policy = WorldRetentionPolicyV1::new(changed)?;
        assert_ne!(original.digest(), policy.digest());
        assert_eq!(original.as_input(), &original_input);
        assert_eq!(
            WorldRetentionPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor())?,
            policy
        );
    }
    Ok(())
}

#[test]
fn every_lease_field_changes_identity_and_policy_reference_is_exact() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    let mut input = lease_input(&policy);
    input.started_at_micros = DAY;
    input.admission_closes_at_micros = 29 * DAY;
    input.retention_deadline_micros = 120 * DAY;
    let original = WorldRetentionLeaseV1::new(&policy, input)?;
    for field in 0..4 {
        let mut changed = input;
        match field {
            0 => changed.timeline_id = TimelineId::from_ulid(ulid::Ulid::from(10u128)),
            1 => changed.started_at_micros += 1,
            2 => changed.admission_closes_at_micros += 1,
            _ => changed.retention_deadline_micros -= 1,
        }
        let lease = WorldRetentionLeaseV1::new(&policy, changed)?;
        assert_ne!(original.digest(), lease.digest());
        assert_eq!(original.as_input(), &input);
    }
    let mut other = policy_input();
    other.policy_revision = 2;
    let other = WorldRetentionPolicyV1::new(other)?;
    assert_eq!(
        WorldRetentionLeaseV1::new(&other, input),
        Err(WorldRetentionErrorV1::PolicyMismatch)
    );
    assert_eq!(
        WorldRetentionLeaseV1::from_canonical_cbor(&original.to_canonical_cbor(), &other),
        Err(WorldRetentionErrorV1::PolicyMismatch)
    );
    input.policy_hash = other.digest();
    assert_ne!(
        WorldRetentionLeaseV1::new(&other, input)?.digest(),
        original.digest()
    );
    input.policy_hash = Hash::zero();
    assert_eq!(
        WorldRetentionLeaseV1::new(&policy, input),
        Err(WorldRetentionErrorV1::PolicyMismatch)
    );
    Ok(())
}

#[test]
fn policy_utf8_integer_widths_and_larger_finite_purposes_are_supported() -> TestResult {
    for revision in [1, 23, 24, 255, 256, 65_535, 65_536, u32::MAX] {
        for purpose in [
            "x".to_owned(),
            "x".repeat(23),
            "x".repeat(24),
            "é".repeat(64),
        ] {
            let mut input = policy_input();
            input.policy_revision = revision;
            input.purpose = purpose;
            input.minimum_post_admission_days = 365;
            input.maximum_active_days = 100;
            input.maximum_total_days = 465;
            let policy = WorldRetentionPolicyV1::new(input.clone())?;
            assert_eq!(policy.to_canonical_cbor(), encode(&policy_wire(&input))?);
            assert_eq!(
                WorldRetentionPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor())?,
                policy
            );
        }
    }
    let mut input = policy_input();
    input.policy_revision = u32::MAX;
    input.purpose = "x".repeat(128);
    input.maximum_active_days = u16::MAX - 90;
    input.maximum_total_days = u16::MAX;
    let policy = WorldRetentionPolicyV1::new(input)?;
    assert!(policy.to_canonical_cbor().len() <= 187);
    assert!(policy.to_canonical_cbor().len() <= MAX_WORLD_RETENTION_RECORD_BYTES_V1);
    assert_eq!(
        WorldRetentionPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor())?,
        policy
    );
    Ok(())
}

#[test]
fn invalid_policy_terms_fail_through_construction_and_decode() -> TestResult {
    for field in 0..8 {
        let mut input = policy_input();
        match field {
            0 => input.policy_revision = 0,
            1 => input.purpose = String::new(),
            2 => input.purpose = "é".repeat(65),
            3 => input.audience_policy_hash = Hash::zero(),
            4 => input.minimum_post_admission_days = 89,
            5 => input.maximum_active_days = 0,
            6 => input.maximum_total_days = 119,
            _ => {
                input.minimum_post_admission_days = u16::MAX;
                input.maximum_active_days = 1;
                input.maximum_total_days = u16::MAX;
            }
        }
        assert!(WorldRetentionPolicyV1::new(input.clone()).is_err());
        assert!(
            WorldRetentionPolicyV1::from_canonical_cbor(&encode(&policy_wire(&input))?).is_err()
        );
    }
    Ok(())
}

#[test]
fn lease_windows_support_shorter_admission_and_extreme_absolute_times() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    for start in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX - 120 * DAY,
    ] {
        for active in [1, 30 * DAY] {
            let input = WorldRetentionLeaseInputV1 {
                started_at_micros: start,
                admission_closes_at_micros: start + active,
                retention_deadline_micros: start + active + 90 * DAY,
                ..lease_input(&policy)
            };
            let lease = WorldRetentionLeaseV1::new(&policy, input)?;
            assert_eq!(lease.to_canonical_cbor(), encode(&lease_wire(&input))?);
            assert!(lease.to_canonical_cbor().len() <= 85);
            assert_eq!(
                WorldRetentionLeaseV1::from_canonical_cbor(&lease.to_canonical_cbor(), &policy)?,
                lease
            );
        }
    }
    Ok(())
}

#[test]
fn lease_span_violations_reject_without_wrapping_arithmetic() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    for field in 0..6 {
        let mut input = lease_input(&policy);
        match field {
            0 => input.started_at_micros = input.admission_closes_at_micros,
            1 => input.started_at_micros = u64::MAX,
            2 => input.admission_closes_at_micros = input.retention_deadline_micros + 1,
            3 => input.admission_closes_at_micros += 1,
            4 => input.retention_deadline_micros += 1,
            _ => input.retention_deadline_micros -= 1,
        }
        assert_eq!(
            WorldRetentionLeaseV1::new(&policy, input),
            Err(WorldRetentionErrorV1::InvalidWindow)
        );
        assert_eq!(
            WorldRetentionLeaseV1::from_canonical_cbor(&encode(&lease_wire(&input))?, &policy),
            Err(WorldRetentionErrorV1::InvalidWindow)
        );
    }
    Ok(())
}

#[test]
fn wrong_policy_wire_fields_and_rules_fail_closed() -> TestResult {
    let Value::Array(fields) = policy_wire(&policy_input()) else {
        return Err("policy fixture is not an array".into());
    };
    let cases = [
        (0, Value::Bytes(b"RTP2".to_vec())),
        (1, Value::Integer(2.into())),
        (2, Value::Integer((u64::from(u32::MAX) + 1).into())),
        (3, Value::Bytes(vec![1])),
        (4, Value::Bytes(vec![7; 31])),
        (5, Value::Integer(65_536.into())),
        (6, Value::Integer(65_536.into())),
        (7, Value::Integer(65_536.into())),
        (8, Value::Integer(1.into())),
        (9, Value::Integer(1.into())),
    ];
    for (index, value) in cases {
        let mut changed = fields.clone();
        changed[index] = value;
        assert!(
            WorldRetentionPolicyV1::from_canonical_cbor(&encode(&Value::Array(changed))?).is_err()
        );
    }
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        changed[index] = Value::Null;
        assert!(
            WorldRetentionPolicyV1::from_canonical_cbor(&encode(&Value::Array(changed))?).is_err()
        );
    }
    Ok(())
}

#[test]
fn wrong_lease_wire_fields_fail_closed() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    let Value::Array(fields) = lease_wire(&lease_input(&policy)) else {
        return Err("lease fixture is not an array".into());
    };
    for (index, value) in [
        (0, Value::Bytes(b"RLS2".to_vec())),
        (1, Value::Integer(0.into())),
        (2, Value::Bytes(vec![1; 15])),
        (3, Value::Bytes(vec![1; 33])),
        (4, Value::Integer((-1).into())),
        (5, Value::Float(1.0)),
        (6, Value::Tag(0, Box::new(Value::Integer(1.into())))),
    ] {
        let mut changed = fields.clone();
        changed[index] = value;
        assert!(WorldRetentionLeaseV1::from_canonical_cbor(
            &encode(&Value::Array(changed))?,
            &policy
        )
        .is_err());
    }
    for index in 0..fields.len() {
        let mut changed = fields.clone();
        changed[index] = Value::Null;
        assert!(WorldRetentionLeaseV1::from_canonical_cbor(
            &encode(&Value::Array(changed))?,
            &policy
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn truncation_oversize_and_wrong_outer_shapes_reject() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    let lease = WorldRetentionLeaseV1::new(&policy, lease_input(&policy))?;
    let policy_bytes = policy.to_canonical_cbor();
    let lease_bytes = lease.to_canonical_cbor();
    for end in 0..policy_bytes.len() {
        assert!(WorldRetentionPolicyV1::from_canonical_cbor(&policy_bytes[..end]).is_err());
    }
    for end in 0..lease_bytes.len() {
        assert!(WorldRetentionLeaseV1::from_canonical_cbor(&lease_bytes[..end], &policy).is_err());
    }
    for bytes in [
        vec![0; 513],
        vec![0x89],
        vec![0x88],
        vec![0x9f, 0xff],
        vec![0xbf, 0xff],
        vec![0x9c],
        vec![0x9d],
        vec![0x9e],
    ] {
        assert!(WorldRetentionPolicyV1::from_canonical_cbor(&bytes).is_err());
        assert!(WorldRetentionLeaseV1::from_canonical_cbor(&bytes, &policy).is_err());
    }
    Ok(())
}

#[test]
fn wrong_cardinality_rejects_an_otherwise_complete_valid_body() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    let lease = WorldRetentionLeaseV1::new(&policy, lease_input(&policy))?;
    for count in [0, 6, 8, 9, 11, 23] {
        let mut bytes = policy.to_canonical_cbor();
        bytes[0] = 0x80 | count;
        assert_eq!(
            WorldRetentionPolicyV1::from_canonical_cbor(&bytes),
            Err(WorldRetentionErrorV1::InvalidEncoding)
        );
        let mut bytes = lease.to_canonical_cbor();
        bytes[0] = 0x80 | count;
        assert_eq!(
            WorldRetentionLeaseV1::from_canonical_cbor(&bytes, &policy),
            Err(WorldRetentionErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn nonpreferred_encodings_and_trailing_bytes_reject() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    let lease = WorldRetentionLeaseV1::new(&policy, lease_input(&policy))?;
    for (original, is_policy) in [
        (policy.to_canonical_cbor(), true),
        (lease.to_canonical_cbor(), false),
    ] {
        let mut variants = Vec::new();
        let mut trailing = original.clone();
        trailing.push(0);
        variants.push(trailing);
        let mut long_array = vec![0x98, original[0] & 31];
        long_array.extend_from_slice(&original[1..]);
        variants.push(long_array);
        let mut long_magic = vec![original[0], 0x58, 4];
        long_magic.extend_from_slice(&original[2..]);
        variants.push(long_magic);
        for version in [
            vec![0x18, 1],
            vec![0x19, 0, 1],
            vec![0x1a, 0, 0, 0, 1],
            vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
        ] {
            let mut bytes = original[..6].to_vec();
            bytes.extend(version);
            bytes.extend_from_slice(&original[7..]);
            variants.push(bytes);
        }
        for bytes in variants {
            if is_policy {
                assert_eq!(
                    WorldRetentionPolicyV1::from_canonical_cbor(&bytes),
                    Err(WorldRetentionErrorV1::NonCanonical)
                );
            } else {
                assert_eq!(
                    WorldRetentionLeaseV1::from_canonical_cbor(&bytes, &policy),
                    Err(WorldRetentionErrorV1::NonCanonical)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn huge_claimed_nested_lengths_and_invalid_utf8_reject_before_allocation() -> TestResult {
    let policy = WorldRetentionPolicyV1::new(policy_input())?;
    let lease = WorldRetentionLeaseV1::new(&policy, lease_input(&policy))?;
    for (prefix, head) in [
        (Vec::new(), 0x9b),
        (vec![0x8a], 0x5b),
        (policy.to_canonical_cbor()[..8].to_vec(), 0x7b),
    ] {
        let mut bytes = prefix;
        bytes.push(head);
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(WorldRetentionPolicyV1::from_canonical_cbor(&bytes).is_err());
    }
    let mut bytes = policy.to_canonical_cbor()[..8].to_vec();
    bytes.extend_from_slice(&[0x61, 0xff]);
    assert_eq!(
        WorldRetentionPolicyV1::from_canonical_cbor(&bytes),
        Err(WorldRetentionErrorV1::InvalidEncoding)
    );
    let mut bytes = lease.to_canonical_cbor()[..7].to_vec();
    bytes.push(0x5b);
    bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(WorldRetentionLeaseV1::from_canonical_cbor(&bytes, &policy).is_err());
    for error in [
        WorldRetentionErrorV1::InvalidEncoding,
        WorldRetentionErrorV1::NonCanonical,
        WorldRetentionErrorV1::UnsupportedValue,
        WorldRetentionErrorV1::FieldOutOfBounds,
        WorldRetentionErrorV1::InvalidWindow,
        WorldRetentionErrorV1::PolicyMismatch,
    ] {
        assert!(!error.to_string().is_empty());
    }
    Ok(())
}
