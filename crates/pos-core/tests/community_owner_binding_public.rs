//! Original owner/metadata bindings are wire data, not a current service grant.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataAnchorV1 as Anchor,
    CommunityMetadataPolicyInputV1 as PolicyInput, CommunityMetadataPolicyV1 as Policy,
    CommunityOwnerBindingInputV1 as OwnerInput, CommunityOwnerBindingV1 as Owner,
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
        _ => Err("fixture array expected".into()),
    }
}
fn logical_digest(domain: &[u8], canonical: &[u8]) -> Hash {
    let mut input = domain.to_vec();
    input.extend_from_slice(canonical);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}
const fn owner_input() -> OwnerInput {
    OwnerInput {
        store_incarnation: [1; 16],
        timeline: timeline(0xab),
        generation: [0xcd; 16],
        native_profile_digest: hash(2),
        installed_owner_catalogue_digest: hash(3),
        authority_catalogue_digest: hash(4),
        durable_profile_digest: hash(5),
        installation_id: [6; 16],
        evidence_not_after_micros: 7,
    }
}
fn catalogue_owner() -> String {
    format!("community-artifact:{}:{}", "ab".repeat(16), "cd".repeat(16))
}
fn owner_value() -> Value {
    Value::Array(vec![
        bytes(b"COB1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[0xab; 16]),
        bytes(&[0xcd; 16]),
        Value::Text(catalogue_owner()),
        bytes(&[2; 32]),
        bytes(&[3; 32]),
        bytes(&[4; 32]),
        bytes(&[5; 32]),
        bytes(&[6; 16]),
        uint(7),
    ])
}
const fn policy_input() -> PolicyInput {
    PolicyInput {
        metadata_owner_registry_binding: hash(8),
        metadata_authority_leaf_grant: hash(9),
        compiled_schema_catalogue_digest: hash(10),
        metadata_not_after_micros: 11,
    }
}
fn policy_value(horizon: u64) -> Value {
    Value::Array(vec![
        bytes(b"NMP1"),
        uint(1),
        bytes(&[8; 32]),
        bytes(&[9; 32]),
        bytes(&[10; 32]),
        uint(horizon),
        uint(4_194_304),
        uint(3_145_728),
        uint(1_000_000),
        Value::Array(vec![uint(0), uint(1), uint(2)]),
    ])
}
fn anchor_value(policy: Hash, horizon: u64) -> Value {
    Value::Array(vec![
        bytes(b"CMA1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[0xaa; 16]),
        bytes(&[0xbb; 16]),
        bytes(policy.as_bytes()),
        bytes(&[8; 32]),
        bytes(&[9; 32]),
        uint(horizon),
    ])
}

#[test]
fn owner_uses_exact_catalogue_spelling_and_existing_adr128_domain() -> TestResult {
    let owner = Owner::new(owner_input())?;
    let expected = encode(&owner_value())?;
    assert_eq!(owner.catalogue_owner_text(), catalogue_owner());
    assert_eq!(owner.catalogue_owner_text().len(), 84);
    assert_eq!(&*owner.to_canonical_cbor(), &expected);
    assert!(*owner.as_input() == owner_input());
    assert_eq!(
        owner.digest(),
        logical_digest(b"PiglorOS.Community.OwnerBinding.v1\0", &expected)
    );
    assert_ne!(
        owner.digest(),
        logical_digest(b"PiglorOS.Community.COB1.v1\0", &expected)
    );
    let decoded = Owner::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == owner_input());
    assert_eq!(decoded.catalogue_owner_text(), catalogue_owner());
    Ok(())
}

#[test]
fn catalogue_owner_cannot_be_substituted_normalized_or_used_as_an_operation_key_name() -> TestResult
{
    for text in [
        String::new(),
        catalogue_owner().to_uppercase(),
        format!("{} ", catalogue_owner()),
        "community:key-owner".into(),
        "x".repeat(129),
    ] {
        let mut value = owner_value();
        fields(&mut value)?[5] = Value::Text(text);
        assert!(Owner::from_canonical_cbor(&encode(&value)?).is_err());
    }
    for field in 0..8 {
        let mut input = owner_input();
        match field {
            0 => input.store_incarnation = [0; 16],
            1 => input.timeline = timeline(0),
            2 => input.generation = [0; 16],
            3 => input.native_profile_digest = Hash::zero(),
            4 => input.installed_owner_catalogue_digest = Hash::zero(),
            5 => input.authority_catalogue_digest = Hash::zero(),
            6 => input.durable_profile_digest = Hash::zero(),
            _ => input.installation_id = [0; 16],
        }
        assert_eq!(Owner::new(input).err(), Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn owner_retains_original_finite_deadlines_without_extending_them() -> TestResult {
    for horizon in [
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX / 2,
    ] {
        let mut input = owner_input();
        input.evidence_not_after_micros = horizon;
        let encoded = Owner::new(input)?.to_canonical_cbor();
        assert!(*Owner::from_canonical_cbor(&encoded)?.as_input() == input);
    }
    for invalid in [0, u64::MAX / 2 + 1, u64::MAX] {
        let mut input = owner_input();
        input.evidence_not_after_micros = invalid;
        assert_eq!(Owner::new(input).err(), Some(Error::BoundsExceeded));
        let mut value = owner_value();
        fields(&mut value)?[11] = uint(invalid);
        assert_eq!(
            Owner::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn metadata_policy_encodes_all_three_bounds_and_only_the_closed_service_actions() -> TestResult {
    let policy = Policy::new(policy_input())?;
    let expected = encode(&policy_value(11))?;
    assert_eq!(&*policy.to_canonical_cbor(), &expected);
    assert!(*policy.as_input() == policy_input());
    assert!(*Policy::from_canonical_cbor(&expected)?.as_input() == policy_input());
    assert_eq!(
        policy.digest(),
        logical_digest(b"PiglorOS.Community.NMP1.v1\0", &expected)
    );
    for field in 6..9 {
        for invalid in [0, 1, u64::MAX] {
            let mut value = policy_value(11);
            fields(&mut value)?[field] = uint(invalid);
            assert_eq!(
                Policy::from_canonical_cbor(&encode(&value)?).err(),
                Some(Error::InvalidBinding)
            );
        }
    }
    for actions in [
        vec![],
        vec![uint(0)],
        vec![uint(0), uint(1), uint(3)],
        vec![uint(2), uint(1), uint(0)],
        vec![uint(0), uint(1), uint(1)],
    ] {
        let mut value = policy_value(11);
        fields(&mut value)?[9] = Value::Array(actions);
        assert!(Policy::from_canonical_cbor(&encode(&value)?).is_err());
    }
    Ok(())
}

#[test]
fn metadata_policy_requires_the_original_registry_grant_catalogue_and_finite_horizon() -> TestResult
{
    for field in 0..3 {
        let mut input = policy_input();
        match field {
            0 => input.metadata_owner_registry_binding = Hash::zero(),
            1 => input.metadata_authority_leaf_grant = Hash::zero(),
            _ => input.compiled_schema_catalogue_digest = Hash::zero(),
        }
        assert_eq!(Policy::new(input).err(), Some(Error::InvalidBinding));
        let mut value = policy_value(11);
        fields(&mut value)?[2 + field] = bytes(&[0; 32]);
        assert_eq!(
            Policy::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for horizon in [
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX / 2,
    ] {
        let mut input = policy_input();
        input.metadata_not_after_micros = horizon;
        let policy = Policy::new(input)?;
        assert_eq!(
            &*policy.to_canonical_cbor(),
            &encode(&policy_value(horizon))?
        );
        assert!(*Policy::from_canonical_cbor(&policy.to_canonical_cbor())?.as_input() == input);
    }
    for invalid in [0, u64::MAX / 2 + 1, u64::MAX] {
        let mut input = policy_input();
        input.metadata_not_after_micros = invalid;
        assert_eq!(Policy::new(input).err(), Some(Error::BoundsExceeded));
        assert_eq!(
            Policy::from_canonical_cbor(&encode(&policy_value(invalid))?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn anchor_derives_exact_policy_bindings_without_selecting_execution_generation() -> TestResult {
    let policy = Policy::new(policy_input())?;
    let anchor = Anchor::new([1; 16], timeline(0xaa), [0xbb; 16], &policy)?;
    let policy_expected = encode(&policy_value(11))?;
    let policy_digest = logical_digest(b"PiglorOS.Community.NMP1.v1\0", &policy_expected);
    let expected = encode(&anchor_value(policy_digest, 11))?;
    assert_eq!(&*anchor.to_canonical_cbor(), &expected);
    assert_eq!(
        anchor.digest(),
        logical_digest(b"PiglorOS.Community.CMA1.v1\0", &expected)
    );
    let input = anchor.as_input();
    assert_eq!(input.store_incarnation, [1; 16]);
    assert_eq!(input.anchor_timeline, timeline(0xaa));
    assert_eq!(input.anchor_generation, [0xbb; 16]);
    assert_eq!(input.metadata_policy_digest, policy_digest);
    assert_eq!(input.metadata_owner_registry_binding, hash(8));
    assert_eq!(input.metadata_authority_leaf_grant, hash(9));
    assert_eq!(input.metadata_not_after_micros, 11);
    assert!(*Anchor::from_canonical_cbor(&expected, &policy)?.as_input() == *input);
    assert_eq!(
        Anchor::new([0; 16], timeline(0xaa), [0xbb; 16], &policy).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Anchor::new([1; 16], timeline(0), [0xbb; 16], &policy).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Anchor::new([1; 16], timeline(0xaa), [0; 16], &policy).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn anchor_rejects_foreign_policy_registry_grant_catalogue_or_renewed_horizon() -> TestResult {
    let policy = Policy::new(policy_input())?;
    let original = Anchor::new([1; 16], timeline(0xaa), [0xbb; 16], &policy)?.to_canonical_cbor();
    for field in 0..4 {
        let mut input = policy_input();
        match field {
            0 => input.metadata_owner_registry_binding = hash(20),
            1 => input.metadata_authority_leaf_grant = hash(21),
            2 => input.compiled_schema_catalogue_digest = hash(22),
            _ => input.metadata_not_after_micros += 1,
        }
        let changed = Policy::new(input)?;
        assert_eq!(
            Anchor::from_canonical_cbor(&original, &changed).err(),
            Some(Error::InvalidBinding)
        );
    }
    for field in 5..9 {
        let mut value = anchor_value(policy.digest(), 11);
        fields(&mut value)?[field] = if field == 8 {
            uint(12)
        } else {
            bytes(&[23; 32])
        };
        assert_eq!(
            Anchor::from_canonical_cbor(&encode(&value)?, &policy).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn every_record_refuses_prefixes_trailers_nonpreferred_versions_and_oversize() -> TestResult {
    let policy = Policy::new(policy_input())?;
    let cases = [
        (owner_value(), 1_048_576),
        (policy_value(11), 1024),
        (anchor_value(policy.digest(), 11), 1024),
    ];
    for (index, (mut value, maximum)) in cases.into_iter().enumerate() {
        let validate = |bytes: &[u8]| match index {
            0 => Owner::from_canonical_cbor(bytes).map(drop),
            1 => Policy::from_canonical_cbor(bytes).map(drop),
            _ => Anchor::from_canonical_cbor(bytes, &policy).map(drop),
        };
        let canonical = encode(&value)?;
        for end in 0..canonical.len() {
            assert!(validate(&canonical[..end]).is_err());
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(validate(&trailing).is_err());
        let mut nonpreferred = canonical;
        nonpreferred.splice(6..7, [0x18, 1]);
        assert_eq!(validate(&nonpreferred), Err(Error::InvalidEncoding));
        for version in [0, 2, u64::MAX] {
            let mut changed = value.clone();
            fields(&mut changed)?[1] = uint(version);
            assert_eq!(validate(&encode(&changed)?), Err(Error::UnsupportedVersion));
        }
        for field in 0..fields(&mut value)?.len() {
            let mut changed = value.clone();
            fields(&mut changed)?[field] = Value::Null;
            assert!(validate(&encode(&changed)?).is_err());
        }
        assert_eq!(validate(&vec![0; maximum + 1]), Err(Error::BoundsExceeded));
    }
    Ok(())
}
