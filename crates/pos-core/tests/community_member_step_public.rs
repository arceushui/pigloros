//! Independent immutable member and input-only invocation producer preimages.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityInvocationStepV1 as Step, CommunityLifecycleErrorV1 as Error,
    CommunityMemberBindingInputV1 as MemberInput, CommunityMemberBindingV1 as Member,
    CommunityPassKeyV1 as Pass, CommunityPreparedInvocationInputV1 as PreparedInput,
    CommunityPreparedInvocationV1 as Prepared, TimelinePositionV1,
};
use pos_core::{Hash, ImplementationKeyV1, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn text(value: &str) -> Value {
    Value::Text(value.into())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("expected fixture array".into()),
    }
}
fn implementation() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(3),
    )?)
}
const fn member_input(implementation: &ImplementationKeyV1) -> MemberInput<'_> {
    MemberInput {
        stable_entry: "Entry-A_1",
        implementation,
        pmf1_digest: hash(4),
        state_schema_digest: hash(5),
        negotiated_tuple_digest: hash(6),
        initial_state_content_digest: hash(7),
        protected_owner_binding_digest: hash(8),
    }
}
fn implementation_value(key: &ImplementationKeyV1) -> Value {
    Value::Array(vec![
        bytes(b"IMK1"),
        uint(1),
        text(key.plugin_id()),
        text(key.version()),
        bytes(key.release_digest().as_bytes()),
    ])
}
fn member_value(input: &MemberInput<'_>) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CMB1"),
        uint(1),
        text(input.stable_entry),
        bytes(&encode(&implementation_value(input.implementation))?),
        bytes(input.pmf1_digest.as_bytes()),
        bytes(input.state_schema_digest.as_bytes()),
        bytes(input.negotiated_tuple_digest.as_bytes()),
        bytes(input.initial_state_content_digest.as_bytes()),
        bytes(input.protected_owner_binding_digest.as_bytes()),
    ]))
}
fn logical_digest(domain: &[u8], value: &[u8]) -> Hash {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(value);
    Hash::from_bytes(*blake3::hash(&bytes).as_bytes())
}
fn pass() -> Fallible<Pass> {
    Ok(Pass::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        [2; 16],
        3,
    )?)
}
fn prepared(member: &Member<'_>) -> Fallible<Prepared<'static>> {
    let artifact = ArtifactRefV1 {
        schema_id: 9,
        byte_length: 0,
        digest: [10; 32],
    };
    Ok(Prepared::new(PreparedInput {
        member_binding_digest: member.digest(),
        invocation_id: [11; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [1; 16],
            seq: 12,
            tick: 13,
            scheduler_position: 14,
        },
        output_base_ordinal: 15,
        principal_ref: artifact,
        authorization_ref: artifact,
        observation_snapshot_ref: artifact,
        observation_bytes: b"",
        prior_state_schema_digest: *member.as_input().state_schema_digest.as_bytes(),
        prior_state_bytes: b"",
        execution_profile_digest: [16; 32],
        trust_policy_snapshot_digest: [17; 32],
        deterministic_budget_id: "budget/v1",
        deterministic_random_domain: [18; 32],
        provenance_root: [19; 32],
        simulation_time: 20,
        watchdog_epochs: 21,
    })?)
}

#[test]
fn member_matches_exact_nine_field_wire_and_borrows_original_implementation() -> TestResult {
    let key = implementation()?;
    let input = member_input(&key);
    let member = Member::new(input)?;
    let expected = encode(&member_value(&input)?)?;
    assert_eq!(&*member.to_canonical_cbor(), &expected);
    assert_eq!(
        member.digest(),
        logical_digest(b"PiglorOS.Community.CMB1.v1\0", &expected)
    );
    let decoded = Member::from_canonical_cbor(&expected, &key)?;
    assert!(*decoded.as_input() == input);
    assert!(std::ptr::eq(
        decoded.as_input().implementation,
        &raw const key
    ));
    let entry = decoded.as_input().stable_entry;
    assert!(entry.as_ptr() >= expected.as_ptr());
    assert!(entry.as_bytes().as_ptr_range().end <= expected.as_ptr_range().end);
    Ok(())
}

#[test]
fn member_checks_all_required_links_and_stable_slot_grammar() -> TestResult {
    let key = implementation()?;
    for field in 0..5 {
        let mut input = member_input(&key);
        match field {
            0 => input.pmf1_digest = Hash::zero(),
            1 => input.state_schema_digest = Hash::zero(),
            2 => input.negotiated_tuple_digest = Hash::zero(),
            3 => input.initial_state_content_digest = Hash::zero(),
            _ => input.protected_owner_binding_digest = Hash::zero(),
        }
        assert_eq!(Member::new(input).err(), Some(Error::InvalidBinding));
        assert_eq!(
            Member::from_canonical_cbor(&encode(&member_value(&input)?)?, &key).err(),
            Some(Error::InvalidBinding)
        );
    }
    let zero_release = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), Hash::zero())?;
    assert_eq!(
        Member::new(member_input(&zero_release)).err(),
        Some(Error::InvalidBinding)
    );
    let zero_bytes = encode(&member_value(&member_input(&zero_release))?)?;
    assert_eq!(
        Member::from_canonical_cbor(&zero_bytes, &zero_release).err(),
        Some(Error::InvalidBinding)
    );
    for invalid in [
        String::new(),
        "a/b".into(),
        "a b".into(),
        "é".into(),
        "a".repeat(65),
    ] {
        let mut input = member_input(&key);
        input.stable_entry = &invalid;
        assert_eq!(Member::new(input).err(), Some(Error::InvalidBinding));
        assert!(Member::from_canonical_cbor(&encode(&member_value(&input)?)?, &key).is_err());
    }
    Ok(())
}

#[test]
fn member_preserves_maximal_accepted_implementation_and_slot_without_truncation() -> TestResult {
    let key = ImplementationKeyV1::new("p".repeat(128), "v".repeat(64), hash(3))?;
    let entry = "E".repeat(64);
    let mut input = member_input(&key);
    input.stable_entry = &entry;
    let member = Member::new(input)?;
    let encoded = member.to_canonical_cbor();
    assert!(encoded.len() <= 1024);
    assert_eq!(&*encoded, &encode(&member_value(&input)?)?);
    assert!(*Member::from_canonical_cbor(&encoded, &key)?.as_input() == input);
    Ok(())
}

#[test]
fn nested_implementation_substitution_never_reconstructs_a_new_registration() -> TestResult {
    let key = implementation()?;
    let encoded = encode(&member_value(&member_input(&key))?)?;
    for foreign in [
        ImplementationKeyV1::new("plugin-b".into(), "host-v1".into(), hash(3))?,
        ImplementationKeyV1::new("plugin-a".into(), "host-v2".into(), hash(3))?,
        ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(9))?,
    ] {
        assert_eq!(
            Member::from_canonical_cbor(&encoded, &foreign).err(),
            Some(Error::InvalidBinding)
        );
    }
    for nested in [vec![0; 238], vec![0], {
        let mut bytes = encode(&implementation_value(&key))?;
        bytes.splice(6..7, [0x18, 1]);
        bytes
    }] {
        let mut value = member_value(&member_input(&key))?;
        fields(&mut value)?[3] = bytes(&nested);
        assert!(Member::from_canonical_cbor(&encode(&value)?, &key).is_err());
    }
    Ok(())
}

#[test]
fn malformed_nonpreferred_versioned_or_trailing_members_refuse() -> TestResult {
    let key = implementation()?;
    let expected = encode(&member_value(&member_input(&key))?)?;
    for end in 0..expected.len() {
        assert!(Member::from_canonical_cbor(&expected[..end], &key).is_err());
    }
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(
        Member::from_canonical_cbor(&trailing, &key).err(),
        Some(Error::InvalidEncoding)
    );
    for (range, replacement) in [(0..1, vec![0x98, 9]), (6..7, vec![0x18, 1])] {
        let mut nonpreferred = expected.clone();
        nonpreferred.splice(range, replacement);
        assert_eq!(
            Member::from_canonical_cbor(&nonpreferred, &key).err(),
            Some(Error::InvalidEncoding)
        );
    }
    for version in [0, 2, u64::MAX] {
        let mut value = member_value(&member_input(&key))?;
        fields(&mut value)?[1] = uint(version);
        assert_eq!(
            Member::from_canonical_cbor(&encode(&value)?, &key).err(),
            Some(Error::UnsupportedVersion)
        );
    }
    for field in 0..9 {
        let mut value = member_value(&member_input(&key))?;
        fields(&mut value)?[field] = Value::Null;
        assert!(Member::from_canonical_cbor(&encode(&value)?, &key).is_err());
    }
    assert_eq!(
        Member::from_canonical_cbor(&vec![0; 1025], &key).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn input_only_step_derives_exact_member_prepared_and_source_identities() -> TestResult {
    let key = implementation()?;
    let member = Member::new(member_input(&key))?;
    let prepared = prepared(&member)?;
    let pass = pass()?;
    let step = Step::new(pass, &member, &prepared, hash(22), 23)?;
    let pass_value = Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ]);
    let expected = encode(&Value::Array(vec![
        bytes(b"CPI1"),
        uint(1),
        bytes(&encode(&pass_value)?),
        bytes(member.digest().as_bytes()),
        bytes(&[11; 16]),
        bytes(&[6; 32]),
        bytes(prepared.digest().as_bytes()),
        bytes(&[19; 32]),
        bytes(&[22; 32]),
        uint(23),
    ]))?;
    assert_eq!(&*step.to_canonical_cbor(), &expected);
    assert_eq!(
        step.digest(),
        logical_digest(b"PiglorOS.Community.CPI1.v1\0", &expected)
    );
    let input = step.as_input();
    assert!(input.pass_key == pass);
    assert_eq!(input.member_binding_digest, member.digest());
    assert_eq!(input.invocation_id, prepared.as_input().invocation_id);
    assert_eq!(input.negotiated_tuple_digest, hash(6));
    assert_eq!(input.prepared_invocation_digest, prepared.digest());
    assert_eq!(input.source_closure_root, hash(19));
    assert_eq!(input.rule_bundle_digest, hash(22));
    assert_eq!(input.evidence_not_after_micros, 23);
    step.validate_canonical_cbor(&expected)?;
    Ok(())
}

#[test]
fn step_rejects_member_schema_timeline_and_finite_policy_substitution() -> TestResult {
    let key = implementation()?;
    let member = Member::new(member_input(&key))?;
    let original = prepared(&member)?;
    for field in 0..3 {
        let mut input = *original.as_input();
        match field {
            0 => input.member_binding_digest = hash(25),
            1 => input.prior_state_schema_digest = [26; 32],
            _ => input.timeline_position.timeline_id = [27; 16],
        }
        let changed = Prepared::new(input)?;
        assert_eq!(
            Step::new(pass()?, &member, &changed, hash(22), 23).err(),
            Some(Error::InvalidBinding)
        );
    }
    assert_eq!(
        Step::new(pass()?, &member, &original, Hash::zero(), 23).err(),
        Some(Error::InvalidBinding)
    );
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Step::new(pass()?, &member, &original, hash(22), horizon).err(),
            Some(Error::BoundsExceeded)
        );
    }
    for horizon in [1, u64::MAX / 2] {
        assert_eq!(
            Step::new(pass()?, &member, &original, hash(22), horizon)?
                .as_input()
                .evidence_not_after_micros,
            horizon
        );
    }
    Ok(())
}

#[test]
fn retained_step_requires_exact_original_preimages_and_canonical_bytes() -> TestResult {
    let key = implementation()?;
    let member = Member::new(member_input(&key))?;
    let prepared = prepared(&member)?;
    let step = Step::new(pass()?, &member, &prepared, hash(22), 23)?;
    let encoded = step.to_canonical_cbor();
    for end in 0..encoded.len() {
        assert_eq!(
            step.validate_canonical_cbor(&encoded[..end]),
            Err(Error::InvalidBinding)
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        step.validate_canonical_cbor(&trailing),
        Err(Error::InvalidBinding)
    );
    let mut nonpreferred = encoded.to_vec();
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        step.validate_canonical_cbor(&nonpreferred),
        Err(Error::InvalidBinding)
    );
    let mut decoded: Value = ciborium::from_reader(encoded.as_slice())?;
    for field in 0..10 {
        let mut changed = decoded.clone();
        fields(&mut changed)?[field] = Value::Null;
        assert_eq!(
            step.validate_canonical_cbor(&encode(&changed)?),
            Err(Error::InvalidBinding)
        );
    }
    fields(&mut decoded)?[1] = uint(2);
    assert_eq!(
        step.validate_canonical_cbor(&encode(&decoded)?),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        step.validate_canonical_cbor(&vec![0; 1024]),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        step.validate_canonical_cbor(&vec![0; 1025]),
        Err(Error::BoundsExceeded)
    );
    let mut different = *prepared.as_input();
    different.watchdog_epochs += 1;
    let changed = Prepared::new(different)?;
    let foreign = Step::new(pass()?, &member, &changed, hash(22), 23)?;
    assert_eq!(
        step.validate_canonical_cbor(&foreign.to_canonical_cbor()),
        Err(Error::InvalidBinding)
    );
    Ok(())
}
