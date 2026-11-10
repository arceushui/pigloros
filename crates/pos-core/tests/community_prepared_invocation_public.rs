//! Independent CIN1/prepared-roster oracles through the public data boundary.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityLifecycleErrorV1 as Error, CommunityPreparedInputSetV1 as InputSet,
    CommunityPreparedInvocationInputV1 as Input, CommunityPreparedInvocationV1 as Prepared,
    TimelinePositionV1, MAX_COMMUNITY_PREPARED_INVOCATION_BYTES_V1 as MAX_RECORD,
    MAX_COMMUNITY_STATE_BYTES_V1 as MAX_PAYLOAD,
};
use pos_core::Hash;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const WIDTHS: [u64; 10] = [
    0,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    4_294_967_295,
    4_294_967_296,
    u64::MAX,
];

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
    Value::Text(value.to_owned())
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
fn artifact(value: u8) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: u32::from(value),
        byte_length: u64::from(value),
        digest: [value; 32],
    }
}
fn artifact_value(reference: ArtifactRefV1) -> Value {
    Value::Array(vec![
        uint(u64::from(reference.schema_id)),
        uint(reference.byte_length),
        bytes(&reference.digest),
    ])
}
fn input<'a>(observation: &'a [u8], state: &'a [u8]) -> Input<'a> {
    Input {
        member_binding_digest: hash(1),
        invocation_id: [2; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [3; 16],
            seq: 4,
            tick: 5,
            scheduler_position: 6,
        },
        output_base_ordinal: 7,
        principal_ref: artifact(8),
        authorization_ref: artifact(9),
        observation_snapshot_ref: artifact(10),
        observation_bytes: observation,
        prior_state_schema_digest: [11; 32],
        prior_state_bytes: state,
        execution_profile_digest: [12; 32],
        trust_policy_snapshot_digest: [13; 32],
        deterministic_budget_id: "budget/v1",
        deterministic_random_domain: [14; 32],
        provenance_root: [15; 32],
        simulation_time: 16,
        watchdog_epochs: 17,
    }
}
fn fixture(input: &Input<'_>) -> Value {
    let position = input.timeline_position;
    Value::Array(vec![
        bytes(b"CIN1"),
        uint(1),
        bytes(input.member_binding_digest.as_bytes()),
        uint(0),
        bytes(&input.invocation_id),
        Value::Array(vec![
            bytes(&position.timeline_id),
            uint(position.seq),
            uint(position.tick),
            uint(u64::from(position.scheduler_position)),
        ]),
        uint(u64::from(input.output_base_ordinal)),
        artifact_value(input.principal_ref),
        artifact_value(input.authorization_ref),
        artifact_value(input.observation_snapshot_ref),
        bytes(input.observation_bytes),
        bytes(&input.prior_state_schema_digest),
        bytes(input.prior_state_bytes),
        bytes(&input.execution_profile_digest),
        bytes(&input.trust_policy_snapshot_digest),
        text(input.deterministic_budget_id),
        bytes(&input.deterministic_random_domain),
        bytes(&input.provenance_root),
        uint(input.simulation_time),
        uint(u64::from(input.watchdog_epochs)),
    ])
}
fn logical_digest(domain: &[u8], canonical: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(canonical);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
fn assert_invalid(value: &Value) -> TestResult {
    assert!(Prepared::from_canonical_cbor(&encode(value)?).is_err());
    Ok(())
}

#[test]
fn prepared_input_has_exact_twenty_fields_and_borrowed_private_ranges() -> TestResult {
    let input = input(b"actual observation", b"actual prior State");
    let prepared = Prepared::new(input)?;
    assert!(std::ptr::eq(
        prepared.as_input().observation_bytes.as_ptr(),
        input.observation_bytes.as_ptr()
    ));
    assert!(std::ptr::eq(
        prepared.as_input().prior_state_bytes.as_ptr(),
        input.prior_state_bytes.as_ptr()
    ));
    assert!(std::ptr::eq(
        prepared.as_input().deterministic_budget_id.as_ptr(),
        input.deterministic_budget_id.as_ptr()
    ));
    let expected = encode(&fixture(&input))?;
    let actual = prepared.to_canonical_cbor();
    assert_eq!(&*actual, &expected);
    assert!(actual.capacity() >= actual.len());
    assert_eq!(
        prepared.digest(),
        logical_digest(b"PiglorOS.Community.CIN1.v1\0", &expected)
    );
    let decoded = Prepared::from_canonical_cbor(&actual)?;
    assert!(*decoded.as_input() == input);
    for range in [
        decoded.as_input().observation_bytes,
        decoded.as_input().prior_state_bytes,
        decoded.as_input().deterministic_budget_id.as_bytes(),
    ] {
        let start = actual.as_ptr() as usize;
        let address = range.as_ptr() as usize;
        assert!(address >= start && address + range.len() <= start + actual.len());
    }
    assert_eq!(&*decoded.to_canonical_cbor(), &expected);
    Ok(())
}

#[test]
fn all_original_scalar_widths_and_zero_watchdog_are_preserved() -> TestResult {
    for value in WIDTHS {
        let mut input = input(b"", b"");
        input.timeline_position.seq = value;
        input.timeline_position.tick = value;
        input.simulation_time = value;
        input.principal_ref.byte_length = value;
        if let Ok(narrow) = u32::try_from(value) {
            input.timeline_position.scheduler_position = narrow;
            input.output_base_ordinal = narrow;
            input.watchdog_epochs = narrow;
            input.principal_ref.schema_id = narrow;
        }
        let encoded = encode(&fixture(&input))?;
        assert_eq!(&*Prepared::new(input)?.to_canonical_cbor(), &encoded);
        assert!(*Prepared::from_canonical_cbor(&encoded)?.as_input() == input);
    }
    Ok(())
}

#[test]
fn all_required_durable_identity_fields_reject_zero_without_minting_authority() -> TestResult {
    for field in 0..11 {
        let mut original = input(b"", b"");
        match field {
            0 => original.member_binding_digest = Hash::zero(),
            1 => original.invocation_id = [0; 16],
            2 => original.timeline_position.timeline_id = [0; 16],
            3 => original.principal_ref.digest = [0; 32],
            4 => original.authorization_ref.digest = [0; 32],
            5 => original.observation_snapshot_ref.digest = [0; 32],
            6 => original.prior_state_schema_digest = [0; 32],
            7 => original.execution_profile_digest = [0; 32],
            8 => original.trust_policy_snapshot_digest = [0; 32],
            9 => original.deterministic_random_domain = [0; 32],
            _ => original.provenance_root = [0; 32],
        }
        assert_eq!(Prepared::new(original).err(), Some(Error::InvalidBinding));
        assert_eq!(
            Prepared::from_canonical_cbor(&encode(&fixture(&original))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    // A zero registered schema ID or empty artifact length is still an exact
    // WIT scalar, not an absent required digest or a source-validity certificate.
    let mut original = input(b"", b"");
    original.principal_ref.schema_id = 0;
    original.principal_ref.byte_length = 0;
    let encoded = Prepared::new(original)?.to_canonical_cbor();
    assert!(*Prepared::from_canonical_cbor(&encoded)?.as_input() == original);
    Ok(())
}

#[test]
fn complete_megabyte_payloads_are_preserved_and_oversize_refused() -> TestResult {
    let observation = vec![0xab; MAX_PAYLOAD];
    let state = vec![0xcd; MAX_PAYLOAD];
    let budget = "b".repeat(128);
    let mut input = input(&observation, &state);
    input.deterministic_budget_id = &budget;
    let encoded = Prepared::new(input)?.to_canonical_cbor();
    assert!(encoded.len() <= MAX_RECORD);
    assert!(*Prepared::from_canonical_cbor(&encoded)?.as_input() == input);
    for field in [10, 12] {
        let mut value = fixture(&input);
        fields(&mut value)?[field] = bytes(&vec![0; MAX_PAYLOAD + 1]);
        assert_invalid(&value)?;
    }
    let oversized = vec![0; MAX_PAYLOAD + 1];
    input.observation_bytes = &oversized;
    assert_eq!(Prepared::new(input).err(), Some(Error::BoundsExceeded));
    input.observation_bytes = b"";
    input.prior_state_bytes = &oversized;
    assert_eq!(Prepared::new(input).err(), Some(Error::BoundsExceeded));
    assert_eq!(
        Prepared::from_canonical_cbor(&vec![0; MAX_RECORD + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn required_identities_and_exact_budget_grammar_are_enforced() -> TestResult {
    let mut original = input(b"", b"");
    original.member_binding_digest = Hash::zero();
    assert_eq!(Prepared::new(original).err(), Some(Error::InvalidBinding));
    original.member_binding_digest = hash(1);
    original.invocation_id = [0; 16];
    assert_eq!(Prepared::new(original).err(), Some(Error::InvalidBinding));
    for field in [2, 4] {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[field] = bytes(&vec![0; if field == 2 { 32 } else { 16 }]);
        assert_invalid(&value)?;
    }
    for invalid in [
        String::new(),
        "Upper".into(),
        "bad space".into(),
        "a:bad".into(),
        "é".into(),
        "a".repeat(129),
    ] {
        let mut original = input(b"", b"");
        original.deterministic_budget_id = &invalid;
        assert_eq!(Prepared::new(original).err(), Some(Error::InvalidBinding));
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[15] = text(&invalid);
        assert_invalid(&value)?;
    }
    for valid in ["a", "0", "a._/-9", &"b".repeat(128)] {
        let mut original = input(b"", b"");
        original.deterministic_budget_id = valid;
        let encoded = Prepared::new(original)?.to_canonical_cbor();
        assert!(*Prepared::from_canonical_cbor(&encoded)?.as_input() == original);
    }
    Ok(())
}

#[test]
fn unsupported_exports_shapes_fixed_widths_and_scalar_overflows_refuse() -> TestResult {
    for code in [1, 2, u64::MAX] {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[3] = uint(code);
        assert_eq!(
            Prepared::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for field in [2, 4, 11, 13, 14, 16, 17] {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[field] = bytes(&[1; 31]);
        assert_invalid(&value)?;
    }
    for field in [6, 19] {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[field] = uint(u64::from(u32::MAX) + 1);
        assert_eq!(
            Prepared::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    for field in [7, 8, 9] {
        for nested in 0..3 {
            let mut value = fixture(&input(b"", b""));
            let reference = &mut fields(&mut value)?[field];
            fields(reference)?[nested] = if nested == 0 {
                uint(u64::from(u32::MAX) + 1)
            } else {
                Value::Null
            };
            assert_invalid(&value)?;
        }
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[field] = Value::Array(Vec::new());
        assert_invalid(&value)?;
    }
    for nested in 0..4 {
        let mut value = fixture(&input(b"", b""));
        let position = &mut fields(&mut value)?[5];
        fields(position)?[nested] = match nested {
            0 => bytes(&[1; 15]),
            3 => uint(u64::from(u32::MAX) + 1),
            _ => Value::Null,
        };
        assert_invalid(&value)?;
    }
    for count in [3, 5] {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[5] = Value::Array(vec![uint(0); count]);
        assert_invalid(&value)?;
    }
    Ok(())
}

#[test]
fn truncation_trailing_nonpreferred_and_future_versions_are_not_inputs() -> TestResult {
    let encoded = encode(&fixture(&input(b"o", b"s")))?;
    for end in 0..encoded.len() {
        assert!(Prepared::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_invalid_bytes(&trailing);
    let mut nonpreferred = encoded.clone();
    nonpreferred.splice(0..1, [0x98, 20]);
    assert_invalid_bytes(&nonpreferred);
    // Version sits after the fixed array head and four-byte magic byte string.
    let mut nonpreferred_version = encoded.clone();
    nonpreferred_version.splice(6..7, [0x18, 1]);
    assert_invalid_bytes(&nonpreferred_version);
    for version in [0, 2, u64::MAX] {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[1] = uint(version);
        assert_eq!(
            Prepared::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::UnsupportedVersion)
        );
    }
    // Change preferred heads throughout the independently encoded field tree.
    let value = fixture(&input(b"o", b"s"));
    if let Value::Array(values) = &value {
        let mut offset = 1;
        for field in values {
            let field_bytes = encode(field)?;
            if field_bytes[0] & 0x1f < 24 {
                let mut changed = encoded.clone();
                changed.splice(
                    offset..=offset,
                    [(field_bytes[0] & 0xe0) | 0x18, field_bytes[0] & 0x1f],
                );
                assert_invalid_bytes(&changed);
            }
            offset += field_bytes.len();
        }
    }
    for field in 0..20 {
        let mut value = fixture(&input(b"", b""));
        fields(&mut value)?[field] = Value::Null;
        assert_invalid(&value)?;
    }
    let mut invalid_utf8 = encoded;
    // Locate the unique budget text in the independent fixture, then corrupt it.
    let position = invalid_utf8
        .windows(9)
        .position(|part| part == b"budget/v1")
        .ok_or("missing budget fixture")?;
    invalid_utf8[position] = 0xff;
    assert_invalid_bytes(&invalid_utf8);
    Ok(())
}

fn assert_invalid_bytes(bytes: &[u8]) {
    assert!(Prepared::from_canonical_cbor(bytes).is_err());
}

fn roster(count: u8) -> Fallible<Vec<Prepared<'static>>> {
    (1..=count)
        .map(|number| {
            let mut input = input(b"", b"");
            input.member_binding_digest = hash(number);
            input.invocation_id = [number; 16];
            Ok(Prepared::new(input)?)
        })
        .collect()
}

#[test]
fn prepared_set_derives_each_exact_cin_hash_and_domain_in_member_order() -> TestResult {
    for count in [0, 1, 23, 24, 64] {
        let members = roster(count)?;
        let set = InputSet::new(&members)?;
        assert!(std::ptr::eq(set.members().as_ptr(), members.as_ptr()));
        let pairs = members
            .iter()
            .map(|member| {
                let input = member.as_input();
                let canonical = encode(&fixture(input))?;
                Ok(Value::Array(vec![
                    bytes(input.member_binding_digest.as_bytes()),
                    bytes(logical_digest(b"PiglorOS.Community.CIN1.v1\0", &canonical).as_bytes()),
                ]))
            })
            .collect::<Fallible<Vec<_>>>()?;
        let expected = encode(&Value::Array(pairs))?;
        assert_eq!(&*set.to_canonical_cbor(), &expected);
        assert_eq!(
            set.digest(),
            logical_digest(b"PiglorOS.Community.PreparedInputSet.v1\0", &expected)
        );
        set.validate_canonical_cbor(&expected)?;
        let mut trailing = expected;
        trailing.push(0);
        assert_eq!(
            set.validate_canonical_cbor(&trailing),
            Err(Error::InvalidBinding)
        );
        assert_eq!(
            set.validate_canonical_cbor(&vec![0; 9 + 64 * 69]),
            Err(Error::InvalidBinding)
        );
        assert_eq!(
            set.validate_canonical_cbor(&vec![0; 9 + 64 * 69 + 1]),
            Err(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn duplicate_member_invocation_substitution_and_partial_rosters_refuse() -> TestResult {
    let members = roster(65)?;
    assert_eq!(InputSet::new(&members).err(), Some(Error::BoundsExceeded));
    let mut members = roster(3)?;
    members.swap(0, 2);
    assert_eq!(InputSet::new(&members).err(), Some(Error::InvalidBinding));
    members.swap(0, 2);
    let mut duplicate = *members[0].as_input();
    duplicate.invocation_id = [4; 16];
    members[1] = Prepared::new(duplicate)?;
    assert_eq!(InputSet::new(&members).err(), Some(Error::InvalidBinding));
    members = roster(3)?;
    let mut repeated_invocation = *members[2].as_input();
    repeated_invocation.invocation_id = members[0].as_input().invocation_id;
    members[2] = Prepared::new(repeated_invocation)?;
    assert_eq!(InputSet::new(&members).err(), Some(Error::InvalidBinding));
    let members = roster(3)?;
    let complete = InputSet::new(&members)?;
    let partial = InputSet::new(&members[..2])?.to_canonical_cbor();
    assert_eq!(
        complete.validate_canonical_cbor(&partial),
        Err(Error::InvalidBinding)
    );
    let mut changed_input = *members[1].as_input();
    changed_input.watchdog_epochs += 1;
    let changed = [Prepared::new(changed_input)?];
    let original = InputSet::new(&members[1..2])?;
    assert_eq!(
        original.validate_canonical_cbor(&InputSet::new(&changed)?.to_canonical_cbor()),
        Err(Error::InvalidBinding)
    );
    Ok(())
}
