//! Exact selected CDP1 policy literals and independent canonical preimages.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDurableBackendV1 as Backend, CommunityDurableProfileInputV1 as Input,
    CommunityDurableProfileV1 as Profile, CommunityLifecycleErrorV1 as Error,
    CommunityProfileMemberV1 as Member, CommunityProfileRetentionV1 as Retention,
    COMMUNITY_CONTROL_OPERATIONS_V1, COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1,
    COMMUNITY_DECISION_DEADLINE_MICROS_V1, COMMUNITY_FOLD_BUDGET_MICROS_V1,
    COMMUNITY_RETAINED_PASS_OUTCOMES_V1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::{Hash, ImplementationKeyV1};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;
const fn hash(number: u8) -> Hash {
    Hash::from_bytes([number; 32])
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
fn policy(values: &[u64]) -> Fallible<Value> {
    Ok(bytes(&encode(&Value::Array(
        values.iter().copied().map(uint).collect(),
    ))?))
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture array expected".into()),
    }
}
fn key() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(10),
    )?)
}
/// Each fixture member's cadence interval in nanoseconds.
const CADENCE: u64 = 10;
/// The fixture's `retention_bytes`.
const RETENTION: [u64; 5] = [12, 13, 14, 15, 16];
const fn initializer() -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: 7,
        byte_length: 8,
        digest: [9; 32],
    }
}
fn roster<'a>(key: &'a ImplementationKeyV1, entries: &'a [String]) -> Fallible<Vec<Member<'a>>> {
    entries
        .iter()
        .map(|entry| {
            Ok(Member::new(
                entry,
                key,
                hash(4),
                hash(5),
                hash(6),
                initializer(),
                CADENCE,
            )?)
        })
        .collect()
}
const fn input<'a>(roster: &'a [Member<'a>], backend: Backend) -> Input<'a> {
    Input {
        backend,
        execution_profile_digest: hash(1),
        roster,
        source_catalogue_digest: hash(2),
        authority_catalogue_digest: hash(3),
        retention: Retention {
            generation_not_after_micros: 12,
            recovery_window_micros: 13,
            quarantine_not_after_micros: 14,
            metadata_not_after_micros: 15,
            recording_not_after_micros: 16,
        },
    }
}
fn expected(
    backend: u64,
    key: &ImplementationKeyV1,
    entries: &[String],
    retention: [u64; 5],
) -> Fallible<Value> {
    let imk = encode(&Value::Array(vec![
        bytes(b"IMK1"),
        uint(1),
        Value::Text(key.plugin_id().into()),
        Value::Text(key.version().into()),
        bytes(key.release_digest().as_bytes()),
    ]))?;
    let rows = entries
        .iter()
        .map(|entry| {
            Value::Array(vec![
                Value::Text(entry.clone()),
                bytes(&imk),
                bytes(&[4; 32]),
                bytes(&[5; 32]),
                bytes(&[6; 32]),
                Value::Array(vec![uint(7), uint(8), bytes(&[9; 32])]),
                uint(CADENCE),
            ])
        })
        .collect();
    Ok(Value::Array(vec![
        bytes(b"CDP1"),
        uint(1),
        uint(backend),
        bytes(&[1; 32]),
        Value::Array(rows),
        policy(&[1, 0, 65_536, 65_536])?,
        bytes(&[2; 32]),
        bytes(&[3; 32]),
        policy(&[
            1,
            4096,
            8192,
            4096,
            4096,
            67_108_864,
            268_435_456,
            67_108_864,
            2048,
            2048,
        ])?,
        policy(&[
            64,
            256,
            8192,
            4096,
            65_536,
            262_144,
            134_217_728,
            1_000_000,
            4_000_000,
            4_000_000,
            4_194_304,
            3_145_728,
            3836,
            16_384,
            65_536,
            12_000_000,
        ])?,
        policy(&retention)?,
        policy(&[
            30_000_000,
            27_000_000,
            24_000_000,
            250_000,
            64,
            1,
            1_073_741_824,
            16_384,
            1,
            0,
        ])?,
        policy(&[1_128_333_313, 1024, 1_048_576, 4096, 86_400_000_000])?,
        policy(&[1, 1, 0])?,
    ]))
}

#[test]
fn complete_profile_encodes_every_selected_policy_and_original_retention_value() -> TestResult {
    let key = key()?;
    let entries = vec!["Entry-A".into(), "Entry-B".into()];
    let roster = roster(&key, &entries)?;
    for (backend, code) in [
        (Backend::RetainedMemory, 0),
        (Backend::SqliteProcessRestart, 1),
    ] {
        let input = input(&roster, backend);
        let profile = Profile::new(input)?;
        let expected = encode(&expected(code, &key, &entries, RETENTION)?)?;
        assert_eq!(&*profile.to_canonical_cbor(), &expected);
        assert!(*profile.as_input() == input);
        assert!(std::ptr::eq(
            profile.as_input().roster.as_ptr(),
            roster.as_ptr()
        ));
        let first = roster[0];
        assert_eq!(first.stable_entry(), "Entry-A");
        assert!(std::ptr::eq(first.implementation(), &raw const key));
        assert_eq!(first.digests(), [hash(4), hash(5), hash(6)]);
        assert_eq!(first.initializer(), initializer());
        assert_eq!(first.cadence_interval_ns(), CADENCE);
        let mut preimage = b"PiglorOS.Community.CDP1.v1\0".to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(
            profile.digest(),
            Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
        );
        assert_eq!(
            Profile::validate_canonical_cbor(&expected, input)?.digest(),
            profile.digest()
        );
    }
    Ok(())
}

#[test]
fn roster_policy_is_complete_strictly_entry_sorted_and_bounded_before_encoding() -> TestResult {
    let key = key()?;
    let entries: Vec<_> = (0..65).map(|number| format!("entry-{number:02}")).collect();
    let all = roster(&key, &entries)?;
    assert_eq!(
        Profile::new(input(&[], Backend::RetainedMemory)).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Profile::new(input(&all, Backend::RetainedMemory)).err(),
        Some(Error::BoundsExceeded)
    );
    let profile = Profile::new(input(&all[..64], Backend::RetainedMemory))?;
    assert_eq!(
        &*profile.to_canonical_cbor(),
        &encode(&expected(0, &key, &entries[..64], RETENTION)?)?
    );
    let reversed = [all[1], all[0]];
    let duplicate = [all[0], all[0]];
    for invalid in [&reversed[..], &duplicate[..]] {
        assert_eq!(
            Profile::new(input(invalid, Backend::RetainedMemory)).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn every_roster_identity_is_nonzero_and_stable_entry_grammar_is_exact() -> TestResult {
    let key = key()?;
    for field in 0..4 {
        let mut digests = [hash(4), hash(5), hash(6)];
        let mut initializer = initializer();
        if field < 3 {
            digests[field] = Hash::zero();
        } else {
            initializer.digest = [0; 32];
        }
        assert_eq!(
            Member::new(
                "entry",
                &key,
                digests[0],
                digests[1],
                digests[2],
                initializer,
                CADENCE,
            )
            .err(),
            Some(Error::InvalidBinding)
        );
    }
    let zero_release = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), Hash::zero())?;
    assert_eq!(
        Member::new(
            "entry",
            &zero_release,
            hash(4),
            hash(5),
            hash(6),
            initializer(),
            CADENCE,
        )
        .err(),
        Some(Error::InvalidBinding)
    );
    for entry in [
        String::new(),
        "a/b".into(),
        "a b".into(),
        "é".into(),
        "e".repeat(65),
    ] {
        assert_eq!(
            Member::new(
                &entry,
                &key,
                hash(4),
                hash(5),
                hash(6),
                initializer(),
                CADENCE
            )
            .err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn execution_source_and_authority_identity_are_not_optional_profile_fields() -> TestResult {
    let key = key()?;
    let entries = vec!["entry".into()];
    let members = roster(&key, &entries)?;
    for field in 0..3 {
        let mut input = input(&members, Backend::RetainedMemory);
        match field {
            0 => input.execution_profile_digest = Hash::zero(),
            1 => input.source_catalogue_digest = Hash::zero(),
            _ => input.authority_catalogue_digest = Hash::zero(),
        }
        assert_eq!(Profile::new(input).err(), Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn finite_original_dates_and_recovery_interval_are_preserved_at_all_boundaries() -> TestResult {
    let key = key()?;
    let entries = vec!["entry".into()];
    let members = roster(&key, &entries)?;
    for field in 0..4 {
        for invalid in [0, u64::MAX / 2 + 1, u64::MAX] {
            let mut input = input(&members, Backend::RetainedMemory);
            match field {
                0 => input.retention.generation_not_after_micros = invalid,
                1 => input.retention.quarantine_not_after_micros = invalid,
                2 => input.retention.metadata_not_after_micros = invalid,
                _ => input.retention.recording_not_after_micros = invalid,
            }
            assert_eq!(Profile::new(input).err(), Some(Error::BoundsExceeded));
        }
    }
    for invalid in [0, 86_400_000_001, u64::MAX] {
        let mut input = input(&members, Backend::RetainedMemory);
        input.retention.recovery_window_micros = invalid;
        assert_eq!(Profile::new(input).err(), Some(Error::BoundsExceeded));
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
        for window in [1, 86_400_000_000] {
            let mut input = input(&members, Backend::RetainedMemory);
            input.retention = Retention {
                generation_not_after_micros: horizon,
                recovery_window_micros: window,
                quarantine_not_after_micros: horizon,
                metadata_not_after_micros: horizon,
                recording_not_after_micros: horizon,
            };
            assert_eq!(
                &*Profile::new(input)?.to_canonical_cbor(),
                &encode(&expected(
                    0,
                    &key,
                    &entries,
                    [horizon, window, horizon, horizon, horizon]
                )?)?
            );
        }
    }
    Ok(())
}

#[test]
fn maximum_roster_strings_and_artifact_scalar_widths_are_never_truncated() -> TestResult {
    let key = ImplementationKeyV1::new("p".repeat(128), "v".repeat(64), hash(10))?;
    let entry = "E".repeat(64);
    let initializer = ArtifactRefV1 {
        schema_id: u32::MAX,
        byte_length: u64::MAX,
        digest: [9; 32],
    };
    let members = [Member::new(
        &entry,
        &key,
        hash(4),
        hash(5),
        hash(6),
        initializer,
        u64::MAX,
    )?];
    let input = input(&members, Backend::SqliteProcessRestart);
    let profile = Profile::new(input)?;
    let encoded = profile.to_canonical_cbor();
    assert!(encoded.len() < 1_048_576);
    assert_eq!(profile.as_input().roster[0].initializer(), initializer);
    assert_eq!(
        Profile::validate_canonical_cbor(&encoded, input)?.digest(),
        profile.digest()
    );
    Ok(())
}

#[test]
fn retained_profile_requires_exact_policy_bytes_and_all_fourteen_fields() -> TestResult {
    let key = key()?;
    let entries = vec!["entry".into()];
    let members = roster(&key, &entries)?;
    let input = input(&members, Backend::RetainedMemory);
    let expected = expected(0, &key, &entries, RETENTION)?;
    let encoded = encode(&expected)?;
    for end in 0..encoded.len() {
        assert_eq!(
            Profile::validate_canonical_cbor(&encoded[..end], input).err(),
            Some(Error::InvalidBinding)
        );
    }
    for field in 0..14 {
        let mut changed = expected.clone();
        fields(&mut changed)?[field] = Value::Null;
        assert_eq!(
            Profile::validate_canonical_cbor(&encode(&changed)?, input).err(),
            Some(Error::InvalidBinding)
        );
    }
    for field in [5, 8, 9, 10, 11, 12, 13] {
        let mut changed = expected.clone();
        fields(&mut changed)?[field] = policy(&[0])?;
        assert_eq!(
            Profile::validate_canonical_cbor(&encode(&changed)?, input).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Profile::validate_canonical_cbor(&trailing, input).err(),
        Some(Error::InvalidBinding)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Profile::validate_canonical_cbor(&nonpreferred, input).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Profile::validate_canonical_cbor(&vec![0; 1_048_576], input).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Profile::validate_canonical_cbor(&vec![0; 1_048_577], input).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn limits_carry_the_sixteenth_fold_budget_entry_and_refuse_the_fifteen_entry_form() -> TestResult {
    // ADR-129 revision 9, R9.7(a) and I82: `fold_budget_micros` is the 16th
    // `limits_bytes` entry, 12 s, below the 24 s worker result deadline. CDP1
    // stays version 1. Its retained bytes are compared with the exact
    // reconstruction, so the earlier 15-entry form is refused.
    assert_eq!(COMMUNITY_FOLD_BUDGET_MICROS_V1, 12_000_000);
    let key = key()?;
    let entries = vec!["entry".into()];
    let members = roster(&key, &entries)?;
    let input = input(&members, Backend::RetainedMemory);
    let expected = expected(0, &key, &entries, RETENTION)?;
    let profile = Profile::validate_canonical_cbor(&encode(&expected)?, input)?;
    let mut fifteen = expected;
    let limits = &mut fields(&mut fifteen)?[9];
    let mut values: Vec<u64> =
        ciborium::de::from_reader::<Vec<u64>, _>(limits.as_bytes().ok_or("limits")?.as_slice())?;
    assert_eq!(values.len(), 16);
    assert_eq!(values.pop(), Some(12_000_000));
    *limits = policy(&values)?;
    let fifteen = encode(&fifteen)?;
    assert_eq!(
        Profile::validate_canonical_cbor(&fifteen, input).err(),
        Some(Error::InvalidBinding)
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.Community.CDP1.v1\0");
    hasher.update(&fifteen);
    assert_ne!(profile.digest().as_bytes(), hasher.finalize().as_bytes());
    Ok(())
}

#[test]
fn recovery_validation_refuses_current_defaults_or_foreign_catalogue_substitution() -> TestResult {
    let key = key()?;
    let entries = vec!["entry".into()];
    let members = roster(&key, &entries)?;
    let original = input(&members, Backend::RetainedMemory);
    let retained = Profile::new(original)?.to_canonical_cbor();
    for field in 0..8 {
        let mut changed = original;
        match field {
            0 => changed.backend = Backend::SqliteProcessRestart,
            1 => changed.execution_profile_digest = hash(21),
            2 => changed.source_catalogue_digest = hash(22),
            3 => changed.authority_catalogue_digest = hash(23),
            4 => changed.retention.generation_not_after_micros += 1,
            5 => changed.retention.recovery_window_micros += 1,
            6 => changed.retention.metadata_not_after_micros += 1,
            _ => changed.retention.recording_not_after_micros += 1,
        }
        assert_eq!(
            Profile::validate_canonical_cbor(&retained, changed).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

fn roster_row(profile: &mut Value) -> Fallible<&mut Vec<Value>> {
    match fields(profile)?.get_mut(4) {
        Some(Value::Array(rows)) => fields(rows.get_mut(0).ok_or("roster row expected")?),
        _ => Err("roster rows expected".into()),
    }
}

#[test]
fn roster_rows_carry_a_nonzero_cadence_interval_as_their_seventh_field() -> TestResult {
    // Revision 10, R10.1 and I84: the interval is 1..=2^64-1 nanoseconds, 0
    // is refused, and the 6-field row form is refused by exact reconstruction.
    let key = key()?;
    assert_eq!(
        Member::new("entry", &key, hash(4), hash(5), hash(6), initializer(), 0).err(),
        Some(Error::InvalidBinding)
    );
    let mut digests = Vec::new();
    for interval in [1, 23, 24, u64::MAX] {
        let members = [Member::new(
            "entry",
            &key,
            hash(4),
            hash(5),
            hash(6),
            initializer(),
            interval,
        )?];
        assert_eq!(members[0].cadence_interval_ns(), interval);
        let input = input(&members, Backend::RetainedMemory);
        let profile = Profile::new(input)?;
        let mut expected = expected(0, &key, &["entry".into()], RETENTION)?;
        roster_row(&mut expected)?[6] = uint(interval);
        assert_eq!(&*profile.to_canonical_cbor(), &encode(&expected)?);
        roster_row(&mut expected)?.pop();
        assert_eq!(
            Profile::validate_canonical_cbor(&encode(&expected)?, input).err(),
            Some(Error::InvalidBinding)
        );
        digests.push(profile.digest());
    }
    digests.sort_by_key(|digest| *digest.as_bytes());
    digests.dedup();
    assert_eq!(digests.len(), 4);
    Ok(())
}

#[test]
fn retention_carries_the_recording_horizon_outside_the_lease_preimage() -> TestResult {
    // Revision 10, R10.4(3) and I92: `recording_not_after_micros` is the 5th
    // `retention_bytes` entry, the 4-entry form is refused, and the
    // `RetentionPolicy` lease digest covers only the first four entries.
    let key = key()?;
    let entries = vec!["entry".into()];
    let members = roster(&key, &entries)?;
    let original = input(&members, Backend::RetainedMemory);
    let mut later = original;
    later.retention.recording_not_after_micros = 17;
    let profile = Profile::new(original)?;
    let changed = Profile::new(later)?;
    let mut preimage = b"PiglorOS.Community.RetentionPolicy.v1\0".to_vec();
    preimage.extend(encode(&Value::Array(
        RETENTION[..4].iter().copied().map(uint).collect(),
    ))?);
    let lease = Hash::from_bytes(*blake3::hash(&preimage).as_bytes());
    assert_eq!(profile.retention_policy_digest(), lease);
    assert_eq!(changed.retention_policy_digest(), lease);
    assert_ne!(profile.digest(), changed.digest());
    let mut four = expected(0, &key, &entries, RETENTION)?;
    fields(&mut four)?[10] = policy(&RETENTION[..4])?;
    assert_eq!(
        Profile::validate_canonical_cbor(&encode(&four)?, original).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn pass_planning_limits_are_the_selected_policy_literals() {
    // Revision 10, R10.4(1), R10.4(4) and R10.7 step 4f.
    assert_eq!(
        COMMUNITY_SHARED_RECORD_LIMITS_V1,
        [65_536, 262_144, 134_217_728]
    );
    assert_eq!(
        COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1,
        [1_000_000, 4_000_000, 4_000_000]
    );
    assert_eq!(COMMUNITY_RETAINED_PASS_OUTCOMES_V1, 256);
    assert_eq!(COMMUNITY_CONTROL_OPERATIONS_V1, 8192);
    assert_eq!(COMMUNITY_DECISION_DEADLINE_MICROS_V1, 27_000_000);
}
