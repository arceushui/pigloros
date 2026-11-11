//! Initialization tests reuse the real tuple/profile reconstruction fixtures.

use super::{
    bytes, encode, negotiated, profile, uint, Error, Fallible, Mode, Profile, TestResult, Tuple,
};
use ciborium::value::Value;
use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDigestListV1, CommunityDurableBackendV1,
    CommunityDurableProfileInputV1, CommunityDurableProfileV1 as DurableProfile,
    CommunityInitializationRequestInputV1, CommunityInitializationRequestV1 as Request,
    CommunityInitializationSourceV1 as Source, CommunityMemberBindingInputV1,
    CommunityMemberBindingV1 as Member, CommunityProfileMemberV1 as ProfileMember,
    CommunityProfileRetentionV1,
};
use pos_core::{Hash, ImplementationKeyV1, Seq, TimelineId};
use pos_runtime::community_plugin_host::CommunityInitializationStateReferenceV1 as State;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}
const fn initializer() -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: 7,
        byte_length: 13,
        digest: [5; 32],
    }
}
fn key(plugin: &str, release: u8) -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        plugin.into(),
        "host-v1".into(),
        hash(release),
    )?)
}
const fn request_input(
    members: &[Hash],
    source: Source,
    profile_digest: Hash,
) -> CommunityInitializationRequestInputV1<'_> {
    CommunityInitializationRequestInputV1 {
        operation_id: [1; 16],
        timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([2; 16])),
        generation: [3; 16],
        expected_prior_generation: None,
        expected_prior_head_digest: None,
        profile_digest,
        member_binding_digests: CommunityDigestListV1::from_digests(members),
        initial_source: source,
        principal_ref: initializer(),
        authorization_ref: initializer(),
        evidence_not_after_micros: 1000,
    }
}
fn durable_input<'a>(
    profile: &Profile,
    roster: &'a [ProfileMember<'a>],
) -> Fallible<CommunityDurableProfileInputV1<'a>> {
    Ok(CommunityDurableProfileInputV1 {
        backend: CommunityDurableBackendV1::RetainedMemory,
        execution_profile_digest: Hash::from_bytes(profile.digest().ok_or("profile absent")?),
        roster,
        source_catalogue_digest: hash(7),
        authority_catalogue_digest: hash(8),
        retention: CommunityProfileRetentionV1 {
            generation_not_after_micros: 1000,
            recovery_window_micros: 1,
            quarantine_not_after_micros: 1000,
            metadata_not_after_micros: 1000,
        },
    })
}
fn independent_hash(domain: &[u8], value: &Value) -> Fallible<Hash> {
    let mut preimage = domain.to_vec();
    preimage.extend(encode(value)?);
    Ok(Hash::from_bytes(*blake3::hash(&preimage).as_bytes()))
}

#[test]
fn producer_binds_tuple_member_request_and_supplied_state_reference() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let tuple = Tuple::new(&negotiated, &profile)?;
    let key = key("plugin-a", 2)?;
    let expected_content = independent_hash(
        b"PiglorOS.Community.CSC1.v1\0",
        &Value::Array(vec![
            bytes(b"CSC1"),
            uint(1),
            bytes(&[3; 32]),
            bytes(b"initial-state"),
        ]),
    )?;
    let state = State {
        schema_digest: hash(3),
        state_content_digest: expected_content,
    };
    let member = tuple.member_binding("entry", &key, hash(3), expected_content, hash(6))?;
    let roster = [tuple.profile_member("entry", &key, hash(3), initializer())?];
    let durable = DurableProfile::new(durable_input(&profile, &roster)?)?;
    let members = [hash(99), member.digest()];
    for source in [
        Source::Initializer(initializer()),
        Source::PriorState(hash(11)),
        Source::Fork {
            timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([12; 16])),
            cut: Seq::from_u64(0),
            selected_head_digest: hash(13),
            operation_id: [14; 16],
        },
    ] {
        let request = Request::new(request_input(&members, source, durable.digest()))?;
        let producer =
            tuple.initialization_producer(&request, &member, &durable, &state, hash(8), 1000)?;
        let fields = producer.as_input();
        assert_eq!(fields.generation_request_digest, request.digest());
        assert_eq!(fields.member_binding_digest, member.digest());
        assert_eq!(fields.state_content_digest, expected_content);
        assert_eq!(fields.initializer_ref, initializer());
        assert_eq!(fields.scope_binding_digest, hash(8));
        assert_eq!(fields.evidence_not_after_micros, 1000);
        let expected = Value::Array(vec![
            bytes(b"CIS1"),
            uint(1),
            bytes(request.digest().as_bytes()),
            bytes(member.digest().as_bytes()),
            Value::Array(vec![uint(7), uint(13), bytes(&[5; 32])]),
            bytes(expected_content.as_bytes()),
            bytes(&[8; 32]),
            uint(1000),
        ]);
        assert_eq!(producer.to_canonical_cbor().as_slice(), encode(&expected)?);
        assert_eq!(
            producer.digest(),
            independent_hash(b"PiglorOS.Community.CIS1.v1\0", &expected)?
        );
        let shortened =
            tuple.initialization_producer(&request, &member, &durable, &state, hash(8), 1)?;
        assert_eq!(shortened.as_input().evidence_not_after_micros, 1);
    }
    Ok(())
}

#[test]
fn producer_rejects_each_negotiated_member_or_state_substitution_independently() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let tuple = Tuple::new(&negotiated, &profile)?;
    let key = key("plugin-a", 2)?;
    let state = State {
        schema_digest: hash(3),
        state_content_digest: hash(4),
    };
    let member =
        tuple.member_binding("entry", &key, hash(3), state.state_content_digest, hash(6))?;
    let other_plugin = self::key("plugin-b", 2)?;
    let other_release = self::key("plugin-a", 9)?;
    for input in [
        CommunityMemberBindingInputV1 {
            implementation: &other_plugin,
            ..*member.as_input()
        },
        CommunityMemberBindingInputV1 {
            implementation: &other_release,
            ..*member.as_input()
        },
        CommunityMemberBindingInputV1 {
            pmf1_digest: hash(9),
            ..*member.as_input()
        },
        CommunityMemberBindingInputV1 {
            negotiated_tuple_digest: hash(9),
            ..*member.as_input()
        },
        CommunityMemberBindingInputV1 {
            state_schema_digest: hash(9),
            ..*member.as_input()
        },
        CommunityMemberBindingInputV1 {
            initial_state_content_digest: hash(9),
            ..*member.as_input()
        },
    ] {
        let changed = Member::new(input)?;
        // Match request/profile to the changed member so they cannot mask its bad binding.
        let roster = [ProfileMember::new(
            input.stable_entry,
            input.implementation,
            input.pmf1_digest,
            input.state_schema_digest,
            input.negotiated_tuple_digest,
            initializer(),
        )?];
        let durable = DurableProfile::new(durable_input(&profile, &roster)?)?;
        let members = [changed.digest()];
        let request = Request::new(request_input(
            &members,
            Source::Initializer(initializer()),
            durable.digest(),
        ))?;
        assert_eq!(
            tuple
                .initialization_producer(&request, &changed, &durable, &state, hash(8), 1000)
                .err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn producer_refuses_absent_member_foreign_profile_and_horizon_extension() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let tuple = Tuple::new(&negotiated, &profile)?;
    let key = key("plugin-a", 2)?;
    let state = State {
        schema_digest: hash(3),
        state_content_digest: hash(4),
    };
    let member =
        tuple.member_binding("entry", &key, hash(3), state.state_content_digest, hash(6))?;
    let roster = [tuple.profile_member("entry", &key, hash(3), initializer())?];
    let input = durable_input(&profile, &roster)?;
    let durable = DurableProfile::new(input)?;
    let members = [member.digest()];
    let request_fields = request_input(
        &members,
        Source::Initializer(initializer()),
        durable.digest(),
    );
    let request = Request::new(request_fields)?;
    let missing = [hash(99)];
    let absent = Request::new(request_input(
        &missing,
        Source::Initializer(initializer()),
        durable.digest(),
    ))?;
    let foreign = Request::new(CommunityInitializationRequestInputV1 {
        profile_digest: hash(99),
        ..request_fields
    })?;
    let extended = Request::new(CommunityInitializationRequestInputV1 {
        evidence_not_after_micros: 1001,
        ..request_fields
    })?;
    for bad in [&absent, &foreign, &extended] {
        assert_eq!(
            tuple
                .initialization_producer(bad, &member, &durable, &state, hash(8), 1000)
                .err(),
            Some(Error::InvalidBinding)
        );
    }
    assert_eq!(
        tuple
            .initialization_producer(&request, &member, &durable, &state, hash(8), 1001)
            .err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        tuple
            .initialization_producer(&request, &member, &durable, &state, hash(8), 0)
            .err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        tuple
            .initialization_producer(&request, &member, &durable, &state, Hash::zero(), 1000)
            .err(),
        Some(Error::InvalidBinding)
    );
    let wrong_execution = DurableProfile::new(CommunityDurableProfileInputV1 {
        execution_profile_digest: hash(99),
        ..input
    })?;
    let wrong_request = Request::new(CommunityInitializationRequestInputV1 {
        profile_digest: wrong_execution.digest(),
        ..request_fields
    })?;
    assert_eq!(
        tuple
            .initialization_producer(
                &wrong_request,
                &member,
                &wrong_execution,
                &state,
                hash(8),
                1000
            )
            .err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn producer_checks_actual_profile_roster_and_its_initializer() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let tuple = Tuple::new(&negotiated, &profile)?;
    let key = key("plugin-a", 2)?;
    let other_key = self::key("plugin-b", 2)?;
    let state = State {
        schema_digest: hash(3),
        state_content_digest: hash(4),
    };
    let member =
        tuple.member_binding("entry", &key, hash(3), state.state_content_digest, hash(6))?;
    let binding = member.as_input();
    let members = [member.digest()];
    for (entry, implementation, pmf, schema, cnt) in [
        ("other", &key, binding.pmf1_digest, hash(3), tuple.digest()),
        (
            "entry",
            &other_key,
            binding.pmf1_digest,
            hash(3),
            tuple.digest(),
        ),
        ("entry", &key, hash(99), hash(3), tuple.digest()),
        ("entry", &key, binding.pmf1_digest, hash(99), tuple.digest()),
        ("entry", &key, binding.pmf1_digest, hash(3), hash(99)),
    ] {
        let roster = [ProfileMember::new(
            entry,
            implementation,
            pmf,
            schema,
            cnt,
            initializer(),
        )?];
        let durable = DurableProfile::new(durable_input(&profile, &roster)?)?;
        let request = Request::new(request_input(
            &members,
            Source::Initializer(initializer()),
            durable.digest(),
        ))?;
        assert_eq!(
            tuple
                .initialization_producer(&request, &member, &durable, &state, hash(8), 1000)
                .err(),
            Some(Error::InvalidBinding)
        );
    }
    let foreign_initializer = ArtifactRefV1 {
        digest: [99; 32],
        ..initializer()
    };
    let original = [tuple.profile_member("entry", &key, hash(3), initializer())?];
    let changed = [tuple.profile_member("entry", &key, hash(3), foreign_initializer)?];
    let original_profile = DurableProfile::new(durable_input(&profile, &original)?)?;
    let changed_profile = DurableProfile::new(durable_input(&profile, &changed)?)?;
    let request = Request::new(request_input(
        &members,
        Source::Initializer(initializer()),
        original_profile.digest(),
    ))?;
    assert_eq!(
        tuple
            .initialization_producer(&request, &member, &changed_profile, &state, hash(8), 1000)
            .err(),
        Some(Error::InvalidBinding)
    );
    // Bind the request to the changed complete profile. A row's initializer is
    // selected from that policy, independently of the generation-level source.
    let matching = Request::new(request_input(
        &members,
        Source::Initializer(initializer()),
        changed_profile.digest(),
    ))?;
    let producer = tuple.initialization_producer(
        &matching,
        &member,
        &changed_profile,
        &state,
        hash(8),
        1000,
    )?;
    assert_eq!(producer.as_input().initializer_ref, foreign_initializer);
    assert_eq!(
        producer.as_input().generation_request_digest,
        matching.digest()
    );
    Ok(())
}
