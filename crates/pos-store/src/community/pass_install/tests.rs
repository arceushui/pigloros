//! Installation wiring and reservation horizons: the owner horizons are an
//! installation input (ADR-129 R10.4(3), R13.2(1)), the reuse horizon is
//! `H_g` and the roster keys are the planner's CQK1 digests.

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDurableBackendV1, CommunityDurableProfileInputV1,
    CommunityDurableProfileV1, CommunityLifecycleErrorV1 as Error, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityQuarantineKeyV1,
};
use pos_core::{Hash, ImplementationKeyV1, TimelineId};
use ulid::Ulid;

use super::{
    community_reservation_horizons_v1, community_reuse_horizon_v1,
    community_roster_quarantine_keys_v1, install_community_pass_profile_v1,
    CommunityOwnerHorizonsV1, CommunityReservationHorizonsV1,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const ENTRIES: [&str; 2] = ["entry-a", "entry-b"];

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([1; 16]))
}

fn key() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(4),
    )?)
}

fn roster(key: &ImplementationKeyV1) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
    ENTRIES
        .iter()
        .map(|entry| {
            Ok(CommunityProfileMemberV1::new(
                entry,
                key,
                hash(5),
                hash(6),
                hash(7),
                ArtifactRefV1 {
                    schema_id: 1,
                    byte_length: 2,
                    digest: [8; 32],
                },
                10,
            )?)
        })
        .collect()
}

fn build_profile<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
    retention: CommunityProfileRetentionV1,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: hash(9),
            roster,
            source_catalogue_digest: hash(10),
            authority_catalogue_digest: hash(11),
            retention,
        },
    )?)
}

const RETENTION: CommunityProfileRetentionV1 = CommunityProfileRetentionV1 {
    generation_not_after_micros: 9_000_000_000,
    recovery_window_micros: 3_600_000_000,
    quarantine_not_after_micros: 9_000_000_000,
    metadata_not_after_micros: 8_000_000_000,
    recording_not_after_micros: 7_000_000_000,
};

const OWNERS: CommunityOwnerHorizonsV1 = CommunityOwnerHorizonsV1 {
    recording_micros: 7_000_000_000,
    metadata_micros: 8_000_000_000,
    evidence_micros: 8_500_000_000,
};

/// R10.4(3): the recording horizon may equal but not exceed the recording
/// owner's admitted horizon, and the minimum pass check still runs.
#[test]
fn installation_bounds_the_recording_horizon_by_the_owner() -> Fallible<()> {
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    let limits = [100, 200];
    assert!(install_community_pass_profile_v1(&profile, &limits, OWNERS).is_ok());
    let below = CommunityOwnerHorizonsV1 {
        recording_micros: OWNERS.recording_micros - 1,
        ..OWNERS
    };
    assert_eq!(
        install_community_pass_profile_v1(&profile, &limits, below).err(),
        Some(Error::InvalidBinding)
    );
    let metadata = CommunityOwnerHorizonsV1 {
        metadata_micros: OWNERS.metadata_micros - 1,
        ..OWNERS
    };
    assert_eq!(
        install_community_pass_profile_v1(&profile, &limits, metadata).err(),
        Some(Error::InvalidBinding)
    );
    // The pass check's own refusals pass through.
    assert_eq!(
        install_community_pass_profile_v1(&profile, &limits[..1], OWNERS).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// A zero or out-of-range owner horizon is no admitted horizon.
#[test]
fn an_invalid_owner_horizon_is_refused() -> Fallible<()> {
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    let limits = [100, 200];
    for owners in [
        CommunityOwnerHorizonsV1 {
            recording_micros: 0,
            ..OWNERS
        },
        CommunityOwnerHorizonsV1 {
            evidence_micros: 0,
            ..OWNERS
        },
        CommunityOwnerHorizonsV1 {
            metadata_micros: 0,
            ..OWNERS
        },
        CommunityOwnerHorizonsV1 {
            evidence_micros: u64::MAX,
            ..OWNERS
        },
        CommunityOwnerHorizonsV1 {
            recording_micros: i64::MAX as u64 + 1,
            ..OWNERS
        },
    ] {
        assert_eq!(
            install_community_pass_profile_v1(&profile, &limits, owners).err(),
            Some(Error::InvalidBinding)
        );
        assert_eq!(
            community_reservation_horizons_v1(&profile, owners, 1).err(),
            Some(Error::InvalidBinding)
        );
    }
    // The largest horizon is admitted.
    let largest = CommunityOwnerHorizonsV1 {
        recording_micros: i64::MAX as u64,
        metadata_micros: i64::MAX as u64,
        evidence_micros: i64::MAX as u64,
    };
    assert!(community_reservation_horizons_v1(&profile, largest, 1).is_ok());
    Ok(())
}

/// R13.2(1): `H_g` is the least of the generation, metadata and owner
/// horizons, and `H_r` the window end clamped to it.
#[test]
fn the_reservation_horizons_take_the_least_term() -> Fallible<()> {
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    let horizons = |owners, time| community_reservation_horizons_v1(&profile, owners, time);
    // The window ends first: H_r is reserve time + window, H_g the
    // metadata horizon.
    assert_eq!(
        horizons(OWNERS, 1_000)?,
        CommunityReservationHorizonsV1 {
            generation_micros: 8_000_000_000,
            outcome_micros: 3_600_000_000 + 1_000,
        }
    );
    // The window end is exactly H_g.
    assert_eq!(
        horizons(OWNERS, 8_000_000_000 - 3_600_000_000)?.outcome_micros,
        8_000_000_000
    );
    // The window passes H_g: H_r clamps.
    assert_eq!(
        horizons(OWNERS, 8_000_000_000)?.outcome_micros,
        8_000_000_000
    );
    // An owner horizon below the metadata and generation horizons.
    let earlier = CommunityOwnerHorizonsV1 {
        evidence_micros: 5_000_000_000,
        ..OWNERS
    };
    assert_eq!(horizons(earlier, 1)?.generation_micros, 5_000_000_000);
    // A generation horizon below the metadata horizon.
    let short = CommunityProfileRetentionV1 {
        generation_not_after_micros: 4_000_000_000,
        ..RETENTION
    };
    let generation = build_profile(&roster, short)?;
    assert_eq!(
        community_reservation_horizons_v1(&generation, OWNERS, 1)?.generation_micros,
        4_000_000_000
    );
    // The window end saturates, so a sample at the top clamps to `H_g`.
    assert_eq!(horizons(OWNERS, u64::MAX)?.outcome_micros, 8_000_000_000);
    Ok(())
}

/// R13.2(1), R13.2(4a): the horizon a reused observation must reach is `H_g`,
/// whatever the sample: the least of the generation, metadata and owner
/// evidence horizons.
#[test]
fn the_reuse_horizon_is_the_generation_horizon() -> Fallible<()> {
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    assert_eq!(community_reuse_horizon_v1(&profile, OWNERS)?, 8_000_000_000);
    assert_eq!(
        community_reuse_horizon_v1(
            &profile,
            CommunityOwnerHorizonsV1 {
                evidence_micros: 5_000_000_000,
                ..OWNERS
            }
        )?,
        5_000_000_000
    );
    for (profile_horizons, expected) in [
        (
            CommunityProfileRetentionV1 {
                generation_not_after_micros: 4_000_000_000,
                ..RETENTION
            },
            4_000_000_000,
        ),
        (
            CommunityProfileRetentionV1 {
                metadata_not_after_micros: 6_000_000_000,
                ..RETENTION
            },
            6_000_000_000,
        ),
    ] {
        let profile = build_profile(&roster, profile_horizons)?;
        assert_eq!(community_reuse_horizon_v1(&profile, OWNERS)?, expected);
    }
    assert_eq!(
        community_reuse_horizon_v1(
            &profile,
            CommunityOwnerHorizonsV1 {
                evidence_micros: 0,
                ..OWNERS
            }
        )
        .err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// R10.6: one CQK1 digest per roster member, in roster order.
#[test]
fn the_roster_keys_are_the_cqk1_digests_in_roster_order() -> Fallible<()> {
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    let keys = community_roster_quarantine_keys_v1(&profile, timeline())?;
    let expected: Vec<Hash> = roster
        .iter()
        .map(|member| {
            CommunityQuarantineKeyV1::new(
                timeline(),
                member.stable_entry(),
                member.implementation(),
            )
            .map(|key| key.digest())
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(keys, expected);
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
    Ok(())
}

/// The Reserve writer's horizon inputs are installed with the same refusals
/// as the installation check, and nothing is installed on a refusal.
#[cfg(target_os = "linux")]
#[test]
fn the_domain_installs_its_horizons_with_the_installation_refusals() -> Fallible<()> {
    const SEAL: pos_core::AuthorityTrustRootSealV1 =
        pos_core::AuthorityTrustRootSealV1::for_composition_root();
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    let limits = [100, 200];
    let mut domain = crate::community::MemoryCommunityDomainV1::new(
        crate::memory::MemoryStore::new(),
        [0x5a; 16],
        crate::MemoryTrustedClockAuthorityV1::new(),
    )?;
    assert!(domain.pass_horizons.is_none());
    for refused in [
        CommunityOwnerHorizonsV1 {
            recording_micros: OWNERS.recording_micros - 1,
            ..OWNERS
        },
        CommunityOwnerHorizonsV1 {
            metadata_micros: OWNERS.metadata_micros - 1,
            ..OWNERS
        },
        CommunityOwnerHorizonsV1 {
            evidence_micros: 0,
            ..OWNERS
        },
    ] {
        assert_eq!(
            domain
                .install_pass_horizons(&SEAL, &profile, &limits, refused)
                .err(),
            Some(Error::InvalidBinding)
        );
        assert!(domain.pass_horizons.is_none());
    }
    // The minimum pass is checked too: State limits that do not cover the
    // roster refuse.
    assert_eq!(
        domain
            .install_pass_horizons(&SEAL, &profile, &limits[..1], OWNERS)
            .err(),
        Some(Error::InvalidBinding)
    );
    assert!(domain.pass_horizons.is_none());
    let installation = domain.install_pass_horizons(&SEAL, &profile, &limits, OWNERS)?;
    assert_eq!(
        installation,
        install_community_pass_profile_v1(&profile, &limits, OWNERS)?
    );
    let installed = domain.pass_horizons.ok_or("installed")?;
    assert_eq!(installed.owners, OWNERS);
    assert_eq!(installed.profile_digest, profile.digest());
    assert_eq!(
        installed.retention.generation_not_after_micros,
        RETENTION.generation_not_after_micros
    );
    Ok(())
}

/// R15.8(3): a reinstallation is quiescent: it is refused while a pass is
/// unresolved, and goes through once it resolves.
#[cfg(target_os = "linux")]
#[test]
fn a_reinstallation_is_refused_while_a_pass_is_unresolved() -> Fallible<()> {
    const SEAL: pos_core::AuthorityTrustRootSealV1 =
        pos_core::AuthorityTrustRootSealV1::for_composition_root();
    let key = key()?;
    let roster = roster(&key)?;
    let profile = build_profile(&roster, RETENTION)?;
    let limits = [100, 200];
    let mut domain = crate::community::MemoryCommunityDomainV1::new(
        crate::memory::MemoryStore::new(),
        [0x5a; 16],
        crate::MemoryTrustedClockAuthorityV1::new(),
    )?;
    domain.install_pass_horizons(&SEAL, &profile, &limits, OWNERS)?;
    let reservation = pos_core::community_lifecycle::CommunityReservationInputV1 {
        pass_key: pos_core::community_lifecycle::CommunityPassKeyV1::new(timeline(), [2; 16], 1)?,
        request_digest: hash(1),
        native_producer_ordinal: 1,
        predecessor_head_digest: hash(2),
        roster_digest: hash(3),
        prepared_input_set_digest: hash(4),
        profile_digest: hash(5),
        evidence_not_after_micros: 1,
    };
    let record = |status| crate::community::pass_record::CommunityPassRecordV1 {
        reserved: crate::community::CommunityReservedPassV1 {
            reservation,
            cbq1_digest: hash(6),
            quote_maxima: [1, 2, 3],
            trace_rows: 2,
            members: Vec::new(),
            metadata_key: [1; 16],
            failure_cohort_key: [2; 16],
            generation_horizon_micros: 1,
            outcome_horizon_micros: 1,
        },
        prior_shared_counts: pos_core::community_lifecycle::CommunitySharedCountsV1::default(),
        materialization: None,
        status,
        live: false,
    };
    domain.pass_records.insert(
        (timeline(), [9; 16]),
        record(crate::community::CommunityPassStatusV1::Sealed),
    );
    assert_eq!(
        domain
            .install_pass_horizons(&SEAL, &profile, &limits, OWNERS)
            .err(),
        Some(Error::PassUnresolved)
    );
    domain.pass_records.insert(
        (timeline(), [9; 16]),
        record(crate::community::CommunityPassStatusV1::Aborted),
    );
    assert!(domain
        .install_pass_horizons(&SEAL, &profile, &limits, OWNERS)
        .is_ok());
    Ok(())
}
