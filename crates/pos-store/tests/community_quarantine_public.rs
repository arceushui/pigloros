//! The retained-Memory pre-execution quarantine `SetReason` (#560 A4e-1;
//! ADR-129 annex "Durable quarantine", revision 8 R8.5–R8.6, revision 9
//! R9.9 and tests I52, I65–I71) through the domain's public seam, over one
//! real initialized Memory domain whose own Plugin trust registry has
//! adopted a policy that revokes the member release.
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod plugin_trust_registry_fixtures;

#[path = "support/community_initialization_fixture.rs"]
pub mod community_initialization_fixture;

use std::time::Duration;

use community_initialization_fixture::*;
use plugin_trust_registry_fixtures::{release_one, release_two, ManifestSpec};
use pos_core::community_lifecycle::{
    CommunityDurableProfileInputV1, CommunityDurableProfileV1, CommunityLifecycleErrorV1 as Error,
    CommunityPluginHostErrorV1 as Host, CommunityProfileRetentionV1,
    CommunityQuarantineDispositionV1 as Disposition, CommunityQuarantineOutcomeV1,
    CommunityQuarantineReasonV1 as Reason, RevocationBasisV1 as Basis, TrustDenialBasisV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, ImplementationKeyV1};
use pos_store::community::CommunityQuarantineReceiptV1;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// One `SetReason` on `case` with `claim`, the release `manifest` and the
/// installed CDP1 `profile`, through the public entry.
fn set_reason_with(
    case: &mut QuarantineCase,
    profile: &CommunityDurableProfileV1<'_>,
    manifest: &ManifestSpec,
    claim: Claim<'_>,
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    with_set_reason(
        case,
        profile,
        manifest,
        claim,
        |world, metadata, context, call| {
            world
                .domain
                .set_quarantine_reason(&SEAL, context, &mut world.authority, metadata, call)
        },
    )
}

/// One `SetReason` with the default profile and `release_one`.
fn set_reason(
    case: &mut QuarantineCase,
    claim: Claim<'_>,
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    set_reason_with(case, &profile, &release_one(), claim)
}

/// The receipt's CQO1, decoded.
fn outcome(receipt: &CommunityQuarantineReceiptV1) -> Fallible<CommunityQuarantineOutcomeV1> {
    Ok(CommunityQuarantineOutcomeV1::from_canonical_cbor(
        receipt.outcome(),
    )?)
}

// ------------------------------------------------------------------ tests

/// I52, I65, I66: before execution (no `PassKey`), each revocation the
/// store's own registry reports, with the matching claimed basis, records
/// `Revoked` under the first-use proof: an `Applied` CQO1 with no prior
/// ledger that selects a new CQR1 and binds the CQC1.
#[test]
fn each_registry_revocation_quarantines_before_execution() -> TestResult {
    for (revocation, basis) in [
        (Revocation::Artifact, Basis::Artifact),
        (Revocation::PublisherKey, Basis::PublisherKey),
        (Revocation::OperatorDenial, Basis::OperatorDenial),
    ] {
        let mut case = QuarantineCase::new(&SEAL, revocation)?;
        let receipt = set_reason(&mut case, claim(basis))??;
        assert_eq!(receipt.timeline(), target());
        assert_eq!(receipt.control_operation_id(), CONTROL);
        assert!(receipt.disposition() == Disposition::Applied);
        let fields = *outcome(&receipt)?.as_input();
        assert_eq!(fields.control_operation_id, CONTROL);
        assert_eq!(fields.control_request_digest, receipt.request_digest());
        assert_eq!(fields.prior_ledger_digest, None);
        assert_eq!(
            fields.selected_ledger_digest,
            receipt.selected_ledger_digest()
        );
        assert!(fields.disposition == Disposition::Applied);
        assert_eq!(fields.evidence_not_after_micros, HORIZON);
    }
    Ok(())
}

/// I66 erratum: a claimed basis other than the one the registry reports,
/// and a release the registry does not report revoked, give 12.
#[test]
fn the_registry_must_report_the_claimed_revocation() -> TestResult {
    for (revocation, basis) in [
        (Revocation::Artifact, Basis::PublisherKey),
        (Revocation::PublisherKey, Basis::OperatorDenial),
        (Revocation::OperatorDenial, Basis::Artifact),
        (Revocation::None, Basis::Artifact),
    ] {
        let mut case = QuarantineCase::new(&SEAL, revocation)?;
        assert_eq!(
            set_reason(&mut case, claim(basis))?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// I66: reason 0, 1 or 3, a host code other than 2 and a zero control
/// identity give 3 before any authority call, even with nothing revoked.
#[test]
fn only_reason_2_from_host_code_2_is_admitted() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::None)?;
    let base = claim(Basis::Artifact);
    for refused in [
        Claim {
            reason: Reason::Trapped,
            ..base
        },
        Claim {
            reason: Reason::ResourceExhausted,
            ..base
        },
        Claim {
            reason: Reason::Unavailable,
            ..base
        },
        Claim {
            host: Host::WorkerCrashed,
            reason: Reason::Unavailable,
            ..base
        },
        Claim {
            host: Host::ArtifactTrustDenied {
                basis: TrustDenialBasisV1::Untrusted,
            },
            ..base
        },
        Claim {
            control: [0; 16],
            ..base
        },
        Claim {
            entry: "not a slot!",
            ..base
        },
    ] {
        assert_eq!(
            set_reason(&mut case, refused)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

/// I71: a lost reply is recovered by an identical retry under the same
/// control identity, which returns the original CQO1; a retry with other
/// bound content is `Conflict`.
#[test]
fn an_identical_retry_returns_the_original_and_a_conflicting_one_is_4() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let first = claim(Basis::Artifact);
    let receipt = set_reason(&mut case, first)??;
    assert_eq!(set_reason(&mut case, first)??, receipt);
    for conflicting in [
        Claim {
            ledger: Some(receipt.selected_ledger_digest()),
            ..first
        },
        Claim {
            head: Some(hash(0x77)),
            ..first
        },
        Claim {
            generation: OTHER_GENERATION,
            ..first
        },
    ] {
        assert_eq!(
            set_reason(&mut case, conflicting)?.err(),
            Some(Error::Conflict)
        );
    }
    Ok(())
}

/// Annex and I52: an already active reason keeps its evidence and horizon
/// and returns `AlreadyQuarantined` with the existing CQR1; a second
/// first-use `SetReason` without the current predecessor is `Conflict`.
#[test]
fn an_active_reason_is_already_quarantined_and_needs_its_predecessor() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let first = set_reason(&mut case, claim(Basis::Artifact))??;
    let again = Claim {
        control: [0x41; 16],
        ..claim(Basis::Artifact)
    };
    assert_eq!(set_reason(&mut case, again)?.err(), Some(Error::Conflict));
    let receipt = set_reason(
        &mut case,
        Claim {
            ledger: Some(first.selected_ledger_digest()),
            ..again
        },
    )??;
    assert!(receipt.disposition() == Disposition::AlreadyQuarantined);
    assert_eq!(
        receipt.selected_ledger_digest(),
        first.selected_ledger_digest()
    );
    let fields = *outcome(&receipt)?.as_input();
    assert_eq!(
        fields.prior_ledger_digest,
        Some(first.selected_ledger_digest())
    );
    assert_eq!(
        fields.selected_ledger_digest,
        first.selected_ledger_digest()
    );
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    assert!(fields.disposition == Disposition::AlreadyQuarantined);
    // Its own retry returns it unchanged.
    assert_eq!(
        set_reason(
            &mut case,
            Claim {
                ledger: Some(first.selected_ledger_digest()),
                ..again
            },
        )??,
        receipt
    );
    Ok(())
}

/// I52: the first-use proof refuses a CQK1 no CMB1 of T's current
/// generation names (another entry), a Timeline with no generation in this
/// domain, and a domain where only another incarnation initialized T.
#[test]
fn the_first_use_proof_needs_a_cmb1_of_the_current_generation() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    for refused in [
        Claim {
            entry: "Entry-C_1",
            ..claim(Basis::Artifact)
        },
        Claim {
            timeline: other_timeline(),
            ..claim(Basis::Artifact)
        },
    ] {
        assert_eq!(
            set_reason(&mut case, refused)?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    // A second domain with the same revocation that never initialized T.
    let roster = Roster::release_one()?;
    let (domain, material) = Bootstrapped::revoked(&SEAL, &roster, Revocation::Artifact)?;
    let mut fresh = QuarantineCase {
        domain,
        roster,
        material,
        head: case.head,
    };
    assert_eq!(
        set_reason(&mut fresh, claim(Basis::Artifact))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// The CAS premises: another generation is `StaleGeneration` and another
/// head `StaleFrontier`.
#[test]
fn a_stale_generation_or_head_is_refused() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    assert_eq!(
        set_reason(
            &mut case,
            Claim {
                generation: OTHER_GENERATION,
                ..claim(Basis::Artifact)
            }
        )?
        .err(),
        Some(Error::StaleGeneration)
    );
    assert_eq!(
        set_reason(
            &mut case,
            Claim {
                head: Some(hash(0x77)),
                ..claim(Basis::Artifact)
            }
        )?
        .err(),
        Some(Error::StaleFrontier)
    );
    Ok(())
}

/// R9.9(7): the evidence must be the member's release (another release, or
/// one with another PMF1, gives 12) and the claimed TPS1 digest the one the
/// registry retains.
#[test]
fn the_failure_must_name_the_member_release_and_the_retained_tps1() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let other_pmf1 = ManifestSpec {
        pmf1: 0x5e,
        ..release_one()
    };
    for manifest in [release_two(), other_pmf1] {
        assert_eq!(
            set_reason_with(&mut case, &profile, &manifest, claim(Basis::Artifact))?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    assert_eq!(
        set_reason(
            &mut case,
            Claim {
                tps1: Some(hash(0x78)),
                ..claim(Basis::Artifact)
            }
        )?
        .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// I67: a denied metadata `write` (an exhausted owner wall source) gives 12
/// and leaves the first-use proof unused.
#[test]
fn a_denied_metadata_write_gives_12_with_no_effect() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let registry = metadata_registry(&SEAL)?;
    let mut denied = metadata_authority(&SEAL, registry, 0)?;
    std::mem::swap(&mut case.domain.metadata, &mut denied);
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    std::mem::swap(&mut case.domain.metadata, &mut denied);
    let receipt = set_reason(&mut case, claim(Basis::Artifact))??;
    assert_eq!(outcome(&receipt)?.as_input().prior_ledger_digest, None);
    Ok(())
}

/// I68: the bound is min(D, owner `expires_at`); a writer at it refuses
/// with no effect, and one just before it commits.
#[test]
fn the_writer_refuses_at_the_command_bound() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let zero = Duration::ZERO;
    case.domain.script_mono(&[
        zero,
        zero,
        zero,
        zero,
        Duration::from_micros(EXPIRES - NOW),
        zero,
    ]);
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    case.domain.script_mono(&[
        zero,
        zero,
        zero,
        zero,
        Duration::from_micros(EXPIRES - NOW - 1),
        zero,
    ]);
    let receipt = set_reason(&mut case, claim(Basis::Artifact))??;
    assert_eq!(outcome(&receipt)?.as_input().prior_ledger_digest, None);
    Ok(())
}

/// The CDP1 `rows` under `quarantine` as its quarantine horizon.
fn profile_with_quarantine<'a>(
    rows: &'a [pos_core::community_lifecycle::CommunityProfileMemberV1<'a>],
    catalogue: Hash,
    quarantine: u64,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            retention: CommunityProfileRetentionV1 {
                quarantine_not_after_micros: quarantine,
                ..profile_until(rows, HORIZON, hash(1), catalogue)?
                    .as_input()
                    .retention
            },
            ..*profile_until(rows, HORIZON, hash(1), catalogue)?.as_input()
        },
    )?)
}

/// A case whose generation was initialized under a CDP1 with quarantine
/// horizon `quarantine`.
fn case_with_quarantine(quarantine: u64) -> Fallible<QuarantineCase> {
    let roster = Roster::release_one()?;
    let (mut domain, material) = Bootstrapped::revoked(&SEAL, &roster, Revocation::Artifact)?;
    let rows = roster.rows()?;
    let profile = profile_with_quarantine(&rows, domain.world.catalogue, quarantine)?;
    let receipt = initialize_target(&SEAL, &mut domain, &roster, &profile)??;
    Ok(QuarantineCase {
        head: initial_head(&receipt)?,
        domain,
        roster: Roster::release_one()?,
        material,
    })
}

/// I68: the bound min(D, owner `expires_at`) = `EXPIRES` fits a quarantine
/// horizon equal to it and is `EvidenceExpired` one micro past; a profile
/// other than the generation's is `InvalidBinding`.
#[test]
fn the_bound_must_fit_the_quarantine_horizon_of_the_generation_profile() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    for (quarantine, expired) in [(EXPIRES - 1, true), (EXPIRES, false)] {
        let mut case = case_with_quarantine(quarantine)?;
        let profile = profile_with_quarantine(&rows, case.domain.world.catalogue, quarantine)?;
        let outcome = set_reason_with(&mut case, &profile, &release_one(), claim(Basis::Artifact))?;
        if expired {
            assert_eq!(outcome.err(), Some(Error::EvidenceExpired));
            let other = profile_with_quarantine(&rows, case.domain.world.catalogue, EXPIRES)?;
            assert_eq!(
                set_reason_with(&mut case, &other, &release_one(), claim(Basis::Artifact))?.err(),
                Some(Error::InvalidBinding)
            );
        } else {
            let receipt = outcome?;
            assert_eq!(
                self::outcome(&receipt)?
                    .as_input()
                    .evidence_not_after_micros,
                EXPIRES
            );
        }
    }
    Ok(())
}

/// The member's IMK1 must be the roster's: another implementation of the
/// same entry has no CMB1 in the generation.
#[test]
fn another_implementation_of_the_entry_is_not_admitted() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let other = ImplementationKeyV1::new(
        case.roster.implementation.plugin_id().to_owned(),
        "host-v2".into(),
        case.roster.implementation.release_digest(),
    )?;
    assert_eq!(
        set_reason(
            &mut case,
            Claim {
                implementation: Some(&other),
                ..claim(Basis::Artifact)
            }
        )?
        .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}
