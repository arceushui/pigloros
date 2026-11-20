//! The retained-Memory `initialize` entry (#560 A3c-2c-3; ADR-129 A5.3,
//! A5.4, A5.5, R6.1, R6.3, R6.5, R6.9, revision 7 R7.11–R7.13) through the
//! domain's public seam, over one real bootstrapped Memory domain, its
//! Plugin trust registry, its metadata and lifecycle authorities and the
//! installed initializer owner.
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod plugin_trust_registry_fixtures;

#[path = "support/community_initialization_fixture.rs"]
pub mod community_initialization_fixture;

use std::time::Duration;

use community_initialization_fixture::*;
use pos_core::community_lifecycle::{
    community_initializer_set_ref_v1, CommunityDurableProfileV1, CommunityGenerationAdmissionV1,
    CommunityInitializationSourceV1 as Source, CommunityLifecycleErrorV1 as Error,
    CommunityMetadataPolicyV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};
use pos_store::community::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1 as Request,
    CommunityInitializationContextV1, CommunityInitializationInstallationV1,
    CommunityInitializationReceiptV1, CommunityInitializeCallV1, CommunityInitializeFormV1,
    CommunityInitializerOwnerV1,
};
use zeroize::Zeroizing;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The caller's decision locators.
#[derive(Clone, Copy)]
struct Leaves<'a> {
    administrative: Hash,
    initializers: &'a [Hash],
    members: &'a [Hash],
    /// A credential to present instead of the pinned adapter's FAE1.
    credential: Option<&'a [u8]>,
}

const GRANTED: Leaves<'static> = Leaves {
    administrative: DATA_LEAF,
    initializers: &[DATA_LEAF],
    members: &[DATA_LEAF, DATA_LEAF],
    credential: None,
};

/// The code-0 caller form of `profile` on `timeline` under `operation`.
fn form(
    profile: &CommunityDurableProfileV1<'_>,
    timeline: TimelineId,
    operation: [u8; 16],
) -> CommunityInitializeFormV1 {
    CommunityInitializeFormV1 {
        timeline,
        operation_id: operation,
        initial_source: Source::Initializer(community_initializer_set_ref_v1(profile)),
    }
}

const fn installation<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
) -> CommunityInitializationInstallationV1<'a> {
    CommunityInitializationInstallationV1 {
        store_incarnation: INCARNATION,
        profile,
        native_profile_digest: NATIVE_PROFILE,
        installed_owner_catalogue_digest: hash(0x62),
        installation_id: [0x63; 16],
        state_limit_bytes: &STATE_LIMITS,
    }
}

fn owner(
    roster: &Roster,
    profile: &CommunityDurableProfileV1<'_>,
) -> Fallible<CommunityInitializerOwnerV1> {
    Ok(CommunityInitializerOwnerV1::new(
        &SEAL,
        profile,
        vec![Zeroizing::new(roster.state.clone()); 2],
    )?)
}

/// One `initialize` call on `domain` with `context`'s installation.
fn call_with(
    domain: &mut Bootstrapped,
    context: CommunityInitializationContextV1<'_>,
    form: CommunityInitializeFormV1,
    leaves: Leaves<'_>,
) -> Fallible<Result<CommunityInitializationReceiptV1, Error>> {
    let request = Request::derive(&CommunityAdministrativeOperationV1::Initialize {
        timeline: form.timeline,
        operation_id: form.operation_id,
        initial_source: form.initial_source,
        expected_prior_generation: None,
        expected_prior_head_digest: None,
    })?;
    let credential = match leaves.credential {
        Some(credential) => credential.to_vec(),
        None => domain.world.credential(request)?,
    };
    let world = &mut domain.world;
    Ok(world.domain.initialize(
        &SEAL,
        context,
        &mut world.authority,
        &mut domain.metadata,
        CommunityInitializeCallV1 {
            credential: &credential,
            form,
            administrative_leaf: leaves.administrative,
            initializer_leaves: leaves.initializers,
            member_leaves: leaves.members,
        },
    ))
}

/// One `initialize` call with the default installation of `profile`.
fn call(
    domain: &mut Bootstrapped,
    roster: &Roster,
    profile: &CommunityDurableProfileV1<'_>,
    form: CommunityInitializeFormV1,
    leaves: Leaves<'_>,
) -> Fallible<Result<CommunityInitializationReceiptV1, Error>> {
    let owner = owner(roster, profile)?;
    let policy = CommunityMetadataPolicyV1::new(*domain.policy.as_input())?;
    let context = CommunityInitializationContextV1 {
        installation: installation(profile),
        binding: pos_store::community::CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        },
        initializer: &owner,
    };
    call_with(domain, context, form, leaves)
}

/// A bootstrapped domain, its roster and nothing else.
fn bootstrapped(admit: bool, timeline: bool) -> Fallible<(Bootstrapped, Roster)> {
    let roster = Roster::release_one()?;
    Ok((Bootstrapped::new(&SEAL, &roster, admit, timeline)?, roster))
}

// ------------------------------------------------------------------ tests

/// I24 (first initialize, retry) and I35: the first initialize commits
/// `anchor_G`; a retry returns the original receipt unchanged, even with
/// initializer locators that would no longer authorize (I20: a retry needs
/// no initializer decision); a new operation on `anchor_T` is then
/// `StaleGeneration`.
#[test]
fn the_first_initialize_commits_anchor_g_and_a_retry_returns_it() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let first = form(&profile, target(), OPERATION);
    let receipt = call(&mut domain, &roster, &profile, first, GRANTED)??;
    assert_eq!(receipt.timeline(), target());
    assert_eq!(receipt.generation(), GENERATION);
    let admission =
        CommunityGenerationAdmissionV1::from_canonical_cbor(receipt.generation_admission())?;
    let fields = admission.as_input();
    assert_eq!(fields.timeline, target());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(fields.generation_request_digest, receipt.request_digest());
    assert_eq!(fields.evidence_not_after_micros, HORIZON);

    let retried = call(
        &mut domain,
        &roster,
        &profile,
        first,
        Leaves {
            initializers: &[LEAVES[1]],
            ..GRANTED
        },
    )??;
    assert_eq!(retried, receipt);

    let next = form(&profile, target(), [0x11; 16]);
    assert_eq!(
        call(&mut domain, &roster, &profile, next, GRANTED)?.err(),
        Some(Error::StaleGeneration)
    );
    Ok(())
}

/// A5.3(5): a retry whose bound content differs (another CDP1) is
/// `Conflict` once its own decision is allowed; an unauthorized retry is 12.
#[test]
fn a_retry_with_other_bound_content_is_a_conflict() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let catalogue = domain.world.catalogue;
    let profile = profile_until(&rows, HORIZON, hash(1), catalogue)?;
    let other = profile_until(&rows, HORIZON, hash(0x31), catalogue)?;
    call(
        &mut domain,
        &roster,
        &profile,
        form(&profile, target(), OPERATION),
        GRANTED,
    )??;
    assert_eq!(
        call(
            &mut domain,
            &roster,
            &other,
            form(&other, target(), OPERATION),
            GRANTED
        )?
        .err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        call(
            &mut domain,
            &roster,
            &other,
            form(&other, target(), OPERATION),
            Leaves {
                administrative: METADATA_LEAF,
                ..GRANTED
            }
        )?
        .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// I24: a Timeline other than `anchor_T`, and an unauthorized caller on
/// either Timeline, give 12; the domain then still initializes `anchor_G`.
#[test]
fn only_an_authorized_call_on_anchor_t_initializes() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    for (timeline, administrative) in [
        (other_timeline(), DATA_LEAF),
        (other_timeline(), METADATA_LEAF),
        (target(), METADATA_LEAF),
    ] {
        assert_eq!(
            call(
                &mut domain,
                &roster,
                &profile,
                form(&profile, timeline, OPERATION),
                Leaves {
                    administrative,
                    ..GRANTED
                },
            )?
            .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    let receipt = call(
        &mut domain,
        &roster,
        &profile,
        form(&profile, target(), OPERATION),
        GRANTED,
    )??;
    assert_eq!(receipt.generation(), GENERATION);
    Ok(())
}

/// I31 and the A5.5 step-1 shape: a source other than the P6 derivation,
/// a member or initializer locator count other than the roster's members
/// or distinct initializers (64 members sharing one CSC1 need one row,
/// I20), and an installation of another incarnation or native profile, each
/// give `InvalidBinding` before any authority call.
#[test]
fn shape_errors_refuse_before_any_authority_call() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let good = form(&profile, target(), OPERATION);
    let foreign = CommunityInitializeFormV1 {
        initial_source: Source::Initializer(pos_core::community_lifecycle::ArtifactRefV1 {
            digest: [9; 32],
            ..community_initializer_set_ref_v1(&profile)
        }),
        ..good
    };
    for (candidate, leaves) in [
        (foreign, GRANTED),
        (
            good,
            Leaves {
                members: &[DATA_LEAF],
                ..GRANTED
            },
        ),
        (
            good,
            Leaves {
                initializers: &[DATA_LEAF, DATA_LEAF],
                ..GRANTED
            },
        ),
    ] {
        assert_eq!(
            call(&mut domain, &roster, &profile, candidate, leaves)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    let owner = owner(&roster, &profile)?;
    let policy = CommunityMetadataPolicyV1::new(*domain.policy.as_input())?;
    for (incarnation, native) in [([0x5b; 16], NATIVE_PROFILE), (INCARNATION, hash(0x6f))] {
        let context = CommunityInitializationContextV1 {
            installation: CommunityInitializationInstallationV1 {
                store_incarnation: incarnation,
                native_profile_digest: native,
                ..installation(&profile)
            },
            binding: pos_store::community::CommunityDomainBindingV1 {
                metadata_policy: &policy,
                installed_catalogue_digest: INSTALLED_CATALOGUE,
                native_profile_digest: NATIVE_PROFILE,
            },
            initializer: &owner,
        };
        assert_eq!(
            call_with(&mut domain, context, good, GRANTED)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    call(&mut domain, &roster, &profile, good, GRANTED)??;
    Ok(())
}

/// A5.5 step 5 and I20: with the administrative decision allowed, a denied
/// initializer `read`, a denied member `execute` and a refused metadata
/// `write` each give 12 with no effect; the next call still commits
/// `anchor_G`.
#[test]
fn every_step_five_decision_is_required() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let good = form(&profile, target(), OPERATION);
    for leaves in [
        Leaves {
            initializers: &[LEAVES[0]],
            ..GRANTED
        },
        Leaves {
            members: &[DATA_LEAF, LEAVES[0]],
            ..GRANTED
        },
    ] {
        assert_eq!(
            call(&mut domain, &roster, &profile, good, leaves)?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    // An installed metadata authority with one trusted sample admits the
    // `inspect` decision and then cannot evaluate `write`.
    let registry = metadata_registry(&SEAL)?;
    let healthy = std::mem::replace(
        &mut domain.metadata,
        metadata_authority(&SEAL, registry.clone(), 1)?,
    );
    assert_eq!(
        call(&mut domain, &roster, &profile, good, GRANTED)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    // And one with none refuses the `inspect` decision of a retry lookup.
    domain.metadata = metadata_authority(&SEAL, registry, 0)?;
    assert_eq!(
        call(&mut domain, &roster, &profile, good, GRANTED)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    domain.metadata = healthy;
    let receipt = call(&mut domain, &roster, &profile, good, GRANTED)??;
    assert_eq!(receipt.generation(), GENERATION);
    Ok(())
}

/// I26 and R6.5(4): a Memory domain with no active release for the roster's
/// Plugin gives 10, judged after every decision.
#[test]
fn no_active_release_is_admission_denied() -> TestResult {
    let (mut domain, roster) = bootstrapped(false, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    assert_eq!(
        call(
            &mut domain,
            &roster,
            &profile,
            form(&profile, target(), OPERATION),
            GRANTED
        )?
        .err(),
        Some(Error::AdmissionDenied)
    );
    Ok(())
}

/// Owner decision on #560, 2026-11-20, item 2: every CPN1, CIS1 and CSR1
/// carries the CDP1 generation horizon, which must not end before the
/// call's decision bound.
#[test]
fn the_generation_horizon_must_outlive_the_decision_bound() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let catalogue = domain.world.catalogue;
    // The bound is min(t_r + 32 s, expires_at) = EXPIRES.
    let short = profile_until(&rows, EXPIRES - 1, hash(1), catalogue)?;
    assert_eq!(
        call(
            &mut domain,
            &roster,
            &short,
            form(&short, target(), OPERATION),
            GRANTED
        )?
        .err(),
        Some(Error::EvidenceExpired)
    );
    let exact = profile_until(&rows, EXPIRES, hash(1), catalogue)?;
    let receipt = call(
        &mut domain,
        &roster,
        &exact,
        form(&exact, target(), OPERATION),
        GRANTED,
    )??;
    let admission =
        CommunityGenerationAdmissionV1::from_canonical_cbor(receipt.generation_admission())?;
    assert_eq!(admission.as_input().evidence_not_after_micros, EXPIRES);
    Ok(())
}

/// Owner decision on #560, 2026-11-20: the decision bound must also not
/// pass the NMP1 metadata horizon every CMB1, CMS1 and successor CSI1
/// carries. With the generation horizon far later, one microsecond short of
/// the bound is `EvidenceExpired` and exactly the bound initializes.
#[test]
fn the_metadata_horizon_must_outlive_the_decision_bound() -> TestResult {
    let roster = Roster::release_one()?;
    for (metadata_horizon, expired) in [(EXPIRES - 1, true), (EXPIRES, false)] {
        let mut domain = Bootstrapped::until(&SEAL, &roster, true, true, metadata_horizon)?;
        let rows = roster.rows()?;
        let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
        let outcome = call(
            &mut domain,
            &roster,
            &profile,
            form(&profile, target(), OPERATION),
            GRANTED,
        )?;
        if expired {
            assert_eq!(outcome.err(), Some(Error::EvidenceExpired));
        } else {
            assert_eq!(outcome?.generation(), GENERATION);
        }
    }
    Ok(())
}

/// A5.4 and owner decision on #560, 2026-11-20, item 1: the final writer
/// refuses at or after the decision bound, measured as `t_r` plus the guard
/// monotonic time since the guard start, and on a monotonic rollback; the
/// aborted first initialize leaves `anchor_G` for a new operation (I24).
#[test]
fn the_writer_refuses_at_or_after_the_decision_bound() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let bound = Duration::from_micros(EXPIRES - NOW);
    let zero = Duration::ZERO;
    // Two marks reserve, two open the guard, and the last is the writer's.
    for (operation, writer) in [
        ([0x31; 16], bound),
        ([0x32; 16], Duration::from_micros(EXPIRES - NOW - 1)),
    ] {
        domain.script_mono(&[zero, zero, zero, zero, writer, zero]);
        let outcome = call(
            &mut domain,
            &roster,
            &profile,
            form(&profile, target(), operation),
            GRANTED,
        )?;
        if writer == bound {
            assert_eq!(outcome.err(), Some(Error::EvidenceUnavailable));
        } else {
            assert_eq!(outcome?.generation(), GENERATION);
        }
    }
    Ok(())
}

/// The final writer also refuses a monotonic source that runs backwards
/// from the guard start.
#[test]
fn the_writer_refuses_a_monotonic_rollback() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let late = Duration::from_secs(1);
    domain.script_mono(&[late, late, late, late, Duration::ZERO, Duration::ZERO]);
    assert_eq!(
        call(
            &mut domain,
            &roster,
            &profile,
            form(&profile, target(), OPERATION),
            GRANTED
        )?
        .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// CSH1 binds the Timeline's actual Event logical head, so a store without
/// the Timeline cannot initialize it (12); an unbootstrapped domain has no
/// anchor (12).
#[test]
fn the_domain_must_hold_the_anchor_and_the_timeline() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, false)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let good = form(&profile, target(), OPERATION);
    assert_eq!(
        call(&mut domain, &roster, &profile, good, GRANTED)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let (store, _harness) = trusted_store(true)?;
    let world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        pos_store::MemoryTrustedClockAuthorityV1::new(),
    )?;
    domain.world.domain = world.domain;
    assert_eq!(
        call(&mut domain, &roster, &profile, good, GRANTED)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// R6.2(3) and I21: a credential that does not verify gives 12 before any
/// decision, and the domain then still initializes.
#[test]
fn a_credential_that_does_not_verify_gives_12() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let good = form(&profile, target(), OPERATION);
    assert_eq!(
        call(
            &mut domain,
            &roster,
            &profile,
            good,
            Leaves {
                credential: Some(&[0x80]),
                ..GRANTED
            },
        )?
        .err(),
        Some(Error::EvidenceUnavailable)
    );
    call(&mut domain, &roster, &profile, good, GRANTED)??;
    Ok(())
}

/// I37 at the entry: State limits whose CBQ1 byte maximum exceeds the CDP1
/// shared per-record limit give `BoundsExceeded` before any CGI1 is minted.
#[test]
fn an_over_limit_budget_quote_is_bounds_exceeded() -> TestResult {
    let (mut domain, roster) = bootstrapped(true, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    let owner = owner(&roster, &profile)?;
    let policy = CommunityMetadataPolicyV1::new(*domain.policy.as_input())?;
    let limits = [128 * 1024 * 1024, 0];
    let context = CommunityInitializationContextV1 {
        installation: CommunityInitializationInstallationV1 {
            state_limit_bytes: &limits,
            ..installation(&profile)
        },
        binding: pos_store::community::CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        },
        initializer: &owner,
    };
    assert_eq!(
        call_with(
            &mut domain,
            context,
            form(&profile, target(), OPERATION),
            GRANTED
        )?
        .err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
