//! The reset core (I208's reset bullet, I209, I214): its refusals in order,
//! the successor ledger it commits and the shares it re-arms, with the
//! evidence of the reasons it clears already expired.

use std::collections::BTreeMap;

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyV1,
    CommunityPassKeyV1, CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1,
    CommunityQuarantineOutcomeV1, CommunityQuarantineReasonEvidenceV1 as Evidence,
    CommunityQuarantineReasonV1 as Reason, CommunityReservationInputV1, CommunitySharedCountsV1,
    COMMUNITY_ERASURE_TARGET_LINE_V1,
};
use pos_core::{ArtifactDataClassV1, AuthorityTrustRootSealV1, Hash};
use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;

use super::CommunityQuarantineResetCallV1;
use crate::community::erasure_budget::{
    CommunityErasureBudgetPortV1, CommunityPendingReservationV1,
};
use crate::community::pass_record::{
    CommunityPassRecordV1, CommunityPassStatusV1, CommunityReservedPassV1,
};
use crate::community::quarantine::{
    CommunityQuarantineReceiptV1, QuarantineLedgerV1, QuarantineReasonStateV1, RetainedControlV1,
};
use crate::community::{
    CommunityDomainBindingV1, CommunityPreExecutionTrustV1, CommunityQuarantineContextV1,
};
use crate::community_initialization_fixture::{
    hash, profile_until, target, Fallible, QuarantineCase, Revocation, Roster, ENTRIES, GENERATION,
    HORIZON, INSTALLED_CATALOGUE, NATIVE_PROFILE,
};
use crate::erasure_budget_rows::{community_rows, erasure_row};
use crate::plugin_trust_registry_fixtures::{release_one, Material};

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The ledger head the seeded quarantine holds.
const HEAD: Hash = Hash::from_bytes([0x93; 32]);

/// The control identity of the reset.
const CONTROL: [u8; 16] = [0x50; 16];

/// What one reset claims; each field may be varied.
#[derive(Clone)]
struct Claim {
    control: [u8; 16],
    ledger: Hash,
    reasons: Vec<Evidence>,
    generation: [u8; 16],
    head: Option<Hash>,
    tps1: Option<Hash>,
    principal: u32,
    deadline: u64,
}

/// The reasons the seeded ledger holds: a trap, then a revocation.
fn held() -> Vec<Evidence> {
    vec![
        Evidence {
            reason: Reason::Trapped,
            failure_evidence_digest: hash(0x94),
        },
        Evidence {
            reason: Reason::Revoked,
            failure_evidence_digest: hash(0x95),
        },
    ]
}

impl Claim {
    /// The claim that resets the seeded ledger.
    fn of_seeded() -> Self {
        Self {
            control: CONTROL,
            ledger: HEAD,
            reasons: held(),
            generation: GENERATION,
            head: None,
            tps1: None,
            principal: 7,
            deadline: HORIZON,
        }
    }

    fn with(mut self, change: impl FnOnce(&mut Self)) -> Self {
        change(&mut self);
        self
    }
}

/// The CQK1 digest of the first roster entry.
fn member_key(case: &QuarantineCase) -> Fallible<Hash> {
    Ok(CommunityQuarantineKeyV1::new(target(), ENTRIES[0], &case.roster.implementation)?.digest())
}

/// An initialized domain with the first member's ledger seeded: both
/// reasons, evidence that expired long ago, and the revocation's `F_q` share
/// spent.
fn seeded(revocation: Revocation) -> Fallible<QuarantineCase> {
    let mut case = QuarantineCase::new(&SEAL, revocation)?;
    let key = member_key(&case)?;
    let domain = &mut case.domain.world.domain;
    domain.quarantine_index.insert(
        key,
        QuarantineLedgerV1 {
            head: HEAD,
            ordinal: 3,
            reasons: held(),
            evidence_not_after_micros: 1,
            states: BTreeMap::from([
                (
                    Reason::Trapped.code(),
                    QuarantineReasonStateV1 {
                        evidence_not_after_micros: 1,
                        share_spent: false,
                    },
                ),
                (
                    Reason::Revoked.code(),
                    QuarantineReasonStateV1 {
                        evidence_not_after_micros: 1,
                        share_spent: true,
                    },
                ),
            ]),
        },
    );
    domain
        .erasure_contexts
        .entry(target())
        .or_default()
        .active_pairs = 3;
    Ok(case)
}

/// The reset of `claim` through the public entry.
fn reset(
    case: &mut QuarantineCase,
    claim: &Claim,
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    let rows = case.roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let (projection, policy) = release_and_policy(case)?;
    let trust = trust_of(
        (&case.domain.harness.env.anchor, &case.material),
        &projection,
    )?;
    let call = call_of((&case.roster, &case.material, case.head), claim, trust);
    let context = CommunityQuarantineContextV1 {
        profile: &profile,
        binding: CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        },
    };
    let world = &mut case.domain.world;
    Ok(world
        .domain
        .reset_quarantine(&SEAL, context, &world.authority, &call))
}

/// The member release's projection and the installed metadata policy.
fn release_and_policy(
    case: &QuarantineCase,
) -> Fallible<(
    ValidatedPluginManifestProjectionV1,
    CommunityMetadataPolicyV1,
)> {
    Ok((
        release_one().projection()?,
        CommunityMetadataPolicyV1::new(*case.domain.policy.as_input())?,
    ))
}

/// The trust evidence of the case's gate for the release `projection`.
fn trust_of<'a>(
    (anchor, material): (&'a PluginTrustPolicyAnchorV1, &'a Material),
    projection: &'a ValidatedPluginManifestProjectionV1,
) -> Fallible<CommunityPreExecutionTrustV1<'a>> {
    Ok(CommunityPreExecutionTrustV1 {
        anchor,
        tps1_bytes: &material.tps1,
        evidence: &material.evidence,
        projection,
        trusted_utc: material.trusted()?,
        tick: material.tick,
    })
}

/// The call of `claim` over `trust`.
fn call_of<'a>(
    (roster, material, head): (&'a Roster, &'a Material, Hash),
    claim: &'a Claim,
    trust: CommunityPreExecutionTrustV1<'a>,
) -> CommunityQuarantineResetCallV1<'a> {
    let retained = Hash::from_bytes(material.tps1_digest());
    CommunityQuarantineResetCallV1 {
        timeline: target(),
        stable_entry: ENTRIES[0],
        implementation: &roster.implementation,
        control_operation_id: claim.control,
        expected_ledger_digest: claim.ledger,
        expected_reasons: &claim.reasons,
        expected_generation: claim.generation,
        expected_state_head_digest: claim.head.unwrap_or(head),
        trust_snapshot_digest: claim.tps1.unwrap_or(retained),
        trust,
        principal_ref: ArtifactRefV1 {
            schema_id: claim.principal,
            byte_length: 10,
            digest: [0x51; 32],
        },
        authorization_ref: ArtifactRefV1 {
            schema_id: 8,
            byte_length: 11,
            digest: [0x52; 32],
        },
        authorization_not_after_micros: claim.deadline,
    }
}

/// The seeded ledger as the index holds it now.
fn ledger(case: &QuarantineCase) -> Fallible<&QuarantineLedgerV1> {
    Ok(case
        .domain
        .world
        .domain
        .quarantine_index
        .get(&member_key(case)?)
        .ok_or("no ledger")?)
}

/// The domain's active `(member, reason)` pairs.
fn active_pairs(case: &QuarantineCase) -> u64 {
    case.domain
        .world
        .domain
        .erasure_contexts
        .get(&target())
        .map_or(0, |context| context.active_pairs)
}

/// I209: with the evidence of both reasons long expired, a reset still
/// applies from the index alone. Its ledger and CQO1 carry the reset's own
/// metadata horizon, not the expired one, the active set is empty and the
/// retry index holds the reset.
#[test]
fn a_reset_applies_from_the_index_alone() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let inventory = case.domain.world.domain.inventory_generation;
    let receipt = reset(&mut case, &Claim::of_seeded())??;
    let current = ledger(&case)?;
    assert_eq!(current.head, receipt.selected_ledger_digest());
    assert_ne!(current.head, HEAD);
    assert_eq!(current.ordinal, 4);
    assert!(current.reasons.is_empty());
    assert!(current.states.is_empty());
    assert_eq!(current.evidence_not_after_micros, HORIZON);
    assert!(!receipt.already_quarantined);
    assert_eq!(receipt.timeline(), target());
    assert_eq!(receipt.control_operation_id(), CONTROL);
    let outcome = CommunityQuarantineOutcomeV1::from_canonical_cbor(receipt.outcome())?;
    let fields = outcome.as_input();
    assert!(matches!(
        fields.disposition,
        CommunityQuarantineDispositionV1::Applied
    ));
    assert_eq!(fields.prior_ledger_digest, Some(HEAD));
    assert_eq!(fields.selected_ledger_digest, current.head);
    assert_eq!(fields.control_request_digest, receipt.request_digest());
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    let domain = &case.domain.world.domain;
    assert!(domain
        .quarantine_controls
        .contains_key(&(target(), CONTROL)));
    assert_eq!(domain.inventory_generation, inventory + 1);
    assert!(domain
        .quarantine_controls
        .get(&(target(), CONTROL))
        .is_some_and(|retained| matches!(retained.kind, RetainedControlV1::Reset(_))));
    Ok(())
}

/// A reset of a ledger the earlier reset emptied is a new reset: it needs
/// the same premises, and it appends one more empty revision.
#[test]
fn a_reset_of_an_empty_ledger_appends_another_revision() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let first = reset(&mut case, &Claim::of_seeded())??;
    let again = Claim::of_seeded().with(|c| {
        c.control = [0x51; 16];
        c.ledger = first.selected_ledger_digest();
        c.reasons = Vec::new();
    });
    let second = reset(&mut case, &again)??;
    assert_ne!(
        second.selected_ledger_digest(),
        first.selected_ledger_digest()
    );
    assert_eq!(ledger(&case)?.ordinal, 5);
    assert!(ledger(&case)?.reasons.is_empty());
    assert_eq!(active_pairs(&case), 2);
    Ok(())
}

/// I214: a reset re-arms only the shares a pre-execution `SetReason` spent
/// (R15.3(6)). The seeded ledger holds both kinds of pair: the trap, as a
/// failure Abort activates it (no share spent), and the revocation, as a
/// pre-execution `SetReason` does (share spent). Exactly the revocation's
/// pair comes back; a ledger of Abort-activated pairs alone re-arms none.
#[test]
fn a_reset_re_arms_only_the_spent_shares() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    assert_eq!(active_pairs(&case), 3);
    reset(&mut case, &Claim::of_seeded())??;
    assert_eq!(active_pairs(&case), 2);
    let mut unspent = seeded(Revocation::None)?;
    let key = member_key(&unspent)?;
    for state in unspent
        .domain
        .world
        .domain
        .quarantine_index
        .get_mut(&key)
        .ok_or("no ledger")?
        .states
        .values_mut()
    {
        state.share_spent = false;
    }
    reset(&mut unspent, &Claim::of_seeded())??;
    assert_eq!(active_pairs(&unspent), 3);
    Ok(())
}

/// An identical retry returns the original receipt and changes nothing;
/// every other bound field conflicts.
#[test]
fn a_retry_returns_the_original_or_conflicts() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let receipt = reset(&mut case, &Claim::of_seeded())??;
    let head = ledger(&case)?.head;
    assert_eq!(reset(&mut case, &Claim::of_seeded())??, receipt);
    assert_eq!(ledger(&case)?.head, head);
    assert_eq!(active_pairs(&case), 2);
    for changed in [
        Claim::of_seeded().with(|c| c.ledger = hash(0x70)),
        Claim::of_seeded().with(|c| {
            c.reasons.pop();
        }),
        Claim::of_seeded().with(|c| c.generation = [0x21; 16]),
        Claim::of_seeded().with(|c| c.head = Some(hash(0x72))),
        Claim::of_seeded().with(|c| c.tps1 = Some(hash(0x73))),
        Claim::of_seeded().with(|c| c.principal = 9),
        Claim::of_seeded().with(|c| c.deadline += 1),
    ] {
        assert_eq!(reset(&mut case, &changed)?.err(), Some(Error::Conflict));
    }
    assert_eq!(ledger(&case)?.head, head);
    Ok(())
}

/// The premises, each refused with its code and nothing changed: another
/// ledger digest or reason set (4), another generation (5) and head (6),
/// another TPS1 digest (12), no index row (12).
#[test]
fn a_premise_that_does_not_hold_refuses_the_reset() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let refused: [(Claim, Error); 8] = [
        (
            Claim::of_seeded().with(|c| c.ledger = hash(0x70)),
            Error::Conflict,
        ),
        (
            Claim::of_seeded().with(|c| {
                c.reasons.pop();
            }),
            Error::Conflict,
        ),
        (
            Claim::of_seeded().with(|c| c.reasons[1].failure_evidence_digest = hash(0x71)),
            Error::Conflict,
        ),
        (
            Claim::of_seeded().with(|c| c.reasons[0].reason = Reason::Unavailable),
            Error::Conflict,
        ),
        (
            Claim::of_seeded().with(|c| c.reasons.push(c.reasons[1])),
            Error::Conflict,
        ),
        (
            Claim::of_seeded().with(|c| c.generation = [0x21; 16]),
            Error::StaleGeneration,
        ),
        (
            Claim::of_seeded().with(|c| c.head = Some(hash(0x72))),
            Error::StaleFrontier,
        ),
        (
            Claim::of_seeded().with(|c| c.tps1 = Some(hash(0x73))),
            Error::EvidenceUnavailable,
        ),
    ];
    for (claim, error) in refused {
        assert_eq!(reset(&mut case, &claim)?.err(), Some(error));
        assert_eq!(ledger(&case)?.head, HEAD);
        assert_eq!(active_pairs(&case), 3);
        assert!(case.domain.world.domain.quarantine_controls.is_empty());
    }
    case.domain.world.domain.quarantine_index.clear();
    assert_eq!(
        reset(&mut case, &Claim::of_seeded())?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A reset needs no unresolved pass of T (7).
#[test]
fn an_unresolved_pass_refuses_the_reset() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let pass = unresolved_pass(case.head)?;
    case.domain
        .world
        .domain
        .pass_records
        .insert((target(), [9; 16]), pass);
    assert_eq!(
        reset(&mut case, &Claim::of_seeded())?.err(),
        Some(Error::PassUnresolved)
    );
    assert_eq!(ledger(&case)?.head, HEAD);
    Ok(())
}

/// A reset cannot override Revoked while the trust source still denies the
/// release (12), and the quarantine stays.
#[test]
fn a_reset_cannot_override_a_revoked_release() -> TestResult {
    let mut case = seeded(Revocation::Artifact)?;
    assert_eq!(
        reset(&mut case, &Claim::of_seeded())?.err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(ledger(&case)?.head, HEAD);
    assert_eq!(active_pairs(&case), 3);
    Ok(())
}

/// A pass of T that no terminal record resolved.
fn unresolved_pass(head: Hash) -> Fallible<CommunityPassRecordV1> {
    Ok(CommunityPassRecordV1 {
        reserved: CommunityReservedPassV1 {
            reservation: CommunityReservationInputV1 {
                pass_key: CommunityPassKeyV1::new(target(), GENERATION, 7)?,
                request_digest: hash(80),
                native_producer_ordinal: 5,
                predecessor_head_digest: head,
                roster_digest: hash(81),
                prepared_input_set_digest: hash(82),
                profile_digest: hash(83),
                evidence_not_after_micros: HORIZON,
            },
            cbq1_digest: hash(84),
            quote_maxima: [1, 2, 3],
            trace_rows: 2,
            members: Vec::new(),
            metadata_key: [0x61; 16],
            failure_cohort_key: [0x62; 16],
            generation_horizon_micros: HORIZON,
            outcome_horizon_micros: HORIZON,
        },
        prior_shared_counts: CommunitySharedCountsV1 {
            nodes: 0,
            edges: 0,
            declared_inputs: 0,
            encoded_record_bytes: 0,
        },
        materialization: None,
        status: CommunityPassStatusV1::Reserved,
        sealed_result_digest: None,
        live: false,
    })
}

/// What a refused reset leaves alone: the ledger head and ordinal, the
/// active pairs, the retained controls, the inventory generation and the
/// pending ledger.
fn untouched(case: &QuarantineCase) -> Fallible<(Hash, u64, u64, usize, u64, usize)> {
    let domain = &case.domain.world.domain;
    Ok((
        ledger(case)?.head,
        ledger(case)?.ordinal,
        active_pairs(case),
        domain.quarantine_controls.len(),
        domain.inventory_generation,
        domain.pending_reservations.len(),
    ))
}

/// The seeded domain with the first member's context of three members, so
/// `F_q` is 24 targets less the three active pairs' 6.
fn contextual() -> Fallible<QuarantineCase> {
    let mut case = seeded(Revocation::None)?;
    assert_eq!(active_pairs(&case), 3);
    case.domain
        .world
        .domain
        .erasure_contexts
        .entry(target())
        .or_default()
        .members = 3;
    Ok(case)
}

/// The reset of the seeded claim: applied, or the refusal and what it left.
fn reset_or_refused(mut case: QuarantineCase, applied: bool) -> TestResult {
    let before = untouched(&case)?;
    let result = reset(&mut case, &Claim::of_seeded())?;
    if applied {
        result?;
        assert_eq!(active_pairs(&case), 2);
        assert!(ledger(&case)?.reasons.is_empty());
    } else {
        assert_eq!(result.err(), Some(Error::CapacityExhausted));
        assert_eq!(untouched(&case)?, before);
        assert_eq!(ledger(&case)?.reasons.len(), 2);
    }
    Ok(())
}

/// R13.1(3), I136: a reset re-arms the spent `F_q` share (two targets and a
/// row), which must fit the actor's budget like any reserve. With T's actor
/// exactly at the community line after the re-arm the reset applies; one
/// target more pending gives 14, keeps the quarantine and changes nothing.
#[test]
fn a_reset_that_cannot_re_arm_its_reserve_gives_14() -> TestResult {
    for (extra, applied) in [(0, true), (1, false)] {
        let mut case = contextual()?;
        let domain = &mut case.domain.world.domain;
        let base = domain
            .erasure_budget(target())?
            .actors
            .iter()
            .map(|actor| actor.targets)
            .max()
            .ok_or("an actor")?;
        let free = COMMUNITY_ERASURE_TARGET_LINE_V1 - base - (24 - 6) - 2;
        domain
            .store
            .bind_erasure_rows_for_test(target(), community_rows(1_000, free / 2)?);
        // Pending targets take the rest of the line, and `extra` one more.
        domain.pending_reservations.insert(
            (target(), [9; 16]),
            CommunityPendingReservationV1 {
                targets: free % 2 + extra,
                rows: 0,
            },
        );
        reset_or_refused(case, applied)?;
    }
    Ok(())
}

/// The same on the rows side: consented rows cost no targets, so only T's
/// 4,096-row bound can refuse. The re-arm adds one row to T's `F_q` rows
/// (nine held, ten after), so T's committed rows of 4,086 reset and 4,087
/// give 14.
#[test]
fn a_reset_that_cannot_re_arm_its_rows_gives_14() -> TestResult {
    for (committed, applied) in [(4_086_u64, true), (4_087, false)] {
        let mut case = contextual()?;
        let domain = &mut case.domain.world.domain;
        let held = domain
            .erasure_budget(target())?
            .rows
            .get(&target())
            .copied()
            .ok_or("rows of T")?;
        let consented = (0..committed - held)
            .map(|seed| erasure_row("budget", ArtifactDataClassV1::ConsentedSharedData, 0, seed))
            .collect::<Fallible<Vec<_>>>()?;
        domain.store.bind_erasure_rows_for_test(target(), consented);
        reset_or_refused(case, applied)?;
    }
    Ok(())
}

/// R13.1(3): the reserve a reset re-arms is two targets per spent share. With
/// both reasons' shares spent it is four targets: exactly at the line the
/// reset applies, one target more pending gives 14 and changes nothing.
#[test]
fn a_reset_re_arms_two_targets_per_spent_share() -> TestResult {
    for (extra, applied) in [(0, true), (1, false)] {
        let mut case = contextual()?;
        let key = member_key(&case)?;
        let domain = &mut case.domain.world.domain;
        for state in domain
            .quarantine_index
            .get_mut(&key)
            .ok_or("no ledger")?
            .states
            .values_mut()
        {
            state.share_spent = true;
        }
        let base = domain
            .erasure_budget(target())?
            .actors
            .iter()
            .map(|actor| actor.targets)
            .max()
            .ok_or("an actor")?;
        let free = COMMUNITY_ERASURE_TARGET_LINE_V1 - base - (24 - 6) - 4;
        domain
            .store
            .bind_erasure_rows_for_test(target(), community_rows(1_000, free / 2)?);
        domain.pending_reservations.insert(
            (target(), [9; 16]),
            CommunityPendingReservationV1 {
                targets: free % 2 + extra,
                rows: 0,
            },
        );
        let before = untouched(&case)?;
        let result = reset(&mut case, &Claim::of_seeded())?;
        if applied {
            result?;
            assert_eq!(active_pairs(&case), 1);
        } else {
            assert_eq!(result.err(), Some(Error::CapacityExhausted));
            assert_eq!(untouched(&case)?, before);
        }
    }
    Ok(())
}

/// R13.1(3): a reset that re-arms no share holds nothing more, so even an
/// actor already past the line is never refused for the budget.
#[test]
fn a_reset_that_re_arms_nothing_is_never_refused_for_the_budget() -> TestResult {
    let mut case = contextual()?;
    let key = member_key(&case)?;
    let domain = &mut case.domain.world.domain;
    for state in domain
        .quarantine_index
        .get_mut(&key)
        .ok_or("no ledger")?
        .states
        .values_mut()
    {
        state.share_spent = false;
    }
    domain.pending_reservations.insert(
        (target(), [9; 16]),
        CommunityPendingReservationV1 {
            targets: COMMUNITY_ERASURE_TARGET_LINE_V1 + 1,
            rows: 0,
        },
    );
    reset(&mut case, &Claim::of_seeded())??;
    assert_eq!(active_pairs(&case), 3);
    Ok(())
}
