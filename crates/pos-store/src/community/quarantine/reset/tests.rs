//! The reset core (I208's reset bullet, I209, I214): its refusals in order,
//! the successor ledger it commits and the shares it re-arms, with the
//! evidence of the reasons it clears already expired.

use std::collections::BTreeMap;
use std::time::Duration;

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyV1, CommunityPassKeyV1,
    CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1, CommunityQuarantineOutcomeV1,
    CommunityQuarantineReasonEvidenceV1 as Evidence, CommunityQuarantineReasonV1 as Reason,
    CommunityReservationInputV1, CommunitySharedCountsV1, COMMUNITY_ERASURE_TARGET_LINE_V1,
};
use pos_core::{ArtifactDataClassV1, AuthorityTrustRootSealV1, Hash};
use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;

use super::{
    CommunityQuarantineResetCallV1, CommunityResetTrustEvidenceV1, ResetPreparedV1, StagedResetV1,
};
use crate::community::erasure_budget::{
    CommunityErasureBudgetPortV1, CommunityPendingReservationV1,
};
use crate::community::lifecycle_authority::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1,
};
use crate::community::pass_record::{
    CommunityPassRecordV1, CommunityPassStatusV1, CommunityReservedPassV1,
};
use crate::community::quarantine::{
    CommunityQuarantineReceiptV1, QuarantineLedgerV1, QuarantineReasonStateV1, RetainedControlV1,
};
use crate::community::{
    CommunityDomainBindingV1, CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityV1,
    CommunityQuarantineContextV1, MemoryCommunityDomainV1,
};
use crate::community_initialization_fixture::{
    hash, metadata_authority_until, metadata_registry_until, profile_until, target, Fallible,
    QuarantineCase, Revocation, DATA_LEAF, ENTRIES, EXPIRES, GENERATION, HORIZON,
    INSTALLED_CATALOGUE, METADATA_LEAF, NATIVE_PROFILE, NOW,
};
use crate::erasure_budget_rows::{community_rows, erasure_row};
#[cfg(target_os = "linux")]
use crate::plugin_trust_registry::PluginTrustPolicyRegistryV1;
use crate::plugin_trust_registry_fixtures::{release_one, spec, tps_after, Material, Spec};

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
}

/// What one reset call varies besides its claim: the administrative leaf,
/// the FAE1 expiry and whether the trust histories are the member's.
#[derive(Clone)]
struct Setup {
    leaf: Hash,
    expires: u64,
    histories: bool,
    /// The metadata authority's leaf grant the policy names, if not the
    /// installed one.
    metadata_leaf: Option<Hash>,
}

impl Setup {
    /// The call of the reset grant's holder with the member's histories.
    const fn standard() -> Self {
        Self {
            leaf: DATA_LEAF,
            expires: EXPIRES,
            histories: true,
            metadata_leaf: None,
        }
    }

    fn with(mut self, change: impl FnOnce(&mut Self)) -> Self {
        change(&mut self);
        self
    }
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
/// spent. The registry is evaluated at UTC second 0 and Tick 0, the
/// coordinates a reset evaluates at under the fixture's wall.
fn seeded(revocation: Revocation) -> Fallible<QuarantineCase> {
    let mut case = QuarantineCase::at(&SEAL, (revocation, true))?;
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

/// The FAE1 of `claim`'s reset, or none for a control identity the request
/// derivation refuses.
fn credential(case: &QuarantineCase, claim: &Claim, setup: &Setup) -> Fallible<Vec<u8>> {
    Ok(CommunityAdministrativeRequestV1::derive(
        &CommunityAdministrativeOperationV1::QuarantineReset {
            timeline: target(),
            control_operation_id: claim.control,
        },
    )
    .ok()
    .map(|request| case.domain.world.credential_until(request, setup.expires))
    .transpose()?
    .unwrap_or_default())
}

/// The metadata policy the call names: the installed one, or with the
/// leaf grant `setup` replaces.
fn metadata_policy(case: &QuarantineCase, setup: &Setup) -> Fallible<CommunityMetadataPolicyV1> {
    let mut input = *case.domain.policy.as_input();
    if let Some(leaf) = setup.metadata_leaf {
        input.metadata_authority_leaf_grant = leaf;
    }
    Ok(CommunityMetadataPolicyV1::new(input)?)
}

/// The trust histories `setup` presents: the member's, or none.
fn histories<'a>(material: &'a Material, setup: &Setup) -> (Vec<&'a [u8]>, Vec<&'a [u8]>) {
    if setup.histories {
        material.histories()
    } else {
        (Vec::new(), Vec::new())
    }
}

/// The FAE1 and the manifest projection of the reset call.
fn call_evidence(
    case: &QuarantineCase,
    claim: &Claim,
    setup: &Setup,
) -> Fallible<(Vec<u8>, ValidatedPluginManifestProjectionV1)> {
    Ok((credential(case, claim, setup)?, release_one().projection()?))
}

/// Run `run` with the installed composition and the call of `claim` under
/// `setup`.
fn with_call<T>(
    case: &mut QuarantineCase,
    claim: &Claim,
    setup: &Setup,
    run: impl FnOnce(
        &mut MemoryCommunityDomainV1,
        CommunityQuarantineContextV1<'_>,
        &mut CommunityLifecycleAuthorityV1,
        &mut CommunityMetadataAuthorityV1,
        &CommunityQuarantineResetCallV1<'_>,
    ) -> T,
) -> Fallible<T> {
    let rows = case.roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let policy = metadata_policy(case, setup)?;
    let (credential, projection) = call_evidence(case, claim, setup)?;
    let (ptr1, prv1) = histories(&case.material, setup);
    let call = CommunityQuarantineResetCallV1 {
        credential: &credential,
        administrative_leaf: setup.leaf,
        timeline: target(),
        stable_entry: ENTRIES[0],
        implementation: &case.roster.implementation,
        control_operation_id: claim.control,
        expected_ledger_digest: claim.ledger,
        expected_reasons: &claim.reasons,
        expected_generation: claim.generation,
        expected_state_head_digest: claim.head.unwrap_or(case.head),
        trust_evidence: CommunityResetTrustEvidenceV1 {
            ptr1_histories: &ptr1,
            prv1_histories: &prv1,
            projection: &projection,
        },
    };
    let context = CommunityQuarantineContextV1 {
        profile: &profile,
        binding: CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        },
    };
    let world = &mut case.domain.world;
    Ok(run(
        &mut world.domain,
        context,
        &mut world.authority,
        &mut case.domain.metadata,
        &call,
    ))
}

/// The reset of `claim` through the public entry.
fn reset(
    case: &mut QuarantineCase,
    claim: &Claim,
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    reset_with(case, claim, &Setup::standard())
}

/// The reset of `claim` through the public entry under `setup`.
fn reset_with(
    case: &mut QuarantineCase,
    claim: &Claim,
    setup: &Setup,
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    with_call(
        case,
        claim,
        setup,
        |domain, context, authority, metadata, call| {
            domain.reset_quarantine(&SEAL, context, authority, metadata, call)
        },
    )
}

/// Every step before the writer, whose staged commit is returned.
fn staged(case: &mut QuarantineCase, setup: &Setup) -> Fallible<StagedResetV1> {
    with_call(
        case,
        &Claim::of_seeded(),
        setup,
        |domain, context, authority, metadata, call| match domain
            .prepare_reset(context, authority, metadata, call)?
        {
            ResetPreparedV1::Staged(staged, _) => Ok(*staged),
            ResetPreparedV1::Original(_) => Err(Error::InvalidBinding),
        },
    )?
    .map_err(Into::into)
}

/// The reset of the seeded claim, with `seam` run on the domain and the
/// staged reset after `prepare_reset` (every step before the writer) and
/// before `commit_reset` (the writer).
fn reset_between(
    case: &mut QuarantineCase,
    seam: impl FnOnce(&mut MemoryCommunityDomainV1, &mut StagedResetV1),
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    with_call(
        case,
        &Claim::of_seeded(),
        &Setup::standard(),
        |domain, context, authority, metadata, call| match domain
            .prepare_reset(context, authority, metadata, call)?
        {
            ResetPreparedV1::Staged(mut staged, authenticated) => {
                seam(domain, &mut staged);
                domain.commit_reset(context, authority, metadata, (*staged, authenticated))
            }
            ResetPreparedV1::Original(receipt) => Ok(receipt),
        },
    )
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
    ] {
        assert_eq!(reset(&mut case, &changed)?.err(), Some(Error::Conflict));
    }
    assert_eq!(ledger(&case)?.head, head);
    Ok(())
}

/// I239: a retry is answered before the trust evaluation, so it returns the
/// original receipt although its evidence no longer verifies. Another
/// principal (the retained leaf's grantee is not the decision's) gives 4,
/// and a caller without the grant gets 12.
#[test]
fn a_retry_is_answered_from_the_retained_reset_and_its_principal() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let receipt = reset(&mut case, &Claim::of_seeded())??;
    let blind = Setup::standard().with(|s| s.histories = false);
    assert_eq!(
        reset_with(&mut case, &Claim::of_seeded(), &blind)??,
        receipt
    );
    let outsider = Setup::standard().with(|s| s.leaf = hash(0x7f));
    assert_eq!(
        reset_with(&mut case, &Claim::of_seeded(), &outsider)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let retained = case
        .domain
        .world
        .domain
        .quarantine_controls
        .get_mut(&(target(), CONTROL))
        .ok_or("no retained reset")?;
    let RetainedControlV1::Reset(held) = &mut retained.kind else {
        return Err("not a reset".into());
    };
    held.leaf_grant_id = METADATA_LEAF;
    assert_eq!(
        reset(&mut case, &Claim::of_seeded())?.err(),
        Some(Error::Conflict)
    );
    Ok(())
}

/// R9.7, I245: a control identity that is a committed materialization's
/// `M_id` of T gives 4 before any premise, and nothing changes.
#[test]
fn a_materialization_identity_conflicts() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    case.domain
        .world
        .domain
        .materialization_ids
        .insert((target(), CONTROL));
    assert_eq!(
        reset(&mut case, &Claim::of_seeded())?.err(),
        Some(Error::Conflict)
    );
    assert_eq!(ledger(&case)?.head, HEAD);
    assert!(case.domain.world.domain.quarantine_controls.is_empty());
    Ok(())
}

/// The premises, each refused with its code and nothing changed: another
/// ledger digest or reason set (4), a reason set that is not valid (3: more
/// than four, codes not strictly ascending, a zero evidence digest),
/// another generation (5) and head (6), no index row (12).
#[test]
fn a_premise_that_does_not_hold_refuses_the_reset() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let refused: [(Claim, Error); 9] = [
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
            Error::InvalidBinding,
        ),
        (
            Claim::of_seeded().with(|c| c.reasons.push(c.reasons[1])),
            Error::InvalidBinding,
        ),
        (
            Claim::of_seeded().with(|c| {
                c.reasons = vec![
                    c.reasons[0],
                    c.reasons[1],
                    Evidence {
                        reason: Reason::Unavailable,
                        failure_evidence_digest: hash(0x96),
                    },
                    Evidence {
                        reason: Reason::Unavailable,
                        failure_evidence_digest: hash(0x97),
                    },
                    Evidence {
                        reason: Reason::Unavailable,
                        failure_evidence_digest: hash(0x98),
                    },
                ];
            }),
            Error::InvalidBinding,
        ),
        (
            Claim::of_seeded().with(|c| c.reasons[0].failure_evidence_digest = hash(0)),
            Error::InvalidBinding,
        ),
        (
            Claim::of_seeded().with(|c| c.generation = [0x21; 16]),
            Error::StaleGeneration,
        ),
        (
            Claim::of_seeded().with(|c| c.head = Some(hash(0x72))),
            Error::StaleFrontier,
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

/// I237: a caller without the reset grant gets 12 whatever the premise:
/// an existing control identity, an absent one, a CQK1 with no index row
/// and a T with an unresolved pass. It learns nothing about the state.
#[test]
fn a_caller_without_the_grant_gets_12_for_every_premise() -> TestResult {
    let outsider = Setup::standard().with(|s| s.leaf = hash(0x7f));
    let mut case = seeded(Revocation::None)?;
    reset(&mut case, &Claim::of_seeded())??;
    let existing = Claim::of_seeded();
    let absent = Claim::of_seeded().with(|c| c.control = [0x51; 16]);
    for claim in [&existing, &absent] {
        assert_eq!(
            reset_with(&mut case, claim, &outsider)?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    case.domain.world.domain.quarantine_index.clear();
    assert_eq!(
        reset_with(&mut case, &absent, &outsider)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let mut busy = seeded(Revocation::None)?;
    let pass = unresolved_pass(busy.head)?;
    busy.domain
        .world
        .domain
        .pass_records
        .insert((target(), [9; 16]), pass);
    assert_eq!(
        reset_with(&mut busy, &Claim::of_seeded(), &outsider)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A zero control identity is a shape refusal (3) before any authority; a
/// credential that does not verify, or expired at the sample, gives 12.
#[test]
fn the_shape_precedes_the_authority_and_a_bad_credential_gives_12() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let zero = Claim::of_seeded().with(|c| c.control = [0; 16]);
    assert_eq!(reset(&mut case, &zero)?.err(), Some(Error::InvalidBinding));
    let expired = Setup::standard().with(|s| s.expires = 400);
    assert_eq!(
        reset_with(&mut case, &Claim::of_seeded(), &expired)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(ledger(&case)?.head, HEAD);
    Ok(())
}

/// I238: the host derives the refs from the administrative decision, the
/// deadline `B` as the earlier of the decision bound, the FAE1 expiry and the
/// metadata owner's expiry, and the TPS1 digest the registry retains.
#[test]
fn the_host_derives_the_refs_the_deadline_and_the_trust_snapshot() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let request = CommunityAdministrativeRequestV1::derive(
        &CommunityAdministrativeOperationV1::QuarantineReset {
            timeline: target(),
            control_operation_id: CONTROL,
        },
    )?;
    let (_, admission) = case.domain.world.call_and_admit(request, DATA_LEAF)?;
    let ready = staged(&mut case, &Setup::standard())?;
    assert_eq!(ready.authority.leaf_grant_id, DATA_LEAF);
    assert_eq!(ready.authority.principal_ref, admission.principal_ref());
    assert_eq!(
        ready.authority.authorization_ref,
        admission.authorization_ref()
    );
    assert_eq!(ready.authority.bound_micros, EXPIRES);
    assert_eq!(
        ready.premises.trust_snapshot_digest,
        Hash::from_bytes(case.material.tps1_digest())
    );
    let short = Setup::standard().with(|s| s.expires = 10_000_000);
    assert_eq!(
        staged(&mut case, &short)?.authority.bound_micros,
        10_000_000
    );
    Ok(())
}

/// Evidence the registry cannot verify at the host's coordinates gives 12,
/// and the quarantine stays.
#[test]
fn histories_that_do_not_verify_refuse_the_reset() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let blind = Setup::standard().with(|s| s.histories = false);
    assert_eq!(
        reset_with(&mut case, &Claim::of_seeded(), &blind)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(ledger(&case)?.head, HEAD);
    Ok(())
}

/// I241: the writer refuses (12) when the inventory generation or the CSI1
/// the operation read moved, and writes nothing.
#[test]
fn a_moved_inventory_generation_or_selection_refuses_the_writer() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let before = untouched(&case)?;
    let result = reset_between(&mut case, |domain, _| domain.inventory_generation += 1)?;
    assert_eq!(result.err(), Some(Error::EvidenceUnavailable));
    assert_eq!(untouched(&case)?.0, before.0);
    let result = reset_between(&mut case, |domain, _| {
        if let Some((_, sealed)) = domain.selection.as_mut() {
            sealed.address = hash(0x99);
        } else if let Some(record) = domain.bootstrap.as_mut() {
            record.selection.address = hash(0x99);
        }
    })?;
    assert_eq!(result.err(), Some(Error::EvidenceUnavailable));
    assert_eq!(untouched(&case)?.0, before.0);
    assert!(case.domain.world.domain.quarantine_controls.is_empty());
    Ok(())
}

/// The writer refuses (12) at and after the deadline `B`, which is the FAE1
/// expiry here, and the quarantine stays; one microsecond before it commits.
/// Every case reads all five scripted marks (the reservation's two, the
/// guard's two and the writer's elapsed mark), so the offset on the fifth is
/// the writer's elapsed time.
#[test]
fn the_writer_refuses_at_and_after_the_deadline() -> TestResult {
    let bound = EXPIRES - NOW;
    for (offset, refused) in [(bound - 1, false), (bound, true), (bound + 1_000, true)] {
        let mut case = seeded(Revocation::None)?;
        let zero = Duration::ZERO;
        let marks = |case: &QuarantineCase| {
            case.domain
                .mono
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .samples_taken()
        };
        let setup = marks(&case);
        case.domain
            .script_mono(&[zero, zero, zero, zero, Duration::from_micros(offset)]);
        let result = reset(&mut case, &Claim::of_seeded())?;
        assert_eq!(marks(&case) - setup, 5);
        if refused {
            assert_eq!(result.err(), Some(Error::EvidenceUnavailable));
            assert_eq!(ledger(&case)?.head, HEAD);
            assert!(case.domain.world.domain.quarantine_controls.is_empty());
        } else {
            result?;
            assert_ne!(ledger(&case)?.head, HEAD);
        }
    }
    Ok(())
}

/// I238: the metadata owner's expiry lowers `B` when it is the earliest.
#[test]
fn the_metadata_owners_expiry_lowers_the_deadline() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    case.domain.metadata = metadata_authority_until(
        &SEAL,
        metadata_registry_until(&SEAL, 20_000_000)?,
        (64, 20_000_000),
    )?;
    assert_eq!(
        staged(&mut case, &Setup::standard())?
            .authority
            .bound_micros,
        20_000_000
    );
    Ok(())
}

/// A denied metadata `write` decision gives 12 before the retry lookup,
/// even for a retry the original receipt would answer.
#[test]
fn a_denied_metadata_write_refuses_every_reset() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    reset(&mut case, &Claim::of_seeded())??;
    let denied = Setup::standard().with(|s| s.metadata_leaf = Some(hash(0x7e)));
    for claim in [
        Claim::of_seeded(),
        Claim::of_seeded().with(|c| c.control = [0x51; 16]),
    ] {
        assert_eq!(
            reset_with(&mut case, &claim, &denied)?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// I241b: any of the evaluated decisions or the TPS1 digest that differs at
/// the writer gives 12 and writes nothing.
#[test]
fn a_decision_that_differs_at_the_writer_refuses_it() -> TestResult {
    type Tamper = fn(&mut StagedResetV1);
    // The leaf grant is also the locator of the second evaluation, so another
    // leaf is refused by that evaluation itself before the comparison.
    let tampers: [Tamper; 4] = [
        |staged| staged.authority.leaf_grant_id = METADATA_LEAF,
        |staged| staged.authority.authorization_ref.digest[0] ^= 1,
        |staged| staged.authority.metadata.2.push(hash(1)),
        |staged| staged.premises.trust_snapshot_digest = hash(0x55),
    ];
    for tamper in tampers {
        let mut case = seeded(Revocation::None)?;
        let before = untouched(&case)?;
        let result = reset_between(&mut case, |_, staged| tamper(staged))?;
        assert_eq!(result.err(), Some(Error::EvidenceUnavailable));
        assert_eq!(untouched(&case)?, before);
    }
    Ok(())
}

/// A writer past the deadline with a changed decision refuses too, and writes
/// nothing. Both refusals are 12, so which one is judged first cannot be
/// observed; the bound check consumes the call and is judged first.
#[test]
fn a_late_writer_with_a_changed_decision_refuses() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let zero = Duration::ZERO;
    let late = Duration::from_micros(EXPIRES - NOW);
    case.domain.script_mono(&[zero, zero, zero, zero, late]);
    let before = untouched(&case)?;
    let result = reset_between(&mut case, |_, staged| {
        staged.premises.trust_snapshot_digest = hash(0x55);
    })?;
    assert_eq!(result.err(), Some(Error::EvidenceUnavailable));
    assert_eq!(untouched(&case)?, before);
    Ok(())
}

/// I241b: a TPS1 the registry adopts between the evaluation and the writer
/// gives 12 and writes nothing.
#[test]
fn a_changed_trust_snapshot_refuses_the_writer() -> TestResult {
    let mut case = seeded(Revocation::None)?;
    let newer = case.domain.harness.env.material(
        &Spec {
            revocation_tick: 0,
            ..spec(2, 2).at(0, 0)
        },
        &tps_after(&case.material),
    )?;
    assert_ne!(newer.tps1_digest(), case.material.tps1_digest());
    let anchor = case.domain.harness.env.anchor.clone();
    let trusted = newer.trusted()?;
    let before = untouched(&case)?;
    let result = reset_between(&mut case, |domain, _| {
        let advanced = PluginTrustPolicyRegistryV1::advance_policy(
            &mut domain.store,
            &anchor,
            &newer.tps1,
            &newer.evidence,
            trusted,
            newer.tick,
        );
        assert!(advanced.is_ok());
    })?;
    assert_eq!(result.err(), Some(Error::EvidenceUnavailable));
    assert_eq!(untouched(&case)?, before);
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

/// The reset applied: two active pairs stay and no reason is left.
fn assert_applied(
    case: &QuarantineCase,
    result: Result<CommunityQuarantineReceiptV1, Error>,
) -> TestResult {
    result?;
    assert_eq!(active_pairs(case), 2);
    let ledger = ledger(case)?;
    assert!(ledger.reasons.is_empty());
    Ok(())
}

/// The reset refused with 14 and left what `before` held.
fn assert_refused(
    case: &QuarantineCase,
    result: Result<CommunityQuarantineReceiptV1, Error>,
    before: (Hash, u64, u64, usize, u64, usize),
) -> TestResult {
    assert_eq!(result.err(), Some(Error::CapacityExhausted));
    let now = untouched(case)?;
    assert_eq!(now, before);
    let ledger = ledger(case)?;
    assert_eq!(ledger.reasons.len(), 2);
    Ok(())
}

/// The reset of the seeded claim: applied, or the refusal and what it left.
fn reset_or_refused(mut case: QuarantineCase, applied: bool) -> TestResult {
    let before = untouched(&case)?;
    let result = reset(&mut case, &Claim::of_seeded())?;
    if applied {
        assert_applied(&case, result)
    } else {
        assert_refused(&case, result, before)
    }
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
