//! The committed state of a `SetReason` that the domain exposes to no
//! caller (I65, I67, I71): the sealed records and their CAU1, the CFO1's
//! ARD1, the keys and inventory generation, the quarantine index and the
//! set union, and the commit's compare-and-swap and the retry's evidence
//! checks.

use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, CommunityArtifactOperationV1, CommunityAuthorityEvidenceV1,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationV1, CommunityProducerBindingV1,
    CommunityQuarantineDispositionV1 as Disposition, CommunityQuarantineKeyV1,
    CommunityQuarantineReasonEvidenceV1 as Evidence, CommunityQuarantineReasonV1 as Reason,
    CommunityQuarantineRevisionV1, RevocationBasisV1 as Basis,
};
use pos_core::{
    ArtifactOptionalityV1, ArtifactRegistrationPersistencePortV1, ArtifactTransitionRuleV1,
    AuthorityTrustRootSealV1, ErasureArtifactClassV1,
};

use super::{
    CommunityQuarantineReceiptV1, QuarantineLedgerV1, SetReasonPreparedV1, StagedSetReasonV1,
};
use crate::community::MemoryCommunityDomainV1;
use crate::community_initialization_fixture::{
    claim, hash, initial_head, initialize_target, profile_until, profile_with_quarantine, target,
    with_set_reason, Bootstrapped, Claim, Fallible, QuarantineCase, Revocation, Roster, CONTROL,
    ENTRIES, EXPIRES, GENERATION, HORIZON, METADATA_LEAF,
};
use crate::memory::MemoryStore;
use crate::plugin_trust_registry_fixtures::{release_one, ManifestSpec};
use crate::MemoryTrustedClockAuthorityV1;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The staged commit of a new `SetReason` for `claim` under the default
/// profile.
fn staged(case: &mut QuarantineCase, claim: Claim<'_>) -> Fallible<StagedSetReasonV1> {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let prepared = with_set_reason(
        &SEAL,
        case,
        &profile,
        &release_one(),
        claim,
        |world, metadata, context, call| {
            world
                .domain
                .prepare_set_reason(&SEAL, context, &mut world.authority, metadata, call)
        },
    )??;
    match prepared {
        SetReasonPreparedV1::Staged(staged, _, _) => Ok(*staged),
        SetReasonPreparedV1::Original(_) => Err("expected a new SetReason".into()),
    }
}

/// The full `SetReason` through the public entry.
fn set_reason(
    case: &mut QuarantineCase,
    claim: Claim<'_>,
) -> Fallible<Result<CommunityQuarantineReceiptV1, Error>> {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    with_set_reason(
        &SEAL,
        case,
        &profile,
        &release_one(),
        claim,
        |world, metadata, context, call| {
            world
                .domain
                .set_quarantine_reason(&SEAL, context, &mut world.authority, metadata, call)
        },
    )
}

const fn domain(case: &QuarantineCase) -> &MemoryCommunityDomainV1 {
    &case.domain.world.domain
}

/// The plaintext of each sealed record of the `SetReason` `control`.
fn records(case: &QuarantineCase, control: [u8; 16]) -> Fallible<Vec<Vec<u8>>> {
    let domain = domain(case);
    let committed = domain
        .quarantine_controls
        .get(&(target(), control))
        .ok_or("no committed SetReason")?;
    let key = domain
        .keys
        .get(&committed.metadata_key)
        .ok_or("no metadata key")?;
    Ok(committed
        .records
        .iter()
        .map(|sealed| key.open(sealed).map(|bytes| bytes.to_vec()))
        .collect::<Result<Vec<_>, Error>>()?)
}

/// I65, I67: one transaction adds the metadata and cohort keys and one
/// inventory generation, allocates no producer ordinal and leaves CSI1
/// unchanged; the CFO1 ARD1 is `TimelineReplay`, Required, Remove, with no
/// children; the CAU1 is Control/H(CQC1) with exactly the metadata `write`
/// row; the CMI1 producer is `[1, H(CQC1)]`; and the index names the CQR1.
#[test]
fn a_new_reason_commits_every_record_in_one_transaction() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let before = domain(&case);
    let keys = before.keys.len();
    let inventory = before.inventory_generation;
    let ordinal = before.native_producer_ordinal;
    let selection = before.selection.as_ref().map(|(_, sealed)| sealed.address);
    let receipt = set_reason(&mut case, claim(Basis::Artifact))??;
    let after = domain(&case);
    assert_eq!(after.keys.len(), keys + 2);
    assert_eq!(after.inventory_generation, inventory + 1);
    assert_eq!(after.native_producer_ordinal, ordinal);
    assert_eq!(
        after.selection.as_ref().map(|(_, sealed)| sealed.address),
        selection
    );
    let ledger = after
        .quarantine_index
        .values()
        .next()
        .ok_or("no index entry")?;
    assert_eq!(ledger.head, receipt.selected_ledger_digest());
    assert_eq!(ledger.ordinal, 1);
    let committed = after
        .quarantine_controls
        .values()
        .next()
        .ok_or("no committed SetReason")?;
    let admission = committed.admission.as_ref().ok_or("no COA1")?;
    let owner = community_catalogue_owner_v1(target(), GENERATION)?;
    let row = ArtifactRegistrationPersistencePortV1::read_artifact_registration(
        &after.store,
        &owner,
        admission.as_input().registration_address,
    )?
    .ok_or("no ARD1")?;
    let fields = row.registration().fields();
    assert_eq!(
        fields.artifact_class,
        ErasureArtifactClassV1::TimelineReplay
    );
    assert_eq!(fields.optionality, ArtifactOptionalityV1::Required);
    assert_eq!(fields.transition_rule, ArtifactTransitionRuleV1::Remove);
    assert!(fields.child_artifacts.is_empty());
    let metadata_intent = *after
        .keys
        .get(&committed.metadata_key)
        .ok_or("no metadata key")?
        .intent()
        .as_input();
    // The metadata CKP1 carries the installed metadata horizon (R9.9(2)).
    assert_eq!(metadata_intent.evidence_not_after_micros, HORIZON);
    let metadata_key = metadata_intent.authority_request_digest;

    // CCI1, CBQ1, CSB1, CPV1, CAU1, CMI1, CCI1, CQC1, CQR1, CQO1.
    let plain = records(&case, CONTROL)?;
    assert_eq!(plain.len(), 10);
    assert_eq!(plain[9].as_slice(), receipt.outcome());
    let evidence = CommunityAuthorityEvidenceV1::from_canonical_cbor(&plain[4])?;
    let evidence = evidence.as_input();
    assert!(evidence.operation == CommunityArtifactOperationV1::Control(CONTROL));
    assert_eq!(evidence.input_identity, receipt.request_digest());
    assert_eq!(evidence.inventory_generation, inventory);
    assert_eq!(evidence.decision_rows.len(), 1);
    let decision = evidence.decision_rows[0];
    assert_eq!(decision.leaf_grant_id, METADATA_LEAF);
    assert_eq!(decision.request_digest, metadata_key);
    assert_eq!(evidence.object_bindings.len(), 1);
    assert_eq!(
        evidence.object_bindings[0].registration_address,
        admission.as_input().registration_address
    );
    let materialization = CommunityMaterializationV1::from_canonical_cbor(&plain[5])?;
    let materialization = materialization.as_input();
    assert!(
        materialization.producer == CommunityProducerBindingV1::Control(receipt.request_digest())
    );
    assert_eq!(
        materialization.materialization.attestation_address,
        admission.digest()
    );
    Ok(())
}

/// I71: an identical retry adds no key, record or inventory generation.
#[test]
fn a_retry_adds_nothing() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let receipt = set_reason(&mut case, claim(Basis::Artifact))??;
    let keys = domain(&case).keys.len();
    let inventory = domain(&case).inventory_generation;
    assert_eq!(set_reason(&mut case, claim(Basis::Artifact))??, receipt);
    assert_eq!(domain(&case).keys.len(), keys);
    assert_eq!(domain(&case).inventory_generation, inventory);
    Ok(())
}

/// Annex: an active reason persists only its CQC1/CQO1 outcome, under one
/// new metadata key, and publishes no ARD1 or index change.
#[test]
fn an_active_reason_persists_only_its_outcome() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let first = set_reason(&mut case, claim(Basis::Artifact))??;
    let keys = domain(&case).keys.len();
    let again = [0x41; 16];
    let receipt = set_reason(
        &mut case,
        Claim {
            control: again,
            ledger: Some(first.selected_ledger_digest()),
            ..claim(Basis::Artifact)
        },
    )??;
    assert!(receipt.disposition() == Disposition::AlreadyQuarantined);
    let after = domain(&case);
    assert_eq!(after.keys.len(), keys + 1);
    let ledger = after
        .quarantine_index
        .values()
        .next()
        .ok_or("no index entry")?;
    assert_eq!(ledger.head, first.selected_ledger_digest());
    let committed = after
        .quarantine_controls
        .get(&(target(), again))
        .ok_or("no committed SetReason")?;
    assert!(committed.admission.is_none());
    // CCI1, CQC1, CQO1.
    assert_eq!(records(&case, again)?.len(), 3);
    Ok(())
}

/// Annex: a different additional reason appends one revision with the set
/// union, in reason order, one ordinal past its predecessor and no later
/// than its predecessor's horizon.
#[test]
fn a_new_reason_appends_the_set_union() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let first = set_reason(&mut case, claim(Basis::Artifact))??;
    // Stand in for a reason only an Abort can set (A4e-2): replace the
    // active set with `Unavailable` at an earlier horizon.
    let key = {
        let (key, ledger) = case
            .domain
            .world
            .domain
            .quarantine_index
            .iter_mut()
            .next()
            .ok_or("no index entry")?;
        ledger.reasons = vec![Evidence {
            reason: Reason::Unavailable,
            failure_evidence_digest: hash(0x91),
        }];
        ledger.evidence_not_after_micros = HORIZON - 1;
        *key
    };
    let next = [0x42; 16];
    let receipt = set_reason(
        &mut case,
        Claim {
            control: next,
            ledger: Some(first.selected_ledger_digest()),
            ..claim(Basis::Artifact)
        },
    )??;
    assert!(receipt.disposition() == Disposition::Applied);
    let ledger = domain(&case)
        .quarantine_index
        .get(&key)
        .ok_or("no index entry")?;
    assert_eq!(ledger.ordinal, 2);
    assert_eq!(ledger.head, receipt.selected_ledger_digest());
    assert_eq!(ledger.evidence_not_after_micros, HORIZON - 1);
    let codes: Vec<u8> = ledger.reasons.iter().map(|row| row.reason.code()).collect();
    assert_eq!(codes, [2, 3]);
    let plain = records(&case, next)?;
    let implementation = Roster::release_one()?.implementation;
    let revision = CommunityQuarantineRevisionV1::from_canonical_cbor(&plain[8], &implementation)?;
    let revision = revision.as_input();
    assert_eq!(revision.ledger_ordinal, 2);
    assert_eq!(
        revision.predecessor_ledger_digest,
        Some(first.selected_ledger_digest())
    );
    assert_eq!(revision.evidence_not_after_micros, HORIZON - 1);
    let rows: Vec<u8> = revision
        .active_reasons
        .iter()
        .map(|row| row.reason.code())
        .collect();
    assert_eq!(rows, [2, 3]);
    Ok(())
}

/// The commit compares the inventory generation and CSI1 it read and
/// refuses either moved; an ARD1 already published refuses too. Each
/// leaves no index entry.
#[test]
fn the_commit_refuses_moved_premises_or_a_taken_registration() -> TestResult {
    for fault in 0..3 {
        let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
        let mut staged = staged(&mut case, claim(Basis::Artifact))?;
        let domain = &mut case.domain.world.domain;
        let expected = match fault {
            0 => {
                staged.inventory_generation += 1;
                Error::EvidenceUnavailable
            }
            1 => {
                staged.read_selection = hash(0x92);
                Error::EvidenceUnavailable
            }
            _ => {
                let batch = &staged.evidence.as_ref().ok_or("no batch")?.batch;
                domain.store.commit_community_artifact_batch(batch)?;
                Error::Conflict
            }
        };
        assert_eq!(domain.commit_set_reason(staged).err(), Some(expected));
        assert!(domain.quarantine_index.is_empty());
        assert!(domain.quarantine_controls.is_empty());
    }
    Ok(())
}

/// A retry whose retained CQO1 or CFO1 ARD1 no longer resolves is 12.
#[test]
fn a_retry_needs_its_retained_evidence() -> TestResult {
    for fault in 0..3 {
        let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
        set_reason(&mut case, claim(Basis::Artifact))??;
        let domain = &mut case.domain.world.domain;
        let committed = domain
            .quarantine_controls
            .values_mut()
            .next()
            .ok_or("no committed SetReason")?;
        match fault {
            0 => {
                let key = committed.metadata_key;
                domain.keys.remove(&key);
            }
            1 => committed.receipt.outcome = zeroize::Zeroizing::new(vec![0x80]),
            _ => committed.generation = [0x99; 16],
        }
        assert_eq!(
            set_reason(&mut case, claim(Basis::Artifact))?.err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// The trusted-clock reservation refuses a domain other than the
/// lifecycle authority's installed one.
#[test]
fn the_reservation_refuses_another_domain() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let foreign = MemoryCommunityDomainV1::new(
        MemoryStore::new(),
        [0x5b; 16],
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    case.domain.world.domain = foreign;
    assert_eq!(
        set_reason(&mut case, claim(Basis::Artifact))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// Owner 2026-11-21 (#560), review L3: an already active reason writes no
/// CFO1, so the CFO1 and quarantine horizons are not checked, even when the
/// bound is past the generation's quarantine horizon.
#[test]
fn an_active_reason_skips_the_horizon_check() -> TestResult {
    let roster = Roster::release_one()?;
    let (mut domain, material) = Bootstrapped::revoked(&SEAL, &roster, Revocation::Artifact)?;
    let rows = roster.rows()?;
    let short = profile_with_quarantine(&rows, domain.world.catalogue, EXPIRES - 1)?;
    let receipt = initialize_target(&SEAL, &mut domain, &roster, &short)??;
    let mut case = QuarantineCase {
        head: initial_head(&receipt)?,
        domain,
        roster: Roster::release_one()?,
        material,
    };
    let implementation = Roster::release_one()?.implementation;
    let key = CommunityQuarantineKeyV1::new(target(), ENTRIES[0], &implementation)?.digest();
    let head = hash(0x93);
    case.domain.world.domain.quarantine_index.insert(
        key,
        QuarantineLedgerV1 {
            head,
            ordinal: 1,
            reasons: vec![Evidence {
                reason: Reason::Revoked,
                failure_evidence_digest: hash(0x94),
            }],
            evidence_not_after_micros: EXPIRES - 1,
        },
    );
    let outcome = with_set_reason(
        &SEAL,
        &mut case,
        &short,
        &release_one(),
        Claim {
            ledger: Some(head),
            ..claim(Basis::Artifact)
        },
        |world, metadata, context, call| {
            world
                .domain
                .set_quarantine_reason(&SEAL, context, &mut world.authority, metadata, call)
        },
    )??;
    assert!(outcome.disposition() == Disposition::AlreadyQuarantined);
    assert_eq!(outcome.selected_ledger_digest(), head);
    // A new reason under the same horizon is still `EvidenceExpired`.
    case.domain.world.domain.quarantine_index.clear();
    let refused = with_set_reason(
        &SEAL,
        &mut case,
        &short,
        &release_one(),
        Claim {
            control: [0x44; 16],
            ..claim(Basis::Artifact)
        },
        |world, metadata, context, call| {
            world
                .domain
                .set_quarantine_reason(&SEAL, context, &mut world.authority, metadata, call)
        },
    )?;
    assert_eq!(refused.err(), Some(Error::EvidenceExpired));
    Ok(())
}

/// The member's trust row needs the active release to be the member's PMF1
/// (R6.5). After initialize, a re-signed PMF1 of the same release digest
/// becomes active: the PMF1 differs while the release digest matches, so
/// `SetReason` gives 12.
#[test]
fn a_re_signed_active_release_is_not_the_member_release() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::PublisherKey)?;
    let mut resigned = ManifestSpec::new("plugin-a", 0x02, 0x11, None);
    resigned.epoch = 2;
    assert_eq!(resigned.release_digest()?, release_one().release_digest()?);
    let domain = &mut case.domain;
    std::mem::swap(&mut domain.harness.store, &mut domain.world.domain.store);
    let admitted = domain.harness.admit(&case.material, &resigned, 3);
    std::mem::swap(&mut domain.harness.store, &mut domain.world.domain.store);
    admitted??;
    assert_eq!(
        set_reason(&mut case, claim(Basis::PublisherKey))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}
