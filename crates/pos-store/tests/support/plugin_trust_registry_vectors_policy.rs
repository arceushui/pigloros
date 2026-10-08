// This file is `include!`d by the adapter test crates, so rustfmt does not format it; keep it in
// rustfmt style by hand.
// Shared public acceptance vectors of the ADR-103 revision 4 Plugin trust policy registry port:
// G1, H1, R1-R6, S1, S2, X1, and the retained-record accessors. The including module declares
// `type Store: Backend` and sees the crate's `fixtures` module, so one body runs the vectors on
// every adapter and a vector is written once. The file is `include!`d, never a module of its own.
//
// Every expected value is stated independently of the registry: digests are recomputed by the
// shared fixture from the public encodings, and each denial names the exact error variant the
// accepted contract assigns it.

use crate::fixtures::{
    activation, digest, release_one, release_three, release_two, spec, tps_after, Env, Harness,
    ManifestSpec, RegistryError, Spec, TestResult, TpsSpec,
};
use pos_conformance::{
    PluginFloorErrorV1, PluginFloorKindV1, PluginTrustBridgeErrorV1, TrustPolicySnapshotV1,
};
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use pos_store::plugin_trust_registry::{
    PluginTrustCommitOutcomeV1, PluginTrustLedgerKindV1, PluginTrustPolicyRegistryV1,
    PolicyAdvanceKindV1,
};

const fn rollback_error(kind: PluginFloorKindV1) -> RegistryError {
    RegistryError::Floor(PluginFloorErrorV1::Rollback(kind))
}

const fn fork_error(kind: PluginFloorKindV1) -> RegistryError {
    RegistryError::Floor(PluginFloorErrorV1::Fork(kind))
}

// ---------------------------------------------------------------------------
// G1: advance_policy
// ---------------------------------------------------------------------------

#[test]
fn a_denied_admission_records_nothing_until_advance_policy_records_it() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    h.admit(&genesis, &one, 1)??;
    let revoking = h.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![two.release_digest()],
            ..Spec::default().at(51, 6)
        },
        &tps_after(&genesis),
    )?;
    h.assert_admit_denied(
        &revoking,
        &two,
        RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
    )?;
    let before = h.snapshot(&[&one, &two])?;
    assert_eq!(before.policy.tps1_epoch(), 1);

    let outcome = h.advance(&revoking)??;
    assert_eq!(outcome.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(outcome.tps1_digest, revoking.tps1_digest());
    assert_eq!(outcome.tps1_epoch, 2);
    assert_eq!(outcome.ptr1_floor, Some(revoking.terminal_root()));
    assert_eq!(outcome.prv1_floor, Some(revoking.terminal_revocation()));
    let after = h.snapshot(&[&one, &two])?;
    assert_eq!(after.policy.tps1_epoch(), 2);
    assert_eq!(after.policy.tps1_bytes(), revoking.tps1.as_slice());
    assert_eq!(after.decisions, before.decisions);
    assert_eq!(after.active, before.active);
    assert_eq!(after.events, before.events);
    assert_eq!(after.ledger.len(), before.ledger.len() + 1);
    let row = after.ledger.last().ok_or("no row")?;
    assert_eq!(row.kind(), PluginTrustLedgerKindV1::Advance);
    assert_eq!(row.row_seq(), 3);
    assert_eq!(row.trusted_utc_second(), Some(51));
    assert_eq!(row.tick(), Some(6));
    assert_eq!(row.tps1_digest(), revoking.tps1_digest());
    assert_eq!(row.ptr1_floor(), Some(revoking.terminal_root()));
    assert_eq!(row.prv1_floor(), Some(revoking.terminal_revocation()));
    assert_eq!(row.plugin_id(), None);
    assert_eq!(row.pmf1_digest(), None);
    assert_eq!(row.activation_event(), None);

    // The same evidence again is a no-op: no ledger row, only the UTC floor.
    let again = h.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![two.release_digest()],
            ..Spec::default().at(52, 7)
        },
        &tps_after(&genesis),
    )?;
    let noop = h.advance(&again)??;
    assert_eq!(noop.outcome, PolicyAdvanceKindV1::Unchanged);
    assert_eq!(h.ledger()?.len(), after.ledger.len());
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(52));

    // The release the evidence revoked is now denied for good.
    h.assert_admit_denied(
        &again,
        &two,
        RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
    )?;
    Ok(())
}

#[test]
fn advance_policy_initializes_absent_floors_from_the_first_evidence() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    assert_eq!(h.policy()?.ptr1_floor(), None);
    assert_eq!(h.policy()?.prv1_floor(), None);
    let outcome = h.advance(&genesis)??;
    assert_eq!(outcome.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(outcome.ptr1_floor, Some(genesis.terminal_root()));
    assert_eq!(outcome.prv1_floor, Some(genesis.terminal_revocation()));
    let policy = h.policy()?;
    assert_eq!(policy.ptr1_floor(), Some(genesis.terminal_root()));
    assert_eq!(policy.prv1_floor(), Some(genesis.terminal_revocation()));
    assert_eq!(policy.highest_trusted_utc_second(), Some(50));
    let rows = h.ledger()?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].kind(), PluginTrustLedgerKindV1::Advance);
    assert_eq!(rows[1].row_seq(), 2);
    assert_eq!(rows[1].trusted_utc_second(), Some(50));
    assert_eq!(rows[1].tick(), Some(5));
    Ok(())
}

#[test]
fn a_tps1_only_artifact_denial_blocks_admission_but_not_advance_policy() -> TestResult {
    for denied in [[0x03; 32], [0x12; 32], [0x30; 32]] {
        let mut h = Harness::<Store>::open()?;
        let genesis = h.env.genesis()?;
        let tps = TpsSpec {
            extra_artifacts: vec![denied],
            ..tps_after(&genesis)
        };
        let material = h.env.material(&spec(1, 2), &tps)?;
        let two = release_two();
        h.assert_admit_denied(
            &material,
            &two,
            RegistryError::Bridge(PluginTrustBridgeErrorV1::TpsArtifactDenied),
        )?;
        assert_eq!(
            h.advance(&material)??.outcome,
            PolicyAdvanceKindV1::Advanced
        );
        h.assert_admit_denied(
            &material,
            &two,
            RegistryError::Bridge(PluginTrustBridgeErrorV1::TpsArtifactDenied),
        )?;
    }
    // An unrelated denial leaves the release admissible.
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let tps = TpsSpec {
        extra_artifacts: vec![[0x77; 32]],
        ..tps_after(&genesis)
    };
    let material = h.env.material(&spec(1, 2), &tps)?;
    h.admit(&material, &release_two(), 1)??;
    Ok(())
}

// ---------------------------------------------------------------------------
// H1: the PTR1 and PRV1 floors
// ---------------------------------------------------------------------------

#[test]
fn ptr1_floor_follows_the_lower_equal_fork_and_descendant_rules() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    assert_eq!(h.advance(&genesis)??.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(
        h.advance(&h.same_policy(51, 6)?)??.outcome,
        PolicyAdvanceKindV1::Unchanged
    );
    let two = h
        .env
        .material(&spec(2, 2).at(52, 7), &tps_after(&genesis))?;
    h.advance(&two)??;
    assert_eq!(h.policy()?.ptr1_floor(), Some(two.terminal_root()));

    // A lower root version under a newer policy epoch.
    let lower = h.env.material(&spec(1, 3).at(53, 8), &tps_after(&two))?;
    h.assert_advance_denied(&lower, rollback_error(PluginFloorKindV1::Root))?;

    // The same root version with another digest.
    let fork = h.env.material(
        &Spec {
            root_variant: 1,
            ..spec(2, 3).at(53, 8)
        },
        &tps_after(&two),
    )?;
    h.assert_advance_denied(&fork, fork_error(PluginFloorKindV1::Root))?;

    // A descendant: the history contains exactly the retained pair.
    let three = h.env.material(&spec(3, 3).at(53, 8), &tps_after(&two))?;
    h.advance(&three)??;
    assert_eq!(h.policy()?.ptr1_floor(), Some(three.terminal_root()));
    assert_eq!(h.policy()?.prv1_floor(), Some(three.terminal_revocation()));

    // A greater version on another branch: the history holds another digest at version 3.
    let branch = h.env.material(
        &Spec {
            root_variant: 1,
            ..spec(4, 4).at(54, 9)
        },
        &tps_after(&three),
    )?;
    h.assert_advance_denied(&branch, fork_error(PluginFloorKindV1::Root))?;
    Ok(())
}

#[test]
fn prv1_floor_follows_the_equal_fork_and_descendant_rules_independently() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let two = h
        .env
        .material(&spec(2, 2).at(51, 6), &tps_after(&genesis))?;
    let three = h.env.material(&spec(3, 3).at(52, 7), &tps_after(&two))?;
    h.advance(&genesis)??;
    h.advance(&two)??;
    h.advance(&three)??;

    // The retained TPS1 with another PRV1 digest at the same epoch; PTR1 is unchanged.
    let fork = h.env.material(
        &Spec {
            revocation_variant: 1,
            ..spec(3, 3).at(53, 8)
        },
        &tps_after(&two),
    )?;
    assert_eq!(fork.tps1, three.tps1);
    h.assert_advance_denied(&fork, fork_error(PluginFloorKindV1::Revocation))?;

    // Older PRV1 evidence carries an older TPS1, so it fails the continuity step.
    let older = h
        .env
        .material(&spec(2, 2).at(53, 8), &tps_after(&genesis))?;
    h.assert_advance_denied(
        &older,
        RegistryError::Bridge(PluginTrustBridgeErrorV1::StaleSnapshot),
    )?;

    // A descendant PRV1 under an unchanged PTR1.
    let four = h.env.material(&spec(3, 4).at(53, 8), &tps_after(&three))?;
    let outcome = h.advance(&four)??;
    assert_eq!(outcome.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(h.policy()?.ptr1_floor(), Some(three.terminal_root()));
    assert_eq!(h.policy()?.prv1_floor(), Some(four.terminal_revocation()));

    // A greater epoch on another branch: the history holds another digest at epoch 4.
    let branch = h.env.material(
        &Spec {
            revocation_variant: 1,
            ..spec(3, 5).at(54, 9)
        },
        &tps_after(&four),
    )?;
    h.assert_advance_denied(&branch, fork_error(PluginFloorKindV1::Revocation))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// R1 to R6: rollback
// ---------------------------------------------------------------------------

/// A provisioned store holding two admitted releases, the second active.
fn two_releases() -> TestResult<Harness<Store>> {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &release_one(), 1)??;
    h.admit(&genesis, &release_two(), 2)??;
    Ok(h)
}

#[test]
fn rollback_moves_the_pointer_to_a_retained_release_and_never_lowers_a_floor() -> TestResult {
    let mut h = two_releases()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    let later = h
        .env
        .material(&spec(2, 2).at(51, 6), &tps_after(&genesis))?;
    h.advance(&later)??;
    let before = h.snapshot(&[&one, &two])?;

    let material = h
        .env
        .material(&spec(2, 2).at(52, 7), &tps_after(&genesis))?;
    let receipt = h.rollback(&material, &one, 5)??;
    assert_eq!(receipt.outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(receipt.scope(), "scope");
    assert_eq!(receipt.plugin_id(), "plugin-a");
    assert_eq!(receipt.target_pmf1_digest(), [0x01; 32]);
    assert_eq!(receipt.target_release_digest(), [0x11; 32]);
    assert_eq!(receipt.replaced_pmf1_digest(), [0x03; 32]);
    assert_eq!(receipt.tps1_digest(), later.tps1_digest());
    assert_eq!(receipt.tps1_epoch(), 2);
    assert_eq!(receipt.tps1_effective_position(), 9);
    assert_eq!(receipt.terminal_root(), later.terminal_root());
    assert_eq!(receipt.terminal_revocation(), later.terminal_revocation());
    assert_eq!(receipt.trusted_utc_second(), 52);
    assert_eq!(receipt.tick(), 7);
    assert_eq!(receipt.activation_event().seq().as_u64(), 3);

    let after = h.snapshot(&[&one, &two])?;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x01; 32]);
    assert_eq!(
        h.active("plugin-a")?.activation_event(),
        receipt.activation_event()
    );
    assert_eq!(after.decisions, before.decisions, "decisions are immutable");
    assert_eq!(after.policy.ptr1_floor(), before.policy.ptr1_floor());
    assert_eq!(after.policy.prv1_floor(), before.policy.prv1_floor());
    assert_eq!(after.policy.highest_trusted_utc_second(), Some(52));
    assert_eq!(after.ledger.len(), before.ledger.len() + 1);
    let row = after.ledger.last().ok_or("no row")?;
    assert_eq!(row.kind(), PluginTrustLedgerKindV1::Rollback);
    assert_eq!(row.row_seq(), 5);
    assert_eq!(row.plugin_id(), Some("plugin-a"));
    assert_eq!(row.pmf1_digest(), Some([0x01; 32]));
    assert_eq!(row.release_digest(), Some([0x11; 32]));
    assert_eq!(row.previous_active_pmf1_digest(), Some([0x03; 32]));
    assert_eq!(row.activation_event(), Some(receipt.activation_event()));
    assert_eq!(row.trusted_utc_second(), Some(52));
    assert_eq!(row.tick(), Some(7));
    assert_eq!(row.ptr1_floor(), Some(later.terminal_root()));
    assert_eq!(row.prv1_floor(), Some(later.terminal_revocation()));
    Ok(())
}

#[test]
fn rollback_requires_an_active_release_and_a_non_active_target() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    h.admit(&genesis, &one, 1)??;

    // The target digest is retained, but no release of that Plugin ID is active.
    let fabricated = ManifestSpec::new("plugin-b", 0x01, 0x11, None);
    h.assert_rollback_denied(&genesis, &fabricated, RegistryError::NoActiveRelease)?;

    // The pointer was reached by an admission, so the target is active.
    h.assert_rollback_denied(&genesis, &one, RegistryError::RollbackTargetActive)?;
    Ok(())
}

#[test]
fn an_identical_rollback_replays_and_any_other_identity_is_target_active() -> TestResult {
    let mut h = two_releases()?;
    let one = release_one();
    let two = release_two();
    let first = h.rollback(&h.same_policy(51, 6)?, &one, 7)??;
    let before = h.snapshot(&[&one, &two])?;

    let replay = h.rollback(&h.same_policy(52, 7)?, &one, 7)??;
    assert_eq!(
        replay.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(replay.activation_event(), first.activation_event());
    assert_eq!(replay.trusted_utc_second(), 51);
    assert_eq!(replay.tick(), 6);
    assert_eq!(replay.replaced_pmf1_digest(), [0x03; 32]);
    let after = h.snapshot(&[&one, &two])?;
    assert_eq!(after.events, before.events);
    assert_eq!(after.ledger, before.ledger);
    assert_eq!(after.active, before.active);
    assert_eq!(after.policy.highest_trusted_utc_second(), Some(52));

    // Another payload, another Timeline identity, or newer evidence is another identity.
    h.assert_rollback_denied(
        &h.same_policy(53, 8)?,
        &one,
        RegistryError::RollbackTargetActive,
    )?;
    let genesis = h.env.genesis()?;
    let newer = h
        .env
        .material(&spec(2, 2).at(54, 9), &tps_after(&genesis))?;
    h.advance(&newer)??;
    assert_eq!(
        h.rollback_with(&newer, &one, activation(h.timeline, 7))?,
        Err(RegistryError::RollbackTargetActive)
    );
    Ok(())
}

#[test]
fn a_pointer_reached_by_an_admission_is_never_a_rollback_replay() -> TestResult {
    let mut h = two_releases()?;
    h.assert_rollback_denied(
        &h.env.genesis()?,
        &release_two(),
        RegistryError::RollbackTargetActive,
    )?;
    Ok(())
}

#[test]
fn an_unknown_rollback_target_is_one_never_admitted_in_this_scope() -> TestResult {
    let mut h = two_releases()?;
    let genesis = h.env.genesis()?;
    let never_admitted = ManifestSpec::new("plugin-a", 0x99, 0x19, None);
    h.assert_rollback_denied(
        &genesis,
        &never_admitted,
        RegistryError::UnknownRollbackTarget,
    )?;

    // A digest retained only under another scope, while this scope has an active pointer.
    let other = Env::new("scope-two")?;
    h.store.provision(&other.anchor, &other.genesis_tps1)?;
    let other_genesis = other.genesis()?;
    h.store.admit(
        &other.anchor,
        &other_genesis.tps1,
        &other_genesis.evidence,
        &ManifestSpec::new("plugin-a", 0x50, 0x60, None).projection()?,
        other_genesis.trusted()?,
        other_genesis.tick,
        activation(h.timeline, 3),
    )?;
    let foreign_digest_in_other_scope = release_one();
    assert_eq!(
        h.store.retained_release_decision("scope-two", [0x01; 32])?,
        None
    );
    assert_eq!(
        h.store.rollback(
            &other.anchor,
            &other_genesis.tps1,
            &other_genesis.evidence,
            &foreign_digest_in_other_scope.projection()?,
            other_genesis.trusted()?,
            other_genesis.tick,
            activation(h.timeline, 4)
        ),
        Err(RegistryError::UnknownRollbackTarget)
    );
    Ok(())
}

#[test]
fn rollback_reports_policy_denials_before_an_unknown_target() -> TestResult {
    let mut h = two_releases()?;
    let genesis = h.env.genesis()?;
    let target = ManifestSpec::new("plugin-a", 0x99, 0x19, None);

    let revoked_key = h.env.material(
        &Spec {
            epochs: 2,
            revoked_publisher_epochs: vec![1],
            ..Spec::default()
        },
        &tps_after(&genesis),
    )?;
    h.assert_rollback_denied(
        &revoked_key,
        &target,
        RegistryError::Trust(PluginTrustErrorV1::PublisherKeyRevoked),
    )?;
    let revoked_artifact = h.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![target.release_digest()],
            ..Spec::default()
        },
        &tps_after(&genesis),
    )?;
    h.assert_rollback_denied(
        &revoked_artifact,
        &target,
        RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
    )?;
    let mut expired = target.clone();
    expired.not_after = 50;
    h.assert_rollback_denied(
        &genesis,
        &expired,
        RegistryError::Trust(PluginTrustErrorV1::ManifestExpired),
    )?;
    let tps_denied = h.env.material(
        &spec(1, 2),
        &TpsSpec {
            extra_artifacts: vec![target.pmf1_digest()],
            ..tps_after(&genesis)
        },
    )?;
    h.assert_rollback_denied(
        &tps_denied,
        &target,
        RegistryError::Bridge(PluginTrustBridgeErrorV1::TpsArtifactDenied),
    )?;

    // Once the policy advanced, older evidence fails in its own step.
    let current = h
        .env
        .material(&spec(2, 2).at(51, 6), &tps_after(&genesis))?;
    h.advance(&current)??;
    let older_root = h
        .env
        .material(&spec(1, 3).at(52, 7), &tps_after(&current))?;
    h.assert_rollback_denied(
        &older_root,
        &target,
        rollback_error(PluginFloorKindV1::Root),
    )?;
    let older_tps = h.same_policy(52, 7)?;
    h.assert_rollback_denied(
        &older_tps,
        &target,
        RegistryError::Bridge(PluginTrustBridgeErrorV1::StaleSnapshot),
    )?;
    Ok(())
}

#[test]
fn rollback_ignores_the_chain_rule_and_the_forward_move_is_also_a_rollback() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    let three = release_three();
    h.admit(&genesis, &one, 1)??;
    h.admit(&genesis, &two, 2)??;
    h.admit(&genesis, &three, 3)??;
    h.admit(
        &genesis,
        &ManifestSpec::new("plugin-b", 0x21, 0x31, None),
        4,
    )??;

    // R1 is neither the active release nor its successor, yet it is a valid target.
    h.rollback(&genesis, &one, 5)??;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x01; 32]);
    assert_eq!(
        h.active("plugin-b")?.pmf1_digest(),
        [0x21; 32],
        "one Plugin ID's rollback never displaces another's pointer"
    );

    // With R1 active and R2 retained, R3 (linked to R2) is not admissible.
    let relinked_three = ManifestSpec::new("plugin-a", 0x09, 0x13, Some(0x12));
    h.assert_admit_denied(
        &genesis,
        &relinked_three,
        RegistryError::ReleaseChainViolation,
    )?;
    h.rollback(&genesis, &two, 6)??;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x03; 32]);
    h.admit(&genesis, &relinked_three, 7)??;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x09; 32]);
    Ok(())
}

#[test]
fn a_rollback_without_a_usable_event_changes_nothing() -> TestResult {
    let mut h = two_releases()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    let before = h.snapshot(&[&one, &two])?;
    let unknown = activation(pos_core::TimelineId::new(), 1);
    assert_eq!(
        h.rollback_with(&genesis, &one, unknown)?,
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(h.snapshot(&[&one, &two])?, before);
    Ok(())
}

#[test]
fn a_stored_receipt_grants_no_authority_after_a_later_revocation() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let receipt = h.admit(&genesis, &one, 1)??;
    let revoking = h.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![one.release_digest()],
            ..Spec::default().at(51, 6)
        },
        &tps_after(&genesis),
    )?;
    h.assert_admit_denied(
        &revoking,
        &one,
        RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
    )?;
    h.assert_rollback_denied(
        &revoking,
        &one,
        RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
    )?;
    let retained = h
        .store
        .retained_release_decision("scope", one.pmf1_digest())?
        .ok_or("no decision")?;
    assert_eq!(&retained, receipt.decision());
    Ok(())
}

// ---------------------------------------------------------------------------
// S1 and S2: scopes and uninterpreted TPS1 content
// ---------------------------------------------------------------------------

#[test]
fn an_unprovisioned_scope_is_missing_state_and_never_affects_a_provisioned_one() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let absent = Env::new("absent")?;
    let material = absent.genesis()?;
    let one = release_one();
    assert_eq!(
        h.store.admit(
            &absent.anchor,
            &material.tps1,
            &material.evidence,
            &one.projection()?,
            material.trusted()?,
            material.tick,
            activation(h.timeline, 1)
        ),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        h.store.rollback(
            &absent.anchor,
            &material.tps1,
            &material.evidence,
            &one.projection()?,
            material.trusted()?,
            material.tick,
            activation(h.timeline, 1)
        ),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        h.store.advance_policy(
            &absent.anchor,
            &material.tps1,
            &material.evidence,
            material.trusted()?,
            material.tick
        ),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        h.store.retained_release_decision("absent", [1; 32]),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        h.store.active_release("absent", "plugin-a"),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        h.store.retained_policy_state("absent"),
        Err(RegistryError::MissingState)
    );
    assert_eq!(h.store.ledger("absent"), Err(RegistryError::MissingState));
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &one, 1)??;
    Ok(())
}

#[test]
fn two_scopes_keep_independent_floors_pointers_and_ledgers() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let other = Env::new("scope-two")?;
    h.store.provision(&other.anchor, &other.genesis_tps1)?;
    let genesis = h.env.genesis()?;
    let other_genesis = other.genesis()?;
    let one = release_one();
    h.admit(&genesis, &one, 1)??;
    h.store.admit(
        &other.anchor,
        &other_genesis.tps1,
        &other_genesis.evidence,
        &one.projection()?,
        other_genesis.trusted()?,
        other_genesis.tick,
        activation(h.timeline, 2),
    )?;
    let first = h.store.retained_policy_state("scope")?;
    let second = h.store.retained_policy_state("scope-two")?;
    assert_eq!(first.ptr1_floor(), Some(genesis.terminal_root()));
    assert_eq!(second.ptr1_floor(), Some(other_genesis.terminal_root()));
    assert_ne!(first.ptr1_floor(), second.ptr1_floor());
    assert_ne!(first.tps1_digest(), second.tps1_digest());

    // Advancing one scope leaves the other untouched.
    let before = h.snapshot(&[&one])?;
    let later = other.material(&spec(2, 2).at(51, 6), &tps_after(&other_genesis))?;
    h.store.advance_policy(
        &other.anchor,
        &later.tps1,
        &later.evidence,
        later.trusted()?,
        later.tick,
    )?;
    assert_eq!(h.snapshot(&[&one])?, before);
    assert_eq!(h.store.ledger("scope-two")?.len(), 3);
    assert_eq!(h.store.ledger("scope")?.len(), 2);
    Ok(())
}

#[test]
fn unused_tps1_content_is_retained_byte_for_byte_and_never_interpreted() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let tps = TpsSpec {
        extras: true,
        ..tps_after(&genesis)
    };
    let material = h.env.material(&spec(1, 2), &tps)?;
    let snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&material.tps1)?;
    assert_eq!(snapshot.minimum_versions.len(), 1);
    assert!(snapshot
        .trust_roots
        .iter()
        .any(|root| root.key_id == "global.root"));
    assert!(snapshot.revoked_key_ids.iter().any(|id| id == "legacy.key"));

    let receipt = h.admit(&material, &release_one(), 1)??;
    assert_eq!(receipt.decision().tps1_digest(), digest(&material.tps1));
    assert_eq!(h.policy()?.tps1_bytes(), material.tps1.as_slice());
    assert_eq!(
        h.advance(&material)??.outcome,
        PolicyAdvanceKindV1::Unchanged
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// X1: admission-level denials leave the state byte-identical
// ---------------------------------------------------------------------------

#[test]
fn every_admission_denial_names_its_error_and_changes_nothing() -> TestResult {
    let genesis_after = |h: &Harness<Store>, spec: &Spec, tps: TpsSpec| -> TestResult<_> {
        let base = h.env.genesis()?;
        h.env.material(
            spec,
            &TpsSpec {
                previous: Some(base.tps1_digest()),
                ..tps
            },
        )
    };
    let mut h = Harness::<Store>::open()?;
    let one = release_one();
    let key_denied = genesis_after(
        &h,
        &Spec {
            epochs: 2,
            revoked_publisher_epochs: vec![1],
            ..Spec::default()
        },
        TpsSpec::default(),
    )?;
    h.assert_admit_denied(
        &key_denied,
        &one,
        RegistryError::Trust(PluginTrustErrorV1::PublisherKeyRevoked),
    )?;
    for revoked in [[0x11; 32], [0x30; 32], [0x33; 32]] {
        let artifact_denied = genesis_after(
            &h,
            &Spec {
                epochs: 2,
                revoked_artifacts: vec![revoked],
                ..Spec::default()
            },
            TpsSpec::default(),
        )?;
        h.assert_admit_denied(
            &artifact_denied,
            &one,
            RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
        )?;
    }
    let genesis = h.env.genesis()?;
    let mut expired = release_one();
    expired.not_after = 50;
    h.assert_admit_denied(
        &genesis,
        &expired,
        RegistryError::Trust(PluginTrustErrorV1::ManifestExpired),
    )?;
    let mut unknown_key = release_one();
    unknown_key.epoch = 9;
    h.assert_admit_denied(
        &genesis,
        &unknown_key,
        RegistryError::Trust(PluginTrustErrorV1::UnknownPublisherKey),
    )?;
    let not_granted = ManifestSpec::new("plugin-z", 0x01, 0x11, None);
    h.assert_admit_denied(
        &genesis,
        &not_granted,
        RegistryError::Trust(PluginTrustErrorV1::PluginIdNotGranted),
    )?;
    let tps_denied = genesis_after(
        &h,
        &spec(1, 2),
        TpsSpec {
            extra_artifacts: vec![one.pmf1_digest()],
            ..TpsSpec::default()
        },
    )?;
    h.assert_admit_denied(
        &tps_denied,
        &one,
        RegistryError::Bridge(PluginTrustBridgeErrorV1::TpsArtifactDenied),
    )?;
    Ok(())
}

#[test]
fn an_expired_tps1_is_denied_exactly_at_offline_valid_through() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let at_through = h.env.material(
        &spec(1, 2),
        &TpsSpec {
            offline_valid_through: "1970-01-01T00:00:50Z".to_owned(),
            ..tps_after(&genesis)
        },
    )?;
    h.assert_admit_denied(
        &at_through,
        &one,
        RegistryError::Bridge(PluginTrustBridgeErrorV1::Expired),
    )?;
    let one_second_left = h.env.material(
        &spec(1, 2),
        &TpsSpec {
            offline_valid_through: "1970-01-01T00:00:51Z".to_owned(),
            ..tps_after(&genesis)
        },
    )?;
    h.admit(&one_second_left, &one, 1)??;
    Ok(())
}

// ---------------------------------------------------------------------------
// The retained-record accessors
// ---------------------------------------------------------------------------

#[test]
fn retained_records_report_every_fact_of_the_transaction_that_made_them() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &release_one(), 1)??;
    let material = h.env.material(
        &spec(2, 2).at(51, 6),
        &TpsSpec {
            position: 11,
            ..tps_after(&genesis)
        },
    )?;
    let two = release_two();
    let receipt = h.admit(&material, &two, 2)??;
    let decision = receipt.decision();
    assert_eq!(receipt.outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(decision.scope(), "scope");
    assert_eq!(decision.plugin_id(), "plugin-a");
    assert_eq!(decision.pmf1_digest(), [0x03; 32]);
    assert_eq!(decision.release_digest(), [0x12; 32]);
    assert_eq!(decision.previous_release_digest(), Some([0x11; 32]));
    assert_eq!(decision.tps1_digest(), material.tps1_digest());
    assert_eq!(decision.tps1_epoch(), 2);
    assert_eq!(decision.tps1_effective_position(), 11);
    assert_eq!(decision.terminal_root(), material.terminal_root());
    assert_eq!(
        decision.terminal_revocation(),
        material.terminal_revocation()
    );
    assert_eq!(decision.trusted_utc_second(), 51);
    assert_eq!(decision.tick(), 6);
    assert_eq!(
        h.store.retained_release_decision("scope", [0x03; 32])?,
        Some(decision.clone())
    );

    let policy = h.policy()?;
    assert_eq!(policy.scope(), "scope");
    assert_eq!(policy.tps1_epoch(), 2);
    assert_eq!(policy.tps1_digest(), material.tps1_digest());
    assert_eq!(policy.tps1_effective_position(), 11);
    assert_eq!(policy.tps1_bytes(), material.tps1.as_slice());
    assert_eq!(policy.ptr1_floor(), Some(material.terminal_root()));
    assert_eq!(policy.prv1_floor(), Some(material.terminal_revocation()));
    assert_eq!(policy.highest_trusted_utc_second(), Some(51));

    let active = h.active("plugin-a")?;
    assert_eq!(active.scope(), "scope");
    assert_eq!(active.plugin_id(), "plugin-a");
    assert_eq!(active.pmf1_digest(), [0x03; 32]);
    assert_eq!(active.release_digest(), [0x12; 32]);
    assert_eq!(active.activation_event(), decision.activation_event());

    let rows = h.ledger()?;
    let row = rows.last().ok_or("no row")?;
    assert_eq!(row.kind(), PluginTrustLedgerKindV1::Admission);
    assert_eq!(row.row_seq(), 3);
    assert_eq!(row.tps1_digest(), material.tps1_digest());
    assert_eq!(row.tps1_epoch(), 2);
    assert_eq!(row.tps1_effective_position(), 11);
    assert_eq!(row.ptr1_floor(), Some(material.terminal_root()));
    assert_eq!(row.prv1_floor(), Some(material.terminal_revocation()));
    assert_eq!(row.trusted_utc_second(), Some(51));
    assert_eq!(row.tick(), Some(6));
    assert_eq!(row.plugin_id(), Some("plugin-a"));
    assert_eq!(row.pmf1_digest(), Some([0x03; 32]));
    assert_eq!(row.release_digest(), Some([0x12; 32]));
    assert_eq!(row.previous_active_pmf1_digest(), Some([0x01; 32]));
    assert_eq!(row.activation_event(), Some(decision.activation_event()));
    let identity = decision.activation_event();
    assert_eq!(identity.event_type(), "plugin.activation.v1");
    assert_eq!(identity.timeline_id(), h.timeline);
    Ok(())
}

// ---------------------------------------------------------------------------
// The closed error
// ---------------------------------------------------------------------------

#[test]
fn registry_error_messages_are_stable_and_secret_free() {
    use std::error::Error;

    let direct = [
        (
            RegistryError::MissingState,
            "Plugin trust state is not provisioned",
        ),
        (RegistryError::CorruptState, "Plugin trust state is corrupt"),
        (
            RegistryError::AnchorMismatch,
            "Plugin trust anchor differs from the persisted anchor",
        ),
        (
            RegistryError::TrustedTimeUnavailable,
            "trusted UTC source is unavailable",
        ),
        (
            RegistryError::TrustedTimeRegressed,
            "trusted UTC second is below the retained highest second",
        ),
        (
            RegistryError::ReleaseChainViolation,
            "release does not continue the active release chain",
        ),
        (
            RegistryError::ReleaseConflict,
            "release decision already retained with a different identity",
        ),
        (
            RegistryError::UnknownRollbackTarget,
            "rollback target was never admitted in this scope",
        ),
        (
            RegistryError::NoActiveRelease,
            "no active release to roll back",
        ),
        (
            RegistryError::RollbackTargetActive,
            "rollback target is already active",
        ),
        (
            RegistryError::ActivationEventRejected,
            "activation Event was rejected",
        ),
        (
            RegistryError::NestedTransaction,
            "registry operation entered inside a transaction",
        ),
        (
            RegistryError::WalRequired,
            "registry storage requires WAL journal mode",
        ),
        (RegistryError::StorageBusy, "registry storage is busy"),
        (
            RegistryError::StorageFailed,
            "registry storage operation failed",
        ),
        (
            RegistryError::StorageIndeterminate,
            "registry storage commit outcome is unknown",
        ),
        (
            RegistryError::StorePoisoned,
            "registry storage handle is poisoned",
        ),
    ];
    for (error, message) in direct {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
    let wrapped = [
        (
            RegistryError::Bridge(PluginTrustBridgeErrorV1::StaleSnapshot),
            "TPS1 bridge: TPS1 snapshot epoch is not newer than the retained snapshot",
        ),
        (
            rollback_error(PluginFloorKindV1::Root),
            "trust floor: PTR1 candidate is below the retained floor",
        ),
        (
            RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
            "release authorization: Plugin manifest artifact is revoked",
        ),
    ];
    for (error, message) in wrapped {
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_some());
    }
}
