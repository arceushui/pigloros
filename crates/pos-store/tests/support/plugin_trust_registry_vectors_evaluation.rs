// This file is `include!`d by the adapter test crates, so rustfmt does not format it; keep it in
// rustfmt style by hand.
// Shared public acceptance vectors of the ADR-103 revision 5 read-only current-release
// evaluation: EV1 to EV8 and EV11 (the SQLite-only and in-crate vectors EV9, EV9b, EV10, and
// EV12 to EV14 live next to the adapters). The including module declares `type Store: Backend`
// and sees the crate's `fixtures` module, so one body runs the vectors on every adapter.
//
// Every expected value is stated independently of the registry: the digests are the fixture
// constants, and each refusal names the exact error variant the contract assigns it.

use crate::fixtures::{
    activation, bound_store, foreign_operator_signer, release_one, release_two, spec,
    tps1_signed_by, tps_after, Env, Harness, ManifestSpec, Material, Registry, RegistryError, Spec,
    TestResult, TpsSpec,
};
use pos_conformance::{PluginFloorErrorV1, PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use pos_store::plugin_trust_registry::{CurrentReleaseEvaluationV1, PluginTrustPolicyRegistryV1};

const fn bridge(error: PluginTrustBridgeErrorV1) -> RegistryError {
    RegistryError::Bridge(error)
}

const fn trust(error: PluginTrustErrorV1) -> RegistryError {
    RegistryError::Trust(error)
}

/// A release no step after the first failing one would accept: an ungranted Plugin ID.
fn unauthorized() -> ManifestSpec {
    ManifestSpec::new("plugin-z", 0x51, 0x51, None)
}

/// A provisioned store with `release_one` admitted and active under the genesis policy at UTC
/// second 50 and Tick 5, so the highest trusted UTC second is 50 and both floors exist.
fn admitted() -> TestResult<Harness<Store>> {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &release_one(), 1)??;
    Ok(h)
}

// ---------------------------------------------------------------------------
// EV1: the facts, and nothing written
// ---------------------------------------------------------------------------

#[test]
fn an_evaluation_reports_the_retained_facts_and_changes_nothing() -> TestResult {
    let h = admitted()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    let later = h.same_policy(60, 8)?;
    let evaluation = h.evaluate(&later, &one)??;
    let decision = before
        .decisions
        .first()
        .and_then(Option::as_ref)
        .ok_or("no decision")?;
    let active = before
        .active
        .first()
        .and_then(Option::as_ref)
        .ok_or("no pointer")?;
    assert_eq!(evaluation.scope(), "scope");
    assert_eq!(evaluation.plugin_id(), "plugin-a");
    assert_eq!(evaluation.pmf1_digest(), [0x01; 32]);
    assert_eq!(evaluation.release_digest(), [0x11; 32]);
    assert_eq!(evaluation.previous_release_digest(), None);
    assert_eq!(evaluation.pmf1_digest(), decision.pmf1_digest());
    assert_eq!(evaluation.release_digest(), decision.release_digest());
    assert_eq!(evaluation.tps1_digest(), before.policy.tps1_digest());
    assert_eq!(evaluation.tps1_epoch(), before.policy.tps1_epoch());
    assert_eq!(
        evaluation.tps1_effective_position(),
        before.policy.tps1_effective_position()
    );
    assert_eq!(Some(evaluation.ptr1_floor()), before.policy.ptr1_floor());
    assert_eq!(Some(evaluation.prv1_floor()), before.policy.prv1_floor());
    assert_eq!(evaluation.trusted_utc_second(), 60);
    assert_eq!(evaluation.tick(), 8);
    assert_eq!(evaluation.activation_event(), active.activation_event());
    // Nothing moved: not the policy, the ledger, the pointer, the Events, nor the UTC floor.
    assert_eq!(h.snapshot(&[&one])?, before);
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(50));
    // The value is plain data: a second evaluation is equal.
    assert_eq!(h.evaluate(&later, &one)??, evaluation);
    Ok(())
}

// ---------------------------------------------------------------------------
// EV2: the precedence table (public rows)
// ---------------------------------------------------------------------------

#[test]
fn an_unprovisioned_scope_is_missing_state_before_anything_else() -> TestResult {
    let (store, _timeline, _guard) = bound_store::<Store>()?;
    let env = Env::new("scope")?;
    let genesis = env.genesis()?;
    let result = store.evaluate_current_release(
        &env.anchor,
        b"garbage",
        &genesis.evidence,
        &unauthorized().projection()?,
        genesis.trusted()?,
        genesis.tick + 1,
    );
    assert_eq!(result, Err(RegistryError::MissingState));
    Ok(())
}

#[test]
fn the_anchor_and_the_utc_floor_precede_tps1_authentication() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let stale_clock = h.same_policy(40, 5)?;
    let bad = unauthorized();
    for anchor in h.env.anchors_with_one_changed_field()? {
        let result = h.store.evaluate_current_release(
            &anchor,
            b"garbage",
            &stale_clock.evidence,
            &bad.projection()?,
            stale_clock.trusted()?,
            stale_clock.tick,
        );
        assert_eq!(result, Err(RegistryError::AnchorMismatch));
    }
    // A UTC second below the retained highest, with garbage TPS1 bytes and an unauthorized
    // release, is a regression and nothing else.
    assert_eq!(
        h.evaluate_raw(b"garbage", &stale_clock, &bad, 49, 6)?,
        Err(RegistryError::TrustedTimeRegressed)
    );
    // The equal second is accepted by the clock check and reaches the TPS1 authentication.
    assert_eq!(
        h.evaluate_raw(b"garbage", &genesis, &bad, 50, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::InvalidSnapshot))
    );
    Ok(())
}

#[test]
fn tps1_authentication_and_continuity_precede_the_bridge() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let bad = unauthorized();
    // Another scope's TPS1 under the same operator key authenticates as the wrong scope.
    let foreign = Env::new("other-scope")?.genesis()?;
    assert_eq!(
        h.evaluate_raw(&foreign.tps1, &genesis, &bad, 50, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::ScopeMismatch))
    );
    // A different epoch-1 TPS1 is not newer than the retained one.
    let same_epoch = h.env.material(
        &Spec::default(),
        &TpsSpec {
            position: 10,
            ..TpsSpec::default()
        },
    )?;
    assert_ne!(same_epoch.tps1, genesis.tps1);
    assert_eq!(
        h.evaluate_raw(&same_epoch.tps1, &genesis, &bad, 50, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::StaleSnapshot))
    );
    // A newer TPS1 that does not name the retained one as its predecessor.
    let orphan = h.env.material(
        &spec(1, 2).at(51, 6),
        &TpsSpec {
            previous: Some([9; 32]),
            ..TpsSpec::default()
        },
    )?;
    assert_eq!(
        h.evaluate_raw(&orphan.tps1, &genesis, &bad, 50, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::SnapshotDiscontinuity))
    );
    // A valid successor is not adopted by an evaluation, whatever else is wrong with the call.
    let next = h.env.material(&spec(1, 2).at(51, 6), &tps_after(&genesis))?;
    assert_eq!(
        h.evaluate_raw(&next.tps1, &next, &bad, 55, 9)?,
        Err(RegistryError::PolicyNotAdvanced)
    );
    // A TPS1 signed by another operator key fails the pinned key, with the stale bridge
    // evidence, the wrong coordinates, and the unauthorized release failing later steps too.
    let forged = tps1_signed_by(
        &h.env.scope,
        &genesis.evidence,
        &TpsSpec::default(),
        &foreign_operator_signer(),
    )?;
    assert_eq!(
        h.evaluate_raw(&forged, &next, &bad, 55, 9)?,
        Err(bridge(PluginTrustBridgeErrorV1::InvalidOperatorSignature))
    );
    Ok(())
}

#[test]
fn the_bridge_checks_run_in_order_before_release_authorization() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let bad = unauthorized();
    let foreign = Env::new("other-scope")?.genesis()?;
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &foreign, &bad, 50, 5)?,
        Err(bridge(PluginTrustBridgeErrorV1::ScopeMismatch))
    );
    // Evidence of epoch 2 against the retained epoch-1 TPS1, with the wrong coordinates too.
    let next = h.env.material(&spec(1, 2).at(51, 6), &tps_after(&genesis))?;
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &next, &bad, 55, 9)?,
        Err(bridge(PluginTrustBridgeErrorV1::EpochMismatch))
    );
    // The call's UTC second is checked before its Tick.
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &genesis, &bad, 51, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::EvaluationUtcMismatch))
    );
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &genesis, &bad, 50, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::EvaluationTickMismatch))
    );
    // With the bridge satisfied, release authorization names the failure.
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &genesis, &bad, 50, 5)?,
        Err(trust(PluginTrustErrorV1::PluginIdNotGranted))
    );
    Ok(())
}

#[test]
fn a_retained_tps1_that_is_expired_is_refused_before_release_authorization() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    // The TPS1 of epoch 2 is valid through second 60: adoptable at 51, expired from 60 on.
    let short = TpsSpec {
        offline_valid_through: "1970-01-01T00:01:00Z".to_owned(),
        ..tps_after(&genesis)
    };
    let adopted = h.env.material(&spec(1, 2).at(51, 6), &short)?;
    h.advance(&adopted)??;
    let one = release_one();
    assert!(h.evaluate(&adopted, &one)?.is_ok());
    let expired = h.env.material(&spec(1, 2).at(60, 6), &short)?;
    assert_eq!(expired.tps1, adopted.tps1);
    let bad = unauthorized();
    assert_eq!(
        h.evaluate(&expired, &bad)?,
        Err(bridge(PluginTrustBridgeErrorV1::Expired))
    );
    Ok(())
}

#[test]
fn release_authorization_precedes_the_tps1_artifact_denial_and_the_floor_plan() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    // The retained TPS1 denies the release digest, and the release also has an unknown key.
    let denying = TpsSpec {
        extra_artifacts: vec![one.release_digest()],
        ..tps_after(&genesis)
    };
    let adopted = h.env.material(&spec(1, 2).at(51, 6), &denying)?;
    h.advance(&adopted)??;
    let unknown_key = ManifestSpec {
        epoch: 3,
        ..release_one()
    };
    assert_eq!(
        h.evaluate(&adopted, &unknown_key)?,
        Err(trust(PluginTrustErrorV1::UnknownPublisherKey))
    );
    assert_eq!(
        h.evaluate(&adopted, &one)?,
        Err(bridge(PluginTrustBridgeErrorV1::TpsArtifactDenied))
    );
    // Other Trust failures also precede the denial, for releases the TPS1 denies.
    let at_sixty = h.env.material(&spec(1, 2).at(60, 6), &denying)?;
    let expired = ManifestSpec {
        not_after: 55,
        ..release_one()
    };
    assert_eq!(
        h.evaluate(&at_sixty, &expired)?,
        Err(trust(PluginTrustErrorV1::ManifestExpired))
    );
    let ungranted = ManifestSpec::new("plugin-z", 0x01, 0x11, None);
    assert_eq!(
        h.evaluate(&adopted, &ungranted)?,
        Err(trust(PluginTrustErrorV1::PluginIdNotGranted))
    );
    Ok(())
}

#[test]
fn a_forked_floor_precedes_the_active_pointer_check() -> TestResult {
    let h = admitted()?;
    // The same PRV1 epoch with another digest, under the identical retained TPS1.
    let fork = h.env.material(
        &Spec {
            revocation_variant: 1,
            ..Spec::default()
        },
        &TpsSpec::default(),
    )?;
    assert_eq!(fork.tps1, h.env.genesis()?.tps1);
    // `release_two` is not the active release either; the fork is reported first.
    assert_eq!(
        h.evaluate(&fork, &release_two())?,
        Err(RegistryError::Floor(PluginFloorErrorV1::Fork(
            PluginFloorKindV1::Revocation
        )))
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// EV3: the UTC floor is read, never raised
// ---------------------------------------------------------------------------

#[test]
fn the_utc_floor_is_enforced_but_never_raised_by_an_evaluation() -> TestResult {
    let h = admitted()?;
    let one = release_one();
    // Equal to the retained highest second is accepted; lower is a regression.
    assert!(h.evaluate(&h.same_policy(50, 5)?, &one)?.is_ok());
    h.assert_evaluate_denied(
        &h.same_policy(49, 5)?,
        &one,
        RegistryError::TrustedTimeRegressed,
    )?;
    // Above the highest second it succeeds and leaves the floor where it was.
    let above = h.evaluate(&h.same_policy(70, 5)?, &one)??;
    assert_eq!(above.trusted_utc_second(), 70);
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(50));
    // Two evaluations at decreasing seconds, both at or above the highest, both succeed.
    assert!(h.evaluate(&h.same_policy(65, 5)?, &one)?.is_ok());
    assert!(h.evaluate(&h.same_policy(55, 5)?, &one)?.is_ok());
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(50));
    Ok(())
}

// ---------------------------------------------------------------------------
// EV4: the evidence is bound to the call's coordinates
// ---------------------------------------------------------------------------

#[test]
fn evidence_built_at_other_coordinates_than_the_call_is_refused() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &genesis, &one, 51, 5)?,
        Err(bridge(PluginTrustBridgeErrorV1::EvaluationUtcMismatch))
    );
    assert_eq!(
        h.evaluate_raw(&genesis.tps1, &genesis, &one, 50, 6)?,
        Err(bridge(PluginTrustBridgeErrorV1::EvaluationTickMismatch))
    );
    assert_eq!(h.snapshot(&[&one])?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// EV5: active-pointer equality
// ---------------------------------------------------------------------------

#[test]
fn only_the_active_release_of_a_plugin_id_evaluates() -> TestResult {
    let mut h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    // Both floors exist and no pointer does.
    h.advance(&genesis)??;
    h.assert_evaluate_denied(&genesis, &one, RegistryError::ReleaseNotActive)?;
    h.admit(&genesis, &one, 1)??;
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    h.assert_evaluate_denied(&genesis, &two, RegistryError::ReleaseNotActive)?;
    // The direct successor replaces the predecessor.
    h.admit(&genesis, &two, 2)??;
    h.assert_evaluate_denied(&genesis, &one, RegistryError::ReleaseNotActive)?;
    let successor = h.evaluate(&genesis, &two)??;
    assert_eq!(successor.pmf1_digest(), [0x03; 32]);
    assert_eq!(successor.release_digest(), [0x12; 32]);
    assert_eq!(successor.previous_release_digest(), Some([0x11; 32]));
    // A rollback restores the predecessor.
    h.rollback(&genesis, &one, 3)??;
    h.assert_evaluate_denied(&genesis, &two, RegistryError::ReleaseNotActive)?;
    let restored = h.evaluate(&genesis, &one)??;
    assert_eq!(restored.pmf1_digest(), [0x01; 32]);
    assert_eq!(
        restored.activation_event(),
        h.active("plugin-a")?.activation_event()
    );
    // The same content signed again has another complete-PMF1 digest and is not the active one.
    let resigned = ManifestSpec::new("plugin-a", 0x21, 0x11, None);
    h.assert_evaluate_denied(&genesis, &resigned, RegistryError::ReleaseNotActive)?;
    // Another granted Plugin ID has no pointer at all.
    let other_plugin = ManifestSpec::new("plugin-b", 0x41, 0x31, None);
    h.assert_evaluate_denied(&genesis, &other_plugin, RegistryError::ReleaseNotActive)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// EV6: denials
// ---------------------------------------------------------------------------

#[test]
fn an_adopted_revocation_refuses_the_release_although_its_receipt_is_unchanged() -> TestResult {
    let one = release_one();
    let key = Spec {
        epochs: 2,
        revoked_publisher_epochs: vec![1],
        ..Spec::default().at(51, 6)
    };
    let artifact = Spec {
        epochs: 2,
        revoked_artifacts: vec![one.release_digest()],
        ..Spec::default().at(51, 6)
    };
    // A revocation that first takes effect at the evaluation Tick already refuses.
    let at_the_tick = Spec {
        revocation_tick: 6,
        ..artifact.clone()
    };
    let key_at_the_tick = Spec {
        revocation_tick: 6,
        ..key.clone()
    };
    let cases = [
        (key, PluginTrustErrorV1::PublisherKeyRevoked),
        (key_at_the_tick, PluginTrustErrorV1::PublisherKeyRevoked),
        (artifact, PluginTrustErrorV1::ArtifactRevoked),
        (at_the_tick, PluginTrustErrorV1::ArtifactRevoked),
    ];
    for (revoking, expected) in cases {
        let mut h = admitted()?;
        let genesis = h.env.genesis()?;
        let before = h.snapshot(&[&one])?;
        let material = h.env.material(&revoking, &tps_after(&genesis))?;
        h.advance(&material)??;
        h.assert_evaluate_denied(&material, &one, trust(expected))?;
        // The stored decision and pointer still describe the release: no receipt gives authority.
        let after = h.snapshot(&[&one])?;
        assert_eq!(after.decisions, before.decisions);
        assert_eq!(after.active, before.active);
    }
    Ok(())
}

#[test]
fn a_revocation_that_takes_effect_after_the_evaluation_tick_does_not_refuse() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let pending = h.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![one.release_digest()],
            revocation_tick: 7,
            ..Spec::default().at(51, 6)
        },
        &tps_after(&genesis),
    )?;
    h.advance(&pending)??;
    assert!(h.evaluate(&pending, &one)?.is_ok());
    Ok(())
}

#[test]
fn a_tps1_only_artifact_denial_refuses_the_release() -> TestResult {
    let one = release_one();
    // The PMF1 digest, the release digest, and a descriptor digest.
    for denied in [[0x01; 32], [0x11; 32], [0x30; 32]] {
        let mut h = admitted()?;
        let genesis = h.env.genesis()?;
        let tps = TpsSpec {
            extra_artifacts: vec![denied],
            ..tps_after(&genesis)
        };
        let material = h.env.material(&spec(1, 2).at(51, 6), &tps)?;
        h.advance(&material)??;
        h.assert_evaluate_denied(
            &material,
            &one,
            bridge(PluginTrustBridgeErrorV1::TpsArtifactDenied),
        )?;
    }
    Ok(())
}

#[test]
fn an_expired_unknown_or_ungranted_release_is_refused_without_any_adoption() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let at_sixty = h.same_policy(60, 5)?;
    let short_lived = ManifestSpec {
        not_after: 55,
        ..release_one()
    };
    h.assert_evaluate_denied(
        &at_sixty,
        &short_lived,
        trust(PluginTrustErrorV1::ManifestExpired),
    )?;
    // The same release is still inside its interval one second earlier.
    assert!(h.evaluate(&h.same_policy(54, 5)?, &short_lived)?.is_ok());
    let unknown_key = ManifestSpec {
        epoch: 3,
        ..release_one()
    };
    h.assert_evaluate_denied(
        &genesis,
        &unknown_key,
        trust(PluginTrustErrorV1::UnknownPublisherKey),
    )?;
    h.assert_evaluate_denied(
        &genesis,
        &unauthorized(),
        trust(PluginTrustErrorV1::PluginIdNotGranted),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// EV7: policy adoption
// ---------------------------------------------------------------------------

#[test]
fn a_valid_successor_policy_is_refused_until_it_is_adopted() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let next = h.env.material(&spec(1, 2).at(51, 6), &tps_after(&genesis))?;
    // New evidence with new bytes that the registry never adopted.
    h.assert_evaluate_denied(&next, &one, RegistryError::PolicyNotAdvanced)?;
    // The old evidence with the retained bytes still succeeds.
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    // New evidence with the retained bytes does not agree with the retained epoch.
    assert_eq!(
        h.evaluate_bytes(&genesis.tps1, &next, &one)?,
        Err(bridge(PluginTrustBridgeErrorV1::EpochMismatch))
    );
    h.advance(&next)??;
    // After the adoption the old bytes are stale and the new bytes with new evidence succeed.
    let old_again = h.same_policy(52, 6)?;
    assert_eq!(old_again.tps1, genesis.tps1);
    assert_eq!(
        h.evaluate(&old_again, &one)?,
        Err(bridge(PluginTrustBridgeErrorV1::StaleSnapshot))
    );
    assert!(h.evaluate(&next, &one)?.is_ok());
    Ok(())
}

#[test]
fn a_scope_that_was_provisioned_but_never_adopted_is_not_advanced() -> TestResult {
    let h = Harness::<Store>::open()?;
    let genesis = h.env.genesis()?;
    // Absent floors are refused as unadopted policy, before the missing pointer is noticed.
    h.assert_evaluate_denied(&genesis, &release_one(), RegistryError::PolicyNotAdvanced)
}

#[test]
fn older_root_evidence_and_a_pending_revocation_disagree_with_the_retained_tps1() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let bad = unauthorized();
    // The retained policy is PTR1 version 2, PRV1 epoch 2.
    let newer = h.env.material(&spec(2, 2).at(51, 6), &tps_after(&genesis))?;
    h.advance(&newer)??;
    // Evidence of PTR1 version 1 with the same key set against the retained version-2 TPS1; the
    // unauthorized release would fail the next step, so the bridge error comes first.
    let older = h.env.material(&spec(1, 2).at(52, 7), &tps_after(&genesis))?;
    assert_eq!(
        h.evaluate_bytes(&newer.tps1, &older, &bad)?,
        Err(bridge(PluginTrustBridgeErrorV1::BridgeRootMismatch))
    );

    // A revocation that is already in the retained PRV1 epoch with a future effective Tick is
    // absent from the retained TPS1 until then.
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let pending = Spec {
        epochs: 2,
        revoked_artifacts: vec![[0x77; 32]],
        revocation_tick: 9,
        ..Spec::default()
    };
    let retained = h.env.material(&pending.at(51, 6), &tps_after(&genesis))?;
    h.advance(&retained)??;
    assert!(h.evaluate(&retained, &one)?.is_ok());
    let effective = h.env.material(&pending.at(52, 9), &tps_after(&genesis))?;
    assert_eq!(
        h.evaluate_bytes(&retained.tps1, &effective, &bad)?,
        Err(bridge(PluginTrustBridgeErrorV1::BridgeRevocationMismatch))
    );
    Ok(())
}

#[test]
fn the_bridge_reports_expiry_then_root_then_revocation_mappings() -> TestResult {
    let bad = unauthorized();
    // Expiry precedes the root mapping: the retained TPS1 of PTR1 version 2 is valid through
    // second 60, and the evidence at second 60 is of version 1.
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let short = TpsSpec {
        offline_valid_through: "1970-01-01T00:01:00Z".to_owned(),
        ..tps_after(&genesis)
    };
    let newer = h.env.material(&spec(2, 2).at(51, 6), &short)?;
    h.advance(&newer)??;
    let older = h.env.material(&spec(1, 2).at(60, 7), &short)?;
    assert_ne!(older.tps1, newer.tps1);
    assert_eq!(
        h.evaluate_bytes(&newer.tps1, &older, &bad)?,
        Err(bridge(PluginTrustBridgeErrorV1::Expired))
    );

    // The root mapping precedes the revocation mapping: version-1 evidence against the retained
    // version-2 TPS1, with a revocation that became effective and is absent from that TPS1.
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let pending = Spec {
        roots: 2,
        epochs: 2,
        revoked_artifacts: vec![[0x77; 32]],
        revocation_tick: 9,
        ..Spec::default()
    };
    let retained = h.env.material(&pending.at(51, 6), &tps_after(&genesis))?;
    h.advance(&retained)??;
    let both = Spec {
        roots: 1,
        ..pending
    };
    let failing = h.env.material(&both.at(52, 9), &tps_after(&genesis))?;
    assert_eq!(
        h.evaluate_bytes(&retained.tps1, &failing, &bad)?,
        Err(bridge(PluginTrustBridgeErrorV1::BridgeRootMismatch))
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// EV8: scope isolation and the anchor
// ---------------------------------------------------------------------------

/// Evaluate `manifest` in the scope of `env`, which may differ from the harness scope.
fn evaluate_in(
    h: &Harness<Store>,
    env: &Env,
    material: &Material,
    manifest: &ManifestSpec,
) -> TestResult<Registry<CurrentReleaseEvaluationV1>> {
    Ok(h.store.evaluate_current_release(
        &env.anchor,
        &material.tps1,
        &material.evidence,
        &manifest.projection()?,
        material.trusted()?,
        material.tick,
    ))
}

#[test]
fn scopes_evaluate_independently() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    let other = Env::new("other-scope")?;
    let other_genesis = other.genesis()?;
    // An unprovisioned scope is missing while the provisioned scope is unaffected.
    assert_eq!(
        evaluate_in(&h, &other, &other_genesis, &one)?,
        Err(RegistryError::MissingState)
    );
    assert!(h.evaluate(&genesis, &one)?.is_ok());
    // The same PMF1 digest becomes active in a second scope.
    h.store.provision(&other.anchor, &other.genesis_tps1)?;
    h.store.admit(
        &other.anchor,
        &other_genesis.tps1,
        &other_genesis.evidence,
        &one.projection()?,
        other_genesis.trusted()?,
        other_genesis.tick,
        activation(h.timeline, 2),
    )?;
    let in_other = evaluate_in(&h, &other, &other_genesis, &one)??;
    assert_eq!(in_other.scope(), "other-scope");
    assert_eq!(in_other.pmf1_digest(), [0x01; 32]);
    assert_eq!(h.evaluate(&genesis, &one)??.scope(), "scope");
    // Replacing the release in the first scope leaves the second scope's pointer alone.
    h.admit(&genesis, &two, 3)??;
    h.assert_evaluate_denied(&genesis, &one, RegistryError::ReleaseNotActive)?;
    assert!(evaluate_in(&h, &other, &other_genesis, &one)?.is_ok());
    assert_eq!(
        evaluate_in(&h, &other, &other_genesis, &two)?,
        Err(RegistryError::ReleaseNotActive)
    );
    Ok(())
}

#[test]
fn every_anchor_field_is_compared() -> TestResult {
    let h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let projection = one.projection()?;
    for anchor in h.env.anchors_with_one_changed_field()? {
        let result = h.store.evaluate_current_release(
            &anchor,
            &genesis.tps1,
            &genesis.evidence,
            &projection,
            genesis.trusted()?,
            genesis.tick,
        );
        assert_eq!(result, Err(RegistryError::AnchorMismatch));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EV11: the policy facts come from the retained policy, not the decision
// ---------------------------------------------------------------------------

#[test]
fn the_policy_facts_follow_the_retained_policy_after_an_adoption() -> TestResult {
    let mut h = admitted()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let newer = h.env.material(&spec(2, 2).at(52, 7), &tps_after(&genesis))?;
    h.advance(&newer)??;
    let decision = h
        .store
        .retained_release_decision("scope", one.pmf1_digest())?
        .ok_or("no decision")?;
    let evaluation = h.evaluate(&newer, &one)??;
    // The release facts are the decision's.
    assert_eq!(evaluation.pmf1_digest(), decision.pmf1_digest());
    assert_eq!(evaluation.release_digest(), decision.release_digest());
    assert_eq!(evaluation.activation_event(), decision.activation_event());
    // The policy facts are the adopted ones, which differ from the decision's own.
    assert_eq!(evaluation.tps1_digest(), newer.tps1_digest());
    assert_eq!(evaluation.tps1_epoch(), 2);
    assert_eq!(evaluation.ptr1_floor(), newer.terminal_root());
    assert_eq!(evaluation.prv1_floor(), newer.terminal_revocation());
    assert_eq!(decision.tps1_digest(), genesis.tps1_digest());
    assert_eq!(decision.tps1_epoch(), 1);
    assert_ne!(decision.terminal_root(), newer.terminal_root());
    assert_eq!(evaluation.trusted_utc_second(), 52);
    assert_eq!(evaluation.tick(), 7);
    Ok(())
}
