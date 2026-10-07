//! Public acceptance vectors for the ADR-103 revision 4 Plugin trust policy registry port on
//! the Memory adapter (slice #568): C1, D1-D3, E1-E3, and F1-F2.
//!
//! Every expected value is stated independently of the registry: digests are
//! recomputed by the shared fixture from the public encodings, and each
//! denial names the exact error variant the accepted contract assigns it.
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

use std::time::Duration;

use fixtures::{
    activation, bound_store, digest, release_one, release_three, release_two, spec, tps_after,
    trusted, Env, Harness, ManifestSpec, RegistryError, Spec, TestResult, TpsSpec, TICK, UTC,
};
use pos_conformance::{PluginFloorErrorV1, PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::{ScriptedTrustedWallSourceV1, ScriptedWallSampleV1},
    CanonicalBytes, CorrelationId, EntityId, EventDraft, EventId, Hash, Hasher, Kind, Seq,
    TimelineId,
};
use pos_crypto::plugin_trust::PluginTrustErrorV1;
use pos_store::{
    memory::MemoryStore,
    plugin_trust_registry::{
        ActivationEventInputV1, PluginTrustCommitOutcomeV1, PluginTrustLedgerKindV1,
        PluginTrustPolicyRegistryV1, PolicyAdvanceKindV1, ProvisionOutcomeV1, TrustedUtcSecondV1,
    },
};

// ---------------------------------------------------------------------------
// C1: the trusted UTC second
// ---------------------------------------------------------------------------

#[test]
fn utc_second_floors_microseconds_at_the_boundaries() -> TestResult {
    let sample = |micros: u64| {
        TrustedUtcSecondV1::from_source(&mut ScriptedTrustedWallSourceV1::from_micros([micros]))
    };
    for (micros, second) in [
        (0, 0),
        (1, 0),
        (999_999, 0),
        (1_000_000, 1),
        (1_000_001, 1),
        (1_999_999, 1),
        (2_000_000, 2),
        (1_234_567_890_123_456, 1_234_567_890),
    ] {
        assert_eq!(sample(micros)?.as_i64(), second);
    }
    let largest = u64::try_from(i64::MAX)?;
    assert_eq!(sample(largest)?.as_i64(), 9_223_372_036_854);
    assert!(sample(1_000_000)? < sample(2_000_000)?);
    assert_eq!(sample(3_000_000)?, sample(3_999_999)?);
    Ok(())
}

#[test]
fn utc_second_fails_closed_when_the_source_fails() -> TestResult {
    let above_bound = u64::try_from(i64::MAX)? + 1;
    let mut sources = [
        ScriptedTrustedWallSourceV1::from_micros([above_bound]),
        ScriptedTrustedWallSourceV1::from_micros(std::iter::empty()),
        ScriptedTrustedWallSourceV1::new([ScriptedWallSampleV1::Unavailable]),
        ScriptedTrustedWallSourceV1::new([ScriptedWallSampleV1::System(
            std::time::UNIX_EPOCH - Duration::from_secs(1),
        )]),
    ];
    for source in &mut sources {
        assert_eq!(
            TrustedUtcSecondV1::from_source(source),
            Err(RegistryError::TrustedTimeUnavailable)
        );
    }
    Ok(())
}

#[test]
fn utc_second_samples_the_source_exactly_once() -> TestResult {
    let mut source = ScriptedTrustedWallSourceV1::from_micros([5_000_000, 6_000_000]);
    assert_eq!(TrustedUtcSecondV1::from_source(&mut source)?.as_i64(), 5);
    assert_eq!(source.remaining(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// D1: provisioning
// ---------------------------------------------------------------------------

#[test]
fn provisioning_creates_a_scope_with_no_floors_clock_or_release() -> TestResult {
    let (mut store, _timeline) = bound_store()?;
    let env = Env::new("scope")?;
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Created)
    );
    let policy = store.retained_policy_state("scope")?;
    assert_eq!(policy.scope(), "scope");
    assert_eq!(policy.tps1_epoch(), 1);
    assert_eq!(policy.tps1_digest(), digest(&env.genesis_tps1));
    assert_eq!(policy.tps1_effective_position(), 9);
    assert_eq!(policy.tps1_bytes(), env.genesis_tps1.as_slice());
    assert_eq!(policy.ptr1_floor(), None);
    assert_eq!(policy.prv1_floor(), None);
    assert_eq!(policy.highest_trusted_utc_second(), None);
    let ledger = store.ledger("scope")?;
    assert_eq!(ledger.len(), 1);
    let row = &ledger[0];
    assert_eq!(row.row_seq(), 1);
    assert_eq!(row.kind(), PluginTrustLedgerKindV1::Provision);
    assert_eq!(row.tps1_digest(), digest(&env.genesis_tps1));
    assert_eq!(row.tps1_epoch(), 1);
    assert_eq!(row.tps1_effective_position(), 9);
    assert_eq!(row.ptr1_floor(), None);
    assert_eq!(row.prv1_floor(), None);
    assert_eq!(row.trusted_utc_second(), None);
    assert_eq!(row.tick(), None);
    assert_eq!(row.plugin_id(), None);
    assert_eq!(row.pmf1_digest(), None);
    assert_eq!(row.release_digest(), None);
    assert_eq!(row.previous_active_pmf1_digest(), None);
    assert_eq!(row.activation_event(), None);
    assert_eq!(store.active_release("scope", "plugin-a")?, None);
    assert_eq!(store.retained_release_decision("scope", [1; 32])?, None);
    Ok(())
}

#[test]
fn identical_reprovisioning_is_unchanged_and_writes_no_row() -> TestResult {
    let mut h = Harness::new()?;
    let before = h.snapshot(&[])?;
    assert_eq!(
        h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Unchanged)
    );
    assert_eq!(h.snapshot(&[])?, before);
    assert_eq!(h.ledger()?.len(), 1);
    Ok(())
}

#[test]
fn provisioning_accepts_only_the_pinned_genesis_snapshot() -> TestResult {
    let (mut store, _timeline) = bound_store()?;
    let env = Env::new("scope")?;
    let genesis_digest = digest(&env.genesis_tps1);
    let later = env.material(&spec(2, 2), &TpsSpec::after(genesis_digest))?;
    let other_genesis = env.material(
        &Spec::default(),
        &TpsSpec {
            position: 10,
            ..TpsSpec::default()
        },
    )?;
    let invalid_genesis = Err(RegistryError::Bridge(
        PluginTrustBridgeErrorV1::InvalidGenesis,
    ));
    for bytes in [&later.tps1, &other_genesis.tps1] {
        assert_eq!(store.provision(&env.anchor, bytes), invalid_genesis);
    }
    assert_eq!(
        store.ledger("scope"),
        Err(RegistryError::MissingState),
        "a refused provisioning creates nothing"
    );
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Created)
    );
    for bytes in [&later.tps1, &other_genesis.tps1] {
        assert_eq!(store.provision(&env.anchor, bytes), invalid_genesis);
    }
    Ok(())
}

#[test]
fn provisioning_rejects_an_unsigned_or_malformed_snapshot() -> TestResult {
    let (mut store, _timeline) = bound_store()?;
    let env = Env::new("scope")?;
    let mut tampered = env.genesis_tps1.clone();
    let last = tampered.last_mut().ok_or("empty TPS1")?;
    *last ^= 1;
    assert_eq!(
        store.provision(&env.anchor, &tampered),
        Err(RegistryError::Bridge(
            PluginTrustBridgeErrorV1::InvalidOperatorSignature
        ))
    );
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1[..5]),
        Err(RegistryError::Bridge(
            PluginTrustBridgeErrorV1::InvalidSnapshot
        ))
    );
    let foreign = Env::new("other")?;
    assert_eq!(
        store.provision(&env.anchor, &foreign.genesis_tps1),
        Err(RegistryError::Bridge(
            PluginTrustBridgeErrorV1::ScopeMismatch
        ))
    );
    assert_eq!(store.ledger("scope"), Err(RegistryError::MissingState));
    Ok(())
}

#[test]
fn a_changed_anchor_field_is_an_anchor_mismatch_in_every_operation() -> TestResult {
    // Two of the five anchor fields cannot mismatch: a different scope text is a new scope
    // (see the next vector), and the constructor fixes the operator role. The other three
    // fields are each varied alone.
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    let anchors = h.env.anchors_with_one_changed_field()?;
    assert_eq!(anchors.len(), 3);
    for anchor in &anchors {
        assert_ne!(anchor, &h.env.anchor);
        assert_eq!(
            h.store.provision(anchor, &h.env.genesis_tps1),
            Err(RegistryError::AnchorMismatch)
        );
        assert_eq!(
            h.store.advance_policy(
                anchor,
                &genesis.tps1,
                &genesis.evidence,
                genesis.trusted()?,
                genesis.tick
            ),
            Err(RegistryError::AnchorMismatch)
        );
        assert_eq!(
            h.store.admit(
                anchor,
                &genesis.tps1,
                &genesis.evidence,
                &one.projection()?,
                genesis.trusted()?,
                genesis.tick,
                activation(h.timeline, 1)
            ),
            Err(RegistryError::AnchorMismatch)
        );
        assert_eq!(
            h.store.rollback(
                anchor,
                &genesis.tps1,
                &genesis.evidence,
                &one.projection()?,
                genesis.trusted()?,
                genesis.tick,
                activation(h.timeline, 1)
            ),
            Err(RegistryError::AnchorMismatch)
        );
    }
    assert_eq!(h.snapshot(&[&one])?, before);
    Ok(())
}

#[test]
fn another_scope_text_is_a_new_scope_not_a_mismatch() -> TestResult {
    let mut h = Harness::new()?;
    let other = Env::new("scope-two")?;
    assert_eq!(
        h.store.provision(&other.anchor, &other.genesis_tps1),
        Ok(ProvisionOutcomeV1::Created)
    );
    assert_eq!(h.store.ledger("scope-two")?.len(), 1);
    assert_eq!(h.store.ledger("scope")?.len(), 1);
    Ok(())
}

#[test]
fn reprovisioning_after_the_policy_advanced_leaves_the_later_snapshot() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let later = h.env.material(&spec(2, 2), &tps_after(&genesis))?;
    h.advance(&later)??;
    let before = h.snapshot(&[])?;
    assert_eq!(before.policy.tps1_epoch(), 2);
    assert_eq!(
        h.store.provision(&h.env.anchor, &h.env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Unchanged)
    );
    assert_eq!(h.snapshot(&[])?, before);
    assert_eq!(h.policy()?.tps1_bytes(), later.tps1.as_slice());
    Ok(())
}

// ---------------------------------------------------------------------------
// D2: the highest trusted UTC second
// ---------------------------------------------------------------------------

#[test]
fn utc_floor_is_raised_by_every_committed_transaction_and_replay() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    assert_eq!(h.policy()?.highest_trusted_utc_second(), None);

    h.admit(&genesis, &one, 1)??;
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(50));

    // Equal is accepted; a no-op advance raises the floor but writes no ledger row.
    let rows = h.ledger()?.len();
    let noop = h.advance(&h.same_policy(50, 5)?)??;
    assert_eq!(noop.outcome, PolicyAdvanceKindV1::Unchanged);
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(50));
    h.advance(&h.same_policy(51, 6)?)??;
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(51));
    assert_eq!(h.ledger()?.len(), rows);

    // A lower second fails closed in every operation and changes nothing.
    let before = h.snapshot(&[&one])?;
    let lower = h.same_policy(50, 5)?;
    assert_eq!(h.advance(&lower)?, Err(RegistryError::TrustedTimeRegressed));
    assert_eq!(
        h.admit(&lower, &two, 2)?,
        Err(RegistryError::TrustedTimeRegressed)
    );
    assert_eq!(
        h.rollback(&lower, &one, 2)?,
        Err(RegistryError::TrustedTimeRegressed)
    );
    assert_eq!(h.snapshot(&[&one])?, before);

    // A denied admission does not ratchet the floor.
    let mut expired = release_two();
    expired.not_after = 60;
    assert_eq!(
        h.admit(&h.same_policy(60, 7)?, &expired, 2)?,
        Err(RegistryError::Trust(PluginTrustErrorV1::ManifestExpired))
    );
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(51));

    // A committed admission, a replay, a rollback, and a rollback replay raise it.
    h.admit(&h.same_policy(52, 8)?, &two, 2)??;
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(52));
    let replay = h.admit(&h.same_policy(53, 9)?, &two, 2)??;
    assert_eq!(
        replay.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(53));
    h.rollback(&h.same_policy(54, 10)?, &one, 3)??;
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(54));
    let replayed = h.rollback(&h.same_policy(55, 11)?, &one, 3)??;
    assert_eq!(
        replayed.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(55));

    // A committed advance raises it too.
    let later = h
        .env
        .material(&spec(2, 2).at(56, 12), &tps_after(&genesis))?;
    assert_eq!(h.advance(&later)??.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(h.policy()?.highest_trusted_utc_second(), Some(56));
    Ok(())
}

// ---------------------------------------------------------------------------
// D3: the evidence coordinates must equal the transaction's
// ---------------------------------------------------------------------------

#[test]
fn evidence_coordinates_must_equal_the_trusted_utc_and_tick() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    let utc_mismatch = RegistryError::Bridge(PluginTrustBridgeErrorV1::EvaluationUtcMismatch);
    let tick_mismatch = RegistryError::Bridge(PluginTrustBridgeErrorV1::EvaluationTickMismatch);
    for (second, tick, expected) in [
        (UTC + 1, TICK, utc_mismatch),
        (UTC - 1, TICK, utc_mismatch),
        (UTC, TICK + 1, tick_mismatch),
        (UTC, TICK - 1, tick_mismatch),
        (UTC + 1, TICK + 1, utc_mismatch),
    ] {
        let utc = trusted(second)?;
        assert_eq!(
            h.store
                .advance_policy(&h.env.anchor, &genesis.tps1, &genesis.evidence, utc, tick),
            Err(expected)
        );
        assert_eq!(
            h.store.admit(
                &h.env.anchor,
                &genesis.tps1,
                &genesis.evidence,
                &one.projection()?,
                utc,
                tick,
                activation(h.timeline, 1)
            ),
            Err(expected)
        );
        assert_eq!(
            h.store.rollback(
                &h.env.anchor,
                &genesis.tps1,
                &genesis.evidence,
                &one.projection()?,
                utc,
                tick,
                activation(h.timeline, 1)
            ),
            Err(expected)
        );
    }
    assert_eq!(h.snapshot(&[&one])?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// E1: the scoped release chain
// ---------------------------------------------------------------------------

#[test]
fn release_chain_allows_first_same_content_and_direct_successor_only() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let mut resigned = ManifestSpec::new("plugin-a", 0x02, 0x11, None);
    resigned.epoch = 2;

    // Rule 1: the first activation of a Plugin ID.
    assert_eq!(h.store.active_release("scope", "plugin-a")?, None);
    let first = h.admit(&genesis, &release_one(), 1)??;
    assert_eq!(first.outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x01; 32]);
    assert_eq!(h.active("plugin-a")?.release_digest(), [0x11; 32]);

    // Rule 2: the same content re-signed under a later publisher key epoch.
    h.admit(&genesis, &resigned, 2)??;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x02; 32]);
    assert_eq!(h.active("plugin-a")?.release_digest(), [0x11; 32]);

    // Rule 3: the direct successor of the active release.
    h.admit(&genesis, &release_two(), 3)??;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x03; 32]);
    assert_eq!(h.active("plugin-a")?.release_digest(), [0x12; 32]);

    let rows = h.ledger()?;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[1].previous_active_pmf1_digest(), None);
    assert_eq!(rows[2].previous_active_pmf1_digest(), Some([0x01; 32]));
    assert_eq!(rows[3].previous_active_pmf1_digest(), Some([0x02; 32]));
    Ok(())
}

#[test]
fn release_chain_rejects_a_never_seen_older_release_and_a_sibling_fork() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &release_one(), 1)??;
    h.admit(&genesis, &release_two(), 2)??;
    let older = ManifestSpec::new("plugin-a", 0x04, 0x10, None);
    let sibling = ManifestSpec::new("plugin-a", 0x06, 0x14, Some(0x11));
    let unlinked_successor = ManifestSpec::new("plugin-a", 0x07, 0x15, Some(0x99));
    for manifest in [&older, &sibling, &unlinked_successor] {
        h.assert_admit_denied(&genesis, manifest, RegistryError::ReleaseChainViolation)?;
    }
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x03; 32]);
    Ok(())
}

#[test]
fn release_chain_is_independent_per_plugin_id_and_per_scope() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    h.admit(&genesis, &release_one(), 1)??;
    h.admit(&genesis, &release_two(), 2)??;

    // Another Plugin ID has its own chain: its first activation needs no link.
    h.admit(
        &genesis,
        &ManifestSpec::new("plugin-b", 0x21, 0x31, None),
        3,
    )??;
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x03; 32]);
    assert_eq!(h.active("plugin-b")?.pmf1_digest(), [0x21; 32]);
    assert_eq!(h.active("plugin-b")?.plugin_id(), "plugin-b");

    // Another scope has its own pointers and decisions, even for the same PMF1 digest.
    let other = Env::new("scope-two")?;
    h.store.provision(&other.anchor, &other.genesis_tps1)?;
    let other_genesis = other.genesis()?;
    assert_eq!(h.store.active_release("scope-two", "plugin-a")?, None);
    let receipt = h.store.admit(
        &other.anchor,
        &other_genesis.tps1,
        &other_genesis.evidence,
        &release_one().projection()?,
        other_genesis.trusted()?,
        other_genesis.tick,
        activation(h.timeline, 9),
    )?;
    assert_eq!(receipt.decision().scope(), "scope-two");
    let in_two = h
        .store
        .active_release("scope-two", "plugin-a")?
        .ok_or("no pointer")?;
    assert_eq!(in_two.pmf1_digest(), [0x01; 32]);
    assert_eq!(in_two.scope(), "scope-two");
    assert!(h
        .store
        .retained_release_decision("scope", [0x03; 32])?
        .is_some());
    assert_eq!(
        h.store.retained_release_decision("scope-two", [0x03; 32])?,
        None
    );
    assert_eq!(h.store.ledger("scope-two")?.len(), 2);
    Ok(())
}

#[test]
fn the_disclosed_chain_deadlock_needs_a_publisher_relink() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    h.admit(&genesis, &one, 1)??;
    h.admit(&genesis, &two, 2)??;
    h.rollback(&genesis, &one, 3)??;

    // R3 links to R2, but the active release is R1.
    h.assert_admit_denied(
        &genesis,
        &release_three(),
        RegistryError::ReleaseChainViolation,
    )?;

    // R2 later became revoked, so rolling back to it is denied too.
    let revoked = h.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![two.release_digest()],
            ..Spec::default()
        },
        &tps_after(&genesis),
    )?;
    h.assert_rollback_denied(
        &revoked,
        &two,
        RegistryError::Trust(PluginTrustErrorV1::ArtifactRevoked),
    )?;

    // A release re-linked to R1 is accepted.
    h.admit(
        &genesis,
        &ManifestSpec::new("plugin-a", 0x08, 0x16, Some(0x11)),
        4,
    )??;
    Ok(())
}

// ---------------------------------------------------------------------------
// E2 and E3: the activation Event
// ---------------------------------------------------------------------------

#[test]
fn every_decision_and_rollback_carries_its_activation_event_identity() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let admitted = h.admit(&genesis, &release_one(), 1)??;
    let second = h.admit(&genesis, &release_two(), 2)??;
    let rolled = h.rollback(&genesis, &release_one(), 3)??;
    let events = h.events()?;
    assert_eq!(events.len(), 3);
    let identities = [
        admitted.decision().activation_event(),
        second.decision().activation_event(),
        rolled.activation_event(),
    ];
    for (identity, event) in identities.into_iter().zip(&events) {
        assert_eq!(identity.timeline_id(), h.timeline);
        assert_eq!(identity.event_id(), event.id);
        assert_eq!(identity.seq(), event.seq);
        assert_eq!(identity.event_type(), "plugin.activation.v1");
        assert_eq!(identity.event_type(), event.event_type.as_str());
        assert_eq!(identity.schema_version(), event.schema_version);
        assert_eq!(identity.payload_digest(), *event.payload_hash.as_bytes());
    }
    assert_eq!(
        h.active("plugin-a")?.activation_event(),
        rolled.activation_event()
    );
    assert_eq!(
        rolled.activation_event().seq(),
        Seq::from_u64(3),
        "a rollback commits its own Event"
    );
    Ok(())
}

#[test]
fn the_identity_sequence_is_the_logical_timeline_sequence() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    for tag in [100, 101] {
        h.store
            .append(h.timeline, &[activation(h.timeline, tag).draft])?;
    }
    let receipt = h.admit(&genesis, &release_one(), 1)??;
    let identity = receipt.decision().activation_event();
    assert_eq!(identity.seq(), Seq::from_u64(3));
    let events = h.events()?;
    let event = events.last().ok_or("no event")?;
    assert_eq!(identity.event_id(), event.id);
    assert_eq!(identity.seq(), event.seq);
    assert_eq!(
        identity.origin_logical_seq(),
        event.origin.map(|origin| origin.origin_logical_seq)
    );
    assert_eq!(identity.origin_logical_seq(), Some(Seq::from_u64(3)));
    assert_eq!(
        identity.payload_digest(),
        digest(event.payload.as_slice()),
        "the digest is BLAKE3-256 of the payload"
    );
    Ok(())
}

#[test]
fn an_unknown_activation_timeline_leaves_the_state_byte_identical() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    let unknown = activation(TimelineId::new(), 1);
    assert_eq!(
        h.admit_with(&genesis, &one, unknown.clone())?,
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(h.snapshot(&[&one])?, before);
    h.admit(&genesis, &one, 1)??;
    let after_admit = h.snapshot(&[&one, &release_two()])?;
    assert_eq!(
        h.rollback_with(&genesis, &one, unknown)?,
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(h.snapshot(&[&one, &release_two()])?, after_admit);
    Ok(())
}

#[test]
fn a_geographic_activation_draft_is_rejected_like_a_generic_append() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let before = h.snapshot(&[&one])?;
    let geographic = ActivationEventInputV1 {
        timeline: h.timeline,
        draft: EventDraft::new(
            EntityId::new(),
            Kind::new("geo.location"),
            CanonicalBytes::from_vec(vec![1]),
        ),
    };
    assert_eq!(
        h.admit_with(&genesis, &one, geographic)?,
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(h.snapshot(&[&one])?, before);
    Ok(())
}

#[test]
fn a_store_without_an_erasure_gate_cannot_admit_or_roll_back() -> TestResult {
    let mut store = MemoryStore::new().without_erasure_gate();
    let env = Env::new("scope")?;
    store.provision(&env.anchor, &env.genesis_tps1)?;
    let timeline = TimelineId::new();
    let genesis = env.genesis()?;
    let one = release_one();
    let before = store.retained_policy_state("scope")?;
    assert_eq!(
        store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &one.projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(timeline, 1)
        ),
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(
        store.rollback(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &one.projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(timeline, 1)
        ),
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(store.retained_policy_state("scope")?, before);
    assert_eq!(store.ledger("scope")?.len(), 1);
    // Policy advancement carries no Event, so it still works.
    store.advance_policy(
        &env.anchor,
        &genesis.tps1,
        &genesis.evidence,
        genesis.trusted()?,
        genesis.tick,
    )?;
    Ok(())
}

#[test]
fn an_unbound_fail_closed_erasure_gate_refuses_the_activation_fence() -> TestResult {
    let mut store = MemoryStore::new();
    let timeline = store.create_timeline("unbound")?.id();
    let env = Env::new("scope")?;
    store.provision(&env.anchor, &env.genesis_tps1)?;
    let genesis = env.genesis()?;
    assert_eq!(
        store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &release_one().projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(timeline, 1)
        ),
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(store.ledger("scope")?.len(), 1);
    Ok(())
}

/// A hasher whose payload digest is not BLAKE3-256.
struct OffsetHasher;

impl Hasher for OffsetHasher {
    fn genesis_hash(&self) -> Hash {
        Hash::zero()
    }

    fn hash_payload(&self, payload: &CanonicalBytes) -> Hash {
        Hash::from_bytes(digest(&[payload.as_slice(), b"offset".as_slice()].concat()))
    }

    fn hash_event(
        &self,
        previous_hash: &Hash,
        event_id_bytes: &[u8],
        payload: &CanonicalBytes,
    ) -> Hash {
        pos_crypto::chain::hash_event(previous_hash, event_id_bytes, payload)
    }
}

#[test]
fn a_store_with_another_payload_hasher_can_never_activate() -> TestResult {
    let mut store = MemoryStore::with_hasher(Box::new(OffsetHasher));
    store.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    let timeline = store.create_timeline("offset")?.id();
    let env = Env::new("scope")?;
    store.provision(&env.anchor, &env.genesis_tps1)?;
    let genesis = env.genesis()?;
    let before = store.retained_policy_state("scope")?;
    assert_eq!(
        store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &release_one().projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(timeline, 1)
        ),
        Err(RegistryError::ActivationEventRejected)
    );
    assert_eq!(store.retained_policy_state("scope")?, before);
    assert!(store.read(timeline, SeqRange::all())?.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// F1 and F2: idempotency
// ---------------------------------------------------------------------------

#[test]
fn an_identical_admission_returns_the_original_receipt_and_commits_only_the_utc_raise() -> TestResult
{
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let first = h.admit(&genesis, &one, 1)??;
    let before = h.snapshot(&[&one])?;
    let replay = h.admit(&h.same_policy(51, 6)?, &one, 1)??;
    assert_eq!(
        replay.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(replay.decision(), first.decision());
    assert_eq!(replay.decision().trusted_utc_second(), 50);
    assert_eq!(replay.decision().tick(), 5);
    let after = h.snapshot(&[&one])?;
    assert_eq!(after.events, before.events);
    assert_eq!(after.ledger, before.ledger);
    assert_eq!(after.decisions, before.decisions);
    assert_eq!(after.active, before.active);
    assert_eq!(after.policy.highest_trusted_utc_second(), Some(51));
    assert_eq!(after.policy.tps1_bytes(), before.policy.tps1_bytes());
    assert_eq!(after.policy.ptr1_floor(), before.policy.ptr1_floor());
    Ok(())
}

#[test]
fn a_changed_event_identity_component_is_a_release_conflict() -> TestResult {
    // Each case changes exactly one component: the payload, the Timeline, or the event type.
    // The schema version has one value (`SchemaVersion::V1`), so it cannot be varied.
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    h.admit(&genesis, &one, 1)??;
    let second_timeline = h.store.create_timeline("second")?.id();
    let other_type = ActivationEventInputV1 {
        timeline: h.timeline,
        draft: EventDraft::new(
            EntityId::new(),
            Kind::new("plugin.other.v1"),
            CanonicalBytes::from_vec(vec![1]),
        ),
    };
    let before = h.snapshot(&[&one])?;
    for changed in [
        activation(h.timeline, 2),
        activation(second_timeline, 1),
        other_type,
    ] {
        assert_eq!(
            h.admit_with(&genesis, &one, changed)?,
            Err(RegistryError::ReleaseConflict)
        );
    }
    assert_eq!(h.snapshot(&[&one])?, before);
    Ok(())
}

#[test]
fn replay_ignores_the_fields_outside_the_identity() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let first = h.admit(&genesis, &one, 1)??;
    let mut retried = activation(h.timeline, 1);
    retried.draft.causation_id = Some(EventId::new());
    retried.draft.correlation_id = Some(CorrelationId::new());
    let replay = h.admit_with(&genesis, &one, retried)??;
    assert_eq!(replay.decision(), first.decision());
    assert_eq!(h.events()?.len(), 1);
    Ok(())
}

#[test]
fn newer_valid_evidence_conflicts_and_is_recorded_only_by_advance_policy() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    h.admit(&genesis, &one, 1)??;
    let newer = h
        .env
        .material(&spec(2, 2).at(51, 6), &tps_after(&genesis))?;
    h.assert_admit_denied(&newer, &one, RegistryError::ReleaseConflict)?;
    assert_eq!(h.policy()?.tps1_epoch(), 1);
    let advanced = h.advance(&newer)??;
    assert_eq!(advanced.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(h.policy()?.tps1_epoch(), 2);
    assert_eq!(h.policy()?.ptr1_floor(), Some(newer.terminal_root()));
    Ok(())
}

#[test]
fn older_or_forked_evidence_fails_in_its_own_step_before_the_stored_decision() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    h.admit(&genesis, &one, 1)??;
    let current = h
        .env
        .material(&spec(2, 2).at(51, 6), &tps_after(&genesis))?;
    h.advance(&current)??;

    // Older TPS1 and PRV1 evidence.
    let older = h.same_policy(52, 7)?;
    h.assert_admit_denied(
        &older,
        &one,
        RegistryError::Bridge(PluginTrustBridgeErrorV1::StaleSnapshot),
    )?;

    // An older PTR1 under a newer policy epoch.
    let older_root = h
        .env
        .material(&spec(1, 3).at(52, 7), &tps_after(&current))?;
    h.assert_admit_denied(
        &older_root,
        &one,
        RegistryError::Floor(PluginFloorErrorV1::Rollback(PluginFloorKindV1::Root)),
    )?;

    // The retained TPS1 with another PRV1 digest at the same epoch.
    let forked = h.env.material(
        &Spec {
            revocation_variant: 1,
            ..spec(2, 2).at(52, 7)
        },
        &tps_after(&genesis),
    )?;
    assert_eq!(forked.tps1, current.tps1);
    h.assert_admit_denied(
        &forked,
        &one,
        RegistryError::Floor(PluginFloorErrorV1::Fork(PluginFloorKindV1::Revocation)),
    )?;

    // A failed fresh validation returns its own error, never the stored decision.
    let regressed = h.same_policy(40, 4)?;
    h.assert_admit_denied(&regressed, &one, RegistryError::TrustedTimeRegressed)?;
    Ok(())
}

#[test]
fn readmitting_a_rolled_back_release_returns_its_original_receipt() -> TestResult {
    let mut h = Harness::new()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    h.admit(&genesis, &one, 1)??;
    let second = h.admit(&genesis, &two, 2)??;
    h.rollback(&h.same_policy(51, 6)?, &one, 3)??;
    let before = h.snapshot(&[&one, &two])?;
    let replay = h.admit(&h.same_policy(52, 7)?, &two, 2)??;
    assert_eq!(
        replay.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(replay.decision(), second.decision());
    let after = h.snapshot(&[&one, &two])?;
    assert_eq!(after.active, before.active);
    assert_eq!(after.events, before.events);
    assert_eq!(after.ledger, before.ledger);
    assert_eq!(h.active("plugin-a")?.pmf1_digest(), [0x01; 32]);
    Ok(())
}
