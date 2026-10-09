//! The shared signed-release test world at the public seam.
//!
//! These vectors exercise the parts of `pos_plugin_publisher::test_support`
//! that the installer vectors in `installer_public.rs` do not reach: a world
//! parametrised by Plugin, owner, Component, and validity interval, evidence
//! at expired coordinates and with revocations, registry policy advances that
//! revoke a publisher key or a release, and an operator rollback. Each helper
//! is checked against the real registry, not a stub.
#![cfg(target_os = "linux")]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use pos_conformance::{PluginFloorErrorV1, PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, ValidatedPluginManifestProjectionV1,
};
use pos_plugin_publisher::{
    test_support::{
        encoding::{Material, Spec, OWNER, SCOPE, TICK, UTC},
        release::{pmf1_digest, Shape, REAL_COMPONENT_BYTES},
        spy_registry::Call,
        world::{key_bytes, register, wall, Config, World},
        BoxResult,
    },
    PluginReleaseInstallErrorV1,
};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1};
use pos_store::plugin_trust_registry::{
    ActiveReleaseV1, PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1,
    PolicyAdvanceKindV1,
};
use sha2::{Digest as _, Sha256};

type TestResult = BoxResult<()>;

const fn authorization_error(error: PluginTrustErrorV1) -> PluginReleaseInstallErrorV1 {
    PluginReleaseInstallErrorV1::Authorization(error)
}

#[test]
fn a_world_for_another_plugin_installs_its_own_component_and_interval() -> TestResult {
    let mut world = World::with_config(Config {
        plugin_id: "plugin-z",
        owner: "owner-z",
        ..Config::default()
    })?;
    let shape = Shape {
        version: "3.1.0",
        component: b"\0asm another component",
        not_before: 10,
        not_after: 90,
        ..world.first_shape()
    };
    let published = world.publish(shape)?;
    let digest = pmf1_digest(&world.store.read_verified(published.address())?);
    let installed = world
        .install(published.address(), 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    assert_eq!(installed.admission().decision().plugin_id(), "plugin-z");
    assert_eq!(installed.admission().decision().pmf1_digest(), digest);
    let snapshot = world.snapshot(&[digest])?;
    assert_eq!(
        snapshot.active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(digest)
    );
    assert_eq!(snapshot.events.len(), 1);
    Ok(())
}

#[test]
fn a_release_signed_at_an_unlisted_epoch_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let second = register(&mut world.keys, OWNER, 2)?;
    assert_ne!(key_bytes(&second), key_bytes(&world.publisher));
    let shape = Shape {
        epoch: 2,
        ..world.first_shape()
    };
    let published = world.publish_with(&second, shape)?;
    let refused = world.install(published.address(), 1)?;
    assert_eq!(
        refused.err(),
        Some(authorization_error(PluginTrustErrorV1::UnknownPublisherKey))
    );
    assert!(world.registry.admits.is_empty());
    Ok(())
}

#[test]
fn evidence_at_expired_coordinates_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let expired = world.expired_material()?;
    let early = world.not_yet_valid_material()?;
    for material in [expired, early] {
        let mut source = wall(material.utc)?;
        let result = world.install_with(published.address(), &material, &mut source, 1);
        assert_eq!(
            result.err(),
            Some(authorization_error(PluginTrustErrorV1::ManifestExpired))
        );
        assert_eq!(source.remaining(), 1);
    }
    assert!(world.registry.admits.is_empty());
    Ok(())
}

#[test]
fn evidence_with_a_revoked_key_or_release_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let keys = world.key_revoked_material(&[1])?;
    let mut source = wall(keys.utc)?;
    let result = world.install_with(published.address(), &keys, &mut source, 1);
    assert_eq!(
        result.err(),
        Some(authorization_error(PluginTrustErrorV1::PublisherKeyRevoked))
    );
    let artifacts = world.artifact_revoked_material(&[published.release_digest()])?;
    let mut source = wall(artifacts.utc)?;
    let result = world.install_with(published.address(), &artifacts, &mut source, 1);
    assert_eq!(
        result.err(),
        Some(authorization_error(PluginTrustErrorV1::ArtifactRevoked))
    );
    assert!(world.registry.admits.is_empty());
    Ok(())
}

#[test]
fn a_policy_advance_revoking_the_publisher_key_blocks_later_installs() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    let outcome = world
        .advance_revoking_keys(&[1])?
        .map_err(|error| format!("advance failed: {error}"))?;
    assert_eq!(outcome.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(outcome.tps1_epoch, 2);
    // The world's evidence follows the committed advance exactly.
    let retained = world.registry.retained_policy_state(SCOPE)?;
    assert_eq!(retained.tps1_epoch(), 2);
    assert_eq!(retained.tps1_digest(), world.material()?.tps1_digest());
    let refused = world.install(second.address(), 2)?;
    assert_eq!(
        refused.err(),
        Some(authorization_error(PluginTrustErrorV1::PublisherKeyRevoked))
    );
    assert_eq!(world.registry.admits.len(), 1);
    Ok(())
}

#[test]
fn a_policy_advance_revoking_a_release_blocks_installing_it() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let outcome = world
        .advance_revoking_artifacts(&[published.release_digest()])?
        .map_err(|error| format!("advance failed: {error}"))?;
    assert_eq!(outcome.outcome, PolicyAdvanceKindV1::Advanced);
    let refused = world.install(published.address(), 1)?;
    assert_eq!(
        refused.err(),
        Some(authorization_error(PluginTrustErrorV1::ArtifactRevoked))
    );
    assert!(world.registry.admits.is_empty());
    Ok(())
}

#[test]
fn a_refused_policy_advance_leaves_the_world_evidence_unchanged() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    assert!(world.install(published.address(), 1)?.is_ok());
    let before = world.material()?.tps1;
    let before_state = world.snapshot(&[])?;
    // Evidence one second before the retained highest trusted second regresses.
    world.spec.utc_offset = -1;
    let refused = world.advance_revoking_keys(&[1])?;
    assert_eq!(
        refused.err(),
        Some(PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed)
    );
    assert!(world.spec.adopted.is_empty());
    assert_eq!(world.previous, None);
    world.spec.utc_offset = 0;
    assert_eq!(world.material()?.tps1, before);
    assert_eq!(world.snapshot(&[])?, before_state);
    Ok(())
}

#[test]
fn an_operator_rollback_reactivates_the_earlier_release() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    assert!(world.install(second.address(), 2)?.is_ok());
    let first_digest = pmf1_digest(&world.store.read_verified(first.address())?);
    let second_digest = pmf1_digest(&world.store.read_verified(second.address())?);
    let receipt = world
        .rollback_to(first.address(), 3)?
        .map_err(|error| format!("rollback failed: {error}"))?;
    assert_eq!(receipt.target_pmf1_digest(), first_digest);
    assert_eq!(receipt.replaced_pmf1_digest(), second_digest);
    let snapshot = world.snapshot(&[first_digest, second_digest])?;
    assert_eq!(
        snapshot.active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(first_digest)
    );
    // The evidence is unchanged, both decisions stay retained, and three activations exist.
    let current = world.material()?.tps1_digest();
    assert_eq!(snapshot.policy.tps1_digest(), current);
    assert!(snapshot.decisions.iter().all(Option::is_some));
    assert_eq!(snapshot.events.len(), 3);
    Ok(())
}

#[test]
fn sequential_policy_advances_keep_every_earlier_revocation() -> TestResult {
    let mut world = World::with_config(Config {
        second_epoch_key: true,
        ..Config::default()
    })?;
    // The epoch-1 release is signed before the epoch-2 key joins the Key registry.
    let signed_by_one = world.publish(Shape::first())?;
    world.register_second_epoch()?;
    let second_epoch = Shape {
        version: "2.0.0",
        epoch: 2,
        ..Shape::first()
    };
    let revoked = world.publish_second_epoch(second_epoch)?;
    let third_epoch = Shape {
        version: "3.0.0",
        ..second_epoch
    };
    let clean = world.publish_second_epoch(third_epoch)?;
    // Advance 1 revokes one epoch-2 release digest: PRV1 epoch 2.
    let artifacts = world
        .advance_revoking_artifacts(&[revoked.release_digest()])?
        .map_err(|error| format!("artifact advance failed: {error}"))?;
    assert_eq!(artifacts.tps1_epoch, 2);
    let refused = world.install(revoked.address(), 1)?;
    assert_eq!(
        refused.err(),
        Some(authorization_error(PluginTrustErrorV1::ArtifactRevoked))
    );
    // Advance 2 revokes the epoch-1 key: PRV1 epoch 3 keeps the artifact revocation.
    let keys = world
        .advance_revoking_keys(&[1])?
        .map_err(|error| format!("key advance failed: {error}"))?;
    assert_eq!(keys.outcome, PolicyAdvanceKindV1::Advanced);
    assert_eq!(keys.tps1_epoch, 3);
    assert_eq!(world.spec.adopted.len(), 2);
    assert_eq!(world.spec.revoked_epochs, [1]);
    assert_eq!(world.spec.revoked_artifacts, [revoked.release_digest()]);
    let retained = world.registry.retained_policy_state(SCOPE)?;
    assert_eq!(retained.tps1_epoch(), 3);
    assert_eq!(retained.tps1_digest(), world.material()?.tps1_digest());
    // The key revocation is enforced, and so is the artifact revocation of advance 1.
    let refused = world.install(signed_by_one.address(), 1)?;
    assert_eq!(
        refused.err(),
        Some(authorization_error(PluginTrustErrorV1::PublisherKeyRevoked))
    );
    let refused = world.install(revoked.address(), 1)?;
    assert_eq!(
        refused.err(),
        Some(authorization_error(PluginTrustErrorV1::ArtifactRevoked))
    );
    assert!(world.registry.admits.is_empty());
    // A release signed by the unrevoked epoch-2 key and not revoked itself still installs.
    assert!(world.install(clean.address(), 1)?.is_ok());
    assert_eq!(world.registry.admits.len(), 1);
    Ok(())
}

#[test]
fn a_release_carrying_the_real_component_installs_with_its_digests() -> TestResult {
    let mut world = World::new()?;
    let component = REAL_COMPONENT_BYTES;
    let shape = Shape::first().with_real_component();
    assert_eq!(shape.component, component);
    // A WebAssembly Component preamble: magic, then version 13 with layer 1.
    assert_eq!(component.get(..8), Some(&b"\0asm\x0d\0\x01\0"[..]));
    let published = world.publish(shape)?;
    let bundle = world.store.read_verified(published.address())?;
    // The component layer is the file's bytes, and the PMF1 descriptor names its SHA-256.
    let member_listed = bundle.member_bytes().any(|bytes| bytes == component);
    assert!(member_listed);
    let sha256 = Sha256::digest(component);
    let pmf1 = bundle.pmf1();
    let digest_listed = pmf1.windows(32).any(|window| window == sha256.as_slice());
    assert!(digest_listed);
    let installed = world
        .install(published.address(), 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    assert!(installed.execution().is_bound_to(&projection));
    assert_eq!(installed.execution().pmf1_digest(), pmf1_digest(&bundle));
    Ok(())
}

/// The world holding its installed first release, with that release's address and PMF1 digest.
type InstalledWorld = (World, BundleAddressV1, [u8; 32]);

/// Install the first release into `world`.
fn installed_world(mut world: World) -> BoxResult<InstalledWorld> {
    let published = world.publish(Shape::first())?;
    let digest = pmf1_digest(&world.store.read_verified(published.address())?);
    world
        .install(published.address(), 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    Ok((world, published.address().clone(), digest))
}

/// EV15: with a clock the spy stamps evaluations 1-based and strictly increasing, an `admit`
/// is one unstamped entry that leaves the clock alone, the evaluation delegates and returns the
/// inner result, and the `forced` error does not apply to it.
#[test]
fn a_clocked_spy_stamps_every_evaluation_and_leaves_admits_unstamped() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let (mut world, address, digest) = installed_world(World::with_clock(Arc::clone(&clock))?)?;
    let admit = world.registry.admits.first().cloned().ok_or("no admit")?;
    assert_eq!(world.registry.admits.len(), 1);
    assert_eq!(
        world.registry.calls.borrow().as_slice(),
        [Call::Admit(admit)]
    );
    assert_eq!(clock.load(Ordering::SeqCst), 0);

    let utc = world.material()?.utc;
    let evaluation = world.evaluate_at(&address, utc, TICK)??;
    assert_eq!(evaluation.pmf1_digest(), digest);
    assert_eq!(evaluation.plugin_id(), "plugin-a");
    assert_eq!(evaluation.trusted_utc_second(), utc);
    assert_eq!(evaluation.tick(), TICK);
    assert_eq!(clock.load(Ordering::SeqCst), 1);

    // The forced error is an `admit` injection only, and the inner result is returned as is.
    world.registry.forced = Some(PluginTrustPolicyRegistryErrorV1::StorageFailed);
    let wrong_utc = world.evaluate_at(&address, utc + 1, TICK)?;
    assert_eq!(
        wrong_utc.err(),
        Some(PluginTrustPolicyRegistryErrorV1::Bridge(
            PluginTrustBridgeErrorV1::EvaluationUtcMismatch
        ))
    );
    let wrong_tick = world.evaluate_at(&address, utc, TICK + 1)?;
    assert_eq!(
        wrong_tick.err(),
        Some(PluginTrustPolicyRegistryErrorV1::Bridge(
            PluginTrustBridgeErrorV1::EvaluationTickMismatch
        ))
    );
    assert_eq!(clock.load(Ordering::SeqCst), 3);
    assert_eq!(world.registry.admits.len(), 1);
    let stamps = world.registry.calls.borrow().clone();
    assert_eq!(stamps.len(), 4);
    assert_eq!(
        stamps[1..],
        [
            Call::Evaluate {
                stamp: 1,
                utc,
                tick: TICK,
            },
            Call::Evaluate {
                stamp: 2,
                utc: utc + 1,
                tick: TICK,
            },
            Call::Evaluate {
                stamp: 3,
                utc,
                tick: TICK + 1,
            },
        ]
    );
    Ok(())
}

/// EV15: a spy without a clock records stamp 0, and a following `admit` still appends one entry.
#[test]
fn an_unclocked_spy_records_stamp_zero() -> TestResult {
    let (mut world, address, _) = installed_world(World::new()?)?;
    let utc = world.material()?.utc;
    world.evaluate_at(&address, utc, TICK)??;
    world.evaluate_at(&address, utc, TICK)??;
    let evaluate = Call::Evaluate {
        stamp: 0,
        utc,
        tick: TICK,
    };
    let calls = world.registry.calls.borrow().clone();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1..], [evaluate.clone(), evaluate]);
    // The replay appends exactly one more `Admit` entry and appears in `admits`.
    world
        .install(&address, 1)?
        .map_err(|error| format!("replay failed: {error}"))?;
    assert_eq!(world.registry.admits.len(), 2);
    let calls = world.registry.calls.borrow().clone();
    assert_eq!(calls.len(), 4);
    assert!(matches!(calls.last(), Some(Call::Admit(_))));
    Ok(())
}

/// The number of artifact revocations effective at the evidence's Tick.
fn denials(material: &Material) -> usize {
    material.evidence.effective_artifact_revocations().count()
}

/// R7-T1 (#581): the `Material` accessors expose the raw records and the anchor the evidence
/// was verified from, so a consumer can verify them again.
#[test]
fn material_accessors_reproduce_the_evidence() -> TestResult {
    let mut world = World::new()?;
    world.advance_revoking_keys(&[1])??;
    let material = world.material()?;
    assert_eq!(material.prv1_records().len(), 2);
    let records = material
        .prv1_records()
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let again = verify_plugin_trust_v1(
        material.root_anchor(),
        &[material.ptr1()],
        &records,
        material.utc,
        TICK,
    )?;
    assert_eq!(again.terminal_root(), material.evidence.terminal_root());
    assert_eq!(
        again.terminal_revocation(),
        material.evidence.terminal_revocation()
    );
    Ok(())
}

/// R7-T1 (#581): a new revocation takes the Tick of the record that first lists it, a carried
/// one keeps its Tick, and record Ticks are non-decreasing (the verifier accepts the history).
#[test]
fn a_revocation_takes_the_tick_of_the_record_that_first_lists_it() -> TestResult {
    let mut world = World::new()?;
    let first = [0x01; 32];
    let second = [0x02; 32];
    // Adopted at Tick 8, before the Tick 9 revocation is effective.
    world.advance_revoking_artifacts_at(&[first], 9, 8)??;
    assert_eq!(denials(&world.material()?), 0);
    world.advance_revoking_artifacts_at(&[second], 12, 11)??;
    let effective_at = |tick: u64| -> BoxResult<Vec<[u8; 32]>> {
        let spec = Spec {
            tick,
            ..world.spec.clone()
        };
        let material = world.policy.material(&spec)?;
        Ok(material.evidence.effective_artifact_revocations().collect())
    };
    assert!(effective_at(8)?.is_empty());
    assert_eq!(effective_at(9)?, [first]);
    assert_eq!(effective_at(11)?, [first]);
    assert_eq!(effective_at(12)?, [first, second]);
    Ok(())
}

/// R7-T1 (#581): the TPS1-only denial is adopted through `advance_policy`, no PRV1 record lists
/// it, and the registry then refuses the release with the operator's denial.
#[test]
fn an_operator_denial_is_adopted_without_a_revocation_entry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    world
        .install(published.address(), 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    let address = published.address().clone();
    world.advance_operator_denying(&[published.release_digest()])??;
    assert!(world.spec.revoked_artifacts.is_empty());
    let retained = world.registry.retained_policy_state(SCOPE)?;
    assert_eq!(retained.tps1_digest(), world.material()?.tps1_digest());
    assert_eq!(denials(&world.material()?), 0);
    let refused = world.evaluate_at(&address, UTC, TICK)?;
    assert_eq!(
        refused.err(),
        Some(PluginTrustPolicyRegistryErrorV1::Bridge(
            PluginTrustBridgeErrorV1::TpsArtifactDenied
        ))
    );
    Ok(())
}

/// R7-T1 (#581): the forked-floor material has the retained TPS1 bytes and a same-epoch PRV1
/// record of a different digest, which the registry refuses as a fork.
#[test]
fn the_forked_floor_material_is_refused_as_a_fork() -> TestResult {
    let (world, address, _) = installed_world(World::new()?)?;
    let genuine = world.material()?;
    let forked = world.forked_floor_material()?;
    assert_eq!(forked.tps1, genuine.tps1);
    assert_ne!(forked.prv1_records(), genuine.prv1_records());
    let refused = world.evaluate_material_at(&address, &forked, UTC, TICK)?;
    assert_eq!(
        refused.err(),
        Some(PluginTrustPolicyRegistryErrorV1::Floor(
            PluginFloorErrorV1::Fork(PluginFloorKindV1::Revocation)
        ))
    );
    Ok(())
}

/// R7-T1 (#581): a release with an invalid field-26 signature is refused by the installer's
/// signature check, but a direct registry admission plants it as the active release.
#[test]
fn a_direct_admission_plants_a_release_with_a_bad_signature() -> TestResult {
    let mut world = World::new()?;
    let address = world.publish_with_signature(Shape::first(), [0; 64])?;
    let refused = world.install(&address, 1)?;
    let signature_refused = matches!(refused, Err(PluginReleaseInstallErrorV1::Signature(_)));
    assert!(signature_refused);
    assert!(world.registry.admits.is_empty());
    world
        .admit_directly(&address, 1)?
        .map_err(|error| format!("direct admission failed: {error}"))?;
    let digest = pmf1_digest(&world.store.read_verified(&address)?);
    let active = world.snapshot(&[])?.active;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(digest)
    );
    Ok(())
}
