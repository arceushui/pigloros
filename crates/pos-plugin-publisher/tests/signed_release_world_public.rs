//! The shared signed-release test world at the public seam.
//!
//! These vectors exercise the parts of `pos_plugin_publisher::test_support`
//! that the installer vectors in `installer_public.rs` do not reach: a world
//! parametrised by Plugin, owner, Component, and validity interval, evidence
//! at expired coordinates and with revocations, registry policy advances that
//! revoke a publisher key or a release, and an operator rollback. Each helper
//! is checked against the real registry, not a stub.
#![cfg(target_os = "linux")]

use pos_crypto::plugin_trust::{PluginTrustErrorV1, ValidatedPluginManifestProjectionV1};
use pos_plugin_publisher::{
    test_support::{
        encoding::{OWNER, SCOPE},
        release::{pmf1_digest, Shape, REAL_COMPONENT_BYTES},
        world::{key_bytes, register, wall, Config, World},
        BoxResult,
    },
    PluginReleaseInstallErrorV1,
};
use pos_plugin_release::ReleaseSourceV1;
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
