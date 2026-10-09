//! The signed Plugin release installer at the public seam (ADR-061 revision 2,
//! ADR-103 revision 4).
//!
//! Releases are signed and published by the #571 publisher into a real local
//! OCI store, trust evidence is built from independently encoded PTR1, PRV1,
//! and TPS1 records, and admission runs against the Memory adapter of the
//! Plugin trust policy registry through a call-recording spy. Every refusal
//! before the registry is checked against an observable-state-identical registry, an
//! empty `admit` log, and an unconsumed trusted wall source.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use ed25519_dalek::SigningKey;
use pos_conformance::{PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::ScriptedTrustedWallSourceV1,
    OwnerIdV1,
};
use pos_crypto::plugin_manifest::PluginReleaseSignatureErrorV1;
use pos_crypto::plugin_trust::{PluginTrustErrorV1, ValidatedPluginManifestProjectionV1};
use pos_plugin_publisher::test_support::{
    encoding::{Material, Spec, OTHER_OWNER, OWNER, SCOPE, TICK, UTC},
    release::{make_draft, pmf1_digest, PrivateRoot, Shape, COMPONENT_BYTES},
    world::{key_bytes, register, wall, World},
    BoxResult,
};
use pos_plugin_publisher::{
    publish_plugin_release_v1, sign_plugin_release_v1, verify_plugin_release_historical_v1,
    ContentValidationV1, PluginReleaseInstallErrorV1, ReleaseSignatureMathV1, SigningKeyStateV1,
};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1};
use pos_store::plugin_trust_registry::{
    ActiveReleaseV1, PluginTrustCommitOutcomeV1, PluginTrustPolicyRegistryErrorV1,
    PluginTrustPolicyRegistryV1,
};

type TestResult = BoxResult<()>;

// ---------------------------------------------------------------------------
// Shared assertions
// ---------------------------------------------------------------------------

/// The installation was refused before the registry: exactly `expected`, no
/// `admit` call, no clock sample, and an observable-state-identical registry.
fn assert_refused_before_registry(
    world: &mut World,
    address: &BundleAddressV1,
    material: &Material,
    expected: PluginReleaseInstallErrorV1,
) -> TestResult {
    let digests = [pmf1_digest(&world.store.read_verified(address)?)];
    let before = world.snapshot(&digests)?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(address, material, &mut source, 1);
    assert_eq!(result.err(), Some(expected));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

const fn signature_error() -> PluginReleaseInstallErrorV1 {
    PluginReleaseInstallErrorV1::Signature(PluginReleaseSignatureErrorV1::InvalidSignature)
}

const fn authorization_error(error: PluginTrustErrorV1) -> PluginReleaseInstallErrorV1 {
    PluginReleaseInstallErrorV1::Authorization(error)
}

// ---------------------------------------------------------------------------
// Positive installation
// ---------------------------------------------------------------------------

#[test]
fn installs_a_signed_release_and_returns_the_admission_and_execution_projection() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let bundle = world.store.read_verified(published.address())?;
    let installed = world
        .install(published.address(), 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    let decision = installed.admission().decision();
    assert_eq!(
        installed.admission().outcome(),
        PluginTrustCommitOutcomeV1::Committed
    );
    assert_eq!(decision.scope(), SCOPE);
    assert_eq!(decision.plugin_id(), "plugin-a");
    assert_eq!(decision.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(decision.release_digest(), published.release_digest());
    assert_eq!(decision.previous_release_digest(), None);
    assert_eq!(decision.trusted_utc_second(), UTC);
    assert_eq!(decision.tick(), TICK);
    // The execution projection is the one of the same PMF1 bytes.
    let execution = installed.execution();
    assert_eq!(execution.plugin_id(), "plugin-a");
    assert_eq!(execution.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(execution.release_digest(), published.release_digest());
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    assert!(execution.is_bound_to(&projection));
    // The signature fact names the exact signer and the resolved key.
    let signature = installed.release_signature();
    assert_eq!(signature.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(signature.release_digest(), published.release_digest());
    assert_eq!(signature.owner(), OwnerIdV1::new(OWNER)?);
    assert_eq!(signature.epoch(), 1);
    assert_eq!(signature.public_key(), key_bytes(&world.publisher));
    // Content validation was explicitly not performed (#574).
    assert_eq!(
        installed.content_validation(),
        ContentValidationV1::NotPerformed
    );
    // One admit call, at the sampled UTC second and the evidence's own Tick.
    let material = world.material()?;
    assert_eq!(world.registry.admits.len(), 1);
    assert_eq!(world.registry.admits[0].utc, UTC);
    assert_eq!(world.registry.admits[0].tick, TICK);
    assert_eq!(world.registry.admits[0].tps1, material.tps1);
    assert_eq!(world.registry.admits[0].timeline, world.timeline);
    // The release is active and exactly one activation Event was appended.
    let active = world.registry.active_release(SCOPE, "plugin-a")?;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(pmf1_digest(&bundle))
    );
    assert_eq!(
        world
            .registry
            .store
            .read(world.timeline, SeqRange::all())?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn installing_the_same_release_twice_is_an_idempotent_replay() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let first = world
        .install(published.address(), 1)?
        .map_err(|error| format!("first install failed: {error}"))?;
    let digests = [pmf1_digest(
        &world.store.read_verified(published.address())?,
    )];
    let before = world.snapshot(&digests)?;
    let second = world
        .install(published.address(), 1)?
        .map_err(|error| format!("second install failed: {error}"))?;
    assert_eq!(
        first.admission().outcome(),
        PluginTrustCommitOutcomeV1::Committed
    );
    assert_eq!(
        second.admission().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(second.admission().decision(), first.admission().decision());
    assert_eq!(second.execution(), first.execution());
    // A replay appends no Event, writes no ledger row, and repoints nothing.
    assert_eq!(world.snapshot(&digests)?, before);
    assert_eq!(world.registry.admits.len(), 2);
    Ok(())
}

#[test]
fn a_changed_activation_identity_for_the_same_release_conflicts() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    assert!(world.install(published.address(), 1)?.is_ok());
    let digests = [pmf1_digest(
        &world.store.read_verified(published.address())?,
    )];
    let before = world.snapshot(&digests)?;
    let result = world.install(published.address(), 2)?;
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::ReleaseConflict
        ))
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// The release chain passes through typed
// ---------------------------------------------------------------------------

#[test]
fn the_release_chain_is_enforced_by_the_registry_and_passes_through() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    let installed = world
        .install(second.address(), 2)?
        .map_err(|error| format!("successor install failed: {error}"))?;
    assert_eq!(
        installed.admission().decision().previous_release_digest(),
        Some(first.release_digest())
    );
    // A release that is neither the active content nor its direct successor.
    let unlinked = world.publish(Shape {
        version: "3.0.0",
        ..Shape::first()
    })?;
    let digests = [
        pmf1_digest(&world.store.read_verified(unlinked.address())?),
        pmf1_digest(&world.store.read_verified(first.address())?),
    ];
    let before = world.snapshot(&digests)?;
    let refused = world.install(unlinked.address(), 3)?;
    let violation = PluginReleaseInstallErrorV1::Registry(
        PluginTrustPolicyRegistryErrorV1::ReleaseChainViolation,
    );
    assert_eq!(refused.err(), Some(violation));
    assert_eq!(world.snapshot(&digests)?, before);
    // Presenting the superseded release again with its original identity is a
    // replay: the active pointer stays on the successor.
    let replay = world
        .install(first.address(), 1)?
        .map_err(|error| format!("replay failed: {error}"))?;
    assert_eq!(
        replay.admission().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    let active = world.registry.active_release(SCOPE, "plugin-a")?;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(installed.admission().decision().pmf1_digest())
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry errors pass through typed
// ---------------------------------------------------------------------------

#[test]
fn every_registry_error_variant_passes_through_typed() -> TestResult {
    let errors = [
        PluginTrustPolicyRegistryErrorV1::MissingState,
        PluginTrustPolicyRegistryErrorV1::CorruptState,
        PluginTrustPolicyRegistryErrorV1::AnchorMismatch,
        PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable,
        PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed,
        PluginTrustPolicyRegistryErrorV1::ReleaseChainViolation,
        PluginTrustPolicyRegistryErrorV1::ReleaseConflict,
        PluginTrustPolicyRegistryErrorV1::UnknownRollbackTarget,
        PluginTrustPolicyRegistryErrorV1::NoActiveRelease,
        PluginTrustPolicyRegistryErrorV1::RollbackTargetActive,
        PluginTrustPolicyRegistryErrorV1::ActivationEventRejected,
        PluginTrustPolicyRegistryErrorV1::NestedTransaction,
        PluginTrustPolicyRegistryErrorV1::WalRequired,
        PluginTrustPolicyRegistryErrorV1::StorageBusy,
        PluginTrustPolicyRegistryErrorV1::StorageFailed,
        PluginTrustPolicyRegistryErrorV1::StorageIndeterminate,
        PluginTrustPolicyRegistryErrorV1::StorePoisoned,
        PluginTrustPolicyRegistryErrorV1::Bridge(PluginTrustBridgeErrorV1::EvaluationUtcMismatch),
        PluginTrustPolicyRegistryErrorV1::Floor(pos_conformance::PluginFloorErrorV1::Rollback(
            PluginFloorKindV1::Root,
        )),
        PluginTrustPolicyRegistryErrorV1::Trust(PluginTrustErrorV1::ArtifactRevoked),
    ];
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let digests = [pmf1_digest(
        &world.store.read_verified(published.address())?,
    )];
    let before = world.snapshot(&digests)?;
    for error in errors {
        world.registry.forced = Some(error);
        let result = world.install(published.address(), 1)?;
        assert_eq!(
            result.err(),
            Some(PluginReleaseInstallErrorV1::Registry(error))
        );
        assert_eq!(world.snapshot(&digests)?, before);
    }
    assert_eq!(world.registry.admits.len(), errors.len());
    Ok(())
}

/// A real registry refusal, not a forced one: the sampled UTC second is below
/// the retained highest second (the policy snapshot carries that high-water
/// mark), and the observable registry state is identical before and after.
#[test]
fn a_real_registry_refusal_leaves_the_observable_state_identical() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    let digests = [pmf1_digest(&world.store.read_verified(second.address())?)];
    let before = world.snapshot(&digests)?;
    assert_eq!(before.policy.highest_trusted_utc_second(), Some(UTC));
    let earlier = world.policy.material(&Spec {
        utc_offset: -1,
        ..Spec::default()
    })?;
    let mut source = wall(earlier.utc)?;
    let result = world.install_with(second.address(), &earlier, &mut source, 2);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::TrustedTimeRegressed
        ))
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn an_unprovisioned_registry_refuses_after_the_signature_verified() -> TestResult {
    let mut world = World::build(None, false)?;
    let published = world.publish(Shape::first())?;
    let result = world.install(published.address(), 1)?;
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::MissingState
        ))
    );
    assert_eq!(world.registry.admits.len(), 1);
    Ok(())
}

#[test]
fn the_registry_binds_the_sampled_second_to_the_evidence() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let digests = [pmf1_digest(
        &world.store.read_verified(published.address())?,
    )];
    let before = world.snapshot(&digests)?;
    let material = world.material()?;
    let mut skewed = wall(UTC + 1)?;
    let result = world.install_with(published.address(), &material, &mut skewed, 1);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::Bridge(
                PluginTrustBridgeErrorV1::EvaluationUtcMismatch
            )
        ))
    );
    assert_eq!(world.registry.admits[0].utc, UTC + 1);
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn an_unavailable_trusted_clock_refuses_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let material = world.material()?;
    let mut exhausted = ScriptedTrustedWallSourceV1::from_micros([]);
    let result = world.install_with(published.address(), &material, &mut exhausted, 1);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable
        ))
    );
    assert!(world.registry.admits.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Signature refusals happen before the registry
// ---------------------------------------------------------------------------

#[test]
fn a_release_with_a_bad_signature_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let material = world.material()?;
    // Unsigned: the all-zero signature of an unsigned PMF1.
    let unsigned_release = world.publish_with_signature(Shape::first(), [0; 64])?;
    assert_refused_before_registry(&mut world, &unsigned_release, &material, signature_error())?;
    // One flipped bit of an otherwise valid signature.
    let valid = *sign_plugin_release_v1(
        &mut world.keys,
        &world.publisher,
        1,
        &make_draft(Shape::first())?,
    )?
    .signature();
    let mut flipped = valid;
    flipped[10] ^= 1;
    let flipped_release = world.publish_with_signature(Shape::first(), flipped)?;
    assert_refused_before_registry(&mut world, &flipped_release, &material, signature_error())?;
    // The other owner's valid signature spliced into the publisher's PMF1.
    let foreign = world.other_owner_signature()?;
    let foreign_release = world.publish_with_signature(Shape::first(), foreign)?;
    assert_refused_before_registry(&mut world, &foreign_release, &material, signature_error())?;
    // The control: the genuine signature installs.
    let genuine = world.publish_with_signature(Shape::first(), valid)?;
    assert!(world.install(&genuine, 1)?.is_ok());
    Ok(())
}

#[test]
fn a_release_signed_by_an_unlisted_key_is_refused_before_the_registry() -> TestResult {
    // PTR1 lists a different key for the publisher's epoch 1 than the one that signed.
    let listed = SigningKey::from_bytes(&[0x5a; 32])
        .verifying_key()
        .to_bytes();
    let mut world = World::build(Some(listed), true)?;
    let published = world.publish(Shape::first())?;
    let material = world.material()?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        signature_error(),
    )
}

#[test]
fn signature_verification_precedes_the_registry_call() -> TestResult {
    let mut world = World::new()?;
    let forged = world.publish_with_signature(Shape::first(), [0x77; 64])?;
    let genuine = world.publish(Shape {
        version: "2.0.0",
        ..Shape::first()
    })?;
    // Even a registry that would fail every call is never reached by a bad signature.
    world.registry.forced = Some(PluginTrustPolicyRegistryErrorV1::StorageFailed);
    let refused = world.install(&forged, 1)?;
    assert_eq!(refused.err(), Some(signature_error()));
    assert!(world.registry.admits.is_empty());
    // A good signature reaches the registry, and its error is the one returned.
    let reached = world.install(genuine.address(), 1)?;
    assert_eq!(
        reached.err(),
        Some(PluginReleaseInstallErrorV1::Registry(
            PluginTrustPolicyRegistryErrorV1::StorageFailed
        ))
    );
    assert_eq!(world.registry.admits.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Authorization refusals happen before the signature and the registry
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_publisher_key_is_refused_before_signature_and_registry() -> TestResult {
    let mut world = World::new()?;
    let genuine = world.publish(Shape::first())?;
    let forged = world.publish_with_signature(
        Shape {
            version: "2.0.0",
            ..Shape::first()
        },
        [0x77; 64],
    )?;
    let revoked = world.policy.material(&Spec {
        revoked_epochs: vec![1],
        ..Spec::default()
    })?;
    let expected = authorization_error(PluginTrustErrorV1::PublisherKeyRevoked);
    assert_refused_before_registry(&mut world, genuine.address(), &revoked, expected.clone())?;
    // The authorization error outranks the signature error of a forged release.
    assert_refused_before_registry(&mut world, &forged, &revoked, expected)
}

#[test]
fn an_unlisted_publisher_epoch_is_refused_before_signature_and_registry() -> TestResult {
    let mut world = World::new()?;
    let second = register(&mut world.keys, OWNER, 2)?;
    let draft = make_draft(Shape::first())?;
    let published = publish_plugin_release_v1(&mut world.keys, &second, 2, &draft, &world.store)?;
    let material = world.material()?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        authorization_error(PluginTrustErrorV1::UnknownPublisherKey),
    )
}

#[test]
fn a_release_outside_its_validity_interval_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let expected = authorization_error(PluginTrustErrorV1::ManifestExpired);
    // The interval is [40, 60): 60 is expired and 39 is not yet valid.
    for offset in [10, -11] {
        let material = world.policy.material(&Spec {
            utc_offset: offset,
            ..Spec::default()
        })?;
        let address = published.address();
        assert_refused_before_registry(&mut world, address, &material, expected.clone())?;
    }
    Ok(())
}

#[test]
fn a_revoked_release_digest_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let material = world.policy.material(&Spec {
        revoked_artifacts: vec![published.release_digest()],
        ..Spec::default()
    })?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        authorization_error(PluginTrustErrorV1::ArtifactRevoked),
    )
}

#[test]
fn a_release_by_an_owner_without_the_grant_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let shape = Shape {
        owner: OTHER_OWNER,
        ..Shape::first()
    };
    let draft = make_draft(shape)?;
    let published =
        publish_plugin_release_v1(&mut world.keys, &world.other, 1, &draft, &world.store)?;
    let material = world.material()?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &material,
        authorization_error(PluginTrustErrorV1::PluginIdNotGranted),
    )
}

// ---------------------------------------------------------------------------
// Tampered or unreadable releases
// ---------------------------------------------------------------------------

#[test]
fn a_pmf1_that_does_not_bind_its_component_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let draft = make_draft(Shape::first())?;
    let pmf1 = draft.unsigned()?.with_signature(1, [0; 64])?;
    let mismatched = world.publish_raw(&pmf1, b"another component")?;
    let material = world.material()?;
    let digests = [pmf1_digest(&world.store.read_verified(&mismatched)?)];
    let before = world.snapshot(&digests)?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(&mismatched, &material, &mut source, 1);
    assert!(matches!(
        result,
        Err(PluginReleaseInstallErrorV1::Manifest(_))
    ));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn a_noncanonical_pmf1_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let garbage = world.publish_raw(b"not a PMF1", COMPONENT_BYTES)?;
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(&garbage, &material, &mut source, 1);
    assert!(matches!(
        result,
        Err(PluginReleaseInstallErrorV1::Manifest(_))
    ));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

fn overwrite_component(directory: &Path) -> BoxResult<usize> {
    let mut changed = 0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            changed += overwrite_component(&path)?;
        } else if fs::read(&path)? == COMPONENT_BYTES {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            fs::write(&path, vec![0x55; COMPONENT_BYTES.len()])?;
            changed += 1;
        }
    }
    Ok(changed)
}

#[test]
fn a_release_corrupted_in_the_store_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    assert!(overwrite_component(world.root.path())? >= 1);
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(published.address(), &material, &mut source, 1);
    assert!(matches!(
        result,
        Err(PluginReleaseInstallErrorV1::Source(_))
    ));
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

#[test]
fn an_unknown_address_is_refused_before_the_registry() -> TestResult {
    let mut world = World::new()?;
    let scratch = PrivateRoot::new()?;
    let other_store = scratch.store()?;
    let published = publish_plugin_release_v1(
        &mut world.keys,
        &world.publisher,
        1,
        &make_draft(Shape::first())?,
        &other_store,
    )?;
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.install_with(published.address(), &material, &mut source, 1);
    assert_eq!(
        result.err(),
        Some(PluginReleaseInstallErrorV1::Source(
            ReleaseSourceErrorV1::NotFound
        ))
    );
    assert!(world.registry.admits.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Historical validity is not current trust
// ---------------------------------------------------------------------------

#[test]
fn a_rotated_and_revoked_key_still_verifies_historically_but_is_not_installable() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let bundle = world.store.read_verified(published.address())?;
    // Rotate: a later epoch supersedes epoch 1 in the key registry.
    drop(register(&mut world.keys, OWNER, 2)?);
    let historical = verify_plugin_release_historical_v1(&bundle, &world.keys)?;
    assert_eq!(historical.signature(), ReleaseSignatureMathV1::Valid);
    assert_eq!(historical.key_state(), SigningKeyStateV1::Rotated);
    // Current trust evidence revokes the epoch-1 key: the installer refuses.
    let revoked = world.policy.material(&Spec {
        revoked_epochs: vec![1],
        ..Spec::default()
    })?;
    assert_refused_before_registry(
        &mut world,
        published.address(),
        &revoked,
        authorization_error(PluginTrustErrorV1::PublisherKeyRevoked),
    )
}
