//! The production Plugin release rollback entry at the public seam (ADR-103 revision 7,
//! vector R7-T8).
//!
//! Releases are signed and published by the #571 publisher into a real local OCI store, trust
//! evidence is built from independently encoded PTR1, PRV1, and TPS1 records, and both the
//! installs and the rollback run against the Memory adapter of the Plugin trust policy registry
//! through a call-recording spy. Every refusal before the registry is checked against an
//! observable-state-identical registry, an empty `rollback` log, and an unconsumed trusted wall
//! source.
#![cfg(target_os = "linux")]

use pos_conformance::{PluginFloorKindV1, PluginTrustBridgeErrorV1};
use pos_core::store::{EventStore as _, SeqRange};
use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_crypto::plugin_manifest::PluginReleaseSignatureErrorV1;
use pos_crypto::plugin_trust::{PluginTrustErrorV1, ValidatedPluginManifestProjectionV1};
use pos_plugin_publisher::test_support::{
    encoding::{Material, SCOPE, TICK, UTC},
    release::{make_draft, pmf1_digest, PrivateRoot, Shape, COMPONENT_BYTES},
    world::{key_bytes, wall, World},
    BoxResult,
};
use pos_plugin_publisher::{
    publish_plugin_release_v1, sign_plugin_release_v1, PluginReleaseRollbackErrorV1,
    PublishedPluginReleaseV1,
};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1};
use pos_store::plugin_trust_registry::{
    ActiveReleaseV1, PluginTrustCommitOutcomeV1, PluginTrustLedgerKindV1,
    PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1,
};

type TestResult = BoxResult<()>;

// ---------------------------------------------------------------------------
// Shared setup and assertions
// ---------------------------------------------------------------------------

/// A world with R1 installed (activation tag 1) and its successor R2 installed (tag 2), so R2
/// is active and R1 is a retained rollback target.
fn two_installed() -> BoxResult<(World, PublishedPluginReleaseV1, PublishedPluginReleaseV1)> {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    world
        .install(first.address(), 1)?
        .map_err(|error| format!("R1 install failed: {error}"))?;
    let second = world.publish(successor(&first))?;
    world
        .install(second.address(), 2)?
        .map_err(|error| format!("R2 install failed: {error}"))?;
    Ok((world, first, second))
}

/// The direct successor shape of `first`.
const fn successor(first: &PublishedPluginReleaseV1) -> Shape {
    Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    }
}

/// The complete PMF1 digest of the release at `address`.
fn digest_of(world: &World, address: &BundleAddressV1) -> BoxResult<[u8; 32]> {
    Ok(pmf1_digest(&world.store.read_verified(address)?))
}

/// The rollback was refused before the registry: exactly `expected`, no `rollback` call, no
/// clock sample, and an observable-state-identical registry.
fn assert_refused_before_registry(
    world: &mut World,
    address: &BundleAddressV1,
    material: &Material,
    expected: &PluginReleaseRollbackErrorV1,
) -> TestResult {
    let before = world.snapshot(&[])?;
    let admits = world.registry.admits.len();
    let mut source = wall(material.utc)?;
    let result = world.roll_back_with(address, material, &mut source, 3);
    assert_eq!(result.err().as_ref(), Some(expected));
    assert!(world.registry.rollbacks.is_empty());
    assert_eq!(world.registry.admits.len(), admits);
    assert_eq!(source.remaining(), 1);
    assert_eq!(world.snapshot(&[])?, before);
    Ok(())
}

const fn signature_error() -> PluginReleaseRollbackErrorV1 {
    PluginReleaseRollbackErrorV1::Signature(PluginReleaseSignatureErrorV1::InvalidSignature)
}

const fn registry_error(error: PluginTrustPolicyRegistryErrorV1) -> PluginReleaseRollbackErrorV1 {
    PluginReleaseRollbackErrorV1::Registry(error)
}

// ---------------------------------------------------------------------------
// Positive rollback and replay
// ---------------------------------------------------------------------------

#[test]
fn rolls_back_to_the_earlier_release_through_the_production_entry() -> TestResult {
    let (mut world, first, second) = two_installed()?;
    let first_digest = digest_of(&world, first.address())?;
    let second_digest = digest_of(&world, second.address())?;
    let rolled = world
        .roll_back(first.address(), 3)?
        .map_err(|error| format!("rollback failed: {error}"))?;
    // The receipt names R1 as the target and R2 as the replaced release.
    let receipt = rolled.receipt();
    assert_eq!(receipt.outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(receipt.scope(), SCOPE);
    assert_eq!(receipt.plugin_id(), "plugin-a");
    assert_eq!(receipt.target_pmf1_digest(), first_digest);
    assert_eq!(receipt.target_release_digest(), first.release_digest());
    assert_eq!(receipt.replaced_pmf1_digest(), second_digest);
    assert_eq!(receipt.trusted_utc_second(), UTC);
    assert_eq!(receipt.tick(), TICK);
    // The execution projection is the target's own.
    let bundle = world.store.read_verified(first.address())?;
    let execution = rolled.execution();
    assert_eq!(execution.pmf1_digest(), first_digest);
    assert_eq!(execution.release_digest(), first.release_digest());
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    assert!(execution.is_bound_to(&projection));
    // The signature fact names the target and the resolved key, and it is the release proof
    // the registry received, at the sampled UTC second and the evidence's own Tick.
    let signature = rolled.release_signature();
    assert_eq!(signature.pmf1_digest(), first_digest);
    assert_eq!(signature.release_digest(), first.release_digest());
    assert_eq!(signature.public_key(), key_bytes(&world.publisher));
    let material = world.material()?;
    assert_eq!(world.registry.rollbacks.len(), 1);
    let call = &world.registry.rollbacks[0];
    assert_eq!(*call.release_proof, signature);
    assert_eq!(call.utc, UTC);
    assert_eq!(call.tick, TICK);
    assert_eq!(call.tps1, material.tps1);
    assert_eq!(call.timeline, world.timeline);
    // The rollback is no admission.
    assert_eq!(world.registry.admits.len(), 2);
    // R1 is active again, and the ledger's last row is the rollback from R2 to R1.
    let active = world.registry.active_release(SCOPE, "plugin-a")?;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(first_digest)
    );
    let ledger = world.registry.ledger(SCOPE)?;
    let last = ledger.last().ok_or("empty ledger")?;
    assert_eq!(last.kind(), PluginTrustLedgerKindV1::Rollback);
    assert_eq!(last.pmf1_digest(), Some(first_digest));
    assert_eq!(last.release_digest(), Some(first.release_digest()));
    assert_eq!(last.previous_active_pmf1_digest(), Some(second_digest));
    // Two installs and one rollback: three activation Events.
    let events = world.registry.store.read(world.timeline, SeqRange::all())?;
    assert_eq!(events.len(), 3);
    Ok(())
}

#[test]
fn the_retry_after_a_lost_acknowledgement_is_an_idempotent_replay() -> TestResult {
    let (mut world, first, second) = two_installed()?;
    let first_rollback = world
        .roll_back(first.address(), 3)?
        .map_err(|error| format!("rollback failed: {error}"))?;
    let digests = [
        digest_of(&world, first.address())?,
        digest_of(&world, second.address())?,
    ];
    let before = world.snapshot(&digests)?;
    // The acknowledgement was lost: the caller repeats the identical rollback.
    let retry = world
        .roll_back(first.address(), 3)?
        .map_err(|error| format!("retry failed: {error}"))?;
    assert_eq!(
        retry.receipt().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(
        retry.receipt().target_pmf1_digest(),
        first_rollback.receipt().target_pmf1_digest()
    );
    assert_eq!(
        retry.receipt().activation_event(),
        first_rollback.receipt().activation_event()
    );
    assert_eq!(retry.execution(), first_rollback.execution());
    assert_eq!(
        retry.release_signature(),
        first_rollback.release_signature()
    );
    // A replay appends no Event, writes no ledger row, and repoints nothing.
    assert_eq!(world.snapshot(&digests)?, before);
    assert_eq!(world.registry.rollbacks.len(), 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry refusals pass through typed
// ---------------------------------------------------------------------------

#[test]
fn a_never_admitted_target_is_an_unknown_rollback_target() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    // R2 is published and signed but was never installed.
    let second = world.publish(successor(&first))?;
    let before = world.snapshot(&[digest_of(&world, second.address())?])?;
    let refused = world.roll_back(second.address(), 2)?;
    assert_eq!(
        refused.err(),
        Some(registry_error(
            PluginTrustPolicyRegistryErrorV1::UnknownRollbackTarget
        ))
    );
    assert_eq!(world.registry.rollbacks.len(), 1);
    assert_eq!(
        world.snapshot(&[digest_of(&world, second.address())?])?,
        before
    );
    Ok(())
}

#[test]
fn rolling_back_to_the_active_release_is_refused() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    assert!(world.install(first.address(), 1)?.is_ok());
    let digests = [digest_of(&world, first.address())?];
    let before = world.snapshot(&digests)?;
    // R1 is active, and no rollback row carries this activation identity.
    let refused = world.roll_back(first.address(), 2)?;
    assert_eq!(
        refused.err(),
        Some(registry_error(
            PluginTrustPolicyRegistryErrorV1::RollbackTargetActive
        ))
    );
    assert_eq!(world.snapshot(&digests)?, before);
    Ok(())
}

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
        PluginTrustPolicyRegistryErrorV1::PolicyNotAdvanced,
        PluginTrustPolicyRegistryErrorV1::ReleaseNotActive,
        PluginTrustPolicyRegistryErrorV1::ReleaseProofMismatch,
        PluginTrustPolicyRegistryErrorV1::Bridge(PluginTrustBridgeErrorV1::EvaluationUtcMismatch),
        PluginTrustPolicyRegistryErrorV1::Floor(pos_conformance::PluginFloorErrorV1::Rollback(
            PluginFloorKindV1::Root,
        )),
        PluginTrustPolicyRegistryErrorV1::Trust(PluginTrustErrorV1::ArtifactRevoked),
    ];
    let (mut world, first, _) = two_installed()?;
    let before = world.snapshot(&[])?;
    for error in errors {
        world.registry.forced = Some(error);
        let result = world.roll_back(first.address(), 3)?;
        assert_eq!(result.err(), Some(registry_error(error)));
        assert_eq!(world.snapshot(&[])?, before);
    }
    assert_eq!(world.registry.rollbacks.len(), errors.len());
    Ok(())
}

#[test]
fn an_unavailable_trusted_clock_refuses_before_the_registry() -> TestResult {
    let (mut world, first, _) = two_installed()?;
    let material = world.material()?;
    let mut exhausted = ScriptedTrustedWallSourceV1::from_micros([]);
    let result = world.roll_back_with(first.address(), &material, &mut exhausted, 3);
    assert_eq!(
        result.err(),
        Some(registry_error(
            PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable
        ))
    );
    assert!(world.registry.rollbacks.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Refusals before the registry
// ---------------------------------------------------------------------------

#[test]
fn a_target_with_a_tampered_signature_is_refused_before_the_registry() -> TestResult {
    let (mut world, _, _) = two_installed()?;
    let material = world.material()?;
    let valid = *sign_plugin_release_v1(
        &mut world.keys,
        &world.publisher,
        1,
        &make_draft(Shape::first())?,
    )?
    .signature();
    let mut flipped = valid;
    flipped[10] ^= 1;
    let tampered = world.publish_with_signature(Shape::first(), flipped)?;
    // Even a registry that would fail every call is never reached by a bad signature.
    world.registry.forced = Some(PluginTrustPolicyRegistryErrorV1::StorageFailed);
    assert_refused_before_registry(&mut world, &tampered, &material, &signature_error())
}

#[test]
fn a_revoked_target_is_refused_before_the_signature_check_and_the_registry() -> TestResult {
    let (mut world, first, _) = two_installed()?;
    let forged = world.publish_with_signature(Shape::first(), [0x77; 64])?;
    let revoked = world.key_revoked_material(&[1])?;
    let expected =
        PluginReleaseRollbackErrorV1::Authorization(PluginTrustErrorV1::PublisherKeyRevoked);
    // A revoked artifact is not silently restored.
    assert_refused_before_registry(&mut world, first.address(), &revoked, &expected)?;
    // The authorization error outranks the signature error of a forged target.
    assert_refused_before_registry(&mut world, &forged, &revoked, &expected)
}

#[test]
fn an_address_holding_nothing_is_refused_before_the_registry() -> TestResult {
    let (mut world, _, _) = two_installed()?;
    let scratch = PrivateRoot::new()?;
    let other_store = scratch.store()?;
    let elsewhere = publish_plugin_release_v1(
        &mut world.keys,
        &world.publisher,
        1,
        &make_draft(Shape::first())?,
        &other_store,
    )?;
    let material = world.material()?;
    assert_refused_before_registry(
        &mut world,
        elsewhere.address(),
        &material,
        &PluginReleaseRollbackErrorV1::Source(ReleaseSourceErrorV1::NotFound),
    )
}

#[test]
fn a_noncanonical_target_pmf1_is_refused_before_the_registry() -> TestResult {
    let (mut world, _, _) = two_installed()?;
    let garbage = world.publish_raw(b"not a PMF1", COMPONENT_BYTES)?;
    let material = world.material()?;
    let mut source = wall(material.utc)?;
    let result = world.roll_back_with(&garbage, &material, &mut source, 3);
    let Err(PluginReleaseRollbackErrorV1::Manifest(cause)) = &result else {
        return Err(format!("expected a manifest refusal, got {result:?}").into());
    };
    // The error displays its cause transparently.
    assert_eq!(
        result.as_ref().err().map(ToString::to_string),
        Some(cause.to_string())
    );
    assert!(world.registry.rollbacks.is_empty());
    assert_eq!(source.remaining(), 1);
    Ok(())
}

// ---------------------------------------------------------------------------
// The closed error
// ---------------------------------------------------------------------------

#[test]
fn every_rollback_error_displays_its_cause_transparently() {
    let cases = [
        (
            PluginReleaseRollbackErrorV1::Source(ReleaseSourceErrorV1::NotFound),
            ReleaseSourceErrorV1::NotFound.to_string(),
        ),
        (
            PluginReleaseRollbackErrorV1::Authorization(PluginTrustErrorV1::ArtifactRevoked),
            PluginTrustErrorV1::ArtifactRevoked.to_string(),
        ),
        (
            signature_error(),
            PluginReleaseSignatureErrorV1::InvalidSignature.to_string(),
        ),
        (
            registry_error(PluginTrustPolicyRegistryErrorV1::NoActiveRelease),
            PluginTrustPolicyRegistryErrorV1::NoActiveRelease.to_string(),
        ),
    ];
    for (error, cause) in cases {
        assert_eq!(error.to_string(), cause);
    }
}
