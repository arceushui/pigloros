//! The community release rollback entry at its public seam (ADR-103 revision 7 decision 4.3,
//! vector R7-T9), on the shared signed-release test world of `pos-plugin-publisher`.
//!
//! Every vector installs real signed releases into the world's Memory registry through
//! `install_community_release_v1`, rolls back through `rollback_community_release_v1`, and
//! observes the activation Events on the world's Timeline. The last tests list the total host
//! error mapping of a failed rollback, one row per variant of both rollback error enums.
#![cfg(target_os = "linux")]

use ciborium::Value;
use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::event::{Event, SchemaVersion};
use pos_core::ids::{EntityId, TimelineId};
use pos_core::store::{EventStore, SeqRange};
use pos_crypto::plugin_manifest::{PluginManifestErrorV1, PluginReleaseSignatureErrorV1 as Sig};
use pos_crypto::plugin_trust::PluginTrustErrorV1 as Trust;
use pos_plugin_publisher::test_support::{
    encoding::{Material, SCOPE},
    release::{pmf1_digest, Shape, COMPONENT_BYTES},
    world::{wall, World},
    BoxResult,
};
use pos_plugin_publisher::{
    PluginReleaseInstallErrorV1 as Installer, PluginReleaseRollbackErrorV1 as Entry,
    PublishedPluginReleaseV1, RolledBackPluginReleaseV1,
};
use pos_plugin_release::{
    BundleAddressV1, ReleaseSourceErrorV1 as S, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_runtime::community_plugin_host::{
    host_error_for_install_v1, host_error_for_rollback_v1, install_community_release_v1,
    rollback_community_release_v1, ActivationTargetV1, CommunityInstallErrorV1 as Install,
    CommunityInstallRequestV1, CommunityRollbackErrorV1 as Rollback,
};
use pos_store::plugin_trust_registry::{
    ActiveReleaseV1, PluginTrustCommitOutcomeV1, PluginTrustLedgerKindV1,
    PluginTrustPolicyRegistryErrorV1 as Reg, PluginTrustPolicyRegistryV1,
};

#[path = "common/host_errors.rs"]
pub mod host_errors;

use host_errors::{
    Error as Host, ARTIFACT, EXPIRED, INVALID, KEY, MISMATCH, NOT_ACTIVE, TSU, UNTRUSTED,
};

type TestResult = BoxResult<()>;
type RolledBack = Result<RolledBackPluginReleaseV1, Rollback>;

const RESERVED: &str = "pigloros.plugin.release-activated";

/// The wrapper request of `material` on `timeline`, activating on a fresh entity.
fn request_for<'a>(
    anchor: &'a PluginTrustPolicyAnchorV1,
    timeline: TimelineId,
    material: &'a Material,
) -> CommunityInstallRequestV1<'a> {
    CommunityInstallRequestV1 {
        anchor,
        tps1_bytes: &material.tps1,
        evidence: &material.evidence,
        target: ActivationTargetV1 {
            timeline,
            entity: EntityId::new(),
        },
    }
}

/// Install the release at `address` through the community install wrapper.
fn install(world: &mut World, address: &BundleAddressV1) -> TestResult {
    let material = world.material()?;
    let mut clock = wall(material.utc)?;
    let request = request_for(&world.anchor, world.timeline, &material);
    let registry = &mut world.registry;
    install_community_release_v1(&world.store, address, registry, &mut clock, &request)?;
    Ok(())
}

/// One rollback wrapper call from the world's own store with `material`.
fn roll_back_with(
    world: &mut World,
    address: &BundleAddressV1,
    material: &Material,
) -> BoxResult<RolledBack> {
    let mut clock = wall(material.utc)?;
    let request = request_for(&world.anchor, world.timeline, material);
    let registry = &mut world.registry;
    let store = &world.store;
    Ok(rollback_community_release_v1(
        store, address, registry, &mut clock, &request,
    ))
}

/// Roll back to the release at `address` with the world's current evidence.
fn roll_back(world: &mut World, address: &BundleAddressV1) -> BoxResult<RolledBack> {
    let material = world.material()?;
    roll_back_with(world, address, &material)
}

fn events(world: &World) -> BoxResult<Vec<Event>> {
    Ok(world.registry.store.read(world.timeline, SeqRange::all())?)
}

/// A world with R1 installed and its direct successor R2 installed, so R2 is active.
fn two_installed() -> BoxResult<(World, PublishedPluginReleaseV1, PublishedPluginReleaseV1)> {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    install(&mut world, first.address())?;
    let second = world.publish(Shape {
        version: "2.0.0",
        previous: Some(first.release_digest()),
        ..Shape::first()
    })?;
    install(&mut world, second.address())?;
    Ok((world, first, second))
}

/// The registry was not asked to roll back and no Event beyond the installs was appended.
fn assert_nothing_rolled_back(world: &World, installs: usize) -> TestResult {
    assert!(world.registry.rollbacks.is_empty());
    assert_eq!(events(world)?.len(), installs);
    Ok(())
}

// ---------------------------------------------------------------------------
// The rollback and its activation Event
// ---------------------------------------------------------------------------

#[test]
fn a_rollback_commits_the_targets_activation_event_and_reactivates_it() -> TestResult {
    let (mut world, first, second) = two_installed()?;
    let first_digest = pmf1_digest(&world.store.read_verified(first.address())?);
    let second_digest = pmf1_digest(&world.store.read_verified(second.address())?);
    let rolled = roll_back(&mut world, first.address())??;
    let receipt = rolled.receipt();
    assert_eq!(receipt.outcome(), PluginTrustCommitOutcomeV1::Committed);
    assert_eq!(receipt.target_pmf1_digest(), first_digest);
    assert_eq!(receipt.replaced_pmf1_digest(), second_digest);
    assert_eq!(world.registry.rollbacks.len(), 1);
    // The Event has the reserved type and the target's four-element payload, which is the
    // payload of the target's own install Event.
    let committed = events(&world)?;
    assert_eq!(committed.len(), 3);
    let event = &committed[2];
    assert_eq!(event.event_type.as_str(), RESERVED);
    assert_eq!(event.schema_version, SchemaVersion::V1);
    let expected = Value::Array(vec![
        Value::Text(SCOPE.to_owned()),
        Value::Text("plugin-a".to_owned()),
        Value::Bytes(first_digest.to_vec()),
        Value::Bytes(first.release_digest().to_vec()),
    ]);
    let payload: Value = ciborium::from_reader(event.payload.as_slice())?;
    assert_eq!(payload, expected);
    assert_eq!(event.payload, committed[0].payload);
    assert_ne!(event.payload, committed[1].payload);
    // R1 is active again, and the ledger row of the rollback is no admission.
    let active = world.registry.active_release(SCOPE, "plugin-a")?;
    assert_eq!(
        active.as_ref().map(ActiveReleaseV1::pmf1_digest),
        Some(first_digest)
    );
    let ledger = world.registry.ledger(SCOPE)?;
    let last = ledger.last().ok_or("empty ledger")?;
    assert_eq!(last.kind(), PluginTrustLedgerKindV1::Rollback);
    assert_eq!(last.previous_active_pmf1_digest(), Some(second_digest));
    Ok(())
}

#[test]
fn a_repeated_rollback_is_an_idempotent_replay_without_a_second_event() -> TestResult {
    let (mut world, first, _second) = two_installed()?;
    let rolled = roll_back(&mut world, first.address())??;
    let replay = roll_back(&mut world, first.address())??;
    assert_eq!(
        replay.receipt().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(
        replay.receipt().activation_event(),
        rolled.receipt().activation_event()
    );
    assert_eq!(events(&world)?.len(), 3);
    Ok(())
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn a_source_failure_is_reported_as_source() -> TestResult {
    let (mut world, ..) = two_installed()?;
    let missing = BundleAddressV1::new(format!("sha256:{}", "ab".repeat(32)), 1)?;
    let result = roll_back(&mut world, &missing)?;
    assert_eq!(result.err(), Some(Rollback::Source(S::NotFound)));
    assert_nothing_rolled_back(&world, 2)
}

#[test]
fn a_manifest_failure_is_reported_as_manifest() -> TestResult {
    let (mut world, ..) = two_installed()?;
    let address = world.publish_raw(b"not a PMF1", COMPONENT_BYTES)?;
    let result = roll_back(&mut world, &address)?;
    assert!(matches!(result, Err(Rollback::Manifest(_))));
    assert_nothing_rolled_back(&world, 2)
}

/// A hostile source that returns one fixed bundle whatever address is asked for.
struct Fixed(VerifiedReleaseBundleV1);

impl ReleaseSourceV1 for Fixed {
    fn read_verified(&self, _: &BundleAddressV1) -> Result<VerifiedReleaseBundleV1, S> {
        Ok(self.0.clone())
    }
}

#[test]
fn a_bundle_of_another_address_is_not_found_and_rolls_back_nothing() -> TestResult {
    let (mut world, first, second) = two_installed()?;
    let source = Fixed(world.store.read_verified(second.address())?);
    let material = world.material()?;
    let mut clock = wall(material.utc)?;
    let request = request_for(&world.anchor, world.timeline, &material);
    let registry = &mut world.registry;
    let address = first.address();
    let result = rollback_community_release_v1(&source, address, registry, &mut clock, &request);
    assert_eq!(result.err(), Some(Rollback::Source(S::NotFound)));
    assert_nothing_rolled_back(&world, 2)
}

#[test]
fn an_expired_target_is_refused_by_the_entry_before_the_registry() -> TestResult {
    let (mut world, first, _second) = two_installed()?;
    let material = world.expired_material()?;
    let result = roll_back_with(&mut world, first.address(), &material)?;
    let refused = result.err().ok_or("the rollback was not refused")?;
    assert!(matches!(
        refused,
        Rollback::Rollback(Entry::Authorization(_))
    ));
    assert_eq!(host_error_for_rollback_v1(refused), EXPIRED);
    assert_nothing_rolled_back(&world, 2)
}

#[test]
fn a_rollback_to_the_active_release_is_refused_by_the_registry() -> TestResult {
    let (mut world, _first, second) = two_installed()?;
    let result = roll_back(&mut world, second.address())?;
    let refused = result.err().ok_or("the rollback was not refused")?;
    assert_eq!(
        refused,
        Rollback::Rollback(Entry::Registry(Reg::RollbackTargetActive))
    );
    assert_eq!(host_error_for_rollback_v1(refused), TSU);
    assert_eq!(world.registry.rollbacks.len(), 1);
    assert_eq!(events(&world)?.len(), 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// The total host error mapping
// ---------------------------------------------------------------------------

/// The number of arms `index` distinguishes: two outer ones and five wrapped ones.
const ARMS: usize = 7;
const MANIFEST: PluginManifestErrorV1 = PluginManifestErrorV1::InvalidEncoding { ordinal: 3 };

/// The arm of one input in the two rollback enums: `0` and `1` for the outer `Source` and
/// `Manifest`, `2` and up for the wrapped entry error. Both matches are exhaustive without a
/// wildcard, so a variant added later fails to compile here until it is given a row.
const fn index(error: &Rollback) -> usize {
    match error {
        Rollback::Source(_) => 0,
        Rollback::Manifest(_) => 1,
        Rollback::Rollback(inner) => {
            2 + match inner {
                Entry::Source(_) => 0,
                Entry::Manifest(_) => 1,
                Entry::Authorization(_) => 2,
                Entry::Signature(_) => 3,
                Entry::Registry(_) => 4,
            }
        }
    }
}

/// The install failure that `error` mirrors, variant for variant.
fn as_install(error: &Rollback) -> Install {
    match error.clone() {
        Rollback::Source(inner) => Install::Source(inner),
        Rollback::Manifest(inner) => Install::Manifest(inner),
        Rollback::Rollback(inner) => Install::Install(match inner {
            Entry::Source(inner) => Installer::Source(inner),
            Entry::Manifest(inner) => Installer::Manifest(inner),
            Entry::Authorization(inner) => Installer::Authorization(inner),
            Entry::Signature(inner) => Installer::Signature(inner),
            Entry::Registry(inner) => Installer::Registry(inner),
        }),
    }
}

/// Every row maps to its expected host error, and to the host error of its install twin.
fn assert_rows(rows: &[(Rollback, Host)]) {
    for (input, expected) in rows {
        assert_eq!(
            host_error_for_rollback_v1(input.clone()),
            *expected,
            "{input:?}"
        );
        let twin = host_error_for_install_v1(as_install(input));
        assert_eq!(twin, *expected, "{input:?}");
    }
}

const fn entry(error: Entry) -> Rollback {
    Rollback::Rollback(error)
}

const fn reg(error: Reg) -> Rollback {
    entry(Entry::Registry(error))
}

#[test]
fn every_variant_of_both_rollback_errors_has_a_row() {
    let rows = [
        (Rollback::Source(S::NotFound), TSU),
        (Rollback::Manifest(MANIFEST), INVALID),
        (entry(Entry::Source(S::DigestMismatch)), INVALID),
        (entry(Entry::Manifest(MANIFEST)), INVALID),
        (entry(Entry::Authorization(Trust::PublisherKeyRevoked)), KEY),
        (entry(Entry::Signature(Sig::InvalidSignature)), UNTRUSTED),
        (reg(Reg::ReleaseNotActive), NOT_ACTIVE),
    ];
    assert_rows(&rows);
    let mut listed: Vec<usize> = rows.iter().map(|(input, _)| index(input)).collect();
    listed.sort_unstable();
    assert_eq!(listed, (0..ARMS).collect::<Vec<_>>());
}

#[test]
fn rollback_refusals_use_the_existing_rows() {
    let rows = [
        (Rollback::Source(S::DigestMismatch), INVALID),
        (entry(Entry::Source(S::NotFound)), TSU),
        (entry(Entry::Signature(Sig::Manifest(MANIFEST))), INVALID),
        (
            entry(Entry::Authorization(Trust::ArtifactRevoked)),
            ARTIFACT,
        ),
        (entry(Entry::Authorization(Trust::ManifestExpired)), EXPIRED),
        (reg(Reg::UnknownRollbackTarget), TSU),
        (reg(Reg::NoActiveRelease), TSU),
        (reg(Reg::RollbackTargetActive), TSU),
        (reg(Reg::ReleaseProofMismatch), TSU),
        (reg(Reg::PolicyNotAdvanced), MISMATCH),
        (reg(Reg::Trust(Trust::ArtifactRevoked)), ARTIFACT),
    ];
    assert_rows(&rows);
}
