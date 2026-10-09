//! The community release install entry at its public seam (ADR-061 revision 7 decision 9,
//! vector R7-A2), on the shared signed-release test world of `pos-plugin-publisher`.
//!
//! Every vector installs a real signed release into the world's Memory registry through
//! `install_community_release_v1` and observes the activation Event on the world's Timeline.
#![cfg(target_os = "linux")]

use std::cell::Cell;

use ciborium::Value;
use pos_core::event::{Event, SchemaVersion};
use pos_core::ids::EntityId;
use pos_core::store::{EventStore, SeqRange};
use pos_plugin_publisher::test_support::{
    encoding::{Material, SCOPE},
    release::{pmf1_digest, Shape, COMPONENT_BYTES},
    world::{wall, World},
    BoxResult,
};
use pos_plugin_publisher::{InstalledPluginReleaseV1, PluginReleaseInstallErrorV1};
use pos_plugin_release::{
    BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_runtime::community_plugin_host::{
    install_community_release_v1, ActivationTargetV1, CommunityInstallErrorV1,
    CommunityInstallRequestV1,
};
use pos_store::plugin_trust_registry::PluginTrustCommitOutcomeV1;

type TestResult = BoxResult<()>;
type Installed = Result<InstalledPluginReleaseV1, CommunityInstallErrorV1>;
type Fault = CommunityInstallErrorV1;
type Refusal = PluginReleaseInstallErrorV1;

/// One wrapper call on the world's store, registry, anchor and Timeline.
fn run(
    world: &mut World,
    address: &BundleAddressV1,
    material: &Material,
    entity: EntityId,
) -> BoxResult<Installed> {
    let mut clock = wall(material.utc)?;
    let request = CommunityInstallRequestV1 {
        anchor: &world.anchor,
        tps1_bytes: &material.tps1,
        evidence: &material.evidence,
        target: ActivationTargetV1 {
            timeline: world.timeline,
            entity,
        },
    };
    let registry = &mut world.registry;
    let store = &world.store;
    Ok(install_community_release_v1(
        store, address, registry, &mut clock, request,
    ))
}

/// Install from the world's own store with its current evidence.
fn install(world: &mut World, address: &BundleAddressV1, entity: EntityId) -> BoxResult<Installed> {
    let material = world.material()?;
    run(world, address, &material, entity)
}

fn events(world: &World) -> BoxResult<Vec<Event>> {
    Ok(world.registry.store.read(world.timeline, SeqRange::all())?)
}

/// A source whose second read would return another closure.
struct Flipping {
    first: VerifiedReleaseBundleV1,
    second: VerifiedReleaseBundleV1,
    reads: Cell<usize>,
}

impl ReleaseSourceV1 for Flipping {
    fn read_verified(
        &self,
        _: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        if reads == 0 {
            Ok(self.first.clone())
        } else {
            Ok(self.second.clone())
        }
    }
}

#[test]
fn the_first_install_commits_one_activation_event_on_the_supplied_timeline() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let bundle = world.store.read_verified(published.address())?;
    let entity = EntityId::new();
    let installed = install(&mut world, published.address(), entity)??;
    assert_eq!(
        installed.admission().outcome(),
        PluginTrustCommitOutcomeV1::Committed
    );
    let committed = events(&world)?;
    assert_eq!(committed.len(), 1);
    let event = &committed[0];
    let reserved = "pigloros.plugin.release-activated";
    assert_eq!(event.event_type.as_str(), reserved);
    let origin = event.origin.as_ref();
    assert_eq!(origin.map(|o| o.origin_timeline_id), Some(world.timeline));
    assert_eq!(event.schema_version, SchemaVersion::V1);
    assert_eq!(event.entity, entity);
    let expected = Value::Array(vec![
        Value::Text(SCOPE.to_owned()),
        Value::Text("plugin-a".to_owned()),
        Value::Bytes(pmf1_digest(&bundle).to_vec()),
        Value::Bytes(published.release_digest().to_vec()),
    ]);
    let payload: Value = ciborium::from_reader(event.payload.as_slice())?;
    assert_eq!(payload, expected);
    Ok(())
}

#[test]
fn a_replay_with_another_entity_appends_no_second_event() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let entity = EntityId::new();
    let first = install(&mut world, published.address(), entity)??;
    let first_event = events(&world)?.remove(0);
    let replay = install(&mut world, published.address(), EntityId::new())??;
    assert_eq!(
        replay.admission().outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(
        replay.admission().decision().release_digest(),
        first.admission().decision().release_digest()
    );
    let committed = events(&world)?;
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0].entity, entity);
    assert_eq!(committed[0].id, first_event.id);
    Ok(())
}

#[test]
fn a_source_that_would_change_on_a_second_read_cannot_affect_the_install() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    let other = Shape {
        version: "1.0.1",
        ..world.first_shape()
    };
    let second = world.publish(other)?;
    let source = Flipping {
        first: world.store.read_verified(first.address())?,
        second: world.store.read_verified(second.address())?,
        reads: Cell::new(0),
    };
    let material = world.material()?;
    let mut clock = wall(material.utc)?;
    let request = CommunityInstallRequestV1 {
        anchor: &world.anchor,
        tps1_bytes: &material.tps1,
        evidence: &material.evidence,
        target: ActivationTargetV1 {
            timeline: world.timeline,
            entity: EntityId::new(),
        },
    };
    let registry = &mut world.registry;
    let address = first.address();
    let result = install_community_release_v1(&source, address, registry, &mut clock, request);
    let installed = result?;
    assert_eq!(source.reads.get(), 1);
    let decision = installed.admission().decision();
    assert_eq!(decision.release_digest(), first.release_digest());
    assert_ne!(first.release_digest(), second.release_digest());
    let committed = events(&world)?;
    assert_eq!(committed.len(), 1);
    let payload: Value = ciborium::from_reader(committed[0].payload.as_slice())?;
    let digest = Value::Bytes(first.release_digest().to_vec());
    let items = payload.as_array();
    assert_eq!(items.and_then(|items| items.get(3)), Some(&digest));
    Ok(())
}

#[test]
fn a_source_failure_is_reported_as_source() -> TestResult {
    let mut world = World::new()?;
    let missing = BundleAddressV1::new(format!("sha256:{}", "ab".repeat(32)), 1)?;
    let result = install(&mut world, &missing, EntityId::new())?;
    assert!(matches!(result, Err(Fault::Source(_))));
    assert!(events(&world)?.is_empty());
    Ok(())
}

#[test]
fn a_manifest_failure_is_reported_as_manifest() -> TestResult {
    let mut world = World::new()?;
    let address = world.publish_raw(b"not a PMF1", COMPONENT_BYTES)?;
    let result = install(&mut world, &address, EntityId::new())?;
    assert!(matches!(result, Err(Fault::Manifest(_))));
    assert!(world.registry.admits.is_empty());
    assert!(events(&world)?.is_empty());
    Ok(())
}

#[test]
fn an_installer_refusal_is_reported_as_install() -> TestResult {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let material = world.expired_material()?;
    let address = published.address();
    let result = run(&mut world, address, &material, EntityId::new())?;
    let refused = matches!(result, Err(Fault::Install(Refusal::Authorization(_))));
    assert!(refused);
    assert!(world.registry.admits.is_empty());
    assert!(events(&world)?.is_empty());
    Ok(())
}

/// A hostile source that returns one fixed bundle whatever address is asked for.
struct Fixed(VerifiedReleaseBundleV1);

impl ReleaseSourceV1 for Fixed {
    fn read_verified(
        &self,
        _: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        Ok(self.0.clone())
    }
}

#[test]
fn a_bundle_of_another_address_is_not_found_and_installs_nothing() -> TestResult {
    let mut world = World::new()?;
    let first = world.publish(Shape::first())?;
    let other = Shape {
        version: "1.0.1",
        ..world.first_shape()
    };
    let second = world.publish(other)?;
    let source = Fixed(world.store.read_verified(second.address())?);
    let material = world.material()?;
    let mut clock = wall(material.utc)?;
    let request = CommunityInstallRequestV1 {
        anchor: &world.anchor,
        tps1_bytes: &material.tps1,
        evidence: &material.evidence,
        target: ActivationTargetV1 {
            timeline: world.timeline,
            entity: EntityId::new(),
        },
    };
    let registry = &mut world.registry;
    let address = first.address();
    let result = install_community_release_v1(&source, address, registry, &mut clock, request);
    assert_eq!(
        result.err(),
        Some(Fault::Source(ReleaseSourceErrorV1::NotFound))
    );
    assert!(world.registry.admits.is_empty());
    assert!(events(&world)?.is_empty());
    Ok(())
}
