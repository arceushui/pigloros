//! R8-W1: `gate_for_driver` and its inner `gate_at`, on the shared signed-release test world
//! (installed at second 50 and Tick 5; the shipped manifest is valid for seconds `[40, 60)`).

use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_plugin_publisher::test_support::{
    encoding::TICK,
    release::{pmf1_digest, Shape, COMPONENT_BYTES},
    world::World,
    BoxResult,
};

use super::*;
use crate::community_plugin_host::{FixedTrustMaterialSourceV1, TrustDenialBasisV1};

type TestResult = BoxResult<()>;

const PLUGIN_ID: &str = "plugin-a";
const TSU: CommunityPluginHostErrorV1 = CommunityPluginHostErrorV1::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};

/// A world with its first release installed and active, and a source of its current material.
struct Rig {
    world: World,
    address: BundleAddressV1,
    release: [u8; 32],
    material: FixedTrustMaterialSourceV1,
}

impl Rig {
    fn new() -> BoxResult<Self> {
        let mut world = World::new()?;
        let published = world.publish(Shape::first())?;
        world.install(published.address(), 1)??;
        let current = world.material()?;
        let material = FixedTrustMaterialSourceV1::new(CommunityPluginTrustMaterialV1::new(
            world.anchor.clone(),
            current.root_anchor().clone(),
            current.tps1.clone(),
            vec![current.ptr1().to_vec()],
            current.prv1_records().to_vec(),
        ));
        Ok(Self {
            address: published.address().clone(),
            release: published.release_digest(),
            world,
            material,
        })
    }
}

fn expectation() -> CommunityPluginExpectationV1 {
    CommunityPluginExpectationV1 {
        plugin_id: PLUGIN_ID.to_owned(),
        release: None,
    }
}

/// A scripted source with one sample at `second` and a spare one at second 70.
fn wall_at(second: u64) -> ScriptedTrustedWallSourceV1 {
    ScriptedTrustedWallSourceV1::from_micros([second * 1_000_000, 70_000_000])
}

fn gate_at_second(
    rig: &Rig,
    second: u64,
) -> Result<GatedCommunityReleaseV1, CommunityPluginHostErrorV1> {
    let registry: &dyn PluginTrustPolicyRegistryV1 = &rig.world.registry;
    let mut wall = wall_at(second);
    gate_for_driver(
        registry,
        &expectation(),
        &rig.world.store,
        &rig.address,
        &rig.material,
        &mut wall,
        TICK,
    )
}

#[test]
fn an_installed_release_is_gated_at_exactly_one_sampled_second() -> TestResult {
    let rig = Rig::new()?;
    let registry: &dyn PluginTrustPolicyRegistryV1 = &rig.world.registry;
    let mut wall = wall_at(50);
    let gated = gate_for_driver(
        registry,
        &expectation(),
        &rig.world.store,
        &rig.address,
        &rig.material,
        &mut wall,
        TICK,
    )?;
    assert_eq!(wall.remaining(), 1, "one sample was consumed");
    assert_eq!(gated.plugin_id(), PLUGIN_ID);
    assert_eq!(gated.release_digest(), rig.release);
    assert_eq!(gated.component(), COMPONENT_BYTES);
    assert_eq!((gated.utc_second(), gated.tick()), (50, TICK));
    Ok(())
}

#[test]
fn the_gated_second_is_the_sampled_one() -> TestResult {
    let rig = Rig::new()?;
    assert_eq!(gate_at_second(&rig, 59)?.utc_second(), 59);
    let expired = gate_at_second(&rig, 60).err();
    let basis = TrustDenialBasisV1::Expired;
    let denied = CommunityPluginHostErrorV1::ArtifactTrustDenied { basis };
    assert_eq!(expired, Some(denied));
    Ok(())
}

#[test]
fn gating_for_a_driver_writes_nothing_to_the_registry() -> TestResult {
    let rig = Rig::new()?;
    let bundle = rig.world.store.read_verified(&rig.address)?;
    let digests = [pmf1_digest(&bundle)];
    let before = rig.world.snapshot(&digests)?;
    gate_at_second(&rig, 50)?;
    gate_at_second(&rig, 55)?;
    assert_eq!(rig.world.snapshot(&digests)?, before);
    Ok(())
}

#[test]
fn a_registry_refusal_maps_by_the_gate_rows() -> TestResult {
    let mut rig = Rig::new()?;
    let successor = rig.world.publish(Shape {
        version: "2.0.0",
        previous: Some(rig.release),
        ..Shape::first()
    })?;
    let registry: &dyn PluginTrustPolicyRegistryV1 = &rig.world.registry;
    let mut wall = wall_at(50);
    let refused = gate_for_driver(
        registry,
        &expectation(),
        &rig.world.store,
        successor.address(),
        &rig.material,
        &mut wall,
        TICK,
    );
    let basis = TrustDenialBasisV1::NotActive;
    let not_active = CommunityPluginHostErrorV1::ArtifactTrustDenied { basis };
    assert_eq!(refused.err(), Some(not_active));
    Ok(())
}

#[test]
fn an_unavailable_clock_is_trust_state_unavailable_before_any_read() -> TestResult {
    let rig = Rig::new()?;
    let calls = rig.world.registry.calls.borrow().len();
    let registry: &dyn PluginTrustPolicyRegistryV1 = &rig.world.registry;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([]);
    let refused = gate_for_driver(
        registry,
        &expectation(),
        &rig.world.store,
        &rig.address,
        &rig.material,
        &mut wall,
        TICK,
    );
    assert_eq!(refused.err(), Some(TSU));
    assert_eq!(rig.world.registry.calls.borrow().len(), calls);
    Ok(())
}

#[test]
fn the_inner_gate_given_a_closed_pass_calls_no_registry() -> TestResult {
    let rig = Rig::new()?;
    let calls = rig.world.registry.calls.borrow().len();
    let pass = CommunityPassV1::open_at_for_test(50, TICK)?;
    let open = gate_at(
        &rig.world.registry,
        &expectation(),
        &rig.world.store,
        &rig.address,
        &rig.material,
        &pass,
    );
    assert!(open.is_ok(), "the open pass is gated");
    let after_open = rig.world.registry.calls.borrow().len();
    assert_eq!(after_open, calls + 1, "an open pass evaluates once");
    pass.close_for_test();
    let closed = gate_at(
        &rig.world.registry,
        &expectation(),
        &rig.world.store,
        &rig.address,
        &rig.material,
        &pass,
    );
    assert_eq!(closed.err(), Some(TSU));
    assert_eq!(rig.world.registry.calls.borrow().len(), after_open);
    Ok(())
}
