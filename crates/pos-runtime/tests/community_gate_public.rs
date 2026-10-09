//! The execution-time trust gate at its public seam (ADR-061 revision 7 decisions 2 and 3,
//! ADR-103 revision 5), on the shared signed-release test world of `pos-plugin-publisher`.
//!
//! Every vector installs or publishes a real signed release into the world's Memory registry,
//! feeds the gate the world's raw PTR1 and PRV1 records through a material source, and asserts
//! the host error the mapping assigns to one real fault. The world's evidence is built at
//! second 50 and Tick 5; the shipped manifest is valid for seconds `[40, 60)` and the PTR1 and
//! PRV1 records expire at second 100.
#![cfg(target_os = "linux")]

use std::cell::{Cell, RefCell};

use pos_crypto::plugin_manifest::component_digest_v1;
use pos_plugin_publisher::publish_plugin_release_v1;
use pos_plugin_publisher::test_support::{
    encoding::{Material, OTHER_OWNER, OWNER, SCOPE, TICK},
    release::{make_draft, pmf1_digest, Shape, COMPONENT_BYTES},
    world::{register, wall, Config, World},
    BoxResult,
};
use pos_plugin_release::{
    BundleAddressV1, ContentValidationV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_runtime::community_plugin_host::{
    gate_community_release_v1, CommunityPassAuthorizationV1, CommunityPassV1,
    CommunityPluginExpectationV1, CommunityPluginTrustMaterialV1, GatedCommunityReleaseV1,
    PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1, ReleaseIdentityV1,
};
use pos_store::plugin_trust_registry::{
    PluginTrustPolicyRegistryErrorV1 as Reg, PluginTrustPolicyRegistryV1, TrustedUtcSecondV1,
};

#[path = "common/host_errors.rs"]
pub mod host_errors;
#[path = "common/scripted_registry.rs"]
pub mod scripted_registry;

use host_errors::{Error, ARTIFACT, EXPIRED, KEY, MISMATCH, NOT_ACTIVE, OPERATOR, TSU, UNTRUSTED};
use scripted_registry::Scripted;

type Gate = Result<(GatedCommunityReleaseV1, CommunityPassAuthorizationV1), Error>;
type TestResult = BoxResult<()>;

const PLUGIN_ID: &str = "plugin-a";
/// A release digest that no fixture release has.
const UNRELATED: [u8; 32] = [0x77; 32];

/// A material source the test can swap between passes and whose reads it counts.
struct Source {
    current: RefCell<Option<CommunityPluginTrustMaterialV1>>,
    reads: Cell<usize>,
}

impl Source {
    const fn of(material: CommunityPluginTrustMaterialV1) -> Self {
        Self {
            current: RefCell::new(Some(material)),
            reads: Cell::new(0),
        }
    }

    const fn unavailable() -> Self {
        Self {
            current: RefCell::new(None),
            reads: Cell::new(0),
        }
    }

    fn set(&self, material: CommunityPluginTrustMaterialV1) {
        *self.current.borrow_mut() = Some(material);
    }
}

impl PluginTrustMaterialSourceV1 for Source {
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1> {
        self.reads.set(self.reads.get() + 1);
        let current = self.current.borrow().clone();
        current.ok_or(PluginTrustMaterialUnavailableV1)
    }
}

/// An offline-bundle-shaped source (Air-Gapped): it owns the bytes and builds the material
/// from them on every call.
struct OfflineBundle(CommunityPluginTrustMaterialV1);

impl PluginTrustMaterialSourceV1 for OfflineBundle {
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1> {
        let bundle = &self.0;
        Ok(CommunityPluginTrustMaterialV1::new(
            bundle.policy_anchor().clone(),
            bundle.root_anchor().clone(),
            bundle.tps1_bytes().to_vec(),
            bundle.roots().to_vec(),
            bundle.revocations().to_vec(),
        ))
    }
}

fn trust_material(world: &World, material: &Material) -> CommunityPluginTrustMaterialV1 {
    CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    )
}

/// The material of the world's current evidence.
fn current(world: &World) -> BoxResult<CommunityPluginTrustMaterialV1> {
    Ok(trust_material(world, &world.material()?))
}

fn open_pass(utc: i64, tick: u64) -> BoxResult<CommunityPassV1> {
    let utc = TrustedUtcSecondV1::from_source(&mut wall(utc)?)?;
    Ok(CommunityPassV1::open_for_test(utc, tick))
}

fn expectation(plugin_id: &str) -> CommunityPluginExpectationV1 {
    CommunityPluginExpectationV1 {
        plugin_id: plugin_id.to_owned(),
        release: None,
    }
}

/// One gate call through the counting wrapper: the result and the registry calls it made.
fn run(
    world: &World,
    expected: &CommunityPluginExpectationV1,
    address: &BundleAddressV1,
    source: &dyn PluginTrustMaterialSourceV1,
    pass: &CommunityPassV1,
) -> (Gate, usize) {
    let reg = Scripted::counting(&world.registry);
    let gate = gate_community_release_v1(&reg, expected, &world.store, address, source, pass);
    (gate, reg.calls())
}

/// A world with one release at `address` and a source of the world's current material.
struct Rig {
    world: World,
    address: BundleAddressV1,
    release: [u8; 32],
    source: Source,
}

impl Rig {
    /// The world with its first release installed and active.
    fn new() -> BoxResult<Self> {
        Self::with_world(World::new()?)
    }

    fn with_world(mut world: World) -> BoxResult<Self> {
        let published = world.publish(Shape::first())?;
        world
            .install(published.address(), 1)?
            .map_err(|error| format!("install failed: {error}"))?;
        let source = Source::of(current(&world)?);
        Ok(Self {
            address: published.address().clone(),
            release: published.release_digest(),
            world,
            source,
        })
    }

    /// Feed the source the world's current material again, after a fixture changed it.
    fn sync(&self) -> TestResult {
        self.source.set(current(&self.world)?);
        Ok(())
    }

    fn gate_for(&self, address: &BundleAddressV1, utc: i64, tick: u64) -> BoxResult<Gate> {
        let pass = open_pass(utc, tick)?;
        let expected = expectation(PLUGIN_ID);
        let (gate, _) = run(&self.world, &expected, address, &self.source, &pass);
        Ok(gate)
    }

    fn gate(&self, utc: i64, tick: u64) -> BoxResult<Gate> {
        self.gate_for(&self.address, utc, tick)
    }

    /// The gate's error at second `utc` and Tick `tick`.
    fn error(&self, utc: i64, tick: u64) -> BoxResult<Option<Error>> {
        Ok(self.gate(utc, tick)?.err())
    }
}

fn component_layer(bundle: &VerifiedReleaseBundleV1) -> BoxResult<Vec<u8>> {
    let bytes = bundle
        .members()
        .iter()
        .zip(bundle.member_bytes())
        .find(|(member, _)| member.member() == "component")
        .map(|(_, bytes)| bytes.to_vec());
    bytes.ok_or_else(|| "no component layer".into())
}

/// R7-G1: the happy path yields the registry's facts and the closure's Component.
#[test]
fn an_installed_active_release_gates_ok_with_the_registry_facts() -> TestResult {
    let rig = Rig::new()?;
    let (gated, authorization) = rig.gate(50, TICK)??;
    let bundle = rig.world.store.read_verified(&rig.address)?;
    let component = component_layer(&bundle)?;
    let retained = rig.world.registry.retained_policy_state(SCOPE)?;
    assert_eq!(gated.plugin_id(), PLUGIN_ID);
    assert_eq!(gated.pmf1_digest(), pmf1_digest(&bundle));
    assert_eq!(gated.release_digest(), rig.release);
    assert_eq!(gated.component(), COMPONENT_BYTES);
    assert_eq!(gated.component(), component);
    assert_eq!(gated.component_digest(), component_digest_v1(&component));
    assert_eq!(gated.tps1_digest(), retained.tps1_digest());
    let validation = gated.content_validation();
    assert_eq!(validation, ContentValidationV1::NotPerformed);
    assert_eq!(gated.identity(), authorization.identity());
    assert_eq!((gated.utc_second(), gated.tick()), (50, TICK));
    assert_eq!(gated.execution().plugin_id(), PLUGIN_ID);
    assert_eq!(authorization.plugin_id(), PLUGIN_ID);
    assert_eq!(authorization.pmf1_digest(), gated.pmf1_digest());
    assert_eq!(authorization.release_digest(), gated.release_digest());
    assert_eq!(authorization.component_digest(), gated.component_digest());
    assert_eq!(authorization.tps1_digest(), gated.tps1_digest());
    assert_eq!(authorization.tick(), TICK);
    assert!(authorization.is_pass_open());
    Ok(())
}

/// R7-G2: N gates change nothing the registry holds.
#[test]
fn the_gate_is_read_only() -> TestResult {
    let rig = Rig::new()?;
    let pmf1 = pmf1_digest(&rig.world.store.read_verified(&rig.address)?);
    let before = rig.world.snapshot(&[pmf1])?;
    for tick in [TICK, TICK, TICK + 3] {
        rig.gate(55, tick)??;
    }
    assert_eq!(rig.world.snapshot(&[pmf1])?, before);
    Ok(())
}

/// R7-G3, steps 1-2: a source failure beats every later fault, and a manifest failure beats the
/// identity, the material and the registry.
#[test]
fn closure_phases_come_before_identity_material_and_registry() -> TestResult {
    let rig = Rig::new()?;
    let wrong = expectation("plugin-z");
    let pass = open_pass(120, TICK)?;
    let missing = BundleAddressV1::new(format!("sha256:{}", "ab".repeat(32)), 100)?;
    let broken = Source::unavailable();
    let (gate, calls) = run(&rig.world, &wrong, &missing, &broken, &pass);
    assert_eq!(gate.err(), Some(TSU));
    assert_eq!((broken.reads.get(), calls), (0, 0));
    let garbage = rig.world.publish_raw(b"not a pmf1", COMPONENT_BYTES)?;
    let (gate, calls) = run(&rig.world, &wrong, &garbage, &broken, &pass);
    assert_eq!(gate.err(), Some(Error::InvalidManifest));
    assert_eq!((broken.reads.get(), calls), (0, 0));
    Ok(())
}

/// R7-G3, steps 3-5: identity beats the material, the material beats verification, and
/// verification beats the registry.
#[test]
fn identity_material_and_verification_come_before_the_registry() -> TestResult {
    let rig = Rig::new()?;
    let broken = Source::unavailable();
    let pass = open_pass(120, TICK)?;
    let wrong = expectation("plugin-z");
    let (gate, calls) = run(&rig.world, &wrong, &rig.address, &broken, &pass);
    assert_eq!(gate.err(), Some(NOT_ACTIVE));
    assert_eq!((broken.reads.get(), calls), (0, 0));
    let right = expectation(PLUGIN_ID);
    let (gate, calls) = run(&rig.world, &right, &rig.address, &broken, &pass);
    assert_eq!(gate.err(), Some(TSU));
    assert_eq!((broken.reads.get(), calls), (1, 0));
    // The PTR1 and PRV1 records expire at second 100, which also fails the manifest.
    let (gate, calls) = run(&rig.world, &right, &rig.address, &rig.source, &pass);
    assert_eq!(gate.err(), Some(EXPIRED));
    assert_eq!((rig.source.reads.get(), calls), (1, 0));
    Ok(())
}

/// R7-G4: the expiry rows, one real fault each.
#[test]
fn expiry_rows_map_to_expired() -> TestResult {
    let rig = Rig::new()?;
    // The manifest is valid for seconds `[40, 60)`; the PTR1 and PRV1 records until 100.
    assert!(rig.gate(59, TICK)?.is_ok());
    assert_eq!(rig.error(60, TICK)?, Some(EXPIRED));
    // The world gives the PTR1 and the PRV1 the same expiry (second 100), so their expiry is one
    // fixture: `verify_plugin_trust_v1` reports `Expired` for either.
    assert_eq!(rig.error(100, TICK)?, Some(EXPIRED));
    // The TPS1 of this world is valid offline until second 55.
    let world = World::with_config(Config {
        tps1_valid_through: "1970-01-01T00:00:55Z",
        ..Config::default()
    })?;
    let rig = Rig::with_world(world)?;
    assert!(rig.gate(54, TICK)?.is_ok());
    assert_eq!(rig.error(55, TICK)?, Some(EXPIRED));
    Ok(())
}

/// R7-G4: an unknown publisher key and an ungranted Plugin ID on published, uninstalled releases.
#[test]
fn unknown_key_and_ungranted_plugin_id_map_to_untrusted() -> TestResult {
    let mut rig = Rig::new()?;
    let world = &mut rig.world;
    let second = register(&mut world.keys, OWNER, 2)?;
    let epoch_two = Shape {
        epoch: 2,
        version: "2.0.0",
        ..world.first_shape()
    };
    let unknown = world.publish_with(&second, epoch_two)?;
    let foreign = Shape {
        owner: OTHER_OWNER,
        version: "3.0.0",
        ..world.first_shape()
    };
    let draft = make_draft(foreign)?;
    let ungranted =
        publish_plugin_release_v1(&mut world.keys, &world.other, 1, &draft, &world.store)?;
    let unknown = unknown.address();
    assert_eq!(rig.gate_for(unknown, 50, TICK)?.err(), Some(UNTRUSTED));
    let ungranted = ungranted.address();
    assert_eq!(rig.gate_for(ungranted, 50, TICK)?.err(), Some(UNTRUSTED));
    Ok(())
}

/// R7-G4: stale policy, a forked floor and newer unadopted policy are policy mismatches.
#[test]
fn stale_forked_and_unadopted_policy_map_to_policy_mismatch() -> TestResult {
    let mut rig = Rig::new()?;
    let forked = rig.world.forked_floor_material()?;
    rig.source.set(trust_material(&rig.world, &forked));
    assert_eq!(rig.error(50, TICK)?, Some(MISMATCH));
    let newer = rig.world.unadopted_material(&[UNRELATED], TICK)?;
    rig.source.set(trust_material(&rig.world, &newer));
    assert_eq!(rig.error(50, TICK)?, Some(MISMATCH));
    rig.sync()?;
    assert!(rig.gate(50, TICK)?.is_ok());
    // After an advance the material of the earlier epoch is stale.
    let old = current(&rig.world)?;
    rig.world.advance_revoking_artifacts(&[UNRELATED])??;
    rig.source.set(old);
    assert_eq!(rig.error(50, TICK)?, Some(MISMATCH));
    rig.sync()?;
    assert!(rig.gate(50, TICK)?.is_ok());
    Ok(())
}

/// R7-G4: unreadable material and a poisoned registry handle are `TrustStateUnavailable`.
#[test]
fn unreadable_material_and_a_poisoned_handle_map_to_unavailable() -> TestResult {
    let rig = Rig::new()?;
    let pass = open_pass(50, TICK)?;
    let expected = expectation(PLUGIN_ID);
    let broken = Source::unavailable();
    let (gate, _) = run(&rig.world, &expected, &rig.address, &broken, &pass);
    assert_eq!(gate.err(), Some(TSU));
    let reg = Scripted::failing(&rig.world.registry, Reg::StorePoisoned);
    let (address, source) = (&rig.address, &rig.source);
    let gate = gate_community_release_v1(&reg, &expected, &rig.world.store, address, source, &pass);
    assert_eq!(gate.err(), Some(TSU));
    assert_eq!(reg.calls(), 1);
    Ok(())
}

/// R7-G4: a revoked key, a revoked artifact and the operator's TPS1-only denial.
#[test]
fn revocation_rows_map_to_their_basis() -> TestResult {
    let mut rig = Rig::new()?;
    rig.world.advance_operator_denying(&[rig.release])??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(OPERATOR));
    let mut rig = Rig::new()?;
    rig.world.advance_revoking_artifacts(&[rig.release])??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(ARTIFACT));
    let mut rig = Rig::new()?;
    rig.world.advance_revoking_keys(&[1])??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(KEY));
    Ok(())
}

/// R7-G5a: a revocation adopted before it is effective, then adopted with its denial.
#[test]
fn a_revocation_adopted_before_it_is_effective_refuses_from_its_tick() -> TestResult {
    let mut rig = Rig::new()?;
    let effective = TICK + 4;
    // The `e+1` record carries Tick `T` and is adopted at `T - 1`.
    rig.world
        .advance_revoking_artifacts_at(&[rig.release], effective, effective - 1)??;
    rig.sync()?;
    assert!(rig.gate(50, effective - 1)?.is_ok());
    assert_eq!(rig.error(50, effective)?, Some(MISMATCH));
    // The `e+2` record repeats the set at a Tick of at least `T` and the TPS1 lists the denial.
    rig.world
        .advance_revoking_artifacts_at(&[], effective, effective)??;
    rig.sync()?;
    assert_eq!(rig.error(50, effective)?, Some(ARTIFACT));
    Ok(())
}

/// R7-G5b: material for a revocation that was never adopted fails at every pass Tick.
#[test]
fn a_revocation_that_was_never_adopted_is_a_policy_mismatch_at_every_tick() -> TestResult {
    let mut rig = Rig::new()?;
    let effective = TICK + 4;
    let material = rig.world.unadopted_material(&[rig.release], effective)?;
    rig.source.set(trust_material(&rig.world, &material));
    for tick in [0, effective - 1, effective, effective + 10] {
        assert_eq!(rig.error(50, tick)?, Some(MISMATCH), "tick {tick}");
    }
    rig.world
        .advance_revoking_artifacts_at(&[rig.release], effective, effective)??;
    rig.sync()?;
    assert_eq!(rig.error(50, effective)?, Some(ARTIFACT));
    Ok(())
}

/// R7-G6: a revoking PRV1, once adopted and supplied, is honoured on the next gate.
#[test]
fn swapping_the_material_between_passes_is_honoured_without_a_reinstall() -> TestResult {
    let mut rig = Rig::new()?;
    assert!(rig.gate(50, TICK)?.is_ok());
    rig.world.advance_revoking_artifacts(&[rig.release])??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(ARTIFACT));
    assert_eq!(rig.source.reads.get(), 2);
    Ok(())
}

/// R7-G7: the gate takes the second as a value and reads no clock.
#[test]
fn the_gate_reads_no_clock() -> TestResult {
    let rig = Rig::new()?;
    let mut source = wall(50)?;
    let utc = TrustedUtcSecondV1::from_source(&mut source)?;
    let pass = CommunityPassV1::open_for_test(utc, TICK);
    let expected = expectation(PLUGIN_ID);
    let (gate, _) = run(&rig.world, &expected, &rig.address, &rig.source, &pass);
    assert!(gate.is_ok());
    assert_eq!(source.remaining(), 0);
    assert_eq!(pass.utc(), utc);
    assert_eq!(pass.tick(), TICK);
    Ok(())
}

/// R7-G8: a successor admitted after the Driver was built, and the converse after a rollback.
#[test]
fn a_successor_and_a_rollback_swap_which_release_is_active() -> TestResult {
    let mut rig = Rig::new()?;
    let second = rig.world.publish(Shape {
        version: "2.0.0",
        previous: Some(rig.release),
        ..Shape::first()
    })?;
    rig.world
        .install(second.address(), 2)?
        .map_err(|error| format!("install failed: {error}"))?;
    assert_eq!(rig.gate(50, TICK)?.err(), Some(NOT_ACTIVE));
    assert!(rig.gate_for(second.address(), 50, TICK)?.is_ok());
    rig.world.rollback_to(&rig.address, 3)??;
    assert!(rig.gate(50, TICK)?.is_ok());
    let converse = rig.gate_for(second.address(), 50, TICK)?;
    assert_eq!(converse.err(), Some(NOT_ACTIVE));
    Ok(())
}

/// R7-G9: a stored admission gives no authority once the key is revoked and adopted.
#[test]
fn a_stored_admission_gives_no_authority() -> TestResult {
    let mut rig = Rig::new()?;
    let pmf1 = pmf1_digest(&rig.world.store.read_verified(&rig.address)?);
    let before = rig.world.snapshot(&[pmf1])?;
    assert!(before.decisions[0].is_some());
    rig.world.advance_revoking_keys(&[1])??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(KEY));
    let after = rig.world.snapshot(&[pmf1])?;
    assert_eq!(after.decisions, before.decisions);
    assert_eq!(after.active, before.active);
    Ok(())
}

/// R7-G10: an offline-bundle-shaped source gives identical results, and a bundle whose records
/// have expired at the pass second fails closed.
#[test]
fn an_offline_bundle_source_gives_identical_results_and_expires_with_its_records() -> TestResult {
    let rig = Rig::new()?;
    let offline = OfflineBundle(current(&rig.world)?);
    let expected = expectation(PLUGIN_ID);
    let pass = open_pass(50, TICK)?;
    let (online, _) = run(&rig.world, &expected, &rig.address, &rig.source, &pass);
    let (bundled, _) = run(&rig.world, &expected, &rig.address, &offline, &pass);
    let ((online, _), (bundled, _)) = (online?, bundled?);
    assert_eq!(online, bundled);
    let late = open_pass(100, TICK)?;
    let (gate, _) = run(&rig.world, &expected, &rig.address, &offline, &late);
    assert_eq!(gate.err(), Some(EXPIRED));
    Ok(())
}

/// R7-G11a: two launches at one Tick need two gate calls, each changing no registry state.
#[test]
fn two_launches_at_one_tick_need_two_gate_calls() -> TestResult {
    let rig = Rig::new()?;
    let pmf1 = pmf1_digest(&rig.world.store.read_verified(&rig.address)?);
    let before = rig.world.snapshot(&[pmf1])?;
    let pass = open_pass(50, TICK)?;
    let expected = expectation(PLUGIN_ID);
    let (first, _) = run(&rig.world, &expected, &rig.address, &rig.source, &pass);
    let (second, _) = run(&rig.world, &expected, &rig.address, &rig.source, &pass);
    let ((_, first), (_, second)) = (first?, second?);
    assert_eq!(first.tick(), second.tick());
    assert_eq!(first.component_digest(), second.component_digest());
    assert!(first.is_pass_open() && second.is_pass_open());
    assert_eq!(rig.world.snapshot(&[pmf1])?, before);
    Ok(())
}

/// R7-G12: the gate re-verifies field 26, and a registry denial wins over a signature fault.
#[test]
fn a_bad_signature_is_refused_after_the_registry_accepted_the_release() -> TestResult {
    let mut world = World::new()?;
    let address = world.publish_with_signature(Shape::first(), [0; 64])?;
    world
        .admit_directly(&address, 1)?
        .map_err(|error| format!("direct admission failed: {error}"))?;
    let pmf1 = pmf1_digest(&world.store.read_verified(&address)?);
    assert!(world.snapshot(&[pmf1])?.decisions[0].is_some());
    let source = Source::of(current(&world)?);
    // The release digest is not used by this vector.
    let mut rig = Rig {
        world,
        address,
        release: [0; 32],
        source,
    };
    assert_eq!(rig.error(50, TICK)?, Some(UNTRUSTED));
    rig.world.advance_revoking_keys(&[1])??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(KEY));
    Ok(())
}

/// R7-G13: seconds inside the manifest interval `[40, 60)`, with the highest second 55.
#[test]
fn a_clock_below_the_committed_second_is_refused_and_above_it_accepted() -> TestResult {
    let mut rig = Rig::new()?;
    rig.world.advance_policy_at(5)??;
    rig.sync()?;
    assert_eq!(rig.error(50, TICK)?, Some(TSU));
    assert_eq!(rig.error(54, TICK)?, Some(TSU));
    assert!(rig.gate(55, TICK)?.is_ok());
    // The gate ratchets nothing: a clock that regresses between two gates above the committed
    // second is accepted.
    assert!(rig.gate(58, TICK)?.is_ok());
    assert!(rig.gate(56, TICK)?.is_ok());
    Ok(())
}

/// R7-G14: a gate call on a closed pass is refused before any other step.
#[test]
fn a_closed_pass_is_refused_with_no_registry_call() -> TestResult {
    let rig = Rig::new()?;
    let pass = open_pass(50, TICK)?;
    let expected = expectation(PLUGIN_ID);
    let (gate, _) = run(&rig.world, &expected, &rig.address, &rig.source, &pass);
    let (_, authorization) = gate?;
    assert!(authorization.is_pass_open());
    pass.close_for_test();
    assert!(!pass.is_open());
    assert!(!authorization.is_pass_open());
    let (gate, calls) = run(&rig.world, &expected, &rig.address, &rig.source, &pass);
    assert_eq!(gate.err(), Some(TSU));
    assert_eq!((calls, rig.source.reads.get()), (0, 1));
    Ok(())
}

/// R7-C1: the Component comes from the re-supplied `(source, address)` pair.
#[test]
fn the_component_source_is_the_resupplied_pair() -> TestResult {
    let mut rig = Rig::new()?;
    // A simulated restart: a freshly opened source over the same store.
    let reopened = rig.world.root.store()?;
    let pass = open_pass(50, TICK)?;
    let expected = expectation(PLUGIN_ID);
    let registry = &rig.world.registry;
    let (address, material) = (&rig.address, &rig.source);
    let gate = gate_community_release_v1(registry, &expected, &reopened, address, material, &pass);
    let (gated, _) = gate?;
    assert_eq!(gated.component(), COMPONENT_BYTES);
    // A different release of the same Plugin ID: not active, and with a pair, no registry call.
    let other = rig.world.publish(Shape {
        version: "2.0.0",
        previous: Some(rig.release),
        ..Shape::first()
    })?;
    let first_pmf1 = pmf1_digest(&rig.world.store.read_verified(&rig.address)?);
    let paired = CommunityPluginExpectationV1 {
        release: Some((first_pmf1, rig.release)),
        ..expectation(PLUGIN_ID)
    };
    let (gate, calls) = run(&rig.world, &paired, other.address(), &rig.source, &pass);
    assert_eq!((gate.err(), calls), (Some(NOT_ACTIVE), 0));
    // Without a pair the registry decides: the pointer names another release.
    let (gate, calls) = run(&rig.world, &expected, other.address(), &rig.source, &pass);
    assert_eq!(gate.err(), Some(NOT_ACTIVE));
    assert!(calls >= 1);
    // A release published under another Plugin ID is refused before any registry call.
    let foreign = rig.world.publish(Shape {
        plugin_id: "plugin-b",
        ..Shape::first()
    })?;
    let (gate, calls) = run(&rig.world, &expected, foreign.address(), &rig.source, &pass);
    assert_eq!((gate.err(), calls), (Some(NOT_ACTIVE), 0));
    // An absent address is unavailable.
    let absent = BundleAddressV1::new(format!("sha256:{}", "cd".repeat(32)), 100)?;
    let (gate, _) = run(&rig.world, &expected, &absent, &rig.source, &pass);
    assert_eq!(gate.err(), Some(TSU));
    Ok(())
}

/// The `test-support` authorization has arbitrary fields and follows its pass.
#[test]
fn a_test_support_authorization_has_arbitrary_fields_and_follows_its_pass() -> TestResult {
    let pass = open_pass(50, TICK)?;
    let identity = ReleaseIdentityV1 {
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
    };
    let authorization =
        CommunityPassAuthorizationV1::for_test(&pass, "plugin-x", identity, [3; 32], 99, [4; 32]);
    assert_eq!(authorization.plugin_id(), "plugin-x");
    assert_eq!(authorization.identity(), identity);
    assert_eq!(authorization.pmf1_digest(), [1; 32]);
    assert_eq!(authorization.release_digest(), [2; 32]);
    assert_eq!(authorization.component_digest(), [3; 32]);
    assert_eq!(authorization.tick(), 99);
    assert_eq!(authorization.tps1_digest(), [4; 32]);
    assert!(authorization.is_pass_open());
    pass.close_for_test();
    assert!(!authorization.is_pass_open());
    Ok(())
}
