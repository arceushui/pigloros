//! The host pass seam at its public API (ADR-061 revision 7 decision 10, #584), on the shared
//! signed-release test world of `pos-plugin-publisher` and the supervisor's pass harness.
//!
//! Every vector installs real signed releases into the world's Memory registry, builds each
//! Driver from the release the gate accepted, and runs whole passes through
//! `CommunityPluginHostV1::run_pass` over the probe worker. The probe's Component bytes name its
//! behaviour (`draft:<type>` stages one Event, `fuel` fails). The world's evidence is built at
//! second 50 and Tick 5.
#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_core::PluginId;
use pos_plugin_publisher::test_support::{
    encoding::{Material, Spec as Coordinates, TICK, UTC},
    release::Shape,
    spy_registry::Call,
    world::{wall, Config, World as SignedWorld},
    BoxResult, ScriptedTrustedWallSourceV1,
};
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1};
use pos_plugin_supervisor::pass_harness::{
    initial, FailingPort, GatedSpec, LostPort, PanickingSource, Source, StampedPort,
    World as PassWorld,
};
use pos_plugin_supervisor::test_support::{self, err};
use pos_plugin_supervisor::{
    CommunityMemberV1, CommunityPluginHandleV1, InvocationContextSourceV1, ReceiptDispositionV1,
};
use pos_runtime::community_plugin_host::{
    gate_community_release_v1, AtomicCommitFailureV1, CommunityPassAuthorizationV1,
    CommunityPassOutcomeV1, CommunityPassV1, CommunityPluginExpectationV1,
    CommunityPluginHostErrorV1, CommunityPluginHostV1, CommunityPluginMemberV1,
    CommunityPluginTrustMaterialV1, CommunityStageV1, MemberPassV1, PassResultV1,
    PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1, RevocationBasisV1,
    TrustDenialBasisV1,
};
use pos_runtime::{PluginAvailabilityV1 as Availability, PluginRegistry, RuntimeError};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1 as Reg;

type Error = CommunityPluginHostErrorV1;
type TestResult = BoxResult<()>;
/// The coordinates, predecessor TPS1 digest and evidence of a policy advance.
type Advance = (Coordinates, Option<[u8; 32]>, Material);

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
/// A generous watchdog for invocations that should finish promptly.
const PROMPT: Duration = Duration::from_mins(1);
/// The Plugin IDs the world's PTR1 grants besides the default `plugin-a`.
const GRANTED: &[&str] = &["plugin-b", "plugin-c"];
/// A release digest that no fixture release has.
const UNRELATED: [u8; 32] = [0x77; 32];
/// A sample second that differs from the second the world's evidence is built at.
const SAMPLE: i64 = 55;
/// The registry's mirror of an available Plugin.
const AVAILABLE: Option<Availability> = Some(Availability::Available);
/// The registry's mirror of a revoked Plugin.
const REVOKED: Option<Availability> = Some(Availability::Revoked);

const TSU: Error = Error::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};
const NOT_ACTIVE: Error = Error::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::NotActive,
};
const MISMATCH: Error = Error::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::PolicyMismatch,
};
const ARTIFACT: Error = Error::ArtifactRevoked {
    basis: RevocationBasisV1::Artifact,
};
const KEY: Error = Error::ArtifactRevoked {
    basis: RevocationBasisV1::PublisherKey,
};
const INVALID: Error = Error::InvalidInvocation;
/// The classification of a store error at admission.
const COMMIT_FAILED: Error = Error::AtomicCommitFailed {
    failure: AtomicCommitFailureV1::Operational,
};

/// One member of a rig: the Plugin ID, the Event type it owns, the probe behaviour, and whether
/// its Driver misbehaves or stays out of the registry.
#[derive(Clone, Copy)]
struct Spec {
    plugin_id: &'static str,
    event_type: &'static str,
    component: &'static [u8],
    panics: bool,
    registered: bool,
}

impl Spec {
    /// The release shape that publishes this member's Plugin and probe behaviour.
    const fn shape(&self) -> Shape {
        Shape {
            plugin_id: self.plugin_id,
            component: self.component,
            ..Shape::first()
        }
        .with_optional_capability()
    }
}

const ALPHA: Spec = Spec {
    plugin_id: "plugin-a",
    event_type: "community.alpha",
    component: b"draft:community.alpha",
    panics: false,
    registered: true,
};
const BETA: Spec = Spec {
    plugin_id: "plugin-b",
    event_type: "community.beta",
    component: b"draft:community.beta",
    ..ALPHA
};
const GAMMA: Spec = Spec {
    plugin_id: "plugin-c",
    event_type: "community.gamma",
    component: b"draft:community.gamma",
    ..ALPHA
};
/// A first member whose worker exhausts its fuel.
const FUEL_ALPHA: Spec = Spec {
    component: b"fuel",
    ..ALPHA
};
/// A first member that echoes its state, to tell a committed state from a staged one.
const CHAIN_ALPHA: Spec = Spec {
    component: b"chain:community.alpha",
    ..ALPHA
};
/// A first member whose invocation source panics.
const PANIC_ALPHA: Spec = Spec {
    panics: true,
    ..ALPHA
};
/// A second member whose Driver is built but never registered.
const UNREGISTERED_BETA: Spec = Spec {
    registered: false,
    ..BETA
};

/// A material source the test swaps between passes; a clone shares the material.
#[derive(Clone)]
struct Swap(Rc<RefCell<Option<CommunityPluginTrustMaterialV1>>>);

impl Swap {
    fn of(material: CommunityPluginTrustMaterialV1) -> Self {
        Self(Rc::new(RefCell::new(Some(material))))
    }

    fn set(&self, material: Option<CommunityPluginTrustMaterialV1>) {
        *self.0.borrow_mut() = material;
    }
}

impl PluginTrustMaterialSourceV1 for Swap {
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1> {
        let current = self.0.borrow().clone();
        current.ok_or(PluginTrustMaterialUnavailableV1)
    }
}

fn trust_material(world: &SignedWorld, material: &Material) -> CommunityPluginTrustMaterialV1 {
    CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    )
}

/// What the rig keeps of one member.
struct Part {
    handle: CommunityPluginHandleV1,
    address: BundleAddressV1,
    swap: Swap,
    expected: CommunityPluginExpectationV1,
    release: [u8; 32],
}

/// The signed-release world, the pass world, and a host over one member per spec.
struct Rig {
    signed: SignedWorld,
    pass: PassWorld,
    host: CommunityPluginHostV1<CommunityMemberV1>,
    parts: Vec<Part>,
    material: CommunityPluginTrustMaterialV1,
    refuse: Arc<AtomicBool>,
}

/// The source of the Driver of `spec`.
fn source_for(
    spec: &Spec,
    number: u8,
    refuse: &Arc<AtomicBool>,
) -> Box<dyn InvocationContextSourceV1> {
    if spec.panics {
        Box::new(PanickingSource)
    } else {
        Box::new(Source::switched(number, Arc::clone(refuse)))
    }
}

/// Publish and install the release of `spec`, gate it once, and build its Driver from the gated
/// release. The gate here only supplies the Driver's release, so its calls are not a pass's.
fn add_member(
    signed: &mut SignedWorld,
    pass: &mut PassWorld,
    spec: &Spec,
    number: u8,
    material: &CommunityPluginTrustMaterialV1,
    refuse: &Arc<AtomicBool>,
) -> BoxResult<Part> {
    let published = signed.publish(spec.shape())?;
    let installed = signed.install(published.address(), number)?;
    installed.map_err(|error| format!("install failed: {error}"))?;
    let swap = Swap::of(material.clone());
    let expected = CommunityPluginExpectationV1 {
        plugin_id: spec.plugin_id.to_owned(),
        release: None,
    };
    let open = CommunityPassV1::open_at_for_test(u32::try_from(UTC)?, TICK)?;
    let (gated, _authorization) = gate_community_release_v1(
        &signed.registry,
        &expected,
        &signed.store,
        published.address(),
        &swap,
        &open,
    )?;
    let built = pass.add_gated(GatedSpec {
        name: spec.plugin_id,
        event_type: spec.event_type,
        gated,
        watchdog: PROMPT,
        source: source_for(spec, number, refuse),
        register: spec.registered,
    })?;
    Ok(Part {
        handle: built.handle,
        address: published.address().clone(),
        swap,
        expected: built.expected,
        release: published.release_digest(),
    })
}

impl Rig {
    fn new(specs: &[Spec]) -> BoxResult<Self> {
        Self::build(specs, None)
    }

    fn build(specs: &[Spec], clock: Option<Arc<AtomicU64>>) -> BoxResult<Self> {
        let mut signed = SignedWorld::with_config(Config {
            extra_plugin_ids: GRANTED,
            clock,
            ..Config::default()
        })?;
        let mut pass = PassWorld::new(PROBE);
        let material = trust_material(&signed, &signed.material()?);
        let refuse = Arc::new(AtomicBool::new(false));
        let mut parts = Vec::new();
        for (index, wanted) in specs.iter().enumerate() {
            let number = u8::try_from(index)? + 1;
            let added = add_member(&mut signed, &mut pass, wanted, number, &material, &refuse)?;
            parts.push(added);
        }
        let mut rig = Self {
            signed,
            pass,
            host: CommunityPluginHostV1::new(Vec::new()),
            parts,
            material,
            refuse,
        };
        rig.restart()?;
        Ok(rig)
    }

    /// The members the composition builds for `addresses`, one per member in order, each over a
    /// freshly opened source of the same store, as after a restart.
    fn members_at(&self, addresses: &[BundleAddressV1]) -> BoxResult<Vec<CommunityMemberV1>> {
        let member = |(part, address): (&Part, &BundleAddressV1)| -> BoxResult<CommunityMemberV1> {
            Ok(CommunityMemberV1::new(
                part.handle.clone(),
                Box::new(self.signed.root.store()?),
                address.clone(),
                Box::new(part.swap.clone()),
                part.expected.clone(),
            ))
        };
        self.parts.iter().zip(addresses).map(member).collect()
    }

    fn addresses(&self) -> Vec<BundleAddressV1> {
        let address = |part: &Part| part.address.clone();
        self.parts.iter().map(address).collect()
    }

    /// Replace the host by one over members re-supplied from the same addresses.
    fn restart(&mut self) -> TestResult {
        let members = self.members_at(&self.addresses())?;
        self.host = CommunityPluginHostV1::new(members);
        Ok(())
    }

    fn handle(&self, index: usize) -> &CommunityPluginHandleV1 {
        &self.parts[index].handle
    }

    fn swap(&self, index: usize) -> &Swap {
        &self.parts[index].swap
    }

    /// Feed every member the world's current material again, after a fixture changed it.
    fn sync_material(&mut self) -> TestResult {
        self.material = trust_material(&self.signed, &self.signed.material()?);
        for part in &self.parts {
            part.swap.set(Some(self.material.clone()));
        }
        Ok(())
    }

    fn run(&mut self) -> BoxResult<CommunityPassOutcomeV1> {
        self.run_at(TICK)
    }

    fn run_at(&mut self, tick: u64) -> BoxResult<CommunityPassOutcomeV1> {
        let mut clock = wall(UTC)?;
        self.run_clocked(&mut clock, tick)
    }

    /// One pass at `tick` that samples `clock`.
    fn run_clocked(
        &mut self,
        clock: &mut ScriptedTrustedWallSourceV1,
        tick: u64,
    ) -> BoxResult<CommunityPassOutcomeV1> {
        let registry = &self.signed.registry;
        Ok(self.pass.run(&mut self.host, registry, clock, tick)?)
    }

    /// One pass whose admission goes through a port stamped from `clock`, and the stamps.
    fn run_stamped(
        &mut self,
        clock: &Arc<AtomicU64>,
        wall: &mut ScriptedTrustedWallSourceV1,
    ) -> BoxResult<(CommunityPassOutcomeV1, Vec<u64>)> {
        let prepared = self.pass.prepare()?;
        let mut port = StampedPort::new(&mut self.pass.store, Arc::clone(clock));
        let request = prepared.request(TICK, &mut port);
        let registry = &self.signed.registry;
        let host = &mut self.host;
        let outcome = host.run_pass(&mut self.pass.registry, registry, wall, request);
        Ok((outcome, port.stamps().to_vec()))
    }

    /// Whether no member launched a worker in the pass.
    fn nothing_launched(&self) -> bool {
        let idle = |part: &Part| part.handle.receipts().is_empty();
        self.parts.iter().all(idle)
    }

    /// Whether every member's last failure is `error`.
    fn every_failure_is(&self, error: Error) -> bool {
        let marked = |part: &Part| part.handle.last_failure() == Some(error);
        self.parts.iter().all(marked)
    }

    fn all_slots_empty(&self) -> bool {
        self.parts.iter().all(|part| slot_is_empty(&part.handle))
    }

    /// The registry's mirror of the availability of member `index`.
    fn registry_availability(&self, index: usize) -> Option<Availability> {
        let plugin = self.handle(index).plugin_id();
        self.pass.registry.availability(plugin)
    }

    /// Adopt the policy advance through the host's policy refresh at `tick`, and make the signed
    /// world's current evidence follow it, as `advance_to` does for a fixture adoption.
    fn adopt(&mut self, advance: Advance, tick: u64) -> TestResult {
        let (coordinates, previous, material) = advance;
        let supplied = trust_material(&self.signed, &material);
        let mut clock = wall(material.utc)?;
        let registry = &mut self.signed.registry;
        let host = &mut self.host;
        let _outcome = host.refresh_policy(registry, &supplied, &mut clock, tick)?;
        self.signed.spec = coordinates;
        self.signed.previous = previous;
        self.sync_material()
    }
}

/// Whether the slot of `handle` is empty: an offer into it succeeds, and is then withdrawn.
fn slot_is_empty(handle: &CommunityPluginHandleV1) -> bool {
    let record = test_support::negotiated();
    let authorization = test_support::authorization_for(&record, b"slot");
    let empty = handle.offer_authorization(authorization).is_ok();
    handle.close_pass();
    empty
}

fn gate_error(entry: &MemberPassV1) -> Option<Error> {
    entry.gate.as_ref().err().copied()
}

fn gate_errors(outcome: &CommunityPassOutcomeV1) -> Vec<Option<Error>> {
    outcome.gates.iter().map(gate_error).collect()
}

fn launch_failures(outcome: &CommunityPassOutcomeV1) -> Vec<Option<Error>> {
    let failure = |entry: &MemberPassV1| entry.launch_failure;
    outcome.gates.iter().map(failure).collect()
}

fn invocation_ids(outcome: &CommunityPassOutcomeV1) -> Vec<Option<[u8; 16]>> {
    let id = |entry: &MemberPassV1| entry.invocation_id;
    outcome.gates.iter().map(id).collect()
}

/// The number of Events the pass committed, if it committed.
fn committed_events(outcome: &CommunityPassOutcomeV1) -> Option<usize> {
    match &outcome.result {
        PassResultV1::Committed(Some(receipt)) => Some(receipt.committed_events().len()),
        _ => None,
    }
}

const fn is_refused(outcome: &CommunityPassOutcomeV1) -> bool {
    matches!(outcome.result, PassResultV1::Refused)
}

const fn is_in_doubt(outcome: &CommunityPassOutcomeV1) -> bool {
    matches!(outcome.result, PassResultV1::InDoubt)
}

fn dispositions(handle: &CommunityPluginHandleV1) -> Vec<ReceiptDispositionV1> {
    let receipts = handle.receipts();
    receipts.iter().map(|receipt| receipt.disposition).collect()
}

/// A wall source with no sample, which fails.
fn silent() -> ScriptedTrustedWallSourceV1 {
    ScriptedTrustedWallSourceV1::from_micros(Vec::<u64>::new())
}

/// R7-S1: the sample is proved before every gate by value flow, and every gate is ordered before
/// admission by the shared clock.
#[test]
fn the_sample_precedes_every_gate_and_every_gate_precedes_admission() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let mut rig = Rig::build(&[ALPHA, BETA], Some(Arc::clone(&clock)))?;
    let before = rig.signed.registry.calls.borrow().len();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([55_700_000, 60_000_000]);
    let (outcome, admits) = rig.run_stamped(&clock, &mut wall)?;

    // One sample, floored to its second; the pass carries the explicit Tick.
    assert_eq!(wall.remaining(), 1);
    assert_eq!((outcome.utc, outcome.tick), (Some(SAMPLE), TICK));
    assert_eq!(committed_events(&outcome), Some(2), "{outcome:?}");
    let calls = rig.signed.registry.calls.borrow().clone();
    let evaluations: Vec<_> = calls
        .iter()
        .skip(before)
        .filter_map(|call| match call {
            Call::Evaluate { stamp, utc, tick } => Some((*stamp, *utc, *tick)),
            Call::Admit(_) => None,
        })
        .collect();
    assert_eq!(evaluations.len(), 2, "{calls:?}");
    let at_the_sample = |(_, utc, tick): &(u64, i64, u64)| (*utc, *tick) == (SAMPLE, TICK);
    assert!(evaluations.iter().all(at_the_sample));
    // Every gate stamp is below the one stamp of the admission.
    assert_eq!(admits.len(), 1);
    assert!(evaluations.iter().all(|(stamp, _, _)| *stamp < admits[0]));

    // Close and sync, as post-conditions: every slot is empty, the registry is mirrored.
    assert!(rig.all_slots_empty());
    assert_eq!(rig.registry_availability(0), AVAILABLE);
    assert_eq!(rig.registry_availability(1), AVAILABLE);
    assert!(outcome.gates.iter().all(|entry| entry.sync.is_ok()));
    Ok(())
}

/// R7-S1: a refused pass has no admit stamp.
#[test]
fn a_refused_pass_makes_no_admission_call() -> TestResult {
    let clock = Arc::new(AtomicU64::new(0));
    let mut rig = Rig::build(&[ALPHA, BETA], Some(Arc::clone(&clock)))?;
    rig.swap(1).set(None);
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([50_000_000]);
    let (outcome, admits) = rig.run_stamped(&clock, &mut wall)?;
    assert!(is_refused(&outcome), "{outcome:?}");
    assert!(admits.is_empty());
    Ok(())
}

/// R7-S1: the plain anchored stage call, which takes no committed prefix, commits the pass too.
#[test]
fn the_plain_anchored_stage_call_commits_the_pass() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let mut clock = wall(UTC)?;
    let prepared = rig.pass.prepare()?;
    let request = prepared.anchored_request(TICK, &mut rig.pass.store);
    let registry = &rig.signed.registry;
    let host = &mut rig.host;
    let outcome = host.run_pass(&mut rig.pass.registry, registry, &mut clock, request);
    assert_eq!(committed_events(&outcome), Some(2), "{outcome:?}");
    Ok(())
}

/// R7-S2: one refused gate refuses the whole pass of three members, launches nothing, stages
/// nothing, reports every gate, records the refusal and gates again at the next pass.
#[test]
fn a_gate_refusal_of_one_member_refuses_the_whole_pass() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA, GAMMA])?;
    rig.swap(1).set(None);
    let outcome = rig.run()?;
    assert!(is_refused(&outcome), "{outcome:?}");
    assert_eq!(gate_errors(&outcome), [None, Some(TSU), None]);
    assert_eq!(launch_failures(&outcome), [None, Some(TSU), None]);
    assert!(outcome.gates[0].gate.is_ok());
    // No worker was launched and nothing was staged.
    assert!(rig.nothing_launched());
    assert!(rig.pass.events().is_empty());
    // The refusal was recorded for the refused member only.
    assert_eq!(rig.handle(1).last_failure(), Some(TSU));
    assert_eq!(rig.handle(0).last_failure(), None);
    assert_eq!(rig.handle(2).last_failure(), None);
    assert!(rig.all_slots_empty());

    // The next pass gates again, and now commits.
    rig.swap(1).set(Some(rig.material.clone()));
    let next = rig.run()?;
    assert_eq!(committed_events(&next), Some(3), "{next:?}");
    assert!(next.gates.iter().all(|entry| entry.gate.is_ok()));
    Ok(())
}

/// R7-S3: material that differs from the retained state is `PolicyMismatch` until the host
/// refreshes the policy, which calls `advance_policy`.
#[test]
fn unadopted_material_is_a_mismatch_until_the_policy_is_refreshed() -> TestResult {
    let mut rig = Rig::new(&[ALPHA])?;
    let newer = rig.signed.unadopted_material(&[UNRELATED], TICK)?;
    let supplied = trust_material(&rig.signed, &newer);
    rig.swap(0).set(Some(supplied.clone()));
    let refused = rig.run()?;
    assert_eq!(gate_errors(&refused), [Some(MISMATCH)]);

    let mut clock = wall(newer.utc)?;
    let registry = &mut rig.signed.registry;
    let host = &mut rig.host;
    let _outcome = host.refresh_policy(registry, &supplied, &mut clock, TICK)?;
    let adopted = rig.run()?;
    assert_eq!(committed_events(&adopted), Some(1), "{adopted:?}");
    Ok(())
}

/// R7-S3: a clock failure and a record that does not verify are returned before the registry is
/// touched.
#[test]
fn a_policy_refresh_fails_on_the_clock_and_on_unverifiable_records() -> TestResult {
    let mut rig = Rig::new(&[ALPHA])?;
    let supplied = rig.material.clone();
    let registry = &mut rig.signed.registry;
    let host = &mut rig.host;
    let clockless = host.refresh_policy(registry, &supplied, &mut silent(), TICK);
    assert!(matches!(clockless, Err(Reg::TrustedTimeUnavailable)));
    // The PTR1 and PRV1 records expire at second 100.
    let mut late = wall(150)?;
    let expired = host.refresh_policy(registry, &supplied, &mut late, TICK);
    assert!(matches!(expired, Err(Reg::Trust(_))));
    Ok(())
}

/// R7-S4: a Plugin revoked after activation is quarantined `Revoked`, every later pass is
/// refused, and clearing the quarantine meets a fresh refusal at the next gate (the disclosed
/// registry-wide deadlock; #560 changes it).
#[test]
fn a_revoked_plugin_refuses_every_later_pass_until_the_deadlock_is_resolved() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let first = rig.run()?;
    assert_eq!(committed_events(&first), Some(2), "{first:?}");

    let release = rig.parts[0].release;
    rig.signed.advance_revoking_artifacts(&[release])??;
    rig.sync_material()?;
    for _ in 0..2 {
        let refused = rig.run()?;
        assert!(is_refused(&refused), "{refused:?}");
        assert_eq!(gate_errors(&refused), [Some(ARTIFACT), None]);
        assert_eq!(rig.handle(0).availability(), Availability::Revoked);
        assert_eq!(rig.registry_availability(0), REVOKED);
    }
    // The healthy sibling never ran again.
    assert_eq!(rig.handle(1).receipts().len(), 1);

    let alpha = rig.handle(0).clone();
    alpha.clear_quarantine(&mut rig.pass.registry)?;
    assert_eq!(alpha.availability(), Availability::Available);
    let fresh = rig.run()?;
    assert_eq!(gate_errors(&fresh), [Some(ARTIFACT), None]);
    assert_eq!(launch_failures(&fresh), [Some(ARTIFACT), None]);
    assert_eq!(rig.handle(0).last_failure(), Some(ARTIFACT));
    Ok(())
}

/// R7-S5: nothing is usable after a pass, on success and on each refusal path.
#[test]
fn every_slot_is_empty_after_a_success_and_after_a_refusal() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let committed = rig.run()?;
    assert_eq!(committed_events(&committed), Some(2), "{committed:?}");
    assert!(rig.all_slots_empty());
    // A gate refusal.
    rig.swap(0).set(None);
    let refused = rig.run()?;
    assert!(is_refused(&refused), "{refused:?}");
    assert!(rig.all_slots_empty());
    // A sample failure.
    let unsampled = rig.run_clocked(&mut silent(), TICK)?;
    assert!(is_refused(&unsampled), "{unsampled:?}");
    assert!(rig.all_slots_empty());
    Ok(())
}

/// R7-S5: a failure while staging: the first member exhausts its fuel, so the second never runs
/// and its authorization is unconsumed until the pass closes.
#[test]
fn every_slot_is_empty_after_a_failure_while_staging() -> TestResult {
    let mut rig = Rig::new(&[FUEL_ALPHA, BETA])?;
    let failed = rig.run()?;
    let PassResultV1::Failed { host, error } = &failed.result else {
        std::panic::resume_unwind(Box::new(format!("the pass did not fail: {failed:?}")))
    };
    assert_eq!(*host, Some(Error::FuelExhausted));
    assert!(matches!(
        **error,
        RuntimeError::CommunityPlugin(Error::FuelExhausted)
    ));
    assert!(rig.handle(1).receipts().is_empty());
    assert!(rig.all_slots_empty());
    Ok(())
}

/// R7-S5: a Driver whose source panics is caught by the registry; the pass fails and every slot
/// is empty.
#[test]
fn every_slot_is_empty_after_a_driver_panics() -> TestResult {
    let mut rig = Rig::new(&[PANIC_ALPHA, BETA])?;
    let failed = rig.run()?;
    assert!(
        matches!(failed.result, PassResultV1::Failed { host: None, .. }),
        "{failed:?}"
    );
    assert!(rig.all_slots_empty());
    Ok(())
}

/// How a probe member treats the authorization offered to it.
#[derive(Clone, Copy)]
enum Mode {
    /// Offer it to the real member.
    Forward,
    /// Keep it in the stash and leave the member's slot empty.
    Stash,
    /// Panic instead of offering it.
    PanicOffer,
    /// Offer it, and panic when the member's invocation ID is read.
    PanicId,
}

/// The authorizations that probe members kept.
type Stash = Rc<RefCell<Vec<CommunityPassAuthorizationV1>>>;

/// A member that delegates to a real one, except as its mode says.
struct Probe {
    inner: CommunityMemberV1,
    mode: Mode,
    stash: Stash,
}

impl CommunityPluginMemberV1 for Probe {
    fn plugin(&self) -> PluginId {
        self.inner.plugin()
    }

    fn expectation(&self) -> &CommunityPluginExpectationV1 {
        self.inner.expectation()
    }

    fn release_source(&self) -> &dyn ReleaseSourceV1 {
        self.inner.release_source()
    }

    fn release_address(&self) -> &BundleAddressV1 {
        self.inner.release_address()
    }

    fn trust_material(&self) -> &dyn PluginTrustMaterialSourceV1 {
        self.inner.trust_material()
    }

    fn offer_authorization(
        &self,
        authorization: CommunityPassAuthorizationV1,
    ) -> Result<(), Error> {
        match self.mode {
            Mode::Stash => {
                self.stash.borrow_mut().push(authorization);
                Ok(())
            }
            Mode::PanicOffer => std::panic::resume_unwind(Box::new("the offer panicked")),
            Mode::Forward | Mode::PanicId => self.inner.offer_authorization(authorization),
        }
    }

    fn record_refusal(&self, error: Error) {
        self.inner.record_refusal(error);
    }

    fn close_pass(&self) {
        self.inner.close_pass();
    }

    fn pass_failure(&self) -> Option<Error> {
        self.inner.pass_failure()
    }

    fn pass_invocation_id(&self) -> Option<[u8; 16]> {
        if matches!(self.mode, Mode::PanicId) {
            std::panic::resume_unwind(Box::new("the member panicked"));
        }
        self.inner.pass_invocation_id()
    }

    fn sync_registry(&self, registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
        self.inner.sync_registry(registry)
    }
}

impl Rig {
    /// A host over probe members, one per mode in order, and the stash they share.
    fn probes(&self, modes: &[Mode]) -> BoxResult<(CommunityPluginHostV1<Probe>, Stash)> {
        let stash = Stash::default();
        let members = self.members_at(&self.addresses())?;
        let probe = |(inner, mode): (CommunityMemberV1, &Mode)| Probe {
            inner,
            mode: *mode,
            stash: Rc::clone(&stash),
        };
        let probes: Vec<Probe> = members.into_iter().zip(modes).map(probe).collect();
        Ok((CommunityPluginHostV1::new(probes), stash))
    }

    /// One pass of `host` at the rig's second and Tick; a panic out of `run_pass` is the error.
    fn run_probes(
        &mut self,
        host: &mut CommunityPluginHostV1<Probe>,
    ) -> BoxResult<CommunityPassOutcomeV1> {
        let mut clock = wall(UTC)?;
        let prepared = self.pass.prepare()?;
        let caught = catch_unwind(AssertUnwindSafe(|| {
            let request = prepared.request(TICK, &mut self.pass.store);
            let registry = &self.signed.registry;
            host.run_pass(&mut self.pass.registry, registry, &mut clock, request)
        }));
        caught.map_err(|_| "the pass panicked".into())
    }
}

/// Whether every authorization the probes kept reports its pass closed.
fn stash_is_closed(stash: &Stash) -> bool {
    let kept = stash.borrow();
    !kept.is_empty() && kept.iter().all(|held| !held.is_pass_open())
}

/// R7-S5: the pass-open flag is closed when `run_pass` returns normally.
#[test]
fn a_pass_closes_the_authorizations_it_issued() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let (mut host, stash) = rig.probes(&[Mode::Stash, Mode::Stash])?;
    let outcome = rig.run_probes(&mut host)?;
    // The slots stayed empty, so the Drivers could not launch.
    let failed = matches!(outcome.result, PassResultV1::Failed { host: Some(TSU), .. });
    assert!(failed, "{outcome:?}");
    assert_eq!(stash.borrow().len(), 2);
    assert!(stash_is_closed(&stash));
    Ok(())
}

/// R7-S5: a panic that unwinds out of a member still closes the pass-open flag and the slots.
#[test]
fn a_panic_out_of_a_member_still_closes_the_pass() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let (mut host, stash) = rig.probes(&[Mode::Stash, Mode::PanicId])?;
    let outcome = rig.run_probes(&mut host);
    assert!(outcome.is_err(), "the panic must unwind");
    assert!(stash_is_closed(&stash));
    assert!(rig.all_slots_empty());
    Ok(())
}

/// R7-S5: a panic in the second member's offer leaves the first member's slot occupied at the
/// unwind, and the guard empties it.
#[test]
fn a_panic_in_an_offer_leaves_no_slot_occupied() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let (mut host, _stash) = rig.probes(&[Mode::Forward, Mode::PanicOffer])?;
    let outcome = rig.run_probes(&mut host);
    assert!(outcome.is_err(), "the panic must unwind");
    assert!(rig.nothing_launched());
    assert!(rig.all_slots_empty());
    Ok(())
}

/// One pass whose admission loses the commit acknowledgement.
fn lost_commit(rig: &mut Rig) -> BoxResult<CommunityPassOutcomeV1> {
    let mut clock = wall(UTC)?;
    let prepared = rig.pass.prepare()?;
    let mut port = LostPort(&mut rig.pass.store);
    let request = prepared.request(TICK, &mut port);
    let registry = &rig.signed.registry;
    let host = &mut rig.host;
    Ok(host.run_pass(&mut rig.pass.registry, registry, &mut clock, request))
}

/// R7-S5: a lost commit acknowledgement is reported `InDoubt` and keeps the staged state for
/// `recover_scheduled_pass`.
#[test]
fn a_lost_commit_is_in_doubt_and_keeps_the_staged_state() -> TestResult {
    let mut rig = Rig::new(&[CHAIN_ALPHA, BETA])?;
    let outcome = lost_commit(&mut rig)?;
    assert!(is_in_doubt(&outcome), "{outcome:?}");
    for handle in [rig.handle(0), rig.handle(1)] {
        assert_eq!(handle.committed_state(), initial());
        assert_eq!(dispositions(handle), [ReceiptDispositionV1::Staged]);
    }
    assert!(rig.all_slots_empty());

    let store = &mut rig.pass.store;
    let recovered = rig.pass.registry.recover_scheduled_pass(store)?;
    assert_eq!(recovered.map(|r| r.committed_events().len()), Some(2));
    assert_eq!(rig.handle(0).committed_state().bytes, b"initial+");
    Ok(())
}

/// R7-S5: a deterministic admission failure is a failed pass, not in doubt; the staged state is
/// discarded and every slot is empty.
#[test]
fn a_failed_admission_discards_the_pass_and_empties_every_slot() -> TestResult {
    let mut rig = Rig::new(&[CHAIN_ALPHA, BETA])?;
    let mut clock = wall(UTC)?;
    let prepared = rig.pass.prepare()?;
    let mut port = FailingPort(&mut rig.pass.store);
    let request = prepared.request(TICK, &mut port);
    let registry = &rig.signed.registry;
    let host = &mut rig.host;
    let outcome = host.run_pass(&mut rig.pass.registry, registry, &mut clock, request);
    let failed = matches!(outcome.result, PassResultV1::Failed { host: Some(COMMIT_FAILED), .. });
    assert!(failed, "{outcome:?}");
    for handle in [rig.handle(0), rig.handle(1)] {
        assert_eq!(handle.committed_state(), initial());
        assert_eq!(dispositions(handle), [ReceiptDispositionV1::Discarded]);
    }
    assert!(rig.all_slots_empty());
    Ok(())
}

/// Whether `shown` mentions every word.
fn mentions(shown: &str, words: &[&str]) -> bool {
    words.iter().all(|word| shown.contains(word))
}

/// Every result and the stage call format, so that a failed assertion can show them.
#[test]
fn outcomes_and_stage_calls_format() -> TestResult {
    let mut committed = Rig::new(&[ALPHA, BETA])?;
    let shown = format!("{:?}", committed.run()?);
    let words = ["Committed", "plugin-a", "MemberPassV1", "tps1_digest"];
    assert!(mentions(&shown, &words), "{shown}");

    let mut refused = Rig::new(&[ALPHA])?;
    refused.swap(0).set(None);
    let shown = format!("{:?}", refused.run()?);
    let words = ["Refused", "TrustStateUnavailable"];
    assert!(mentions(&shown, &words), "{shown}");

    let mut failed = Rig::new(&[FUEL_ALPHA, BETA])?;
    let shown = format!("{:?}", failed.run()?);
    assert!(mentions(&shown, &["Failed", "FuelExhausted"]), "{shown}");

    let mut doubtful = Rig::new(&[ALPHA])?;
    let shown = format!("{:?}", lost_commit(&mut doubtful)?);
    assert!(mentions(&shown, &["InDoubt"]), "{shown}");

    let events = [];
    let with_events = format!("{:?}", CommunityStageV1::WithEvents(&events));
    assert!(mentions(&with_events, &["WithEvents"]), "{with_events}");
    assert_eq!(format!("{:?}", CommunityStageV1::Anchored), "Anchored");
    Ok(())
}

/// R7-S6: one UTC second per pass, however many members and gates.
#[test]
fn a_pass_takes_exactly_one_sample() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA, GAMMA])?;
    let mut clock = ScriptedTrustedWallSourceV1::from_micros([50_000_000; 5]);
    let outcome = rig.run_clocked(&mut clock, TICK)?;
    assert_eq!(committed_events(&outcome), Some(3), "{outcome:?}");
    assert_eq!(clock.remaining(), 4);
    Ok(())
}

/// R7-S6: a failing sample refuses every member, records each refusal, and calls no registry.
#[test]
fn a_failing_sample_refuses_every_member_without_a_registry_call() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA, GAMMA])?;
    let before = rig.signed.registry.calls.borrow().len();
    let outcome = rig.run_clocked(&mut silent(), TICK)?;
    assert!(is_refused(&outcome), "{outcome:?}");
    assert_eq!(outcome.utc, None);
    assert_eq!(gate_errors(&outcome), [Some(TSU); 3]);
    assert_eq!(launch_failures(&outcome), [Some(TSU); 3]);
    assert!(rig.every_failure_is(TSU));
    assert_eq!(rig.signed.registry.calls.borrow().len(), before);
    assert!(rig.nothing_launched());
    Ok(())
}

/// A rig whose first pass committed both members.
fn after_a_committed_pass() -> BoxResult<Rig> {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    let first = rig.run()?;
    assert_eq!(committed_events(&first), Some(2), "{first:?}");
    assert_eq!(invocation_ids(&first), [Some([1; 16]), Some([2; 16])]);
    Ok(rig)
}

/// R7-S7: a sibling refuses the gate in the next pass; nothing of the first pass is carried.
#[test]
fn a_sibling_gate_refusal_leaves_no_stale_attribution() -> TestResult {
    let mut rig = after_a_committed_pass()?;
    rig.swap(1).set(None);
    let second = rig.run()?;
    assert_eq!(invocation_ids(&second), [None, None]);
    assert_eq!(launch_failures(&second), [None, Some(TSU)]);
    assert_eq!(gate_errors(&second), [None, Some(TSU)]);
    Ok(())
}

/// R7-S7: a quarantined member has no launch failure and no invocation ID: it was not run.
#[test]
fn a_quarantined_member_is_not_run_and_carries_nothing() -> TestResult {
    let mut rig = after_a_committed_pass()?;
    rig.handle(0).record_refusal(Error::FuelExhausted);
    let alpha = rig.handle(0);
    assert_eq!(alpha.availability(), Availability::ResourceExhausted);
    let second = rig.run()?;
    assert!(
        matches!(second.result, PassResultV1::Failed { host: None, .. }),
        "{second:?}"
    );
    assert_eq!(invocation_ids(&second), [None, None]);
    assert_eq!(launch_failures(&second), [None, None]);
    assert_eq!(gate_errors(&second), [None, None]);
    Ok(())
}

/// R7-S7: a context source that fails in the next pass leaves the member without an invocation
/// ID, and its failure is this pass's.
#[test]
fn a_failing_context_source_leaves_no_invocation_id() -> TestResult {
    let mut rig = after_a_committed_pass()?;
    rig.refuse.store(true, Ordering::SeqCst);
    let second = rig.run()?;
    assert_eq!(invocation_ids(&second), [None, None]);
    assert_eq!(launch_failures(&second), [Some(INVALID), None]);
    let failed = matches!(second.result, PassResultV1::Failed { host: Some(INVALID), .. });
    assert!(failed, "{second:?}");
    Ok(())
}

/// R7-S8: an occupied slot fails the offer and refuses the whole pass.
#[test]
fn an_occupied_slot_refuses_the_whole_pass() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA, GAMMA])?;
    let record = test_support::negotiated();
    let held = test_support::authorization_for(&record, b"held");
    rig.handle(1).offer_authorization(held)?;
    let outcome = rig.run()?;
    assert!(is_refused(&outcome), "{outcome:?}");
    assert_eq!(gate_errors(&outcome), [None, Some(INVALID), None]);
    assert_eq!(launch_failures(&outcome), [None, Some(INVALID), None]);
    // Nothing was launched or staged, and the earlier offer was dropped with the held one.
    assert!(rig.nothing_launched());
    assert!(rig.pass.events().is_empty());
    assert!(rig.all_slots_empty());
    Ok(())
}

/// A member whose Driver is not registered still gets its slot closed, and its failed sync is
/// reported in its entry without changing the result.
#[test]
fn a_failed_sync_is_reported_in_the_entry_and_not_in_the_result() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, UNREGISTERED_BETA])?;
    let outcome = rig.run()?;
    assert_eq!(committed_events(&outcome), Some(1), "{outcome:?}");
    assert!(outcome.gates[0].sync.is_ok());
    assert!(outcome.gates[1].sync.is_err());
    assert!(rig.all_slots_empty());
    Ok(())
}

/// R7-B3: a gate-time denial only marks the Plugin and the next pass gates it again.
#[test]
fn a_denial_only_marks_the_plugin_and_the_next_pass_gates_it_again() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    rig.swap(0).set(None);
    let denied = rig.run()?;
    assert_eq!(gate_errors(&denied), [Some(TSU), None]);
    assert_eq!(rig.handle(0).availability(), Availability::Available);
    assert_eq!(rig.handle(0).last_failure(), Some(TSU));
    assert_eq!(rig.registry_availability(0), AVAILABLE);
    rig.swap(0).set(Some(rig.material.clone()));
    let regated = rig.run()?;
    assert_eq!(committed_events(&regated), Some(2), "{regated:?}");
    Ok(())
}

/// R7-B3: a gate-time revocation recorded through `record_refusal` quarantines the Plugin
/// `Revoked`, and the sync mirrors it into the registry.
#[test]
fn a_revocation_quarantines_the_plugin_and_the_sync_mirrors_it() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    rig.signed.advance_revoking_keys(&[1])??;
    rig.sync_material()?;
    let revoked = rig.run()?;
    assert_eq!(gate_errors(&revoked), [Some(KEY), Some(KEY)]);
    for index in 0..2 {
        assert_eq!(rig.handle(index).availability(), Availability::Revoked);
        assert_eq!(rig.registry_availability(index), REVOKED);
    }
    Ok(())
}

/// R7-B7: an authorization in a member slot does not survive a policy refresh; one held outside
/// a slot stays valid until its creator closes its pass; a gate after the refresh reflects the
/// new policy.
#[test]
fn a_policy_refresh_empties_slots_and_leaves_held_authorizations() -> TestResult {
    let mut rig = Rig::new(&[ALPHA])?;
    let old = rig.material.clone();
    let record = test_support::negotiated();
    let offered = test_support::authorization_for(&record, b"offered");
    rig.handle(0).offer_authorization(offered)?;

    // A pass the test opens and holds an authorization of.
    let expected = CommunityPluginExpectationV1 {
        plugin_id: ALPHA.plugin_id.to_owned(),
        release: None,
    };
    let open = CommunityPassV1::open_at_for_test(u32::try_from(UTC)?, TICK)?;
    let (_gated, held) = gate_community_release_v1(
        &rig.signed.registry,
        &expected,
        &rig.signed.store,
        &rig.parts[0].address,
        rig.swap(0),
        &open,
    )?;

    let newer = rig.signed.unadopted_material(&[UNRELATED], TICK)?;
    let new_material = trust_material(&rig.signed, &newer);
    let mut clock = wall(newer.utc)?;
    let registry = &mut rig.signed.registry;
    let host = &mut rig.host;
    let _outcome = host.refresh_policy(registry, &new_material, &mut clock, TICK)?;

    // The slot is empty: the Driver's launch is `TrustStateUnavailable`.
    let launch = err(rig.pass.stage_offered());
    let refused = matches!(launch, RuntimeError::CommunityPlugin(TSU));
    assert!(refused, "{launch:?}");
    // The held authorization stays valid until its creator closes the pass.
    assert!(held.is_pass_open());
    open.close_for_test();
    assert!(!held.is_pass_open());

    // A new gate reflects the new policy: the old material no longer matches the retained TPS1.
    let fresh = CommunityPassV1::open_at_for_test(u32::try_from(UTC)?, TICK)?;
    let regate = |material: &CommunityPluginTrustMaterialV1| {
        let source = Swap::of(material.clone());
        let gate = gate_community_release_v1(
            &rig.signed.registry,
            &expected,
            &rig.signed.store,
            &rig.parts[0].address,
            &source,
            &fresh,
        );
        gate.err()
    };
    assert_eq!(regate(&old), Some(MISMATCH));
    assert_eq!(regate(&new_material), None);
    Ok(())
}

/// R7-G5c: the revocation sequence of R7-G5a, with every adoption through `refresh_policy`.
#[test]
fn a_revocation_adopted_through_the_host_refuses_from_its_tick() -> TestResult {
    let mut rig = Rig::new(&[ALPHA])?;
    let effective = TICK + 4;
    let release = rig.parts[0].release;

    // The `e+1` record carries Tick `T` and is adopted at `T - 1`.
    let signed = &rig.signed;
    let first = signed.unadopted_advance(&[release], effective, effective - 1)?;
    rig.adopt(first, effective - 1)?;
    let before = rig.run_at(effective - 1)?;
    assert_eq!(gate_errors(&before), [None], "{before:?}");
    let at = rig.run_at(effective)?;
    assert_eq!(gate_errors(&at), [Some(MISMATCH)], "{at:?}");

    // The `e+2` record repeats the set at a Tick of at least `T`, and its TPS1 lists the denial.
    let second = rig.signed.unadopted_advance(&[], effective, effective)?;
    rig.adopt(second, effective)?;
    let refused = rig.run_at(effective)?;
    assert_eq!(gate_errors(&refused), [Some(ARTIFACT)], "{refused:?}");
    Ok(())
}

/// R7-C1b: the composition's re-supplied pairs after a simulated restart are the ones `run_pass`
/// uses; an address that holds another release, another Plugin or nothing is refused.
#[test]
fn the_resupplied_pairs_after_a_restart_are_the_ones_the_pass_uses() -> TestResult {
    let mut rig = Rig::new(&[ALPHA, BETA])?;
    rig.restart()?;
    let restarted = rig.run()?;
    assert_eq!(committed_events(&restarted), Some(2), "{restarted:?}");

    // A different release of the same Plugin ID, published but never installed.
    let successor = Shape {
        version: "2.0.0",
        previous: Some(rig.parts[0].release),
        ..ALPHA.shape()
    };
    let successor = rig.signed.publish(successor)?;
    // A release of another Plugin ID.
    let foreign = rig.signed.publish(GAMMA.shape())?;
    // An address that holds nothing in this store.
    let mut elsewhere = SignedWorld::new()?;
    let absent = elsewhere.publish(Shape::first())?;

    let own = rig.addresses();
    let wrong = [
        (successor.address(), NOT_ACTIVE),
        (foreign.address(), NOT_ACTIVE),
        (absent.address(), TSU),
    ];
    for (address, expected) in wrong {
        let members = rig.members_at(&[address.clone(), own[1].clone()])?;
        rig.host = CommunityPluginHostV1::new(members);
        let before = rig.signed.registry.calls.borrow().len();
        let refused = rig.run()?;
        let after = rig.signed.registry.calls.borrow().len();
        assert!(is_refused(&refused), "{refused:?}");
        assert_eq!(gate_errors(&refused), [Some(expected), None]);
        // Only the second member, at its own address, reached the registry.
        assert_eq!(after - before, 1);
    }
    Ok(())
}
