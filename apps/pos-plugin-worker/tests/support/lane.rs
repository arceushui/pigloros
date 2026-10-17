//! Signed-release lanes on the real `pos-plugin-worker` binary (ADR-061 revision 7, #585).
//!
//! A lane runs the real compatibility fixtures. It publishes and installs real signed releases
//! into the shared signed-release test world of `pos-plugin-publisher`, builds each Driver from
//! the release the gate accepted, and runs whole host passes through
//! `CommunityPluginHostV1::run_pass` over the supervisor's pass world. The handoff vectors and
//! the community pipeline conformance runners share it.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use pos_plugin_publisher::test_support::{
    encoding::{Material, TICK, UTC},
    release::Shape,
    world::{wall, World as SignedWorld},
    BoxResult, BundleAddressV1,
};
use pos_plugin_supervisor::pass_harness::{GatedSpec, Source, World as PassWorld};
use pos_plugin_supervisor::{
    CommunityMemberV1, CommunityPluginHandleV1, CommunityPluginSubjectOutcomeV1 as Outcome,
};
use pos_runtime::community_plugin_host::{
    gate_community_release_v1, pinned_runtime_v1, CommunityPassOutcomeV1, CommunityPassV1,
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginExpectationV1,
    CommunityPluginHostV1, CommunityPluginModeV1, CommunityPluginTrustMaterialV1,
    GatedCommunityReleaseV1, MemberPassV1, PassResultV1, PluginTrustMaterialSourceV1,
    PluginTrustMaterialUnavailableV1,
};

use super::subcase::WORKER;

type TestResult = BoxResult<()>;
type Mode = CommunityPluginModeV1;
type Host = CommunityPluginHostV1<CommunityMemberV1>;

/// Bytes of one committed compatibility fixture.
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            "../../../../plugins/community/examples/compatibility-prototype/fixtures/",
            $name
        ))
    };
}

/// The committed Rust guest.
pub const RUST_GUEST: &[u8] = fixture!("rust-guest.wasm");
/// The committed C guest.
pub const C_GUEST: &[u8] = fixture!("c-guest.wasm");
/// The worker watchdog of every member.
///
/// Generous for compiling a fixture in an unoptimized, instrumented worker.
/// A ceiling only: a healthy invocation finishes far sooner.
pub const WATCHDOG: Duration = Duration::from_mins(5);
/// The memory budget of the fixtures' releases: 256 pages (16 MiB).
///
/// The Rust guest reserves 17 pages (1.1 MiB) at start and the world's default budget is one
/// page.
pub const MEMORY: u64 = 16 * 1_048_576;
/// The one Event type both fixtures' `drive` export emits.
pub const EVENT_TYPE: &str = "prototype.driven";

/// One member of a lane.
///
/// It names the Plugin ID, the Component it publishes, and whether its Driver is registered in
/// the pass world.
#[derive(Clone, Copy)]
pub struct Spec {
    /// The Plugin ID of the release.
    pub plugin_id: &'static str,
    /// The Component the release publishes.
    pub guest: &'static [u8],
    /// Whether the Driver is registered in the pass world.
    pub registered: bool,
}

impl Spec {
    /// The release shape that publishes this member.
    #[must_use]
    pub const fn shape(&self) -> Shape {
        Shape {
            plugin_id: self.plugin_id,
            component: self.guest,
            ..Shape::first()
        }
        .with_optional_capability()
        .with_worker_abi()
        .with_memory_bytes(MEMORY)
    }
}

/// The first member, on the Rust fixture.
pub const ALPHA: Spec = Spec {
    plugin_id: "plugin-a",
    guest: RUST_GUEST,
    registered: true,
};
/// The first member, on the C fixture.
pub const ALPHA_C: Spec = Spec {
    guest: C_GUEST,
    ..ALPHA
};

/// A material source the test swaps between passes; a clone shares the material.
#[derive(Clone)]
pub struct Swap(Rc<RefCell<Option<CommunityPluginTrustMaterialV1>>>);

impl Swap {
    /// A source that supplies `material`.
    #[must_use]
    pub fn of(material: CommunityPluginTrustMaterialV1) -> Self {
        Self(Rc::new(RefCell::new(Some(material))))
    }

    /// Supply `material` from now on, or nothing.
    pub fn set(&self, material: Option<CommunityPluginTrustMaterialV1>) {
        *self.0.borrow_mut() = material;
    }
}

impl PluginTrustMaterialSourceV1 for Swap {
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1> {
        let current = self.0.borrow().clone();
        current.ok_or(PluginTrustMaterialUnavailableV1)
    }
}

/// The trust material of `world` with the policy records of `material`.
#[must_use]
pub fn trust_material(world: &SignedWorld, material: &Material) -> CommunityPluginTrustMaterialV1 {
    CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    )
}

/// The host profile of `mode`: what the worker's own pinned runtime equals.
#[must_use]
pub fn profile(mode: Mode) -> CommunityPluginExecutionProfileV1 {
    let ceilings = CommunityPluginCeilingsV1::V1;
    CommunityPluginExecutionProfileV1::new(mode, ceilings, Some(pinned_runtime_v1()))
}

/// A release published and installed in the signed world.
#[derive(Clone)]
pub struct Published {
    /// The member the release publishes.
    pub spec: Spec,
    /// The closure address of the release.
    pub address: BundleAddressV1,
    /// The release digest.
    pub release: [u8; 32],
}

/// Publish the release of `spec` and install it as the active release, with activation `tag`.
///
/// # Errors
/// Returns the signed world's publication or installation error.
pub fn publish(signed: &mut SignedWorld, spec: Spec, tag: u8) -> BoxResult<Published> {
    publish_shape(signed, spec, spec.shape(), tag)
}

/// As [`publish`], for an explicit `shape` of `spec`.
///
/// # Errors
/// Returns the signed world's publication or installation error.
pub fn publish_shape(
    signed: &mut SignedWorld,
    spec: Spec,
    shape: Shape,
    tag: u8,
) -> BoxResult<Published> {
    let published = signed.publish(shape)?;
    let installed = signed.install(published.address(), tag)?;
    installed.map_err(|error| format!("install failed: {error}"))?;
    Ok(Published {
        spec,
        address: published.address().clone(),
        release: published.release_digest(),
    })
}

/// What a lane's members are built from.
struct Setup<'a> {
    signed: &'a SignedWorld,
    material: CommunityPluginTrustMaterialV1,
    refuse: Arc<AtomicBool>,
    profile: CommunityPluginExecutionProfileV1,
}

/// What the lane keeps of one member.
pub struct Part {
    /// The member's Driver handle.
    pub handle: CommunityPluginHandleV1,
    /// The closure address the member is supplied from.
    pub address: BundleAddressV1,
    /// The member's trust material source.
    pub swap: Swap,
    /// The Plugin ID and release the Driver was built for.
    pub expected: CommunityPluginExpectationV1,
}

/// Gate the release of `entry` once, to build its Driver from. The gate here only supplies the
/// Driver's release, so its call is not a pass's.
fn gated_release(
    signed: &SignedWorld,
    entry: &Published,
    swap: &Swap,
) -> BoxResult<GatedCommunityReleaseV1> {
    let expected = CommunityPluginExpectationV1 {
        plugin_id: entry.spec.plugin_id.to_owned(),
        release: None,
    };
    let open = CommunityPassV1::open_at_for_test(u32::try_from(UTC)?, TICK)?;
    let (gated, _authorization) = gate_community_release_v1(
        &signed.registry,
        &expected,
        &signed.store,
        &entry.address,
        swap,
        &open,
    )?;
    Ok(gated)
}

/// Register the Driver of `entry` in `pass` and keep what the lane needs of it.
fn add_part(
    setup: &Setup<'_>,
    pass: &mut PassWorld,
    entry: &Published,
    number: u8,
) -> BoxResult<Part> {
    let swap = Swap::of(setup.material.clone());
    let source = Box::new(Source::switched(number, Arc::clone(&setup.refuse)));
    let built = pass.add_gated(GatedSpec {
        name: entry.spec.plugin_id,
        event_type: EVENT_TYPE,
        gated: gated_release(setup.signed, entry, &swap)?,
        profile: setup.profile.clone(),
        watchdog: WATCHDOG,
        source,
        register: entry.spec.registered,
    })?;
    Ok(Part {
        handle: built.handle,
        address: entry.address.clone(),
        swap,
        expected: built.expected,
    })
}

/// The member of `part` over the closure at `address`, expecting `expected`.
///
/// # Errors
/// Returns the error of opening the signed world's root store.
pub fn member_of(
    signed: &SignedWorld,
    part: &Part,
    address: &BundleAddressV1,
    expected: &CommunityPluginExpectationV1,
) -> BoxResult<CommunityMemberV1> {
    Ok(CommunityMemberV1::new(
        part.handle.clone(),
        Box::new(signed.root.store()?),
        address.clone(),
        Box::new(part.swap.clone()),
        expected.clone(),
    ))
}

/// The member of `part` over its own closure and expectation.
///
/// # Errors
/// Returns the error of opening the signed world's root store.
pub fn member_for(signed: &SignedWorld, part: &Part) -> BoxResult<CommunityMemberV1> {
    member_of(signed, part, &part.address, &part.expected)
}

/// One host over one pass world, in one Execution Mode.
pub struct Lane {
    /// The Execution Mode of every member.
    pub mode: Mode,
    /// The pass world the members' Drivers are registered in.
    pub pass: PassWorld,
    /// The host over the members, in host schedule order.
    pub host: Host,
    /// The members, in host schedule order.
    pub parts: Vec<Part>,
    /// Set to make every member's context source refuse.
    pub refuse: Arc<AtomicBool>,
}

impl Lane {
    /// A lane over a fresh pass world on the real worker, with one member per entry.
    ///
    /// # Errors
    /// Returns the error of gating, building or registering a member.
    pub fn new(signed: &SignedWorld, entries: &[Published], mode: Mode) -> BoxResult<Self> {
        Self::over(signed, entries, mode, PassWorld::new(WORKER))
    }

    /// As [`Self::new`], over `pass`, which may already hold other Drivers.
    ///
    /// # Errors
    /// Returns the error of gating, building or registering a member.
    pub fn over(
        signed: &SignedWorld,
        entries: &[Published],
        mode: Mode,
        mut pass: PassWorld,
    ) -> BoxResult<Self> {
        let refuse = Arc::new(AtomicBool::new(false));
        let setup = Setup {
            signed,
            material: trust_material(signed, &signed.material()?),
            refuse: Arc::clone(&refuse),
            profile: profile(mode),
        };
        let mut parts = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let number = u8::try_from(index)? + 1;
            parts.push(add_part(&setup, &mut pass, entry, number)?);
        }
        let members = parts
            .iter()
            .map(|part| member_for(signed, part))
            .collect::<BoxResult<Vec<_>>>()?;
        Ok(Self {
            mode,
            pass,
            host: CommunityPluginHostV1::new(members),
            parts,
            refuse,
        })
    }

    /// Replace the host by one over the first member alone.
    ///
    /// The member is supplied from `address` and expects `expected`.
    ///
    /// # Errors
    /// Returns the error of opening the signed world's root store.
    pub fn rehost(
        &mut self,
        signed: &SignedWorld,
        address: &BundleAddressV1,
        expected: &CommunityPluginExpectationV1,
    ) -> TestResult {
        let member = member_of(signed, &self.parts[0], address, expected)?;
        self.host = CommunityPluginHostV1::new(vec![member]);
        Ok(())
    }

    /// Supply every member `material`.
    pub fn feed(&self, material: &CommunityPluginTrustMaterialV1) {
        for part in &self.parts {
            part.swap.set(Some(material.clone()));
        }
    }

    /// Supply every member the signed world's current evidence.
    ///
    /// # Errors
    /// Returns the error of reading the signed world's material.
    pub fn follow(&self, signed: &SignedWorld) -> TestResult {
        self.feed(&trust_material(signed, &signed.material()?));
        Ok(())
    }

    /// One pass at the world's Tick whose trusted clock reads `utc`.
    ///
    /// # Errors
    /// Returns the error of the clock or of the pass world's observation.
    pub fn run_at(&mut self, signed: &SignedWorld, utc: i64) -> BoxResult<CommunityPassOutcomeV1> {
        let mut clock = wall(utc)?;
        let registry = &signed.registry;
        let host = &mut self.host;
        Ok(self.pass.run(host, registry, &mut clock, TICK)?)
    }

    /// One pass at the world's Tick and second.
    ///
    /// # Errors
    /// Returns the error of the clock or of the pass world's observation.
    pub fn run(&mut self, signed: &SignedWorld) -> BoxResult<CommunityPassOutcomeV1> {
        self.run_at(signed, UTC)
    }

    /// The subject outcome of every member of `pass`, in host order, as #194 assembles it.
    ///
    /// The receipt is the newest one of the entry's invocation ID.
    #[must_use]
    pub fn outcomes(&self, pass: &CommunityPassOutcomeV1) -> Vec<Outcome> {
        let assemble = |(entry, part): (&MemberPassV1, &Part)| {
            let handle = &part.handle;
            let receipt = entry.invocation_id.and_then(|id| handle.receipt_for(id));
            Outcome::assemble(entry, pass.tick, self.mode, receipt.as_ref())
        };
        pass.gates.iter().zip(&self.parts).map(assemble).collect()
    }

    /// The subject outcome of the first member of `pass`.
    ///
    /// # Errors
    /// Returns an error when the pass has no entry.
    pub fn first(&self, pass: &CommunityPassOutcomeV1) -> BoxResult<Outcome> {
        let assembled = self.outcomes(pass).into_iter().next();
        Ok(assembled.ok_or("the pass has no entry")?)
    }

    /// The handle of the first member.
    #[must_use]
    pub fn handle(&self) -> &CommunityPluginHandleV1 {
        &self.parts[0].handle
    }
}

/// Whether `pass` committed a batch with at least one Event.
#[must_use]
pub const fn is_committed(pass: &CommunityPassOutcomeV1) -> bool {
    matches!(pass.result, PassResultV1::Committed(Some(_)))
}

/// Assert that `pass` committed, printing the lane's first receipts when it did not.
///
/// # Panics
/// Panics when the pass did not commit a batch with an Event.
pub fn assert_committed(lane: &Lane, pass: &CommunityPassOutcomeV1) {
    let receipts = lane.handle().receipts();
    assert!(is_committed(pass), "{pass:?} {receipts:?}");
}

/// Run one pass of the lane and assemble its first outcome, which must be committed.
///
/// # Errors
/// Returns the error of the pass or of assembling its first outcome.
pub fn committed(lane: &mut Lane, signed: &SignedWorld) -> BoxResult<Outcome> {
    let pass = lane.run(signed)?;
    assert_committed(lane, &pass);
    lane.first(&pass)
}
