//! The #194 handoff surface at its public API (ADR-061 revision 7 decisions 12 and 13, #585), on
//! the real `pos-plugin-worker` binary and the real compatibility fixtures.
//!
//! Every vector publishes and installs real signed releases into the shared signed-release test
//! world of `pos-plugin-publisher`, builds each Driver from the release the gate accepted, runs
//! whole host passes through `CommunityPluginHostV1::run_pass`, and assembles the subject
//! outcome of each member with `CommunityPluginSubjectOutcomeV1::assemble`. The world's evidence
//! is built at second 50 and Tick 5. The supervisor's own tests have only the probe worker, so
//! the end-to-end vectors live here.
#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_plugin_host::pinned_runtime;
use pos_plugin_publisher::test_support::{
    encoding::{Material, TICK, UTC},
    release::Shape,
    world::{wall, Config, World as SignedWorld},
    BoxResult, BundleAddressV1,
};
use pos_plugin_supervisor::pass_harness::{GatedSpec, Source, World as PassWorld};
use pos_plugin_supervisor::{
    CommunityMemberV1, CommunityPluginHandleV1, CommunityPluginSubjectOutcomeV1 as Outcome,
    CommunityPluginSubjectResultV1 as Verdict, ContentValidationV1,
    ReceiptDispositionV1 as Disposition,
};
use pos_runtime::community_plugin_host::{
    gate_community_release_v1, AtomicCommitFailureV1, CommunityPassOutcomeV1, CommunityPassV1,
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginExpectationV1,
    CommunityPluginHostErrorV1, CommunityPluginHostV1, CommunityPluginModeV1,
    CommunityPluginTrustMaterialV1, ComponentTrapClassV1, GatedCommunityReleaseV1, MemberPassV1,
    PassResultV1, PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1,
    RevocationBasisV1 as Revoke, TrapReproductionV1, TrustDenialBasisV1 as Denial,
};

type Error = CommunityPluginHostErrorV1;
type TestResult = BoxResult<()>;
type Mode = CommunityPluginModeV1;
type Host = CommunityPluginHostV1<CommunityMemberV1>;

/// Bytes of one committed compatibility fixture.
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            "../../../plugins/community/examples/compatibility-prototype/fixtures/",
            $name
        ))
    };
}

const RUST_GUEST: &[u8] = fixture!("rust-guest.wasm");
const C_GUEST: &[u8] = fixture!("c-guest.wasm");
const WORKER: &str = env!("CARGO_BIN_EXE_pos-plugin-worker");
/// Generous for compiling a fixture in an unoptimized, instrumented worker.
/// A ceiling only: a healthy invocation finishes far sooner.
const WATCHDOG: Duration = Duration::from_mins(5);
/// The memory budget of the fixtures' releases: 256 pages (16 MiB), because the Rust guest
/// reserves 17 pages (1.1 MiB) at start and the world's default budget is one page.
const MEMORY: u64 = 16 * 1_048_576;
/// The Plugin IDs the world's PTR1 grants besides the default `plugin-a`.
const GRANTED: &[&str] = &["plugin-b"];
/// The one Event type both fixtures' `drive` export emits.
const EVENT_TYPE: &str = "prototype.driven";
/// A release digest that no fixture release has.
const UNRELATED: [u8; 32] = [0x77; 32];
/// The invocation ID of the first member of a lane.
const FIRST_ID: [u8; 16] = [1; 16];
/// The class name of every pre-execution rejection.
const PRE: &str = "PreExecutionRejection";
const LOCAL: Mode = Mode::Local;
const AIR_GAPPED: Mode = Mode::AirGapped;

const NOT_ACTIVE: Error = Error::ArtifactTrustDenied {
    basis: Denial::NotActive,
};
/// The class names of the failures that are not pre-execution rejections.
const AUTH: &str = "Authoritative";
const OP: &str = "Operational";

/// One member of a lane: the Plugin ID, the Component it publishes, and whether its Driver is
/// registered in the pass world.
#[derive(Clone, Copy)]
struct Spec {
    plugin_id: &'static str,
    guest: &'static [u8],
    registered: bool,
}

impl Spec {
    /// The release shape that publishes this member.
    const fn shape(&self) -> Shape {
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

const ALPHA: Spec = Spec {
    plugin_id: "plugin-a",
    guest: RUST_GUEST,
    registered: true,
};
/// The first member, on the C fixture.
const ALPHA_C: Spec = Spec {
    guest: C_GUEST,
    ..ALPHA
};
/// A second member whose Driver is built but never registered, so that it never runs.
const BETA: Spec = Spec {
    plugin_id: "plugin-b",
    registered: false,
    ..ALPHA
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

/// The host profile of `mode`: what the worker's own pinned runtime equals.
fn profile(mode: Mode) -> BoxResult<CommunityPluginExecutionProfileV1> {
    let runtime = pinned_runtime().map_err(|error| format!("{error:?}"))?;
    let ceilings = CommunityPluginCeilingsV1::V1;
    let built = CommunityPluginExecutionProfileV1::new(mode, ceilings, Some(runtime));
    Ok(built)
}

/// A release published and installed in the signed world.
#[derive(Clone)]
struct Published {
    spec: Spec,
    address: BundleAddressV1,
    release: [u8; 32],
}

/// Publish the release of `spec` and install it as the active release, with activation `tag`.
fn publish(signed: &mut SignedWorld, spec: Spec, tag: u8) -> BoxResult<Published> {
    publish_shape(signed, spec, spec.shape(), tag)
}

/// As [`publish`], for an explicit `shape` of `spec`.
fn publish_shape(
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
struct Part {
    handle: CommunityPluginHandleV1,
    address: BundleAddressV1,
    swap: Swap,
    expected: CommunityPluginExpectationV1,
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
fn member_of(
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
fn member_for(signed: &SignedWorld, part: &Part) -> BoxResult<CommunityMemberV1> {
    member_of(signed, part, &part.address, &part.expected)
}

/// One host over one pass world, in one Execution Mode.
struct Lane {
    mode: Mode,
    pass: PassWorld,
    host: Host,
    parts: Vec<Part>,
    refuse: Arc<AtomicBool>,
}

impl Lane {
    fn new(signed: &SignedWorld, entries: &[Published], mode: Mode) -> BoxResult<Self> {
        let refuse = Arc::new(AtomicBool::new(false));
        let setup = Setup {
            signed,
            material: trust_material(signed, &signed.material()?),
            refuse: Arc::clone(&refuse),
            profile: profile(mode)?,
        };
        let mut pass = PassWorld::new(WORKER);
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

    /// Replace the host by one over the first member alone, supplied from `address` and
    /// expecting `expected`.
    fn rehost(
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
    fn feed(&self, material: &CommunityPluginTrustMaterialV1) {
        for part in &self.parts {
            part.swap.set(Some(material.clone()));
        }
    }

    /// Supply every member the signed world's current evidence.
    fn follow(&self, signed: &SignedWorld) -> TestResult {
        self.feed(&trust_material(signed, &signed.material()?));
        Ok(())
    }

    /// One pass at the world's Tick whose trusted clock reads `utc`.
    fn run_at(&mut self, signed: &SignedWorld, utc: i64) -> BoxResult<CommunityPassOutcomeV1> {
        let mut clock = wall(utc)?;
        let registry = &signed.registry;
        let host = &mut self.host;
        Ok(self.pass.run(host, registry, &mut clock, TICK)?)
    }

    fn run(&mut self, signed: &SignedWorld) -> BoxResult<CommunityPassOutcomeV1> {
        self.run_at(signed, UTC)
    }

    /// The subject outcome of every member of `pass`, in host order, as #194 assembles it: the
    /// receipt is the newest one of the entry's invocation ID.
    fn outcomes(&self, pass: &CommunityPassOutcomeV1) -> Vec<Outcome> {
        let assemble = |(entry, part): (&MemberPassV1, &Part)| {
            let handle = &part.handle;
            let receipt = entry.invocation_id.and_then(|id| handle.receipt_for(id));
            Outcome::assemble(entry, pass.tick, self.mode, receipt.as_ref())
        };
        pass.gates.iter().zip(&self.parts).map(assemble).collect()
    }

    /// The subject outcome of the first member of `pass`.
    fn first(&self, pass: &CommunityPassOutcomeV1) -> BoxResult<Outcome> {
        let assembled = self.outcomes(pass).into_iter().next();
        Ok(assembled.ok_or("the pass has no entry")?)
    }

    /// The handle of the first member.
    fn handle(&self) -> &CommunityPluginHandleV1 {
        &self.parts[0].handle
    }
}

/// A signed world with `plugin-a` published and installed, and a Local lane over it.
fn single() -> BoxResult<(SignedWorld, Published, Lane)> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let lane = Lane::new(&signed, std::slice::from_ref(&alpha), LOCAL)?;
    Ok((signed, alpha, lane))
}

/// A signed world with `plugin-a` and the unregistered `plugin-b` installed, and a Local lane
/// over both.
fn pair() -> BoxResult<(SignedWorld, Lane)> {
    let mut signed = SignedWorld::with_config(Config {
        extra_plugin_ids: GRANTED,
        ..Config::default()
    })?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let beta = publish(&mut signed, BETA, 2)?;
    let lane = Lane::new(&signed, &[alpha, beta], LOCAL)?;
    Ok((signed, lane))
}

/// The output digest of a committed result.
const fn committed_digest(outcome: &Outcome) -> Option<[u8; 32]> {
    match outcome.result {
        Verdict::Committed { output_digest, .. } => output_digest,
        _ => None,
    }
}

const fn is_committed(pass: &CommunityPassOutcomeV1) -> bool {
    matches!(pass.result, PassResultV1::Committed(Some(_)))
}

/// A refusal of the class `PreExecutionRejection`.
const fn refused(error: &'static str, basis: Option<&'static str>) -> Verdict {
    Verdict::Refused {
        error,
        basis,
        class: PRE,
    }
}

const fn failed(error: &'static str, class: &'static str) -> Verdict {
    Verdict::Failed { error, class }
}

/// Assert that `pass` committed, printing the lane's first receipts when it did not.
fn assert_committed(lane: &Lane, pass: &CommunityPassOutcomeV1) {
    let receipts = lane.handle().receipts();
    assert!(is_committed(pass), "{pass:?} {receipts:?}");
}

/// Run one pass of the lane and assemble its first outcome, which must be committed.
fn committed(lane: &mut Lane, signed: &SignedWorld) -> BoxResult<Outcome> {
    let pass = lane.run(signed)?;
    assert_committed(lane, &pass);
    lane.first(&pass)
}

/// The outcomes of the same release in `guest`'s Local and Air-Gapped lanes over one signed
/// world, so that the digests of the two records are comparable.
fn both_modes(guest: Spec) -> BoxResult<(Outcome, Outcome)> {
    let mut signed = SignedWorld::new()?;
    let entry = publish(&mut signed, guest, 1)?;
    let entries = std::slice::from_ref(&entry);
    let mut local = Lane::new(&signed, entries, LOCAL)?;
    let mut air_gapped = Lane::new(&signed, entries, AIR_GAPPED)?;
    Ok((
        committed(&mut local, &signed)?,
        committed(&mut air_gapped, &signed)?,
    ))
}

/// R7-H1: signed release, install, then Local and Air-Gapped passes through the seam produce
/// identical subject outcome records except the mode, on the real `rust-guest.wasm` and
/// `c-guest.wasm` fixtures.
#[test]
fn local_and_air_gapped_passes_give_identical_outcomes_on_both_real_guests() -> TestResult {
    for guest in [ALPHA, ALPHA_C] {
        let (local, air_gapped) = both_modes(guest)?;
        assert_eq!((local.mode, air_gapped.mode), (LOCAL, AIR_GAPPED));
        let renamed = Outcome {
            mode: LOCAL,
            ..air_gapped
        };
        assert_eq!(renamed, local);
        assert!(local.execution_profile_digest.is_some(), "{local:?}");
        assert!(local.pmf1_digest.is_some() && local.tps1_digest.is_some());
        assert!(committed_digest(&local).is_some(), "{local:?}");
    }
    Ok(())
}

/// The refusal of an `ArtifactTrustDenied` with the basis named `basis`.
const fn refused_by(basis: &'static str) -> Verdict {
    refused("ArtifactTrustDenied", Some(basis))
}

/// The refusal of an `ArtifactRevoked` with the basis named `basis`.
const fn revoked_by(basis: &'static str) -> Verdict {
    refused("ArtifactRevoked", Some(basis))
}

type Row = (Error, Verdict);

const fn pre(error: Error, name: &'static str) -> Row {
    (error, refused(name, None))
}

const fn fail(error: Error, name: &'static str, class: &'static str) -> Row {
    (error, failed(name, class))
}

const fn deny(basis: Denial, name: &'static str) -> Row {
    (Error::ArtifactTrustDenied { basis }, refused_by(name))
}

const fn revoke(basis: Revoke, name: &'static str) -> Row {
    (Error::ArtifactRevoked { basis }, revoked_by(name))
}

/// R7-H2 (golden list): every closed name, basis and class of decisions 3 and 5, with the
/// outcome result the assembler must give for a failure of the pass.
fn golden() -> Vec<Row> {
    let trap = |reproduction| Error::ComponentTrap {
        class: ComponentTrapClassV1::Other,
        reproduction,
    };
    let commit = |failure| Error::AtomicCommitFailed { failure };
    let unverified = trap(TrapReproductionV1::Unverified);
    let reproduced = trap(TrapReproductionV1::ReproducedByConformance);
    let operational = commit(AtomicCommitFailureV1::Operational);
    let typed = commit(AtomicCommitFailureV1::DeterministicTypedResult);
    vec![
        pre(Error::InvalidManifest, "InvalidManifest"),
        deny(Denial::Expired, "Expired"),
        deny(Denial::NotActive, "NotActive"),
        deny(Denial::Untrusted, "Untrusted"),
        deny(Denial::PolicyMismatch, "PolicyMismatch"),
        deny(Denial::TrustStateUnavailable, "TrustStateUnavailable"),
        revoke(Revoke::PublisherKey, "PublisherKey"),
        revoke(Revoke::Artifact, "Artifact"),
        revoke(Revoke::OperatorDenial, "OperatorDenial"),
        pre(Error::IncompatibleAbi, "IncompatibleAbi"),
        pre(Error::MissingFeature { index: 0 }, "MissingFeature"),
        pre(Error::CapabilityDenied { index: 0 }, "CapabilityDenied"),
        pre(Error::InvalidInvocation, "InvalidInvocation"),
        fail(Error::InvalidGuestOutput, "InvalidGuestOutput", AUTH),
        fail(Error::UnsupportedSchema, "UnsupportedSchema", AUTH),
        fail(Error::StateMigrationFailed, "StateMigrationFailed", AUTH),
        fail(Error::GuestDeclaredFailure, "GuestDeclaredFailure", AUTH),
        fail(unverified, "ComponentTrap", OP),
        fail(reproduced, "ComponentTrap", AUTH),
        fail(Error::WorkerCrashed, "WorkerCrashed", OP),
        fail(Error::FuelExhausted, "FuelExhausted", AUTH),
        fail(Error::MemoryLimitExceeded, "MemoryLimitExceeded", AUTH),
        fail(Error::HostCallLimitExceeded, "HostCallLimitExceeded", AUTH),
        fail(Error::OutputLimitExceeded, "OutputLimitExceeded", AUTH),
        fail(
            Error::DeterministicDeadlineExceeded,
            "DeterministicDeadlineExceeded",
            AUTH,
        ),
        fail(
            Error::OperationalWatchdogStop,
            "OperationalWatchdogStop",
            OP,
        ),
        fail(operational, "AtomicCommitFailed", OP),
        fail(typed, "AtomicCommitFailed", AUTH),
    ]
}

/// A member whose gate was `Ok` and that did not run: a sibling refused the whole pass.
fn not_run_entry() -> BoxResult<MemberPassV1> {
    let (signed, mut lane) = pair()?;
    lane.parts[1].swap.set(None);
    let mut pass = lane.run(&signed)?;
    assert!(pass.gates[0].gate.is_ok(), "{pass:?}");
    Ok(pass.gates.swap_remove(0))
}

const fn error_of(result: &Verdict) -> &'static str {
    match result {
        Verdict::Refused { error, .. } | Verdict::Failed { error, .. } => error,
        _ => "none",
    }
}

const fn basis_of(result: &Verdict) -> Option<&'static str> {
    match result {
        Verdict::Refused { basis, .. } => *basis,
        _ => None,
    }
}

const fn class_of(result: &Verdict) -> &'static str {
    match result {
        Verdict::Refused { class, .. } | Verdict::Failed { class, .. } => class,
        _ => "none",
    }
}

/// R7-H2: the golden list is compared for the failures of a pass and for gate errors, and the
/// class names are the three of `HostFailureClassV1`.
#[test]
fn every_closed_name_basis_and_class_appears_verbatim() -> TestResult {
    let mut entry = not_run_entry()?;
    let mut classes = Vec::new();
    let mut names = Vec::new();
    let mut bases = Vec::new();
    for (error, expected) in golden() {
        entry.launch_failure = Some(error);
        let outcome = Outcome::assemble(&entry, TICK, LOCAL, None);
        assert_eq!(outcome.result, expected, "{error:?}");
        classes.push(class_of(&outcome.result));
        assert_eq!(error_of(&expected), error.name());
        assert_eq!(basis_of(&expected), error.basis_name());
        names.push(error.name());
        bases.extend(error.basis_name().map(|basis| (error.name(), basis)));
        if class_of(&expected) == PRE {
            let kept = std::mem::replace(&mut entry.gate, Err(error));
            let gated = Outcome::assemble(&entry, TICK, LOCAL, None);
            entry.gate = kept;
            assert_eq!(gated.result, expected, "gate error {error:?}");
            assert_eq!(gated.pmf1_digest, None);
        }
    }
    classes.sort_unstable();
    classes.dedup();
    assert_eq!(classes, [AUTH, OP, PRE]);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 20);
    bases.sort_unstable();
    bases.dedup();
    let denied = bases.iter().filter(|row| row.0 == "ArtifactTrustDenied");
    assert_eq!(denied.count(), 5);
    assert_eq!(bases.len(), 8);
    Ok(())
}

/// The first member's outcome of one pass at `utc`, after the signed world changed and the
/// lane followed its evidence.
fn faulted(
    signed: &SignedWorld,
    lane: &mut Lane,
    utc: i64,
) -> BoxResult<(CommunityPassOutcomeV1, Outcome)> {
    lane.follow(signed)?;
    let pass = lane.run_at(signed, utc)?;
    let outcome = lane.first(&pass)?;
    Ok((pass, outcome))
}

/// The refusal a faulted gate reports: no digest is known.
fn assert_refused(outcome: &Outcome, expected: Verdict, pass: &CommunityPassOutcomeV1) {
    assert_eq!(outcome.result, expected, "{pass:?}");
    let digests = (
        outcome.pmf1_digest,
        outcome.release_digest,
        outcome.tps1_digest,
    );
    assert_eq!(digests, (None, None, None));
    assert_eq!(outcome.execution_profile_digest, None);
    assert_eq!(outcome.plugin_id, "plugin-a");
    assert_eq!(outcome.tick, TICK);
}

/// R7-H2: a release revoked by artifact and a publisher key revoked.
#[test]
fn a_revoked_release_and_a_revoked_key_are_refused_with_their_basis() -> TestResult {
    let (mut signed, alpha, mut lane) = single()?;
    signed.advance_revoking_artifacts(&[alpha.release])??;
    let (pass, outcome) = faulted(&signed, &mut lane, UTC)?;
    assert_refused(&outcome, revoked_by("Artifact"), &pass);

    let (mut signed, _alpha, mut lane) = single()?;
    signed.advance_revoking_keys(&[1])??;
    let (pass, outcome) = faulted(&signed, &mut lane, UTC)?;
    assert_refused(&outcome, revoked_by("PublisherKey"), &pass);
    Ok(())
}

/// R7-H2: a clock past the release's validity, and a clock below the committed second.
#[test]
fn an_expired_release_and_a_clock_regression_are_refused_with_their_basis() -> TestResult {
    let (signed, _alpha, mut lane) = single()?;
    let (pass, outcome) = faulted(&signed, &mut lane, 60)?;
    assert_refused(&outcome, refused_by("Expired"), &pass);

    let (mut signed, _alpha, mut lane) = single()?;
    signed.advance_policy_at(5)??;
    let (pass, outcome) = faulted(&signed, &mut lane, 54)?;
    assert_refused(&outcome, refused_by("TrustStateUnavailable"), &pass);
    Ok(())
}

/// R7-H2: material the registry has not adopted is a policy mismatch.
#[test]
fn stale_policy_is_refused_as_a_mismatch() -> TestResult {
    let (signed, _alpha, mut lane) = single()?;
    let newer = signed.unadopted_material(&[UNRELATED], TICK)?;
    lane.feed(&trust_material(&signed, &newer));
    let pass = lane.run(&signed)?;
    let outcome = lane.first(&pass)?;
    assert_refused(&outcome, refused_by("PolicyMismatch"), &pass);
    Ok(())
}

/// Publish the successor of `first` on the C fixture and install it as the active release.
fn successor(signed: &mut SignedWorld, first: &Published, tag: u8) -> BoxResult<Published> {
    let shape = Shape {
        version: "2.0.0",
        previous: Some(first.release),
        ..ALPHA_C.shape()
    };
    publish_shape(signed, ALPHA_C, shape, tag)
}

/// R7-H2: a successor that was rolled back is no longer the active release.
#[test]
fn a_rolled_back_release_is_refused_as_not_active() -> TestResult {
    let (mut signed, first, mut lane) = single()?;
    let second = successor(&mut signed, &first, 2)?;
    signed.rollback_to(&first.address, 3)??;
    let expected = lane.parts[0].expected.clone();
    lane.rehost(&signed, &second.address, &expected)?;
    let (pass, outcome) = faulted(&signed, &mut lane, UTC)?;
    assert_refused(&outcome, refused_by("NotActive"), &pass);
    Ok(())
}

const fn is_failed(pass: &CommunityPassOutcomeV1) -> bool {
    matches!(pass.result, PassResultV1::Failed { .. })
}

/// R7-H2 (a): a supervisor-side refusal at `drive()` writes a receipt with a failure and the
/// disposition `Discarded`, and the receipt governs the assembled result.
#[test]
fn a_refusal_at_drive_is_assembled_from_its_receipt() -> TestResult {
    let (mut signed, first, mut lane) = single()?;
    let second = successor(&mut signed, &first, 2)?;
    // The gate accepts the active successor; the Driver was built for the first release. The
    // mismatch is caught at `drive()` by the release identity (R7-B2); the successor's other
    // Component bytes make the Component-digest check (R7-C2) refuse the same way, so this
    // recipe stands for both.
    let unpinned = CommunityPluginExpectationV1 {
        plugin_id: "plugin-a".to_owned(),
        release: None,
    };
    lane.rehost(&signed, &second.address, &unpinned)?;
    let pass = lane.run(&signed)?;
    assert!(is_failed(&pass), "{pass:?}");
    let outcome = lane.first(&pass)?;
    assert_eq!(outcome.result, refused_by("NotActive"), "{pass:?}");
    let receipts = lane.handle().receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].failure, Some(NOT_ACTIVE));
    assert_eq!(receipts[0].disposition, Disposition::Discarded);
    // The gate was `Ok`, so the digests are known; the receipt supplies the profile digest.
    let known = outcome.pmf1_digest.is_some() && outcome.release_digest.is_some();
    assert!(known, "{outcome:?}");
    let recorded = receipts[0].negotiated.execution_profile_digest();
    assert!(recorded.is_some());
    assert_eq!(outcome.execution_profile_digest, recorded);
    Ok(())
}

/// R7-H2 (b): a failing `source.context()` leaves no receipt and no invocation ID, and the
/// result is assembled from the member's launch failure.
#[test]
fn a_failing_context_is_assembled_from_the_launch_failure() -> TestResult {
    let (signed, _alpha, mut lane) = single()?;
    lane.refuse.store(true, Ordering::SeqCst);
    let pass = lane.run(&signed)?;
    assert_eq!(pass.gates[0].invocation_id, None);
    assert!(lane.handle().receipts().is_empty());
    let outcome = lane.first(&pass)?;
    assert_eq!(outcome.result, refused("InvalidInvocation", None));
    let known = outcome.pmf1_digest.is_some() && outcome.tps1_digest.is_some();
    assert!(known, "{outcome:?}");
    assert_eq!(outcome.execution_profile_digest, None);
    Ok(())
}

/// R7-H3: the outcome record has exactly these fields, carries the content-validation fact and
/// the profile digest, and no field claims signature validity (the exhaustive destructure below
/// is the guard: a new field fails to compile).
#[test]
fn the_outcome_carries_the_validation_fact_and_no_signature_claim() -> TestResult {
    let (signed, _alpha, mut lane) = single()?;
    let outcome = committed(&mut lane, &signed)?;
    let Outcome {
        plugin_id,
        pmf1_digest: _,
        release_digest: _,
        tps1_digest: _,
        execution_profile_digest,
        tick,
        mode,
        content_validation,
        result: _,
    } = outcome;
    assert_eq!(plugin_id, "plugin-a");
    assert_eq!((tick, mode), (TICK, LOCAL));
    assert_eq!(content_validation, ContentValidationV1::NotPerformed);
    assert!(execution_profile_digest.is_some());
    Ok(())
}

/// R7-H5: pass N commits a member; in pass N+1 a sibling refuses the gate. The member's
/// invocation ID is constant, so its stale `Committed` receipt is still findable, and the
/// assembled result is `NotRun`.
#[test]
fn a_sibling_gate_refusal_leaves_a_committed_member_not_run() -> TestResult {
    let (signed, mut lane) = pair()?;
    let first = lane.run(&signed)?;
    assert_committed(&lane, &first);
    let before = lane.outcomes(&first);
    assert!(committed_digest(&before[0]).is_some(), "{before:?}");
    assert_eq!(before[1].result, Verdict::NotRun);
    lane.parts[1].swap.set(None);
    let second = lane.run(&signed)?;
    let stale = lane.handle().receipt_for(FIRST_ID);
    let kept = stale.map(|receipt| receipt.disposition);
    assert_eq!(kept, Some(Disposition::Committed));
    let outcomes = lane.outcomes(&second);
    assert_eq!(outcomes[0].result, Verdict::NotRun);
    assert_eq!(outcomes[1].result, refused_by("TrustStateUnavailable"));
    assert!(outcomes[0].pmf1_digest.is_some());
    assert_eq!(outcomes[0].execution_profile_digest, None);
    Ok(())
}

/// R7-H5: a quarantined member is not run, whatever its stale receipt says.
#[test]
fn a_quarantined_member_is_not_run_after_a_committed_pass() -> TestResult {
    let (signed, mut lane) = pair()?;
    let first = lane.run(&signed)?;
    assert_committed(&lane, &first);
    lane.handle().record_refusal(Error::FuelExhausted);
    let second = lane.run(&signed)?;
    assert!(lane.handle().receipt_for(FIRST_ID).is_some());
    let outcomes = lane.outcomes(&second);
    assert_eq!(outcomes[0].result, Verdict::NotRun);
    assert!(outcomes[0].tps1_digest.is_some());
    assert_eq!(outcomes[0].execution_profile_digest, None);
    Ok(())
}

/// R7-H5: a context source that fails in pass N+1 gives the launch failure, never `Committed`.
#[test]
fn a_failing_context_after_a_committed_pass_is_not_committed() -> TestResult {
    let (signed, mut lane) = pair()?;
    let first = lane.run(&signed)?;
    assert_committed(&lane, &first);
    lane.refuse.store(true, Ordering::SeqCst);
    let second = lane.run(&signed)?;
    assert!(lane.handle().receipt_for(FIRST_ID).is_some());
    let outcomes = lane.outcomes(&second);
    assert_eq!(outcomes[0].result, refused("InvalidInvocation", None));
    Ok(())
}

/// R7-H5: with a constant invocation ID in two committed passes, the newest receipt governs.
#[test]
fn the_newest_receipt_of_a_constant_invocation_id_governs() -> TestResult {
    let (signed, _alpha, mut lane) = single()?;
    let first = committed(&mut lane, &signed)?;
    let second = committed(&mut lane, &signed)?;
    let receipts = lane.handle().receipts();
    assert_eq!(receipts.len(), 2);
    let newest = lane.handle().receipt_for(FIRST_ID);
    assert_eq!(newest, receipts.last().cloned());
    // The second pass starts from the state the first one committed, so its output differs.
    assert_ne!(committed_digest(&first), committed_digest(&second));
    assert_eq!(committed_digest(&second), receipts[1].output_digest);
    Ok(())
}
