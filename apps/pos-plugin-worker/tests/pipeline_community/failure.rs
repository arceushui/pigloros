//! PCF-CPH-005 and PCF-CPH-006: scheduled-pass discard and no host domain fallback (#633).
//!
//! A scheduled pass is one atomic unit (ADR-021 decision 7): a Driver of either isolation class
//! that fails while it stages discards every Driver's staged output, the sibling of the other
//! class included, and the pass commits nothing. Failure diagnosis stays invocation-local: the
//! sibling stays available, and only the failing Plugin may be quarantined. A community Driver's
//! guest trap quarantines it as `Trapped`; a first-party Driver's failure quarantines nothing.
//! That classification belongs to the isolation class and is recorded, not compared.
//!
//! The host has no domain fallback and no implicit retry: a failed pass launches exactly one
//! worker for the failing step, a registered first-party Plugin with the same domain contract is
//! never run in its place, and a quarantined Plugin refuses the whole pass until the host clears
//! it. Recovery is a new pass under new invocation identities, and the failed invocation's
//! output is never reused.
//!
//! The community Driver fails on the real worker: the lane feeds the real guest the observation
//! on which it executes `unreachable`. The first-party Driver fails by unwinding, which the
//! registry reports as `DriverPanicked`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use pos_plugin_publisher::test_support::{world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::World as PassWorld;
use pos_runtime::community_plugin_host::{
    CommunityPassOutcomeV1, CommunityPluginHostErrorV1, CommunityPluginModeV1 as Mode,
};

use crate::authority::pass_refusal;
use crate::first_party::{entity_of, register_switched, Native};
use crate::harness::Capture;
use crate::parity::{observe, record, Observed, Order, ENTITY, STORE, TWIN_TYPE};
use crate::support::lane::{publish, Lane, Published, ALPHA};
use crate::support::subcase::WORKER;
use crate::support::test_ok::TestOk;

/// The first-party Plugin beside the community release.
///
/// It implements the same domain contract (one Event per step, for the same entity) under its
/// own Event type, since an Event type has one owner.
pub const SIBLING: Native = Native::twin(TWIN_TYPE);

/// One Local lane over a registry that holds a first-party Plugin and a community release.
pub struct Mixed {
    /// The lane; its first member is the community release.
    pub lane: Lane,
    /// The first-party Driver's step counter.
    steps: Arc<AtomicUsize>,
    /// Set to make the first-party Driver fail; public so a case can fail it mid-lane, while the
    /// private fields stay bookkeeping the lane owns.
    pub fail: Arc<AtomicBool>,
    /// Set to make the first-party Driver stage two drafts instead of one.
    pub burst: Arc<AtomicBool>,
    order: Order,
    /// The first-party steps and the community launches before the next pass.
    seen: (usize, usize),
}

/// What one pass of a mixed lane shows.
pub struct Pass {
    /// The authority outcome, with the Driver steps of this pass alone.
    pub observed: Observed,
    /// The typed refusal that failed the pass, or `none`.
    pub refusal: String,
    /// The gate refusal of every refused member, or `none`.
    pub gate: String,
}

impl Mixed {
    /// A lane over the community release `entries` and the first-party Plugin `native`,
    /// registered in `order`.
    ///
    /// # Errors
    /// Returns the error of registering either Plugin or of building the lane.
    pub fn new(
        signed: &SignedWorld,
        entries: &[Published],
        native: Native,
        order: Order,
    ) -> BoxResult<Self> {
        let entity = entity_of(ENTITY)?;
        let (lane, switched) = match order {
            Order::TwinFirst => {
                let mut pass = PassWorld::new(WORKER);
                let switched = register_switched(&mut pass.registry, native, entity)?;
                (Lane::over(signed, entries, Mode::Local, pass)?, switched)
            }
            Order::CommunityFirst => {
                let mut lane = Lane::new(signed, entries, Mode::Local)?;
                let switched = register_switched(&mut lane.pass.registry, native, entity)?;
                (lane, switched)
            }
        };
        Ok(Self {
            lane,
            steps: switched.steps,
            fail: switched.fail,
            burst: switched.burst,
            order,
            seen: (0, 0),
        })
    }

    /// Run one pass and describe it, with the Driver steps of this pass in registration order.
    ///
    /// The community Driver's steps are its worker launches: every launch leaves one receipt.
    ///
    /// # Errors
    /// Returns the error of the pass world's observation.
    pub fn pass(&mut self, signed: &SignedWorld) -> BoxResult<Pass> {
        let outcome = self.lane.run(signed)?;
        let native = self.steps.load(Ordering::SeqCst);
        let launches = self.lane.handle().receipts().len();
        let (native_steps, community) = (native - self.seen.0, launches - self.seen.1);
        self.seen = (native, launches);
        let steps = match self.order {
            Order::TwinFirst => format!("{native_steps},{community}"),
            Order::CommunityFirst => format!("{community},{native_steps}"),
        };
        Ok(Pass {
            observed: observe(&self.lane, &outcome, steps),
            refusal: pass_refusal(&outcome.result),
            gate: gate_refusals(&outcome),
        })
    }

    /// The failure and disposition of every receipt of the community member, oldest first.
    #[must_use]
    pub fn receipts(&self) -> String {
        let receipts = self.lane.handle().receipts();
        let rows: Vec<String> = receipts
            .iter()
            .map(|receipt| {
                let failure = receipt
                    .failure
                    .map_or("none", CommunityPluginHostErrorV1::name);
                format!("{failure}/{:?}", receipt.disposition)
            })
            .collect();
        rows.join(",")
    }

    /// Bound the Event drafts one scheduled pass of the lane may stage to `drafts`, the host
    /// Tick draft budget of the registry.
    pub fn limit(&mut self, drafts: u64) {
        let registry = std::mem::take(&mut self.lane.pass.registry);
        self.lane.pass.registry = registry.with_resource_limit(drafts);
    }

    /// Clear the community member's quarantine, in the registry and in its handle.
    ///
    /// # Errors
    /// Returns the registry's composition error.
    pub fn clear(&mut self) -> BoxResult<()> {
        let registry = &mut self.lane.pass.registry;
        Ok(self.lane.parts[0].handle.clear_quarantine(registry)?)
    }
}

/// The gate refusal of every refused member of `outcome`, in host order, or `none`.
fn gate_refusals(outcome: &CommunityPassOutcomeV1) -> String {
    let refused: Vec<String> = outcome
        .gates
        .iter()
        .filter_map(|entry| entry.gate.as_ref().err())
        .map(|error| {
            let name = error.name();
            let basis = error.basis_name();
            basis.map_or_else(|| name.to_owned(), |basis| format!("{name}({basis})"))
        })
        .collect();
    if refused.is_empty() {
        "none".to_owned()
    } else {
        refused.join(",")
    }
}

/// Record what one pass shows under `path`, with its typed refusal.
pub fn record_pass(capture: &mut Capture, path: &str, pass: &Pass) {
    record(capture, path, &pass.observed);
    capture.record(STORE, &format!("{path}.refusal"), &pass.refusal);
}

/// A failed pass of a mixed lane and the pass that follows the recovery.
struct Contained {
    failed: Pass,
    recovered: Pass,
    receipts: String,
}

impl Contained {
    /// Whether the failed pass committed nothing and left the sibling available, and the next
    /// pass committed both Events.
    fn holds(&self) -> bool {
        let failed = &self.failed.observed;
        let recovered = &self.recovered.observed;
        failed.result() == "Failed"
            && failed.committed() == 0
            && failed.first_available()
            && recovered.result() == "Committed"
            && recovered.committed() == 2
    }
}

/// A community Driver that traps on the real worker after the first-party sibling staged, then
/// the pass after the host cleared its quarantine.
fn community_fails(signed: &SignedWorld, entries: &[Published]) -> BoxResult<Contained> {
    let mut mixed = Mixed::new(signed, entries, SIBLING, Order::TwinFirst)?;
    mixed.lane.trap.store(true, Ordering::SeqCst);
    let failed = mixed.pass(signed)?;
    mixed.lane.trap.store(false, Ordering::SeqCst);
    mixed.clear()?;
    let recovered = mixed.pass(signed)?;
    Ok(Contained {
        failed,
        recovered,
        receipts: mixed.receipts(),
    })
}

/// A first-party Driver that fails after the community sibling staged, then the next pass.
fn first_party_fails(signed: &SignedWorld, entries: &[Published]) -> BoxResult<Contained> {
    let failing = Native {
        name: "first-party-failing",
        ..SIBLING
    };
    let mut mixed = Mixed::new(signed, entries, failing, Order::CommunityFirst)?;
    mixed.fail.store(true, Ordering::SeqCst);
    let failed = mixed.pass(signed)?;
    mixed.fail.store(false, Ordering::SeqCst);
    let recovered = mixed.pass(signed)?;
    Ok(Contained {
        failed,
        recovered,
        receipts: mixed.receipts(),
    })
}

/// Record the failed and the recovered pass under `path`.
fn record_contained(capture: &mut Capture, path: &str, contained: &Contained) {
    record_pass(capture, &format!("{path}-fails"), &contained.failed);
    let recovered = format!("{path}-recovered");
    record(capture, &recovered, &contained.recovered.observed);
    let key = format!("{path}.community-receipts");
    capture.record(STORE, &key, &contained.receipts);
}

/// PCF-CPH-005: a failing Driver of either class discards the whole scheduled pass.
///
/// A community Driver that traps on the real worker after the first-party sibling staged, and a
/// first-party Driver that fails after the community sibling staged, each fail the pass: nothing
/// is committed, the sibling's staged output is discarded and the sibling stays available. Only
/// the trapping community Plugin is quarantined. The next pass, after the host cleared that
/// quarantine, commits both Events.
#[must_use]
pub fn failure_containment() -> Capture {
    containment().test_ok()
}

fn containment() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let community = community_fails(&signed, entries)?;
    let first_party = first_party_fails(&signed, entries)?;
    let mut capture = Capture::default();
    record_contained(&mut capture, "community", &community);
    record_contained(&mut capture, "first-party", &first_party);
    let same = community.holds() && first_party.holds();
    capture.record(STORE, "parity.whole-pass-discarded-either-class", same);
    Ok(capture)
}

/// PCF-CPH-006: no host domain fallback and no implicit retry.
///
/// A community Driver registered before a first-party Plugin with the same domain contract traps
/// on the real worker: the pass launches exactly one worker, and the first-party Plugin is not
/// stepped in its place. While the community Plugin is quarantined, the next pass is refused as a
/// whole before any Driver runs, so the first-party Plugin never runs alone. After the host
/// clears the quarantine, a new pass under new invocation identities commits both Events, and
/// the failed invocation's receipt stays discarded.
#[must_use]
pub fn no_fallback_or_retry() -> Capture {
    no_fallback().test_ok()
}

fn no_fallback() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let mut mixed = Mixed::new(&signed, entries, SIBLING, Order::CommunityFirst)?;
    mixed.lane.trap.store(true, Ordering::SeqCst);
    let failed = mixed.pass(&signed)?;
    mixed.lane.trap.store(false, Ordering::SeqCst);
    let quarantined = mixed.pass(&signed)?;
    mixed.lane.generation.store(1, Ordering::SeqCst);
    mixed.clear()?;
    let recovered = mixed.pass(&signed)?;
    let receipts = mixed.lane.handle().receipts();
    // The context source, not the host, issues invocation IDs; the lane generation models a
    // recovery under a new identity. The check proves the recovery added one new receipt beside
    // the discarded one, not that the host issues the ID.
    let renewed = receipts.len() == 2 && receipts[0].invocation_id != receipts[1].invocation_id;
    let mut capture = Capture::default();
    record_pass(&mut capture, "failed", &failed);
    record_pass(&mut capture, "quarantined", &quarantined);
    record(&mut capture, "recovered", &recovered.observed);
    capture.record(STORE, "recovered.community-receipts", mixed.receipts());
    capture.record(STORE, "recovered.fresh-id-new-receipt", renewed);
    Ok(capture)
}
