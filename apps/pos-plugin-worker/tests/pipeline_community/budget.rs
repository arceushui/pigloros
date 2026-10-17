//! PCF-CPH-010 and PCF-CPH-015: over-budget parity (#634, #656).
//!
//! An over-budget Plugin of either isolation class fails closed with a typed outcome and no
//! runtime default (ADR-021 decision 7). The two classes are bound by different budgets, so the
//! parity is semantic: a typed non-commit that discards the whole scheduled pass, the other
//! class's staged output included, commits no Event and leaves the sibling available, and the
//! next pass within budget commits.
//!
//! A community release declares its deterministic budget. The release of PCF-CPH-010 declares
//! one page of memory, below what the real guest reserves when it is instantiated, so every
//! launch on the real worker ends `MemoryLimitExceeded`, which quarantines the Plugin
//! `ResourceExhausted`. The budget belongs to the release: after the host clears the
//! quarantine, the next launch is exhausted again, and the pass within budget runs a Driver the
//! host built from an in-budget successor release.
//!
//! PCF-CPH-015 starves the other budgets of a release the same way, as the `PCF1` sub-cases
//! `res.1`, `res.3` and `res.4` do: one unit of fuel ends the C guest `FuelExhausted`, two host
//! calls end the Rust guest, which makes three (time, random and log), `HostCallLimitExceeded`,
//! and one Event byte ends it, since its one Event has an 8-byte payload,
//! `OutputLimitExceeded`. Each quarantines the Plugin `ResourceExhausted`.
//!
//! A first-party native Driver has no release budget. It is bound by the host Tick draft budget
//! of the registry: a Driver that stages more drafts than the budget leaves fails the pass
//! `ResourceExhausted` and quarantines nothing, and its next pass within budget commits. Which
//! Plugin is quarantined is isolation-specific, so it is recorded, not compared.

use std::sync::atomic::Ordering;

use pos_plugin_publisher::test_support::{release::Shape, world::World as SignedWorld, BoxResult};
use pos_plugin_supervisor::pass_harness::StoreKind;

use crate::failure::{record_pass, Mixed, Pass, SIBLING};
use crate::harness::Capture;
use crate::parity::{on_every_store, record, Order, StoreCapture};
use crate::support::lane::{publish, publish_shape, Published, Spec, ALPHA, ALPHA_C};

/// The memory budget of the over-budget release: one page.
///
/// The Rust guest reserves 17 pages when it is instantiated.
const ONE_PAGE: u64 = 65_536;
/// The host Tick draft budget of the first-party lane: one draft for each of its two Drivers.
const PASS_DRAFTS: u64 = 2;

/// Publish the successor of `first`, on the same member within the fixtures' budgets, and
/// install it as the active release.
fn in_budget(signed: &mut SignedWorld, first: &Published) -> BoxResult<Published> {
    let shape = Shape {
        version: "2.0.0",
        previous: Some(first.release),
        ..first.spec.shape()
    };
    publish_shape(signed, first.spec, shape, 2)
}

/// The passes of a lane whose community release is over its memory budget.
struct Exhausted {
    failed: Pass,
    quarantined: Pass,
    again: Pass,
    receipts: String,
}

/// A community Driver that exceeds its release's memory budget on the real worker after the
/// first-party sibling staged; the pass while it is quarantined; and the pass after the host
/// cleared that quarantine; all on a `kind` store.
fn community_exhausted(
    signed: &SignedWorld,
    first: &Published,
    kind: StoreKind,
) -> BoxResult<Exhausted> {
    let entries = std::slice::from_ref(first);
    let mut mixed = Mixed::new(kind, signed, entries, SIBLING, Order::TwinFirst)?;
    let failed = mixed.pass(signed)?;
    let quarantined = mixed.pass(signed)?;
    mixed.clear()?;
    let again = mixed.pass(signed)?;
    Ok(Exhausted {
        failed,
        quarantined,
        again,
        receipts: mixed.receipts(),
    })
}

/// A first-party Driver over the pass budget and its next pass within budget.
struct OverBudget {
    failed: Pass,
    recovered: Pass,
    receipts: String,
}

/// A first-party Driver that stages more drafts than the pass budget leaves after the community
/// sibling staged, then the next pass, within budget, on a `kind` store.
fn first_party_over(
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<OverBudget> {
    let mut mixed = Mixed::new(kind, signed, entries, SIBLING, Order::CommunityFirst)?;
    mixed.limit(PASS_DRAFTS);
    mixed.burst.store(true, Ordering::SeqCst);
    let failed = mixed.pass(signed)?;
    mixed.burst.store(false, Ordering::SeqCst);
    let recovered = mixed.pass(signed)?;
    Ok(OverBudget {
        failed,
        recovered,
        receipts: mixed.receipts(),
    })
}

/// Whether `failed` is a typed non-commit that discarded the whole pass: it failed with a typed
/// refusal, committed nothing, and the first registered Plugin, the sibling, stays available.
fn discarded(failed: &Pass) -> bool {
    let observed = &failed.observed;
    observed.result() == "Failed"
        && observed.committed() == 0
        && observed.first_available()
        && failed.refusal != "none"
}

/// Whether `pass` committed the Events of both Drivers.
fn commits_both(pass: &Pass) -> bool {
    pass.observed.result() == "Committed" && pass.observed.committed() == 2
}

/// Run a first-party Driver over the host Tick draft budget beside the community release
/// `entries`, then within it, on a `kind` store, and record both passes.
///
/// It returns whether the over-budget pass discarded the whole pass and whether the pass
/// within budget committed both Events.
fn record_first_party(
    capture: &mut StoreCapture<'_>,
    signed: &SignedWorld,
    entries: &[Published],
    kind: StoreKind,
) -> BoxResult<(bool, bool)> {
    let first_party = first_party_over(signed, entries, kind)?;
    record_pass(capture, "first-party-exhausted", &first_party.failed);
    let recovered = &first_party.recovered.observed;
    record(capture, "first-party-recovered", recovered);
    let receipts = &first_party.receipts;
    capture.record("first-party.community-receipts", receipts);
    let failed = discarded(&first_party.failed);
    Ok((failed, commits_both(&first_party.recovered)))
}

/// PCF-CPH-010: an over-budget Plugin of either class discards the whole scheduled pass.
///
/// A community Driver whose release memory budget the real guest exceeds, after the first-party
/// sibling staged, and a first-party Driver that stages more drafts than the host Tick draft
/// budget leaves, after the community sibling staged, each fail the pass with a typed refusal:
/// nothing is committed, the sibling's staged output is discarded and the sibling stays
/// available. Only the community Plugin is quarantined, and its release stays exhausted once
/// the quarantine is cleared. A fresh lane over an in-budget successor release, and the
/// first-party lane within budget, each commit both Events in the next pass.
#[must_use]
pub fn over_budget_parity() -> Capture {
    on_every_store(over_budget)
}

fn over_budget(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut signed = SignedWorld::new()?;
    let shape = ALPHA.shape().with_memory_bytes(ONE_PAGE);
    let first = publish_shape(&mut signed, ALPHA, shape, 1)?;
    let community = community_exhausted(&signed, &first, kind)?;
    let second = in_budget(&mut signed, &first)?;
    let entries = std::slice::from_ref(&second);
    let mut renewed = Mixed::new(kind, &signed, entries, SIBLING, Order::TwinFirst)?;
    let successor = renewed.pass(&signed)?;
    let (first_party_failed, first_party_within) =
        record_first_party(capture, &signed, entries, kind)?;
    record_pass(capture, "community-exhausted", &community.failed);
    record_pass(capture, "community-quarantined", &community.quarantined);
    record_pass(capture, "community-cleared", &community.again);
    capture.record("community.community-receipts", &community.receipts);
    record(capture, "community-successor", &successor.observed);
    let failed = discarded(&community.failed) && first_party_failed;
    capture.record("parity.whole-pass-discarded-either-class", failed);
    let within = commits_both(&successor) && first_party_within;
    capture.record("parity.next-pass-within-budget-commits", within);
    Ok(())
}

/// One release budget of PCF-CPH-015 and the member whose real guest exceeds it.
struct Starved {
    /// The capture path of the budget.
    path: &'static str,
    /// The member the release publishes.
    spec: Spec,
    /// The member's release shape with the budget its guest exceeds.
    shape: Shape,
}

/// The fuel, host-call and output budgets of PCF-CPH-015, as `PCF1` starves them.
///
/// One unit of fuel ends the C guest before it returns. The Rust guest makes three host calls
/// (time, random and log) and emits one Event with an 8-byte payload.
const STARVED: [Starved; 3] = [
    Starved {
        path: "fuel",
        spec: ALPHA_C,
        shape: ALPHA_C.shape().with_fuel(1),
    },
    Starved {
        path: "host-calls",
        spec: ALPHA,
        shape: ALPHA.shape().with_host_calls(2),
    },
    Starved {
        path: "output",
        spec: ALPHA,
        shape: ALPHA.shape().with_event_bytes(1),
    },
];

/// The passes of a lane whose community release one budget of PCF-CPH-015 starves.
struct Starvation {
    /// The pass in which the community release exhausts its budget.
    exhausted: Pass,
    /// The next pass, while the community Plugin is quarantined.
    quarantined: Pass,
    /// The community member's receipts after both passes.
    receipts: String,
    /// The pass of a fresh lane over the in-budget successor release.
    successor: Pass,
}

/// A community Driver whose release `starved` exhausts on the real worker after the first-party
/// sibling staged, and the pass while it is quarantined; then the next pass, in a fresh lane over
/// an in-budget successor release; all on a `kind` store.
fn starve(starved: &Starved, kind: StoreKind) -> BoxResult<Starvation> {
    let mut signed = SignedWorld::new()?;
    let first = publish_shape(&mut signed, starved.spec, starved.shape, 1)?;
    let entries = std::slice::from_ref(&first);
    let mut mixed = Mixed::new(kind, &signed, entries, SIBLING, Order::TwinFirst)?;
    let exhausted = mixed.pass(&signed)?;
    let quarantined = mixed.pass(&signed)?;
    let receipts = mixed.receipts();
    let second = in_budget(&mut signed, &first)?;
    let entries = std::slice::from_ref(&second);
    let mut renewed = Mixed::new(kind, &signed, entries, SIBLING, Order::TwinFirst)?;
    let successor = renewed.pass(&signed)?;
    Ok(Starvation {
        exhausted,
        quarantined,
        receipts,
        successor,
    })
}

/// Record the passes of `starvation` under `path`.
fn record_starvation(capture: &mut StoreCapture<'_>, path: &str, starvation: &Starvation) {
    let exhausted = &starvation.exhausted;
    record_pass(capture, &format!("{path}.exhausted"), exhausted);
    let quarantined = &starvation.quarantined;
    record_pass(capture, &format!("{path}.quarantined"), quarantined);
    let receipts_path = format!("{path}.community-receipts");
    capture.record(&receipts_path, &starvation.receipts);
    let successor = &starvation.successor.observed;
    record(capture, &format!("{path}.successor"), successor);
}

/// PCF-CPH-015: a release over its fuel, host-call or output budget discards the whole pass.
///
/// A community Driver whose release fuel, host-call or output budget the real guest exceeds,
/// after the first-party sibling staged, fails the pass with that typed limit: nothing is
/// committed, the sibling's staged output is discarded and the sibling stays available, and the
/// Plugin is quarantined `ResourceExhausted`. A first-party Driver that stages more drafts than
/// the host Tick draft budget leaves, after the community sibling staged, fails the pass the
/// same way and quarantines nothing. A fresh lane over each in-budget successor release, and
/// the first-party lane within budget, each commit both Events in the next pass.
#[must_use]
pub fn other_limits_parity() -> Capture {
    on_every_store(other_limits)
}

fn other_limits(kind: StoreKind, capture: &mut StoreCapture<'_>) -> BoxResult<()> {
    let mut failed = true;
    let mut within = true;
    for starved in &STARVED {
        let starvation = starve(starved, kind)?;
        record_starvation(capture, starved.path, &starvation);
        failed &= discarded(&starvation.exhausted);
        within &= commits_both(&starvation.successor);
    }
    let mut signed = SignedWorld::new()?;
    let alpha = publish(&mut signed, ALPHA, 1)?;
    let entries = std::slice::from_ref(&alpha);
    let (first_party_failed, first_party_within) =
        record_first_party(capture, &signed, entries, kind)?;
    failed &= first_party_failed;
    capture.record("parity.whole-pass-discarded-either-class", failed);
    within &= first_party_within;
    capture.record("parity.next-pass-within-budget-commits", within);
    Ok(())
}
