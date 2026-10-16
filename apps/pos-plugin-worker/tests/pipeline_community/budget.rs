//! PCF-CPH-010: over-budget parity (#634).
//!
//! An over-budget Plugin of either isolation class fails closed with a typed outcome and no
//! runtime default (ADR-021 decision 7). The two classes are bound by different budgets, so the
//! parity is semantic: a typed non-commit that discards the whole scheduled pass, the other
//! class's staged output included, commits no Event and leaves the sibling available, and the
//! next pass within budget commits.
//!
//! A community release declares its deterministic budget. The release here declares one page of
//! memory, below what the real guest reserves when it is instantiated, so every launch on the
//! real worker ends `MemoryLimitExceeded`, which quarantines the Plugin `ResourceExhausted`. The
//! budget belongs to the release: after the host clears the quarantine, the next launch is
//! exhausted again, and the pass within budget runs a Driver the host built from an in-budget
//! successor release.
//!
//! A first-party native Driver has no release budget. It is bound by the host Tick draft budget
//! of the registry: a Driver that stages more drafts than the budget leaves fails the pass
//! `ResourceExhausted` and quarantines nothing, and its next pass within budget commits. Which
//! Plugin is quarantined is isolation-specific, so it is recorded, not compared.

use std::sync::atomic::Ordering;

use pos_plugin_publisher::test_support::{release::Shape, world::World as SignedWorld, BoxResult};

use crate::failure::{record_pass, Mixed, Pass, SIBLING};
use crate::harness::Capture;
use crate::parity::{record, Order, STORE};
use crate::support::lane::{publish_shape, Published, ALPHA};
use crate::support::test_ok::TestOk;

/// The memory budget of the over-budget release: one page.
///
/// The Rust guest reserves 17 pages when it is instantiated.
const ONE_PAGE: u64 = 65_536;
/// The host Tick draft budget of the first-party lane: one draft for each of its two Drivers.
const PASS_DRAFTS: u64 = 2;

/// Publish the successor of `first` within the fixtures' memory budget and install it as the
/// active release.
fn in_budget(signed: &mut SignedWorld, first: &Published) -> BoxResult<Published> {
    let shape = Shape {
        version: "2.0.0",
        previous: Some(first.release),
        ..ALPHA.shape()
    };
    publish_shape(signed, ALPHA, shape, 2)
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
/// cleared that quarantine.
fn community_exhausted(signed: &SignedWorld, first: &Published) -> BoxResult<Exhausted> {
    let entries = std::slice::from_ref(first);
    let mut mixed = Mixed::new(signed, entries, SIBLING, Order::TwinFirst)?;
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
/// sibling staged, then the next pass, within budget.
fn first_party_over(signed: &SignedWorld, entries: &[Published]) -> BoxResult<OverBudget> {
    let mut mixed = Mixed::new(signed, entries, SIBLING, Order::CommunityFirst)?;
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
    over_budget().test_ok()
}

fn over_budget() -> BoxResult<Capture> {
    let mut signed = SignedWorld::new()?;
    let shape = ALPHA.shape().with_memory_bytes(ONE_PAGE);
    let first = publish_shape(&mut signed, ALPHA, shape, 1)?;
    let community = community_exhausted(&signed, &first)?;
    let second = in_budget(&mut signed, &first)?;
    let entries = std::slice::from_ref(&second);
    let mut renewed = Mixed::new(&signed, entries, SIBLING, Order::TwinFirst)?;
    let successor = renewed.pass(&signed)?;
    let first_party = first_party_over(&signed, entries)?;
    let mut capture = Capture::default();
    record_pass(&mut capture, "community-exhausted", &community.failed);
    record_pass(
        &mut capture,
        "community-quarantined",
        &community.quarantined,
    );
    record_pass(&mut capture, "community-cleared", &community.again);
    capture.record(STORE, "community.community-receipts", &community.receipts);
    record(&mut capture, "community-successor", &successor.observed);
    record_pass(&mut capture, "first-party-exhausted", &first_party.failed);
    let recovered = &first_party.recovered.observed;
    record(&mut capture, "first-party-recovered", recovered);
    let receipts = &first_party.receipts;
    capture.record(STORE, "first-party.community-receipts", receipts);
    let failed = discarded(&community.failed) && discarded(&first_party.failed);
    capture.record(STORE, "parity.whole-pass-discarded-either-class", failed);
    let within = commits_both(&successor) && commits_both(&first_party.recovered);
    capture.record(STORE, "parity.next-pass-within-budget-commits", within);
    Ok(capture)
}
