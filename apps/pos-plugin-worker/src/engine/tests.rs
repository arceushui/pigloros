//! Seam tests that need the engine in-process. Every scenario that the real
//! worker binary can show through the supervisor lives in
//! `tests/worker_public.rs` instead, and runs only once.

use std::sync::atomic::AtomicU64;

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_supervisor::test_support::{negotiated_with, ok};
use pos_runtime::community_plugin_host::HostInputs;

use super::*;

const RUST_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
const PLUGIN_ID: &str = "pigloros.compatibility-prototype";

type Error = CommunityPluginHostErrorV1;

fn request(call: WorkerCallV1) -> WorkerRequestV1 {
    let negotiated = negotiated_with(PLUGIN_ID, DeterministicBudgetV1::MAXIMA, Vec::new());
    WorkerRequestV1 {
        component: RUST_GUEST.to_vec(),
        negotiation: negotiated.to_transport(),
        watchdog_millis: 600_000,
        host_inputs: HostInputs {
            simulation_time: 42,
        },
        call,
    }
}

fn host() -> ComponentHost {
    ok(ComponentHost::new())
}

#[test]
fn a_rejected_transport_gets_no_reply() {
    let mut foreign = request(WorkerCallV1::Describe);
    foreign.negotiation.world.push('x');
    assert_eq!(run(&host(), foreign, EPOCH_TICK), None);
}

#[test]
fn a_record_for_another_mode_gets_no_reply() {
    let mut air_gapped = request(WorkerCallV1::Describe);
    air_gapped.negotiation.mode = CommunityPluginModeV1::AirGapped;
    assert_eq!(run(&host(), air_gapped, EPOCH_TICK), None);
    // The same record is served once it is the worker's own mode.
    let local = request(WorkerCallV1::Describe);
    assert!(run(&host(), local, EPOCH_TICK).is_some());
}

#[test]
fn an_elapsed_watchdog_stops_the_guest_with_the_operational_error() {
    let mut elapsed = request(WorkerCallV1::Describe);
    elapsed.watchdog_millis = 0;
    let outcome = run(&host(), elapsed, EPOCH_TICK);
    assert_eq!(outcome, Some(Err(Error::OperationalWatchdogStop)));
}

#[test]
fn the_ticker_advances_until_the_call_returns() {
    let ticks = AtomicU64::new(0);
    let advance = || {
        ticks.fetch_add(1, Ordering::AcqRel);
    };
    // Deterministic: the call returns only once the ticker has fired three
    // times, so a ticker that never advances makes this test hang, not flake.
    let seen = ticking(advance, Duration::from_millis(1), || {
        while ticks.load(Ordering::Acquire) < 3 {
            thread::yield_now();
        }
        ticks.load(Ordering::Acquire)
    });
    assert!(seen >= 3);
}

#[test]
fn a_panicking_call_still_stops_the_ticker() {
    let ticks = AtomicU64::new(0);
    let advance = || {
        ticks.fetch_add(1, Ordering::AcqRel);
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ticking(advance, Duration::from_millis(1), || -> u8 {
            std::panic::resume_unwind(Box::new("call failed"))
        })
    }));
    // Without the drop guard the scope would wait forever for the ticker.
    assert!(outcome.is_err());
}

#[test]
fn watchdog_epochs_count_whole_ticks() {
    assert_eq!(watchdog_epochs(60_000, EPOCH_TICK), 6_000);
    assert_eq!(watchdog_epochs(19, EPOCH_TICK), 1);
    assert_eq!(watchdog_epochs(9, EPOCH_TICK), 0);
    assert_eq!(watchdog_epochs(7, Duration::ZERO), 7);
    assert_eq!(watchdog_epochs(u64::MAX, Duration::ZERO), u32::MAX);
    assert_eq!(watchdog_epochs(7, Duration::MAX), 0);
}
