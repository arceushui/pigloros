//! Seam tests that need the engine in-process. Every scenario that the real
//! worker binary can show through the supervisor lives in
//! `tests/worker_public.rs` instead, and runs only once.

use std::sync::atomic::AtomicU64;

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_supervisor::test_support::{negotiated_under, ok};
use pos_runtime::community_plugin_host::{CeilingValuesV1, HostInputs};

use super::*;

const RUST_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
const PLUGIN_ID: &str = "pigloros.compatibility-prototype";

type Error = CommunityPluginHostErrorV1;

const LOCAL: CommunityPluginModeV1 = CommunityPluginModeV1::Local;
const AIR_GAPPED: CommunityPluginModeV1 = CommunityPluginModeV1::AirGapped;

/// The profile a worker of `mode` builds for itself.
fn profile(
    mode: CommunityPluginModeV1,
    ceilings: CommunityPluginCeilingsV1,
) -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(mode, ceilings, Some(ok(pinned_runtime())))
}

fn request(call: WorkerCallV1) -> WorkerRequestV1 {
    request_in(call, LOCAL)
}

/// A request whose record the supervisor negotiated for `mode`.
fn request_in(call: WorkerCallV1, mode: CommunityPluginModeV1) -> WorkerRequestV1 {
    request_under(call, &profile(mode, CommunityPluginCeilingsV1::V1))
}

fn request_under(
    call: WorkerCallV1,
    profile: &CommunityPluginExecutionProfileV1,
) -> WorkerRequestV1 {
    let budget = DeterministicBudgetV1::MAXIMA;
    let negotiated = negotiated_under(PLUGIN_ID, budget, Vec::new(), profile);
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
    assert_eq!(run(&host(), foreign, EPOCH_TICK, LOCAL), None);
}

/// R7-P3: a record is served by the worker of its own mode and by no other.
#[test]
fn a_record_is_served_only_by_the_worker_of_its_mode() {
    let host = host();
    for (record, worker) in [(AIR_GAPPED, LOCAL), (LOCAL, AIR_GAPPED)] {
        let other = request_in(WorkerCallV1::Describe, record);
        assert_eq!(run(&host, other, EPOCH_TICK, worker), None);
    }
    for mode in [LOCAL, AIR_GAPPED] {
        let own = request_in(WorkerCallV1::Describe, mode);
        assert!(run(&host, own, EPOCH_TICK, mode).is_some());
    }
}

/// R7-P5: a transported digest that is not the worker's own gets no reply.
#[test]
fn a_record_with_a_foreign_profile_digest_gets_no_reply() {
    let host = host();
    let own = request(WorkerCallV1::Describe);
    let digest = own.negotiation.execution_profile_digest;
    assert!(digest.is_some());
    let mut flipped = own.clone();
    flipped.negotiation.execution_profile_digest = digest.map(|mut digest| {
        digest[0] ^= 1;
        digest
    });
    assert_eq!(run(&host, flipped, EPOCH_TICK, LOCAL), None);
    let mut missing = own.clone();
    missing.negotiation.execution_profile_digest = None;
    assert_eq!(run(&host, missing, EPOCH_TICK, LOCAL), None);
    assert!(run(&host, own, EPOCH_TICK, LOCAL).is_some());
}

/// R7-P8: ceilings other than V1 change the digest, so the worker, which
/// rebuilds the V1 ceilings, gets no reply.
#[test]
fn a_record_negotiated_under_other_ceilings_gets_no_reply() {
    let values = CeilingValuesV1 {
        memory_bytes: 512 * 65_536,
        ..CommunityPluginCeilingsV1::V1.values()
    };
    let narrower = ok(CommunityPluginCeilingsV1::new(values));
    let host_profile = profile(LOCAL, narrower);
    let own = profile(LOCAL, CommunityPluginCeilingsV1::V1);
    assert_ne!(host_profile.digest(), own.digest());
    let request = request_under(WorkerCallV1::Describe, &host_profile);
    let transported = request.negotiation.execution_profile_digest;
    assert_eq!(transported, host_profile.digest());
    assert_eq!(run(&host(), request, EPOCH_TICK, LOCAL), None);
}

#[test]
fn an_elapsed_watchdog_stops_the_guest_with_the_operational_error() {
    let mut elapsed = request(WorkerCallV1::Describe);
    elapsed.watchdog_millis = 0;
    let outcome = run(&host(), elapsed, EPOCH_TICK, LOCAL);
    assert_eq!(outcome, Some(Err(Error::OperationalWatchdogStop)));
}

/// How long a ticker test may take before it counts as hung.
const HUNG_AFTER: Duration = Duration::from_secs(30);

/// Run `test` on its own thread and wait for its result for at most
/// [`HUNG_AFTER`], so a regression fails fast instead of stalling the job.
///
/// A hung thread is left behind: it is detached, so it cannot keep the test
/// process from exiting.
fn within_deadline<T: Send + 'static>(test: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (sender, receiver) = std::sync::mpsc::channel();
    thread::spawn(move || {
        // The receiver is gone only after the deadline, when nobody listens.
        let _sent = sender.send(test());
    });
    receiver.recv_timeout(HUNG_AFTER).ok()
}

#[test]
fn the_ticker_advances_until_the_call_returns() {
    let seen = within_deadline(|| {
        let ticks = AtomicU64::new(0);
        let advance = || {
            ticks.fetch_add(1, Ordering::AcqRel);
        };
        // The call returns once the ticker has fired three times.
        ticking(advance, Duration::from_millis(1), || {
            while ticks.load(Ordering::Acquire) < 3 {
                thread::yield_now();
            }
            ticks.load(Ordering::Acquire)
        })
    });
    assert!(
        seen.is_some_and(|seen| seen >= 3),
        "the ticker never advanced"
    );
}

#[test]
fn a_panicking_call_still_stops_the_ticker() {
    let outcome = within_deadline(|| {
        std::panic::catch_unwind(|| {
            ticking(
                || (),
                Duration::from_millis(1),
                || -> u8 { std::panic::resume_unwind(Box::new("call failed")) },
            )
        })
        .is_err()
    });
    // Without the drop guard the scope never joins the ticker: no result.
    assert_eq!(outcome, Some(true), "the ticker outlived a panicking call");
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
