//! The Component worker program driven through the supervisor (ADR-061 r4).
//!
//! Each invocation launches the real `pos-plugin-worker` binary as a fresh,
//! confined subprocess and runs one #539 compatibility fixture in it. The
//! supervisor's process, framing and watchdog cases are tested against its
//! probe worker in `crates/pos-plugin-supervisor`.

use std::path::PathBuf;
use std::time::Duration;

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_supervisor::test_support::{invocation, negotiated_with, ok};
use pos_plugin_supervisor::{CommunityPluginSupervisorV1, WorkerProgramV1};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, ComponentTrapClassV1, HostInputs, NegotiatedCommunityPluginV1,
    TrapReproductionV1,
};

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
const WATCHDOG: Duration = Duration::from_mins(5);
const PLUGIN_ID: &str = "pigloros.compatibility-prototype";
const INPUTS: HostInputs = HostInputs {
    simulation_time: 42,
};

type Error = CommunityPluginHostErrorV1;

fn negotiated(budget: DeterministicBudgetV1) -> NegotiatedCommunityPluginV1 {
    negotiated_with(PLUGIN_ID, budget, Vec::new())
}

fn supervisor() -> CommunityPluginSupervisorV1 {
    WorkerProgramV1::new(PathBuf::from(WORKER))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, WATCHDOG))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor")))
}

const ROOMY: DeterministicBudgetV1 = DeterministicBudgetV1::MAXIMA;

#[test]
fn both_fixtures_describe_the_negotiated_plugin_in_fresh_workers() {
    for guest in [RUST_GUEST, C_GUEST] {
        let report = ok(supervisor().describe(&negotiated(ROOMY), guest, INPUTS));
        assert_eq!(ok(report.result).plugin_id, PLUGIN_ID);
        assert!(report.metering.call_fuel > 0);
    }
}

#[test]
fn both_fixtures_reduce_and_drive_identically() {
    let negotiated = negotiated(ROOMY);
    let call = invocation(b"observation");
    let mut outputs = Vec::new();
    for guest in [RUST_GUEST, C_GUEST] {
        let reduced = ok(supervisor().reduce(&negotiated, guest, &call, INPUTS));
        let driven = ok(supervisor().drive(&negotiated, guest, &call, INPUTS));
        outputs.push((ok(reduced.result), ok(driven.result)));
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(outputs[0].0.invocation_id, call.invocation_id);
    assert_ne!(outputs[0].0, outputs[0].1);
}

#[test]
fn deterministic_failures_are_authoritative_in_the_worker() {
    let starved = negotiated(DeterministicBudgetV1 { fuel: 1, ..ROOMY });
    assert_eq!(
        supervisor().describe(&starved, C_GUEST, INPUTS),
        Err(Error::FuelExhausted)
    );
    let trap = supervisor().reduce(&negotiated(ROOMY), RUST_GUEST, &invocation(b"trap"), INPUTS);
    assert_eq!(
        trap,
        Err(Error::ComponentTrap {
            class: ComponentTrapClassV1::Unreachable,
            reproduction: TrapReproductionV1::Unverified,
        })
    );
}

#[test]
fn bytes_that_do_not_implement_the_world_are_incompatible() {
    assert_eq!(
        supervisor().describe(&negotiated(ROOMY), b"not a component", INPUTS),
        Err(Error::IncompatibleAbi)
    );
}
