//! The Component worker program driven through the supervisor (ADR-061 r4).
//!
//! Each invocation launches the real `pos-plugin-worker` binary as a fresh,
//! confined subprocess and runs one #539 compatibility fixture in it. The
//! supervisor's process, framing and watchdog cases are tested against its
//! probe worker in `crates/pos-plugin-supervisor`.

use std::path::PathBuf;
use std::time::Duration;

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_host::pinned_runtime;
use pos_plugin_supervisor::test_support::{
    authorization_for, invocation_for, negotiated_under, ok,
};
use pos_plugin_supervisor::{CommunityPluginSupervisorV1, WorkerProgramV1};
use pos_runtime::community_plugin_host::{
    CeilingValuesV1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginHostErrorV1, CommunityPluginModeV1, ComponentTrapClassV1, HostInputs,
    InvocationReportV1, NegotiatedCommunityPluginV1, PluginDescriptorV1, PluginInvocationV1,
    PluginOutputV1, TrapReproductionV1,
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

const LOCAL: CommunityPluginModeV1 = CommunityPluginModeV1::Local;
const AIR_GAPPED: CommunityPluginModeV1 = CommunityPluginModeV1::AirGapped;

/// The profile of a host in `mode`: what the worker's own profile equals.
fn profile(
    mode: CommunityPluginModeV1,
    ceilings: CommunityPluginCeilingsV1,
) -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(mode, ceilings, Some(ok(pinned_runtime())))
}

fn negotiated_in(
    budget: DeterministicBudgetV1,
    mode: CommunityPluginModeV1,
) -> NegotiatedCommunityPluginV1 {
    let profile = profile(mode, CommunityPluginCeilingsV1::V1);
    negotiated_under(PLUGIN_ID, budget, Vec::new(), &profile)
}

fn negotiated(budget: DeterministicBudgetV1) -> NegotiatedCommunityPluginV1 {
    negotiated_in(budget, LOCAL)
}

fn supervisor() -> CommunityPluginSupervisorV1 {
    WorkerProgramV1::new(PathBuf::from(WORKER))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, WATCHDOG))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor")))
}

const ROOMY: DeterministicBudgetV1 = DeterministicBudgetV1::MAXIMA;

type Described = Result<InvocationReportV1<PluginDescriptorV1>, Error>;
type Produced = Result<InvocationReportV1<PluginOutputV1>, Error>;

/// `describe` of `guest` in a fresh worker, given a fresh authorization of `record`.
fn describe(record: &NegotiatedCommunityPluginV1, guest: &[u8]) -> Described {
    let authorization = Some(authorization_for(record, guest));
    supervisor().describe(authorization, record, guest, INPUTS)
}

/// `reduce` of `guest` in a fresh worker, given a fresh authorization of `record`.
fn reduce(
    record: &NegotiatedCommunityPluginV1,
    guest: &[u8],
    invocation: &PluginInvocationV1,
) -> Produced {
    let authorization = Some(authorization_for(record, guest));
    supervisor().reduce(authorization, record, guest, invocation, INPUTS)
}

/// `drive` of `guest` in a fresh worker, given a fresh authorization of `record`.
fn drive(
    record: &NegotiatedCommunityPluginV1,
    guest: &[u8],
    invocation: &PluginInvocationV1,
) -> Produced {
    let authorization = Some(authorization_for(record, guest));
    supervisor().drive(authorization, record, guest, invocation, INPUTS)
}

#[test]
fn both_fixtures_describe_the_negotiated_plugin_in_fresh_workers() {
    for guest in [RUST_GUEST, C_GUEST] {
        let report = ok(describe(&negotiated(ROOMY), guest));
        assert_eq!(ok(report.result).plugin_id, PLUGIN_ID);
        assert!(report.metering.call_fuel > 0);
    }
}

#[test]
fn both_fixtures_reduce_and_drive_identically() {
    let negotiated = negotiated(ROOMY);
    let invocation = invocation_for(b"observation", &negotiated);
    let mut outputs = Vec::new();
    for guest in [RUST_GUEST, C_GUEST] {
        let reduced = ok(reduce(&negotiated, guest, &invocation));
        let driven = ok(drive(&negotiated, guest, &invocation));
        outputs.push((ok(reduced.result), ok(driven.result)));
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(outputs[0].0.invocation_id, invocation.invocation_id);
    assert_ne!(outputs[0].0, outputs[0].1);
}

#[test]
fn deterministic_failures_are_authoritative_in_the_worker() {
    let starved = negotiated(DeterministicBudgetV1 { fuel: 1, ..ROOMY });
    assert_eq!(describe(&starved, C_GUEST), Err(Error::FuelExhausted));
    let record = negotiated(ROOMY);
    let trap = reduce(&record, RUST_GUEST, &invocation_for(b"trap", &record));
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
    let incompatible = describe(&negotiated(ROOMY), b"not a component");
    assert_eq!(incompatible, Err(Error::IncompatibleAbi));
}

/// R7-P4: on the real `rust-guest.wasm`, Local and Air-Gapped launches give
/// the same results, and the two records differ only in the recorded mode.
///
/// The receipt half of the vector (the Driver adapter's receipts differing only
/// in the recorded mode) is deferred to the adapter ticket (#583/#584); this
/// test compares the negotiated records the receipts embed.
#[test]
fn local_and_air_gapped_launches_produce_identical_results() {
    let run = |mode| {
        let negotiated = negotiated_in(ROOMY, mode);
        let invocation = invocation_for(b"observation", &negotiated);
        let described = ok(describe(&negotiated, RUST_GUEST));
        let reduced = ok(reduce(&negotiated, RUST_GUEST, &invocation));
        let driven = ok(drive(&negotiated, RUST_GUEST, &invocation));
        (negotiated, (described, reduced, driven))
    };
    let (local, local_reports) = run(LOCAL);
    let (air_gapped, air_gapped_reports) = run(AIR_GAPPED);
    // Output digest, state, drafts, metering and log: the whole reports.
    assert_eq!(local_reports, air_gapped_reports);
    assert!(local_reports.2.metering.call_fuel > 0);
    assert_eq!(local.mode(), LOCAL);
    assert_eq!(air_gapped.mode(), AIR_GAPPED);
    assert!(local.execution_profile_digest().is_some());
    let mut recorded = local.to_transport();
    recorded.mode = AIR_GAPPED;
    assert_eq!(recorded, air_gapped.to_transport());
}

/// R7-P8: a host profile with non-V1 ceilings has another digest, its record
/// gets no reply from the worker, and the launch ends `WorkerCrashed`.
#[test]
fn a_host_profile_with_non_v1_ceilings_ends_worker_crashed() {
    let values = CeilingValuesV1 {
        memory_bytes: 512 * 65_536,
        ..CommunityPluginCeilingsV1::V1.values()
    };
    let narrower = ok(CommunityPluginCeilingsV1::new(values));
    let host_profile = profile(LOCAL, narrower);
    assert_ne!(
        host_profile.digest(),
        profile(LOCAL, CommunityPluginCeilingsV1::V1).digest()
    );
    let record = negotiated_under(PLUGIN_ID, ROOMY, Vec::new(), &host_profile);
    assert_eq!(record.execution_profile_digest(), host_profile.digest());
    let launched = describe(&record, RUST_GUEST);
    assert_eq!(launched, Err(Error::WorkerCrashed));
}
