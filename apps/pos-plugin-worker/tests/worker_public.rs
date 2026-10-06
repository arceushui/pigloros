//! The Component worker program driven through the supervisor (ADR-061 r4).
//!
//! Each invocation launches the real `pos-plugin-worker` binary as a fresh,
//! confined subprocess and runs one #539 compatibility fixture in it. The
//! supervisor's process, framing and watchdog cases are tested against its
//! probe worker in `crates/pos-plugin-supervisor`.

use std::path::PathBuf;
use std::time::Duration;

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1,
    PluginExecutionProjectionV1,
};
use pos_crypto::plugin_worker_ipc::WorkerExportV1;
use pos_plugin_supervisor::{
    CommunityPluginSupervisorV1, WorkerInvocationV1, WorkerProgramV1, WorkerReportV1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginHostAbiV1, CommunityPluginHostErrorV1, CommunityPluginModeV1,
    NegotiatedCommunityPluginV1,
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

type Invocation<T> = Result<WorkerReportV1<T>, CommunityPluginHostErrorV1>;

fn negotiated(budget: DeterministicBudgetV1) -> NegotiatedCommunityPluginV1 {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: "pigloros.compatibility-prototype".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 1,
            required_features: Vec::new(),
        },
        capabilities: Vec::new(),
        budget,
    };
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    );
    let execution = PluginExecutionProjectionV1::from(fixture);
    negotiate_community_plugin_v1(&execution, &CommunityPluginHostAbiV1::v1(), &profile)
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

const ROOMY: DeterministicBudgetV1 = DeterministicBudgetV1 {
    memory_bytes: 64 * 1_048_576,
    fuel: 100_000_000,
    ..DeterministicBudgetV1::MAXIMA
};

fn run<T>(
    component: &[u8],
    export: WorkerExportV1,
    budget: DeterministicBudgetV1,
    validate: impl FnOnce(&[u8]) -> Option<T>,
) -> Invocation<T> {
    let supervisor = WorkerProgramV1::new(PathBuf::from(WORKER))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, WATCHDOG))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor")));
    let invocation = WorkerInvocationV1 {
        export,
        component,
        simulation_time: 42,
        invocation: b"",
    };
    supervisor.invoke(&negotiated(budget), &invocation, validate)
}

fn describe(component: &[u8], budget: DeterministicBudgetV1) -> Invocation<Vec<u8>> {
    run(component, WorkerExportV1::Describe, budget, |payload| {
        Some(payload.to_vec())
    })
}

/// The structural CBOR head of the fixtures' `describe` payload:
/// `result::ok` (`[0, ...]`) of a 14-field `plugin-descriptor` record whose
/// first field is the `bounded-text` record of the Plugin ID.
fn descriptor_prefix() -> Vec<u8> {
    let mut prefix = vec![0x82, 0x00, 0x8e, 0x81];
    let id = b"pigloros.compatibility-prototype";
    prefix.extend_from_slice(&[0x98, u8::try_from(id.len()).unwrap_or(0)]);
    for byte in id {
        if *byte < 24 {
            prefix.push(*byte);
        } else {
            prefix.extend_from_slice(&[0x18, *byte]);
        }
    }
    prefix
}

#[test]
fn both_fixtures_describe_the_same_plugin_in_fresh_workers() {
    let rust = describe(RUST_GUEST, ROOMY);
    let c = describe(C_GUEST, ROOMY);
    let rust_payload = rust.as_ref().map(|report| report.output.clone());
    assert!(
        rust_payload
            .as_ref()
            .is_ok_and(|payload| payload.starts_with(&descriptor_prefix())),
        "{rust:?}"
    );
    assert_eq!(rust_payload, c.as_ref().map(|report| report.output.clone()));
    assert!(rust.is_ok_and(|report| report.call_fuel > 0 && report.memory_bytes > 0));
}

#[test]
fn the_host_validator_decides_guest_output() {
    let rejected = run(RUST_GUEST, WorkerExportV1::Describe, ROOMY, |_| None::<()>);
    assert_eq!(rejected, Err(CommunityPluginHostErrorV1::InvalidGuestOutput));
}

#[test]
fn deterministic_budgets_are_authoritative_failures_in_the_worker() {
    let starved = DeterministicBudgetV1 { fuel: 1, ..ROOMY };
    assert_eq!(
        describe(C_GUEST, starved),
        Err(CommunityPluginHostErrorV1::FuelExhausted)
    );
    let small = DeterministicBudgetV1 {
        memory_bytes: 65_536,
        ..ROOMY
    };
    assert_eq!(
        describe(RUST_GUEST, small),
        Err(CommunityPluginHostErrorV1::MemoryLimitExceeded)
    );
}

#[test]
fn unsupported_requests_and_components_fail_closed() {
    assert_eq!(
        describe(b"not a component", ROOMY),
        Err(CommunityPluginHostErrorV1::IncompatibleAbi)
    );
    let reduce = run(RUST_GUEST, WorkerExportV1::Reduce, ROOMY, |_| Some(()));
    assert_eq!(reduce, Err(CommunityPluginHostErrorV1::InvalidInvocation));
}
