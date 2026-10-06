use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1,
    PluginExecutionProjectionV1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, ArtifactRefV1, CommunityPluginModeV1, ComponentTrapClassV1,
    HostInputs, PluginInvocationV1, TimelinePositionV1, TrapReproductionV1,
};

use super::*;

const RUST_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
const C_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/c-guest.wasm"
);
const PLUGIN_ID: &str = "pigloros.compatibility-prototype";

type Error = CommunityPluginHostErrorV1;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn transport(budget: DeterministicBudgetV1) -> NegotiatedTransportV1 {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
        plugin_id: PLUGIN_ID.to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 0,
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
    let negotiated =
        negotiate_community_plugin_v1(&execution, &CommunityPluginHostAbiV1::v1(), &profile);
    ok(negotiated).to_transport()
}

fn invocation(observation: &[u8]) -> PluginInvocationV1 {
    let artifact = |schema_id| ArtifactRefV1 {
        schema_id,
        byte_length: 0,
        digest: [0; 32],
    };
    PluginInvocationV1 {
        invocation_id: [0x11; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [0x22; 16],
            seq: 11,
            tick: 3,
            scheduler_position: 0,
        },
        output_base_ordinal: 0,
        principal_ref: artifact(1),
        authorization_decision: artifact(2),
        observation_snapshot: artifact(3),
        observation_bytes: observation.to_vec(),
        prior_state_schema: [2; 32],
        prior_state_bytes: b"prior".to_vec(),
        execution_profile_digest: [3; 32],
        trust_policy_snapshot_digest: [4; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [7; 32],
        provenance_root: [5; 32],
    }
}

fn request(component: &[u8], call: WorkerCallV1) -> WorkerRequestV1 {
    WorkerRequestV1 {
        component: component.to_vec(),
        negotiation: transport(DeterministicBudgetV1::MAXIMA),
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
fn both_guests_describe_the_negotiated_plugin() {
    for guest in [RUST_GUEST, C_GUEST] {
        let outcome = invoke(request(guest, WorkerCallV1::Describe));
        let Some(Ok(WorkerReturnV1::Described(report))) = outcome else {
            std::panic::resume_unwind(Box::new(format!("{outcome:?}")));
        };
        assert_eq!(ok(report.result).plugin_id, PLUGIN_ID);
        assert!(report.metering.call_fuel > 0);
    }
}

#[test]
fn reduce_and_drive_return_validated_outputs() {
    for call in [
        WorkerCallV1::Reduce(invocation(b"observation")),
        WorkerCallV1::Drive(invocation(b"observation")),
    ] {
        let outcome = run(&host(), request(RUST_GUEST, call), EPOCH_TICK);
        let Some(Ok(WorkerReturnV1::Produced(report))) = outcome else {
            std::panic::resume_unwind(Box::new(format!("{outcome:?}")));
        };
        assert_eq!(ok(report.result).invocation_id, [0x11; 16]);
    }
}

#[test]
fn engine_failures_are_closed_outcomes() {
    let trap = request(RUST_GUEST, WorkerCallV1::Reduce(invocation(b"trap")));
    assert_eq!(
        run(&host(), trap, EPOCH_TICK),
        Some(Err(Error::ComponentTrap {
            class: ComponentTrapClassV1::Unreachable,
            reproduction: TrapReproductionV1::Unverified,
        }))
    );
    let mut starved = request(RUST_GUEST, WorkerCallV1::Describe);
    starved.negotiation = transport(DeterministicBudgetV1 {
        fuel: 1,
        ..DeterministicBudgetV1::MAXIMA
    });
    assert_eq!(
        run(&host(), starved, EPOCH_TICK),
        Some(Err(Error::FuelExhausted))
    );
    let invalid = request(b"not a component", WorkerCallV1::Describe);
    assert_eq!(
        run(&host(), invalid, EPOCH_TICK),
        Some(Err(Error::IncompatibleAbi))
    );
}

#[test]
fn a_rejected_transport_gets_no_reply() {
    let mut foreign = request(RUST_GUEST, WorkerCallV1::Describe);
    foreign.negotiation.world.push('x');
    assert_eq!(run(&host(), foreign, EPOCH_TICK), None);
}

#[test]
fn the_epoch_ticker_stops_a_running_guest() {
    let mut elapsed = request(RUST_GUEST, WorkerCallV1::Describe);
    elapsed.watchdog_millis = 0;
    let stopped = Some(Err(Error::OperationalWatchdogStop));
    assert_eq!(run(&host(), elapsed, EPOCH_TICK), stopped);
    // One epoch, advanced continuously: a 1 MiB reduce cannot finish first.
    let large = invocation(&vec![0xa5; 1_048_576]);
    let mut ticking = request(RUST_GUEST, WorkerCallV1::Reduce(large));
    ticking.watchdog_millis = 1;
    assert_eq!(run(&host(), ticking, Duration::ZERO), stopped);
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
