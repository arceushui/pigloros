//! #541 engine gates: load-time import types, pinned runtime, limits, trap
//! classes and guest-output classification.
//!
//! `components/probe.wat` imports every `host-v1` function with its exact
//! type and selects one misbehaviour from the Simulation Time it is given, so
//! each closed outcome is reached through a real Wasmtime invocation.

use std::sync::LazyLock;

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1,
    PluginExecutionProjectionV1,
};
use pos_plugin_host::{
    pinned_runtime, ArtifactRefV1, ComponentHost, HostInputs, LoadError, LoadedComponent,
    PinnedExecutionV1, PluginInvocationV1, RuntimeNotPinnedV1, TimelinePositionV1,
    MAX_OBSERVATION_BYTES_V1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginHostAbiV1, CommunityPluginHostErrorV1, CommunityPluginModeV1,
    ComponentTrapClassV1, NegotiatedCommunityPluginV1, PinnedComponentRuntimeV1,
    TrapReproductionV1,
};

type Error = CommunityPluginHostErrorV1;

const PROBE: &str = include_str!("components/probe.wat");
const RUST_GUEST: &[u8] = include_bytes!(
    "../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
const PLUGIN_ID: &str = "pigloros.compatibility-prototype";
const BUDGET: DeterministicBudgetV1 = DeterministicBudgetV1::MAXIMA;

struct Engine {
    host: ComponentHost,
    probe: LoadedComponent,
    rust: LoadedComponent,
}

static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    let host = ok(ComponentHost::new(), "pinned engine");
    let probe = ok(host.load(&component(PROBE)), "probe");
    let rust = ok(host.load(RUST_GUEST), "Rust guest");
    Engine { host, probe, rust }
});

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("{context}: {error:?}")))
    })
}

fn component(text: &str) -> Vec<u8> {
    ok(wat::parse_str(text), "component text")
}

fn release(
    plugin_id: &str,
    max_minor: u16,
    features: &[&str],
    budget: DeterministicBudgetV1,
) -> PluginExecutionProjectionV1 {
    PluginExecutionProjectionV1::from(PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
        plugin_id: plugin_id.to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor,
            required_features: features.iter().map(|id| (*id).to_owned()).collect(),
        },
        capabilities: Vec::new(),
        budget,
    })
}

fn negotiate(
    release: &PluginExecutionProjectionV1,
    host: &CommunityPluginHostAbiV1,
    runtime: Option<PinnedComponentRuntimeV1>,
) -> NegotiatedCommunityPluginV1 {
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        runtime,
    );
    ok(
        negotiate_community_plugin_v1(release, host, &profile),
        "negotiation",
    )
}

fn pinned(
    release: &PluginExecutionProjectionV1,
    host: &CommunityPluginHostAbiV1,
) -> PinnedExecutionV1 {
    let runtime = ok(pinned_runtime(), "pinned runtime");
    ok(
        PinnedExecutionV1::new(negotiate(release, host, Some(runtime))),
        "pinned execution",
    )
}

fn execution(budget: DeterministicBudgetV1) -> PinnedExecutionV1 {
    pinned(
        &release(PLUGIN_ID, 0, &[], budget),
        &CommunityPluginHostAbiV1::v1(),
    )
}

/// Run the probe's `describe` with `selector` under `budget`.
fn probe(selector: u64, budget: DeterministicBudgetV1) -> Option<Error> {
    let inputs = HostInputs {
        simulation_time: selector,
    };
    ENGINE
        .host
        .describe(&ENGINE.probe, &execution(budget), inputs, 1)
        .err()
}

const fn trap(class: ComponentTrapClassV1) -> Option<Error> {
    Some(Error::ComponentTrap {
        class,
        reproduction: TrapReproductionV1::Unverified,
    })
}

fn invocation(observation_bytes: usize) -> PluginInvocationV1 {
    let artifact = ArtifactRefV1 {
        schema_id: 1,
        byte_length: 0,
        digest: [0; 32],
    };
    PluginInvocationV1 {
        invocation_id: [1; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [2; 16],
            seq: 0,
            tick: 0,
            scheduler_position: 0,
        },
        output_base_ordinal: 0,
        principal_ref: artifact,
        authorization_decision: artifact,
        observation_snapshot: artifact,
        observation_bytes: vec![0; observation_bytes],
        prior_state_schema: [3; 32],
        prior_state_bytes: Vec::new(),
        execution_profile_digest: [4; 32],
        trust_policy_snapshot_digest: [5; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [6; 32],
        provenance_root: [7; 32],
    }
}

#[test]
fn wasm_traps_map_to_their_pinned_trap_classes() {
    assert_eq!(probe(1, BUDGET), trap(ComponentTrapClassV1::Unreachable));
    assert_eq!(
        probe(2, BUDGET),
        trap(ComponentTrapClassV1::IntegerArithmetic)
    );
    assert_eq!(
        probe(3, BUDGET),
        trap(ComponentTrapClassV1::MemoryOutOfBounds)
    );
    assert_eq!(probe(4, BUDGET), trap(ComponentTrapClassV1::IndirectCall));
    assert_eq!(probe(5, BUDGET), trap(ComponentTrapClassV1::StackExhausted));
    assert_eq!(
        probe(6, BUDGET),
        trap(ComponentTrapClassV1::TableOutOfBounds)
    );
}

#[test]
fn fuel_and_memory_limits_are_not_traps() {
    assert_eq!(probe(7, BUDGET), Some(Error::FuelExhausted));
    assert_eq!(probe(8, BUDGET), Some(Error::MemoryLimitExceeded));
}

#[test]
fn host_calls_stop_at_the_effective_limit() {
    let ten = DeterministicBudgetV1 {
        host_calls: 10,
        ..BUDGET
    };
    assert_eq!(probe(9, ten), Some(Error::HostCallLimitExceeded));
    let none = DeterministicBudgetV1 {
        host_calls: 0,
        ..BUDGET
    };
    assert_eq!(probe(0, none), Some(Error::HostCallLimitExceeded));
    assert_eq!(probe(13, BUDGET), Some(Error::HostCallLimitExceeded));
}

#[test]
fn operational_logs_stop_at_their_call_message_and_byte_limits() {
    assert_eq!(probe(10, BUDGET), Some(Error::OutputLimitExceeded));
    assert_eq!(probe(11, BUDGET), Some(Error::OutputLimitExceeded));
    let short = DeterministicBudgetV1 {
        log_bytes: 255,
        ..BUDGET
    };
    assert_eq!(probe(16, short), Some(Error::OutputLimitExceeded));
    let exact = DeterministicBudgetV1 {
        log_bytes: 256,
        ..BUDGET
    };
    assert_eq!(probe(16, exact), Some(Error::InvalidGuestOutput));
    let single = DeterministicBudgetV1 {
        log_calls: 1,
        ..BUDGET
    };
    assert_eq!(probe(10, single), Some(Error::OutputLimitExceeded));
}

#[test]
fn malformed_guest_values_are_invalid_guest_output_not_traps() {
    // Invalid UTF-8 in a log message and a 31-byte random domain.
    assert_eq!(probe(12, BUDGET), Some(Error::InvalidGuestOutput));
    assert_eq!(probe(14, BUDGET), Some(Error::InvalidGuestOutput));
    // A return the host's Canonical ABI lift cannot read, and a well-formed
    // return of the wrong type.
    assert_eq!(probe(15, BUDGET), Some(Error::InvalidGuestOutput));
    assert_eq!(probe(0, BUDGET), Some(Error::InvalidGuestOutput));
    // `reduce` takes no invocation, so lowering the invocation fails.
    let failure = ENGINE
        .host
        .reduce(
            &ENGINE.probe,
            &execution(BUDGET),
            &invocation(0),
            HostInputs { simulation_time: 0 },
            1,
        )
        .err();
    assert_eq!(failure, Some(Error::InvalidGuestOutput));
}

#[test]
fn imported_functions_must_have_their_exact_host_v1_types() {
    let denied = [
        "(component (import \"simulation-time\" (func (result u64))))",
        "(component (import \"pigloros:plugin/host-v1@0.1.0\" (core module)))",
        "(component (import \"pigloros:plugin/contract-v1@0.1.0\" (instance
           (export \"simulation-time\" (func (result u64))))))",
        "(component (import \"pigloros:plugin/host-v1@0.1.0\" (instance
           (export \"deterministic-random\" (func (param \"domain\" string)
             (param \"offset\" u64) (param \"length\" u32) (result u64))))))",
        "(component (import \"pigloros:plugin/host-v1@0.1.0\" (instance
           (export \"simulation-time\" (func (result (result string)))))))",
        "(component (import \"pigloros:plugin/host-v1@0.1.0\" (instance
           (export \"record-operational-log\"
             (func (param \"category\" u16) (result (result (error string))))))))",
    ];
    for text in denied {
        let loaded = ENGINE.host.load(&component(text)).err();
        assert_eq!(loaded, Some(LoadError::ImportDenied), "{text}");
    }
}

#[test]
fn execution_requires_the_profile_to_pin_this_runtime() {
    let release = release(PLUGIN_ID, 0, &[], BUDGET);
    let host = CommunityPluginHostAbiV1::v1();
    let unpinned = negotiate(&release, &host, None);
    assert_eq!(PinnedExecutionV1::new(unpinned), Err(RuntimeNotPinnedV1));
    let runtime = ok(pinned_runtime(), "pinned runtime");
    let other = ok(
        PinnedComponentRuntimeV1::new(
            "0.0.0".to_owned(),
            runtime.resolved_features().to_vec(),
            runtime.engine(),
            runtime.trap_table().to_vec(),
        ),
        "other runtime",
    );
    let foreign = negotiate(&release, &host, Some(other));
    assert_eq!(PinnedExecutionV1::new(foreign), Err(RuntimeNotPinnedV1));
    let partial = ok(
        PinnedComponentRuntimeV1::new(
            runtime.wasmtime_version().to_owned(),
            runtime.resolved_features().to_vec(),
            runtime.engine(),
            runtime.trap_table()[..2].to_vec(),
        ),
        "partial runtime",
    );
    let partial = negotiate(&release, &host, Some(partial));
    assert_eq!(PinnedExecutionV1::new(partial), Err(RuntimeNotPinnedV1));
    let pinned = pinned(&release, &host);
    assert_eq!(pinned.negotiated().plugin_id(), PLUGIN_ID);
}

#[test]
fn describe_must_match_the_negotiated_release() {
    let inputs = HostInputs { simulation_time: 0 };
    let featured = ok(
        CommunityPluginHostAbiV1::new(0, 0, vec!["feature.a".to_owned()]),
        "host ABI",
    );
    let v1 = CommunityPluginHostAbiV1::v1();
    let mismatches = [
        pinned(&release("other.plugin", 0, &[], BUDGET), &v1),
        pinned(&release(PLUGIN_ID, 1, &[], BUDGET), &v1),
        pinned(&release(PLUGIN_ID, 0, &["feature.a"], BUDGET), &featured),
    ];
    for execution in mismatches {
        let failure = ENGINE
            .host
            .describe(&ENGINE.rust, &execution, inputs, 1)
            .err();
        assert_eq!(failure, Some(Error::InvalidGuestOutput));
    }
}

#[test]
fn invocations_outside_their_bounds_never_reach_the_guest() {
    let inputs = HostInputs { simulation_time: 0 };
    let execution = execution(BUDGET);
    let large = invocation(MAX_OBSERVATION_BYTES_V1 + 1);
    let reduced = ENGINE
        .host
        .reduce(&ENGINE.rust, &execution, &large, inputs, 0);
    assert_eq!(reduced.err(), Some(Error::InvalidInvocation));
    let driven = ENGINE
        .host
        .drive(&ENGINE.rust, &execution, &large, inputs, 0);
    assert_eq!(driven.err(), Some(Error::InvalidInvocation));
}

#[test]
fn the_watchdog_deadline_counts_epochs_after_the_invocation_starts() {
    ENGINE.host.increment_epoch();
    let inputs = HostInputs { simulation_time: 0 };
    let report = ENGINE
        .host
        .drive(&ENGINE.rust, &execution(BUDGET), &invocation(4), inputs, 1);
    assert!(report.is_ok_and(|report| report.result.is_ok()));
}
