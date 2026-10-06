//! #541 engine gates: load-time import types, pinned runtime, limits, trap
//! classes and guest-output classification.
//!
//! `components/probe.wat` imports every `host-v1` function with its exact
//! type and selects one misbehaviour from the Simulation Time it is given, so
//! each closed outcome is reached through a real Wasmtime invocation.

pub mod common;

use std::sync::LazyLock;

use common::{
    execution, invocation, negotiate, ok, options, pinned, release, BUDGET, PLUGIN_ID, RUST_GUEST,
};
use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_host::{
    pinned_runtime, ComponentHost, LoadError, LoadedComponent, PinnedExecutionV1,
    RuntimeNotPinnedV1,
};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostAbiV1, CommunityPluginHostErrorV1, ComponentTrapClassV1,
    PinnedComponentRuntimeV1, TrapReproductionV1, MAX_OBSERVATION_BYTES_V1,
};

type Error = CommunityPluginHostErrorV1;

const PROBE: &str = include_str!("components/probe.wat");
/// A watchdog that never fires during a test, so only deterministic limits
/// stop the guest.
const NO_WATCHDOG: u32 = u32::MAX;

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

fn component(text: &str) -> Vec<u8> {
    ok(wat::parse_str(text), "component text")
}

/// Run the probe's `describe` with `selector` under `budget`.
fn probe(selector: u64, budget: DeterministicBudgetV1) -> Option<Error> {
    ENGINE
        .host
        .describe(
            &ENGINE.probe,
            &execution(budget),
            options(selector, NO_WATCHDOG),
        )
        .err()
}

const fn trap(class: ComponentTrapClassV1) -> Error {
    Error::ComponentTrap {
        class,
        reproduction: TrapReproductionV1::Unverified,
    }
}

#[test]
fn wasm_traps_map_to_their_pinned_trap_classes() {
    let classes = [
        (1, ComponentTrapClassV1::Unreachable),
        (2, ComponentTrapClassV1::IntegerArithmetic),
        (3, ComponentTrapClassV1::MemoryOutOfBounds),
        (4, ComponentTrapClassV1::IndirectCall),
        (5, ComponentTrapClassV1::StackExhausted),
        (6, ComponentTrapClassV1::TableOutOfBounds),
    ];
    for (selector, class) in classes {
        assert_eq!(probe(selector, BUDGET), Some(trap(class)), "{selector}");
    }
}

#[test]
fn fuel_and_memory_limits_are_not_traps() {
    assert_eq!(probe(7, BUDGET), Some(Error::FuelExhausted));
    assert_eq!(probe(8, BUDGET), Some(Error::MemoryLimitExceeded));
    // Table growth past 65,536 elements is a limiter denial too.
    assert_eq!(probe(17, BUDGET), Some(Error::MemoryLimitExceeded));
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
    // A return the host's Canonical ABI lift cannot read, and a well-typed
    // descriptor that fails validation.
    assert_eq!(probe(15, BUDGET), Some(Error::InvalidGuestOutput));
    // A guest `realloc` that returns a pointer past memory while the host
    // lowers a `deterministic-random` result.
    assert_eq!(probe(18, BUDGET), Some(Error::InvalidGuestOutput));
    assert_eq!(probe(0, BUDGET), Some(Error::InvalidGuestOutput));
}

#[test]
fn guest_exports_must_have_their_exact_guest_v1_types() {
    let untyped = "(component
        (core module $m (func (export \"f\")))
        (core instance $i (instantiate $m))
        (func $f (canon lift (core func $i \"f\")))
        (instance $g (export \"describe\" (func $f)) (export \"reduce\" (func $f))
          (export \"drive\" (func $f)))
        (export \"pigloros:plugin/guest-v1@0.1.0\" (instance $g)))";
    let loaded = ENGINE.host.load(&component(untyped)).err();
    assert_eq!(loaded, Some(LoadError::MistypedGuestExport));
    // One export at a time, then the right parameters with a wrong result.
    let variants = [
        (
            "(export \"describe\" (func $describe))",
            "(export \"describe\" (func $invoke))",
        ),
        (
            "(export \"reduce\" (func $invoke))",
            "(export \"reduce\" (func $describe))",
        ),
        (
            "(export \"drive\" (func $invoke)))",
            "(export \"drive\" (func $describe)))",
        ),
        (
            "(result (result $plugin-output (error $plugin-error)))",
            "(result (result $plugin-descriptor (error $plugin-error)))",
        ),
    ];
    for (exact, mistyped) in variants {
        let variant = PROBE.replace(exact, mistyped);
        assert_ne!(variant, PROBE, "{mistyped}");
        let loaded = ENGINE.host.load(&component(&variant)).err();
        assert_eq!(loaded, Some(LoadError::MistypedGuestExport), "{mistyped}");
    }
    let not_a_function = "(component
        (core module $m (func (export \"f\")))
        (core instance $i (instantiate $m))
        (func $f (canon lift (core func $i \"f\")))
        (instance $empty)
        (instance $g (export \"describe\" (instance $empty)) (export \"reduce\" (func $f))
          (export \"drive\" (func $f)))
        (export \"pigloros:plugin/guest-v1@0.1.0\" (instance $g)))";
    let loaded = ENGINE.host.load(&component(not_a_function)).err();
    assert_eq!(loaded, Some(LoadError::MissingGuestExport));
    assert_eq!(
        Error::from(LoadError::MistypedGuestExport),
        Error::IncompatibleAbi
    );
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
        "(component (import \"pigloros:plugin/host-v1@0.1.0\" (instance
           (type $v (variant (case \"text\" string)))
           (export \"failure\" (type $e (eq $v)))
           (export \"simulation-time\" (func (result $e))))))",
    ];
    for text in denied {
        let loaded = ENGINE.host.load(&component(text)).err();
        assert_eq!(loaded, Some(LoadError::ImportDenied), "{text}");
    }
}

/// A runtime like the pinned one with one recorded value replaced.
enum RuntimeChange {
    Version,
    Features,
    Engine,
    TrapTable,
}

fn runtime_with(change: &RuntimeChange) -> PinnedComponentRuntimeV1 {
    let runtime = ok(pinned_runtime(), "pinned runtime");
    let mut version = runtime.wasmtime_version().to_owned();
    let mut features = runtime.resolved_features().to_vec();
    let mut engine = runtime.engine();
    let mut trap_table = runtime.trap_table().to_vec();
    match change {
        RuntimeChange::Version => "0.0.0".clone_into(&mut version),
        RuntimeChange::Features => {
            features.remove(0);
        }
        RuntimeChange::Engine => engine.consume_fuel = false,
        RuntimeChange::TrapTable => trap_table.truncate(2),
    }
    ok(
        PinnedComponentRuntimeV1::new(version, features, engine, trap_table),
        "changed runtime",
    )
}

#[test]
fn execution_requires_the_profile_to_pin_this_runtime() {
    let release = release(PLUGIN_ID, 0, &[], BUDGET);
    let host = CommunityPluginHostAbiV1::v1();
    let unpinned = negotiate(&release, &host, None);
    assert_eq!(PinnedExecutionV1::new(unpinned), Err(RuntimeNotPinnedV1));
    let changes = [
        RuntimeChange::Version,
        RuntimeChange::Features,
        RuntimeChange::Engine,
        RuntimeChange::TrapTable,
    ];
    for change in &changes {
        let negotiated = negotiate(&release, &host, Some(runtime_with(change)));
        assert_eq!(PinnedExecutionV1::new(negotiated), Err(RuntimeNotPinnedV1));
    }
    let pinned = pinned(&release, &host);
    assert_eq!(pinned.negotiated().plugin_id(), PLUGIN_ID);
}

#[test]
fn describe_must_match_the_negotiated_release() {
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
            .describe(&ENGINE.rust, &execution, options(0, NO_WATCHDOG))
            .err();
        assert_eq!(failure, Some(Error::InvalidGuestOutput));
    }
}

#[test]
fn invocations_outside_their_bounds_never_reach_the_guest() {
    let execution = execution(BUDGET);
    let large = invocation(&vec![0; MAX_OBSERVATION_BYTES_V1 + 1]);
    let reduced = ENGINE
        .host
        .reduce(&ENGINE.rust, &execution, &large, options(0, 0));
    assert_eq!(reduced.err(), Some(Error::InvalidInvocation));
    let driven = ENGINE
        .host
        .drive(&ENGINE.rust, &execution, &large, options(0, 0));
    assert_eq!(driven.err(), Some(Error::InvalidInvocation));
}

#[test]
fn the_watchdog_deadline_counts_epochs_after_the_invocation_starts() {
    // A host of its own: advancing the shared engine's epoch would stop
    // invocations running concurrently in other tests.
    let host = ok(ComponentHost::new(), "pinned engine");
    let rust = ok(host.load(RUST_GUEST), "Rust guest");
    host.increment_epoch();
    let observation = invocation(b"four");
    let report = host.drive(&rust, &execution(BUDGET), &observation, options(0, 1));
    let stopped = host.drive(&rust, &execution(BUDGET), &observation, options(0, 0));
    assert_eq!(stopped.err(), Some(Error::OperationalWatchdogStop));
    assert!(report.is_ok_and(|report| report.result.is_ok()));
}
