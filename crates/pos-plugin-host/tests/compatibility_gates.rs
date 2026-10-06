//! ADR-061 revision 4 compatibility gates, run through the #541 engine.
//!
//! Two independently written guests (Rust and C) implement the same
//! `pigloros:plugin/community-plugin@0.1.0` behaviour. Their validated outputs
//! must equal each other, an in-test oracle of the specified behaviour, and
//! themselves on every repetition. Both run under the default V1 execution
//! profile (64 MiB of memory, 10^9 fuel). The recorded budget measurements
//! are exact, because fuel and memory are deterministic for the pinned
//! Wasmtime and fixture bytes.

mod common;

use std::sync::LazyLock;

use common::{
    execution, invocation, ok, options, BUDGET, DOMAIN, INVOCATION_ID, PLUGIN_ID, RUST_GUEST, SEQ,
};
use pos_crypto::plugin_execution::{DeterministicBudgetV1, COMMUNITY_PLUGIN_WORLD_V1};
use pos_plugin_host::{ComponentHost, GuestExport, LoadError, LoadedComponent};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, CommunityPluginHostErrorV1, ComponentTrapClassV1, EventDraftV1,
    HostInputs, InvocationOptionsV1, InvocationReportV1, OperationalLogRecord,
    PluginDescriptorV1, PluginOutputV1, TrapReproductionV1,
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

type Error = CommunityPluginHostErrorV1;
type Outcome = Result<InvocationReportV1<PluginOutputV1>, Error>;

const C_GUEST: &[u8] = fixture!("c-guest.wasm");
const AMBIENT_WASI_IMPORT: &[u8] = fixture!("ambient-wasi-import.wasm");
const UNDECLARED_HOST_FUNCTION: &[u8] = fixture!("undeclared-host-function.wasm");
const MISTYPED_HOST_FUNCTION: &[u8] = fixture!("mistyped-host-function.wasm");
const NO_GUEST_EXPORTS: &[u8] = fixture!("no-guest-exports.wasm");

const INPUTS: HostInputs = HostInputs {
    simulation_time: 42,
};
const OPTIONS: InvocationOptionsV1 = options(INPUTS.simulation_time, 1);
const LARGE_OBSERVATION_BYTES: usize = 1024 * 1024;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Fuel, memory and host calls of one measured invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Measurement {
    guest: &'static str,
    call: &'static str,
    startup_fuel: u64,
    call_fuel: u64,
    memory_bytes: u64,
    host_calls: u64,
}

/// Measurements recorded in `docs/evidence/adr-061-r4-prototype.md`.
const MEASUREMENTS: [Measurement; 6] = [
    measured("rust", "describe", 1, 3_113, 1_179_648, 0),
    measured("rust", "reduce", 1, 21_112, 1_179_648, 3),
    measured("rust", "reduce-1MiB", 1, 16_798_314, 2_293_760, 3),
    measured("c", "describe", 19, 3_019, 131_072, 0),
    measured("c", "reduce", 19, 20_744, 131_072, 3),
    measured("c", "reduce-1MiB", 19, 9_982_361, 1_179_648, 3),
];
/// Component byte sizes recorded in the evidence document.
const COMPONENT_BYTES: [(&str, usize); 2] = [("rust", 51_947), ("c", 88_893)];

const fn measured(
    guest: &'static str,
    call: &'static str,
    startup_fuel: u64,
    call_fuel: u64,
    memory_bytes: u64,
    host_calls: u64,
) -> Measurement {
    Measurement {
        guest,
        call,
        startup_fuel,
        call_fuel,
        memory_bytes,
        host_calls,
    }
}

struct Prototype {
    host: ComponentHost,
    rust: LoadedComponent,
    c: LoadedComponent,
}

static PROTOTYPE: LazyLock<Prototype> = LazyLock::new(|| {
    let host = ok(ComponentHost::new(), "pinned engine");
    let rust = ok(host.load(RUST_GUEST), "Rust guest");
    let c = ok(host.load(C_GUEST), "C guest");
    Prototype { host, rust, c }
});

fn guests() -> [(&'static str, &'static LoadedComponent); 2] {
    [("rust", &PROTOTYPE.rust), ("c", &PROTOTYPE.c)]
}

fn run(
    guest: &LoadedComponent,
    export: GuestExport,
    observation: &[u8],
    budget: DeterministicBudgetV1,
) -> Outcome {
    let host = &PROTOTYPE.host;
    let execution = execution(budget);
    let invocation = invocation(observation);
    if export == GuestExport::Drive {
        host.drive(guest, &execution, &invocation, OPTIONS)
    } else {
        host.reduce(guest, &execution, &invocation, OPTIONS)
    }
}

fn fnv1a(mut hash: u64, input: &[u8]) -> u64 {
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The specified `reduce`/`drive` output, computed independently of both guests.
fn expected_output(observation: &[u8], event_type: &str) -> PluginOutputV1 {
    let mut random = [0; 16];
    let mut reader = blake3::Hasher::new_keyed(&DOMAIN).finalize_xof();
    reader.set_position(SEQ);
    reader.fill(&mut random);
    let mut hash = fnv1a(FNV_OFFSET, b"prior");
    hash = fnv1a(hash, observation);
    hash = fnv1a(hash, &INPUTS.simulation_time.to_le_bytes());
    hash = fnv1a(hash, &random);
    let state = hash.to_le_bytes().to_vec();
    let mut output = PluginOutputV1 {
        invocation_id: INVOCATION_ID,
        event_drafts: vec![EventDraftV1 {
            event_schema_id: 1,
            entity_id: INVOCATION_ID,
            event_type: event_type.to_owned(),
            canonical_payload: state.clone(),
            dependency_digests: Vec::new(),
        }],
        next_state_schema: [2; 32],
        next_state_bytes: state,
        trace_annotations: Vec::new(),
        consumed_dependencies: Vec::new(),
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    output
}

fn expected_descriptor() -> PluginDescriptorV1 {
    PluginDescriptorV1 {
        plugin_id: PLUGIN_ID.to_owned(),
        release_semver: "0.1.0".to_owned(),
        world: COMMUNITY_PLUGIN_WORLD_V1.to_owned(),
        abi_major: 0,
        min_abi_minor: 0,
        max_abi_minor: 0,
        required_features: Vec::new(),
        event_schema_digests: vec![[1; 32]],
        state_schema_digest: [2; 32],
        manifest_digest: [0; 32],
        release_digest: [0; 32],
    }
}

fn log(category: u16, message: &str) -> Vec<OperationalLogRecord> {
    vec![OperationalLogRecord {
        category,
        message: message.to_owned(),
    }]
}

const fn measurement(
    guest: &'static str,
    call: &'static str,
    metering: Measurement,
) -> Measurement {
    Measurement {
        guest,
        call,
        ..metering
    }
}

const fn metered<T>(report: &InvocationReportV1<T>) -> Measurement {
    measured(
        "",
        "",
        report.metering.startup_fuel,
        report.metering.call_fuel,
        report.metering.memory_bytes,
        report.metering.host_calls,
    )
}

fn recorded(guest_name: &str, call: &str) -> Measurement {
    MEASUREMENTS
        .into_iter()
        .find(|entry| entry.guest == guest_name && entry.call == call)
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("measurement not recorded")))
}

fn describe(guest: &LoadedComponent) -> Result<InvocationReportV1<PluginDescriptorV1>, Error> {
    PROTOTYPE
        .host
        .describe(guest, &execution(BUDGET), OPTIONS)
}

#[test]
fn both_guests_describe_the_negotiated_plugin_without_migrations() {
    for (name, guest) in guests() {
        let report = ok(describe(guest), name);
        assert_eq!(report.result, Ok(expected_descriptor()), "{name}");
        assert!(report.operational_log.is_empty(), "{name}");
    }
}

#[test]
fn both_guests_reduce_and_drive_identically_on_every_repetition() {
    for (export, message, event_type) in [
        (GuestExport::Reduce, "reduce", "prototype.reduced"),
        (GuestExport::Drive, "drive", "prototype.driven"),
    ] {
        let expected = expected_output(b"observation", event_type);
        for (name, guest) in guests() {
            for _ in 0..3 {
                let report = ok(run(guest, export, b"observation", BUDGET), name);
                assert_eq!(report.result, Ok(expected.clone()), "{name} {message}");
                assert_eq!(report.operational_log, log(1, message), "{name} {message}");
            }
        }
    }
}

#[test]
fn large_observations_stay_identical_across_guests() {
    let observation = vec![0xa5; LARGE_OBSERVATION_BYTES];
    let expected = expected_output(&observation, "prototype.reduced");
    for (name, guest) in guests() {
        let report = ok(run(guest, GuestExport::Reduce, &observation, BUDGET), name);
        assert_eq!(report.result, Ok(expected.clone()), "{name}");
    }
}

#[test]
fn budget_measurements_match_the_recorded_evidence() {
    let large = vec![0xa5; LARGE_OBSERVATION_BYTES];
    let mut measurements = Vec::new();
    for (name, guest) in guests() {
        let report = ok(describe(guest), name);
        measurements.push(measurement(name, "describe", metered(&report)));
        let report = ok(
            run(guest, GuestExport::Reduce, b"observation", BUDGET),
            name,
        );
        measurements.push(measurement(name, "reduce", metered(&report)));
        let report = ok(run(guest, GuestExport::Reduce, &large, BUDGET), name);
        measurements.push(measurement(name, "reduce-1MiB", metered(&report)));
    }
    assert_eq!(measurements, MEASUREMENTS);
    assert_eq!(
        [("rust", RUST_GUEST.len()), ("c", C_GUEST.len())],
        COMPONENT_BYTES
    );
}

#[test]
fn fuel_exhaustion_is_fuel_exhausted_and_discards_completed_host_calls() {
    let observation = vec![0xa5; LARGE_OBSERVATION_BYTES];
    for (name, guest) in guests() {
        let recorded = recorded(name, "reduce-1MiB");
        let total = recorded.startup_fuel + recorded.call_fuel;
        let exact = DeterministicBudgetV1 {
            fuel: total,
            ..BUDGET
        };
        assert!(
            run(guest, GuestExport::Reduce, &observation, exact).is_ok(),
            "{name}"
        );
        // Half the budget runs out while hashing the observation, after the
        // guest's `record-operational-log` call succeeded; the failure carries
        // none of that work. Wasmtime checks fuel only at function entries and
        // loop headers, so no sharper edge than the measured total is assumed.
        let half = DeterministicBudgetV1 {
            fuel: total / 2,
            ..BUDGET
        };
        let failure = run(guest, GuestExport::Reduce, &observation, half).err();
        assert_eq!(failure, Some(Error::FuelExhausted), "{name}");
        let starved = DeterministicBudgetV1 { fuel: 1, ..BUDGET };
        let failure = PROTOTYPE
            .host
            .describe(guest, &execution(starved), OPTIONS)
            .err();
        assert_eq!(failure, Some(Error::FuelExhausted), "{name}");
    }
}

#[test]
fn memory_limit_stops_growth_exactly_at_the_limit() {
    let observation = vec![0xa5; LARGE_OBSERVATION_BYTES];
    for (name, guest) in guests() {
        let peak = recorded(name, "reduce-1MiB").memory_bytes;
        let exact = DeterministicBudgetV1 {
            memory_bytes: peak,
            ..BUDGET
        };
        assert!(
            run(guest, GuestExport::Reduce, &observation, exact).is_ok(),
            "{name}"
        );
        let below = DeterministicBudgetV1 {
            memory_bytes: peak - 65_536,
            ..BUDGET
        };
        let failure = run(guest, GuestExport::Reduce, &observation, below).err();
        assert_eq!(failure, Some(Error::MemoryLimitExceeded), "{name}");
        let one_page = DeterministicBudgetV1 {
            memory_bytes: 65_536,
            ..BUDGET
        };
        let failure = PROTOTYPE
            .host
            .describe(guest, &execution(one_page), OPTIONS)
            .err();
        assert_eq!(failure, Some(Error::MemoryLimitExceeded), "{name}");
    }
}

#[test]
fn guest_traps_after_a_host_call_return_only_the_trap_class() {
    let trap = Error::ComponentTrap {
        class: ComponentTrapClassV1::Unreachable,
        reproduction: TrapReproductionV1::Unverified,
    };
    for (name, guest) in guests() {
        let failure = run(guest, GuestExport::Reduce, b"trap", BUDGET).err();
        assert_eq!(failure, Some(trap), "{name}");
    }
}

#[test]
fn an_elapsed_watchdog_is_an_operational_stop() {
    let execution = execution(BUDGET);
    let invocation = invocation(b"observation");
    for (name, guest) in guests() {
        let failure = PROTOTYPE
            .host
            .reduce(guest, &execution, &invocation, options(42, 0))
            .err();
        assert_eq!(failure, Some(Error::OperationalWatchdogStop), "{name}");
    }
}

#[test]
fn ambient_undeclared_and_mistyped_imports_are_denied_before_execution() {
    let host = &PROTOTYPE.host;
    for (name, component) in [
        ("ambient WASI import", AMBIENT_WASI_IMPORT),
        ("undeclared host-v1 function", UNDECLARED_HOST_FUNCTION),
        ("mistyped host-v1 function", MISTYPED_HOST_FUNCTION),
    ] {
        assert_eq!(
            host.load(component).err(),
            Some(LoadError::ImportDenied),
            "{name}"
        );
    }
    assert_eq!(
        host.load(NO_GUEST_EXPORTS).err(),
        Some(LoadError::MissingGuestExport)
    );
    assert_eq!(
        host.load(b"not a component").err(),
        Some(LoadError::InvalidComponent)
    );
}

#[test]
fn guest_exports_have_their_wit_names() {
    let names = GuestExport::ALL.map(GuestExport::name);
    assert_eq!(names, ["describe", "reduce", "drive"]);
}
