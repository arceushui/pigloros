//! ADR-061 revision 4 compatibility gates for the #539 prototype.
//!
//! Two independently written guests (Rust and C) implement the same
//! `pigloros:plugin/community-plugin@0.1.0` behaviour. Their outputs must equal
//! each other, an in-test oracle of the specified behaviour, and themselves on
//! every repetition. The recorded budget measurements are exact, because fuel
//! and memory are deterministic for the pinned Wasmtime and fixture bytes.

use std::sync::LazyLock;

use pos_plugin_host::{
    ComponentHost, GuestExport, HostInputs, InvocationFailure, InvocationLimits,
    InvocationReport, LoadError, LoadedComponent, OperationalLogRecord, Trap, Val,
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
const AMBIENT_WASI_IMPORT: &[u8] = fixture!("ambient-wasi-import.wasm");
const UNDECLARED_HOST_FUNCTION: &[u8] = fixture!("undeclared-host-function.wasm");
const MISTYPED_HOST_FUNCTION: &[u8] = fixture!("mistyped-host-function.wasm");
const NO_GUEST_EXPORTS: &[u8] = fixture!("no-guest-exports.wasm");

const LIMITS: InvocationLimits = InvocationLimits {
    fuel: 100_000_000,
    memory_bytes: 64 * 1024 * 1024,
    watchdog_epochs: 1,
};
const INPUTS: HostInputs = HostInputs {
    simulation_time: 42,
};
const DOMAIN: [u8; 32] = [7; 32];
const SEQ: u64 = 11;
const LARGE_OBSERVATION_BYTES: usize = 1024 * 1024;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Fuel and memory of one measured invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Measurement {
    guest: &'static str,
    call: &'static str,
    startup_fuel: u64,
    call_fuel: u64,
    memory_bytes: u64,
}

/// Measurements recorded in `docs/evidence/adr-061-r4-prototype.md`.
const MEASUREMENTS: [Measurement; 6] = [
    measured("rust", "describe", 0, 0, 0),
    measured("rust", "reduce", 0, 0, 0),
    measured("rust", "reduce-1MiB", 0, 0, 0),
    measured("c", "describe", 0, 0, 0),
    measured("c", "reduce", 0, 0, 0),
    measured("c", "reduce-1MiB", 0, 0, 0),
];
/// Component byte sizes recorded in the evidence document.
const COMPONENT_BYTES: [(&str, usize); 2] = [("rust", 0), ("c", 0)];

const fn measured(
    guest: &'static str,
    call: &'static str,
    startup_fuel: u64,
    call_fuel: u64,
    memory_bytes: u64,
) -> Measurement {
    Measurement {
        guest,
        call,
        startup_fuel,
        call_fuel,
        memory_bytes,
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

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("{context}: {error:?}")))
    })
}

fn guests() -> [(&'static str, &'static LoadedComponent); 2] {
    [("rust", &PROTOTYPE.rust), ("c", &PROTOTYPE.c)]
}

fn run(
    guest: &LoadedComponent,
    export: GuestExport,
    args: &[Val],
    limits: InvocationLimits,
) -> Result<InvocationReport, InvocationFailure> {
    PROTOTYPE.host.invoke(guest, export, args, limits, INPUTS)
}

fn record(fields: Vec<(&str, Val)>) -> Val {
    Val::Record(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn bytes(value: &[u8]) -> Val {
    Val::List(value.iter().copied().map(Val::U8).collect())
}

fn digest(value: &[u8]) -> Val {
    record(vec![("value", bytes(value))])
}

fn text(value: &str) -> Val {
    record(vec![("utf8", bytes(value.as_bytes()))])
}

fn empty() -> Val {
    Val::List(Vec::new())
}

fn artifact(schema_id: u32) -> Val {
    record(vec![
        ("schema-id", Val::U32(schema_id)),
        ("byte-length", Val::U64(0)),
        ("digest", digest(&[0; 32])),
    ])
}

fn invocation(kind: &str, observation: &[u8], domain: &[u8]) -> Val {
    record(vec![
        ("invocation-id", bytes(b"invocation-1")),
        ("kind", Val::Enum(kind.to_owned())),
        (
            "timeline-position",
            record(vec![
                ("timeline-id", bytes(b"timeline")),
                ("seq", Val::U64(SEQ)),
                ("tick", Val::U64(3)),
                ("scheduler-position", Val::U32(0)),
            ]),
        ),
        ("output-base-ordinal", Val::U32(0)),
        ("principal-ref", artifact(1)),
        ("authorization-decision", artifact(2)),
        ("observation-snapshot", artifact(3)),
        ("observation-bytes", bytes(observation)),
        ("prior-state-schema", digest(&[2; 32])),
        ("prior-state-bytes", bytes(b"prior")),
        ("execution-profile-digest", digest(&[3; 32])),
        ("trust-policy-snapshot-digest", digest(&[4; 32])),
        ("deterministic-budget-id", text("budget")),
        ("deterministic-random-domain", digest(domain)),
        ("provenance-root", digest(&[5; 32])),
    ])
}

fn ok_result(value: Val) -> Val {
    Val::Result(Ok(Some(Box::new(value))))
}

fn fnv1a(mut hash: u64, input: &[u8]) -> u64 {
    for byte in input {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The specified `reduce`/`drive` result, computed independently of both guests.
fn expected_output(observation: &[u8], event_type: &str) -> Val {
    let mut random = [0; 16];
    let mut reader = blake3::Hasher::new_keyed(&DOMAIN).finalize_xof();
    reader.set_position(SEQ);
    reader.fill(&mut random);
    let mut hash = fnv1a(FNV_OFFSET, b"prior");
    hash = fnv1a(hash, observation);
    hash = fnv1a(hash, &INPUTS.simulation_time.to_le_bytes());
    hash = fnv1a(hash, &random);
    let state = hash.to_le_bytes();
    ok_result(record(vec![
        ("invocation-id", bytes(b"invocation-1")),
        (
            "event-drafts",
            Val::List(vec![record(vec![
                ("event-schema-id", Val::U32(1)),
                ("entity-id", bytes(b"invocation-1")),
                ("event-type", text(event_type)),
                ("canonical-payload", bytes(&state)),
                ("dependency-digests", empty()),
            ])]),
        ),
        ("next-state-schema", digest(&[2; 32])),
        ("next-state-bytes", bytes(&state)),
        ("trace-annotations", empty()),
        ("consumed-dependencies", empty()),
        ("output-digest", digest(&state.repeat(4))),
    ]))
}

fn expected_descriptor() -> Val {
    ok_result(record(vec![
        ("plugin-id", text("pigloros.compatibility-prototype")),
        ("release-semver", text("0.1.0")),
        ("world", text("pigloros:plugin/community-plugin@0.1.0")),
        ("abi-major", Val::U16(0)),
        ("min-abi-minor", Val::U16(1)),
        ("max-abi-minor", Val::U16(1)),
        ("required-features", empty()),
        ("event-schema-digests", Val::List(vec![digest(&[1; 32])])),
        ("state-schema-digest", digest(&[2; 32])),
        ("capabilities", empty()),
        ("migrations", empty()),
        ("dependencies", empty()),
        ("manifest-digest", digest(&[0; 32])),
        ("release-digest", digest(&[0; 32])),
    ]))
}

fn log(category: u16, message: &str) -> Vec<OperationalLogRecord> {
    vec![OperationalLogRecord {
        category,
        message: message.to_owned(),
    }]
}

fn measure(guest: &LoadedComponent, export: GuestExport, args: &[Val]) -> (u64, u64, u64) {
    let report = ok(run(guest, export, args, LIMITS), "measured invocation");
    (report.startup_fuel, report.call_fuel, report.memory_bytes)
}

fn measurement(guest_name: &'static str, call: &'static str, values: (u64, u64, u64)) -> Measurement {
    measured(guest_name, call, values.0, values.1, values.2)
}

fn recorded(guest_name: &str, call: &str) -> Measurement {
    MEASUREMENTS
        .into_iter()
        .find(|entry| entry.guest == guest_name && entry.call == call)
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("measurement not recorded")))
}

#[test]
fn both_guests_describe_the_same_plugin_without_migrations() {
    for (name, guest) in guests() {
        let report = ok(run(guest, GuestExport::Describe, &[], LIMITS), name);
        assert_eq!(report.value, expected_descriptor(), "{name}");
        assert!(report.operational_log.is_empty(), "{name}");
    }
}

#[test]
fn both_guests_reduce_and_drive_identically_on_every_repetition() {
    for (export, kind, message, event_type) in [
        (GuestExport::Reduce, "reduce", "reduce", "prototype.reduced"),
        (GuestExport::Drive, "drive", "drive", "prototype.driven"),
    ] {
        let args = [invocation(kind, b"observation", &DOMAIN)];
        let expected = expected_output(b"observation", event_type);
        for (name, guest) in guests() {
            for _ in 0..3 {
                let report = ok(run(guest, export, &args, LIMITS), name);
                assert_eq!(report.value, expected, "{name} {kind}");
                assert_eq!(report.operational_log, log(1, message), "{name} {kind}");
            }
        }
    }
}

#[test]
fn large_observations_stay_identical_across_guests() {
    let observation = vec![0xa5; LARGE_OBSERVATION_BYTES];
    let args = [invocation("reduce", &observation, &DOMAIN)];
    let expected = expected_output(&observation, "prototype.reduced");
    for (name, guest) in guests() {
        let report = ok(run(guest, GuestExport::Reduce, &args, LIMITS), name);
        assert_eq!(report.value, expected, "{name}");
    }
}

#[test]
fn budget_measurements_match_the_recorded_evidence() {
    let small = [invocation("reduce", b"observation", &DOMAIN)];
    let large_observation = vec![0xa5; LARGE_OBSERVATION_BYTES];
    let large = [invocation("reduce", &large_observation, &DOMAIN)];
    let mut measurements = Vec::new();
    for (name, guest) in guests() {
        measurements.push(measurement(name, "describe", measure(guest, GuestExport::Describe, &[])));
        measurements.push(measurement(name, "reduce", measure(guest, GuestExport::Reduce, &small)));
        measurements.push(measurement(name, "reduce-1MiB", measure(guest, GuestExport::Reduce, &large)));
    }
    assert_eq!(measurements, MEASUREMENTS);
    assert_eq!([("rust", RUST_GUEST.len()), ("c", C_GUEST.len())], COMPONENT_BYTES);
}

#[test]
fn fuel_exhaustion_is_fuel_exhausted_and_discards_completed_host_calls() {
    let args = [invocation("reduce", b"observation", &DOMAIN)];
    for (name, guest) in guests() {
        let recorded = recorded(name, "reduce");
        let total = recorded.startup_fuel + recorded.call_fuel;
        let exact = InvocationLimits { fuel: total, ..LIMITS };
        assert!(run(guest, GuestExport::Reduce, &args, exact).is_ok(), "{name}");
        // One unit short, the guest has already logged and hashed when the
        // fuel runs out; the failure carries none of that work.
        let short = InvocationLimits { fuel: total - 1, ..LIMITS };
        let failure = run(guest, GuestExport::Reduce, &args, short).err();
        assert_eq!(failure, Some(InvocationFailure::FuelExhausted), "{name}");
        let starved = InvocationLimits { fuel: 1, ..LIMITS };
        let failure = run(guest, GuestExport::Describe, &[], starved).err();
        assert_eq!(failure, Some(InvocationFailure::FuelExhausted), "{name}");
    }
}

#[test]
fn memory_limit_stops_growth_exactly_at_the_limit() {
    let observation = vec![0xa5; LARGE_OBSERVATION_BYTES];
    let args = [invocation("reduce", &observation, &DOMAIN)];
    for (name, guest) in guests() {
        let peak = recorded(name, "reduce-1MiB").memory_bytes;
        let exact = InvocationLimits { memory_bytes: peak, ..LIMITS };
        assert!(run(guest, GuestExport::Reduce, &args, exact).is_ok(), "{name}");
        let below = InvocationLimits { memory_bytes: peak - 65_536, ..LIMITS };
        let failure = run(guest, GuestExport::Reduce, &args, below).err();
        assert_eq!(failure, Some(InvocationFailure::MemoryLimitExceeded), "{name}");
        let none = InvocationLimits { memory_bytes: 0, ..LIMITS };
        let failure = run(guest, GuestExport::Describe, &[], none).err();
        assert_eq!(failure, Some(InvocationFailure::MemoryLimitExceeded), "{name}");
    }
}

#[test]
fn guest_traps_after_a_host_call_return_no_output() {
    let args = [invocation("reduce", b"trap", &DOMAIN)];
    for (name, guest) in guests() {
        let failure = run(guest, GuestExport::Reduce, &args, LIMITS).err();
        let trap = InvocationFailure::ComponentTrap(Trap::UnreachableCodeReached);
        assert_eq!(failure, Some(trap), "{name}");
    }
}

#[test]
fn an_elapsed_watchdog_is_an_operational_stop() {
    let args = [invocation("reduce", b"observation", &DOMAIN)];
    let elapsed = InvocationLimits { watchdog_epochs: 0, ..LIMITS };
    for (name, guest) in guests() {
        let failure = run(guest, GuestExport::Reduce, &args, elapsed).err();
        assert_eq!(failure, Some(InvocationFailure::OperationalWatchdogStop), "{name}");
    }
}

#[test]
fn refused_host_calls_and_mistyped_arguments_fail_closed() {
    let short_domain = [invocation("reduce", b"observation", &DOMAIN[..31])];
    for (name, guest) in guests() {
        let failure = run(guest, GuestExport::Reduce, &short_domain, LIMITS).err();
        assert_eq!(failure, Some(InvocationFailure::HostCallRejected), "{name}");
        let failure = run(guest, GuestExport::Reduce, &[], LIMITS).err();
        assert_eq!(failure, Some(InvocationFailure::Rejected), "{name}");
    }
}

#[test]
fn ambient_and_undeclared_imports_are_denied_before_execution() {
    let host = &PROTOTYPE.host;
    for (name, component) in [
        ("ambient WASI import", AMBIENT_WASI_IMPORT),
        ("undeclared host-v1 function", UNDECLARED_HOST_FUNCTION),
        ("mistyped host-v1 function", MISTYPED_HOST_FUNCTION),
    ] {
        assert_eq!(host.load(component).err(), Some(LoadError::ImportDenied), "{name}");
    }
    assert_eq!(host.load(NO_GUEST_EXPORTS).err(), Some(LoadError::MissingGuestExport));
    assert_eq!(host.load(b"not a component").err(), Some(LoadError::InvalidComponent));
}

#[test]
fn guest_exports_have_their_wit_names() {
    let names = GuestExport::ALL.map(GuestExport::name);
    assert_eq!(names, ["describe", "reduce", "drive"]);
}
