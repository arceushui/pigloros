//! The steerable probe guest, run through the #541 engine.
//!
//! `probe-guest.wasm` is the compatibility Rust guest with faults selected by
//! its observation bytes, under both `reduce` and `drive`: `reserved` drafts
//! the reserved host release-activation Event type under a valid output
//! digest, `fallback-declared` and `fallback-activated` draft the ADR-119
//! reserved host types the same way (#665), and `bad-digest` returns a zeroed
//! output digest. Any other observation behaves exactly like the Rust guest.
//!
//! These tests prove only the guest side of the selectors: this
//! crate cannot reach the registry or the real worker, so the host's
//! `ReservedHostDraft` refusal is proven by PCF-CPH-013 and, for the ADR-119
//! types, by PCF-CPH-017 of PCH1 version 2, and the pass that `bad-digest`
//! fails with `InvalidGuestOutput` by PCF-CPH-014, in the PCH1 runner.
//!
//! The probe guest also reaches each host-call and output limit of a release
//! budget exactly (#625): the `res.5` to `res.7` sub-cases of the Plugin
//! conformance fixtures lower its `state_bytes`, `log_calls` and `log_bytes`
//! budgets one below what its `drive` uses, and the real worker proves them at
//! pass level (`apps/pos-plugin-worker/tests/conformance_fixtures_public.rs`).

pub mod common;

use std::sync::LazyLock;

use common::{execution, invocation, ok, options, BUDGET, RUST_GUEST};
use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_plugin_host::{ComponentHost, GuestExport, LoadedComponent};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, CommunityPluginHostErrorV1, InvocationOptionsV1, InvocationReportV1,
    PluginOutputV1, PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1,
};

/// The committed probe guest, built by `build-fixtures.sh`.
const PROBE_GUEST: &[u8] = include_bytes!(
    "../../../plugins/community/examples/compatibility-prototype/fixtures/probe-guest.wasm"
);
const OPTIONS: InvocationOptionsV1 = options(42, 1);
/// The exports the selectors steer.
const EXPORTS: [GuestExport; 2] = [GuestExport::Reduce, GuestExport::Drive];
/// Observations next to the selectors, which must not select anything.
const UNSELECTED: [&[u8]; 5] = [
    b"observation",
    b"reserve",
    b"bad-digest\0",
    b"fallback-declare",
    b"fallback-activated ",
];
/// The ADR-119 fallback declaration type.
///
/// This crate does not depend on `pos-core`, so the ADR-119 types are spelled
/// out; they equal `COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1` and
/// `COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1`.
const DECLARED: &str = "pigloros.composition.fallback-declared";
/// The ADR-119 fallback activation type.
const ACTIVATED: &str = "pigloros.composition.fallback-activated";
/// Each type selector and the reserved host Event type its draft carries.
const TYPE_SELECTORS: [(&[u8], &str); 3] = [
    (b"reserved", PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1),
    (b"fallback-declared", DECLARED),
    (b"fallback-activated", ACTIVATED),
];

type Outcome = Result<InvocationReportV1<PluginOutputV1>, CommunityPluginHostErrorV1>;

struct Guests {
    host: ComponentHost,
    rust: LoadedComponent,
    probe: LoadedComponent,
}

static GUESTS: LazyLock<Guests> = LazyLock::new(|| {
    let host = ok(ComponentHost::new(), "pinned engine");
    let rust = ok(host.load(RUST_GUEST), "Rust guest");
    let probe = ok(host.load(PROBE_GUEST), "probe guest");
    Guests { host, rust, probe }
});

fn run(guest: &LoadedComponent, export: GuestExport, observation: &[u8]) -> Outcome {
    let host = &GUESTS.host;
    let execution = execution(BUDGET);
    let invocation = invocation(observation);
    if export == GuestExport::Drive {
        host.drive(guest, &execution, &invocation, OPTIONS)
    } else {
        host.reduce(guest, &execution, &invocation, OPTIONS)
    }
}

#[test]
fn unselected_observations_behave_exactly_like_the_rust_guest() {
    for export in EXPORTS {
        for bytes in UNSELECTED {
            let expected = ok(run(&GUESTS.rust, export, bytes), "Rust guest");
            let probe = ok(run(&GUESTS.probe, export, bytes), "probe guest");
            assert_eq!(probe.result, expected.result, "{export:?} {bytes:?}");
            let log = expected.operational_log;
            assert_eq!(probe.operational_log, log, "{export:?} {bytes:?}");
        }
        let trap = run(&GUESTS.rust, export, b"trap").err();
        assert!(trap.is_some(), "{export:?}");
        let probe = run(&GUESTS.probe, export, b"trap").err();
        assert_eq!(probe, trap, "{export:?}");
    }
}

/// The probe guest under `selector` drafts exactly one Event of `reserved`
/// under a valid digest, and is otherwise equal to the Rust guest.
fn drafts_the_reserved_type(export: GuestExport, selector: &[u8], reserved: &str) {
    let rust = ok(run(&GUESTS.rust, export, selector), "Rust guest");
    let mut expected = ok(rust.result, "Rust guest output");
    reserved.clone_into(&mut expected.event_drafts[0].event_type);
    expected.output_digest = plugin_output_digest_v1(&expected);
    let probe = ok(run(&GUESTS.probe, export, selector), "probe guest");
    assert_eq!(probe.operational_log, rust.operational_log, "{export:?}");
    let output = ok(probe.result, "probe guest output");
    let types: Vec<&str> = output
        .event_drafts
        .iter()
        .map(|draft| draft.event_type.as_str())
        .collect();
    assert_eq!(types, [reserved], "{export:?} {reserved}");
    let digest = plugin_output_digest_v1(&output);
    assert_eq!(output.output_digest, digest, "{export:?} {reserved}");
    assert_eq!(output, expected, "{export:?} {reserved}");
}

#[test]
fn each_type_selector_drafts_its_reserved_host_type_under_a_valid_digest() {
    for export in EXPORTS {
        for (selector, reserved) in TYPE_SELECTORS {
            drafts_the_reserved_type(export, selector, reserved);
        }
    }
}

#[test]
fn the_bad_digest_selector_is_invalid_guest_output() {
    for export in EXPORTS {
        let rust = ok(run(&GUESTS.rust, export, b"bad-digest"), "Rust guest");
        assert!(rust.result.is_ok(), "{export:?}");
        let failure = run(&GUESTS.probe, export, b"bad-digest").err();
        let invalid = CommunityPluginHostErrorV1::InvalidGuestOutput;
        assert_eq!(failure, Some(invalid), "{export:?}");
    }
}

/// The failure of the probe guest's `drive` of `b"observation"` under `budget`,
/// or `None` when it returns.
fn drive_under(budget: DeterministicBudgetV1) -> Option<CommunityPluginHostErrorV1> {
    let execution = execution(budget);
    let invocation = invocation(b"observation");
    GUESTS
        .host
        .drive(&GUESTS.probe, &execution, &invocation, OPTIONS)
        .err()
}

/// One budget member at exactly what the probe guest's `drive` uses, the same
/// member one below it, and the error that the lower budget gives.
struct Bound {
    name: &'static str,
    exact: DeterministicBudgetV1,
    below: DeterministicBudgetV1,
    error: CommunityPluginHostErrorV1,
}

/// The `drive` uses three host calls (time, random and log), one Event whose
/// payload is the 8-byte state, the 8-byte state itself, and one log call
/// whose message is `drive` (5 bytes).
const BOUNDS: [Bound; 5] = [
    Bound {
        name: "host_calls",
        exact: DeterministicBudgetV1 {
            host_calls: 3,
            ..BUDGET
        },
        below: DeterministicBudgetV1 {
            host_calls: 2,
            ..BUDGET
        },
        error: CommunityPluginHostErrorV1::HostCallLimitExceeded,
    },
    Bound {
        name: "event_bytes",
        exact: DeterministicBudgetV1 {
            event_bytes: 8,
            ..BUDGET
        },
        below: DeterministicBudgetV1 {
            event_bytes: 7,
            ..BUDGET
        },
        error: CommunityPluginHostErrorV1::OutputLimitExceeded,
    },
    Bound {
        name: "state_bytes",
        exact: DeterministicBudgetV1 {
            state_bytes: 8,
            ..BUDGET
        },
        below: DeterministicBudgetV1 {
            state_bytes: 7,
            ..BUDGET
        },
        error: CommunityPluginHostErrorV1::OutputLimitExceeded,
    },
    Bound {
        name: "log_calls",
        exact: DeterministicBudgetV1 {
            log_calls: 1,
            ..BUDGET
        },
        below: DeterministicBudgetV1 {
            log_calls: 0,
            ..BUDGET
        },
        error: CommunityPluginHostErrorV1::OutputLimitExceeded,
    },
    Bound {
        name: "log_bytes",
        exact: DeterministicBudgetV1 {
            log_bytes: 5,
            ..BUDGET
        },
        below: DeterministicBudgetV1 {
            log_bytes: 4,
            ..BUDGET
        },
        error: CommunityPluginHostErrorV1::OutputLimitExceeded,
    },
];

#[test]
fn the_probe_guest_reaches_each_call_and_output_limit_exactly() {
    for bound in BOUNDS {
        assert_eq!(drive_under(bound.exact), None, "{}", bound.name);
        let failure = drive_under(bound.below);
        assert_eq!(failure, Some(bound.error), "{}", bound.name);
    }
}
