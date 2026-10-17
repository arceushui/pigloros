//! The steerable probe guest, run through the #541 engine.
//!
//! `probe-guest.wasm` is the compatibility Rust guest with two faults selected
//! by its observation bytes, under both `reduce` and `drive`: `reserved` drafts
//! the reserved host Event type under a valid output digest, and `bad-digest`
//! returns a zeroed output digest. Any other observation behaves exactly like
//! the Rust guest.
//!
//! These tests prove only the guest side of `reserved`: this crate cannot reach
//! the registry, so the host's `ReservedHostDraft` refusal is proven by
//! PCF-CPH-013 in the PCH1 runner.

pub mod common;

use std::sync::LazyLock;

use common::{execution, invocation, ok, options, BUDGET, RUST_GUEST};
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
const UNSELECTED: [&[u8]; 3] = [b"observation", b"reserve", b"bad-digest\0"];

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

#[test]
fn the_reserved_selector_drafts_the_reserved_host_type_under_a_valid_digest() {
    for export in EXPORTS {
        let rust = ok(run(&GUESTS.rust, export, b"reserved"), "Rust guest");
        let mut expected = ok(rust.result, "Rust guest output");
        expected.event_drafts[0].event_type = PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1.to_owned();
        expected.output_digest = plugin_output_digest_v1(&expected);
        let probe = ok(run(&GUESTS.probe, export, b"reserved"), "probe guest");
        assert_eq!(probe.operational_log, rust.operational_log, "{export:?}");
        let output = ok(probe.result, "probe guest output");
        let types: Vec<&str> = output
            .event_drafts
            .iter()
            .map(|draft| draft.event_type.as_str())
            .collect();
        let reserved = [PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1];
        assert_eq!(types, reserved, "{export:?}");
        let digest = plugin_output_digest_v1(&output);
        assert_eq!(output.output_digest, digest, "{export:?}");
        assert_eq!(output, expected, "{export:?}");
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
