//! The ADR-135 §4 Air-Gapped test shape (#1422).
//!
//! An Air-Gapped end-to-end test re-executes its own test binary under
//! `scripts/air-gapped-namespace.sh`: a network namespace that holds only `lo`
//! (up), empty capability sets, `no_new_privs` and the test seccomp
//! address-family filter. This is a test harness, never a production
//! override: the Gateway reads only `/proc/self`. The test here proves the
//! shape itself on the runner, through the files ADR-135 §4 names.
#![cfg(target_os = "linux")]

use std::{
    fs,
    net::{TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::Command,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Set only for the re-executed child, which then runs the test body.
const INSIDE: &str = "PIGLOROS_AIR_GAPPED_TEST_NAMESPACE";
/// The kernel's fallback tunnel devices, which exist in every network
/// namespace while their module is loaded (ADR-135 §4 item 1).
const FALLBACK_DEVICES: [&str; 9] = [
    "sit0", "tunl0", "ip6tnl0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "ip6gre0",
];

/// Run `body` as `test` of this binary inside the Air-Gapped test shape: the
/// parent re-executes the binary under the namespace script and requires
/// the child to pass.
fn in_air_gapped_namespace(test: &str, body: impl FnOnce() -> TestResult) -> TestResult {
    if std::env::var_os(INSIDE).is_some() {
        return body();
    }
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/air-gapped-namespace.sh");
    let status = Command::new(script)
        .arg(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture"])
        .env(INSIDE, "1")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{test} failed in the Air-Gapped test namespace: {status}").into())
    }
}

/// The value of `key` in `/proc/self/status`.
fn status_field<'a>(status: &'a str, key: &str) -> Result<&'a str, String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .map(str::trim)
        .ok_or_else(|| format!("/proc/self/status has no {key}"))
}

#[test]
fn the_air_gapped_test_shape_has_only_loopback_and_no_network_capability() -> TestResult {
    in_air_gapped_namespace(
        "the_air_gapped_test_shape_has_only_loopback_and_no_network_capability",
        || {
            let status = fs::read_to_string("/proc/self/status")?;
            for key in ["CapEff", "CapPrm", "CapAmb", "CapBnd", "CapInh"] {
                assert_eq!(status_field(&status, key)?, "0000000000000000", "{key}");
            }
            assert_eq!(status_field(&status, "NoNewPrivs")?, "1");
            assert_eq!(status_field(&status, "Seccomp")?, "2");

            let devices = fs::read_to_string("/proc/self/net/dev")?;
            let names = devices
                .lines()
                .skip(2)
                .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
                .collect::<Vec<_>>();
            assert!(names.contains(&"lo"), "{names:?}");
            assert!(
                names
                    .iter()
                    .all(|name| *name == "lo" || FALLBACK_DEVICES.contains(name)),
                "{names:?}"
            );
            let routes = fs::read_to_string("/proc/self/net/route")?;
            assert_eq!(routes.lines().count(), 1, "{routes}");

            // `lo` is up: a loopback listener accepts; nothing else is routed.
            let listener = TcpListener::bind("127.0.0.1:0")?;
            TcpStream::connect(listener.local_addr()?)?;
            let probe = UdpSocket::bind("0.0.0.0:0")?;
            assert!(probe.connect("192.0.2.1:9").is_err());
            Ok(())
        },
    )
}
