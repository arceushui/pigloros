//! The provider case manifest through its public interface: the committed
//! vector is exactly what the code states, byte for byte, and it names every
//! case once.
//!
//! After a deliberate change of the cases, rewrite the vector with
//! `cargo test -p pos-conformance --test provider_case_manifest_public --
//! --ignored regenerate`, and review the diff.

use pos_conformance::{case_manifest_v1, ProviderConformanceCase};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const COMMITTED: &str = include_str!("vectors/provider-cases-v1.json");

/// The vector's exact text: pretty-printed, keys in alphabetical order and a
/// final newline, which the shell collector and the Python checker read.
fn vector_text() -> Result<String, serde_json::Error> {
    Ok(serde_json::to_string_pretty(&case_manifest_v1())? + "\n")
}

#[test]
fn the_committed_vector_is_what_the_code_states() -> TestResult {
    let committed: Value = serde_json::from_str(COMMITTED)?;
    assert_eq!(committed, case_manifest_v1());
    assert_eq!(COMMITTED, vector_text()?);
    Ok(())
}

#[test]
#[ignore = "rewrites the committed vector; run it by name after a deliberate change"]
fn regenerate_the_committed_vector() -> TestResult {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/provider-cases-v1.json"
    );
    std::fs::write(path, vector_text()?)?;
    Ok(())
}

#[test]
fn a_limit_bound_is_the_overshoot_times_its_ceiling() {
    let manifest = case_manifest_v1();
    let overshoot = manifest["overshoot"].as_u64().unwrap_or(0);
    assert_eq!(overshoot, 2);
    let ceilings = &manifest["ceilings"];
    let expected = [
        ("work-area-exhaustion", "work_bytes"),
        ("task-exhaustion", "tasks"),
        ("memory-exhaustion", "memory_bytes"),
        ("watchdog-expiry", "watchdog_ms"),
        ("oversized-output", "output_bytes"),
        ("cancel-while-running", "watchdog_ms"),
        ("revoked-while-running", "watchdog_ms"),
        ("broker-crash-recovery", "watchdog_ms"),
    ];
    for (id, ceiling) in expected {
        let case = manifest["cases"]
            .as_array()
            .and_then(|cases| cases.iter().find(|case| case["id"] == id));
        let bound = case
            .and_then(|case| case["arguments"][1].as_str())
            .and_then(|text| text.parse::<u64>().ok());
        assert_eq!(
            bound,
            ceilings[ceiling].as_u64().map(|value| value * overshoot),
            "{id}"
        );
    }
}

#[test]
fn every_case_is_named_once_in_report_order() {
    let manifest = case_manifest_v1();
    let ids: Vec<&str> = manifest["cases"]
        .as_array()
        .map(|cases| {
            cases
                .iter()
                .filter_map(|case| case["id"].as_str())
                .collect()
        })
        .unwrap_or_default();
    let expected: Vec<&str> = ProviderConformanceCase::ALL
        .iter()
        .map(|case| case.id())
        .collect();
    assert_eq!(ids, expected);
    assert_eq!(manifest["version"], 1);
}

#[test]
fn every_driver_is_one_of_the_four() {
    let manifest = case_manifest_v1();
    let drivers: Vec<&str> = manifest["cases"]
        .as_array()
        .map(|cases| {
            cases
                .iter()
                .filter_map(|case| case["driver"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(drivers.len(), ProviderConformanceCase::ALL.len());
    for name in ["single-execute", "control", "admission", "concurrent"] {
        assert!(drivers.contains(&name), "{name}");
    }
    assert!(drivers
        .iter()
        .all(|name| ["single-execute", "control", "admission", "concurrent"].contains(name)));
}
