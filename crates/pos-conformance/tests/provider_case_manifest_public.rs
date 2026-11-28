//! The provider case manifest through its public interface: the committed
//! vector is exactly what the code states, and it names every case once.

use pos_conformance::{case_manifest_v1, ProviderConformanceCase};
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const COMMITTED: &str = include_str!("vectors/provider-cases-v1.json");

#[test]
fn the_committed_vector_is_what_the_code_states() -> TestResult {
    let committed: Value = serde_json::from_str(COMMITTED)?;
    assert_eq!(committed, case_manifest_v1());
    Ok(())
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
