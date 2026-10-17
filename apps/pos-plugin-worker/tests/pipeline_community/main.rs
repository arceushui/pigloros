//! Cross-path community Plugin-host conformance, profile `PCH1` version 1 (#489, #631).
//!
//! The immutable manifest under `fixtures/conformance/pipeline/community/v1` names every case
//! that proves ADR-021 decision 7 across the two accepted isolation classes: an
//! operator-trusted native Driver and a governed community Driver that runs a real Component in
//! the real `pos-plugin-worker`. The cases run here because only this package's tests can launch
//! the worker binary. Every case runs and records its captures on both stores of the community
//! pass world, `MemoryStore` and in-memory `SQLite` (#638); the trust registry stays on
//! `MemoryStore`.
//!
//! The runner reuses the fail-closed harness of the first-party profile `PPC1`
//! (`apps/piglor-gateway/tests/pipeline_conformance/harness.rs`) unchanged: an unknown magic,
//! version or field, a changed fixture byte, a skipped mandatory case, a runner without a case,
//! a missing or unexpected capture, a diverging value, and evidence whose observation profile
//! differs from the declared tag all fail. Only the magic differs: the community magic and
//! version are checked here first, then the harness parses the document under its own rules.
#![cfg(target_os = "linux")]

pub mod authority;
pub mod budget;
pub mod fail_closed;
pub mod failure;
pub mod first_party;
#[path = "../../../piglor-gateway/tests/pipeline_conformance/harness.rs"]
pub mod harness;
pub mod parity;
pub mod replay;
#[path = "../support/mod.rs"]
pub mod support;

use harness::{
    load_manifest, require_version, run_suite, verify_pinned, Capture, Case, ConformanceError,
    Manifest, Runner, PROFILE_MAGIC, PROFILE_VERSION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::test_ok::TestOk;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Magic of a community Plugin-host conformance profile manifest.
const COMMUNITY_MAGIC: &str = "PCH1";
/// The only supported community profile manifest version.
const COMMUNITY_VERSION: u64 = 1;

/// The immutable profile manifest and its pinned SHA-256.
const MANIFEST: &[u8] =
    include_bytes!("../../../../fixtures/conformance/pipeline/community/v1/manifest.json");
const MANIFEST_SHA256: &str = "54e9b7383fb56208badf407724e68395356aa0650b78110ae508ecf8b381828b";

/// Every runner of profile version 1, by case identifier.
const RUNNERS: [(&str, Runner); 13] = [
    ("PCF-CPH-001", parity::single_pass_parity),
    ("PCF-CPH-002", parity::mixed_registry_order),
    ("PCF-CPH-003", authority::foreign_proposal_parity),
    ("PCF-CPH-004", authority::single_lineage_owner),
    ("PCF-CPH-005", failure::failure_containment),
    ("PCF-CPH-006", failure::no_fallback_or_retry),
    ("PCF-CPH-007", fail_closed::missing_implementation),
    ("PCF-CPH-008", fail_closed::unavailable_implementation),
    ("PCF-CPH-009", fail_closed::invalid_implementation),
    ("PCF-CPH-010", budget::over_budget_parity),
    ("PCF-CPH-011", replay::replay_parity),
    ("PCF-CPH-012", replay::lost_acknowledgement_recovery),
    ("PCF-CPH-013", authority::reserved_proposal_parity),
];

/// Parse a `PCH1` manifest under the harness rules of `PPC1`.
///
/// The harness pins its own magic, so the community magic and version are checked first with the
/// harness's `require_version`, and the document is then handed to `load_manifest` under the
/// magic and version its rule set expects. Every other rule is the harness's own.
fn load_community_manifest(bytes: &[u8]) -> Result<Manifest, ConformanceError> {
    let invalid = ConformanceError::InvalidManifest;
    let parsed = serde_json::from_slice::<Value>(bytes);
    let mut root = parsed.map_err(|error| invalid(format!("not JSON: {error}")))?;
    let object = root
        .as_object_mut()
        .ok_or_else(|| invalid("the manifest is not an object".to_owned()))?;
    require_version(object, COMMUNITY_MAGIC, COMMUNITY_VERSION)?;
    object.insert("magic".to_owned(), Value::from(PROFILE_MAGIC));
    object.insert("version".to_owned(), Value::from(PROFILE_VERSION));
    let shared = serde_json::to_vec(&root).map_err(|error| invalid(error.to_string()))?;
    load_manifest(&shared)
}

/// Whether `case` is mandatory and runs on both stores of the community pass world.
fn mandatory_on_both_stores(case: &Case) -> bool {
    case.mandatory && case.stores == ["memory", "sqlite"]
}

/// Every mandatory case of `PCH1` version 1 passes on the real worker. The exclusions record
/// what the profile does not prove yet, with the subtask that owns it.
#[test]
fn pch1_every_mandatory_case_passes_on_the_real_worker() {
    verify_pinned(MANIFEST, MANIFEST_SHA256).test_ok();
    let manifest = load_community_manifest(MANIFEST).test_ok();
    let report = run_suite(&manifest, &RUNNERS);

    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    assert!(report.skipped_optional.is_empty());
    assert!(report.not_applicable.is_empty());
    assert_eq!(manifest.suite, "pigloros.pipeline-community-host");
    assert_eq!(report.passed.len(), RUNNERS.len());
    assert_eq!(manifest.cases.len(), RUNNERS.len());
    assert!(manifest.cases.iter().all(mandatory_on_both_stores));
    assert_eq!(manifest.exclusions.len(), 2);
}

// ── Fail-closed harness behaviour ───────────────────────────────────────────

fn case(id: &str, mandatory: bool) -> Value {
    json!({
        "id": id,
        "title": "harness case",
        "sources": ["#489"],
        "mandatory": mandatory,
        "applicability": {"status": "applicable"},
        "stores": ["memory"],
        "observation_profile": null,
        "expected": {"key": "value"},
    })
}

fn document(cases: &[Value]) -> Value {
    json!({
        "magic": "PCH1",
        "version": 1,
        "suite": "harness",
        "sources": ["#489"],
        "exclusions": [],
        "cases": cases,
    })
}

fn load(root: &Value) -> Result<Manifest, ConformanceError> {
    load_community_manifest(&serde_json::to_vec(root).test_ok())
}

fn records_value() -> Capture {
    let mut capture = Capture::default();
    capture.record("memory", "key", "value");
    capture
}

fn unsupported(found: &str) -> Result<Manifest, ConformanceError> {
    Err(ConformanceError::UnsupportedVersion(found.to_owned()))
}

fn unknown(at: &str, field: &str) -> Result<Manifest, ConformanceError> {
    Err(ConformanceError::UnknownField {
        at: at.to_owned(),
        field: field.to_owned(),
    })
}

/// A changed byte of the manifest, such as an extra case, fails the pin.
#[test]
fn pch1_a_changed_manifest_byte_fails_the_pin() {
    let mut changed = MANIFEST.to_vec();
    changed.push(b' ');
    assert!(matches!(
        verify_pinned(&changed, MANIFEST_SHA256),
        Err(ConformanceError::DigestMismatch { .. })
    ));
}

/// An unknown magic or version, the first-party magic included, or an unknown field fails
/// before any case is read; the first-party loader refuses the community manifest the same way.
#[test]
fn pch1_an_unknown_magic_version_or_field_fails_closed() {
    let mut root = document(&[]);
    assert!(load(&root).is_ok());
    root["version"] = json!(2);
    assert_eq!(load(&root), unsupported("PCH1/2"));
    root["version"] = json!(1);
    root["magic"] = json!("PPC1");
    assert_eq!(load(&root), unsupported("PPC1/1"));
    root["magic"] = json!("PCH0");
    assert_eq!(load(&root), unsupported("PCH0/1"));
    root["magic"] = json!("PCH1");
    root["waiver"] = json!(true);
    assert_eq!(load(&root), unknown("manifest", "waiver"));
    let mut extended = case("X", true);
    extended["skip"] = json!(true);
    assert_eq!(load(&document(&[extended])), unknown("cases[0]", "skip"));
    assert!(matches!(
        load_community_manifest(b"not json"),
        Err(ConformanceError::InvalidManifest(_))
    ));
    assert_eq!(load_manifest(MANIFEST), unsupported("PCH1/1"));
}

/// A case without a runner is a skipped mandatory case, whether it is a case of the profile or
/// an extra one, and a runner without a case is unknown.
#[test]
fn pch1_a_skipped_case_an_extra_case_or_an_unknown_runner_fails() {
    let manifest = load_community_manifest(MANIFEST).test_ok();
    let skipped: Vec<ConformanceError> = manifest
        .cases
        .iter()
        .map(|case| ConformanceError::SkippedMandatoryCase(case.id.clone()))
        .collect();
    assert_eq!(run_suite(&manifest, &[]).failures, skipped);

    let extra = load(&document(&[case("X", true), case("Y", true)])).test_ok();
    let runners: [(&str, Runner); 1] = [("X", records_value)];
    let failures = run_suite(&extra, &runners).failures;
    let missing = ConformanceError::SkippedMandatoryCase("Y".to_owned());
    assert_eq!(failures, vec![missing]);

    let runners: [(&str, Runner); 3] = [
        ("X", records_value),
        ("Y", records_value),
        ("Z", records_value),
    ];
    let failures = run_suite(&extra, &runners).failures;
    let unknown_runner = ConformanceError::UnknownRunner("Z".to_owned());
    assert_eq!(failures, vec![unknown_runner]);
}

/// The runner table names exactly the cases of the manifest, in manifest order.
#[test]
fn pch1_every_case_has_exactly_one_runner() {
    let manifest = load_community_manifest(MANIFEST).test_ok();
    let cases = manifest.cases.iter().map(|case| case.id.as_str());
    let cases: Vec<&str> = cases.collect();
    let runners: Vec<&str> = RUNNERS.iter().map(|(id, _)| *id).collect();
    assert_eq!(cases, runners);
}

/// One byte of a pinned lower-case hexadecimal digest.
fn hex_byte(pair: &[u8]) -> Option<u8> {
    let text = std::str::from_utf8(pair).ok()?;
    u8::from_str_radix(text, 16).ok()
}

/// The pin is the plain SHA-256 of the manifest bytes, not an artefact of the shared helper.
#[test]
fn pch1_the_pin_is_the_sha256_of_the_manifest() -> TestResult {
    let pairs = MANIFEST_SHA256.as_bytes().chunks(2);
    let pinned = pairs.map(hex_byte).collect::<Option<Vec<u8>>>();
    let pinned = pinned.ok_or("the pin is not hexadecimal")?;
    assert_eq!(Sha256::digest(MANIFEST).to_vec(), pinned);
    Ok(())
}

/// The version directory holds exactly the pinned manifest.
#[test]
fn pch1_the_v1_directory_holds_exactly_the_pinned_files() -> TestResult {
    let directory = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/conformance/pipeline/community/v1"
    );
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        files.push((name, harness::sha256_hex(&std::fs::read(entry.path())?)));
    }
    files.sort();
    let pinned = ("manifest.json".to_owned(), MANIFEST_SHA256.to_owned());
    assert_eq!(files, vec![pinned]);
    Ok(())
}
