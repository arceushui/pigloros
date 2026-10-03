//! Cross-path pipeline conformance, profile `PPC1` version 1 (#488, #321a).
//!
//! The immutable manifest under `fixtures/conformance/pipeline/v1` names
//! every case of the first-party and in-process profile: human and AI
//! ingress through atomic host admission (#316, #318, #319), failure
//! precedence, recovery, Replay and evaluation non-authority (#320), the
//! ADR-021 Revision 3 observation profiles and their composition-time
//! assignment (#504), participant-authorized recovery (#507), draft and
//! exclusive Event-type ownership (#484, #486, ADR-024 Revision 1), source
//! quarantine (#493, ADR-024 Revision 2), revocation persistence (#483)
//! and the ADR-021 Revision 4 consent-sensitive Driver subscriptions
//! (#494). Each case runs only through public seams, on `MemoryStore` and
//! `SQLite` wherever a store is involved, and its expected observations are
//! data in the manifest.
//!
//! The suite fails closed: an unknown manifest version or field, a changed
//! fixture byte, a skipped mandatory case, a missing or unexpected capture,
//! a diverging value, or evidence whose observation profile differs from the
//! declared tag is a failure. Community Plugin-host cases are #489.

pub mod composition;
pub mod consent_subscriptions;
pub mod eval_seam;
pub mod gateway;
pub mod harness;
pub mod ingress;
pub mod nonparticipant;
pub mod ownership;
pub mod participant_recovery;
pub mod profiles;
pub mod quarantine;
pub mod revocation;
pub mod support;

use harness::{
    load_manifest, run_suite, verify_pinned, Applicability, Capture, ConformanceError, Runner,
    PROFILE_KEY,
};
use serde_json::{json, Value};
use support::TestOk;

/// The immutable profile manifest and its pinned SHA-256.
const MANIFEST: &[u8] =
    include_bytes!("../../../../fixtures/conformance/pipeline/v1/manifest.json");
const MANIFEST_SHA256: &str = "f62908ed161c9fdfda7d549b2e906548d0ca12b1281c470497ea701a748c1c6f";

/// Every runner of profile version 1, by case identifier.
const RUNNERS: [(&str, Runner); 54] = [
    ("PCF-ING-001", ingress::ingress_parity),
    ("PCF-ING-002", ingress::human_admission_receipt),
    ("PCF-ING-003", gateway::first_party_has_no_privileged_route),
    ("PCF-ING-004", eval_seam::unowned_output_parity),
    ("PCF-FP-001", gateway::authorization_precedence),
    ("PCF-FP-002", ingress::store_failure_precedence),
    ("PCF-FP-003", ingress::scheduled_pass_discard),
    ("PCF-REC-001", ingress::disconnect_after_commit),
    ("PCF-REC-002", ingress::lost_acknowledgement_recovery),
    ("PCF-REC-003", ingress::exact_retry_and_conflict),
    (
        "PCF-REC-004",
        participant_recovery::participant_commit_recovery,
    ),
    ("PCF-RPL-001", ingress::replay_never_resubmits),
    ("PCF-EVL-001", ingress::evaluation_non_authority),
    ("PCF-R3-001", profiles::participant_pass_needs_its_fence),
    ("PCF-R3-002", profiles::one_pass_one_profile),
    ("PCF-R3-003", profiles::digest_domain_separation),
    ("PCF-R3-005", profiles::participant_views_are_per_driver),
    (
        "PCF-R3-006",
        profiles::participant_views_are_revalidated_at_commit,
    ),
    (
        "PCF-R3-007",
        nonparticipant::non_participant_pass_is_subscription_scoped,
    ),
    (
        "PCF-R3-008",
        nonparticipant::late_revocation_or_freeze_aborts_the_pass,
    ),
    ("PCF-R3-009", composition::unassigned_driver_is_rejected),
    (
        "PCF-R3-010",
        composition::participant_bound_driver_never_stages_anchored,
    ),
    ("PCF-R3-011", composition::mixed_composition_is_rejected),
    (
        "PCF-R4-001",
        consent_subscriptions::cursor_modality_subscription_is_rejected,
    ),
    (
        "PCF-R4-002",
        consent_subscriptions::cursor_fork_and_retention_subscriptions_are_rejected,
    ),
    (
        "PCF-R4-003",
        consent_subscriptions::verified_prefix_delivery_loses_nothing,
    ),
    (
        "PCF-R4-004",
        consent_subscriptions::cursor_subscription_to_ordinary_types_is_unchanged,
    ),
    (
        "PCF-R4-005",
        consent_subscriptions::registration_snapshot_governs,
    ),
    ("PCF-REG-001", ownership::second_claimant_rejected),
    ("PCF-REG-002", ownership::duplicate_declaration_rejected),
    ("PCF-REG-003", ownership::host_type_not_claimable),
    ("PCF-REG-004", ownership::order_independent),
    ("PCF-REG-005", ownership::latent_overlaps_fail_closed),
    ("PCF-REG-006", ownership::recorder_single_claimant),
    ("PCF-EVAL-001", ownership::persona_owns_no_eval_type),
    ("PCF-EVAL-002", eval_seam::derivation_units),
    (
        "PCF-EVAL-003",
        eval_seam::exactly_once_across_restart_discard_and_fork,
    ),
    ("PCF-EVAL-004", eval_seam::budget_never_splits_a_pair),
    ("PCF-EVAL-005", eval_seam::subscriptions_are_consent_gated),
    ("PCF-EVAL-006", eval_seam::replay_never_derives),
    ("PCF-EVAL-007", eval_seam::predictor_supplied_label),
    ("PCF-EVAL-008", eval_seam::injected_orphan_outcome),
    ("PCF-EVAL-009", eval_seam::legacy_history),
    ("PCF-EVAL-010", eval_seam::derived_evaluation_profile_tag),
    (
        "PCF-EVAL-R2-001",
        quarantine::bad_eligible_sources_are_quarantined,
    ),
    (
        "PCF-EVAL-R2-002",
        quarantine::invalid_probabilities_are_quarantined,
    ),
    ("PCF-EVAL-R2-003", quarantine::later_mapping_derives_once),
    (
        "PCF-EVAL-R2-004",
        quarantine::mapping_rollback_never_rederives,
    ),
    (
        "PCF-EVAL-R2-005",
        quarantine::precedence_and_bounded_decoding,
    ),
    (
        "PCF-EVAL-R2-006",
        quarantine::invalid_prefix_discards_the_pass,
    ),
    (
        "PCF-EVAL-R2-007",
        quarantine::erased_sources_never_reach_eval,
    ),
    ("PCF-REV-001", revocation::learned_revocation_is_persisted),
    ("PCF-REV-002", revocation::equal_epochs_distinct_revisions),
    ("PCF-REV-003", revocation::cross_connection_staleness),
];

#[test]
fn every_mandatory_case_of_profile_v1_passes_through_public_seams() {
    verify_pinned(MANIFEST, MANIFEST_SHA256).test_ok();
    let manifest = load_manifest(MANIFEST).test_ok();
    let report = run_suite(&manifest, &RUNNERS);

    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    assert!(report.skipped_optional.is_empty());
    assert_eq!(manifest.suite, "pigloros.pipeline-cross-path");
    assert_eq!(report.passed.len(), RUNNERS.len());
    let inapplicable: Vec<String> = manifest
        .cases
        .iter()
        .filter(|case| case.applicability != Applicability::Applicable)
        .map(|case| case.id.clone())
        .collect();
    assert_eq!(report.not_applicable, inapplicable);
    assert_eq!(manifest.cases.len(), 55);
    assert_eq!(
        report.passed.len() + report.not_applicable.len(),
        manifest.cases.len()
    );
    assert!(manifest
        .cases
        .iter()
        .all(|case| case.mandatory && !case.id.is_empty()));
    assert_eq!(manifest.exclusions.len(), 2);
}

// ── Fail-closed harness behaviour ───────────────────────────────────────────

fn case(id: &str, mandatory: bool, profile: Option<&str>, expected: &Value) -> Value {
    json!({
        "id": id,
        "title": "harness case",
        "sources": ["#488"],
        "mandatory": mandatory,
        "applicability": {"status": "applicable"},
        "stores": ["memory"],
        "observation_profile": profile,
        "expected": expected,
    })
}

fn manifest(cases: &[Value]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "magic": "PPC1",
        "version": 1,
        "suite": "harness",
        "sources": ["#488"],
        "exclusions": [],
        "cases": cases,
    }))
    .test_ok()
}

fn records_nothing() -> Capture {
    Capture::default()
}

fn records_value() -> Capture {
    let mut capture = Capture::default();
    capture.record("memory", "key", "value");
    capture
}

fn records_non_participant_value() -> Capture {
    let mut capture = records_value();
    capture.record("memory", PROFILE_KEY, "non-participant");
    capture
}

fn records_twice() -> Capture {
    let mut capture = records_value();
    capture.record("memory", "key", "other");
    capture
}

fn panics() -> Capture {
    std::panic::resume_unwind(Box::new("injected runner fault"))
}

fn failures(cases: &[Value], runners: &[(&str, Runner)]) -> Vec<ConformanceError> {
    run_suite(&load_manifest(&manifest(cases)).test_ok(), runners).failures
}

fn expected() -> Value {
    json!({"key": "value"})
}

#[test]
fn a_changed_fixture_byte_fails_the_pin() {
    let mut changed = MANIFEST.to_vec();
    changed.push(b' ');
    assert!(matches!(
        verify_pinned(&changed, MANIFEST_SHA256),
        Err(ConformanceError::DigestMismatch { .. })
    ));
}

#[test]
fn an_unknown_magic_version_or_field_fails_closed() {
    let mut document: Value = serde_json::from_slice(&manifest(&[])).test_ok();
    document["version"] = json!(2);
    assert_eq!(
        load_manifest(&serde_json::to_vec(&document).test_ok()),
        Err(ConformanceError::UnsupportedVersion("PPC1/2".to_owned()))
    );
    document["version"] = json!(1);
    document["magic"] = json!("PPC0");
    assert_eq!(
        load_manifest(&serde_json::to_vec(&document).test_ok()),
        Err(ConformanceError::UnsupportedVersion("PPC0/1".to_owned()))
    );
    document["magic"] = json!("PPC1");
    document["waiver"] = json!(true);
    assert_eq!(
        load_manifest(&serde_json::to_vec(&document).test_ok()),
        Err(ConformanceError::UnknownField {
            at: "manifest".to_owned(),
            field: "waiver".to_owned(),
        })
    );
    let mut extended = case("X", true, None, &expected());
    extended["skip"] = json!(true);
    assert_eq!(
        load_manifest(&manifest(&[extended])),
        Err(ConformanceError::UnknownField {
            at: "cases[0]".to_owned(),
            field: "skip".to_owned(),
        })
    );
    assert!(matches!(
        load_manifest(b"not json"),
        Err(ConformanceError::InvalidManifest(_))
    ));
}

#[test]
fn a_skipped_mandatory_case_or_an_unknown_runner_fails() {
    assert_eq!(
        failures(&[case("X", true, None, &expected())], &[]),
        vec![ConformanceError::SkippedMandatoryCase("X".to_owned())]
    );
    let optional = run_suite(
        &load_manifest(&manifest(&[case("X", false, None, &expected())])).test_ok(),
        &[],
    );
    assert!(optional.failures.is_empty());
    assert_eq!(optional.skipped_optional, vec!["X".to_owned()]);
    assert_eq!(
        failures(
            &[case("X", true, None, &expected())],
            &[("X", records_value), ("Y", records_value)]
        ),
        vec![ConformanceError::UnknownRunner("Y".to_owned())]
    );
    assert_eq!(
        failures(
            &[case("X", true, None, &expected())],
            &[("X", records_value), ("X", records_value)]
        ),
        vec![ConformanceError::DuplicateCase("X".to_owned())]
    );
    assert_eq!(
        load_manifest(&manifest(&[
            case("X", true, None, &expected()),
            case("X", true, None, &expected()),
        ])),
        Err(ConformanceError::DuplicateCase("X".to_owned()))
    );
}

#[test]
fn a_missing_unexpected_or_diverging_capture_fails() {
    let key = "memory/key".to_owned();
    assert_eq!(
        failures(
            &[case("X", true, None, &expected())],
            &[("X", records_nothing)]
        ),
        vec![ConformanceError::MissingCapture {
            case: "X".to_owned(),
            key: key.clone(),
        }]
    );
    assert_eq!(
        failures(
            &[case("X", true, None, &json!({}))],
            &[("X", records_value)]
        ),
        vec![ConformanceError::UnexpectedCapture {
            case: "X".to_owned(),
            key: key.clone(),
            value: "value".to_owned(),
        }]
    );
    assert_eq!(
        failures(
            &[case("X", true, None, &json!({"key": "other"}))],
            &[("X", records_value)]
        ),
        vec![ConformanceError::Divergence {
            case: "X".to_owned(),
            key: key.clone(),
            expected: "other".to_owned(),
            actual: "value".to_owned(),
        }]
    );
    assert_eq!(
        failures(
            &[case("X", true, None, &expected())],
            &[("X", records_twice)]
        ),
        vec![ConformanceError::Divergence {
            case: "X".to_owned(),
            key,
            expected: "value".to_owned(),
            actual: "value | other".to_owned(),
        }]
    );
    assert_eq!(
        failures(&[case("X", true, None, &expected())], &[("X", panics)]),
        vec![ConformanceError::RunnerPanicked {
            case: "X".to_owned(),
            message: "injected runner fault".to_owned(),
        }]
    );
}

#[test]
fn a_non_participant_artifact_presented_as_participant_bound_fails_closed() {
    let profile = format!("memory/{PROFILE_KEY}");
    assert_eq!(
        failures(
            &[case("X", true, Some("participant-bound"), &expected())],
            &[("X", records_non_participant_value)]
        ),
        vec![ConformanceError::ProfileTagMismatch {
            case: "X".to_owned(),
            key: profile.clone(),
            declared: "participant-bound".to_owned(),
            captured: "non-participant".to_owned(),
        }]
    );
    assert_eq!(
        failures(
            &[case("X", true, Some("non-participant"), &expected())],
            &[("X", records_value)]
        ),
        vec![ConformanceError::MissingCapture {
            case: "X".to_owned(),
            key: profile,
        }]
    );
    assert!(failures(
        &[case("X", true, Some("non-participant"), &expected())],
        &[("X", records_non_participant_value)]
    )
    .is_empty());
    assert!(matches!(
        load_manifest(&manifest(&[case("X", true, Some("observer"), &expected())])),
        Err(ConformanceError::InvalidManifest(_))
    ));
}

#[test]
fn an_inapplicable_case_is_recorded_and_never_executed() {
    let mut inapplicable = case("X", true, None, &json!({}));
    inapplicable["applicability"] = json!({"status": "profile-inapplicable", "reason": "Wave 9"});
    inapplicable["stores"] = json!([]);
    let manifest_bytes = manifest(&[inapplicable.clone()]);
    let parsed = load_manifest(&manifest_bytes).test_ok();
    assert_eq!(
        parsed.cases[0].applicability,
        Applicability::ProfileInapplicable {
            reason: "Wave 9".to_owned()
        }
    );
    let report = run_suite(&parsed, &[]);
    assert_eq!(report.not_applicable, vec!["X".to_owned()]);
    assert!(report.failures.is_empty());
    assert_eq!(
        run_suite(&parsed, &[("X", records_nothing)]).failures,
        vec![ConformanceError::InapplicableCaseExecuted("X".to_owned())]
    );
    inapplicable["stores"] = json!(["memory"]);
    assert!(matches!(
        load_manifest(&manifest(&[inapplicable])),
        Err(ConformanceError::InvalidManifest(_))
    ));
    let mut unnamed = case("X", true, None, &expected());
    unnamed["stores"] = json!(["cloud"]);
    assert!(matches!(
        load_manifest(&manifest(&[unnamed])),
        Err(ConformanceError::InvalidManifest(_))
    ));
}

#[test]
fn the_legacy_history_fixture_fails_closed_on_an_unknown_version_or_field() {
    let legacy = |version: u64, extra: bool| {
        let mut document = json!({
            "magic": "PLH1",
            "version": version,
            "description": "harness",
            "subjects": {},
            "events": [],
            "expected_report": [],
        });
        if extra {
            document["waiver"] = json!(true);
        }
        serde_json::to_vec(&document).test_ok()
    };
    assert!(eval_seam::parse_legacy_history(&legacy(1, false)).is_ok());
    assert_eq!(
        eval_seam::parse_legacy_history(&legacy(2, false)).err(),
        Some(ConformanceError::UnsupportedVersion("PLH1/2".to_owned()))
    );
    assert!(matches!(
        eval_seam::parse_legacy_history(&legacy(1, true)),
        Err(ConformanceError::UnknownField { .. })
    ));
    assert!(verify_pinned(b"{}", eval_seam::LEGACY_HISTORY_SHA256).is_err());
}

#[test]
fn the_v1_directory_holds_exactly_the_pinned_files() {
    let directory = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/conformance/pipeline/v1"
    );
    let mut files: Vec<(String, String)> = std::fs::read_dir(directory)
        .test_ok()
        .map(|entry| {
            let entry = entry.test_ok();
            (
                entry.file_name().to_string_lossy().into_owned(),
                harness::sha256_hex(&std::fs::read(entry.path()).test_ok()),
            )
        })
        .collect();
    files.sort();
    assert_eq!(
        files,
        vec![
            (
                "legacy-eval-history.json".to_owned(),
                eval_seam::LEGACY_HISTORY_SHA256.to_owned()
            ),
            ("manifest.json".to_owned(), MANIFEST_SHA256.to_owned()),
        ]
    );
}
