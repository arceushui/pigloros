use ed25519_dalek::SigningKey;
use pos_conformance::{
    non_interference_capture_profiles_v1, non_interference_normalization_digest_v1,
    ExecutionModeV1, NonInterferenceDivergenceCoordinateV1, NonInterferenceModeResultRefV1,
    NonInterferenceReportErrorV1, NonInterferenceReportOutcomeV1, NonInterferenceReportV1,
    NonInterferenceVariantV1, MAX_NON_INTERFERENCE_REPORT_BYTES_V1,
};
use std::fmt::Debug;

fn test_ok<T, E: Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected report error: {error:?}")))
    })
}

fn digest(value: u8) -> [u8; 32] {
    [value.max(1); 32]
}

fn outcomes() -> Vec<NonInterferenceReportOutcomeV1> {
    let variants = [
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::WarmCache,
        NonInterferenceVariantV1::ColdCache,
    ];
    let modes = [
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ];
    non_interference_capture_profiles_v1()
        .into_iter()
        .enumerate()
        .flat_map(|(profile_index, profile)| {
            variants
                .into_iter()
                .enumerate()
                .map(move |(variant_index, variant)| {
                    let ordinal =
                        u8::try_from(profile_index * 4 + variant_index + 1).unwrap_or(u8::MAX);
                    NonInterferenceReportOutcomeV1 {
                        fixture_id: profile.fixture_id.clone(),
                        variant,
                        fixture_digest: digest(ordinal),
                        profile_digest: profile.profile_digest,
                        normalization_digest: test_ok(
                            non_interference_normalization_digest_v1(&profile.fixture_id)
                                .ok_or("missing normalization"),
                        ),
                        modes: modes
                            .into_iter()
                            .enumerate()
                            .map(|(mode_index, mode)| NonInterferenceModeResultRefV1 {
                                mode,
                                genuine_execution: true,
                                result_digest: digest(
                                    ordinal.saturating_add(
                                        u8::try_from(mode_index).unwrap_or(u8::MAX),
                                    ),
                                ),
                                artifact_digest: digest(ordinal.saturating_add(50)),
                                execution_provenance_digest: digest(ordinal.saturating_add(100)),
                                equal: true,
                            })
                            .collect(),
                        first_divergence: None,
                    }
                })
        })
        .collect()
}

fn report() -> NonInterferenceReportV1 {
    test_ok(NonInterferenceReportV1::sign(
        outcomes(),
        &SigningKey::from_bytes(&[7; 32]),
        &[b"control-secret".as_slice(), b"canary-secret".as_slice()],
    ))
}

#[test]
fn signed_report_binds_all_48_outcomes_and_192_genuine_executions() {
    let report = report();
    assert_eq!(report.outcomes.len(), 48);
    assert_eq!(
        report
            .outcomes
            .iter()
            .map(|outcome| outcome.modes.len())
            .sum::<usize>(),
        192
    );
    assert!(report.is_conformant());
    let bytes = test_ok(report.to_canonical_cbor());
    assert!(bytes.len() <= MAX_NON_INTERFERENCE_REPORT_BYTES_V1);
    assert_eq!(
        test_ok(NonInterferenceReportV1::from_canonical_cbor(&bytes)),
        report
    );
    assert!(test_ok(pos_reference::verify_non_interference_report_v1(
        &bytes
    )));
}

#[test]
fn report_records_the_first_failed_mode_without_claiming_conformance() {
    let mut values = outcomes();
    values[0].modes[1].equal = false;
    values[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::AirGapped,
        surface_ordinal: 2,
        byte_offset: 4,
    });
    let report = test_ok(NonInterferenceReportV1::sign(
        values,
        &SigningKey::from_bytes(&[7; 32]),
        &[],
    ));
    assert!(!report.is_conformant());
    assert!(!test_ok(pos_reference::verify_non_interference_report_v1(
        &test_ok(report.to_canonical_cbor())
    )));
}

#[test]
fn report_rejects_missing_reordered_duplicate_and_synthetic_results() {
    let mut missing = outcomes();
    missing.pop();
    let mut reordered = outcomes();
    reordered.swap(0, 1);
    let mut duplicate_mode = outcomes();
    duplicate_mode[0].modes[1].mode = ExecutionModeV1::Local;
    let mut synthetic = outcomes();
    synthetic[0].modes[0].genuine_execution = false;
    for invalid in [missing, reordered, duplicate_mode, synthetic] {
        assert_eq!(
            NonInterferenceReportV1::sign(invalid, &SigningKey::from_bytes(&[7; 32]), &[]),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
    }
}

#[test]
fn report_rejects_missing_or_mismatched_divergence_coordinates() {
    let mut missing = outcomes();
    missing[0].modes[0].equal = false;
    let mut unexpected = outcomes();
    unexpected[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        surface_ordinal: 0,
        byte_offset: 0,
    });
    for invalid in [missing, unexpected] {
        assert_eq!(
            NonInterferenceReportV1::sign(invalid, &SigningKey::from_bytes(&[7; 32]), &[]),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
    }
}

#[test]
fn report_rejects_tampered_digest_signature_unknown_fields_and_trailing_bytes() {
    let report = report();
    let mut wrong_digest = report.clone();
    wrong_digest.report_digest[0] ^= 1;
    assert_eq!(
        wrong_digest.validate(),
        Err(NonInterferenceReportErrorV1::DigestInvalid)
    );
    let mut wrong_signature = report.clone();
    let mut signature = *wrong_signature.signature.as_bytes();
    signature[0] ^= 1;
    wrong_signature.signature = pos_core::Signature::from_bytes(signature);
    assert_eq!(
        wrong_signature.validate(),
        Err(NonInterferenceReportErrorV1::SignatureInvalid)
    );

    let bytes = test_ok(report.to_canonical_cbor());
    let mut json: serde_json::Value = test_ok(serde_json::to_value(&report));
    json["unknown"] = serde_json::json!(true);
    let unknown = test_ok(pos_crypto::canonical::encode(&json));
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(unknown.as_slice()),
        Err(NonInterferenceReportErrorV1::NonCanonical)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(&trailing),
        Err(NonInterferenceReportErrorV1::NonCanonical)
    );
}

#[test]
fn report_refuses_secret_material_and_oversized_input() {
    let secret = b"NI-TOOL-001";
    assert_eq!(
        NonInterferenceReportV1::sign(outcomes(), &SigningKey::from_bytes(&[7; 32]), &[secret]),
        Err(NonInterferenceReportErrorV1::SecretDetected)
    );

    let oversized = vec![0; MAX_NON_INTERFERENCE_REPORT_BYTES_V1 + 1];
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(&oversized),
        Err(NonInterferenceReportErrorV1::TooLarge)
    );
}
