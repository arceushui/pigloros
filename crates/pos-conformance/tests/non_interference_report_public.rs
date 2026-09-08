use ed25519_dalek::SigningKey;
use pos_conformance::{
    non_interference_capture_profiles_v1, non_interference_normalization_digest_v1,
    ExecutionModeV1, NonInterferenceDivergenceCoordinateV1, NonInterferenceExecutionArtifactBodyV1,
    NonInterferenceExecutionArtifactV1, NonInterferenceModeResultRefV1,
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
                            .map(|mode| NonInterferenceModeResultRefV1 {
                                mode,
                                result_digest: digest(ordinal),
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

fn report_bundle() -> (NonInterferenceReportV1, Vec<Vec<u8>>) {
    let mut outcomes = outcomes();
    let artifacts = execution_artifacts(&mut outcomes);
    let report = test_ok(NonInterferenceReportV1::sign(
        outcomes,
        &SigningKey::from_bytes(&[7; 32]),
        &[b"control-secret".as_slice(), b"canary-secret".as_slice()],
    ));
    (report, artifacts)
}

fn trusted_signer() -> [u8; 32] {
    SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
}

fn trusted_executor() -> [u8; 32] {
    SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()
}

fn execution_artifacts(outcomes: &mut [NonInterferenceReportOutcomeV1]) -> Vec<Vec<u8>> {
    let mut artifacts = Vec::new();
    for outcome in outcomes {
        for reference in &mut outcome.modes {
            let artifact = test_ok(NonInterferenceExecutionArtifactV1::sign(
                NonInterferenceExecutionArtifactBodyV1 {
                    fixture_id: outcome.fixture_id.clone(),
                    variant: outcome.variant,
                    mode: reference.mode,
                    profile_digest: outcome.profile_digest,
                    normalization_digest: outcome.normalization_digest,
                    result_digest: reference.result_digest,
                    execution_provenance_digest: reference.execution_provenance_digest,
                },
                &SigningKey::from_bytes(&[8; 32]),
            ));
            reference.artifact_digest = test_ok(artifact.content_digest());
            artifacts.push(test_ok(artifact.to_canonical_cbor()));
        }
    }
    artifacts
}

#[test]
fn signed_report_binds_all_48_outcomes_and_192_genuine_executions() {
    let (report, artifacts) = report_bundle();
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
        test_ok(NonInterferenceReportV1::from_canonical_cbor(
            &bytes,
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts
        )),
        report
    );
    assert!(test_ok(pos_reference::verify_non_interference_report_v1(
        &bytes,
        &trusted_signer(),
        &[trusted_executor()],
        &artifacts
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
    let artifacts = execution_artifacts(&mut values);
    let report = test_ok(NonInterferenceReportV1::sign(
        values,
        &SigningKey::from_bytes(&[7; 32]),
        &[],
    ));
    assert!(!report.is_conformant());
    assert!(!test_ok(pos_reference::verify_non_interference_report_v1(
        &test_ok(report.to_canonical_cbor()),
        &trusted_signer(),
        &[trusted_executor()],
        &artifacts
    )));
}

#[test]
fn report_rejects_missing_reordered_duplicate_and_cross_mode_results() {
    let mut missing = outcomes();
    missing.pop();
    let mut reordered = outcomes();
    reordered.swap(0, 1);
    let mut duplicate_mode = outcomes();
    duplicate_mode[0].modes[1].mode = ExecutionModeV1::Local;
    let mut cross_mode_divergence = outcomes();
    cross_mode_divergence[0].modes[1].result_digest = digest(250);
    for invalid in [missing, reordered, duplicate_mode, cross_mode_divergence] {
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
    let mut impossible_surface = outcomes();
    impossible_surface[0].modes[0].equal = false;
    impossible_surface[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        surface_ordinal: u16::MAX,
        byte_offset: 0,
    });
    for invalid in [missing, unexpected, impossible_surface] {
        assert_eq!(
            NonInterferenceReportV1::sign(invalid, &SigningKey::from_bytes(&[7; 32]), &[]),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
    }
}

#[test]
fn report_rejects_tampered_digest_signature_unknown_fields_and_trailing_bytes() {
    let (report, artifacts) = report_bundle();
    let mut wrong_digest = report.clone();
    wrong_digest.report_digest[0] ^= 1;
    assert_eq!(
        wrong_digest.validate(&trusted_signer(), &[trusted_executor()], &artifacts),
        Err(NonInterferenceReportErrorV1::DigestInvalid)
    );
    let mut wrong_signature = report.clone();
    let mut signature = *wrong_signature.signature.as_bytes();
    signature[0] ^= 1;
    wrong_signature.signature = pos_core::Signature::from_bytes(signature);
    assert_eq!(
        wrong_signature.validate(&trusted_signer(), &[trusted_executor()], &artifacts),
        Err(NonInterferenceReportErrorV1::SignatureInvalid)
    );
    assert_eq!(
        report.validate(
            &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            &[trusted_executor()],
            &artifacts
        ),
        Err(NonInterferenceReportErrorV1::SignatureInvalid)
    );

    let bytes = test_ok(report.to_canonical_cbor());
    let mut json: serde_json::Value = test_ok(serde_json::to_value(&report));
    json["unknown"] = serde_json::json!(true);
    let unknown = test_ok(pos_crypto::canonical::encode(&json));
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(
            unknown.as_slice(),
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts
        ),
        Err(NonInterferenceReportErrorV1::NonCanonical)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(
            &trailing,
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts
        ),
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
        NonInterferenceReportV1::from_canonical_cbor(
            &oversized,
            &trusted_signer(),
            &[trusted_executor()],
            &[]
        ),
        Err(NonInterferenceReportErrorV1::TooLarge)
    );
}

fn assert_both_verifiers_reject_artifacts(
    report: &NonInterferenceReportV1,
    artifacts: &[Vec<u8>],
    trusted_executors: &[[u8; 32]],
    expected: NonInterferenceReportErrorV1,
) {
    let bytes = test_ok(report.to_canonical_cbor());
    assert_eq!(
        report.validate(&trusted_signer(), trusted_executors, artifacts),
        Err(expected)
    );
    assert!(pos_reference::verify_non_interference_report_v1(
        &bytes,
        &trusted_signer(),
        trusted_executors,
        artifacts
    )
    .is_err());
}

#[test]
fn report_rejects_artifacts_from_an_untrusted_executor() {
    let (report, artifacts) = report_bundle();
    assert_both_verifiers_reject_artifacts(
        &report,
        &artifacts,
        &[[201; 32]],
        NonInterferenceReportErrorV1::InvalidShape,
    );
}

#[test]
fn report_rejects_missing_and_duplicate_execution_artifacts() {
    let (report, artifacts) = report_bundle();
    let mut missing = artifacts.clone();
    missing.pop();
    assert_both_verifiers_reject_artifacts(
        &report,
        &missing,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::InvalidShape,
    );

    let mut duplicate = artifacts;
    duplicate[1] = duplicate[0].clone();
    assert_both_verifiers_reject_artifacts(
        &report,
        &duplicate,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::InvalidShape,
    );
}

#[test]
fn report_rejects_oversized_execution_artifacts() {
    let (report, mut oversized) = report_bundle();
    oversized[0] = vec![0; 4 * 1024 + 1];
    assert_both_verifiers_reject_artifacts(
        &report,
        &oversized,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::TooLarge,
    );
}

#[test]
fn report_rejects_an_execution_artifact_with_a_tampered_signature() {
    let (report, mut tampered) = report_bundle();
    let mut artifact = test_ok(NonInterferenceExecutionArtifactV1::from_canonical_cbor(
        &tampered[0],
    ));
    let mut signature = *artifact.signature.as_bytes();
    signature[0] ^= 1;
    artifact.signature = pos_core::Signature::from_bytes(signature);
    tampered[0] = test_ok(pos_crypto::canonical::encode(&artifact))
        .as_slice()
        .to_vec();
    assert_both_verifiers_reject_artifacts(
        &report,
        &tampered,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::SignatureInvalid,
    );
}

#[test]
fn report_rejects_an_artifact_bound_to_the_wrong_execution_coordinate() {
    let mut values = outcomes();
    let mut artifacts = execution_artifacts(&mut values);
    let original = test_ok(NonInterferenceExecutionArtifactV1::from_canonical_cbor(
        &artifacts[0],
    ));
    let mismatched = test_ok(NonInterferenceExecutionArtifactV1::sign(
        NonInterferenceExecutionArtifactBodyV1 {
            fixture_id: original.fixture_id,
            variant: original.variant,
            mode: ExecutionModeV1::AirGapped,
            profile_digest: original.profile_digest,
            normalization_digest: original.normalization_digest,
            result_digest: original.result_digest,
            execution_provenance_digest: original.execution_provenance_digest,
        },
        &SigningKey::from_bytes(&[8; 32]),
    ));
    values[0].modes[0].artifact_digest = test_ok(mismatched.content_digest());
    artifacts[0] = test_ok(mismatched.to_canonical_cbor());
    let report = test_ok(NonInterferenceReportV1::sign(
        values,
        &SigningKey::from_bytes(&[7; 32]),
        &[],
    ));
    assert_both_verifiers_reject_artifacts(
        &report,
        &artifacts,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::InvalidShape,
    );
}
