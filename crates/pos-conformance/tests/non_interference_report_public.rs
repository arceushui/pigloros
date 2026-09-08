use ed25519_dalek::SigningKey;
use pos_conformance::{
    execute_wave8_non_interference_matrix, non_interference_capture_profiles_v1,
    non_interference_normalization_digest_v1, normalize_non_interference_capture_v1,
    ExecutionModeV1, NonInterferenceDivergenceCoordinateV1, NonInterferenceExecutionArtifactBodyV1,
    NonInterferenceExecutionArtifactV1, NonInterferenceExecutionErrorV1,
    NonInterferenceModeResultRefV1, NonInterferenceNormalizationV1, NonInterferenceRawCaptureV1,
    NonInterferenceRawOperationalV1, NonInterferenceReportErrorV1, NonInterferenceReportOutcomeV1,
    NonInterferenceReportV1, NonInterferenceVariantV1,
    MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1, MAX_NON_INTERFERENCE_REPORT_BYTES_V1,
};
use serde::Serialize;
use std::fmt::Debug;

use pos_reference::IndependentNonInterferenceReportErrorV1 as IndependentError;

fn test_ok<T, E: Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected report error: {error:?}")))
    })
}

fn digest(value: u8) -> [u8; 32] {
    [value.max(1); 32]
}

fn outcomes() -> Vec<NonInterferenceReportOutcomeV1> {
    let cases = test_ok(execute_wave8_non_interference_matrix([11; 32], |run| {
        let Some(profile) = non_interference_capture_profiles_v1()
            .into_iter()
            .find(|profile| profile.fixture_id == run.subject.fixture_id)
        else {
            return Err(NonInterferenceExecutionErrorV1::CaptureUnavailable);
        };
        normalize_non_interference_capture_v1(
            run.subject.fixture_id,
            NonInterferenceRawCaptureV1 {
                surface_names: profile.surface_names.clone(),
                authoritative: profile
                    .surface_names
                    .iter()
                    .map(|_| run.subject.permitted_input.to_vec())
                    .collect(),
                public: profile
                    .surface_names
                    .iter()
                    .map(|_| b"public".to_vec())
                    .collect(),
                operational: profile
                    .surface_normalizations
                    .iter()
                    .copied()
                    .map(raw_operational)
                    .collect(),
                unexpected_network_accesses: 0,
                provenance_digest: [12; 32],
            },
        )
    }));
    cases
        .chunks_exact(4)
        .map(|modes| {
            let profile = non_interference_capture_profiles_v1()
                .into_iter()
                .find(|profile| profile.fixture_id == modes[0].fixture_id)
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing profile")));
            assert!(modes.iter().all(|case| {
                case.fixture_id == modes[0].fixture_id
                    && case.variant == modes[0].variant
                    && case.fixture_digest == modes[0].fixture_digest
            }));
            NonInterferenceReportOutcomeV1 {
                fixture_id: modes[0].fixture_id.clone(),
                variant: modes[0].variant,
                fixture_digest: modes[0].fixture_digest,
                profile_digest: profile.profile_digest,
                normalization_digest: test_ok(
                    non_interference_normalization_digest_v1(&profile.fixture_id)
                        .ok_or("missing normalization"),
                ),
                modes: modes
                    .iter()
                    .map(|case| NonInterferenceModeResultRefV1 {
                        mode: case.mode,
                        result_digest: case.authoritative_digest,
                        artifact_digest: [1; 32],
                        execution_provenance_digest: case.provenance_digest,
                        equal: case.authoritative_equal
                            && case.public_equal
                            && case.operational_equal
                            && case.first_divergence.is_none()
                            && case.first_cross_mode_divergence.is_none(),
                    })
                    .collect(),
                first_divergence: None,
            }
        })
        .collect()
}

fn raw_operational(
    normalization: NonInterferenceNormalizationV1,
) -> NonInterferenceRawOperationalV1 {
    match normalization {
        NonInterferenceNormalizationV1::CategoryCountDigest => {
            NonInterferenceRawOperationalV1::CategoryCountDigest {
                category: 1,
                count: 1,
                digest: [13; 32],
                excluded_sensitive: Vec::new(),
            }
        }
        NonInterferenceNormalizationV1::CountClass => NonInterferenceRawOperationalV1::CountClass {
            class: 1,
            count: 1,
            excluded_sensitive: Vec::new(),
        },
        NonInterferenceNormalizationV1::CategoryCount => {
            NonInterferenceRawOperationalV1::CategoryCount {
                category: 1,
                count: 1,
                excluded_sensitive: Vec::new(),
            }
        }
        NonInterferenceNormalizationV1::CategoryCountPaddedLength => {
            NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
                category: 1,
                count: 1,
                padded_length: 64,
                excluded_sensitive: Vec::new(),
            }
        }
        NonInterferenceNormalizationV1::OmitOperational => {
            NonInterferenceRawOperationalV1::OmitOperational {
                excluded_sensitive: Vec::new(),
            }
        }
        NonInterferenceNormalizationV1::ByteExact => {
            NonInterferenceRawOperationalV1::ByteExact(b"operational".to_vec())
        }
    }
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

fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    test_ok(pos_crypto::canonical::encode(value))
        .as_slice()
        .to_vec()
}

fn reverse_top_level_map_order(bytes: &[u8]) -> Vec<u8> {
    let mut value: ciborium::Value = test_ok(ciborium::from_reader(bytes));
    let Some(fields) = value.as_map_mut() else {
        std::panic::resume_unwind(Box::new("signed evidence must encode as a map"));
    };
    fields.reverse();
    let mut noncanonical = Vec::new();
    test_ok(ciborium::into_writer(&value, &mut noncanonical));
    noncanonical
}

#[derive(Serialize)]
struct UnsignedReportForTest<'a> {
    #[serde(rename = "m")]
    magic: &'a str,
    #[serde(rename = "v")]
    version: u16,
    #[serde(rename = "f")]
    fixture_set_digest: [u8; 32],
    #[serde(rename = "p")]
    profile_set_digest: [u8; 32],
    #[serde(rename = "n")]
    normalization_set_digest: [u8; 32],
    #[serde(rename = "a")]
    artifact_set_digest: [u8; 32],
    #[serde(rename = "e")]
    execution_provenance_digest: [u8; 32],
    #[serde(rename = "o")]
    outcomes: &'a [NonInterferenceReportOutcomeV1],
    #[serde(rename = "k")]
    signer_public_key: [u8; 32],
}

fn refresh_report_digest(report: &mut NonInterferenceReportV1) {
    let unsigned = canonical_bytes(&UnsignedReportForTest {
        magic: &report.magic,
        version: report.version,
        fixture_set_digest: report.fixture_set_digest,
        profile_set_digest: report.profile_set_digest,
        normalization_set_digest: report.normalization_set_digest,
        artifact_set_digest: report.artifact_set_digest,
        execution_provenance_digest: report.execution_provenance_digest,
        outcomes: &report.outcomes,
        signer_public_key: report.signer_public_key,
    });
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.NonInterference.Report.v1");
    hasher.update(&[0]);
    hasher.update(&unsigned);
    report.report_digest = *hasher.finalize().as_bytes();
}

fn mutated_report(
    base: &NonInterferenceReportV1,
    mutation: impl FnOnce(&mut NonInterferenceReportV1),
) -> NonInterferenceReportV1 {
    let mut value = base.clone();
    mutation(&mut value);
    value
}

fn mutated_artifact(
    base: &NonInterferenceExecutionArtifactV1,
    mutation: impl FnOnce(&mut NonInterferenceExecutionArtifactV1),
) -> NonInterferenceExecutionArtifactV1 {
    let mut value = base.clone();
    mutation(&mut value);
    value
}

fn divergent_report(base: &NonInterferenceReportV1) -> NonInterferenceReportV1 {
    mutated_report(base, |value| {
        value.outcomes[0].modes[0].equal = false;
        value.outcomes[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
            fixture_id: "NI-TOOL-001".to_owned(),
            variant: NonInterferenceVariantV1::Success,
            mode: ExecutionModeV1::Local,
            surface_ordinal: 0,
            byte_offset: 0,
        });
    })
}

fn artifact_body(
    outcome: &NonInterferenceReportOutcomeV1,
    reference: &NonInterferenceModeResultRefV1,
) -> NonInterferenceExecutionArtifactBodyV1 {
    NonInterferenceExecutionArtifactBodyV1 {
        fixture_id: outcome.fixture_id.clone(),
        variant: outcome.variant,
        mode: reference.mode,
        fixture_digest: outcome.fixture_digest,
        profile_digest: outcome.profile_digest,
        normalization_digest: outcome.normalization_digest,
        result_digest: reference.result_digest,
        execution_provenance_digest: reference.execution_provenance_digest,
        equal: reference.equal,
        divergence: (!reference.equal).then(|| {
            outcome
                .first_divergence
                .clone()
                .filter(|coordinate| coordinate.mode == reference.mode)
                .unwrap_or_else(|| NonInterferenceDivergenceCoordinateV1 {
                    fixture_id: outcome.fixture_id.clone(),
                    variant: outcome.variant,
                    mode: reference.mode,
                    surface_ordinal: 0,
                    byte_offset: 0,
                })
        }),
    }
}

fn execution_artifacts(outcomes: &mut [NonInterferenceReportOutcomeV1]) -> Vec<Vec<u8>> {
    let mut artifacts = Vec::new();
    for outcome in outcomes {
        for mode_index in 0..outcome.modes.len() {
            let body = artifact_body(outcome, &outcome.modes[mode_index]);
            let artifact = test_ok(NonInterferenceExecutionArtifactV1::sign(
                body,
                &SigningKey::from_bytes(&[8; 32]),
            ));
            outcome.modes[mode_index].artifact_digest = test_ok(artifact.content_digest());
            artifacts.push(test_ok(artifact.to_canonical_cbor()));
        }
    }
    artifacts
}

#[test]
fn signed_report_binds_all_48_outcomes_and_192_execution_artifact_references() {
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
        byte_offset: 2 * 1024 * 1024,
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
    let mut impossible_offset = outcomes();
    impossible_offset[0].modes[0].equal = false;
    impossible_offset[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        surface_ordinal: 0,
        byte_offset: u64::MAX,
    });
    for invalid in [missing, unexpected, impossible_surface, impossible_offset] {
        assert_eq!(
            NonInterferenceReportV1::sign(invalid, &SigningKey::from_bytes(&[7; 32]), &[]),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
    }
}

#[test]
fn independent_verifier_rejects_every_report_shape_boundary() {
    let (report, artifacts) = report_bundle();
    let mut invalid = vec![
        mutated_report(&report, |value| value.magic = "NIR2".to_owned()),
        mutated_report(&report, |value| value.version = 2),
        mutated_report(&report, |value| {
            value.outcomes.pop();
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].fixture_id = "NI-CACHE-002".to_owned();
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].variant = NonInterferenceVariantV1::Denial;
        }),
        mutated_report(&report, |value| value.outcomes[0].fixture_digest = [0; 32]),
        mutated_report(&report, |value| {
            value.outcomes[0].profile_digest = digest(201);
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].normalization_digest = digest(202);
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes.pop();
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes[1].mode = ExecutionModeV1::Local;
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes[0].result_digest = [0; 32];
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes[0].artifact_digest = [0; 32];
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes[0].execution_provenance_digest = [0; 32];
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes[1].result_digest = digest(203);
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].modes[0].equal = false;
        }),
        mutated_report(&report, |value| {
            value.outcomes[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
                fixture_id: "NI-TOOL-001".to_owned(),
                variant: NonInterferenceVariantV1::Success,
                mode: ExecutionModeV1::Local,
                surface_ordinal: 0,
                byte_offset: 0,
            });
        }),
    ];
    let coordinate_mutations: [fn(&mut NonInterferenceDivergenceCoordinateV1); 5] = [
        |coordinate: &mut NonInterferenceDivergenceCoordinateV1| {
            coordinate.fixture_id = "NI-CACHE-002".to_owned();
        },
        |coordinate: &mut NonInterferenceDivergenceCoordinateV1| {
            coordinate.variant = NonInterferenceVariantV1::Denial;
        },
        |coordinate: &mut NonInterferenceDivergenceCoordinateV1| {
            coordinate.mode = ExecutionModeV1::Fork;
        },
        |coordinate: &mut NonInterferenceDivergenceCoordinateV1| {
            coordinate.surface_ordinal = u16::MAX;
        },
        |coordinate: &mut NonInterferenceDivergenceCoordinateV1| {
            coordinate.byte_offset = u64::MAX;
        },
    ];
    for mutation in coordinate_mutations {
        let mut value = divergent_report(&report);
        if let Some(coordinate) = &mut value.outcomes[0].first_divergence {
            mutation(coordinate);
        }
        invalid.push(value);
    }

    for value in invalid {
        assert_eq!(
            value.to_canonical_cbor(),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
        assert_eq!(
            value.validate(&trusted_signer(), &[trusted_executor()], &artifacts),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
        assert_eq!(
            pos_reference::verify_non_interference_report_v1(
                &canonical_bytes(&value),
                &trusted_signer(),
                &[trusted_executor()],
                &artifacts,
            ),
            Err(IndependentError::InvalidShape)
        );
    }
}

#[test]
fn independent_verifier_rejects_each_invalid_report_digest_layer() {
    let (report, artifacts) = report_bundle();
    for invalid in [
        mutated_report(&report, |value| value.fixture_set_digest = digest(204)),
        mutated_report(&report, |value| value.profile_set_digest = digest(205)),
        mutated_report(&report, |value| {
            value.normalization_set_digest = digest(206);
        }),
        mutated_report(&report, |value| value.artifact_set_digest = digest(207)),
        mutated_report(&report, |value| {
            value.execution_provenance_digest = digest(208);
        }),
        mutated_report(&report, |value| value.report_digest = [0; 32]),
    ] {
        assert_eq!(
            invalid.validate(&trusted_signer(), &[trusted_executor()], &artifacts),
            Err(NonInterferenceReportErrorV1::DigestInvalid)
        );
        assert_eq!(
            pos_reference::verify_non_interference_report_v1(
                &canonical_bytes(&invalid),
                &trusted_signer(),
                &[trusted_executor()],
                &artifacts,
            ),
            Err(IndependentError::DigestInvalid)
        );
    }
}

#[test]
fn report_rejects_tampered_digest_and_signature() {
    let (report, artifacts) = report_bundle();
    let mut wrong_digest = report.clone();
    wrong_digest.report_digest[0] ^= 1;
    assert_eq!(
        wrong_digest.validate(&trusted_signer(), &[trusted_executor()], &artifacts),
        Err(NonInterferenceReportErrorV1::DigestInvalid)
    );
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &canonical_bytes(&wrong_digest),
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::DigestInvalid)
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
        pos_reference::verify_non_interference_report_v1(
            &canonical_bytes(&wrong_signature),
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::SignatureInvalid)
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
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &bytes,
            &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::SignatureInvalid)
    );
}

#[test]
fn both_report_verifiers_reject_noncanonical_report_encodings() {
    let (report, artifacts) = report_bundle();
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
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            unknown.as_slice(),
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::NonCanonical)
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
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &trailing,
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::NonCanonical)
    );

    let noncanonical = reverse_top_level_map_order(&test_ok(report.to_canonical_cbor()));
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(
            &noncanonical,
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(NonInterferenceReportErrorV1::NonCanonical)
    );
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &noncanonical,
            &trusted_signer(),
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::NonCanonical)
    );
}

#[test]
fn report_rejects_an_invalid_signer_encoding_before_signature_verification() {
    let (mut report, artifacts) = report_bundle();
    report.signer_public_key = [u8::MAX; 32];
    refresh_report_digest(&mut report);
    assert_eq!(
        report.validate(&[u8::MAX; 32], &[trusted_executor()], &artifacts),
        Err(NonInterferenceReportErrorV1::SignatureInvalid)
    );
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &canonical_bytes(&report),
            &[u8::MAX; 32],
            &[trusted_executor()],
            &artifacts,
        ),
        Err(IndependentError::SignatureInvalid)
    );

    let (valid_report, valid_artifacts) = report_bundle();
    let mut short_signature = test_ok(serde_json::to_value(&valid_report));
    short_signature["s"] = serde_json::json!([1]);
    let short_signature = canonical_bytes(&short_signature);
    assert_eq!(
        NonInterferenceReportV1::from_canonical_cbor(
            &short_signature,
            &trusted_signer(),
            &[trusted_executor()],
            &valid_artifacts,
        ),
        Err(NonInterferenceReportErrorV1::NonCanonical)
    );
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &short_signature,
            &trusted_signer(),
            &[trusted_executor()],
            &valid_artifacts,
        ),
        Err(IndependentError::SignatureInvalid)
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
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &oversized,
            &trusted_signer(),
            &[trusted_executor()],
            &[],
        ),
        Err(IndependentError::TooLarge)
    );
}

#[test]
fn shared_size_error_does_not_claim_the_report_limit_for_artifacts() {
    assert_eq!(
        NonInterferenceReportErrorV1::TooLarge.to_string(),
        "non-interference evidence exceeds its declared size bound"
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
fn report_rejects_an_unknown_artifact_content_address() {
    let mut values = outcomes();
    let artifacts = execution_artifacts(&mut values);
    values[0].modes[0].artifact_digest = digest(210);
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
fn artifact_signing_rejects_every_invalid_body_boundary() {
    let values = outcomes();
    let base = artifact_body(&values[0], &values[0].modes[0]);
    let mut invalid = vec![
        {
            let mut value = base.clone();
            value.fixture_id = "unknown".to_owned();
            value
        },
        {
            let mut value = base.clone();
            value.profile_digest = digest(211);
            value
        },
        {
            let mut value = base.clone();
            value.normalization_digest = digest(212);
            value
        },
        {
            let mut value = base.clone();
            value.fixture_digest = [0; 32];
            value
        },
        {
            let mut value = base.clone();
            value.result_digest = [0; 32];
            value
        },
        {
            let mut value = base.clone();
            value.execution_provenance_digest = [0; 32];
            value
        },
        {
            let mut value = base.clone();
            value.divergence = Some(NonInterferenceDivergenceCoordinateV1 {
                fixture_id: value.fixture_id.clone(),
                variant: value.variant,
                mode: value.mode,
                surface_ordinal: 0,
                byte_offset: 0,
            });
            value
        },
        {
            let mut value = base.clone();
            value.equal = false;
            value
        },
    ];
    let mut divergent = base;
    divergent.equal = false;
    divergent.divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: divergent.fixture_id.clone(),
        variant: divergent.variant,
        mode: divergent.mode,
        surface_ordinal: 0,
        byte_offset: 0,
    });
    let coordinate_mutations: [fn(&mut NonInterferenceDivergenceCoordinateV1); 5] = [
        |coordinate| coordinate.fixture_id = "NI-CACHE-002".to_owned(),
        |coordinate| coordinate.variant = NonInterferenceVariantV1::Denial,
        |coordinate| coordinate.mode = ExecutionModeV1::Fork,
        |coordinate| coordinate.surface_ordinal = u16::MAX,
        |coordinate| coordinate.byte_offset = u64::MAX,
    ];
    for mutation in coordinate_mutations {
        let mut value = divergent.clone();
        if let Some(coordinate) = &mut value.divergence {
            mutation(coordinate);
        }
        invalid.push(value);
    }

    for body in invalid {
        assert_eq!(
            NonInterferenceExecutionArtifactV1::sign(body, &SigningKey::from_bytes(&[8; 32])),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
    }
}

#[test]
fn both_verifiers_reject_each_invalid_artifact_shape() {
    let (report, artifacts) = report_bundle();
    let base = test_ok(NonInterferenceExecutionArtifactV1::from_canonical_cbor(
        &artifacts[0],
    ));
    let mut invalid = vec![
        mutated_artifact(&base, |value| value.magic = "NIA2".to_owned()),
        mutated_artifact(&base, |value| value.version = 2),
        mutated_artifact(&base, |value| value.fixture_id = "unknown".to_owned()),
        mutated_artifact(&base, |value| value.profile_digest = digest(213)),
        mutated_artifact(&base, |value| value.normalization_digest = digest(214)),
        mutated_artifact(&base, |value| value.fixture_digest = [0; 32]),
        mutated_artifact(&base, |value| value.result_digest = [0; 32]),
        mutated_artifact(&base, |value| value.execution_provenance_digest = [0; 32]),
        mutated_artifact(&base, |value| value.executor_public_key = [0; 32]),
        mutated_artifact(&base, |value| {
            value.divergence = Some(NonInterferenceDivergenceCoordinateV1 {
                fixture_id: value.fixture_id.clone(),
                variant: value.variant,
                mode: value.mode,
                surface_ordinal: 0,
                byte_offset: 0,
            });
        }),
        mutated_artifact(&base, |value| value.equal = false),
    ];
    let mut divergent = base;
    divergent.equal = false;
    divergent.divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: divergent.fixture_id.clone(),
        variant: divergent.variant,
        mode: divergent.mode,
        surface_ordinal: 0,
        byte_offset: 0,
    });
    let coordinate_mutations: [fn(&mut NonInterferenceDivergenceCoordinateV1); 5] = [
        |coordinate| coordinate.fixture_id = "NI-CACHE-002".to_owned(),
        |coordinate| coordinate.variant = NonInterferenceVariantV1::Denial,
        |coordinate| coordinate.mode = ExecutionModeV1::Fork,
        |coordinate| coordinate.surface_ordinal = u16::MAX,
        |coordinate| coordinate.byte_offset = u64::MAX,
    ];
    for mutation in coordinate_mutations {
        let mut value = divergent.clone();
        if let Some(coordinate) = &mut value.divergence {
            mutation(coordinate);
        }
        invalid.push(value);
    }
    for value in invalid {
        assert_eq!(
            value.to_canonical_cbor(),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
        let replacement = canonical_bytes(&value);
        assert_eq!(
            NonInterferenceExecutionArtifactV1::from_canonical_cbor(&replacement),
            Err(NonInterferenceReportErrorV1::InvalidShape)
        );
        let mut replaced = artifacts.clone();
        replaced[0] = replacement;
        assert_eq!(
            pos_reference::verify_non_interference_report_v1(
                &test_ok(report.to_canonical_cbor()),
                &trusted_signer(),
                &[trusted_executor()],
                &replaced,
            ),
            Err(IndependentError::InvalidShape)
        );
    }
}

#[test]
fn both_verifiers_reject_noncanonical_artifact_encodings() {
    let (report, artifacts) = report_bundle();
    let base = test_ok(NonInterferenceExecutionArtifactV1::from_canonical_cbor(
        &artifacts[0],
    ));
    let mut json = test_ok(serde_json::to_value(&base));
    json["unknown"] = serde_json::json!(true);
    let unknown = canonical_bytes(&json);
    let mut trailing = artifacts[0].clone();
    trailing.push(0);
    let noncanonical = reverse_top_level_map_order(&artifacts[0]);
    for replacement in [unknown, trailing, noncanonical] {
        assert_eq!(
            NonInterferenceExecutionArtifactV1::from_canonical_cbor(&replacement),
            Err(NonInterferenceReportErrorV1::NonCanonical)
        );
        let mut replaced = artifacts.clone();
        replaced[0] = replacement;
        assert_eq!(
            pos_reference::verify_non_interference_report_v1(
                &test_ok(report.to_canonical_cbor()),
                &trusted_signer(),
                &[trusted_executor()],
                &replaced,
            ),
            Err(IndependentError::NonCanonical)
        );
    }

    let oversized = vec![0; MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1 + 1];
    assert_eq!(
        NonInterferenceExecutionArtifactV1::from_canonical_cbor(&oversized),
        Err(NonInterferenceReportErrorV1::TooLarge)
    );
    let mut replaced = artifacts;
    replaced[0] = oversized;
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &test_ok(report.to_canonical_cbor()),
            &trusted_signer(),
            &[trusted_executor()],
            &replaced,
        ),
        Err(IndependentError::TooLarge)
    );
}

#[test]
fn artifact_signature_boundaries_fail_closed() {
    let (report, artifacts) = report_bundle();
    let base = test_ok(NonInterferenceExecutionArtifactV1::from_canonical_cbor(
        &artifacts[0],
    ));
    let invalid_key = mutated_artifact(&base, |value| value.executor_public_key = [u8::MAX; 32]);
    let invalid_key_bytes = canonical_bytes(&invalid_key);
    assert_eq!(
        NonInterferenceExecutionArtifactV1::from_canonical_cbor(&invalid_key_bytes),
        Err(NonInterferenceReportErrorV1::SignatureInvalid)
    );
    let mut replaced = artifacts.clone();
    replaced[0] = invalid_key_bytes;
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &test_ok(report.to_canonical_cbor()),
            &trusted_signer(),
            &[[u8::MAX; 32]],
            &replaced,
        ),
        Err(IndependentError::SignatureInvalid)
    );

    let mut short_signature = test_ok(serde_json::to_value(&base));
    short_signature["s"] = serde_json::json!([1]);
    let short_signature = canonical_bytes(&short_signature);
    assert_eq!(
        NonInterferenceExecutionArtifactV1::from_canonical_cbor(&short_signature),
        Err(NonInterferenceReportErrorV1::NonCanonical)
    );
    let mut replaced = artifacts;
    replaced[0] = short_signature;
    assert_eq!(
        pos_reference::verify_non_interference_report_v1(
            &test_ok(report.to_canonical_cbor()),
            &trusted_signer(),
            &[trusted_executor()],
            &replaced,
        ),
        Err(IndependentError::SignatureInvalid)
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
    for (variant, mode) in [
        (NonInterferenceVariantV1::Denial, ExecutionModeV1::Local),
        (
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::AirGapped,
        ),
    ] {
        let mut values = outcomes();
        let mut artifacts = execution_artifacts(&mut values);
        let original = test_ok(NonInterferenceExecutionArtifactV1::from_canonical_cbor(
            &artifacts[0],
        ));
        let mismatched = test_ok(NonInterferenceExecutionArtifactV1::sign(
            NonInterferenceExecutionArtifactBodyV1 {
                fixture_id: original.fixture_id,
                variant,
                mode,
                fixture_digest: original.fixture_digest,
                profile_digest: original.profile_digest,
                normalization_digest: original.normalization_digest,
                result_digest: original.result_digest,
                execution_provenance_digest: original.execution_provenance_digest,
                equal: original.equal,
                divergence: original.divergence,
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
}

#[test]
fn report_cannot_rebind_executor_artifacts_to_a_different_fixture_digest() {
    let (original, artifacts) = report_bundle();
    let mut values = original.outcomes;
    values[0].fixture_digest[0] ^= 1;
    let rebound = test_ok(NonInterferenceReportV1::sign(
        values,
        &SigningKey::from_bytes(&[7; 32]),
        &[],
    ));
    assert_both_verifiers_reject_artifacts(
        &rebound,
        &artifacts,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::InvalidShape,
    );
}

#[test]
fn report_cannot_reclassify_an_executor_equal_result_as_divergent() {
    let (original, artifacts) = report_bundle();
    let mut values = original.outcomes;
    values[0].modes[0].equal = false;
    values[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        surface_ordinal: 0,
        byte_offset: 0,
    });
    let reclassified = test_ok(NonInterferenceReportV1::sign(
        values,
        &SigningKey::from_bytes(&[7; 32]),
        &[],
    ));
    assert_both_verifiers_reject_artifacts(
        &reclassified,
        &artifacts,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::InvalidShape,
    );
}

#[test]
fn report_cannot_move_an_executor_signed_divergence_coordinate() {
    let mut values = outcomes();
    values[0].modes[0].equal = false;
    values[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        surface_ordinal: 0,
        byte_offset: 0,
    });
    let artifacts = execution_artifacts(&mut values);
    values[0].first_divergence = Some(NonInterferenceDivergenceCoordinateV1 {
        fixture_id: "NI-TOOL-001".to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        surface_ordinal: 1,
        byte_offset: 0,
    });
    let moved = test_ok(NonInterferenceReportV1::sign(
        values,
        &SigningKey::from_bytes(&[7; 32]),
        &[],
    ));
    assert_both_verifiers_reject_artifacts(
        &moved,
        &artifacts,
        &[trusted_executor()],
        NonInterferenceReportErrorV1::InvalidShape,
    );
}
