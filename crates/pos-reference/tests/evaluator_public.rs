pub mod support;

use std::error::Error;

use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, EvaluatorError, EvaluatorIdentity, ResourceUsage,
    SubjectAdapter, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{
    CaseStatus, ConformanceReport, EvaluationRequest, IndependenceEvidence, SubjectAdapterKind,
};
use pos_reference::profile::{
    DeterministicBudget, EvaluatorHardCaps, NamespacedFailure, ProfileError,
};
use support::{BundleMutation, ProfileMutation, ReleaseMutation, TrustMutation};

type TestResult = Result<(), Box<dyn Error>>;

struct PublicAdapter {
    subject_digest: [u8; 32],
    output: Vec<u8>,
}

struct KindAdapter {
    kind: SubjectAdapterKind,
    subject_digest: [u8; 32],
    output: Vec<u8>,
}

struct RecordingAdapter {
    subject_digest: [u8; 32],
    output: Vec<u8>,
    attempts: Vec<CaseAttempt>,
}

struct MixedOracleAdapter {
    subject_digest: [u8; 32],
    output: Vec<u8>,
}

struct MismatchedOracleAdapter {
    subject_digest: [u8; 32],
    output: Vec<u8>,
}

enum AdverseBehavior {
    WrongOutput,
    AdapterUnavailable,
    ExcessiveUsage,
    SubjectUnavailable,
    WrongResultKind,
}

struct AdverseAdapter {
    subject_digest: [u8; 32],
    behavior: AdverseBehavior,
}

impl SubjectAdapter for PublicAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, _: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        Ok(SubjectObservation {
            result: SubjectResult::Output(self.output.clone()),
            usage: ResourceUsage::default(),
        })
    }
}

impl SubjectAdapter for KindAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        self.kind
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, _: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        Ok(SubjectObservation {
            result: SubjectResult::Output(self.output.clone()),
            usage: ResourceUsage::default(),
        })
    }
}

impl SubjectAdapter for RecordingAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        self.attempts.push(attempt.clone());
        Ok(SubjectObservation {
            result: SubjectResult::Output(self.output.clone()),
            usage: ResourceUsage::default(),
        })
    }
}

impl SubjectAdapter for MixedOracleAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        let result = match attempt.family {
            1 => SubjectResult::Failure(NamespacedFailure {
                owner_id: "test-provider".to_owned(),
                contract_version: "1.0.0".to_owned(),
                code_id: "denied".to_owned(),
            }),
            2 => SubjectResult::Divergence {
                classification: 2,
                first_coordinate: vec![1, 2],
            },
            _ => SubjectResult::Output(self.output.clone()),
        };
        Ok(SubjectObservation {
            result,
            usage: ResourceUsage::default(),
        })
    }
}

impl SubjectAdapter for MismatchedOracleAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        let result = match attempt.family {
            1 => SubjectResult::Failure(NamespacedFailure {
                owner_id: "test-provider".to_owned(),
                contract_version: "1.0.0".to_owned(),
                code_id: "different".to_owned(),
            }),
            2 => SubjectResult::Divergence {
                classification: 3,
                first_coordinate: vec![9],
            },
            _ => SubjectResult::Output(self.output.clone()),
        };
        Ok(SubjectObservation {
            result,
            usage: ResourceUsage::default(),
        })
    }
}

impl SubjectAdapter for AdverseAdapter {
    fn kind(&self) -> SubjectAdapterKind {
        SubjectAdapterKind::ExportedArtifact
    }

    fn subject_artifact_digest(&self) -> [u8; 32] {
        self.subject_digest
    }

    fn execute(&mut self, _: &CaseAttempt) -> Result<SubjectObservation, AdapterError> {
        match self.behavior {
            AdverseBehavior::AdapterUnavailable => Err(AdapterError::Unavailable),
            AdverseBehavior::WrongOutput => Ok(SubjectObservation {
                result: SubjectResult::Output(b"wrong".to_vec()),
                usage: ResourceUsage::default(),
            }),
            AdverseBehavior::ExcessiveUsage => Ok(SubjectObservation {
                result: SubjectResult::Output(Vec::new()),
                usage: ResourceUsage {
                    memory_bytes: u64::MAX,
                    ..ResourceUsage::default()
                },
            }),
            AdverseBehavior::SubjectUnavailable => Ok(SubjectObservation {
                result: SubjectResult::Unavailable,
                usage: ResourceUsage::default(),
            }),
            AdverseBehavior::WrongResultKind => Ok(SubjectObservation {
                result: SubjectResult::Failure(NamespacedFailure {
                    owner_id: "test-provider".to_owned(),
                    contract_version: "1.0.0".to_owned(),
                    code_id: "unexpected".to_owned(),
                }),
                usage: ResourceUsage::default(),
            }),
        }
    }
}

fn evaluator_identity() -> EvaluatorIdentity {
    EvaluatorIdentity {
        source_digest: [61; 32],
        binary_digest: [62; 32],
        independence: IndependenceEvidence {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [47; 32],
            shared_code_audit_digest: [64; 32],
            reviewer_ids: vec!["reviewer-one".to_owned()],
        },
    }
}

fn request_with_limits(
    bytes: &[u8],
    report_bytes_limit: u64,
    diagnostic_bytes_limit: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut request = EvaluationRequest::from_canonical_cbor(bytes)?;
    request.output_capability.report_bytes_limit = report_bytes_limit;
    request.output_capability.diagnostic_bytes_limit = diagnostic_bytes_limit;
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request.to_canonical_cbor()?)
}

fn request_with(
    bytes: &[u8],
    update: impl FnOnce(&mut EvaluationRequest),
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut request = EvaluationRequest::from_canonical_cbor(bytes)?;
    update(&mut request);
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request.to_canonical_cbor()?)
}

#[test]
fn signed_public_corpus_produces_deterministic_self_verified_cnr1() -> TestResult {
    let corpus = support::corpus()?;
    let mut first_adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output.clone(),
    };
    let first = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut first_adapter,
    )?;
    let mut second_adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    let second = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut second_adapter,
    )?;

    assert_eq!(first.report_bytes, second.report_bytes);
    assert_eq!(first.report_digest, second.report_digest);
    assert_eq!(first.report.cases.len(), 7);
    assert!(first
        .report
        .cases
        .iter()
        .all(|case| case.outcome == CaseStatus::Pass));
    assert_eq!(
        ConformanceReport::from_canonical_cbor(&first.report_bytes),
        Ok(first.report)
    );
    Ok(())
}

#[test]
fn evaluator_accepts_every_current_profile_claim_layer() -> TestResult {
    for claim_layer in 0..=6 {
        let corpus = support::corpus_for_claim_layer(claim_layer)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        let result = evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?;
        assert!(result
            .report
            .cases
            .iter()
            .all(|case| case.claim_layer == claim_layer));
    }
    Ok(())
}

#[test]
fn evaluator_enforces_profile_independence_requirements() -> TestResult {
    let corpus = support::corpus()?;
    let updates: [fn(&mut EvaluatorIdentity); 3] = [
        |identity: &mut EvaluatorIdentity| identity.independence.technical_independent = false,
        |identity: &mut EvaluatorIdentity| identity.independence.authorship_independent = false,
        |identity: &mut EvaluatorIdentity| identity.independence.declaration_digest = [99; 32],
    ];
    for update in updates {
        let mut identity = evaluator_identity();
        update(&mut identity);
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output.clone(),
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &identity,
                &mut adapter,
            ),
            Err(EvaluatorError::Independence)
        );
    }
    Ok(())
}

#[test]
fn public_gateway_and_plugin_protocols_execute_complete_profiles() -> TestResult {
    for kind in [
        SubjectAdapterKind::PublicGatewayProtocol,
        SubjectAdapterKind::PublicPluginProtocol,
    ] {
        let corpus = support::corpus_for_adapter(kind)?;
        let mut adapter = KindAdapter {
            kind,
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        let output = evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?;
        assert!(output
            .report
            .cases
            .iter()
            .all(|case| case.outcome == CaseStatus::Pass));
    }
    Ok(())
}

#[test]
fn public_hard_caps_reject_zero_and_excessive_fixture_budgets() {
    let caps = EvaluatorHardCaps {
        max_profile_bytes: 100,
        max_cases: 100,
        max_bundle_members: 100,
        max_member_path_bytes: 100,
        max_member_bytes: 100,
        max_total_bundle_bytes: 100,
        max_compression_expansion: 100,
        max_structural_nesting: 100,
        max_coordinate_bytes: 100,
        max_diagnostic_bytes: 100,
        max_deterministic_memory_bytes: 100,
        max_deterministic_cpu_fuel: 100,
        max_deterministic_host_calls: 100,
        max_deterministic_event_count: 100,
        max_deterministic_output_bytes: 100,
        max_deterministic_storage_bytes: 100,
        max_deterministic_execution_steps: 100,
        max_deterministic_simulation_time_ns: 100,
    };
    let budget = |memory_bytes| DeterministicBudget {
        memory_bytes,
        cpu_fuel: 1,
        host_calls: 1,
        event_count: 1,
        output_bytes: 1,
        storage_bytes: 1,
        execution_steps: 1,
        simulation_time_ns: 1,
    };
    assert_eq!(caps.admits(budget(0)), Err(ProfileError::FieldOutOfBounds));
    assert_eq!(
        caps.admits(budget(101)),
        Err(ProfileError::FieldOutOfBounds)
    );
}

#[test]
fn replay_claims_accept_each_matching_redaction_state() -> TestResult {
    for state in 1..=3 {
        let corpus =
            support::corpus_with_profile_mutation(ProfileMutation::FixtureClaimState(state))?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        let output = evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?;
        let affected = output
            .report
            .cases
            .iter()
            .find(|case| case.redaction_state == state)
            .ok_or("mutated redaction case is absent")?;
        assert_eq!(affected.replay_claim, state);
        if state == 1 {
            assert_eq!(affected.outcome, CaseStatus::Pass);
        } else {
            assert_eq!(affected.outcome, CaseStatus::Unavailable);
            assert_eq!(affected.expected_digest, None);
            assert_eq!(affected.actual_digest, None);
        }
        assert!(output
            .report
            .cases
            .iter()
            .all(|case| { case.redaction_state == state || case.outcome == CaseStatus::Pass }));
    }
    Ok(())
}

#[test]
fn signed_bundle_rejects_structured_and_prefixed_secret_material() -> TestResult {
    let cbor_secret = [0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x61, b'x'];
    let cbor_array_secret = [
        0x81, 0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x61, b'x',
    ];
    let cbor_tag_secret = [
        0xc0, 0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x61, b'x',
    ];
    let cbor_nonempty_integer = [0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x00];
    let secrets = [
        br#"{"password":"x"}"#.as_slice(),
        br#"{"api-key":"x"}"#.as_slice(),
        br#"{"credential":"x"}"#.as_slice(),
        br#"{"access_token_digest":"00"}"#.as_slice(),
        br#"[{"client_secret":"x"}]"#.as_slice(),
        cbor_secret.as_slice(),
        cbor_array_secret.as_slice(),
        cbor_tag_secret.as_slice(),
        cbor_nonempty_integer.as_slice(),
        b"-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----".as_slice(),
        b"prefix bearer abcdefghijklmnop suffix".as_slice(),
        b"prefix basic abcdefghijklmnop suffix".as_slice(),
        b"prefix AKIAabcdefghijklmnop suffix".as_slice(),
        b"prefix ASIAabcdefghijklmnop suffix".as_slice(),
        b"prefix ghp_abcdefghijklmnop suffix".as_slice(),
        b"prefix gho_abcdefghijklmnop suffix".as_slice(),
        b"prefix ghu_abcdefghijklmnop suffix".as_slice(),
        b"prefix ghs_abcdefghijklmnop suffix".as_slice(),
        b"prefix ghr_abcdefghijklmnop suffix".as_slice(),
        b"prefix github_pat_abcdefghijklmnop suffix".as_slice(),
        b"prefix glpat-abcdefghijklmnop suffix".as_slice(),
        b"prefix xoxb-abcdefghijklmnop suffix".as_slice(),
        b"prefix xoxa-abcdefghijklmnop suffix".as_slice(),
        b"prefix xoxp-abcdefghijklmnop suffix".as_slice(),
        b"prefix xoxr-abcdefghijklmnop suffix".as_slice(),
        b"prefix xoxs-abcdefghijklmnop suffix".as_slice(),
        b"prefix sk_live_abcdefghijklmnop suffix".as_slice(),
        b"prefix sk_test_abcdefghijklmnop suffix".as_slice(),
        b"prefix AIzaabcdefghijklmnop suffix".as_slice(),
        b"prefix eyJabcdefghijklmnopqrst suffix".as_slice(),
    ];
    for secret in secrets {
        let corpus = support::corpus_with_secret(secret)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn signed_bundle_allows_empty_secret_slots_and_noncredential_text() -> TestResult {
    let empty_cbor_secret = [0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x60];
    let empty_cbor_secret_bytes = [0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x40];
    let empty_cbor_secret_null = [0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0xf6];
    for public_data in [
        br#"{"password":null,"token":"","ordinary":"secret"}"#.as_slice(),
        empty_cbor_secret.as_slice(),
        empty_cbor_secret_bytes.as_slice(),
        empty_cbor_secret_null.as_slice(),
        b"short bearer value and short ghp_token".as_slice(),
    ] {
        let corpus = support::corpus_with_secret(public_data)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        let artifacts = evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?;
        assert!(artifacts
            .report
            .cases
            .iter()
            .all(|case| case.outcome == CaseStatus::Pass));
    }
    Ok(())
}

#[test]
fn evaluator_rejects_empty_archives_and_mismatched_trust_snapshots() -> TestResult {
    let corpus = support::corpus()?;
    let mismatched_request = request_with(&corpus.request, |request| {
        request.trust_policy_snapshot_digest = [90; 32];
    })?;
    for (request, archive) in [
        (corpus.request.as_slice(), &[][..]),
        (mismatched_request.as_slice(), corpus.archive.as_slice()),
    ] {
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output.clone(),
        };
        assert_eq!(
            evaluate(
                request,
                archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_returns_typed_nonpass_for_an_unsupported_request_version() -> TestResult {
    let corpus = support::corpus()?;
    let mut request: ciborium::value::Value = ciborium::from_reader(corpus.request.as_slice())?;
    let ciborium::value::Value::Array(fields) = &mut request else {
        return Err("request is not an array".into());
    };
    fields[1] = ciborium::value::Value::Integer(2_u64.into());
    let mut request_bytes = Vec::new();
    ciborium::into_writer(&request, &mut request_bytes)?;
    let mut adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    assert_eq!(
        evaluate(
            &request_bytes,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        ),
        Err(EvaluatorError::UnsupportedVersion)
    );
    Ok(())
}

#[test]
fn air_gapped_evaluation_preserves_declared_non_network_capabilities() -> TestResult {
    let corpus = support::air_gapped_corpus()?;
    let mut adapter = RecordingAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
        attempts: Vec::new(),
    };
    let result = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut adapter,
    )?;
    assert_eq!(result.report.cases.len(), 7);
    assert_eq!(adapter.attempts.len(), 7);
    assert!(adapter.attempts.iter().all(|attempt| {
        attempt.mode == 1
            && !attempt.network_allowed
            && attempt.capability_ids.len() == 1
            && attempt.capability_ids[0] == "read-public-bundle"
    }));
    Ok(())
}

#[test]
fn evaluator_rejects_semantically_invalid_signed_release_admission() -> TestResult {
    let corpus = support::corpus_with_invalid_release_admission()?;
    let mut adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    assert_eq!(
        evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        ),
        Err(EvaluatorError::Profile)
    );
    Ok(())
}

#[test]
fn evaluator_matches_output_failure_and_divergence_oracles() -> TestResult {
    let corpus = support::mixed_oracle_corpus()?;
    let mut adapter = MixedOracleAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    let result = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut adapter,
    )?;
    assert!(result
        .report
        .cases
        .iter()
        .all(|case| case.outcome == CaseStatus::Pass));
    assert!(result
        .report
        .cases
        .iter()
        .any(|case| { case.first_coordinate.as_deref() == Some([1_u8, 2_u8].as_slice()) }));
    Ok(())
}

#[test]
fn evaluator_reports_mismatched_failure_and_divergence_oracles() -> TestResult {
    let corpus = support::mixed_oracle_corpus()?;
    let mut adapter = MismatchedOracleAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    let result = evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut adapter,
    )?;
    assert_eq!(
        result
            .report
            .cases
            .iter()
            .filter(|case| case.outcome == CaseStatus::Fail)
            .count(),
        2
    );
    Ok(())
}

#[test]
fn evaluator_reports_each_closed_adverse_subject_result() -> TestResult {
    for behavior in [
        AdverseBehavior::WrongOutput,
        AdverseBehavior::AdapterUnavailable,
        AdverseBehavior::ExcessiveUsage,
        AdverseBehavior::SubjectUnavailable,
        AdverseBehavior::WrongResultKind,
    ] {
        let corpus = support::corpus()?;
        let mut adapter = AdverseAdapter {
            subject_digest: corpus.subject_digest,
            behavior,
        };
        let result = evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?;
        assert!(result
            .report
            .cases
            .iter()
            .all(|case| case.outcome != CaseStatus::Pass));
        assert!(result.diagnostic_bytes.is_some());
    }
    Ok(())
}

#[test]
fn evaluator_enforces_adapter_identity_and_bounded_outputs() -> TestResult {
    let corpus = support::corpus()?;
    let mut wrong_adapter = PublicAdapter {
        subject_digest: [99; 32],
        output: corpus.expected_output.clone(),
    };
    assert_eq!(
        evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut wrong_adapter,
        ),
        Err(EvaluatorError::AdapterIdentity)
    );

    let request = request_with_limits(&corpus.request, 1, 0)?;
    let mut adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output.clone(),
    };
    assert_eq!(
        evaluate(
            &request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        ),
        Err(EvaluatorError::OutputLimit)
    );

    for diagnostic_limit in [0, 1] {
        let report_limit = 1024 * 1024;
        let request = request_with_limits(&corpus.request, report_limit, diagnostic_limit)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output.clone(),
        };
        assert!(evaluate(
            &request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?
        .diagnostic_bytes
        .is_none());
    }
    Ok(())
}

const PROFILE_MUTATIONS: &[ProfileMutation] = &[
    ProfileMutation::Magic,
    ProfileMutation::Version,
    ProfileMutation::ProfileId,
    ProfileMutation::ProfileSemver,
    ProfileMutation::Lifecycle,
    ProfileMutation::NormativeDigest,
    ProfileMutation::MatrixDigest,
    ProfileMutation::MatrixContent,
    ProfileMutation::FixturePolicyDigest,
    ProfileMutation::LimitationsDigest,
    ProfileMutation::PublicationDigest,
    ProfileMutation::PreviousDigest,
    ProfileMutation::ExecutionProfilesEmpty,
    ProfileMutation::ExecutionProfilesUnsorted,
    ProfileMutation::ProvidersEmpty,
    ProfileMutation::ProvidersUnsorted,
    ProfileMutation::FixturesEmpty,
    ProfileMutation::FixturesUnsorted,
    ProfileMutation::AllowedDivergenceUndeclared,
    ProfileMutation::AllowedDivergenceUnsorted,
    ProfileMutation::AllowedDivergenceCoordinate,
    ProfileMutation::ProtocolId,
    ProfileMutation::ProtocolDigest,
    ProfileMutation::ProtocolRequestDigest,
    ProfileMutation::ProtocolReportDigest,
    ProfileMutation::HardCapZero,
    ProfileMutation::HardCapAboveMaximum,
    ProfileMutation::RequirementDigest,
    ProfileMutation::RequirementDeclaration,
    ProfileMutation::FixtureModesEmpty,
    ProfileMutation::FixtureModesUnsorted,
    ProfileMutation::FixtureModeOutOfRange,
    ProfileMutation::FixtureModeOverflow,
    ProfileMutation::FixtureAdapter,
    ProfileMutation::FixtureProvider,
    ProfileMutation::FixtureCaseId,
    ProfileMutation::FixtureExecutionDigest,
    ProfileMutation::FixtureClaimLayer,
    ProfileMutation::FixtureFamily,
    ProfileMutation::FixtureOutcome,
    ProfileMutation::FixtureReplay,
    ProfileMutation::FixtureRedaction,
    ProfileMutation::FixtureBudget,
    ProfileMutation::FixtureBudgetAboveCap,
    ProfileMutation::FixtureWatchdog,
    ProfileMutation::FixtureNetworkPlugin,
    ProfileMutation::FixtureNetworkAirGapped,
    ProfileMutation::FixtureCapabilities,
    ProfileMutation::FixtureCapabilitiesUnsorted,
    ProfileMutation::FixtureAuxiliaryTooMany,
    ProfileMutation::FixtureDuplicatePath,
    ProfileMutation::FixtureDescriptor,
    ProfileMutation::FixturePayloadDescriptor,
    ProfileMutation::FixtureOracle,
    ProfileMutation::FixtureOracleOutputMissing,
    ProfileMutation::FixtureOracleDivergenceCoordinate,
    ProfileMutation::FixtureDivergenceCoordinateType,
    ProfileMutation::FixtureUnexpectedVerificationError,
    ProfileMutation::FixtureFailureVersion,
    ProfileMutation::FixtureClaimMismatch,
    ProfileMutation::FixtureProvenance,
    ProfileMutation::FixtureDowngradeBinding,
    ProfileMutation::FixtureDigest,
    ProfileMutation::ExecutionMagic,
    ProfileMutation::ExecutionVersion,
    ProfileMutation::ExecutionId,
    ProfileMutation::ExecutionSemver,
    ProfileMutation::ExecutionModes,
    ProfileMutation::ExecutionArchitecture,
    ProfileMutation::ExecutionNumerics,
    ProfileMutation::ExecutionDriverOrder,
    ProfileMutation::ExecutionTickPolicy,
    ProfileMutation::ExecutionSchemas,
    ProfileMutation::ExecutionArtifacts,
    ProfileMutation::ExecutionNetwork,
    ProfileMutation::ExecutionBudget,
    ProfileMutation::ExecutionCompatibility,
    ProfileMutation::ExecutionPrevious,
    ProfileMutation::ExecutionDigest,
    ProfileMutation::RegistryMagic,
    ProfileMutation::RegistryVersion,
    ProfileMutation::RegistryProviders,
    ProfileMutation::RegistryDigest,
    ProfileMutation::PackageMagic,
    ProfileMutation::PackageVersion,
    ProfileMutation::PackageProvider,
    ProfileMutation::PackageClaimLayer,
    ProfileMutation::PackageAdapter,
    ProfileMutation::PackageSchemas,
    ProfileMutation::PackageSupportRole,
    ProfileMutation::PackageDigest,
];

#[test]
fn evaluator_rejects_each_cryptographically_bound_profile_contract_mutation() -> TestResult {
    for &mutation in PROFILE_MUTATIONS {
        let corpus = support::corpus_with_profile_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_execution_matrix_contract_boundary() -> TestResult {
    for index in 0..=84 {
        let corpus = support::corpus_with_profile_mutation(ProfileMutation::MatrixBoundary(index))?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile),
            "execution matrix boundary {index} was accepted"
        );
    }
    Ok(())
}

#[test]
fn evaluator_accepts_an_executed_matrix_case_with_consistent_counts() -> TestResult {
    let corpus = support::corpus_with_profile_mutation(ProfileMutation::MatrixExecutedCase)?;
    let mut adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
    };
    evaluate(
        &corpus.request,
        &corpus.archive,
        &corpus.trust_policy,
        &evaluator_identity(),
        &mut adapter,
    )?;
    Ok(())
}

#[test]
fn evaluator_rejects_wrong_types_at_each_required_profile_contract_field() -> TestResult {
    let mutations = (0..16)
        .map(ProfileMutation::RawProfileField)
        .chain(
            (0..23)
                .filter(|index| ![13, 19, 20, 22].contains(index))
                .map(ProfileMutation::RawFixtureField),
        )
        .chain(
            (0..15)
                .map(ProfileMutation::RawExecutionField)
                .chain((0..2).map(ProfileMutation::RawExecutionNetworkField))
                .chain((0..8).map(ProfileMutation::RawExecutionBudgetField))
                .chain((0..2).map(ProfileMutation::RawExecutionVersionField))
                .chain((0..3).map(ProfileMutation::RawRegistryField))
                .chain((0..7).map(ProfileMutation::RawRegistryRecordField))
                .chain((0..11).map(ProfileMutation::RawPackageField)),
        )
        .chain((0..4).map(ProfileMutation::RawPackageProviderField))
        .chain((0..2).map(ProfileMutation::RawPackageSchemaBindingField))
        .chain((0..4).map(ProfileMutation::RawPackageSchemaDescriptorField))
        .chain((0..4).map(ProfileMutation::RawPackageSupportDescriptorField))
        .chain((0..2).map(ProfileMutation::RawProviderBindingField))
        .chain((0..4).map(ProfileMutation::RawRequiredProviderField))
        .chain((0..5).map(ProfileMutation::RawProtocolField))
        .chain((0..18).map(ProfileMutation::RawHardCapField))
        .chain((0..5).map(ProfileMutation::RawRequirementField))
        .chain((0..4).map(ProfileMutation::RawFixtureProviderField))
        .chain((0..4).map(ProfileMutation::RawFixtureSchemaField))
        .chain((0..4).map(ProfileMutation::RawFixturePayloadField))
        .chain((0..4).map(ProfileMutation::RawFixtureAuxiliaryField))
        .chain((0..2).map(ProfileMutation::RawFixtureOracleField))
        .chain((0..8).map(ProfileMutation::RawFixtureBudgetField))
        .chain((0..1).map(ProfileMutation::RawFixtureSafetyField))
        .chain((0..2).map(ProfileMutation::RawFixtureCapabilityField))
        .chain((0..7).map(ProfileMutation::RawFixtureProvenanceField))
        .chain((0..2).map(ProfileMutation::RawFixtureTransitionField));
    for mutation in mutations {
        let corpus = support::corpus_with_profile_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_malformed_profile_contract_containers() -> TestResult {
    let mutations = (0..4)
        .flat_map(|index| {
            [
                ProfileMutation::ArtifactEncoding(index),
                ProfileMutation::ArtifactShape(index),
            ]
        })
        .chain((0..17).map(ProfileMutation::RecordShape));
    for mutation in mutations {
        let corpus = support::corpus_with_profile_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_profile_textual_contract_boundary() -> TestResult {
    let mutations = (0..5)
        .map(ProfileMutation::IdentifierBoundary)
        .chain((0..17).map(ProfileMutation::SemanticVersionBoundary))
        .chain((0..12).map(ProfileMutation::MemberPathBoundary))
        .chain((0..9).map(ProfileMutation::MediaTypeBoundary))
        .chain((0..4).map(ProfileMutation::ExecutionListBoundary));
    for mutation in mutations {
        let corpus = support::corpus_with_profile_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_profile_numeric_and_relationship_boundary() -> TestResult {
    let mutations = (0..2)
        .map(ProfileMutation::ProviderKeyNumericBoundary)
        .chain(std::iter::once(ProfileMutation::DivergenceCoordinateLong))
        .chain((0..7).map(ProfileMutation::SelectedCapBoundary))
        .chain((0..10).map(ProfileMutation::ExecutionContractBoundary))
        .chain((0..9).map(ProfileMutation::FixtureSemanticBoundary))
        .chain((0..8).map(ProfileMutation::ProvenanceBoundary))
        .chain((0..3).map(ProfileMutation::DescriptorValueBoundary))
        .chain((0..5).map(ProfileMutation::RelationshipBoundary))
        .chain((0..9).map(ProfileMutation::ProviderContractBoundary))
        .chain(
            (0..support::MEMBER_CLOSURE_BOUNDARY_COUNT).map(ProfileMutation::MemberClosureBoundary),
        );
    for mutation in mutations {
        let corpus = support::corpus_with_profile_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        let expected = match mutation {
            ProfileMutation::MemberClosureBoundary(index)
                if support::member_closure_breaks_archive(index) =>
            {
                Err(EvaluatorError::Bundle)
            }
            _ => Err(EvaluatorError::Profile),
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            expected
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_request_identities_not_admitted_by_the_profile() -> TestResult {
    let corpus = support::corpus()?;
    for request in [
        request_with(&corpus.request, |request| {
            request.execution_profile_digest = [90; 32];
        })?,
        request_with(&corpus.request, |request| {
            request.evaluator_protocol_digest = [91; 32];
        })?,
        request_with(&corpus.request, |request| {
            request.evaluator_hard_caps_digest = [92; 32];
        })?,
    ] {
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output.clone(),
        };
        assert_eq!(
            evaluate(
                &request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_request_bound_archive_attack() -> TestResult {
    let mutations = [
        BundleMutation::Encoding,
        BundleMutation::ManifestShape,
        BundleMutation::DescriptorRecordShape,
        BundleMutation::MemberRecordShape,
        BundleMutation::ExpectedRecordShape,
        BundleMutation::Magic,
        BundleMutation::Version,
        BundleMutation::Mode,
        BundleMutation::ProfileDigest,
        BundleMutation::DescriptorOrder,
        BundleMutation::DescriptorDuplicate,
        BundleMutation::DescriptorSize,
        BundleMutation::DescriptorDigest,
        BundleMutation::DescriptorRole,
        BundleMutation::DescriptorEmpty,
        BundleMutation::DescriptorRoleOverflow,
        BundleMutation::DescriptorMissingPath,
        BundleMutation::MemberOrder,
        BundleMutation::MemberDuplicate,
        BundleMutation::MemberBytes,
        BundleMutation::MemberEmpty,
        BundleMutation::MemberRoleOverflow,
        BundleMutation::ExpectedOrder,
        BundleMutation::ExpectedDuplicate,
        BundleMutation::ExpectedClaimLayerOverflow,
        BundleMutation::ExpectedModeOverflow,
        BundleMutation::ExpectedClaimLayerAbove,
        BundleMutation::ExpectedModeAbove,
        BundleMutation::ExpectedMissingPath,
        BundleMutation::ExpectedDigest,
        BundleMutation::Signer,
        BundleMutation::Signature,
        BundleMutation::ArchiveShape,
    ];
    for mutation in mutations {
        let corpus = support::corpus_with_bundle_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_profile_inconsistent_expected_result_records() -> TestResult {
    for mutation in [
        BundleMutation::ProfileExpectedCount,
        BundleMutation::ProfileExpectedCase,
        BundleMutation::ProfileExpectedMode,
        BundleMutation::ProfileExpectedBinding,
    ] {
        let corpus = support::corpus_with_bundle_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_wrong_types_at_each_required_archive_field() -> TestResult {
    let mutations = (0..6)
        .map(BundleMutation::RawManifestField)
        .chain((0..4).map(BundleMutation::RawDescriptorField))
        .chain((0..3).map(BundleMutation::RawMemberField))
        .chain((0..6).map(BundleMutation::RawExpectedField))
        .chain((0..4).map(BundleMutation::RawArchiveField));
    for mutation in mutations {
        let corpus = support::corpus_with_bundle_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_archive_textual_contract_boundary() -> TestResult {
    let mutations = (0..8)
        .map(BundleMutation::PathBoundary)
        .chain((0..2).map(BundleMutation::ExpectedCaseBoundary));
    for mutation in mutations {
        let corpus = support::corpus_with_bundle_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_request_bound_trust_policy_attack() -> TestResult {
    let mutations = [
        TrustMutation::Encoding,
        TrustMutation::Shape,
        TrustMutation::RootRecordShape,
        TrustMutation::MinimumVersionRecordShape,
        TrustMutation::Magic,
        TrustMutation::Version,
        TrustMutation::PolicyId,
        TrustMutation::Epoch,
        TrustMutation::RootsEmpty,
        TrustMutation::RootsMultiple,
        TrustMutation::RootsTooMany,
        TrustMutation::DuplicateRootKey,
        TrustMutation::Revocations,
        TrustMutation::RevocationsTooMany,
        TrustMutation::RevocationsOrder,
        TrustMutation::RevokedArtifact,
        TrustMutation::Replacements,
        TrustMutation::ReplacementsTooMany,
        TrustMutation::ReplacementsOrder,
        TrustMutation::KeyId,
        TrustMutation::KeyEpoch,
        TrustMutation::Algorithm,
        TrustMutation::PublicKey,
        TrustMutation::VersionsTooMany,
        TrustMutation::VersionsOrder,
        TrustMutation::Expiry,
        TrustMutation::PreviousInvalid,
        TrustMutation::Signature,
    ];
    for mutation in mutations {
        let corpus = support::corpus_with_trust_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_wrong_types_at_each_required_trust_policy_field() -> TestResult {
    let mutations = (0..10)
        .map(TrustMutation::RawField)
        .chain((0..4).map(TrustMutation::RawRootField))
        .chain((0..2).map(TrustMutation::RawMinimumVersionField));
    for mutation in mutations {
        let corpus = support::corpus_with_trust_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_trust_policy_textual_contract_boundary() -> TestResult {
    let mutations = (0..5)
        .map(TrustMutation::IdentifierBoundary)
        .chain((0..16).map(TrustMutation::SemanticVersionBoundary))
        .chain((0..4).map(TrustMutation::ExpiryBoundary));
    for mutation in mutations {
        let corpus = support::corpus_with_trust_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Bundle)
        );
    }
    Ok(())
}

#[test]
fn evaluator_accepts_supported_trust_policy_evolution() -> TestResult {
    for mutation in [
        TrustMutation::AdditionalRoot,
        TrustMutation::NonMatchingRevocations,
        TrustMutation::VersionsEmpty,
        TrustMutation::Previous,
    ] {
        let corpus = support::corpus_with_trust_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        let report = evaluate(
            &corpus.request,
            &corpus.archive,
            &corpus.trust_policy,
            &evaluator_identity(),
            &mut adapter,
        )?;
        assert!(report
            .report
            .cases
            .iter()
            .all(|case| case.outcome == CaseStatus::Pass));
    }
    Ok(())
}

#[test]
fn evaluator_rejects_each_signed_release_admission_attack() -> TestResult {
    let mutations = [
        ReleaseMutation::Magic,
        ReleaseMutation::Version,
        ReleaseMutation::Lifecycle,
        ReleaseMutation::CaseId,
        ReleaseMutation::ExecutionDigest,
        ReleaseMutation::TrustDigest,
        ReleaseMutation::FromProvider,
        ReleaseMutation::ToProvider,
        ReleaseMutation::AllowFallback,
        ReleaseMutation::SignerId,
        ReleaseMutation::Signature,
        ReleaseMutation::MissingMember,
        ReleaseMutation::ExtraMember,
        ReleaseMutation::MissingBinding,
    ];
    for mutation in mutations {
        let corpus = support::corpus_with_release_mutation(mutation)?;
        let mut adapter = PublicAdapter {
            subject_digest: corpus.subject_digest,
            output: corpus.expected_output,
        };
        assert_eq!(
            evaluate(
                &corpus.request,
                &corpus.archive,
                &corpus.trust_policy,
                &evaluator_identity(),
                &mut adapter,
            ),
            Err(EvaluatorError::Profile)
        );
    }
    Ok(())
}
