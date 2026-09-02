pub mod support;

use std::error::Error;

use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, EvaluatorError, EvaluatorIdentity, ResourceUsage,
    SubjectAdapter, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{
    CaseStatus, ConformanceReport, EvaluationRequest, IndependenceEvidence, SubjectAdapterKind,
};
use pos_reference::profile::NamespacedFailure;
use support::{BundleMutation, ProfileMutation, TrustMutation};

type TestResult = Result<(), Box<dyn Error>>;

struct PublicAdapter {
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
            declaration_digest: [63; 32],
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
fn signed_bundle_rejects_structured_and_prefixed_secret_material() -> TestResult {
    let cbor_secret = [0xa1, 0x66, b's', b'e', b'c', b'r', b'e', b't', 0x61, b'x'];
    let secrets = [
        br#"{"password":"x"}"#.as_slice(),
        cbor_secret.as_slice(),
        b"-----BEGIN PRIVATE KEY-----\nvalue\n-----END PRIVATE KEY-----".as_slice(),
        b"prefix ghp_abcdefghijklmnop suffix".as_slice(),
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

    for (report_limit, diagnostic_limit) in [(1, 0), (1024 * 1024, 1)] {
        let request = request_with_limits(&corpus.request, report_limit, diagnostic_limit)?;
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
    }

    let request = request_with_limits(&corpus.request, 1024 * 1024, 0)?;
    let mut adapter = PublicAdapter {
        subject_digest: corpus.subject_digest,
        output: corpus.expected_output,
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
    Ok(())
}

#[test]
fn evaluator_rejects_each_cryptographically_bound_profile_contract_mutation() -> TestResult {
    let mutations = [
        ProfileMutation::Magic,
        ProfileMutation::Version,
        ProfileMutation::ProfileId,
        ProfileMutation::Lifecycle,
        ProfileMutation::NormativeDigest,
        ProfileMutation::ExecutionProfilesEmpty,
        ProfileMutation::ProvidersEmpty,
        ProfileMutation::FixturesEmpty,
        ProfileMutation::AllowedDivergenceUndeclared,
        ProfileMutation::ProtocolId,
        ProfileMutation::ProtocolDigest,
        ProfileMutation::HardCapZero,
        ProfileMutation::RequirementDigest,
        ProfileMutation::FixtureModesEmpty,
        ProfileMutation::FixtureModesUnsorted,
        ProfileMutation::FixtureAdapter,
        ProfileMutation::FixtureProvider,
        ProfileMutation::FixtureClaimLayer,
        ProfileMutation::FixtureFamily,
        ProfileMutation::FixtureOutcome,
        ProfileMutation::FixtureReplay,
        ProfileMutation::FixtureRedaction,
        ProfileMutation::FixtureBudget,
        ProfileMutation::FixtureWatchdog,
        ProfileMutation::FixtureNetworkPlugin,
        ProfileMutation::FixtureCapabilities,
        ProfileMutation::FixtureDescriptor,
        ProfileMutation::FixtureOracle,
        ProfileMutation::FixtureProvenance,
        ProfileMutation::FixtureDowngradeBinding,
        ProfileMutation::FixtureDigest,
    ];
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
fn evaluator_rejects_each_request_bound_archive_attack() -> TestResult {
    let mutations = [
        BundleMutation::Magic,
        BundleMutation::Version,
        BundleMutation::Mode,
        BundleMutation::ProfileDigest,
        BundleMutation::DescriptorOrder,
        BundleMutation::DescriptorDuplicate,
        BundleMutation::DescriptorSize,
        BundleMutation::DescriptorDigest,
        BundleMutation::DescriptorRole,
        BundleMutation::MemberOrder,
        BundleMutation::MemberDuplicate,
        BundleMutation::MemberBytes,
        BundleMutation::ExpectedOrder,
        BundleMutation::ExpectedDuplicate,
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
fn evaluator_rejects_each_request_bound_trust_policy_attack() -> TestResult {
    let mutations = [
        TrustMutation::Magic,
        TrustMutation::Version,
        TrustMutation::PolicyId,
        TrustMutation::Epoch,
        TrustMutation::RootsEmpty,
        TrustMutation::RootsMultiple,
        TrustMutation::Revocations,
        TrustMutation::Replacements,
        TrustMutation::KeyId,
        TrustMutation::KeyEpoch,
        TrustMutation::Algorithm,
        TrustMutation::PublicKey,
        TrustMutation::VersionsEmpty,
        TrustMutation::VersionsOrder,
        TrustMutation::Expiry,
        TrustMutation::Previous,
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
