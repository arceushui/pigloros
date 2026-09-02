mod support;

use std::error::Error;

use pos_reference::evaluator::{
    evaluate, AdapterError, CaseAttempt, EvaluatorError, EvaluatorIdentity, ResourceUsage,
    SubjectAdapter, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_protocol::{
    CaseStatus, ConformanceReport, IndependenceEvidence, SubjectAdapterKind,
};

type TestResult = Result<(), Box<dyn Error>>;

struct PublicAdapter {
    subject_digest: [u8; 32],
    output: Vec<u8>,
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
