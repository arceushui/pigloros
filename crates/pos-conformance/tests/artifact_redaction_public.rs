use pos_conformance::{
    CausalTraceEntryV1, DependencyClassV1, RedactionStateV1, ReplayClaimV1,
    StructuralCausalTraceEntryV1,
};
use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluatorV1,
};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected artifact redaction fixture error: {error:?}"
            )))
        })
    }
}

fn evaluation(
    current: ErasureReplayClaimV1,
    rule: ArtifactTransitionRuleV1,
    state: ArtifactStateV1,
) -> pos_core::ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        current,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::ReproManifest,
                ErasureReferenceV1::from_digest([1; 32]),
                ArtifactDataClassV1::PrivateSubjectData,
                Some(ErasureKeyRoleV1::DataEncryption),
                ErasureReferenceV1::from_digest([2; 32]),
                ArtifactOptionalityV1::Required,
                rule,
            ),
            current_claim: current,
            state,
        }],
    )
    .test_ok()
}

#[test]
fn public_artifacts_consume_the_host_evaluation_without_strengthening() {
    let claims = [
        ReplayClaimV1::Exact,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ReplayClaimV1::StructuralOnly,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::IncompatibleProfile,
    ];
    let dispositions = [
        (
            ArtifactTransitionRuleV1::PreserveExact,
            ArtifactStateV1::Retained,
        ),
        (
            ArtifactTransitionRuleV1::RedactViews,
            ArtifactStateV1::TransitionApplied,
        ),
        (
            ArtifactTransitionRuleV1::RetainStructure,
            ArtifactStateV1::TransitionApplied,
        ),
        (
            ArtifactTransitionRuleV1::Remove,
            ArtifactStateV1::TransitionApplied,
        ),
        (
            ArtifactTransitionRuleV1::PreserveExact,
            ArtifactStateV1::MissingRequiredOutput,
        ),
        (
            ArtifactTransitionRuleV1::PreserveExact,
            ArtifactStateV1::Invalidated,
        ),
    ];

    for claim in claims {
        let core_claim = match claim {
            ReplayClaimV1::Exact => ErasureReplayClaimV1::Exact,
            ReplayClaimV1::ExactAuthoritativeWithRedactedViews => {
                ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
            }
            ReplayClaimV1::StructuralOnly => ErasureReplayClaimV1::StructuralOnly,
            ReplayClaimV1::UnverifiableArtifactsMissing => {
                ErasureReplayClaimV1::UnverifiableArtifactsMissing
            }
            ReplayClaimV1::IncompatibleProfile => ErasureReplayClaimV1::IncompatibleProfile,
        };
        for (rule, state) in dispositions {
            let degraded = claim.after_artifact_evaluation(&evaluation(core_claim, rule, state));
            assert!(degraded.is_no_stronger_than(claim));
        }
    }
}

#[test]
fn structural_causal_trace_retains_only_minimized_node_and_edge_identity() {
    let trace = CausalTraceEntryV1 {
        cause_seq: 11,
        effect_seq: 17,
        relation: "subject-secret-relation".to_owned(),
        visibility: "subject-secret-label".to_owned(),
        dependency_class: DependencyClassV1::EndogenousRecomputed,
    };
    let structural = trace.structural();
    assert_eq!(
        structural,
        StructuralCausalTraceEntryV1 {
            cause_seq: 11,
            effect_seq: 17,
            dependency_class: DependencyClassV1::EndogenousRecomputed,
        }
    );
    let serialized = serde_json::to_string(&structural).test_ok();
    assert!(!serialized.contains("subject-secret-relation"));
    assert!(!serialized.contains("subject-secret-label"));
    assert!(!serialized.contains("relation"));
    assert!(!serialized.contains("visibility"));
}

#[test]
fn public_redaction_state_tracks_erasure_independently_of_profile_support() {
    let cases = [
        (
            ArtifactTransitionRuleV1::PreserveExact,
            ArtifactStateV1::Retained,
            RedactionStateV1::None,
        ),
        (
            ArtifactTransitionRuleV1::RedactViews,
            ArtifactStateV1::TransitionApplied,
            RedactionStateV1::RedactedViews,
        ),
        (
            ArtifactTransitionRuleV1::RetainStructure,
            ArtifactStateV1::TransitionApplied,
            RedactionStateV1::StructuralOnly,
        ),
        (
            ArtifactTransitionRuleV1::Remove,
            ArtifactStateV1::Erased,
            RedactionStateV1::EvidenceMissing,
        ),
    ];
    for (rule, state, expected) in cases {
        let evaluated = evaluation(ErasureReplayClaimV1::IncompatibleProfile, rule, state);
        assert_eq!(
            RedactionStateV1::None.after_artifact_evaluation(&evaluated),
            expected
        );
        assert_eq!(
            RedactionStateV1::EvidenceMissing.after_artifact_evaluation(&evaluated),
            RedactionStateV1::EvidenceMissing
        );
    }
}
