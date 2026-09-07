use pos_conformance::{
    CausalTraceEntryV1, DependencyClassV1, ReplayClaimV1, StructuralCausalTraceEntryV1,
};
use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluatorV1,
};

fn evaluation(
    current: ErasureReplayClaimV1,
    rule: ArtifactTransitionRuleV1,
    state: ArtifactStateV1,
) -> pos_core::ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        current,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1 {
                artifact_class: ErasureArtifactClassV1::ReproManifest,
                artifact_digest: ErasureReferenceV1::from_digest([1; 32]),
                data_class: ArtifactDataClassV1::PrivateSubjectData,
                key_role: Some(ErasureKeyRoleV1::DataEncryption),
                owner: ErasureReferenceV1::from_digest([2; 32]),
                optionality: ArtifactOptionalityV1::Required,
                transition_rule: rule,
            },
            current_claim: current,
            state,
        }],
    )
    .expect("a unique registered artifact should evaluate")
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
    let serialized = serde_json::to_string(&structural).expect("structural trace should serialize");
    assert!(!serialized.contains("subject-secret-relation"));
    assert!(!serialized.contains("subject-secret-label"));
    assert!(!serialized.contains("relation"));
    assert!(!serialized.contains("visibility"));
}
