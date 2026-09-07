use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureErrorV1, ErasureKeyRoleV1,
    ErasureReferenceV1, ErasureReplayClaimV1, RegisteredArtifactV1, ReplayClaimEvaluatorV1,
};

fn reference(byte: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([byte; 32])
}

fn input(
    artifact_class: ErasureArtifactClassV1,
    byte: u8,
    optionality: ArtifactOptionalityV1,
    transition_rule: ArtifactTransitionRuleV1,
    state: ArtifactStateV1,
) -> ArtifactClaimInputV1 {
    ArtifactClaimInputV1 {
        registration: RegisteredArtifactV1 {
            artifact_class,
            artifact_digest: reference(byte),
            data_class: ArtifactDataClassV1::PrivateSubjectData,
            key_role: Some(ErasureKeyRoleV1::DataEncryption),
            owner: reference(byte.wrapping_add(64)),
            optionality,
            transition_rule,
        },
        current_claim: ErasureReplayClaimV1::Exact,
        state,
    }
}

#[test]
fn every_artifact_class_uses_its_registered_one_way_transition() {
    let classes = [
        ErasureArtifactClassV1::TimelineReplay,
        ErasureArtifactClassV1::ReproManifest,
        ErasureArtifactClassV1::CausalTrace,
        ErasureArtifactClassV1::CalibrationReport,
        ErasureArtifactClassV1::Export,
        ErasureArtifactClassV1::ForkOrSnapshot,
        ErasureArtifactClassV1::ConformanceReport,
    ];
    for (index, artifact_class) in classes.into_iter().enumerate() {
        let evaluation = ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[input(
                artifact_class,
                index as u8 + 1,
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::RetainStructure,
                ArtifactStateV1::TransitionApplied,
            )],
        )
        .expect("a unique registered artifact should evaluate");
        assert_eq!(
            evaluation.replay_claim,
            ErasureReplayClaimV1::StructuralOnly
        );
        assert_eq!(evaluation.artifacts[0].from, ErasureReplayClaimV1::Exact);
        assert_eq!(
            evaluation.artifacts[0].to,
            ErasureReplayClaimV1::StructuralOnly
        );
        assert!(!evaluation.artifacts[0].authoritative_use_permitted);
    }
}

#[test]
fn transition_rules_produce_the_adr_060_claims() {
    let cases = [
        (
            ArtifactTransitionRuleV1::PreserveExact,
            ErasureReplayClaimV1::Exact,
            true,
        ),
        (
            ArtifactTransitionRuleV1::RedactViews,
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            true,
        ),
        (
            ArtifactTransitionRuleV1::RetainStructure,
            ErasureReplayClaimV1::StructuralOnly,
            false,
        ),
        (
            ArtifactTransitionRuleV1::Remove,
            ErasureReplayClaimV1::UnverifiableArtifactsMissing,
            false,
        ),
    ];
    for (index, (rule, expected, authoritative)) in cases.into_iter().enumerate() {
        let evaluation = ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[input(
                ErasureArtifactClassV1::ReproManifest,
                index as u8 + 1,
                ArtifactOptionalityV1::Required,
                rule,
                ArtifactStateV1::TransitionApplied,
            )],
        )
        .expect("registered transition should evaluate");
        assert_eq!(evaluation.replay_claim, expected);
        assert_eq!(
            evaluation.artifacts[0].authoritative_use_permitted,
            authoritative
        );
    }
}

#[test]
fn export_takes_the_weakest_required_member_and_ignores_optional_absence() {
    let evaluation = ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[
            input(
                ErasureArtifactClassV1::CausalTrace,
                3,
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::RetainStructure,
                ArtifactStateV1::TransitionApplied,
            ),
            input(
                ErasureArtifactClassV1::CalibrationReport,
                2,
                ArtifactOptionalityV1::Optional,
                ArtifactTransitionRuleV1::Remove,
                ArtifactStateV1::Missing,
            ),
            input(
                ErasureArtifactClassV1::TimelineReplay,
                1,
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::RedactViews,
                ArtifactStateV1::TransitionApplied,
            ),
        ],
    )
    .expect("distinct export members should evaluate");
    assert_eq!(
        evaluation.replay_claim,
        ErasureReplayClaimV1::StructuralOnly
    );
    assert_eq!(evaluation.artifacts[0].artifact_digest, reference(1));
    assert_eq!(evaluation.artifacts[1].artifact_digest, reference(3));
    assert_eq!(evaluation.artifacts[2].artifact_digest, reference(2));
}

#[test]
fn missing_or_invalidated_required_artifacts_are_unverifiable_and_not_authoritative() {
    for state in [ArtifactStateV1::Missing, ArtifactStateV1::Invalidated] {
        let evaluation = ReplayClaimEvaluatorV1::evaluate(
            ErasureReplayClaimV1::Exact,
            &[input(
                ErasureArtifactClassV1::ForkOrSnapshot,
                1,
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
                state,
            )],
        )
        .expect("registered absence should produce a lower claim");
        assert_eq!(
            evaluation.replay_claim,
            ErasureReplayClaimV1::UnverifiableArtifactsMissing
        );
        assert!(!evaluation.artifacts[0].authoritative_use_permitted);
    }
}

#[test]
fn retained_artifact_preserves_an_existing_weaker_claim() {
    let mut artifact = input(
        ErasureArtifactClassV1::TimelineReplay,
        1,
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    );
    artifact.current_claim = ErasureReplayClaimV1::StructuralOnly;
    let evaluation = ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::StructuralOnly,
        &[artifact],
    )
    .expect("retained evidence should evaluate");
    assert_eq!(
        evaluation.replay_claim,
        ErasureReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        evaluation.artifacts[0].to,
        ErasureReplayClaimV1::StructuralOnly
    );
}

#[test]
fn incompatible_profile_remains_orthogonal_to_erasure() {
    let mut artifact = input(
        ErasureArtifactClassV1::ConformanceReport,
        1,
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::Remove,
        ArtifactStateV1::TransitionApplied,
    );
    artifact.current_claim = ErasureReplayClaimV1::IncompatibleProfile;
    let evaluation = ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::IncompatibleProfile,
        &[artifact],
    )
    .expect("orthogonal profile state should evaluate");
    assert_eq!(
        evaluation.replay_claim,
        ErasureReplayClaimV1::IncompatibleProfile
    );
    assert_eq!(
        evaluation.artifacts[0].to,
        ErasureReplayClaimV1::IncompatibleProfile
    );
}

#[test]
fn duplicate_artifact_policy_fails_closed() {
    let artifact = input(
        ErasureArtifactClassV1::ReproManifest,
        1,
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    );
    assert_eq!(
        ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::Exact, &[artifact, artifact]),
        Err(ErasureErrorV1::PolicyConflict)
    );
}

#[test]
fn empty_required_closure_preserves_the_enclosing_claim() {
    let evaluation = ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        &[],
    )
    .expect("an empty member set should preserve its enclosing claim");
    assert_eq!(
        evaluation.replay_claim,
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    assert!(evaluation.artifacts.is_empty());
}

#[test]
fn registrations_record_every_pre_erasure_policy_fact() {
    let registration = input(
        ErasureArtifactClassV1::CalibrationReport,
        7,
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::RedactViews,
        ArtifactStateV1::Retained,
    )
    .registration;
    assert_eq!(registration.artifact_digest, reference(7));
    assert_eq!(registration.data_class, ArtifactDataClassV1::PrivateSubjectData);
    assert_eq!(registration.key_role, Some(ErasureKeyRoleV1::DataEncryption));
    assert_eq!(registration.owner, reference(71));
    assert_eq!(registration.optionality, ArtifactOptionalityV1::Required);
    assert_eq!(
        registration.transition_rule,
        ArtifactTransitionRuleV1::RedactViews
    );

    for data_class in [
        ArtifactDataClassV1::PrivateSubjectData,
        ArtifactDataClassV1::ConsentedSharedData,
        ArtifactDataClassV1::PublicRecord,
        ArtifactDataClassV1::AggregateData,
        ArtifactDataClassV1::StructuralAuditMetadata,
    ] {
        assert_eq!(data_class, data_class);
    }
}
