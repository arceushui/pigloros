use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactRedactionStateV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureErrorV1,
    ErasureKeyRoleV1, ErasureReferenceV1, ErasureReplayClaimV1, RegisteredArtifactV1,
    ReplayClaimEvaluatorV1,
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
        registration: RegisteredArtifactV1::new(
            artifact_class,
            reference(byte),
            ArtifactDataClassV1::PrivateSubjectData,
            Some(ErasureKeyRoleV1::DataEncryption),
            reference(byte.wrapping_add(64)),
            optionality,
            transition_rule,
        ),
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
        assert_eq!(
            evaluation.artifacts[0].redaction_state,
            ArtifactRedactionStateV1::StructuralOnly
        );
    }
}

#[test]
fn transition_rules_produce_the_adr_060_claims() {
    let cases = [
        (
            ArtifactTransitionRuleV1::PreserveExact,
            ErasureReplayClaimV1::Exact,
            ArtifactRedactionStateV1::None,
            true,
        ),
        (
            ArtifactTransitionRuleV1::RedactViews,
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            ArtifactRedactionStateV1::RedactedViews,
            true,
        ),
        (
            ArtifactTransitionRuleV1::RetainStructure,
            ErasureReplayClaimV1::StructuralOnly,
            ArtifactRedactionStateV1::StructuralOnly,
            false,
        ),
        (
            ArtifactTransitionRuleV1::Remove,
            ErasureReplayClaimV1::UnverifiableArtifactsMissing,
            ArtifactRedactionStateV1::EvidenceMissing,
            false,
        ),
    ];
    for (index, (rule, expected, redaction, authoritative)) in cases.into_iter().enumerate() {
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
        assert_eq!(evaluation.redaction_state, redaction);
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
                ArtifactStateV1::Erased,
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
    assert_eq!(
        evaluation.redaction_state,
        ArtifactRedactionStateV1::StructuralOnly
    );
    assert_eq!(evaluation.artifacts[0].artifact_digest, reference(1));
    assert_eq!(evaluation.artifacts[1].artifact_digest, reference(3));
    assert_eq!(evaluation.artifacts[2].artifact_digest, reference(2));
}

#[test]
fn every_missing_prerequisite_and_quarantined_artifact_is_unverifiable() {
    for state in [
        ArtifactStateV1::MissingParentCut,
        ArtifactStateV1::MissingFrozenInput,
        ArtifactStateV1::MissingKey,
        ArtifactStateV1::MissingSchema,
        ArtifactStateV1::MissingPlugin,
        ArtifactStateV1::MissingModel,
        ArtifactStateV1::MissingRuntime,
        ArtifactStateV1::MissingRequiredOutput,
        ArtifactStateV1::Erased,
        ArtifactStateV1::Invalidated,
    ] {
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
        assert_eq!(
            evaluation.redaction_state,
            ArtifactRedactionStateV1::EvidenceMissing
        );
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
    let evaluation =
        ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::StructuralOnly, &[artifact])
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
    let evaluation =
        ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::IncompatibleProfile, &[artifact])
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
    assert_eq!(evaluation.redaction_state, ArtifactRedactionStateV1::None);
}

#[test]
fn public_claim_weakener_rejects_an_upgrade() {
    assert_eq!(
        ErasureReplayClaimV1::StructuralOnly.weakened_to(ErasureReplayClaimV1::Exact),
        ErasureReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        ErasureReplayClaimV1::Exact.weakened_to(ErasureReplayClaimV1::StructuralOnly),
        ErasureReplayClaimV1::StructuralOnly
    );
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
    assert_eq!(registration.artifact_digest(), reference(7));
    assert_eq!(
        registration.data_class(),
        ArtifactDataClassV1::PrivateSubjectData
    );
    assert_eq!(
        registration.key_role(),
        Some(ErasureKeyRoleV1::DataEncryption)
    );
    assert_eq!(registration.owner(), reference(71));
    assert_eq!(registration.optionality(), ArtifactOptionalityV1::Required);
    assert_eq!(
        registration.transition_rule(),
        ArtifactTransitionRuleV1::RedactViews
    );
    assert_eq!(
        registration.artifact_class(),
        ErasureArtifactClassV1::CalibrationReport
    );
}

#[test]
fn authoritative_release_requires_the_exact_registered_class_and_digest() {
    let retained = input(
        ErasureArtifactClassV1::ReproManifest,
        1,
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    );
    let erased = input(
        ErasureArtifactClassV1::ForkOrSnapshot,
        2,
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::Remove,
        ArtifactStateV1::Erased,
    );
    let evaluation =
        ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::Exact, &[retained, erased])
            .expect("distinct registered artifacts should evaluate");

    assert_eq!(
        evaluation.require_authoritative_use(ErasureArtifactClassV1::ReproManifest, reference(1),),
        Ok(())
    );
    assert_eq!(
        evaluation.require_authoritative_use(ErasureArtifactClassV1::ForkOrSnapshot, reference(2),),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        evaluation.require_authoritative_use(ErasureArtifactClassV1::TimelineReplay, reference(1),),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        evaluation.require_authoritative_use(ErasureArtifactClassV1::ReproManifest, reference(9),),
        Err(ErasureErrorV1::PolicyConflict)
    );
}
