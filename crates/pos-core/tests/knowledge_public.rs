use pos_core::{
    AiGoalPolicyRevisionV1, BeliefRecordDraftV1, BeliefRecordV1, CanonicalBytes, ConfidenceV1,
    EntityId, Hash, KnowledgeSnapshotDraftV1, KnowledgeSnapshotV1, MemoryPolicyRevisionV1,
    ObservationArtifactV1, ObservationRecordDraftV1, ObservationRecordV1,
    ObservationSnapshotDraftV1, ObservationSnapshotV1, ObservationStatusV1, PluginId,
    PreferenceValueRevisionV1, PrincipalRefV1, Seq, TimelineId,
};
use ulid::Ulid;

fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn belief_draft(
    entity_id: EntityId,
    predicate: &str,
    observation_digest: Hash,
) -> BeliefRecordDraftV1 {
    BeliefRecordDraftV1 {
        entity_id,
        predicate: predicate.to_owned(),
        confidence: ConfidenceV1::try_new(750_000).expect("bounded confidence"),
        provenance_digest: hash_from_repeated_byte(23),
        observation_record_digests: vec![observation_digest],
    }
}

#[test]
fn knowledge_snapshot_preserves_epistemic_and_revision_meanings() {
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let observation =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .expect("observation reference");
    let belief = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "prefers.tea",
        observation.digest(),
    ))
    .expect("belief");
    let snapshot = KnowledgeSnapshotV1::try_from_draft(KnowledgeSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").expect("principal"),
        participant_id,
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        observation_snapshot_digest: hash_from_repeated_byte(25),
        observations: vec![observation],
        beliefs: vec![belief.clone()],
        preference_value_revision: Some(
            PreferenceValueRevisionV1::try_new(hash_from_repeated_byte(26))
                .expect("preference revision"),
        ),
        ai_goal_policy_revision: Some(
            AiGoalPolicyRevisionV1::try_new(hash_from_repeated_byte(27))
                .expect("AI policy revision"),
        ),
        memory_policy_revision: MemoryPolicyRevisionV1::try_new(hash_from_repeated_byte(28))
            .expect("memory policy revision"),
        prior_snapshot_digest: Some(hash_from_repeated_byte(29)),
        external_provenance: vec![hash_from_repeated_byte(30)],
        provenance_digest: hash_from_repeated_byte(31),
    })
    .expect("knowledge snapshot");

    assert_eq!(snapshot.beliefs(), &[belief]);
    assert_eq!(
        snapshot
            .preference_value_revision()
            .map(PreferenceValueRevisionV1::digest),
        Some(hash_from_repeated_byte(26))
    );
    assert_eq!(
        snapshot
            .ai_goal_policy_revision()
            .map(AiGoalPolicyRevisionV1::digest),
        Some(hash_from_repeated_byte(27))
    );
    assert_eq!(
        snapshot.memory_policy_revision().digest(),
        hash_from_repeated_byte(28)
    );
    assert_eq!(
        KnowledgeSnapshotV1::decode(&snapshot.encode().expect("canonical KNS1")),
        Ok(snapshot)
    );
}

#[test]
fn knowledge_snapshot_rejects_noncanonical_belief_order() {
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let observation =
        ObservationRecordV1::try_from_draft(record_draft(ObservationStatusV1::NotObserved, None))
            .expect("observation reference");
    let later = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "z.last",
        observation.digest(),
    ))
    .expect("later belief");
    let earlier = BeliefRecordV1::try_from_draft(belief_draft(
        participant_id,
        "a.first",
        observation.digest(),
    ))
    .expect("earlier belief");
    let mut draft = KnowledgeSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").expect("principal"),
        participant_id,
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        observation_snapshot_digest: hash_from_repeated_byte(25),
        observations: vec![observation],
        beliefs: vec![later, earlier],
        preference_value_revision: None,
        ai_goal_policy_revision: None,
        memory_policy_revision: MemoryPolicyRevisionV1::try_new(hash_from_repeated_byte(28))
            .expect("memory policy revision"),
        prior_snapshot_digest: None,
        external_provenance: Vec::new(),
        provenance_digest: hash_from_repeated_byte(31),
    };

    assert_eq!(
        KnowledgeSnapshotV1::try_from_draft(draft.clone()),
        Err(pos_core::AuthorityErrorV1::NonCanonicalOrder)
    );
    draft.beliefs.reverse();
    assert!(KnowledgeSnapshotV1::try_from_draft(draft).is_ok());
}

fn observation_snapshot_draft(
    records: Vec<ObservationRecordV1>,
    artifacts: Vec<ObservationArtifactV1>,
) -> ObservationSnapshotDraftV1 {
    ObservationSnapshotDraftV1 {
        principal: PrincipalRefV1::try_new([7; 16], "host.test").expect("principal"),
        participant_id: EntityId::from_ulid(Ulid::from(1_u128)),
        plugin_id: PluginId::from_ulid(Ulid::from(11_u128)),
        installation_id: [12; 16],
        timeline_id: TimelineId::from_ulid(Ulid::from(2_u128)),
        observed_through: Seq::from_u64(7),
        authority_timeline: TimelineId::from_ulid(Ulid::from(13_u128)),
        authority_position: Seq::from_u64(6),
        authorization_request_digest: hash_from_repeated_byte(14),
        authorization_decision_digest: hash_from_repeated_byte(15),
        grant_chain_bindings: vec![hash_from_repeated_byte(16)],
        consent_policy_revision: hash_from_repeated_byte(17),
        capability_policy_revision: hash_from_repeated_byte(18),
        revocation_epoch: 3,
        visibility_policy_revision: hash_from_repeated_byte(19),
        schema_revision: hash_from_repeated_byte(20),
        minimization_revision: hash_from_repeated_byte(6),
        records,
        artifacts,
        prior_snapshot_digest: Some(hash_from_repeated_byte(21)),
        provenance_digest: hash_from_repeated_byte(22),
    }
}

fn record_draft(
    status: ObservationStatusV1,
    artifact_digest: Option<Hash>,
) -> ObservationRecordDraftV1 {
    ObservationRecordDraftV1 {
        participant_id: EntityId::from_ulid(Ulid::from(1_u128)),
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        status,
        artifact_digest,
        source_timeline: TimelineId::from_ulid(Ulid::from(2_u128)),
        source_position: Seq::from_u64(7),
        schema: "profile.v1".to_owned(),
        source_digest: hash_from_repeated_byte(3),
        projection_digest: Some(hash_from_repeated_byte(4)),
        provenance_digest: hash_from_repeated_byte(5),
        minimization_revision: hash_from_repeated_byte(6),
    }
}

#[test]
fn observation_record_round_trip_binds_participant_source_and_minimization() {
    let artifact = ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed"))
        .expect("bounded observation artifact");
    let draft = record_draft(ObservationStatusV1::Present, Some(artifact.digest()));
    let participant_id = draft.participant_id;
    let record =
        ObservationRecordV1::try_from_draft(draft.clone()).expect("valid observation record");

    assert_eq!(record.participant_id(), participant_id);
    assert_eq!(record.status(), ObservationStatusV1::Present);
    assert_eq!(record.artifact_digest(), Some(artifact.digest()));
    assert_ne!(record.digest(), Hash::zero());
    assert_eq!(
        ObservationRecordV1::decode(&record.encode().expect("canonical OBR1")),
        Ok(record)
    );

    let mut changed_timeline = draft.clone();
    changed_timeline.source_timeline = TimelineId::from_ulid(Ulid::from(9_u128));
    let mut changed_participant = draft.clone();
    changed_participant.participant_id = EntityId::from_ulid(Ulid::from(10_u128));
    let mut changed_position = draft.clone();
    changed_position.source_position = Seq::from_u64(8);
    let mut changed_minimization = draft;
    changed_minimization.minimization_revision = hash_from_repeated_byte(9);
    for changed in [
        changed_participant,
        changed_timeline,
        changed_position,
        changed_minimization,
    ] {
        assert_ne!(
            ObservationRecordV1::try_from_draft(changed)
                .expect("independently varied valid record")
                .digest(),
            record.digest()
        );
    }
}

#[test]
fn typed_absence_cannot_carry_observation_value_bytes() {
    let result = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Unauthorized,
        Some(hash_from_repeated_byte(1)),
    ));

    assert_eq!(result, Err(pos_core::AuthorityErrorV1::UnauthorizedSource));
}

#[test]
fn observation_snapshot_is_authorization_bound_and_content_addressed() {
    let artifact = ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed"))
        .expect("bounded observation artifact");
    let record = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Present,
        Some(artifact.digest()),
    ))
    .expect("observation record");
    let snapshot = ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
        vec![record.clone()],
        vec![artifact.clone()],
    ))
    .expect("authorized snapshot");

    assert_eq!(snapshot.records(), &[record]);
    assert_eq!(snapshot.artifact(artifact.digest()), Some(&artifact));
    assert_eq!(snapshot.revocation_epoch(), 3);
    assert_ne!(snapshot.digest(), Hash::zero());
    assert_eq!(
        ObservationSnapshotV1::decode(&snapshot.encode().expect("canonical OBS1")),
        Ok(snapshot)
    );
}

#[test]
fn observation_snapshot_rejects_noncanonical_records_and_unbound_artifacts() {
    let artifact = ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed"))
        .expect("bounded observation artifact");
    let mut later = record_draft(ObservationStatusV1::Present, Some(artifact.digest()));
    later.source_position = Seq::from_u64(8);
    let later = ObservationRecordV1::try_from_draft(later).expect("later record");
    let earlier = ObservationRecordV1::try_from_draft(record_draft(
        ObservationStatusV1::Present,
        Some(artifact.digest()),
    ))
    .expect("earlier record");

    assert_eq!(
        ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
            vec![later, earlier],
            vec![artifact.clone()],
        )),
        Err(pos_core::AuthorityErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        ObservationSnapshotV1::try_from_draft(observation_snapshot_draft(
            Vec::new(),
            vec![artifact,]
        )),
        Err(pos_core::AuthorityErrorV1::ProvenanceMissing)
    );
}
