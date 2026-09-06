use pos_core::{
    CanonicalBytes, EntityId, Hash, ObservationArtifactV1, ObservationRecordDraftV1,
    ObservationRecordV1, ObservationStatusV1, Seq, TimelineId,
};
use ulid::Ulid;

fn hash_from_repeated_byte(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
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
