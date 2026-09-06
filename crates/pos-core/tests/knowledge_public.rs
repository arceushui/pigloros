use pos_core::{
    CanonicalBytes, EntityId, Hash, ObservationArtifactV1, ObservationRecordDraftV1,
    ObservationRecordV1, ObservationStatusV1, Seq, TimelineId,
};
use ulid::Ulid;

fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

#[test]
fn observation_record_round_trip_binds_participant_source_and_minimization() {
    let participant_id = EntityId::from_ulid(Ulid::from(1_u128));
    let source_timeline = TimelineId::from_ulid(Ulid::from(2_u128));
    let artifact = ObservationArtifactV1::try_new(CanonicalBytes::from_static(b"allowed"))
        .expect("bounded observation artifact");
    let record = ObservationRecordV1::try_from_draft(ObservationRecordDraftV1 {
        participant_id,
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        status: ObservationStatusV1::Present,
        artifact_digest: Some(artifact.digest()),
        source_timeline,
        source_position: Seq::from_u64(7),
        schema: "profile.v1".to_owned(),
        source_digest: hash(3),
        projection_digest: Some(hash(4)),
        provenance_digest: hash(5),
        minimization_revision: hash(6),
    })
    .expect("valid observation record");

    assert_eq!(record.participant_id(), participant_id);
    assert_eq!(record.status(), ObservationStatusV1::Present);
    assert_eq!(record.artifact_digest(), Some(artifact.digest()));
    assert_ne!(record.digest(), Hash::zero());
    assert_eq!(
        ObservationRecordV1::decode(&record.encode().expect("canonical OBR1")),
        Ok(record)
    );
}

#[test]
fn typed_absence_cannot_carry_observation_value_bytes() {
    let result = ObservationRecordV1::try_from_draft(ObservationRecordDraftV1 {
        participant_id: EntityId::new(),
        resource: "projection.profile".to_owned(),
        data_category: "profile.preferences".to_owned(),
        status: ObservationStatusV1::Unauthorized,
        artifact_digest: Some(hash(1)),
        source_timeline: TimelineId::new(),
        source_position: Seq::from_u64(1),
        schema: "profile.v1".to_owned(),
        source_digest: hash(2),
        projection_digest: None,
        provenance_digest: hash(3),
        minimization_revision: hash(4),
    });

    assert_eq!(result, Err(pos_core::AuthorityErrorV1::UnauthorizedSource));
}
