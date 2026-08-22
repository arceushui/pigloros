use pos_core::{
    GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStateV1,
    OwnTracksEnrollmentStatusV1,
};

#[test]
fn absent_enrollment_pairs_once_and_advances_the_epoch() -> Result<(), Box<dyn std::error::Error>> {
    let state = OwnTracksEnrollmentStateV1::absent();
    let request = OwnTracksEnrollmentRequestV1::new(
        pos_core::TimelineId::new(),
        pos_core::EntityId::new(),
        GeoLocationAdmissionFenceV1::new(1, ([7; 32], 2, [8; 32]), (1, false, 3)),
        [9; 32],
    );

    let active = state.pair(&request)?;

    assert_eq!(active.status(), OwnTracksEnrollmentStatusV1::Active);
    assert_eq!(active.admission_epoch(), 4);
    assert!(active.has_pairing_verifier());
    Ok(())
}

#[test]
fn rotate_replaces_the_verifier_and_revoke_removes_it() -> Result<(), Box<dyn std::error::Error>> {
    let state = OwnTracksEnrollmentStateV1::absent().pair(&OwnTracksEnrollmentRequestV1::new(
        pos_core::TimelineId::new(),
        pos_core::EntityId::new(),
        GeoLocationAdmissionFenceV1::new(1, ([7; 32], 2, [8; 32]), (1, false, 3)),
        [9; 32],
    ))?;

    let rotated = state.rotate([10; 32])?;
    assert!(rotated.has_pairing_verifier());
    assert_eq!(rotated.admission_epoch(), 5);

    let revoked = rotated.revoke()?;
    assert_eq!(revoked.status(), OwnTracksEnrollmentStatusV1::Revoked);
    assert!(!revoked.has_pairing_verifier());
    assert_eq!(revoked.admission_epoch(), 6);
    Ok(())
}

#[test]
fn withdrawn_consent_cannot_pair_an_enrollment() {
    let result = OwnTracksEnrollmentStateV1::absent().pair(&OwnTracksEnrollmentRequestV1::new(
        pos_core::TimelineId::new(),
        pos_core::EntityId::new(),
        GeoLocationAdmissionFenceV1::new(1, ([7; 32], 2, [8; 32]), (1, true, 3)),
        [9; 32],
    ));

    assert!(result.is_err());
}

#[test]
fn absent_enrollment_persistence_round_trips_and_garbage_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let absent = OwnTracksEnrollmentStateV1::absent();
    let bytes = absent.persistence_bytes()?;
    let restored = OwnTracksEnrollmentStateV1::from_persistence_bytes(&bytes)?;
    assert_eq!(restored.status(), OwnTracksEnrollmentStatusV1::Absent);
    assert!(OwnTracksEnrollmentStateV1::from_persistence_bytes(&[0xff]).is_err());
    Ok(())
}
