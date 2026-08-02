use pos_core::{
    EntityId, EventStore, GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1,
    OwnTracksEnrollmentStatusV1, OwnTracksEnrollmentStore,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

fn request(
    timeline: pos_core::TimelineId,
    entity: EntityId,
    epoch: u64,
    verifier: [u8; 32],
) -> OwnTracksEnrollmentRequestV1 {
    OwnTracksEnrollmentRequestV1::new(
        timeline,
        entity,
        GeoLocationAdmissionFenceV1::new(1, ([1; 32], 2, [2; 32]), (1, false, epoch)),
        verifier,
    )
}

fn assert_enrollment_contract<S>(store: &mut S)
where
    S: EventStore + OwnTracksEnrollmentStore,
{
    assert_eq!(
        store.owntracks_enrollment_status().unwrap().status(),
        OwnTracksEnrollmentStatusV1::Absent
    );
    assert_eq!(
        store
            .owntracks_enrollment_status()
            .unwrap()
            .policy_version(),
        None
    );

    let timeline = store.create_timeline("owntracks-enrollment").unwrap();
    let entity = EntityId::new();
    assert_eq!(
        store
            .pair_owntracks_enrollment(request(timeline.id(), entity, 3, [3; 32]))
            .unwrap(),
        OwnTracksEnrollmentStatusV1::Active
    );
    let active = store.owntracks_enrollment_status().unwrap();
    assert_eq!(active.status(), OwnTracksEnrollmentStatusV1::Active);
    assert_eq!(active.policy_version(), Some(1));

    assert!(store
        .pair_owntracks_enrollment(request(timeline.id(), entity, 4, [4; 32]))
        .is_err());
    assert_eq!(
        store.owntracks_enrollment_status().unwrap().status(),
        OwnTracksEnrollmentStatusV1::Active
    );

    assert_eq!(
        store.rotate_owntracks_enrollment_verifier([5; 32]).unwrap(),
        OwnTracksEnrollmentStatusV1::Active
    );
    assert_eq!(
        store.revoke_owntracks_enrollment().unwrap(),
        OwnTracksEnrollmentStatusV1::Revoked
    );
    assert_eq!(
        store.owntracks_enrollment_status().unwrap().status(),
        OwnTracksEnrollmentStatusV1::Revoked
    );
    assert!(store.rotate_owntracks_enrollment_verifier([6; 32]).is_err());

    assert_eq!(
        store
            .pair_owntracks_enrollment(request(timeline.id(), entity, 5, [7; 32]))
            .unwrap(),
        OwnTracksEnrollmentStatusV1::Active
    );
}

#[test]
fn memory_enrollment_contract() {
    assert_enrollment_contract(&mut MemoryStore::new());
}

#[test]
fn sqlite_enrollment_contract() {
    assert_enrollment_contract(&mut SqliteStore::open_in_memory().unwrap());
}
