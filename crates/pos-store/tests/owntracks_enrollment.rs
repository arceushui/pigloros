use pos_core::{
    EntityId, EventStore, GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1,
    OwnTracksEnrollmentStatusV1, OwnTracksEnrollmentStore,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected enrollment fixture error: {error:?}"
            )))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| {
            std::panic::resume_unwind(Box::new("missing enrollment fixture value"))
        })
    }
}

const fn request(
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
        store.owntracks_enrollment_status().test_ok().status(),
        OwnTracksEnrollmentStatusV1::Absent
    );
    assert_eq!(
        store
            .owntracks_enrollment_status()
            .test_ok()
            .policy_version(),
        None
    );

    let timeline = store.create_timeline("owntracks-enrollment").test_ok();
    let entity = EntityId::new();
    assert_eq!(
        store
            .pair_owntracks_enrollment(request(timeline.id(), entity, 3, [3; 32]))
            .test_ok(),
        OwnTracksEnrollmentStatusV1::Active
    );
    let active = store.owntracks_enrollment_status().test_ok();
    assert_eq!(active.status(), OwnTracksEnrollmentStatusV1::Active);
    assert_eq!(active.policy_version(), Some(1));

    assert!(store
        .pair_owntracks_enrollment(request(timeline.id(), entity, 4, [4; 32]))
        .is_err());
    assert_eq!(
        store.owntracks_enrollment_status().test_ok().status(),
        OwnTracksEnrollmentStatusV1::Active
    );

    assert_eq!(
        store
            .rotate_owntracks_enrollment_verifier([5; 32])
            .test_ok(),
        OwnTracksEnrollmentStatusV1::Active
    );
    assert_eq!(
        store.revoke_owntracks_enrollment().test_ok(),
        OwnTracksEnrollmentStatusV1::Revoked
    );
    assert_eq!(
        store.owntracks_enrollment_status().test_ok().status(),
        OwnTracksEnrollmentStatusV1::Revoked
    );
    assert!(store.rotate_owntracks_enrollment_verifier([6; 32]).is_err());

    assert_eq!(
        store
            .pair_owntracks_enrollment(request(timeline.id(), entity, 5, [7; 32]))
            .test_ok(),
        OwnTracksEnrollmentStatusV1::Active
    );
}

#[test]
fn memory_enrollment_contract() {
    assert_enrollment_contract(&mut MemoryStore::new());
}

#[test]
fn sqlite_enrollment_contract() {
    assert_enrollment_contract(&mut SqliteStore::open_in_memory().test_ok());
}

fn assert_deleting_enrolled_timeline_revokes<S>(store: &mut S)
where
    S: EventStore + OwnTracksEnrollmentStore,
{
    let timeline = store.create_timeline("delete-enrolled").test_ok();
    store
        .pair_owntracks_enrollment(request(timeline.id(), EntityId::new(), 3, [8; 32]))
        .test_ok();
    store.delete_timeline(timeline.id()).test_ok();
    assert_eq!(
        store.owntracks_enrollment_status().test_ok().status(),
        OwnTracksEnrollmentStatusV1::Revoked
    );
}

#[test]
fn deleting_memory_enrolled_timeline_revokes_enrollment() {
    assert_deleting_enrolled_timeline_revokes(&mut MemoryStore::new());
}

#[test]
fn deleting_sqlite_enrolled_timeline_revokes_enrollment() {
    assert_deleting_enrolled_timeline_revokes(&mut SqliteStore::open_in_memory().test_ok());
}
