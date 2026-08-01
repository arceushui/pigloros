use pos_core::{
    geo_admission::{
        GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
        GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
    },
    CanonicalBytes, EntityId, EventStore, TimelineId,
};
use pos_store::memory::MemoryStore;
use pos_store::sqlite::SqliteStore;

fn request(
    timeline: TimelineId,
    entity: EntityId,
    dedup: ([u8; 32], [u8; 32]),
) -> GeoLocationAdmissionRequestV1 {
    GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
        timeline,
        entity,
        CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
        7,
        ([1; 32], 8, [2; 32]),
        (1, false, 9),
        dedup,
    ))
}

fn fence() -> GeoLocationAdmissionFenceV1 {
    GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9))
}

fn assert_admission_contract<S>(store: &mut S)
where
    S: EventStore + GeoLocationAdmissionAdmin + GeoLocationAdmissionStore,
{
    let unfenced_timeline = store.create_timeline("unfenced-geo-admission").unwrap();
    let unfenced_entity = EntityId::new();
    let missing_fence = store
        .admit_geo_location(request(
            unfenced_timeline.id(),
            unfenced_entity,
            ([3; 32], [3; 32]),
        ))
        .unwrap_err();
    assert!(matches!(
        missing_fence,
        pos_core::CoreError::GeographicAdmissionValidationFailed
    ));
    assert!(store
        .read(unfenced_timeline.id(), pos_core::SeqRange::all())
        .unwrap()
        .is_empty());

    let timeline = store.create_timeline("geo-admission").unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();

    let accepted = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap();
    assert!(accepted.is_accepted());
    assert!(store
        .read(timeline.id(), pos_core::SeqRange::all())
        .is_err());

    let duplicate = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap();
    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.event_id(), accepted.event_id());

    let conflict = store
        .admit_geo_location(request(timeline.id(), entity, ([6; 32], [5; 32])))
        .unwrap();
    assert!(conflict.is_conflict());

    store
        .set_geo_location_admission_fence(
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, true, 10)),
        )
        .unwrap();
    let denied = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap_err();
    assert!(matches!(
        denied,
        pos_core::CoreError::GeographicAdmissionValidationFailed
    ));
    assert!(store
        .read(timeline.id(), pos_core::SeqRange::all())
        .is_err());
}

#[test]
fn memory_admission_is_atomic_and_revalidates_before_deduplication() {
    assert_admission_contract(&mut MemoryStore::default());
}

#[test]
fn sqlite_admission_is_atomic_and_revalidates_before_deduplication() {
    assert_admission_contract(&mut SqliteStore::open_in_memory().unwrap());
}

#[test]
fn sqlite_admission_rolls_back_every_artifact_when_link_write_fails() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("rollback-geo-admission").unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(
            "CREATE TRIGGER deny_geo_link BEFORE INSERT ON geographic_admission_links
             BEGIN SELECT RAISE(ABORT, 'deny geo link'); END;",
        )
        .unwrap();

    assert!(store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .is_err());
    assert!(store
        .read(timeline.id(), pos_core::SeqRange::all())
        .unwrap()
        .is_empty());

    for table in [
        "events",
        "geographic_admission_snapshots",
        "geographic_admission_links",
        "geographic_presence",
        "geographic_admission_dedup",
    ] {
        let count: i64 = inspection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back with the admission");
    }
    let head: i64 = inspection
        .query_row(
            "SELECT head_seq FROM timelines WHERE id = ?1",
            [timeline.id().to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(head, 0);
}
