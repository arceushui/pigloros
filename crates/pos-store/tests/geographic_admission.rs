use std::collections::VecDeque;

use pos_core::{
    geo_admission::{
        GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
        GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
    },
    AdmissionClock, CanonicalBytes, CoreError, EntityId, EventStore, TimelineId, WallTime,
    APPEND_IDENTITY_RETENTION_MICROS,
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

struct SequenceClock(VecDeque<WallTime>);

impl SequenceClock {
    fn new(values: impl IntoIterator<Item = WallTime>) -> Self {
        Self(values.into_iter().collect())
    }
}

impl AdmissionClock for SequenceClock {
    fn now(&mut self) -> Result<WallTime, CoreError> {
        self.0
            .pop_front()
            .ok_or_else(|| CoreError::Storage("test clock exhausted".to_owned()))
    }
}

fn assert_expired_dedup_allows_one_new_admission<S>(store: &mut S)
where
    S: EventStore + GeoLocationAdmissionAdmin + GeoLocationAdmissionStore,
{
    let timeline = store.create_timeline("dedup-expiry").unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    let first = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap();
    let after_expiry = store
        .admit_geo_location(request(timeline.id(), entity, ([6; 32], [5; 32])))
        .unwrap();
    assert!(first.is_accepted());
    assert!(after_expiry.is_accepted());
    assert_ne!(first.event_id(), after_expiry.event_id());
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
fn memory_expired_geographic_dedup_allows_one_new_admission() {
    let mut store = MemoryStore::with_clock(Box::new(SequenceClock::new([
        WallTime::from_micros(1),
        WallTime::from_micros(APPEND_IDENTITY_RETENTION_MICROS.saturating_add(2)),
    ])));
    assert_expired_dedup_allows_one_new_admission(&mut store);
}

#[test]
fn sqlite_expired_geographic_dedup_allows_one_new_admission() {
    let mut store = SqliteStore::open_with_clock(
        ":memory:",
        Box::new(SequenceClock::new([
            WallTime::from_micros(1),
            WallTime::from_micros(APPEND_IDENTITY_RETENTION_MICROS.saturating_add(2)),
        ])),
    )
    .unwrap();
    assert_expired_dedup_allows_one_new_admission(&mut store);
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

#[test]
fn sqlite_rejects_a_preexisting_unlinked_geographic_marker_before_deduplication() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("unlinked-geographic-state").unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    rusqlite::Connection::open(path)
        .unwrap()
        .execute(
            "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)",
            [timeline.id().to_string()],
        )
        .unwrap();

    let error = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap_err();
    assert!(matches!(
        error,
        pos_core::CoreError::GeographicAdmissionValidationFailed
    ));
}

#[test]
fn sqlite_rejects_an_orphaned_geographic_snapshot_before_deduplication() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store
        .create_timeline("orphaned-geographic-snapshot")
        .unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    rusqlite::Connection::open(path)
        .unwrap()
        .execute(
            "INSERT INTO geographic_admission_snapshots (event_id, snapshot_cbor) VALUES (?1, ?2)",
            ["orphaned-event", "orphaned-snapshot"],
        )
        .unwrap();

    let error = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap_err();
    assert!(matches!(
        error,
        pos_core::CoreError::GeographicAdmissionValidationFailed
    ));
}
