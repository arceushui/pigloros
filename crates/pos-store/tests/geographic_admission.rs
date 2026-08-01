use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use pos_core::{
    geo_admission::{
        GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
        GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
        GeoLocationReplayVerifier,
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
    request_with_epoch(timeline, entity, 9, dedup)
}

fn request_with_epoch(
    timeline: TimelineId,
    entity: EntityId,
    admission_epoch: u64,
    dedup: ([u8; 32], [u8; 32]),
) -> GeoLocationAdmissionRequestV1 {
    request_with_admission_state(
        timeline,
        entity,
        AdmissionState {
            policy: (1, false, admission_epoch),
            ..initial_admission_state()
        },
        dedup,
    )
}

#[derive(Clone, Copy)]
struct AdmissionState {
    binding_revision: u64,
    consent: ([u8; 32], u64, [u8; 32]),
    policy: (u32, bool, u64),
}

impl AdmissionState {
    fn fence(self) -> GeoLocationAdmissionFenceV1 {
        GeoLocationAdmissionFenceV1::new(self.binding_revision, self.consent, self.policy)
    }
}

fn request_with_admission_state(
    timeline: TimelineId,
    entity: EntityId,
    state: AdmissionState,
    dedup: ([u8; 32], [u8; 32]),
) -> GeoLocationAdmissionRequestV1 {
    GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
        timeline,
        entity,
        CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
        state.binding_revision,
        state.consent,
        state.policy,
        dedup,
    ))
}

fn fence() -> GeoLocationAdmissionFenceV1 {
    GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9))
}

fn initial_admission_state() -> AdmissionState {
    AdmissionState {
        binding_revision: 7,
        consent: ([1; 32], 8, [2; 32]),
        policy: (1, false, 9),
    }
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

struct FenceReplacingClock {
    store: SqliteStore,
    timeline: TimelineId,
    entity: EntityId,
    replacement: GeoLocationAdmissionFenceV1,
    replaced: Arc<AtomicBool>,
}

impl FenceReplacingClock {
    fn new(
        path: &str,
        timeline: TimelineId,
        entity: EntityId,
        replacement: GeoLocationAdmissionFenceV1,
        replaced: Arc<AtomicBool>,
    ) -> Self {
        Self {
            store: SqliteStore::open(path).unwrap(),
            timeline,
            entity,
            replacement,
            replaced,
        }
    }
}

impl AdmissionClock for FenceReplacingClock {
    fn now(&mut self) -> Result<WallTime, CoreError> {
        if !self.replaced.load(Ordering::Relaxed) {
            self.store.set_geo_location_admission_fence(
                self.timeline,
                self.entity,
                self.replacement.clone(),
            )?;
            self.replaced.store(true, Ordering::Relaxed);
        }
        Ok(WallTime::from_micros(1))
    }
}

struct CountingFixedClock(Arc<AtomicBool>);

impl AdmissionClock for CountingFixedClock {
    fn now(&mut self) -> Result<WallTime, CoreError> {
        self.0.store(true, Ordering::Relaxed);
        Ok(WallTime::from_micros(1))
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

fn assert_replaced_fence_rejects_stale_epoch<S>(store: &mut S)
where
    S: EventStore + GeoLocationAdmissionAdmin + GeoLocationAdmissionStore,
{
    let timeline = store.create_timeline("re-pair").unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    let stale = request(timeline.id(), entity, ([4; 32], [5; 32]));
    store
        .set_geo_location_admission_fence(
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 10)),
        )
        .unwrap();

    assert!(matches!(
        store.admit_geo_location(stale),
        Err(pos_core::CoreError::GeographicAdmissionValidationFailed)
    ));
    assert!(store
        .admit_geo_location(request_with_epoch(
            timeline.id(),
            entity,
            10,
            ([4; 32], [5; 32]),
        ))
        .unwrap()
        .is_accepted());
}

fn assert_each_reconsent_field_rejects_stale_admission<S>(store: &mut S)
where
    S: EventStore + GeoLocationAdmissionAdmin + GeoLocationAdmissionStore,
{
    let initial = initial_admission_state();
    let replacements = [
        AdmissionState {
            binding_revision: 12,
            ..initial
        },
        AdmissionState {
            consent: ([3; 32], 8, [2; 32]),
            ..initial
        },
        AdmissionState {
            consent: ([1; 32], 11, [2; 32]),
            ..initial
        },
        AdmissionState {
            consent: ([1; 32], 8, [4; 32]),
            ..initial
        },
        AdmissionState {
            policy: (2, false, 9),
            ..initial
        },
        AdmissionState {
            policy: (1, false, 10),
            ..initial
        },
    ];

    for (index, replacement) in replacements.into_iter().enumerate() {
        let timeline = store.create_timeline("re-consent-field").unwrap();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, initial.fence())
            .unwrap();
        let stale =
            request_with_admission_state(timeline.id(), entity, initial, ([4; 32], [5; 32]));
        store
            .set_geo_location_admission_fence(timeline.id(), entity, replacement.fence())
            .unwrap();

        assert!(matches!(
            store.admit_geo_location(stale),
            Err(CoreError::GeographicAdmissionValidationFailed)
        ));
        assert!(store
            .admit_geo_location(request_with_admission_state(
                timeline.id(),
                entity,
                replacement,
                ([6 + index as u8; 32], [7 + index as u8; 32]),
            ))
            .unwrap()
            .is_accepted());
    }
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
fn sqlite_rejects_a_missing_fence_before_consulting_the_admission_clock() {
    let called = Arc::new(AtomicBool::new(false));
    let mut store = SqliteStore::open_with_clock(
        ":memory:",
        Box::new(CountingFixedClock(Arc::clone(&called))),
    )
    .unwrap();
    let timeline = store.create_timeline("missing-fence-before-clock").unwrap();

    assert!(matches!(
        store.admit_geo_location(request(timeline.id(), EntityId::new(), ([4; 32], [5; 32]))),
        Err(CoreError::GeographicAdmissionValidationFailed)
    ));
    assert!(!called.load(Ordering::Relaxed));
}

#[test]
fn sqlite_rechecks_a_revoked_fence_before_committing_geographic_admission() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut setup = SqliteStore::open(path).unwrap();
    let timeline = setup.create_timeline("recheck-revoked-fence").unwrap();
    let original_timeline = timeline.clone();
    let entity = EntityId::new();
    let revoked = Arc::new(AtomicBool::new(false));
    setup
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    drop(setup);

    let mut store = SqliteStore::open_with_clock(
        path,
        Box::new(FenceReplacingClock::new(
            path,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, true, 10)),
            Arc::clone(&revoked),
        )),
    )
    .unwrap();
    let error = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap_err();
    assert!(matches!(
        error,
        CoreError::GeographicAdmissionValidationFailed
    ));
    assert!(revoked.load(Ordering::Relaxed));

    assert!(store
        .read(timeline.id(), pos_core::SeqRange::all())
        .unwrap()
        .is_empty());
    assert_eq!(
        store.get_timeline(timeline.id()).unwrap(),
        Some(original_timeline)
    );
    let mut reopened = SqliteStore::open(path).unwrap();
    assert!(matches!(
        reopened.admit_geo_location(request(timeline.id(), entity, ([6; 32], [7; 32]))),
        Err(CoreError::GeographicAdmissionValidationFailed)
    ));
}

#[test]
fn sqlite_rechecks_a_reconsented_fence_before_committing_geographic_admission() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut setup = SqliteStore::open(path).unwrap();
    let timeline = setup.create_timeline("recheck-reconsented-fence").unwrap();
    let original_timeline = timeline.clone();
    let entity = EntityId::new();
    let replaced = Arc::new(AtomicBool::new(false));
    setup
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    drop(setup);

    let replacement = AdmissionState {
        binding_revision: 12,
        consent: ([3; 32], 11, [4; 32]),
        policy: (2, false, 10),
    };
    let mut store = SqliteStore::open_with_clock(
        path,
        Box::new(FenceReplacingClock::new(
            path,
            timeline.id(),
            entity,
            replacement.fence(),
            Arc::clone(&replaced),
        )),
    )
    .unwrap();
    assert!(matches!(
        store.admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32]))),
        Err(CoreError::GeographicAdmissionValidationFailed)
    ));
    assert!(replaced.load(Ordering::Relaxed));
    assert!(store
        .read(timeline.id(), pos_core::SeqRange::all())
        .unwrap()
        .is_empty());
    assert_eq!(
        store.get_timeline(timeline.id()).unwrap(),
        Some(original_timeline)
    );
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
fn memory_replaced_geographic_fence_rejects_stale_epoch() {
    assert_replaced_fence_rejects_stale_epoch(&mut MemoryStore::default());
}

#[test]
fn sqlite_replaced_geographic_fence_rejects_stale_epoch() {
    assert_replaced_fence_rejects_stale_epoch(&mut SqliteStore::open_in_memory().unwrap());
}

#[test]
fn memory_reconsent_fields_reject_stale_admission() {
    assert_each_reconsent_field_rejects_stale_admission(&mut MemoryStore::default());
}

#[test]
fn sqlite_reconsent_fields_reject_stale_admission() {
    assert_each_reconsent_field_rejects_stale_admission(
        &mut SqliteStore::open_in_memory().unwrap(),
    );
}

#[test]
fn sqlite_replay_verifier_accepts_only_the_exact_durable_snapshot_link() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("replay-verifier").unwrap();
    let entity = EntityId::new();
    store
        .set_geo_location_admission_fence(timeline.id(), entity, fence())
        .unwrap();
    let accepted = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .unwrap();
    let event_id = accepted.event_id().unwrap();
    let event_seq = accepted.event_seq().unwrap();
    let timeline_id = timeline.id().to_string();
    let event_id_text = event_id.to_string();
    let inspection = rusqlite::Connection::open(path).unwrap();
    let (event_hash, snapshot_cbor): (Vec<u8>, Vec<u8>) = inspection
        .query_row(
            "SELECT event.payload_hash, snapshot.snapshot_cbor
             FROM events AS event
             JOIN geographic_admission_snapshots AS snapshot ON snapshot.event_id = event.event_id
             JOIN geographic_admission_links AS link
               ON link.timeline_id = event.timeline_id AND link.event_id = event.event_id
             WHERE event.timeline_id = ?1 AND event.event_id = ?2",
            [&timeline_id, &event_id_text],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let event_hash = pos_core::Hash::from_bytes(event_hash.try_into().unwrap());
    let snapshot_hash = pos_crypto::chain::hash_payload(&CanonicalBytes::from_vec(snapshot_cbor));
    let evidence = |event_seq, event_payload_hash, expected_snapshot_hash| {
        GeoLocationReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            event_payload_hash,
            expected_snapshot_hash,
        )
    };

    store
        .set_geo_location_admission_fence(
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, true, 10)),
        )
        .unwrap();
    assert!(store
        .verify_v1_event_snapshot_link(evidence(event_seq, event_hash, snapshot_hash))
        .is_ok());
    assert!(store
        .verify_v1_event_snapshot_link(evidence(event_seq.next(), event_hash, snapshot_hash))
        .unwrap_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert!(store
        .verify_v1_event_snapshot_link(evidence(
            event_seq,
            pos_core::Hash::from_bytes([0; 32]),
            snapshot_hash,
        ))
        .unwrap_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert!(store
        .verify_v1_event_snapshot_link(evidence(
            event_seq,
            event_hash,
            pos_core::Hash::from_bytes([0; 32]),
        ))
        .unwrap_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert_eq!(
        inspection
            .execute(
                "UPDATE events SET entity_id = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
                rusqlite::params![EntityId::new().to_string(), &timeline_id, &event_id_text],
            )
            .unwrap(),
        1
    );
    assert!(store
        .verify_v1_event_snapshot_link(evidence(event_seq, event_hash, snapshot_hash))
        .unwrap_err()
        .to_string()
        .contains("geographic admission validation failed"));
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
