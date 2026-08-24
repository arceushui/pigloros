use pos_core::{
    CanonicalBytes, EntityId, Event, EventDraft, EventId, Kind, SchemaVersion, Seq, SeqRange,
    Timeline, TimelineMeta, WallTime,
};
use pos_store::{
    import_timeline, import_timeline_with_id, memory::MemoryStore, AppendDedupKey,
    AppendDedupScope, AppendIdentity, EventStore, TimelineExport,
};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected store fixture error: {error:?}"
            )))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing store fixture value")))
    }
}

trait TestErrorExt<T, E> {
    fn test_err(self) -> E;
}

impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
    fn test_err(self) -> E {
        match self {
            Ok(value) => std::panic::resume_unwind(Box::new(format!(
                "unexpected successful store fixture value: {value:?}"
            ))),
            Err(error) => error,
        }
    }
}

fn geographic_event(kind: &str, entity: EntityId) -> Event {
    let payload = CanonicalBytes::from_vec(b"protected".to_vec());
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(kind),
        payload: payload.clone(),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(1),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: pos_crypto::chain::hash_payload(&payload),
    }
}

fn assert_generic_geographic_admission_is_closed(store: &mut dyn EventStore) {
    let timeline = store.create_timeline("generic-admission").test_ok();
    let entity = EntityId::new();

    for kind in ["geo.location", "geo.cell"] {
        assert!(store
            .append(
                timeline.id(),
                &[EventDraft::new(
                    entity,
                    Kind::new(kind),
                    CanonicalBytes::from_vec(b"blocked".to_vec()),
                )],
            )
            .is_err());
        assert!(store
            .append_committed(timeline.id(), &[geographic_event(kind, entity)])
            .is_err());
    }

    assert!(store
        .append_or_duplicate(
            timeline.id(),
            AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([1; 32]),
                AppendDedupScope::from_keyed_hash([2; 32]),
            ),
            WallTime::from_micros(1),
            EventDraft::new(
                entity,
                Kind::new("geo.location"),
                CanonicalBytes::from_vec(b"blocked".to_vec()),
            ),
        )
        .is_err());

    store
        .append(
            timeline.id(),
            &[EventDraft::new(
                entity,
                Kind::new("ordinary.event"),
                CanonicalBytes::from_vec(b"allowed".to_vec()),
            )],
        )
        .test_ok();
    assert_eq!(
        store.read(timeline.id(), SeqRange::all()).test_ok().len(),
        1
    );

    for kind in ["geo.location", "geo.cell"] {
        let imported = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("sensitive-import")),
            events: vec![geographic_event(kind, entity)],
            parent_fork_hash: None,
        };
        assert!(import_timeline(store, imported).is_err());
        assert_eq!(store.list_timelines().test_ok().len(), 1);

        let imported = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("sensitive-import-with-id")),
            events: vec![geographic_event(kind, entity)],
            parent_fork_hash: None,
        };
        assert!(import_timeline_with_id(store, imported).is_err());
        assert_eq!(store.list_timelines().test_ok().len(), 1);
    }
}

fn assert_generic_consent_admission_is_closed(store: &mut dyn EventStore) {
    let timeline = store.create_timeline("generic-consent-admission").test_ok();
    let entity = EntityId::new();
    let draft = EventDraft::new(
        entity,
        Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
        CanonicalBytes::from_static(b"forbidden-consent-draft"),
    );

    assert!(store
        .append(timeline.id(), std::slice::from_ref(&draft))
        .is_err());
    assert!(store
        .append_bounded(timeline.id(), std::slice::from_ref(&draft), 10)
        .is_err());
    assert!(store
        .append_or_duplicate(
            timeline.id(),
            AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([3; 32]),
                AppendDedupScope::from_keyed_hash([4; 32]),
            ),
            WallTime::from_micros(1),
            draft.clone(),
        )
        .is_err());
    assert!(store
        .append_committed(
            timeline.id(),
            &[geographic_event(
                pos_core::EVENT_TYPE_CONSENT_REVOKED_V1,
                entity,
            )]
        )
        .is_err());

    assert!(store
        .append_consent_bounded(
            timeline.id(),
            &[EventDraft::new(
                entity,
                Kind::new("ordinary.event"),
                CanonicalBytes::from_static(b"not-consent"),
            )],
            10,
        )
        .is_err());
}

#[test]
fn memory_generic_geographic_admission_is_closed() {
    assert_generic_geographic_admission_is_closed(&mut MemoryStore::default());
}

#[test]
fn sqlite_generic_geographic_admission_is_closed() {
    let mut store = pos_store::sqlite::SqliteStore::open_in_memory().test_ok();
    assert_generic_geographic_admission_is_closed(&mut store);
}

#[test]
fn memory_generic_consent_admission_is_closed() {
    assert_generic_consent_admission_is_closed(&mut MemoryStore::default());
}

#[test]
fn sqlite_generic_consent_admission_is_closed() {
    let mut store = pos_store::sqlite::SqliteStore::open_in_memory().test_ok();
    assert_generic_consent_admission_is_closed(&mut store);
}

#[test]
fn sqlite_existing_geo_rows_are_detected_at_read_time_without_marker_backfill() {
    let database = tempfile::NamedTempFile::new().test_ok();
    let mut store =
        pos_store::sqlite::SqliteStore::open(database.path().to_str().test_ok()).test_ok();
    let timeline = store.create_timeline("pre-existing-v1").test_ok();
    let connection = rusqlite::Connection::open(database.path()).test_ok();
    let event = geographic_event("geo.location", EntityId::new());
    connection
        .execute(
            "INSERT INTO events (
                timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                causation_id, correlation_id, schema_version, payload_hash, signature
             ) VALUES (?1, 1, ?2, ?3, ?4, ?5, 1, NULL, NULL, 1, ?6, NULL)",
            rusqlite::params![
                timeline.id().to_string(),
                event.id.to_string(),
                event.entity.to_string(),
                event.event_type.as_str(),
                event.payload.as_slice(),
                event.payload_hash.as_bytes(),
            ],
        )
        .test_ok();
    let marker_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM geographic_presence", [], |row| {
            row.get(0)
        })
        .test_ok();
    assert_eq!(marker_count, 0);

    assert_eq!(store.root_timeline_count_bounded(1).test_ok(), 0);

    assert!(store.read(timeline.id(), SeqRange::all()).is_err());
    let marker_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM geographic_presence", [], |row| {
            row.get(0)
        })
        .test_ok();
    assert_eq!(marker_count, 0);
}

#[test]
fn sqlite_public_adapter_still_reads_ordinary_events() {
    let mut store = pos_store::sqlite::SqliteStore::open_in_memory().test_ok();
    let timeline = store.create_timeline("ordinary").test_ok();
    store
        .append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("ordinary.event"),
                CanonicalBytes::from_vec(b"payload".to_vec()),
            )],
        )
        .test_ok();
    assert_eq!(
        store.read(timeline.id(), SeqRange::all()).test_ok().len(),
        1
    );
}

#[test]
fn sqlite_event_id_lookup_propagates_storage_errors() {
    let database = tempfile::NamedTempFile::new().test_ok();
    let mut store =
        pos_store::sqlite::SqliteStore::open(database.path().to_str().test_ok()).test_ok();
    let timeline = store.create_timeline("event-id-storage-error").test_ok();
    let connection = rusqlite::Connection::open(database.path()).test_ok();
    connection.execute("DROP TABLE events", []).test_ok();

    assert!(store
        .read_event_by_id(timeline.id(), EventId::new())
        .test_err()
        .to_string()
        .contains("storage error"));
}
