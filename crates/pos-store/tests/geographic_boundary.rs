use pos_core::geo_admission::GeoLocationAdmissionStore;
use pos_core::{
    CanonicalBytes, ConsentAuthority, ConsentGrantedV1, ConsentRevokedV1, EntityId, Event,
    EventDraft, EventId, Kind, SchemaVersion, Seq, SeqRange, Timeline, TimelineMeta, WallTime,
};
use pos_store::{
    import_timeline, import_timeline_with_id, memory::MemoryStore, AppendDedupKey,
    AppendDedupScope, AppendIdentity, EventStore, TimelineExport,
};
use std::num::NonZeroUsize;

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
            ConsentAuthority::new().append_permit(),
            10,
        )
        .is_err());
}

fn assert_consent_coordinate_mismatch_is_closed<S: EventStore + GeoLocationAdmissionStore>(
    store: &mut S,
) {
    let timeline = store
        .create_timeline("consent-coordinate-mismatch")
        .test_ok();
    let authority = ConsentAuthority::new();
    store
        .bind_consent_authority(authority.append_permit())
        .test_ok();
    let permit = authority.append_permit();
    assert_eq!(
        store.protected_logical_head(timeline.id()).test_ok(),
        Seq::from_u64(0)
    );
    let subject = EntityId::new();
    let grant = ConsentGrantedV1 {
        subject_id: subject,
        grantee_id: EntityId::new(),
        purpose: "coordinate-check".to_owned(),
        modalities: pos_core::MODALITY_LOCATION,
        min_geo_resolution: 1,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: 1,
    };
    let grant_draft = EventDraft::new(
        EntityId::new(),
        Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
        grant.encode().test_ok(),
    );
    let foreign_permit = ConsentAuthority::new().append_permit();
    assert!(store
        .append_consent_bounded(
            timeline.id(),
            std::slice::from_ref(&grant_draft),
            foreign_permit,
            10,
        )
        .test_err()
        .to_string()
        .contains("does not match the bound authority"));
    assert!(store
        .append_consent_bounded(timeline.id(), &[grant_draft], permit, 10,)
        .test_err()
        .to_string()
        .contains("coordinate mismatch"));

    let revocation = ConsentRevokedV1 {
        subject_id: subject,
        grantee_id: grant.grantee_id,
        grant_seq: grant.grant_seq,
        fence_seq: 1,
    };
    let revocation_draft = EventDraft::new(
        EntityId::new(),
        Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
        revocation.encode().test_ok(),
    );
    assert!(store
        .append_consent_bounded(timeline.id(), &[revocation_draft], permit, 10,)
        .test_err()
        .to_string()
        .contains("coordinate mismatch"));
}

fn assert_bounded_scope_withdrawal<S: EventStore>(store: &mut S) {
    let timeline = store.create_timeline("bounded-withdrawal").test_ok();
    let scope = AppendDedupScope::from_keyed_hash([8; 32]);
    for key in [9, 10] {
        store
            .append_or_duplicate(
                timeline.id(),
                AppendIdentity::new(AppendDedupKey::from_keyed_hash([key; 32]), scope),
                WallTime::from_micros(u64::from(key)),
                EventDraft::new(
                    EntityId::new(),
                    Kind::new("ordinary.bounded-withdrawal"),
                    CanonicalBytes::from_static(b"payload"),
                ),
            )
            .test_ok();
    }
    let first = store
        .remove_append_identities_bounded(scope, NonZeroUsize::new(1).test_ok())
        .test_ok();
    assert_eq!(first.removed, 1);
    assert!(first.more_may_remain);
    let second = store
        .remove_append_identities_bounded(scope, NonZeroUsize::new(1).test_ok())
        .test_ok();
    assert_eq!(second.removed, 1);
    assert!(!second.more_may_remain);
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
fn memory_consent_coordinate_validation_is_closed() {
    assert_consent_coordinate_mismatch_is_closed(&mut MemoryStore::default());
}

#[test]
fn sqlite_consent_coordinate_validation_is_closed() {
    let mut store = pos_store::sqlite::SqliteStore::open_in_memory().test_ok();
    assert_consent_coordinate_mismatch_is_closed(&mut store);
}

#[test]
fn memory_bounded_scope_withdrawal_reports_remaining_work() {
    assert_bounded_scope_withdrawal(&mut MemoryStore::default());
}

#[test]
fn sqlite_bounded_scope_withdrawal_reports_remaining_work() {
    let mut store = pos_store::sqlite::SqliteStore::open_in_memory().test_ok();
    assert_bounded_scope_withdrawal(&mut store);
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
