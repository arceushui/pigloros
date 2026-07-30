use pos_core::{
    CanonicalBytes, EntityId, Event, EventDraft, EventId, Kind, SchemaVersion, Seq, SeqRange,
    WallTime,
};
use pos_store::{
    memory::MemoryStore, open_store, AppendDedupKey, AppendDedupScope, AppendIdentity, EventStore,
    GeographicEvidenceStore, StoreConfig,
};

#[test]
fn sqlite_public_seams_execute_non_test_adapter_paths() {
    let mut store = open_store(StoreConfig::SqliteInMemory).unwrap();
    let timeline = store.create_timeline("public-boundary").unwrap();
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("public.event"),
        CanonicalBytes::from_vec(b"payload".to_vec()),
    );
    store.append(timeline.id(), &[draft]).unwrap();
    assert_eq!(store.list_timelines().unwrap().len(), 1);
    assert_eq!(store.root_timeline_count_bounded(4).unwrap(), 1);
    assert_eq!(store.read(timeline.id(), SeqRange::all()).unwrap().len(), 1);
}

#[test]
fn public_adapter_constructors_execute_normal_library_instances() {
    let _memory_with_hasher = MemoryStore::with_hasher(Box::new(pos_crypto::chain::Blake3Hasher));
    let _memory = MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(
        WallTime::from_micros(1),
    )));
    pos_store::sqlite::SqliteStore::open_in_memory().unwrap();
    pos_store::sqlite::SqliteStore::open_with_clock(
        ":memory:",
        Box::new(pos_core::FixedAdmissionClock(WallTime::from_micros(1))),
    )
    .unwrap();
}

#[test]
fn memory_public_seams_cover_owned_range_and_identified_deletion() {
    let mut store = MemoryStore::default();
    let readable = store.create_timeline("memory-owned-range").unwrap();
    store
        .append(
            readable.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("public.event"),
                CanonicalBytes::from_vec(b"payload".to_vec()),
            )],
        )
        .unwrap();
    assert_eq!(
        store
            .read_own(
                readable.id(),
                SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
            )
            .unwrap()
            .len(),
        1
    );

    let deletable = store.create_timeline("memory-identified-deletion").unwrap();
    store
        .append_or_duplicate(
            deletable.id(),
            AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([9; 32]),
                AppendDedupScope::from_keyed_hash([9; 32]),
            ),
            WallTime::from_micros(9),
            EventDraft::new(
                EntityId::new(),
                Kind::new("public.event"),
                CanonicalBytes::from_vec(b"identified".to_vec()),
            ),
        )
        .unwrap();
    store.delete_timeline(deletable.id()).unwrap();
}

#[test]
fn sqlite_open_fails_closed_when_the_current_schema_cannot_be_initialized() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute("CREATE TABLE events (unexpected_column INTEGER)", [])
        .unwrap();
    drop(connection);

    assert!(pos_store::sqlite::SqliteStore::open(database.path().to_str().unwrap()).is_err());
}

#[test]
fn sqlite_fork_fails_closed_for_an_unknown_parent() {
    let mut store = pos_store::sqlite::SqliteStore::open_in_memory().unwrap();

    assert!(store
        .fork(pos_core::TimelineId::new(), Seq::ZERO, "missing-parent")
        .is_err());
}

fn run_geographic_boundary<S: EventStore + GeographicEvidenceStore>(store: &mut S) {
    let parent = store.create_timeline("geo-parent").unwrap();
    let entity = EntityId::new();
    let ordinary_id = append_ordinary_event(store, parent.id(), entity);
    assert!(store
        .read_event_by_id(parent.id(), ordinary_id)
        .unwrap()
        .is_some());
    assert!(store.chain_hash_at(parent.id(), Seq::from_u64(1)).is_ok());
    let child = store
        .fork(parent.id(), Seq::from_u64(1), "geo-child")
        .unwrap();
    let geo = geographic_event(entity);
    let geo_id = geo.id;
    store
        .append_committed(parent.id(), std::slice::from_ref(&geo))
        .unwrap();

    assert_append_paths_are_closed(store, parent.id(), entity, &geo);
    assert_generic_paths_are_closed(store, parent.id(), child.id(), entity, geo_id);
    assert_privileged_projector_contract(store, parent.id(), child.id(), geo_id, ordinary_id);
}

fn append_ordinary_event(
    store: &mut dyn EventStore,
    timeline: pos_core::TimelineId,
    entity: EntityId,
) -> EventId {
    store
        .append(
            timeline,
            &[EventDraft::new(
                entity,
                Kind::new("ordinary.event"),
                CanonicalBytes::from_vec(b"ordinary".to_vec()),
            )],
        )
        .unwrap()
        .first()
        .expect("ordinary event appended")
        .id
}

fn geographic_event(entity: EntityId) -> Event {
    let payload = CanonicalBytes::from_vec(b"protected".to_vec());
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new("geo.location"),
        payload: payload.clone(),
        wall_time: WallTime::from_micros(2),
        seq: Seq::from_u64(2),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: pos_crypto::chain::hash_payload(&payload),
    }
}

fn assert_append_paths_are_closed(
    store: &mut dyn EventStore,
    parent: pos_core::TimelineId,
    entity: EntityId,
    geo: &Event,
) {
    assert!(store.append_committed(parent, &[]).is_err());
    assert!(store
        .append_committed(parent, std::slice::from_ref(geo))
        .is_err());
    assert!(store
        .append(
            parent,
            &[EventDraft::new(
                entity,
                Kind::new("geo.location"),
                CanonicalBytes::from_vec(b"blocked-geographic".to_vec()),
            )],
        )
        .is_err());
    assert!(store
        .append_or_duplicate(
            parent,
            AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([3; 32]),
                AppendDedupScope::from_keyed_hash([4; 32]),
            ),
            WallTime::from_micros(4),
            EventDraft::new(
                entity,
                Kind::new("ordinary.event"),
                CanonicalBytes::from_vec(b"blocked".to_vec()),
            ),
        )
        .is_err());
}

fn assert_generic_paths_are_closed<S: EventStore + GeographicEvidenceStore>(
    store: &mut S,
    parent: pos_core::TimelineId,
    child: pos_core::TimelineId,
    entity: EntityId,
    geo_id: EventId,
) {
    for timeline in [parent, child] {
        assert!(store.read(timeline, SeqRange::all()).is_err());
        assert!(store.read_own(timeline, SeqRange::all()).is_err());
        assert!(store
            .read_bounded(
                timeline,
                SeqRange::all(),
                pos_core::EventReadBounds::new(1024, 1024, 8, 8),
            )
            .is_err());
        assert!(store.read_event_by_id(timeline, geo_id).is_err());
        assert!(store.chain_hash_at(timeline, Seq::from_u64(1)).is_err());
        assert!(store.delete_timeline(timeline).is_err());
        assert!(pos_core::export_timeline(store, timeline).is_err());
    }
    assert!(store.fork(parent, Seq::from_u64(1), "denied").is_err());
    assert!(store
        .append(
            parent,
            &[EventDraft::new(
                entity,
                Kind::new("ordinary.event"),
                CanonicalBytes::from_vec(b"blocked".to_vec()),
            )],
        )
        .is_err());
    assert!(store
        .append_or_duplicate(
            parent,
            AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([1; 32]),
                AppendDedupScope::from_keyed_hash([2; 32]),
            ),
            WallTime::from_micros(3),
            EventDraft::new(
                entity,
                Kind::new("geo.location"),
                CanonicalBytes::from_vec(b"blocked".to_vec()),
            ),
        )
        .is_err());
    assert_unknown_timeline_paths_are_closed(store, entity);
    assert_eq!(store.list_timelines().unwrap().len(), 0);
}

fn assert_unknown_timeline_paths_are_closed<S: EventStore + GeographicEvidenceStore>(
    store: &mut S,
    entity: EntityId,
) {
    let unknown = pos_core::TimelineId::new();
    assert!(store
        .append(unknown, &[ordinary_draft(entity, b"unknown")])
        .is_err());
    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .audit(store, unknown, EventId::new())
        .is_err());
    assert!(store.chain_hash_at(unknown, Seq::ZERO).is_err());
    assert!(store.delete_timeline(unknown).is_err());
}

fn ordinary_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
    EventDraft::new(
        entity,
        Kind::new("ordinary.event"),
        CanonicalBytes::from_vec(payload.to_vec()),
    )
}

fn assert_privileged_projector_contract<S: GeographicEvidenceStore>(
    store: &S,
    parent: pos_core::TimelineId,
    child: pos_core::TimelineId,
    geo_id: EventId,
    ordinary_id: EventId,
) {
    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .project_bounded(
            store,
            parent,
            pos_core::EventReadBounds::new(1024, 1024, 8, 8),
        )
        .is_ok());
    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .audit(store, parent, geo_id)
        .is_ok());
    let projector = pos_core::CoreGeographicVisibilityProjector::new();
    assert!(projector.audit(store, parent, EventId::new()).is_err());
    assert!(projector.audit(store, parent, ordinary_id).is_err());
    assert!(projector.audit(store, child, geo_id).is_err());
    assert!(projector.audit(store, child, ordinary_id).is_err());
}

#[test]
fn memory_and_sqlite_match_geographic_boundary_contract() {
    let mut memory = MemoryStore::default();
    run_geographic_boundary(&mut memory);
    run_geographic_boundary(&mut pos_store::sqlite::SqliteStore::open_in_memory().unwrap());
}

#[test]
fn privileged_memory_lookup_fails_closed_for_an_unknown_timeline() {
    let store = MemoryStore::default();

    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .audit(&store, pos_core::TimelineId::new(), EventId::new())
        .is_err());
}

fn sqlite_file_store() -> (tempfile::NamedTempFile, pos_store::sqlite::SqliteStore) {
    let database = tempfile::NamedTempFile::new().unwrap();
    let store = pos_store::sqlite::SqliteStore::open(database.path().to_str().unwrap()).unwrap();
    (database, store)
}

#[test]
fn sqlite_privileged_lookup_propagates_missing_event_table() {
    let (database, mut store) = sqlite_file_store();
    let timeline = store.create_timeline("missing-table").unwrap();
    let event = append_ordinary_event(&mut store, timeline.id(), EntityId::new());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection.execute("DROP TABLE events", []).unwrap();

    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .audit(&store, timeline.id(), event)
        .is_err());

    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .project_bounded(
            &store,
            timeline.id(),
            pos_core::EventReadBounds::new(1024, 1024, 8, 8),
        )
        .is_err());
}

#[test]
fn sqlite_marker_corruption_fails_closed_from_the_public_adapter() {
    let (database, mut store) = sqlite_file_store();
    let timeline = store.create_timeline("missing-marker").unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute("DROP TABLE geographic_presence", [])
        .unwrap();

    assert!(store.read(timeline.id(), SeqRange::all()).is_err());
}

#[test]
fn sqlite_privileged_lookup_propagates_malformed_event_payload() {
    let (database, mut store) = sqlite_file_store();
    let timeline = store.create_timeline("malformed-payload").unwrap();
    let event = append_ordinary_event(&mut store, timeline.id(), EntityId::new());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE events SET payload = 1 WHERE event_id = ?1",
            [event.to_string()],
        )
        .unwrap();

    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .audit(&store, timeline.id(), event)
        .is_err());
}

#[test]
fn sqlite_privileged_lookup_rejects_malformed_event_sequence() {
    let (database, mut store) = sqlite_file_store();
    let timeline = store.create_timeline("malformed-sequence").unwrap();
    let event = append_ordinary_event(&mut store, timeline.id(), EntityId::new());
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE events SET seq = -1 WHERE event_id = ?1",
            [event.to_string()],
        )
        .unwrap();

    assert!(pos_core::CoreGeographicVisibilityProjector::new()
        .audit(&store, timeline.id(), event)
        .is_err());
}
