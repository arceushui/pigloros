#![cfg(feature = "sqlite")]

use std::sync::Arc;

use pos_core::{
    store::SeqRange, ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, CanonicalBytes, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, EventDraft, EventId,
    EventOriginV1, KeyIdentityV1, KeyRoleV1, Kind, RegisteredArtifactV1, ReplayClaimEvaluatorV1,
    Seq, Signature, TimelineId,
};
use pos_store::{
    export_timeline, export_timeline_own, import_timeline_with_id, memory::MemoryStore,
    sqlite::SqliteStore, EventStore,
};

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([181; 32]);

fn bind_test_erasure_gate(store: &mut dyn EventStore) -> Result<(), pos_core::CoreError> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

fn export_evaluation() -> pos_core::ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([182; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn append(
    store: &mut dyn EventStore,
    timeline: TimelineId,
    value: u8,
) -> Result<Event, pos_core::CoreError> {
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("timeline.origin.v1"),
        CanonicalBytes::from_vec(vec![value]),
    );
    store
        .append(timeline, &[draft])
        .map(|mut events| events.remove(0))
}

fn assert_origin(event: &Event, owner: TimelineId, origin_seq: u64, visible_seq: u64) {
    assert_eq!(event.seq, Seq::from_u64(visible_seq));
    assert_eq!(
        event.origin,
        Some(EventOriginV1 {
            origin_timeline_id: owner,
            origin_logical_seq: Seq::from_u64(origin_seq),
        })
    );
}

fn exercise_fork_origins(
    store: &mut dyn EventStore,
) -> Result<(TimelineId, TimelineId, TimelineId), Box<dyn std::error::Error>> {
    bind_test_erasure_gate(store)?;
    let root = store.create_timeline("origin-root")?;
    let first = append(store, root.id(), 1)?;
    let second = append(store, root.id(), 2)?;
    assert_origin(&first, root.id(), 1, 1);
    assert_origin(&second, root.id(), 2, 2);

    let child = store.fork(root.id(), Seq::from_u64(2), "origin-child")?;
    let child_event = append(store, child.id(), 3)?;
    assert_origin(&child_event, child.id(), 3, 3);
    let own_child = store.read_own(child.id(), SeqRange::all())?;
    assert_eq!(own_child.len(), 1);
    assert_origin(&own_child[0], child.id(), 3, 1);

    let nested = store.fork(child.id(), Seq::from_u64(3), "origin-nested")?;
    let nested_event = append(store, nested.id(), 4)?;
    assert_origin(&nested_event, nested.id(), 4, 4);
    let stitched = store.read(nested.id(), SeqRange::all())?;
    assert_eq!(stitched.len(), 4);
    for (event, owner, seq) in [
        (&stitched[0], root.id(), 1),
        (&stitched[1], root.id(), 2),
        (&stitched[2], child.id(), 3),
        (&stitched[3], nested.id(), 4),
    ] {
        assert_origin(event, owner, seq, seq);
    }
    Ok((root.id(), child.id(), nested.id()))
}

#[test]
fn memory_and_sqlite_retain_first_commit_context_through_nested_forks(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_fork_origins(&mut MemoryStore::new())?;
    exercise_fork_origins(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

#[test]
fn cow_round_trip_and_flattening_keep_the_correct_origin() -> Result<(), Box<dyn std::error::Error>>
{
    let mut source = MemoryStore::new();
    let (root, child, nested) = exercise_fork_origins(&mut source)?;
    let mut signed = source.read_own(nested, SeqRange::all())?[0].clone();
    signed.id = EventId::new();
    signed.seq = Seq::from_u64(2);
    signed.payload = CanonicalBytes::from_vec(vec![5]);
    signed.payload_hash = pos_core::Hash::from_bytes(*blake3::hash(&[5]).as_bytes());
    signed.signature = Some(Signature::from_bytes([7; 64]));
    signed.signature_identity = Some(KeyIdentityV1::new(
        "origin-owner",
        KeyRoleV1::TimelineIntegritySigning,
        1,
    ));
    signed.origin = None;
    source.append_committed(nested, &[signed])?;
    let evaluation = export_evaluation();
    let mut destination = SqliteStore::open_in_memory()?;
    bind_test_erasure_gate(&mut destination)?;
    for id in [root, child, nested] {
        let exported = export_timeline_own(&source, id, EXPORT_DIGEST, &evaluation)?;
        assert!(exported.events.iter().all(|event| event.origin.is_some()));
        import_timeline_with_id(&mut destination, exported)?;
    }
    let original = source.read(nested, SeqRange::all())?;
    assert!(original[4].signature.is_some());
    let imported = destination.read(nested, SeqRange::all())?;
    assert_eq!(original, imported);

    let flat = export_timeline(&source, nested, EXPORT_DIGEST, &evaluation)?;
    assert!(flat.timeline.meta.fork_point.is_none());
    assert!(flat
        .events
        .iter()
        .all(|event| event.signature.is_none() && event.signature_identity.is_none()));
    assert!(flat.events[4].signature.is_none());
    for (index, event) in flat.events.iter().enumerate() {
        assert_origin(event, nested, (index + 1) as u64, (index + 1) as u64);
    }
    let mut flat_destination = MemoryStore::new();
    bind_test_erasure_gate(&mut flat_destination)?;
    import_timeline_with_id(&mut flat_destination, flat)?;
    let flattened = flat_destination.read(nested, SeqRange::all())?;
    assert!(flattened.iter().all(|event| event.origin.is_some()));
    Ok(())
}

#[test]
fn sqlite_file_reopen_preserves_origin_columns() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("origin.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let nested = {
        let mut store = SqliteStore::open(path)?;
        let (_, _, nested) = exercise_fork_origins(&mut store)?;
        nested
    };
    let mut reopened = SqliteStore::open(path)?;
    bind_test_erasure_gate(&mut reopened)?;
    let events = reopened.read(nested, SeqRange::all())?;
    assert_eq!(events.len(), 4);
    assert_origin(&events[3], nested, 4, 4);
    Ok(())
}

#[test]
fn cow_import_rejects_a_transplanted_origin_in_both_stores(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut source = MemoryStore::new();
    let (root, child, _) = exercise_fork_origins(&mut source)?;
    let evaluation = export_evaluation();
    let root_export = export_timeline_own(&source, root, EXPORT_DIGEST, &evaluation)?;
    let mut child_export = export_timeline_own(&source, child, EXPORT_DIGEST, &evaluation)?;
    child_export.events[0].origin = Some(EventOriginV1 {
        origin_timeline_id: root,
        origin_logical_seq: Seq::from_u64(3),
    });

    let mut memory = MemoryStore::new();
    bind_test_erasure_gate(&mut memory)?;
    import_timeline_with_id(&mut memory, root_export.clone())?;
    assert!(import_timeline_with_id(&mut memory, child_export.clone()).is_err());
    assert!(memory.get_timeline(child)?.is_none());

    let mut sqlite = SqliteStore::open_in_memory()?;
    bind_test_erasure_gate(&mut sqlite)?;
    import_timeline_with_id(&mut sqlite, root_export)?;
    assert!(import_timeline_with_id(&mut sqlite, child_export).is_err());
    assert!(sqlite.get_timeline(child)?.is_none());
    Ok(())
}

#[test]
fn sqlite_read_rejects_corrupt_persisted_origin() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("corrupt-origin.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let root = {
        let mut store = SqliteStore::open(path)?;
        bind_test_erasure_gate(&mut store)?;
        let root = store.create_timeline("origin-corruption")?;
        append(&mut store, root.id(), 1)?;
        root.id()
    };
    let conn = rusqlite::Connection::open(path)?;
    conn.execute(
        "UPDATE events SET origin_timeline_id = ?1 WHERE timeline_id = ?2",
        rusqlite::params![TimelineId::new().to_string(), root.to_string()],
    )?;
    drop(conn);
    let mut store = SqliteStore::open(path)?;
    bind_test_erasure_gate(&mut store)?;
    assert!(store.read(root, SeqRange::all()).is_err());
    drop(store);

    let conn = rusqlite::Connection::open(path)?;
    conn.execute(
        "UPDATE events SET origin_timeline_id = ?1, origin_logical_seq = 2 WHERE timeline_id = ?1",
        rusqlite::params![root.to_string()],
    )?;
    drop(conn);
    let mut store = SqliteStore::open(path)?;
    bind_test_erasure_gate(&mut store)?;
    assert!(store.read(root, SeqRange::all()).is_err());
    Ok(())
}

#[test]
fn sqlite_read_rejects_malformed_origin_column_types_and_values(
) -> Result<(), Box<dyn std::error::Error>> {
    use rusqlite::types::Value;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("malformed-origin.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let mut setup = SqliteStore::open(path)?;
    bind_test_erasure_gate(&mut setup)?;
    let timeline = setup.create_timeline("malformed-origin")?.id();
    append(&mut setup, timeline, 1)?;
    drop(setup);

    for value in [
        Value::Blob(vec![0xff]),
        Value::Text("invalid-ulid".to_owned()),
    ] {
        let connection = rusqlite::Connection::open(path)?;
        connection.execute(
            "UPDATE events SET origin_timeline_id = ?1 WHERE timeline_id = ?2",
            rusqlite::params![value, timeline.to_string()],
        )?;
        drop(connection);
        let mut reader = SqliteStore::open(path)?;
        bind_test_erasure_gate(&mut reader)?;
        assert!(reader.read(timeline, SeqRange::all()).is_err());
    }
    for value in [
        Value::Text("not-an-integer".to_owned()),
        Value::Integer(-1),
        Value::Integer(0),
    ] {
        let connection = rusqlite::Connection::open(path)?;
        connection.pragma_update(None, "ignore_check_constraints", true)?;
        connection.execute(
            "UPDATE events SET origin_timeline_id = ?1, origin_logical_seq = ?2 WHERE timeline_id = ?3",
            rusqlite::params![timeline.to_string(), value, timeline.to_string()],
        )?;
        drop(connection);
        let mut reader = SqliteStore::open(path)?;
        bind_test_erasure_gate(&mut reader)?;
        assert!(reader.read(timeline, SeqRange::all()).is_err());
    }
    Ok(())
}
