use pos_core::{
    geo_admission::{
        GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
        GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
        GeoLocationReplayVerifier,
    },
    CanonicalBytes, EntityId, EventStore,
};
use pos_store::sqlite::SqliteStore;

fn request(
    timeline: pos_core::TimelineId,
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

fn assert_replay_verifier_rejects_durable_corruption(
    store: &SqliteStore,
    inspection: &rusqlite::Connection,
    evidence: GeoLocationReplayEvidenceV1,
    timeline_id: &str,
    event_id: &str,
    event_hash: pos_core::Hash,
) {
    assert_eq!(
        inspection
            .execute(
                "UPDATE events SET payload_hash = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
                rusqlite::params![vec![0_u8], timeline_id, event_id],
            )
            .unwrap(),
        1
    );
    assert!(store
        .verify_v1_event_snapshot_link(evidence)
        .unwrap_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert_eq!(
        inspection
            .execute(
                "UPDATE events SET payload_hash = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
                rusqlite::params![event_hash.as_bytes().as_slice(), timeline_id, event_id],
            )
            .unwrap(),
        1
    );
    inspection
        .execute(
            "UPDATE geographic_admission_links SET snapshot_cbor = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![vec![0_u8], timeline_id, event_id],
        )
        .unwrap();
    inspection
        .execute(
            "UPDATE geographic_admission_snapshots SET snapshot_cbor = ?1 WHERE event_id = ?2",
            rusqlite::params![vec![0_u8], event_id],
        )
        .unwrap();
    assert!(store
        .verify_v1_event_snapshot_link(evidence)
        .unwrap_err()
        .to_string()
        .contains("geographic admission validation failed"));
    inspection.execute_batch("DROP TABLE events").unwrap();
    assert!(store
        .verify_v1_event_snapshot_link(evidence)
        .unwrap_err()
        .to_string()
        .contains("no such table"));
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

    assert_replay_verifier_rejects_durable_corruption(
        &store,
        &inspection,
        evidence(event_seq, event_hash, snapshot_hash),
        &timeline_id,
        &event_id_text,
        event_hash,
    );
}
