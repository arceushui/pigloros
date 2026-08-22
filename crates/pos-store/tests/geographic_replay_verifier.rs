use pos_core::{
    geo_admission::{
        GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1, GeoLocationAdmissionRequestV1,
        GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1, GeoLocationReplayVerifier,
    },
    CanonicalBytes, EntityId, EventStore, OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStore,
};
use pos_store::sqlite::SqliteStore;

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected replay fixture error: {error:?}"
            )))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing replay fixture value")))
    }
}

trait TestErrorExt<T, E> {
    fn test_err(self) -> E;
}

impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
    fn test_err(self) -> E {
        match self {
            Ok(value) => std::panic::resume_unwind(Box::new(format!(
                "unexpected successful replay fixture value: {value:?}"
            ))),
            Err(error) => error,
        }
    }
}

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
        (1, false, 10),
        dedup,
    ))
}

const fn fence() -> GeoLocationAdmissionFenceV1 {
    GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9))
}

fn pair(store: &mut SqliteStore, timeline: pos_core::TimelineId, entity: EntityId) {
    store
        .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
            timeline,
            entity,
            fence(),
            [42; 32],
        ))
        .test_ok();
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
            .test_ok(),
        1
    );
    assert!(store
        .verify_v1_event_snapshot_link(evidence)
        .test_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert_eq!(
        inspection
            .execute(
                "UPDATE events SET payload_hash = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
                rusqlite::params![event_hash.as_bytes().as_slice(), timeline_id, event_id],
            )
            .test_ok(),
        1
    );
    inspection
        .execute(
            "UPDATE geographic_admission_links SET snapshot_cbor = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![vec![0_u8], timeline_id, event_id],
        )
        .test_ok();
    inspection
        .execute(
            "UPDATE geographic_admission_snapshots SET snapshot_cbor = ?1 WHERE event_id = ?2",
            rusqlite::params![vec![0_u8], event_id],
        )
        .test_ok();
    assert!(store
        .verify_v1_event_snapshot_link(evidence)
        .test_err()
        .to_string()
        .contains("geographic admission validation failed"));
    inspection.execute_batch("DROP TABLE events").test_ok();
    assert!(store
        .verify_v1_event_snapshot_link(evidence)
        .test_err()
        .to_string()
        .contains("no such table"));
}

#[test]
fn sqlite_replay_verifier_accepts_only_the_exact_durable_snapshot_link() {
    let database = tempfile::NamedTempFile::new().test_ok();
    let path = database.path().to_str().test_ok();
    let mut store = SqliteStore::open(path).test_ok();
    let timeline = store.create_timeline("replay-verifier").test_ok();
    let entity = EntityId::new();
    pair(&mut store, timeline.id(), entity);
    let accepted = store
        .admit_geo_location(request(timeline.id(), entity, ([4; 32], [5; 32])))
        .test_ok();
    let event_id = accepted.event_id().test_ok();
    let event_seq = accepted.event_seq().test_ok();
    let timeline_id = timeline.id().to_string();
    let event_id_text = event_id.to_string();
    let inspection = rusqlite::Connection::open(path).test_ok();
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
        .test_ok();
    let event_hash = pos_core::Hash::from_bytes(event_hash.try_into().test_ok());
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

    store.revoke_owntracks_enrollment().test_ok();
    assert!(store
        .verify_v1_event_snapshot_link(evidence(event_seq, event_hash, snapshot_hash))
        .is_ok());
    assert!(store
        .verify_v1_event_snapshot_link(evidence(event_seq.next(), event_hash, snapshot_hash))
        .test_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert!(store
        .verify_v1_event_snapshot_link(evidence(
            event_seq,
            pos_core::Hash::from_bytes([0; 32]),
            snapshot_hash,
        ))
        .test_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert!(store
        .verify_v1_event_snapshot_link(evidence(
            event_seq,
            event_hash,
            pos_core::Hash::from_bytes([0; 32]),
        ))
        .test_err()
        .to_string()
        .contains("geographic admission validation failed"));
    assert_eq!(
        inspection
            .execute(
                "UPDATE events SET entity_id = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
                rusqlite::params![EntityId::new().to_string(), &timeline_id, &event_id_text],
            )
            .test_ok(),
        1
    );
    assert!(store
        .verify_v1_event_snapshot_link(evidence(event_seq, event_hash, snapshot_hash))
        .test_err()
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
