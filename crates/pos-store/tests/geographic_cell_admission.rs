use ciborium::value::Value;
use pos_core::{
    clock::AdmissionClock,
    event::Kind,
    geo_cell_admission::{
        hash_admission_consent_record_bytes, AdmissionConsentRecordV1, AdmissionEntitlementDraftV1,
        AdmissionSnapshotHash, AdmissionSnapshotId, GeoCellAdmissionFenceV1,
        GeoCellAdmissionInputV1, GeoCellAdmissionRequestV1, GeographicAdmissionAdmin,
        GeographicAdmissionConsentResolver, GeographicAdmissionFingerprintV1,
        GeographicAdmissionOutcome, GeographicAdmissionStore, GeographicObservationV1,
        GeographicReplayEvidenceV1, GeographicReplayVerifier, ValidatedGeoCellV1,
    },
    CanonicalBytes, EntityId, EventStore, Hash, Hasher, TimelineId, WallTime,
    GEOGRAPHIC_CELL_EVENT_TYPE,
};
use pos_store::memory::MemoryStore;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

const CELL_BYTES: &[u8] =
    b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01";

fn cbor_value(value: &Value) -> CanonicalBytes {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    CanonicalBytes::from_vec(bytes)
}

fn consent_id() -> AdmissionSnapshotId {
    AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").unwrap()
}

fn conflict_consent_id() -> AdmissionSnapshotId {
    AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FB0").unwrap()
}

fn consent_record(id: AdmissionSnapshotId, revision: u64) -> AdmissionConsentRecordV1 {
    let canonical_bytes = cbor_value(&Value::Map(vec![
        (
            Value::Text("record_id".to_owned()),
            Value::Text(id.as_str().to_owned()),
        ),
        (
            Value::Text("revision".to_owned()),
            Value::Integer(revision.into()),
        ),
    ]));
    AdmissionConsentRecordV1::from_persistence_parts(id, revision, canonical_bytes)
}

fn alternate_consent_record(id: AdmissionSnapshotId, revision: u64) -> AdmissionConsentRecordV1 {
    let canonical_bytes = cbor_value(&Value::Map(vec![
        (
            Value::Text("record_id".to_owned()),
            Value::Text(id.as_str().to_owned()),
        ),
        (
            Value::Text("revision".to_owned()),
            Value::Integer(revision.into()),
        ),
        (
            Value::Text("variant".to_owned()),
            Value::Text("alternate".to_owned()),
        ),
    ]));
    AdmissionConsentRecordV1::from_persistence_parts(id, revision, canonical_bytes)
}

#[allow(clippy::too_many_arguments)]
fn draft_with_consent(
    timeline: TimelineId,
    entity: EntityId,
    consent_record_id: AdmissionSnapshotId,
    consent_revision: u64,
    purpose: &str,
    entitled_principals: Vec<EntityId>,
    visibility_scope: &str,
    maximum_h3_resolution: u8,
    admission_policy_version: u32,
    admission_epoch: u64,
) -> AdmissionEntitlementDraftV1 {
    let record = consent_record(consent_record_id.clone(), consent_revision);
    AdmissionEntitlementDraftV1::new(
        timeline,
        entity,
        consent_record_id,
        consent_revision,
        hash_admission_consent_record_bytes(record.canonical_bytes()),
        purpose,
        entitled_principals,
        visibility_scope,
        maximum_h3_resolution,
        admission_policy_version,
        admission_epoch,
    )
    .unwrap()
}

#[derive(Default)]
struct FlappingHasher(AtomicUsize);

trait TestGeographicAdmissionAdmin: GeographicAdmissionAdmin {
    fn install_geo_cell_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoCellAdmissionFenceV1,
    ) -> Result<(), pos_core::CoreError> {
        self.set_geo_cell_admission_consent_record(consent_record(
            fence.draft().consent_record_id().clone(),
            fence.draft().consent_revision(),
        ))?;
        self.set_geo_cell_admission_fence(timeline, entity, fence)
    }
}

impl<T: GeographicAdmissionAdmin + ?Sized> TestGeographicAdmissionAdmin for T {}

impl Hasher for FlappingHasher {
    fn genesis_hash(&self) -> Hash {
        Hash::zero()
    }

    fn hash_payload(&self, _payload: &CanonicalBytes) -> Hash {
        if self.0.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
            Hash::zero()
        } else {
            Hash::from_bytes([1; 32])
        }
    }

    fn hash_event(
        &self,
        _previous_hash: &Hash,
        _event_id_bytes: &[u8],
        _payload: &CanonicalBytes,
    ) -> Hash {
        Hash::zero()
    }
}

fn request(timeline: TimelineId, entity: EntityId) -> GeoCellAdmissionRequestV1 {
    request_with(timeline, entity, "timeline-replay", 13)
}

fn request_with(
    timeline: TimelineId,
    entity: EntityId,
    purpose: &str,
    admission_epoch: u64,
) -> GeoCellAdmissionRequestV1 {
    request_with_consent(timeline, entity, consent_id(), purpose, admission_epoch)
}

fn request_with_consent(
    timeline: TimelineId,
    entity: EntityId,
    consent_record_id: AdmissionSnapshotId,
    purpose: &str,
    admission_epoch: u64,
) -> GeoCellAdmissionRequestV1 {
    let draft = draft_with_consent(
        timeline,
        entity,
        consent_record_id,
        12,
        purpose,
        vec![entity],
        "private",
        9,
        1,
        admission_epoch,
    );
    GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
        ValidatedGeoCellV1::from_adr031_bytes(&pos_core::CanonicalBytes::from_static(CELL_BYTES))
            .unwrap(),
        pos_core::geo_cell_admission::SourceTimeBucket::new(123),
        GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false),
        GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
    ))
    .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn core_geo_cell_decoder_reaches_nested_cell_and_snapshot_identity_errors() {
    let cell: Value = ciborium::from_reader(CELL_BYTES).unwrap();
    let valid_id = Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned());
    let valid_hash =
        Value::Text("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned());
    let make_payload = |cell: Value, snapshot_id: Value, snapshot_hash: Value| {
        cbor_value(&Value::Map(vec![
            (Value::Text("cell".to_owned()), cell),
            (
                Value::Text("quality_flags".to_owned()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("policy_version".to_owned()),
                Value::Integer(1.into()),
            ),
            (
                Value::Text("source_time_bucket".to_owned()),
                Value::Integer(2_000_000.into()),
            ),
            (Value::Text("admission_snapshot_id".to_owned()), snapshot_id),
            (
                Value::Text("admission_snapshot_hash".to_owned()),
                snapshot_hash,
            ),
        ]))
    };

    let mut invalid_cell = cell.clone();
    if let Value::Map(entries) = &mut invalid_cell {
        entries[0].1 = Value::Text("not-an-h3-cell".to_owned());
    }
    assert!(GeographicObservationV1::decode(&make_payload(
        invalid_cell,
        valid_id.clone(),
        valid_hash.clone(),
    ))
    .is_err());
    let mut invalid_h3 = cell.clone();
    if let Value::Map(entries) = &mut invalid_h3 {
        entries[0].1 = Value::Text("8928308280ffffe".to_owned());
    }
    assert!(GeographicObservationV1::decode(&make_payload(
        invalid_h3,
        valid_id.clone(),
        valid_hash.clone(),
    ))
    .is_err());
    assert!(matches!(
        GeographicObservationV1::decode(&make_payload(
            cell.clone(),
            Value::Text("lowercase".to_owned()),
            valid_hash,
        )),
        Err(pos_core::geo_cell_admission::GeoCellAdmissionError::InvalidSnapshotIdentity)
    ));
    assert!(matches!(
        GeographicObservationV1::decode(&make_payload(
            cell.clone(),
            Value::Integer(1.into()),
            Value::Text(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
        )),
        Err(
            pos_core::geo_cell_admission::GeoCellAdmissionError::WrongFieldType(
                "admission_snapshot_id"
            )
        )
    ));
    assert!(matches!(
        GeographicObservationV1::decode(&make_payload(
            cell.clone(),
            valid_id,
            Value::Text("not-a-hash".to_owned()),
        )),
        Err(pos_core::geo_cell_admission::GeoCellAdmissionError::InvalidSnapshotHash)
    ));
    assert!(matches!(
        GeographicObservationV1::decode(&make_payload(
            cell,
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
            Value::Integer(1.into()),
        )),
        Err(
            pos_core::geo_cell_admission::GeoCellAdmissionError::WrongFieldType(
                "admission_snapshot_hash"
            )
        )
    ));

    let mut missing_nested_index = ciborium::from_reader(CELL_BYTES).unwrap();
    if let Value::Map(entries) = &mut missing_nested_index {
        entries.retain(|(key, _)| key != &Value::Text("index".to_owned()));
    }
    assert!(GeographicObservationV1::decode(&make_payload(
        missing_nested_index,
        Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        Value::Text("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned()),
    ))
    .is_err());
    let mut missing_nested_resolution = ciborium::from_reader(CELL_BYTES).unwrap();
    if let Value::Map(entries) = &mut missing_nested_resolution {
        entries.retain(|(key, _)| key != &Value::Text("resolution".to_owned()));
    }
    assert!(GeographicObservationV1::decode(&make_payload(
        missing_nested_resolution,
        Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
        Value::Text("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned()),
    ))
    .is_err());
    let mut missing_outer_cell: Value = ciborium::from_reader(
        make_payload(
            ciborium::from_reader(CELL_BYTES).unwrap(),
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
            Value::Text(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
        )
        .as_slice(),
    )
    .unwrap();
    if let Value::Map(entries) = &mut missing_outer_cell {
        entries.retain(|(key, _)| key != &Value::Text("cell".to_owned()));
    }
    assert!(GeographicObservationV1::decode(&cbor_value(&missing_outer_cell)).is_err());
    let mut missing_outer_bucket: Value = ciborium::from_reader(
        make_payload(
            ciborium::from_reader(CELL_BYTES).unwrap(),
            Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
            Value::Text(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
        )
        .as_slice(),
    )
    .unwrap();
    if let Value::Map(entries) = &mut missing_outer_bucket {
        entries.retain(|(key, _)| key != &Value::Text("source_time_bucket".to_owned()));
    }
    assert!(GeographicObservationV1::decode(&cbor_value(&missing_outer_bucket)).is_err());
}

#[allow(clippy::too_many_lines)]
fn run_atomic_contract<S>(store: &mut S)
where
    S: EventStore + GeographicAdmissionAdmin + GeographicAdmissionStore + GeographicReplayVerifier,
{
    let timeline = store.create_timeline("geo-cell-contract").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();

    let accepted = store.admit(first.clone()).unwrap();
    let (event_id, event_seq, snapshot_id, snapshot_hash, event_hash) = match &accepted {
        GeographicAdmissionOutcome::Accepted {
            persisted_event,
            event_id,
            event_seq,
            snapshot_id,
            snapshot_hash,
        } => (
            *event_id,
            *event_seq,
            snapshot_id.clone(),
            *snapshot_hash,
            persisted_event.payload_hash,
        ),
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(
        accepted.persisted_event().unwrap().event_type.as_str(),
        GEOGRAPHIC_CELL_EVENT_TYPE
    );

    let duplicate = store.admit(first.clone()).unwrap();
    assert!(matches!(
        duplicate,
        GeographicAdmissionOutcome::Duplicate { .. }
    ));
    assert_eq!(duplicate.event_id(), Some(event_id));
    assert_eq!(duplicate.event_seq(), Some(event_seq));
    assert_eq!(duplicate.snapshot_id(), Some(&snapshot_id));
    assert_eq!(duplicate.snapshot_hash(), Some(snapshot_hash));

    let conflict = request_with_consent(
        timeline.id(),
        entity,
        conflict_consent_id(),
        "different-purpose",
        13,
    );
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence_with_id(
                timeline.id(),
                entity,
                conflict_consent_id(),
                "different-purpose",
                13,
            ),
        )
        .unwrap();
    let conflict = store.admit(conflict).unwrap();
    assert!(conflict.is_conflict());
    assert!(conflict.event_id().is_none());
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();

    store
        .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            event_hash,
            snapshot_id.clone(),
            snapshot_hash,
        ))
        .unwrap();
    for evidence in [
        GeographicReplayEvidenceV1::new(
            TimelineId::new(),
            event_id,
            event_seq,
            event_hash,
            snapshot_id.clone(),
            snapshot_hash,
        ),
        GeographicReplayEvidenceV1::new(
            timeline.id(),
            pos_core::EventId::new(),
            event_seq,
            event_hash,
            snapshot_id.clone(),
            snapshot_hash,
        ),
        GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq.next(),
            event_hash,
            snapshot_id.clone(),
            snapshot_hash,
        ),
        GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            Hash::from_bytes([0xff; 32]),
            snapshot_id.clone(),
            snapshot_hash,
        ),
        GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            event_hash,
            AdmissionSnapshotId::new(),
            snapshot_hash,
        ),
        GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            event_hash,
            snapshot_id.clone(),
            AdmissionSnapshotHash::from_bytes([0xff; 32]),
        ),
    ] {
        assert!(store.verify_geo_cell_event(evidence).is_err());
    }

    let forbidden = draft_with_consent(
        timeline.id(),
        entity,
        consent_id(),
        12,
        "timeline-replay",
        vec![entity],
        "private",
        9,
        1,
        14,
    );
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            GeoCellAdmissionFenceV1::new(forbidden, [7; 32], 11, false),
        )
        .unwrap();
    assert!(store.admit(first).is_err());
}

fn admission_fence(
    timeline: TimelineId,
    entity: EntityId,
    admission_epoch: u64,
) -> GeoCellAdmissionFenceV1 {
    admission_fence_with(timeline, entity, "timeline-replay", admission_epoch)
}

fn admission_fence_with(
    timeline: TimelineId,
    entity: EntityId,
    purpose: &str,
    admission_epoch: u64,
) -> GeoCellAdmissionFenceV1 {
    admission_fence_with_id(timeline, entity, consent_id(), purpose, admission_epoch)
}

fn admission_fence_with_id(
    timeline: TimelineId,
    entity: EntityId,
    consent_record_id: AdmissionSnapshotId,
    purpose: &str,
    admission_epoch: u64,
) -> GeoCellAdmissionFenceV1 {
    let draft = draft_with_consent(
        timeline,
        entity,
        consent_record_id,
        12,
        purpose,
        vec![entity],
        "private",
        9,
        1,
        admission_epoch,
    );
    GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false)
}

#[test]
fn memory_geo_cell_admission_is_atomic_and_replayable() {
    run_atomic_contract(&mut MemoryStore::new());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admission_is_atomic_and_replayable() {
    run_atomic_contract(&mut SqliteStore::open_in_memory().unwrap());
}

fn run_response_loss_recovery<S>(store: &mut S)
where
    S: EventStore + GeographicAdmissionAdmin + GeographicAdmissionStore,
{
    let timeline = store.create_timeline("geo-cell-response-loss").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();

    // Model the client losing the Accepted response after durable commit.
    assert!(store.admit(first.clone()).unwrap().is_accepted());
    let recovered = store.admit(first).unwrap();
    assert!(matches!(
        recovered,
        GeographicAdmissionOutcome::Duplicate { .. }
    ));
}

#[test]
fn memory_geo_cell_response_loss_retry_returns_verified_duplicate() {
    run_response_loss_recovery(&mut MemoryStore::new());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_response_loss_retry_returns_verified_duplicate() {
    run_response_loss_recovery(&mut SqliteStore::open_in_memory().unwrap());
}

#[test]
fn memory_geo_cell_exclusive_admission_boundary_has_one_durable_event() {
    let mut store = MemoryStore::new();
    let timeline = store
        .create_timeline("geo-cell-exclusive-boundary")
        .unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(store.admit(first.clone()).unwrap().is_accepted());
    for _ in 0..8 {
        assert!(matches!(
            store.admit(first.clone()).unwrap(),
            GeographicAdmissionOutcome::Duplicate { .. }
        ));
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_identical_admissions_are_unique_across_store_handles() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut setup = SqliteStore::open(path).unwrap();
    let timeline = setup
        .create_timeline("geo-cell-concurrent-admission")
        .unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    setup
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    drop(setup);

    let mut left = SqliteStore::open(path).unwrap();
    let mut right = SqliteStore::open(path).unwrap();
    let left_request = first.clone();
    let right_request = first;
    let (left_result, right_result) = std::thread::scope(|scope| {
        let left_handle = scope.spawn(move || left.admit(left_request));
        let right_handle = scope.spawn(move || right.admit(right_request));
        (left_handle.join().unwrap(), right_handle.join().unwrap())
    });
    let outcomes = [left_result, right_result];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome
                .as_ref()
                .is_ok_and(GeographicAdmissionOutcome::is_accepted))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.as_ref().is_ok_and(|value| {
                matches!(value, GeographicAdmissionOutcome::Duplicate { .. })
            }))
            .count(),
        1
    );
}

#[test]
fn generic_event_append_cannot_admit_geo_cell() {
    let mut store = MemoryStore::new();
    let timeline = store.create_timeline("generic-boundary").unwrap();
    let result = store.append(
        timeline.id(),
        &[pos_core::EventDraft::new(
            EntityId::new(),
            Kind::new(GEOGRAPHIC_CELL_EVENT_TYPE),
            pos_core::CanonicalBytes::from_static(CELL_BYTES),
        )],
    );
    assert!(matches!(
        result,
        Err(pos_core::CoreError::TimelineNotFound(_))
    ));
    assert!(store
        .read(timeline.id(), pos_core::SeqRange::all())
        .unwrap()
        .is_empty());
}

struct ErrorClock;

impl AdmissionClock for ErrorClock {
    fn now(&mut self) -> Result<WallTime, pos_core::CoreError> {
        Err(pos_core::CoreError::Storage("clock failed".to_owned()))
    }
}

#[test]
fn memory_geo_cell_admission_fail_closed_without_fence_or_clock() {
    let mut store = MemoryStore::new();
    let timeline = store.create_timeline("geo-cell-errors").unwrap();
    let entity = EntityId::new();
    let initial_request = request(timeline.id(), entity);
    assert!(store.admit(initial_request).is_err());
    assert!(store
        .install_geo_cell_admission_fence(
            TimelineId::new(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .is_err());
    assert!(store
        .install_geo_cell_admission_fence(
            timeline.id(),
            EntityId::new(),
            admission_fence(timeline.id(), entity, 13),
        )
        .is_err());

    let mut clock_error = MemoryStore::with_clock(Box::new(ErrorClock));
    let timeline = clock_error.create_timeline("geo-cell-clock-error").unwrap();
    let entity = EntityId::new();
    clock_error
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(clock_error
        .admit(request(timeline.id(), entity))
        .unwrap()
        .is_unavailable());

    let mut overflow = MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(
        WallTime::from_micros(u64::MAX),
    )));
    let timeline = overflow
        .create_timeline("geo-cell-expiry-overflow")
        .unwrap();
    let entity = EntityId::new();
    overflow
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(overflow
        .admit(request(timeline.id(), entity))
        .unwrap()
        .is_unavailable());
}

#[test]
fn memory_geo_cell_admission_returns_unknown_when_hash_verification_changes() {
    let mut store = MemoryStore::with_hasher(Box::new(FlappingHasher::default()));
    let timeline = store.create_timeline("geo-cell-flapping-hasher").unwrap();
    let entity = EntityId::new();
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(matches!(
        store.admit(request(timeline.id(), entity)),
        Err(pos_core::CoreError::GeographicAdmissionValidationFailed)
    ));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_precommit_failure_rolls_back_everything() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-rollback").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(
            "CREATE TRIGGER deny_geo_cell_link
             BEFORE INSERT ON geographic_cell_admission_links
             BEGIN SELECT RAISE(ABORT, 'deny geo.cell link'); END;",
        )
        .unwrap();
    assert!(store.admit(first.clone()).is_err());
    let counts: (i64, i64, i64, i64) = inspection
        .query_row(
            "SELECT
                (SELECT count(*) FROM events),
                (SELECT count(*) FROM geographic_cell_admission_snapshots),
                (SELECT count(*) FROM geographic_cell_admission_links),
                (SELECT count(*) FROM geographic_cell_admission_dedup)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
    inspection
        .execute_batch("DROP TRIGGER deny_geo_cell_link")
        .unwrap();
    assert!(store.admit(first).unwrap().is_accepted());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admission_fail_closed_without_fence_or_clock() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let timeline = store.create_timeline("geo-cell-sqlite-errors").unwrap();
    let entity = EntityId::new();
    assert!(store.admit(request(timeline.id(), entity)).is_err());
    assert!(store
        .install_geo_cell_admission_fence(
            TimelineId::new(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .is_err());
    assert!(store
        .install_geo_cell_admission_fence(
            timeline.id(),
            EntityId::new(),
            admission_fence(timeline.id(), entity, 13),
        )
        .is_err());

    let mut clock_error = SqliteStore::open_with_clock(":memory:", Box::new(ErrorClock)).unwrap();
    let timeline = clock_error
        .create_timeline("geo-cell-sqlite-clock-error")
        .unwrap();
    let entity = EntityId::new();
    clock_error
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(clock_error
        .admit(request(timeline.id(), entity))
        .unwrap()
        .is_unavailable());

    let mut overflow = SqliteStore::open_with_clock(
        ":memory:",
        Box::new(pos_core::FixedAdmissionClock(WallTime::from_micros(
            u64::MAX,
        ))),
    )
    .unwrap();
    let timeline = overflow
        .create_timeline("geo-cell-sqlite-expiry-overflow")
        .unwrap();
    let entity = EntityId::new();
    overflow
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(overflow
        .admit(request(timeline.id(), entity))
        .unwrap()
        .is_unavailable());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admission_returns_unknown_when_hash_verification_changes() {
    let mut store =
        SqliteStore::open_in_memory_with_hasher(Box::new(FlappingHasher::default())).unwrap();
    let timeline = store.create_timeline("geo-cell-flapping-hasher").unwrap();
    let entity = EntityId::new();
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(matches!(
        store.admit(request(timeline.id(), entity)),
        Ok(GeographicAdmissionOutcome::OutcomeUnknown)
    ));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_expired_dedup_is_removed_before_a_new_admission() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-expired-dedup").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(store.admit(first.clone()).unwrap().is_accepted());
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute(
            "UPDATE geographic_cell_admission_dedup SET expires_at = 0",
            [],
        )
        .unwrap();
    assert!(store.admit(first).unwrap().is_accepted());
    assert_eq!(
        inspection
            .query_row(
                "SELECT count(*) FROM geographic_cell_admission_dedup",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admin_rejects_a_matching_fence_for_an_unknown_timeline() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let timeline = TimelineId::new();
    let entity = EntityId::new();
    assert!(matches!(
        store.install_geo_cell_admission_fence(
            timeline,
            entity,
            admission_fence(timeline, entity, 13),
        ),
        Err(pos_core::CoreError::TimelineNotFound(_))
    ));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_consent_records_are_immutable_and_resolver_fail_closed() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let id = consent_id();
    let record = consent_record(id.clone(), 12);
    assert!(store
        .set_geo_cell_admission_consent_record(record.clone())
        .is_ok());
    assert!(store.set_geo_cell_admission_consent_record(record).is_ok());
    assert!(store
        .set_geo_cell_admission_consent_record(alternate_consent_record(id.clone(), 12))
        .is_err());
    assert!(store
        .set_geo_cell_admission_consent_record(consent_record(id.clone(), 0))
        .is_err());
    assert!(store.resolve_admission_consent(&id, 12).is_ok());
    assert!(store.resolve_admission_consent(&id, 13).is_err());

    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_revision = 'not-an-integer'
             WHERE consent_record_id = ?1 AND consent_revision = 12",
            [id.as_str()],
        )
        .unwrap();
    assert!(store.resolve_admission_consent(&id, 12).is_err());
    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_revision = 12, consent_record_hash = 'not-a-blob'
             WHERE consent_record_id = ?1",
            [id.as_str()],
        )
        .unwrap();
    assert!(store.resolve_admission_consent(&id, 12).is_err());
    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = ?1, consent_record_cbor = 'not-a-blob'
             WHERE consent_record_id = ?2 AND consent_revision = 12",
            rusqlite::params![
                consent_record(id.clone(), 12).hash().as_bytes().as_slice(),
                id.as_str()
            ],
        )
        .unwrap();
    assert!(store.resolve_admission_consent(&id, 12).is_err());
    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_cbor = ?1
             WHERE consent_record_id = ?2 AND consent_revision = 12",
            rusqlite::params![
                consent_record(id.clone(), 12).canonical_bytes().as_slice(),
                id.as_str()
            ],
        )
        .unwrap();
    inspection
        .execute(
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 14, X'00', X'00')",
            [id.as_str()],
        )
        .unwrap();
    assert!(store.resolve_admission_consent(&id, 14).is_err());

    inspection
        .execute(
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 0, ?2, ?3)",
            rusqlite::params![
                id.as_str(),
                [0_u8; 32].as_slice(),
                b"negative-revision".as_slice()
            ],
        )
        .unwrap();
    assert!(store.resolve_admission_consent(&id, 0).is_err());

    inspection
        .execute_batch("DROP TABLE geographic_cell_admission_consent_records")
        .unwrap();
    assert!(store.resolve_admission_consent(&id, 12).is_err());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_consent_storage_type_errors_fail_closed() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let id = consent_id();
    let record = consent_record(id.clone(), 12);
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(
            "CREATE TRIGGER deny_geo_cell_consent_insert
             BEFORE INSERT ON geographic_cell_admission_consent_records
             BEGIN SELECT RAISE(ABORT, 'deny consent insert'); END;",
        )
        .unwrap();
    assert!(store
        .set_geo_cell_admission_consent_record(record.clone())
        .is_err());
    inspection
        .execute_batch("DROP TRIGGER deny_geo_cell_consent_insert")
        .unwrap();
    store
        .set_geo_cell_admission_consent_record(record.clone())
        .unwrap();
    inspection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();

    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = 'not-a-blob'
             WHERE consent_record_id = ?1 AND consent_revision = 12",
            [id.as_str()],
        )
        .unwrap();
    assert!(store
        .set_geo_cell_admission_consent_record(record.clone())
        .is_err());
    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = ?1, consent_record_cbor = 'not-a-blob'
             WHERE consent_record_id = ?2 AND consent_revision = 12",
            rusqlite::params![record.hash().as_bytes().as_slice(), id.as_str()],
        )
        .unwrap();
    assert!(store
        .set_geo_cell_admission_consent_record(record.clone())
        .is_err());
    inspection
        .execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = X'00', consent_record_cbor = X'00'
             WHERE consent_record_id = ?1 AND consent_revision = 12",
            [id.as_str()],
        )
        .unwrap();
    assert!(store.set_geo_cell_admission_consent_record(record).is_err());

    inspection.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert!(store
        .set_geo_cell_admission_consent_record(consent_record(id.clone(), 12))
        .is_err());
    inspection.execute_batch("ROLLBACK").unwrap();

    let timeline = store.create_timeline("geo-cell-admin-lock").unwrap();
    let entity = EntityId::new();
    let fence = admission_fence(timeline.id(), entity, 13);
    inspection.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert!(store
        .set_geo_cell_admission_fence(timeline.id(), entity, fence.clone())
        .is_err());
    inspection.execute_batch("ROLLBACK").unwrap();
    inspection.execute_batch("DROP TABLE timelines").unwrap();
    assert!(store
        .set_geo_cell_admission_fence(timeline.id(), entity, fence)
        .is_err());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admission_rejects_a_resolved_consent_that_does_not_match_the_fence() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-consent-mismatch").unwrap();
    let entity = EntityId::new();
    let fence = admission_fence(timeline.id(), entity, 13);
    store
        .set_geo_cell_admission_consent_record(alternate_consent_record(
            fence.draft().consent_record_id().clone(),
            fence.draft().consent_revision(),
        ))
        .unwrap();
    store
        .set_geo_cell_admission_fence(timeline.id(), entity, fence)
        .unwrap();
    assert!(store.admit(request(timeline.id(), entity)).is_err());
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_geo_cell_trigger_rolls_back(trigger_name: &str, trigger_body: &str) {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-trigger-rollback").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(&format!(
            "CREATE TRIGGER {trigger_name}
             BEFORE INSERT ON {trigger_body}
             BEGIN SELECT RAISE(ABORT, 'deny geo.cell artifact'); END;"
        ))
        .unwrap();
    assert!(store.admit(first).is_err());
    let counts: (i64, i64, i64, i64) = inspection
        .query_row(
            "SELECT
                (SELECT count(*) FROM events),
                (SELECT count(*) FROM geographic_cell_admission_snapshots),
                (SELECT count(*) FROM geographic_cell_admission_links),
                (SELECT count(*) FROM geographic_cell_admission_dedup)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_each_sidecar_failure_rolls_back_everything() {
    assert_sqlite_geo_cell_trigger_rolls_back(
        "deny_geo_cell_snapshot",
        "geographic_cell_admission_snapshots",
    );
    assert_sqlite_geo_cell_trigger_rolls_back("deny_geo_cell_presence", "geographic_presence");
    assert_sqlite_geo_cell_trigger_rolls_back(
        "deny_geo_cell_dedup",
        "geographic_cell_admission_dedup",
    );
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_geo_cell_corruption_is_not_a_duplicate<F>(mutate: F)
where
    F: FnOnce(&rusqlite::Connection, &str, &str, &str),
{
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-corruption").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(store.admit(first.clone()).unwrap().is_accepted());
    let inspection = rusqlite::Connection::open(path).unwrap();
    let timeline_text = timeline.id().to_string();
    let (event_id, snapshot_id): (String, String) = inspection
        .query_row(
            "SELECT event_id, snapshot_id FROM geographic_cell_admission_dedup LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    mutate(&inspection, &timeline_text, &event_id, &snapshot_id);
    let result = store.admit(first);
    assert!(!matches!(
        result,
        Ok(GeographicAdmissionOutcome::Accepted { .. }
            | GeographicAdmissionOutcome::Duplicate { .. })
    ));
}

#[cfg(feature = "sqlite")]
#[test]
#[allow(clippy::too_many_lines)]
fn sqlite_geo_cell_duplicate_verification_rejects_each_durable_mismatch() {
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET timeline_id = ?1",
            [TimelineId::new().to_string()],
        )
        .unwrap();
        let _ = timeline;
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET entity_id = ?1",
            [EntityId::new().to_string()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, event_id| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET event_id = ?1",
            [pos_core::EventId::new().to_string()],
        )
        .unwrap();
        let _ = event_id;
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET event_seq = event_seq + 1",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET payload_hash = X'00' WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET payload = X'00' WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET entity_id = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![EntityId::new().to_string(), timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET seq = seq + 1 WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET event_type = 'other.event' WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET entity_id = 'not-an-entity' WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "DELETE FROM events WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_cbor = X'00'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_hash = ?1",
            [vec![0xff; 32]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_snapshots SET snapshot_hash = X'00';",
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET timeline_id = ?1",
            [TimelineId::new().to_string()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET timeline_id = 'not-a-timeline'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET entity_id = ?1",
            [EntityId::new().to_string()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET entity_id = 'not-an-entity'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_id = ?1",
            [pos_core::EventId::new().to_string()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_id = 'not-an-event'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, snapshot_id| {
        db.execute(
            "DELETE FROM geographic_cell_admission_snapshots WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_seq = event_seq + 1",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "DELETE FROM geographic_cell_admission_links WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET event_seq = event_seq + 1",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_id = 'not-a-ulid'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_links SET snapshot_hash = X'00';",
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_cbor = X'00'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "DELETE FROM geographic_cell_admission_links WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
}

#[cfg(feature = "sqlite")]
#[test]
#[allow(clippy::too_many_lines)]
fn sqlite_geo_cell_duplicate_rejects_wrong_durable_storage_types() {
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET timeline_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET entity_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET intent = ?1",
            ["not-a-blob"],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET event_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET event_seq = ?1",
            ["not-an-integer"],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET snapshot_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_dedup SET snapshot_hash = 'not-a-blob';",
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET entity_id = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![vec![1_u8], timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET seq = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![vec![1_u8], timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET event_type = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![vec![1_u8], timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        db.execute(
            "UPDATE events SET schema_version = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![vec![1_u8], timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET payload = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params!["not-a-blob", timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET payload_hash = ?1 WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params!["not-a-blob", timeline, event_id],
        )
        .unwrap();
    });

    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_snapshots SET snapshot_hash = 'not-a-blob';",
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET timeline_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET entity_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_seq = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_cbor = ?1",
            ["not-a-blob"],
        )
        .unwrap();
    });

    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET event_seq = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_id = ?1",
            [vec![1_u8]],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_links SET snapshot_hash = 'not-a-blob';",
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_cbor = ?1",
            ["not-a-blob"],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        let hash = blake3::hash(&[0_u8]);
        db.execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = ?1, consent_record_cbor = X'00'
             WHERE consent_record_id = ?2 AND consent_revision = 12",
            rusqlite::params![hash.as_bytes().as_slice(), consent_id().as_str()],
        )
        .unwrap();
    });
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_dedup_rejects_malformed_identity_and_hash_values() {
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET timeline_id = 'not-a-timeline'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET entity_id = 'not-an-entity'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET intent = X'00'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET event_id = 'not-an-event'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_dedup SET snapshot_id = 'not-a-snapshot'",
            [],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_corruption_is_not_a_duplicate(|db, _, _, _| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_dedup SET snapshot_hash = X'00';",
        )
        .unwrap();
    });
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admin_fails_closed_on_durable_write_errors() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-admin-errors").unwrap();
    let entity = EntityId::new();
    let fence = admission_fence(timeline.id(), entity, 13);
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(
            "CREATE TRIGGER deny_geo_cell_fence_insert
             BEFORE INSERT ON geographic_cell_admission_fences
             BEGIN SELECT RAISE(ABORT, 'deny geo.cell fence insert'); END;",
        )
        .unwrap();
    assert!(store
        .install_geo_cell_admission_fence(timeline.id(), entity, fence.clone())
        .is_err());
    inspection
        .execute_batch("DROP TRIGGER deny_geo_cell_fence_insert")
        .unwrap();
    store
        .install_geo_cell_admission_fence(timeline.id(), entity, fence.clone())
        .unwrap();
    inspection
        .execute_batch(
            "CREATE TRIGGER deny_geo_cell_fence_update
             BEFORE UPDATE ON geographic_cell_admission_fences
             BEGIN SELECT RAISE(ABORT, 'deny geo.cell fence update'); END;",
        )
        .unwrap();
    assert!(store
        .install_geo_cell_admission_fence(timeline.id(), entity, fence)
        .is_err());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_admission_reports_unavailable_when_writer_is_locked() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-writer-lock").unwrap();
    let entity = EntityId::new();
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert!(matches!(
        store.admit(request(timeline.id(), entity)),
        Ok(GeographicAdmissionOutcome::Unavailable)
    ));
    inspection.execute_batch("ROLLBACK").unwrap();
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_geo_cell_new_admission_rejects_mutation<F>(mutate: F)
where
    F: FnOnce(&rusqlite::Connection, &str, &str),
{
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store
        .create_timeline("geo-cell-new-admission-corruption")
        .unwrap();
    let entity = EntityId::new();
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let inspection = rusqlite::Connection::open(path).unwrap();
    mutate(&inspection, &timeline.id().to_string(), &entity.to_string());
    assert!(store.admit(request(timeline.id(), entity)).is_err());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_new_admission_fails_closed_on_fence_and_append_errors() {
    assert_sqlite_geo_cell_new_admission_rejects_mutation(|db, timeline, entity| {
        db.execute(
            "UPDATE geographic_cell_admission_fences SET fence_cbor = X'00'
             WHERE timeline_id = ?1 AND entity_id = ?2",
            rusqlite::params![timeline, entity],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_new_admission_rejects_mutation(|db, timeline, _| {
        db.execute(
            "UPDATE timelines SET chain_head = X'00' WHERE id = ?1",
            [timeline],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_new_admission_rejects_mutation(|db, timeline, _| {
        db.execute(
            "UPDATE timelines SET head_seq = 'not-an-integer' WHERE id = ?1",
            [timeline],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_new_admission_rejects_mutation(|db, timeline, _| {
        db.execute(
            "UPDATE timelines SET chain_head = 'not-a-blob' WHERE id = ?1",
            [timeline],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_new_admission_rejects_mutation(|db, _, _| {
        db.execute_batch(
            "CREATE TRIGGER deny_geo_cell_event_insert
             BEFORE INSERT ON events
             BEGIN SELECT RAISE(ABORT, 'deny geo.cell event'); END;",
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_new_admission_rejects_mutation(|db, _, _| {
        db.execute_batch(
            "CREATE TRIGGER deny_geo_cell_timeline_update
             BEFORE UPDATE OF head_seq ON timelines
             BEGIN SELECT RAISE(ABORT, 'deny geo.cell timeline update'); END;",
        )
        .unwrap();
    });
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_geo_cell_missing_table_fails_closed(table: &str) {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-missing-table").unwrap();
    let entity = EntityId::new();
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(&format!("DROP TABLE {table}"))
        .unwrap();
    assert!(store.admit(request(timeline.id(), entity)).is_err());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_missing_tables_fail_closed_at_each_admission_stage() {
    for table in [
        "geographic_cell_admission_fences",
        "geographic_cell_admission_consent_records",
        "geographic_cell_admission_dedup",
        "events",
        "geographic_cell_admission_snapshots",
        "geographic_cell_admission_links",
        "geographic_presence",
    ] {
        assert_sqlite_geo_cell_missing_table_fails_closed(table);
    }
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_geo_cell_duplicate_missing_table_fails_closed(table: &str) {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store
        .create_timeline("geo-cell-duplicate-missing-table")
        .unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    assert!(store.admit(first.clone()).unwrap().is_accepted());
    let inspection = rusqlite::Connection::open(path).unwrap();
    inspection
        .execute_batch(&format!("DROP TABLE {table}"))
        .unwrap();
    assert!(store.admit(first).is_err());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_duplicate_missing_tables_fail_closed() {
    for table in [
        "geographic_cell_admission_dedup",
        "geographic_cell_admission_consent_records",
        "events",
        "geographic_cell_admission_snapshots",
        "geographic_cell_admission_links",
        "geographic_cell_admission_consent_records",
    ] {
        assert_sqlite_geo_cell_duplicate_missing_table_fails_closed(table);
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_replay_missing_sidecars_fail_closed() {
    for table in [
        "geographic_cell_admission_snapshots",
        "geographic_cell_admission_links",
    ] {
        let database = tempfile::NamedTempFile::new().unwrap();
        let path = database.path().to_str().unwrap();
        let mut store = SqliteStore::open(path).unwrap();
        let timeline = store
            .create_timeline("geo-cell-replay-missing-table")
            .unwrap();
        let entity = EntityId::new();
        let first = request(timeline.id(), entity);
        store
            .install_geo_cell_admission_fence(
                timeline.id(),
                entity,
                admission_fence(timeline.id(), entity, 13),
            )
            .unwrap();
        let accepted = store.admit(first).unwrap();
        let GeographicAdmissionOutcome::Accepted {
            event_id,
            event_seq,
            snapshot_id,
            snapshot_hash,
            persisted_event,
        } = accepted
        else {
            unreachable!();
        };
        let inspection = rusqlite::Connection::open(path).unwrap();
        inspection
            .execute_batch(&format!("DROP TABLE {table}"))
            .unwrap();
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                persisted_event.payload_hash,
                snapshot_id,
                snapshot_hash,
            ))
            .is_err());
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_replay_missing_rows_fail_closed() {
    for table in [
        "geographic_cell_admission_snapshots",
        "geographic_cell_admission_links",
    ] {
        let database = tempfile::NamedTempFile::new().unwrap();
        let path = database.path().to_str().unwrap();
        let mut store = SqliteStore::open(path).unwrap();
        let timeline = store
            .create_timeline("geo-cell-replay-missing-row")
            .unwrap();
        let entity = EntityId::new();
        let first = request(timeline.id(), entity);
        store
            .install_geo_cell_admission_fence(
                timeline.id(),
                entity,
                admission_fence(timeline.id(), entity, 13),
            )
            .unwrap();
        let accepted = store.admit(first).unwrap();
        let GeographicAdmissionOutcome::Accepted {
            event_id,
            event_seq,
            snapshot_id,
            snapshot_hash,
            persisted_event,
        } = accepted
        else {
            unreachable!();
        };
        let inspection = rusqlite::Connection::open(path).unwrap();
        let (column, value) = if table.ends_with("snapshots") {
            ("snapshot_id", snapshot_id.as_str().to_owned())
        } else {
            ("event_id", event_id.to_string())
        };
        inspection
            .execute(&format!("DELETE FROM {table} WHERE {column} = ?1"), [value])
            .unwrap();
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                persisted_event.payload_hash,
                snapshot_id,
                snapshot_hash,
            ))
            .is_err());
    }
}

#[cfg(feature = "sqlite")]
fn assert_sqlite_geo_cell_replay_rejects_mutation<F>(mutate: F)
where
    F: FnOnce(&rusqlite::Connection, &str, &str, &str),
{
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-replay-corruption").unwrap();
    let entity = EntityId::new();
    let first = request(timeline.id(), entity);
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let accepted = store.admit(first).unwrap();
    let GeographicAdmissionOutcome::Accepted {
        event_id,
        event_seq,
        snapshot_id,
        snapshot_hash,
        persisted_event,
    } = accepted
    else {
        unreachable!();
    };
    let inspection = rusqlite::Connection::open(path).unwrap();
    mutate(
        &inspection,
        &timeline.id().to_string(),
        &event_id.to_string(),
        snapshot_id.as_str(),
    );
    assert!(store
        .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            persisted_event.payload_hash,
            snapshot_id,
            snapshot_hash,
        ))
        .is_err());
}

#[cfg(feature = "sqlite")]
#[test]
#[allow(clippy::too_many_lines)]
fn sqlite_geo_cell_replay_rejects_durable_corruption() {
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        let hash = blake3::hash(&[0_u8]);
        db.execute(
            "UPDATE events SET payload = X'00', payload_hash = ?1
             WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![hash.as_bytes().as_slice(), timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET event_type = 'other.event'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET payload_hash = X'01'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE events SET event_id = ?1
             WHERE timeline_id = ?2 AND event_id = ?3",
            rusqlite::params![pos_core::EventId::new().to_string(), timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_hash = ?1
             WHERE snapshot_id = ?2",
            rusqlite::params![vec![0xff_u8; 32], snapshot_id],
        )
        .unwrap();
        let _ = timeline;
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET timeline_id = 'not-a-timeline'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET event_seq = event_seq + 1
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_id = 'not-a-ulid'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_cbor = X'00'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE geographic_cell_admission_snapshots SET snapshot_hash = X'00';",
        )
        .unwrap();
        let _ = snapshot_id;
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_hash = 'not-a-blob'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET timeline_id = X'01'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET entity_id = X'01'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_id = X'01'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_seq = event_seq + 1
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_cbor = 'not-a-blob'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET entity_id = 'not-an-entity'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET event_id = 'not-an-event'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, snapshot_id| {
        db.execute(
            "UPDATE geographic_cell_admission_snapshots SET snapshot_cbor = X'00'
             WHERE snapshot_id = ?1",
            [snapshot_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_hash = X'00'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET event_seq = X'01'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_id = X'01'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_hash = 'not-a-blob'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, timeline, event_id, _| {
        db.execute(
            "UPDATE geographic_cell_admission_links SET snapshot_cbor = 'not-a-blob'
             WHERE timeline_id = ?1 AND event_id = ?2",
            rusqlite::params![timeline, event_id],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, _| {
        db.execute(
            "DELETE FROM geographic_cell_admission_consent_records
             WHERE consent_record_id = ?1 AND consent_revision = 12",
            [consent_id().as_str()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = ?1
             WHERE consent_record_id = ?2 AND consent_revision = 12",
            rusqlite::params![vec![0xff_u8; 32], consent_id().as_str()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, _| {
        db.execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_cbor = X'00'
             WHERE consent_record_id = ?1 AND consent_revision = 12",
            [consent_id().as_str()],
        )
        .unwrap();
    });
    assert_sqlite_geo_cell_replay_rejects_mutation(|db, _, _, _| {
        let hash = blake3::hash(&[0_u8]);
        db.execute(
            "UPDATE geographic_cell_admission_consent_records
             SET consent_record_hash = ?1, consent_record_cbor = X'00'
             WHERE consent_record_id = ?2 AND consent_revision = 12",
            rusqlite::params![hash.as_bytes().as_slice(), consent_id().as_str()],
        )
        .unwrap();
    });
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_geo_cell_replay_reaches_payload_and_snapshot_row_decode_errors() {
    let database = tempfile::NamedTempFile::new().unwrap();
    let path = database.path().to_str().unwrap();
    let mut store = SqliteStore::open(path).unwrap();
    let timeline = store.create_timeline("geo-cell-replay-row-errors").unwrap();
    let entity = EntityId::new();
    store
        .install_geo_cell_admission_fence(
            timeline.id(),
            entity,
            admission_fence(timeline.id(), entity, 13),
        )
        .unwrap();
    let accepted = store.admit(request(timeline.id(), entity)).unwrap();
    let GeographicAdmissionOutcome::Accepted {
        event_id,
        event_seq,
        snapshot_id,
        snapshot_hash,
        persisted_event,
    } = accepted
    else {
        unreachable!();
    };
    let inspection = rusqlite::Connection::open(path).unwrap();
    let invalid_payload = CanonicalBytes::from_static(b"not-a-geo-cell");
    let invalid_hash = pos_crypto::chain::hash_payload(&invalid_payload);
    inspection
        .execute(
            "UPDATE events SET payload = ?1, payload_hash = ?2
             WHERE timeline_id = ?3 AND event_id = ?4",
            rusqlite::params![
                invalid_payload.as_slice(),
                invalid_hash.as_bytes().as_slice(),
                timeline.id().to_string(),
                event_id.to_string()
            ],
        )
        .unwrap();
    assert!(store
        .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            invalid_hash,
            snapshot_id.clone(),
            snapshot_hash,
        ))
        .is_err());
    inspection
        .execute(
            "UPDATE events SET payload = ?1, payload_hash = ?2
             WHERE timeline_id = ?3 AND event_id = ?4",
            rusqlite::params![
                persisted_event.payload.as_slice(),
                persisted_event.payload_hash.as_bytes().as_slice(),
                timeline.id().to_string(),
                event_id.to_string()
            ],
        )
        .unwrap();
    inspection
        .execute(
            "UPDATE geographic_cell_admission_snapshots SET event_seq = 'not-an-integer'
             WHERE snapshot_id = ?1",
            [snapshot_id.as_str()],
        )
        .unwrap();
    assert!(store
        .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            persisted_event.payload_hash,
            snapshot_id,
            snapshot_hash,
        ))
        .is_err());
}
