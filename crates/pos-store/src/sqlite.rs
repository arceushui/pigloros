//! `SQLite` WAL append-only `EventStore` backend.
//!
//! Events are stored in a single table, append-only.
//! Batched transactions ensure throughput >= 2k ev/s on `SQLite`-WAL.
//! Fork is copy-on-write: only a metadata row is inserted at fork time (O(1)).
//! Child reads stitch parent events up to `fork_seq` with child events.

use rusqlite::{
    params, types::ToSql, Connection, OpenFlags, OptionalExtension, TransactionBehavior,
};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use pos_core::{
    clock::{AdmissionClock, Seq, SystemAdmissionClock, WallTime},
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    geo_admission::{
        GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
        GeoLocationReplayEvidenceV1, GeoLocationReplayVerifier,
    },
    geo_cell_admission::{
        hash_admission_snapshot_bytes, AdmissionConsentRecordV1, AdmissionEntitlementSnapshotV1,
        AdmissionSnapshotHash, AdmissionSnapshotId, ConsentRecordHash, GeoCellAdmissionFenceV1,
        GeographicAdmissionAdmin, GeographicAdmissionConsentResolver,
        GeographicAdmissionFingerprintV1, GeographicAdmissionOutcome, GeographicAdmissionStore,
        GeographicObservationV1, GeographicReplayEvidenceV1, GeographicReplayVerifier,
        ValidatedGeographicAdmissionV1,
    },
    hasher::Hasher,
    ids::{EntityId, EventId, TimelineId},
    owntracks_enrollment::{
        OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStateV1, OwnTracksEnrollmentStatusV1,
        OwnTracksEnrollmentStatusViewV1, OwnTracksEnrollmentStore,
    },
    owntracks_ingress::{
        OwnTracksIngressInputV1, OwnTracksIngressStore, PreparedOwnTracksIngressV1,
    },
    store::{
        checked_append_identity_expires_at, AppendDedupScope, AppendIdentity, AppendIntent,
        AppendOrDuplicateOutcome, EventReadBounds, EventStore, PurgeOutcome, SeqRange,
    },
    timeline::{Timeline, TimelineMeta, TimelineMode},
    ConsentAppendPermit, CoreError, ErasureCoordinatorRecordV1, ErasureErrorV1,
    ErasureFreezeAuthorizationVerifierV1, ErasurePersistencePortV1, ErasureReferenceV1,
    ErasureStateResolverV1, Hash, KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, GEOGRAPHIC_EVENT_TYPE,
};

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: force [`SqliteStore::open_in_memory`] to fail.
    pub(crate) static FAIL_OPEN_IN_MEMORY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force `query` after `prepare` to fail.
    static FAIL_STMT_QUERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force `BEGIN IMMEDIATE` in append/import to fail.
    static FAIL_BEGIN_IMMEDIATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force SQLite busy-timeout configuration to fail.
    static FAIL_BUSY_TIMEOUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force event-signature schema statement preparation to fail.
    static FAIL_SIGNATURE_SCHEMA_PREPARE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force event-signature schema parameter binding to fail.
    static FAIL_SIGNATURE_SCHEMA_QUERY: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force event-signature schema row decoding to fail.
    static FAIL_SIGNATURE_SCHEMA_ROW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force key-registry CBOR serialization to fail.
    static FAIL_REGISTRY_SERIALIZATION: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Test-only fault injection: make import_committed see a vanished timeline after write.
    static FAIL_IMPORT_VANISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: make import_committed's get_timeline hit a storage error.
    static FAIL_IMPORT_GET_STORAGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force `Rows::next` to return Err.
    static FAIL_ROWS_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only evidence that full Event queries start only after metadata validation.
    static BOUNDED_EVENT_QUERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test-only count of rows examined by bounded metadata queries.
    static BOUNDED_METADATA_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test-only count of full Event rows fetched by bounded reads.
    static BOUNDED_EVENT_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to prove the elapsed bound covers final materialization.
    static BOUNDED_MATERIALIZATION_DELAY_MILLIS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    /// Test-only phase delay used to cover each bounded-read elapsed guard.
    static BOUNDED_READ_DELAY_PHASE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    /// Test-only fault injection for the open-time sequence validation query.
    static FAIL_SEQUENCE_VALIDATION_QUERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection for bounded fork-chain reads.
    static FAIL_BOUNDED_CHAIN_QUERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct RegistryStateWriter {
    bytes: Vec<u8>,
    fail: bool,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl std::io::Write for RegistryStateWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail {
            return Err(std::io::Error::other(
                "injected registry serialization failure",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
fn bounded_materialization_delay_for_test() {
    let delay_millis = BOUNDED_MATERIALIZATION_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_read_delay_for_test(phase: u8) {
    if BOUNDED_READ_DELAY_PHASE.with(std::cell::Cell::get) == phase {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

pub struct SqliteStore {
    conn: Connection,
    hasher: Box<dyn Hasher>,
    clock: Box<dyn AdmissionClock>,
    consent_authority_permit: Option<ConsentAppendPermit>,
    #[cfg(test)]
    destruction_transaction_hook:
        Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

impl SqliteStore {
    fn configure_busy_timeout(conn: &Connection) -> rusqlite::Result<()> {
        #[cfg(test)]
        if FAIL_BUSY_TIMEOUT.with(std::cell::Cell::get) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
    }

    fn geo_cell_consent_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        consent_record_id: &AdmissionSnapshotId,
        consent_revision: u64,
    ) -> Result<AdmissionConsentRecordV1, CoreError> {
        let row = tx
            .query_row(
                "SELECT consent_revision, consent_record_hash, consent_record_cbor
                 FROM geographic_cell_admission_consent_records
                 WHERE consent_record_id = ?1 AND consent_revision = ?2",
                params![
                    consent_record_id.as_str(),
                    i64::try_from(consent_revision).unwrap_or(i64::MAX)
                ],
                |row| {
                    row.get::<_, i64>(0).and_then(|revision| {
                        row.get::<_, Vec<u8>>(1).and_then(|hash| {
                            row.get::<_, Vec<u8>>(2)
                                .map(|bytes| (revision, hash, bytes))
                        })
                    })
                },
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?
            .ok_or(CoreError::GeographicAdmissionValidationFailed)?;
        let stored_revision =
            u64::try_from(row.0).map_err(|_| CoreError::GeographicAdmissionValidationFailed);
        let stored_hash: Result<[u8; 32], CoreError> = row
            .1
            .try_into()
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed);
        stored_revision.and_then(|stored_revision| {
            stored_hash.and_then(|stored_hash| {
                let record = AdmissionConsentRecordV1::from_persistence_parts(
                    consent_record_id.clone(),
                    stored_revision,
                    CanonicalBytes::from_vec(row.2),
                );
                if stored_revision != consent_revision
                    || record.hash() != ConsentRecordHash::from_bytes(stored_hash)
                {
                    Err(CoreError::GeographicAdmissionValidationFailed)
                } else {
                    Ok(record)
                }
            })
        })
    }

    fn append_one_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        hasher: &dyn Hasher,
        timeline: TimelineId,
        draft: EventDraft,
    ) -> Result<Event, CoreError> {
        let head = tx.query_row(
            "SELECT head_seq, chain_head FROM timelines WHERE id = ?1",
            params![timeline.to_string()],
            |row| {
                row.get::<_, i64>(0).and_then(|head_seq| {
                    row.get::<_, Vec<u8>>(1)
                        .map(|chain_head| (head_seq, chain_head))
                })
            },
        );
        let (head_seq, chain_head) = match head {
            Ok(value) => value,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(CoreError::TimelineNotFound(timeline));
            }
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let hash_bytes: [u8; 32] = match chain_head.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return Err(CoreError::Serialization("bad hash length".to_owned())),
        };
        let seq = Seq::from_u64(u64::try_from(head_seq).unwrap_or(0)).next();
        let event_id = EventId::new();
        let event_id_text = event_id.to_string();
        let payload_hash = hasher.hash_payload(&draft.payload);
        let next_chain_head = hasher.hash_event(
            &pos_core::Hash::from_bytes(hash_bytes),
            event_id_text.as_bytes(),
            &draft.payload,
        );
        let wall_time = draft.wall_time.unwrap_or_else(WallTime::now);
        if let Err(error) = tx.execute(
            "INSERT INTO events
             (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
              causation_id, correlation_id, schema_version, payload_hash, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                timeline.to_string(),
                i64::try_from(seq.as_u64()).unwrap_or(i64::MAX),
                event_id_text,
                draft.entity.to_string(),
                draft.event_type.as_str(),
                draft.payload.as_slice(),
                i64::try_from(wall_time.as_micros()).unwrap_or(i64::MAX),
                draft.causation_id.map(|id| id.to_string()),
                draft.correlation_id.map(|id| id.to_string()),
                i64::from(draft.schema_version.as_u32()),
                payload_hash.as_bytes().as_slice(),
                Option::<&[u8]>::None,
            ],
        ) {
            return Err(CoreError::Storage(error.to_string()));
        }
        if let Err(error) = tx.execute(
            "UPDATE timelines SET head_seq = ?1, chain_head = ?2 WHERE id = ?3",
            params![
                i64::try_from(seq.as_u64()).unwrap_or(i64::MAX),
                next_chain_head.as_bytes().as_slice(),
                timeline.to_string(),
            ],
        ) {
            return Err(CoreError::Storage(error.to_string()));
        }
        Ok(Event {
            id: event_id,
            entity: draft.entity,
            event_type: draft.event_type,
            payload: draft.payload,
            wall_time,
            seq,
            causation_id: draft.causation_id,
            correlation_id: draft.correlation_id,
            schema_version: draft.schema_version,
            signature: None,
            signature_identity: None,
            payload_hash,
        })
    }

    fn retained_event_matches_draft(
        tx: &rusqlite::Transaction<'_>,
        event_id: &str,
        timeline: TimelineId,
        draft: &EventDraft,
    ) -> Result<bool, CoreError> {
        let retained = tx.query_row(
            "SELECT CASE
                WHEN EXISTS (
                    SELECT 1 FROM events
                    WHERE event_id = ?1
                      AND timeline_id = ?2
                      AND entity_id = ?3
                      AND event_type = ?4
                      AND payload = ?5
                      AND causation_id IS ?6
                      AND correlation_id IS ?7
                      AND schema_version = ?8
                ) THEN 1
                WHEN EXISTS (SELECT 1 FROM events WHERE event_id = ?1) THEN 0
                ELSE -1
             END",
            params![
                event_id,
                timeline.to_string(),
                draft.entity.to_string(),
                draft.event_type.as_str(),
                draft.payload.as_slice(),
                draft.causation_id.map(|id| id.to_string()),
                draft.correlation_id.map(|id| id.to_string()),
                i64::from(draft.schema_version.as_u32()),
            ],
            |row| row.get::<_, i64>(0),
        );
        match retained {
            Ok(1) => Ok(true),
            Ok(0) => Ok(false),
            Ok(_) => Err(CoreError::Storage(
                "append identity points to a missing Event".to_owned(),
            )),
            Err(error) => Err(CoreError::Storage(error.to_string())),
        }
    }

    /// Open a `SQLite` WAL store at the given path. Use `":memory:"` for in-memory.
    ///
    /// # Errors
    /// Returns `CoreError::Storage` if the database cannot be opened or schema initialisation fails.
    pub fn open(path: &str) -> Result<Self, CoreError> {
        Self::open_with_hasher(path, Box::new(pos_crypto::chain::Blake3Hasher))
    }

    /// Open an existing `SQLite` store without creating or initializing it.
    ///
    /// This is intended for read-only consumers such as static-site builds.
    /// The database must already exist and contain the current schema.
    ///
    /// # Errors
    /// Returns `CoreError::Storage` if the database cannot be opened, has an
    /// unsupported encoding/schema, or fails invariant validation.
    pub fn open_read_only(path: &str) -> Result<Self, CoreError> {
        Self::open_with_options(
            path,
            Box::new(pos_crypto::chain::Blake3Hasher),
            OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_URI),
            false,
        )
    }

    /// Open a `SQLite` WAL store with a custom hasher.
    ///
    /// # Errors
    /// Returns `CoreError::Storage` if the database cannot be opened or schema initialisation fails.
    pub fn open_with_hasher(path: &str, hasher: Box<dyn Hasher>) -> Result<Self, CoreError> {
        Self::open_with_options(
            path,
            hasher,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
            true,
        )
    }

    fn open_with_options(
        path: &str,
        hasher: Box<dyn Hasher>,
        flags: OpenFlags,
        initialize_schema: bool,
    ) -> Result<Self, CoreError> {
        let conn = Connection::open_with_flags(path, flags)
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        Self::configure_busy_timeout(&conn).map_err(|e| CoreError::Storage(e.to_string()))?;

        Self::require_utf8_encoding(&conn)?;
        let store = Self {
            conn,
            hasher,
            clock: Box::new(SystemAdmissionClock),
            consent_authority_permit: None,
            #[cfg(test)]
            destruction_transaction_hook: None,
        };
        if initialize_schema {
            store.init_schema()?;
        } else {
            store.validate_erasure_schema()?;
        }
        store.validate_event_signature_schema()?;
        store.validate_event_sequence_invariant()?;
        Ok(store)
    }

    /// Open a `SQLite` store with a trusted admission clock.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] when the database cannot be opened.
    pub fn open_with_clock(path: &str, clock: Box<dyn AdmissionClock>) -> Result<Self, CoreError> {
        let mut store = Self::open(path)?;
        store.clock = clock;
        Ok(store)
    }

    /// Open an in-memory `SQLite` store (useful for tests without a temp file).
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] if the connection or schema initialisation fails.
    pub fn open_in_memory() -> Result<Self, CoreError> {
        #[cfg(test)]
        if FAIL_OPEN_IN_MEMORY.with(std::cell::Cell::get) {
            return Err(CoreError::Storage(
                "injected open_in_memory failure".to_owned(),
            ));
        }
        // Delegate to `open` so connection/schema errors share the same hittable paths.
        Self::open(":memory:")
    }

    /// Open an in-memory `SQLite` store with a custom hasher.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] if the connection or schema initialisation fails.
    pub fn open_in_memory_with_hasher(hasher: Box<dyn Hasher>) -> Result<Self, CoreError> {
        #[cfg(test)]
        if FAIL_OPEN_IN_MEMORY.with(std::cell::Cell::get) {
            return Err(CoreError::Storage(
                "injected open_in_memory failure".to_owned(),
            ));
        }
        Self::open_with_hasher(":memory:", hasher)
    }

    #[inline]
    fn query_prepared<'conn>(
        stmt: &'conn mut rusqlite::Statement<'_>,
        query_params: &[&dyn ToSql],
    ) -> rusqlite::Result<rusqlite::Rows<'conn>> {
        #[cfg(test)]
        if FAIL_STMT_QUERY.with(std::cell::Cell::get) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        stmt.query(query_params)
    }

    fn storage_error(error: &rusqlite::Error) -> CoreError {
        CoreError::Storage(error.to_string())
    }

    // `Result::map_err` supplies the owned error; keeping this function pointer
    // avoids duplicating closure-only coverage regions at every adapter boundary.
    #[allow(clippy::needless_pass_by_value)]
    fn into_storage_error(error: rusqlite::Error) -> CoreError {
        Self::storage_error(&error)
    }

    fn require_utf8_encoding(conn: &Connection) -> Result<(), CoreError> {
        let encoding: String = conn
            .query_row("PRAGMA encoding", [], |row| row.get(0))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        if encoding == "UTF-8" {
            Ok(())
        } else {
            Err(CoreError::Storage(format!(
                "unsupported SQLite encoding {encoding}; UTF-8 is required for bounded Event metadata"
            )))
        }
    }

    #[allow(clippy::too_many_lines)]
    fn init_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS timelines (
                 id          TEXT PRIMARY KEY,
                 name        TEXT,
                 mode        TEXT NOT NULL,
                 parent_id   TEXT,
                 fork_seq    INTEGER,
                 head_seq    INTEGER NOT NULL DEFAULT 0,
                 chain_head  BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS timeline_owners (
                 timeline_id TEXT PRIMARY KEY,
                 owner_id    TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS events (
                 timeline_id TEXT NOT NULL,
                 seq         INTEGER NOT NULL,
                 event_id    TEXT NOT NULL,
                 entity_id   TEXT NOT NULL,
                 event_type  TEXT NOT NULL,
                 payload     BLOB NOT NULL,
                 wall_time   INTEGER NOT NULL,
                 causation_id TEXT,
                 correlation_id TEXT,
                 schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                 payload_hash BLOB NOT NULL,
                 signature   BLOB,
                 signature_owner_id TEXT,
                 signature_role INTEGER,
                 signature_epoch INTEGER,
                 PRIMARY KEY (timeline_id, seq)
             );
             CREATE TABLE IF NOT EXISTS key_registry (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 state_cbor BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS erasure_records (
                 request_digest BLOB NOT NULL PRIMARY KEY CHECK (length(request_digest) = 32),
                 state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
                 record_cbor BLOB NOT NULL CHECK (length(record_cbor) <= 67108864)
             );
             CREATE TABLE IF NOT EXISTS erasure_states (
                 state_digest BLOB NOT NULL PRIMARY KEY CHECK (length(state_digest) = 32),
                 request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
                 state_cbor BLOB NOT NULL CHECK (length(state_cbor) <= 1048576)
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
             CREATE TABLE IF NOT EXISTS append_identities (
                 dedup_key BLOB PRIMARY KEY CHECK (length(dedup_key) = 32),
                 scope_key BLOB NOT NULL CHECK (length(scope_key) = 32),
                 event_id TEXT NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_append_identities_expiry
             ON append_identities(expires_at);
             CREATE INDEX IF NOT EXISTS idx_append_identities_scope
             ON append_identities(scope_key);
             CREATE TABLE IF NOT EXISTS pending_append_identity_cleanup (
                 scope_key BLOB PRIMARY KEY CHECK (length(scope_key) = 32)
             );
             CREATE TABLE IF NOT EXISTS geographic_presence (
                 timeline_id TEXT PRIMARY KEY,
                 has_evidence INTEGER NOT NULL CHECK (has_evidence = 1)
             );
             CREATE TABLE IF NOT EXISTS owntracks_enrollment (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 state_cbor BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS geographic_admission_snapshots (
                 event_id TEXT PRIMARY KEY,
                 snapshot_cbor BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS geographic_admission_links (
                 timeline_id TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 event_seq INTEGER NOT NULL,
                 snapshot_cbor BLOB NOT NULL,
                 PRIMARY KEY (timeline_id, event_id)
             );
             CREATE TABLE IF NOT EXISTS geographic_admission_dedup (
                 fingerprint BLOB PRIMARY KEY CHECK (length(fingerprint) = 32),
                 timeline_id TEXT NOT NULL,
                 intent BLOB NOT NULL CHECK (length(intent) = 32),
                 event_id TEXT NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_geographic_admission_dedup_expiry
             ON geographic_admission_dedup(expires_at);
             CREATE TABLE IF NOT EXISTS geographic_cell_admission_fences (
                 timeline_id TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 fence_cbor BLOB NOT NULL,
                 PRIMARY KEY (timeline_id, entity_id)
             );
             CREATE TABLE IF NOT EXISTS geographic_cell_admission_snapshots (
                 snapshot_id TEXT PRIMARY KEY,
                 snapshot_hash BLOB NOT NULL CHECK (length(snapshot_hash) = 32),
                 timeline_id TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 event_seq INTEGER NOT NULL,
                 snapshot_cbor BLOB NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_geo_cell_snapshots_event
             ON geographic_cell_admission_snapshots(timeline_id, event_id);
             CREATE TABLE IF NOT EXISTS geographic_cell_admission_links (
                 timeline_id TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 event_seq INTEGER NOT NULL,
                 snapshot_id TEXT NOT NULL,
                 snapshot_hash BLOB NOT NULL CHECK (length(snapshot_hash) = 32),
                 snapshot_cbor BLOB NOT NULL,
                 PRIMARY KEY (timeline_id, event_id)
             );
             CREATE TABLE IF NOT EXISTS geographic_cell_admission_dedup (
                 fingerprint BLOB PRIMARY KEY CHECK (length(fingerprint) = 32),
                 timeline_id TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 intent BLOB NOT NULL,
                 event_id TEXT NOT NULL,
                 event_seq INTEGER NOT NULL,
                 snapshot_id TEXT NOT NULL,
                 snapshot_hash BLOB NOT NULL CHECK (length(snapshot_hash) = 32),
                 expires_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_geo_cell_admission_dedup_expiry
             ON geographic_cell_admission_dedup(expires_at);
             CREATE TABLE IF NOT EXISTS geographic_cell_admission_consent_records (
                 consent_record_id TEXT NOT NULL,
                 consent_revision INTEGER NOT NULL,
                 consent_record_hash BLOB NOT NULL CHECK (length(consent_record_hash) = 32),
                 consent_record_cbor BLOB NOT NULL,
                 PRIMARY KEY (consent_record_id, consent_revision)
             );",
            )
            .map_err(|error| Self::storage_error(&error))?;
        self.validate_erasure_schema()
    }

    fn validate_erasure_schema(&self) -> Result<(), CoreError> {
        let tables = [
            (
                "erasure_records",
                "PRAGMA table_info(erasure_records)",
                [
                    ("request_digest", "BLOB", 1_i64, 1_i64),
                    ("state_digest", "BLOB", 1_i64, 0_i64),
                    ("record_cbor", "BLOB", 1_i64, 0_i64),
                ],
                [
                    "request_digest",
                    "state_digest",
                    "record_cbor",
                    "length(request_digest)=32",
                    "length(state_digest)=32",
                    "length(record_cbor)<=67108864",
                ],
            ),
            (
                "erasure_states",
                "PRAGMA table_info(erasure_states)",
                [
                    ("state_digest", "BLOB", 1_i64, 1_i64),
                    ("request_digest", "BLOB", 1_i64, 0_i64),
                    ("state_cbor", "BLOB", 1_i64, 0_i64),
                ],
                [
                    "state_digest",
                    "request_digest",
                    "state_cbor",
                    "length(state_digest)=32",
                    "length(request_digest)=32",
                    "length(state_cbor)<=1048576",
                ],
            ),
        ];
        for (table, columns_query, expected_columns, markers) in tables {
            let sql = self
                .conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| Self::storage_error(&error))?
                .ok_or_else(|| {
                    CoreError::Storage(format!("SQLite schema is missing {table} table"))
                })?;
            let normalized = sql
                .to_ascii_lowercase()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            if markers.iter().any(|marker| !normalized.contains(*marker)) {
                return Err(CoreError::Storage(format!(
                    "SQLite {table} table has an incompatible schema"
                )));
            }
            let mut statement = self
                .conn
                .prepare(columns_query)
                .map_err(Self::into_storage_error)?;
            let columns = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(Self::into_storage_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Self::into_storage_error)?;
            let expected_columns = expected_columns
                .map(|(name, kind, not_null, primary_key)| {
                    (name.to_owned(), kind.to_owned(), not_null, primary_key)
                })
                .to_vec();
            if columns != expected_columns {
                return Err(CoreError::Storage(format!(
                    "SQLite {table} table has an incompatible schema: columns or key constraints"
                )));
            }
        }
        Ok(())
    }

    fn validate_event_signature_schema(&self) -> Result<(), CoreError> {
        #[cfg(test)]
        let schema_query = if FAIL_SIGNATURE_SCHEMA_PREPARE.with(std::cell::Cell::get) {
            "PRAGMA table_info("
        } else if FAIL_SIGNATURE_SCHEMA_ROW.with(std::cell::Cell::get) {
            "SELECT 1"
        } else {
            "PRAGMA table_info(events)"
        };
        #[cfg(not(test))]
        let schema_query = "PRAGMA table_info(events)";
        let mut statement = self
            .conn
            .prepare(schema_query)
            .map_err(Self::into_storage_error)?;
        #[cfg(test)]
        let rows = {
            let invalid_parameter = 0_i64;
            let invalid_params: [&dyn ToSql; 1] = [&invalid_parameter];
            let query_params: &[&dyn ToSql] =
                if FAIL_SIGNATURE_SCHEMA_QUERY.with(std::cell::Cell::get) {
                    &invalid_params
                } else {
                    &[]
                };
            statement.query_map(query_params, |row| row.get::<_, String>(1))
        };
        #[cfg(not(test))]
        let rows = statement.query_map([], |row| row.get::<_, String>(1));
        let rows = rows.map_err(Self::into_storage_error)?;
        let mut columns = HashSet::new();
        for row in rows {
            columns.insert(row.map_err(Self::into_storage_error)?);
        }
        drop(statement);
        match (
            columns.contains("signature_owner_id"),
            columns.contains("signature_role"),
            columns.contains("signature_epoch"),
        ) {
            (true, true, true) => Ok(()),
            _ => Err(CoreError::Storage(
                "SQLite events table is missing required signature identity columns".to_owned(),
            )),
        }
    }

    fn geographic_fence_permits(
        &self,
        request: &GeoLocationAdmissionRequestV1,
    ) -> Result<bool, CoreError> {
        let persisted = self
            .conn
            .query_row(
                "SELECT state_cbor FROM owntracks_enrollment WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        persisted.map_or(Ok(false), |bytes| {
            OwnTracksEnrollmentStateV1::from_persistence_bytes(&bytes)
                .map(|state| state.permits_geographic_admission(request))
        })
    }

    fn geographic_fence_permits_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        request: &GeoLocationAdmissionRequestV1,
    ) -> Result<bool, CoreError> {
        let persisted = tx
            .query_row(
                "SELECT state_cbor FROM owntracks_enrollment WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        persisted.map_or(Ok(false), |bytes| {
            OwnTracksEnrollmentStateV1::from_persistence_bytes(&bytes)
                .map(|state| state.permits_geographic_admission(request))
        })
    }

    fn geographic_dedup_outcome(
        tx: &rusqlite::Transaction<'_>,
        request: &GeoLocationAdmissionRequestV1,
        admitted_at: WallTime,
    ) -> Result<Option<GeoLocationAdmissionOutcome>, CoreError> {
        let existing = tx.query_row(
            "SELECT intent, event_id, expires_at
             FROM geographic_admission_dedup WHERE fingerprint = ?1",
            params![request.fingerprint().as_owner_keyed_bytes().as_slice()],
            |row| {
                row.get::<_, Vec<u8>>(0).and_then(|intent| {
                    row.get::<_, String>(1).and_then(|event_id| {
                        row.get::<_, i64>(2)
                            .map(|expires| (intent, event_id, expires))
                    })
                })
            },
        );
        match existing {
            Ok((intent, event_id, expiry))
                if u64::try_from(expiry).unwrap_or(0) > admitted_at.as_micros() =>
            {
                let intent: [u8; 32] = intent.try_into().map_err(|_| {
                    CoreError::Storage(
                        "geographic admission dedup has invalid intent length".to_owned(),
                    )
                })?;
                let retained =
                    pos_core::geo_admission::GeoLocationAdmissionIntentV1::from_owner_keyed_bytes(
                        intent,
                    );
                let event_id = parse_event_id(&event_id)?;
                Ok(Some(GeoLocationAdmissionOutcome::classify_retained_intent(
                    request.intent(),
                    retained,
                    event_id,
                )))
            }
            Ok(_) => {
                tx.execute(
                    "DELETE FROM geographic_admission_dedup WHERE fingerprint = ?1",
                    params![request.fingerprint().as_owner_keyed_bytes().as_slice()],
                )
                .map_err(|error| CoreError::Storage(error.to_string()))?;
                Ok(None)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(CoreError::Storage(error.to_string())),
        }
    }

    fn geographic_admission_integrity_is_intact(
        tx: &rusqlite::Transaction<'_>,
        timeline: TimelineId,
    ) -> Result<bool, CoreError> {
        tx.query_row(
            "SELECT NOT EXISTS (
                SELECT 1
                FROM geographic_presence
                WHERE timeline_id = ?1
                  AND NOT EXISTS (
                    SELECT 1 FROM events
                    WHERE timeline_id = ?1 AND event_type IN (?2, ?3)
                  )
                UNION ALL
                SELECT 1
                FROM events AS event
                WHERE event.timeline_id = ?1
                  AND event.event_type IN (?2, ?3)
                  AND (
                    NOT EXISTS (
                        SELECT 1
                        FROM geographic_presence
                        WHERE timeline_id = event.timeline_id
                    )
                    OR NOT EXISTS (
                        SELECT 1
                        FROM geographic_admission_links AS link
                        JOIN geographic_admission_snapshots AS snapshot
                          ON snapshot.event_id = link.event_id
                         AND snapshot.snapshot_cbor = link.snapshot_cbor
                        WHERE link.timeline_id = event.timeline_id
                          AND link.event_id = event.event_id
                          AND link.event_seq = event.seq
                    )
                  )
                UNION ALL
                SELECT 1
                FROM geographic_admission_links AS link
                WHERE link.timeline_id = ?1
                  AND NOT EXISTS (
                    SELECT 1
                    FROM events AS event
                    JOIN geographic_admission_snapshots AS snapshot
                      ON snapshot.event_id = link.event_id
                     AND snapshot.snapshot_cbor = link.snapshot_cbor
                    WHERE event.timeline_id = link.timeline_id
                      AND event.event_id = link.event_id
                      AND event.seq = link.event_seq
                      AND event.event_type IN (?2, ?3)
                  )
                UNION ALL
                SELECT 1
                FROM geographic_admission_snapshots AS snapshot
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM geographic_admission_links AS link
                    JOIN events AS event
                      ON event.timeline_id = link.timeline_id
                     AND event.event_id = link.event_id
                     AND event.seq = link.event_seq
                     AND event.event_type IN (?2, ?3)
                    WHERE link.event_id = snapshot.event_id
                      AND link.snapshot_cbor = snapshot.snapshot_cbor
                )
            )",
            params![
                timeline.to_string(),
                pos_core::GEOGRAPHIC_EVENT_TYPE,
                pos_core::GEOGRAPHIC_CELL_EVENT_TYPE,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map(|intact| intact == 1)
        .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn validate_event_sequence_invariant(&self) -> Result<(), CoreError> {
        const SQL: &str = "SELECT EXISTS (
                    SELECT 1
                    FROM (
                        SELECT timelines.head_seq AS head_seq,
                               typeof(timelines.head_seq) AS head_storage_class,
                               count(events.seq) AS event_count,
                               min(events.seq) AS first_seq,
                               max(events.seq) AS last_seq,
                               sum(
                                   CASE
                                       WHEN events.seq IS NOT NULL
                                        AND typeof(events.seq) != 'integer'
                                       THEN 1 ELSE 0
                                   END
                               ) AS invalid_seq_types
                        FROM timelines
                        LEFT JOIN events ON events.timeline_id = timelines.id
                        GROUP BY timelines.id
                    )
                    WHERE head_storage_class != 'integer'
                       OR invalid_seq_types != 0
                       OR head_seq != event_count
                       OR (head_seq > 0 AND (first_seq != 1 OR last_seq != head_seq))
                )";
        #[cfg(test)]
        if FAIL_SEQUENCE_VALIDATION_QUERY.with(std::cell::Cell::get) {
            return Err(CoreError::Storage(
                "injected sequence validation failure".to_owned(),
            ));
        }
        let query = self.conn.query_row(SQL, [], read_first_i64);
        let invalid = match query {
            Ok(invalid) => invalid,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        if invalid == 0 {
            Ok(())
        } else {
            Err(CoreError::Storage(
                "SQLite Event rows must be contiguous from seq 1 through timelines.head_seq"
                    .to_owned(),
            ))
        }
    }

    fn get_head_seq(&self, timeline_id: TimelineId) -> Result<Seq, CoreError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT head_seq FROM timelines WHERE id = ?1",
                params![timeline_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| Self::storage_error(&error))?;
        Ok(Seq::from_u64(u64::try_from(n).unwrap_or(0)))
    }

    /// Read raw events directly from a timeline row (no fork stitching).
    fn read_own_events(
        &self,
        timeline_id: TimelineId,
        from: Seq,
        to: Option<Seq>,
    ) -> Result<Vec<Event>, CoreError> {
        Self::read_own_events_on(&self.conn, timeline_id, from, to)
    }

    fn read_own_events_on(
        conn: &Connection,
        timeline_id: TimelineId,
        from: Seq,
        to: Option<Seq>,
    ) -> Result<Vec<Event>, CoreError> {
        Self::read_own_events_limited_on(conn, timeline_id, from, to, None, None, u64::MAX)
    }

    fn read_own_events_limited_on(
        conn: &Connection,
        timeline_id: TimelineId,
        from: Seq,
        to: Option<Seq>,
        limit: Option<usize>,
        started: Option<Instant>,
        max_elapsed_micros: u64,
    ) -> Result<Vec<Event>, CoreError> {
        const SQL: &str = "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                                causation_id, correlation_id, schema_version, payload_hash, signature,
                                signature_owner_id, signature_role, signature_epoch
                         FROM events
                         WHERE timeline_id = ?1
                           AND seq >= ?2
                           AND (?3 IS NULL OR seq <= ?3)
                         ORDER BY seq ASC
                         LIMIT ?4";
        let sql_limit = limit.map_or(i64::MAX, |value| i64::try_from(value).unwrap_or(i64::MAX));
        let prepared = conn.prepare(SQL);
        let mut stmt = prepared.map_err(|error| CoreError::Storage(error.to_string()))?;
        let timeline_id_param = timeline_id.to_string();
        let from_param = seq_as_i64(from);
        let to_param = to.map(seq_as_i64);
        let query_params: [&dyn ToSql; 4] =
            [&timeline_id_param, &from_param, &to_param, &sql_limit];
        let mut rows = match Self::query_prepared(&mut stmt, &query_params) {
            Ok(rows) => rows,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let mut events = Vec::new();
        loop {
            #[cfg(test)]
            bounded_read_delay_for_test(1);
            if let Some(started) = started {
                let elapsed_micros =
                    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                if elapsed_micros > max_elapsed_micros {
                    return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
                }
            }
            #[cfg(test)]
            if FAIL_ROWS_NEXT.with(std::cell::Cell::get) {
                return Err(CoreError::Storage(
                    "injected row iteration failure".to_owned(),
                ));
            }
            let next = rows.next();
            let row = match next.map_err(|e| CoreError::Storage(e.to_string())) {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(e) => return Err(e),
            };
            #[cfg(test)]
            if limit.is_some() {
                BOUNDED_EVENT_ROWS.with(|count| count.set(count.get().saturating_add(1)));
            }
            events.push(decode_event_row(row)?);
        }

        #[cfg(test)]
        bounded_read_delay_for_test(2);
        if let Some(started) = started {
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > max_elapsed_micros {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
        }

        Ok(events)
    }

    fn validate_own_events_bounded(
        conn: &Connection,
        timeline_id: TimelineId,
        from: Seq,
        to: Seq,
        max_events: usize,
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<usize, CoreError> {
        const SQL: &str = "SELECT seq, typeof(payload), length(CAST(payload AS BLOB)),
                                length(CAST(event_type AS BLOB))
                         FROM events
                         WHERE timeline_id = ?1 AND seq >= ?2 AND seq <= ?3
                         ORDER BY seq ASC
                         LIMIT ?4";
        let sql_limit = i64::try_from(max_events).unwrap_or(i64::MAX);
        let mut stmt = match conn.prepare(SQL) {
            Ok(stmt) => stmt,
            Err(error) => {
                let message = error.to_string();
                return Err(CoreError::Storage(message));
            }
        };
        let timeline_id_param = timeline_id.to_string();
        let from_param = seq_as_i64(from);
        let to_param = seq_as_i64(to);
        let query_params: [&dyn ToSql; 4] =
            [&timeline_id_param, &from_param, &to_param, &sql_limit];
        let mut rows = match Self::query_prepared(&mut stmt, &query_params) {
            Ok(rows) => rows,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let mut field_sizes: Vec<(String, i64, i64)> = Vec::new();
        loop {
            #[cfg(test)]
            bounded_read_delay_for_test(3);
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > bounds.max_elapsed_micros() {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
            #[cfg(test)]
            if FAIL_ROWS_NEXT.with(std::cell::Cell::get) {
                return Err(CoreError::Storage(
                    "injected row iteration failure".to_owned(),
                ));
            }
            let next = rows.next();
            match next {
                Ok(Some(row)) => {
                    #[cfg(test)]
                    BOUNDED_METADATA_ROWS.with(|count| count.set(count.get().saturating_add(1)));
                    let _: i64 = match row.get(0) {
                        Ok(seq) => seq,
                        Err(error) => return Err(CoreError::Storage(error.to_string())),
                    };
                    let payload_type: String = row
                        .get(1)
                        .map_err(|error| CoreError::Storage(error.to_string()))?;
                    let payload_length: i64 = row
                        .get(2)
                        .map_err(|error| CoreError::Storage(error.to_string()))?;
                    let event_type_length: i64 = row
                        .get(3)
                        .map_err(|error| CoreError::Storage(error.to_string()))?;
                    field_sizes.push((payload_type, payload_length, event_type_length));
                }
                Ok(None) => break,
                Err(error) => {
                    let message = error.to_string();
                    return Err(CoreError::Storage(message));
                }
            }
        }

        #[cfg(test)]
        bounded_read_delay_for_test(4);
        let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        if elapsed_micros > bounds.max_elapsed_micros() {
            return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
        }
        if field_sizes.len() != max_events {
            return Err(CoreError::Storage(format!(
                "timeline {timeline_id} violates the contiguous Event sequence invariant"
            )));
        }
        let total_bytes = Self::validate_bounded_event_metadata(&field_sizes, bounds, started)?;

        Ok(total_bytes)
    }

    fn validate_bounded_event_metadata(
        field_sizes: &[(String, i64, i64)],
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<usize, CoreError> {
        let mut total_bytes = 0_usize;
        for (payload_storage_class, stored_payload_size, stored_event_type_size) in field_sizes {
            #[cfg(test)]
            bounded_read_delay_for_test(9);
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > bounds.max_elapsed_micros() {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
            if payload_storage_class != "blob" {
                return Err(CoreError::Storage(format!(
                    "event payload has SQLite storage class {payload_storage_class}; BLOB is required for bounded reads"
                )));
            }
            let payload_size = sqlite_usize_or_max(*stored_payload_size);
            if payload_size > bounds.max_payload_bytes() {
                return Err(CoreError::PayloadTooLarge { size: payload_size });
            }
            let event_type_size = sqlite_usize_or_max(*stored_event_type_size);
            if event_type_size > bounds.max_event_type_bytes() {
                return Err(CoreError::EventMetadataTooLarge {
                    field: "event_type",
                    size: event_type_size,
                });
            }
            total_bytes = total_bytes.saturating_add(payload_size.saturating_add(event_type_size));
            if total_bytes > bounds.max_total_bytes() {
                return Err(CoreError::ReadBytesTooLarge { size: total_bytes });
            }
        }
        Ok(total_bytes)
    }

    fn read_logical_bounded(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<Event>, CoreError> {
        let tx = match self.conn.unchecked_transaction() {
            Ok(tx) => tx,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let chain = Self::fork_chain_bounded_on(
            &tx,
            timeline_id,
            bounds.max_fork_depth(),
            started,
            bounds.max_elapsed_micros(),
        )?;
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(u64::MAX, Seq::as_u64);
        Self::plan_bounded_pages(&tx, &chain, from, to, bounds, started)
            .and_then(|plans| Self::materialize_bounded_pages(&tx, &plans, bounds, started))
    }

    fn plan_bounded_pages(
        conn: &rusqlite::Transaction<'_>,
        chain: &[BoundedForkSegment],
        from: u64,
        to: u64,
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<BoundedSegmentPage>, CoreError> {
        let mut logical_offset = 0_u64;
        let mut remaining = bounds.max_events();
        let mut total_bytes = 0_usize;
        let mut plans = Vec::new();

        for (index, segment) in chain.iter().enumerate() {
            #[cfg(test)]
            bounded_read_delay_for_test(5);
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > bounds.max_elapsed_micros() {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
            let segment_prefix = segment.fork.map_or(0, Seq::as_u64);
            let segment_len = chain.get(index + 1).and_then(|next| next.fork).map_or(
                Ok(segment.head),
                |cap| {
                    cap.as_u64().checked_sub(segment_prefix).ok_or_else(|| {
                        CoreError::Storage(format!(
                            "Fork point precedes inherited history for timeline {}",
                            segment.id
                        ))
                    })
                },
            )?;
            if segment_len > segment.head {
                return Err(CoreError::Storage(format!(
                    "Fork point exceeds parent logical Event head for timeline {}",
                    segment.id
                )));
            }
            if let Some(plan) =
                crate::stitch::plan_page(logical_offset, segment_len, from, to, remaining)
            {
                let raw_from = Seq::from_u64(plan.raw_start);
                let take = plan.take;
                let raw_to = Seq::from_u64(
                    raw_from
                        .as_u64()
                        .saturating_add(u64::try_from(take - 1).unwrap_or(u64::MAX)),
                );
                let segment_bounds = bounds
                    .with_max_total_bytes(bounds.max_total_bytes().saturating_sub(total_bytes));
                let segment_bytes = match Self::validate_own_events_bounded(
                    conn,
                    segment.id,
                    raw_from,
                    raw_to,
                    take,
                    segment_bounds,
                    started,
                ) {
                    Ok(bytes) => bytes,
                    Err(CoreError::ReadBytesTooLarge { size }) => {
                        return Err(CoreError::ReadBytesTooLarge {
                            size: total_bytes.saturating_add(size),
                        })
                    }
                    Err(error) => return Err(error),
                };
                total_bytes = total_bytes.saturating_add(segment_bytes);
                plans.push(BoundedSegmentPage {
                    id: segment.id,
                    raw_from,
                    raw_to,
                    take,
                    logical_offset,
                    bounds: segment_bounds,
                });
                remaining -= take;
            }
            logical_offset = logical_offset.saturating_add(segment_len);
            if remaining == 0 || logical_offset >= to {
                break;
            }
        }
        Ok(plans)
    }

    fn materialize_bounded_pages(
        conn: &rusqlite::Transaction<'_>,
        plans: &[BoundedSegmentPage],
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<Event>, CoreError> {
        let mut selected = Vec::new();
        for plan in plans {
            #[cfg(test)]
            bounded_read_delay_for_test(6);
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > bounds.max_elapsed_micros() {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
            #[cfg(test)]
            BOUNDED_EVENT_QUERIES.with(|queries| queries.set(queries.get() + 1));
            let mut events = Self::read_own_events_limited_on(
                conn,
                plan.id,
                plan.raw_from,
                Some(plan.raw_to),
                Some(plan.take),
                Some(started),
                plan.bounds.max_elapsed_micros(),
            )?;
            for event in &mut events {
                event.seq = Seq::from_u64(plan.logical_offset.saturating_add(event.seq.as_u64()));
            }
            selected.extend(events);
            #[cfg(test)]
            bounded_materialization_delay_for_test();
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > bounds.max_elapsed_micros() {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
        }
        #[cfg(test)]
        bounded_read_delay_for_test(7);
        let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        if elapsed_micros > bounds.max_elapsed_micros() {
            return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
        }
        Ok(selected)
    }

    /// Walk the fork chain for a timeline, returning [root, ..., leaf].
    fn fork_chain(&self, timeline_id: TimelineId) -> Result<ForkChain, CoreError> {
        Self::fork_chain_on(&self.conn, timeline_id)
    }

    fn fork_chain_on(conn: &Connection, timeline_id: TimelineId) -> Result<ForkChain, CoreError> {
        Self::fork_chain_with_leaf_head_on(conn, timeline_id).map(|(chain, _)| chain)
    }

    fn fork_chain_with_leaf_head_on(
        conn: &Connection,
        timeline_id: TimelineId,
    ) -> Result<ForkChainWithLeafHead, CoreError> {
        let mut chain = Vec::new();
        let mut leaf_head = 0;
        let mut visited = HashSet::new();
        let mut current = timeline_id;
        loop {
            if !visited.insert(current) {
                return Err(CoreError::Storage(format!(
                    "fork ancestry contains a cycle at timeline {current}"
                )));
            }
            let row = match conn
                .query_row(
                    "SELECT parent_id, fork_seq, head_seq FROM timelines WHERE id = ?1",
                    params![current.to_string()],
                    ForkChainRow::read,
                )
                .optional()
            {
                Ok(row) => row,
                Err(error) => return Err(CoreError::Storage(error.to_string())),
            };
            let row = match row {
                Some(row) => Some(row.decode(current)?),
                None => None,
            };

            match row {
                None => return Err(CoreError::TimelineNotFound(current)),
                Some(DecodedForkChainRow::Root { head }) => {
                    if chain.is_empty() {
                        leaf_head = head;
                    }
                    chain.push((current, Seq::ZERO));
                    break;
                }
                Some(DecodedForkChainRow::Fork { parent, fork, head }) => {
                    if chain.is_empty() {
                        leaf_head = head;
                    }
                    chain.push((current, fork));
                    current = parent;
                }
            }
        }
        chain.reverse();
        Ok((chain, leaf_head))
    }

    fn logical_segment_length(
        &self,
        chain: &[(TimelineId, Seq)],
        index: usize,
        timeline: TimelineId,
    ) -> Result<u64, CoreError> {
        let prefix = chain[index].1.as_u64();
        let local_head = self.get_head_seq(timeline)?.as_u64();
        let length = chain.get(index + 1).map_or(Ok(local_head), |(_, fork)| {
            fork.as_u64().checked_sub(prefix).ok_or_else(|| {
                CoreError::Storage(format!(
                    "Fork point precedes inherited history for timeline {timeline}"
                ))
            })
        })?;
        if length > local_head {
            return Err(CoreError::Storage(format!(
                "Fork point exceeds parent logical Event head for timeline {timeline}"
            )));
        }
        Ok(length)
    }

    fn add_logical_segment(logical_head: u64, segment: u64) -> Result<u64, CoreError> {
        logical_head
            .checked_add(segment)
            .ok_or_else(|| CoreError::Storage("logical Timeline head overflow".to_owned()))
    }

    fn fork_chain_bounded_on(
        conn: &Connection,
        timeline_id: TimelineId,
        max_depth: usize,
        started: Instant,
        max_elapsed_micros: u64,
    ) -> Result<Vec<BoundedForkSegment>, CoreError> {
        let mut chain = Vec::new();
        let mut current = timeline_id;
        let mut depth = 0_usize;
        loop {
            #[cfg(test)]
            bounded_read_delay_for_test(8);
            let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            if elapsed_micros > max_elapsed_micros {
                return Err(CoreError::ReadTimeTooLarge { elapsed_micros });
            }
            let chain_query = {
                #[cfg(test)]
                if FAIL_BOUNDED_CHAIN_QUERY.with(std::cell::Cell::get) {
                    Err(rusqlite::Error::InvalidQuery)
                } else {
                    conn.query_row(
                        "SELECT parent_id, fork_seq, head_seq FROM timelines WHERE id = ?1",
                        params![current.to_string()],
                        ForkChainRow::read,
                    )
                    .optional()
                }
                #[cfg(not(test))]
                {
                    conn.query_row(
                        "SELECT parent_id, fork_seq, head_seq FROM timelines WHERE id = ?1",
                        params![current.to_string()],
                        ForkChainRow::read,
                    )
                    .optional()
                }
            };
            let row = match chain_query {
                Ok(row) => row,
                Err(error) => return Err(CoreError::Storage(error.to_string())),
            };
            let row = match row {
                Some(row) => row.decode(current)?,
                None => return Err(CoreError::TimelineNotFound(current)),
            };

            match row {
                DecodedForkChainRow::Root { head } => {
                    chain.push(BoundedForkSegment {
                        id: current,
                        fork: None,
                        head,
                    });
                    break;
                }
                DecodedForkChainRow::Fork { parent, fork, head } => {
                    let next_depth = depth.saturating_add(1);
                    if next_depth > max_depth {
                        return Err(CoreError::ForkDepthTooLarge { depth: next_depth });
                    }
                    chain.push(BoundedForkSegment {
                        id: current,
                        fork: Some(fork),
                        head,
                    });
                    depth = next_depth;
                    current = parent;
                }
            }
        }
        chain.reverse();
        Ok(chain)
    }
}

#[derive(Debug)]
struct BoundedForkSegment {
    id: TimelineId,
    fork: Option<Seq>,
    head: u64,
}

#[derive(Clone, Copy)]
struct BoundedSegmentPage {
    id: TimelineId,
    raw_from: Seq,
    raw_to: Seq,
    take: usize,
    logical_offset: u64,
    bounds: EventReadBounds,
}

#[derive(Debug)]
struct ForkChainRow {
    parent_id: Option<String>,
    fork_seq: Option<i64>,
    head_seq: i64,
}

/// A stitched Timeline ancestry entry. The root's prefix is always zero;
/// non-root entries carry their validated fork sequence.
type ForkChain = Vec<(TimelineId, Seq)>;
type ForkChainWithLeafHead = (ForkChain, u64);

#[derive(Debug)]
enum DecodedForkChainRow {
    Root {
        head: u64,
    },
    Fork {
        parent: TimelineId,
        fork: Seq,
        head: u64,
    },
}

impl ForkChainRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        row.get(0).and_then(|parent_id| {
            row.get(1).and_then(|fork_seq| {
                row.get(2).map(|head_seq| Self {
                    parent_id,
                    fork_seq,
                    head_seq,
                })
            })
        })
    }

    fn decode(self, current: TimelineId) -> Result<DecodedForkChainRow, CoreError> {
        let head = u64::try_from(self.head_seq).map_err(|_| {
            CoreError::Storage(format!("timeline {current} has a negative Event head"))
        })?;
        match (self.parent_id, self.fork_seq) {
            (None, None) => Ok(DecodedForkChainRow::Root { head }),
            (None, Some(_)) => Err(CoreError::Storage(format!(
                "root timeline {current} has Fork sequence metadata"
            ))),
            (Some(parent), Some(fork_seq)) => {
                let parent = parse_timeline_id(&parent)?;
                let fork = u64::try_from(fork_seq).map_err(|_| {
                    CoreError::Storage(format!(
                        "Fork timeline {current} has a negative Fork sequence"
                    ))
                })?;
                Ok(DecodedForkChainRow::Fork {
                    parent,
                    fork: Seq::from_u64(fork),
                    head,
                })
            }
            (Some(_), None) => Err(CoreError::Storage(format!(
                "Fork timeline {current} is missing its Fork sequence"
            ))),
        }
    }
}

#[derive(Debug)]
struct TimelineRow {
    id: String,
    name: Option<String>,
    mode: String,
    parent_id: Option<String>,
    fork_seq: Option<i64>,
    head_seq: i64,
}

struct GeographicCellDedupRow {
    timeline: TimelineId,
    entity: EntityId,
    intent: Vec<u8>,
    event_id: EventId,
    event_seq: Seq,
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
}

fn read_first_i64(row: &rusqlite::Row<'_>) -> rusqlite::Result<i64> {
    row.get(0)
}

fn sqlite_usize_or_max(value: i64) -> usize {
    // SQLite `length(BLOB)` and `count(*)` are non-negative. Saturating an
    // unexpected negative or platform-width overflow remains fail-closed for
    // payload bounds and avoids wrapping to a small allocation.
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn read_timeline_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineRow> {
    Ok(TimelineRow {
        id: row.get(0)?,
        name: row.get(1)?,
        mode: row.get(2)?,
        parent_id: row.get(3)?,
        fork_seq: row.get(4)?,
        head_seq: row.get(5)?,
    })
}

fn timeline_fields_to_timeline(
    id_str: &str,
    name: Option<String>,
    mode_s: &str,
    parent_id: Option<String>,
    fork_seq: Option<i64>,
    head_seq: i64,
) -> Result<Timeline, CoreError> {
    let id = parse_timeline_id(id_str)?;
    let mode = parse_mode(mode_s);
    let fork_point = match (parent_id, fork_seq) {
        (Some(p), Some(s)) => Some((
            parse_timeline_id(&p)?,
            Seq::from_u64(u64::try_from(s).unwrap_or(0)),
        )),
        _ => None,
    };
    let meta = TimelineMeta {
        id,
        mode,
        name,
        owner: None,
        fork_point,
    };
    let mut tl = Timeline::new(meta);
    tl.head = Seq::from_u64(u64::try_from(head_seq).unwrap_or(0));
    Ok(tl)
}

impl SqliteStore {
    fn append_or_duplicate_with_limit(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: &EventDraft,
        max_owned_events: Option<u64>,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        crate::ensure_non_geographic_draft(draft, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                self.append_or_duplicate_with_limit_visible(
                    timeline,
                    identity,
                    admitted_at,
                    draft,
                    max_owned_events,
                )
            })
    }

    fn append_or_duplicate_with_limit_visible(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: &EventDraft,
        max_owned_events: Option<u64>,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        let logical_prefix = self.logical_prefix(timeline)?;
        self.get_head_seq(timeline)
            .map(Seq::as_u64)
            .and_then(|head_seq| {
                let tx = self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(Self::into_storage_error)?;
                let existing = tx.query_row(
                    "SELECT event_id, expires_at FROM append_identities WHERE dedup_key = ?1",
                    params![identity.dedup_key.as_bytes().as_slice()],
                    |row| {
                        row.get::<_, String>(0).and_then(|event_id| {
                            row.get::<_, i64>(1).map(|expires| (event_id, expires))
                        })
                    },
                );
                match existing {
                    Ok((event_id, expires_at))
                        if u64::try_from(expires_at).unwrap_or(0) > admitted_at.as_micros() =>
                    {
                        return Self::retained_event_matches_draft(&tx, &event_id, timeline, draft)
                            .and_then(|matches| {
                                if matches {
                                    parse_event_id(&event_id).map(|id| {
                                        Some(AppendOrDuplicateOutcome::Duplicate { event_id: id })
                                    })
                                } else {
                                    Ok(Some(AppendOrDuplicateOutcome::Conflict))
                                }
                            });
                    }
                    Err(rusqlite::Error::QueryReturnedNoRows) => {}
                    Err(error) => return Err(CoreError::Storage(error.to_string())),
                    Ok(_) => {
                        tx.execute(
                            "DELETE FROM append_identities WHERE dedup_key = ?1",
                            params![identity.dedup_key.as_bytes().as_slice()],
                        )
                        .map_err(|error| CoreError::Storage(error.to_string()))?;
                    }
                }
                if max_owned_events.is_some_and(|maximum| head_seq >= maximum) {
                    return Ok(None);
                }
                let expires_at = checked_append_identity_expires_at(admitted_at)?;
                let event = Self::append_one_in_transaction(
                    &tx,
                    self.hasher.as_ref(),
                    timeline,
                    draft.clone(),
                )?;
                tx.execute(
                    "INSERT INTO append_identities (dedup_key, scope_key, event_id, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
                    params![
                        identity.dedup_key.as_bytes().as_slice(),
                        identity.scope.as_bytes().as_slice(),
                        event.id.to_string(),
                        i64::try_from(expires_at.as_micros()).unwrap_or(i64::MAX),
                    ],
                )
                .map_err(|error| CoreError::Storage(error.to_string()))?;
                tx.commit()
                    .map_err(|error| CoreError::Storage(error.to_string()))?;
                Self::logical_event(logical_prefix, event)
                    .map(|event| Some(AppendOrDuplicateOutcome::Appended(Box::new(event))))
            })
    }
}

impl SqliteStore {
    #[inline]
    fn timeline_contains_geographic_evidence(
        &self,
        timeline: TimelineId,
    ) -> Result<bool, CoreError> {
        match self.conn.query_row(
            "SELECT EXISTS (
                WITH RECURSIVE timeline_lineage(timeline_id) AS (
                    SELECT ?1
                    UNION
                    SELECT timelines.parent_id
                    FROM timelines
                    JOIN timeline_lineage
                      ON timelines.id = timeline_lineage.timeline_id
                    WHERE timelines.parent_id IS NOT NULL
                )
                SELECT 1
                FROM geographic_presence
                JOIN timeline_lineage
                  ON geographic_presence.timeline_id = timeline_lineage.timeline_id
                UNION ALL
                SELECT 1
                FROM events
                JOIN timeline_lineage
                  ON events.timeline_id = timeline_lineage.timeline_id
                WHERE events.event_type IN (?2, ?3)
            )",
            params![
                timeline.to_string(),
                pos_core::GEOGRAPHIC_EVENT_TYPE,
                pos_core::GEOGRAPHIC_CELL_EVENT_TYPE,
            ],
            |row| row.get(0),
        ) {
            Ok(contains) => Ok(contains),
            Err(error) => Err(Self::storage_error(&error)),
        }
    }

    fn ensure_generic_timeline_visibility(&self, timeline: TimelineId) -> Result<(), CoreError> {
        crate::ensure_generic_timeline_visibility(
            self.timeline_contains_geographic_evidence(timeline),
            timeline,
        )
    }

    fn ensure_admin_visibility(&self, timeline: TimelineId) -> Result<(), CoreError> {
        crate::ensure_generic_timeline_visibility(
            self.timeline_contains_geographic_evidence(timeline),
            timeline,
        )
    }

    fn append_visible(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        if drafts.is_empty() {
            return Ok(Vec::new());
        }
        let logical_prefix = self.logical_prefix(timeline)?;
        let mut committed = Vec::with_capacity(drafts.len());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        for draft in drafts {
            committed.push(Self::append_one_in_transaction(
                &tx,
                self.hasher.as_ref(),
                timeline,
                draft.clone(),
            )?);
        }
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        committed
            .into_iter()
            .map(|event| Self::logical_event(logical_prefix, event))
            .collect()
    }

    fn append_bounded_visible(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        max_owned_events: u64,
        gateway_consent: bool,
        permit: Option<ConsentAppendPermit>,
        cleanup_scope: Option<AppendDedupScope>,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        if gateway_consent {
            let bound_permit = self.consent_authority_permit.ok_or_else(|| {
                CoreError::Storage("Gateway consent authority is not bound".to_owned())
            })?;
            let permit = permit.ok_or_else(|| {
                CoreError::Storage("Gateway consent append permit is missing".to_owned())
            })?;
            if permit != bound_permit {
                return Err(CoreError::Storage(
                    "Gateway consent append permit does not match the bound authority".to_owned(),
                ));
            }
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let (chain, owned_head) = Self::fork_chain_with_leaf_head_on(&tx, timeline)?;
        let logical_prefix = chain.last().map_or(0, |(_, fork)| fork.as_u64());
        let owner = if gateway_consent {
            Some(crate::ensure_gateway_consent_drafts(
                drafts,
                timeline,
                Self::timeline_owner_in_transaction(&tx, timeline)?,
                logical_prefix.saturating_add(owned_head).saturating_add(1),
            )?)
        } else {
            None
        };
        let batch_len = u64::try_from(drafts.len()).unwrap_or(u64::MAX);
        let next_head = owned_head.saturating_add(batch_len);
        if next_head > max_owned_events {
            return Ok(None);
        }
        let mut committed = Vec::with_capacity(drafts.len());
        for draft in drafts {
            committed.push(Self::append_one_in_transaction(
                &tx,
                self.hasher.as_ref(),
                timeline,
                draft.clone(),
            )?);
        }
        if let Some(scope) = cleanup_scope {
            tx.execute(
                "INSERT OR IGNORE INTO pending_append_identity_cleanup (scope_key) VALUES (?1)",
                params![scope.as_bytes().as_slice()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        }
        let owner_result = owner.map_or_else(
            || Ok(()),
            |owner| {
                Self::timeline_owner_in_transaction(&tx, timeline).and_then(|current| {
                    current.map_or_else(
                        || Self::persist_timeline_owner(&tx, timeline, owner),
                        |_| Ok(()),
                    )
                })
            },
        );
        owner_result
            .and_then(|()| tx.commit().map_err(Self::into_storage_error))
            .map(|()| {
                Some(
                    committed
                        .into_iter()
                        .map(|mut event| {
                            event.seq = Seq::from_u64(logical_prefix + event.seq.as_u64());
                            event
                        })
                        .collect(),
                )
            })
    }

    fn logical_prefix(&self, timeline: TimelineId) -> Result<u64, CoreError> {
        self.get_timeline(timeline)?
            .ok_or(CoreError::TimelineNotFound(timeline))
            .map(|timeline| {
                timeline
                    .meta
                    .fork_point
                    .map_or(0, |(_, fork)| fork.as_u64())
            })
    }

    fn logical_event(prefix: u64, mut event: Event) -> Result<Event, CoreError> {
        event.seq =
            Seq::from_u64(prefix.checked_add(event.seq.as_u64()).ok_or_else(|| {
                CoreError::Storage("logical Timeline sequence overflow".to_owned())
            })?);
        Ok(event)
    }
}

impl OwnTracksEnrollmentStore for SqliteStore {
    fn pair_owntracks_enrollment(
        &mut self,
        request: OwnTracksEnrollmentRequestV1,
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        let timeline = request.timeline();
        let exists = self
            .conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM timelines WHERE id = ?1)",
                params![timeline.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        if exists != 1 {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let current = Self::enrollment_state_in_transaction(&tx)?;
        let next = current.pair(&request)?;
        Self::write_enrollment_state(&tx, &next)?;
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(next.status())
    }

    fn owntracks_enrollment_status(&self) -> Result<OwnTracksEnrollmentStatusViewV1, CoreError> {
        let state = self
            .conn
            .query_row(
                "SELECT state_cbor FROM owntracks_enrollment WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?
            .map_or(Ok(OwnTracksEnrollmentStateV1::absent()), |bytes| {
                OwnTracksEnrollmentStateV1::from_persistence_bytes(&bytes)
            })?;
        Ok(state.status_view())
    }

    fn rotate_owntracks_enrollment_verifier(
        &mut self,
        verifier: [u8; 32],
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.transition_enrollment_state(|state| state.rotate(verifier))
    }

    fn revoke_owntracks_enrollment(&mut self) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.transition_enrollment_state(OwnTracksEnrollmentStateV1::revoke)
    }
}

impl OwnTracksIngressStore for SqliteStore {
    fn prepare_owntracks_ingress(
        &mut self,
        input: OwnTracksIngressInputV1,
    ) -> Result<PreparedOwnTracksIngressV1, CoreError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let enrollment = Self::enrollment_state_in_transaction(&tx)?;
        tx.commit()
            .map_err(Self::into_storage_error)
            .and_then(|()| enrollment.prepare_owntracks_ingress(&input))
    }
}

impl SqliteStore {
    fn enrollment_state_in_transaction(
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<OwnTracksEnrollmentStateV1, CoreError> {
        tx.query_row(
            "SELECT state_cbor FROM owntracks_enrollment WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| CoreError::Storage(error.to_string()))?
        .map_or(Ok(OwnTracksEnrollmentStateV1::absent()), |bytes| {
            OwnTracksEnrollmentStateV1::from_persistence_bytes(&bytes)
        })
    }

    fn write_enrollment_state(
        tx: &rusqlite::Transaction<'_>,
        state: &OwnTracksEnrollmentStateV1,
    ) -> Result<(), CoreError> {
        state.persistence_bytes().and_then(|bytes| {
            tx.execute(
                "INSERT INTO owntracks_enrollment (singleton, state_cbor) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET state_cbor = excluded.state_cbor",
                params![bytes],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))
            .map(|_| ())
        })
    }

    fn transition_enrollment_state(
        &mut self,
        transition: impl FnOnce(
            OwnTracksEnrollmentStateV1,
        ) -> Result<OwnTracksEnrollmentStateV1, CoreError>,
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let next = transition(Self::enrollment_state_in_transaction(&tx)?)?;
        Self::write_enrollment_state(&tx, &next)?;
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(next.status())
    }
}

impl SqliteStore {
    fn geo_cell_fence_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        timeline: TimelineId,
        entity: EntityId,
    ) -> Result<Option<GeoCellAdmissionFenceV1>, CoreError> {
        let bytes = tx
            .query_row(
                "SELECT fence_cbor FROM geographic_cell_admission_fences
                 WHERE timeline_id = ?1 AND entity_id = ?2",
                params![timeline.to_string(), entity.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        bytes
            .map(|bytes| GeoCellAdmissionFenceV1::from_persistence_bytes(&bytes))
            .transpose()
    }

    fn append_geo_cell_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        hasher: &dyn Hasher,
        timeline: TimelineId,
        entity: EntityId,
        event_id: EventId,
        payload: CanonicalBytes,
        wall_time: WallTime,
    ) -> Result<Event, CoreError> {
        let (head_seq, chain_head): (i64, Vec<u8>) = tx
            .query_row(
                "SELECT head_seq, chain_head FROM timelines WHERE id = ?1",
                params![timeline.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| Self::storage_error(&error))?;
        let chain_head: [u8; 32] = chain_head
            .try_into()
            .map_err(|_| CoreError::Serialization("bad hash length".to_owned()))?;
        let seq = Seq::from_u64(u64::try_from(head_seq).unwrap_or(0)).next();
        let payload_hash = hasher.hash_payload(&payload);
        let event_id_text = event_id.to_string();
        let next_chain_head = hasher.hash_event(
            &Hash::from_bytes(chain_head),
            event_id_text.as_bytes(),
            &payload,
        );
        tx.execute(
            "INSERT INTO events
             (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
              causation_id, correlation_id, schema_version, payload_hash, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, 1, ?8, NULL)",
            params![
                timeline.to_string(),
                i64::try_from(seq.as_u64()).unwrap_or(i64::MAX),
                event_id_text,
                entity.to_string(),
                pos_core::GEOGRAPHIC_CELL_EVENT_TYPE,
                payload.as_slice(),
                i64::try_from(wall_time.as_micros()).unwrap_or(i64::MAX),
                payload_hash.as_bytes().as_slice(),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "UPDATE timelines SET head_seq = ?1, chain_head = ?2 WHERE id = ?3",
            params![
                i64::try_from(seq.as_u64()).unwrap_or(i64::MAX),
                next_chain_head.as_bytes().as_slice(),
                timeline.to_string(),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(Event {
            id: event_id,
            entity,
            event_type: Kind::new(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE),
            payload,
            wall_time,
            seq,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash,
        })
    }

    fn read_geo_cell_dedup(
        tx: &rusqlite::Transaction<'_>,
        fingerprint: GeographicAdmissionFingerprintV1,
    ) -> Result<Option<GeographicCellDedupRow>, CoreError> {
        let row = tx
            .query_row(
                "SELECT timeline_id, entity_id, intent, event_id, event_seq,
                        snapshot_id, snapshot_hash
                 FROM geographic_cell_admission_dedup WHERE fingerprint = ?1",
                params![fingerprint.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let Some((timeline, entity, intent, event_id, event_seq, snapshot_id, snapshot_hash)) = row
        else {
            return Ok(None);
        };
        let snapshot_hash: [u8; 32] = snapshot_hash.try_into().map_err(|_| {
            CoreError::Storage("geo.cell dedup has invalid snapshot hash length".to_owned())
        })?;
        Ok(Some(GeographicCellDedupRow {
            timeline: parse_timeline_id(&timeline)?,
            entity: parse_entity_id(&entity)?,
            intent,
            event_id: parse_event_id(&event_id)?,
            event_seq: Seq::from_u64(u64::try_from(event_seq).unwrap_or(0)),
            snapshot_id: AdmissionSnapshotId::from_canonical(&snapshot_id)
                .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?,
            snapshot_hash: AdmissionSnapshotHash::from_bytes(snapshot_hash),
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn verify_geo_cell_dedup_row(
        tx: &rusqlite::Transaction<'_>,
        hasher: &dyn Hasher,
        row: &GeographicCellDedupRow,
        request: &ValidatedGeographicAdmissionV1,
    ) -> Result<bool, CoreError> {
        if row.timeline != request.timeline()
            || row.entity != request.entity()
            || row.intent.as_slice() != request.intent().as_persistence_bytes().as_slice()
        {
            return Ok(false);
        }
        let event = tx
            .query_row(
                "SELECT entity_id, seq, event_type, schema_version, payload, payload_hash
                 FROM events WHERE timeline_id = ?1 AND event_id = ?2",
                params![row.timeline.to_string(), row.event_id.to_string()],
                |query| {
                    Ok((
                        query.get::<_, String>(0)?,
                        query.get::<_, i64>(1)?,
                        query.get::<_, String>(2)?,
                        query.get::<_, i64>(3)?,
                        query.get::<_, Vec<u8>>(4)?,
                        query.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let Some((entity, seq, event_type, schema_version, payload, payload_hash)) = event else {
            return Ok(false);
        };
        let payload_hash: [u8; 32] = match payload_hash.try_into() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let payload = CanonicalBytes::from_vec(payload);
        let Ok(observation) = GeographicObservationV1::decode(&payload) else {
            return Ok(false);
        };
        if parse_entity_id(&entity)? != row.entity
            || u64::try_from(seq).unwrap_or(0) != row.event_seq.as_u64()
            || event_type != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || schema_version != 1
            || hasher.hash_payload(&payload).as_bytes() != &payload_hash
            || observation.snapshot_id() != &row.snapshot_id
            || observation.snapshot_hash() != row.snapshot_hash
        {
            return Ok(false);
        }
        let snapshot = tx
            .query_row(
                "SELECT snapshot_hash, timeline_id, entity_id, event_id, event_seq, snapshot_cbor
                 FROM geographic_cell_admission_snapshots WHERE snapshot_id = ?1",
                params![row.snapshot_id.as_str()],
                |query| {
                    Ok((
                        query.get::<_, Vec<u8>>(0)?,
                        query.get::<_, String>(1)?,
                        query.get::<_, String>(2)?,
                        query.get::<_, String>(3)?,
                        query.get::<_, i64>(4)?,
                        query.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let Some((stored_hash, timeline, entity, event_id, event_seq, snapshot_cbor)) = snapshot
        else {
            return Ok(false);
        };
        let stored_hash: [u8; 32] = match stored_hash.try_into() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let snapshot_cbor = CanonicalBytes::from_vec(snapshot_cbor);
        let Ok(linkage) = AdmissionEntitlementSnapshotV1::canonical_linkage(&snapshot_cbor) else {
            return Ok(false);
        };
        if AdmissionSnapshotHash::from_bytes(stored_hash) != row.snapshot_hash
            || hash_admission_snapshot_bytes(&snapshot_cbor) != row.snapshot_hash
            || linkage.snapshot_id() != &row.snapshot_id
            || linkage.timeline() != row.timeline
            || linkage.entity() != row.entity
            || linkage.event_id() != row.event_id
            || linkage.event_seq() != row.event_seq
            || parse_timeline_id(&timeline)? != row.timeline
            || parse_entity_id(&entity)? != row.entity
            || parse_event_id(&event_id)? != row.event_id
            || u64::try_from(event_seq).unwrap_or(0) != row.event_seq.as_u64()
        {
            return Ok(false);
        }
        let consent_record = Self::geo_cell_consent_in_transaction(
            tx,
            linkage.consent_record_id(),
            linkage.consent_revision(),
        )?;
        if !consent_record.matches_linkage(&linkage) {
            return Ok(false);
        }
        let link = tx
            .query_row(
                "SELECT event_seq, snapshot_id, snapshot_hash, snapshot_cbor
                 FROM geographic_cell_admission_links
                 WHERE timeline_id = ?1 AND event_id = ?2",
                params![row.timeline.to_string(), row.event_id.to_string()],
                |query| {
                    Ok((
                        query.get::<_, i64>(0)?,
                        query.get::<_, String>(1)?,
                        query.get::<_, Vec<u8>>(2)?,
                        query.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let Some((event_seq, snapshot_id, snapshot_hash, link_cbor)) = link else {
            return Ok(false);
        };
        let link_hash: [u8; 32] = match snapshot_hash.try_into() {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        Ok(
            u64::try_from(event_seq).unwrap_or(0) == row.event_seq.as_u64()
                && AdmissionSnapshotId::from_canonical(&snapshot_id)
                    .is_ok_and(|id| id == row.snapshot_id)
                && AdmissionSnapshotHash::from_bytes(link_hash) == row.snapshot_hash
                && link_cbor == snapshot_cbor.as_slice(),
        )
    }
}

impl GeographicAdmissionAdmin for SqliteStore {
    fn set_geo_cell_admission_consent_record(
        &mut self,
        record: AdmissionConsentRecordV1,
    ) -> Result<(), CoreError> {
        if AdmissionSnapshotId::from_canonical(record.id().as_str()).is_err()
            || record.revision() == 0
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let record_hash = record.hash().as_bytes();
        tx.execute(
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(consent_record_id, consent_revision) DO NOTHING",
            params![
                record.id().as_str(),
                i64::try_from(record.revision()).unwrap_or(i64::MAX),
                record_hash.as_slice(),
                record.canonical_bytes().as_slice(),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        let stored = tx
            .query_row(
                "SELECT consent_record_hash, consent_record_cbor
                 FROM geographic_cell_admission_consent_records
                 WHERE consent_record_id = ?1 AND consent_revision = ?2",
                params![
                    record.id().as_str(),
                    i64::try_from(record.revision()).unwrap_or(i64::MAX),
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        if stored.0.as_slice() != record_hash.as_slice()
            || stored.1.as_slice() != record.canonical_bytes().as_slice()
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn set_geo_cell_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoCellAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        if fence.draft().timeline() != timeline || fence.draft().entity() != entity {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let bytes = fence.persistence_bytes();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let exists = tx
            .query_row(
                "SELECT 1 FROM timelines WHERE id = ?1",
                params![timeline.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        if exists.is_none() {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        tx.execute(
            "INSERT INTO geographic_cell_admission_fences (timeline_id, entity_id, fence_cbor)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(timeline_id, entity_id) DO UPDATE SET fence_cbor = excluded.fence_cbor",
            params![timeline.to_string(), entity.to_string(), bytes.as_slice()],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))
    }
}

impl GeographicAdmissionConsentResolver for SqliteStore {
    fn resolve_admission_consent(
        &self,
        consent_record_id: &AdmissionSnapshotId,
        consent_revision: u64,
    ) -> Result<AdmissionConsentRecordV1, CoreError> {
        self.conn
            .query_row(
                "SELECT consent_revision, consent_record_hash, consent_record_cbor
                 FROM geographic_cell_admission_consent_records
                 WHERE consent_record_id = ?1 AND consent_revision = ?2",
                params![
                    consent_record_id.as_str(),
                    i64::try_from(consent_revision).unwrap_or(i64::MAX)
                ],
                |row| {
                    row.get::<_, i64>(0).and_then(|revision| {
                        row.get::<_, Vec<u8>>(1).and_then(|hash| {
                            row.get::<_, Vec<u8>>(2)
                                .map(|bytes| (revision, hash, bytes))
                        })
                    })
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    CoreError::GeographicAdmissionValidationFailed
                }
                other => CoreError::Storage(other.to_string()),
            })
            .and_then(|(revision, hash, bytes)| {
                u64::try_from(revision)
                    .map_err(|_| CoreError::GeographicAdmissionValidationFailed)
                    .and_then(|revision| {
                        hash.try_into()
                            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)
                            .and_then(|stored_hash| {
                                let record = AdmissionConsentRecordV1::from_persistence_parts(
                                    consent_record_id.clone(),
                                    revision,
                                    CanonicalBytes::from_vec(bytes),
                                );
                                if revision != consent_revision
                                    || record.hash() != ConsentRecordHash::from_bytes(stored_hash)
                                {
                                    Err(CoreError::GeographicAdmissionValidationFailed)
                                } else {
                                    Ok(record)
                                }
                            })
                    })
            })
    }
}

impl GeographicAdmissionStore for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn admit(
        &mut self,
        request: ValidatedGeographicAdmissionV1,
    ) -> Result<GeographicAdmissionOutcome, CoreError> {
        let Ok(admitted_at) = self.clock.now() else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Ok(expires_at) = checked_append_identity_expires_at(admitted_at) else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Ok(tx) = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
        else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Some(fence) =
            Self::geo_cell_fence_in_transaction(&tx, request.timeline(), request.entity())?
        else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        if !fence.permits(&request) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let consent_record = Self::geo_cell_consent_in_transaction(
            &tx,
            request.fence().draft().consent_record_id(),
            request.fence().draft().consent_revision(),
        )?;
        if !consent_record.matches_draft(request.fence().draft()) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        tx.execute(
            "DELETE FROM geographic_cell_admission_dedup WHERE expires_at <= ?1",
            params![i64::try_from(admitted_at.as_micros()).unwrap_or(i64::MAX)],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        if let Some(row) = Self::read_geo_cell_dedup(&tx, request.fingerprint())? {
            if row.intent.as_slice() != request.intent().as_persistence_bytes().as_slice() {
                return Ok(GeographicAdmissionOutcome::Conflict);
            }
            let verified =
                Self::verify_geo_cell_dedup_row(&tx, self.hasher.as_ref(), &row, &request)?;
            return if verified {
                if tx.commit().is_err() {
                    return Ok(GeographicAdmissionOutcome::OutcomeUnknown);
                }
                Ok(GeographicAdmissionOutcome::Duplicate {
                    event_id: row.event_id,
                    event_seq: row.event_seq,
                    snapshot_id: row.snapshot_id,
                    snapshot_hash: row.snapshot_hash,
                })
            } else {
                Ok(GeographicAdmissionOutcome::OutcomeUnknown)
            };
        }

        let event_id = EventId::new();
        let event_seq = tx
            .query_row(
                "SELECT head_seq FROM timelines WHERE id = ?1",
                params![request.timeline().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| CoreError::Storage(error.to_string()))
            .map(|head| Seq::from_u64(u64::try_from(head).unwrap_or(0)).next())?;
        let snapshot_id = AdmissionSnapshotId::new();
        let snapshot =
            AdmissionEntitlementSnapshotV1::new(snapshot_id.clone(), &request, event_id, event_seq);
        let snapshot_cbor = snapshot.canonical_bytes();
        let snapshot_hash = snapshot.hash();
        let payload = request.payload(snapshot_id.clone(), snapshot_hash).encode();
        let event = Self::append_geo_cell_in_transaction(
            &tx,
            self.hasher.as_ref(),
            request.timeline(),
            request.entity(),
            event_id,
            payload,
            admitted_at,
        )?;
        tx.execute(
            "INSERT INTO geographic_cell_admission_snapshots
             (snapshot_id, snapshot_hash, timeline_id, entity_id, event_id, event_seq, snapshot_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                snapshot_id.as_str(),
                snapshot_hash.as_bytes().as_slice(),
                request.timeline().to_string(),
                request.entity().to_string(),
                event.id.to_string(),
                i64::try_from(event.seq.as_u64()).unwrap_or(i64::MAX),
                snapshot_cbor.as_slice(),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "INSERT INTO geographic_cell_admission_links
             (timeline_id, event_id, event_seq, snapshot_id, snapshot_hash, snapshot_cbor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.timeline().to_string(),
                event.id.to_string(),
                i64::try_from(event.seq.as_u64()).unwrap_or(i64::MAX),
                snapshot_id.as_str(),
                snapshot_hash.as_bytes().as_slice(),
                snapshot_cbor.as_slice(),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)
             ON CONFLICT(timeline_id) DO UPDATE SET has_evidence = 1",
            params![request.timeline().to_string()],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "INSERT INTO geographic_cell_admission_dedup
             (fingerprint, timeline_id, entity_id, intent, event_id, event_seq,
              snapshot_id, snapshot_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request.fingerprint().as_bytes().as_slice(),
                request.timeline().to_string(),
                request.entity().to_string(),
                request.intent().as_persistence_bytes().as_slice(),
                event.id.to_string(),
                i64::try_from(event.seq.as_u64()).unwrap_or(i64::MAX),
                snapshot_id.as_str(),
                snapshot_hash.as_bytes().as_slice(),
                i64::try_from(expires_at.as_micros()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        let row = GeographicCellDedupRow {
            timeline: request.timeline(),
            entity: request.entity(),
            intent: request.intent().as_persistence_bytes().as_slice().to_vec(),
            event_id: event.id,
            event_seq: event.seq,
            snapshot_id: snapshot_id.clone(),
            snapshot_hash,
        };
        if !Self::verify_geo_cell_dedup_row(&tx, self.hasher.as_ref(), &row, &request)? {
            return Ok(GeographicAdmissionOutcome::OutcomeUnknown);
        }
        if tx.commit().is_err() {
            return Ok(GeographicAdmissionOutcome::OutcomeUnknown);
        }
        Ok(GeographicAdmissionOutcome::Accepted {
            persisted_event: Box::new(event.clone()),
            event_id: event.id,
            event_seq: event.seq,
            snapshot_id,
            snapshot_hash,
        })
    }
}

impl GeographicReplayVerifier for SqliteStore {
    #[allow(clippy::too_many_lines)]
    fn verify_geo_cell_event(&self, evidence: GeographicReplayEvidenceV1) -> Result<(), CoreError> {
        let events = Self::read_own_events_on(
            &self.conn,
            evidence.timeline(),
            evidence.event_seq(),
            Some(evidence.event_seq()),
        )?;
        let Some(event) = events
            .into_iter()
            .find(|event| event.id == evidence.event_id())
        else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        if event.event_type.as_str() != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || event.schema_version != SchemaVersion::V1
            || event.payload_hash != evidence.event_payload_hash()
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let observation = GeographicObservationV1::decode(&event.payload)
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        if observation.snapshot_id() != evidence.snapshot_id()
            || observation.snapshot_hash() != evidence.snapshot_hash()
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let snapshot = self
            .conn
            .query_row(
                "SELECT snapshot_hash, timeline_id, entity_id, event_id, event_seq, snapshot_cbor
                 FROM geographic_cell_admission_snapshots WHERE snapshot_id = ?1",
                params![evidence.snapshot_id().as_str()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    CoreError::GeographicAdmissionValidationFailed
                }
                other => CoreError::Storage(other.to_string()),
            })?;
        let snapshot_hash: [u8; 32] = snapshot
            .0
            .try_into()
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        let snapshot_cbor = CanonicalBytes::from_vec(snapshot.5);
        let linkage = AdmissionEntitlementSnapshotV1::canonical_linkage(&snapshot_cbor)?;
        if AdmissionSnapshotHash::from_bytes(snapshot_hash) != evidence.snapshot_hash()
            || hash_admission_snapshot_bytes(&snapshot_cbor).as_bytes() != snapshot_hash
            || linkage.snapshot_id() != evidence.snapshot_id()
            || linkage.timeline() != evidence.timeline()
            || linkage.entity() != event.entity
            || linkage.event_id() != evidence.event_id()
            || linkage.event_seq() != evidence.event_seq()
            || parse_timeline_id(&snapshot.1)? != evidence.timeline()
            || parse_entity_id(&snapshot.2)? != event.entity
            || parse_event_id(&snapshot.3)? != evidence.event_id()
            || u64::try_from(snapshot.4).unwrap_or(0) != evidence.event_seq().as_u64()
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let consent_record = self
            .resolve_admission_consent(linkage.consent_record_id(), linkage.consent_revision())?;
        if !consent_record.matches_linkage(&linkage) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let link = self
            .conn
            .query_row(
                "SELECT event_seq, snapshot_id, snapshot_hash, snapshot_cbor
                 FROM geographic_cell_admission_links
                 WHERE timeline_id = ?1 AND event_id = ?2",
                params![
                    evidence.timeline().to_string(),
                    evidence.event_id().to_string()
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    CoreError::GeographicAdmissionValidationFailed
                }
                other => CoreError::Storage(other.to_string()),
            })?;
        let link_hash: [u8; 32] = link
            .2
            .try_into()
            .map_err(|_| CoreError::GeographicAdmissionValidationFailed)?;
        if u64::try_from(link.0).unwrap_or(0) != evidence.event_seq().as_u64()
            || AdmissionSnapshotId::from_canonical(&link.1)
                .map_or(true, |id| id != *evidence.snapshot_id())
            || AdmissionSnapshotHash::from_bytes(link_hash) != evidence.snapshot_hash()
            || link.3 != snapshot_cbor.as_slice()
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(())
    }
}

impl GeoLocationAdmissionStore for SqliteStore {
    fn protected_logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
        self.logical_head_unchecked(timeline)
    }

    fn admit_geo_location(
        &mut self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, CoreError> {
        if !self.geographic_fence_permits(&request)? {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let admitted_at = self.clock.now()?;
        let expires_at = checked_append_identity_expires_at(admitted_at)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        if !Self::geographic_fence_permits_in_transaction(&tx, &request)? {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        if !Self::geographic_admission_integrity_is_intact(&tx, request.timeline())? {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }

        if let Some(outcome) = Self::geographic_dedup_outcome(&tx, &request, admitted_at)? {
            return match tx.commit() {
                Ok(()) => Ok(outcome),
                Err(_) => Ok(GeoLocationAdmissionOutcome::outcome_unknown()),
            };
        }

        let draft = EventDraft::new(
            request.entity(),
            Kind::new(GEOGRAPHIC_EVENT_TYPE),
            request.payload().clone(),
        )
        .with_wall_time(admitted_at);
        let event =
            Self::append_one_in_transaction(&tx, self.hasher.as_ref(), request.timeline(), draft)?;
        let link = pos_core::geo_admission::GeoLocationAdmissionLinkV1::for_snapshot(
            request.timeline(),
            event.id,
            event.seq,
            request.snapshot(),
        );
        tx.execute(
            "INSERT INTO geographic_admission_snapshots (event_id, snapshot_cbor) VALUES (?1, ?2)",
            params![event.id.to_string(), link.snapshot_cbor().as_slice()],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "INSERT INTO geographic_admission_links (timeline_id, event_id, event_seq, snapshot_cbor)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                request.timeline().to_string(),
                event.id.to_string(),
                i64::try_from(event.seq.as_u64()).unwrap_or(i64::MAX),
                link.snapshot_cbor().as_slice(),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)
             ON CONFLICT(timeline_id) DO UPDATE SET has_evidence = 1",
            params![request.timeline().to_string()],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "INSERT INTO geographic_admission_dedup
             (fingerprint, timeline_id, intent, event_id, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.fingerprint().as_owner_keyed_bytes().as_slice(),
                request.timeline().to_string(),
                request.intent().as_owner_keyed_bytes().as_slice(),
                event.id.to_string(),
                i64::try_from(expires_at.as_micros()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        let commit_result = tx.commit();
        match commit_result {
            Ok(()) => Ok(GeoLocationAdmissionOutcome::accepted(event.id, event.seq)),
            Err(_) => Ok(GeoLocationAdmissionOutcome::outcome_unknown()),
        }
    }
}

impl GeoLocationReplayVerifier for SqliteStore {
    fn verify_v1_event_snapshot_link(
        &self,
        evidence: GeoLocationReplayEvidenceV1,
    ) -> Result<(), CoreError> {
        let stored = self.conn.query_row(
            "SELECT event.entity_id, event.schema_version, event.payload,
                    event.payload_hash, link.snapshot_cbor
             FROM events AS event
             JOIN geographic_admission_links AS link
               ON link.timeline_id = event.timeline_id
              AND link.event_id = event.event_id
              AND link.event_seq = event.seq
             JOIN geographic_admission_snapshots AS snapshot
               ON snapshot.event_id = link.event_id
              AND snapshot.snapshot_cbor = link.snapshot_cbor
            WHERE event.timeline_id = ?1
               AND event.event_id = ?2
               AND event.seq = ?3
               AND event.event_type = ?4",
            params![
                evidence.timeline().to_string(),
                evidence.event_id().to_string(),
                i64::try_from(evidence.event_seq().as_u64()).unwrap_or(i64::MAX),
                GEOGRAPHIC_EVENT_TYPE,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        );
        let (event_entity, schema_version, payload, stored_event_hash, snapshot_cbor) = match stored
        {
            Ok(value) => value,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(CoreError::GeographicAdmissionValidationFailed);
            }
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let Ok(stored_event_hash) = stored_event_hash.try_into() else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        let stored_event_hash = Hash::from_bytes(stored_event_hash);
        let snapshot_cbor = CanonicalBytes::from_vec(snapshot_cbor);
        let Ok(snapshot) =
            pos_core::geo_admission::GeoLocationAdmissionSnapshotV1::from_deterministic_cbor(
                &snapshot_cbor,
            )
        else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        let canonical_link = pos_core::geo_admission::GeoLocationAdmissionLinkV1::for_snapshot(
            evidence.timeline(),
            evidence.event_id(),
            evidence.event_seq(),
            &snapshot,
        );
        if snapshot.timeline() != evidence.timeline()
            || snapshot.entity().to_string() != event_entity
            || schema_version != i64::from(pos_core::SchemaVersion::V1.as_u32())
            || canonical_link.snapshot_cbor() != &snapshot_cbor
            || self.hasher.hash_payload(&CanonicalBytes::from_vec(payload)) != stored_event_hash
            || stored_event_hash != evidence.event_payload_hash()
            || self.hasher.hash_payload(&snapshot_cbor) != evidence.snapshot_hash()
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        Ok(())
    }
}

impl SqliteStore {
    fn timeline_owner(&self, timeline: TimelineId) -> Result<Option<EntityId>, CoreError> {
        self.conn
            .query_row(
                "SELECT owner_id FROM timeline_owners WHERE timeline_id = ?1",
                params![timeline.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?
            .map(|owner| parse_entity_id(&owner))
            .transpose()
    }

    fn timeline_owner_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        timeline: TimelineId,
    ) -> Result<Option<EntityId>, CoreError> {
        tx.query_row(
            "SELECT owner_id FROM timeline_owners WHERE timeline_id = ?1",
            params![timeline.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| CoreError::Storage(error.to_string()))?
        .map(|owner| parse_entity_id(&owner))
        .transpose()
    }

    fn persist_timeline_owner(
        tx: &rusqlite::Transaction<'_>,
        timeline: TimelineId,
        owner: EntityId,
    ) -> Result<(), CoreError> {
        tx.execute(
            "INSERT INTO timeline_owners (timeline_id, owner_id) VALUES (?1, ?2)",
            params![timeline.to_string(), owner.to_string()],
        )
        .map(|_| ())
        .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn logical_head_unchecked(&self, id: TimelineId) -> Result<Seq, CoreError> {
        let chain = self.fork_chain(id)?;
        chain
            .iter()
            .enumerate()
            .try_fold(0_u64, |logical_head, (index, (timeline, _))| {
                self.logical_segment_length(&chain, index, *timeline)
                    .and_then(|segment| Self::add_logical_segment(logical_head, segment))
            })
            .map(Seq::from_u64)
    }

    fn save_key_registry_in_transaction(
        &self,
        registry: &KeyRegistryStateV1,
    ) -> Result<(), CoreError> {
        registry
            .validate()
            .map_err(|error| CoreError::Serialization(error.to_string()))?;
        self.load_key_registry()?
            .unwrap_or_default()
            .validate_replacement(registry)
            .map_err(|error| CoreError::Serialization(error.to_string()))?;
        #[cfg(not(test))]
        let mut state_cbor = Vec::new();
        #[cfg(test)]
        let mut state_cbor = RegistryStateWriter {
            bytes: Vec::new(),
            fail: FAIL_REGISTRY_SERIALIZATION.with(std::cell::Cell::get),
        };
        ciborium::into_writer(registry, &mut state_cbor)
            .map_err(|error| CoreError::Serialization(error.to_string()))?;
        #[cfg(test)]
        let state_cbor = state_cbor.bytes;
        self.conn
            .execute(
                "INSERT INTO key_registry (singleton, state_cbor) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET state_cbor = excluded.state_cbor",
                params![state_cbor],
            )
            .map(|_| ())
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn initialize_timeline_with_key_registry_in_transaction(
        &mut self,
        name: &str,
        expected_registry: &KeyRegistryStateV1,
    ) -> Result<Timeline, CoreError> {
        let persisted = self.load_key_registry()?;
        if persisted
            .as_ref()
            .is_some_and(|current| current != expected_registry)
        {
            return Err(CoreError::Storage(
                "durable key registry changed during ledger initialization".to_owned(),
            ));
        }
        if persisted.is_none() {
            self.save_key_registry_in_transaction(expected_registry)?;
        }

        self.list_timelines()?
            .into_iter()
            .find(|timeline| timeline.meta.name.as_deref() == Some(name))
            .map_or_else(|| self.create_timeline(name), Ok)
    }
}

impl EventStore for SqliteStore {
    fn bind_consent_authority(&mut self, permit: ConsentAppendPermit) -> Result<(), CoreError> {
        match self.consent_authority_permit {
            Some(existing) if existing != permit => Err(CoreError::Storage(
                "Gateway consent authority is already bound".to_owned(),
            )),
            Some(_) => Ok(()),
            None => {
                self.consent_authority_permit = Some(permit);
                Ok(())
            }
        }
    }

    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        let meta = TimelineMeta::root(name);
        let timeline = Timeline::new(meta);
        let chain_head = self.hasher.genesis_hash();
        self.conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, ?2, ?3, NULL, NULL, 0, ?4)",
                params![
                    timeline.id().to_string(),
                    timeline.meta.name.as_deref(),
                    mode_str(timeline.mode()),
                    chain_head.as_bytes().as_slice(),
                ],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(timeline)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        crate::ensure_non_geographic_drafts(drafts, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| self.append_visible(timeline, drafts))
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
        let state_cbor = match self.conn.query_row(
            "SELECT state_cbor FROM key_registry WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(bytes) => bytes,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        ciborium::from_reader(state_cbor.as_slice())
            .map_err(|error| CoreError::Serialization(error.to_string()))
            .and_then(|registry: KeyRegistryStateV1| {
                registry
                    .validate()
                    .map(|()| registry)
                    .map_err(|error| CoreError::Serialization(error.to_string()))
            })
            .map(Some)
    }

    fn save_key_registry(&mut self, registry: &KeyRegistryStateV1) -> Result<(), CoreError> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result = self.save_key_registry_in_transaction(registry);
        finish_immediate_transaction(&self.conn, result)
    }

    fn initialize_timeline_with_key_registry(
        &mut self,
        name: &str,
        expected_registry: &KeyRegistryStateV1,
    ) -> Result<Timeline, CoreError> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result =
            self.initialize_timeline_with_key_registry_in_transaction(name, expected_registry);
        finish_immediate_transaction(&self.conn, result)
    }

    fn append_signed_authorized(
        &mut self,
        timeline: TimelineId,
        expected_registry: &KeyRegistryStateV1,
        create_event: &mut dyn FnMut(&KeyRegistryStateV1, Seq) -> Result<Event, CoreError>,
    ) -> Result<(), CoreError> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result = (|| {
            let persisted = self.load_key_registry()?.ok_or_else(|| {
                CoreError::Storage("durable key registry is unavailable".to_owned())
            })?;
            if persisted != *expected_registry {
                return Err(CoreError::Storage(
                    "durable key registry changed during signing".to_owned(),
                ));
            }
            let head = self
                .get_timeline(timeline)?
                .ok_or(CoreError::TimelineNotFound(timeline))?;
            let event = create_event(&persisted, head.head.next())?;
            self.append_committed(timeline, &[event])
        })();
        finish_immediate_transaction(&self.conn, result)
    }

    fn begin_key_registry_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<(pos_core::KeyDestructionBeginOutcomeV1, KeyRegistryStateV1), CoreError> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        #[cfg(test)]
        if let Some((started, release)) = self.destruction_transaction_hook.take() {
            assert!(started.send(()).is_ok());
            assert!(release.recv().is_ok());
        }
        let result = (|| {
            let mut registry = self.load_key_registry()?.ok_or_else(|| {
                CoreError::Storage("durable key registry is unavailable".to_owned())
            })?;
            let outcome = registry
                .begin_key_destruction(request)
                .map_err(|error| CoreError::Storage(format!("ledger key destruction: {error}")))?;
            self.save_key_registry_in_transaction(&registry)?;
            Ok((outcome, registry))
        })();
        finish_immediate_transaction(&self.conn, result)
    }

    fn complete_key_registry_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<(KeyDestructionOutcomeV1, KeyRegistryStateV1), CoreError> {
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let result = (|| {
            let mut registry = self.load_key_registry()?.ok_or_else(|| {
                CoreError::Storage("durable key registry is unavailable".to_owned())
            })?;
            let outcome = registry
                .complete_key_destruction(request, deletion_receipt)
                .map_err(|error| CoreError::Storage(format!("ledger key destruction: {error}")))?;
            self.save_key_registry_in_transaction(&registry)?;
            Ok((outcome, registry))
        })();
        finish_immediate_transaction(&self.conn, result)
    }

    fn append_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        max_owned_events: u64,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        crate::ensure_non_geographic_drafts(drafts, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                self.append_bounded_visible(timeline, drafts, max_owned_events, false, None, None)
            })
    }

    fn append_consent_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        max_owned_events: u64,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        crate::ensure_gateway_consent_types(drafts, timeline).and_then(|()| {
            self.append_bounded_visible(
                timeline,
                drafts,
                max_owned_events,
                true,
                Some(permit),
                None,
            )
        })
    }

    fn append_consent_revocation_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        max_owned_events: u64,
        cleanup_scope: AppendDedupScope,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        crate::ensure_gateway_consent_revocation(drafts, timeline)
            .and_then(|()| crate::ensure_gateway_consent_types(drafts, timeline))
            .and_then(|()| {
                self.append_bounded_visible(
                    timeline,
                    drafts,
                    max_owned_events,
                    true,
                    Some(permit),
                    Some(cleanup_scope),
                )
            })
    }

    fn append_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        self.append_or_duplicate_with_limit(timeline, identity, admitted_at, &draft, None)
            .and_then(crate::unbounded_append_outcome)
    }

    fn purge_expired_append_identities(&mut self, now: WallTime) -> Result<usize, CoreError> {
        match self.conn.execute(
            "DELETE FROM append_identities WHERE expires_at <= ?1",
            params![i64::try_from(now.as_micros()).unwrap_or(i64::MAX)],
        ) {
            Ok(deleted) => Ok(deleted),
            Err(error) => Err(CoreError::Storage(error.to_string())),
        }
    }

    fn append_intent_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        let admitted_at = self.clock.now()?;
        let mut draft = intent.into_draft();
        draft.wall_time = Some(admitted_at);
        self.append_or_duplicate(timeline, identity, admitted_at, draft)
    }

    fn append_intent_or_duplicate_bounded(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        max_owned_events: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        let admitted_at = self.clock.now()?;
        let mut draft = intent.into_draft();
        draft.wall_time = Some(admitted_at);
        self.append_or_duplicate_with_limit(
            timeline,
            identity,
            admitted_at,
            &draft,
            Some(max_owned_events),
        )
    }

    fn read_event_by_id(
        &self,
        timeline: TimelineId,
        event_id: EventId,
    ) -> Result<Option<Event>, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)?;
        let chain = self.fork_chain(timeline)?;
        let located = self
            .conn
            .query_row(
                "SELECT timeline_id, seq FROM events WHERE event_id = ?1",
                params![event_id.to_string()],
                |row| {
                    row.get::<_, String>(0)
                        .and_then(|timeline| row.get::<_, i64>(1).map(|seq| (timeline, seq)))
                },
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let Some((owner, local_seq)) = located else {
            return Ok(None);
        };
        let owner = parse_timeline_id(&owner)?;
        let Some(index) = chain.iter().position(|(id, _)| *id == owner) else {
            return Ok(None);
        };
        let prefix = chain[index].1.as_u64();
        let local_limit = self.logical_segment_length(&chain, index, owner)?;
        let local_seq = u64::try_from(local_seq).map_err(|_| {
            CoreError::Storage(format!("timeline {owner} has a negative Event sequence"))
        })?;
        if local_seq > local_limit {
            return Ok(None);
        }
        {
            let mut events = Self::read_own_events_limited_on(
                &self.conn,
                owner,
                Seq::from_u64(local_seq),
                Some(Seq::from_u64(local_seq)),
                Some(1),
                None,
                u64::MAX,
            )?;
            events
                .pop()
                .map(|event| Self::logical_event(prefix, event))
                .transpose()
        }
    }

    fn purge_expired_append_identities_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        let now = self.clock.now()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let mut stmt = tx.prepare("SELECT dedup_key FROM append_identities WHERE expires_at <= ?1 ORDER BY expires_at, dedup_key LIMIT ?2").map_err(|error| CoreError::Storage(error.to_string()))?;
        let keys: Result<Vec<Vec<u8>>, _> = stmt
            .query_map(
                params![
                    i64::try_from(now.as_micros()).unwrap_or(i64::MAX),
                    i64::try_from(limit.get()).unwrap_or(i64::MAX)
                ],
                |row| row.get(0),
            )
            .and_then(Iterator::collect);
        let keys = keys.map_err(|error| CoreError::Storage(error.to_string()))?;
        drop(stmt);
        for key in &keys {
            tx.execute(
                "DELETE FROM append_identities WHERE dedup_key = ?1",
                params![key],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        }
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(PurgeOutcome {
            removed: keys.len(),
            more_may_remain: keys.len() == limit.get(),
        })
    }

    fn remove_append_identities(&mut self, scope: AppendDedupScope) -> Result<usize, CoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let removed = tx
            .execute(
                "DELETE FROM append_identities WHERE scope_key = ?1",
                params![scope.as_bytes().as_slice()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.execute(
            "DELETE FROM pending_append_identity_cleanup WHERE scope_key = ?1",
            params![scope.as_bytes().as_slice()],
        )
        .map_err(|error| CoreError::Storage(error.to_string()))?;
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(removed)
    }

    fn remove_append_identities_bounded(
        &mut self,
        scope: AppendDedupScope,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let mut stmt = tx
            .prepare("SELECT dedup_key FROM append_identities WHERE scope_key = ?1 ORDER BY expires_at, dedup_key LIMIT ?2")
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let keys: Result<Vec<Vec<u8>>, _> = stmt
            .query_map(
                params![
                    scope.as_bytes().as_slice(),
                    i64::try_from(limit.get()).unwrap_or(i64::MAX)
                ],
                |row| row.get(0),
            )
            .and_then(Iterator::collect);
        let keys = keys.map_err(|error| CoreError::Storage(error.to_string()))?;
        drop(stmt);
        for key in &keys {
            tx.execute(
                "DELETE FROM append_identities WHERE scope_key = ?1 AND dedup_key = ?2",
                params![scope.as_bytes().as_slice(), key],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        }
        let more_may_remain = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM append_identities WHERE scope_key = ?1)",
                params![scope.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?
            != 0;
        if more_may_remain {
            tx.execute(
                "INSERT OR IGNORE INTO pending_append_identity_cleanup (scope_key) VALUES (?1)",
                params![scope.as_bytes().as_slice()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        } else {
            tx.execute(
                "DELETE FROM pending_append_identity_cleanup WHERE scope_key = ?1",
                params![scope.as_bytes().as_slice()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        }
        tx.commit()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(PurgeOutcome {
            removed: keys.len(),
            more_may_remain,
        })
    }

    fn pending_append_identity_cleanup(&mut self) -> Result<Option<AppendDedupScope>, CoreError> {
        let bytes = self
            .conn
            .query_row(
                "SELECT scope_key FROM pending_append_identity_cleanup ORDER BY scope_key LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        bytes
            .map(|bytes| {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                    CoreError::Storage("invalid pending cleanup scope length".to_owned())
                })?;
                Ok(AppendDedupScope::from_keyed_hash(bytes))
            })
            .transpose()
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| {
                let chain = self.fork_chain(timeline)?;
                let mut all: Vec<Event> = Vec::new();

                for (i, &(tid, _)) in chain.iter().enumerate() {
                    let logical_prefix = chain[i].1.as_u64();
                    if i + 1 < chain.len() {
                        let logical_fork = chain[i + 1].1;
                        let fork_point_error = CoreError::Storage(format!(
                            "Fork point precedes inherited history for timeline {tid}"
                        ));
                        let local_limit = logical_fork
                            .as_u64()
                            .checked_sub(logical_prefix)
                            .ok_or(fork_point_error)?;
                        self.get_head_seq(tid)
                            .map(Seq::as_u64)
                            .and_then(|local_head| {
                                if local_limit > local_head {
                                    return Err(CoreError::Storage(format!(
                                        "Fork point exceeds parent logical Event head for timeline {tid}"
                                    )));
                                }
                                self.read_own_events(
                                    tid,
                                    Seq::ZERO,
                                    Some(Seq::from_u64(local_limit)),
                                )
                                .map(|events| all.extend(events))
                            })?;
                    } else {
                        // Leaf: all own events; range applied after logical renumber.
                        let events = self.read_own_events(tid, Seq::ZERO, None)?;
                        all.extend(events);
                    }
                }

                Ok(crate::stitch::renumber_and_filter(all, range))
            })
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        let started = Instant::now();
        if bounds.max_elapsed_micros() == 0 {
            return Err(CoreError::ReadTimeTooLarge { elapsed_micros: 0 });
        }
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.read_logical_bounded(timeline, range, bounds, started))
    }

    fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        // Ensure timeline exists (and surface TimelineNotFound for missing ids).
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| {
                let _ = self
                    .get_timeline(timeline)?
                    .ok_or(CoreError::TimelineNotFound(timeline))?;
                self.read_own_events(timeline, range.from, range.to)
            })
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.ensure_generic_timeline_visibility(parent)
            .and_then(|()| {
                let head = self.logical_head(parent)?;
                if at_seq > head {
                    return Err(CoreError::ForkBeyondHead {
                        fork_seq: at_seq.as_u64(),
                        head: head.as_u64(),
                    });
                }

                // Compute chain hash at the fork point
                let fork_hash = self.compute_chain_hash_at(parent, at_seq)?;

                let meta = self.timeline_owner(parent)?.map_or_else(
                    || TimelineMeta::forked_from(parent, at_seq, name),
                    |owner| TimelineMeta::forked_from_owned(parent, at_seq, name, owner),
                );
                let child = Timeline::new(meta);

                let tx = match self
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                {
                    Ok(tx) => tx,
                    Err(error) => return Err(CoreError::Storage(error.to_string())),
                };
                tx.execute(
            "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                child.id().to_string(),
                child.meta.name.as_deref(),
                mode_str(child.mode()),
                parent.to_string(),
                i64::try_from(at_seq.as_u64()).unwrap_or(i64::MAX),
                fork_hash.as_bytes().as_slice(),
            ],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;

                if let Some(owner) = child.meta.owner {
                    Self::persist_timeline_owner(&tx, child.id(), owner)?;
                }

                if let Err(error) = tx.commit() {
                    return Err(CoreError::Storage(error.to_string()));
                }

                Ok(child)
            })
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, mode, parent_id, fork_seq, head_seq FROM timelines")
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        let mut rows = match Self::query_prepared(&mut stmt, &[]) {
            Ok(rows) => rows,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let mut timelines = Vec::new();
        loop {
            #[cfg(test)]
            if FAIL_ROWS_NEXT.with(std::cell::Cell::get) {
                return Err(CoreError::Storage(
                    "injected row iteration failure".to_owned(),
                ));
            }
            let next = rows.next();
            let row = match next.map_err(|e| CoreError::Storage(e.to_string())) {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(e) => return Err(e),
            };
            let timeline_row =
                read_timeline_row(row).map_err(|e| CoreError::Storage(e.to_string()))?;
            let timeline = timeline_fields_to_timeline(
                &timeline_row.id,
                timeline_row.name,
                &timeline_row.mode,
                timeline_row.parent_id,
                timeline_row.fork_seq,
                timeline_row.head_seq,
            )?;
            let mut timeline = timeline;
            timeline.meta.owner = self.timeline_owner(timeline.id())?;
            if !crate::generic_timeline_is_visible(
                self.timeline_contains_geographic_evidence(timeline.id()),
            )? {
                continue;
            }
            timelines.push(timeline);
        }

        Ok(timelines)
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
        let stop_after = maximum.saturating_add(1);
        let limit = i64::try_from(stop_after).unwrap_or(i64::MAX);
        self.conn
            .query_row(
                "SELECT count(*) FROM (
                    SELECT 1 FROM timelines
                    WHERE parent_id IS NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM geographic_presence
                          WHERE geographic_presence.timeline_id = timelines.id
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM events
                          WHERE events.timeline_id = timelines.id
                            AND events.event_type IN (?2, ?3)
                      )
                    LIMIT ?1
                 )",
                params![
                    limit,
                    pos_core::GEOGRAPHIC_EVENT_TYPE,
                    pos_core::GEOGRAPHIC_CELL_EVENT_TYPE,
                ],
                read_first_i64,
            )
            .map(sqlite_usize_or_max)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, mode, parent_id, fork_seq, head_seq FROM timelines WHERE id = ?1",
                params![id.to_string()],
                read_timeline_row,
            )
            .optional()
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        match row {
            None => Ok(None),
            Some(timeline_row) => {
                let timeline = timeline_fields_to_timeline(
                    &timeline_row.id,
                    timeline_row.name,
                    &timeline_row.mode,
                    timeline_row.parent_id,
                    timeline_row.fork_seq,
                    timeline_row.head_seq,
                )?;
                let mut timeline = timeline;
                timeline.meta.owner = self.timeline_owner(timeline.id())?;
                crate::generic_timeline_is_visible(
                    self.timeline_contains_geographic_evidence(timeline.id()),
                )
                .map(|visible| visible.then_some(timeline))
            }
        }
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.ensure_generic_timeline_visibility(id)?;
        self.logical_head_unchecked(id)
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        let id = meta.id;
        // Resolve fork parent before the duplicate-id check so storage failures on the
        // parent lookup are exercised (and fail closed before INSERT).
        let chain_head = match meta.fork_point {
            Some((parent, at_seq)) => {
                let parent_head = self.logical_head(parent)?;
                if at_seq > parent_head {
                    return Err(CoreError::ForkBeyondHead {
                        fork_seq: at_seq.as_u64(),
                        head: parent_head.as_u64(),
                    });
                }
                self.compute_chain_hash_at(parent, at_seq)?
            }
            None => self.hasher.genesis_hash(),
        };
        if self.get_timeline(id)?.is_some() {
            return Err(CoreError::Storage(format!("timeline already exists: {id}")));
        }
        let (parent_id, fork_seq) = match meta.fork_point {
            Some((parent, at_seq)) => (Some(parent.to_string()), Some(seq_as_i64(at_seq))),
            None => (None, None),
        };
        let timeline = Timeline::new(meta);
        let insert_rows = |conn: &Connection| -> Result<(), CoreError> {
            conn.execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
                params![
                    timeline.id().to_string(),
                    timeline.meta.name.as_deref(),
                    mode_str(timeline.mode()),
                    parent_id.as_deref(),
                    fork_seq,
                    chain_head.as_bytes().as_slice(),
                ],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
            if let Some(owner) = timeline.meta.owner {
                conn.execute(
                    "INSERT INTO timeline_owners (timeline_id, owner_id) VALUES (?1, ?2)",
                    params![timeline.id().to_string(), owner.to_string()],
                )
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            }
            Ok(())
        };
        if self.conn.is_autocommit() {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            insert_rows(&tx)?;
            tx.commit()
                .map_err(|error| CoreError::Storage(error.to_string()))?;
        } else {
            insert_rows(&self.conn)?;
        }
        Ok(timeline)
    }

    fn append_committed(
        &mut self,
        timeline: TimelineId,
        events: &[Event],
    ) -> Result<(), CoreError> {
        if events.is_empty() {
            let _ = self
                .get_timeline(timeline)?
                .ok_or(CoreError::TimelineNotFound(timeline))?;
            return Ok(());
        }
        crate::ensure_non_geographic_events(events, timeline)
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                let (head_seq, prev_hash) = match self.conn.query_row(
                    "SELECT head_seq, chain_head FROM timelines WHERE id = ?1",
                    params![timeline.to_string()],
                    |row| match (row.get::<_, i64>(0), row.get::<_, Vec<u8>>(1)) {
                        (Ok(n), Ok(bytes)) => Ok((n, bytes)),
                        (Err(e), _) | (_, Err(e)) => Err(e),
                    },
                ) {
                    Ok((n, bytes)) => {
                        let arr: [u8; 32] = bytes
                            .try_into()
                            .map_err(|_| CoreError::Serialization("bad hash length".to_owned()))?;
                        (
                            Seq::from_u64(u64::try_from(n).unwrap_or(0)),
                            pos_core::Hash::from_bytes(arr),
                        )
                    }
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        return Err(CoreError::TimelineNotFound(timeline));
                    }
                    Err(e) => return Err(CoreError::Storage(e.to_string())),
                };

                let ordered = pos_core::store::validate_committed_batch(
                    head_seq,
                    events,
                    &mut |id| {
                        self.conn
                            .query_row(
                                "SELECT 1 FROM events WHERE event_id = ?1",
                                params![id.to_string()],
                                |_| Ok(()),
                            )
                            .optional()
                            .map_or(true, |row| row.is_some()) // treat lookup failure as taken to fail closed
                    },
                    &*self.hasher,
                )?;

                // Join an outer import transaction when present; otherwise own the txn.
                let own_tx = self.conn.is_autocommit();
                if own_tx {
                    self.conn
                        .execute_batch(begin_immediate_sql())
                        .map_err(|e| CoreError::Storage(e.to_string()))?;
                }
                let applied = self.write_committed_rows(timeline, head_seq, prev_hash, &ordered);
                if own_tx {
                    match &applied {
                        Ok(()) => self
                            .conn
                            .execute_batch("COMMIT")
                            .map_err(|e| CoreError::Storage(e.to_string()))?,
                        Err(_) => match self.conn.execute_batch("ROLLBACK") {
                            Ok(()) | Err(_) => {}
                        },
                    }
                }
                applied
            })
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        self.ensure_admin_visibility(id).and_then(|()| {
            let id_str = id.to_string();
            // Refuse delete while child forks still reference this timeline.
            let child_count_query = self.conn.query_row(
                "SELECT COUNT(*) FROM timelines WHERE parent_id = ?1",
                params![id_str],
                |row| row.get(0),
            );
            let child_count: i64 =
                child_count_query.map_err(|error| Self::storage_error(&error))?;
            if child_count > 0 {
                return Err(CoreError::Storage(
                    "cannot delete timeline that still has forks".to_owned(),
                ));
            }

            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM append_identities
             WHERE event_id IN (SELECT event_id FROM events WHERE timeline_id = ?1)",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_admission_dedup WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_admission_links WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_admission_snapshots
                 WHERE event_id IN (SELECT event_id FROM events WHERE timeline_id = ?1)",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_cell_admission_fences WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_cell_admission_dedup WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_cell_admission_links WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_cell_admission_snapshots WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            let enrollment = Self::enrollment_state_in_transaction(&tx)?;
            let enrollment_result = if enrollment.permits_geographic_admission_target(id) {
                enrollment
                    .revoke()
                    .and_then(|revoked| Self::write_enrollment_state(&tx, &revoked))
            } else {
                Ok(())
            };
            enrollment_result.and_then(|()| {
                tx.execute("DELETE FROM events WHERE timeline_id = ?1", params![id_str])
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                tx.execute(
                    "DELETE FROM geographic_presence WHERE timeline_id = ?1",
                    params![id_str],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;
                tx.execute(
                    "DELETE FROM timeline_owners WHERE timeline_id = ?1",
                    params![id_str],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;
                let deleted = tx
                    .execute("DELETE FROM timelines WHERE id = ?1", params![id_str])
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                if deleted == 0 {
                    return Err(CoreError::TimelineNotFound(id));
                }
                tx.commit().map_err(|e| CoreError::Storage(e.to_string()))
            })
        })
    }

    fn chain_hash_at(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<pos_core::Hash, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.compute_chain_hash_at(timeline, at_seq))
    }

    fn import_committed(
        &mut self,
        meta: TimelineMeta,
        events: &[Event],
    ) -> Result<Timeline, CoreError> {
        // Single transaction so create+append is all-or-nothing for concurrent readers.
        self.conn
            .execute_batch(begin_immediate_sql())
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let expected_id = meta.id;
        let result = (|| {
            self.create_timeline_with_meta(meta)?;
            self.append_committed(expected_id, events)?;
            #[cfg(test)]
            if FAIL_IMPORT_VANISH.with(std::cell::Cell::get) {
                // Delete row so get_timeline returns Ok(None) inside this transaction.
                drop(self.conn.execute(
                    "DELETE FROM timelines WHERE id = ?1",
                    params![expected_id.to_string()],
                ));
            }
            #[cfg(test)]
            if FAIL_IMPORT_GET_STORAGE.with(std::cell::Cell::get) {
                drop(self.conn.execute_batch("DROP TABLE timelines"));
            }
            self.get_timeline(expected_id)?
                .ok_or(CoreError::TimelineNotFound(expected_id))
        })();
        match result {
            Ok(tl) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                Ok(tl)
            }
            Err(err) => {
                match self.conn.execute_batch("ROLLBACK") {
                    Ok(()) | Err(_) => {}
                }
                Err(err)
            }
        }
    }
}

impl SqliteStore {
    fn write_committed_rows(
        &self,
        timeline: TimelineId,
        head_seq: Seq,
        mut prev_hash: pos_core::Hash,
        ordered: &[Event],
    ) -> Result<(), CoreError> {
        let mut new_head = head_seq;
        for event in ordered {
            let id_str = event.id.to_string();
            prev_hash = self
                .hasher
                .hash_event(&prev_hash, id_str.as_bytes(), &event.payload);
            let sig_bytes = event.signature.as_ref().map(|s| s.as_bytes().as_slice());
            let signature_owner_id = event
                .signature_identity
                .map(|identity| identity.owner_id.as_str().to_owned());
            let signature_role = event
                .signature_identity
                .map(|identity| i64::from(identity.role.code()));
            let signature_epoch = event
                .signature_identity
                .map(|identity| {
                    i64::try_from(identity.epoch).map_err(|_| {
                        CoreError::Storage(
                            "signature key epoch exceeds SQLite INTEGER range".to_owned(),
                        )
                    })
                })
                .transpose()?;
            self.conn
                .execute(
                    "INSERT INTO events
                     (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                      causation_id, correlation_id, schema_version, payload_hash, signature,
                      signature_owner_id, signature_role, signature_epoch)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        timeline.to_string(),
                        seq_as_i64(event.seq),
                        id_str,
                        event.entity.to_string(),
                        event.event_type.as_str(),
                        event.payload.as_slice(),
                        u64_as_i64(event.wall_time.as_micros()),
                        event.causation_id.map(|id| id.to_string()),
                        event.correlation_id.map(|id| id.to_string()),
                        i64::from(event.schema_version.as_u32()),
                        event.payload_hash.as_bytes().as_slice(),
                        sig_bytes,
                        signature_owner_id,
                        signature_role,
                        signature_epoch,
                    ],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            new_head = event.seq;
        }
        self.conn
            .execute(
                "UPDATE timelines SET head_seq = ?1, chain_head = ?2 WHERE id = ?3",
                params![
                    seq_as_i64(new_head),
                    prev_hash.as_bytes().as_slice(),
                    timeline.to_string(),
                ],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn compute_chain_hash_at(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<pos_core::Hash, CoreError> {
        let logical_head = self.logical_head(timeline)?;
        if at_seq > logical_head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: logical_head.as_u64(),
            });
        }
        let mut hash = self.hasher.genesis_hash();
        if at_seq == Seq::ZERO {
            return Ok(hash);
        }
        for event in self.read(timeline, SeqRange::bounded(Seq::from_u64(1), at_seq))? {
            let id_str = event.id.to_string();
            hash = self
                .hasher
                .hash_event(&hash, id_str.as_bytes(), &event.payload);
        }
        Ok(hash)
    }
}

impl ErasureStateResolverV1 for SqliteStore {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<pos_core::ErasureStateV1>, ErasureErrorV1> {
        resolve_sqlite_erasure_state(&self.conn, digest)
    }
}

impl ErasurePersistencePortV1 for SqliteStore {
    fn load_record(
        &self,
        request: ErasureReferenceV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        load_sqlite_erasure_record(&self.conn, request).and_then(|record| {
            record
                .map(|record| {
                    record
                        .verify_recovered_freeze_authorization(verifier)
                        .map(|()| record)
                })
                .transpose()
        })
    }

    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        records
            .iter()
            .map(|record| {
                record.to_canonical_cbor().and_then(|record_bytes| {
                    record
                        .state()
                        .to_canonical_cbor()
                        .map(|state_bytes| (record.clone(), record_bytes, state_bytes))
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|encoded| {
                if encoded.is_empty() {
                    return Ok(());
                }
                self.conn
                    .execute_batch(begin_immediate_sql())
                    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
                let result = encoded
                    .iter()
                    .try_for_each(|(record, record_bytes, state_bytes)| {
                        stage_erasure_record_sql(&self.conn, record, record_bytes, state_bytes)
                    });
                finish_erasure_transaction(&self.conn, result)
            })
    }

    fn compare_and_swap_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        expected_ledger: ErasureReferenceV1,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        compare_and_swap_erasure_record_sql(
            &self.conn,
            request,
            ErasureCasExpectation::ScopeExtension(expected_ledger),
            &record,
        )
    }

    fn compare_and_swap_administrative_resolution(
        &mut self,
        request: ErasureReferenceV1,
        expected_head: Option<ErasureReferenceV1>,
        record: ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        compare_and_swap_erasure_record_sql(
            &self.conn,
            request,
            ErasureCasExpectation::AdministrativeResolution(expected_head),
            &record,
        )
    }
}

#[derive(Clone, Copy)]
enum ErasureCasExpectation {
    ScopeExtension(ErasureReferenceV1),
    AdministrativeResolution(Option<ErasureReferenceV1>),
}

fn compare_and_swap_erasure_record_sql(
    conn: &Connection,
    request: ErasureReferenceV1,
    expectation: ErasureCasExpectation,
    record: &ErasureCoordinatorRecordV1,
) -> Result<(), ErasureErrorV1> {
    let record_bytes = record.to_canonical_cbor()?;
    let state_bytes = record.state().to_canonical_cbor()?;
    conn.execute_batch(begin_immediate_sql())
        .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let result = load_sqlite_erasure_record(conn, request).and_then(|current| {
        let current = current.ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if current.eq(record) {
            return Ok(());
        }
        let expectation_matches = match expectation {
            ErasureCasExpectation::ScopeExtension(expected) => {
                current.scope_extension_ledger() == Some(expected)
            }
            ErasureCasExpectation::AdministrativeResolution(expected) => {
                current.administrative_resolution_head() == expected
            }
        };
        if !expectation_matches {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        stage_erasure_record_sql(conn, record, &record_bytes, &state_bytes)
    });
    finish_erasure_transaction(conn, result)
}

fn load_sqlite_erasure_record(
    conn: &Connection,
    request: ErasureReferenceV1,
) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
    conn.query_row(
        "SELECT state_digest, record_cbor
         FROM erasure_records WHERE request_digest = ?1",
        params![request.digest().as_slice()],
        |row| {
            row.get::<_, Vec<u8>>(0).and_then(|state_digest| {
                row.get::<_, Vec<u8>>(1)
                    .map(|record_cbor| (state_digest, record_cbor))
            })
        },
    )
    .optional()
    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?
    .map(|(state_digest, bytes)| {
        ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes).and_then(|record| {
            let metadata_digest: [u8; 32] = state_digest
                .try_into()
                .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
            let expected_digest = ErasureReferenceV1::from_digest(metadata_digest);
            if record.request().reference() != request
                || record.state().state_digest() != expected_digest
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            let resolver = SqliteErasureStateResolver { conn };
            resolver
                .resolve_state(expected_digest)
                .and_then(|state| state.ok_or(ErasureErrorV1::ProvenanceMissing))
                .and_then(|_| record.state().verify_predecessor_chain(&resolver))
                .and_then(|()| validate_sqlite_correction(conn, &record))
                .map(|()| record)
        })
    })
    .transpose()
}

struct SqliteErasureStateResolver<'a> {
    conn: &'a Connection,
}

impl ErasureStateResolverV1 for SqliteErasureStateResolver<'_> {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<pos_core::ErasureStateV1>, ErasureErrorV1> {
        resolve_sqlite_erasure_state(self.conn, digest)
    }
}

fn resolve_sqlite_erasure_state(
    conn: &Connection,
    digest: ErasureReferenceV1,
) -> Result<Option<pos_core::ErasureStateV1>, ErasureErrorV1> {
    conn.query_row(
        "SELECT request_digest, state_cbor
         FROM erasure_states WHERE state_digest = ?1",
        params![digest.digest().as_slice()],
        |row| {
            row.get::<_, Vec<u8>>(0).and_then(|request_digest| {
                row.get::<_, Vec<u8>>(1)
                    .map(|state_cbor| (request_digest, state_cbor))
            })
        },
    )
    .optional()
    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?
    .map(|(request_digest, bytes)| {
        let request_digest: [u8; 32] = request_digest
            .try_into()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
        pos_core::ErasureStateV1::from_canonical_cbor(&bytes).and_then(|state| {
            if state.state_digest() == digest
                && state.request() == ErasureReferenceV1::from_digest(request_digest)
            {
                Ok(state)
            } else {
                Err(ErasureErrorV1::ProvenanceMissing)
            }
        })
    })
    .transpose()
}

fn stage_erasure_record_sql(
    conn: &Connection,
    record: &ErasureCoordinatorRecordV1,
    record_bytes: &[u8],
    state_bytes: &[u8],
) -> Result<(), ErasureErrorV1> {
    let request = record.request().reference();
    validate_sqlite_correction(conn, record).and_then(|()| {
        let state_digest = record.state().state_digest();
        validate_erasure_record_slot(conn, request, record, record_bytes).and_then(
            |existing_state_digest| {
                persist_erasure_state(
                    conn,
                    request,
                    record,
                    state_digest,
                    state_bytes,
                    existing_state_digest,
                )
                .and_then(|()| insert_erasure_record(conn, request, state_digest, record_bytes))
            },
        )
    })
}

fn validate_sqlite_correction(
    conn: &Connection,
    record: &ErasureCoordinatorRecordV1,
) -> Result<(), ErasureErrorV1> {
    let Some(correction) = record.supporting_records().correction_provenance() else {
        return Ok(());
    };
    conn.query_row(
        "SELECT record_cbor FROM erasure_records WHERE request_digest = ?1",
        params![correction.rejected_request().digest().as_slice()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)
    .and_then(|bytes| bytes.ok_or(ErasureErrorV1::ProvenanceMissing))
    .and_then(|bytes| ErasureCoordinatorRecordV1::from_canonical_cbor(&bytes))
    .and_then(|predecessor| record.validate_correction_predecessor(&predecessor))
}

fn validate_erasure_record_slot(
    conn: &Connection,
    request: ErasureReferenceV1,
    record: &ErasureCoordinatorRecordV1,
    record_bytes: &[u8],
) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
    let existing_row = conn
        .query_row(
            "SELECT state_digest, record_cbor
             FROM erasure_records WHERE request_digest = ?1",
            params![request.digest().as_slice()],
            |row| {
                row.get::<_, Vec<u8>>(0).and_then(|state_digest| {
                    row.get::<_, Vec<u8>>(1)
                        .map(|record_cbor| (state_digest, record_cbor))
                })
            },
        )
        .optional()
        .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)?;
    let Some((metadata_state_digest, existing_bytes)) = existing_row else {
        if record.state().previous_state().is_some() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        return Ok(None);
    };
    let existing = ErasureCoordinatorRecordV1::from_canonical_cbor(&existing_bytes)?;
    let metadata_state_digest: [u8; 32] = metadata_state_digest
        .try_into()
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    if ErasureReferenceV1::from_digest(metadata_state_digest) != existing.state().state_digest() {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    if existing_bytes.as_slice() != record_bytes {
        existing.validate_replacement(record)?;
    }
    Ok(Some(existing.state().state_digest()))
}

struct ErasureStateRow {
    request_digest: Vec<u8>,
    state_cbor: Vec<u8>,
}

fn load_erasure_state_row(
    conn: &Connection,
    digest: ErasureReferenceV1,
) -> Result<Option<ErasureStateRow>, ErasureErrorV1> {
    conn.query_row(
        "SELECT request_digest, state_cbor
         FROM erasure_states WHERE state_digest = ?1",
        params![digest.digest().as_slice()],
        |row| {
            row.get::<_, Vec<u8>>(0).and_then(|request_digest| {
                row.get::<_, Vec<u8>>(1).map(|state_cbor| ErasureStateRow {
                    request_digest,
                    state_cbor,
                })
            })
        },
    )
    .optional()
    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)
}

fn persist_erasure_state(
    conn: &Connection,
    request: ErasureReferenceV1,
    record: &ErasureCoordinatorRecordV1,
    state_digest: ErasureReferenceV1,
    state_bytes: &[u8],
    existing_state_digest: Option<ErasureReferenceV1>,
) -> Result<(), ErasureErrorV1> {
    load_erasure_state_row(conn, state_digest).and_then(|row| {
        if let Some(row) = row {
            validate_erasure_state_row(request, state_bytes, row.request_digest, &row.state_cbor)
        } else {
            if existing_state_digest == Some(state_digest) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            validate_erasure_predecessor(conn, request, record).and_then(|()| {
                conn.execute(
                    "INSERT INTO erasure_states
                     (state_digest, request_digest, state_cbor) VALUES (?1, ?2, ?3)",
                    params![
                        state_digest.digest().as_slice(),
                        request.digest().as_slice(),
                        state_bytes,
                    ],
                )
                .map(|_| ())
                .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)
            })
        }
    })
}

fn validate_erasure_state_row(
    request: ErasureReferenceV1,
    state_bytes: &[u8],
    request_digest: Vec<u8>,
    stored_state: &[u8],
) -> Result<(), ErasureErrorV1> {
    let metadata_request: [u8; 32] = request_digest
        .try_into()
        .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
    let expected_request = ErasureReferenceV1::from_digest(metadata_request);
    if stored_state != state_bytes {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    if expected_request != request {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    Ok(())
}

fn validate_erasure_predecessor(
    conn: &Connection,
    request: ErasureReferenceV1,
    record: &ErasureCoordinatorRecordV1,
) -> Result<(), ErasureErrorV1> {
    let Some(previous) = record.state().previous_state() else {
        return Ok(());
    };
    load_erasure_state_row(conn, previous)
        .and_then(|row| row.ok_or(ErasureErrorV1::ProvenanceMissing))
        .and_then(|row| {
            let metadata_request: [u8; 32] = row
                .request_digest
                .try_into()
                .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
            pos_core::ErasureStateV1::from_canonical_cbor(&row.state_cbor).and_then(
                |decoded_previous| {
                    if ErasureReferenceV1::from_digest(metadata_request) != request {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                    record.state().validate_predecessor(&decoded_previous)
                },
            )
        })
}

fn insert_erasure_record(
    conn: &Connection,
    request: ErasureReferenceV1,
    state_digest: ErasureReferenceV1,
    record_bytes: &[u8],
) -> Result<(), ErasureErrorV1> {
    conn.execute(
        "INSERT INTO erasure_records
         (request_digest, state_digest, record_cbor) VALUES (?1, ?2, ?3)
         ON CONFLICT(request_digest) DO UPDATE SET
           state_digest = excluded.state_digest,
           record_cbor = excluded.record_cbor",
        params![
            request.digest().as_slice(),
            state_digest.digest().as_slice(),
            record_bytes,
        ],
    )
    .map(|_| ())
    .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)
}

fn finish_erasure_transaction<T>(
    conn: &Connection,
    result: Result<T, ErasureErrorV1>,
) -> Result<T, ErasureErrorV1> {
    match result {
        Ok(value) => {
            if conn.execute_batch("COMMIT").is_ok() {
                Ok(value)
            } else {
                drop(conn.execute_batch("ROLLBACK"));
                Err(ErasureErrorV1::ReceiptCommitFailed)
            }
        }
        Err(error) => {
            if conn.execute_batch("ROLLBACK").is_err() {
                return Err(ErasureErrorV1::ReceiptCommitFailed);
            }
            Err(error)
        }
    }
}

#[cfg(test)]
fn begin_immediate_sql() -> &'static str {
    if FAIL_BEGIN_IMMEDIATE.with(std::cell::Cell::get) {
        return "SELECT RAISE(ABORT, 'begin fault')";
    }
    "BEGIN IMMEDIATE"
}

#[cfg(not(test))]
const fn begin_immediate_sql() -> &'static str {
    "BEGIN IMMEDIATE"
}

fn finish_immediate_transaction<T>(
    conn: &Connection,
    result: Result<T, CoreError>,
) -> Result<T, CoreError> {
    match result {
        Ok(value) => match conn.execute_batch("COMMIT") {
            Ok(()) => Ok(value),
            Err(commit_error) => match conn.execute_batch("ROLLBACK") {
                Ok(()) => Err(CoreError::Storage(format!(
                    "transaction commit failed: {commit_error}"
                ))),
                Err(rollback_error) => Err(CoreError::Storage(format!(
                    "transaction commit failed: {commit_error}; rollback failed: {rollback_error}"
                ))),
            },
        },
        Err(error) => match conn.execute_batch("ROLLBACK") {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(CoreError::Storage(format!(
                "{error}; rollback failed: {rollback_error}"
            ))),
        },
    }
}

const fn mode_str(mode: TimelineMode) -> &'static str {
    match mode {
        TimelineMode::Historical => "historical",
        TimelineMode::Live => "live",
        TimelineMode::Future => "future",
    }
}

/// Persist a [`Seq`] as `SQLite` INTEGER (saturates at [`i64::MAX`]).
fn seq_as_i64(seq: Seq) -> i64 {
    i64::try_from(seq.as_u64()).unwrap_or(i64::MAX)
}

/// Persist a `u64` micros value as `SQLite` INTEGER (saturates at [`i64::MAX`]).
fn u64_as_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn parse_mode(s: &str) -> TimelineMode {
    match s {
        "historical" => TimelineMode::Historical,
        "future" => TimelineMode::Future,
        _ => TimelineMode::Live,
    }
}

fn decode_signature(bytes: Option<Vec<u8>>) -> Result<Option<pos_core::Signature>, CoreError> {
    bytes
        .map(|bytes| {
            bytes
                .try_into()
                .map(pos_core::Signature::from_bytes)
                .map_err(|_| CoreError::Serialization("bad signature length".to_owned()))
        })
        .transpose()
}

fn decode_event_row(row: &rusqlite::Row<'_>) -> Result<Event, CoreError> {
    let seq: i64 = row.get(0).map_err(|e| CoreError::Storage(e.to_string()))?;
    let event_id: String = row.get(1).map_err(|e| CoreError::Storage(e.to_string()))?;
    let entity_id: String = row.get(2).map_err(|e| CoreError::Storage(e.to_string()))?;
    let event_type: String = row.get(3).map_err(|e| CoreError::Storage(e.to_string()))?;
    let payload: Vec<u8> = row.get(4).map_err(|e| CoreError::Storage(e.to_string()))?;
    let wall_time: i64 = row.get(5).map_err(|e| CoreError::Storage(e.to_string()))?;
    let causation_id: Option<String> = row.get(6).map_err(|e| CoreError::Storage(e.to_string()))?;
    let correlation_id: Option<String> =
        row.get(7).map_err(|e| CoreError::Storage(e.to_string()))?;
    let ph_bytes: Vec<u8> = row.get(9).map_err(|e| CoreError::Storage(e.to_string()))?;
    let sig_bytes: Option<Vec<u8>> = row.get(10).map_err(|e| CoreError::Storage(e.to_string()))?;
    let signature_owner_id: Option<String> =
        row.get(11).map_err(|e| CoreError::Storage(e.to_string()))?;
    let signature_role: Option<i64> = row.get(12).map_err(|e| CoreError::Storage(e.to_string()))?;
    let signature_epoch: Option<i64> =
        row.get(13).map_err(|e| CoreError::Storage(e.to_string()))?;
    let ph_arr: [u8; 32] = ph_bytes
        .try_into()
        .map_err(|_| CoreError::Serialization("bad hash".to_owned()))?;
    let signature = decode_signature(sig_bytes)?;
    let signature_identity =
        decode_signature_identity(signature_owner_id, signature_role, signature_epoch)?;
    let event = Event {
        id: parse_event_id(&event_id)?,
        entity: parse_entity_id(&entity_id)?,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_vec(payload),
        wall_time: WallTime::from_micros(u64::try_from(wall_time).unwrap_or(0)),
        seq: Seq::from_u64(u64::try_from(seq).unwrap_or(0)),
        causation_id: causation_id.as_deref().map(parse_event_id).transpose()?,
        correlation_id: correlation_id
            .as_deref()
            .map(parse_correlation_id)
            .transpose()?,
        schema_version: SchemaVersion::V1,
        signature,
        signature_identity,
        payload_hash: pos_core::Hash::from_bytes(ph_arr),
    };
    pos_core::store::validate_event_signature(&event)?;
    Ok(event)
}

fn decode_signature_identity(
    owner_id: Option<String>,
    role: Option<i64>,
    epoch: Option<i64>,
) -> Result<Option<KeyIdentityV1>, CoreError> {
    match (owner_id, role, epoch) {
        (None, None, None) => Ok(None),
        (Some(owner_id), Some(role), Some(epoch)) => {
            let owner_id = OwnerIdV1::new(owner_id)
                .map_err(|_| CoreError::Serialization("bad signature owner".to_owned()))?;
            Ok(Some(KeyIdentityV1::new(
                owner_id,
                KeyRoleV1::from_code(
                    u8::try_from(role)
                        .map_err(|_| CoreError::Serialization("bad signature role".to_owned()))?,
                )
                .map_err(|_| CoreError::Serialization("bad signature role".to_owned()))?,
                u64::try_from(epoch)
                    .map_err(|_| CoreError::Serialization("bad signature epoch".to_owned()))?,
            )))
        }
        _ => Err(CoreError::Serialization(
            "signature identity is incomplete".to_owned(),
        )),
    }
}

fn parse_timeline_id(s: &str) -> Result<TimelineId, CoreError> {
    let ulid = s
        .parse::<ulid::Ulid>()
        .map_err(|_| CoreError::Serialization(format!("invalid ULID: {s}")))?;
    Ok(TimelineId::from_ulid(ulid))
}

fn parse_event_id(s: &str) -> Result<EventId, CoreError> {
    let ulid = s
        .parse::<ulid::Ulid>()
        .map_err(|_| CoreError::Serialization(format!("invalid ULID: {s}")))?;
    Ok(EventId::from_ulid(ulid))
}

fn parse_entity_id(s: &str) -> Result<EntityId, CoreError> {
    let ulid = s
        .parse::<ulid::Ulid>()
        .map_err(|_| CoreError::Serialization(format!("invalid ULID: {s}")))?;
    Ok(EntityId::from_ulid(ulid))
}

fn parse_correlation_id(s: &str) -> Result<pos_core::CorrelationId, CoreError> {
    let ulid = s
        .parse::<ulid::Ulid>()
        .map_err(|_| CoreError::Serialization(format!("invalid ULID: {s}")))?;
    Ok(pos_core::CorrelationId::from_ulid(ulid))
}

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(4);

#[cfg(test)]
use pos_core::geo_cell_admission::{
    hash_admission_consent_record_bytes, AdmissionEntitlementDraftV1, GeoCellAdmissionInputV1,
    GeoCellAdmissionRequestV1, SourceTimeBucket, ValidatedGeoCellV1,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        geo_admission::GeoLocationAdmissionFenceV1,
        ids::{EntityId, EventId},
        store::{EventReadBounds, SeqRange},
        CoreError, KeyRegistrationV1, OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStatusV1,
        OwnTracksEnrollmentStore,
    };

    struct TestFreezeAuthorizationVerifier;

    const TEST_FREEZE_AUTHORIZATION_VERIFIER: TestFreezeAuthorizationVerifier =
        TestFreezeAuthorizationVerifier;

    impl ErasureFreezeAuthorizationVerifierV1 for TestFreezeAuthorizationVerifier {
        fn validate_freeze_authorization(
            &self,
            admission: &pos_core::ErasureFreezeAdmissionEvidenceV1,
            authorization: &pos_core::ErasureFreezeAuthorizationEvidenceV1,
        ) -> Result<(), ErasureErrorV1> {
            (authorization.admission_body_digest() == admission.authorization_body_digest()?)
                .then_some(())
                .ok_or(ErasureErrorV1::Unauthorized)
        }
    }

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected sqlite-store fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing sqlite-store fixture value"))
            })
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful sqlite-store fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:\t"))
                    .and_then(|uids| uids.split_whitespace().next())
                    .and_then(|uid| uid.parse::<u32>().ok())
            })
            == Some(0)
    }

    fn read_bounds(max_payload_bytes: usize) -> EventReadBounds {
        EventReadBounds::new(max_payload_bytes, usize::MAX, usize::MAX, usize::MAX)
    }
    use pos_crypto::chain::hash_payload;

    pub(super) fn make_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    pub(super) fn new_store() -> SqliteStore {
        SqliteStore::open_in_memory().test_ok()
    }

    fn destroy_store(
        store: &mut SqliteStore,
        request: KeyDestructionRequestV1,
    ) -> Result<(KeyDestructionOutcomeV1, KeyRegistryStateV1), CoreError> {
        store.begin_key_registry_destruction(request)?;
        store.complete_key_registry_destruction(request, pos_core::deletion_receipt(&request))
    }

    #[test]
    fn sqlite_validation_boundaries_fail_closed_for_missing_and_mismatched_rows() {
        let mut store = new_store();
        let missing_timeline = TimelineId::new();
        let missing = store
            .append(
                missing_timeline,
                &[make_draft(EntityId::new(), b"missing-timeline")],
            )
            .test_err();
        assert!(matches!(
            missing,
            CoreError::TimelineNotFound(id) if id == missing_timeline
        ));

        let consent_id =
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .test_ok();
        tx.execute(
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![consent_id.as_str(), 12_i64, vec![0_u8; 32], b"mismatched"],
        )
        .test_ok();
        let error = SqliteStore::geo_cell_consent_in_transaction(&tx, &consent_id, 12).test_err();
        assert!(matches!(
            error,
            CoreError::GeographicAdmissionValidationFailed
        ));
        tx.rollback().test_ok();
    }

    #[test]
    fn sqlite_consent_row_decoding_failures_are_typed() {
        let consent_id =
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok();
        let mut missing = new_store();
        let tx = missing
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .test_ok();
        assert!(matches!(
            SqliteStore::geo_cell_consent_in_transaction(&tx, &consent_id, 12),
            Err(CoreError::GeographicAdmissionValidationFailed)
        ));
        tx.rollback().test_ok();

        for statement in [
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 'bad', zeroblob(32), zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, 'bad', zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, zeroblob(32), 7)",
        ] {
            let mut store = new_store();
            store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON")
                .test_ok();
            let tx = store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .test_ok();
            tx.execute(statement, rusqlite::params![consent_id.as_str()])
                .test_ok();
            assert!(matches!(
                SqliteStore::geo_cell_consent_in_transaction(&tx, &consent_id, 12),
                Err(CoreError::Storage(_) | CoreError::GeographicAdmissionValidationFailed)
            ));
            tx.rollback().test_ok();
        }

        for statement in [
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, -1, zeroblob(32), zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, zeroblob(31), zeroblob(1))",
        ] {
            let mut store = new_store();
            store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON")
                .test_ok();
            let tx = store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .test_ok();
            tx.execute(statement, rusqlite::params![consent_id.as_str()])
                .test_ok();
            assert!(matches!(
                SqliteStore::geo_cell_consent_in_transaction(&tx, &consent_id, 12),
                Err(CoreError::GeographicAdmissionValidationFailed)
            ));
            tx.rollback().test_ok();
        }
    }

    #[test]
    fn sqlite_private_append_rejects_an_unknown_timeline() {
        let mut store = new_store();
        let tx = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .test_ok();
        let error = SqliteStore::append_one_in_transaction(
            &tx,
            store.hasher.as_ref(),
            TimelineId::new(),
            make_draft(EntityId::new(), b"unknown"),
        )
        .test_err();
        assert!(matches!(error, CoreError::TimelineNotFound(_)));
        tx.rollback().test_ok();
    }

    pub(super) fn geo_cell_request(
        timeline: TimelineId,
        entity: EntityId,
    ) -> (
        AdmissionConsentRecordV1,
        GeoCellAdmissionFenceV1,
        GeoCellAdmissionRequestV1,
    ) {
        let consent_id =
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok();
        let consent = AdmissionConsentRecordV1::from_persistence_parts(
            consent_id.clone(),
            12,
            CanonicalBytes::from_static(b"sqlite-geo-cell-consent"),
        );
        let draft = AdmissionEntitlementDraftV1::new(
            timeline,
            entity,
            consent_id,
            12,
            hash_admission_consent_record_bytes(consent.canonical_bytes()),
            "sqlite-geo-cell",
            vec![entity],
            "private",
            9,
            1,
            13,
        )
        .test_ok();
        let fence = GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false);
        let request = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(
                b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01",
            ))
            .test_ok(),
            SourceTimeBucket::new(123),
            fence.clone(),
            GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        (consent, fence, request)
    }

    #[test]
    fn geo_cell_commit_uncertainty_returns_recoverable_outcomes() {
        let mut store = new_store();
        let timeline = store
            .create_timeline("geo-cell-commit-uncertainty")
            .test_ok();
        let entity = EntityId::new();
        let (consent, fence, request) = geo_cell_request(timeline.id(), entity);
        store
            .set_geo_cell_admission_consent_record(consent)
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, fence)
            .test_ok();

        store.conn.commit_hook(Some(|| true)).test_ok();
        assert!(matches!(
            store.admit(request.clone()),
            Ok(GeographicAdmissionOutcome::OutcomeUnknown)
        ));
        store.conn.commit_hook::<fn() -> bool>(None).test_ok();
        assert!(store.admit(request.clone()).test_ok().is_accepted());

        store.conn.commit_hook(Some(|| true)).test_ok();
        assert!(matches!(
            store.admit(request.clone()),
            Ok(GeographicAdmissionOutcome::OutcomeUnknown)
        ));
        store.conn.commit_hook::<fn() -> bool>(None).test_ok();
        assert!(store.admit(request).test_ok().is_duplicate());
    }

    /// Local setup shim for pre-ADR-054 adapter tests. It is deliberately
    /// confined to this test module; production exposes no fence setter.
    trait EnrollmentTestSetup {
        fn set_geo_location_admission_fence(
            &mut self,
            timeline: TimelineId,
            entity: EntityId,
            fence: GeoLocationAdmissionFenceV1,
        ) -> Result<(), CoreError>;
    }

    impl EnrollmentTestSetup for SqliteStore {
        fn set_geo_location_admission_fence(
            &mut self,
            timeline: TimelineId,
            entity: EntityId,
            fence: GeoLocationAdmissionFenceV1,
        ) -> Result<(), CoreError> {
            if self.owntracks_enrollment_status()?.status() == OwnTracksEnrollmentStatusV1::Active {
                self.revoke_owntracks_enrollment()?;
            }
            if fence.consent().withdrawn() {
                return Ok(());
            }
            self.pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline, entity, fence, [42; 32],
            ))
            .map(|_| ())
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_request(timeline: TimelineId, entity: EntityId) -> GeoLocationAdmissionRequestV1 {
        GeoLocationAdmissionRequestV1::from_input(
            pos_core::geo_admission::GeoLocationAdmissionInputV1::new(
                timeline,
                entity,
                CanonicalBytes::from_static(b"geographic-commit-outcome"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 10),
                ([4; 32], [5; 32]),
            ),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_fence() -> GeoLocationAdmissionFenceV1 {
        GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9))
    }

    fn append_identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            pos_core::AppendDedupKey::from_keyed_hash([key; 32]),
            pos_core::AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn appended_event_id(
        store: &SqliteStore,
        timeline: TimelineId,
        outcome: &AppendOrDuplicateOutcome,
    ) -> EventId {
        assert!(matches!(outcome, AppendOrDuplicateOutcome::Appended(_)));
        store.read(timeline, SeqRange::all()).test_ok()[0].id
    }

    struct ErrorClock;

    impl AdmissionClock for ErrorClock {
        fn now(&mut self) -> Result<WallTime, CoreError> {
            Err(CoreError::Storage("clock failed".to_owned()))
        }
    }

    struct FenceDroppingClock {
        path: String,
    }

    impl AdmissionClock for FenceDroppingClock {
        fn now(&mut self) -> Result<WallTime, CoreError> {
            Connection::open(&self.path)
                .and_then(|connection| connection.execute_batch("DROP TABLE owntracks_enrollment"))
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            Ok(WallTime::from_micros(1))
        }
    }

    struct FenceRevokingClock {
        path: String,
    }

    impl AdmissionClock for FenceRevokingClock {
        fn now(&mut self) -> Result<WallTime, CoreError> {
            Connection::open(&self.path)
                .and_then(|connection| connection.execute_batch("DELETE FROM owntracks_enrollment"))
                .map_err(|error| CoreError::Storage(error.to_string()))
                .map(|()| WallTime::from_micros(1))
        }
    }

    #[test]
    fn fence_dropping_clock_maps_a_durable_connection_error_to_storage() {
        let mut clock = FenceDroppingClock {
            path: "/definitely/missing/pigloros/fence.db".to_owned(),
        };

        assert_storage_err(clock.now());
    }

    #[test]
    fn fence_revoking_clock_maps_a_durable_connection_error_to_storage() {
        let mut clock = FenceRevokingClock {
            path: "/definitely/missing/pigloros/fence.db".to_owned(),
        };

        assert_storage_err(clock.now());
    }

    #[test]
    fn fence_revoking_clock_maps_a_durable_update_error_to_storage() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let mut clock = FenceRevokingClock {
            path: database.path().to_str().test_ok().to_owned(),
        };

        assert_storage_err(clock.now());
    }

    #[test]
    fn lifecycle_clock_and_open_errors_fail_closed() {
        assert!(SqliteStore::open_with_clock(
            "/definitely/missing/pigloros/lifecycle.db",
            Box::new(pos_core::FixedAdmissionClock(WallTime::from_micros(1))),
        )
        .is_err());
        let mut store = new_store();
        store.clock = Box::new(ErrorClock);
        let timeline = store.create_timeline("clock-error").test_ok();
        let intent = AppendIntent::new(&make_draft(EntityId::new(), b"payload"));
        assert!(store
            .append_intent_or_duplicate(timeline.id(), append_identity(90, 90), intent)
            .is_err());
        let bounded_intent = AppendIntent::new(&make_draft(EntityId::new(), b"bounded-clock"));
        assert!(store
            .append_intent_or_duplicate_bounded(
                timeline.id(),
                append_identity(92, 92),
                bounded_intent,
                1,
            )
            .is_err());
        assert!(store
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());

        let mut overflow = SqliteStore::open_with_clock(
            ":memory:",
            Box::new(pos_core::FixedAdmissionClock(WallTime::from_micros(
                u64::MAX,
            ))),
        )
        .test_ok();
        let timeline = overflow.create_timeline("overflow").test_ok();
        let intent = AppendIntent::new(&make_draft(EntityId::new(), b"payload"));
        assert!(overflow
            .append_intent_or_duplicate(timeline.id(), append_identity(91, 91), intent)
            .is_err());

        let mut transaction = new_store();
        transaction.conn.execute_batch("BEGIN").test_ok();
        assert!(transaction
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());
        drop(transaction.conn.execute_batch("ROLLBACK"));

        let mut prepare = new_store();
        prepare
            .conn
            .execute_batch("DROP TABLE append_identities")
            .test_ok();
        assert!(prepare
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());

        let mut query = new_store();
        query.conn.execute_batch(
            "DROP TABLE append_identities;
             CREATE TABLE append_identities (dedup_key INTEGER, scope_key BLOB, event_id TEXT, expires_at INTEGER);
             INSERT INTO append_identities VALUES (1, X'00', 'id', 0);",
        ).test_ok();
        assert!(query
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_clock_and_transactional_fence_failures_are_fail_closed() {
        let mut clock_error =
            SqliteStore::open_with_clock(":memory:", Box::new(ErrorClock)).test_ok();
        let timeline = clock_error
            .create_timeline("geographic-clock-error")
            .test_ok();
        let entity = EntityId::new();
        clock_error
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        assert_storage_err(
            clock_error
                .admit_geo_location(geographic_request(timeline.id(), entity))
                .map(|_| ()),
        );
        assert!(clock_error
            .read(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());

        let mut overflow = SqliteStore::open_with_clock(
            ":memory:",
            Box::new(pos_core::FixedAdmissionClock(WallTime::from_micros(
                u64::MAX,
            ))),
        )
        .test_ok();
        let timeline = overflow
            .create_timeline("geographic-expiry-overflow")
            .test_ok();
        let entity = EntityId::new();
        overflow
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        assert_storage_err(
            overflow
                .admit_geo_location(geographic_request(timeline.id(), entity))
                .map(|_| ()),
        );
        assert!(overflow
            .read(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());

        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let mut store = SqliteStore::open_with_clock(
            &path,
            Box::new(FenceDroppingClock { path: path.clone() }),
        )
        .test_ok();
        let timeline = store.create_timeline("transactional-fence-read").test_ok();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        assert_storage_err(
            store
                .admit_geo_location(geographic_request(timeline.id(), entity))
                .map(|_| ()),
        );
        assert!(store
            .read(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());
    }

    #[test]
    fn geographic_replay_verifier_reads_the_durable_event_snapshot_link() {
        let mut store = new_store();
        let timeline = store.create_timeline("replay-row").test_ok();
        let entity = EntityId::new();
        let missing_fence_error = store
            .admit_geo_location(geographic_request(timeline.id(), entity))
            .test_err();
        assert_eq!(
            std::mem::discriminant(&missing_fence_error),
            std::mem::discriminant(&CoreError::GeographicAdmissionValidationFailed)
        );
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)",
                params![timeline.id().to_string()],
            )
            .test_ok();
        let integrity_error = store
            .admit_geo_location(geographic_request(timeline.id(), entity))
            .test_err();
        assert_eq!(
            std::mem::discriminant(&integrity_error),
            std::mem::discriminant(&CoreError::GeographicAdmissionValidationFailed)
        );
        store
            .conn
            .execute(
                "DELETE FROM geographic_presence WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        let request = geographic_request(timeline.id(), entity);
        let outcome = store.admit_geo_location(request.clone()).test_ok();
        let event_id = outcome.event_id().test_ok();
        let event_seq = outcome.event_seq().test_ok();
        let link = pos_core::geo_admission::GeoLocationAdmissionLinkV1::for_snapshot(
            timeline.id(),
            event_id,
            event_seq,
            request.snapshot(),
        );
        let evidence = GeoLocationReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            hash_payload(request.payload()),
            hash_payload(link.snapshot_cbor()),
        );

        assert!(store.verify_v1_event_snapshot_link(evidence).is_ok());
    }

    #[test]
    fn geographic_admission_rechecks_a_revoked_fence_in_the_transaction() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let mut store = SqliteStore::open_with_clock(
            &path,
            Box::new(FenceRevokingClock { path: path.clone() }),
        )
        .test_ok();
        let timeline = store.create_timeline("revoked-fence").test_ok();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        let error = store
            .admit_geo_location(geographic_request(timeline.id(), entity))
            .test_err();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&CoreError::GeographicAdmissionValidationFailed)
        );
    }

    #[test]
    fn geographic_replay_verifier_maps_each_durable_row_decode_failure_to_storage() {
        for (name, statement) in [
            ("entity", "UPDATE events SET entity_id = X'00' WHERE event_id = ?1"),
            (
                "schema-version",
                "UPDATE events SET schema_version = X'00' WHERE event_id = ?1",
            ),
            ("payload", "UPDATE events SET payload = 'not-a-blob' WHERE event_id = ?1"),
            (
                "payload-hash",
                "UPDATE events SET payload_hash = 'not-a-blob' WHERE event_id = ?1",
            ),
            (
                "snapshot",
                "UPDATE geographic_admission_links SET snapshot_cbor = 'not-a-blob' WHERE event_id = ?1",
            ),
        ] {
            let mut store = new_store();
            let timeline = store.create_timeline(name).test_ok();
            let entity = EntityId::new();
            let request = geographic_request(timeline.id(), entity);
            store
                .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
                .test_ok();
            let outcome = store
                .admit_geo_location(request.clone())
                .test_ok();
            let event_id = outcome.event_id().test_ok();
            let event_seq = outcome.event_seq().test_ok();
            let link = pos_core::geo_admission::GeoLocationAdmissionLinkV1::for_snapshot(
                timeline.id(),
                event_id,
                event_seq,
                request.snapshot(),
            );
            let evidence = GeoLocationReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                hash_payload(request.payload()),
                hash_payload(link.snapshot_cbor()),
            );
            store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON")
                .test_ok();
            store
                .conn
                .execute(statement, params![event_id.to_string()])
                .test_ok();
            if name == "snapshot" {
                store
                    .conn
                    .execute(
                        "UPDATE geographic_admission_snapshots SET snapshot_cbor = 'not-a-blob' WHERE event_id = ?1",
                        params![event_id.to_string()],
                    )
                    .test_ok();
            }

            let result = store.verify_v1_event_snapshot_link(evidence);
            assert_storage_err(result);
        }
    }

    #[test]
    fn read_event_by_id_fails_closed_on_query_error() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-event-by-id").test_ok();
        store.conn.execute("DROP TABLE events", []).test_ok();
        let error = store.read_event_by_id(timeline.id(), EventId::new());
        assert!(error.test_err().to_string().contains("storage error"));
    }

    #[test]
    fn read_event_by_id_rejects_an_unknown_timeline() {
        let store = new_store();
        let timeline = TimelineId::new();
        let error = store.read_event_by_id(timeline, EventId::new()).test_err();
        assert!(error
            .to_string()
            .contains(&format!("timeline not found: {timeline}")));
    }

    #[test]
    fn read_own_surfaces_a_timeline_lookup_storage_error() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-own-storage-error").test_ok();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT id, name, mode, parent_id, fork_seq, \
                 X'0102' AS head_seq FROM timelines_real",
                [],
            )
            .test_ok();

        assert_storage_err(store.read_own(timeline.id(), SeqRange::all()));
    }

    #[test]
    fn read_event_by_id_fails_closed_when_event_row_read_fails() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-event-row").test_ok();
        let event = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"row")])
            .test_ok()
            .pop()
            .test_ok();
        FAIL_ROWS_NEXT.with(|flag| flag.set(true));
        let result = store.read_event_by_id(timeline.id(), event.id);
        FAIL_ROWS_NEXT.with(|flag| flag.set(false));
        assert!(result.is_err());
    }

    #[test]
    fn lifecycle_delete_errors_fail_closed() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-failure").test_ok();
        let outcome = store
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(92, 92),
                AppendIntent::new(&make_draft(EntityId::new(), b"payload")),
            )
            .test_ok();
        let event_id = appended_event_id(&store, timeline.id(), &outcome);
        store
            .conn
            .execute(
                "UPDATE append_identities SET expires_at = 0 WHERE event_id = ?1",
                rusqlite::params![event_id.to_string()],
            )
            .test_ok();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER deny_identity_delete BEFORE DELETE ON append_identities
                 BEGIN SELECT RAISE(ABORT, 'delete denied'); END;",
            )
            .test_ok();
        assert!(store
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(92, 92),
                AppendIntent::new(&make_draft(EntityId::new(), b"different")),
            )
            .is_err());
        assert!(store
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());

        let mut commit_failure = new_store();
        let timeline = commit_failure.create_timeline("commit-failure").test_ok();
        let outcome = commit_failure
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(93, 93),
                AppendIntent::new(&make_draft(EntityId::new(), b"payload")),
            )
            .test_ok();
        let event_id = appended_event_id(&commit_failure, timeline.id(), &outcome);
        commit_failure
            .conn
            .execute(
                "UPDATE append_identities SET expires_at = 0 WHERE event_id = ?1",
                rusqlite::params![event_id.to_string()],
            )
            .test_ok();
        commit_failure.conn.commit_hook(Some(|| true)).test_ok();
        assert!(commit_failure
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_surfaces_storage_failures_without_partial_events() {
        let entity = EntityId::new();

        let mut missing = new_store();
        assert!(missing
            .append_or_duplicate(
                TimelineId::new(),
                append_identity(1, 1),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut bad_hash = new_store();
        let timeline = bad_hash.create_timeline("bad-hash").test_ok();
        bad_hash
            .conn
            .execute("UPDATE timelines SET chain_head = x'00'", [])
            .test_ok();
        assert!(bad_hash
            .append_or_duplicate(
                timeline.id(),
                append_identity(2, 2),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut events = new_store();
        let timeline = events.create_timeline("events").test_ok();
        events.conn.execute("DROP TABLE events", []).test_ok();
        assert!(events
            .append_or_duplicate(
                timeline.id(),
                append_identity(3, 3),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut update = new_store();
        let timeline = update.create_timeline("update").test_ok();
        update.conn.execute_batch("CREATE TRIGGER deny_head BEFORE UPDATE ON timelines BEGIN SELECT RAISE(ABORT, 'deny'); END;").test_ok();
        assert!(update
            .append_or_duplicate(
                timeline.id(),
                append_identity(4, 4),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut identity = new_store();
        let timeline = identity.create_timeline("identity").test_ok();
        identity.conn.execute_batch("CREATE TRIGGER deny_identity BEFORE INSERT ON append_identities BEGIN SELECT RAISE(ABORT, 'deny'); END;").test_ok();
        assert!(identity
            .append_or_duplicate(
                timeline.id(),
                append_identity(5, 5),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());
        assert!(identity
            .read(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());

        let mut commit = new_store();
        let timeline = commit.create_timeline("commit").test_ok();
        commit.conn.commit_hook(Some(|| true)).test_ok();
        assert!(commit
            .append_or_duplicate(
                timeline.id(),
                append_identity(6, 6),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());
    }

    #[test]
    fn store_owned_clock_intent_and_bounded_cleanup_contract() {
        let admission = WallTime::from_micros(pos_core::APPEND_IDENTITY_RETENTION_MICROS + 42);
        let mut store = SqliteStore::open_with_clock(
            ":memory:",
            Box::new(pos_core::FixedAdmissionClock(admission)),
        )
        .test_ok();
        let timeline = store.create_timeline("clock").test_ok();
        let draft = make_draft(EntityId::new(), b"payload");
        let intent = AppendIntent::new(&draft);
        let first = store
            .append_intent_or_duplicate(timeline.id(), append_identity(7, 7), intent.clone())
            .test_ok();
        let event_id = appended_event_id(&store, timeline.id(), &first);
        assert_eq!(
            store
                .append_intent_or_duplicate(timeline.id(), append_identity(7, 7), intent)
                .test_ok(),
            AppendOrDuplicateOutcome::Duplicate { event_id }
        );
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
                .test_ok(),
            PurgeOutcome {
                removed: 0,
                more_may_remain: false
            }
        );

        store
            .conn
            .execute(
                "UPDATE append_identities SET expires_at = 0 WHERE event_id = ?1",
                rusqlite::params![event_id.to_string()],
            )
            .test_ok();
        let outcome = store
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(7, 7),
                AppendIntent::new(&make_draft(EntityId::new(), b"different")),
            )
            .test_ok();
        let _ = appended_event_id(&store, timeline.id(), &outcome);
        store
            .conn
            .execute("UPDATE append_identities SET expires_at = 0", [])
            .test_ok();
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
                .test_ok(),
            PurgeOutcome {
                removed: 1,
                more_may_remain: true
            }
        );
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
                .test_ok(),
            PurgeOutcome {
                removed: 0,
                more_may_remain: false
            }
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_rejects_corrupt_identity_rows_and_identity_table_errors() {
        let entity = EntityId::new();
        let mut corrupt = new_store();
        let timeline = corrupt.create_timeline("corrupt").test_ok();
        corrupt.conn.execute(
            "INSERT INTO append_identities (dedup_key, scope_key, event_id, expires_at) VALUES (?1, ?2, 'bad', 100)",
            params![[7_u8; 32].as_slice(), [7_u8; 32].as_slice()],
        ).test_ok();
        assert!(corrupt
            .append_or_duplicate(
                timeline.id(),
                append_identity(7, 7),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut missing = new_store();
        let timeline = missing.create_timeline("missing-table").test_ok();
        missing
            .conn
            .execute("DROP TABLE append_identities", [])
            .test_ok();
        assert!(missing
            .append_or_duplicate(
                timeline.id(),
                append_identity(8, 8),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());
    }

    #[test]
    fn retained_identity_lookup_errors_are_storage_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("retained-identity-query").test_ok();
        let identity = append_identity(9, 9);
        let draft = make_draft(EntityId::new(), b"payload");
        store
            .append_or_duplicate(
                timeline.id(),
                identity,
                WallTime::from_micros(1),
                draft.clone(),
            )
            .test_ok();
        store.conn.execute("DROP TABLE events", []).test_ok();

        let error = store
            .append_or_duplicate_with_limit_visible(
                timeline.id(),
                identity,
                WallTime::from_micros(2),
                &draft,
                None,
            )
            .test_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn append_identity_timeline_lookup_errors_are_storage_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("identity-timeline-query").test_ok();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        let draft = make_draft(EntityId::new(), b"payload");
        let error = store.append_or_duplicate_with_limit_visible(
            timeline.id(),
            append_identity(10, 10),
            WallTime::from_micros(1),
            &draft,
            None,
        );
        assert!(error.test_err().to_string().contains("storage error"));
    }

    #[test]
    fn delete_child_count_lookup_errors_are_storage_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-child-count-query").test_ok();
        let _decoy = store.create_timeline("delete-child-count-decoy").test_ok();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .test_ok();
        let view_sql = format!(
            "CREATE VIEW timelines AS SELECT id, name, mode, \
             CASE WHEN id = '{}' THEN parent_id ELSE row_error() END AS parent_id, \
             fork_seq, head_seq FROM timelines_real",
            timeline.id()
        );
        store.conn.execute(&view_sql, []).test_ok();
        let error = store.delete_timeline(timeline.id());
        assert!(error.test_err().to_string().contains("storage error"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_and_cleanup_surface_transaction_and_query_failures() {
        let entity = EntityId::new();

        let mut transaction = new_store();
        let timeline = transaction.create_timeline("transaction").test_ok();
        transaction.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        assert!(transaction
            .append_or_duplicate(
                timeline.id(),
                append_identity(9, 9),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());
        transaction.conn.execute_batch("ROLLBACK").test_ok();

        let mut timeline_query = new_store();
        timeline_query
            .conn
            .execute("DROP TABLE timelines", [])
            .test_ok();
        assert!(timeline_query
            .append_or_duplicate(
                TimelineId::new(),
                append_identity(10, 10),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut cleanup = new_store();
        cleanup
            .conn
            .execute("DROP TABLE append_identities", [])
            .test_ok();
        assert!(cleanup
            .purge_expired_append_identities(WallTime::from_micros(100))
            .is_err());

        let mut withdrawal = new_store();
        withdrawal
            .conn
            .execute("DROP TABLE append_identities", [])
            .test_ok();
        assert!(withdrawal
            .remove_append_identities(pos_core::AppendDedupScope::from_keyed_hash([11; 32]))
            .is_err());
    }

    #[test]
    fn append_or_duplicate_fails_closed_on_corrupt_retained_event_rows() {
        let entity = EntityId::new();
        let mut missing_event = new_store();
        let timeline = missing_event.create_timeline("missing-event").test_ok();
        missing_event
            .append_or_duplicate(
                timeline.id(),
                append_identity(11, 11),
                WallTime::from_micros(1),
                make_draft(entity, b"x"),
            )
            .test_ok();
        missing_event
            .conn
            .execute("DROP TABLE events", [])
            .test_ok();
        assert!(missing_event
            .append_or_duplicate(
                timeline.id(),
                append_identity(11, 11),
                WallTime::from_micros(2),
                make_draft(entity, b"x"),
            )
            .is_err());

        let mut malformed_event_id = new_store();
        let timeline = malformed_event_id
            .create_timeline("malformed-event-id")
            .test_ok();
        malformed_event_id
            .append_or_duplicate(
                timeline.id(),
                append_identity(12, 12),
                WallTime::from_micros(1),
                make_draft(entity, b"x"),
            )
            .test_ok();
        malformed_event_id
            .conn
            .execute("UPDATE events SET event_id = 'bad'", [])
            .test_ok();
        malformed_event_id
            .conn
            .execute("UPDATE append_identities SET event_id = 'bad'", [])
            .test_ok();
        assert!(malformed_event_id
            .append_or_duplicate(
                timeline.id(),
                append_identity(12, 12),
                WallTime::from_micros(2),
                make_draft(entity, b"x"),
            )
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_and_get_timeline() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let got = store.get_timeline(tl.id()).test_ok();
        assert!(got.is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_and_read() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"hello"), make_draft(entity, b"world")],
            )
            .test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload.as_slice(), b"hello");
        assert_eq!(events[1].payload.as_slice(), b"world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_is_opaque_and_unchanged() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00];
        store.append(tl.id(), &[make_draft(entity, &raw)]).test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events[0].payload.as_slice(), &raw[..]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_copy_on_write_parent_unaffected() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
            )
            .test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").test_ok();
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        let parent_events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(parent_events.len(), 2);

        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert_eq!(child_events.len(), 2); // p1 + c1
        assert_eq!(child_events[0].payload.as_slice(), b"p1");
        assert_eq!(child_events[1].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nested_forks_expose_one_logical_sequence() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[
                    make_draft(entity, b"r1"),
                    make_draft(entity, b"r2"),
                    make_draft(entity, b"r3"),
                ],
            )
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(2), "child").test_ok();
        let child_event = store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(child.head, Seq::ZERO);
        assert_eq!(child_event.seq, Seq::from_u64(3));
        assert_eq!(store.logical_head(child.id()).test_ok(), Seq::from_u64(3));

        let grandchild = store
            .fork(child.id(), Seq::from_u64(3), "grandchild")
            .test_ok();
        let grandchild_event = store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(grandchild_event.seq, Seq::from_u64(4));
        assert_eq!(
            store.logical_head(grandchild.id()).test_ok(),
            Seq::from_u64(4)
        );
        assert_eq!(
            store
                .read(grandchild.id(), SeqRange::all())
                .test_ok()
                .iter()
                .map(|event| (event.seq, event.payload.as_slice()))
                .collect::<Vec<_>>(),
            vec![
                (Seq::from_u64(1), b"r1".as_slice()),
                (Seq::from_u64(2), b"r2".as_slice()),
                (Seq::from_u64(3), b"c1".as_slice()),
                (Seq::from_u64(4), b"g1".as_slice()),
            ]
        );
        assert_eq!(
            store
                .read_event_by_id(grandchild.id(), grandchild_event.id)
                .test_ok()
                .test_ok()
                .seq,
            Seq::from_u64(4)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn logical_sequence_lookup_integrity_failures_are_fail_closed() {
        let mut store = new_store();
        let root = store.create_timeline("integrity-root").test_ok();
        let entity = EntityId::new();
        let event = store
            .append(root.id(), &[make_draft(entity, b"root")])
            .test_ok()
            .pop()
            .test_ok();
        assert!(matches!(
            SqliteStore::logical_event(u64::MAX, event),
            Err(CoreError::Storage(_))
        ));
        assert!(matches!(
            store.chain_hash_at(root.id(), Seq::from_u64(2)),
            Err(CoreError::ForkBeyondHead { .. })
        ));

        let unrelated = store.create_timeline("unrelated").test_ok();
        let unrelated_event = store
            .append(unrelated.id(), &[make_draft(entity, b"unrelated")])
            .test_ok()
            .pop()
            .test_ok();
        assert!(store
            .read_event_by_id(root.id(), unrelated_event.id)
            .test_ok()
            .is_none());

        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let hidden = store
            .append(root.id(), &[make_draft(entity, b"after-fork")])
            .test_ok()
            .pop()
            .test_ok();
        assert!(store
            .read_event_by_id(child.id(), hidden.id)
            .test_ok()
            .is_none());

        let mut negative = new_store();
        let negative_root = negative.create_timeline("negative").test_ok();
        let negative_event = negative
            .append(negative_root.id(), &[make_draft(entity, b"negative")])
            .test_ok()
            .pop()
            .test_ok();
        negative
            .conn
            .execute(
                "UPDATE events SET seq = -1 WHERE event_id = ?1",
                params![negative_event.id.to_string()],
            )
            .test_ok();
        assert!(matches!(
            negative.read_event_by_id(negative_root.id(), negative_event.id),
            Err(CoreError::Storage(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn malformed_logical_fork_ranges_fail_closed() {
        let entity = EntityId::new();
        let mut underflow = new_store();
        let underflow_root = underflow.create_timeline("underflow-root").test_ok();
        underflow
            .append(underflow_root.id(), &[make_draft(entity, b"root")])
            .test_ok();
        let underflow_child = underflow
            .fork(underflow_root.id(), Seq::from_u64(1), "underflow-child")
            .test_ok();
        let child_event = underflow
            .append(underflow_child.id(), &[make_draft(entity, b"child")])
            .test_ok()
            .pop()
            .test_ok();
        let grandchild = underflow
            .fork(
                underflow_child.id(),
                Seq::from_u64(2),
                "underflow-grandchild",
            )
            .test_ok();
        underflow
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0 WHERE id = ?1",
                params![grandchild.id().to_string()],
            )
            .test_ok();
        assert!(underflow.read(grandchild.id(), SeqRange::all()).is_err());
        assert!(underflow
            .read_bounded(grandchild.id(), SeqRange::all(), read_bounds(16))
            .is_err());
        assert!(underflow
            .read_event_by_id(grandchild.id(), child_event.id)
            .is_err());

        let mut exceeding = new_store();
        let exceeding_root = exceeding.create_timeline("exceeding-root").test_ok();
        exceeding
            .append(exceeding_root.id(), &[make_draft(entity, b"root")])
            .test_ok();
        let exceeding_child = exceeding
            .fork(exceeding_root.id(), Seq::from_u64(1), "exceeding-child")
            .test_ok();
        exceeding
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 2 WHERE id = ?1",
                params![exceeding_child.id().to_string()],
            )
            .test_ok();
        assert!(exceeding
            .read(exceeding_child.id(), SeqRange::all())
            .is_err());
        assert!(exceeding
            .read_bounded(exceeding_child.id(), SeqRange::all(), read_bounds(16))
            .is_err());
        assert!(exceeding.logical_head(exceeding_child.id()).is_err());
        let root_event = exceeding
            .read_event_by_id(
                exceeding_root.id(),
                exceeding
                    .read(exceeding_root.id(), SeqRange::all())
                    .test_ok()[0]
                    .id,
            )
            .test_ok()
            .test_ok();
        assert!(exceeding
            .read_event_by_id(exceeding_child.id(), root_event.id)
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cyclic_fork_ancestry_fails_closed() {
        let mut store = new_store();
        let root = store.create_timeline("cycle-root").test_ok();
        store
            .append(root.id(), &[make_draft(EntityId::new(), b"root")])
            .test_ok();
        let child = store
            .fork(root.id(), Seq::from_u64(1), "cycle-child")
            .test_ok();
        store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = ?1, fork_seq = 1 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .test_ok();

        assert!(store.logical_head(child.id()).is_err());
        assert!(store.read(child.id(), SeqRange::all()).is_err());
        assert!(store.read_event_by_id(child.id(), EventId::new()).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_beyond_head_returns_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let result = store.fork(tl.id(), Seq::from_u64(99), "bad");
        assert!(matches!(result, Err(CoreError::ForkBeyondHead { .. })));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_unknown_timeline_returns_error() {
        let store = new_store();
        let unknown = TimelineId::new();
        let result = store.read(unknown, SeqRange::all());
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_propagates_chain_and_event_query_errors() {
        let mut store = new_store();
        let error = store
            .read_bounded(TimelineId::new(), SeqRange::all(), read_bounds(1))
            .test_err();
        assert!(matches!(error, CoreError::TimelineNotFound(_)));

        let timeline = store.create_timeline("missing-events").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        store.conn.execute("DROP TABLE events", []).test_ok();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
        let _: CoreError = error;

        let mut materialization_store = new_store();
        let timeline = materialization_store
            .create_timeline("invalid-event-row")
            .test_ok();
        materialization_store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        materialization_store
            .conn
            .execute(
                "UPDATE events SET event_id = 'not-a-ulid' WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        let error = materialization_store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
        assert!(matches!(error, CoreError::Serialization(_)));

        let mut chain_store = new_store();
        let timeline = chain_store.create_timeline("missing-timelines").test_ok();
        chain_store
            .conn
            .execute("DROP TABLE timelines", [])
            .test_ok();
        let error = chain_store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
        let _: CoreError = error;

        let invalid_type_store = new_store();
        let timeline_id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        invalid_type_store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'invalid-parent-type', 'live', X'0102', 0, 0, ?2)",
                params![timeline_id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        let error = invalid_type_store
            .read_bounded(timeline_id, SeqRange::all(), read_bounds(1))
            .test_err();
        let _: CoreError = error;

        invalid_type_store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = ?1, fork_seq = X'0102' WHERE id = ?2",
                params![TimelineId::new().to_string(), timeline_id.to_string()],
            )
            .test_ok();
        let error = invalid_type_store
            .read_bounded(timeline_id, SeqRange::all(), read_bounds(1))
            .test_err();
        let _: CoreError = error;
    }

    #[test]
    fn bounded_read_propagates_snapshot_and_metadata_query_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("snapshot").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        store.conn.execute_batch("BEGIN").test_ok();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
        store.conn.execute_batch("ROLLBACK").test_ok();
        let _: CoreError = error;

        let mut query_store = new_store();
        let query_timeline = query_store.create_timeline("query").test_ok();
        query_store
            .append(query_timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        FAIL_ROWS_NEXT.with(|fail| fail.set(true));
        let error = query_store
            .read_bounded(query_timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
        FAIL_ROWS_NEXT.with(|fail| fail.set(false));
        let _: CoreError = error;

        store.conn.execute("DROP TABLE events", []).test_ok();
        store
            .conn
            .execute_batch(&format!(
                "CREATE VIEW events AS
                 SELECT '{}' AS timeline_id, 1 AS seq",
                timeline.id()
            ))
            .test_ok();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
        let _: CoreError = error;
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_returns_selected_event() {
        let mut store = new_store();
        let timeline = store.create_timeline("bounded").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"ok")])
            .test_ok();
        let child = store
            .fork(timeline.id(), Seq::from_u64(1), "bounded-child")
            .test_ok();
        store
            .append(child.id(), &[make_draft(EntityId::new(), b"child")])
            .test_ok();
        let events = store
            .read_bounded(
                child.id(),
                SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(2)),
                read_bounds(5),
            )
            .test_ok();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload.as_slice(), b"ok");
        assert_eq!(events[1].payload.as_slice(), b"child");
        let error = store
            .read_bounded(child.id(), SeqRange::all(), read_bounds(4))
            .test_err();
        assert!(matches!(error, CoreError::PayloadTooLarge { size: 5 }));
        let empty = store
            .read_bounded(
                child.id(),
                SeqRange::from_seq(Seq::from_u64(3)),
                read_bounds(usize::MAX),
            )
            .test_ok();
        assert!(empty.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_aggregate_event_bytes_before_full_event_query() {
        let mut store = new_store();
        let timeline = store.create_timeline("aggregate-bytes").test_ok();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[
                    EventDraft::new(entity, Kind::new("x"), CanonicalBytes::from_static(b"1234")),
                    EventDraft::new(entity, Kind::new("x"), CanonicalBytes::from_static(b"5678")),
                ],
            )
            .test_ok();

        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));
        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes(4, 1, usize::MAX, 2, 9),
            )
            .test_err();
        assert!(matches!(error, CoreError::ReadBytesTooLarge { size: 10 }));
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 0));

        let events = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes(4, 1, usize::MAX, 2, 10),
            )
            .test_ok();
        assert_eq!(events.len(), 2);
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 1));

        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 0),
            )
            .test_err();
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_MATERIALIZATION_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_MATERIALIZATION_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        let child = store
            .fork(timeline.id(), Seq::from_u64(2), "bounded-time-child")
            .test_ok();
        for phase in 1..=9 {
            BOUNDED_READ_DELAY_PHASE.with(|current| current.set(phase));
            let read_timeline = if phase == 8 {
                child.id()
            } else {
                timeline.id()
            };
            let time_error = store
                .read_bounded(
                    read_timeline,
                    SeqRange::all(),
                    EventReadBounds::new_with_total_bytes_and_elapsed(
                        4,
                        1,
                        usize::MAX,
                        2,
                        10,
                        1_000,
                    ),
                )
                .test_err();
            BOUNDED_READ_DELAY_PHASE.with(|current| current.set(0));
            assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_validates_metadata_before_querying_payloads() {
        let mut store = new_store();
        let timeline = store.create_timeline("two-phase").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"large")])
            .test_ok();

        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(4))
            .test_err();
        assert!(matches!(error, CoreError::PayloadTooLarge { size: 5 }));
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 0));

        store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(5))
            .test_ok();
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_event_type_before_full_event_query() {
        let mut store = new_store();
        let timeline = store.create_timeline("metadata").test_ok();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("x".repeat(5)),
            CanonicalBytes::from_static(b"x"),
        );
        store.append(timeline.id(), &[oversized]).test_ok();
        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 4, usize::MAX, usize::MAX),
            )
            .test_err();

        assert!(matches!(
            error,
            CoreError::EventMetadataTooLarge {
                field: "event_type",
                size: 5
            }
        ));
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 0));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_text_payload_storage_before_full_event_query() {
        let mut store = new_store();
        let timeline = store.create_timeline("text-payload").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET payload = CAST(?1 AS TEXT) WHERE timeline_id = ?2",
                params!["ééé", timeline.id().to_string()],
            )
            .test_ok();
        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(4, usize::MAX, usize::MAX, usize::MAX),
            )
            .test_err();

        assert!(error.to_string().contains("storage class text"));
        assert!(error.to_string().contains("BLOB"));
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 0));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_enforces_exact_fork_depth_and_stops_cycles() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let mut timelines = vec![root];
        for depth in 1..=65 {
            let parent = timelines.last().test_ok();
            let child = store
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .test_ok();
            timelines.push(child);
        }
        let bounds = EventReadBounds::new(1, 1, 64, usize::MAX);

        assert!(store
            .read_bounded(timelines[64].id(), SeqRange::all(), bounds)
            .test_ok()
            .is_empty());
        let error = store
            .read_bounded(timelines[65].id(), SeqRange::all(), bounds)
            .test_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));

        let cycle = timelines[1].id();
        store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = ?1 WHERE id = ?1",
                params![cycle.to_string()],
            )
            .test_ok();
        let error = store
            .read_bounded(cycle, SeqRange::all(), bounds)
            .test_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));

        let invalid_parent = timelines[2].id();
        store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = 'not-a-ulid' WHERE id = ?1",
                params![invalid_parent.to_string()],
            )
            .test_ok();
        let error = store
            .read_bounded(invalid_parent, SeqRange::all(), bounds)
            .test_err();
        assert!(matches!(error, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_seeks_late_across_forks_and_fetches_only_the_page() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<_> = (0..4_096).map(|_| make_draft(entity, b"x")).collect();
        store.append(root.id(), &drafts).test_ok();
        let child = store
            .fork(root.id(), Seq::from_u64(4_096), "child")
            .test_ok();
        store
            .append(
                child.id(),
                &[make_draft(entity, b"y"), make_draft(entity, b"z")],
            )
            .test_ok();
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 4);

        BOUNDED_METADATA_ROWS.with(|count| count.set(0));
        BOUNDED_EVENT_ROWS.with(|count| count.set(0));
        let page = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_095)), bounds)
            .test_ok();
        assert_eq!(
            page.iter()
                .map(|event| event.seq.as_u64())
                .collect::<Vec<_>>(),
            vec![4_095, 4_096, 4_097, 4_098]
        );
        BOUNDED_METADATA_ROWS.with(|count| assert_eq!(count.get(), 4));
        BOUNDED_EVENT_ROWS.with(|count| assert_eq!(count.get(), 4));

        BOUNDED_METADATA_ROWS.with(|count| count.set(0));
        BOUNDED_EVENT_ROWS.with(|count| count.set(0));
        let exhausted = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_098)), bounds)
            .test_ok();
        assert_eq!(exhausted.len(), 1);
        assert_eq!(exhausted[0].seq.as_u64(), 4_098);
        BOUNDED_METADATA_ROWS.with(|count| assert_eq!(count.get(), 1));
        BOUNDED_EVENT_ROWS.with(|count| assert_eq!(count.get(), 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_event_query_uses_the_timeline_sequence_index() {
        let store = new_store();
        let detail: String = store
            .conn
            .query_row(
                "EXPLAIN QUERY PLAN
                 SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                        causation_id, correlation_id, schema_version, payload_hash, signature
                 FROM events
                 WHERE timeline_id = ?1 AND seq >= ?2 AND seq <= ?3
                 ORDER BY seq ASC LIMIT ?4",
                params!["timeline", 4_000_i64, 4_100_i64, 101_i64],
                |row| row.get(3),
            )
            .test_ok();

        assert!(detail.contains("SEARCH events USING INDEX"));
        assert!(detail.contains("sqlite_autoindex_events_1"));
        assert!(!detail.contains("SCAN events"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_offline_event_sequence_invariant_violations() {
        let file = tempfile::NamedTempFile::new().test_ok();
        let path = file.path().to_str().test_ok();
        let timeline_id = {
            let mut store = SqliteStore::open(path).test_ok();
            let timeline = store.create_timeline("offline-gap").test_ok();
            let entity = EntityId::new();
            store
                .append(
                    timeline.id(),
                    &[
                        make_draft(entity, b"a"),
                        make_draft(entity, b"b"),
                        make_draft(entity, b"c"),
                    ],
                )
                .test_ok();
            timeline.id()
        };
        {
            let conn = Connection::open(path).test_ok();
            conn.execute(
                "DELETE FROM events WHERE timeline_id = ?1 AND seq = 2",
                params![timeline_id.to_string()],
            )
            .test_ok();
        }

        let result = SqliteStore::open(path);
        let Err(error) = result else {
            std::panic::resume_unwind(Box::new("offline sequence gaps must be rejected"));
        };
        assert!(error.to_string().contains("contiguous from seq 1"));

        let type_file = tempfile::NamedTempFile::new().test_ok();
        let type_path = type_file.path().to_str().test_ok();
        let entity = EntityId::new();
        let timeline_id = {
            let mut store = SqliteStore::open(type_path).test_ok();
            let timeline = store.create_timeline("offline-type").test_ok();
            store
                .append(
                    timeline.id(),
                    &[
                        make_draft(entity, b"a"),
                        make_draft(entity, b"b"),
                        make_draft(entity, b"c"),
                    ],
                )
                .test_ok();
            timeline.id()
        };
        {
            let conn = Connection::open(type_path).test_ok();
            conn.execute(
                "UPDATE events SET seq = 1.5 WHERE timeline_id = ?1 AND seq = 2",
                params![timeline_id.to_string()],
            )
            .test_ok();
        }
        let result = SqliteStore::open(type_path);
        let _ = result.err().test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_sequence_gaps_in_the_selected_window() {
        let mut store = new_store();
        let timeline = store.create_timeline("runtime-gap").test_ok();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[
                    make_draft(entity, b"a"),
                    make_draft(entity, b"b"),
                    make_draft(entity, b"c"),
                ],
            )
            .test_ok();
        store
            .conn
            .execute(
                "DELETE FROM events WHERE timeline_id = ?1 AND seq = 2",
                params![timeline.id().to_string()],
            )
            .test_ok();

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 2),
            )
            .test_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut type_store = new_store();
        let timeline = type_store.create_timeline("runtime-type").test_ok();
        type_store
            .append(
                timeline.id(),
                &[
                    make_draft(entity, b"a"),
                    make_draft(entity, b"b"),
                    make_draft(entity, b"c"),
                ],
            )
            .test_ok();
        type_store
            .conn
            .execute(
                "UPDATE events SET seq = 1.5 WHERE timeline_id = ?1 AND seq = 2",
                params![timeline.id().to_string()],
            )
            .test_ok();
        let error = type_store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(1)),
                EventReadBounds::new(1, usize::MAX, 0, 2),
            )
            .test_err();
        assert!(matches!(error, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_invalid_timeline_sequence_metadata() {
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 1);

        let mut root_fork_store = new_store();
        let root = root_fork_store.create_timeline("root-fork").test_ok();
        root_fork_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0 WHERE id = ?1",
                params![root.id().to_string()],
            )
            .test_ok();
        let error = root_fork_store
            .read_bounded(root.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(error.to_string().contains("root timeline"));

        let mut root_head_store = new_store();
        let root = root_head_store.create_timeline("root-head").test_ok();
        root_head_store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = -1 WHERE id = ?1",
                params![root.id().to_string()],
            )
            .test_ok();
        let error = root_head_store
            .read_bounded(root.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(error.to_string().contains("negative Event head"));

        let mut head_type_store = new_store();
        let root = head_type_store.create_timeline("root-head-type").test_ok();
        head_type_store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = X'0102' WHERE id = ?1",
                params![root.id().to_string()],
            )
            .test_ok();
        let error = head_type_store
            .read_bounded(root.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(matches!(error, CoreError::Storage(_)));

        let mut child_store = new_store();
        let root = child_store.create_timeline("parent").test_ok();
        let child = child_store.fork(root.id(), Seq::ZERO, "child").test_ok();
        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
                params![child.id().to_string()],
            )
            .test_ok();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(error.to_string().contains("missing its Fork sequence"));

        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0, head_seq = -1 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .test_ok();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(error.to_string().contains("negative Event head"));

        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = -1, head_seq = 0 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .test_ok();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(error.to_string().contains("negative Fork sequence"));

        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 1 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .test_ok();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .test_err();
        assert!(error.to_string().contains("Fork point exceeds"));
    }

    #[test]
    fn bounded_root_count_ignores_children_and_caps_at_maximum_plus_one() {
        let mut store = new_store();
        let first = store.create_timeline("first").test_ok();
        for index in 0..64 {
            store
                .fork(first.id(), Seq::ZERO, &format!("child-{index}"))
                .test_ok();
        }

        store.create_timeline("second").test_ok();
        assert_eq!(store.root_timeline_count_bounded(0).test_ok(), 1);
        assert_eq!(store.root_timeline_count_bounded(1).test_ok(), 2);
        assert_eq!(store.root_timeline_count_bounded(10).test_ok(), 2);
        assert_eq!(store.root_timeline_count_bounded(usize::MAX).test_ok(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_size_conversion_saturates_invalid_values() {
        assert_eq!(sqlite_usize_or_max(2), 2);
        assert_eq!(sqlite_usize_or_max(-1), usize::MAX);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_to_unknown_timeline_returns_error() {
        let mut store = new_store();
        let unknown = TimelineId::new();
        let entity = EntityId::new();
        let result = store.append(unknown, &[make_draft(entity, b"x")]);
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_returns_all() {
        let mut store = new_store();
        store.create_timeline("a").test_ok();
        store.create_timeline("b").test_ok();
        store.create_timeline("c").test_ok();
        let list = store.list_timelines().test_ok();
        assert_eq!(list.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_batch_returns_empty() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let result = store.append(tl.id(), &[]).test_ok();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_range_filters_correctly() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).test_ok();
        let events = store
            .read(
                tl.id(),
                SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(4)),
            )
            .test_ok();
        assert_eq!(events.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parent_events_after_fork_invisible_to_child() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"before")])
            .test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").test_ok();
        store
            .append(tl.id(), &[make_draft(entity, b"after-fork")])
            .test_ok();
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert!(!child_events
            .iter()
            .any(|e| e.payload.as_slice() == b"after-fork"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_with_file_path_creates_persistent_store() {
        // Exercises SqliteStore::open(path) — the non-memory path.
        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_str().test_ok().to_owned();
        // Keep the file alive through the temp binding; open with path.
        let mut store = SqliteStore::open(&path).test_ok();
        let tl = store.create_timeline("persistent").test_ok();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"hello")])
            .test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"hello");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_includes_fork_metadata() {
        // Exercises the fork_point reconstruction in list_timelines.
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"e1"), make_draft(entity, b"e2")],
            )
            .test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").test_ok();

        let list = store.list_timelines().test_ok();
        assert_eq!(list.len(), 2);

        // Find the forked timeline in the list.
        let found = list.iter().find(|t| t.id() == child.id()).test_ok();
        let fork_point = found.meta.fork_point.test_ok();
        assert_eq!(fork_point.0, tl.id());
        assert_eq!(fork_point.1, Seq::from_u64(1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_includes_fork_metadata() {
        // Exercises the fork_point reconstruction in get_timeline.
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "fork1").test_ok();

        let retrieved = store.get_timeline(child.id()).test_ok().test_ok();
        let fork_point = retrieved.meta.fork_point.test_ok();
        assert_eq!(fork_point.0, tl.id());
        assert_eq!(fork_point.1, Seq::from_u64(1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mode_str_covers_all_variants() {
        // Exercises mode_str for all TimelineMode variants, including Historical and Future.
        assert_eq!(mode_str(TimelineMode::Historical), "historical");
        assert_eq!(mode_str(TimelineMode::Live), "live");
        assert_eq!(mode_str(TimelineMode::Future), "future");
        // Also round-trip through parse_mode.
        assert_eq!(parse_mode("historical"), TimelineMode::Historical);
        assert_eq!(parse_mode("future"), TimelineMode::Future);
        assert_eq!(parse_mode("live"), TimelineMode::Live);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mode_str_future_is_persisted_and_read() {
        // Exercises the TimelineMode::Future arm by inserting a future timeline
        // directly and reading it back through get_timeline.
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
             VALUES (?1, 'future-tl', 'future', NULL, NULL, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        let tl = store.get_timeline(id).test_ok().test_ok();
        assert_eq!(tl.mode(), TimelineMode::Future);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_returns_none_for_unknown_id() {
        let store = new_store();
        let unknown = TimelineId::new();
        let result = store.get_timeline(unknown).test_ok();
        assert!(result.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_event_with_correlation_id_round_trips() {
        // Exercises parse_correlation_id via a stored event that has a correlation_id.
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"correlated");
        draft.correlation_id = Some(pos_core::CorrelationId::new());
        store.append(tl.id(), &[draft]).test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 1);
        assert!(events[0].correlation_id.is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn explicit_wall_time_is_preserved() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let pinned = WallTime::from_micros(999_888_777);
        let draft = make_draft(entity, b"pinned").with_wall_time(pinned);
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert_eq!(committed[0].wall_time, pinned);
        let read_back = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(read_back[0].wall_time, pinned);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn absent_wall_time_yields_nonzero_timestamp() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let draft = make_draft(entity, b"no-wall-time");
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert!(committed[0].wall_time.as_micros() > 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn grandchild_fork_chain_stitches_correctly() {
        // Exercises compute_chain_hash_at and read for a multi-level fork chain.
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();

        // Append 3 events to root.
        store
            .append(
                root.id(),
                &[
                    make_draft(entity, b"r1"),
                    make_draft(entity, b"r2"),
                    make_draft(entity, b"r3"),
                ],
            )
            .test_ok();

        // Fork root at seq 2.
        let child = store.fork(root.id(), Seq::from_u64(2), "child").test_ok();

        // Append 2 events to child.
        store
            .append(
                child.id(),
                &[make_draft(entity, b"c1"), make_draft(entity, b"c2")],
            )
            .test_ok();

        // Fork child at logical seq 3 (r1, r2, c1) to get grandchild.
        let grandchild = store
            .fork(child.id(), Seq::from_u64(3), "grandchild")
            .test_ok();

        // Append to grandchild.
        store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .test_ok();

        // Grandchild logical view matches MemoryStore: r1, r2, c1, g1.
        let events = store.read(grandchild.id(), SeqRange::all()).test_ok();
        let payloads: Vec<&[u8]> = events.iter().map(|e| e.payload.as_slice()).collect();
        assert_eq!(payloads, vec![b"r1" as &[u8], b"r2", b"c1", b"g1"]);
        assert_eq!(events[0].seq.as_u64(), 1);
        assert_eq!(events[3].seq.as_u64(), 4);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let result = SqliteStore::open(dir.path().to_str().test_ok());
        assert!(
            matches!(result, Err(CoreError::Storage(_))),
            "expected Storage error opening a directory path"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_objects_that_conflict_with_schema_initialization() {
        let file = tempfile::NamedTempFile::new().test_ok();
        {
            let conn = Connection::open(file.path()).test_ok();
            conn.execute("CREATE TABLE events (unexpected_column INTEGER)", [])
                .test_ok();
        }

        let result = SqliteStore::open(file.path().to_str().test_ok());
        let _ = result.err().test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_incompatible_erasure_persistence_schema() {
        for schema in [
            "CREATE TABLE erasure_records (request_digest BLOB PRIMARY KEY);",
            "CREATE TABLE erasure_states (state_digest BLOB PRIMARY KEY);",
            "CREATE TABLE erasure_records (
                request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
                state_digest BLOB NOT NULL CHECK (length(state_digest) = 32),
                record_cbor BLOB NOT NULL CHECK (length(record_cbor) <= 67108864)
            );",
            "CREATE TABLE erasure_states (
                state_digest BLOB PRIMARY KEY CHECK (length(state_digest) = 32),
                request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
                state_cbor BLOB NOT NULL CHECK (length(state_cbor) <= 1048576)
            );",
        ] {
            let file = tempfile::NamedTempFile::new().test_ok();
            {
                let conn = Connection::open(file.path()).test_ok();
                conn.execute(schema, []).test_ok();
            }
            let error = SqliteStore::open(file.path().to_str().test_ok())
                .err()
                .test_ok();
            assert!(matches!(
                error,
                CoreError::Storage(message) if message.contains("incompatible schema")
            ));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_an_events_table_without_role_columns() {
        let file = tempfile::NamedTempFile::new().test_ok();
        {
            let conn = Connection::open(file.path()).test_ok();
            conn.execute_batch(
                "CREATE TABLE events (
                    timeline_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    wall_time INTEGER NOT NULL,
                    causation_id TEXT,
                    correlation_id TEXT,
                    schema_version INTEGER NOT NULL,
                    payload_hash BLOB NOT NULL,
                    signature BLOB,
                    PRIMARY KEY (timeline_id, seq)
                );",
            )
            .test_ok();
        }

        let error = SqliteStore::open(file.path().to_str().test_ok())
            .err()
            .test_ok();
        assert!(matches!(
            error,
            CoreError::Storage(message)
                if message.contains("missing required signature identity columns")
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_events_table_with_only_one_signature_identity_column() {
        for identity_column in [
            "signature_owner_id TEXT",
            "signature_role INTEGER",
            "signature_epoch INTEGER",
        ] {
            let file = tempfile::NamedTempFile::new().test_ok();
            {
                let conn = Connection::open(file.path()).test_ok();
                conn.execute_batch(&format!(
                    "CREATE TABLE events (
                        timeline_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        event_id TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload BLOB NOT NULL,
                        wall_time INTEGER NOT NULL,
                        causation_id TEXT,
                        correlation_id TEXT,
                        schema_version INTEGER NOT NULL,
                        payload_hash BLOB NOT NULL,
             signature BLOB,
                         {identity_column},
                        PRIMARY KEY (timeline_id, seq)
                    );"
                ))
                .test_ok();
            }

            let error = SqliteStore::open(file.path().to_str().test_ok())
                .err()
                .test_ok();
            assert!(matches!(
                error,
                CoreError::Storage(message)
                    if message.contains("missing required signature identity columns")
            ));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_read_only_requires_and_reads_an_existing_current_schema() {
        let directory = tempfile::tempdir().test_ok();
        let missing = directory.path().join("missing.db");
        let error = SqliteStore::open_read_only(missing.to_str().test_ok())
            .err()
            .test_ok();
        assert!(matches!(error, CoreError::Storage(_)));
        assert!(!missing.exists());

        let path = directory.path().join("ledger.db");
        let mut writable = SqliteStore::open(path.to_str().test_ok()).test_ok();
        writable.create_timeline("ledger").test_ok();
        drop(writable);

        let readonly = SqliteStore::open_read_only(path.to_str().test_ok()).test_ok();
        assert_eq!(readonly.list_timelines().test_ok().len(), 1);

        let uri = format!("file:{}?mode=ro", path.to_str().test_ok());
        let readonly_uri = SqliteStore::open_read_only(&uri).test_ok();
        assert_eq!(readonly_uri.list_timelines().test_ok().len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_existing_utf16_databases_before_schema_use() {
        for encoding in ["UTF-16le", "UTF-16be"] {
            let file = tempfile::NamedTempFile::new().test_ok();
            {
                let conn = Connection::open(file.path()).test_ok();
                conn.execute_batch(&format!(
                    "PRAGMA encoding = '{encoding}';
                     CREATE TABLE imported_marker (value TEXT);"
                ))
                .test_ok();
            }

            let Err(error) = SqliteStore::open(file.path().to_str().test_ok()) else {
                std::panic::resume_unwind(Box::new("UTF-16 database must be rejected"));
            };
            assert!(error.to_string().contains("unsupported SQLite encoding"));
            assert!(error.to_string().contains("UTF-8 is required"));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_databases_are_utf8() {
        let store = new_store();
        let encoding: String = store
            .conn
            .query_row("PRAGMA encoding", [], |row| row.get(0))
            .test_ok();
        assert_eq!(encoding, "UTF-8");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_rejects_bad_chain_head_hash_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = ?1 WHERE id = ?2",
                rusqlite::params![vec![1u8, 2, 3], tl.id().to_string()],
            )
            .test_ok();
        let entity = EntityId::new();
        let err = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_event_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET event_id = 'not-a-ulid' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.read(tl.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_entity_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET entity_id = 'bad-entity' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.read(tl.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_causation_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.causation_id = Some(EventId::new());
        store.append(tl.id(), &[draft]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET causation_id = 'bad-cause' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.read(tl.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_correlation_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.correlation_id = Some(pos_core::CorrelationId::new());
        store.append(tl.id(), &[draft]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET correlation_id = 'bad-corr' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.read(tl.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_bad_payload_hash_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET payload_hash = ?1 WHERE timeline_id = ?2",
                rusqlite::params![vec![9u8, 9], tl.id().to_string()],
            )
            .test_ok();
        let err = store.read(tl.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_rejects_invalid_parent_ulid() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'bad-parent', 'live', 'not-ulid', 0, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        let err = store.get_timeline(id).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_rejects_invalid_timeline_ulid() {
        let store = new_store();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES ('not-ulid', 'x', 'live', NULL, NULL, 0, ?1)",
                rusqlite::params![genesis.as_bytes().as_slice()],
            )
            .test_ok();
        let err = store.list_timelines().test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parse_helpers_reject_invalid_ulids() {
        assert!(parse_timeline_id("nope").is_err());
        assert!(parse_event_id("nope").is_err());
        assert!(parse_entity_id("nope").is_err());
        assert!(parse_correlation_id("nope").is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_head_seq_fails_for_unknown_timeline() {
        let store = new_store();
        let err = store.get_head_seq(TimelineId::new()).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_chain_rejects_invalid_parent_ulid() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'x', 'live', 'bad-parent-ulid', 0, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        let err = store.fork_chain(id).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_storage_err(result: Result<impl Sized, CoreError>) {
        match result {
            Err(CoreError::Storage(_)) => {}
            Err(e) => {
                std::panic::resume_unwind(Box::new(format!("expected CoreError::Storage, got {e}")))
            }
            Ok(_) => std::panic::resume_unwind(Box::new("expected CoreError::Storage, got Ok")),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store.conn.execute("DROP TABLE events", []).test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.conn.execute("DROP TABLE events", []).test_ok();
        assert_storage_err(
            store
                .append(tl.id(), &[make_draft(entity, b"x")])
                .map(|_| ()),
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(store.create_timeline("main").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_when_timelines_table_dropped() {
        let store = new_store();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    fn bounded_root_count_fails_when_timelines_table_dropped() {
        let store = new_store();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(store.root_timeline_count_bounded(1).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_when_timelines_table_dropped() {
        let store = new_store();
        let id = TimelineId::new();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(store.fork(tl.id(), Seq::ZERO, "branch").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(
            store
                .append(tl.id(), &[make_draft(entity, b"x")])
                .map(|_| ()),
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_event_seq() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET seq = 'not-an-int' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_event_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET event_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_entity_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET entity_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_event_type() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET event_type = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_payload() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET payload = 42 WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_wall_time() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET wall_time = 'not-an-int' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_causation_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.causation_id = Some(EventId::new());
        store.append(tl.id(), &[draft]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET causation_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_correlation_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.correlation_id = Some(pos_core::CorrelationId::new());
        store.append(tl.id(), &[draft]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET correlation_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_schema_rejects_non_v1_schema_version() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        assert!(store
            .conn
            .execute(
                "UPDATE events SET schema_version = 'not-an-int' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .is_err());
        assert!(store
            .conn
            .execute(
                "UPDATE events SET schema_version = 2 WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .is_err());
        assert_eq!(
            store.read(tl.id(), SeqRange::all()).test_ok()[0].schema_version,
            SchemaVersion::V1
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_payload_hash() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET payload_hash = 'not-a-blob' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_on_wrong_type_timeline_id() {
        let store = new_store();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (X'0102', 'x', 'live', NULL, NULL, 0, ?1)",
                rusqlite::params![genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_on_wrong_type_mode() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'x', X'0102', NULL, NULL, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_on_wrong_type_head_seq() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'x', 'live', NULL, NULL, X'0102', ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_on_wrong_type_mode() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'x', X'0102', NULL, NULL, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_on_wrong_type_head_seq() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'x', 'live', NULL, NULL, X'0102', ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_chain_fails_on_wrong_type_parent_id() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'x', 'live', X'0102', 0, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.fork_chain(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_chain_fails_on_wrong_type_fork_seq() {
        let store = new_store();
        let id = TimelineId::new();
        let parent = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'root', 'live', NULL, NULL, 0, ?2)",
                rusqlite::params![parent.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', ?2, X'0102', 0, ?3)",
                rusqlite::params![
                    id.to_string(),
                    parent.to_string(),
                    genesis.as_bytes().as_slice()
                ],
            )
            .test_ok();
        assert_storage_err(store.fork_chain(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_malformed_fork_chain_metadata() {
        let mut root_store = new_store();
        let root = root_store.create_timeline("root").test_ok();
        root_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0 WHERE id = ?1",
                params![root.id().to_string()],
            )
            .test_ok();
        let root_error = root_store.read(root.id(), SeqRange::all()).test_err();
        assert!(root_error.to_string().contains("root timeline"));

        let mut child_store = new_store();
        let root = child_store.create_timeline("root").test_ok();
        let child = child_store.fork(root.id(), Seq::ZERO, "child").test_ok();
        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
                params![child.id().to_string()],
            )
            .test_ok();
        let child_error = child_store.read(child.id(), SeqRange::all()).test_err();
        assert!(child_error
            .to_string()
            .contains("missing its Fork sequence"));

        let mut nested_store = new_store();
        let root = nested_store.create_timeline("nested-root").test_ok();
        nested_store
            .append(root.id(), &[make_draft(EntityId::new(), b"root")])
            .test_ok();
        let child = nested_store
            .fork(root.id(), Seq::from_u64(1), "nested-child")
            .test_ok();
        let grandchild = nested_store
            .fork(child.id(), Seq::from_u64(1), "nested-grandchild")
            .test_ok();
        nested_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0 WHERE id = ?1",
                params![grandchild.id().to_string()],
            )
            .test_ok();
        let error = nested_store
            .read(grandchild.id(), SeqRange::all())
            .test_err();
        assert!(error
            .to_string()
            .contains("Fork point precedes inherited history"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_forked_timeline_fails_when_parent_events_corrupt() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
            )
            .test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET payload = 42 WHERE timeline_id = ?1 AND seq = 1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(child.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_parent_events_corrupt() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET payload = 42 WHERE timeline_id = ?1 AND seq = 1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.fork(tl.id(), Seq::from_u64(1), "branch").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_for_unknown_parent_timeline() {
        let mut store = new_store();
        let unknown = TimelineId::new();
        assert!(matches!(
            store.fork(unknown, Seq::ZERO, "branch"),
            Err(CoreError::TimelineNotFound(id)) if id == unknown
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_on_readonly_database_file() {
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return;
        }

        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_owned();
        let tl_id = {
            let mut store = SqliteStore::open(path.to_str().test_ok()).test_ok();
            let tl = store.create_timeline("main").test_ok();
            tl.id()
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).test_ok();
        let mut store = SqliteStore::open(path.to_str().test_ok()).test_ok();
        let entity = EntityId::new();
        let result = store.append(tl_id, &[make_draft(entity, b"x")]);
        assert_storage_err(result.map(|_| ()));
        drop(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o644),
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_fails_on_corrupted_database_file() {
        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_str().test_ok().to_owned();
        std::fs::write(&path, b"not-a-sqlite-database").test_ok();
        assert_storage_err(SqliteStore::open(&path).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_in_memory_respects_fault_injection() {
        FAIL_OPEN_IN_MEMORY.with(|f| f.set(true));
        let result = SqliteStore::open_in_memory();
        FAIL_OPEN_IN_MEMORY.with(|f| f.set(false));
        assert!(matches!(result, Err(CoreError::Storage(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_in_memory_with_hasher_respects_fault_injection() {
        FAIL_OPEN_IN_MEMORY.with(|f| f.set(true));
        let result =
            SqliteStore::open_in_memory_with_hasher(Box::new(pos_crypto::chain::Blake3Hasher));
        FAIL_OPEN_IN_MEMORY.with(|f| f.set(false));
        assert!(matches!(result, Err(CoreError::Storage(_))));
    }

    #[test]
    fn open_propagates_sequence_validation_query_errors() {
        FAIL_SEQUENCE_VALIDATION_QUERY.with(|fail| fail.set(true));
        let result = SqliteStore::open_in_memory();
        FAIL_SEQUENCE_VALIDATION_QUERY.with(|fail| fail.set(false));
        let _ = result.err().test_ok();
    }

    #[test]
    fn sequence_validation_returns_query_errors() {
        let store = new_store();
        store.conn.execute("DROP TABLE events", []).test_ok();
        let _ = store.validate_event_sequence_invariant().test_err();
    }

    fn install_row_error_function(store: &SqliteStore) {
        store
            .conn
            .create_scalar_function(
                "row_error",
                0,
                rusqlite::functions::FunctionFlags::default(),
                |_context| {
                    Err::<String, _>(rusqlite::Error::UserFunctionError(Box::new(
                        std::io::Error::other("injected row error"),
                    )))
                },
            )
            .test_ok();
    }

    #[test]
    fn read_own_events_returns_row_iteration_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("row-error").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE events RENAME TO events_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW events AS SELECT timeline_id, seq, row_error() AS event_id,
                 entity_id, event_type, payload, wall_time, causation_id, correlation_id,
                 schema_version, payload_hash, signature, NULL AS signature_owner_id,
                 NULL AS signature_role,
                 NULL AS signature_epoch FROM events_real",
                [],
            )
            .test_ok();
        let _ = store
            .read_own_events(timeline.id(), Seq::from_u64(1), None)
            .test_err();
    }

    #[test]
    fn bounded_metadata_returns_row_iteration_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("bounded-row-error").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .test_ok();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE events RENAME TO events_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW events AS SELECT timeline_id, seq, typeof(row_error()) AS payload,
                 length(CAST(row_error() AS BLOB)), event_type
                 FROM events_real",
                [],
            )
            .test_ok();
        let _ = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .test_err();
    }

    #[test]
    fn full_event_query_preparation_errors_are_storage_errors() {
        let store = new_store();
        store.conn.execute("DROP TABLE events", []).test_ok();
        let error = SqliteStore::read_own_events_limited_on(
            &store.conn,
            TimelineId::new(),
            Seq::ZERO,
            None,
            None,
            None,
            u64::MAX,
        )
        .test_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn bounded_metadata_query_preparation_errors_are_storage_errors() {
        let store = new_store();
        store.conn.execute("DROP TABLE events", []).test_ok();
        let error = SqliteStore::validate_own_events_bounded(
            &store.conn,
            TimelineId::new(),
            Seq::ZERO,
            Seq::ZERO,
            1,
            read_bounds(1),
            Instant::now(),
        )
        .test_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn list_timelines_returns_row_iteration_errors() {
        let mut store = new_store();
        store.create_timeline("list-row-error").test_ok();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT id, row_error() AS name, mode, parent_id,
                 fork_seq, head_seq FROM timelines_real",
                [],
            )
            .test_ok();
        let _ = store.list_timelines().test_err();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_on_wrong_type_head_seq() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = X'0102' WHERE id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        let entity = EntityId::new();
        assert_storage_err(
            store
                .append(tl.id(), &[make_draft(entity, b"x")])
                .map(|_| ()),
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_on_wrong_type_chain_head_column() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = 123 WHERE id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .test_ok();
        let entity = EntityId::new();
        assert_storage_err(
            store
                .append(tl.id(), &[make_draft(entity, b"x")])
                .map(|_| ()),
        );
    }

    #[test]
    fn read_fails_when_rows_next_injected() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        FAIL_ROWS_NEXT.with(|f| f.set(true));
        let result = store.read(tl.id(), SeqRange::all());
        FAIL_ROWS_NEXT.with(|f| f.set(false));
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    fn list_fails_when_rows_next_injected() {
        let mut store = new_store();
        store.create_timeline("main").test_ok();
        FAIL_ROWS_NEXT.with(|f| f.set(true));
        let result = store.list_timelines();
        FAIL_ROWS_NEXT.with(|f| f.set(false));
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    fn statement_query_failures_are_mapped_at_each_production_caller() {
        let mut store = new_store();
        let timeline = store.create_timeline("query-failure").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"event")])
            .test_ok();

        FAIL_STMT_QUERY.with(|fail| fail.set(true));
        let own = store.read_own(timeline.id(), SeqRange::all());
        FAIL_STMT_QUERY.with(|fail| fail.set(false));
        assert_storage_err(own.map(|_| ()));

        FAIL_STMT_QUERY.with(|fail| fail.set(true));
        let bounded = store.read_bounded(timeline.id(), SeqRange::all(), read_bounds(1));
        FAIL_STMT_QUERY.with(|fail| fail.set(false));
        assert_storage_err(bounded.map(|_| ()));

        FAIL_STMT_QUERY.with(|fail| fail.set(true));
        let listed = store.list_timelines();
        FAIL_STMT_QUERY.with(|fail| fail.set(false));
        assert_storage_err(listed.map(|_| ()));

        let mut stmt = store.conn.prepare("SELECT ?1").test_ok();
        FAIL_STMT_QUERY.with(|fail| fail.set(true));
        assert!(SqliteStore::query_prepared(&mut stmt, &[]).is_err());
        FAIL_STMT_QUERY.with(|fail| fail.set(false));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_on_wrong_type_name() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, X'0102', 'live', NULL, NULL, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_on_wrong_type_parent_id() {
        let store = new_store();
        let id = TimelineId::new();
        let parent = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'root', 'live', NULL, NULL, 0, ?2)",
                rusqlite::params![parent.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', X'0102', 1, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_on_wrong_type_fork_seq_with_parent() {
        let store = new_store();
        let id = TimelineId::new();
        let parent = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'root', 'live', NULL, NULL, 0, ?2)",
                rusqlite::params![parent.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', ?2, X'0102', 0, ?3)",
                rusqlite::params![
                    id.to_string(),
                    parent.to_string(),
                    genesis.as_bytes().as_slice()
                ],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_on_wrong_type_name() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, X'0102', 'live', NULL, NULL, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_on_wrong_type_parent_id() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', X'0102', 1, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_on_wrong_type_fork_seq_with_parent() {
        let store = new_store();
        let id = TimelineId::new();
        let parent = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', ?2, X'0102', 0, ?3)",
                rusqlite::params![
                    id.to_string(),
                    parent.to_string(),
                    genesis.as_bytes().as_slice()
                ],
            )
            .test_ok();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_on_readonly_database_file() {
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return;
        }

        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_owned();
        let tl_id = {
            let mut store = SqliteStore::open(path.to_str().test_ok()).test_ok();
            let tl = store.create_timeline("main").test_ok();
            let entity = EntityId::new();
            store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
            tl.id()
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).test_ok();
        let mut store = SqliteStore::open(path.to_str().test_ok()).test_ok();
        assert_storage_err(store.fork(tl_id, Seq::from_u64(1), "branch").map(|_| ()));
        drop(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o644),
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_rejects_invalid_fork_parent_ulid() {
        let store = new_store();
        let id = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', 'not-ulid', 1, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .test_ok();
        let err = store.list_timelines().test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_chain_hash_at_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store.conn.execute("DROP TABLE timelines", []).test_ok();
        assert_storage_err(
            store
                .compute_chain_hash_at(tl.id(), Seq::from_u64(1))
                .map(|_| ()),
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_when_events_table_is_error_view() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute("ALTER TABLE events RENAME TO events_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW events AS
                 SELECT timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                        causation_id, correlation_id, schema_version, payload_hash
                 FROM events_real
                 WHERE (SELECT RAISE(ABORT, 'fail'))",
                [],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_update_head_fails_on_readonly_database_file() {
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return;
        }

        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_owned();
        let (tl_id, entity) = {
            let mut store = SqliteStore::open(path.to_str().test_ok()).test_ok();
            let tl = store.create_timeline("main").test_ok();
            (tl.id(), EntityId::new())
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).test_ok();
        let mut store = SqliteStore::open(path.to_str().test_ok()).test_ok();
        assert_storage_err(store.append(tl_id, &[make_draft(entity, b"x")]).map(|_| ()));
        drop(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o644),
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_connection_is_query_only() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.conn.execute("PRAGMA query_only = ON", []).test_ok();
        assert_storage_err(
            store
                .append(tl.id(), &[make_draft(entity, b"x")])
                .map(|_| ()),
        );
    }

    #[test]
    fn list_timelines_fails_when_timelines_table_is_error_view() {
        let store = new_store();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS
                 SELECT id, name, mode, parent_id, fork_seq, head_seq
                 FROM timelines_real
                 WHERE (SELECT RAISE(ABORT, 'fail'))",
                [],
            )
            .test_ok();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_when_timelines_table_is_error_view() {
        let store = new_store();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT * FROM no_such_timelines_table",
                [],
            )
            .test_ok();
        assert_storage_err(store.get_timeline(TimelineId::new()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_timeline_head_update_blocked() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        store
            .conn
            .execute(
                "CREATE TRIGGER block_head_update BEFORE UPDATE ON timelines
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END",
                [],
            )
            .test_ok();
        let entity = EntityId::new();
        assert_storage_err(
            store
                .append(tl.id(), &[make_draft(entity, b"x")])
                .map(|_| ()),
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_database_is_locked() {
        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_str().test_ok().to_owned();
        let mut store = SqliteStore::open(&path).test_ok();
        let tl = store.create_timeline("main").test_ok();
        let locker = Connection::open(&path).test_ok();
        locker.execute("BEGIN IMMEDIATE", []).test_ok();

        let entity = EntityId::new();
        let result = store.append(tl.id(), &[make_draft(entity, b"x")]);
        locker.execute("ROLLBACK", []).test_ok();
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_bounded_append_is_all_or_nothing_at_the_owned_event_ceiling() {
        let mut store = new_store();
        let timeline = store.create_timeline("bounded").test_ok();
        let entity = EntityId::new();
        let two_drafts = [make_draft(entity, b"one"), make_draft(entity, b"two")];

        assert_eq!(
            store
                .append_bounded(timeline.id(), &two_drafts, 1)
                .test_ok(),
            None
        );
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::ZERO
        );
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());

        let exact_fit = store
            .append_bounded(timeline.id(), &two_drafts, 2)
            .test_ok()
            .test_ok();
        assert_eq!(exact_fit.len(), 2);
        assert_eq!(exact_fit[0].seq, Seq::from_u64(1));
        assert_eq!(exact_fit[1].seq, Seq::from_u64(2));

        assert_eq!(
            store
                .append_bounded(timeline.id(), &two_drafts, 3)
                .test_ok(),
            None
        );
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(2)
        );
        assert_eq!(
            store
                .read_own(timeline.id(), SeqRange::all())
                .test_ok()
                .len(),
            2
        );

        let empty = store
            .append_bounded(timeline.id(), &[], 2)
            .test_ok()
            .test_ok();
        assert!(empty.is_empty());
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(2)
        );

        let fork = store
            .fork(timeline.id(), Seq::from_u64(2), "bounded-fork")
            .test_ok();
        let fork_event = store
            .append_bounded(fork.id(), &[make_draft(entity, b"fork")], 1)
            .test_ok()
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(fork_event.seq, Seq::from_u64(3));
        assert_eq!(
            store
                .append_bounded(fork.id(), &[make_draft(entity, b"too-many")], 1)
                .test_ok(),
            None
        );
        assert_eq!(
            store.read_own(fork.id(), SeqRange::all()).test_ok().len(),
            1
        );

        let corrupt_fork = store
            .fork(timeline.id(), Seq::from_u64(2), "corrupt-fork")
            .test_ok();
        store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 'not-an-integer' WHERE id = ?1",
                params![corrupt_fork.id().to_string()],
            )
            .test_ok();
        assert!(matches!(
            store.append_bounded(
                corrupt_fork.id(),
                &[make_draft(entity, b"must-not-commit")],
                1,
            ),
            Err(CoreError::Storage(_))
        ));
        let (head, events) = store
            .conn
            .query_row(
                "SELECT head_seq, (SELECT COUNT(*) FROM events WHERE timeline_id = ?1)
                 FROM timelines WHERE id = ?1",
                params![corrupt_fork.id().to_string()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .test_ok();
        assert_eq!((head, events), (0, 0));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_writer_contention_serializes_generic_appends() {
        use std::{sync::mpsc, thread, time::Duration};

        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let mut store_a = SqliteStore::open(&path).test_ok();
        let timeline = store_a.create_timeline("contended").test_ok();
        store_a
            .append(timeline.id(), &[make_draft(EntityId::new(), b"a")])
            .test_ok();
        let mut store_b = SqliteStore::open(&path).test_ok();

        let blocker = Connection::open(&path).test_ok();
        blocker
            .execute_batch("BEGIN IMMEDIATE; UPDATE timelines SET name = name;")
            .test_ok();

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let timeline_id = timeline.id();
        let worker = thread::spawn(move || {
            started_tx.send(()).test_ok();
            let result = store_b.append(timeline_id, &[make_draft(EntityId::new(), b"b")]);
            done_tx.send(result).test_ok();
        });
        started_rx.recv().test_ok();
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        blocker.execute_batch("COMMIT;").test_ok();
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .test_ok()
                .test_ok()
                .len(),
            1
        );
        worker.join().test_ok();

        let store = SqliteStore::open(&path).test_ok();
        let events = store.read(timeline.id(), SeqRange::all()).test_ok();
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            vec![Seq::from_u64(1), Seq::from_u64(2)]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.payload.as_slice())
                .collect::<Vec<_>>(),
            vec![b"a".as_slice(), b"b".as_slice()]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_connection_already_in_txn() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        let err = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_err();
        let bounded_err = store
            .append_bounded(tl.id(), &[make_draft(entity, b"bounded")], 1)
            .test_err();
        drop(store.conn.execute_batch("ROLLBACK"));
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(matches!(bounded_err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        // Returning true from the commit hook forces SQLite to convert COMMIT into rollback.
        store.conn.commit_hook(Some(|| true)).test_ok();
        let err = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        let bounded_err = store
            .append_bounded(tl.id(), &[make_draft(entity, b"bounded")], 1)
            .test_err();
        assert!(matches!(bounded_err, CoreError::Storage(_)));
        store.conn.commit_hook::<fn() -> bool>(None).test_ok();
        assert!(store
            .read_own(tl.id(), SeqRange::all())
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_reports_an_unknown_outcome_when_commit_aborts() {
        let mut store = new_store();
        let timeline = store.create_timeline("geographic-commit-failure").test_ok();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        store.conn.commit_hook(Some(|| true)).test_ok();

        let outcome = store
            .admit_geo_location(geographic_request(timeline.id(), entity))
            .test_ok();

        assert!(outcome.is_outcome_unknown());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn retained_geographic_admission_reports_an_unknown_outcome_when_commit_aborts() {
        let mut store = new_store();
        let timeline = store
            .create_timeline("geographic-retained-commit-failure")
            .test_ok();
        let entity = EntityId::new();
        let request = geographic_request(timeline.id(), entity);
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        assert!(store
            .admit_geo_location(request.clone())
            .test_ok()
            .is_accepted());
        store.conn.commit_hook(Some(|| true)).test_ok();

        let outcome = store.admit_geo_location(request).test_ok();

        assert!(outcome.is_outcome_unknown());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_maps_durable_read_and_transaction_failures() {
        let mut store = new_store();
        let timeline = store.create_timeline("missing-fence-table").test_ok();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        store
            .conn
            .execute_batch("DROP TABLE owntracks_enrollment")
            .test_ok();
        assert_storage_err(
            store
                .admit_geo_location(geographic_request(timeline.id(), entity))
                .map(|_| ()),
        );

        let mut store = new_store();
        let timeline = store.create_timeline("missing-link-table").test_ok();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        store
            .conn
            .execute_batch("DROP TABLE geographic_admission_links")
            .test_ok();
        assert_storage_err(
            store
                .admit_geo_location(geographic_request(timeline.id(), entity))
                .map(|_| ()),
        );

        let mut store = new_store();
        let timeline = store
            .create_timeline("outer-admission-transaction")
            .test_ok();
        let entity = EntityId::new();
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        store.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        let result = store
            .admit_geo_location(geographic_request(timeline.id(), entity))
            .map(|_| ());
        drop(store.conn.execute_batch("ROLLBACK"));
        assert_storage_err(result);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_maps_durable_dedup_and_fence_failures() {
        let mut store = new_store();
        let timeline = store.create_timeline("malformed-dedup-event").test_ok();
        let entity = EntityId::new();
        let request = geographic_request(timeline.id(), entity);
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        assert!(store
            .admit_geo_location(request.clone())
            .test_ok()
            .is_accepted());
        store
            .conn
            .execute(
                "UPDATE geographic_admission_dedup SET event_id = 'not-a-ulid' WHERE fingerprint = ?1",
                params![request.fingerprint().as_owner_keyed_bytes().as_slice()],
            )
            .test_ok();
        assert!(matches!(
            store.admit_geo_location(request),
            Err(CoreError::Serialization(_))
        ));

        let mut store = new_store();
        let timeline = store.create_timeline("expired-dedup-delete").test_ok();
        let entity = EntityId::new();
        let request = geographic_request(timeline.id(), entity);
        store
            .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
            .test_ok();
        assert!(store
            .admit_geo_location(request.clone())
            .test_ok()
            .is_accepted());
        store
            .conn
            .execute(
                "UPDATE geographic_admission_dedup SET expires_at = 0 WHERE fingerprint = ?1",
                params![request.fingerprint().as_owner_keyed_bytes().as_slice()],
            )
            .test_ok();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER deny_expired_geographic_dedup BEFORE DELETE ON geographic_admission_dedup
                 BEGIN SELECT RAISE(ABORT, 'deny expired geographic dedup'); END;",
            )
            .test_ok();
        assert_storage_err(store.admit_geo_location(request).map(|_| ()));

        let mut store = new_store();
        store.conn.execute_batch("DROP TABLE timelines").test_ok();
        assert_storage_err(store.set_geo_location_admission_fence(
            TimelineId::new(),
            EntityId::new(),
            geographic_fence(),
        ));

        let mut store = new_store();
        let timeline = store.create_timeline("deny-fence-write").test_ok();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER deny_geographic_fence BEFORE INSERT ON owntracks_enrollment
                 BEGIN SELECT RAISE(ABORT, 'deny geographic fence'); END;",
            )
            .test_ok();
        assert_storage_err(store.set_geo_location_admission_fence(
            timeline.id(),
            EntityId::new(),
            geographic_fence(),
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_rolls_back_event_and_sidecar_write_failures() {
        for (name, table) in [
            ("event", "events"),
            ("snapshot", "geographic_admission_snapshots"),
            ("link", "geographic_admission_links"),
            ("presence", "geographic_presence"),
            ("dedup", "geographic_admission_dedup"),
        ] {
            let mut store = new_store();
            let timeline = store.create_timeline(name).test_ok();
            let entity = EntityId::new();
            store
                .set_geo_location_admission_fence(timeline.id(), entity, geographic_fence())
                .test_ok();
            store
                .conn
                .execute_batch(&format!(
                    "CREATE TRIGGER deny_{name} BEFORE INSERT ON {table}
                     BEGIN SELECT RAISE(ABORT, 'deny {name}'); END;"
                ))
                .test_ok();
            assert_storage_err(
                store
                    .admit_geo_location(geographic_request(timeline.id(), entity))
                    .map(|_| ()),
            );
            assert!(store
                .read(timeline.id(), SeqRange::all())
                .test_ok()
                .is_empty());
            for sidecar in [
                "geographic_admission_snapshots",
                "geographic_admission_links",
                "geographic_presence",
                "geographic_admission_dedup",
            ] {
                let count: i64 = store
                    .conn
                    .query_row(&format!("SELECT COUNT(*) FROM {sidecar}"), [], |row| {
                        row.get(0)
                    })
                    .test_ok();
                assert_eq!(count, 0, "{sidecar} must roll back with the admission");
            }
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_sidecar_cleanup_failures_are_fail_closed() {
        for table in [
            "geographic_admission_dedup",
            "geographic_admission_links",
            "geographic_admission_snapshots",
            "geographic_presence",
        ] {
            let mut store = new_store();
            let timeline = store.create_timeline(table).test_ok();
            store
                .conn
                .authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
                    if matches!(
                        context.action,
                        rusqlite::hooks::AuthAction::Delete { table_name } if table_name == table
                    ) {
                        rusqlite::hooks::Authorization::Deny
                    } else {
                        rusqlite::hooks::Authorization::Allow
                    }
                }))
                .test_ok();
            assert_storage_err(store.delete_timeline(timeline.id()));
            store
                .conn
                .authorizer(
                    None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
                )
                .test_ok();
            assert!(store.get_timeline(timeline.id()).test_ok().is_some());
            store.delete_timeline(timeline.id()).test_ok();
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_chain_head_corrupted() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();

        // Corrupt the chain_head to wrong length via raw SQL
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = ? WHERE id = ?",
                params![
                    vec![0u8; 16], // Wrong length - should be 32 bytes
                    tl.id().to_string()
                ],
            )
            .test_ok();

        // append should fail when trying to get_chain_head
        let result = store.append(tl.id(), &[make_draft(entity, b"x")]);
        assert!(result.is_err());
        // The exact error type may vary, but the operation should fail
        match result.test_err() {
            CoreError::Storage(_) | CoreError::Serialization(_) => {} // Expected for corrupt data
            other => std::panic::resume_unwind(Box::new(format!(
                "Expected Storage or Serialization error, got {other:?}"
            ))),
        }
        assert!(store
            .append_bounded(tl.id(), &[make_draft(entity, b"bounded")], 1)
            .is_err());
        let event_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE timeline_id = ?1",
                params![tl.id().to_string()],
                |row| row.get(0),
            )
            .test_ok();
        assert_eq!(event_count, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_preserves_identity_sqlite() {
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = new_store();
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        let committed = src
            .append(
                tl.id(),
                &[make_draft(entity, b"one"), make_draft(entity, b"two")],
            )
            .test_ok();
        let export = export_timeline(&src, tl.id()).test_ok();
        let original_tl_id = tl.id();
        let original_ids: Vec<_> = committed.iter().map(|e| e.id).collect();

        let mut dst = new_store();
        let imported = import_timeline_with_id(&mut dst, export).test_ok();
        assert_eq!(imported.id(), original_tl_id);
        let events = dst.read(original_tl_id, SeqRange::all()).test_ok();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, original_ids[0]);
        assert_eq!(events[1].id, original_ids[1]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_removes_and_blocks_fork_parent() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[EventDraft::new(
                    entity,
                    Kind::new("t"),
                    CanonicalBytes::from_vec(b"r1".to_vec()),
                )],
            )
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let err = store.delete_timeline(root.id()).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        store.delete_timeline(child.id()).test_ok();
        store.delete_timeline(root.id()).test_ok();
        assert!(store.get_timeline(root.id()).test_ok().is_none());
        let err = store.delete_timeline(root.id()).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_removes_geo_cell_sidecars() {
        let mut store = new_store();
        let timeline = store.create_timeline("geo-cell-sidecars").test_ok();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        let event_id = EventId::new().to_string();
        let snapshot_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let hash = vec![7_u8; 32];
        store
            .conn
            .execute(
                "INSERT INTO geographic_cell_admission_fences
                 (timeline_id, entity_id, fence_cbor) VALUES (?1, ?2, ?3)",
                params![&timeline_id, &entity_id, vec![1_u8]],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO geographic_cell_admission_snapshots
                 (snapshot_id, snapshot_hash, timeline_id, entity_id, event_id, event_seq, snapshot_cbor)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                params![snapshot_id, &hash, &timeline_id, &entity_id, &event_id, vec![2_u8]],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO geographic_cell_admission_links
                 (timeline_id, event_id, event_seq, snapshot_id, snapshot_hash, snapshot_cbor)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5)",
                params![&timeline_id, &event_id, snapshot_id, &hash, vec![2_u8]],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO geographic_cell_admission_dedup
                 (fingerprint, timeline_id, entity_id, intent, event_id, event_seq,
                  snapshot_id, snapshot_hash, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, 1)",
                params![
                    vec![3_u8; 32],
                    &timeline_id,
                    &entity_id,
                    vec![4_u8],
                    &event_id,
                    snapshot_id,
                    &hash
                ],
            )
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO geographic_cell_admission_consent_records
                 (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
                 VALUES (?1, 12, ?2, ?3)",
                params![snapshot_id, &hash, vec![5_u8]],
            )
            .test_ok();

        store.delete_timeline(timeline.id()).test_ok();
        for table in [
            "geographic_cell_admission_fences",
            "geographic_cell_admission_snapshots",
            "geographic_cell_admission_links",
            "geographic_cell_admission_dedup",
        ] {
            let count: i64 = store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .test_ok();
            assert_eq!(count, 0, "{table} retained deleted timeline state");
        }
        let consent_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM geographic_cell_admission_consent_records",
                [],
                |row| row.get(0),
            )
            .test_ok();
        assert_eq!(
            consent_count, 1,
            "authoritative consent lifecycle was deleted"
        );
    }

    #[test]
    fn delete_timeline_rolls_back_when_geo_cell_sidecar_cleanup_is_denied() {
        for table in [
            "geographic_cell_admission_fences",
            "geographic_cell_admission_dedup",
            "geographic_cell_admission_links",
            "geographic_cell_admission_snapshots",
        ] {
            let mut store = new_store();
            let timeline = store.create_timeline("geo-cell-cleanup-error").test_ok();
            store
                .conn
                .authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
                    if matches!(
                        context.action,
                        rusqlite::hooks::AuthAction::Delete { table_name } if table_name == table
                    ) {
                        rusqlite::hooks::Authorization::Deny
                    } else {
                        rusqlite::hooks::Authorization::Allow
                    }
                }))
                .test_ok();
            assert!(store.delete_timeline(timeline.id()).is_err());
            store
                .conn
                .authorizer(
                    None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
                )
                .test_ok();
            assert!(store.get_timeline(timeline.id()).test_ok().is_some());
            store.delete_timeline(timeline.id()).test_ok();
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_query_row_errors() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        store
            .conn
            .execute_batch("DROP TABLE timelines; CREATE TABLE timelines (id TEXT)")
            .test_ok();
        let err = store.delete_timeline(tl.id()).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_already_in_transaction() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        store.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        let err = store.delete_timeline(tl.id()).test_err();
        drop(store.conn.execute_batch("ROLLBACK"));
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    fn delete_timeline_fails_when_event_deletion_is_aborted() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        store
            .append(tl.id(), &[make_draft(EntityId::new(), b"event")])
            .test_ok();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER abort_event_deletion
                 BEFORE DELETE ON events
                 BEGIN
                    SELECT RAISE(ABORT, 'event deletion blocked');
                 END",
            )
            .test_ok();
        assert_storage_err(store.delete_timeline(tl.id()));
    }

    #[test]
    fn delete_timeline_fails_when_append_identity_table_is_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        store
            .conn
            .execute_batch("DROP TABLE append_identities")
            .test_ok();
        assert_storage_err(store.delete_timeline(tl.id()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        store.conn.commit_hook(Some(|| true)).test_ok();
        let err = store.delete_timeline(tl.id()).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_timelines_delete_aborted() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER deny_timeline_delete BEFORE DELETE ON timelines
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
            )
            .test_ok();
        let err = store.delete_timeline(tl.id()).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_validates_seq_hash_and_ids_sqlite() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .test_ok()
            .remove(0);

        store.append_committed(tl.id(), &[]).test_ok();

        // Collision / non-contiguous with head.
        let err = store
            .append_committed(tl.id(), std::slice::from_ref(&first))
            .test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Gap.
        let mut gap = first.clone();
        gap.id = EventId::new();
        gap.seq = Seq::from_u64(3);
        gap.payload_hash = hash_payload(&gap.payload);
        let err = store.append_committed(tl.id(), &[gap]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Seq 0.
        let mut zero = first.clone();
        zero.id = EventId::new();
        zero.seq = Seq::ZERO;
        zero.payload_hash = hash_payload(&zero.payload);
        let err = store.append_committed(tl.id(), &[zero]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // Bad payload hash.
        let mut bad = first.clone();
        bad.id = EventId::new();
        bad.seq = Seq::from_u64(2);
        bad.payload_hash = pos_core::Hash::from_bytes([9u8; 32]);
        let err = store.append_committed(tl.id(), &[bad]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("payload_hash")));

        // Duplicate id within batch.
        let mut a = first.clone();
        a.id = EventId::new();
        a.seq = Seq::from_u64(2);
        a.payload = CanonicalBytes::from_vec(b"x".to_vec());
        a.payload_hash = hash_payload(&a.payload);
        let mut b = a.clone();
        b.seq = Seq::from_u64(3);
        b.payload = CanonicalBytes::from_vec(b"y".to_vec());
        b.payload_hash = hash_payload(&b.payload);
        let err = store.append_committed(tl.id(), &[a, b]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rolls_back_on_append_fail_sqlite() {
        use pos_core::store::{export_timeline, import_timeline_with_id};
        let mut src = new_store();
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        src.append(
            tl.id(),
            &[EventDraft::new(
                entity,
                Kind::new("t"),
                CanonicalBytes::from_vec(b"one".to_vec()),
            )],
        )
        .test_ok();
        let mut export = export_timeline(&src, tl.id()).test_ok();
        export.events[0].payload_hash = pos_core::Hash::from_bytes([1u8; 32]);
        let mut dst = new_store();
        let err = import_timeline_with_id(&mut dst, export).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(dst.get_timeline(tl.id()).test_ok().is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_and_append_committed_error_paths() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let err = store
            .create_timeline_with_meta(root.meta.clone())
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        let orphan = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "orphan");
        let err = store.create_timeline_with_meta(orphan).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        store.append_committed(root.id(), &[]).test_ok();
        let err = store.append_committed(TimelineId::new(), &[]).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        let entity = EntityId::new();
        let mut good = store
            .append(root.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        let err = store
            .append_committed(root.id(), &[good.clone()])
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        good.seq = Seq::from_u64(99);
        good.payload_hash = pos_core::Hash::from_bytes([1u8; 32]);
        let err = store
            .append_committed(root.id(), &[good.clone()])
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        good.seq = Seq::ZERO;
        good.payload_hash = hash_payload(&good.payload);
        let err = store.append_committed(root.id(), &[good]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_fork_child_succeeds() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .test_ok();
        let child_meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(1), "imported-child");
        // Preserve a chosen id by rebuilding meta (forked_from generates a new id).
        let chosen = TimelineMeta {
            id: TimelineId::new(),
            mode: child_meta.mode,
            name: child_meta.name,
            owner: child_meta.owner,
            fork_point: child_meta.fork_point,
        };
        let chosen_id = chosen.id;
        let child = store.create_timeline_with_meta(chosen).test_ok();
        assert_eq!(child.id(), chosen_id);
        assert_eq!(child.meta.fork_point, Some((root.id(), Seq::from_u64(1))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_fails_when_get_timeline_errors() {
        let mut store = new_store();
        let meta = TimelineMeta::root("x");
        store
            .conn
            .execute_batch("DROP TABLE timelines; CREATE TABLE timelines (id TEXT)")
            .test_ok();
        let err = store.create_timeline_with_meta(meta).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        good.id = EventId::new();
        good.seq = Seq::from_u64(2);
        good.payload_hash = hash_payload(&good.payload);
        store.conn.execute_batch("DROP TABLE events").test_ok();
        let err = store.append_committed(tl.id(), &[good]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_chain_head_corrupted() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        good.id = EventId::new();
        good.seq = Seq::from_u64(2);
        good.payload_hash = hash_payload(&good.payload);
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = ? WHERE id = ?",
                params![vec![0u8; 16], tl.id().to_string()],
            )
            .test_ok();
        let err = store.append_committed(tl.id(), &[good]).test_err();
        assert!(matches!(
            err,
            CoreError::Storage(_) | CoreError::Serialization(_)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_as_i64_and_u64_as_i64_saturate() {
        assert_eq!(seq_as_i64(Seq::from_u64(42)), 42);
        assert_eq!(seq_as_i64(Seq::from_u64(u64::MAX)), i64::MAX);
        assert_eq!(u64_as_i64(7), 7);
        assert_eq!(u64_as_i64(u64::MAX), i64::MAX);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_missing_timeline_with_events() {
        let mut store = new_store();
        let entity = EntityId::new();
        let tl = store.create_timeline("tmp").test_ok();
        let ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        let err = store.append_committed(TimelineId::new(), &[ev]).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_joins_outer_transaction() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        store.append_committed(tl.id(), &[ev]).test_ok();
        store.conn.execute_batch("ROLLBACK").test_ok();
        // Outer rollback undoes the joined append.
        let events = store.read_own(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store.conn.commit_hook(Some(|| true)).test_ok();
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_insert_fails_on_readonly() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("db.sqlite");
        let path_s = path.to_str().test_ok();
        {
            let mut store = SqliteStore::open(path_s).test_ok();
            let _ = store.create_timeline("seed").test_ok();
        }
        let mut perms = std::fs::metadata(&path).test_ok().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).test_ok();
        let mut store = SqliteStore::open(path_s).test_ok();
        let err = store
            .create_timeline_with_meta(TimelineMeta::root("x"))
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_empty_get_timeline_err() {
        let mut store = new_store();
        let id = TimelineId::new();
        store
            .conn
            .execute_batch("DROP TABLE timelines; CREATE TABLE timelines (id TEXT)")
            .test_ok();
        let err = store.append_committed(id, &[]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    fn append_committed_preserves_optional_ids() {
        use pos_core::ids::CorrelationId;
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = new_store();
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        let mut drafts = vec![make_draft(entity, b"one"), make_draft(entity, b"two")];
        drafts[0].causation_id = Some(EventId::new());
        drafts[0].correlation_id = Some(CorrelationId::new());
        assert_eq!(drafts[1].causation_id, None);
        assert_eq!(drafts[1].correlation_id, None);
        src.append(tl.id(), &drafts).test_ok();
        let export = export_timeline(&src, tl.id()).test_ok();
        assert!(export.events[0].causation_id.is_some());
        assert!(export.events[0].correlation_id.is_some());
        assert_eq!(export.events[1].causation_id, None);
        assert_eq!(export.events[1].correlation_id, None);

        let mut dst = new_store();
        let imported = import_timeline_with_id(&mut dst, export).test_ok();
        let events = dst.read(imported.id(), SeqRange::all()).test_ok();
        assert!(events[0].causation_id.is_some());
        assert!(events[0].correlation_id.is_some());
        assert_eq!(events[1].causation_id, None);
        assert_eq!(events[1].correlation_id, None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_row_get_type_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        // Force head_seq to a non-integer blob so row.get::<i64> fails.
        store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = x'00' WHERE id = ?",
                params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_chain_head_type_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        // head_seq stays i64; chain_head becomes INTEGER so Vec<u8> get fails.
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = 1 WHERE id = ?",
                params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_update_head_fails() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER abort_head_update BEFORE UPDATE ON timelines
                 BEGIN SELECT RAISE(ABORT, 'no update'); END;",
            )
            .test_ok();
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_roundtrips_on_append_committed_and_read() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"signed")])
            .test_ok()
            .remove(0);
        // Re-import onto a fresh timeline with a signature attached.
        let mut meta = TimelineMeta::root("imported");
        meta.id = TimelineId::new();
        let other = store.create_timeline_with_meta(meta).test_ok();
        ev.seq = Seq::from_u64(1);
        ev.id = EventId::new();
        ev.signature = Some(pos_core::Signature::from_bytes([7u8; 64]));
        ev.signature_identity = Some(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::TimelineIntegritySigning,
            1,
        ));
        ev.payload_hash = hash_payload(&ev.payload);
        store.append_committed(other.id(), &[ev.clone()]).test_ok();
        let read = store.read(other.id(), SeqRange::all()).test_ok();
        assert_eq!(read[0].signature, ev.signature);
        assert_eq!(read[0].signature_identity, ev.signature_identity);

        let mut too_large = ev;
        too_large.id = EventId::new();
        too_large.signature_identity = Some(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::TimelineIntegritySigning,
            u64::try_from(i64::MAX).unwrap_or_default() + 1,
        ));
        too_large.seq = Seq::from_u64(2);
        assert!(matches!(
            store.append_committed(other.id(), &[too_large]),
            Err(CoreError::Storage(message)) if message.contains("SQLite INTEGER range")
        ));
    }

    #[test]
    fn read_rejects_malformed_signature_identity() {
        let mut store = new_store();
        let timeline = store.create_timeline("signature-identity").test_ok();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"identity")])
            .test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET signature_owner_id = 'test-owner',
                 signature_role = -1, signature_epoch = 1
                 WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        assert!(matches!(
            store.read(timeline.id(), SeqRange::all()),
            Err(CoreError::Serialization(_))
        ));
        store
            .conn
            .execute(
                "UPDATE events SET signature = zeroblob(64), signature_role = NULL,
                 signature_epoch = NULL WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        assert!(matches!(
            store.read(timeline.id(), SeqRange::all()),
            Err(CoreError::Serialization(message))
                if message.contains("signature identity is incomplete")
        ));
        store
            .conn
            .execute(
                "UPDATE events SET signature_owner_id = 'test-owner',
                 signature_role = 99, signature_epoch = 1
                 WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        assert!(matches!(
            store.read(timeline.id(), SeqRange::all()),
            Err(CoreError::Serialization(_))
        ));
        store
            .conn
            .execute(
                "UPDATE events SET signature_owner_id = 'test-owner',
                 signature_role = 1, signature_epoch = -1
                 WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        assert!(matches!(
            store.read(timeline.id(), SeqRange::all()),
            Err(CoreError::Serialization(_))
        ));
        store
            .conn
            .execute(
                "UPDATE events SET signature_role = NULL, signature_epoch = 1
                 WHERE timeline_id = ?1",
                params![timeline.id().to_string()],
            )
            .test_ok();
        assert!(matches!(
            store.read(timeline.id(), SeqRange::all()),
            Err(CoreError::Serialization(_))
        ));
    }

    #[test]
    fn registry_storage_errors_are_reported_by_sqlite_port() {
        let store = new_store();
        store.conn.execute("DROP TABLE key_registry", []).test_ok();
        assert!(matches!(
            store.load_key_registry(),
            Err(CoreError::Storage(_))
        ));

        let mut save_store = new_store();
        save_store
            .conn
            .execute("DROP TABLE key_registry", [])
            .test_ok();
        assert!(matches!(
            save_store.save_key_registry(&KeyRegistryStateV1::new()),
            Err(CoreError::Storage(_))
        ));

        let malformed = new_store();
        malformed
            .conn
            .execute(
                "INSERT INTO key_registry (singleton, state_cbor) VALUES (1, X'01')",
                [],
            )
            .test_ok();
        assert!(matches!(
            malformed.load_key_registry(),
            Err(CoreError::Serialization(_))
        ));

        let mut missing = new_store();
        let timeline = missing.create_timeline("missing-registry").test_ok();
        let mut create_event = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        let error = missing
            .append_signed_authorized(timeline.id(), &KeyRegistryStateV1::new(), &mut create_event)
            .test_err();
        assert!(error.to_string().contains("durable key registry"));
    }

    #[test]
    fn sqlite_ledger_initialization_is_atomic() {
        let mut store = new_store();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_ledger_timeline BEFORE INSERT ON timelines
                 BEGIN SELECT RAISE(ABORT, 'reject ledger timeline'); END",
            )
            .test_ok();

        let error = store
            .initialize_timeline_with_key_registry("ledger", &KeyRegistryStateV1::new())
            .test_err();
        assert!(error.to_string().contains("reject ledger timeline"));
        assert!(store.load_key_registry().test_ok().is_none());
        assert!(store.list_timelines().test_ok().is_empty());
    }

    #[test]
    fn sqlite_ledger_initialization_rejects_a_changed_registry() {
        let mut store = new_store();
        let mut persisted = KeyRegistryStateV1::new();
        persisted
            .register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([3; 32]),
                Some(pos_core::PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();
        store.save_key_registry(&persisted).test_ok();

        let error = store
            .initialize_timeline_with_key_registry("ledger", &KeyRegistryStateV1::new())
            .test_err();
        assert!(error
            .to_string()
            .contains("changed during ledger initialization"));
        assert!(store.list_timelines().test_ok().is_empty());
    }

    #[test]
    fn sqlite_key_registry_persists_and_rejects_stale_authorization() {
        let mut store = new_store();
        let mut persisted = KeyRegistryStateV1::new();
        persisted
            .register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([3; 32]),
                Some(pos_core::PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();
        store.save_key_registry(&persisted).test_ok();
        assert_eq!(store.load_key_registry().test_ok(), Some(persisted.clone()));

        let timeline = store.create_timeline("stale-registry").test_ok();
        let mut callback_called = false;
        let mut create_event = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            callback_called = true;
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        let error = store
            .append_signed_authorized(timeline.id(), &KeyRegistryStateV1::new(), &mut create_event)
            .test_err();
        assert!(error.to_string().contains("changed during signing"));
        assert!(!callback_called);

        let mut successful = new_store();
        successful.save_key_registry(&persisted).test_ok();
        let successful_timeline = successful.create_timeline("successful-signing").test_ok();
        let mut event = successful
            .append(
                successful_timeline.id(),
                &[make_draft(EntityId::new(), b"seed")],
            )
            .test_ok()
            .remove(0);
        event.id = EventId::new();
        let mut create_event = |_: &KeyRegistryStateV1, seq: Seq| {
            event.seq = seq;
            Ok::<Event, CoreError>(event.clone())
        };
        successful
            .append_signed_authorized(successful_timeline.id(), &persisted, &mut create_event)
            .test_ok();

        let mut missing_timeline = new_store();
        missing_timeline.save_key_registry(&persisted).test_ok();
        let mut create_event = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(matches!(
            missing_timeline.append_signed_authorized(
                TimelineId::new(),
                &persisted,
                &mut create_event,
            ),
            Err(CoreError::TimelineNotFound(_))
        ));
    }

    #[test]
    fn sqlite_key_registry_rejects_non_live_initial_snapshots() {
        let mut registry = KeyRegistryStateV1::new();
        let identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let material_digest = Hash::from_bytes([3; 32]);
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                material_digest,
                Some(pos_core::PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();
        let request =
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([5; 32]));
        registry.begin_key_destruction(request).test_ok();

        let mut store = new_store();
        assert!(matches!(
            store.save_key_registry(&registry),
            Err(CoreError::Serialization(_))
        ));
        assert!(store.load_key_registry().test_ok().is_none());

        registry
            .complete_key_destruction(request, pos_core::deletion_receipt(&request))
            .test_ok();
        let mut destroyed_store = new_store();
        assert!(matches!(
            destroyed_store.save_key_registry(&registry),
            Err(CoreError::Serialization(_))
        ));
        assert!(destroyed_store.load_key_registry().test_ok().is_none());
    }

    #[test]
    fn sqlite_key_registry_destruction_wins_when_started_before_signing() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok();
        let identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let material_digest = Hash::from_bytes([3; 32]);
        let mut registry = KeyRegistryStateV1::new();
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                material_digest,
                Some(pos_core::PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();

        let mut setup = SqliteStore::open(path).test_ok();
        setup.save_key_registry(&registry).test_ok();
        let timeline = setup.create_timeline("destruction-first").test_ok();
        let timeline_id = timeline.id();
        setup
            .append(timeline_id, &[make_draft(EntityId::new(), b"seed")])
            .test_ok();
        drop(setup);

        let mut destruction_store = SqliteStore::open(path).test_ok();
        let mut signing_store = SqliteStore::open(path).test_ok();
        signing_store.conn.busy_timeout(Duration::ZERO).test_ok();
        let request =
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([7; 32]));
        let (destruction_started_tx, destruction_started_rx) = std::sync::mpsc::channel();
        let (release_destruction_tx, release_destruction_rx) = std::sync::mpsc::channel();
        destruction_store.destruction_transaction_hook =
            Some((destruction_started_tx, release_destruction_rx));
        let (callback_called_tx, callback_called_rx) = std::sync::mpsc::channel();
        let (signing_result_tx, signing_result_rx) = std::sync::mpsc::channel();

        let (destruction_result, signing_result) = std::thread::scope(|scope| {
            let destruction_handle =
                scope.spawn(move || destroy_store(&mut destruction_store, request));
            destruction_started_rx.recv().test_ok();

            let signing_handle = scope.spawn(move || {
                let mut callback = move |_registry: &KeyRegistryStateV1, _seq: Seq| {
                    assert!(callback_called_tx.send(()).is_ok());
                    Err::<Event, _>(CoreError::Storage(
                        "destroyed signing key callback must not run".to_owned(),
                    ))
                };
                let result =
                    signing_store.append_signed_authorized(timeline_id, &registry, &mut callback);
                assert!(signing_result_tx.send(result).is_ok());
            });
            let signing_result = signing_result_rx.recv_timeout(Duration::from_secs(1));
            let release_result = release_destruction_tx.send(());
            let signing_join = signing_handle.join();
            let destruction_join = destruction_handle.join();

            release_result.test_ok();
            signing_join.test_ok();
            (destruction_join.test_ok(), signing_result.test_ok())
        });

        assert!(destruction_result.is_ok());
        assert!(matches!(
            signing_result,
            Err(CoreError::Storage(message))
                if message.to_ascii_lowercase().contains("database is locked")
        ));
        assert!(callback_called_rx.try_recv().is_err());

        let verify = SqliteStore::open(path).test_ok();
        assert_eq!(verify.read(timeline_id, SeqRange::all()).test_ok().len(), 1);
        assert!(verify
            .load_key_registry()
            .test_ok()
            .and_then(|value| value.tombstone(identity))
            .is_some());
    }

    #[test]
    fn registry_destruction_reports_a_missing_durable_snapshot() {
        let mut store = new_store();
        let request = KeyDestructionRequestV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        );
        let error = store.begin_key_registry_destruction(request).test_err();
        assert!(error.to_string().contains("durable key registry"));
    }

    #[test]
    fn sqlite_registry_transaction_and_callback_failures_are_reported() {
        let mut persisted = KeyRegistryStateV1::new();
        persisted
            .register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([3; 32]),
                Some(pos_core::PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();

        let mut locked = new_store();
        locked.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        let mut locked_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(matches!(
            locked.append_signed_authorized(TimelineId::new(), &persisted, &mut locked_callback,),
            Err(CoreError::Storage(_))
        ));
        assert!(matches!(
            locked.begin_key_registry_destruction(KeyDestructionRequestV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([3; 32]),
                Hash::from_bytes([2; 32]),
            )),
            Err(CoreError::Storage(_))
        ));
        locked.conn.execute_batch("ROLLBACK").test_ok();

        let mut callback_failure = new_store();
        callback_failure.save_key_registry(&persisted).test_ok();
        let timeline = callback_failure
            .create_timeline("callback-failure")
            .test_ok();
        let mut callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback failed".to_owned()))
        };
        assert!(callback_failure
            .append_signed_authorized(timeline.id(), &persisted, &mut callback)
            .test_err()
            .to_string()
            .contains("callback failed"));

        let mut invalid_destruction = new_store();
        invalid_destruction.save_key_registry(&persisted).test_ok();
        let invalid_request = KeyDestructionRequestV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([9; 32]),
            Hash::from_bytes([2; 32]),
        );
        assert!(invalid_destruction
            .begin_key_registry_destruction(invalid_request)
            .test_err()
            .to_string()
            .contains("ledger key destruction"));

        let mut save_failure = new_store();
        save_failure.save_key_registry(&persisted).test_ok();
        save_failure
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_key_registry_update BEFORE UPDATE ON key_registry
                 BEGIN SELECT RAISE(ABORT, 'reject registry update'); END",
            )
            .test_ok();
        let valid_request = KeyDestructionRequestV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([3; 32]),
            Hash::from_bytes([2; 32]),
        );
        assert!(save_failure
            .begin_key_registry_destruction(valid_request)
            .test_err()
            .to_string()
            .contains("reject registry update"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_bad_signature_blob_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET signature = X'01' WHERE timeline_id = ?1",
                params![tl.id().to_string()],
            )
            .test_ok();
        let err = store.read(tl.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_own_fork_roundtrip_sqlite() {
        use pos_core::store::{export_timeline_own, import_timeline_with_id};

        let mut src = new_store();
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        let mut dst = new_store();
        import_timeline_with_id(&mut dst, export_timeline_own(&src, root.id()).test_ok()).test_ok();
        let imported =
            import_timeline_with_id(&mut dst, export_timeline_own(&src, child.id()).test_ok())
                .test_ok();
        assert_eq!(
            imported.meta.fork_point,
            Some((root.id(), Seq::from_u64(1)))
        );
        let own = dst.read_own(child.id(), SeqRange::all()).test_ok();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_fork_beyond_head_sqlite() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let mut meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(99), "bad");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).test_err();
        assert!(matches!(err, CoreError::ForkBeyondHead { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn identity_import_preserves_optional_name_none_sqlite() {
        use pos_core::store::{export_timeline_own, import_timeline_with_id};

        let mut src = new_store();
        let mut meta = TimelineMeta::root("named");
        meta.name = None;
        meta.id = TimelineId::new();
        let created = src.create_timeline_with_meta(meta).test_ok();
        assert!(created.meta.name.is_none());

        let mut dst = new_store();
        let imported =
            import_timeline_with_id(&mut dst, export_timeline_own(&src, created.id()).test_ok())
                .test_ok();
        assert!(imported.meta.name.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_outer_txn_already_open() {
        let mut store = new_store();
        store.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .test_err();
        drop(store.conn.execute_batch("ROLLBACK"));
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn pending_cleanup_scope_decodes_and_rejects_invalid_bytes() {
        let mut store = new_store();
        let scope = AppendDedupScope::from_keyed_hash([7; 32]);
        store
            .conn
            .execute(
                "INSERT INTO pending_append_identity_cleanup (scope_key) VALUES (?1)",
                rusqlite::params![scope.as_bytes().as_slice()],
            )
            .test_ok();
        assert_eq!(
            store.pending_append_identity_cleanup().test_ok(),
            Some(scope)
        );

        store
            .conn
            .execute("DELETE FROM pending_append_identity_cleanup", [])
            .test_ok();
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = ON")
            .test_ok();
        store
            .conn
            .execute(
                "INSERT INTO pending_append_identity_cleanup (scope_key) VALUES (?1)",
                rusqlite::params![vec![1_u8; 31]],
            )
            .test_ok();
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = OFF")
            .test_ok();
        let error = store.pending_append_identity_cleanup().test_err();
        assert!(error
            .to_string()
            .contains("invalid pending cleanup scope length"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        store.conn.commit_hook(Some(|| true)).test_ok();
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    fn registry_transaction_reports_commit_and_rollback_failures() {
        let conn = Connection::open_in_memory().test_ok();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             BEGIN;
             CREATE TABLE transaction_parent(id INTEGER PRIMARY KEY);
             CREATE TABLE transaction_child(
                 parent_id INTEGER REFERENCES transaction_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             );
             INSERT INTO transaction_child(parent_id) VALUES (1);",
        )
        .test_ok();
        let commit_error = finish_immediate_transaction::<()>(&conn, Ok(())).test_err();
        assert!(matches!(commit_error, CoreError::Storage(_)));
        assert!(commit_error
            .to_string()
            .contains("transaction commit failed"));

        let rollback_conn = Connection::open_in_memory().test_ok();
        rollback_conn
            .execute_batch(
                "BEGIN;
                 CREATE TABLE transaction_marker(value INTEGER);
                 INSERT INTO transaction_marker(value) VALUES (1);",
            )
            .test_ok();
        rollback_conn.commit_hook(Some(|| true)).test_ok();
        let rollback_error = finish_immediate_transaction::<()>(&rollback_conn, Ok(())).test_err();
        assert!(matches!(rollback_error, CoreError::Storage(_)));
        assert!(rollback_error
            .to_string()
            .contains("transaction commit failed"));
        assert!(rollback_error.to_string().contains("rollback failed"));

        let error_conn = Connection::open_in_memory().test_ok();
        let error_rollback = finish_immediate_transaction::<()>(
            &error_conn,
            Err(CoreError::Storage("operation failed".to_owned())),
        )
        .test_err();
        assert!(matches!(error_rollback, CoreError::Storage(_)));
        assert!(error_rollback.to_string().contains("rollback failed"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_begin_fault_injected() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        FAIL_BEGIN_IMMEDIATE.with(|f| f.set(true));
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        FAIL_BEGIN_IMMEDIATE.with(|f| f.set(false));
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_vanish_fault_injected() {
        let mut store = new_store();
        FAIL_IMPORT_VANISH.with(|f| f.set(true));
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .test_err();
        FAIL_IMPORT_VANISH.with(|f| f.set(false));
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_rolls_back_when_create_rejects_duplicate_id() {
        let mut store = new_store();
        let existing = store.create_timeline("root").test_ok();
        let err = store
            .import_committed(existing.meta.clone(), &[])
            .test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        // Outer txn rolled back; original timeline still present.
        assert!(store.get_timeline(existing.id()).test_ok().is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_get_storage_fault_injected() {
        let mut store = new_store();
        FAIL_IMPORT_GET_STORAGE.with(|f| f.set(true));
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .test_err();
        FAIL_IMPORT_GET_STORAGE.with(|f| f.set(false));
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_surfaces_broken_parent_chain_sqlite() {
        let mut store = new_store();
        let genesis = pos_crypto::chain::genesis_hash();
        let broken_id = TimelineId::new();
        let missing_parent = TimelineId::new();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'broken', 'live', ?2, 1, 0, ?3)",
                params![
                    broken_id.to_string(),
                    missing_parent.to_string(),
                    genesis.as_bytes().as_slice()
                ],
            )
            .test_ok();
        let mut child = TimelineMeta::forked_from(broken_id, Seq::ZERO, "child");
        child.id = TimelineId::new();
        let err = store.create_timeline_with_meta(child).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_propagates_get_timeline_storage_err() {
        let mut store = new_store();
        store.conn.execute_batch("DROP TABLE timelines").test_ok();
        let mut meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "x");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_missing_timeline_errors() {
        let store = new_store();
        let err = store
            .read_own(TimelineId::new(), SeqRange::all())
            .test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_closed_on_event_id_lookup_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store.conn.execute("DROP TABLE events", []).test_ok();
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_existing_event_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .test_ok()
            .remove(0);
        let mut dup = first;
        dup.seq = Seq::from_u64(2);
        dup.payload = CanonicalBytes::from_vec(b"b".to_vec());
        dup.payload_hash = hash_payload(&dup.payload);
        // keep first.id — must hit the SELECT-found path in id_is_taken
        let err = store.append_committed(tl.id(), &[dup]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_signature() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET signature = 123 WHERE timeline_id = ?1",
                params![tl.id().to_string()],
            )
            .test_ok();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_propagates_get_timeline_storage_err() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .test_ok();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT * FROM no_such_timelines_table",
                [],
            )
            .test_ok();
        assert_storage_err(store.read_own(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_insert_trigger_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER abort_committed_insert BEFORE INSERT ON events
                 BEGIN SELECT RAISE(ABORT, 'no insert'); END;",
            )
            .test_ok();
        let err = store.append_committed(tl.id(), &[ev]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_in_memory_with_hasher_uses_custom_hasher() {
        let mut store =
            SqliteStore::open_in_memory_with_hasher(Box::new(pos_crypto::chain::Blake3Hasher))
                .test_ok();
        let tl = store.create_timeline("hasher-test").test_ok();
        let drafts = [make_draft(EntityId::new(), b"payload")];
        let events = store.append(tl.id(), &drafts).test_ok();
        assert_eq!(events.len(), 1);
    }
    #[test]
    fn generic_committed_geographic_events_are_rejected_and_markers_withhold_reads() {
        let mut store = new_store();
        let ordinary = store.create_timeline("ordinary").test_ok();
        store
            .append(ordinary.id(), &[make_draft(EntityId::new(), b"ordinary")])
            .test_ok();
        assert!(store
            .read_event_by_id(ordinary.id(), EventId::new())
            .test_ok()
            .is_none());
        let timeline = store.create_timeline("geo").test_ok();
        let payload = CanonicalBytes::from_vec(b"protected".to_vec());
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("geo.location"),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        assert!(store.append_committed(timeline.id(), &[event]).is_err());
        store
            .conn
            .execute(
                "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)",
                params![timeline.id().to_string()],
            )
            .test_ok();
        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .test_err()
            .to_string()
            .contains("not found"));
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .test_err()
            .to_string()
            .contains("not found"));
        let _ = store.list_timelines().test_ok();
        assert!(store
            .append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("geo.location"),
                    CanonicalBytes::from_vec(b"x".to_vec()),
                )],
            )
            .is_err());
        assert!(store
            .fork(timeline.id(), Seq::from_u64(1), "child")
            .test_err()
            .to_string()
            .contains("not found"));
        assert!(store
            .create_timeline_with_meta(TimelineMeta::forked_from(
                timeline.id(),
                Seq::ZERO,
                "imported",
            ))
            .test_err()
            .to_string()
            .contains("not found"));

        let mut broken = new_store();
        let parent = broken.create_timeline("broken-parent").test_ok();
        let broken_child = broken
            .fork(parent.id(), Seq::ZERO, "broken-child")
            .test_ok();
        broken
            .conn
            .execute(
                "DELETE FROM timelines WHERE id = ?1",
                params![parent.id().to_string()],
            )
            .test_ok();
        assert!(broken
            .read_bounded(broken_child.id(), SeqRange::all(), read_bounds(1024))
            .test_err()
            .to_string()
            .contains("not found"));

        assert!(store.delete_timeline(timeline.id()).is_err());
        assert_eq!(store.root_timeline_count_bounded(1).test_ok(), 1);
    }

    #[test]
    fn generic_read_fails_closed_when_event_sequence_is_malformed() {
        let mut store = new_store();
        let timeline = store.create_timeline("malformed-sequence").test_ok();
        let event = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"ordinary")])
            .test_ok()
            .pop()
            .test_ok();
        store
            .conn
            .execute(
                "UPDATE events SET seq = -1 WHERE event_id = ?1",
                params![event.id.to_string()],
            )
            .test_ok();

        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
    }

    #[test]
    fn storage_error_paths_are_fail_closed() {
        let mut bounded_store = new_store();
        let bounded_timeline = bounded_store.create_timeline("bounded-error").test_ok();
        FAIL_BOUNDED_CHAIN_QUERY.with(|flag| flag.set(true));
        assert!(bounded_store
            .read_bounded(bounded_timeline.id(), SeqRange::all(), read_bounds(1))
            .is_err());
        FAIL_BOUNDED_CHAIN_QUERY.with(|flag| flag.set(false));

        let mut event_store = new_store();
        let event_timeline = event_store.create_timeline("event-error").test_ok();
        event_store
            .conn
            .execute("DROP TABLE timelines", [])
            .test_ok();
        assert!(event_store
            .read_event_by_id(event_timeline.id(), EventId::new())
            .is_err());

        let mut begin_store = new_store();
        let begin_parent = begin_store.create_timeline("begin-error").test_ok();
        begin_store.conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        assert!(begin_store
            .fork(begin_parent.id(), Seq::ZERO, "child")
            .is_err());
        begin_store.conn.execute_batch("ROLLBACK").test_ok();

        let mut commit_store = new_store();
        let commit_parent = commit_store.create_timeline("commit-error").test_ok();
        commit_store.conn.commit_hook(Some(|| true)).test_ok();
        assert!(commit_store
            .fork(commit_parent.id(), Seq::ZERO, "child")
            .is_err());
        commit_store
            .conn
            .commit_hook::<fn() -> bool>(None)
            .test_ok();
        let timeline_count: i64 = commit_store
            .conn
            .query_row("SELECT COUNT(*) FROM timelines", [], |row| row.get(0))
            .test_ok();
        assert_eq!(timeline_count, 1);
    }

    #[test]
    fn geographic_presence_sidecar_failures_fail_closed() {
        geographic_presence_sidecar_read_failures();
        generic_read_failures_fail_closed();
    }

    fn geographic_presence_sidecar_read_failures() {
        geographic_presence_rejects_all_generic_read_and_append_paths();

        let mut list_store = new_store();
        let list_timeline = list_store.create_timeline("list").test_ok();
        list_store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .test_ok();
        assert!(list_store.list_timelines().is_err());
        assert!(list_store.get_timeline(list_timeline.id()).is_err());

        let mut fork_store = new_store();
        let fork_parent = fork_store.create_timeline("fork").test_ok();
        fork_store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .test_ok();
        assert!(fork_store
            .fork(fork_parent.id(), Seq::ZERO, "child")
            .is_err());

        let mut delete_store = new_store();
        let delete_timeline = delete_store.create_timeline("delete").test_ok();
        delete_store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .test_ok();
        assert!(delete_store.delete_timeline(delete_timeline.id()).is_err());
    }

    fn geographic_presence_rejects_all_generic_read_and_append_paths() {
        let mut store = new_store();
        let timeline = store.create_timeline("read").test_ok();
        let retained = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"retained")])
            .test_ok()
            .pop()
            .test_ok();
        store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .test_ok();

        assert!(store.read(timeline.id(), SeqRange::all()).is_err());
        assert!(store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"append")])
            .is_err());
        assert!(store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 1),
                WallTime::from_micros(1),
                make_draft(EntityId::new(), b"deduplicated"),
            )
            .is_err());
        assert!(store
            .read_event_by_id(timeline.id(), EventId::new())
            .is_err());
        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
        assert!(store.read_own(timeline.id(), SeqRange::all()).is_err());
        assert!(store.append_committed(timeline.id(), &[retained]).is_err());
        assert!(store.chain_hash_at(timeline.id(), Seq::ZERO).is_err());
    }

    fn generic_read_failures_fail_closed() {
        let mut privileged_store = new_store();
        let privileged_timeline = privileged_store.create_timeline("privileged").test_ok();
        privileged_store
            .conn
            .execute("DROP TABLE events", [])
            .test_ok();
        assert!(privileged_store
            .read(privileged_timeline.id(), SeqRange::all())
            .is_err());

        let mut missing_timeline_store = new_store();
        let missing_timeline = missing_timeline_store.create_timeline("missing").test_ok();
        missing_timeline_store
            .conn
            .execute("DROP TABLE timelines", [])
            .test_ok();
        assert!(missing_timeline_store
            .read(missing_timeline.id(), SeqRange::all())
            .is_err());

        generic_reads_fail_closed_on_corrupt_or_missing_event_rows();
        geographic_presence_delete_failure_is_fail_closed();
    }

    fn generic_reads_fail_closed_on_corrupt_or_missing_event_rows() {
        let mut missing_store = new_store();
        let missing_timeline = missing_store.create_timeline("audit-missing").test_ok();
        missing_store
            .conn
            .execute("DROP TABLE events", [])
            .test_ok();
        assert!(missing_store
            .read(missing_timeline.id(), SeqRange::all())
            .is_err());

        let mut corrupt_store = new_store();
        let corrupt_timeline = corrupt_store.create_timeline("audit-corrupt").test_ok();
        let payload = CanonicalBytes::from_vec(b"geo".to_vec());
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("ordinary.event"),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        corrupt_store
            .append_committed(corrupt_timeline.id(), std::slice::from_ref(&event))
            .test_ok();
        corrupt_store
            .conn
            .execute(
                "UPDATE events SET payload = 1 WHERE event_id = ?1",
                params![event.id.to_string()],
            )
            .test_ok();
        assert!(corrupt_store
            .read_bounded(corrupt_timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());

        corrupt_store
            .conn
            .execute(
                "UPDATE events SET seq = -1 WHERE event_id = ?1",
                params![event.id.to_string()],
            )
            .test_ok();
        assert!(corrupt_store
            .read_bounded(corrupt_timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_presence_delete_failure_is_fail_closed() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-marker").test_ok();
        store
            .conn
            .authorizer(Some(|context: rusqlite::hooks::AuthContext<'_>| {
                if matches!(
                    context.action,
                    rusqlite::hooks::AuthAction::Delete {
                        table_name: "geographic_presence"
                    }
                ) {
                    rusqlite::hooks::Authorization::Deny
                } else {
                    rusqlite::hooks::Authorization::Allow
                }
            }))
            .test_ok();
        assert!(store.delete_timeline(timeline.id()).is_err());
        store
            .conn
            .authorizer(
                None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
            )
            .test_ok();
    }

    #[test]
    fn erasure_transaction_finish_reports_commit_and_rollback_failures() {
        let conn = Connection::open_in_memory().test_ok();
        conn.execute_batch("BEGIN IMMEDIATE").test_ok();
        conn.commit_hook(Some(|| true)).test_ok();
        assert_eq!(
            finish_erasure_transaction::<()>(&conn, Ok(())),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        conn.commit_hook::<fn() -> bool>(None).test_ok();

        assert_eq!(
            finish_erasure_transaction::<()>(&conn, Err(ErasureErrorV1::PolicyConflict)),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
    }
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::*;
    use pos_core::ConsentAuthority;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected coverage fixture error: {error:?}"
            )))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn some<T>(value: Option<T>) -> T {
        value.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected coverage value")))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_err<T, E: std::fmt::Debug>(value: Result<T, E>) {
        if value.is_ok() {
            std::panic::resume_unwind(Box::new("expected a fail-closed error"));
        }
        std::mem::drop(value);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_equal<T: PartialEq + std::fmt::Debug>(left: T, right: T) {
        if left != right {
            std::panic::resume_unwind(Box::new(format!(
                "coverage fixture values differed: {left:?} != {right:?}"
            )));
        }
        std::mem::drop((left, right));
    }

    #[test]
    fn read_rejects_missing_intermediate_fork_sequence_at_public_boundary() {
        let mut store = tests::new_store();
        let root = ok(store.create_timeline("coverage-root"));
        let child = ok(store.fork(root.id(), Seq::ZERO, "coverage-child"));
        ok(store.conn.execute(
            "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
            rusqlite::params![child.id().to_string()],
        ));
        expect_err(store.read(child.id(), SeqRange::all()));
    }

    #[test]
    fn malformed_durable_rows_are_rejected_by_instrumented_seams() {
        let consent_id = ok(AdmissionSnapshotId::from_canonical(
            "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
        ));
        for statement in [
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, X'01', zeroblob(32), zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, 'bad', zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, zeroblob(32), 7)",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, -1, zeroblob(32), zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, zeroblob(31), zeroblob(1))",
        ] {
            let mut store = tests::new_store();
            ok(store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON"));
            let tx = ok(store
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate));
            ok(tx.execute(statement, rusqlite::params![consent_id.as_str()]));
            expect_err(SqliteStore::geo_cell_consent_in_transaction(
                &tx,
                &consent_id,
                12,
            ));
            ok(tx.rollback());
        }

        let store = tests::new_store();
        ok(store.conn.execute(
            "INSERT INTO owntracks_enrollment (singleton, state_cbor) VALUES (1, zeroblob(1))",
            [],
        ));
        ok(store.conn.execute(
            "UPDATE owntracks_enrollment SET state_cbor = zeroblob(1) WHERE singleton = 1",
            [],
        ));
        expect_err(store.owntracks_enrollment_status());

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("metadata-wrong-type"));
        ok(store.conn.execute(
            "UPDATE timelines SET head_seq = 1 WHERE id = ?1",
            rusqlite::params![timeline.id().to_string()],
        ));
        ok(store
            .conn
            .execute_batch("ALTER TABLE events RENAME TO events_real"));
        let sql = format!(
            "CREATE VIEW events AS SELECT '{id}' AS timeline_id, 1 AS seq,\
             'event' AS event_id, 'entity' AS entity_id, zeroblob(1) AS event_type,\
             zeroblob(1) AS payload, 1 AS wall_time, NULL AS causation_id,\
             NULL AS correlation_id, 1 AS schema_version, zeroblob(32) AS payload_hash,\
             NULL AS signature, NULL AS signature_owner_id, NULL AS signature_role,
             NULL AS signature_epoch",
            id = timeline.id()
        );
        ok(store.conn.execute_batch(&sql));
        expect_err(store.read_bounded(
            timeline.id(),
            SeqRange::all(),
            EventReadBounds::new(1024, 1024, 1024, 8),
        ));

        let store = tests::new_store();
        expect_err(store.resolve_admission_consent(&consent_id, 12));
    }

    #[test]
    fn bounded_metadata_rejects_null_sizes_from_a_durable_view() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("metadata-null-payload"));
        ok(store.conn.execute(
            "UPDATE timelines SET head_seq = 1 WHERE id = ?1",
            rusqlite::params![timeline.id().to_string()],
        ));
        ok(store
            .conn
            .execute_batch("ALTER TABLE events RENAME TO events_real"));
        let sql = format!(
            "CREATE VIEW events AS SELECT '{id}' AS timeline_id, 1 AS seq,\
             'event' AS event_id, 'entity' AS entity_id, NULL AS event_type,\
             NULL AS payload, 1 AS wall_time, NULL AS causation_id,\
             NULL AS correlation_id, 1 AS schema_version, zeroblob(32) AS payload_hash,\
             NULL AS signature, NULL AS signature_owner_id, NULL AS signature_role,
             NULL AS signature_epoch",
            id = timeline.id()
        );
        ok(store.conn.execute_batch(&sql));
        let result = store.read_bounded(
            timeline.id(),
            SeqRange::all(),
            EventReadBounds::new(1024, 1024, 1024, 8),
        );
        expect_err(result);

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("metadata-null-event-type"));
        ok(store.conn.execute(
            "UPDATE timelines SET head_seq = 1 WHERE id = ?1",
            rusqlite::params![timeline.id().to_string()],
        ));
        ok(store
            .conn
            .execute_batch("ALTER TABLE events RENAME TO events_real"));
        let sql = format!(
            "CREATE VIEW events AS SELECT '{id}' AS timeline_id, 1 AS seq,\
             'event' AS event_id, 'entity' AS entity_id, NULL AS event_type,\
             zeroblob(1) AS payload, 1 AS wall_time, NULL AS causation_id,\
             NULL AS correlation_id, 1 AS schema_version, zeroblob(32) AS payload_hash,\
             NULL AS signature, NULL AS signature_owner_id, NULL AS signature_role,
             NULL AS signature_epoch",
            id = timeline.id()
        );
        ok(store.conn.execute_batch(&sql));
        let result = store.read_bounded(
            timeline.id(),
            SeqRange::all(),
            EventReadBounds::new(1024, 1024, 1024, 8),
        );
        expect_err(result);
    }

    #[test]
    fn bounded_metadata_rejects_a_non_text_payload_type() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("metadata-type-error"));
        ok(store.append(
            timeline.id(),
            &[tests::make_draft(EntityId::new(), b"metadata")],
        ));
        ok(store.conn.create_scalar_function(
            "typeof",
            1,
            rusqlite::functions::FunctionFlags::default(),
            |_context| Ok(1_i64),
        ));
        expect_err(store.read_bounded(
            timeline.id(),
            SeqRange::all(),
            EventReadBounds::new(1024, 1024, 1024, 8),
        ));
    }

    #[test]
    fn bounded_chain_and_logical_segments_fail_closed_on_limits_and_storage_errors() {
        let mut store = tests::new_store();
        let root = ok(store.create_timeline("logical-root"));
        ok(store.append(root.id(), &[tests::make_draft(EntityId::new(), b"root")]));
        let child = ok(store.fork(root.id(), Seq::from_u64(1), "logical-child"));
        let chain = ok(SqliteStore::fork_chain_on(&store.conn, child.id()));
        ok(store.conn.execute_batch("DROP TABLE timelines"));
        expect_err(store.logical_segment_length(&chain, 0, root.id()));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("bounded-chain"));
        let segments = ok(SqliteStore::fork_chain_bounded_on(
            &store.conn,
            timeline.id(),
            4,
            Instant::now(),
            10_000,
        ));
        expect_equal(segments.len(), 1);
        FAIL_BOUNDED_CHAIN_QUERY.with(|flag| flag.set(true));
        let query_error = SqliteStore::fork_chain_bounded_on(
            &store.conn,
            timeline.id(),
            4,
            Instant::now(),
            10_000,
        );
        FAIL_BOUNDED_CHAIN_QUERY.with(|flag| flag.set(false));
        expect_err(query_error);
        BOUNDED_READ_DELAY_PHASE.with(|phase| phase.set(8));
        let timeout =
            SqliteStore::fork_chain_bounded_on(&store.conn, timeline.id(), 4, Instant::now(), 0);
        BOUNDED_READ_DELAY_PHASE.with(|phase| phase.set(0));
        expect_err(timeout);

        let mut store = tests::new_store();
        let root = ok(store.create_timeline("logical-head-error-root"));
        ok(store.append(
            root.id(),
            &[tests::make_draft(EntityId::new(), b"root-event")],
        ));
        let child = ok(store.fork(root.id(), Seq::from_u64(1), "logical-head-error-child"));
        ok(store.conn.execute(
            "UPDATE timelines SET fork_seq = 2 WHERE id = ?1",
            rusqlite::params![child.id().to_string()],
        ));
        expect_err(store.logical_head(child.id()));
        expect_err(store.logical_head_unchecked(child.id()));

        let mut missing_fork = tests::new_store();
        let root = ok(missing_fork.create_timeline("read-missing-fork-root"));
        let child = ok(missing_fork.fork(root.id(), Seq::ZERO, "read-missing-fork-child"));
        ok(missing_fork.conn.execute(
            "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
            rusqlite::params![child.id().to_string()],
        ));
        expect_err(missing_fork.read(child.id(), SeqRange::all()));
    }

    #[test]
    fn consent_append_rejects_a_missing_permit_after_authority_binding() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("sqlite-missing-permit"));
        let authority = ConsentAuthority::new();
        ok(store.bind_consent_authority(authority.append_permit()));
        expect_err(store.append_bounded_visible(timeline.id(), &[], 10, true, None, None));
    }

    #[test]
    fn bounded_append_and_identity_cleanup_cover_success_and_continuation_paths() {
        let mut store = tests::new_store();
        let ordinary = ok(store.create_timeline("sqlite-bounded-ordinary"));
        let draft = tests::make_draft(EntityId::new(), b"bounded");
        let committed = ok(store.append_bounded(ordinary.id(), std::slice::from_ref(&draft), 1));
        assert_eq!(committed.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            ok(store.append_bounded(ordinary.id(), std::slice::from_ref(&draft), 1)),
            None
        );

        let consent = ok(store.create_timeline("sqlite-bounded-consent"));
        let subject = EntityId::new();
        let grant = pos_core::ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "bounded-consent".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 1,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let grant_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            ok(grant.encode()),
        );
        let authority = ConsentAuthority::new();
        let permit = authority.append_permit();
        ok(store.bind_consent_authority(permit));
        let consent_event = ok(store.append_consent_bounded(
            consent.id(),
            std::slice::from_ref(&grant_draft),
            permit,
            1,
        ));
        assert_eq!(some(consent_event).len(), 1);

        let scope = AppendDedupScope::from_keyed_hash([91; 32]);
        let identity = |key: u8| {
            AppendIdentity::new(pos_core::AppendDedupKey::from_keyed_hash([key; 32]), scope)
        };
        for key in [92, 93] {
            ok(store.append_or_duplicate(
                ordinary.id(),
                identity(key),
                WallTime::from_micros(1),
                tests::make_draft(EntityId::new(), &[key]),
            ));
        }
        let first =
            ok(store.remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))));
        assert!(first.more_may_remain);
        assert_eq!(ok(store.pending_append_identity_cleanup()), Some(scope));
        let second =
            ok(store.remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))));
        assert!(!second.more_may_remain);
        assert_eq!(ok(store.pending_append_identity_cleanup()), None);
        assert_eq!(ok(store.remove_append_identities(scope)), 0);

        ok(store.append_or_duplicate(
            ordinary.id(),
            AppendIdentity::new(
                pos_core::AppendDedupKey::from_keyed_hash([94; 32]),
                AppendDedupScope::from_keyed_hash([94; 32]),
            ),
            WallTime::from_micros(0),
            tests::make_draft(EntityId::new(), b"expired"),
        ));
        let purged =
            ok(store.purge_expired_append_identities_bounded(some(std::num::NonZeroUsize::new(1))));
        assert_eq!(purged.removed, 1);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn grant_draft(subject: EntityId, grantee: EntityId, grant_seq: u64) -> EventDraft {
        let grant = pos_core::ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: grantee,
            purpose: "owner-boundary".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 1,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq,
        };
        EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            ok(grant.encode()),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revocation_draft(subject: EntityId, grantee: EntityId) -> EventDraft {
        let revocation = pos_core::ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: grantee,
            grant_seq: 1,
            fence_seq: 1,
        };
        EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            ok(revocation.encode()),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn insert_identity(store: &SqliteStore, key: u8, scope: AppendDedupScope, expires_at: i64) {
        ok(store.conn.execute(
            "INSERT INTO append_identities (dedup_key, scope_key, event_id, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                vec![key; 32],
                scope.as_bytes().as_slice(),
                EventId::new().to_string(),
                expires_at,
            ],
        ));
    }

    #[test]
    fn consent_owner_and_cleanup_success_paths_are_persisted() {
        let subject = EntityId::new();
        let grantee = EntityId::new();
        let permit = ConsentAuthority::new().append_permit();
        let mut owner_store = tests::new_store();
        ok(owner_store.bind_consent_authority(permit));
        let owned = ok(owner_store.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("owner-root", subject),
        ));
        let child = ok(owner_store.fork(owned.id(), Seq::ZERO, "owner-child"));
        assert_eq!(
            some(ok(owner_store.get_timeline(child.id()))).meta.owner,
            Some(subject)
        );
        ok(owner_store.delete_timeline(child.id()));
        ok(owner_store.delete_timeline(owned.id()));

        let mut append_store = tests::new_store();
        ok(append_store.bind_consent_authority(permit));
        let timeline = ok(append_store.create_timeline("owner-append"));
        let scope = AppendDedupScope::from_keyed_hash([121; 32]);
        let revocation_draft = revocation_draft(subject, grantee);
        let committed = ok(append_store.append_consent_revocation_bounded(
            timeline.id(),
            std::slice::from_ref(&revocation_draft),
            permit,
            1,
            scope,
        ));
        assert_eq!(some(committed).len(), 1);
        assert_eq!(
            some(ok(append_store.get_timeline(timeline.id())))
                .meta
                .owner,
            Some(subject)
        );
        assert_eq!(
            ok(append_store.pending_append_identity_cleanup()),
            Some(scope)
        );

        let mut existing_owner = tests::new_store();
        ok(existing_owner.bind_consent_authority(permit));
        let existing_timeline = ok(existing_owner.create_timeline("existing-owner"));
        ok(existing_owner.append_consent_bounded(
            existing_timeline.id(),
            std::slice::from_ref(&grant_draft(subject, grantee, 1)),
            permit,
            2,
        ));
        ok(existing_owner.append_consent_bounded(
            existing_timeline.id(),
            std::slice::from_ref(&grant_draft(subject, grantee, 2)),
            permit,
            2,
        ));
    }

    #[test]
    fn consent_owner_storage_failures_fail_closed() {
        let subject = EntityId::new();
        let permit = ConsentAuthority::new().append_permit();
        let grant = grant_draft(subject, EntityId::new(), 1);

        let mut owner_query_error = tests::new_store();
        let owner_query_timeline = ok(owner_query_error.create_timeline("owner-query-error"));
        ok(owner_query_error
            .conn
            .execute_batch("DROP TABLE timeline_owners"));
        expect_err(owner_query_error.get_timeline(owner_query_timeline.id()));

        let mut owner_tx_error = tests::new_store();
        ok(owner_tx_error.bind_consent_authority(permit));
        let owner_tx_timeline = ok(owner_tx_error.create_timeline("owner-tx-error"));
        ok(owner_tx_error
            .conn
            .execute_batch("DROP TABLE timeline_owners"));
        expect_err(owner_tx_error.append_consent_bounded(
            owner_tx_timeline.id(),
            std::slice::from_ref(&grant),
            permit,
            1,
        ));

        let mut owner_write_error = tests::new_store();
        ok(owner_write_error.bind_consent_authority(permit));
        let owner_write_timeline = ok(owner_write_error.create_timeline("owner-write-error"));
        ok(owner_write_error.conn.execute_batch(
            "CREATE TRIGGER deny_timeline_owner BEFORE INSERT ON timeline_owners
             BEGIN SELECT RAISE(ABORT, 'owner write denied'); END",
        ));
        expect_err(owner_write_error.append_consent_bounded(
            owner_write_timeline.id(),
            std::slice::from_ref(&grant),
            permit,
            1,
        ));
    }

    #[test]
    fn owner_lifecycle_storage_failures_fail_closed() {
        let subject = EntityId::new();
        let mut fork_query_error = tests::new_store();
        let parent = ok(fork_query_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("fork-query", subject),
        ));
        ok(fork_query_error
            .conn
            .execute_batch("DROP TABLE timeline_owners"));
        expect_err(fork_query_error.fork(parent.id(), Seq::ZERO, "child"));

        let mut fork_write_error = tests::new_store();
        let parent = ok(fork_write_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("fork-write", subject),
        ));
        ok(fork_write_error.conn.execute_batch(
            "CREATE TRIGGER deny_fork_owner BEFORE INSERT ON timeline_owners
             BEGIN SELECT RAISE(ABORT, 'fork owner denied'); END",
        ));
        expect_err(fork_write_error.fork(parent.id(), Seq::ZERO, "child"));

        let mut list_error = tests::new_store();
        ok(list_error.create_timeline("list-owner-error"));
        ok(list_error.conn.execute_batch("DROP TABLE timeline_owners"));
        expect_err(list_error.list_timelines());

        let mut create_write_error = tests::new_store();
        ok(create_write_error.conn.execute_batch(
            "CREATE TRIGGER deny_create_owner BEFORE INSERT ON timeline_owners
             BEGIN SELECT RAISE(ABORT, 'create owner denied'); END",
        ));
        expect_err(create_write_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("create-owner", subject),
        ));

        let mut delete_write_error = tests::new_store();
        let owned = ok(delete_write_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("delete-owner", subject),
        ));
        ok(delete_write_error.conn.execute_batch(
            "CREATE TRIGGER deny_delete_owner BEFORE DELETE ON timeline_owners
             BEGIN SELECT RAISE(ABORT, 'delete owner denied'); END",
        ));
        expect_err(delete_write_error.delete_timeline(owned.id()));
    }

    #[test]
    fn owned_timeline_transaction_boundaries_are_fail_closed() {
        let subject = EntityId::new();
        let mut nested = tests::new_store();
        ok(nested.conn.execute_batch("BEGIN IMMEDIATE"));
        let nested_timeline = ok(nested.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("nested-owner", subject),
        ));
        assert_eq!(
            some(ok(nested.get_timeline(nested_timeline.id())))
                .meta
                .owner,
            Some(subject)
        );
        ok(nested.conn.execute_batch("ROLLBACK"));

        let mut commit_error = tests::new_store();
        ok(commit_error.conn.commit_hook(Some(|| true)));
        expect_err(commit_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("commit-owner", subject),
        ));
        ok(commit_error.conn.commit_hook::<fn() -> bool>(None));
    }

    #[test]
    fn cleanup_transaction_boundaries_fail_closed() {
        let scope = AppendDedupScope::from_keyed_hash([124; 32]);
        let mut remove_begin = tests::new_store();
        ok(remove_begin.conn.execute_batch("BEGIN IMMEDIATE"));
        expect_err(remove_begin.remove_append_identities(scope));
        ok(remove_begin.conn.execute_batch("ROLLBACK"));

        let mut bounded_begin = tests::new_store();
        ok(bounded_begin.conn.execute_batch("BEGIN IMMEDIATE"));
        expect_err(
            bounded_begin
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );
        ok(bounded_begin.conn.execute_batch("ROLLBACK"));

        let mut remove_pending_error = tests::new_store();
        ok(remove_pending_error
            .conn
            .execute_batch("DROP TABLE pending_append_identity_cleanup"));
        expect_err(remove_pending_error.remove_append_identities(scope));

        let mut remove_commit_error = tests::new_store();
        ok(remove_commit_error.conn.commit_hook(Some(|| true)));
        expect_err(remove_commit_error.remove_append_identities(scope));
        ok(remove_commit_error.conn.commit_hook::<fn() -> bool>(None));

        let mut bounded_commit_error = tests::new_store();
        ok(bounded_commit_error.conn.commit_hook(Some(|| true)));
        expect_err(
            bounded_commit_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );
        ok(bounded_commit_error.conn.commit_hook::<fn() -> bool>(None));
    }

    #[test]
    fn bounded_cleanup_query_and_write_failures_fail_closed() {
        let scope = AppendDedupScope::from_keyed_hash([125; 32]);
        let mut malformed = tests::new_store();
        ok(malformed
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = ON"));
        ok(malformed.conn.execute(
            "INSERT INTO append_identities (dedup_key, scope_key, event_id, expires_at)
             VALUES (1, ?1, ?2, 1)",
            rusqlite::params![scope.as_bytes().as_slice(), EventId::new().to_string()],
        ));
        ok(malformed
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = OFF"));
        expect_err(
            malformed.remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );

        let mut delete_error = tests::new_store();
        insert_identity(&delete_error, 126, scope, 1);
        ok(delete_error.conn.execute_batch(
            "CREATE TRIGGER deny_identity_delete BEFORE DELETE ON append_identities
             BEGIN SELECT RAISE(ABORT, 'identity delete denied'); END",
        ));
        expect_err(
            delete_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );

        let mut marker_insert_error = tests::new_store();
        insert_identity(&marker_insert_error, 127, scope, 1);
        insert_identity(&marker_insert_error, 128, scope, 1);
        ok(marker_insert_error.conn.execute_batch(
            "CREATE TRIGGER deny_cleanup_insert BEFORE INSERT ON pending_append_identity_cleanup
             BEGIN SELECT RAISE(ABORT, 'cleanup insert denied'); END",
        ));
        expect_err(
            marker_insert_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );

        let mut marker_delete_error = tests::new_store();
        ok(marker_delete_error.conn.execute(
            "INSERT INTO pending_append_identity_cleanup (scope_key) VALUES (?1)",
            rusqlite::params![scope.as_bytes().as_slice()],
        ));
        ok(marker_delete_error.conn.execute_batch(
            "CREATE TRIGGER deny_cleanup_delete BEFORE DELETE ON pending_append_identity_cleanup
             BEGIN SELECT RAISE(ABORT, 'cleanup delete denied'); END",
        ));
        expect_err(
            marker_delete_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );
    }

    #[test]
    fn cleanup_storage_failures_fail_closed() {
        let subject = EntityId::new();
        let permit = ConsentAuthority::new().append_permit();
        let revocation = revocation_draft(subject, EntityId::new());
        let mut cleanup_write_error = tests::new_store();
        ok(cleanup_write_error.bind_consent_authority(permit));
        let cleanup_timeline = ok(cleanup_write_error.create_timeline("cleanup-write-error"));
        ok(cleanup_write_error
            .conn
            .execute_batch("DROP TABLE pending_append_identity_cleanup"));
        expect_err(cleanup_write_error.append_consent_revocation_bounded(
            cleanup_timeline.id(),
            std::slice::from_ref(&revocation),
            permit,
            1,
            AppendDedupScope::from_keyed_hash([122; 32]),
        ));

        let scope = AppendDedupScope::from_keyed_hash([123; 32]);
        let mut remove_error = tests::new_store();
        ok(remove_error
            .conn
            .execute_batch("DROP TABLE append_identities"));
        expect_err(remove_error.remove_append_identities(scope));

        let mut bounded_remove_error = tests::new_store();
        ok(bounded_remove_error
            .conn
            .execute_batch("DROP TABLE append_identities"));
        expect_err(
            bounded_remove_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );

        let mut pending_error = tests::new_store();
        ok(pending_error
            .conn
            .execute_batch("DROP TABLE pending_append_identity_cleanup"));
        expect_err(pending_error.pending_append_identity_cleanup());

        let scope = AppendDedupScope::from_keyed_hash([129; 32]);
        let mut query_error = tests::new_store();
        insert_identity(&query_error, 130, scope, 1);
        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reads_for_authorizer = std::sync::Arc::clone(&reads);
        ok(query_error
            .conn
            .authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
                if matches!(
                    context.action,
                    rusqlite::hooks::AuthAction::Read {
                        table_name: "append_identities",
                        column_name: "scope_key"
                    }
                ) && reads_for_authorizer.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0
                {
                    rusqlite::hooks::Authorization::Deny
                } else {
                    rusqlite::hooks::Authorization::Allow
                }
            })));
        expect_err(
            query_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );
        ok(query_error.conn.authorizer(
            None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
        ));

        let scope = AppendDedupScope::from_keyed_hash([131; 32]);
        let mut view_error = tests::new_store();
        insert_identity(&view_error, 132, scope, 1);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_function = std::sync::Arc::clone(&calls);
        ok(view_error.conn.create_scalar_function(
            "scope_for_test",
            0,
            rusqlite::functions::FunctionFlags::default(),
            move |_context| {
                if calls_for_function.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                    Ok(vec![0_u8; 32])
                } else {
                    Err(rusqlite::Error::UserFunctionError(Box::new(
                        std::io::Error::other("scope query denied"),
                    )))
                }
            },
        ));
        ok(view_error
            .conn
            .execute_batch("ALTER TABLE append_identities RENAME TO append_identities_real"));
        ok(view_error.conn.execute_batch(
            "CREATE VIEW append_identities AS
             SELECT dedup_key, scope_for_test() AS scope_key, event_id, expires_at
             FROM append_identities_real",
        ));
        expect_err(
            view_error
                .remove_append_identities_bounded(scope, some(std::num::NonZeroUsize::new(1))),
        );
    }

    #[test]
    fn consent_owner_and_timeline_transaction_authorizers_fail_closed() {
        let subject = EntityId::new();
        let permit = ConsentAuthority::new().append_permit();

        let mut owned = tests::new_store();
        let timeline = ok(owned.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("pre-owned-consent", subject),
        ));
        ok(owned.bind_consent_authority(permit));
        ok(owned.append_consent_bounded(
            timeline.id(),
            std::slice::from_ref(&grant_draft(subject, EntityId::new(), 1)),
            permit,
            1,
        ));

        let mut begin_error = tests::new_store();
        ok(begin_error
            .conn
            .authorizer(Some(|context: rusqlite::hooks::AuthContext<'_>| {
                if matches!(
                    context.action,
                    rusqlite::hooks::AuthAction::Transaction {
                        operation: rusqlite::hooks::TransactionOperation::Begin
                    }
                ) {
                    rusqlite::hooks::Authorization::Deny
                } else {
                    rusqlite::hooks::Authorization::Allow
                }
            })));
        expect_err(begin_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("begin-authorizer", subject),
        ));
        ok(begin_error.conn.authorizer(
            None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
        ));

        let mut nested_write_error = tests::new_store();
        ok(nested_write_error.conn.execute_batch("BEGIN IMMEDIATE"));
        ok(nested_write_error.conn.authorizer(Some(
            |context: rusqlite::hooks::AuthContext<'_>| {
                if matches!(
                    context.action,
                    rusqlite::hooks::AuthAction::Insert {
                        table_name: "timeline_owners"
                    }
                ) {
                    rusqlite::hooks::Authorization::Deny
                } else {
                    rusqlite::hooks::Authorization::Allow
                }
            },
        )));
        expect_err(nested_write_error.create_timeline_with_meta(
            pos_core::timeline::TimelineMeta::root_owned("nested-authorizer", subject),
        ));
        ok(nested_write_error.conn.authorizer(
            None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
        ));
        ok(nested_write_error.conn.execute_batch("ROLLBACK"));
    }

    #[test]
    fn consent_resolver_rejects_durable_type_and_revision_errors() {
        let id = ok(AdmissionSnapshotId::from_canonical(
            "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
        ));
        let malformed_type = tests::new_store();
        ok(malformed_type
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = ON"));
        ok(malformed_type.conn.execute(
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
            VALUES (?1, X'01', zeroblob(32), zeroblob(1))",
            rusqlite::params![id.as_str()],
        ));
        expect_err(malformed_type.resolve_admission_consent(&id, 12));

        let id = ok(AdmissionSnapshotId::from_canonical(
            "01ARZ3NDEKTSV4RRFFQ69G5FB0",
        ));
        let malformed_revision = tests::new_store();
        ok(malformed_revision
            .conn
            .execute_batch("PRAGMA ignore_check_constraints = ON"));
        ok(malformed_revision.conn.execute(
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, -1, zeroblob(32), zeroblob(1))",
            rusqlite::params![id.as_str()],
        ));
        expect_err(malformed_revision.resolve_admission_consent(&id, 12));
    }

    #[test]
    fn deleting_an_enrolled_timeline_revokes_enrollment_state() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("delete-enrolled"));
        let request = OwnTracksEnrollmentRequestV1::new(
            timeline.id(),
            EntityId::new(),
            pos_core::geo_admission::GeoLocationAdmissionFenceV1::new(
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
            ),
            [42; 32],
        );
        ok(store.pair_owntracks_enrollment(request));
        ok(store.delete_timeline(timeline.id()));
        std::mem::drop(store.owntracks_enrollment_status());
    }

    #[test]
    fn fork_hashing_fails_closed_when_parent_event_identity_is_corrupt() {
        let mut store = tests::new_store();
        let parent = ok(store.create_timeline("corrupt-fork-parent"));
        let event = ok(store.append(
            parent.id(),
            &[tests::make_draft(EntityId::new(), b"fork-event")],
        ));
        ok(store.conn.execute(
            "UPDATE events SET event_id = 'bad' WHERE event_id = ?1",
            rusqlite::params![event[0].id.to_string()],
        ));
        expect_err(
            store.create_timeline_with_meta(pos_core::timeline::TimelineMeta::forked_from(
                parent.id(),
                Seq::from_u64(1),
                "corrupt-fork-child",
            )),
        );
    }

    #[test]
    fn enrollment_paths_fail_closed_on_transaction_state_and_commit_errors() {
        let request_for = |timeline: TimelineId| {
            OwnTracksEnrollmentRequestV1::new(
                timeline,
                EntityId::new(),
                pos_core::geo_admission::GeoLocationAdmissionFenceV1::new(
                    7,
                    ([1; 32], 8, [2; 32]),
                    (1, false, 9),
                ),
                [42; 32],
            )
        };

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("enrollment-begin"));
        ok(store.conn.execute_batch("BEGIN IMMEDIATE"));
        expect_err(store.pair_owntracks_enrollment(request_for(timeline.id())));
        ok(store.conn.execute_batch("ROLLBACK"));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("enrollment-query"));
        ok(store.conn.execute_batch("DROP TABLE owntracks_enrollment"));
        expect_err(store.pair_owntracks_enrollment(request_for(timeline.id())));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("enrollment-write"));
        ok(store.conn.execute_batch(
            "CREATE TRIGGER deny_enrollment_write BEFORE INSERT ON owntracks_enrollment \
             BEGIN SELECT RAISE(ABORT, 'enrollment write denied'); END",
        ));
        expect_err(store.pair_owntracks_enrollment(request_for(timeline.id())));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("enrollment-commit"));
        ok(store.conn.commit_hook(Some(|| true)));
        expect_err(store.pair_owntracks_enrollment(request_for(timeline.id())));
        ok(store.conn.commit_hook::<fn() -> bool>(None));

        let mut store = tests::new_store();
        let _timeline = ok(store.create_timeline("enrollment-status"));
        ok(store.conn.execute(
            "UPDATE owntracks_enrollment SET state_cbor = zeroblob(1) WHERE singleton = 1",
            [],
        ));
        std::mem::drop(store.owntracks_enrollment_status());
        ok(store.conn.execute_batch("DROP TABLE owntracks_enrollment"));
        expect_err(store.owntracks_enrollment_status());

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("enrollment-transition"));
        ok(store.pair_owntracks_enrollment(request_for(timeline.id())));
        ok(store.conn.commit_hook(Some(|| true)));
        expect_err(store.revoke_owntracks_enrollment());
        ok(store.conn.commit_hook::<fn() -> bool>(None));
    }

    #[test]
    fn owntracks_ingress_preparation_fails_closed_at_each_transaction_boundary() {
        let input = OwnTracksIngressInputV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            CanonicalBytes::from_vec(vec![5]),
        );

        let mut store = tests::new_store();
        ok(store.conn.execute_batch("BEGIN IMMEDIATE"));
        expect_err(store.prepare_owntracks_ingress(input.clone()));
        ok(store.conn.execute_batch("ROLLBACK"));

        let mut store = tests::new_store();
        ok(store.conn.execute_batch("DROP TABLE owntracks_enrollment"));
        expect_err(store.prepare_owntracks_ingress(input.clone()));

        let mut store = tests::new_store();
        ok(store.conn.commit_hook(Some(|| true)));
        expect_err(store.prepare_owntracks_ingress(input));
        ok(store.conn.commit_hook::<fn() -> bool>(None));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("ingress-commit"));
        let request = OwnTracksEnrollmentRequestV1::new(
            timeline.id(),
            EntityId::new(),
            pos_core::geo_admission::GeoLocationAdmissionFenceV1::new(
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
            ),
            [42; 32],
        );
        ok(store.pair_owntracks_enrollment(request));
        let active_input = OwnTracksIngressInputV1::new(
            [42; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            CanonicalBytes::from_vec(vec![5]),
        );
        ok(store.conn.commit_hook(Some(|| true)));
        let active_result = store.prepare_owntracks_ingress(active_input);
        assert!(
            active_result.is_ok(),
            "active ingress result: {active_result:?}"
        );
        ok(store.conn.commit_hook::<fn() -> bool>(None));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("ingress-locked-transition"));
        let request = OwnTracksEnrollmentRequestV1::new(
            timeline.id(),
            EntityId::new(),
            pos_core::geo_admission::GeoLocationAdmissionFenceV1::new(
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
            ),
            [42; 32],
        );
        ok(store.pair_owntracks_enrollment(request));
        ok(store.conn.execute_batch("BEGIN IMMEDIATE"));
        expect_err(store.revoke_owntracks_enrollment());
        ok(store.conn.execute_batch("ROLLBACK"));
    }

    #[test]
    fn geographic_append_rejects_malformed_timeline_head_rows() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("geo-head-row"));
        let tx = ok(store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate));
        ok(tx.execute(
            "UPDATE timelines SET head_seq = zeroblob(1) WHERE id = ?1",
            rusqlite::params![timeline.id().to_string()],
        ));
        expect_err(SqliteStore::append_geo_cell_in_transaction(
            &tx,
            store.hasher.as_ref(),
            timeline.id(),
            EntityId::new(),
            EventId::new(),
            CanonicalBytes::from_vec(vec![6]),
            WallTime::from_micros(1),
        ));
        ok(tx.rollback());
    }

    #[test]
    fn deleting_a_timeline_fails_closed_when_enrollment_storage_is_unavailable() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("delete-missing-enrollment"));
        ok(store.conn.execute_batch("DROP TABLE owntracks_enrollment"));
        expect_err(store.delete_timeline(timeline.id()));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("delete-without-enrollment"));
        ok(store.delete_timeline(timeline.id()));
    }

    #[test]
    fn geographic_admin_and_replay_rows_fail_closed_on_durable_errors() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("geo-admin-commit"));
        let entity = EntityId::new();
        let (consent, fence, request) = tests::geo_cell_request(timeline.id(), entity);
        ok(store.conn.commit_hook(Some(|| true)));
        expect_err(store.set_geo_cell_admission_consent_record(consent));
        ok(store.conn.commit_hook::<fn() -> bool>(None));
        ok(store.set_geo_cell_admission_consent_record(
            tests::geo_cell_request(timeline.id(), entity).0,
        ));
        ok(store.conn.commit_hook(Some(|| true)));
        expect_err(store.set_geo_cell_admission_fence(timeline.id(), entity, fence));
        ok(store.conn.commit_hook::<fn() -> bool>(None));
        std::mem::drop(
            store.resolve_admission_consent(request.fence().draft().consent_record_id(), 12),
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_cell_dedup_verification_rejects_tampered_sidecars() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("geo-cell-consent-tamper"));
        let entity = EntityId::new();
        let (consent, fence, request) = tests::geo_cell_request(timeline.id(), entity);
        ok(store.set_geo_cell_admission_consent_record(consent));
        ok(store.set_geo_cell_admission_fence(timeline.id(), entity, fence));
        ok(store.conn.execute_batch(
            "CREATE TRIGGER tamper_geo_cell_consent AFTER INSERT ON geographic_cell_admission_dedup
             BEGIN
                 UPDATE geographic_cell_admission_consent_records
                 SET consent_record_hash = zeroblob(32);
             END",
        ));
        let outcome = store.admit(request);
        assert!(
            matches!(outcome, Err(CoreError::GeographicAdmissionValidationFailed)),
            "consent tamper outcome: {outcome:?}"
        );

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("geo-cell-link-tamper"));
        let entity = EntityId::new();
        let (consent, fence, request) = tests::geo_cell_request(timeline.id(), entity);
        ok(store.set_geo_cell_admission_consent_record(consent));
        ok(store.set_geo_cell_admission_fence(timeline.id(), entity, fence));
        ok(store.conn.execute_batch(
            "CREATE TRIGGER tamper_geo_cell_link AFTER INSERT ON geographic_cell_admission_dedup
             BEGIN
                 UPDATE geographic_cell_admission_links
                 SET snapshot_hash = zeroblob(32);
             END",
        ));
        let outcome = store.admit(request);
        assert!(
            matches!(outcome, Ok(GeographicAdmissionOutcome::OutcomeUnknown)),
            "link tamper outcome: {outcome:?}"
        );

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("geo-cell-consent-linkage-tamper"));
        let entity = EntityId::new();
        let (consent, fence, request) = tests::geo_cell_request(timeline.id(), entity);
        ok(store.set_geo_cell_admission_consent_record(consent));
        ok(store.set_geo_cell_admission_fence(timeline.id(), entity, fence));
        ok(store.conn.execute_batch(
            "CREATE TRIGGER tamper_geo_cell_consent_linkage AFTER INSERT ON geographic_cell_admission_dedup
             BEGIN
                 UPDATE geographic_cell_admission_consent_records
                 SET consent_record_cbor = X'74616d70657265642d636f6e73656e74',
                     consent_record_hash = X'41cde6d9f404d9e85ae9d3b323464cb9afe96288b380e05d4a48f0590f8caf4a';
             END",
        ));
        let outcome = store.admit(request);
        assert!(
            matches!(outcome, Ok(GeographicAdmissionOutcome::OutcomeUnknown)),
            "consent linkage tamper outcome: {outcome:?}"
        );
    }

    #[test]
    fn event_lookup_rejects_malformed_durable_owner_and_query_shapes() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("event-query-shape"));
        ok(store.append(
            timeline.id(),
            &[tests::make_draft(EntityId::new(), b"event")],
        ));
        ok(store
            .conn
            .execute_batch("ALTER TABLE events RENAME TO events_real"));
        let sql = format!(
            "CREATE VIEW events AS SELECT '{id}' AS timeline_id, 'test.event' AS event_type",
            id = timeline.id()
        );
        ok(store.conn.execute_batch(&sql));
        expect_err(store.read_event_by_id(timeline.id(), EventId::new()));

        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("event-owner-shape"));
        let event = ok(store.append(
            timeline.id(),
            &[tests::make_draft(EntityId::new(), b"event")],
        ));
        ok(store.conn.execute(
            "UPDATE events SET timeline_id = 'not-a-timeline' WHERE event_id = ?1",
            rusqlite::params![event[0].id.to_string()],
        ));
        expect_err(store.read_event_by_id(timeline.id(), event[0].id));
    }

    #[test]
    fn public_consent_resolution_rejects_malformed_durable_rows() {
        let consent_id = ok(AdmissionSnapshotId::from_canonical(
            "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
        ));
        for statement in [
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 'bad', zeroblob(32), zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, -1, zeroblob(32), zeroblob(1))",
            "INSERT INTO geographic_cell_admission_consent_records
             (consent_record_id, consent_revision, consent_record_hash, consent_record_cbor)
             VALUES (?1, 12, zeroblob(31), zeroblob(1))",
        ] {
            let store = tests::new_store();
            ok(store
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON"));
            ok(store
                .conn
                .execute(statement, rusqlite::params![consent_id.as_str()]));
            expect_err(store.resolve_admission_consent(&consent_id, 12));
        }
    }

    #[test]
    fn retained_identity_query_and_logical_head_overflow_fail_closed() {
        let mut store = tests::new_store();
        let tx = ok(store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate));
        ok(tx.execute_batch("DROP TABLE events"));
        expect_err(SqliteStore::retained_event_matches_draft(
            &tx,
            "missing-event",
            TimelineId::new(),
            &tests::make_draft(EntityId::new(), b"payload"),
        ));
        ok(tx.rollback());

        assert!(matches!(
            SqliteStore::add_logical_segment(u64::MAX, 1),
            Err(CoreError::Storage(message)) if message == "logical Timeline head overflow"
        ));
    }

    #[test]
    fn deleting_an_enrollment_target_revokes_the_durable_capability() {
        let mut store = tests::new_store();
        let timeline = ok(store.create_timeline("enrollment-delete"));
        let request = OwnTracksEnrollmentRequestV1::new(
            timeline.id(),
            EntityId::new(),
            pos_core::geo_admission::GeoLocationAdmissionFenceV1::new(
                1,
                ([1; 32], 1, [2; 32]),
                (1, false, 1),
            ),
            [3; 32],
        );
        ok(store.pair_owntracks_enrollment(request));
        ok(store.delete_timeline(timeline.id()));
        assert_eq!(
            ok(store.owntracks_enrollment_status()).status(),
            OwnTracksEnrollmentStatusV1::Revoked
        );
    }
}

#[cfg(all(test, feature = "sqlite"))]
pub(super) mod key_registry_coverage {
    use super::*;
    use pos_core::{
        CanonicalBytes, EntityId, Event, EventDraft, EventId, EventStore, KeyRegistrationV1,
        PublicKey,
    };

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn registered_state(
    ) -> Result<(KeyRegistryStateV1, KeyIdentityV1, Hash), Box<dyn std::error::Error>> {
        let identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let material_digest = Hash::from_bytes([3; 32]);
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            identity,
            material_digest,
            Some(PublicKey::from_bytes([4; 32])),
        ))?;
        Ok((registry, identity, material_digest))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seed_event(store: &mut SqliteStore, timeline: TimelineId) -> Result<Event, CoreError> {
        store
            .append(
                timeline,
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("registry.coverage"),
                    CanonicalBytes::from_static(b"seed"),
                )],
            )?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::Storage("seed append returned no event".to_owned()))
    }

    #[cfg(test)]
    mod sqlite_key_registry_failure_paths {
        use super::{
            CoreError, Event, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1,
            KeyRegistryStateV1, Seq, SqliteStore, TimelineId, FAIL_BEGIN_IMMEDIATE,
        };

        #[cfg_attr(coverage_nightly, coverage(off))]
        pub(super) fn run(
            registry: &KeyRegistryStateV1,
            identity: KeyIdentityV1,
            material_digest: Hash,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut missing_registry = SqliteStore::open_in_memory()?;
            let missing_timeline = missing_registry.create_timeline("missing-registry")?;
            let mut missing_registry_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
                Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
            };
            assert!(matches!(
                missing_registry.append_signed_authorized(
                    missing_timeline.id(),
                    registry,
                    &mut missing_registry_callback,
                ),
                Err(CoreError::Storage(_))
            ));
            assert!(matches!(
                missing_registry.begin_key_registry_destruction(KeyDestructionRequestV1::new(
                    identity,
                    material_digest,
                    Hash::from_bytes([2; 32]),
                )),
                Err(CoreError::Storage(_))
            ));
            let missing_completion =
                KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([2; 32]));
            assert!(matches!(
                missing_registry.complete_key_registry_destruction(
                    missing_completion,
                    pos_core::deletion_receipt(&missing_completion),
                ),
                Err(CoreError::Storage(_))
            ));

            let mut begin_failure = SqliteStore::open_in_memory()?;
            FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
            let mut begin_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
                Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
            };
            assert!(matches!(
                begin_failure.append_signed_authorized(
                    TimelineId::new(),
                    registry,
                    &mut begin_callback,
                ),
                Err(CoreError::Storage(_))
            ));
            assert!(matches!(
                begin_failure.begin_key_registry_destruction(KeyDestructionRequestV1::new(
                    identity,
                    material_digest,
                    Hash::from_bytes([2; 32]),
                )),
                Err(CoreError::Storage(_))
            ));
            FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));

            let malformed = SqliteStore::open_in_memory()?;
            malformed.conn.execute(
                "INSERT INTO key_registry (singleton, state_cbor) VALUES (1, X'01')",
                [],
            )?;
            assert!(matches!(
                malformed.load_key_registry(),
                Err(CoreError::Serialization(_))
            ));
            Ok(())
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_key_registry_public_paths_are_exercised() -> Result<(), Box<dyn std::error::Error>> {
        let (registry, identity, material_digest) = registered_state()?;
        let mut store = SqliteStore::open_in_memory()?;
        assert!(store.load_key_registry()?.is_none());
        store.save_key_registry(&registry)?;
        assert_eq!(store.load_key_registry()?, Some(registry.clone()));

        let mut existing_timeline_store = SqliteStore::open_in_memory()?;
        let existing_timeline = existing_timeline_store.create_timeline("existing-ledger")?;
        let initialized_timeline = existing_timeline_store
            .initialize_timeline_with_key_registry("existing-ledger", &KeyRegistryStateV1::new())?;
        assert_eq!(initialized_timeline.id(), existing_timeline.id());

        let timeline = store.create_timeline("registry-coverage")?;
        let mut event = seed_event(&mut store, timeline.id())?;
        event.id = EventId::new();
        let mut callback = move |_registry: &KeyRegistryStateV1, seq: Seq| {
            event.seq = seq;
            Ok::<Event, CoreError>(event.clone())
        };
        store.append_signed_authorized(timeline.id(), &registry, &mut callback)?;

        let mut mismatch_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(matches!(
            store.append_signed_authorized(
                timeline.id(),
                &KeyRegistryStateV1::new(),
                &mut mismatch_callback,
            ),
            Err(CoreError::Storage(_))
        ));

        let mut missing_callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(matches!(
            store.append_signed_authorized(TimelineId::new(), &registry, &mut missing_callback,),
            Err(CoreError::TimelineNotFound(_))
        ));

        let mut callback_failure = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback failed".to_owned()))
        };
        assert!(matches!(
            store.append_signed_authorized(timeline.id(), &registry, &mut callback_failure,),
            Err(CoreError::Storage(_))
        ));

        let invalid_request = KeyDestructionRequestV1::new(
            identity,
            Hash::from_bytes([9; 32]),
            Hash::from_bytes([2; 32]),
        );
        assert!(matches!(
            store.begin_key_registry_destruction(invalid_request),
            Err(CoreError::Storage(_))
        ));

        let valid_request =
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([2; 32]));
        store.begin_key_registry_destruction(valid_request)?;
        let (_, destroyed) = store.complete_key_registry_destruction(
            valid_request,
            pos_core::deletion_receipt(&valid_request),
        )?;
        assert!(destroyed.key_record(identity).is_some());
        sqlite_key_registry_failure_paths::run(&registry, identity, material_digest)?;
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn sqlite_key_registry_transaction_boundaries_fail_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (registry, identity, material_digest) = registered_state()?;
        let request =
            KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([2; 32]));

        let mut save_failure = SqliteStore::open_in_memory()?;
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
        let save_result = save_failure.save_key_registry(&registry);
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));
        assert!(matches!(save_result, Err(CoreError::Storage(_))));

        let mut initialization_failure = SqliteStore::open_in_memory()?;
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
        let initialization_result = initialization_failure
            .initialize_timeline_with_key_registry("transaction-failure", &registry);
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));
        assert!(matches!(initialization_result, Err(CoreError::Storage(_))));

        let mut completion_begin_failure = SqliteStore::open_in_memory()?;
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
        let completion_result = completion_begin_failure
            .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request));
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));
        assert!(matches!(completion_result, Err(CoreError::Storage(_))));

        let mut malformed = SqliteStore::open_in_memory()?;
        malformed.conn.execute(
            "INSERT INTO key_registry (singleton, state_cbor) VALUES (1, X'01')",
            [],
        )?;
        let mut callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(matches!(
            malformed.append_signed_authorized(TimelineId::new(), &registry, &mut callback),
            Err(CoreError::Serialization(_))
        ));
        assert!(matches!(
            malformed.begin_key_registry_destruction(request),
            Err(CoreError::Serialization(_))
        ));
        assert!(matches!(
            malformed
                .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request),),
            Err(CoreError::Serialization(_))
        ));

        let mut timeline_failure = SqliteStore::open_in_memory()?;
        timeline_failure.save_key_registry(&registry)?;
        timeline_failure
            .conn
            .execute_batch("DROP TABLE timelines")?;
        let mut callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(matches!(
            timeline_failure.append_signed_authorized(TimelineId::new(), &registry, &mut callback),
            Err(CoreError::Storage(_))
        ));

        let mut invalid_completion = SqliteStore::open_in_memory()?;
        invalid_completion.save_key_registry(&registry)?;
        assert!(matches!(
            invalid_completion
                .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request),),
            Err(CoreError::Storage(_))
        ));

        let mut save_transaction_failure = SqliteStore::open_in_memory()?;
        save_transaction_failure.save_key_registry(&registry)?;
        save_transaction_failure.begin_key_registry_destruction(request)?;
        save_transaction_failure.conn.execute_batch(
            "CREATE TRIGGER deny_key_registry_update
             BEFORE UPDATE ON key_registry
             BEGIN SELECT RAISE(ABORT, 'registry update denied'); END",
        )?;
        assert!(matches!(
            save_transaction_failure
                .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request),),
            Err(CoreError::Storage(_))
        ));
        Ok(())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[cfg(test)]
    fn fixture<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected SQLite coverage fixture error: {error:?}"
            )))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn sqlite_error_mapping_boundaries_are_exercised() {
        FAIL_BUSY_TIMEOUT.with(|flag| flag.set(true));
        let busy_timeout = SqliteStore::open_in_memory();
        FAIL_BUSY_TIMEOUT.with(|flag| flag.set(false));
        assert!(matches!(busy_timeout, Err(CoreError::Storage(_))));

        FAIL_SIGNATURE_SCHEMA_PREPARE.with(|flag| flag.set(true));
        let prepare = SqliteStore::open_in_memory();
        FAIL_SIGNATURE_SCHEMA_PREPARE.with(|flag| flag.set(false));
        assert!(matches!(prepare, Err(CoreError::Storage(_))));

        FAIL_SIGNATURE_SCHEMA_QUERY.with(|flag| flag.set(true));
        let query = SqliteStore::open_in_memory();
        FAIL_SIGNATURE_SCHEMA_QUERY.with(|flag| flag.set(false));
        assert!(matches!(query, Err(CoreError::Storage(_))));

        FAIL_SIGNATURE_SCHEMA_ROW.with(|flag| flag.set(true));
        let row = SqliteStore::open_in_memory();
        FAIL_SIGNATURE_SCHEMA_ROW.with(|flag| flag.set(false));
        assert!(matches!(row, Err(CoreError::Storage(_))));

        let mut store = fixture(SqliteStore::open_in_memory());
        FAIL_REGISTRY_SERIALIZATION.with(|flag| flag.set(true));
        let serialization = store.save_key_registry(&KeyRegistryStateV1::new());
        FAIL_REGISTRY_SERIALIZATION.with(|flag| flag.set(false));
        assert!(matches!(serialization, Err(CoreError::Serialization(_))));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn erasure_reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn erasure_record() -> ErasureCoordinatorRecordV1 {
        let request = fixture(pos_core::ErasureRequestV1::new(
            pos_core::ErasureRequestInputV1 {
                request: erasure_reference(1),
                subject: erasure_reference(2),
                scope: pos_core::ErasureScopeV1::PrivateSubjectData,
                selectors: vec![erasure_reference(3)],
                requester: erasure_reference(4),
                authorization: erasure_reference(5),
                policy: erasure_reference(6),
                request_position: 10,
                horizon_position: 20,
                provenance: erasure_reference(7),
            },
        ));
        let state = fixture(pos_core::ErasureStateV1::submitted(
            request.reference(),
            erasure_reference(8),
            erasure_reference(9),
        ));
        fixture(ErasureCoordinatorRecordV1::from_parts(
            pos_core::ErasureCoordinatorRecordPartsV1 {
                request,
                state,
                targets: Vec::new(),
                acknowledgements: Vec::new(),
                receipt: None,
                receipt_input: None,
                authorize_provenance: None,
                freeze_provenance: None,
                dispatch_provenance: None,
                scope_extension_ledger: None,
                administrative_resolution_head: None,
                supporting_records: pos_core::ErasureSupportingRecordsV1::default(),
            },
            erasure_reference(8),
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn erasure_record_with_predecessor() -> (ErasureCoordinatorRecordV1, pos_core::ErasureStateV1) {
        let submitted = erasure_record();
        let predecessor = submitted.state().clone();
        let mut fields = vec![
            ciborium::value::Value::Text("ERS1".to_owned()),
            ciborium::value::Value::Integer(1_u64.into()),
            ciborium::value::Value::Bytes(submitted.request().reference().digest().to_vec()),
            ciborium::value::Value::Integer(1_u64.into()),
            ciborium::value::Value::Null,
            ciborium::value::Value::Bytes(submitted.state().coordinator().digest().to_vec()),
            ciborium::value::Value::Array(Vec::new()),
            ciborium::value::Value::Array(Vec::new()),
            ciborium::value::Value::Integer(2_u64.into()),
            ciborium::value::Value::Bytes(predecessor.state_digest().digest().to_vec()),
            ciborium::value::Value::Bytes(erasure_reference(10).digest().to_vec()),
        ];
        let mut core_bytes = Vec::new();
        fixture(ciborium::into_writer(&fields, &mut core_bytes));
        let mut digest_input = b"ERS1\0".to_vec();
        digest_input.extend_from_slice(&core_bytes);
        let state_digest = ErasureReferenceV1::from_digest(*blake3::hash(&digest_input).as_bytes());
        fields.push(ciborium::value::Value::Bytes(
            state_digest.digest().to_vec(),
        ));
        let mut state_bytes = Vec::new();
        fixture(ciborium::into_writer(&fields, &mut state_bytes));
        let state = fixture(pos_core::ErasureStateV1::from_canonical_cbor(&state_bytes));
        let record = fixture(ErasureCoordinatorRecordV1::from_parts(
            pos_core::ErasureCoordinatorRecordPartsV1 {
                request: submitted.request().clone(),
                state,
                targets: Vec::new(),
                acknowledgements: Vec::new(),
                receipt: None,
                receipt_input: None,
                authorize_provenance: Some(erasure_reference(10)),
                freeze_provenance: None,
                dispatch_provenance: None,
                scope_extension_ledger: None,
                administrative_resolution_head: None,
                supporting_records: pos_core::ErasureSupportingRecordsV1::default(),
            },
            submitted.state().coordinator(),
        ));
        (record, predecessor)
    }

    // These adapter-internal tests inject malformed rows and SQL failures that
    // cannot cross the public store interface. Public recovery and backend
    // parity remain covered by `tests/erasure_persistence.rs`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn erasure_state_resolution_error_regions_are_instrumented() {
        let record = erasure_record();
        let state_digest = record.state().state_digest();
        let state_query_error = tests::new_store();
        fixture(
            state_query_error
                .conn
                .execute_batch("DROP TABLE erasure_states"),
        );
        assert!(state_query_error.resolve_state(state_digest).is_err());

        let malformed_state_metadata = tests::new_store();
        fixture(
            malformed_state_metadata
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON"),
        );
        fixture(malformed_state_metadata.conn.execute(
            "INSERT INTO erasure_states
             (state_digest, request_digest, state_cbor) VALUES (?1, X'01', X'01')",
            params![state_digest.digest().as_slice()],
        ));
        assert!(malformed_state_metadata
            .resolve_state(state_digest)
            .is_err());

        let mismatched_state_digest = erasure_reference(90);
        let mismatched_state = tests::new_store();
        fixture(mismatched_state.conn.execute(
            "INSERT INTO erasure_states
             (state_digest, request_digest, state_cbor) VALUES (?1, ?2, ?3)",
            params![
                mismatched_state_digest.digest().as_slice(),
                record.request().reference().digest().as_slice(),
                fixture(record.state().to_canonical_cbor())
            ],
        ));
        assert_eq!(
            mismatched_state.resolve_state(mismatched_state_digest),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn erasure_record_load_error_regions_are_instrumented() {
        let record = erasure_record();
        let request = record.request().reference();
        let record_bytes = fixture(record.to_canonical_cbor());
        let record_query_error = tests::new_store();
        fixture(
            record_query_error
                .conn
                .execute_batch("DROP TABLE erasure_records"),
        );
        assert!(record_query_error
            .load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)
            .is_err());

        let malformed_record_metadata = tests::new_store();
        fixture(
            malformed_record_metadata
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON"),
        );
        fixture(malformed_record_metadata.conn.execute(
            "INSERT INTO erasure_records
             (request_digest, state_digest, record_cbor) VALUES (?1, X'01', ?2)",
            params![request.digest().as_slice(), record_bytes],
        ));
        assert!(malformed_record_metadata
            .load_record(request, &TEST_FREEZE_AUTHORIZATION_VERIFIER)
            .is_err());

        for (stored_request, stored_state) in [
            (request, erasure_reference(90)),
            (erasure_reference(91), record.state().state_digest()),
        ] {
            let mismatched_record = tests::new_store();
            fixture(mismatched_record.conn.execute(
                "INSERT INTO erasure_records
                 (request_digest, state_digest, record_cbor) VALUES (?1, ?2, ?3)",
                params![
                    stored_request.digest().as_slice(),
                    stored_state.digest().as_slice(),
                    record_bytes.as_slice()
                ],
            ));
            assert_eq!(
                mismatched_record.load_record(stored_request, &TEST_FREEZE_AUTHORIZATION_VERIFIER),
                Err(ErasureErrorV1::ProvenanceMissing)
            );
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn erasure_commit_error_regions_are_instrumented() {
        let record = erasure_record();
        let mut begin_error = tests::new_store();
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(true));
        let begin_result = begin_error.commit_record(record.clone());
        FAIL_BEGIN_IMMEDIATE.with(|flag| flag.set(false));
        assert!(begin_result.is_err());

        let mut slot_query_error = tests::new_store();
        fixture(
            slot_query_error
                .conn
                .execute_batch("DROP TABLE erasure_records"),
        );
        assert!(slot_query_error.commit_record(record.clone()).is_err());

        let request = record.request().reference();
        let mut malformed_existing_record = tests::new_store();
        fixture(malformed_existing_record.commit_record(record.clone()));
        fixture(malformed_existing_record.conn.execute(
            "UPDATE erasure_records SET record_cbor = X'01' WHERE request_digest = ?1",
            params![request.digest().as_slice()],
        ));
        assert!(malformed_existing_record
            .commit_record(record.clone())
            .is_err());

        let mut state_row_query_error = tests::new_store();
        fixture(
            state_row_query_error
                .conn
                .execute_batch("DROP TABLE erasure_states"),
        );
        assert!(state_row_query_error.commit_record(record.clone()).is_err());

        let state_digest = record.state().state_digest();
        let mut malformed_state_metadata_on_commit = tests::new_store();
        fixture(malformed_state_metadata_on_commit.commit_record(record.clone()));
        fixture(
            malformed_state_metadata_on_commit
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON"),
        );
        fixture(malformed_state_metadata_on_commit.conn.execute(
            "UPDATE erasure_states SET request_digest = X'01' WHERE state_digest = ?1",
            params![state_digest.digest().as_slice()],
        ));
        assert!(malformed_state_metadata_on_commit
            .commit_record(record)
            .is_err());

        let record = erasure_record();
        let state_digest = record.state().state_digest();
        let mut missing_state = tests::new_store();
        fixture(missing_state.commit_record(record.clone()));
        fixture(missing_state.conn.execute(
            "DELETE FROM erasure_states WHERE state_digest = ?1",
            params![state_digest.digest().as_slice()],
        ));
        assert_eq!(
            missing_state.commit_record(record.clone()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        for (request_digest, state_cbor) in [
            (record.request().reference().digest().to_vec(), vec![0_u8]),
            (
                erasure_reference(92).digest().to_vec(),
                fixture(record.state().to_canonical_cbor()),
            ),
        ] {
            let mut corrupt_state = tests::new_store();
            fixture(corrupt_state.commit_record(record.clone()));
            fixture(corrupt_state.conn.execute(
                "UPDATE erasure_states
                 SET request_digest = ?1, state_cbor = ?2 WHERE state_digest = ?3",
                params![request_digest, state_cbor, state_digest.digest().as_slice()],
            ));
            assert_eq!(
                corrupt_state.commit_record(record.clone()),
                Err(ErasureErrorV1::ProvenanceMissing)
            );
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn erasure_exact_cas_retries_reject_a_missing_state_row() {
        let record = erasure_record();
        let request = record.request().reference();
        let state_digest = record.state().state_digest();
        let mut store = tests::new_store();
        fixture(store.commit_record(record.clone()));
        fixture(store.conn.execute(
            "DELETE FROM erasure_states WHERE state_digest = ?1",
            params![state_digest.digest().as_slice()],
        ));
        assert_eq!(
            store.compare_and_swap_scope_extension(request, erasure_reference(90), record.clone(),),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        assert_eq!(
            store.compare_and_swap_administrative_resolution(request, None, record),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn erasure_commit_rejects_corrupt_record_state_metadata() {
        let record = erasure_record();
        let request = record.request().reference();

        for metadata_state_digest in [vec![9_u8], vec![9_u8; 32]] {
            let mut store = tests::new_store();
            fixture(store.commit_record(record.clone()));
            fixture(
                store
                    .conn
                    .execute_batch("PRAGMA ignore_check_constraints = ON"),
            );
            fixture(store.conn.execute(
                "UPDATE erasure_records SET state_digest = ?1 WHERE request_digest = ?2",
                params![metadata_state_digest, request.digest().as_slice()],
            ));

            assert_eq!(
                store.commit_record(record.clone()),
                Err(ErasureErrorV1::ProvenanceMissing)
            );
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn erasure_predecessor_error_regions_are_instrumented() {
        let (next, predecessor) = erasure_record_with_predecessor();
        let next_request = next.request().reference();
        let predecessor_digest = predecessor.state_digest();
        let predecessor_bytes = fixture(predecessor.to_canonical_cbor());

        let predecessor_query_error = tests::new_store();
        fixture(
            predecessor_query_error
                .conn
                .execute_batch("DROP TABLE erasure_states"),
        );
        assert!(
            validate_erasure_predecessor(&predecessor_query_error.conn, next_request, &next,)
                .is_err()
        );

        let malformed_predecessor_metadata = tests::new_store();
        fixture(
            malformed_predecessor_metadata
                .conn
                .execute_batch("PRAGMA ignore_check_constraints = ON"),
        );
        fixture(malformed_predecessor_metadata.conn.execute(
            "INSERT INTO erasure_states
             (state_digest, request_digest, state_cbor) VALUES (?1, X'01', ?2)",
            params![predecessor_digest.digest().as_slice(), predecessor_bytes],
        ));
        assert!(validate_erasure_predecessor(
            &malformed_predecessor_metadata.conn,
            next_request,
            &next,
        )
        .is_err());

        let mismatched_predecessor_request = tests::new_store();
        fixture(mismatched_predecessor_request.conn.execute(
            "INSERT INTO erasure_states
             (state_digest, request_digest, state_cbor) VALUES (?1, ?2, ?3)",
            params![
                predecessor_digest.digest().as_slice(),
                erasure_reference(90).digest().as_slice(),
                predecessor_bytes.as_slice()
            ],
        ));
        assert_eq!(
            validate_erasure_predecessor(&mismatched_predecessor_request.conn, next_request, &next,),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        let malformed_predecessor_state = tests::new_store();
        fixture(malformed_predecessor_state.conn.execute(
            "INSERT INTO erasure_states
             (state_digest, request_digest, state_cbor) VALUES (?1, ?2, X'01')",
            params![
                predecessor_digest.digest().as_slice(),
                next_request.digest().as_slice()
            ],
        ));
        assert!(validate_erasure_predecessor(
            &malformed_predecessor_state.conn,
            next_request,
            &next,
        )
        .is_err());
    }
}
