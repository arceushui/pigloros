//! `SQLite` WAL append-only `EventStore` backend.
//!
//! Events are stored in a single table, append-only.
//! Batched transactions ensure throughput >= 2k ev/s on `SQLite`-WAL.
//! Fork is copy-on-write: only a metadata row is inserted at fork time (O(1)).
//! Child reads stitch parent events up to `fork_seq` with child events.

use rusqlite::{params, types::ToSql, Connection, OpenFlags, TransactionBehavior};

use pos_core::{
    clock::{AdmissionClock, Seq, SystemAdmissionClock, WallTime},
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    geo_admission::{
        GeoLocationAdmissionAdmin, GeoLocationAdmissionFenceV1, GeoLocationAdmissionOutcome,
        GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
    },
    hasher::Hasher,
    ids::{EntityId, EventId, TimelineId},
    store::{
        checked_append_identity_expires_at, AppendDedupScope, AppendIdentity, AppendIntent,
        AppendOrDuplicateOutcome, EventReadBounds, EventStore, PurgeOutcome, SeqRange,
    },
    timeline::{Timeline, TimelineMeta, TimelineMode},
    CoreError, GEOGRAPHIC_EVENT_TYPE,
};

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: force [`SqliteStore::open_in_memory`] to fail.
    pub(crate) static FAIL_OPEN_IN_MEMORY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force `query` after `prepare` to fail.
    static FAIL_STMT_QUERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection: force `BEGIN IMMEDIATE` in append/import to fail.
    static FAIL_BEGIN_IMMEDIATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
    /// Test-only fault injection for the open-time sequence validation query.
    static FAIL_SEQUENCE_VALIDATION_QUERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection for bounded fork-chain reads.
    static FAIL_BOUNDED_CHAIN_QUERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub struct SqliteStore {
    conn: Connection,
    hasher: Box<dyn Hasher>,
    clock: Box<dyn AdmissionClock>,
}

impl SqliteStore {
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

    /// Open a `SQLite` WAL store with a custom hasher.
    ///
    /// # Errors
    /// Returns `CoreError::Storage` if the database cannot be opened or schema initialisation fails.
    pub fn open_with_hasher(path: &str, hasher: Box<dyn Hasher>) -> Result<Self, CoreError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| CoreError::Storage(e.to_string()))?;

        Self::require_utf8_encoding(&conn)?;
        let store = Self {
            conn,
            hasher,
            clock: Box::new(SystemAdmissionClock),
        };
        store.init_schema()?;
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

    fn optional_sequence_query(
        result: rusqlite::Result<Option<i64>>,
    ) -> Result<Option<i64>, CoreError> {
        result.map_err(|error| CoreError::Storage(error.to_string()))
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
                 PRIMARY KEY (timeline_id, seq)
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
             CREATE TABLE IF NOT EXISTS geographic_presence (
                 timeline_id TEXT PRIMARY KEY,
                 has_evidence INTEGER NOT NULL CHECK (has_evidence = 1)
             );
             CREATE TABLE IF NOT EXISTS geographic_admission_fences (
                 timeline_id TEXT NOT NULL,
                 entity_id TEXT NOT NULL,
                 binding_revision INTEGER NOT NULL,
                 consent_identity BLOB NOT NULL CHECK (length(consent_identity) = 32),
                 consent_revision INTEGER NOT NULL,
                 consent_hash BLOB NOT NULL CHECK (length(consent_hash) = 32),
                 policy_version INTEGER NOT NULL,
                 withdrawn INTEGER NOT NULL CHECK (withdrawn IN (0, 1)),
                 admission_epoch INTEGER NOT NULL,
                 PRIMARY KEY (timeline_id, entity_id)
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
             ON geographic_admission_dedup(expires_at);",
            )
            .map_err(|error| Self::storage_error(&error))
    }

    fn geographic_fence_permits(
        &self,
        request: &GeoLocationAdmissionRequestV1,
    ) -> Result<bool, CoreError> {
        let snapshot = request.snapshot();
        let consent = snapshot.consent();
        if consent.withdrawn() {
            return Ok(false);
        }
        self.conn
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM geographic_admission_fences
                    WHERE timeline_id = ?1 AND entity_id = ?2
                      AND binding_revision = ?3
                      AND consent_identity = ?4 AND consent_revision = ?5
                      AND consent_hash = ?6 AND policy_version = ?7
                      AND withdrawn = 0 AND admission_epoch = ?8
                      AND admission_epoch != 0
                )",
                params![
                    request.timeline().to_string(),
                    request.entity().to_string(),
                    i64::try_from(snapshot.binding_revision()).unwrap_or(i64::MAX),
                    consent.identity().as_slice(),
                    i64::try_from(consent.revision()).unwrap_or(i64::MAX),
                    consent.hash().as_slice(),
                    i64::from(consent.policy_version()),
                    i64::try_from(consent.admission_epoch()).unwrap_or(i64::MAX),
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|exists| exists == 1)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn geographic_fence_permits_in_transaction(
        tx: &rusqlite::Transaction<'_>,
        request: &GeoLocationAdmissionRequestV1,
    ) -> Result<bool, CoreError> {
        let snapshot = request.snapshot();
        let consent = snapshot.consent();
        if consent.withdrawn() {
            return Ok(false);
        }
        tx.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM geographic_admission_fences
                WHERE timeline_id = ?1 AND entity_id = ?2
                  AND binding_revision = ?3
                  AND consent_identity = ?4 AND consent_revision = ?5
                  AND consent_hash = ?6 AND policy_version = ?7
                  AND withdrawn = 0 AND admission_epoch = ?8
                  AND admission_epoch != 0
            )",
            params![
                request.timeline().to_string(),
                request.entity().to_string(),
                i64::try_from(snapshot.binding_revision()).unwrap_or(i64::MAX),
                consent.identity().as_slice(),
                i64::try_from(consent.revision()).unwrap_or(i64::MAX),
                consent.hash().as_slice(),
                i64::from(consent.policy_version()),
                i64::try_from(consent.admission_epoch()).unwrap_or(i64::MAX),
            ],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists == 1)
        .map_err(|error| CoreError::Storage(error.to_string()))
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
        Self::read_own_events_limited_on(conn, timeline_id, from, to, None)
    }

    fn read_own_events_limited_on(
        conn: &Connection,
        timeline_id: TimelineId,
        from: Seq,
        to: Option<Seq>,
        limit: Option<usize>,
    ) -> Result<Vec<Event>, CoreError> {
        const SQL: &str = "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                                causation_id, correlation_id, schema_version, payload_hash, signature
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
            let seq: i64 = row.get(0).map_err(|e| CoreError::Storage(e.to_string()))?;
            let event_id: String = row.get(1).map_err(|e| CoreError::Storage(e.to_string()))?;
            let entity_id: String = row.get(2).map_err(|e| CoreError::Storage(e.to_string()))?;
            let event_type: String = row.get(3).map_err(|e| CoreError::Storage(e.to_string()))?;
            let payload: Vec<u8> = row.get(4).map_err(|e| CoreError::Storage(e.to_string()))?;
            let wall_time: i64 = row.get(5).map_err(|e| CoreError::Storage(e.to_string()))?;
            let causation_id: Option<String> =
                row.get(6).map_err(|e| CoreError::Storage(e.to_string()))?;
            let correlation_id: Option<String> =
                row.get(7).map_err(|e| CoreError::Storage(e.to_string()))?;
            let ph_bytes: Vec<u8> = row.get(9).map_err(|e| CoreError::Storage(e.to_string()))?;
            let sig_bytes: Option<Vec<u8>> =
                row.get(10).map_err(|e| CoreError::Storage(e.to_string()))?;
            let ph_arr: [u8; 32] = ph_bytes
                .try_into()
                .map_err(|_| CoreError::Serialization("bad hash".to_owned()))?;
            let signature = match sig_bytes {
                None => None,
                Some(bytes) => {
                    let arr: [u8; 64] = bytes
                        .try_into()
                        .map_err(|_| CoreError::Serialization("bad signature length".to_owned()))?;
                    Some(pos_core::Signature::from_bytes(arr))
                }
            };
            events.push(Event {
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
                payload_hash: pos_core::Hash::from_bytes(ph_arr),
            });
        }

        Ok(events)
    }

    fn read_own_events_bounded(
        conn: &Connection,
        timeline_id: TimelineId,
        from: Seq,
        to: Seq,
        max_events: usize,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
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
                    field_sizes.push((
                        row.get(1)
                            .expect("typeof(non-null SQLite value) returns text"),
                        row.get(2)
                            .expect("length(non-null SQLite BLOB) returns an integer"),
                        row.get(3).expect(
                            "length(CAST(non-null SQLite TEXT AS BLOB)) returns an integer",
                        ),
                    ));
                }
                Ok(None) => break,
                Err(error) => {
                    let message = error.to_string();
                    return Err(CoreError::Storage(message));
                }
            }
        }

        if field_sizes.len() != max_events {
            return Err(CoreError::Storage(format!(
                "timeline {timeline_id} violates the contiguous Event sequence invariant"
            )));
        }
        for (payload_storage_class, stored_payload_size, stored_event_type_size) in field_sizes {
            if payload_storage_class != "blob" {
                return Err(CoreError::Storage(format!(
                    "event payload has SQLite storage class {payload_storage_class}; BLOB is required for bounded reads"
                )));
            }
            let payload_size = sqlite_usize_or_max(stored_payload_size);
            if payload_size > bounds.max_payload_bytes() {
                return Err(CoreError::PayloadTooLarge { size: payload_size });
            }
            let event_type_size = sqlite_usize_or_max(stored_event_type_size);
            if event_type_size > bounds.max_event_type_bytes() {
                return Err(CoreError::EventMetadataTooLarge {
                    field: "event_type",
                    size: event_type_size,
                });
            }
        }

        #[cfg(test)]
        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(queries.get() + 1));
        Self::read_own_events_limited_on(conn, timeline_id, from, Some(to), Some(max_events))
    }

    fn read_logical_bounded(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        let tx = match self.conn.unchecked_transaction() {
            Ok(tx) => tx,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        let chain = Self::fork_chain_bounded_on(&tx, timeline_id, bounds.max_fork_depth())?;
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(u64::MAX, Seq::as_u64);
        let mut logical_offset = 0_u64;
        let mut remaining = bounds.max_events();
        let mut selected = Vec::new();

        for (index, segment) in chain.iter().enumerate() {
            let segment_cap = chain.get(index + 1).and_then(|next| next.fork);
            if segment_cap.is_some_and(|cap| cap.as_u64() > segment.head) {
                return Err(CoreError::Storage(format!(
                    "Fork point exceeds parent Event head for timeline {}",
                    segment.id
                )));
            }
            let segment_len = segment_cap.map_or(segment.head, Seq::as_u64);
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
                let mut events =
                    Self::read_own_events_bounded(&tx, segment.id, raw_from, raw_to, take, bounds)?;
                for event in &mut events {
                    event.seq = Seq::from_u64(logical_offset.saturating_add(event.seq.as_u64()));
                }
                selected.extend(events);
                remaining -= take;
            }
            logical_offset = logical_offset.saturating_add(segment_len);
            if remaining == 0 || logical_offset >= to {
                break;
            }
        }
        Ok(selected)
    }

    /// Walk the fork chain for a timeline, returning [root, ..., leaf].
    fn fork_chain(
        &self,
        timeline_id: TimelineId,
    ) -> Result<Vec<(TimelineId, Option<Seq>)>, CoreError> {
        Self::fork_chain_on(&self.conn, timeline_id)
    }

    fn fork_chain_on(
        conn: &Connection,
        timeline_id: TimelineId,
    ) -> Result<Vec<(TimelineId, Option<Seq>)>, CoreError> {
        let mut chain = Vec::new();
        let mut current = timeline_id;
        loop {
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
                Some(DecodedForkChainRow::Root { .. }) => {
                    chain.push((current, None));
                    break;
                }
                Some(DecodedForkChainRow::Fork { parent, fork, .. }) => {
                    chain.push((current, Some(fork)));
                    current = parent;
                }
            }
        }
        chain.reverse();
        Ok(chain)
    }

    fn fork_chain_bounded_on(
        conn: &Connection,
        timeline_id: TimelineId,
        max_depth: usize,
    ) -> Result<Vec<BoundedForkSegment>, CoreError> {
        let mut chain = Vec::new();
        let mut current = timeline_id;
        let mut depth = 0_usize;
        loop {
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

#[derive(Debug)]
struct ForkChainRow {
    parent_id: Option<String>,
    fork_seq: Option<i64>,
    head_seq: i64,
}

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
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let timeline_text = timeline.to_string();
        let timeline_query = tx.query_row(
            "SELECT head_seq FROM timelines WHERE id = ?1",
            params![&timeline_text],
            |row| row.get::<_, i64>(0),
        );
        let exists = timeline_query
            .optional()
            .map_err(|error| Self::storage_error(&error))?;
        let Some(head_seq) = exists else {
            return Err(CoreError::TimelineNotFound(timeline));
        };
        let existing = tx.query_row(
            "SELECT event_id, expires_at FROM append_identities WHERE dedup_key = ?1",
            params![identity.dedup_key.as_bytes().as_slice()],
            |row| {
                row.get::<_, String>(0)
                    .and_then(|event_id| row.get::<_, i64>(1).map(|expires| (event_id, expires)))
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
        if max_owned_events.is_some_and(|maximum| u64::try_from(head_seq).unwrap_or(0) >= maximum) {
            return Ok(None);
        }
        let expires_at = checked_append_identity_expires_at(admitted_at)?;
        let event =
            Self::append_one_in_transaction(&tx, self.hasher.as_ref(), timeline, draft.clone())?;
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
        Ok(Some(AppendOrDuplicateOutcome::Appended(Box::new(event))))
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

    fn append_visible(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        if drafts.is_empty() {
            return Ok(Vec::new());
        }
        let mut committed = Vec::with_capacity(drafts.len());
        let tx = self
            .conn
            .transaction()
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
        Ok(committed)
    }
}

impl GeoLocationAdmissionAdmin for SqliteStore {
    fn set_geo_location_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoLocationAdmissionFenceV1,
    ) -> Result<(), CoreError> {
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
        let consent = fence.consent();
        self.conn
            .execute(
                "INSERT INTO geographic_admission_fences (
                    timeline_id, entity_id, binding_revision, consent_identity,
                    consent_revision, consent_hash, policy_version, withdrawn, admission_epoch
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(timeline_id, entity_id) DO UPDATE SET
                    binding_revision = excluded.binding_revision,
                    consent_identity = excluded.consent_identity,
                    consent_revision = excluded.consent_revision,
                    consent_hash = excluded.consent_hash,
                    policy_version = excluded.policy_version,
                    withdrawn = excluded.withdrawn,
                    admission_epoch = excluded.admission_epoch",
                params![
                    timeline.to_string(),
                    entity.to_string(),
                    i64::try_from(fence.binding_revision()).unwrap_or(i64::MAX),
                    consent.identity().as_slice(),
                    i64::try_from(consent.revision()).unwrap_or(i64::MAX),
                    consent.hash().as_slice(),
                    i64::from(consent.policy_version()),
                    i64::from(u8::from(consent.withdrawn())),
                    i64::try_from(consent.admission_epoch()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok(())
    }
}

impl GeoLocationAdmissionStore for SqliteStore {
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
        match tx.commit() {
            Ok(()) => Ok(GeoLocationAdmissionOutcome::accepted(event.id)),
            Err(_) => Ok(GeoLocationAdmissionOutcome::outcome_unknown()),
        }
    }
}

impl EventStore for SqliteStore {
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

    fn append_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        self.append_or_duplicate_with_limit(timeline, identity, admitted_at, &draft, None)
            .map(|outcome| outcome.expect("unbounded append cannot hit an event limit"))
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
        let timeline_exists = match self.get_timeline(timeline) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(error) => return Err(error),
        };
        if !timeline_exists {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        Self::optional_sequence_query(
            self.conn
                .query_row(
                    "SELECT seq FROM events WHERE timeline_id = ?1 AND event_id = ?2",
                    params![timeline.to_string(), event_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional(),
        )
        .and_then(|seq| {
            let Some(seq) = seq else {
                return Ok(None);
            };
            let mut events = Self::read_own_events_limited_on(
                &self.conn,
                timeline,
                Seq::from_u64(u64::try_from(seq).unwrap_or(0)),
                Some(Seq::from_u64(u64::try_from(seq).unwrap_or(0))),
                Some(1),
            )?;
            Ok(events.pop())
        })
    }

    fn purge_expired_append_identities_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        let now = self.clock.now()?;
        let tx = self
            .conn
            .transaction()
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
        self.conn
            .execute(
                "DELETE FROM append_identities WHERE scope_key = ?1",
                params![scope.as_bytes().as_slice()],
            )
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| {
                let chain = self.fork_chain(timeline)?;
                let mut all: Vec<Event> = Vec::new();

                for (i, &(tid, _)) in chain.iter().enumerate() {
                    if i + 1 < chain.len() {
                        // Parent: all own events up to the child's fork_seq (raw local seq).
                        // fork_seq is always Some for non-root chain entries (enforced by fork()).
                        let fork_seq = chain[i + 1]
                            .1
                            .expect("non-root chain entry always has fork_seq");
                        let events = self.read_own_events(tid, Seq::ZERO, Some(fork_seq))?;
                        all.extend(events);
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
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| self.read_logical_bounded(timeline, range, bounds))
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
                let head = self.get_head_seq(parent)?;
                if at_seq > head {
                    return Err(CoreError::ForkBeyondHead {
                        fork_seq: at_seq.as_u64(),
                        head: head.as_u64(),
                    });
                }

                // Compute chain hash at the fork point
                let fork_hash = self.compute_chain_hash_at(parent, at_seq)?;

                let meta = TimelineMeta::forked_from(parent, at_seq, name);
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
                crate::generic_timeline_is_visible(
                    self.timeline_contains_geographic_evidence(timeline.id()),
                )
                .map(|visible| visible.then_some(timeline))
            }
        }
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        let id = meta.id;
        // Resolve fork parent before the duplicate-id check so storage failures on the
        // parent lookup are exercised (and fail closed before INSERT).
        let chain_head = match meta.fork_point {
            Some((parent, at_seq)) => {
                let parent_tl = self
                    .get_timeline(parent)?
                    .ok_or(CoreError::TimelineNotFound(parent))?;
                if at_seq > parent_tl.head {
                    return Err(CoreError::ForkBeyondHead {
                        fork_seq: at_seq.as_u64(),
                        head: parent_tl.head.as_u64(),
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
        self.conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
                params![
                    timeline.id().to_string(),
                    timeline.meta.name.as_deref(),
                    mode_str(timeline.mode()),
                    parent_id,
                    fork_seq,
                    chain_head.as_bytes().as_slice(),
                ],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
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
                        Err(_) => {
                            let _ = self.conn.execute_batch("ROLLBACK");
                        }
                    }
                }
                applied
            })
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        self.ensure_generic_timeline_visibility(id).and_then(|()| {
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
                .transaction()
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
                "DELETE FROM geographic_admission_fences WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute("DELETE FROM events WHERE timeline_id = ?1", params![id_str])
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            tx.execute(
                "DELETE FROM geographic_presence WHERE timeline_id = ?1",
                params![id_str],
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
            let deleted = tx
                .execute("DELETE FROM timelines WHERE id = ?1", params![id_str])
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            if deleted == 0 {
                return Err(CoreError::TimelineNotFound(id));
            }
            tx.commit().map_err(|e| CoreError::Storage(e.to_string()))?;
            Ok(())
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
                let _ = self.conn.execute(
                    "DELETE FROM timelines WHERE id = ?1",
                    params![expected_id.to_string()],
                );
            }
            #[cfg(test)]
            if FAIL_IMPORT_GET_STORAGE.with(std::cell::Cell::get) {
                let _ = self.conn.execute_batch("DROP TABLE timelines");
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
                let _ = self.conn.execute_batch("ROLLBACK");
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
            self.conn
                .execute(
                    "INSERT INTO events
                     (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                      causation_id, correlation_id, schema_version, payload_hash, signature)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
        let chain = self.fork_chain(timeline)?;
        let mut hash = self.hasher.genesis_hash();

        for (i, &(tid, _)) in chain.iter().enumerate() {
            // For non-target ancestors: limit = child's fork_seq (always has next element).
            // For the target: limit = at_seq.
            let limit = if tid == timeline {
                at_seq
            } else {
                chain[i + 1]
                    .1
                    .expect("ancestor always has a successor in chain")
            };
            let events = self.read_own_events(tid, Seq::ZERO, Some(limit))?;
            for event in events {
                let id_str = event.id.to_string();
                hash = self
                    .hasher
                    .hash_event(&hash, id_str.as_bytes(), &event.payload);
            }
            if tid == timeline {
                break;
            }
        }
        Ok(hash)
    }
}

fn begin_immediate_sql() -> &'static str {
    #[cfg(test)]
    if FAIL_BEGIN_IMMEDIATE.with(std::cell::Cell::get) {
        return "SELECT RAISE(ABORT, 'begin fault')";
    }
    "BEGIN IMMEDIATE"
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

use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, EventId},
        store::{EventReadBounds, SeqRange},
        CoreError,
    };

    fn read_bounds(max_payload_bytes: usize) -> EventReadBounds {
        EventReadBounds::new(max_payload_bytes, usize::MAX, usize::MAX, usize::MAX)
    }
    use pos_crypto::chain::hash_payload;

    fn make_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    fn new_store() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
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
        store.read(timeline, SeqRange::all()).unwrap()[0].id
    }

    struct ErrorClock;

    impl AdmissionClock for ErrorClock {
        fn now(&mut self) -> Result<WallTime, CoreError> {
            Err(CoreError::Storage("clock failed".to_owned()))
        }
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
        let timeline = store.create_timeline("clock-error").unwrap();
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
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .is_err());

        let mut overflow = SqliteStore::open_with_clock(
            ":memory:",
            Box::new(pos_core::FixedAdmissionClock(WallTime::from_micros(
                u64::MAX,
            ))),
        )
        .unwrap();
        let timeline = overflow.create_timeline("overflow").unwrap();
        let intent = AppendIntent::new(&make_draft(EntityId::new(), b"payload"));
        assert!(overflow
            .append_intent_or_duplicate(timeline.id(), append_identity(91, 91), intent)
            .is_err());

        let mut transaction = new_store();
        transaction.conn.execute_batch("BEGIN").unwrap();
        assert!(transaction
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .is_err());
        let _ = transaction.conn.execute_batch("ROLLBACK");

        let mut prepare = new_store();
        prepare
            .conn
            .execute_batch("DROP TABLE append_identities")
            .unwrap();
        assert!(prepare
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .is_err());

        let mut query = new_store();
        query.conn.execute_batch(
            "DROP TABLE append_identities;
             CREATE TABLE append_identities (dedup_key INTEGER, scope_key BLOB, event_id TEXT, expires_at INTEGER);
             INSERT INTO append_identities VALUES (1, X'00', 'id', 0);",
        ).unwrap();
        assert!(query
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .is_err());
    }

    #[test]
    fn read_event_by_id_fails_closed_on_query_error() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-event-by-id").unwrap();
        store.conn.execute("DROP TABLE events", []).unwrap();
        let error = store.read_event_by_id(timeline.id(), EventId::new());
        assert!(error.unwrap_err().to_string().contains("storage error"));
    }

    #[test]
    fn optional_sequence_query_maps_all_result_variants() {
        assert_eq!(
            SqliteStore::optional_sequence_query(Ok(Some(7))).unwrap(),
            Some(7)
        );
        assert_eq!(
            SqliteStore::optional_sequence_query(Ok(None)).unwrap(),
            None
        );
        let error =
            SqliteStore::optional_sequence_query(Err(rusqlite::Error::InvalidQuery)).unwrap_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn read_event_by_id_rejects_an_unknown_timeline() {
        let store = new_store();
        let timeline = TimelineId::new();
        let error = store
            .read_event_by_id(timeline, EventId::new())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains(&format!("timeline not found: {timeline}")));
    }

    #[test]
    fn read_own_surfaces_a_timeline_lookup_storage_error() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-own-storage-error").unwrap();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT id, name, mode, parent_id, fork_seq, \
                 X'0102' AS head_seq FROM timelines_real",
                [],
            )
            .unwrap();

        assert_storage_err(store.read_own(timeline.id(), SeqRange::all()));
    }

    #[test]
    fn read_event_by_id_fails_closed_when_event_row_read_fails() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-event-row").unwrap();
        let event = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"row")])
            .unwrap()
            .pop()
            .unwrap();
        FAIL_ROWS_NEXT.with(|flag| flag.set(true));
        let result = store.read_event_by_id(timeline.id(), event.id);
        FAIL_ROWS_NEXT.with(|flag| flag.set(false));
        assert!(result.is_err());
    }

    #[test]
    fn lifecycle_delete_errors_fail_closed() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-failure").unwrap();
        let outcome = store
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(92, 92),
                AppendIntent::new(&make_draft(EntityId::new(), b"payload")),
            )
            .unwrap();
        let event_id = appended_event_id(&store, timeline.id(), &outcome);
        store
            .conn
            .execute(
                "UPDATE append_identities SET expires_at = 0 WHERE event_id = ?1",
                rusqlite::params![event_id.to_string()],
            )
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER deny_identity_delete BEFORE DELETE ON append_identities
                 BEGIN SELECT RAISE(ABORT, 'delete denied'); END;",
            )
            .unwrap();
        assert!(store
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(92, 92),
                AppendIntent::new(&make_draft(EntityId::new(), b"different")),
            )
            .is_err());
        assert!(store
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
            .is_err());

        let mut commit_failure = new_store();
        let timeline = commit_failure.create_timeline("commit-failure").unwrap();
        let outcome = commit_failure
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(93, 93),
                AppendIntent::new(&make_draft(EntityId::new(), b"payload")),
            )
            .unwrap();
        let event_id = appended_event_id(&commit_failure, timeline.id(), &outcome);
        commit_failure
            .conn
            .execute(
                "UPDATE append_identities SET expires_at = 0 WHERE event_id = ?1",
                rusqlite::params![event_id.to_string()],
            )
            .unwrap();
        commit_failure.conn.commit_hook(Some(|| true));
        assert!(commit_failure
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
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
        let timeline = bad_hash.create_timeline("bad-hash").unwrap();
        bad_hash
            .conn
            .execute("UPDATE timelines SET chain_head = x'00'", [])
            .unwrap();
        assert!(bad_hash
            .append_or_duplicate(
                timeline.id(),
                append_identity(2, 2),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut events = new_store();
        let timeline = events.create_timeline("events").unwrap();
        events.conn.execute("DROP TABLE events", []).unwrap();
        assert!(events
            .append_or_duplicate(
                timeline.id(),
                append_identity(3, 3),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut update = new_store();
        let timeline = update.create_timeline("update").unwrap();
        update.conn.execute_batch("CREATE TRIGGER deny_head BEFORE UPDATE ON timelines BEGIN SELECT RAISE(ABORT, 'deny'); END;").unwrap();
        assert!(update
            .append_or_duplicate(
                timeline.id(),
                append_identity(4, 4),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut identity = new_store();
        let timeline = identity.create_timeline("identity").unwrap();
        identity.conn.execute_batch("CREATE TRIGGER deny_identity BEFORE INSERT ON append_identities BEGIN SELECT RAISE(ABORT, 'deny'); END;").unwrap();
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
            .unwrap()
            .is_empty());

        let mut commit = new_store();
        let timeline = commit.create_timeline("commit").unwrap();
        commit.conn.commit_hook(Some(|| true));
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
        .unwrap();
        let timeline = store.create_timeline("clock").unwrap();
        let draft = make_draft(EntityId::new(), b"payload");
        let intent = AppendIntent::new(&draft);
        let first = store
            .append_intent_or_duplicate(timeline.id(), append_identity(7, 7), intent.clone())
            .unwrap();
        let event_id = appended_event_id(&store, timeline.id(), &first);
        assert_eq!(
            store
                .append_intent_or_duplicate(timeline.id(), append_identity(7, 7), intent)
                .unwrap(),
            AppendOrDuplicateOutcome::Duplicate { event_id }
        );
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
                .unwrap(),
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
            .unwrap();
        let outcome = store
            .append_intent_or_duplicate(
                timeline.id(),
                append_identity(7, 7),
                AppendIntent::new(&make_draft(EntityId::new(), b"different")),
            )
            .unwrap();
        let _ = appended_event_id(&store, timeline.id(), &outcome);
        store
            .conn
            .execute("UPDATE append_identities SET expires_at = 0", [])
            .unwrap();
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
                .unwrap(),
            PurgeOutcome {
                removed: 1,
                more_may_remain: true
            }
        );
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).unwrap())
                .unwrap(),
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
        let timeline = corrupt.create_timeline("corrupt").unwrap();
        corrupt.conn.execute(
            "INSERT INTO append_identities (dedup_key, scope_key, event_id, expires_at) VALUES (?1, ?2, 'bad', 100)",
            params![[7_u8; 32].as_slice(), [7_u8; 32].as_slice()],
        ).unwrap();
        assert!(corrupt
            .append_or_duplicate(
                timeline.id(),
                append_identity(7, 7),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());

        let mut missing = new_store();
        let timeline = missing.create_timeline("missing-table").unwrap();
        missing
            .conn
            .execute("DROP TABLE append_identities", [])
            .unwrap();
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
        let timeline = store.create_timeline("retained-identity-query").unwrap();
        let identity = append_identity(9, 9);
        let draft = make_draft(EntityId::new(), b"payload");
        store
            .append_or_duplicate(
                timeline.id(),
                identity,
                WallTime::from_micros(1),
                draft.clone(),
            )
            .unwrap();
        store.conn.execute("DROP TABLE events", []).unwrap();

        let error = store
            .append_or_duplicate_with_limit_visible(
                timeline.id(),
                identity,
                WallTime::from_micros(2),
                &draft,
                None,
            )
            .unwrap_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn append_identity_timeline_lookup_errors_are_storage_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("identity-timeline-query").unwrap();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
        let draft = make_draft(EntityId::new(), b"payload");
        let error = store.append_or_duplicate_with_limit_visible(
            timeline.id(),
            append_identity(10, 10),
            WallTime::from_micros(1),
            &draft,
            None,
        );
        assert!(error.unwrap_err().to_string().contains("storage error"));
    }

    #[test]
    fn delete_child_count_lookup_errors_are_storage_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-child-count-query").unwrap();
        let _decoy = store.create_timeline("delete-child-count-decoy").unwrap();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .unwrap();
        let view_sql = format!(
            "CREATE VIEW timelines AS SELECT id, name, mode, \
             CASE WHEN id = '{}' THEN parent_id ELSE row_error() END AS parent_id, \
             fork_seq, head_seq FROM timelines_real",
            timeline.id()
        );
        store.conn.execute(&view_sql, []).unwrap();
        let error = store.delete_timeline(timeline.id());
        assert!(error.unwrap_err().to_string().contains("storage error"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_and_cleanup_surface_transaction_and_query_failures() {
        let entity = EntityId::new();

        let mut transaction = new_store();
        let timeline = transaction.create_timeline("transaction").unwrap();
        transaction.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(transaction
            .append_or_duplicate(
                timeline.id(),
                append_identity(9, 9),
                WallTime::from_micros(1),
                make_draft(entity, b"x")
            )
            .is_err());
        transaction.conn.execute_batch("ROLLBACK").unwrap();

        let mut timeline_query = new_store();
        timeline_query
            .conn
            .execute("DROP TABLE timelines", [])
            .unwrap();
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
            .unwrap();
        assert!(cleanup
            .purge_expired_append_identities(WallTime::from_micros(100))
            .is_err());

        let mut withdrawal = new_store();
        withdrawal
            .conn
            .execute("DROP TABLE append_identities", [])
            .unwrap();
        assert!(withdrawal
            .remove_append_identities(pos_core::AppendDedupScope::from_keyed_hash([11; 32]))
            .is_err());
    }

    #[test]
    fn append_or_duplicate_fails_closed_on_corrupt_retained_event_rows() {
        let entity = EntityId::new();
        let mut missing_event = new_store();
        let timeline = missing_event.create_timeline("missing-event").unwrap();
        missing_event
            .append_or_duplicate(
                timeline.id(),
                append_identity(11, 11),
                WallTime::from_micros(1),
                make_draft(entity, b"x"),
            )
            .unwrap();
        missing_event.conn.execute("DROP TABLE events", []).unwrap();
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
            .unwrap();
        malformed_event_id
            .append_or_duplicate(
                timeline.id(),
                append_identity(12, 12),
                WallTime::from_micros(1),
                make_draft(entity, b"x"),
            )
            .unwrap();
        malformed_event_id
            .conn
            .execute("UPDATE events SET event_id = 'bad'", [])
            .unwrap();
        malformed_event_id
            .conn
            .execute("UPDATE append_identities SET event_id = 'bad'", [])
            .unwrap();
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
        let tl = store.create_timeline("main").unwrap();
        let got = store.get_timeline(tl.id()).unwrap();
        assert!(got.is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_and_read() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"hello"), make_draft(entity, b"world")],
            )
            .unwrap();
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload.as_slice(), b"hello");
        assert_eq!(events[1].payload.as_slice(), b"world");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_is_opaque_and_unchanged() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00];
        store.append(tl.id(), &[make_draft(entity, &raw)]).unwrap();
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events[0].payload.as_slice(), &raw[..]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_copy_on_write_parent_unaffected() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
            )
            .unwrap();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").unwrap();
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .unwrap();

        let parent_events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(parent_events.len(), 2);

        let child_events = store.read(child.id(), SeqRange::all()).unwrap();
        assert_eq!(child_events.len(), 2); // p1 + c1
        assert_eq!(child_events[0].payload.as_slice(), b"p1");
        assert_eq!(child_events[1].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_beyond_head_returns_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
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
            .unwrap_err();
        assert!(matches!(error, CoreError::TimelineNotFound(_)));

        let timeline = store.create_timeline("missing-events").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .unwrap();
        store.conn.execute("DROP TABLE events", []).unwrap();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        let _: CoreError = error;

        let mut chain_store = new_store();
        let timeline = chain_store.create_timeline("missing-timelines").unwrap();
        chain_store
            .conn
            .execute("DROP TABLE timelines", [])
            .unwrap();
        let error = chain_store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
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
            .unwrap();
        let error = invalid_type_store
            .read_bounded(timeline_id, SeqRange::all(), read_bounds(1))
            .unwrap_err();
        let _: CoreError = error;

        invalid_type_store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = ?1, fork_seq = X'0102' WHERE id = ?2",
                params![TimelineId::new().to_string(), timeline_id.to_string()],
            )
            .unwrap();
        let error = invalid_type_store
            .read_bounded(timeline_id, SeqRange::all(), read_bounds(1))
            .unwrap_err();
        let _: CoreError = error;
    }

    #[test]
    fn bounded_read_propagates_snapshot_and_metadata_query_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("snapshot").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .unwrap();
        store.conn.execute_batch("BEGIN").unwrap();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        store.conn.execute_batch("ROLLBACK").unwrap();
        let _: CoreError = error;

        let mut query_store = new_store();
        let query_timeline = query_store.create_timeline("query").unwrap();
        query_store
            .append(query_timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .unwrap();
        FAIL_ROWS_NEXT.with(|fail| fail.set(true));
        let error = query_store
            .read_bounded(query_timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        FAIL_ROWS_NEXT.with(|fail| fail.set(false));
        let _: CoreError = error;

        store.conn.execute("DROP TABLE events", []).unwrap();
        store
            .conn
            .execute_batch(&format!(
                "CREATE VIEW events AS
                 SELECT '{}' AS timeline_id, 1 AS seq",
                timeline.id()
            ))
            .unwrap();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        let _: CoreError = error;
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_returns_selected_event() {
        let mut store = new_store();
        let timeline = store.create_timeline("bounded").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"ok")])
            .unwrap();
        let child = store
            .fork(timeline.id(), Seq::from_u64(1), "bounded-child")
            .unwrap();
        store
            .append(child.id(), &[make_draft(EntityId::new(), b"child")])
            .unwrap();
        let events = store
            .read_bounded(
                child.id(),
                SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(2)),
                read_bounds(5),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload.as_slice(), b"ok");
        assert_eq!(events[1].payload.as_slice(), b"child");
        let error = store
            .read_bounded(child.id(), SeqRange::all(), read_bounds(4))
            .unwrap_err();
        assert!(matches!(error, CoreError::PayloadTooLarge { size: 5 }));
        let empty = store
            .read_bounded(
                child.id(),
                SeqRange::from_seq(Seq::from_u64(3)),
                read_bounds(usize::MAX),
            )
            .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_validates_metadata_before_querying_payloads() {
        let mut store = new_store();
        let timeline = store.create_timeline("two-phase").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"large")])
            .unwrap();

        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(4))
            .unwrap_err();
        assert!(matches!(error, CoreError::PayloadTooLarge { size: 5 }));
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 0));

        store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(5))
            .unwrap();
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_event_type_before_full_event_query() {
        let mut store = new_store();
        let timeline = store.create_timeline("metadata").unwrap();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("x".repeat(5)),
            CanonicalBytes::from_static(b"x"),
        );
        store.append(timeline.id(), &[oversized]).unwrap();
        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 4, usize::MAX, usize::MAX),
            )
            .unwrap_err();

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
        let timeline = store.create_timeline("text-payload").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET payload = CAST(?1 AS TEXT) WHERE timeline_id = ?2",
                params!["ééé", timeline.id().to_string()],
            )
            .unwrap();
        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(0));

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(4, usize::MAX, usize::MAX, usize::MAX),
            )
            .unwrap_err();

        assert!(error.to_string().contains("storage class text"));
        assert!(error.to_string().contains("BLOB"));
        BOUNDED_EVENT_QUERIES.with(|queries| assert_eq!(queries.get(), 0));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_enforces_exact_fork_depth_and_stops_cycles() {
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
        let mut timelines = vec![root];
        for depth in 1..=65 {
            let parent = timelines.last().unwrap();
            let child = store
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .unwrap();
            timelines.push(child);
        }
        let bounds = EventReadBounds::new(1, 1, 64, usize::MAX);

        assert!(store
            .read_bounded(timelines[64].id(), SeqRange::all(), bounds)
            .unwrap()
            .is_empty());
        let error = store
            .read_bounded(timelines[65].id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));

        let cycle = timelines[1].id();
        store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = ?1 WHERE id = ?1",
                params![cycle.to_string()],
            )
            .unwrap();
        let error = store
            .read_bounded(cycle, SeqRange::all(), bounds)
            .unwrap_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));

        let invalid_parent = timelines[2].id();
        store
            .conn
            .execute(
                "UPDATE timelines SET parent_id = 'not-a-ulid' WHERE id = ?1",
                params![invalid_parent.to_string()],
            )
            .unwrap();
        let error = store
            .read_bounded(invalid_parent, SeqRange::all(), bounds)
            .unwrap_err();
        assert!(matches!(error, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_seeks_late_across_forks_and_fetches_only_the_page() {
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<_> = (0..4_096).map(|_| make_draft(entity, b"x")).collect();
        store.append(root.id(), &drafts).unwrap();
        let child = store
            .fork(root.id(), Seq::from_u64(4_096), "child")
            .unwrap();
        store
            .append(
                child.id(),
                &[make_draft(entity, b"y"), make_draft(entity, b"z")],
            )
            .unwrap();
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 4);

        BOUNDED_METADATA_ROWS.with(|count| count.set(0));
        BOUNDED_EVENT_ROWS.with(|count| count.set(0));
        let page = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_095)), bounds)
            .unwrap();
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
            .unwrap();
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
            .unwrap();

        assert!(detail.contains("SEARCH events USING INDEX"));
        assert!(detail.contains("sqlite_autoindex_events_1"));
        assert!(!detail.contains("SCAN events"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_offline_event_sequence_invariant_violations() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        let timeline_id = {
            let mut store = SqliteStore::open(path).unwrap();
            let timeline = store.create_timeline("offline-gap").unwrap();
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
                .unwrap();
            timeline.id()
        };
        {
            let conn = Connection::open(path).unwrap();
            conn.execute(
                "DELETE FROM events WHERE timeline_id = ?1 AND seq = 2",
                params![timeline_id.to_string()],
            )
            .unwrap();
        }

        let result = SqliteStore::open(path);
        let Err(error) = result else {
            panic!("offline sequence gaps must be rejected");
        };
        assert!(error.to_string().contains("contiguous from seq 1"));

        let type_file = tempfile::NamedTempFile::new().unwrap();
        let type_path = type_file.path().to_str().unwrap();
        let entity = EntityId::new();
        let timeline_id = {
            let mut store = SqliteStore::open(type_path).unwrap();
            let timeline = store.create_timeline("offline-type").unwrap();
            store
                .append(
                    timeline.id(),
                    &[
                        make_draft(entity, b"a"),
                        make_draft(entity, b"b"),
                        make_draft(entity, b"c"),
                    ],
                )
                .unwrap();
            timeline.id()
        };
        {
            let conn = Connection::open(type_path).unwrap();
            conn.execute(
                "UPDATE events SET seq = 1.5 WHERE timeline_id = ?1 AND seq = 2",
                params![timeline_id.to_string()],
            )
            .unwrap();
        }
        let result = SqliteStore::open(type_path);
        let _ = result.err().unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_sequence_gaps_in_the_selected_window() {
        let mut store = new_store();
        let timeline = store.create_timeline("runtime-gap").unwrap();
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
            .unwrap();
        store
            .conn
            .execute(
                "DELETE FROM events WHERE timeline_id = ?1 AND seq = 2",
                params![timeline.id().to_string()],
            )
            .unwrap();

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 2),
            )
            .unwrap_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut type_store = new_store();
        let timeline = type_store.create_timeline("runtime-type").unwrap();
        type_store
            .append(
                timeline.id(),
                &[
                    make_draft(entity, b"a"),
                    make_draft(entity, b"b"),
                    make_draft(entity, b"c"),
                ],
            )
            .unwrap();
        type_store
            .conn
            .execute(
                "UPDATE events SET seq = 1.5 WHERE timeline_id = ?1 AND seq = 2",
                params![timeline.id().to_string()],
            )
            .unwrap();
        let error = type_store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(1)),
                EventReadBounds::new(1, usize::MAX, 0, 2),
            )
            .unwrap_err();
        assert!(matches!(error, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_invalid_timeline_sequence_metadata() {
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 1);

        let mut root_fork_store = new_store();
        let root = root_fork_store.create_timeline("root-fork").unwrap();
        root_fork_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0 WHERE id = ?1",
                params![root.id().to_string()],
            )
            .unwrap();
        let error = root_fork_store
            .read_bounded(root.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(error.to_string().contains("root timeline"));

        let mut root_head_store = new_store();
        let root = root_head_store.create_timeline("root-head").unwrap();
        root_head_store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = -1 WHERE id = ?1",
                params![root.id().to_string()],
            )
            .unwrap();
        let error = root_head_store
            .read_bounded(root.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(error.to_string().contains("negative Event head"));

        let mut head_type_store = new_store();
        let root = head_type_store.create_timeline("root-head-type").unwrap();
        head_type_store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = X'0102' WHERE id = ?1",
                params![root.id().to_string()],
            )
            .unwrap();
        let error = head_type_store
            .read_bounded(root.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(matches!(error, CoreError::Storage(_)));

        let mut child_store = new_store();
        let root = child_store.create_timeline("parent").unwrap();
        let child = child_store.fork(root.id(), Seq::ZERO, "child").unwrap();
        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
                params![child.id().to_string()],
            )
            .unwrap();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(error.to_string().contains("missing its Fork sequence"));

        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0, head_seq = -1 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .unwrap();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(error.to_string().contains("negative Event head"));

        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = -1, head_seq = 0 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .unwrap();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(error.to_string().contains("negative Fork sequence"));

        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 1 WHERE id = ?1",
                params![child.id().to_string()],
            )
            .unwrap();
        let error = child_store
            .read_bounded(child.id(), SeqRange::all(), bounds)
            .unwrap_err();
        assert!(error.to_string().contains("Fork point exceeds"));
    }

    #[test]
    fn bounded_root_count_ignores_children_and_caps_at_maximum_plus_one() {
        let mut store = new_store();
        let first = store.create_timeline("first").unwrap();
        for index in 0..64 {
            store
                .fork(first.id(), Seq::ZERO, &format!("child-{index}"))
                .unwrap();
        }

        store.create_timeline("second").unwrap();
        assert_eq!(store.root_timeline_count_bounded(0).unwrap(), 1);
        assert_eq!(store.root_timeline_count_bounded(1).unwrap(), 2);
        assert_eq!(store.root_timeline_count_bounded(10).unwrap(), 2);
        assert_eq!(store.root_timeline_count_bounded(usize::MAX).unwrap(), 2);
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
        store.create_timeline("a").unwrap();
        store.create_timeline("b").unwrap();
        store.create_timeline("c").unwrap();
        let list = store.list_timelines().unwrap();
        assert_eq!(list.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_batch_returns_empty() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let result = store.append(tl.id(), &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_range_filters_correctly() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).unwrap();
        let events = store
            .read(
                tl.id(),
                SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(4)),
            )
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parent_events_after_fork_invisible_to_child() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"before")])
            .unwrap();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").unwrap();
        store
            .append(tl.id(), &[make_draft(entity, b"after-fork")])
            .unwrap();
        let child_events = store.read(child.id(), SeqRange::all()).unwrap();
        assert!(!child_events
            .iter()
            .any(|e| e.payload.as_slice() == b"after-fork"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_with_file_path_creates_persistent_store() {
        // Exercises SqliteStore::open(path) — the non-memory path.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        // Keep the file alive through the temp binding; open with path.
        let mut store = SqliteStore::open(&path).expect("open by path should succeed");
        let tl = store.create_timeline("persistent").unwrap();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"hello")])
            .unwrap();
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"hello");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_includes_fork_metadata() {
        // Exercises the fork_point reconstruction in list_timelines.
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"e1"), make_draft(entity, b"e2")],
            )
            .unwrap();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").unwrap();

        let list = store.list_timelines().unwrap();
        assert_eq!(list.len(), 2);

        // Find the forked timeline in the list.
        let found = list.iter().find(|t| t.id() == child.id()).unwrap();
        let fork_point = found
            .meta
            .fork_point
            .expect("child should have fork_point set");
        assert_eq!(fork_point.0, tl.id());
        assert_eq!(fork_point.1, Seq::from_u64(1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_includes_fork_metadata() {
        // Exercises the fork_point reconstruction in get_timeline.
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        let child = store.fork(tl.id(), Seq::from_u64(1), "fork1").unwrap();

        let retrieved = store
            .get_timeline(child.id())
            .unwrap()
            .expect("child should exist");
        let fork_point = retrieved.meta.fork_point.expect("fork_point should be set");
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
            .unwrap();
        let tl = store.get_timeline(id).unwrap().expect("should exist");
        assert_eq!(tl.mode(), TimelineMode::Future);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_returns_none_for_unknown_id() {
        let store = new_store();
        let unknown = TimelineId::new();
        let result = store.get_timeline(unknown).unwrap();
        assert!(result.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_event_with_correlation_id_round_trips() {
        // Exercises parse_correlation_id via a stored event that has a correlation_id.
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"correlated");
        draft.correlation_id = Some(pos_core::CorrelationId::new());
        store.append(tl.id(), &[draft]).unwrap();
        let events = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].correlation_id.is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn explicit_wall_time_is_preserved() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let pinned = WallTime::from_micros(999_888_777);
        let draft = make_draft(entity, b"pinned").with_wall_time(pinned);
        let committed = store.append(tl.id(), &[draft]).unwrap();
        assert_eq!(committed[0].wall_time, pinned);
        let read_back = store.read(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(read_back[0].wall_time, pinned);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn absent_wall_time_yields_nonzero_timestamp() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let draft = make_draft(entity, b"no-wall-time");
        let committed = store.append(tl.id(), &[draft]).unwrap();
        assert!(committed[0].wall_time.as_micros() > 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn grandchild_fork_chain_stitches_correctly() {
        // Exercises compute_chain_hash_at and read for a multi-level fork chain.
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
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
            .unwrap();

        // Fork root at seq 2.
        let child = store.fork(root.id(), Seq::from_u64(2), "child").unwrap();

        // Append 2 events to child.
        store
            .append(
                child.id(),
                &[make_draft(entity, b"c1"), make_draft(entity, b"c2")],
            )
            .unwrap();

        // Fork child at seq 1 to get grandchild.
        let grandchild = store
            .fork(child.id(), Seq::from_u64(1), "grandchild")
            .unwrap();

        // Append to grandchild.
        store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .unwrap();

        // Grandchild logical view matches MemoryStore: r1, r2, c1, g1.
        let events = store.read(grandchild.id(), SeqRange::all()).unwrap();
        let payloads: Vec<&[u8]> = events.iter().map(|e| e.payload.as_slice()).collect();
        assert_eq!(payloads, vec![b"r1" as &[u8], b"r2", b"c1", b"g1"]);
        assert_eq!(events[0].seq.as_u64(), 1);
        assert_eq!(events[3].seq.as_u64(), 4);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_directory_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = SqliteStore::open(dir.path().to_str().unwrap());
        assert!(
            matches!(result, Err(CoreError::Storage(_))),
            "expected Storage error opening a directory path"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_objects_that_conflict_with_schema_initialization() {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(file.path()).unwrap();
            conn.execute("CREATE TABLE events (unexpected_column INTEGER)", [])
                .unwrap();
        }

        let result = SqliteStore::open(file.path().to_str().unwrap());
        let _ = result.err().unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_rejects_existing_utf16_databases_before_schema_use() {
        for encoding in ["UTF-16le", "UTF-16be"] {
            let file = tempfile::NamedTempFile::new().unwrap();
            {
                let conn = Connection::open(file.path()).unwrap();
                conn.execute_batch(&format!(
                    "PRAGMA encoding = '{encoding}';
                     CREATE TABLE imported_marker (value TEXT);"
                ))
                .unwrap();
            }

            let Err(error) = SqliteStore::open(file.path().to_str().unwrap()) else {
                panic!("UTF-16 database must be rejected");
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
            .unwrap();
        assert_eq!(encoding, "UTF-8");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_rejects_bad_chain_head_hash_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = ?1 WHERE id = ?2",
                rusqlite::params![vec![1u8, 2, 3], tl.id().to_string()],
            )
            .unwrap();
        let entity = EntityId::new();
        let err = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_event_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET event_id = 'not-a-ulid' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        let err = store.read(tl.id(), SeqRange::all()).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_entity_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET entity_id = 'bad-entity' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        let err = store.read(tl.id(), SeqRange::all()).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_causation_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.causation_id = Some(EventId::new());
        store.append(tl.id(), &[draft]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET causation_id = 'bad-cause' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        let err = store.read(tl.id(), SeqRange::all()).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_invalid_correlation_id_ulid() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.correlation_id = Some(pos_core::CorrelationId::new());
        store.append(tl.id(), &[draft]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET correlation_id = 'bad-corr' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        let err = store.read(tl.id(), SeqRange::all()).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_bad_payload_hash_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET payload_hash = ?1 WHERE timeline_id = ?2",
                rusqlite::params![vec![9u8, 9], tl.id().to_string()],
            )
            .unwrap();
        let err = store.read(tl.id(), SeqRange::all()).unwrap_err();
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
            .unwrap();
        let err = store.get_timeline(id).unwrap_err();
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
            .unwrap();
        let err = store.list_timelines().unwrap_err();
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
        let err = store.get_head_seq(TimelineId::new()).unwrap_err();
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
            .unwrap();
        let err = store.fork_chain(id).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_storage_err(result: Result<impl Sized, CoreError>) {
        match result {
            Err(CoreError::Storage(_)) => {}
            Err(e) => panic!("expected CoreError::Storage, got {e}"),
            Ok(_) => panic!("expected CoreError::Storage, got Ok"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store.conn.execute("DROP TABLE events", []).unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.conn.execute("DROP TABLE events", []).unwrap();
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
        store.conn.execute("DROP TABLE timelines", []).unwrap();
        assert_storage_err(store.create_timeline("main").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_fails_when_timelines_table_dropped() {
        let store = new_store();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    fn bounded_root_count_fails_when_timelines_table_dropped() {
        let store = new_store();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
        assert_storage_err(store.root_timeline_count_bounded(1).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_when_timelines_table_dropped() {
        let store = new_store();
        let id = TimelineId::new();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
        assert_storage_err(store.fork(tl.id(), Seq::ZERO, "branch").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
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
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET seq = 'not-an-int' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_event_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET event_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_entity_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET entity_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_event_type() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET event_type = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_payload() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET payload = 42 WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_wall_time() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET wall_time = 'not-an-int' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_causation_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.causation_id = Some(EventId::new());
        store.append(tl.id(), &[draft]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET causation_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_correlation_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut draft = make_draft(entity, b"x");
        draft.correlation_id = Some(pos_core::CorrelationId::new());
        store.append(tl.id(), &[draft]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET correlation_id = X'0102' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_schema_rejects_non_v1_schema_version() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
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
            store.read(tl.id(), SeqRange::all()).unwrap()[0].schema_version,
            SchemaVersion::V1
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_payload_hash() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET payload_hash = 'not-a-blob' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
        assert_storage_err(store.fork_chain(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_malformed_fork_chain_metadata() {
        let mut root_store = new_store();
        let root = root_store.create_timeline("root").unwrap();
        root_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = 0 WHERE id = ?1",
                params![root.id().to_string()],
            )
            .unwrap();
        let root_error = root_store.read(root.id(), SeqRange::all()).unwrap_err();
        assert!(root_error.to_string().contains("root timeline"));

        let mut child_store = new_store();
        let root = child_store.create_timeline("root").unwrap();
        let child = child_store.fork(root.id(), Seq::ZERO, "child").unwrap();
        child_store
            .conn
            .execute(
                "UPDATE timelines SET fork_seq = NULL WHERE id = ?1",
                params![child.id().to_string()],
            )
            .unwrap();
        let child_error = child_store.read(child.id(), SeqRange::all()).unwrap_err();
        assert!(child_error
            .to_string()
            .contains("missing its Fork sequence"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_forked_timeline_fails_when_parent_events_corrupt() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store
            .append(
                tl.id(),
                &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
            )
            .unwrap();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET payload = 42 WHERE timeline_id = ?1 AND seq = 1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(child.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_parent_events_corrupt() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET payload = 42 WHERE timeline_id = ?1 AND seq = 1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.fork(tl.id(), Seq::from_u64(1), "branch").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_for_unknown_parent_timeline() {
        let mut store = new_store();
        let unknown = TimelineId::new();
        assert_storage_err(store.fork(unknown, Seq::ZERO, "branch").map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_on_readonly_database_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let tl_id = {
            let mut store = SqliteStore::open(path.to_str().unwrap()).unwrap();
            let tl = store.create_timeline("main").unwrap();
            tl.id()
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut store = SqliteStore::open(path.to_str().unwrap()).unwrap();
        let entity = EntityId::new();
        let result = store.append(tl_id, &[make_draft(entity, b"x")]);
        assert_storage_err(result.map(|_| ()));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_fails_on_corrupted_database_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        std::fs::write(&path, b"not-a-sqlite-database").unwrap();
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
        let _ = result.err().unwrap();
    }

    #[test]
    fn sequence_validation_returns_query_errors() {
        let store = new_store();
        store.conn.execute("DROP TABLE events", []).unwrap();
        let _ = store.validate_event_sequence_invariant().unwrap_err();
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
            .unwrap();
    }

    #[test]
    fn read_own_events_returns_row_iteration_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("row-error").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .unwrap();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE events RENAME TO events_real", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW events AS SELECT timeline_id, seq, row_error() AS event_id,
                 entity_id, event_type, payload, wall_time, causation_id, correlation_id,
                 schema_version, payload_hash, signature FROM events_real",
                [],
            )
            .unwrap();
        let _ = store
            .read_own_events(timeline.id(), Seq::from_u64(1), None)
            .unwrap_err();
    }

    #[test]
    fn bounded_metadata_returns_row_iteration_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("bounded-row-error").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"x")])
            .unwrap();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE events RENAME TO events_real", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW events AS SELECT timeline_id, seq, typeof(row_error()) AS payload,
                 length(CAST(row_error() AS BLOB)), event_type
                 FROM events_real",
                [],
            )
            .unwrap();
        let _ = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
    }

    #[test]
    fn full_event_query_preparation_errors_are_storage_errors() {
        let store = new_store();
        store.conn.execute("DROP TABLE events", []).unwrap();
        let error = SqliteStore::read_own_events_limited_on(
            &store.conn,
            TimelineId::new(),
            Seq::ZERO,
            None,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn bounded_metadata_query_preparation_errors_are_storage_errors() {
        let store = new_store();
        store.conn.execute("DROP TABLE events", []).unwrap();
        let error = SqliteStore::read_own_events_bounded(
            &store.conn,
            TimelineId::new(),
            Seq::ZERO,
            Seq::ZERO,
            1,
            read_bounds(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("storage error"));
    }

    #[test]
    fn list_timelines_returns_row_iteration_errors() {
        let mut store = new_store();
        store.create_timeline("list-row-error").unwrap();
        install_row_error_function(&store);
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT id, row_error() AS name, mode, parent_id,
                 fork_seq, head_seq FROM timelines_real",
                [],
            )
            .unwrap();
        let _ = store.list_timelines().unwrap_err();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_on_wrong_type_head_seq() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        store
            .conn
            .execute(
                "UPDATE timelines SET head_seq = X'0102' WHERE id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
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
        let tl = store.create_timeline("main").unwrap();
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = 123 WHERE id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
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
        let tl = store.create_timeline("main").unwrap();
        FAIL_ROWS_NEXT.with(|f| f.set(true));
        let result = store.read(tl.id(), SeqRange::all());
        FAIL_ROWS_NEXT.with(|f| f.set(false));
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    fn list_fails_when_rows_next_injected() {
        let mut store = new_store();
        store.create_timeline("main").unwrap();
        FAIL_ROWS_NEXT.with(|f| f.set(true));
        let result = store.list_timelines();
        FAIL_ROWS_NEXT.with(|f| f.set(false));
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    fn statement_query_failures_are_mapped_at_each_production_caller() {
        let mut store = new_store();
        let timeline = store.create_timeline("query-failure").unwrap();
        store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"event")])
            .unwrap();

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

        let mut stmt = store.conn.prepare("SELECT ?1").unwrap();
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
            .unwrap();
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
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 'child', 'live', X'0102', 1, 0, ?2)",
                rusqlite::params![id.to_string(), genesis.as_bytes().as_slice()],
            )
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
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
            .unwrap();
        assert_storage_err(store.get_timeline(id).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_on_readonly_database_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let tl_id = {
            let mut store = SqliteStore::open(path.to_str().unwrap()).unwrap();
            let tl = store.create_timeline("main").unwrap();
            let entity = EntityId::new();
            store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
            tl.id()
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut store = SqliteStore::open(path.to_str().unwrap()).unwrap();
        assert_storage_err(store.fork(tl_id, Seq::from_u64(1), "branch").map(|_| ()));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
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
            .unwrap();
        let err = store.list_timelines().unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_chain_hash_at_fails_when_timelines_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store.conn.execute("DROP TABLE timelines", []).unwrap();
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
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute("ALTER TABLE events RENAME TO events_real", [])
            .unwrap();
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
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_update_head_fails_on_readonly_database_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let (tl_id, entity) = {
            let mut store = SqliteStore::open(path.to_str().unwrap()).unwrap();
            let tl = store.create_timeline("main").unwrap();
            (tl.id(), EntityId::new())
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut store = SqliteStore::open(path.to_str().unwrap()).unwrap();
        assert_storage_err(store.append(tl_id, &[make_draft(entity, b"x")]).map(|_| ()));
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_connection_is_query_only() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.conn.execute("PRAGMA query_only = ON", []).unwrap();
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
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS
                 SELECT id, name, mode, parent_id, fork_seq, head_seq
                 FROM timelines_real
                 WHERE (SELECT RAISE(ABORT, 'fail'))",
                [],
            )
            .unwrap();
        assert_storage_err(store.list_timelines().map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_timeline_fails_when_timelines_table_is_error_view() {
        let store = new_store();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT * FROM no_such_timelines_table",
                [],
            )
            .unwrap();
        assert_storage_err(store.get_timeline(TimelineId::new()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_timeline_head_update_blocked() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        store
            .conn
            .execute(
                "CREATE TRIGGER block_head_update BEFORE UPDATE ON timelines
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END",
                [],
            )
            .unwrap();
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
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        let mut store = SqliteStore::open(&path).unwrap();
        let tl = store.create_timeline("main").unwrap();
        let locker = Connection::open(&path).unwrap();
        locker.execute("BEGIN IMMEDIATE", []).unwrap();

        let entity = EntityId::new();
        let result = store.append(tl.id(), &[make_draft(entity, b"x")]);
        locker.execute("ROLLBACK", []).unwrap();
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_connection_already_in_txn() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let err = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap_err();
        let _ = store.conn.execute_batch("ROLLBACK");
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        // Returning true from the commit hook forces SQLite to convert COMMIT into rollback.
        store.conn.commit_hook(Some(|| true));
        let err = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_fails_when_chain_head_corrupted() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
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
            .unwrap();

        // append should fail when trying to get_chain_head
        let result = store.append(tl.id(), &[make_draft(entity, b"x")]);
        assert!(result.is_err());
        // The exact error type may vary, but the operation should fail
        match result.unwrap_err() {
            CoreError::Storage(_) | CoreError::Serialization(_) => {} // Expected for corrupt data
            other => panic!("Expected Storage or Serialization error, got {other:?}"),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_preserves_identity_sqlite() {
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = new_store();
        let tl = src.create_timeline("shared").unwrap();
        let entity = EntityId::new();
        let committed = src
            .append(
                tl.id(),
                &[make_draft(entity, b"one"), make_draft(entity, b"two")],
            )
            .unwrap();
        let export = export_timeline(&src, tl.id()).unwrap();
        let original_tl_id = tl.id();
        let original_ids: Vec<_> = committed.iter().map(|e| e.id).collect();

        let mut dst = new_store();
        let imported = import_timeline_with_id(&mut dst, export).unwrap();
        assert_eq!(imported.id(), original_tl_id);
        let events = dst.read(original_tl_id, SeqRange::all()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, original_ids[0]);
        assert_eq!(events[1].id, original_ids[1]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_removes_and_blocks_fork_parent() {
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
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
            .unwrap();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        let err = store.delete_timeline(root.id()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        store.delete_timeline(child.id()).unwrap();
        store.delete_timeline(root.id()).unwrap();
        assert!(store.get_timeline(root.id()).unwrap().is_none());
        let err = store.delete_timeline(root.id()).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_query_row_errors() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store
            .conn
            .execute_batch("DROP TABLE timelines; CREATE TABLE timelines (id TEXT)")
            .unwrap();
        let err = store.delete_timeline(tl.id()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_already_in_transaction() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let err = store.delete_timeline(tl.id()).unwrap_err();
        let _ = store.conn.execute_batch("ROLLBACK");
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    fn delete_timeline_fails_when_event_deletion_is_aborted() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store
            .append(tl.id(), &[make_draft(EntityId::new(), b"event")])
            .unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER abort_event_deletion
                 BEFORE DELETE ON events
                 BEGIN
                    SELECT RAISE(ABORT, 'event deletion blocked');
                 END",
            )
            .unwrap();
        assert_storage_err(store.delete_timeline(tl.id()));
    }

    #[test]
    fn delete_timeline_fails_when_append_identity_table_is_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store
            .conn
            .execute_batch("DROP TABLE append_identities")
            .unwrap();
        assert_storage_err(store.delete_timeline(tl.id()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store.conn.commit_hook(Some(|| true));
        let err = store.delete_timeline(tl.id()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_timelines_delete_aborted() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER deny_timeline_delete BEFORE DELETE ON timelines
                 BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
            )
            .unwrap();
        let err = store.delete_timeline(tl.id()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_validates_seq_hash_and_ids_sqlite() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .unwrap()
            .remove(0);

        store.append_committed(tl.id(), &[]).unwrap();

        // Collision / non-contiguous with head.
        let err = store
            .append_committed(tl.id(), std::slice::from_ref(&first))
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Gap.
        let mut gap = first.clone();
        gap.id = EventId::new();
        gap.seq = Seq::from_u64(3);
        gap.payload_hash = hash_payload(&gap.payload);
        let err = store.append_committed(tl.id(), &[gap]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Seq 0.
        let mut zero = first.clone();
        zero.id = EventId::new();
        zero.seq = Seq::ZERO;
        zero.payload_hash = hash_payload(&zero.payload);
        let err = store.append_committed(tl.id(), &[zero]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // Bad payload hash.
        let mut bad = first.clone();
        bad.id = EventId::new();
        bad.seq = Seq::from_u64(2);
        bad.payload_hash = pos_core::Hash::from_bytes([9u8; 32]);
        let err = store.append_committed(tl.id(), &[bad]).unwrap_err();
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
        let err = store.append_committed(tl.id(), &[a, b]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rolls_back_on_append_fail_sqlite() {
        use pos_core::store::{export_timeline, import_timeline_with_id};
        let mut src = new_store();
        let tl = src.create_timeline("shared").unwrap();
        let entity = EntityId::new();
        src.append(
            tl.id(),
            &[EventDraft::new(
                entity,
                Kind::new("t"),
                CanonicalBytes::from_vec(b"one".to_vec()),
            )],
        )
        .unwrap();
        let mut export = export_timeline(&src, tl.id()).unwrap();
        export.events[0].payload_hash = pos_core::Hash::from_bytes([1u8; 32]);
        let mut dst = new_store();
        let err = import_timeline_with_id(&mut dst, export).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(dst.get_timeline(tl.id()).unwrap().is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_and_append_committed_error_paths() {
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
        let err = store
            .create_timeline_with_meta(root.meta.clone())
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        let orphan = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "orphan");
        let err = store.create_timeline_with_meta(orphan).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        store.append_committed(root.id(), &[]).unwrap();
        let err = store.append_committed(TimelineId::new(), &[]).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        let entity = EntityId::new();
        let mut good = store
            .append(root.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        let err = store
            .append_committed(root.id(), &[good.clone()])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        good.seq = Seq::from_u64(99);
        good.payload_hash = pos_core::Hash::from_bytes([1u8; 32]);
        let err = store
            .append_committed(root.id(), &[good.clone()])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));

        good.seq = Seq::ZERO;
        good.payload_hash = hash_payload(&good.payload);
        let err = store.append_committed(root.id(), &[good]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_fork_child_succeeds() {
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .unwrap();
        let child_meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(1), "imported-child");
        // Preserve a chosen id by rebuilding meta (forked_from generates a new id).
        let chosen = TimelineMeta {
            id: TimelineId::new(),
            mode: child_meta.mode,
            name: child_meta.name,
            fork_point: child_meta.fork_point,
        };
        let chosen_id = chosen.id;
        let child = store.create_timeline_with_meta(chosen).unwrap();
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
            .unwrap();
        let err = store.create_timeline_with_meta(meta).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        good.id = EventId::new();
        good.seq = Seq::from_u64(2);
        good.payload_hash = hash_payload(&good.payload);
        store.conn.execute_batch("DROP TABLE events").unwrap();
        let err = store.append_committed(tl.id(), &[good]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_chain_head_corrupted() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
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
            .unwrap();
        let err = store.append_committed(tl.id(), &[good]).unwrap_err();
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
        let tl = store.create_timeline("tmp").unwrap();
        let ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        let err = store
            .append_committed(TimelineId::new(), &[ev])
            .unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_joins_outer_transaction() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        store.append_committed(tl.id(), &[ev]).unwrap();
        store.conn.execute_batch("ROLLBACK").unwrap();
        // Outer rollback undoes the joined append.
        let events = store.read_own(tl.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store.conn.commit_hook(Some(|| true));
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_insert_fails_on_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let path_s = path.to_str().unwrap();
        {
            let mut store = SqliteStore::open(path_s).unwrap();
            let _ = store.create_timeline("seed").unwrap();
        }
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();
        let mut store = SqliteStore::open(path_s).unwrap();
        let err = store
            .create_timeline_with_meta(TimelineMeta::root("x"))
            .unwrap_err();
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
            .unwrap();
        let err = store.append_committed(id, &[]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_preserves_optional_ids() {
        use pos_core::ids::CorrelationId;
        use pos_core::store::{export_timeline, import_timeline_with_id};

        let mut src = new_store();
        let tl = src.create_timeline("shared").unwrap();
        let entity = EntityId::new();
        let mut drafts = vec![make_draft(entity, b"one")];
        drafts[0].causation_id = Some(EventId::new());
        drafts[0].correlation_id = Some(CorrelationId::new());
        src.append(tl.id(), &drafts).unwrap();
        let export = export_timeline(&src, tl.id()).unwrap();
        assert!(export.events[0].causation_id.is_some());
        assert!(export.events[0].correlation_id.is_some());

        let mut dst = new_store();
        let imported = import_timeline_with_id(&mut dst, export).unwrap();
        let events = dst.read(imported.id(), SeqRange::all()).unwrap();
        assert!(events[0].causation_id.is_some());
        assert!(events[0].correlation_id.is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_row_get_type_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
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
            .unwrap();
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_chain_head_type_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
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
            .unwrap();
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_update_head_fails() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
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
            .unwrap();
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signature_roundtrips_on_append_committed_and_read() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"signed")])
            .unwrap()
            .remove(0);
        // Re-import onto a fresh timeline with a signature attached.
        let mut meta = TimelineMeta::root("imported");
        meta.id = TimelineId::new();
        let other = store.create_timeline_with_meta(meta).unwrap();
        ev.seq = Seq::from_u64(1);
        ev.id = EventId::new();
        ev.signature = Some(pos_core::Signature::from_bytes([7u8; 64]));
        ev.payload_hash = hash_payload(&ev.payload);
        store.append_committed(other.id(), &[ev.clone()]).unwrap();
        let read = store.read(other.id(), SeqRange::all()).unwrap();
        assert_eq!(read[0].signature, ev.signature);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_bad_signature_blob_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET signature = X'01' WHERE timeline_id = ?1",
                params![tl.id().to_string()],
            )
            .unwrap();
        let err = store.read(tl.id(), SeqRange::all()).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_own_fork_roundtrip_sqlite() {
        use pos_core::store::{export_timeline_own, import_timeline_with_id};

        let mut src = new_store();
        let root = src.create_timeline("root").unwrap();
        let entity = EntityId::new();
        src.append(root.id(), &[make_draft(entity, b"p1")]).unwrap();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").unwrap();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .unwrap();

        let mut dst = new_store();
        import_timeline_with_id(&mut dst, export_timeline_own(&src, root.id()).unwrap()).unwrap();
        let imported =
            import_timeline_with_id(&mut dst, export_timeline_own(&src, child.id()).unwrap())
                .unwrap();
        assert_eq!(
            imported.meta.fork_point,
            Some((root.id(), Seq::from_u64(1)))
        );
        let own = dst.read_own(child.id(), SeqRange::all()).unwrap();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_fork_beyond_head_sqlite() {
        let mut store = new_store();
        let root = store.create_timeline("root").unwrap();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .unwrap();
        let mut meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(99), "bad");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).unwrap_err();
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
        let created = src.create_timeline_with_meta(meta).unwrap();
        assert!(created.meta.name.is_none());

        let mut dst = new_store();
        let imported =
            import_timeline_with_id(&mut dst, export_timeline_own(&src, created.id()).unwrap())
                .unwrap();
        assert!(imported.meta.name.is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_outer_txn_already_open() {
        let mut store = new_store();
        store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .unwrap_err();
        let _ = store.conn.execute_batch("ROLLBACK");
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_commit_hook_aborts() {
        let mut store = new_store();
        store.conn.commit_hook(Some(|| true));
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_begin_fault_injected() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        FAIL_BEGIN_IMMEDIATE.with(|f| f.set(true));
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
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
            .unwrap_err();
        FAIL_IMPORT_VANISH.with(|f| f.set(false));
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_rolls_back_when_create_rejects_duplicate_id() {
        let mut store = new_store();
        let existing = store.create_timeline("root").unwrap();
        let err = store
            .import_committed(existing.meta.clone(), &[])
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
        // Outer txn rolled back; original timeline still present.
        assert!(store.get_timeline(existing.id()).unwrap().is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_committed_fails_when_get_storage_fault_injected() {
        let mut store = new_store();
        FAIL_IMPORT_GET_STORAGE.with(|f| f.set(true));
        let err = store
            .import_committed(TimelineMeta::root("x"), &[])
            .unwrap_err();
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
            .unwrap();
        let mut child = TimelineMeta::forked_from(broken_id, Seq::ZERO, "child");
        child.id = TimelineId::new();
        let err = store.create_timeline_with_meta(child).unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_propagates_get_timeline_storage_err() {
        let mut store = new_store();
        store.conn.execute_batch("DROP TABLE timelines").unwrap();
        let mut meta = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "x");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_missing_timeline_errors() {
        let store = new_store();
        let err = store
            .read_own(TimelineId::new(), SeqRange::all())
            .unwrap_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_closed_on_event_id_lookup_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
            .remove(0);
        ev.id = EventId::new();
        ev.seq = Seq::from_u64(2);
        ev.payload_hash = hash_payload(&ev.payload);
        store.conn.execute("DROP TABLE events", []).unwrap();
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_existing_event_id() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .unwrap()
            .remove(0);
        let mut dup = first.clone();
        dup.seq = Seq::from_u64(2);
        dup.payload = CanonicalBytes::from_vec(b"b".to_vec());
        dup.payload_hash = hash_payload(&dup.payload);
        // keep first.id — must hit the SELECT-found path in id_is_taken
        let err = store.append_committed(tl.id(), &[dup]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_on_wrong_type_signature() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET signature = 123 WHERE timeline_id = ?1",
                params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_propagates_get_timeline_storage_err() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        store
            .conn
            .execute("ALTER TABLE timelines RENAME TO timelines_real", [])
            .unwrap();
        store
            .conn
            .execute(
                "CREATE VIEW timelines AS SELECT * FROM no_such_timelines_table",
                [],
            )
            .unwrap();
        assert_storage_err(store.read_own(tl.id(), SeqRange::all()).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_fails_when_insert_trigger_aborts() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        let mut ev = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .unwrap()
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
            .unwrap();
        let err = store.append_committed(tl.id(), &[ev]).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_in_memory_with_hasher_uses_custom_hasher() {
        let mut store =
            SqliteStore::open_in_memory_with_hasher(Box::new(pos_crypto::chain::Blake3Hasher))
                .unwrap();
        let tl = store.create_timeline("hasher-test").unwrap();
        let drafts = [make_draft(EntityId::new(), b"payload")];
        let events = store.append(tl.id(), &drafts).unwrap();
        assert_eq!(events.len(), 1);
    }
    #[test]
    fn generic_committed_geographic_events_are_rejected_and_markers_withhold_reads() {
        let mut store = new_store();
        let ordinary = store.create_timeline("ordinary").unwrap();
        store
            .append(ordinary.id(), &[make_draft(EntityId::new(), b"ordinary")])
            .unwrap();
        assert!(store
            .read_event_by_id(ordinary.id(), EventId::new())
            .unwrap()
            .is_none());
        let timeline = store.create_timeline("geo").unwrap();
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
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        assert!(store.append_committed(timeline.id(), &[event]).is_err());
        store
            .conn
            .execute(
                "INSERT INTO geographic_presence (timeline_id, has_evidence) VALUES (?1, 1)",
                params![timeline.id().to_string()],
            )
            .unwrap();
        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .unwrap_err()
            .to_string()
            .contains("not found"));
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .unwrap_err()
            .to_string()
            .contains("not found"));
        let _ = store.list_timelines().unwrap();
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
            .unwrap_err()
            .to_string()
            .contains("not found"));
        assert!(store
            .create_timeline_with_meta(TimelineMeta::forked_from(
                timeline.id(),
                Seq::ZERO,
                "imported",
            ))
            .unwrap_err()
            .to_string()
            .contains("not found"));

        let mut broken = new_store();
        let parent = broken.create_timeline("broken-parent").unwrap();
        let broken_child = broken.fork(parent.id(), Seq::ZERO, "broken-child").unwrap();
        broken
            .conn
            .execute(
                "DELETE FROM timelines WHERE id = ?1",
                params![parent.id().to_string()],
            )
            .unwrap();
        assert!(broken
            .read_bounded(broken_child.id(), SeqRange::all(), read_bounds(1024))
            .unwrap_err()
            .to_string()
            .contains("not found"));

        assert!(store.delete_timeline(timeline.id()).is_err());
        assert_eq!(store.root_timeline_count_bounded(1).unwrap(), 1);
    }

    #[test]
    fn generic_read_fails_closed_when_event_sequence_is_malformed() {
        let mut store = new_store();
        let timeline = store.create_timeline("malformed-sequence").unwrap();
        let event = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"ordinary")])
            .unwrap()
            .pop()
            .expect("one Event");
        store
            .conn
            .execute(
                "UPDATE events SET seq = -1 WHERE event_id = ?1",
                params![event.id.to_string()],
            )
            .unwrap();

        assert!(store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
    }

    #[test]
    fn storage_error_paths_are_fail_closed() {
        let mut bounded_store = new_store();
        let bounded_timeline = bounded_store.create_timeline("bounded-error").unwrap();
        FAIL_BOUNDED_CHAIN_QUERY.with(|flag| flag.set(true));
        assert!(bounded_store
            .read_bounded(bounded_timeline.id(), SeqRange::all(), read_bounds(1))
            .is_err());
        FAIL_BOUNDED_CHAIN_QUERY.with(|flag| flag.set(false));

        let mut event_store = new_store();
        let event_timeline = event_store.create_timeline("event-error").unwrap();
        event_store
            .conn
            .execute("DROP TABLE timelines", [])
            .unwrap();
        assert!(event_store
            .read_event_by_id(event_timeline.id(), EventId::new())
            .is_err());

        let mut begin_store = new_store();
        let begin_parent = begin_store.create_timeline("begin-error").unwrap();
        begin_store.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(begin_store
            .fork(begin_parent.id(), Seq::ZERO, "child")
            .is_err());
        begin_store.conn.execute_batch("ROLLBACK").unwrap();

        let mut commit_store = new_store();
        let commit_parent = commit_store.create_timeline("commit-error").unwrap();
        commit_store.conn.commit_hook(Some(|| true));
        assert!(commit_store
            .fork(commit_parent.id(), Seq::ZERO, "child")
            .is_err());
        commit_store.conn.commit_hook::<fn() -> bool>(None);
        let timeline_count: i64 = commit_store
            .conn
            .query_row("SELECT COUNT(*) FROM timelines", [], |row| row.get(0))
            .unwrap();
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
        let list_timeline = list_store.create_timeline("list").unwrap();
        list_store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .unwrap();
        assert!(list_store.list_timelines().is_err());
        assert!(list_store.get_timeline(list_timeline.id()).is_err());

        let mut fork_store = new_store();
        let fork_parent = fork_store.create_timeline("fork").unwrap();
        fork_store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .unwrap();
        assert!(fork_store
            .fork(fork_parent.id(), Seq::ZERO, "child")
            .is_err());

        let mut delete_store = new_store();
        let delete_timeline = delete_store.create_timeline("delete").unwrap();
        delete_store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .unwrap();
        assert!(delete_store.delete_timeline(delete_timeline.id()).is_err());
    }

    fn geographic_presence_rejects_all_generic_read_and_append_paths() {
        let mut store = new_store();
        let timeline = store.create_timeline("read").unwrap();
        let retained = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"retained")])
            .unwrap()
            .pop()
            .expect("one retained Event");
        store
            .conn
            .execute("DROP TABLE geographic_presence", [])
            .unwrap();

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
        let privileged_timeline = privileged_store.create_timeline("privileged").unwrap();
        privileged_store
            .conn
            .execute("DROP TABLE events", [])
            .unwrap();
        assert!(privileged_store
            .read(privileged_timeline.id(), SeqRange::all())
            .is_err());

        let mut missing_timeline_store = new_store();
        let missing_timeline = missing_timeline_store.create_timeline("missing").unwrap();
        missing_timeline_store
            .conn
            .execute("DROP TABLE timelines", [])
            .unwrap();
        assert!(missing_timeline_store
            .read(missing_timeline.id(), SeqRange::all())
            .is_err());

        generic_reads_fail_closed_on_corrupt_or_missing_event_rows();
        geographic_presence_delete_failure_is_fail_closed();
    }

    fn generic_reads_fail_closed_on_corrupt_or_missing_event_rows() {
        let mut missing_store = new_store();
        let missing_timeline = missing_store.create_timeline("audit-missing").unwrap();
        missing_store.conn.execute("DROP TABLE events", []).unwrap();
        assert!(missing_store
            .read(missing_timeline.id(), SeqRange::all())
            .is_err());

        let mut corrupt_store = new_store();
        let corrupt_timeline = corrupt_store.create_timeline("audit-corrupt").unwrap();
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
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        corrupt_store
            .append_committed(corrupt_timeline.id(), std::slice::from_ref(&event))
            .unwrap();
        corrupt_store
            .conn
            .execute(
                "UPDATE events SET payload = 1 WHERE event_id = ?1",
                params![event.id.to_string()],
            )
            .unwrap();
        assert!(corrupt_store
            .read_bounded(corrupt_timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());

        corrupt_store
            .conn
            .execute(
                "UPDATE events SET seq = -1 WHERE event_id = ?1",
                params![event.id.to_string()],
            )
            .unwrap();
        assert!(corrupt_store
            .read_bounded(corrupt_timeline.id(), SeqRange::all(), read_bounds(1024))
            .is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_presence_delete_failure_is_fail_closed() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-marker").unwrap();
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
            }));
        assert!(store.delete_timeline(timeline.id()).is_err());
        store.conn.authorizer(
            None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
        );
    }
}
