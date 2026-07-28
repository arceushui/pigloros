//! `SQLite` WAL append-only `EventStore` backend.
//!
//! Events are stored in a single table, append-only.
//! Batched transactions ensure throughput >= 2k ev/s on `SQLite`-WAL.
//! Fork is copy-on-write: only a metadata row is inserted at fork time (O(1)).
//! Child reads stitch parent events up to `fork_seq` with child events.

use rusqlite::{params, Connection, OpenFlags};

use pos_core::{
    clock::{Seq, WallTime},
    event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
    hasher::Hasher,
    ids::{EntityId, EventId, TimelineId},
    store::{EventReadBounds, EventStore, SeqRange},
    timeline::{Timeline, TimelineMeta, TimelineMode},
    CoreError,
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
}

pub struct SqliteStore {
    conn: Connection,
    hasher: Box<dyn Hasher>,
}

impl SqliteStore {
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

        let store = Self { conn, hasher };
        store.init_schema()?;
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

    fn query_prepared<'conn>(
        stmt: &'conn mut rusqlite::Statement<'_>,
    ) -> Result<rusqlite::Rows<'conn>, CoreError> {
        let raw = {
            #[cfg(test)]
            {
                if FAIL_STMT_QUERY.with(std::cell::Cell::get) {
                    Err(rusqlite::Error::InvalidQuery)
                } else {
                    stmt.query([])
                }
            }
            #[cfg(not(test))]
            {
                stmt.query([])
            }
        };
        raw.map_err(|e| CoreError::Storage(e.to_string()))
    }

    fn init_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER NOT NULL
             );
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
                 schema_version INTEGER NOT NULL,
                 payload_hash BLOB NOT NULL,
                 signature   BLOB,
                 PRIMARY KEY (timeline_id, seq)
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);",
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        self.run_migrations()
    }

    fn run_migrations(&self) -> Result<(), CoreError> {
        // Get current schema version (0 if table is empty)
        let version: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        // Always ensure v2 columns/indexes exist before stamping the version.
        // Covers: fresh DBs (CREATE TABLE already has them — ALTER is no-op-ish),
        // and legacy DBs that somehow lack a schema_version row (version == 0)
        // while still having a pre-v2 events table without `signature`.
        if version < 2 {
            self.migrate_events_to_v2()?;
            if version == 0 {
                self.conn
                    .execute("INSERT INTO schema_version (version) VALUES (2)", [])
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
            } else {
                self.conn
                    .execute("UPDATE schema_version SET version = 2", [])
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Add `signature` column + unique `event_id` index (idempotent where possible).
    fn migrate_events_to_v2(&self) -> Result<(), CoreError> {
        // Prefer probing the schema over matching error strings.
        let has_signature = self
            .conn
            .prepare("SELECT signature FROM events LIMIT 0")
            .is_ok();
        if !has_signature {
            self.conn
                .execute("ALTER TABLE events ADD COLUMN signature BLOB", [])
                .map_err(|e| CoreError::Storage(e.to_string()))?;
        }
        self.conn
            .execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)",
                [],
            )
            .map_err(|e| {
                CoreError::Storage(format!(
                    "cannot enforce unique event_id index (duplicate EventIds in existing data?): {e}"
                ))
            })?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_run_migrations(&self) -> Result<(), CoreError> {
        self.run_migrations()
    }

    fn get_head_seq(&self, timeline_id: TimelineId) -> Result<Seq, CoreError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT head_seq FROM timelines WHERE id = ?1",
                params![timeline_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
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
        let sql = to.map_or_else(
            || {
                format!(
                    "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                        causation_id, correlation_id, schema_version, payload_hash, signature
                 FROM events WHERE timeline_id = '{}' AND seq >= {}
                 ORDER BY seq ASC",
                    timeline_id,
                    from.as_u64()
                )
            },
            |t| {
                format!(
                    "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                        causation_id, correlation_id, schema_version, payload_hash, signature
                 FROM events WHERE timeline_id = '{}' AND seq >= {} AND seq <= {}
                 ORDER BY seq ASC",
                    timeline_id,
                    from.as_u64(),
                    t.as_u64()
                )
            },
        );

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let mut rows = Self::query_prepared(&mut stmt)?;
        let mut events = Vec::new();
        loop {
            let next = {
                #[cfg(test)]
                {
                    if FAIL_ROWS_NEXT.with(std::cell::Cell::get) {
                        Err(rusqlite::Error::InvalidQuery)
                    } else {
                        rows.next()
                    }
                }
                #[cfg(not(test))]
                {
                    rows.next()
                }
            };
            let row = match next.map_err(|e| CoreError::Storage(e.to_string())) {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(e) => return Err(e),
            };
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
            let schema_version: i64 = row.get(8).map_err(|e| CoreError::Storage(e.to_string()))?;
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
                schema_version: SchemaVersion::new(u32::try_from(schema_version).unwrap_or(0)),
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
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        let sql = format!(
            "SELECT length(payload), length(CAST(event_type AS BLOB))
             FROM events WHERE timeline_id = '{}' AND seq >= {} AND seq <= {}
             ORDER BY seq ASC",
            timeline_id,
            from.as_u64(),
            to.as_u64()
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(stmt) => stmt,
            Err(error) => {
                let message = error.to_string();
                return Err(CoreError::Storage(message));
            }
        };
        let mut rows = stmt.raw_query();
        let mut field_sizes = Vec::new();
        loop {
            let next = {
                #[cfg(test)]
                {
                    if FAIL_ROWS_NEXT.with(std::cell::Cell::get) {
                        Err(rusqlite::Error::InvalidQuery)
                    } else {
                        rows.next()
                    }
                }
                #[cfg(not(test))]
                {
                    rows.next()
                }
            };
            match next {
                Ok(Some(row)) => field_sizes.push((
                    row.get(0)
                        .expect("length(non-null SQLite BLOB) returns an integer"),
                    row.get(1)
                        .expect("length(CAST(non-null SQLite TEXT AS BLOB)) returns an integer"),
                )),
                Ok(None) => break,
                Err(error) => {
                    let message = error.to_string();
                    return Err(CoreError::Storage(message));
                }
            }
        }

        for (stored_payload_size, stored_event_type_size) in field_sizes {
            let payload_size = sqlite_usize_or_max(stored_payload_size);
            if payload_size > bounds.max_payload_bytes {
                return Err(CoreError::PayloadTooLarge { size: payload_size });
            }
            let event_type_size = sqlite_usize_or_max(stored_event_type_size);
            if event_type_size > bounds.max_event_type_bytes {
                return Err(CoreError::EventMetadataTooLarge {
                    field: "event_type",
                    size: event_type_size,
                });
            }
        }

        #[cfg(test)]
        BOUNDED_EVENT_QUERIES.with(|queries| queries.set(queries.get() + 1));
        Self::read_own_events_on(conn, timeline_id, from, Some(to))
    }

    fn own_event_count(
        conn: &Connection,
        timeline_id: TimelineId,
        to: Option<Seq>,
    ) -> Result<u64, CoreError> {
        let result = match to {
            Some(to) => conn.query_row(
                "SELECT count(*) FROM events WHERE timeline_id = ?1 AND seq <= ?2",
                params![
                    timeline_id.to_string(),
                    i64::try_from(to.as_u64()).unwrap_or(i64::MAX)
                ],
                read_first_i64,
            ),
            None => conn.query_row(
                "SELECT count(*) FROM events WHERE timeline_id = ?1",
                params![timeline_id.to_string()],
                read_first_i64,
            ),
        };
        let count = match result {
            Ok(count) => count,
            Err(error) => return Err(CoreError::Storage(error.to_string())),
        };
        Ok(sqlite_usize_or_max(count) as u64)
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
        let chain = Self::fork_chain_on(&tx, timeline_id)?;
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(u64::MAX, Seq::as_u64);
        let mut logical_offset = 0_u64;
        let mut selected = Vec::new();

        for (index, &(segment_id, _)) in chain.iter().enumerate() {
            let segment_cap = chain.get(index + 1).and_then(|(_, fork)| *fork);
            let segment_len = Self::own_event_count(&tx, segment_id, segment_cap)?;
            let segment_start = logical_offset.saturating_add(1);
            let segment_end = logical_offset.saturating_add(segment_len);
            let selected_start = from.max(segment_start);
            let selected_end = to.min(segment_end);

            if selected_start <= selected_end {
                let raw_from = Seq::from_u64(selected_start - logical_offset);
                let raw_to = Seq::from_u64(selected_end - logical_offset);
                let mut events =
                    Self::read_own_events_bounded(&tx, segment_id, raw_from, raw_to, bounds)?;
                for event in &mut events {
                    event.seq = Seq::from_u64(logical_offset.saturating_add(event.seq.as_u64()));
                }
                selected.extend(events);
            }
            logical_offset = segment_end;
            if logical_offset >= to {
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
        let mut chain: Vec<(TimelineId, Option<Seq>)> = Vec::new();
        let mut current = timeline_id;
        loop {
            let row: Option<(Option<String>, Option<i64>)> = conn
                .query_row(
                    "SELECT parent_id, fork_seq FROM timelines WHERE id = ?1",
                    params![current.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| CoreError::Storage(e.to_string()))?;

            match row {
                None => return Err(CoreError::TimelineNotFound(current)),
                Some((None, _)) => {
                    chain.push((current, None));
                    break;
                }
                Some((Some(parent_str), fork_seq)) => {
                    let fork = fork_seq.map(|s| Seq::from_u64(u64::try_from(s).unwrap_or(0)));
                    chain.push((current, fork));
                    current = parse_timeline_id(&parent_str)?;
                }
            }
        }
        chain.reverse();
        Ok(chain)
    }
}

type TimelineRow = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<i64>,
    i64,
);

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
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
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
        if drafts.is_empty() {
            return Ok(Vec::new());
        }

        // Load head seq + chain head in one existence check (avoids a second
        // get_head_seq/? path that cannot fail once the row is known to exist).
        let (mut seq, mut prev_hash) = match self.conn.query_row(
            "SELECT head_seq, chain_head FROM timelines WHERE id = ?1",
            params![timeline.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
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
        let mut committed = Vec::with_capacity(drafts.len());

        let tx = self
            .conn
            .transaction()
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        for draft in drafts {
            seq = seq.next();
            let event_id = EventId::new();
            let id_str = event_id.to_string();
            let payload_hash = self.hasher.hash_payload(&draft.payload);
            let chain_hash = self
                .hasher
                .hash_event(&prev_hash, id_str.as_bytes(), &draft.payload);
            let wall_time = draft.wall_time.unwrap_or_else(WallTime::now);

            tx.execute(
                "INSERT INTO events
                 (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                  causation_id, correlation_id, schema_version, payload_hash, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    timeline.to_string(),
                    i64::try_from(seq.as_u64()).unwrap_or(i64::MAX),
                    id_str,
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
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;

            committed.push(Event {
                id: event_id,
                entity: draft.entity,
                event_type: draft.event_type.clone(),
                payload: draft.payload.clone(),
                wall_time,
                seq,
                causation_id: draft.causation_id,
                correlation_id: draft.correlation_id,
                schema_version: draft.schema_version,
                signature: None,
                payload_hash,
            });

            prev_hash = chain_hash;
        }

        // Update head and chain hash
        tx.execute(
            "UPDATE timelines SET head_seq = ?1, chain_head = ?2 WHERE id = ?3",
            params![
                i64::try_from(seq.as_u64()).unwrap_or(i64::MAX),
                prev_hash.as_bytes().as_slice(),
                timeline.to_string(),
            ],
        )
        .map_err(|e| CoreError::Storage(e.to_string()))?;

        tx.commit().map_err(|e| CoreError::Storage(e.to_string()))?;

        Ok(committed)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
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
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.read_logical_bounded(timeline, range, bounds)
    }

    fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        // Ensure timeline exists (and surface TimelineNotFound for missing ids).
        let _ = self
            .get_timeline(timeline)?
            .ok_or(CoreError::TimelineNotFound(timeline))?;
        self.read_own_events(timeline, range.from, range.to)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
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

        self.conn
            .execute(
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

        Ok(child)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, mode, parent_id, fork_seq, head_seq FROM timelines")
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        let mut rows = Self::query_prepared(&mut stmt)?;
        let mut timelines = Vec::new();
        loop {
            let next = {
                #[cfg(test)]
                {
                    if FAIL_ROWS_NEXT.with(std::cell::Cell::get) {
                        Err(rusqlite::Error::InvalidQuery)
                    } else {
                        rows.next()
                    }
                }
                #[cfg(not(test))]
                {
                    rows.next()
                }
            };
            let row = match next.map_err(|e| CoreError::Storage(e.to_string())) {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(e) => return Err(e),
            };
            let (id_str, name, mode_s, parent_id, fork_seq, head_seq) =
                read_timeline_row(row).map_err(|e| CoreError::Storage(e.to_string()))?;
            timelines.push(timeline_fields_to_timeline(
                &id_str, name, &mode_s, parent_id, fork_seq, head_seq,
            )?);
        }

        Ok(timelines)
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
        let stop_after = maximum.saturating_add(1);
        let limit = i64::try_from(stop_after).unwrap_or(i64::MAX);
        self.conn
            .query_row(
                "SELECT count(*) FROM (
                    SELECT 1 FROM timelines WHERE parent_id IS NULL LIMIT ?1
                 )",
                params![limit],
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
            Some((id_str, name, mode_s, parent_id, fork_seq, head_seq)) => Ok(Some(
                timeline_fields_to_timeline(&id_str, name, &mode_s, parent_id, fork_seq, head_seq)?,
            )),
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
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        let id_str = id.to_string();
        // Refuse delete while child forks still reference this timeline.
        let child_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM timelines WHERE parent_id = ?1",
                params![id_str],
                |row| row.get(0),
            )
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        if child_count > 0 {
            return Err(CoreError::Storage(
                "cannot delete timeline that still has forks".to_owned(),
            ));
        }

        let tx = self
            .conn
            .transaction()
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM events WHERE timeline_id = ?1", params![id_str])
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let deleted = tx
            .execute("DELETE FROM timelines WHERE id = ?1", params![id_str])
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        if deleted == 0 {
            return Err(CoreError::TimelineNotFound(id));
        }
        tx.commit().map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn chain_hash_at(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<pos_core::Hash, CoreError> {
        self.compute_chain_hash_at(timeline, at_seq)
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
        EventReadBounds {
            max_payload_bytes,
            max_event_type_bytes: usize::MAX,
        }
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
    fn bounded_read_propagates_chain_and_count_errors() {
        let mut store = new_store();
        let error = store
            .read_bounded(TimelineId::new(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        assert!(matches!(error, CoreError::TimelineNotFound(_)));

        let timeline = store.create_timeline("missing-events").unwrap();
        store.conn.execute("DROP TABLE events", []).unwrap();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        assert!(matches!(error, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_propagates_snapshot_and_metadata_query_errors() {
        let mut store = new_store();
        let timeline = store.create_timeline("snapshot").unwrap();
        store.conn.execute_batch("BEGIN").unwrap();
        let error = store
            .read_bounded(timeline.id(), SeqRange::all(), read_bounds(1))
            .unwrap_err();
        store.conn.execute_batch("ROLLBACK").unwrap();
        assert!(matches!(error, CoreError::Storage(_)));

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
        assert!(matches!(error, CoreError::Storage(_)));

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
        assert!(matches!(error, CoreError::Storage(_)));
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
                EventReadBounds {
                    max_payload_bytes: 1,
                    max_event_type_bytes: 4,
                },
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
    fn schema_version_is_set_after_open() {
        let store = new_store();
        let version: i64 = store
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .expect("schema_version query should succeed");
        assert!(
            version >= 2,
            "schema_version should be at least 2 after open, got {version}"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_not_duplicated_on_reopen() {
        // Opens the same file twice — second open finds version already set,
        // so the INSERT branch is skipped (covers the version == 0 false path).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        {
            let _store = SqliteStore::open(&path).unwrap();
            // First open: inserts schema_version = 2
        }
        {
            let store = SqliteStore::open(&path).unwrap();
            // Second open: version already = 2, INSERT is skipped
            let count: i64 = store
                .conn
                .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "schema_version should have exactly one row");
            let version: i64 = store
                .conn
                .query_row(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(version, 2);
        }
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
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    fn reopen_fails_when_schema_version_query_breaks() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        {
            let _store = SqliteStore::open(&path).unwrap();
        }
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("DROP TABLE schema_version", []).unwrap();
            conn.execute(
                "CREATE VIEW schema_version AS SELECT (SELECT RAISE(ABORT, 'fail')) AS version",
                [],
            )
            .unwrap();
        }
        assert_storage_err(SqliteStore::open(&path).map(|_| ()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reopen_fails_when_schema_version_insert_breaks() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        {
            let _store = SqliteStore::open(&path).unwrap();
        }
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("DROP TABLE schema_version", []).unwrap();
            conn.execute(
                "CREATE TABLE schema_version (version INTEGER NOT NULL CHECK (version > 100))",
                [],
            )
            .unwrap();
        }
        assert_storage_err(SqliteStore::open(&path).map(|_| ()));
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
    fn read_fails_on_wrong_type_schema_version() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        let entity = EntityId::new();
        store.append(tl.id(), &[make_draft(entity, b"x")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE events SET schema_version = 'not-an-int' WHERE timeline_id = ?1",
                rusqlite::params![tl.id().to_string()],
            )
            .unwrap();
        assert_storage_err(store.read(tl.id(), SeqRange::all()).map(|_| ()));
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
    fn read_fails_when_query_injected() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        FAIL_STMT_QUERY.with(|f| f.set(true));
        let result = store.read(tl.id(), SeqRange::all());
        FAIL_STMT_QUERY.with(|f| f.set(false));
        assert_storage_err(result.map(|_| ()));
    }

    #[test]
    fn list_timelines_fails_when_query_injected() {
        let store = new_store();
        FAIL_STMT_QUERY.with(|f| f.set(true));
        let result = store.list_timelines();
        FAIL_STMT_QUERY.with(|f| f.set(false));
        assert_storage_err(result.map(|_| ()));
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
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delete_timeline_fails_when_events_table_dropped() {
        let mut store = new_store();
        let tl = store.create_timeline("t").unwrap();
        store.conn.execute_batch("DROP TABLE events").unwrap();
        let err = store.delete_timeline(tl.id()).unwrap_err();
        assert!(matches!(err, CoreError::Storage(_)));
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
    fn migrates_v1_schema_to_v2_with_signature_column() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (1);
                 CREATE TABLE timelines (
                     id TEXT PRIMARY KEY, name TEXT, mode TEXT NOT NULL,
                     parent_id TEXT, fork_seq INTEGER, head_seq INTEGER NOT NULL DEFAULT 0,
                     chain_head BLOB NOT NULL
                 );
                 CREATE TABLE events (
                     timeline_id TEXT NOT NULL, seq INTEGER NOT NULL, event_id TEXT NOT NULL,
                     entity_id TEXT NOT NULL, event_type TEXT NOT NULL, payload BLOB NOT NULL,
                     wall_time INTEGER NOT NULL, causation_id TEXT, correlation_id TEXT,
                     schema_version INTEGER NOT NULL, payload_hash BLOB NOT NULL,
                     PRIMARY KEY (timeline_id, seq)
                 );",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&path).unwrap();
        let version: i64 = store
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 2);
        // signature column must exist after migration
        store
            .conn
            .prepare("SELECT signature FROM events LIMIT 0")
            .unwrap();
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
    fn migrates_legacy_events_table_when_schema_version_missing() {
        // version == 0 path must still ALTER a pre-v2 events table (no signature column).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE schema_version (version INTEGER NOT NULL);
                 CREATE TABLE timelines (
                     id TEXT PRIMARY KEY, name TEXT, mode TEXT NOT NULL,
                     parent_id TEXT, fork_seq INTEGER, head_seq INTEGER NOT NULL DEFAULT 0,
                     chain_head BLOB NOT NULL
                 );
                 CREATE TABLE events (
                     timeline_id TEXT NOT NULL, seq INTEGER NOT NULL, event_id TEXT NOT NULL,
                     entity_id TEXT NOT NULL, event_type TEXT NOT NULL, payload BLOB NOT NULL,
                     wall_time INTEGER NOT NULL, causation_id TEXT, correlation_id TEXT,
                     schema_version INTEGER NOT NULL, payload_hash BLOB NOT NULL,
                     PRIMARY KEY (timeline_id, seq)
                 );",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&path).unwrap();
        let version: i64 = store
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 2);
        store
            .conn
            .prepare("SELECT signature FROM events LIMIT 0")
            .unwrap();
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
    fn migrate_v2_ignores_duplicate_signature_column() {
        let store = new_store();
        store
            .conn
            .execute("UPDATE schema_version SET version = 1", [])
            .unwrap();
        store.test_run_migrations().unwrap();
        let version: i64 = store
            .conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn migrate_v2_fails_when_alter_is_not_duplicate_column() {
        let store = new_store();
        store
            .conn
            .execute("UPDATE schema_version SET version = 1", [])
            .unwrap();
        store.conn.execute("DROP TABLE events", []).unwrap();
        store
            .conn
            .execute("CREATE VIEW events AS SELECT 1 AS x", [])
            .unwrap();
        assert_storage_err(store.test_run_migrations());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn migrate_v2_fails_when_index_create_aborts() {
        let store = new_store();
        store
            .conn
            .execute("UPDATE schema_version SET version = 1", [])
            .unwrap();
        // Force index creation to fail: leave a non-unique duplicate event_id first.
        // Drop the unique index so migration will recreate it, then insert dup ids.
        store
            .conn
            .execute("DROP INDEX IF EXISTS idx_events_event_id", [])
            .unwrap();
        let tl = TimelineId::new();
        let genesis = pos_crypto::chain::genesis_hash();
        store
            .conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, 't', 'live', NULL, NULL, 0, ?2)",
                params![tl.to_string(), genesis.as_bytes().as_slice()],
            )
            .unwrap();
        let eid = EventId::new().to_string();
        for seq in 1..=2 {
            store
                .conn
                .execute(
                    "INSERT INTO events
                     (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                      causation_id, correlation_id, schema_version, payload_hash, signature)
                     VALUES (?1, ?2, ?3, ?4, 't', X'00', 0, NULL, NULL, 1, ?5, NULL)",
                    params![
                        tl.to_string(),
                        seq,
                        eid,
                        EntityId::new().to_string(),
                        [0u8; 32].as_slice(),
                    ],
                )
                .unwrap();
        }
        assert_storage_err(store.test_run_migrations());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn migrate_v2_fails_when_version_update_aborts() {
        let store = new_store();
        store
            .conn
            .execute("UPDATE schema_version SET version = 1", [])
            .unwrap();
        store.conn.execute("DROP TABLE schema_version", []).unwrap();
        store
            .conn
            .execute(
                "CREATE TABLE schema_version (version INTEGER NOT NULL CHECK (version < 2))",
                [],
            )
            .unwrap();
        store
            .conn
            .execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
        assert_storage_err(store.test_run_migrations());
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
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_upcast_on_sqlite_default_noop() {
        let mut store = new_store();
        let tl = store.create_timeline("upcast-test").unwrap();
        let drafts = [make_draft(EntityId::new(), b"payload")];
        store.append(tl.id(), &drafts).unwrap();
        let upcasters = pos_core::UpcasterRegistry::new();
        let schema_versions = pos_core::SchemaVersionMap::new();
        let store_ref: &dyn pos_core::EventStore = &store;
        let result = store_ref
            .read_upcast(
                tl.id(),
                pos_core::store::SeqRange::all(),
                &upcasters,
                &schema_versions,
            )
            .unwrap();
        assert!(!result.is_empty());
    }
}
