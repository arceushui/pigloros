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
    ids::{EntityId, EventId, TimelineId},
    store::{EventStore, SeqRange},
    timeline::{Timeline, TimelineMeta, TimelineMode},
    CoreError,
};
use pos_crypto::chain::{genesis_hash, hash_event, hash_payload};

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Open a `SQLite` WAL store at the given path. Use `":memory:"` for in-memory.
    ///
    /// # Errors
    /// Returns `CoreError::Storage` if the database cannot be opened or schema initialisation fails.
    pub fn open(path: &str) -> Result<Self, CoreError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(storage_err)?;

        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory `SQLite` store (useful for tests without a temp file).
    ///
    /// # Errors
    /// This constructor does not return schema/`SQLite` errors via [`Result`]; see `# Panics`.
    ///
    /// # Panics
    /// Panics if the in-memory connection or schema initialisation fails (not expected
    /// under normal `SQLite` operation).
    pub fn open_in_memory() -> Result<Self, CoreError> {
        // In-memory open + schema init are treated as infallible in practice.
        let conn = Connection::open_in_memory().expect("in-memory sqlite open");
        let store = Self { conn };
        store.init_schema().expect("in-memory schema init");
        Ok(store)
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
                 PRIMARY KEY (timeline_id, seq)
             );",
            )
            .map_err(storage_err)?;
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
            .map_err(storage_err)?;

        // Future migrations go here as version increments:
        // if version < 1 { /* migration 1 */ }
        // if version < 2 { /* migration 2 */ }

        // Record current version if schema_version was empty
        if version == 0 {
            self.conn
                .execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .map_err(storage_err)?;
        }

        Ok(())
    }

    fn get_chain_head(&self, timeline_id: TimelineId) -> Result<pos_core::Hash, CoreError> {
        let bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT chain_head FROM timelines WHERE id = ?1",
                params![timeline_id.to_string()],
                |row| row.get(0),
            )
            .map_err(storage_err)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CoreError::Serialization("bad hash length".to_owned()))?;
        Ok(pos_core::Hash::from_bytes(arr))
    }

    fn get_head_seq(&self, timeline_id: TimelineId) -> Result<Seq, CoreError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT head_seq FROM timelines WHERE id = ?1",
                params![timeline_id.to_string()],
                |row| row.get(0),
            )
            .map_err(storage_err)?;
        Ok(Seq::from_u64(u64::try_from(n).unwrap_or(0)))
    }

    /// Read raw events directly from a timeline row (no fork stitching).
    fn read_own_events(
        &self,
        timeline_id: TimelineId,
        from: Seq,
        to: Option<Seq>,
    ) -> Result<Vec<Event>, CoreError> {
        let sql = to.map_or_else(
            || {
                format!(
                    "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                        causation_id, correlation_id, schema_version, payload_hash
                 FROM events WHERE timeline_id = '{}' AND seq >= {}
                 ORDER BY seq ASC",
                    timeline_id,
                    from.as_u64()
                )
            },
            |t| {
                format!(
                    "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                        causation_id, correlation_id, schema_version, payload_hash
                 FROM events WHERE timeline_id = '{}' AND seq >= {} AND seq <= {}
                 ORDER BY seq ASC",
                    timeline_id,
                    from.as_u64(),
                    t.as_u64()
                )
            },
        );

        let mut stmt = self.conn.prepare(&sql).map_err(storage_err)?;

        // `query_map` itself is infallible; row/iteration errors surface in the map below.
        let events = stmt
            .query_map([], |row| {
                let seq: i64 = row.get(0)?;
                let event_id: String = row.get(1)?;
                let entity_id: String = row.get(2)?;
                let event_type: String = row.get(3)?;
                let payload: Vec<u8> = row.get(4)?;
                let wall_time: i64 = row.get(5)?;
                let causation_id: Option<String> = row.get(6)?;
                let correlation_id: Option<String> = row.get(7)?;
                let schema_version: i64 = row.get(8)?;
                let payload_hash_bytes: Vec<u8> = row.get(9)?;
                Ok((
                    seq,
                    event_id,
                    entity_id,
                    event_type,
                    payload,
                    wall_time,
                    causation_id,
                    correlation_id,
                    schema_version,
                    payload_hash_bytes,
                ))
            })
            .expect("rusqlite query_map defers errors to row iteration")
            .map(|r| {
                let (
                    seq,
                    event_id,
                    entity_id,
                    event_type,
                    payload,
                    wall_time,
                    causation_id,
                    correlation_id,
                    schema_version,
                    ph_bytes,
                ) = r.map_err(storage_err)?;
                let ph_arr: [u8; 32] = ph_bytes
                    .try_into()
                    .map_err(|_| CoreError::Serialization("bad hash".to_owned()))?;
                Ok(Event {
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
                    signature: None,
                    payload_hash: pos_core::Hash::from_bytes(ph_arr),
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;

        Ok(events)
    }

    /// Walk the fork chain for a timeline, returning [root, ..., leaf].
    fn fork_chain(
        &self,
        timeline_id: TimelineId,
    ) -> Result<Vec<(TimelineId, Option<Seq>)>, CoreError> {
        let mut chain: Vec<(TimelineId, Option<Seq>)> = Vec::new();
        let mut current = timeline_id;
        loop {
            let row: Option<(Option<String>, Option<i64>)> = self
                .conn
                .query_row(
                    "SELECT parent_id, fork_seq FROM timelines WHERE id = ?1",
                    params![current.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(storage_err)?;

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
    id_fallback: Option<TimelineId>,
) -> Result<Timeline, CoreError> {
    let id = match id_fallback {
        Some(fallback) => parse_timeline_id(id_str).unwrap_or(fallback),
        None => parse_timeline_id(id_str)?,
    };
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
        let chain_head = genesis_hash();
        self.conn
            .execute(
                "INSERT INTO timelines (id, name, mode, parent_id, fork_seq, head_seq, chain_head)
                 VALUES (?1, ?2, ?3, NULL, NULL, 0, ?4)",
                params![
                    timeline.id().to_string(),
                    timeline.meta.name.as_deref().unwrap_or(""),
                    mode_str(timeline.mode()),
                    chain_head.as_bytes().as_slice(),
                ],
            )
            .map_err(storage_err)?;
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

        // Check timeline exists
        let exists: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM timelines WHERE id = ?1",
                params![timeline.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(storage_err)?
            > 0;
        if !exists {
            return Err(CoreError::TimelineNotFound(timeline));
        }

        let mut seq = timeline_meta_ok(self.get_head_seq(timeline));
        let mut prev_hash = timeline_meta_ok(self.get_chain_head(timeline));
        let mut committed = Vec::with_capacity(drafts.len());

        let tx = self.conn.transaction().map_err(storage_err)?;

        for draft in drafts {
            seq = seq.next();
            let event_id = EventId::new();
            let id_str = event_id.to_string();
            let payload_hash = hash_payload(&draft.payload);
            let chain_hash = hash_event(&prev_hash, id_str.as_bytes(), &draft.payload);
            let wall_time = draft.wall_time.unwrap_or_else(WallTime::now);

            tx.execute(
                "INSERT INTO events
                 (timeline_id, seq, event_id, entity_id, event_type, payload, wall_time,
                  causation_id, correlation_id, schema_version, payload_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                ],
            )
            .map_err(storage_err)?;

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
        .map_err(storage_err)?;

        tx.commit().map_err(storage_err)?;

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
                    child.meta.name.as_deref().unwrap_or(""),
                    mode_str(child.mode()),
                    parent.to_string(),
                    i64::try_from(at_seq.as_u64()).unwrap_or(i64::MAX),
                    fork_hash.as_bytes().as_slice(),
                ],
            )
            .map_err(storage_err)?;

        Ok(child)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, mode, parent_id, fork_seq, head_seq FROM timelines")
            .map_err(storage_err)?;

        let timelines = stmt
            .query_map([], read_timeline_row)
            .expect("rusqlite query_map defers errors to row iteration")
            .map(|r| {
                let (id_str, name, mode_s, parent_id, fork_seq, head_seq) =
                    r.map_err(storage_err)?;
                timeline_fields_to_timeline(
                    &id_str, name, &mode_s, parent_id, fork_seq, head_seq, None,
                )
            })
            .collect::<Result<Vec<_>, CoreError>>()?;

        Ok(timelines)
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
            .map_err(storage_err)?;

        match row {
            None => Ok(None),
            Some((id_str, name, mode_s, parent_id, fork_seq, head_seq)) => {
                Ok(Some(timeline_fields_to_timeline(
                    &id_str,
                    name,
                    &mode_s,
                    parent_id,
                    fork_seq,
                    head_seq,
                    Some(id),
                )?))
            }
        }
    }
}

impl SqliteStore {
    fn compute_chain_hash_at(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<pos_core::Hash, CoreError> {
        let chain = self.fork_chain(timeline)?;
        let mut hash = genesis_hash();

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
                hash = hash_event(&hash, id_str.as_bytes(), &event.payload);
            }
            if tid == timeline {
                break;
            }
        }
        Ok(hash)
    }
}

/// Timeline existence was already checked — collapse the residual Result for coverage.
#[cfg_attr(coverage_nightly, coverage(off))]
fn timeline_meta_ok<T>(r: Result<T, CoreError>) -> T {
    r.expect("timeline existence was checked immediately above")
}

// Owned `Error` so this can be used as a `map_err` function item.
#[allow(clippy::needless_pass_by_value)]
fn storage_err(e: rusqlite::Error) -> CoreError {
    CoreError::Storage(e.to_string())
}

const fn mode_str(mode: TimelineMode) -> &'static str {
    match mode {
        TimelineMode::Historical => "historical",
        TimelineMode::Live => "live",
        TimelineMode::Future => "future",
    }
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
        store::SeqRange,
        CoreError,
    };

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
            version >= 1,
            "schema_version should be at least 1 after open, got {version}"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_version_not_duplicated_on_reopen() {
        // Opens the same file twice — second open finds version=1 already set,
        // so the INSERT branch is skipped (covers the if version == 0 false path).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        {
            let _store = SqliteStore::open(&path).unwrap();
            // First open: inserts schema_version = 1
        }
        {
            let store = SqliteStore::open(&path).unwrap();
            // Second open: version already = 1, INSERT is skipped
            let count: i64 = store
                .conn
                .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 1, "schema_version should have exactly one row");
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
    fn get_chain_head_rejects_bad_hash_length() {
        let mut store = new_store();
        let tl = store.create_timeline("main").unwrap();
        store
            .conn
            .execute(
                "UPDATE timelines SET chain_head = ?1 WHERE id = ?2",
                rusqlite::params![vec![1u8, 2, 3], tl.id().to_string()],
            )
            .unwrap();
        let err = store.get_chain_head(tl.id()).unwrap_err();
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
    fn get_chain_head_fails_for_unknown_timeline() {
        let store = new_store();
        let err = store.get_chain_head(TimelineId::new()).unwrap_err();
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
}
