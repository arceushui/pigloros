//! `SQLite` trusted-clock authority adapter.
//!
//! The reservation connection commits reservations, latches and
//! acknowledgements with `synchronous=FULL`. The guard connection holds the
//! file's single write lock from `BEGIN IMMEDIATE` until teardown and never
//! commits. Both connections open the same authority file: the `SqliteStore`
//! file that holds the ARD1 artifact catalog (ADR-112 §2, ADR-093), whose
//! entry count gates the one-time row migration.
//!
//! The acknowledgement table is append-only: triggers abort every `UPDATE`,
//! `DELETE` and replacing `INSERT` on it.

use super::fresh_clock_domain;
use crate::sqlite::{normalize_schema_sql, sqlite_artifact_registration_schema_exists};
use pos_core::trusted_clock::{
    ReleaseGuardPortV1, TrustedClockAcknowledgementRowV1, TrustedClockHighWaterRowV1,
    TrustedClockOverrunLatchRowV1, TrustedClockPortErrorV1, TrustedClockRowsV1,
    TrustedClockStorePortV1, TRUSTED_CLOCK_WAIT_BUDGET,
};
use pos_core::CoreError;
use rusqlite::types::Value::{Blob, Integer as Int};
use rusqlite::types::{FromSql, Value};
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, Row, Statement};
use std::time::Duration;

type PortResult<T> = Result<T, TrustedClockPortErrorV1>;

const SYNCHRONOUS_FULL: i64 = 2;

/// The ARD1 catalog entry count, read inside the reservation transaction.
const CATALOG_ENTRIES: &str = "SELECT count(*) FROM artifact_registrations";

const NOT_A_STORE: &str = "trusted-clock authority requires an initialized SqliteStore \
    authority file holding the complete ARD1 artifact catalog";

/// Statement that reads one schema object's stored definition.
const STORED_SQL: &str = "SELECT sql FROM sqlite_master WHERE name = ?1";

const TAMPERED_SCHEMA: &str = "trusted-clock schema differs from its reviewed definition";

/// The two row tables, the append-only acknowledgement table and its three
/// guard triggers, as `(name, CREATE statement)`. `CREATE ... IF NOT EXISTS`
/// would keep a weaker object of the same name, so `open` creates each
/// missing object and otherwise requires its stored definition to equal this
/// one under the store's schema normalization.
///
/// `normalize_schema_sql` lowercases the whole statement and strips all of
/// its whitespace, string literals included, so a reviewed definition must
/// not rely on a literal's case or spacing. The only literals here are the
/// triggers' fixed `RAISE` messages, which carry no semantics.
const REVIEWED_SCHEMA: [(&str, &str); 6] = [
    (
        "trusted_clock_high_water",
        "CREATE TABLE trusted_clock_high_water (
    singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version        INTEGER NOT NULL,
    clock_domain          BLOB    NOT NULL CHECK (length(clock_domain) = 16),
    high_water_micros     INTEGER NOT NULL CHECK (high_water_micros >= 0),
    reserved_until_micros INTEGER NOT NULL CHECK (reserved_until_micros >= high_water_micros),
    reservation_seq       INTEGER NOT NULL CHECK (reservation_seq >= 0)
) STRICT",
    ),
    (
        "trusted_clock_overrun_latch",
        "CREATE TABLE trusted_clock_overrun_latch (
    singleton                INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version           INTEGER NOT NULL,
    latched                  INTEGER NOT NULL CHECK (latched IN (0, 1)),
    overrun_count            INTEGER NOT NULL CHECK (overrun_count >= 0),
    last_overrun_reservation INTEGER NOT NULL CHECK (last_overrun_reservation >= 0),
    last_overrun_kind        INTEGER NOT NULL CHECK (last_overrun_kind IN (0, 1, 2, 3)),
    last_overrun_at_micros   INTEGER NOT NULL CHECK (last_overrun_at_micros >= 0)
) STRICT",
    ),
    (
        "trusted_clock_overrun_acknowledgements",
        "CREATE TABLE trusted_clock_overrun_acknowledgements (
    ack_seq                         INTEGER PRIMARY KEY CHECK (ack_seq >= 1),
    acknowledged_overrun_count      INTEGER NOT NULL CHECK (acknowledged_overrun_count >= 1),
    operator_principal_digest       BLOB NOT NULL CHECK (length(operator_principal_digest) = 32),
    authorization_provenance_digest BLOB NOT NULL
        CHECK (length(authorization_provenance_digest) = 32),
    trust_revision_digest           BLOB NOT NULL CHECK (length(trust_revision_digest) = 32),
    acknowledged_at_micros          INTEGER NOT NULL CHECK (acknowledged_at_micros >= 0),
    reason_code                     INTEGER NOT NULL CHECK (reason_code IN (1, 2, 3))
) STRICT",
    ),
    (
        "trusted_clock_overrun_acknowledgements_no_replace",
        "CREATE TRIGGER trusted_clock_overrun_acknowledgements_no_replace
    BEFORE INSERT ON trusted_clock_overrun_acknowledgements
    WHEN EXISTS (SELECT 1 FROM trusted_clock_overrun_acknowledgements WHERE ack_seq = NEW.ack_seq)
BEGIN
    SELECT RAISE(ABORT, 'trusted_clock_overrun_acknowledgements is append-only');
END",
    ),
    (
        "trusted_clock_overrun_acknowledgements_no_update",
        "CREATE TRIGGER trusted_clock_overrun_acknowledgements_no_update
    BEFORE UPDATE ON trusted_clock_overrun_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'trusted_clock_overrun_acknowledgements is append-only');
END",
    ),
    (
        "trusted_clock_overrun_acknowledgements_no_delete",
        "CREATE TRIGGER trusted_clock_overrun_acknowledgements_no_delete
    BEFORE DELETE ON trusted_clock_overrun_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'trusted_clock_overrun_acknowledgements is append-only');
END",
    ),
];

const HIGH_WATER_SELECT: &str = "SELECT format_version, clock_domain, high_water_micros,
    reserved_until_micros, reservation_seq FROM trusted_clock_high_water";

const LATCH_SELECT: &str = "SELECT format_version, latched, overrun_count,
    last_overrun_reservation, last_overrun_kind, last_overrun_at_micros
    FROM trusted_clock_overrun_latch";

const HIGH_WATER_UPSERT: &str = "INSERT OR REPLACE INTO trusted_clock_high_water
    (singleton, format_version, clock_domain, high_water_micros, reserved_until_micros,
     reservation_seq)
    VALUES (1, ?1, ?2, ?3, ?4, ?5)";

const LATCH_UPSERT: &str = "INSERT OR REPLACE INTO trusted_clock_overrun_latch
    (singleton, format_version, latched, overrun_count, last_overrun_reservation,
     last_overrun_kind, last_overrun_at_micros)
    VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)";

const ACKNOWLEDGEMENT_INSERT: &str = "INSERT INTO trusted_clock_overrun_acknowledgements
    (acknowledged_overrun_count, operator_principal_digest, authorization_provenance_digest,
     trust_revision_digest, acknowledged_at_micros, reason_code)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

/// Trusted-clock records in one `SQLite` authority file.
#[derive(Debug)]
pub struct SqliteTrustedClockAuthorityV1 {
    reservation: Connection,
    guard: Connection,
}

impl SqliteTrustedClockAuthorityV1 {
    /// Open the reservation and guard connections on the `SqliteStore`
    /// authority file at `path` and create the trusted-clock tables. Rows are
    /// created by the first reservation's one-time migration.
    ///
    /// The file must already be an initialized `SqliteStore` authority file:
    /// open it with `SqliteStore::open` first. Clock rows live in the same
    /// file as the ARD1 catalog, whose entry count gates the migration, so
    /// this fails closed rather than creating trusted-clock tables in a
    /// foreign or empty file (which would also stop a later
    /// `SqliteStore::open` from initializing its schema there).
    ///
    /// The catalog check and the table creation run in one `BEGIN IMMEDIATE`
    /// transaction, so no writer can drop the catalog between them. A path
    /// that does not exist yet is created as an empty file before the
    /// refusal; it holds no schema, so `SqliteStore::open` still initializes
    /// it.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] when the file cannot be opened, lacks
    /// the complete `SqliteStore` ARD1 catalog (`artifact_registrations` and
    /// `artifact_registration_operations`), the schema objects cannot be
    /// created, or an existing trusted-clock table or trigger differs from
    /// its reviewed definition.
    pub fn open(path: &str) -> Result<Self, CoreError> {
        let authority = connect(path)
            .and_then(|reservation| connect(path).map(|guard| Self { reservation, guard }))?;
        // The schema transaction's `BEGIN IMMEDIATE` relies on this bound.
        let refusal = authority
            .reservation
            .busy_timeout(TRUSTED_CLOCK_WAIT_BUDGET)
            .and_then(|()| schema_refusal(&authority.reservation));
        match refusal {
            Ok(None) => Ok(authority),
            Ok(Some(refusal)) => {
                rollback_on(&authority.reservation);
                Err(CoreError::Storage(refusal.to_owned()))
            }
            // Dropping `authority` closes its connections, which rolls back
            // any transaction `schema_refusal` left open.
            Err(error) => Err(CoreError::Storage(error.to_string())),
        }
    }
}

/// In one immediate transaction, require the store's complete ARD1 catalog,
/// then create or verify the reviewed trusted-clock schema. Commits and
/// returns `None` when both hold; otherwise returns the refusal with the
/// transaction still open.
fn schema_refusal(connection: &Connection) -> rusqlite::Result<Option<&'static str>> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .and_then(|()| sqlite_artifact_registration_schema_exists(connection))
        .and_then(|store| {
            if store {
                reviewed_schema_intact(connection)
                    .map(|intact| (!intact).then_some(TAMPERED_SCHEMA))
            } else {
                Ok(Some(NOT_A_STORE))
            }
        })
        .and_then(|refusal| commit_unless(connection, refusal))
}

fn stored_sql(connection: &Connection, name: &str) -> rusqlite::Result<Option<String>> {
    connection
        .query_row(STORED_SQL, [name], |row| row.get(0))
        .optional()
}

/// Create the named object when it is missing, and report whether the
/// stored definition is the reviewed one.
fn ensure_object(connection: &Connection, (name, sql): (&str, &str)) -> rusqlite::Result<bool> {
    stored_sql(connection, name).and_then(|stored| {
        stored.map_or_else(
            || connection.execute_batch(sql).map(|()| true),
            |stored| Ok(normalize_schema_sql(&stored) == normalize_schema_sql(sql)),
        )
    })
}

fn reviewed_schema_intact(connection: &Connection) -> rusqlite::Result<bool> {
    REVIEWED_SCHEMA
        .into_iter()
        .try_fold(true, |intact, object| {
            ensure_object(connection, object).map(|matches| intact && matches)
        })
}

fn commit_unless(
    connection: &Connection,
    refusal: Option<&'static str>,
) -> rusqlite::Result<Option<&'static str>> {
    refusal.map_or_else(
        || connection.execute_batch("COMMIT").map(|()| None),
        |refusal| Ok(Some(refusal)),
    )
}

fn connect(path: &str) -> Result<Connection, CoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_URI;
    Connection::open_with_flags(path, flags).map_err(|error| CoreError::Storage(error.to_string()))
}

fn port_error(error: &rusqlite::Error) -> TrustedClockPortErrorV1 {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => TrustedClockPortErrorV1::Busy,
        _ => TrustedClockPortErrorV1::Storage,
    }
}

fn storage<T>(result: rusqlite::Result<T>) -> PortResult<T> {
    result.or(Err(TrustedClockPortErrorV1::Storage))
}

fn executed(result: rusqlite::Result<usize>) -> PortResult<()> {
    storage(result).map(|_changed| ())
}

fn query_scalar<T: FromSql>(connection: &Connection, sql: &str) -> rusqlite::Result<T> {
    connection.query_row(sql, [], |row| row.get(0))
}

/// Enforce `journal_mode=WAL` and `synchronous=FULL` on the reservation
/// connection and read both back (ADR-112 §4: set before `BEGIN`, then read
/// back). Setting WAL switches a non-WAL file rather than refusing it; the
/// read-back still fails closed when the mode cannot be applied, such as on
/// an in-memory database.
fn durability_matches(connection: &Connection) -> rusqlite::Result<bool> {
    let journal = query_scalar::<String>(connection, "PRAGMA journal_mode=WAL");
    let synchronous = connection
        .execute_batch("PRAGMA synchronous=FULL")
        .and_then(|()| query_scalar::<i64>(connection, "PRAGMA synchronous"));
    let wal = journal.map(|mode| mode == "wal");
    let full = synchronous.map(|level| level == SYNCHRONOUS_FULL);
    wal.and_then(|wal| full.map(|full| wal && full))
}

/// Begin an immediate transaction on `connection`.
///
/// `synchronous=FULL` is set on both connections but read back only on the
/// reservation connection (`durability_matches`, ADR-112 §4): the guard
/// connection never commits, so its level is never relied on.
fn begin_on(connection: &Connection, busy_timeout: Duration) -> PortResult<()> {
    connection
        .busy_timeout(busy_timeout)
        .and_then(|()| connection.execute_batch("PRAGMA synchronous=FULL"))
        .and_then(|()| connection.execute_batch("BEGIN IMMEDIATE"))
        .map_err(|error| port_error(&error))
}

fn rollback_on(connection: &Connection) {
    // Without an open transaction the reported error carries no information.
    drop(connection.execute_batch("ROLLBACK"));
}

fn row_values(row: &Row<'_>, width: usize) -> rusqlite::Result<Vec<Value>> {
    (0..width).map(|index| row.get::<_, Value>(index)).collect()
}

fn collect_rows(statement: &mut Statement<'_>) -> rusqlite::Result<Vec<Vec<Value>>> {
    let width = statement.column_count();
    let rows = statement.query_map([], |row| row_values(row, width));
    rows.and_then(Iterator::collect)
}

fn select(connection: &Connection, sql: &str) -> PortResult<Vec<Vec<Value>>> {
    connection
        .prepare(sql)
        .and_then(|mut statement| collect_rows(&mut statement))
        .map_err(|error| port_error(&error))
}

/// Decode one high-water row; any other width or column type is corrupt.
fn high_water_row(values: &[Value]) -> PortResult<TrustedClockHighWaterRowV1> {
    match *values {
        [Int(version), Blob(ref domain), Int(high_water), Int(reserved_until), Int(seq)] => {
            Ok(TrustedClockHighWaterRowV1 {
                format_version: version,
                clock_domain: domain.clone(),
                high_water_micros: high_water,
                reserved_until_micros: reserved_until,
                reservation_seq: seq,
            })
        }
        _ => Err(TrustedClockPortErrorV1::Corrupt),
    }
}

/// Decode one overrun-latch row; any other width or column type is corrupt.
const fn latch_row(values: &[Value]) -> PortResult<TrustedClockOverrunLatchRowV1> {
    match *values {
        [Int(version), Int(latched), Int(count), Int(reservation), Int(kind), Int(at)] => {
            Ok(TrustedClockOverrunLatchRowV1 {
                format_version: version,
                latched,
                overrun_count: count,
                last_overrun_reservation: reservation,
                last_overrun_kind: kind,
                last_overrun_at_micros: at,
            })
        }
        _ => Err(TrustedClockPortErrorV1::Corrupt),
    }
}

fn high_water_rows(rows: &[Vec<Value>]) -> PortResult<Vec<TrustedClockHighWaterRowV1>> {
    rows.iter().map(Vec::as_slice).map(high_water_row).collect()
}

fn latch_rows(rows: &[Vec<Value>]) -> PortResult<Vec<TrustedClockOverrunLatchRowV1>> {
    rows.iter().map(Vec::as_slice).map(latch_row).collect()
}

fn read_rows_on(connection: &Connection) -> PortResult<TrustedClockRowsV1> {
    let high_water = select(connection, HIGH_WATER_SELECT)?;
    let overrun_latch = select(connection, LATCH_SELECT)?;
    Ok(TrustedClockRowsV1 {
        high_water: high_water_rows(&high_water)?,
        overrun_latch: latch_rows(&overrun_latch)?,
    })
}

impl TrustedClockStorePortV1 for SqliteTrustedClockAuthorityV1 {
    fn verify_durability_pragmas(&mut self) -> PortResult<bool> {
        storage(durability_matches(&self.reservation))
    }

    fn begin_immediate(&mut self, busy_timeout: Duration) -> PortResult<()> {
        begin_on(&self.reservation, busy_timeout)
    }

    /// The ARD1 catalog entry count, read on the reservation connection
    /// inside the open reservation transaction.
    fn authoritative_catalog_entries(&mut self) -> PortResult<u64> {
        storage(query_scalar::<i64>(&self.reservation, CATALOG_ENTRIES))
            .and_then(|count| u64::try_from(count).or(Err(TrustedClockPortErrorV1::Storage)))
    }

    fn read_rows(&mut self) -> PortResult<TrustedClockRowsV1> {
        read_rows_on(&self.reservation)
    }

    fn generate_clock_domain(&mut self) -> PortResult<[u8; 16]> {
        fresh_clock_domain()
    }

    fn write_high_water(&mut self, row: &TrustedClockHighWaterRowV1) -> PortResult<()> {
        let written = self.reservation.execute(
            HIGH_WATER_UPSERT,
            params![
                row.format_version,
                row.clock_domain,
                row.high_water_micros,
                row.reserved_until_micros,
                row.reservation_seq,
            ],
        );
        executed(written)
    }

    fn write_overrun_latch(&mut self, row: &TrustedClockOverrunLatchRowV1) -> PortResult<()> {
        let written = self.reservation.execute(
            LATCH_UPSERT,
            params![
                row.format_version,
                row.latched,
                row.overrun_count,
                row.last_overrun_reservation,
                row.last_overrun_kind,
                row.last_overrun_at_micros,
            ],
        );
        executed(written)
    }

    fn append_acknowledgement(&mut self, row: &TrustedClockAcknowledgementRowV1) -> PortResult<()> {
        let written = self.reservation.execute(
            ACKNOWLEDGEMENT_INSERT,
            params![
                row.acknowledged_overrun_count,
                row.operator_principal_digest.as_slice(),
                row.authorization_provenance_digest.as_slice(),
                row.trust_revision_digest.as_slice(),
                row.acknowledged_at_micros,
                row.reason_code,
            ],
        );
        executed(written)
    }

    fn commit(&mut self) -> PortResult<()> {
        storage(self.reservation.execute_batch("COMMIT"))
    }

    fn rollback(&mut self) {
        rollback_on(&self.reservation);
    }
}

impl ReleaseGuardPortV1 for SqliteTrustedClockAuthorityV1 {
    fn begin_guard(&mut self, busy_timeout: Duration) -> PortResult<()> {
        begin_on(&self.guard, busy_timeout)
    }

    fn reread_rows(&mut self) -> PortResult<TrustedClockRowsV1> {
        read_rows_on(&self.guard)
    }

    fn rollback_and_release(&mut self) {
        rollback_on(&self.guard);
    }
}
