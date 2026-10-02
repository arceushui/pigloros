//! `SQLite` trusted-clock authority adapter.
//!
//! The reservation connection commits reservations, latches and
//! acknowledgements with `synchronous=FULL`. The guard connection holds the
//! file's single write lock from `BEGIN IMMEDIATE` until teardown and never
//! commits. Both connections open the same authority file.

use super::fresh_clock_domain;
use pos_core::trusted_clock::{
    ReleaseGuardPortV1, TrustedClockAcknowledgementRowV1, TrustedClockHighWaterRowV1,
    TrustedClockOverrunLatchRowV1, TrustedClockPortErrorV1, TrustedClockRowsV1,
    TrustedClockStorePortV1, TRUSTED_CLOCK_WAIT_BUDGET,
};
use pos_core::CoreError;
use rusqlite::types::{FromSql, Value};
use rusqlite::{params, Connection, ErrorCode, OpenFlags, Row, Statement};
use std::time::Duration;

type PortResult<T> = Result<T, TrustedClockPortErrorV1>;

const SYNCHRONOUS_FULL: i64 = 2;

const SCHEMA: &str = "PRAGMA journal_mode=WAL;
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS trusted_clock_high_water (
    singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version        INTEGER NOT NULL,
    clock_domain          BLOB    NOT NULL CHECK (length(clock_domain) = 16),
    high_water_micros     INTEGER NOT NULL CHECK (high_water_micros >= 0),
    reserved_until_micros INTEGER NOT NULL CHECK (reserved_until_micros >= high_water_micros),
    reservation_seq       INTEGER NOT NULL CHECK (reservation_seq >= 0)
) STRICT;
CREATE TABLE IF NOT EXISTS trusted_clock_overrun_latch (
    singleton                INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version           INTEGER NOT NULL,
    latched                  INTEGER NOT NULL CHECK (latched IN (0, 1)),
    overrun_count            INTEGER NOT NULL CHECK (overrun_count >= 0),
    last_overrun_reservation INTEGER NOT NULL CHECK (last_overrun_reservation >= 0),
    last_overrun_kind        INTEGER NOT NULL CHECK (last_overrun_kind IN (0, 1, 2, 3)),
    last_overrun_at_micros   INTEGER NOT NULL CHECK (last_overrun_at_micros >= 0)
) STRICT;
CREATE TABLE IF NOT EXISTS trusted_clock_overrun_acknowledgements (
    ack_seq                         INTEGER PRIMARY KEY CHECK (ack_seq >= 1),
    acknowledged_overrun_count      INTEGER NOT NULL CHECK (acknowledged_overrun_count >= 1),
    operator_principal_digest       BLOB NOT NULL CHECK (length(operator_principal_digest) = 32),
    authorization_provenance_digest BLOB NOT NULL
        CHECK (length(authorization_provenance_digest) = 32),
    trust_revision_digest           BLOB NOT NULL CHECK (length(trust_revision_digest) = 32),
    acknowledged_at_micros          INTEGER NOT NULL CHECK (acknowledged_at_micros >= 0),
    reason_code                     INTEGER NOT NULL CHECK (reason_code IN (1, 2, 3))
) STRICT;
COMMIT;";

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
    /// Open the reservation and guard connections on one authority file and
    /// create the trusted-clock tables. Rows are created by the first
    /// reservation's one-time migration.
    ///
    /// # Errors
    /// Returns [`CoreError::Storage`] when the file cannot be opened or the
    /// tables cannot be created.
    pub fn open(path: &str) -> Result<Self, CoreError> {
        let connections = connect(path)
            .and_then(|reservation| connect(path).map(|guard| Self { reservation, guard }));
        connections.and_then(Self::with_schema)
    }

    fn with_schema(self) -> Result<Self, CoreError> {
        let created = self
            .reservation
            .busy_timeout(TRUSTED_CLOCK_WAIT_BUDGET)
            .and_then(|()| self.reservation.execute_batch(SCHEMA));
        created
            .map(|()| self)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }
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
    // `.or(Err(..))` instead of `.map_err(|_| ..)`: a closure would add a
    // region that is uncovered whenever a caller's error arm is unreachable.
    result.or(Err(TrustedClockPortErrorV1::Storage))
}

fn executed(result: rusqlite::Result<usize>) -> PortResult<()> {
    storage(result).map(|_changed| ())
}

fn pragma<T: FromSql>(connection: &Connection, sql: &str) -> rusqlite::Result<T> {
    connection.query_row(sql, [], |row| row.get(0))
}

fn durability_matches(connection: &Connection) -> rusqlite::Result<bool> {
    let journal = pragma::<String>(connection, "PRAGMA journal_mode=WAL");
    let synchronous = connection
        .execute_batch("PRAGMA synchronous=FULL")
        .and_then(|()| pragma::<i64>(connection, "PRAGMA synchronous"));
    let wal = journal.map(|mode| mode == "wal");
    let full = synchronous.map(|level| level == SYNCHRONOUS_FULL);
    wal.and_then(|wal| full.map(|full| wal && full))
}

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
    let selected = connection
        .prepare(sql)
        .and_then(|mut statement| collect_rows(&mut statement));
    storage(selected)
}

fn high_water_row(values: &[Value]) -> PortResult<TrustedClockHighWaterRowV1> {
    match *values {
        [Value::Integer(format_version), Value::Blob(ref clock_domain), Value::Integer(high_water_micros), Value::Integer(reserved_until_micros), Value::Integer(reservation_seq)] => {
            Ok(TrustedClockHighWaterRowV1 {
                format_version,
                clock_domain: clock_domain.clone(),
                high_water_micros,
                reserved_until_micros,
                reservation_seq,
            })
        }
        _ => Err(TrustedClockPortErrorV1::Storage),
    }
}

const fn latch_row(values: &[Value]) -> PortResult<TrustedClockOverrunLatchRowV1> {
    match *values {
        [Value::Integer(format_version), Value::Integer(latched), Value::Integer(overrun_count), Value::Integer(last_overrun_reservation), Value::Integer(last_overrun_kind), Value::Integer(last_overrun_at_micros)] => {
            Ok(TrustedClockOverrunLatchRowV1 {
                format_version,
                latched,
                overrun_count,
                last_overrun_reservation,
                last_overrun_kind,
                last_overrun_at_micros,
            })
        }
        _ => Err(TrustedClockPortErrorV1::Storage),
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

    fn authoritative_catalog_entries(&mut self) -> PortResult<u64> {
        Ok(0)
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
