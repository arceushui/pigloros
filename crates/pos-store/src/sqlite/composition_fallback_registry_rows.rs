//! Row codecs and statements of the `SQLite` composition fallback registry.
//!
//! Every statement runs on the store's one connection, inside the caller's transaction for
//! writes. Columns are read by name, so a decoder never depends on column order; the schema
//! validator has already proved the exact column set. A column that the decoder needs but that
//! is NULL, or a value of the wrong storage class, surfaces as `CorruptState` through
//! [`storage_error`]. `u64` values are stored as the `INTEGER` with the same 64 bits.

use std::cell::Cell;

use pos_core::{EntityId, EventId, Hash, Seq, TimelineId};
use rusqlite::{params, types::FromSql, Connection, ErrorCode, Params, Row};

use crate::composition_fallback_registry::logic::FallbackResult;
use crate::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as Error, FallbackEntryStateV1, FallbackEventIdentityV1,
    FallbackLedgerBodyV1, FallbackLedgerRowV1, FallbackRegistryRowV1, FallbackRegistryStateV1,
};

/// The stored `kind` of a declaration ledger row; an activation row is `2`.
const KIND_DECLARATION: i64 = 1;

const SELECT_ROW: &str = "SELECT r.entity, r.state_revision, r.policy_digest,
        r.activation_ordinal, e.entry_key, e.tenure_ordinal, e.effective_digest,
        e.chain_position
    FROM composition_fallback_rows AS r
    LEFT JOIN composition_fallback_entries AS e
        ON e.scope = r.scope AND e.timeline = r.timeline
    WHERE r.scope = ?1 AND r.timeline = ?2
    ORDER BY e.entry_key";

const SELECT_POLICY: &str =
    "SELECT policy_bytes FROM composition_fallback_policies WHERE policy_digest = ?1";

const SELECT_LEDGER: &str = "SELECT * FROM composition_fallback_ledger
    WHERE scope = ?1 AND timeline = ?2 ORDER BY row_seq";

const UPSERT_ROW: &str = "INSERT INTO composition_fallback_rows
        (scope, timeline, entity, state_revision, policy_digest, activation_ordinal)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    ON CONFLICT (scope, timeline) DO UPDATE SET
        entity = excluded.entity,
        state_revision = excluded.state_revision,
        policy_digest = excluded.policy_digest,
        activation_ordinal = excluded.activation_ordinal";

const DELETE_ENTRIES: &str =
    "DELETE FROM composition_fallback_entries WHERE scope = ?1 AND timeline = ?2";

const INSERT_ENTRY: &str = "INSERT INTO composition_fallback_entries
        (scope, timeline, entry_key, tenure_ordinal, effective_digest, chain_position)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

const INSERT_POLICY: &str = "INSERT INTO composition_fallback_policies
        (policy_digest, policy_bytes) VALUES (?1, ?2)
    ON CONFLICT (policy_digest) DO NOTHING";

const INSERT_DECLARATION: &str = "INSERT INTO composition_fallback_ledger
        (scope, timeline, row_seq, kind, entity, state_revision, policy_digest, request_digest,
         declared_digest, conformance_digest, event_id, event_seq, event_payload_digest)
    VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?6, ?8, ?9, ?10, ?11)";

const INSERT_ACTIVATION: &str = "INSERT INTO composition_fallback_ledger
        (scope, timeline, row_seq, kind, entity, state_revision, policy_digest, request_digest,
         entry_key, closing_tenure_ordinal, activation_ordinal, tick, event_id, event_seq,
         event_payload_digest)
    VALUES (?1, ?2, ?3, 2, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";

/// Classify a failed statement.
///
/// A busy database is `StorageBusy`. A column that holds the wrong storage class, or a NULL
/// where a value is required, is `CorruptState`. Everything else, including every constraint
/// failure, is `StorageFailed`.
pub(super) fn storage_error(error: &rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..) | rusqlite::Error::InvalidColumnType(..) => {
            Error::CorruptState
        }
        other => match other.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Error::StorageBusy,
            _ => Error::StorageFailed,
        },
    }
}

/// The `INTEGER` that carries the same 64 bits as `value`.
const fn sql_u64(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

/// The `u64` that carries the same 64 bits as the stored `INTEGER`.
const fn from_sql_u64(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

/// Reads columns by name, keeping the first failure instead of returning early.
pub(super) struct Columns<'a, 'row> {
    row: &'a Row<'row>,
    failure: Cell<Option<Error>>,
}

impl<'a, 'row> Columns<'a, 'row> {
    pub(super) const fn new(row: &'a Row<'row>) -> Self {
        Self {
            row,
            failure: Cell::new(None),
        }
    }

    pub(super) fn get<T: FromSql + Default>(&self, name: &str) -> T {
        self.row.get(name).unwrap_or_else(|error| {
            let failure = self.failure.get().or(Some(storage_error(&error)));
            self.failure.set(failure);
            T::default()
        })
    }

    fn unsigned(&self, name: &str) -> u64 {
        from_sql_u64(self.get(name))
    }

    fn hash(&self, name: &str) -> Hash {
        Hash::from_bytes(self.get(name))
    }

    fn entity(&self, name: &str) -> EntityId {
        EntityId::from_ulid(ulid::Ulid::from_bytes(self.get(name)))
    }

    /// `value`, or the first failure.
    pub(super) fn finish<T>(&self, value: T) -> FallbackResult<T> {
        self.failure.get().map_or(Ok(value), Err)
    }
}

/// Every row of `sql`, decoded.
pub(super) fn query_many<T>(
    connection: &Connection,
    sql: &str,
    params: impl Params,
    decode: impl Fn(&Row<'_>) -> FallbackResult<T>,
) -> FallbackResult<Vec<T>> {
    let fetched = connection.prepare(sql).and_then(|mut statement| {
        statement
            .query_map(params, |row| Ok(decode(row)))
            .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
    });
    match fetched {
        Ok(rows) => rows.into_iter().collect(),
        Err(error) => Err(storage_error(&error)),
    }
}

fn execute(connection: &Connection, sql: &str, params: impl Params) -> FallbackResult<()> {
    connection
        .execute(sql, params)
        .map(drop)
        .map_err(|error| storage_error(&error))
}

/// One record of the row-and-entries join.
struct JoinedV1 {
    entity: EntityId,
    state_revision: u64,
    policy_digest: Option<Hash>,
    activation_ordinal: u64,
    entry: Option<(String, FallbackEntryStateV1)>,
}

fn decode_joined(row: &Row<'_>) -> FallbackResult<JoinedV1> {
    let cols = Columns::new(row);
    let entry_key: Option<String> = cols.get("entry_key");
    let entry = entry_key.map(|key| {
        let state = FallbackEntryStateV1 {
            tenure_ordinal: cols.unsigned("tenure_ordinal"),
            effective_digest: cols.hash("effective_digest"),
            chain_position: cols.get("chain_position"),
        };
        (key, state)
    });
    let policy_digest: Option<[u8; 32]> = cols.get("policy_digest");
    cols.finish(JoinedV1 {
        entity: cols.entity("entity"),
        state_revision: cols.unsigned("state_revision"),
        policy_digest: policy_digest.map(Hash::from_bytes),
        activation_ordinal: cols.unsigned("activation_ordinal"),
        entry,
    })
}

fn assemble(records: &[JoinedV1]) -> Option<FallbackRegistryRowV1> {
    records.first().map(|first| FallbackRegistryRowV1 {
        entity: first.entity,
        state: FallbackRegistryStateV1 {
            state_revision: first.state_revision,
            policy_digest: first.policy_digest,
            activation_ordinal: first.activation_ordinal,
            entries: records
                .iter()
                .filter_map(|record| record.entry.clone())
                .collect(),
        },
    })
}

/// The stored row of `(scope, timeline)`.
pub(super) fn load_row(
    connection: &Connection,
    scope: &str,
    timeline: TimelineId,
) -> FallbackResult<Option<FallbackRegistryRowV1>> {
    let timeline = timeline.to_string();
    let params = params![scope, timeline];
    query_many(connection, SELECT_ROW, params, decode_joined)
        .map(|records| assemble(&records))
}

/// The retained DFP1 bytes of `policy_digest`.
pub(super) fn load_policy(
    connection: &Connection,
    policy_digest: Hash,
) -> FallbackResult<Option<Vec<u8>>> {
    let digest = *policy_digest.as_bytes();
    query_many(connection, SELECT_POLICY, params![digest], |row| {
        let cols = Columns::new(row);
        cols.finish(cols.get::<Vec<u8>>("policy_bytes"))
    })
    .map(|policies| policies.into_iter().next())
}

fn decode_body(cols: &Columns<'_, '_>) -> FallbackLedgerBodyV1 {
    if cols.get::<i64>("kind") == KIND_DECLARATION {
        FallbackLedgerBodyV1::Declaration {
            conformance_digest: cols.hash("conformance_digest"),
        }
    } else {
        FallbackLedgerBodyV1::Activation {
            entry_key: cols.get("entry_key"),
            closing_tenure_ordinal: cols.unsigned("closing_tenure_ordinal"),
            activation_ordinal: cols.unsigned("activation_ordinal"),
            tick: cols.unsigned("tick"),
        }
    }
}

fn decode_ledger(row: &Row<'_>) -> FallbackResult<FallbackLedgerRowV1> {
    let cols = Columns::new(row);
    let event = FallbackEventIdentityV1 {
        event_id: EventId::from_ulid(ulid::Ulid::from_bytes(cols.get("event_id"))),
        seq: Seq::from_u64(cols.unsigned("event_seq")),
        payload_digest: cols.hash("event_payload_digest"),
    };
    cols.finish(FallbackLedgerRowV1 {
        row_seq: cols.unsigned("row_seq"),
        entity: cols.entity("entity"),
        state_revision: cols.unsigned("state_revision"),
        policy_digest: cols.hash("policy_digest"),
        request_digest: cols.hash("request_digest"),
        event,
        body: decode_body(&cols),
    })
}

/// The ledger of `(scope, timeline)` in row order.
pub(super) fn load_ledger(
    connection: &Connection,
    scope: &str,
    timeline: TimelineId,
) -> FallbackResult<Vec<FallbackLedgerRowV1>> {
    let timeline = timeline.to_string();
    let params = params![scope, timeline];
    query_many(connection, SELECT_LEDGER, params, decode_ledger)
}

const fn entity_bytes(entity: EntityId) -> [u8; 16] {
    entity.inner().to_bytes()
}

/// Replace the row of `(scope, timeline)` and all of its entries.
pub(super) fn write_row(
    connection: &Connection,
    scope: &str,
    timeline: TimelineId,
    row: &FallbackRegistryRowV1,
) -> FallbackResult<()> {
    let timeline = timeline.to_string();
    let state = &row.state;
    let entity = entity_bytes(row.entity);
    let revision = sql_u64(state.state_revision);
    let policy_digest = state.policy_digest.map(|digest| *digest.as_bytes());
    let ordinal = sql_u64(state.activation_ordinal);
    let upsert = params![scope, timeline, entity, revision, policy_digest, ordinal];
    execute(connection, UPSERT_ROW, upsert)
        .and_then(|()| execute(connection, DELETE_ENTRIES, params![scope, timeline]))
        .and_then(|()| {
            state
                .entries
                .iter()
                .try_for_each(|(key, entry)| insert_entry(connection, scope, &timeline, key, entry))
        })
}

fn insert_entry(
    connection: &Connection,
    scope: &str,
    timeline: &str,
    key: &str,
    entry: &FallbackEntryStateV1,
) -> FallbackResult<()> {
    let tenure = sql_u64(entry.tenure_ordinal);
    let digest = entry.effective_digest.as_bytes();
    let position = entry.chain_position;
    let insert = params![scope, timeline, key, tenure, digest, position];
    execute(connection, INSERT_ENTRY, insert)
}

/// Retain `bytes` under `policy_digest`; an identical earlier retention is kept.
pub(super) fn insert_policy(
    connection: &Connection,
    policy_digest: Hash,
    bytes: &[u8],
) -> FallbackResult<()> {
    let params = params![policy_digest.as_bytes(), bytes];
    execute(connection, INSERT_POLICY, params)
}

/// Append one ledger row.
pub(super) fn insert_ledger(
    connection: &Connection,
    scope: &str,
    timeline: TimelineId,
    row: &FallbackLedgerRowV1,
) -> FallbackResult<()> {
    let timeline = timeline.to_string();
    let event = row.event;
    let entity = entity_bytes(row.entity);
    let event_id = event.event_id.inner().to_bytes();
    let event_seq = sql_u64(event.seq.as_u64());
    let (row_seq, revision) = (sql_u64(row.row_seq), sql_u64(row.state_revision));
    let (policy, request) = (row.policy_digest.as_bytes(), row.request_digest.as_bytes());
    let payload = event.payload_digest.as_bytes();
    match &row.body {
        FallbackLedgerBodyV1::Declaration { conformance_digest } => {
            let conformance = conformance_digest.as_bytes();
            let params = params![
                scope,
                timeline,
                row_seq,
                entity,
                revision,
                policy,
                request,
                conformance,
                event_id,
                event_seq,
                payload,
            ];
            execute(connection, INSERT_DECLARATION, params)
        }
        FallbackLedgerBodyV1::Activation {
            entry_key,
            closing_tenure_ordinal,
            activation_ordinal,
            tick,
        } => {
            let params = params![
                scope,
                timeline,
                row_seq,
                entity,
                revision,
                policy,
                request,
                entry_key,
                sql_u64(*closing_tenure_ordinal),
                sql_u64(*activation_ordinal),
                sql_u64(*tick),
                event_id,
                event_seq,
                payload,
            ];
            execute(connection, INSERT_ACTIVATION, params)
        }
    }
}
