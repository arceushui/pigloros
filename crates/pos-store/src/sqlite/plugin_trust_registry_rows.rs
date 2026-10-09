//! Row codecs and statements of the `SQLite` Plugin trust policy registry.
//!
//! Every statement here runs on the store's one connection, inside the caller's transaction
//! for writes. Columns are read by name from `SELECT *`, so a decoder never depends on column
//! order; the schema validator has already proved the exact column set. A column that the
//! decoder needs but that is NULL, or a value of the wrong storage class, surfaces as
//! `CorruptState` through [`storage_error`].
//!
//! Limits: no foreign key ties the active pointer to the decision table, and the row decoders do
//! not cross-check them (the write plans only ever write a pointer in the same transaction as its
//! decision or after reading a retained one). `plan_evaluate` (ADR-103 revision 5, step 11) does
//! cross-check the pointer's decision, as `CorruptState`, for the one pointer it reads.
//! `decode_decision` and `decode_rollback` stay separate because their output types differ in
//! every field name they fill.
//!
//! `u64` coordinates (epochs, versions, Ticks, positions, sequences) are stored as the `INTEGER`
//! with the same 64 bits, so every `u64` round-trips and no `CHECK` compares them.

use std::cell::Cell;

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::{EventId, SchemaVersion, Seq, TimelineId};
use rusqlite::{
    named_params, types::FromSql, Connection, ErrorCode, OptionalExtension, Params, Row,
};

use super::{parse_event_id, parse_timeline_id};
use crate::plugin_trust_registry::logic::{PolicyWriteV1, RetainedScopeV1};
use crate::plugin_trust_registry::types::{PluginTrustLedgerBodyV1, RollbackFactsV1};
use crate::plugin_trust_registry::{
    ActivationEventIdentityV1, ActiveReleaseV1, PluginTrustLedgerKindV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1,
};

pub(super) type RegistryResult<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

/// A retained `(version or epoch, complete-record digest)` floor pair.
type FloorPair = (u64, [u8; 32]);

/// The stored `kind` codes of a ledger row; the schema `CHECK` allows exactly `1..=4`.
const KIND_PROVISION: i64 = 1;
const KIND_ADVANCE: i64 = 2;
const KIND_ADMISSION: i64 = 3;
const KIND_ROLLBACK: i64 = 4;

const fn ledger_kind_code(kind: PluginTrustLedgerKindV1) -> i64 {
    match kind {
        PluginTrustLedgerKindV1::Provision => KIND_PROVISION,
        PluginTrustLedgerKindV1::Advance => KIND_ADVANCE,
        PluginTrustLedgerKindV1::Admission => KIND_ADMISSION,
        PluginTrustLedgerKindV1::Rollback => KIND_ROLLBACK,
    }
}

/// Classify a failed statement.
///
/// A busy database is `StorageBusy`. A column that holds the wrong storage class, or a NULL
/// where a value is required, is `CorruptState`. Everything else, including every constraint
/// failure, is `StorageFailed`.
pub(super) fn storage_error(error: &rusqlite::Error) -> PluginTrustPolicyRegistryErrorV1 {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..) | rusqlite::Error::InvalidColumnType(..) => {
            PluginTrustPolicyRegistryErrorV1::CorruptState
        }
        other => match other.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
                PluginTrustPolicyRegistryErrorV1::StorageBusy
            }
            _ => PluginTrustPolicyRegistryErrorV1::StorageFailed,
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

/// Reads the columns of one row. The first failed read is kept and later reads return
/// placeholders, so a decoder is straight-line code whose one failure branch is [`Self::finish`].
pub(super) struct Columns<'a, 'row> {
    row: &'a Row<'row>,
    failure: Cell<Option<PluginTrustPolicyRegistryErrorV1>>,
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
            self.record(storage_error(&error));
            T::default()
        })
    }

    /// Keep `error` unless an earlier read already failed.
    fn record(&self, error: PluginTrustPolicyRegistryErrorV1) {
        self.failure.set(self.failure.get().or(Some(error)));
    }

    fn corrupt(&self) {
        self.record(PluginTrustPolicyRegistryErrorV1::CorruptState);
    }

    /// The first failed read, or `CorruptState` when the decoder itself rejected the row.
    fn failure_or_corrupt(&self) -> PluginTrustPolicyRegistryErrorV1 {
        self.failure
            .get()
            .unwrap_or(PluginTrustPolicyRegistryErrorV1::CorruptState)
    }

    fn unsigned(&self, name: &str) -> u64 {
        from_sql_u64(self.get(name))
    }

    /// A floor pair that must be present.
    fn required_pair(&self, version: &str, digest: &str) -> FloorPair {
        (self.unsigned(version), self.get(digest))
    }

    /// A floor pair that is absent or complete; one column without the other is `CorruptState`.
    fn optional_pair(&self, version: &str, digest: &str) -> Option<FloorPair> {
        match (
            self.get::<Option<i64>>(version),
            self.get::<Option<[u8; 32]>>(digest),
        ) {
            (None, None) => None,
            (Some(version), Some(digest)) => Some((from_sql_u64(version), digest)),
            _ => {
                self.corrupt();
                None
            }
        }
    }

    /// `value`, or the first failure.
    pub(super) fn finish<T>(&self, value: T) -> RegistryResult<T> {
        self.failure.get().map_or(Ok(value), Err)
    }
}

/// The one row of `sql`, or `None`.
fn query_one<T>(
    connection: &Connection,
    sql: &str,
    params: impl Params,
    decode: impl FnOnce(&Row<'_>) -> RegistryResult<T>,
) -> RegistryResult<Option<T>> {
    match connection
        .query_row(sql, params, |row| Ok(decode(row)))
        .optional()
    {
        Ok(found) => found.transpose(),
        Err(error) => Err(storage_error(&error)),
    }
}

/// Every row of `sql`, decoded.
pub(super) fn query_many<T>(
    connection: &Connection,
    sql: &str,
    params: impl Params,
    decode: impl Fn(&Row<'_>) -> RegistryResult<T>,
) -> RegistryResult<Vec<T>> {
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

/// Run one statement that must change exactly one row.
fn execute_one(connection: &Connection, sql: &str, params: impl Params) -> RegistryResult<()> {
    match connection.execute(sql, params) {
        Ok(1) => Ok(()),
        Ok(_) => Err(PluginTrustPolicyRegistryErrorV1::StorageFailed),
        Err(error) => Err(storage_error(&error)),
    }
}

/// The columns of one activation Event identity; all NULL when there is no Event.
struct EventColumns {
    timeline: Option<String>,
    id: Option<String>,
    seq: Option<i64>,
    event_type: Option<String>,
    schema_version: Option<i64>,
    payload_digest: Option<[u8; 32]>,
    origin_logical_seq: Option<i64>,
}

impl EventColumns {
    fn of(event: Option<&ActivationEventIdentityV1>) -> Self {
        Self {
            timeline: event.map(|event| event.timeline.to_string()),
            id: event.map(|event| event.event_id.to_string()),
            seq: event.map(|event| sql_u64(event.seq.as_u64())),
            event_type: event.map(|event| event.event_type.clone()),
            schema_version: event.map(|event| i64::from(event.schema_version.as_u32())),
            payload_digest: event.map(|event| event.payload_digest),
            origin_logical_seq: event
                .and_then(|event| event.origin_logical_seq)
                .map(|seq| sql_u64(seq.as_u64())),
        }
    }
}

fn decode_event(cols: &Columns<'_, '_>) -> ActivationEventIdentityV1 {
    let timeline = parse_timeline_id(&cols.get::<String>("event_timeline")).unwrap_or_else(|_| {
        cols.corrupt();
        TimelineId::new()
    });
    let event_id = parse_event_id(&cols.get::<String>("event_id")).unwrap_or_else(|_| {
        cols.corrupt();
        EventId::new()
    });
    ActivationEventIdentityV1 {
        timeline,
        event_id,
        seq: Seq::from_u64(cols.unsigned("event_seq")),
        event_type: cols.get("event_type"),
        schema_version: SchemaVersion::V1,
        payload_digest: cols.get("event_payload_digest"),
        origin_logical_seq: cols
            .get::<Option<i64>>("event_origin_logical_seq")
            .map(|seq| Seq::from_u64(from_sql_u64(seq))),
    }
}

fn decode_scope(scope: &str, row: &Row<'_>) -> RegistryResult<RetainedScopeV1> {
    let cols = Columns::new(row);
    let Ok(anchor) = PluginTrustPolicyAnchorV1::new(
        scope,
        cols.get("anchor_ptr1_genesis_digest"),
        cols.get("anchor_operator_key"),
        &cols.get::<String>("anchor_operator_role"),
        cols.get("anchor_genesis_tps1_digest"),
    ) else {
        return Err(cols.failure_or_corrupt());
    };
    let tps1_digest: [u8; 32] = cols.get("tps1_digest");
    let tps1_bytes: Vec<u8> = cols.get("tps1_bytes");
    if *blake3::hash(&tps1_bytes).as_bytes() != tps1_digest {
        return Err(cols.failure_or_corrupt());
    }
    cols.finish(RetainedScopeV1 {
        anchor,
        policy: RetainedPolicyStateV1 {
            scope: scope.to_owned(),
            tps1_epoch: cols.unsigned("tps1_epoch"),
            tps1_digest,
            tps1_effective_position: cols.unsigned("tps1_effective_position"),
            tps1_bytes,
            ptr1_floor: cols.optional_pair("ptr1_version", "ptr1_digest"),
            prv1_floor: cols.optional_pair("prv1_epoch", "prv1_digest"),
            highest_trusted_utc_second: cols.get("highest_trusted_utc"),
        },
    })
}

/// A decision row. The ledger's `Admission` rows use the same column names, so one decoder
/// serves both tables.
fn decode_decision(cols: &Columns<'_, '_>) -> RetainedReleaseDecisionV1 {
    RetainedReleaseDecisionV1 {
        scope: cols.get("scope"),
        plugin_id: cols.get("plugin_id"),
        pmf1_digest: cols.get("pmf1_digest"),
        release_digest: cols.get("release_digest"),
        previous_release_digest: cols.get("previous_release_digest"),
        tps1_digest: cols.get("tps1_digest"),
        tps1_epoch: cols.unsigned("tps1_epoch"),
        tps1_effective_position: cols.unsigned("tps1_effective_position"),
        terminal_root: cols.required_pair("ptr1_version", "ptr1_digest"),
        terminal_revocation: cols.required_pair("prv1_epoch", "prv1_digest"),
        trusted_utc_second: cols.get("trusted_utc"),
        tick: cols.unsigned("tick"),
        activation_event: decode_event(cols),
    }
}

fn decode_rollback(cols: &Columns<'_, '_>) -> RollbackFactsV1 {
    RollbackFactsV1 {
        scope: cols.get("scope"),
        plugin_id: cols.get("plugin_id"),
        target_pmf1_digest: cols.get("pmf1_digest"),
        target_release_digest: cols.get("release_digest"),
        replaced_pmf1_digest: cols.get("previous_active_pmf1_digest"),
        tps1_digest: cols.get("tps1_digest"),
        tps1_epoch: cols.unsigned("tps1_epoch"),
        tps1_effective_position: cols.unsigned("tps1_effective_position"),
        terminal_root: cols.required_pair("ptr1_version", "ptr1_digest"),
        terminal_revocation: cols.required_pair("prv1_epoch", "prv1_digest"),
        trusted_utc_second: cols.get("trusted_utc"),
        tick: cols.unsigned("tick"),
        activation_event: decode_event(cols),
    }
}

fn decode_decision_row(row: &Row<'_>) -> RegistryResult<RetainedReleaseDecisionV1> {
    let cols = Columns::new(row);
    cols.finish(decode_decision(&cols))
}

fn decode_active(row: &Row<'_>) -> RegistryResult<ActiveReleaseV1> {
    let cols = Columns::new(row);
    cols.finish(ActiveReleaseV1 {
        scope: cols.get("scope"),
        plugin_id: cols.get("plugin_id"),
        pmf1_digest: cols.get("pmf1_digest"),
        release_digest: cols.get("release_digest"),
        activation_event: decode_event(&cols),
    })
}

fn decode_ledger_body(kind: i64, cols: &Columns<'_, '_>) -> PluginTrustLedgerBodyV1 {
    match kind {
        KIND_ADVANCE => PluginTrustLedgerBodyV1::Advance {
            utc: cols.get("trusted_utc"),
            tick: cols.unsigned("tick"),
        },
        KIND_ADMISSION => PluginTrustLedgerBodyV1::Admission {
            decision: Box::new(decode_decision(cols)),
            previous_active_pmf1_digest: cols.get("previous_active_pmf1_digest"),
        },
        KIND_ROLLBACK => PluginTrustLedgerBodyV1::Rollback(Box::new(decode_rollback(cols))),
        other => {
            if other != KIND_PROVISION {
                cols.corrupt();
            }
            PluginTrustLedgerBodyV1::Provision
        }
    }
}

fn decode_ledger(row: &Row<'_>) -> RegistryResult<PluginTrustLedgerRowV1> {
    let cols = Columns::new(row);
    let kind: i64 = cols.get("kind");
    let body = decode_ledger_body(kind, &cols);
    // A `Provision` row creates no floor; every later row carries both.
    let (ptr1_floor, prv1_floor) = if kind == KIND_PROVISION {
        (None, None)
    } else {
        (
            Some(cols.required_pair("ptr1_version", "ptr1_digest")),
            Some(cols.required_pair("prv1_epoch", "prv1_digest")),
        )
    };
    cols.finish(PluginTrustLedgerRowV1 {
        row_seq: cols.unsigned("row_seq"),
        tps1_digest: cols.get("tps1_digest"),
        tps1_epoch: cols.unsigned("tps1_epoch"),
        tps1_effective_position: cols.unsigned("tps1_effective_position"),
        ptr1_floor,
        prv1_floor,
        body,
    })
}

/// The scope row, or `None` when the scope is not provisioned.
pub(super) fn load_scope(
    connection: &Connection,
    scope: &str,
) -> RegistryResult<Option<RetainedScopeV1>> {
    query_one(
        connection,
        "SELECT * FROM plugin_trust_scopes WHERE scope = ?1",
        [scope],
        |row| decode_scope(scope, row),
    )
}

/// Whether the scope row exists.
pub(super) fn scope_exists(connection: &Connection, scope: &str) -> RegistryResult<bool> {
    query_one(
        connection,
        "SELECT 1 FROM plugin_trust_scopes WHERE scope = ?1",
        [scope],
        |_| Ok(()),
    )
    .map(|found| found.is_some())
}

/// The retained decision keyed `(scope, PMF1 digest)`.
pub(super) fn load_decision(
    connection: &Connection,
    scope: &str,
    pmf1_digest: [u8; 32],
) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
    query_one(
        connection,
        "SELECT * FROM plugin_trust_decisions WHERE scope = ?1 AND pmf1_digest = ?2",
        rusqlite::params![scope, pmf1_digest],
        decode_decision_row,
    )
}

/// The active pointer of `(scope, exact Plugin ID)`.
pub(super) fn load_active(
    connection: &Connection,
    scope: &str,
    plugin_id: &str,
) -> RegistryResult<Option<ActiveReleaseV1>> {
    query_one(
        connection,
        "SELECT * FROM plugin_trust_active WHERE scope = ?1 AND plugin_id = ?2",
        [scope, plugin_id],
        decode_active,
    )
}

/// The latest `Admission` or `Rollback` row of `(scope, exact Plugin ID)`.
pub(super) fn load_latest_release_row(
    connection: &Connection,
    scope: &str,
    plugin_id: &str,
) -> RegistryResult<Option<PluginTrustLedgerRowV1>> {
    query_one(
        connection,
        "SELECT * FROM plugin_trust_ledger WHERE scope = ?1 AND plugin_id = ?2
         ORDER BY row_seq DESC LIMIT 1",
        [scope, plugin_id],
        decode_ledger,
    )
}

/// The `row_seq` the next ledger row of `scope` takes.
pub(super) fn next_row_seq(connection: &Connection, scope: &str) -> RegistryResult<u64> {
    query_one(
        connection,
        "SELECT MAX(row_seq) AS last FROM plugin_trust_ledger WHERE scope = ?1",
        [scope],
        |row| {
            let cols = Columns::new(row);
            cols.finish(cols.get::<Option<i64>>("last"))
        },
    )
    .map(|found| {
        found
            .flatten()
            .map_or(1, |last| from_sql_u64(last).saturating_add(1))
    })
}

/// Every ledger row of `scope` in row order.
pub(super) fn load_ledger(
    connection: &Connection,
    scope: &str,
) -> RegistryResult<Vec<PluginTrustLedgerRowV1>> {
    query_many(
        connection,
        "SELECT * FROM plugin_trust_ledger WHERE scope = ?1 ORDER BY row_seq",
        [scope],
        decode_ledger,
    )
}

/// Insert the scope row of a provisioning.
pub(super) fn insert_scope(connection: &Connection, scope: &RetainedScopeV1) -> RegistryResult<()> {
    let anchor = &scope.anchor;
    let policy = &scope.policy;
    execute_one(
        connection,
        "INSERT INTO plugin_trust_scopes (
             scope, anchor_ptr1_genesis_digest, anchor_operator_key, anchor_operator_role,
             anchor_genesis_tps1_digest, tps1_epoch, tps1_digest, tps1_effective_position,
             tps1_bytes, ptr1_version, ptr1_digest, prv1_epoch, prv1_digest, highest_trusted_utc)
         VALUES (
             :scope, :anchor_ptr1_genesis_digest, :anchor_operator_key, :anchor_operator_role,
             :anchor_genesis_tps1_digest, :tps1_epoch, :tps1_digest, :tps1_effective_position,
             :tps1_bytes, :ptr1_version, :ptr1_digest, :prv1_epoch, :prv1_digest,
             :highest_trusted_utc)",
        named_params! {
            ":scope": policy.scope,
            ":anchor_ptr1_genesis_digest": anchor.ptr1_genesis_digest(),
            ":anchor_operator_key": anchor.operator_key(),
            ":anchor_operator_role": anchor.operator_role(),
            ":anchor_genesis_tps1_digest": anchor.genesis_tps1_digest(),
            ":tps1_epoch": sql_u64(policy.tps1_epoch),
            ":tps1_digest": policy.tps1_digest,
            ":tps1_effective_position": sql_u64(policy.tps1_effective_position),
            ":tps1_bytes": policy.tps1_bytes,
            ":ptr1_version": policy.ptr1_floor.map(|floor| sql_u64(floor.0)),
            ":ptr1_digest": policy.ptr1_floor.map(|floor| floor.1),
            ":prv1_epoch": policy.prv1_floor.map(|floor| sql_u64(floor.0)),
            ":prv1_digest": policy.prv1_floor.map(|floor| floor.1),
            ":highest_trusted_utc": policy.highest_trusted_utc_second,
        },
    )
}

/// Install the successor TPS1, both floors, and the highest trusted UTC second.
pub(super) fn apply_policy(
    connection: &Connection,
    scope: &str,
    write: &PolicyWriteV1,
) -> RegistryResult<()> {
    execute_one(
        connection,
        "UPDATE plugin_trust_scopes SET
             tps1_epoch = :tps1_epoch, tps1_digest = :tps1_digest,
             tps1_effective_position = :tps1_effective_position, tps1_bytes = :tps1_bytes,
             ptr1_version = :ptr1_version, ptr1_digest = :ptr1_digest,
             prv1_epoch = :prv1_epoch, prv1_digest = :prv1_digest,
             highest_trusted_utc = :highest_trusted_utc
         WHERE scope = :scope",
        named_params! {
            ":scope": scope,
            ":tps1_epoch": sql_u64(write.tps1.epoch()),
            ":tps1_digest": write.tps1.digest(),
            ":tps1_effective_position": sql_u64(write.tps1.effective_timeline_position()),
            ":tps1_bytes": write.tps1.bytes(),
            ":ptr1_version": sql_u64(write.root.0),
            ":ptr1_digest": write.root.1,
            ":prv1_epoch": sql_u64(write.revocation.0),
            ":prv1_digest": write.revocation.1,
            ":highest_trusted_utc": write.utc,
        },
    )
}

/// Raise only the highest trusted UTC second, as an idempotent replay does.
pub(super) fn raise_utc(connection: &Connection, scope: &str, utc: i64) -> RegistryResult<()> {
    execute_one(
        connection,
        "UPDATE plugin_trust_scopes SET highest_trusted_utc = ?2 WHERE scope = ?1",
        rusqlite::params![scope, utc],
    )
}

/// Insert one retained release decision.
pub(super) fn insert_decision(
    connection: &Connection,
    decision: &RetainedReleaseDecisionV1,
) -> RegistryResult<()> {
    let event = EventColumns::of(Some(&decision.activation_event));
    execute_one(
        connection,
        "INSERT INTO plugin_trust_decisions (
             scope, pmf1_digest, plugin_id, release_digest, previous_release_digest,
             tps1_digest, tps1_epoch, tps1_effective_position, ptr1_version, ptr1_digest,
             prv1_epoch, prv1_digest, trusted_utc, tick, event_timeline, event_id, event_seq,
             event_type, event_schema_version, event_payload_digest, event_origin_logical_seq)
         VALUES (
             :scope, :pmf1_digest, :plugin_id, :release_digest, :previous_release_digest,
             :tps1_digest, :tps1_epoch, :tps1_effective_position, :ptr1_version, :ptr1_digest,
             :prv1_epoch, :prv1_digest, :trusted_utc, :tick, :event_timeline, :event_id,
             :event_seq, :event_type, :event_schema_version, :event_payload_digest,
             :event_origin_logical_seq)",
        named_params! {
            ":scope": decision.scope,
            ":pmf1_digest": decision.pmf1_digest,
            ":plugin_id": decision.plugin_id,
            ":release_digest": decision.release_digest,
            ":previous_release_digest": decision.previous_release_digest,
            ":tps1_digest": decision.tps1_digest,
            ":tps1_epoch": sql_u64(decision.tps1_epoch),
            ":tps1_effective_position": sql_u64(decision.tps1_effective_position),
            ":ptr1_version": sql_u64(decision.terminal_root.0),
            ":ptr1_digest": decision.terminal_root.1,
            ":prv1_epoch": sql_u64(decision.terminal_revocation.0),
            ":prv1_digest": decision.terminal_revocation.1,
            ":trusted_utc": decision.trusted_utc_second,
            ":tick": sql_u64(decision.tick),
            ":event_timeline": event.timeline,
            ":event_id": event.id,
            ":event_seq": event.seq,
            ":event_type": event.event_type,
            ":event_schema_version": event.schema_version,
            ":event_payload_digest": event.payload_digest,
            ":event_origin_logical_seq": event.origin_logical_seq,
        },
    )
}

/// Set the active pointer of `(scope, exact Plugin ID)`.
pub(super) fn upsert_active(
    connection: &Connection,
    active: &ActiveReleaseV1,
) -> RegistryResult<()> {
    let event = EventColumns::of(Some(&active.activation_event));
    execute_one(
        connection,
        "INSERT INTO plugin_trust_active (
             scope, plugin_id, pmf1_digest, release_digest, event_timeline, event_id, event_seq,
             event_type, event_schema_version, event_payload_digest, event_origin_logical_seq)
         VALUES (
             :scope, :plugin_id, :pmf1_digest, :release_digest, :event_timeline, :event_id,
             :event_seq, :event_type, :event_schema_version, :event_payload_digest,
             :event_origin_logical_seq)
         ON CONFLICT (scope, plugin_id) DO UPDATE SET
             pmf1_digest = excluded.pmf1_digest, release_digest = excluded.release_digest,
             event_timeline = excluded.event_timeline, event_id = excluded.event_id,
             event_seq = excluded.event_seq, event_type = excluded.event_type,
             event_schema_version = excluded.event_schema_version,
             event_payload_digest = excluded.event_payload_digest,
             event_origin_logical_seq = excluded.event_origin_logical_seq",
        named_params! {
            ":scope": active.scope,
            ":plugin_id": active.plugin_id,
            ":pmf1_digest": active.pmf1_digest,
            ":release_digest": active.release_digest,
            ":event_timeline": event.timeline,
            ":event_id": event.id,
            ":event_seq": event.seq,
            ":event_type": event.event_type,
            ":event_schema_version": event.schema_version,
            ":event_payload_digest": event.payload_digest,
            ":event_origin_logical_seq": event.origin_logical_seq,
        },
    )
}

/// The PMF1 previous-release digest an `Admission` row records; no other kind has one.
fn admission_previous_release(row: &PluginTrustLedgerRowV1) -> Option<[u8; 32]> {
    match &row.body {
        PluginTrustLedgerBodyV1::Admission { decision, .. } => decision.previous_release_digest,
        _ => None,
    }
}

/// Append one ledger row.
pub(super) fn insert_ledger(
    connection: &Connection,
    scope: &str,
    row: &PluginTrustLedgerRowV1,
) -> RegistryResult<()> {
    let event = EventColumns::of(row.activation_event());
    execute_one(
        connection,
        "INSERT INTO plugin_trust_ledger (
             scope, row_seq, kind, tps1_digest, tps1_epoch, tps1_effective_position,
             ptr1_version, ptr1_digest, prv1_epoch, prv1_digest, trusted_utc, tick, plugin_id,
             pmf1_digest, release_digest, previous_release_digest, previous_active_pmf1_digest,
             event_timeline, event_id, event_seq, event_type, event_schema_version,
             event_payload_digest, event_origin_logical_seq)
         VALUES (
             :scope, :row_seq, :kind, :tps1_digest, :tps1_epoch, :tps1_effective_position,
             :ptr1_version, :ptr1_digest, :prv1_epoch, :prv1_digest, :trusted_utc, :tick,
             :plugin_id, :pmf1_digest, :release_digest, :previous_release_digest,
             :previous_active_pmf1_digest, :event_timeline, :event_id, :event_seq, :event_type,
             :event_schema_version, :event_payload_digest, :event_origin_logical_seq)",
        named_params! {
            ":scope": scope,
            ":row_seq": sql_u64(row.row_seq()),
            ":kind": ledger_kind_code(row.kind()),
            ":tps1_digest": row.tps1_digest(),
            ":tps1_epoch": sql_u64(row.tps1_epoch()),
            ":tps1_effective_position": sql_u64(row.tps1_effective_position()),
            ":ptr1_version": row.ptr1_floor().map(|floor| sql_u64(floor.0)),
            ":ptr1_digest": row.ptr1_floor().map(|floor| floor.1),
            ":prv1_epoch": row.prv1_floor().map(|floor| sql_u64(floor.0)),
            ":prv1_digest": row.prv1_floor().map(|floor| floor.1),
            ":trusted_utc": row.trusted_utc_second(),
            ":tick": row.tick().map(sql_u64),
            ":plugin_id": row.plugin_id(),
            ":pmf1_digest": row.pmf1_digest(),
            ":release_digest": row.release_digest(),
            ":previous_release_digest": admission_previous_release(row),
            ":previous_active_pmf1_digest": row.previous_active_pmf1_digest(),
            ":event_timeline": event.timeline,
            ":event_id": event.id,
            ":event_seq": event.seq,
            ":event_type": event.event_type,
            ":event_schema_version": event.schema_version,
            ":event_payload_digest": event.payload_digest,
            ":event_origin_logical_seq": event.origin_logical_seq,
        },
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// `finish` of a row read as `first` then `second`, over a one-column in-memory row.
    fn finished_after(
        first: fn(&Columns<'_, '_>),
        second: fn(&Columns<'_, '_>),
    ) -> Result<RegistryResult<()>, rusqlite::Error> {
        Connection::open_in_memory()?.query_row("SELECT 1 AS present", [], |row| {
            let cols = Columns::new(row);
            first(&cols);
            second(&cols);
            Ok(cols.finish(()))
        })
    }

    fn missing_column(cols: &Columns<'_, '_>) {
        let _: i64 = cols.get("absent");
    }

    fn rejected_row(cols: &Columns<'_, '_>) {
        cols.corrupt();
    }

    #[test]
    fn the_first_failed_read_is_the_one_reported() -> Result<(), rusqlite::Error> {
        assert_eq!(
            finished_after(missing_column, rejected_row)?,
            Err(PluginTrustPolicyRegistryErrorV1::StorageFailed)
        );
        assert_eq!(
            finished_after(rejected_row, missing_column)?,
            Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
        );
        Ok(())
    }
}
