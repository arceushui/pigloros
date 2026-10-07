//! Row codecs and statements of the `SQLite` Plugin trust policy registry.
//!
//! Every statement here runs on the store's one connection, inside the caller's transaction
//! for writes. Columns are read by name from `SELECT *`, so a decoder never depends on column
//! order; the schema validator has already proved the exact column set. A column that the
//! decoder needs but that is NULL, or a value of the wrong storage class, surfaces as
//! `CorruptState` through [`storage_error`].
//!
//! `u64` coordinates (epochs, versions, Ticks, positions, sequences) are stored as the `INTEGER`
//! with the same 64 bits, so every `u64` round-trips and no `CHECK` compares them.

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_core::{SchemaVersion, Seq};
use rusqlite::{named_params, types::FromSql, Connection, ErrorCode, OptionalExtension, Row};

use super::{parse_event_id, parse_timeline_id};
use crate::plugin_trust_registry::logic::{PolicyWriteV1, RetainedScopeV1};
use crate::plugin_trust_registry::types::{PluginTrustLedgerBodyV1, RollbackFactsV1};
use crate::plugin_trust_registry::{
    ActivationEventIdentityV1, ActiveReleaseV1, PluginTrustLedgerKindV1, PluginTrustLedgerRowV1,
    PluginTrustPolicyRegistryErrorV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1,
};

pub(super) type RegistryResult<T> = Result<T, PluginTrustPolicyRegistryErrorV1>;

/// A retained `(version or epoch, complete-record digest)` floor pair.
type Pair = (u64, [u8; 32]);

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

fn column<T: FromSql>(row: &Row<'_>, name: &str) -> RegistryResult<T> {
    row.get(name).map_err(|error| storage_error(&error))
}

fn unsigned(row: &Row<'_>, name: &str) -> RegistryResult<u64> {
    column::<i64>(row, name).map(from_sql_u64)
}

/// A floor pair that must be present.
fn required_pair(row: &Row<'_>, version: &str, digest: &str) -> RegistryResult<Pair> {
    Ok((unsigned(row, version)?, column(row, digest)?))
}

/// A floor pair that is absent or complete; one column without the other is `CorruptState`.
fn optional_pair(row: &Row<'_>, version: &str, digest: &str) -> RegistryResult<Option<Pair>> {
    match (
        column::<Option<i64>>(row, version)?,
        column::<Option<[u8; 32]>>(row, digest)?,
    ) {
        (None, None) => Ok(None),
        (Some(version), Some(digest)) => Ok(Some((from_sql_u64(version), digest))),
        _ => Err(PluginTrustPolicyRegistryErrorV1::CorruptState),
    }
}

fn execute_one(
    connection: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> RegistryResult<()> {
    let changed = connection
        .execute(sql, params)
        .map_err(|error| storage_error(&error))?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PluginTrustPolicyRegistryErrorV1::StorageFailed)
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

fn decode_event(row: &Row<'_>) -> RegistryResult<ActivationEventIdentityV1> {
    let timeline = parse_timeline_id(&column::<String>(row, "event_timeline")?)
        .or(Err(PluginTrustPolicyRegistryErrorV1::CorruptState))?;
    let event_id = parse_event_id(&column::<String>(row, "event_id")?)
        .or(Err(PluginTrustPolicyRegistryErrorV1::CorruptState))?;
    Ok(ActivationEventIdentityV1 {
        timeline,
        event_id,
        seq: Seq::from_u64(unsigned(row, "event_seq")?),
        event_type: column(row, "event_type")?,
        schema_version: SchemaVersion::V1,
        payload_digest: column(row, "event_payload_digest")?,
        origin_logical_seq: column::<Option<i64>>(row, "event_origin_logical_seq")?
            .map(|seq| Seq::from_u64(from_sql_u64(seq))),
    })
}

fn decode_scope(scope: &str, row: &Row<'_>) -> RegistryResult<RetainedScopeV1> {
    let anchor = PluginTrustPolicyAnchorV1::new(
        scope,
        column(row, "anchor_ptr1_genesis_digest")?,
        column(row, "anchor_operator_key")?,
        &column::<String>(row, "anchor_operator_role")?,
        column(row, "anchor_genesis_tps1_digest")?,
    )
    .or(Err(PluginTrustPolicyRegistryErrorV1::CorruptState))?;
    let tps1_digest: [u8; 32] = column(row, "tps1_digest")?;
    let tps1_bytes: Vec<u8> = column(row, "tps1_bytes")?;
    if *blake3::hash(&tps1_bytes).as_bytes() != tps1_digest {
        return Err(PluginTrustPolicyRegistryErrorV1::CorruptState);
    }
    Ok(RetainedScopeV1 {
        anchor,
        policy: RetainedPolicyStateV1 {
            scope: scope.to_owned(),
            tps1_epoch: unsigned(row, "tps1_epoch")?,
            tps1_digest,
            tps1_effective_position: unsigned(row, "tps1_effective_position")?,
            tps1_bytes,
            ptr1_floor: optional_pair(row, "ptr1_version", "ptr1_digest")?,
            prv1_floor: optional_pair(row, "prv1_epoch", "prv1_digest")?,
            highest_trusted_utc_second: column(row, "highest_trusted_utc")?,
        },
    })
}

/// A decision row. The ledger's `Admission` rows use the same column names, so one decoder
/// serves both tables.
fn decode_decision(row: &Row<'_>) -> RegistryResult<RetainedReleaseDecisionV1> {
    Ok(RetainedReleaseDecisionV1 {
        scope: column(row, "scope")?,
        plugin_id: column(row, "plugin_id")?,
        pmf1_digest: column(row, "pmf1_digest")?,
        release_digest: column(row, "release_digest")?,
        previous_release_digest: column(row, "previous_release_digest")?,
        tps1_digest: column(row, "tps1_digest")?,
        tps1_epoch: unsigned(row, "tps1_epoch")?,
        tps1_effective_position: unsigned(row, "tps1_effective_position")?,
        terminal_root: required_pair(row, "ptr1_version", "ptr1_digest")?,
        terminal_revocation: required_pair(row, "prv1_epoch", "prv1_digest")?,
        trusted_utc_second: column(row, "trusted_utc")?,
        tick: unsigned(row, "tick")?,
        activation_event: decode_event(row)?,
    })
}

fn decode_rollback(row: &Row<'_>) -> RegistryResult<RollbackFactsV1> {
    Ok(RollbackFactsV1 {
        scope: column(row, "scope")?,
        plugin_id: column(row, "plugin_id")?,
        target_pmf1_digest: column(row, "pmf1_digest")?,
        target_release_digest: column(row, "release_digest")?,
        replaced_pmf1_digest: column(row, "previous_active_pmf1_digest")?,
        tps1_digest: column(row, "tps1_digest")?,
        tps1_epoch: unsigned(row, "tps1_epoch")?,
        tps1_effective_position: unsigned(row, "tps1_effective_position")?,
        terminal_root: required_pair(row, "ptr1_version", "ptr1_digest")?,
        terminal_revocation: required_pair(row, "prv1_epoch", "prv1_digest")?,
        trusted_utc_second: column(row, "trusted_utc")?,
        tick: unsigned(row, "tick")?,
        activation_event: decode_event(row)?,
    })
}

fn decode_active(row: &Row<'_>) -> RegistryResult<ActiveReleaseV1> {
    Ok(ActiveReleaseV1 {
        scope: column(row, "scope")?,
        plugin_id: column(row, "plugin_id")?,
        pmf1_digest: column(row, "pmf1_digest")?,
        release_digest: column(row, "release_digest")?,
        activation_event: decode_event(row)?,
    })
}

fn decode_ledger_body(kind: i64, row: &Row<'_>) -> RegistryResult<PluginTrustLedgerBodyV1> {
    match kind {
        1 => Ok(PluginTrustLedgerBodyV1::Provision),
        2 => Ok(PluginTrustLedgerBodyV1::Advance {
            utc: column(row, "trusted_utc")?,
            tick: unsigned(row, "tick")?,
        }),
        3 => Ok(PluginTrustLedgerBodyV1::Admission {
            decision: Box::new(decode_decision(row)?),
            previous_active_pmf1_digest: column(row, "previous_active_pmf1_digest")?,
        }),
        4 => Ok(PluginTrustLedgerBodyV1::Rollback(Box::new(
            decode_rollback(row)?,
        ))),
        _ => Err(PluginTrustPolicyRegistryErrorV1::CorruptState),
    }
}

fn decode_ledger(row: &Row<'_>) -> RegistryResult<PluginTrustLedgerRowV1> {
    let kind: i64 = column(row, "kind")?;
    let body = decode_ledger_body(kind, row)?;
    // A `Provision` row creates no floor; every later row carries both.
    let (ptr1_floor, prv1_floor) = if kind == 1 {
        (None, None)
    } else {
        (
            Some(required_pair(row, "ptr1_version", "ptr1_digest")?),
            Some(required_pair(row, "prv1_epoch", "prv1_digest")?),
        )
    };
    Ok(PluginTrustLedgerRowV1 {
        row_seq: unsigned(row, "row_seq")?,
        tps1_digest: column(row, "tps1_digest")?,
        tps1_epoch: unsigned(row, "tps1_epoch")?,
        tps1_effective_position: unsigned(row, "tps1_effective_position")?,
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
    connection
        .query_row(
            "SELECT * FROM plugin_trust_scopes WHERE scope = ?1",
            [scope],
            |row| Ok(decode_scope(scope, row)),
        )
        .optional()
        .map_err(|error| storage_error(&error))?
        .transpose()
}

/// Whether the scope row exists.
pub(super) fn scope_exists(connection: &Connection, scope: &str) -> RegistryResult<bool> {
    connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM plugin_trust_scopes WHERE scope = ?1)",
            [scope],
            |row| row.get(0),
        )
        .map_err(|error| storage_error(&error))
}

/// The retained decision keyed `(scope, PMF1 digest)`.
pub(super) fn load_decision(
    connection: &Connection,
    scope: &str,
    pmf1_digest: [u8; 32],
) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
    connection
        .query_row(
            "SELECT * FROM plugin_trust_decisions WHERE scope = ?1 AND pmf1_digest = ?2",
            rusqlite::params![scope, pmf1_digest],
            |row| Ok(decode_decision(row)),
        )
        .optional()
        .map_err(|error| storage_error(&error))?
        .transpose()
}

/// The active pointer of `(scope, exact Plugin ID)`.
pub(super) fn load_active(
    connection: &Connection,
    scope: &str,
    plugin_id: &str,
) -> RegistryResult<Option<ActiveReleaseV1>> {
    connection
        .query_row(
            "SELECT * FROM plugin_trust_active WHERE scope = ?1 AND plugin_id = ?2",
            [scope, plugin_id],
            |row| Ok(decode_active(row)),
        )
        .optional()
        .map_err(|error| storage_error(&error))?
        .transpose()
}

/// The latest `Admission` or `Rollback` row of `(scope, exact Plugin ID)`.
pub(super) fn load_latest_release_row(
    connection: &Connection,
    scope: &str,
    plugin_id: &str,
) -> RegistryResult<Option<PluginTrustLedgerRowV1>> {
    connection
        .query_row(
            "SELECT * FROM plugin_trust_ledger WHERE scope = ?1 AND plugin_id = ?2
             ORDER BY row_seq DESC LIMIT 1",
            [scope, plugin_id],
            |row| Ok(decode_ledger(row)),
        )
        .optional()
        .map_err(|error| storage_error(&error))?
        .transpose()
}

/// The `row_seq` the next ledger row of `scope` takes.
pub(super) fn next_row_seq(connection: &Connection, scope: &str) -> RegistryResult<u64> {
    connection
        .query_row(
            "SELECT MAX(row_seq) FROM plugin_trust_ledger WHERE scope = ?1",
            [scope],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|error| storage_error(&error))
        .map(|last| last.map_or(1, |last| from_sql_u64(last).saturating_add(1)))
}

/// Every ledger row of `scope` in row order.
pub(super) fn load_ledger(
    connection: &Connection,
    scope: &str,
) -> RegistryResult<Vec<PluginTrustLedgerRowV1>> {
    let mut statement = connection
        .prepare("SELECT * FROM plugin_trust_ledger WHERE scope = ?1 ORDER BY row_seq")
        .map_err(|error| storage_error(&error))?;
    let rows = statement
        .query_map([scope], |row| Ok(decode_ledger(row)))
        .map_err(|error| storage_error(&error))?;
    rows.map(|row| row.map_err(|error| storage_error(&error))?)
        .collect()
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

const fn ledger_kind_code(kind: PluginTrustLedgerKindV1) -> i64 {
    match kind {
        PluginTrustLedgerKindV1::Provision => 1,
        PluginTrustLedgerKindV1::Advance => 2,
        PluginTrustLedgerKindV1::Admission => 3,
        PluginTrustLedgerKindV1::Rollback => 4,
    }
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
